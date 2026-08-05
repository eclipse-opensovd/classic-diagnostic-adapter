/*
 * SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//! Default communication plugin: applies `init_mode` policy.
//!
//! [`DefaultCommunicationPlugin`] is the default [`CommunicationPlugin`]. It
//! is the *only* place `init_mode` policy is applied (see ADR-006's authority
//! model) -- the framework itself never inspects `init_mode` except for the
//! `Always`-mode startup call.
//!
//! Required mode semantics:
//!
//! | Mode        | `activate()`                   | first ECU request               | `trigger_detection()` |
//! |-------------|--------------------------------|---------------------------------|-----------------------|
//! | `Always`    | joins or repeats current state | requests use current readiness  | initialize/re-detect  |
//! | `OnDemand`  | initializes the whole vehicle  | returns pending, triggers once  | initialize/re-detect  |
//! | `Disabled`  | rejected, no network activity  | returns pending, never triggers | initialize/re-detect  |
//!
//! Communication protection is owned and managed exclusively by the lifecycle
//! worker. The plugin does not install, retain, or lift protection.
//!
//! Diagnostic operations request activation directly (see
//! [`CommunicationAccess::request_activate`](crate::lifecycle::access::CommunicationAccess::request_activate))
//! at the point they need communication; the framework does not route a
//! request-pending event to the plugin on their behalf.
//!
//! Other plugins can be substituted via `Setup::with_communication_plugin`.

use std::sync::Arc;

use async_trait::async_trait;
use cda_interfaces::communication_control::{CommunicationInitMode, CommunicationInitializer};

use super::{CommunicationPlugin, CommunicationPluginBuilder};
use crate::lifecycle::{
    controller::CommunicationHandle,
    disable::{DisableError, DisableLease, DisableReason},
    error::CommunicationError,
    guard::CommunicationGuard,
    operation::{
        ActivationCause, CommunicationOperation, CommunicationOperationFailure, DetectionCause,
    },
    state::CommunicationState,
};

/// Default communication plugin: applies `init_mode` policy on top of the
/// framework-serialized lifecycle handle.
///
/// Communication protection is owned by the lifecycle worker, not by this
/// plugin. Lifting occurs automatically when the worker activates
/// communication; reinstallation occurs on error or disable.
pub struct DefaultCommunicationPlugin {
    handle: CommunicationHandle,
    mode: CommunicationInitMode,
}

impl DefaultCommunicationPlugin {
    /// Creates the default plugin for the given `init_mode`.
    ///
    /// The plugin delegates all lifecycle operations to the framework handle
    /// and worker. Communication protection is installed separately by the
    /// framework after the plugin is `Arc`-wrapped.
    #[must_use]
    pub fn new(handle: CommunicationHandle, mode: CommunicationInitMode) -> Self {
        Self { handle, mode }
    }
}

#[async_trait]
impl CommunicationPlugin for DefaultCommunicationPlugin {
    fn state(&self) -> CommunicationState {
        self.handle.state()
    }

    fn acquire(&self) -> Result<CommunicationGuard, CommunicationError> {
        self.handle.acquire()
    }

    async fn activate(
        &self,
        cause: ActivationCause,
    ) -> Result<CommunicationState, CommunicationOperationFailure> {
        match self.mode {
            CommunicationInitMode::Always | CommunicationInitMode::OnDemand => {
                tracing::debug!(?cause, mode = ?self.mode, "Activating communication");
                self.handle.activate().await
            }
            CommunicationInitMode::Disabled => {
                // This plugin rejects enabling communication from 'Disabled' state and
                // only will enable communication in 'Always' or 'OnDemand' modes.
                tracing::debug!(?cause, "Activate rejected: init_mode is Disabled");
                Err(CommunicationOperationFailure::ModeDisabled {
                    operation: CommunicationOperation::Activate,
                })
            }
        }
    }

    fn request_activate(&self, cause: ActivationCause) -> CommunicationState {
        match self.mode {
            CommunicationInitMode::Always | CommunicationInitMode::OnDemand => {
                tracing::debug!(?cause, mode = ?self.mode, "Requesting activation (non-blocking)");
                self.handle.request_activate()
            }
            CommunicationInitMode::Disabled => {
                // This plugin rejects enabling communication from 'Disabled' state and
                // only will enable communication in 'Always' or 'OnDemand' modes.
                tracing::debug!(?cause, "Request_activate rejected: init_mode is Disabled");
                self.handle.state()
            }
        }
    }

    async fn trigger_detection(
        &self,
        cause: DetectionCause,
    ) -> Result<CommunicationState, CommunicationOperationFailure> {
        // Topology re-discovery may construct gateways, unlike
        // plain variant re-detection; it is not implemented yet TODO(networkreset-endpoint),
        // so it is rejected while communication is already Enabled rather than
        // silently performing the weaker re-detection instead. From
        // Disabled/Error there is no topology to reset yet, so it falls
        // through to the same full activation as any other cause.
        if cause == DetectionCause::TopologyRediscovery
            && matches!(self.handle.state(), CommunicationState::Enabled)
        {
            tracing::error!(
                ?cause,
                "Trigger_detection rejected: topology re-discovery is not implemented"
            );
            return Err(CommunicationOperationFailure::NotImplemented {
                operation: CommunicationOperation::Detect,
            });
        }

        tracing::debug!(?cause, mode = ?self.mode, "Triggering whole-vehicle detection");
        self.handle.trigger_detection().await
    }

    async fn disable(&self, reason: DisableReason) -> Result<DisableLease, DisableError> {
        self.handle.disable(reason).await
    }

    async fn register_initializer(&self, initializer: Arc<dyn CommunicationInitializer>) {
        self.handle.register_initializer(initializer).await;
    }
}

#[async_trait]
impl cda_interfaces::Shutdown for DefaultCommunicationPlugin {
    async fn shutdown(&self) {
        self.handle.shutdown().await;
    }
}

/// Factory for the default communication plugin.
#[derive(Default)]
pub struct DefaultCommunicationPluginBuilder;

impl CommunicationPluginBuilder for DefaultCommunicationPluginBuilder {
    type Plugin = DefaultCommunicationPlugin;
    type Error = std::convert::Infallible;

    async fn build(
        self,
        handle: CommunicationHandle,
        mode: CommunicationInitMode,
    ) -> Result<Self::Plugin, Self::Error> {
        Ok(DefaultCommunicationPlugin::new(handle, mode))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use cda_interfaces::communication_control::{
        CommControlError, TransportControl, TransportState,
    };

    use super::*;
    use crate::lifecycle::controller::test_utils::communication_handle_new;

    struct RecordingControl {
        enables: AtomicUsize,
        disables: AtomicUsize,
    }

    #[async_trait]
    impl TransportControl for RecordingControl {
        async fn enable(&self) -> Result<(), CommControlError> {
            self.enables.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        async fn disable(&self) -> Result<(), CommControlError> {
            self.disables.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        async fn state(&self) -> TransportState {
            TransportState::Disabled
        }
    }

    fn plugin_with_mode(
        mode: CommunicationInitMode,
    ) -> (DefaultCommunicationPlugin, Arc<RecordingControl>) {
        let control = Arc::new(RecordingControl {
            enables: AtomicUsize::new(0),
            disables: AtomicUsize::new(0),
        });
        let handle =
            communication_handle_new(Arc::clone(&control) as Arc<dyn TransportControl>, None);
        (DefaultCommunicationPlugin::new(handle, mode), control)
    }

    #[tokio::test]
    async fn always_mode_activate_initializes_transport() {
        let (plugin, control) = plugin_with_mode(CommunicationInitMode::Always);
        assert_eq!(
            plugin.activate(ActivationCause::Startup).await,
            Ok(CommunicationState::Enabled)
        );
        assert_eq!(control.enables.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn on_demand_mode_activate_initializes_transport() {
        let (plugin, control) = plugin_with_mode(CommunicationInitMode::OnDemand);
        assert_eq!(
            plugin.activate(ActivationCause::Explicit).await,
            Ok(CommunicationState::Enabled)
        );
        assert_eq!(control.enables.load(Ordering::Relaxed), 1);
    }

    /// Acceptance 7: ordinary `activate()` in `Disabled` mode is rejected
    /// *without any network activity* -- the transport must never see an
    /// `enable()` call.
    #[tokio::test]
    async fn disabled_mode_activate_rejected_without_network_activity() {
        let (plugin, control) = plugin_with_mode(CommunicationInitMode::Disabled);
        assert_eq!(
            plugin.activate(ActivationCause::Explicit).await,
            Err(CommunicationOperationFailure::ModeDisabled {
                operation: CommunicationOperation::Activate
            })
        );
        assert_eq!(
            control.enables.load(Ordering::Relaxed),
            0,
            "Disabled mode must not touch the transport on an ordinary activate()"
        );
        assert_eq!(plugin.state(), CommunicationState::Disabled);
    }

    /// Acceptance 7: `trigger_detection()` is the *only* path that may
    /// initialize communication while `Disabled`.
    #[tokio::test]
    async fn disabled_mode_trigger_detection_is_the_only_authorized_path() {
        let (plugin, control) = plugin_with_mode(CommunicationInitMode::Disabled);

        // Ordinary activation is inert.
        assert!(plugin.activate(ActivationCause::Explicit).await.is_err());
        assert_eq!(control.enables.load(Ordering::Relaxed), 0);
        assert_eq!(plugin.state(), CommunicationState::Disabled);

        // Only trigger_detection() may initialize communication.
        assert_eq!(
            plugin.trigger_detection(DetectionCause::Explicit).await,
            Ok(CommunicationState::Enabled)
        );
        assert_eq!(control.enables.load(Ordering::Relaxed), 1);
    }

    /// Repeated `trigger_detection()` calls while one is already in flight
    /// join the same generation rather than starting a second transport
    /// activation.
    #[tokio::test]
    async fn repeated_trigger_detection_coalesces() {
        let (plugin, control) = plugin_with_mode(CommunicationInitMode::Disabled);
        let plugin = Arc::new(plugin);
        let a = {
            let plugin = Arc::clone(&plugin);
            tokio::spawn(async move { plugin.trigger_detection(DetectionCause::Explicit).await })
        };
        let b = {
            let plugin = Arc::clone(&plugin);
            tokio::spawn(async move { plugin.trigger_detection(DetectionCause::Explicit).await })
        };
        assert_eq!(a.await.unwrap(), Ok(CommunicationState::Enabled));
        assert_eq!(b.await.unwrap(), Ok(CommunicationState::Enabled));
        assert_eq!(control.enables.load(Ordering::Relaxed), 1);
    }
}
