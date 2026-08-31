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
//! [`DefaultCommunicationPlugin`] is the only place `init_mode` policy is
//! applied. The framework itself never inspects `init_mode`, except for the
//! `Always`-mode startup call.
//!
//! Required mode semantics:
//!
//! | Mode        | `activate()`                   | first ECU request               | `trigger_detection()`   |
//! |-------------|--------------------------------|---------------------------------|-------------------------|
//! | `Always`    | joins or repeats current state | requests use current readiness  | detect while enabled    |
//! | `OnDemand`  | initializes the whole vehicle  | returns pending, triggers once  | detect while enabled    |
//! | `Disabled`  | rejected, no network activity  | returns pending, never triggers | detect while enabled    |
//!
//! Only the first two columns vary by mode. `trigger_detection()` never
//! consults `init_mode`, so under `Disabled` communication has to be enabled out
//! of band before anything can detect.
//!
//! Other plugins can be substituted via `Setup::with_communication_plugin`.

use std::{future::Future, sync::Arc};

use async_trait::async_trait;
use cda_interfaces::communication_control::{
    ActivationCause, CommunicationError, CommunicationGuard, CommunicationInitMode,
    CommunicationLifecycle, CommunicationOperation, CommunicationOperationFailure,
    CommunicationState, CommunicationVariantDetection, DetectionCause, VariantDetectionMode,
};

use super::{CommunicationPlugin, CommunicationPluginBuilder};
use crate::lifecycle::{
    controller::CommunicationHandle,
    disable::{DisableError, DisableLease, DisableReason},
};

/// Default communication plugin: applies `init_mode` policy on top of the
/// framework-serialized lifecycle handle.
pub struct DefaultCommunicationPlugin {
    handle: CommunicationHandle,
    mode: CommunicationInitMode,
}

impl DefaultCommunicationPlugin {
    /// Creates the default plugin for the given `init_mode`. It delegates all
    /// lifecycle operations to the framework handle and worker.
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
                self.handle.enable_and_detect().await
            }
            // `Disabled` authorizes no bring-up through this plugin.
            CommunicationInitMode::Disabled => {
                tracing::debug!(?cause, "activate rejected: init_mode is Disabled");
                Err(CommunicationOperationFailure::ModeDisabled {
                    operation: CommunicationOperation::EnableAndDetect,
                })
            }
        }
    }

    fn request_activate(&self, cause: ActivationCause) -> CommunicationState {
        match self.mode {
            CommunicationInitMode::Always | CommunicationInitMode::OnDemand => {
                tracing::debug!(?cause, mode = ?self.mode, "Requesting activation (non-blocking)");
                self.handle.request_enable_and_detect()
            }
            // See the `Disabled` arm of `activate` above.
            CommunicationInitMode::Disabled => {
                tracing::debug!(?cause, "request_activate rejected: init_mode is Disabled");
                self.handle.state()
            }
        }
    }

    async fn trigger_detection(
        &self,
        cause: DetectionCause,
    ) -> Result<CommunicationState, CommunicationOperationFailure> {
        // TODO: topology rediscovery (#490).

        tracing::debug!(?cause, mode = ?self.mode, "Triggering whole-vehicle detection");

        self.handle.redetect().await
    }

    async fn disable(&self, reason: DisableReason) -> Result<DisableLease, DisableError> {
        self.handle.disable(reason).await
    }

    async fn register_lifecycle_hook(
        &self,
        initializer: Arc<dyn CommunicationLifecycle>,
    ) -> Result<(), CommunicationOperationFailure> {
        self.handle.register_lifecycle_hook(initializer).await
    }

    async fn register_variant_detection(
        &self,
        detector: Arc<dyn CommunicationVariantDetection>,
    ) -> Result<(), CommunicationOperationFailure> {
        self.handle.register_variant_detection(detector).await
    }

    fn variant_detection(&self) -> VariantDetectionMode {
        self.handle.variant_detection()
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

    fn build(
        self,
        handle: CommunicationHandle,
        mode: CommunicationInitMode,
    ) -> impl Future<Output = Result<Self::Plugin, Self::Error>> + Send {
        std::future::ready(Ok(DefaultCommunicationPlugin::new(handle, mode)))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use async_trait::async_trait;
    use cda_interfaces::communication_control::{
        CommControlError, TransportControl, TransportState,
    };

    use super::*;
    use crate::lifecycle::controller::test_utils::communication_handle_new;

    struct RecordingControl {
        enables: AtomicUsize,
        disables: AtomicUsize,
        fail_enable: AtomicBool,
    }

    #[async_trait]
    impl TransportControl for RecordingControl {
        async fn enable(&self) -> Result<(), CommControlError> {
            if self.fail_enable.load(Ordering::Relaxed) {
                return Err(CommControlError::InitFailed("simulated failure".to_owned()));
            }
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

    /// Returns the plugin, its transport, and a second handle to the same
    /// runtime.
    ///
    /// The extra handle stands in for whatever brings communication up out of
    /// band, which under `init_mode = Disabled` is the only way to reach an
    /// enabled transport.
    fn plugin_with_mode(
        mode: CommunicationInitMode,
    ) -> (
        DefaultCommunicationPlugin,
        Arc<RecordingControl>,
        CommunicationHandle,
    ) {
        let control = Arc::new(RecordingControl {
            enables: AtomicUsize::new(0),
            disables: AtomicUsize::new(0),
            fail_enable: AtomicBool::new(false),
        });
        let handle = communication_handle_new(Arc::clone(&control) as Arc<dyn TransportControl>);
        (
            DefaultCommunicationPlugin::new(handle.clone(), mode),
            control,
            handle,
        )
    }

    /// Both admitting modes bring the transport up for the cause they admit.
    /// `Disabled` refuses, covered separately below.
    #[tokio::test]
    async fn admitting_modes_activate_the_transport() {
        for (mode, cause) in [
            (CommunicationInitMode::Always, ActivationCause::Startup),
            (CommunicationInitMode::OnDemand, ActivationCause::Explicit),
        ] {
            let (plugin, control, _handle) = plugin_with_mode(mode);
            assert_eq!(
                plugin.activate(cause).await,
                Ok(CommunicationState::Enabled),
                "{mode:?}"
            );
            assert_eq!(control.enables.load(Ordering::Relaxed), 1, "{mode:?}");
        }
    }

    /// Ordinary `activate()` in `Disabled` mode is rejected without any network
    /// activity. The transport must never see an `enable()` call.
    #[tokio::test]
    async fn disabled_mode_activate_rejected_without_network_activity() {
        let (plugin, control, _handle) = plugin_with_mode(CommunicationInitMode::Disabled);
        assert_eq!(
            plugin.activate(ActivationCause::Explicit).await,
            Err(CommunicationOperationFailure::ModeDisabled {
                operation: CommunicationOperation::EnableAndDetect
            })
        );
        assert_eq!(
            control.enables.load(Ordering::Relaxed),
            0,
            "Disabled mode must not touch the transport on an ordinary activate()"
        );
        assert_eq!(plugin.state(), CommunicationState::Disabled);
    }

    /// `trigger_detection()` never brings a transport up, so `Disabled` mode is
    /// inert on every path this plugin exposes: widening a detection request
    /// into an activation would produce exactly the unauthorized network traffic
    /// the mode exists to prevent.
    #[tokio::test]
    async fn disabled_mode_is_inert_on_every_path_including_detection() {
        let (plugin, control, handle) = plugin_with_mode(CommunicationInitMode::Disabled);

        // Ordinary activation is inert.
        assert!(plugin.activate(ActivationCause::Explicit).await.is_err());
        assert_eq!(control.enables.load(Ordering::Relaxed), 0);
        assert_eq!(plugin.state(), CommunicationState::Disabled);

        // So is detection: refused without touching the transport.
        assert_eq!(
            plugin.trigger_detection(DetectionCause::Explicit).await,
            Err(CommunicationOperationFailure::TransitionFailure {
                operation: CommunicationOperation::Detect
            })
        );
        assert_eq!(
            control.enables.load(Ordering::Relaxed),
            0,
            "a detection request must never enable the transport"
        );
        assert_eq!(plugin.state(), CommunicationState::Disabled);

        // Once something else enables communication, detection is served.
        assert_eq!(handle.enable().await, Ok(CommunicationState::Enabled));
        assert_eq!(
            plugin.trigger_detection(DetectionCause::Explicit).await,
            Ok(CommunicationState::Enabled)
        );
        assert_eq!(control.enables.load(Ordering::Relaxed), 1);
    }

    /// From `Enabled`, `trigger_detection` detects without touching the
    /// transport, in every `init_mode`.
    #[tokio::test]
    async fn trigger_detection_redetects_while_enabled_in_every_init_mode() {
        for mode in [
            CommunicationInitMode::Always,
            CommunicationInitMode::OnDemand,
            CommunicationInitMode::Disabled,
        ] {
            let (plugin, control, handle) = plugin_with_mode(mode);

            // Out of band, since `Disabled` authorizes no bring-up here.
            assert_eq!(
                handle.enable_and_detect().await,
                Ok(CommunicationState::Enabled)
            );
            assert_eq!(control.enables.load(Ordering::Relaxed), 1, "{mode:?}");

            assert_eq!(
                plugin.trigger_detection(DetectionCause::Explicit).await,
                Ok(CommunicationState::Enabled),
                "{mode:?}: detection must be allowed while already enabled"
            );
            assert_eq!(
                control.enables.load(Ordering::Relaxed),
                1,
                "{mode:?}: re-detection must not re-enable the transport"
            );
            assert_eq!(control.disables.load(Ordering::Relaxed), 0, "{mode:?}");
        }
    }

    /// `Error(_)` is a downed transport too, so detection is refused there as
    /// well. Recovery is an activation, which only `activate()` performs.
    #[tokio::test]
    async fn trigger_detection_refused_from_error_in_every_init_mode() {
        for mode in [
            CommunicationInitMode::Always,
            CommunicationInitMode::OnDemand,
            CommunicationInitMode::Disabled,
        ] {
            let (plugin, control, handle) = plugin_with_mode(mode);
            control.fail_enable.store(true, Ordering::Relaxed);
            assert!(handle.enable_and_detect().await.is_err(), "{mode:?}");
            assert!(matches!(plugin.state(), CommunicationState::Error(_)));

            control.fail_enable.store(false, Ordering::Relaxed);
            assert_eq!(
                plugin.trigger_detection(DetectionCause::Explicit).await,
                Err(CommunicationOperationFailure::TransitionFailure {
                    operation: CommunicationOperation::Detect
                }),
                "{mode:?}: detection must not recover a broken transport"
            );
            assert_eq!(
                control.enables.load(Ordering::Relaxed),
                0,
                "{mode:?}: no successful enable may have happened"
            );
        }
    }

    /// An exclusive disable lease outranks detection. The request is refused
    /// rather than re-enabling a transport somebody else took down.
    #[tokio::test]
    async fn trigger_detection_rejected_while_disable_lease_held() {
        let (plugin, control, _handle) = plugin_with_mode(CommunicationInitMode::OnDemand);
        assert_eq!(
            plugin.activate(ActivationCause::Explicit).await,
            Ok(CommunicationState::Enabled)
        );
        let lease = plugin.disable(DisableReason::RuntimeUpdate).await.unwrap();

        assert_eq!(
            plugin.trigger_detection(DetectionCause::Explicit).await,
            Err(CommunicationOperationFailure::DisableLeaseHeld {
                operation: CommunicationOperation::Detect
            })
        );
        assert_eq!(control.enables.load(Ordering::Relaxed), 1);

        assert_eq!(lease.release().await, Ok(CommunicationState::Enabled));
    }

    /// Repeated `trigger_detection()` calls join the in-flight variant detection
    /// rather than starting a second one.
    #[tokio::test]
    async fn repeated_trigger_detection_coalesces() {
        let (plugin, control, handle) = plugin_with_mode(CommunicationInitMode::Disabled);
        assert_eq!(
            handle.enable_and_detect().await,
            Ok(CommunicationState::Enabled)
        );

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
