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
//! | Mode               | `activate()`                   | first ECU request               | `trigger_detection()`   |
//! |--------------------|--------------------------------|---------------------------------|-------------------------|
//! | `Always`           | joins or repeats current state | requests use current readiness  | detect while enabled    |
//! | `WhenNotPersisted` | joins or repeats current state | requests use current readiness  | detect while enabled    |
//! | `OnDemand`         | initializes the whole vehicle  | returns pending, triggers once  | detect while enabled    |
//! | `Disabled`         | rejected, no network activity  | returns pending, never triggers | detect while enabled    |
//!
//! `WhenNotPersisted` differs from `Always` only in how the transport discovers
//! gateways, which is not a plugin concern.
//!
//! Only the first two columns vary by mode. `trigger_detection()` never
//! consults `init_mode`: an explicit detection request (`DetectionCause::Explicit`
//! or `DetectionCause::TopologyRediscovery`, a `networkreset` execution) enables
//! a down transport with a full initialization in every mode, including
//! `Disabled`.
//!
//! Other plugins can be substituted via `Setup::with_communication_plugin`.

use std::sync::Arc;

use async_trait::async_trait;
use cda_interfaces::communication_control::{
    ActivationCause, CommunicationError, CommunicationGuard, CommunicationInitMode,
    CommunicationLifecycle, CommunicationOperation, CommunicationOperationFailure,
    CommunicationState, CommunicationVariantDetection, DetectionCause, VariantDetectionMode,
};

use super::{CommunicationPlugin, CommunicationPluginBuilder};
use crate::lifecycle::{
    controller::CommunicationHandle,
    disable::{DisableError, DisableLease, DisableReason, QuiesceLease},
};

/// Completes an explicit activation after a lazy start: connects all pending
/// gateways, then runs the variant detection of an activation. No-op without
/// pending gateways.
async fn complete_lazy_activation(
    handle: &CommunicationHandle,
) -> Result<(), CommunicationOperationFailure> {
    if !handle.has_pending_gateways().await {
        return Ok(());
    }
    tracing::debug!("Explicit activation connects the gateways pending after a lazy start");
    handle.connect_pending_gateways().await;
    handle.detect_if_needed().await.map(|_| ())
}

/// Default communication plugin: applies `init_mode` policy on top of the
/// framework-serialized lifecycle handle.
/// [[ dimpl~default-communication-policy, Default deferred communication policy, dimpl ]]
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

    /// Enables communication and detects. After a lazy start the pending gateways
    /// are connected and detected as well.
    ///
    /// If that follow-up detection is refused, the error is returned although
    /// pending gateways may already be connected.
    async fn activate(
        &self,
        cause: ActivationCause,
    ) -> Result<CommunicationState, CommunicationOperationFailure> {
        match self.mode {
            CommunicationInitMode::Always
            | CommunicationInitMode::WhenNotPersisted
            | CommunicationInitMode::OnDemand => {
                tracing::debug!(?cause, mode = ?self.mode, "Activating communication");
                let state = self.handle.enable_and_detect().await?;
                // A lazy start left gateways pending: an activation that is not
                // a diagnostic request initializes all of them.
                complete_lazy_activation(&self.handle).await?;
                Ok(state)
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
            CommunicationInitMode::Always
            | CommunicationInitMode::WhenNotPersisted
            | CommunicationInitMode::OnDemand => {
                tracing::debug!(?cause, mode = ?self.mode, "Requesting activation (non-blocking)");
                let state = self.handle.request_enable_and_detect();
                if cause != ActivationCause::DiagnosticRequest
                    && matches!(
                        state,
                        CommunicationState::Enabled | CommunicationState::Enabling(_)
                    )
                {
                    // Joins an activation in flight, then connects the gateways a
                    // lazy start left pending.
                    let handle = self.handle.clone();
                    cda_interfaces::spawn_named!("communication-activate-pending", async move {
                        if handle.enable_and_detect().await.is_ok()
                            && let Err(error) = complete_lazy_activation(&handle).await
                        {
                            tracing::warn!(%error, "Connecting pending gateways failed");
                        }
                    });
                }
                state
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
        // Both causes are an explicit authorization to communicate: they bring
        // a down transport up (with a fresh discovery) in every mode. The match
        // is exhaustive so a future cause has to be decided consciously.
        // [[ dimpl~communication-explicit-detection-enables, Explicit detection brings a stopped transport up, dimpl ]]
        let brings_transport_up = match cause {
            DetectionCause::Explicit | DetectionCause::TopologyRediscovery => true,
        };
        if brings_transport_up && self.handle.state() != CommunicationState::Enabled {
            tracing::debug!(?cause, mode = ?self.mode, "Enabling communication for detection");
            return self.handle.enable_and_detect().await;
        }

        tracing::debug!(?cause, mode = ?self.mode, "Triggering whole-vehicle detection");

        self.handle.redetect().await
    }

    async fn disable(&self, reason: DisableReason) -> Result<DisableLease, DisableError> {
        self.handle.disable(reason).await
    }

    fn quiesce(&self, reason: DisableReason) -> Result<QuiesceLease, DisableError> {
        self.handle.quiesce(reason)
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
    use crate::lifecycle::controller::test_utils::{
        communication_handle_new, communication_handle_with_pending_gateways,
    };

    struct RecordingControl {
        enable_count: AtomicUsize,
        disable_count: AtomicUsize,
        fail_enable: AtomicBool,
    }

    #[async_trait]
    impl TransportControl for RecordingControl {
        async fn enable(&self) -> Result<(), CommControlError> {
            if self.fail_enable.load(Ordering::Relaxed) {
                return Err(CommControlError::InitFailed("simulated failure".to_owned()));
            }
            self.enable_count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        async fn disable(&self) -> Result<(), CommControlError> {
            self.disable_count.fetch_add(1, Ordering::Relaxed);
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
            enable_count: AtomicUsize::new(0),
            disable_count: AtomicUsize::new(0),
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
    /// [[ test~deferred-admitting-modes-activate, Eager and on-demand modes admit communication activation, test ]]
    #[tokio::test]
    async fn admitting_modes_activate_the_transport() {
        for (mode, cause) in [
            (CommunicationInitMode::Always, ActivationCause::Startup),
            (
                CommunicationInitMode::WhenNotPersisted,
                ActivationCause::Startup,
            ),
            (CommunicationInitMode::OnDemand, ActivationCause::Explicit),
        ] {
            let (plugin, control, _handle) = plugin_with_mode(mode);
            assert_eq!(
                plugin.activate(cause).await,
                Ok(CommunicationState::Enabled),
                "{mode:?}"
            );
            assert_eq!(control.enable_count.load(Ordering::Relaxed), 1, "{mode:?}");
        }
    }

    /// Ordinary `activate()` in `Disabled` mode is rejected without any network
    /// activity. The transport must never see an `enable()` call.
    /// [[ test~deferred-disabled-rejects-activation, Disabled mode rejects communication activation, test ]]
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
            control.enable_count.load(Ordering::Relaxed),
            0,
            "Disabled mode must not touch the transport on an ordinary activate()"
        );
        assert_eq!(plugin.state(), CommunicationState::Disabled);
    }

    /// [[ test~deferred-request-activation-policy, Nonblocking activation follows the configured initialization mode, test ]]
    #[tokio::test]
    async fn request_activate_follows_init_mode() {
        for mode in [
            CommunicationInitMode::Always,
            CommunicationInitMode::WhenNotPersisted,
            CommunicationInitMode::OnDemand,
        ] {
            let (plugin, control, handle) = plugin_with_mode(mode);
            assert!(matches!(
                plugin.request_activate(ActivationCause::DiagnosticRequest),
                CommunicationState::Enabling(CommunicationOperation::EnableAndDetect)
                    | CommunicationState::Enabled
            ));
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while handle.state() != CommunicationState::Enabled {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("activation did not complete");
            assert_eq!(control.enable_count.load(Ordering::Relaxed), 1, "{mode:?}");
        }

        let (plugin, control, _handle) = plugin_with_mode(CommunicationInitMode::Disabled);
        assert_eq!(
            plugin.request_activate(ActivationCause::DiagnosticRequest),
            CommunicationState::Disabled
        );
        tokio::task::yield_now().await;
        assert_eq!(control.enable_count.load(Ordering::Relaxed), 0);
    }

    /// An explicit or rediscovery detection request brings a stopped transport
    /// up with a full initialization in every `init_mode`.
    /// [[ test~communication-explicit-detection-enables, Explicit detection brings a stopped transport up, test ]]
    #[tokio::test]
    async fn explicit_detection_enables_a_stopped_transport() {
        for mode in [
            CommunicationInitMode::Always,
            CommunicationInitMode::WhenNotPersisted,
            CommunicationInitMode::OnDemand,
            CommunicationInitMode::Disabled,
        ] {
            for cause in [
                DetectionCause::Explicit,
                DetectionCause::TopologyRediscovery,
            ] {
                let (plugin, control, _handle) = plugin_with_mode(mode);
                let detector = Arc::new(CountingDetector::default());
                plugin
                    .register_variant_detection(Arc::clone(&detector) as _)
                    .await
                    .unwrap();
                assert_eq!(plugin.state(), CommunicationState::Disabled);
                assert_eq!(
                    plugin.trigger_detection(cause).await,
                    Ok(CommunicationState::Enabled),
                    "{mode:?} {cause:?}"
                );
                assert_eq!(
                    detector.runs(),
                    1,
                    "{mode:?} {cause:?}: the registered detector must have run"
                );
                assert_eq!(
                    control.enable_count.load(Ordering::Relaxed),
                    1,
                    "{mode:?} {cause:?}: the detector must have run once"
                );
                assert_eq!(plugin.state(), CommunicationState::Enabled);

                // Enabled now: a second request re-detects without re-enabling.
                assert_eq!(
                    plugin.trigger_detection(cause).await,
                    Ok(CommunicationState::Enabled),
                    "{mode:?} {cause:?}"
                );
                assert_eq!(control.enable_count.load(Ordering::Relaxed), 1);
                assert_eq!(detector.runs(), 2, "{mode:?} {cause:?}: re-detected");
            }
        }
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
            assert_eq!(control.enable_count.load(Ordering::Relaxed), 1, "{mode:?}");

            assert_eq!(
                plugin.trigger_detection(DetectionCause::Explicit).await,
                Ok(CommunicationState::Enabled),
                "{mode:?}: detection must be allowed while already enabled"
            );
            assert_eq!(
                control.enable_count.load(Ordering::Relaxed),
                1,
                "{mode:?}: re-detection must not re-enable the transport"
            );
            assert_eq!(control.disable_count.load(Ordering::Relaxed), 0, "{mode:?}");
        }
    }

    /// `Error(_)` is a stopped transport too: an explicit detection request
    /// recovers it, in every `init_mode`.
    #[tokio::test]
    async fn explicit_detection_recovers_from_error_in_every_init_mode() {
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
                Ok(CommunicationState::Enabled),
                "{mode:?}"
            );
            assert_eq!(control.enable_count.load(Ordering::Relaxed), 1, "{mode:?}");
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
                operation: CommunicationOperation::EnableAndDetect
            })
        );
        assert_eq!(control.enable_count.load(Ordering::Relaxed), 1);

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
        assert_eq!(control.enable_count.load(Ordering::Relaxed), 1);
    }

    /// Fake transport view: `connect_all_pending` clears the pending flag.
    struct FakePending {
        pending: AtomicBool,
        connects: AtomicUsize,
    }

    #[async_trait]
    impl cda_interfaces::topology::PendingGateways for FakePending {
        async fn has_pending(&self) -> bool {
            self.pending.load(Ordering::Relaxed)
        }

        async fn connect_all_pending(&self) {
            self.connects.fetch_add(1, Ordering::Relaxed);
            self.pending.store(false, Ordering::Relaxed);
        }

        async fn forget_pending_addresses(&self) {}
    }

    /// Counts the two kinds of detection.
    #[derive(Default)]
    struct CountingDetector {
        detects: AtomicUsize,
        if_needed: AtomicUsize,
    }

    #[async_trait]
    impl CommunicationVariantDetection for CountingDetector {
        fn name(&self) -> &'static str {
            "counting"
        }

        async fn detect(&self) -> Result<(), CommControlError> {
            self.detects.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        async fn detect_if_needed(&self) -> Result<(), CommControlError> {
            self.if_needed.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    impl CountingDetector {
        /// Detections of either kind.
        fn runs(&self) -> usize {
            self.detects
                .load(Ordering::Relaxed)
                .saturating_add(self.if_needed.load(Ordering::Relaxed))
        }
    }

    /// An enabled plugin with a fake pending-gateway view and a counting detector
    /// registered after the initial activation.
    async fn enabled_plugin_with_pending(
        pending: bool,
    ) -> (
        DefaultCommunicationPlugin,
        Arc<FakePending>,
        Arc<CountingDetector>,
    ) {
        let control = Arc::new(RecordingControl {
            enable_count: AtomicUsize::new(0),
            disable_count: AtomicUsize::new(0),
            fail_enable: AtomicBool::new(false),
        });
        let fake = Arc::new(FakePending {
            pending: AtomicBool::new(pending),
            connects: AtomicUsize::new(0),
        });
        let handle = communication_handle_with_pending_gateways(
            control as Arc<dyn TransportControl>,
            Arc::clone(&fake) as Arc<dyn cda_interfaces::topology::PendingGateways>,
        );
        // The lazy start: communication is enabled without connecting everything.
        assert_eq!(handle.enable().await, Ok(CommunicationState::Enabled));
        let detector = Arc::new(CountingDetector::default());
        handle
            .register_variant_detection(
                Arc::clone(&detector) as Arc<dyn CommunicationVariantDetection>
            )
            .await
            .unwrap();
        (
            DefaultCommunicationPlugin::new(handle, CommunicationInitMode::OnDemand),
            fake,
            detector,
        )
    }

    /// An explicit activation of an enabled runtime with pending gateways
    /// connects them once and runs the activation's detection, not the explicit
    /// re-detection. Without pending gateways it does neither.
    /// [[ test~communication-explicit-activation-connects-pending-gateways-and-detects-if-needed, An explicit activation after a lazy start connects all pending gateways and runs the activation's detection, test ]]
    #[tokio::test]
    async fn explicit_activation_connects_pending_gateways_and_detects_if_needed() {
        let (plugin, fake, detector) = enabled_plugin_with_pending(true).await;
        assert_eq!(
            plugin.activate(ActivationCause::Explicit).await,
            Ok(CommunicationState::Enabled)
        );
        assert_eq!(fake.connects.load(Ordering::Relaxed), 1);
        assert_eq!(detector.if_needed.load(Ordering::Relaxed), 1);
        assert_eq!(detector.detects.load(Ordering::Relaxed), 0);

        // Nothing is pending any more: a repeated activation is a no-op.
        assert_eq!(
            plugin.activate(ActivationCause::Explicit).await,
            Ok(CommunicationState::Enabled)
        );
        assert_eq!(fake.connects.load(Ordering::Relaxed), 1);
        assert_eq!(detector.if_needed.load(Ordering::Relaxed), 1);

        let (plugin, fake, detector) = enabled_plugin_with_pending(false).await;
        assert_eq!(
            plugin.activate(ActivationCause::Explicit).await,
            Ok(CommunicationState::Enabled)
        );
        assert_eq!(fake.connects.load(Ordering::Relaxed), 0);
        assert_eq!(detector.if_needed.load(Ordering::Relaxed), 0);
        assert_eq!(detector.detects.load(Ordering::Relaxed), 0);
    }

    /// The non-awaiting explicit activation does the same work in the
    /// background. A diagnostic-request activation never does.
    #[tokio::test]
    async fn request_activate_connects_pending_gateways_only_for_explicit_causes() {
        let (plugin, fake, detector) = enabled_plugin_with_pending(true).await;
        assert_eq!(
            plugin.request_activate(ActivationCause::DiagnosticRequest),
            CommunicationState::Enabled
        );
        tokio::task::yield_now().await;
        assert_eq!(fake.connects.load(Ordering::Relaxed), 0);

        assert_eq!(
            plugin.request_activate(ActivationCause::Explicit),
            CommunicationState::Enabled
        );
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while detector.if_needed.load(Ordering::Relaxed) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("background activation did not finish");
        assert_eq!(fake.connects.load(Ordering::Relaxed), 1);
        assert_eq!(detector.detects.load(Ordering::Relaxed), 0);
    }
}
