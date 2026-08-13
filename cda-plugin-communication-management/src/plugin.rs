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

//! Generic communication plugin contract.

pub mod default;

use std::{future::Future, sync::Arc};

use async_trait::async_trait;
use cda_interfaces::communication_control::{
    ActivationCause, CommunicationError, CommunicationGuard, CommunicationInitMode,
    CommunicationLifecycle, CommunicationOperationFailure, CommunicationState,
    CommunicationVariantDetection, DetectionCause, VariantDetectionMode,
};

// Re-export CommunicationHandle for plugin builders
pub use crate::lifecycle::controller::CommunicationHandle;
use crate::lifecycle::disable::{DisableError, DisableLease, DisableReason};

/// A replaceable communication plugin wired into the CDA runtime.
///
/// The default implementation is
/// [`DefaultCommunicationPlugin`](default::DefaultCommunicationPlugin), which
/// applies `init_mode` policy per ADR-006's required mode semantics. The
/// framework itself never inspects `init_mode` to initiate communication
/// except for the `Always`-mode startup call; every other decision is the
/// plugin's alone. Diagnostic operations request activation directly via
/// [`CommunicationAccess::request_activate`](cda_interfaces::communication_control::CommunicationAccess::request_activate)
/// at the point they need communication, rather than the framework routing an
/// event to the plugin on their behalf.
///
/// Every implementation must also implement [`cda_interfaces::Shutdown`]. The
/// framework calls it once, at the existing communication cleanup point, before
/// any other runtime task cleanup; implementations decide what "shut down"
/// means (the default plugin disables the transport during normal teardown).
#[async_trait]
pub trait CommunicationPlugin: cda_interfaces::Shutdown {
    /// Returns the authoritative lifecycle state.
    fn state(&self) -> CommunicationState;

    /// Acquires diagnostic communication while it is enabled.
    /// The returned [`CommunicationGuard`] ensures that communication remains
    /// enabled for the duration of its lifetime.
    ///
    /// # Errors
    ///
    /// Returns an error when communication is not enabled.
    fn acquire(&self) -> Result<CommunicationGuard, CommunicationError>;

    /// Activates communication or attempts recovery from an error.
    ///
    /// Returns `Ok(CommunicationState::Enabled)` on success (including when
    /// communication was already enabled)
    ///
    /// # Errors
    /// `Err` when the transport or an
    /// initializer fails, or `init_mode` does not authorize this cause.
    async fn activate(
        &self,
        cause: ActivationCause,
    ) -> Result<CommunicationState, CommunicationOperationFailure>;

    /// Non-blocking activation request: claims the transition (or joins an
    /// in-flight one) and returns immediately, driving the actual work in the
    /// background. Honors `init_mode` exactly as [`activate`](Self::activate)
    /// does, but never awaits the result, so a caller that cannot afford to
    /// block through a full activation sequence (which can take seconds due
    /// to variant detection) can trigger it and immediately report "not
    /// ready" to its own caller instead.
    ///
    /// Returns the current state: `Enabled` when nothing needed to be done,
    /// `Enabling(operation)` once an activation operation has been submitted, or
    /// the pre-existing state unchanged when `init_mode` does not authorize
    /// this cause.
    fn request_activate(&self, cause: ActivationCause) -> CommunicationState;

    /// Requests whole-vehicle (re-)detection.
    ///
    /// Detection runs **against a live transport and never brings one up**.
    /// Every row below holds identically in all three `init_mode`s:
    ///
    /// | State                            | Effect                                          |
    /// |----------------------------------|-------------------------------------------------|
    /// | `Enabled`                        | run the detector; transport and hooks untouched |
    /// | `Disabled` / `Error`             | `TransitionFailure`                             |
    /// | `Enabling(_)`                    | join the in-flight operation                    |
    /// | `Disabling` / `DisabledExclusive`| `DisableLeaseHeld`                              |
    ///
    /// The `Disabled`/`Error` row is the load-bearing one: this operation is
    /// deliberately *not* widened into an activation when the transport is
    /// down. Bringing communication up is a separately authorized decision, and
    /// letting a detection request make it would allow vehicle-network traffic
    /// that nobody asked for - under `init_mode = Disabled`, precisely the
    /// traffic that mode exists to prevent. Communication must be brought up
    /// first, by whatever holds that authority.
    ///
    /// Nothing in the framework enforces this shape: an implementation is free
    /// to apply its own policy, exactly as it is for
    /// [`activate`](Self::activate). The default plugin delegates straight to
    /// [`CommunicationHandle::redetect`](CommunicationHandle::redetect), whose
    /// state rules are the table above.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionFailure`](CommunicationOperationFailure::TransitionFailure)
    /// whenever communication is not `Enabled`, and an error when detection
    /// itself fails.
    async fn trigger_detection(
        &self,
        cause: DetectionCause,
    ) -> Result<CommunicationState, CommunicationOperationFailure>;

    /// Acquires exclusive disable ownership, which makes sure the communication cannot
    /// be re-enabled as long as the [`DisableLease`] is held.
    ///
    /// # Errors
    ///
    /// Returns an error when communication is in use, a disable lease is
    /// already held, or disabling the transport fails.
    async fn disable(&self, reason: DisableReason) -> Result<DisableLease, DisableError>;

    /// Registers a framework-enforced lifecycle hook (initialization and deinitialization).
    ///
    /// Hooks follow the transport: they run on every enable, including one that
    /// runs no detection. Work that should follow *detection* is registered via
    /// [`register_variant_detection`](Self::register_variant_detection)
    /// instead.
    ///
    /// Returns a typed error when the worker has stopped accepting registrations.
    async fn register_lifecycle_hook(
        &self,
        initializer: Arc<dyn CommunicationLifecycle>,
    ) -> Result<(), CommunicationOperationFailure>;

    /// Installs the whole-vehicle variant detector: the last stage of an
    /// activation, and the only thing `trigger_detection` re-runs.
    ///
    /// A single slot, so a second registration replaces the first. Until one is
    /// registered, nothing can settle any ECU's variant and
    /// [`variant_detection`](Self::variant_detection) reports `Never`.
    ///
    /// Returns a typed error when the worker has stopped accepting registrations.
    async fn register_variant_detection(
        &self,
        detector: Arc<dyn CommunicationVariantDetection>,
    ) -> Result<(), CommunicationOperationFailure>;

    /// Returns the effective detection policy for the communication runtime
    /// that is currently enabled, or currently being enabled.
    ///
    /// A read-only capability alongside [`state`](Self::state), not lifecycle
    /// authority. `Never` tells a consumer that nothing is going to settle any
    /// ECU's variant, so it can fail fast instead of waiting for a readiness
    /// signal that will never arrive.
    fn variant_detection(&self) -> VariantDetectionMode;
}

/// Factory for a communication plugin that needs the authoritative handle.
pub trait CommunicationPluginBuilder: Send {
    /// Plugin produced by this factory.
    type Plugin: CommunicationPlugin;
    /// Construction error.
    type Error: std::fmt::Display + Send;

    /// Builds the plugin after the passive transport and communication handle exist.
    fn build(
        self,
        handle: CommunicationHandle,
        mode: CommunicationInitMode,
    ) -> impl Future<Output = Result<Self::Plugin, Self::Error>> + Send;
}

// Note this adapter is not used in the code base
// but is kept anyway, as extension point for OEM plugins.

/// Closure adapter for [`CommunicationPluginBuilder`].
pub struct CommunicationPluginFn<F>(F);

/// Wraps an async closure as a [`CommunicationPluginBuilder`].
pub fn communication_plugin_fn<F>(factory: F) -> CommunicationPluginFn<F> {
    CommunicationPluginFn(factory)
}

impl<F, Fut, P, E> CommunicationPluginBuilder for CommunicationPluginFn<F>
where
    F: FnOnce(CommunicationHandle, CommunicationInitMode) -> Fut + Send,
    Fut: Future<Output = Result<P, E>> + Send,
    P: CommunicationPlugin,
    E: std::fmt::Display + Send,
{
    type Plugin = P;
    type Error = E;

    async fn build(self, handle: CommunicationHandle, mode: CommunicationInitMode) -> Result<P, E> {
        self.0(handle, mode).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use cda_interfaces::communication_control::{
        CommControlError, TransportControl, TransportState,
    };

    use super::*;
    use crate::{
        lifecycle::controller::test_utils::communication_handle_new,
        plugin::default::DefaultCommunicationPlugin,
    };

    struct NoopTransport;

    #[async_trait]
    impl TransportControl for NoopTransport {
        async fn enable(&self) -> Result<(), CommControlError> {
            Ok(())
        }
        async fn disable(&self) -> Result<(), CommControlError> {
            Ok(())
        }
        async fn state(&self) -> TransportState {
            TransportState::Disabled
        }
    }

    /// The closure adapter must forward the handle and mode it was built with
    /// unchanged, and propagate the closure's own result - success and
    /// failure alike - as its own.
    #[tokio::test]
    async fn forwards_handle_mode_and_result_to_the_wrapped_closure() {
        let handle = communication_handle_new(Arc::new(NoopTransport) as Arc<dyn TransportControl>);

        let builder = communication_plugin_fn(|handle, mode| async move {
            Ok::<_, std::convert::Infallible>(DefaultCommunicationPlugin::new(handle, mode))
        });
        let plugin = builder
            .build(handle.clone(), CommunicationInitMode::OnDemand)
            .await
            .expect("the wrapped closure never fails");
        assert_eq!(plugin.state(), handle.state());

        let failing_builder = communication_plugin_fn(|_handle, _mode| async move {
            Err::<DefaultCommunicationPlugin, _>("construction failed")
        });
        let Err(error) = failing_builder
            .build(handle, CommunicationInitMode::OnDemand)
            .await
        else {
            panic!("the wrapped closure's failure must propagate");
        };
        assert_eq!(error, "construction failed");
    }
}
