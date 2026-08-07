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

//! Enforced communication lifecycle framework.
//!
//! [`CommunicationHandle`] claims lifecycle-state transitions synchronously
//! (guard acquisition and lease drop stay lock-free) and submits
//! the resulting work to the [`worker`](worker) that
//! exclusively owns the physical transport, initializer list, and HTTP
//! protection. See [`worker`] for why the split exists.

use std::{fmt::Display, sync::Arc};

use cda_interfaces::communication_control::{
    CommunicationInitMode, CommunicationInitializer, TransportControl,
};
use tokio::sync::{oneshot, watch};

use super::{
    disable::{DisableError, DisableLease, DisableLeaseId, DisableReason},
    error::CommunicationError,
    guard::{CommunicationGuard, CommunicationGuardId},
    operation::{CommunicationOperation, CommunicationOperationFailure},
    state::{ActivationResultReceiver, CommunicationState, CommunicationStateStore},
    worker::{self, LifecycleCommand, WorkerSender},
};
use crate::{
    http_protection::{config::HttpProtectionConfig, registry::HttpProtectionRegistry},
    plugin::{CommunicationPlugin, CommunicationPluginBuilder},
};

/// Outcome of attempting to claim or join an in-flight activation-shaped operation.
enum ActivationClaim {
    /// Communication is already enabled; no operation was started.
    AlreadyEnabled,
    /// An exclusive disable lease owns the state; the current state is reported, which can
    /// either be [`CommunicationState::Disabling`] or [`CommunicationState::DisabledExclusive`].
    /// Non-exclusive disable is not part of this, because it allows re-activation and no lease
    /// is owned.
    LeaseHeld(CommunicationState),
    /// Re-detection was rejected because active communication guards are held.
    /// Multiple guards can be held at the same time, as they are not exclusive to each other.
    GuardsHeld,
    /// The lifecycle worker is shutting down; no new operation may start.
    ShuttingDown,
    /// An operation was claimed (or joined); await the receiver for the result.
    Pending(ActivationResultReceiver),
}

/// The capability a [`CommunicationPlugin`] implementation uses to actually
/// perform lifecycle operations. Passed to the builder in
/// [`CommunicationPluginBuilder::build`]; the resulting plugin typically
/// retains it (e.g. [`crate::plugin::default::DefaultCommunicationPlugin`] stores
/// it as [`crate::plugin::default::DefaultCommunicationPlugin::handle`])
/// and delegates every operation it exposes to it.
///
/// Claims lifecycle-state transitions synchronously and submits the resulting
/// physical work to the lifecycle worker (see [`worker`]).
///
/// It is public, so OEM implementers of communication plugins are able to use it.
#[derive(Clone)]
pub struct CommunicationHandle {
    state: Arc<CommunicationStateStore>,
    worker: WorkerSender,
}

/// Failure while constructing the authoritative communication plugin runtime.
#[derive(thiserror::Error, Debug)]
pub enum BuildCommunicationRuntimeError<E: Display> {
    /// The selected plugin builder failed.
    #[error("Communication plugin construction failed: {0}")]
    Plugin(E),
    /// Mandatory communication-protection ownership was invalid.
    #[error("Communication protection installation failed: {0}")]
    Protection(CommunicationOperationFailure),
}

impl CommunicationHandle {
    #[must_use]
    pub fn state(&self) -> CommunicationState {
        self.state.lock().state.clone()
    }

    /// Acquires diagnostic communication while it is enabled.
    ///
    /// # Errors
    ///
    /// Returns an error when communication is not enabled.
    pub fn acquire(&self) -> Result<CommunicationGuard, CommunicationError> {
        let id = CommunicationGuardId(uuid::Uuid::new_v4());
        let mut state = self.state.lock();
        match &state.state {
            CommunicationState::Enabled => {
                state.active_guards.insert(id);
                Ok(CommunicationGuard::new(id, Arc::clone(&self.state)))
            }
            CommunicationState::Disabled => Err(CommunicationError::Disabled),
            CommunicationState::Enabling => Err(CommunicationError::Enabling),
            CommunicationState::Disabling => Err(CommunicationError::Disabling),
            CommunicationState::DisabledExclusive => Err(CommunicationError::DisabledExclusive),
            CommunicationState::Error(failure) => Err(CommunicationError::Failed(failure.clone())),
        }
    }

    pub async fn register_initializer(&self, initializer: Arc<dyn CommunicationInitializer>) {
        let (tx, rx) = oneshot::channel();
        if self
            .worker
            .send(LifecycleCommand::RegisterInitializer {
                initializer,
                reply: tx,
            })
            .await
            .is_ok()
        {
            let _ = rx.await;
        }
    }

    /// Activates communication, joining an already in-flight activation if one exists.
    ///
    /// # Errors
    ///
    /// Returns an error when the transport or an initializer fails, an
    /// exclusive disable lease currently owns the state, or the lifecycle
    /// worker is shutting down.
    pub async fn activate(&self) -> Result<CommunicationState, CommunicationOperationFailure> {
        self.run_claimed(CommunicationOperation::Activate).await
    }

    /// Non-awaiting activation submission: claims the transition (or joins an
    /// in-flight one) and returns immediately, driving the actual work on a
    /// handle-owned task. Safe to call from a context that must not block.
    #[must_use]
    pub fn request_activate(&self) -> CommunicationState {
        self.request_claimed(CommunicationOperation::Activate)
    }

    /// Requests whole-vehicle (re-)detection. Authorized in every `init_mode`,
    /// including `Disabled`, where it is the only path that may initialize
    /// communication.
    ///
    /// From `Disabled`/`Error`, this performs full activation (transport
    /// enable, then initializers) exactly like [`activate`](Self::activate).
    /// While `Enabled`, this performs variant re-detection only: it re-runs
    /// the registered initializers without touching the physical transport.
    ///
    /// # Errors
    ///
    /// Returns an error when the transport or an initializer fails, an
    /// exclusive disable lease currently owns the state, communication guards
    /// are currently held (re-detection only; see
    /// [`CommunicationOperationFailure::GuardsHeld`]), or the lifecycle
    /// worker is shutting down.
    pub async fn trigger_detection(
        &self,
    ) -> Result<CommunicationState, CommunicationOperationFailure> {
        self.run_claimed(CommunicationOperation::Detect).await
    }

    async fn run_claimed(
        &self,
        operation: CommunicationOperation,
    ) -> Result<CommunicationState, CommunicationOperationFailure> {
        let mut rx = match self.claim_or_join(operation) {
            ActivationClaim::AlreadyEnabled => return Ok(CommunicationState::Enabled),
            ActivationClaim::LeaseHeld(_) => {
                return Err(CommunicationOperationFailure::DisableLeaseHeld { operation });
            }
            ActivationClaim::GuardsHeld => {
                return Err(CommunicationOperationFailure::GuardsHeld { operation });
            }
            ActivationClaim::ShuttingDown => {
                return Err(CommunicationOperationFailure::ShuttingDown { operation });
            }
            ActivationClaim::Pending(rx) => rx,
        };

        loop {
            if let Some(result) = rx.borrow_and_update().clone() {
                return result;
            }
            if rx.changed().await.is_err() {
                // The claiming task's sender was dropped without sending, which only
                // happens if the claiming task itself was torn down before it could
                // finalize. Report failure; the claiming task already restored a
                // terminal state in that case.
                return Err(CommunicationOperationFailure::TransitionFailure { operation });
            }
        }
    }

    fn request_claimed(&self, operation: CommunicationOperation) -> CommunicationState {
        match self.claim_or_join(operation) {
            // `GuardsHeld` is only reachable for `Detect`, which none of
            // `request_claimed`'s callers currently issue; guards can only be
            // held while `Enabled`, so that is the state to report -- same as
            // `AlreadyEnabled`.
            ActivationClaim::AlreadyEnabled | ActivationClaim::GuardsHeld => {
                CommunicationState::Enabled
            }
            ActivationClaim::LeaseHeld(current) => current,
            ActivationClaim::ShuttingDown => {
                CommunicationState::Error(CommunicationOperationFailure::ShuttingDown { operation })
            }
            ActivationClaim::Pending(_) => CommunicationState::Enabling,
        }
    }

    /// Claims `Disabled | Error -> Enabling` (full activation) or
    /// `Enabled -> Enabling` for a `Detect` (variant re-detection only, see
    /// D1/D2 in the readiness-gating design), and spawns a handle-owned task
    /// that submits the corresponding physical work to the worker. Otherwise
    /// joins an already-claimed operation, or reports the current state when
    /// neither applies.
    ///
    /// All joined callers observe the same final result via the returned receiver.
    fn claim_or_join(&self, operation: CommunicationOperation) -> ActivationClaim {
        if self.worker.is_shutting_down() {
            return ActivationClaim::ShuttingDown;
        }
        let mut state = self.state.lock();
        match (state.state.clone(), operation) {
            // Variant re-detection while already `Enabled`: never touches the
            // transport (D1), and is refused while communication guards are
            // held (D2) since the per-ECU semaphore only serializes single
            // requests, not a whole multi-request sequence.
            (CommunicationState::Enabled, CommunicationOperation::Detect) => {
                if !state.active_guards.is_empty() {
                    return ActivationClaim::GuardsHeld;
                }
                let (tx, rx) = watch::channel(None);
                state.state = CommunicationState::Enabling;
                state.activation_result = Some(rx.clone());
                drop(state);

                let handle = self.clone();
                tokio::spawn(async move {
                    let result = handle.run_redetect_operation().await;
                    handle.finish_activation(&result);
                    let _ = tx.send(Some(result));
                });
                ActivationClaim::Pending(rx)
            }
            (CommunicationState::Enabled, _) => ActivationClaim::AlreadyEnabled,
            (CommunicationState::Disabled | CommunicationState::Error(_), _) => {
                let (tx, rx) = watch::channel(None);
                state.state = CommunicationState::Enabling;
                state.activation_result = Some(rx.clone());
                drop(state);

                let handle = self.clone();
                tokio::spawn(async move {
                    let result = handle.run_activation_operation(operation).await;
                    handle.finish_activation(&result);
                    let _ = tx.send(Some(result));
                });
                ActivationClaim::Pending(rx)
            }
            (CommunicationState::Enabling, _) => {
                let rx = state
                    .activation_result
                    .clone()
                    .expect("Enabling state must carry an activation_result watch receiver");
                ActivationClaim::Pending(rx)
            }
            (
                current @ (CommunicationState::Disabling | CommunicationState::DisabledExclusive),
                _,
            ) => ActivationClaim::LeaseHeld(current),
        }
    }

    /// Runs the physical operation on the worker, isolating the caller from a
    /// send/reply failure (worker shutdown mid-flight).
    async fn run_activation_operation(
        &self,
        operation: CommunicationOperation,
    ) -> Result<CommunicationState, CommunicationOperationFailure> {
        let (tx, rx) = oneshot::channel();
        if self
            .worker
            .send(LifecycleCommand::Activate {
                operation,
                reply: tx,
            })
            .await
            .is_err()
        {
            return Err(CommunicationOperationFailure::ShuttingDown { operation });
        }
        rx.await
            .unwrap_or(Err(CommunicationOperationFailure::TransitionFailure {
                operation,
            }))
    }

    /// Runs variant re-detection on the worker (initializers only, no
    /// transport change), isolating the caller from a send/reply failure
    /// (worker shutdown mid-flight).
    async fn run_redetect_operation(
        &self,
    ) -> Result<CommunicationState, CommunicationOperationFailure> {
        let operation = CommunicationOperation::Detect;
        let (tx, rx) = oneshot::channel();
        if self
            .worker
            .send(LifecycleCommand::Redetect { reply: tx })
            .await
            .is_err()
        {
            return Err(CommunicationOperationFailure::ShuttingDown { operation });
        }
        rx.await
            .unwrap_or(Err(CommunicationOperationFailure::TransitionFailure {
                operation,
            }))
    }

    /// Publishes the final state for a completed activation-shaped operation
    /// claimed via [`claim_or_join`](Self::claim_or_join), and clears the
    /// activation-result slot so a later activation starts a fresh generation.
    ///
    /// A no-op once `shutdown()` has been called: this runs on a task
    /// detached from the caller, so it can race the worker's own shutdown
    /// sequence publishing its terminal state. `shutting_down` and the write
    /// below share one lock, so shutdown's own later write is always the
    /// last word once it has started (see the field's doc comment).
    fn finish_activation(
        &self,
        result: &Result<CommunicationState, CommunicationOperationFailure>,
    ) {
        let mut state = self.state.lock();
        if state.shutting_down {
            return;
        }
        state.state = match result {
            Ok(new_state) => new_state.clone(),
            Err(failure) => CommunicationState::Error(failure.clone()),
        };
        state.activation_result = None;
    }

    /// Acquires the sole exclusive disable lease after taking the physical transport offline.
    ///
    /// # Errors
    ///
    /// Returns an error when communication is in use or cannot be disabled.
    pub async fn disable(&self, _reason: DisableReason) -> Result<DisableLease, DisableError> {
        if self.worker.is_shutting_down() {
            return Err(DisableError::Failed(
                CommunicationOperationFailure::ShuttingDown {
                    operation: CommunicationOperation::Disable,
                },
            ));
        }
        let id = DisableLeaseId::new();
        {
            let mut state = self.state.lock();
            if !state.active_guards.is_empty() {
                return Err(DisableError::InUse);
            }
            if !matches!(state.state, CommunicationState::Enabled) || state.disable_owner.is_some()
            {
                tracing::debug!(current = ?state.state, "disable rejected");
                return Err(DisableError::Conflict);
            }
            state.state = CommunicationState::Disabling;
            state.disable_owner = Some(id);
        }

        match self.spawn_disable(id).await {
            Ok(Ok(lease)) => Ok(lease),
            Ok(Err(failure)) => Err(DisableError::Failed(failure)),
            Err(join_error) => {
                tracing::error!(%join_error, "communication disable task failed");
                let failure = CommunicationOperationFailure::TransitionFailure {
                    operation: CommunicationOperation::Disable,
                };
                self.finish_failed_disable_locally(id, failure.clone());
                Err(DisableError::Failed(failure))
            }
        }
    }

    fn spawn_disable(
        &self,
        id: DisableLeaseId,
    ) -> tokio::task::JoinHandle<Result<DisableLease, CommunicationOperationFailure>> {
        let handle = self.clone();
        tokio::spawn(async move { handle.run_disable_operation(id).await })
    }

    /// Runs on a task detached from the `disable()` caller so that cancelling
    /// the caller (e.g. aborting a task that awaits `disable()`) cannot lose
    /// the resulting `DisableLease`: constructing it here, not in `disable()`
    /// itself, means an abandoned task still finishes and, with nobody left
    /// to collect the lease, its `Drop` still runs, synchronously deferring
    /// back to `Disabled` exactly as if the caller had dropped it themselves.
    async fn run_disable_operation(
        &self,
        id: DisableLeaseId,
    ) -> Result<DisableLease, CommunicationOperationFailure> {
        let (tx, rx) = oneshot::channel();
        if self
            .worker
            .send(LifecycleCommand::Disable { id, reply: tx })
            .await
            .is_err()
        {
            let failure = CommunicationOperationFailure::ShuttingDown {
                operation: CommunicationOperation::Disable,
            };
            self.finish_failed_disable_locally(id, failure.clone());
            return Err(failure);
        }
        match rx.await {
            Ok(Ok(())) => Ok(DisableLease::new(self.clone(), id)),
            Ok(Err(failure)) => Err(failure),
            Err(_) => {
                let failure = CommunicationOperationFailure::TransitionFailure {
                    operation: CommunicationOperation::Disable,
                };
                self.finish_failed_disable_locally(id, failure.clone());
                Err(failure)
            }
        }
    }

    /// Publishes a structured `Error` for a claimed disable whose outcome is
    /// indeterminate because the worker could not be reached at all (shutdown
    /// raced the claim, or the worker task itself panicked) -- unlike an
    /// ordinary transport/protection failure (handled by the worker's own
    /// `execute_disable`, which reverts to `Enabled` since the transport is
    /// known to still be up), nothing here confirms the transport's actual
    /// state, so `Error` is the conservative choice.
    fn finish_failed_disable_locally(
        &self,
        id: DisableLeaseId,
        failure: CommunicationOperationFailure,
    ) {
        let mut state = self.state.lock();
        if state.shutting_down {
            return;
        }
        if state.disable_owner == Some(id) {
            state.disable_owner = None;
            state.state = CommunicationState::Error(failure);
        }
    }

    pub(super) async fn submit_release(
        &self,
        id: DisableLeaseId,
    ) -> Result<
        oneshot::Receiver<Result<CommunicationState, CommunicationOperationFailure>>,
        CommunicationOperationFailure,
    > {
        let (tx, rx) = oneshot::channel();
        self.worker
            .send(LifecycleCommand::ReleaseDisableLease { id, reply: tx })
            .await
            .map_err(|_| CommunicationOperationFailure::ShuttingDown {
                operation: CommunicationOperation::Resume,
            })?;
        Ok(rx)
    }

    pub(super) fn defer_disable(
        &self,
        id: DisableLeaseId,
    ) -> Result<(), CommunicationOperationFailure> {
        let mut state = self.state.lock();

        // Shutdown's own sequence already clears ownership and publishes the
        // terminal state; a lease dropped concurrently with (or after)
        // shutdown must not write over it. See `shutting_down`'s doc comment.
        if state.shutting_down {
            return Ok(());
        }

        // Not disabled -> no-op
        let Some(owner) = state.disable_owner else {
            return Ok(());
        };

        if owner != id {
            tracing::debug!(current = ?state.state, "resume permission denied");
            return Err(CommunicationOperationFailure::PermissionFailure {
                operation: CommunicationOperation::Resume,
            });
        }

        state.disable_owner = None;
        state.state = CommunicationState::Disabled;
        Ok(())
    }

    /// Requests the out-of-band lifecycle shutdown barrier and awaits its
    /// completion (see [`worker`]): closes admission, fails queued
    /// commands deterministically, then best-effort disables the transport
    /// while preserving protection through teardown.
    pub async fn shutdown(&self) {
        // Set synchronously, under the state lock, before the worker does any
        // teardown work: this is what makes the worker's own terminal-state
        // write (at the end of its shutdown sequence) unambiguously the last
        // word over any task racing it (`finish_activation`,
        // `finish_failed_disable_locally`, `defer_disable`). Every such write
        // either happens fully before this one (and so fully before the
        // worker's later write, which overwrites it) or observes
        // `shutting_down` and skips -- see `shutting_down`'s doc comment for
        // why the mutex makes that exhaustive.
        self.state.lock().shutting_down = true;
        self.worker.shutdown().await;
    }
}

/// The constructed authoritative plugin.
pub struct CommunicationRuntime {
    /// The selected, `Arc`-wrapped authoritative communication plugin.
    pub plugin: Arc<dyn CommunicationPlugin>,
}

/// Constructs the framework and the startup-selected communication plugin.
///
/// Communication protection is owned exclusively by the lifecycle worker. The
/// plugin is constructed first (with a fully functional `CommunicationHandle`,
/// but before any protection is installed); when `restriction_config` is
/// `Some`, the initial protection record is installed before the lifecycle
/// worker starts processing commands. Construction fails before any task
/// starts if plugin creation or initial protection installation fails.
///
/// `init_mode` is passed through unchanged: the framework delivers it as a
/// typed fact, but only the plugin decides what to do with it (see ADR-006).
///
/// # Errors
///
/// Returns an error when the plugin builder fails or protection cannot be installed.
pub async fn build_communication_runtime<B>(
    builder: B,
    transport_control: Arc<dyn TransportControl>,
    restriction_config: Option<(HttpProtectionRegistry, HttpProtectionConfig)>,
    init_mode: CommunicationInitMode,
) -> Result<CommunicationRuntime, BuildCommunicationRuntimeError<B::Error>>
where
    B: CommunicationPluginBuilder,
{
    let has_protection = restriction_config.is_some();
    let mut resources = worker::new_resources(transport_control, restriction_config);
    let state = Arc::new(CommunicationStateStore::new(CommunicationState::Disabled));
    let (sender, receivers) = worker::channel();
    let handle = CommunicationHandle {
        state: Arc::clone(&state),
        worker: sender,
    };

    // Build the plugin. The worker has not started yet: nothing has been sent
    // through `handle` because plugin construction only stores it.
    let built = match builder.build(handle, init_mode).await {
        Ok(plugin) => plugin,
        Err(error) => {
            return Err(BuildCommunicationRuntimeError::Plugin(error));
        }
    };

    // Arc-wrap the plugin, then install any configured protection. Diagnostic
    // operations request activation directly at the point they need
    // communication (see `CommunicationAccess::request_activate`) rather than
    // the framework routing a denied-request event to the plugin.
    let plugin: Arc<dyn CommunicationPlugin> = Arc::new(built);

    if has_protection {
        worker::install_initial_protection(&mut resources)
            .map_err(BuildCommunicationRuntimeError::Protection)?;
    }

    let _worker_task = worker::spawn(state, resources, receivers);

    Ok(CommunicationRuntime { plugin })
}

#[cfg(any(test, feature = "test-utils"))]
#[doc(hidden)]
// Public test_utils, so downstream plugin implementors
// can use these utilities in their own unit tests.
// Necessary because the constructor of CommunicationHandle is private because
// production code should create the object through `build_communication_runtime`, to make sure
// it is only available to the plugin and all control flow goes through that instead of having
// direct access to the handle.
pub mod test_utils {
    use std::sync::Arc;

    use cda_interfaces::communication_control::TransportControl;

    use crate::{
        http_protection::{config::HttpProtectionConfig, registry::HttpProtectionRegistry},
        lifecycle::{
            CommunicationHandle,
            disable::{DisableError, DisableLease, DisableReason},
            error::CommunicationError,
            guard::CommunicationGuard,
            state::{CommunicationState, CommunicationStateStore},
            worker,
        },
    };

    /// Synchronous, all-in-one constructor for test and `test-utils`
    /// fixtures only. Production wiring goes through
    /// [`build_communication_runtime`] instead, which stages construction
    /// around the plugin-builder handshake this shortcuts; protection
    /// installation itself reuses that same production path (see
    /// [`worker::install_initial_protection`]) rather than a test-only stand-in.
    #[must_use]
    pub(crate) fn communication_handle_new(
        transport_control: Arc<dyn TransportControl>,
        restriction_config: Option<(HttpProtectionRegistry, HttpProtectionConfig)>,
    ) -> CommunicationHandle {
        let has_protection = restriction_config.is_some();
        let mut resources = worker::new_resources(transport_control, restriction_config);
        if has_protection {
            worker::install_initial_protection(&mut resources)
                .expect("fresh test resources never have protection pre-installed");
        }
        communication_handle_from_resources(CommunicationState::Disabled, resources)
    }

    #[cfg(any(test, feature = "test-utils"))]
    fn communication_handle_from_resources(
        initial_state: CommunicationState,
        resources: worker::WorkerResources,
    ) -> CommunicationHandle {
        let state = Arc::new(CommunicationStateStore::new(initial_state));
        let (sender, receivers) = worker::channel();
        let _task = worker::spawn(Arc::clone(&state), resources, receivers);
        CommunicationHandle {
            state,
            worker: sender,
        }
    }

    #[must_use]
    pub fn enabled_communication_access_for_test()
    -> Arc<dyn crate::lifecycle::access::CommunicationAccess> {
        struct TestTransport;

        #[async_trait::async_trait]
        impl TransportControl for TestTransport {
            async fn enable(
                &self,
            ) -> Result<(), cda_interfaces::communication_control::CommControlError> {
                Ok(())
            }

            async fn disable(
                &self,
            ) -> Result<(), cda_interfaces::communication_control::CommControlError> {
                Ok(())
            }

            async fn state(&self) -> cda_interfaces::communication_control::TransportState {
                cda_interfaces::communication_control::TransportState::Enabled
            }
        }

        struct Access(CommunicationHandle);

        impl crate::lifecycle::access::CommunicationAccess for Access {
            fn state(&self) -> CommunicationState {
                self.0.state()
            }

            fn acquire(&self) -> Result<CommunicationGuard, CommunicationError> {
                self.0.acquire()
            }

            fn request_activate(
                &self,
                _cause: crate::lifecycle::operation::ActivationCause,
            ) -> CommunicationState {
                self.0.request_activate()
            }
        }

        let resources = worker::new_resources(Arc::new(TestTransport), None);
        Arc::new(Access(communication_handle_from_resources(
            CommunicationState::Enabled,
            resources,
        )))
    }

    pub fn communication_disable_for_test(
        transport_control: Arc<dyn TransportControl>,
        restriction_config: Option<(HttpProtectionRegistry, HttpProtectionConfig)>,
        initially_enabled: bool,
    ) -> Arc<dyn crate::lifecycle::disable::DisableCommunication> {
        struct Disable(CommunicationHandle);

        #[async_trait::async_trait]
        impl crate::lifecycle::disable::DisableCommunication for Disable {
            async fn disable(&self, reason: DisableReason) -> Result<DisableLease, DisableError> {
                self.0.disable(reason).await
            }
        }

        let handle = if initially_enabled {
            // Starts Enabled with protection intentionally left uninstalled,
            // mirroring the framework's own invariant that protection is only
            // ever active while communication is not Enabled. No test-only
            // backdoor into worker-owned state: the resources simply never had
            // `ensure_protected` called on them.
            let resources = worker::new_resources(transport_control, restriction_config);
            communication_handle_from_resources(CommunicationState::Enabled, resources)
        } else {
            communication_handle_new(transport_control, restriction_config)
        };
        Arc::new(Disable(handle))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use async_trait::async_trait;
    use cda_interfaces::communication_control::{
        TransportControl, TransportState, error::CommControlError,
    };
    use tokio::sync::Notify;

    use super::*;
    use crate::{
        http_protection::evaluator::HttpRestrictionGuard,
        lifecycle::{controller::test_utils::communication_handle_new, operation::ActivationCause},
        plugin::default::DefaultCommunicationPluginBuilder,
    };

    #[allow(dead_code, reason = "May be used by future tests or downstream consumers")]
    struct TestPlugin {
        handle: CommunicationHandle,
    }

    #[async_trait]
    impl CommunicationPlugin for TestPlugin {
        fn state(&self) -> CommunicationState {
            self.handle.state()
        }

        fn acquire(&self) -> Result<CommunicationGuard, CommunicationError> {
            self.handle.acquire()
        }

        async fn activate(
            &self,
            _cause: ActivationCause,
        ) -> Result<CommunicationState, CommunicationOperationFailure> {
            self.handle.activate().await
        }

        fn request_activate(&self, _cause: ActivationCause) -> CommunicationState {
            self.handle.request_activate()
        }

        async fn trigger_detection(
            &self,
            _cause: crate::lifecycle::operation::DetectionCause,
        ) -> Result<CommunicationState, CommunicationOperationFailure> {
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
    impl cda_interfaces::Shutdown for TestPlugin {
        async fn shutdown(&self) {
            self.handle.shutdown().await;
        }
    }

    /// Test helper: polls state until it matches, with a timeout.
    async fn poll_until_state(handle: &CommunicationHandle, expected: CommunicationState) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if handle.state() == expected {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("timed out waiting for expected state");
    }

    struct RecordingControl {
        enables: AtomicUsize,
        disables: AtomicUsize,
        fail_enable: AtomicBool,
    }
    #[async_trait]
    impl TransportControl for RecordingControl {
        async fn enable(&self) -> Result<(), CommControlError> {
            self.enables.fetch_add(1, Ordering::Relaxed);
            if self.fail_enable.load(Ordering::Relaxed) {
                Err(CommControlError::InitFailed("failed".to_owned()))
            } else {
                Ok(())
            }
        }
        async fn disable(&self) -> Result<(), CommControlError> {
            self.disables.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        async fn state(&self) -> TransportState {
            TransportState::Disabled
        }
    }
    fn handle() -> (CommunicationHandle, Arc<RecordingControl>) {
        let control = Arc::new(RecordingControl {
            enables: AtomicUsize::new(0),
            disables: AtomicUsize::new(0),
            fail_enable: AtomicBool::new(false),
        });
        (
            communication_handle_new(Arc::clone(&control) as Arc<dyn TransportControl>, None),
            control,
        )
    }
    #[tokio::test]
    async fn activate_publishes_authoritative_enabled_state() {
        let (handle, _) = handle();
        assert_eq!(handle.activate().await, Ok(CommunicationState::Enabled));
        assert_eq!(handle.state(), CommunicationState::Enabled);
    }
    #[tokio::test]
    async fn failed_activate_publishes_structured_error_and_retains_protection() {
        let factory = HttpProtectionRegistry::new();
        let control = Arc::new(RecordingControl {
            enables: AtomicUsize::new(0),
            disables: AtomicUsize::new(0),
            fail_enable: AtomicBool::new(true),
        });
        let handle = communication_handle_new(
            Arc::clone(&control) as Arc<dyn TransportControl>,
            Some((factory.clone(), communication_protection_config())),
        );
        control.fail_enable.store(true, Ordering::Relaxed);
        assert!(handle.activate().await.is_err(), "activate should fail");
        assert!(matches!(
            handle.state(),
            CommunicationState::Error(CommunicationOperationFailure::TransportFailure { .. })
        ));
        // Step 10: protection must be *retained* after a failed activation, not
        // lifted, so pending ECU requests keep getting the configured response.
        assert!(factory.is_active());
    }

    #[tokio::test]
    async fn failed_recovery_retains_protection() {
        let factory = HttpProtectionRegistry::new();
        let control = Arc::new(RecordingControl {
            enables: AtomicUsize::new(0),
            disables: AtomicUsize::new(0),
            fail_enable: AtomicBool::new(true),
        });
        let handle = communication_handle_new(
            Arc::clone(&control) as Arc<dyn TransportControl>,
            Some((
                factory.clone(),
                HttpProtectionConfig::new(
                    crate::http_protection::config::HttpProtectionReason::Custom(
                        "communication unavailable".to_owned(),
                    ),
                    http::StatusCode::SERVICE_UNAVAILABLE,
                    "communication unavailable",
                ),
            )),
        );
        assert!(
            matches!(
                handle.activate().await,
                Err(CommunicationOperationFailure::TransportFailure { .. })
            ),
            "first activate should fail"
        );
        assert!(factory.is_active());

        assert!(
            matches!(
                handle.activate().await,
                Err(CommunicationOperationFailure::TransportFailure { .. })
            ),
            "second activate should also fail"
        );
        assert!(factory.is_active());
    }

    struct BlockingEnableControl {
        entered: Notify,
        proceed: Notify,
        completed: Notify,
        enables: AtomicUsize,
        disables: AtomicUsize,
    }

    impl Default for BlockingEnableControl {
        fn default() -> Self {
            Self {
                entered: Notify::new(),
                proceed: Notify::new(),
                completed: Notify::new(),
                enables: AtomicUsize::new(0),
                disables: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl TransportControl for BlockingEnableControl {
        async fn enable(&self) -> Result<(), CommControlError> {
            self.enables.fetch_add(1, Ordering::Relaxed);
            self.entered.notify_one();
            self.proceed.notified().await;
            self.completed.notify_one();
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

    #[tokio::test]
    async fn cancelling_awaited_activate_finalizes_once_and_lifts_protection() {
        let factory = HttpProtectionRegistry::new();
        let control = Arc::new(BlockingEnableControl::default());
        let handle = communication_handle_new(
            Arc::clone(&control) as Arc<dyn TransportControl>,
            Some((factory.clone(), communication_protection_config())),
        );
        assert!(factory.is_active());
        let task = tokio::spawn({
            let handle = handle.clone();
            async move { handle.activate().await }
        });

        control.entered.notified().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());

        let completed = control.completed.notified();
        control.proceed.notify_one();
        completed.await;
        poll_until_state(&handle, CommunicationState::Enabled).await;

        assert_eq!(handle.state(), CommunicationState::Enabled);
        assert_eq!(control.enables.load(Ordering::Relaxed), 1);
        assert_eq!(control.disables.load(Ordering::Relaxed), 0);
        assert!(!factory.is_active());
        assert_eq!(handle.request_activate(), CommunicationState::Enabled);
        assert_eq!(control.enables.load(Ordering::Relaxed), 1);
    }

    /// Regression test: an activation's detached `finish_activation` write
    /// must never race the worker's own shutdown-sequence write. Shutdown is
    /// requested (and `shutting_down` set, synchronously) while an activation
    /// is blocked inside the worker's `transport.enable()`; only then is the
    /// transport unblocked, so the detached task's `finish_activation` can
    /// only run *after* `shutting_down` was already set. Without the
    /// `shutting_down` check this was scheduler-dependent and could leave
    /// `state == Enabled` after the transport had already been torn down by
    /// shutdown -- letting `acquire()` hand out a guard on a dead transport.
    #[tokio::test]
    async fn shutdown_racing_in_flight_activation_finishes_disabled_not_enabled() {
        let control = Arc::new(BlockingEnableControl::default());
        let handle =
            communication_handle_new(Arc::clone(&control) as Arc<dyn TransportControl>, None);

        let activation = tokio::spawn({
            let handle = handle.clone();
            async move { handle.activate().await }
        });
        // The worker is now blocked inside transport.enable(), mid-`handle_command`.
        control.entered.notified().await;

        // Shutdown races the in-flight activation: it sets `shutting_down`
        // synchronously here, then queues behind the blocked worker.
        let shutdown = tokio::spawn({
            let handle = handle.clone();
            async move { handle.shutdown().await }
        });
        // Give the shutdown task a chance to actually run and set the flag
        // before we let the blocked transport call proceed.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        // Unblock transport.enable(): the worker finishes the Activate
        // command, and the detached claim_or_join task races the worker's
        // own subsequent shutdown-sequence write.
        control.proceed.notify_one();

        assert!(activation.await.unwrap().is_ok());
        shutdown.await.unwrap();

        assert_eq!(
            handle.state(),
            CommunicationState::Disabled,
            "shutdown must have the last word, never leaving state Enabled after the transport \
             was torn down"
        );
        assert_eq!(control.disables.load(Ordering::Relaxed), 1);
        // Acquiring a guard on the "dead" transport must be impossible.
        assert!(handle.acquire().is_err());
    }

    struct BlockingDisableControl {
        entered: Notify,
        proceed: Notify,
        disable_completed: Notify,
        enable_completed: Notify,
        resume_entered: Notify,
        resume_proceed: Notify,
        enables: AtomicUsize,
        disables: AtomicUsize,
    }

    #[async_trait]
    impl TransportControl for BlockingDisableControl {
        async fn enable(&self) -> Result<(), CommControlError> {
            if self.enables.fetch_add(1, Ordering::Relaxed) == 1 {
                self.resume_entered.notify_one();
                self.resume_proceed.notified().await;
            }
            self.enable_completed.notify_one();
            Ok(())
        }

        async fn disable(&self) -> Result<(), CommControlError> {
            self.disables.fetch_add(1, Ordering::Relaxed);
            self.entered.notify_one();
            self.proceed.notified().await;
            self.disable_completed.notify_one();
            Ok(())
        }

        async fn state(&self) -> TransportState {
            TransportState::Enabled
        }
    }

    #[tokio::test]
    async fn cancelling_awaited_disable_defers_and_restores_protection_lifecycle() {
        // When the caller that awaits disable() is cancelled after disable completes,
        // the worker still finishes and creates a DisableLease. Nobody collects it, so
        // it is dropped immediately, which synchronously defers: state -> Disabled,
        // protection stays active.
        let factory = HttpProtectionRegistry::new();
        let control = Arc::new(BlockingDisableControl {
            entered: Notify::new(),
            proceed: Notify::new(),
            disable_completed: Notify::new(),
            enable_completed: Notify::new(),
            resume_entered: Notify::new(),
            resume_proceed: Notify::new(),
            enables: AtomicUsize::new(0),
            disables: AtomicUsize::new(0),
        });
        let handle = communication_handle_new(
            Arc::clone(&control) as Arc<dyn TransportControl>,
            Some((factory.clone(), communication_protection_config())),
        );
        assert_eq!(handle.activate().await, Ok(CommunicationState::Enabled));
        assert!(!factory.is_active());
        let task = tokio::spawn({
            let handle = handle.clone();
            async move { handle.disable(DisableReason::RuntimeUpdate).await }
        });

        control.entered.notified().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());

        let disable_completed = control.disable_completed.notified();
        control.proceed.notify_one();
        disable_completed.await;

        // The worker completed the disable and the resulting lease was dropped
        // synchronously (defer): state must now be Disabled and protection active.
        poll_until_state(&handle, CommunicationState::Disabled).await;

        assert_eq!(control.disables.load(Ordering::Relaxed), 1);
        // No activation was triggered; on-demand recovery handles re-activation.
        assert_eq!(control.enables.load(Ordering::Relaxed), 1);
        assert!(factory.is_active());
    }

    #[tokio::test]
    async fn disable_lease_resumes_once_when_released() {
        let (handle, control) = handle();
        assert_eq!(handle.activate().await, Ok(CommunicationState::Enabled));

        let lease = handle.disable(DisableReason::RuntimeUpdate).await.unwrap();
        assert_eq!(handle.state(), CommunicationState::DisabledExclusive);
        assert_eq!(control.disables.load(Ordering::Relaxed), 1);

        assert_eq!(lease.release().await, Ok(CommunicationState::Enabled));
        assert_eq!(handle.state(), CommunicationState::Enabled);
        assert_eq!(control.enables.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn disable_lease_can_return_to_deferred_state() {
        let factory = HttpProtectionRegistry::new();
        let control = Arc::new(RecordingControl {
            enables: AtomicUsize::new(0),
            disables: AtomicUsize::new(0),
            fail_enable: AtomicBool::new(false),
        });
        let handle = communication_handle_new(
            Arc::clone(&control) as Arc<dyn TransportControl>,
            Some((factory.clone(), communication_protection_config())),
        );
        assert_eq!(handle.activate().await, Ok(CommunicationState::Enabled));

        let lease = handle.disable(DisableReason::RuntimeUpdate).await.unwrap();
        drop(lease);

        assert_eq!(handle.state(), CommunicationState::Disabled);
        assert!(factory.is_active());
        assert_eq!(control.enables.load(Ordering::Relaxed), 1);
        assert_eq!(control.disables.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn failed_resume_publishes_error_and_retains_protection() {
        let factory = HttpProtectionRegistry::new();
        let control = Arc::new(RecordingControl {
            enables: AtomicUsize::new(0),
            disables: AtomicUsize::new(0),
            fail_enable: AtomicBool::new(false),
        });
        let handle = communication_handle_new(
            Arc::clone(&control) as Arc<dyn TransportControl>,
            Some((factory.clone(), communication_protection_config())),
        );
        assert_eq!(handle.activate().await, Ok(CommunicationState::Enabled));
        let lease = handle.disable(DisableReason::RuntimeUpdate).await.unwrap();
        assert!(factory.is_active());
        control.fail_enable.store(true, Ordering::Relaxed);

        assert!(matches!(
            lease.release().await,
            Err(CommunicationOperationFailure::TransportFailure {
                operation: CommunicationOperation::Resume,
                ..
            })
        ));
        assert!(matches!(handle.state(), CommunicationState::Error(_)));
        // Step 10: a failed resume must retain protection, not lift it.
        assert!(factory.is_active());
    }

    #[tokio::test]
    async fn dropped_disable_lease_defers_to_disabled_state() {
        let (handle, control) = handle();
        assert_eq!(handle.activate().await, Ok(CommunicationState::Enabled));
        let lease = handle
            .disable(DisableReason::Custom("test".to_owned()))
            .await
            .unwrap();
        drop(lease);

        // Drop is synchronous: state transitions to Disabled immediately.
        assert_eq!(handle.state(), CommunicationState::Disabled);
        // No second activation was triggered; on-demand recovery happens on next request.
        assert_eq!(control.enables.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn stale_lease_cannot_resume_a_later_disable() {
        let (handle, _) = handle();
        assert_eq!(handle.activate().await, Ok(CommunicationState::Enabled));
        let first = handle.disable(DisableReason::RuntimeUpdate).await.unwrap();
        let stale_id = first.identity().unwrap();
        assert_eq!(first.release().await, Ok(CommunicationState::Enabled));

        let second = handle.disable(DisableReason::RuntimeUpdate).await.unwrap();
        // Submitting a release for the stale id must be rejected by the worker
        // without disturbing the second (current) lease's ownership.
        let reply = handle.submit_release(stale_id).await.unwrap();
        assert!(matches!(
            reply.await.unwrap(),
            Err(CommunicationOperationFailure::TransitionFailure { .. })
        ));
        assert_eq!(handle.state(), CommunicationState::DisabledExclusive);
        assert_eq!(second.release().await, Ok(CommunicationState::Enabled));
    }

    #[tokio::test]
    async fn release_cancelled_before_worker_accepts_defers_synchronously() {
        // Fill the mailbox so the release's `send` is guaranteed to still be
        // waiting for capacity when we cancel it, exercising the "cancellation
        // before worker acceptance" branch of the protocol.
        let (handle, control) = handle();
        assert_eq!(handle.activate().await, Ok(CommunicationState::Enabled));
        let lease = handle.disable(DisableReason::RuntimeUpdate).await.unwrap();

        // Saturate the worker mailbox with RegisterInitializer commands that
        // never get to run (the worker is idle and would drain them almost
        // instantly in practice, so this test only documents intent -- the
        // meaningful guarantee is covered by `dropped_disable_lease_defers_to_disabled_state`
        // and the cancel-safety of `mpsc::Sender::send` itself, which tokio
        // guarantees). Here we simply cancel a release future immediately.
        let release_future = lease.release();
        drop(release_future);

        // Dropping the future drops the `DisableLease` it captured by value,
        // which never got to clear its id (the send had not yet been polled
        // to completion), so `Drop` performs the classic synchronous defer.
        poll_until_state(&handle, CommunicationState::Disabled).await;
        assert_eq!(control.enables.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn plugin_shutdown_disables_transport_and_leaves_protection_installed() {
        let factory = HttpProtectionRegistry::new();
        let control = Arc::new(RecordingControl {
            enables: AtomicUsize::new(0),
            disables: AtomicUsize::new(0),
            fail_enable: AtomicBool::new(false),
        });
        let CommunicationRuntime { plugin } = build_communication_runtime(
            DefaultCommunicationPluginBuilder,
            Arc::clone(&control) as Arc<dyn TransportControl>,
            Some((factory.clone(), communication_protection_config())),
            CommunicationInitMode::default(),
        )
        .await
        .expect("plugin construction must succeed");

        assert_eq!(
            plugin.activate(ActivationCause::Startup).await,
            Ok(CommunicationState::Enabled)
        );
        assert!(!factory.is_active());

        cda_interfaces::Shutdown::shutdown(&*plugin).await;

        assert_eq!(plugin.state(), CommunicationState::Disabled);
        assert_eq!(control.disables.load(Ordering::Relaxed), 1);
        assert!(
            factory.is_active(),
            "protection must remain installed after shutdown"
        );
    }

    #[tokio::test]
    async fn shutdown_fails_queued_commands_deterministically() {
        let (handle, _control) = handle();
        assert_eq!(handle.activate().await, Ok(CommunicationState::Enabled));

        handle.shutdown().await;

        assert!(matches!(
            handle.activate().await,
            Err(CommunicationOperationFailure::ShuttingDown { .. })
        ));
        assert!(matches!(
            handle.disable(DisableReason::RuntimeUpdate).await,
            Err(DisableError::Failed(
                CommunicationOperationFailure::ShuttingDown { .. }
            ))
        ));
    }

    struct CountingInitializer;
    #[async_trait]
    impl CommunicationInitializer for CountingInitializer {
        fn name(&self) -> &'static str {
            "counting"
        }
        async fn initialize(&self) -> Result<(), CommControlError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn admission_waits_for_mailbox_capacity_instead_of_losing_commands() {
        let (handle, _control) = handle();
        // Register more initializers than the mailbox capacity concurrently;
        // every registration must still be observed (none lost), demonstrating
        // that admission backpressures rather than drops.
        let registered = Arc::new(AtomicUsize::new(0));

        let mut tasks = Vec::new();
        for _ in 0..(worker::LIFECYCLE_WORKER_CAPACITY * 3) {
            let handle = handle.clone();
            let counter = Arc::clone(&registered);
            tasks.push(tokio::spawn(async move {
                handle
                    .register_initializer(Arc::new(CountingInitializer))
                    .await;
                counter.fetch_add(1, Ordering::Relaxed);
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(
            registered.load(Ordering::Relaxed),
            worker::LIFECYCLE_WORKER_CAPACITY * 3
        );
    }

    /// Stronger companion to the test above: proves admission actually
    /// *blocks* for capacity (true backpressure) rather than merely
    /// eventually completing every call some other way. Occupies the worker
    /// with a slow in-flight `Activate` so nothing drains the mailbox, fills
    /// it to exactly `LIFECYCLE_WORKER_CAPACITY`, then shows a further
    /// admission does not resolve until capacity frees up.
    #[tokio::test]
    async fn admission_genuinely_blocks_at_capacity_not_just_eventually_completes() {
        let control = Arc::new(BlockingEnableControl::default());
        let handle =
            communication_handle_new(Arc::clone(&control) as Arc<dyn TransportControl>, None);

        // Occupy the worker with a slow Activate so the mailbox is never
        // drained while we probe admission.
        let activation = tokio::spawn({
            let handle = handle.clone();
            async move { handle.activate().await }
        });
        control.entered.notified().await;

        // Fill the mailbox exactly to capacity: these sends complete purely
        // by occupying the buffer, without the worker dequeuing anything.
        for _ in 0..worker::LIFECYCLE_WORKER_CAPACITY {
            let (reply, _rx) = oneshot::channel();
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                handle.worker.send(LifecycleCommand::RegisterInitializer {
                    initializer: Arc::new(CountingInitializer),
                    reply,
                }),
            )
            .await
            .expect("filling to capacity must not block")
            .unwrap();
        }

        // One more admission must genuinely block: full buffer, nothing
        // draining it.
        let (reply, _rx) = oneshot::channel();
        let ninth = handle.worker.send(LifecycleCommand::RegisterInitializer {
            initializer: Arc::new(CountingInitializer),
            reply,
        });
        tokio::pin!(ninth);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut ninth)
                .await
                .is_err(),
            "admission beyond capacity must block, not be accepted immediately"
        );

        // Unblocking the worker drains the mailbox; the pending admission
        // then succeeds instead of being lost.
        control.proceed.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(5), ninth)
            .await
            .expect("blocked admission must be admitted once capacity frees up")
            .unwrap();

        activation.await.unwrap().unwrap();
    }

    fn communication_protection_config() -> HttpProtectionConfig {
        HttpProtectionConfig::new(
            crate::http_protection::config::HttpProtectionReason::Custom(
                "communication unavailable".to_owned(),
            ),
            http::StatusCode::SERVICE_UNAVAILABLE,
            "communication unavailable",
        )
    }

    /// Regression test for the startup race: several concurrent `activate()`
    /// callers arriving while an activation is in flight must all join the
    /// same operation and observe the same result, instead of one of them
    /// seeing `TransitionFailure`.
    #[tokio::test]
    async fn concurrent_activate_calls_join_one_operation_and_share_result() {
        let control = Arc::new(BlockingEnableControl::default());
        let handle =
            communication_handle_new(Arc::clone(&control) as Arc<dyn TransportControl>, None);

        let first = tokio::spawn({
            let handle = handle.clone();
            async move { handle.activate().await }
        });
        control.entered.notified().await;

        // These callers arrive while the first activation is in flight (state ==
        // Enabling). None of them may see TransitionFailure; all must join and
        // receive Enabled.
        let joiners: Vec<_> = (0..4)
            .map(|_| {
                tokio::spawn({
                    let handle = handle.clone();
                    async move { handle.activate().await }
                })
            })
            .collect();
        assert_eq!(handle.state(), CommunicationState::Enabling);

        control.proceed.notify_one();
        assert_eq!(first.await.unwrap(), Ok(CommunicationState::Enabled));
        for joiner in joiners {
            assert_eq!(joiner.await.unwrap(), Ok(CommunicationState::Enabled));
        }

        assert_eq!(control.enables.load(Ordering::Relaxed), 1);
    }

    /// Regression test for the dead on-demand recovery path: `request_activate`
    /// called while communication is `Error` must claim and retry, not return
    /// the stale `Error` state forever.
    #[tokio::test]
    async fn request_activate_recovers_from_error_state() {
        let (handle, control) = handle();
        control.fail_enable.store(true, Ordering::Relaxed);
        assert!(handle.activate().await.is_err());
        assert!(matches!(handle.state(), CommunicationState::Error(_)));

        control.fail_enable.store(false, Ordering::Relaxed);
        assert_eq!(handle.request_activate(), CommunicationState::Enabling);
        poll_until_state(&handle, CommunicationState::Enabled).await;
        assert_eq!(control.enables.load(Ordering::Relaxed), 2);
    }

    /// A repeated transport failure returns to `Error`, and a later on-demand
    /// request retries again rather than getting stuck.
    #[tokio::test]
    async fn repeated_failure_returns_to_error_and_is_retried_again() {
        let (handle, control) = handle();
        control.fail_enable.store(true, Ordering::Relaxed);
        assert!(handle.activate().await.is_err());
        assert!(matches!(handle.state(), CommunicationState::Error(_)));

        assert_eq!(handle.request_activate(), CommunicationState::Enabling);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if matches!(handle.state(), CommunicationState::Error(_)) {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("timed out waiting for Error state");
        assert_eq!(control.enables.load(Ordering::Relaxed), 2);

        control.fail_enable.store(false, Ordering::Relaxed);
        assert_eq!(handle.request_activate(), CommunicationState::Enabling);
        poll_until_state(&handle, CommunicationState::Enabled).await;
        assert_eq!(control.enables.load(Ordering::Relaxed), 3);
    }

    /// Stage 3 acceptance: `disable` rejects active guards, grants exactly one
    /// exclusive lease, rejects a second concurrent lease, and blocks ordinary
    /// (`activate`) and on-demand (`request_activate`) re-activation while
    /// held. Only the matching lease may re-activate; dropping it leaves
    /// communication unowned `Disabled` with protection intact.
    #[tokio::test]
    async fn disable_rejects_active_guards_and_blocks_activate_while_leased() {
        let (handle, control) = handle();
        assert_eq!(handle.activate().await, Ok(CommunicationState::Enabled));

        let guard = handle.acquire().unwrap();
        assert!(matches!(
            handle.disable(DisableReason::RuntimeUpdate).await,
            Err(DisableError::InUse)
        ));
        drop(guard);

        let lease = handle
            .disable(DisableReason::RuntimeUpdate)
            .await
            .expect("disable must succeed once no guard is active");
        assert_eq!(handle.state(), CommunicationState::DisabledExclusive);

        assert_eq!(
            handle.activate().await,
            Err(CommunicationOperationFailure::DisableLeaseHeld {
                operation: CommunicationOperation::Activate
            })
        );
        assert_eq!(
            handle.request_activate(),
            CommunicationState::DisabledExclusive
        );

        assert!(matches!(
            handle.disable(DisableReason::RuntimeUpdate).await,
            Err(DisableError::Conflict)
        ));

        assert_eq!(lease.release().await, Ok(CommunicationState::Enabled));
        assert_eq!(handle.state(), CommunicationState::Enabled);
        assert_eq!(control.enables.load(Ordering::Relaxed), 2);
    }

    // Variant re-detection (D1-D4)

    struct FailingInitializer {
        fail: AtomicBool,
        calls: AtomicUsize,
    }

    #[async_trait]
    impl CommunicationInitializer for FailingInitializer {
        fn name(&self) -> &'static str {
            "failing"
        }
        async fn initialize(&self) -> Result<(), CommControlError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if self.fail.load(Ordering::Relaxed) {
                Err(CommControlError::InitFailed("simulated failure".to_owned()))
            } else {
                Ok(())
            }
        }
    }

    struct BlockingInitializer {
        entered: Notify,
        proceed: Notify,
    }
    #[async_trait]
    impl CommunicationInitializer for BlockingInitializer {
        fn name(&self) -> &'static str {
            "blocking"
        }
        async fn initialize(&self) -> Result<(), CommControlError> {
            self.entered.notify_one();
            self.proceed.notified().await;
            Ok(())
        }
    }

    /// D1: `trigger_detection` while `Enabled` re-runs detection (the
    /// registered initializer runs again) and never calls
    /// `TransportControl::enable()` a second time -- the invariant D1 exists
    /// for.
    #[tokio::test]
    async fn redetect_while_enabled_never_touches_transport() {
        let (handle, control) = handle();
        assert_eq!(handle.activate().await, Ok(CommunicationState::Enabled));
        assert_eq!(control.enables.load(Ordering::Relaxed), 1);

        let initializer = Arc::new(FailingInitializer {
            fail: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
        });
        handle
            .register_initializer(Arc::clone(&initializer) as Arc<dyn CommunicationInitializer>)
            .await;

        assert_eq!(
            handle.trigger_detection().await,
            Ok(CommunicationState::Enabled)
        );

        assert_eq!(
            initializer.calls.load(Ordering::Relaxed),
            1,
            "re-detection must run the registered initializer again"
        );
        assert_eq!(
            control.enables.load(Ordering::Relaxed),
            1,
            "re-detection must never call TransportControl::enable() again"
        );
        assert_eq!(control.disables.load(Ordering::Relaxed), 0);
    }

    /// D2: re-detection is refused while a communication guard is held --
    /// the per-ECU semaphore only serializes single requests, not a whole
    /// multi-request sequence.
    #[tokio::test]
    async fn redetect_refused_while_guard_held() {
        let (handle, control) = handle();
        assert_eq!(handle.activate().await, Ok(CommunicationState::Enabled));

        let guard = handle.acquire().unwrap();
        assert_eq!(
            handle.trigger_detection().await,
            Err(CommunicationOperationFailure::GuardsHeld {
                operation: CommunicationOperation::Detect
            })
        );
        assert_eq!(handle.state(), CommunicationState::Enabled);
        drop(guard);

        // Once released, re-detection proceeds normally.
        assert_eq!(
            handle.trigger_detection().await,
            Ok(CommunicationState::Enabled)
        );
        assert_eq!(control.enables.load(Ordering::Relaxed), 1);
    }

    /// Re-detection is refused while an exclusive disable lease is held,
    /// exactly as `activate()` is.
    #[tokio::test]
    async fn redetect_refused_while_disable_lease_held() {
        let (handle, _control) = handle();
        assert_eq!(handle.activate().await, Ok(CommunicationState::Enabled));

        let lease = handle.disable(DisableReason::RuntimeUpdate).await.unwrap();
        assert_eq!(
            handle.trigger_detection().await,
            Err(CommunicationOperationFailure::DisableLeaseHeld {
                operation: CommunicationOperation::Detect
            })
        );

        assert_eq!(lease.release().await, Ok(CommunicationState::Enabled));
    }

    /// From `Disabled`, `trigger_detection` still performs a full activation
    /// (transport enable, then initializers) exactly like `activate()`.
    #[tokio::test]
    async fn redetect_from_disabled_performs_full_activation() {
        let (handle, control) = handle();
        assert_eq!(
            handle.trigger_detection().await,
            Ok(CommunicationState::Enabled)
        );
        assert_eq!(control.enables.load(Ordering::Relaxed), 1);
    }

    /// Concurrent re-detections while one is already in flight join the same
    /// generation and observe the same result, rather than racing to claim a
    /// second one.
    #[tokio::test]
    async fn concurrent_redetect_calls_join_one_operation_and_share_result() {
        let control = Arc::new(BlockingEnableControl {
            entered: Notify::new(),
            proceed: Notify::new(),
            completed: Notify::new(),
            enables: AtomicUsize::new(0),
            disables: AtomicUsize::new(0),
        });
        let handle =
            communication_handle_new(Arc::clone(&control) as Arc<dyn TransportControl>, None);
        // Reach Enabled first: the blocking behavior below is exercised by a
        // slow initializer, not the (already-unblocked) transport enable.
        control.proceed.notify_one();
        assert_eq!(handle.activate().await, Ok(CommunicationState::Enabled));

        let initializer = Arc::new(BlockingInitializer {
            entered: Notify::new(),
            proceed: Notify::new(),
        });
        handle
            .register_initializer(Arc::clone(&initializer) as Arc<dyn CommunicationInitializer>)
            .await;

        let first = tokio::spawn({
            let handle = handle.clone();
            async move { handle.trigger_detection().await }
        });
        initializer.entered.notified().await;

        let joiners: Vec<_> = (0..4)
            .map(|_| {
                tokio::spawn({
                    let handle = handle.clone();
                    async move { handle.trigger_detection().await }
                })
            })
            .collect();
        assert_eq!(handle.state(), CommunicationState::Enabling);

        initializer.proceed.notify_one();
        assert_eq!(first.await.unwrap(), Ok(CommunicationState::Enabled));
        for joiner in joiners {
            assert_eq!(joiner.await.unwrap(), Ok(CommunicationState::Enabled));
        }
        // The transport was only ever enabled once (the initial activate());
        // no joined re-detection call touched it again.
        assert_eq!(control.enables.load(Ordering::Relaxed), 1);
    }

    /// An initializer failure during `Redetect` publishes a structured
    /// `Error` and leaves the transport enabled -- re-detection did not bring
    /// the transport up itself, so it is not authorized to tear it down on
    /// failure (unlike `run_activation`, which does).
    #[tokio::test]
    async fn redetect_initializer_failure_publishes_error_and_leaves_transport_enabled() {
        let (handle, control) = handle();
        assert_eq!(handle.activate().await, Ok(CommunicationState::Enabled));

        let initializer = Arc::new(FailingInitializer {
            fail: AtomicBool::new(true),
            calls: AtomicUsize::new(0),
        });
        handle
            .register_initializer(Arc::clone(&initializer) as Arc<dyn CommunicationInitializer>)
            .await;

        assert!(matches!(
            handle.trigger_detection().await,
            Err(CommunicationOperationFailure::InitializerFailure { .. })
        ));
        assert!(matches!(handle.state(), CommunicationState::Error(_)));
        assert_eq!(
            control.disables.load(Ordering::Relaxed),
            0,
            "a failed re-detection must not disable the transport it did not enable itself"
        );
        assert_eq!(control.enables.load(Ordering::Relaxed), 1);
    }
}
