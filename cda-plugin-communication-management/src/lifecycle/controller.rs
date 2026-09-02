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

//! [`CommunicationHandle`] claims lifecycle-state transitions synchronously and
//! submits the resulting work to the `worker`, which owns the transport and the
//! initializer list.

use std::{fmt::Display, sync::Arc};

use cda_interfaces::{
    communication_control::{
        CommunicationError, CommunicationGuard, CommunicationInitMode, CommunicationLifecycle,
        CommunicationOperation, CommunicationOperationFailure, CommunicationState,
        CommunicationVariantDetection, TransportControl, VariantDetectionMode,
    },
    dlt_ctx,
};
use tokio::{
    sync::{oneshot, watch},
    task::JoinHandle,
};

use super::{
    disable::{DisableError, DisableLease, DisableLeaseId, DisableOwner, DisableReason},
    guard::ActiveGuard,
    state::{CommunicationStateStore, EnablingResultReceiver, detection_mode},
    transition::{self, LifecycleDecision, LifecycleRequest},
    worker::{self, LifecycleCommand, WorkerSender},
};
use crate::plugin::{CommunicationPlugin, CommunicationPluginBuilder};

/// Test helpers for downstream plugin implementors. [`CommunicationHandle`]'s
/// constructor is private, so production code goes through
/// `build_communication_runtime`.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

/// Result of applying a [`LifecycleDecision`].
enum ClaimOutcome {
    /// The operation already settled. Nothing to await.
    Settled(Result<CommunicationState, CommunicationOperationFailure>),
    /// An exclusive disable lease owns the state, which is either
    /// [`CommunicationState::Disabling`] or
    /// [`CommunicationState::DisabledExclusive`].
    LeaseHeld(CommunicationState),
    /// An operation was claimed or joined. Await the receiver for the result.
    ///
    /// The receiver also identifies the attempt, via
    /// [`watch::Receiver::same_channel`].
    Pending(EnablingResultReceiver),
}

/// The capability a [`CommunicationPlugin`] uses to perform lifecycle
/// operations. Passed to [`CommunicationPluginBuilder::build`]. Plugins
/// typically retain it and delegate their operations to it.
#[derive(Clone)]
pub struct CommunicationHandle {
    state: Arc<CommunicationStateStore>,
    worker: WorkerSender,
    worker_task: Arc<tokio::sync::Mutex<Option<JoinHandle<()>>>>,
}

/// Failure while constructing the authoritative communication plugin runtime.
#[derive(thiserror::Error, Debug)]
pub enum BuildCommunicationRuntimeError<E: Display> {
    /// The selected plugin builder failed.
    #[error("Communication plugin construction failed: {0}")]
    Plugin(E),
}

impl CommunicationHandle {
    /// Returns the current authoritative communication lifecycle state.
    #[must_use]
    pub fn state(&self) -> CommunicationState {
        self.state.lock().state.clone()
    }

    /// Acquires diagnostic communication while it is enabled.
    ///
    /// Holding a guard refuses a `disable()` and a new whole-vehicle detection.
    /// A detection already in flight does not refuse guards.
    ///
    /// # Errors
    ///
    /// Returns an error when communication is not enabled.
    pub fn acquire(&self) -> Result<CommunicationGuard, CommunicationError> {
        let mut state = self.state.lock();
        transition::guard_admission(&state.state)?;
        // Must be atomic with the admission check above. Otherwise a
        // `disable()` could claim `Enabled -> Disabling` in the gap.
        Ok(ActiveGuard::register(&mut state, Arc::clone(&self.state)))
    }

    /// Registers a hook that runs during subsequent lifecycle transitions.
    ///
    /// Hooks run in registration order during activation and detection, and in
    /// reverse order during deinitialization. Registering the same hook twice
    /// runs it twice.
    ///
    /// # Errors
    ///
    /// Returns an error when the lifecycle worker is shutting down or unavailable.
    pub async fn register_lifecycle_hook(
        &self,
        initializer: Arc<dyn CommunicationLifecycle>,
    ) -> Result<(), CommunicationOperationFailure> {
        self.submit_and_await(CommunicationOperation::RegisterLifecycleHook, |reply| {
            LifecycleCommand::RegisterLifecycleHook { initializer, reply }
        })
        .await
    }

    /// Installs the whole-vehicle variant detector.
    ///
    /// A single slot. Registering a second detector replaces the first. Until
    /// one is registered, no operation settles any ECU's variant and
    /// [`variant_detection`](Self::variant_detection) reports `Never`.
    ///
    /// # Errors
    ///
    /// Returns an error when the lifecycle worker is shutting down or unavailable.
    pub async fn register_variant_detection(
        &self,
        detector: Arc<dyn CommunicationVariantDetection>,
    ) -> Result<(), CommunicationOperationFailure> {
        self.submit_and_await(CommunicationOperation::RegisterVariantDetection, |reply| {
            LifecycleCommand::RegisterVariantDetection { detector, reply }
        })
        .await
    }

    fn construct_worker_failure(
        &self,
        operation: CommunicationOperation,
    ) -> CommunicationOperationFailure {
        if self.worker.is_shutting_down() {
            CommunicationOperationFailure::ShuttingDown { operation }
        } else {
            CommunicationOperationFailure::WorkerUnavailable { operation }
        }
    }

    /// Sends a worker command built from a fresh reply channel, mapping a send
    /// failure to [`worker_failure`](Self::construct_worker_failure). Returns the reply
    /// channel un-awaited, for the callers that handle the receive side
    /// themselves. See [`submit_and_await`](Self::submit_and_await) for the
    /// common case.
    async fn submit<T>(
        &self,
        operation: CommunicationOperation,
        build: impl FnOnce(
            oneshot::Sender<Result<T, CommunicationOperationFailure>>,
        ) -> LifecycleCommand,
    ) -> Result<
        oneshot::Receiver<Result<T, CommunicationOperationFailure>>,
        CommunicationOperationFailure,
    > {
        let (tx, rx) = oneshot::channel();
        self.worker
            .send(build(tx))
            .await
            .map_err(|_| self.construct_worker_failure(operation))?;
        Ok(rx)
    }

    /// As [`submit`](Self::submit), but awaits the reply, mapping a closed
    /// channel to [`worker_failure`](Self::construct_worker_failure).
    async fn submit_and_await<T>(
        &self,
        operation: CommunicationOperation,
        build: impl FnOnce(
            oneshot::Sender<Result<T, CommunicationOperationFailure>>,
        ) -> LifecycleCommand,
    ) -> Result<T, CommunicationOperationFailure> {
        self.submit(operation, build)
            .await?
            .await
            .unwrap_or_else(|_| Err(self.construct_worker_failure(operation)))
    }

    /// Activates communication, joining an already in-flight activation if one exists.
    ///
    /// Runs all three stages: transport, lifecycle hooks, then variant
    /// detection. The last is subject to the configured
    /// [`VariantDetectionMode`]. Use [`enable`](Self::enable) to bring
    /// communication up without detecting.
    ///
    /// Stages run only when this claims a transition. Called while already
    /// `Enabled`, it returns `Ok(Enabled)` and runs no detector. Use
    /// [`redetect`](Self::redetect) to detect against a live transport.
    /// Detection concludes per ECU and asynchronously, so `VariantState` is the
    /// readiness signal, not this method's return value.
    ///
    /// # Errors
    ///
    /// Returns an error when the transport, a lifecycle hook, or detection
    /// fails, an exclusive disable lease currently owns the state, or the
    /// lifecycle worker is shutting down.
    #[tracing::instrument(skip_all, fields(dlt_context = dlt_ctx!("COMM")))]
    pub async fn enable_and_detect(
        &self,
    ) -> Result<CommunicationState, CommunicationOperationFailure> {
        self.run_claimed(LifecycleRequest::EnableAndDetect).await
    }

    /// Non-awaiting counterpart to
    /// [`enable_and_detect`](Self::enable_and_detect). Claims the transition or
    /// joins an in-flight one, then returns immediately and drives the work on a
    /// detached task.
    ///
    /// A returned [`CommunicationState::Enabled`] means there was nothing to
    /// claim, so no detector ran.
    ///
    /// If the detached task panics or is aborted before any caller joins it, the
    /// state stays `Enabling(_)` until the next caller claims or joins the same
    /// operation.
    #[must_use]
    pub fn request_enable_and_detect(&self) -> CommunicationState {
        self.request_claimed(LifecycleRequest::EnableAndDetect)
    }

    /// Enables communication without running variant detection. The transport
    /// comes up and every registered lifecycle hook initializes, but nothing
    /// settles any ECU's variant.
    ///
    /// Every ECU stays `NotTested` afterwards and
    /// [`variant_detection`](Self::variant_detection) reports `Never`, so
    /// variant-dependent SOVD requests fail fast rather than wait.
    ///
    /// # Errors
    ///
    /// Returns an error when the transport or a lifecycle hook fails, an
    /// exclusive disable lease currently owns the state, or the lifecycle
    /// worker is shutting down.
    pub async fn enable(&self) -> Result<CommunicationState, CommunicationOperationFailure> {
        self.run_claimed(LifecycleRequest::Enable).await
    }

    /// Non-awaiting counterpart to [`enable`](Self::enable), mirroring
    /// [`request_enable_and_detect`](Self::request_enable_and_detect).
    #[must_use]
    pub fn request_enable(&self) -> CommunicationState {
        self.request_claimed(LifecycleRequest::Enable)
    }

    /// Runs whole-vehicle variant detection.
    ///
    /// The detection stage on its own. It touches neither the transport nor the
    /// lifecycle hooks and is valid only while `Enabled`. From any other state
    /// it fails with
    /// [`TransitionFailure`](CommunicationOperationFailure::TransitionFailure)
    /// rather than enabling communication first.
    ///
    /// Not a lifecycle transition. The runtime stays `Enabled` throughout, so
    /// single sends keep being served and only multi-request activities are
    /// held off. A failure also leaves it `Enabled` and publishes
    /// [`variant_detection`](Self::variant_detection) as `Never`.
    ///
    /// # Errors
    ///
    /// Returns an error when detection fails, communication is not `Enabled`,
    /// an exclusive disable lease currently owns the state, a multi-request
    /// activity guard is currently held (see
    /// [`CommunicationOperationFailure::GuardsHeld`]), or the lifecycle worker
    /// is shutting down.
    pub async fn redetect(&self) -> Result<CommunicationState, CommunicationOperationFailure> {
        self.run_claimed(LifecycleRequest::Detect).await
    }

    /// Returns the effective detection policy for the runtime that is currently
    /// enabled, or being enabled.
    ///
    /// `Never` means nothing is currently going to settle any ECU's
    /// `VariantState`. Consumers use it to answer immediately instead of waiting
    /// out a readiness timeout. It is not permanent, because an explicit
    /// [`redetect`](Self::redetect) runs the detector regardless of
    /// configuration.
    #[must_use]
    pub fn variant_detection(&self) -> VariantDetectionMode {
        self.state.lock().variant_detection
    }

    async fn run_claimed(
        &self,
        request: LifecycleRequest,
    ) -> Result<CommunicationState, CommunicationOperationFailure> {
        let operation = request.operation();
        let mut rx = match self.claim_or_join(request) {
            ClaimOutcome::Settled(result) => return result,
            ClaimOutcome::LeaseHeld(_) => {
                return Err(CommunicationOperationFailure::DisableLeaseHeld { operation });
            }
            ClaimOutcome::Pending(rx) => rx,
        };

        loop {
            if let Some(result) = rx.borrow_and_update().clone() {
                return result;
            }
            if rx.changed().await.is_err() {
                return Err(self.fail_closed_enabling_attempt(operation, &rx));
            }
        }
    }

    fn request_claimed(&self, request: LifecycleRequest) -> CommunicationState {
        match self.claim_or_join(request) {
            ClaimOutcome::Settled(Ok(settled)) => settled,
            ClaimOutcome::Settled(Err(failure)) => CommunicationState::Error(failure),
            ClaimOutcome::LeaseHeld(current) => current,
            ClaimOutcome::Pending(_) => self.state(),
        }
    }

    /// Applies the verdict [`transition::decide`] returns for `request`. All
    /// joined callers observe the same final result via the returned receiver.
    fn claim_or_join(&self, request: LifecycleRequest) -> ClaimOutcome {
        let operation = request.operation();
        let mut state = self.state.lock();
        match transition::decide(&state, self.worker.is_shutting_down(), request) {
            // Detection leaves transport and hooks untouched and writes its own
            // slot rather than `state.state`.
            LifecycleDecision::ClaimDetection => self.spawn_redetect(&mut state),
            LifecycleDecision::JoinDetection => Self::join_detection(&mut state),
            LifecycleDecision::Claim(shape) => self.spawn_enabling(&mut state, shape),
            LifecycleDecision::Join(in_flight) => {
                Self::join_in_flight(&mut state, in_flight, operation)
            }
            LifecycleDecision::AlreadyEnabled => {
                ClaimOutcome::Settled(Ok(CommunicationState::Enabled))
            }
            LifecycleDecision::LeaseHeld(current) => ClaimOutcome::LeaseHeld(current),
            LifecycleDecision::GuardsHeld => {
                ClaimOutcome::Settled(Err(CommunicationOperationFailure::GuardsHeld { operation }))
            }
            LifecycleDecision::ShuttingDown => {
                ClaimOutcome::Settled(Err(CommunicationOperationFailure::ShuttingDown {
                    operation,
                }))
            }
            // `NotEnabled` covers a `Detect` against a down transport. The
            // other three are lease verdicts that `decide` never returns here.
            LifecycleDecision::NotEnabled
            | LifecycleDecision::ClaimDisable { .. }
            | LifecycleDecision::SettleDisabled
            | LifecycleDecision::Conflict => {
                ClaimOutcome::Settled(Err(CommunicationOperationFailure::TransitionFailure {
                    operation,
                }))
            }
        }
    }

    fn join_in_flight(
        state: &mut std::sync::MutexGuard<'_, super::state::CommunicationStateData>,
        in_flight: CommunicationOperation,
        requested: CommunicationOperation,
    ) -> ClaimOutcome {
        match state.enabling_result.as_ref() {
            Some(rx) if rx.has_changed().is_ok() => ClaimOutcome::Pending(rx.clone()),
            Some(_) => {
                let failure = CommunicationOperationFailure::WorkerUnavailable {
                    operation: in_flight,
                };
                state.state = CommunicationState::Error(failure.clone());
                state.enabling_result = None;
                ClaimOutcome::Settled(Err(failure))
            }
            // Only shutdown clears the result slot while `Enabling`.
            None => ClaimOutcome::Settled(Err(CommunicationOperationFailure::ShuttingDown {
                operation: requested,
            })),
        }
    }

    fn spawn_enabling(
        &self,
        state: &mut std::sync::MutexGuard<'_, super::state::CommunicationStateData>,
        operation: CommunicationOperation,
    ) -> ClaimOutcome {
        let (tx, rx) = watch::channel(None);
        let detector = state
            .runs_detection_for(operation)
            .then(|| state.variant_detector())
            .flatten();

        state.state = CommunicationState::Enabling(operation);
        state.enabling_result = Some(rx.clone());
        state.variant_detection = detection_mode(detector.as_ref());

        let handle = self.clone();
        cda_interfaces::spawn_named!(
            &format!("communication-enabling-{operation:?}"),
            async move {
                let result = handle.run_enabling_operation(operation, detector).await;
                let result = handle.finish_enabling(result, operation);
                let _ = tx.send(Some(result));
            }
        );
        ClaimOutcome::Pending(rx)
    }

    /// Claims the detection slot and leaves `state.state` alone. The runtime
    /// stays `Enabled` throughout, so communication that does not depend on the
    /// variant remains available.
    fn spawn_redetect(
        &self,
        state: &mut std::sync::MutexGuard<'_, super::state::CommunicationStateData>,
    ) -> ClaimOutcome {
        let (tx, rx) = watch::channel(None);
        let detector = state.variant_detector();

        state.detection_in_flight = Some(rx.clone());
        state.variant_detection = detection_mode(detector.as_ref());

        let handle = self.clone();
        cda_interfaces::spawn_named!("communication-redetect", async move {
            let result = handle.run_redetect_operation(detector).await;
            let result = handle.finish_detection(result);
            let _ = tx.send(Some(result));
        });
        ClaimOutcome::Pending(rx)
    }

    /// Joins the detection already in flight.
    ///
    /// Separate from `join_in_flight`, which reads a different slot. This one
    /// never publishes a lifecycle state, because a dead detection task leaves
    /// the runtime `Enabled` just as a failed one does.
    fn join_detection(
        state: &mut std::sync::MutexGuard<'_, super::state::CommunicationStateData>,
    ) -> ClaimOutcome {
        if let Some(rx) = state
            .detection_in_flight
            .as_ref()
            .filter(|rx| rx.has_changed().is_ok())
            .cloned()
        {
            return ClaimOutcome::Pending(rx);
        }

        // The sender died without publishing. Clear the slot so the next caller
        // claims a fresh detection instead of joining a dead one.
        state.detection_in_flight = None;
        state.variant_detection = VariantDetectionMode::Never;
        ClaimOutcome::Settled(Err(CommunicationOperationFailure::WorkerUnavailable {
            operation: CommunicationOperation::Detect,
        }))
    }

    /// Runs the physical operation on the worker, isolating the caller from a
    /// send/reply failure (worker shutdown mid-flight).
    async fn run_enabling_operation(
        &self,
        operation: CommunicationOperation,
        detector: Option<Arc<dyn CommunicationVariantDetection>>,
    ) -> Result<CommunicationState, CommunicationOperationFailure> {
        self.submit_and_await(operation, |reply| LifecycleCommand::Activate {
            operation,
            detector,
            reply,
        })
        .await
    }

    /// Runs variant detection on the worker (detector only, no transport
    /// change), isolating the caller from a send/reply failure.
    async fn run_redetect_operation(
        &self,
        detector: Option<Arc<dyn CommunicationVariantDetection>>,
    ) -> Result<CommunicationState, CommunicationOperationFailure> {
        self.submit_and_await(CommunicationOperation::Detect, |reply| {
            LifecycleCommand::Redetect { detector, reply }
        })
        .await
    }

    /// Publishes the final state for a completed enabling operation and clears
    /// the enabling-result slot.
    ///
    /// Runs detached from the caller and can race the worker's shutdown
    /// sequence. See
    /// [`publish_enabling_result`](super::state::CommunicationStateData::publish_enabling_result).
    fn finish_enabling(
        &self,
        result: Result<CommunicationState, CommunicationOperationFailure>,
        operation: CommunicationOperation,
    ) -> Result<CommunicationState, CommunicationOperationFailure> {
        self.state.lock().publish_enabling_result(result, operation)
    }

    /// Clears the detection slot and returns the result unchanged, without
    /// changing the lifecycle state. On failure it also resets the effective
    /// detection mode.
    fn finish_detection(
        &self,
        result: Result<CommunicationState, CommunicationOperationFailure>,
    ) -> Result<CommunicationState, CommunicationOperationFailure> {
        let mut state = self.state.lock();
        // Shutdown publishes the terminal state. A detection finishing
        // alongside it must not overwrite that.
        if state.shutting_down {
            return Err(CommunicationOperationFailure::ShuttingDown {
                operation: CommunicationOperation::Detect,
            });
        }
        state.detection_in_flight = None;
        if result.is_err() {
            state.variant_detection = VariantDetectionMode::Never;
        }
        result
    }

    /// Fails the current enabling attempt with `WorkerUnavailable` when the
    /// watch channel closes before a result was published.
    ///
    /// State is changed only when the current slot belongs to the same channel,
    /// so a stale finalizer cannot overwrite a newer attempt.
    fn fail_closed_enabling_attempt(
        &self,
        operation: CommunicationOperation,
        failed: &EnablingResultReceiver,
    ) -> CommunicationOperationFailure {
        let failure = CommunicationOperationFailure::WorkerUnavailable { operation };
        let mut state = self.state.lock();
        // Detection changes nothing physical and publishes no lifecycle state,
        // not even a failed one.
        if operation == CommunicationOperation::Detect {
            if state
                .detection_in_flight
                .as_ref()
                .is_some_and(|current| current.same_channel(failed))
            {
                state.detection_in_flight = None;
                state.variant_detection = VariantDetectionMode::Never;
            }
            return failure;
        }
        if state
            .enabling_result
            .as_ref()
            .is_some_and(|current| current.same_channel(failed))
        {
            state.state = CommunicationState::Error(failure.clone());
            state.enabling_result = None;
        }
        failure
    }

    /// Acquires the sole exclusive disable lease, taking the physical transport
    /// offline if it was up.
    ///
    /// Granted from `Enabled` and from `Disabled`. The lease is exclusive
    /// ownership of the runtime, not an operation on the transport, so a
    /// consumer such as a runtime update does not have to bring the vehicle
    /// network up to become eligible.
    ///
    /// `DisableOwner::resumes_transport` records what `release()` means. A lease
    /// taken from `Enabled` resumes, one taken from `Disabled` returns to
    /// `Disabled`.
    ///
    /// `Enabling(_)`, `Disabling`, `DisabledExclusive` and `Error(_)` are
    /// conflicts. `Error(_)` has an unknown transport state, so neither resume
    /// shape can be chosen.
    ///
    /// # Errors
    ///
    /// Returns an error when communication is in use or cannot be disabled.
    #[tracing::instrument(skip_all, fields(dlt_context = dlt_ctx!("COMM")))]
    pub async fn disable(&self, reason: DisableReason) -> Result<DisableLease, DisableError> {
        let id = DisableLeaseId::new();
        {
            let mut state = self.state.lock();
            match transition::decide(
                &state,
                self.worker.is_shutting_down(),
                LifecycleRequest::Disable,
            ) {
                LifecycleDecision::ClaimDisable { resumes_transport } => {
                    // Decide under one lock whether releasing brings the
                    // transport back, and whether it detects when it does.
                    let resume_detects = state.variant_detection == VariantDetectionMode::Always;
                    state.state = CommunicationState::Disabling;
                    state.disable_owner = Some(DisableOwner {
                        id,
                        resumes_transport,
                        resume_detects,
                    });
                }
                LifecycleDecision::GuardsHeld => return Err(DisableError::InUse),
                LifecycleDecision::ShuttingDown => {
                    return Err(DisableError::Failed(
                        CommunicationOperationFailure::ShuttingDown {
                            operation: CommunicationOperation::Disable,
                        },
                    ));
                }
                // Every remaining verdict means this state cannot grant a
                // lease.
                LifecycleDecision::Conflict
                | LifecycleDecision::Claim(_)
                | LifecycleDecision::ClaimDetection
                | LifecycleDecision::Join(_)
                | LifecycleDecision::JoinDetection
                | LifecycleDecision::AlreadyEnabled
                | LifecycleDecision::SettleDisabled
                | LifecycleDecision::LeaseHeld(_)
                | LifecycleDecision::NotEnabled => {
                    tracing::debug!(
                        state = ?state.state,
                        ?reason,
                        "Disable rejected: current state does not permit an exclusive lease"
                    );
                    return Err(DisableError::Conflict);
                }
            }
        }

        match self.spawn_disable(id, reason).await {
            Ok(Ok(lease)) => Ok(lease),
            Ok(Err(failure)) => Err(DisableError::Failed(failure)),
            Err(join_error) => {
                tracing::error!(%join_error, "Communication disable task failed");
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
        reason: DisableReason,
    ) -> JoinHandle<Result<DisableLease, CommunicationOperationFailure>> {
        let handle = self.clone();
        cda_interfaces::spawn_named!("communication-disable", async move {
            handle.run_disable_operation(id, reason).await
        })
    }

    /// Runs detached from the `disable()` caller so that cancelling the caller
    /// cannot lose the resulting `DisableLease`. The lease is constructed here,
    /// so an abandoned task still finishes and the lease's `Drop` still defers
    /// back to `Disabled`.
    async fn run_disable_operation(
        &self,
        id: DisableLeaseId,
        reason: DisableReason,
    ) -> Result<DisableLease, CommunicationOperationFailure> {
        let operation = CommunicationOperation::Disable;
        // `submit` rather than `submit_and_await`, because
        // `finish_failed_disable_locally` must run only for a locally
        // synthesized failure. The worker's `execute_disable` publishes its own.
        let rx = match self
            .submit(operation, |reply| LifecycleCommand::Disable {
                id,
                reason,
                reply,
            })
            .await
        {
            Ok(rx) => rx,
            Err(failure) => {
                self.finish_failed_disable_locally(id, failure.clone());
                return Err(failure);
            }
        };
        match rx.await {
            Ok(Ok(())) => Ok(DisableLease::new(self.clone(), id)),
            Ok(Err(failure)) => Err(failure),
            Err(_) => {
                let failure = self.construct_worker_failure(operation);
                self.finish_failed_disable_locally(id, failure.clone());
                Err(failure)
            }
        }
    }

    /// Publishes `Error` for a claimed disable whose outcome is unknown because
    /// the worker could not be reached. A transport failure the worker did
    /// report is published by `finish_failed_disable` instead.
    fn finish_failed_disable_locally(
        &self,
        id: DisableLeaseId,
        failure: CommunicationOperationFailure,
    ) {
        let mut state = self.state.lock();
        if state.shutting_down {
            return;
        }
        if DisableOwner::owns(state.disable_owner, id) {
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
        self.submit(CommunicationOperation::Resume, |reply| {
            LifecycleCommand::ReleaseDisableLease { id, reply }
        })
        .await
    }

    pub(super) async fn submit_finish(
        &self,
        id: DisableLeaseId,
    ) -> Result<
        oneshot::Receiver<Result<(), CommunicationOperationFailure>>,
        CommunicationOperationFailure,
    > {
        self.submit(CommunicationOperation::FinishDisableLease, |reply| {
            LifecycleCommand::FinishDisableLease { id, reply }
        })
        .await
    }

    pub(super) fn defer_disable(
        &self,
        id: DisableLeaseId,
    ) -> Result<(), CommunicationOperationFailure> {
        let mut state = self.state.lock();

        // Shutdown already clears ownership and publishes the terminal state. A
        // lease dropped alongside it must not overwrite that.
        if state.shutting_down {
            return Ok(());
        }

        // Not disabled -> no-op
        let Some(owner) = state.disable_owner else {
            return Ok(());
        };

        if owner.id != id {
            tracing::debug!("Resume permission denied");
            return Err(CommunicationOperationFailure::PermissionFailure {
                operation: CommunicationOperation::Resume,
            });
        }

        state.disable_owner = None;
        state.state = CommunicationState::Disabled;
        Ok(())
    }

    /// Requests the out-of-band lifecycle shutdown barrier and awaits its
    /// completion (see `worker`): closes admission, fails queued
    /// commands deterministically, then best-effort disables the transport.
    #[tracing::instrument(skip_all, fields(dlt_context = dlt_ctx!("COMM")))]
    pub async fn shutdown(&self) {
        // Set under the state lock before the worker starts tearing down. Every
        // racing state write then either lands before it and is overwritten by
        // the worker's terminal write, or observes the flag and skips.
        self.state.lock().shutting_down = true;
        self.worker.shutdown().await;
        if let Some(task) = self.worker_task.lock().await.take()
            && let Err(error) = task.await
        {
            tracing::error!(%error, "Communication lifecycle worker terminated unexpectedly");
            let mut state = self.state.lock();
            // Only `Enabling` names its own operation. From every other state
            // the teardown that just failed was the disable-shaped one.
            let operation = match state.state {
                CommunicationState::Enabling(operation) => operation,
                CommunicationState::Enabled
                | CommunicationState::Disabled
                | CommunicationState::Disabling
                | CommunicationState::DisabledExclusive
                | CommunicationState::RecoveryRequired(_)
                | CommunicationState::Error(_) => CommunicationOperation::Disable,
            };
            state.disable_owner = None;
            state.enabling_result = None;
            state.detection_in_flight = None;
            state.state =
                CommunicationState::Error(CommunicationOperationFailure::WorkerUnavailable {
                    operation,
                });
        }
    }
}

/// The constructed authoritative plugin.
pub struct CommunicationRuntime {
    /// The selected, `Arc`-wrapped authoritative communication plugin.
    pub plugin: Arc<dyn CommunicationPlugin>,
}

struct WorkerBuildGuard(Option<WorkerSender>);

impl Drop for WorkerBuildGuard {
    fn drop(&mut self) {
        if let Some(worker) = self.0.take() {
            worker.request_shutdown();
        }
    }
}

/// Constructs the framework and the startup-selected communication plugin.
///
/// The lifecycle worker is started before the plugin builder receives its
/// fully functional [`CommunicationHandle`].
///
/// `init_mode` is passed through unchanged for the plugin to interpret.
/// `variant_detection` is framework policy, applied by the worker.
///
/// # Errors
///
/// Returns an error when the plugin builder fails.
pub async fn build_communication_runtime<B>(
    builder: B,
    transport_control: Arc<dyn TransportControl>,
    init_mode: CommunicationInitMode,
    variant_detection: VariantDetectionMode,
) -> Result<CommunicationRuntime, BuildCommunicationRuntimeError<B::Error>>
where
    B: CommunicationPluginBuilder,
{
    let resources = worker::new_resources(transport_control);
    let state = Arc::new(CommunicationStateStore::new(
        CommunicationState::Disabled,
        variant_detection,
    ));
    let (sender, receivers) = worker::channel();
    let worker_task = Arc::new(tokio::sync::Mutex::new(None));
    let handle = CommunicationHandle {
        state: Arc::clone(&state),
        worker: sender,
        worker_task: Arc::clone(&worker_task),
    };

    *worker_task.lock().await = Some(worker::spawn(state, resources, receivers));

    let mut build_guard = WorkerBuildGuard(Some(handle.worker.clone()));

    let built = match builder.build(handle.clone(), init_mode).await {
        Ok(plugin) => plugin,
        Err(error) => {
            handle.shutdown().await;
            build_guard.0 = None;
            return Err(BuildCommunicationRuntimeError::Plugin(error));
        }
    };
    build_guard.0 = None;

    let plugin: Arc<dyn CommunicationPlugin> = Arc::new(built);

    Ok(CommunicationRuntime { plugin })
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
    use crate::lifecycle::controller::test_utils::{
        communication_handle_new, communication_handle_with_detection_mode,
    };

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
            communication_handle_new(Arc::clone(&control) as Arc<dyn TransportControl>),
            control,
        )
    }

    #[derive(Default)]
    struct BlockingEnableControl {
        entered: Notify,
        proceed: Notify,
        completed: Notify,
        enables: AtomicUsize,
        disables: AtomicUsize,
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

    /// A detached `finish_enabling` write must not overwrite the worker's
    /// shutdown-sequence write, which would leave `state == Enabled` on a
    /// torn-down transport.
    #[tokio::test]
    async fn shutdown_racing_in_flight_activation_finishes_disabled_not_enabled() {
        let control = Arc::new(BlockingEnableControl::default());
        let handle = communication_handle_new(Arc::clone(&control) as Arc<dyn TransportControl>);

        let activation = tokio::spawn({
            let handle = handle.clone();
            async move { handle.enable_and_detect().await }
        });
        // The worker is now blocked inside transport.enable(), mid-`handle_command`.
        control.entered.notified().await;

        // Sets `shutting_down` synchronously, then queues behind the worker.
        let shutdown = tokio::spawn({
            let handle = handle.clone();
            async move { handle.shutdown().await }
        });
        // Let the shutdown task set the flag before unblocking the transport.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        // The worker finishes Activate and the detached task races the
        // shutdown-sequence write.
        control.proceed.notify_one();

        assert!(matches!(
            activation.await.unwrap(),
            Err(CommunicationOperationFailure::ShuttingDown {
                operation: CommunicationOperation::EnableAndDetect
            })
        ));
        shutdown.await.unwrap();

        assert_eq!(
            handle.state(),
            CommunicationState::Disabled,
            "shutdown must have the last word, never leaving state Enabled after the transport \
             was torn down"
        );
        assert_eq!(control.disables.load(Ordering::Relaxed), 1);
        assert!(handle.acquire().is_err());
    }

    #[derive(Default)]
    struct BlockingDisableControl {
        entered: Notify,
        proceed: Notify,
        disable_completed: Notify,
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
    async fn activation_joins_in_flight_lease_resume() {
        let control = Arc::new(BlockingDisableControl::default());
        let handle = communication_handle_new(Arc::clone(&control) as Arc<dyn TransportControl>);
        assert_eq!(
            handle.enable_and_detect().await,
            Ok(CommunicationState::Enabled)
        );

        let disable = tokio::spawn({
            let handle = handle.clone();
            async move { handle.disable(DisableReason::RuntimeUpdate).await }
        });
        control.entered.notified().await;
        control.proceed.notify_one();
        let lease = disable.await.unwrap().unwrap();

        let release = tokio::spawn(async move { lease.release().await });
        control.resume_entered.notified().await;
        assert_eq!(
            handle.state(),
            CommunicationState::Enabling(CommunicationOperation::Resume)
        );

        let activation = tokio::spawn({
            let handle = handle.clone();
            async move { handle.enable_and_detect().await }
        });
        tokio::task::yield_now().await;
        control.resume_proceed.notify_one();

        assert_eq!(release.await.unwrap(), Ok(CommunicationState::Enabled));
        assert_eq!(activation.await.unwrap(), Ok(CommunicationState::Enabled));
        assert_eq!(control.enables.load(Ordering::Relaxed), 2);
    }

    /// A lease is granted from `Disabled` too, and releasing it returns to
    /// `Disabled`. A release that activated would let a consumer holding only
    /// `DisableCommunication` start communication `init_mode` never
    /// authorized.
    #[tokio::test]
    async fn lease_from_disabled_touches_no_transport_and_releases_back_to_disabled() {
        let (handle, control) = handle();
        assert_eq!(handle.state(), CommunicationState::Disabled);

        let lease = handle
            .disable(DisableReason::RuntimeUpdate)
            .await
            .expect("a lease must be granted from a deferred runtime");
        assert_eq!(handle.state(), CommunicationState::DisabledExclusive);
        assert_eq!(
            control.disables.load(Ordering::Relaxed),
            0,
            "nothing was up, so nothing may be taken down"
        );

        // Exclusivity still holds while the lease is out.
        assert!(matches!(
            handle.disable(DisableReason::RuntimeUpdate).await,
            Err(DisableError::Conflict)
        ));
        assert_eq!(
            handle.enable_and_detect().await,
            Err(CommunicationOperationFailure::DisableLeaseHeld {
                operation: CommunicationOperation::EnableAndDetect
            })
        );

        assert_eq!(lease.release().await, Ok(CommunicationState::Disabled));
        assert_eq!(handle.state(), CommunicationState::Disabled);
        assert_eq!(
            control.enables.load(Ordering::Relaxed),
            0,
            "releasing must never enable a runtime the releaser did not find enabled"
        );
    }

    /// A lease over a runtime that was never enabled must not deinitialize its
    /// hooks. `deinitialize()` without a preceding `initialize()` breaks
    /// `CommunicationLifecycle`'s paired contract.
    #[tokio::test]
    async fn lease_from_disabled_does_not_deinitialize_uninitialized_hooks() {
        let (handle, _control) = handle();
        let hook = Arc::new(DeinitTrackingInitializer {
            fail: AtomicBool::new(false),
            init_calls: AtomicUsize::new(0),
            deinit_calls: AtomicUsize::new(0),
        });
        handle
            .register_lifecycle_hook(Arc::clone(&hook) as Arc<dyn CommunicationLifecycle>)
            .await
            .expect("registration must succeed");

        let lease = handle.disable(DisableReason::RuntimeUpdate).await.unwrap();
        assert_eq!(hook.init_calls.load(Ordering::Relaxed), 0);
        assert_eq!(
            hook.deinit_calls.load(Ordering::Relaxed),
            0,
            "a hook that never initialized must not be deinitialized"
        );

        assert_eq!(lease.release().await, Ok(CommunicationState::Disabled));
        assert_eq!(hook.init_calls.load(Ordering::Relaxed), 0);
        assert_eq!(hook.deinit_calls.load(Ordering::Relaxed), 0);
    }

    /// Dropping a lease taken from `Disabled` is the same no-op resume as
    /// releasing it.
    #[tokio::test]
    async fn dropping_a_lease_from_disabled_leaves_it_disabled() {
        let (handle, control) = handle();
        let lease = handle.disable(DisableReason::RuntimeUpdate).await.unwrap();
        drop(lease);
        assert_eq!(handle.state(), CommunicationState::Disabled);
        assert_eq!(control.enables.load(Ordering::Relaxed), 0);
        assert_eq!(control.disables.load(Ordering::Relaxed), 0);
    }

    /// `Error(_)` has an unknown transport state, so no lease is granted from
    /// it.
    #[tokio::test]
    async fn lease_refused_from_error() {
        let (handle, control) = handle();
        control.fail_enable.store(true, Ordering::Relaxed);
        assert!(handle.enable_and_detect().await.is_err());
        assert!(matches!(handle.state(), CommunicationState::Error(_)));

        assert!(matches!(
            handle.disable(DisableReason::RuntimeUpdate).await,
            Err(DisableError::Conflict)
        ));
    }

    #[tokio::test]
    async fn stale_lease_cannot_resume_a_later_disable() {
        let (handle, _) = handle();
        assert_eq!(
            handle.enable_and_detect().await,
            Ok(CommunicationState::Enabled)
        );
        let first = handle.disable(DisableReason::RuntimeUpdate).await.unwrap();
        let stale_id = first.identity().unwrap();
        assert_eq!(first.release().await, Ok(CommunicationState::Enabled));

        let second = handle.disable(DisableReason::RuntimeUpdate).await.unwrap();
        // The stale id must be rejected without disturbing the current lease.
        let reply = handle.submit_release(stale_id).await.unwrap();
        assert_eq!(
            reply.await.unwrap(),
            Err(CommunicationOperationFailure::TransitionFailure {
                operation: CommunicationOperation::Resume,
            })
        );
        assert_eq!(handle.state(), CommunicationState::DisabledExclusive);
        assert_eq!(second.release().await, Ok(CommunicationState::Enabled));
    }

    #[tokio::test]
    async fn stale_lease_finish_reports_the_exact_finish_operation() {
        let (handle, _) = handle();
        let first = handle.disable(DisableReason::RuntimeUpdate).await.unwrap();
        let stale_id = first.identity().unwrap();
        assert_eq!(first.finish().await, Ok(()));

        let second = handle.disable(DisableReason::RuntimeUpdate).await.unwrap();
        let reply = handle.submit_finish(stale_id).await.unwrap();
        assert_eq!(
            reply.await.unwrap(),
            Err(CommunicationOperationFailure::TransitionFailure {
                operation: CommunicationOperation::FinishDisableLease,
            })
        );
        assert_eq!(handle.state(), CommunicationState::DisabledExclusive);
        assert_eq!(second.finish().await, Ok(()));
    }

    /// A `release()` future abandoned before its first poll must still defer. It
    /// owns the lease and never reached the `self.id = None` that hands
    /// ownership to the worker, so dropping it runs the lease's `Drop`.
    #[tokio::test]
    async fn dropping_unpolled_release_future_defers_synchronously() {
        let (handle, control) = handle();
        assert_eq!(
            handle.enable_and_detect().await,
            Ok(CommunicationState::Enabled)
        );
        let lease = handle.disable(DisableReason::RuntimeUpdate).await.unwrap();

        let release_future = lease.release();
        drop(release_future);

        // Asserted without polling. Deferring must not need a later await.
        assert_eq!(handle.state(), CommunicationState::Disabled);
        assert_eq!(control.enables.load(Ordering::Relaxed), 1);
    }

    /// A release that reaches the worker after teardown has begun must refuse
    /// rather than bring the transport back up.
    ///
    /// The flag is set directly rather than via `shutdown()`, which would also
    /// close admission and refuse the release at the mailbox.
    #[tokio::test]
    async fn release_reaching_the_worker_after_shutdown_began_does_not_resume() {
        let (handle, control) = handle();
        assert_eq!(
            handle.enable_and_detect().await,
            Ok(CommunicationState::Enabled)
        );
        let lease = handle.disable(DisableReason::RuntimeUpdate).await.unwrap();
        assert_eq!(handle.state(), CommunicationState::DisabledExclusive);
        let enables_before = control.enables.load(Ordering::Relaxed);

        handle.state.lock().shutting_down = true;

        assert!(
            matches!(
                lease.release().await,
                Err(CommunicationOperationFailure::ShuttingDown {
                    operation: CommunicationOperation::Resume
                })
            ),
            "a release racing teardown must report shutdown, not a stale lease"
        );
        assert_eq!(
            control.enables.load(Ordering::Relaxed),
            enables_before,
            "the transport must not be re-enabled once teardown has begun"
        );
        // The refused release must not publish a state of its own.
        assert_eq!(handle.state(), CommunicationState::DisabledExclusive);
    }

    #[tokio::test]
    async fn shutdown_fails_queued_commands_deterministically() {
        let (handle, _control) = handle();
        assert_eq!(
            handle.enable_and_detect().await,
            Ok(CommunicationState::Enabled)
        );

        handle.shutdown().await;

        assert!(matches!(
            handle.enable_and_detect().await,
            Err(CommunicationOperationFailure::ShuttingDown { .. })
        ));
        assert!(matches!(
            handle.disable(DisableReason::RuntimeUpdate).await,
            Err(DisableError::Failed(
                CommunicationOperationFailure::ShuttingDown { .. }
            ))
        ));
        assert_eq!(
            handle
                .register_lifecycle_hook(Arc::new(CountingInitializer))
                .await,
            Err(CommunicationOperationFailure::ShuttingDown {
                operation: CommunicationOperation::RegisterLifecycleHook,
            })
        );
    }

    struct CountingInitializer;
    #[async_trait]
    impl CommunicationLifecycle for CountingInitializer {
        fn name(&self) -> &'static str {
            "counting"
        }
        async fn initialize(&self) -> Result<(), CommControlError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn registration_reports_unavailable_worker_after_unexpected_exit() {
        let (handle, _control) = handle();
        let task = handle
            .worker_task
            .lock()
            .await
            .take()
            .expect("test handle must own a worker task");
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());

        assert_eq!(
            handle
                .register_lifecycle_hook(Arc::new(CountingInitializer))
                .await,
            Err(CommunicationOperationFailure::WorkerUnavailable {
                operation: CommunicationOperation::RegisterLifecycleHook,
            })
        );
    }

    /// Admission backpressures instead of dropping commands. With the mailbox
    /// filled to `LIFECYCLE_WORKER_CAPACITY` and nothing draining it, a further
    /// registration blocks until capacity frees up, and is then served.
    #[tokio::test]
    async fn admission_blocks_at_capacity_instead_of_losing_commands() {
        let control = Arc::new(BlockingEnableControl::default());
        let handle = communication_handle_new(Arc::clone(&control) as Arc<dyn TransportControl>);

        // Occupy the worker with a slow Activate so nothing drains the mailbox.
        let activation = tokio::spawn({
            let handle = handle.clone();
            async move { handle.enable_and_detect().await }
        });
        control.entered.notified().await;

        // Fill the mailbox exactly to capacity. Uses the raw sender, because
        // `register_lifecycle_hook` also awaits the worker's reply, which never
        // arrives while the worker is blocked.
        for _ in 0..worker::LIFECYCLE_WORKER_CAPACITY {
            let (reply, _rx) = oneshot::channel();
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                handle.worker.send(LifecycleCommand::RegisterLifecycleHook {
                    initializer: Arc::new(CountingInitializer),
                    reply,
                }),
            )
            .await
            .expect("filling to capacity must not block")
            .unwrap();
        }

        // One more admission must block. Through the public API, because it is
        // the handle's admission path that has to backpressure.
        let over_capacity = handle.register_lifecycle_hook(Arc::new(CountingInitializer));
        tokio::pin!(over_capacity);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut over_capacity)
                .await
                .is_err(),
            "admission beyond capacity must block, not be accepted immediately"
        );

        // Unblocking the worker drains the mailbox and the pending admission is
        // served.
        control.proceed.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(5), over_capacity)
            .await
            .expect("blocked admission must be admitted once capacity frees up")
            .expect("the admitted registration must succeed");

        activation.await.unwrap().unwrap();
    }

    /// Concurrent `activate()` callers arriving while an activation is in flight
    /// must all join it and observe the same result.
    #[tokio::test]
    async fn concurrent_activate_calls_join_one_operation_and_share_result() {
        let control = Arc::new(BlockingEnableControl::default());
        let handle = communication_handle_new(Arc::clone(&control) as Arc<dyn TransportControl>);

        let first = tokio::spawn({
            let handle = handle.clone();
            async move { handle.enable_and_detect().await }
        });
        control.entered.notified().await;

        // These arrive while the first activation is in flight.
        let joiners: Vec<_> = (0..4)
            .map(|_| {
                tokio::spawn({
                    let handle = handle.clone();
                    async move { handle.enable_and_detect().await }
                })
            })
            .collect();
        assert_eq!(
            handle.state(),
            CommunicationState::Enabling(CommunicationOperation::EnableAndDetect)
        );

        control.proceed.notify_one();
        assert_eq!(first.await.unwrap(), Ok(CommunicationState::Enabled));
        for joiner in joiners {
            assert_eq!(joiner.await.unwrap(), Ok(CommunicationState::Enabled));
        }

        assert_eq!(control.enables.load(Ordering::Relaxed), 1);
    }

    /// `request_activate` called while communication is `Error` must claim and
    /// retry rather than return the stale `Error` state.
    #[tokio::test]
    async fn repeated_failure_returns_to_error_and_is_retried_again() {
        let (handle, control) = handle();
        control.fail_enable.store(true, Ordering::Relaxed);
        assert!(handle.enable_and_detect().await.is_err());
        assert!(matches!(handle.state(), CommunicationState::Error(_)));

        assert_eq!(
            handle.request_enable_and_detect(),
            CommunicationState::Enabling(CommunicationOperation::EnableAndDetect)
        );
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
        assert_eq!(
            handle.request_enable_and_detect(),
            CommunicationState::Enabling(CommunicationOperation::EnableAndDetect)
        );
        poll_until_state(&handle, CommunicationState::Enabled).await;
        assert_eq!(control.enables.load(Ordering::Relaxed), 3);
    }

    /// `disable` rejects active guards, grants exactly one exclusive lease and
    /// blocks re-activation while it is held. Only the matching lease may
    /// re-activate. Dropping it leaves communication unowned `Disabled`.
    #[tokio::test]
    async fn disable_rejects_active_guards_and_blocks_activate_while_leased() {
        let (handle, control) = handle();
        assert_eq!(
            handle.enable_and_detect().await,
            Ok(CommunicationState::Enabled)
        );

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
        assert_eq!(control.disables.load(Ordering::Relaxed), 1);

        assert_eq!(
            handle.enable_and_detect().await,
            Err(CommunicationOperationFailure::DisableLeaseHeld {
                operation: CommunicationOperation::EnableAndDetect
            })
        );
        assert_eq!(
            handle.request_enable_and_detect(),
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

    /// `finish` must never enable the transport, even though this lease was taken
    /// from an enabled runtime.
    #[tokio::test]
    async fn finish_stays_disabled_and_leaves_the_runtime_reusable() {
        let (handle, control) = handle();
        assert_eq!(
            handle.enable_and_detect().await,
            Ok(CommunicationState::Enabled)
        );
        assert_eq!(control.enables.load(Ordering::Relaxed), 1);

        let lease = handle
            .disable(DisableReason::RuntimeUpdate)
            .await
            .expect("disable must succeed once no guard is active");
        assert_eq!(handle.state(), CommunicationState::DisabledExclusive);

        assert_eq!(lease.finish().await, Ok(()));

        assert_eq!(handle.state(), CommunicationState::Disabled);
        assert_eq!(
            control.enables.load(Ordering::Relaxed),
            1,
            "finish must not re-enable the transport"
        );

        assert_eq!(
            handle.enable_and_detect().await,
            Ok(CommunicationState::Enabled)
        );
        assert_eq!(control.enables.load(Ordering::Relaxed), 2);
    }

    /// A lease taken from an already-disabled runtime also stays disabled under
    /// `finish`.
    #[tokio::test]
    async fn finish_from_already_disabled_stays_disabled() {
        let (handle, _control) = handle();

        let lease = handle
            .disable(DisableReason::RuntimeUpdate)
            .await
            .expect("disable must succeed from Disabled");
        assert_eq!(handle.state(), CommunicationState::DisabledExclusive);

        assert_eq!(lease.finish().await, Ok(()));

        assert_eq!(handle.state(), CommunicationState::Disabled);
    }

    #[derive(Default)]
    struct DeinitTrackingInitializer {
        fail: AtomicBool,
        init_calls: AtomicUsize,
        deinit_calls: AtomicUsize,
    }

    #[async_trait]
    impl CommunicationLifecycle for DeinitTrackingInitializer {
        fn name(&self) -> &'static str {
            "deinit-tracking"
        }
        async fn initialize(&self) -> Result<(), CommControlError> {
            self.init_calls.fetch_add(1, Ordering::Relaxed);
            if self.fail.load(Ordering::Relaxed) {
                Err(CommControlError::InitFailed("simulated failure".to_owned()))
            } else {
                Ok(())
            }
        }
        async fn deinitialize(&self) {
            self.deinit_calls.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Shutdown must notify registered hooks before tearing down the transport,
    /// so keep-alive work started in `initialize()` does not outlive it.
    #[tokio::test]
    async fn shutdown_deinitializes_registered_hooks() {
        let (handle, _control) = handle();
        let initializer = Arc::new(DeinitTrackingInitializer::default());
        handle
            .register_lifecycle_hook(Arc::clone(&initializer) as Arc<dyn CommunicationLifecycle>)
            .await
            .expect("registration must succeed");
        assert_eq!(
            handle.enable_and_detect().await,
            Ok(CommunicationState::Enabled)
        );
        assert_eq!(initializer.deinit_calls.load(Ordering::Relaxed), 0);

        handle.shutdown().await;

        assert_eq!(initializer.deinit_calls.load(Ordering::Relaxed), 1);
    }

    /// When a later initializer fails during activation, the ones that already
    /// succeeded must be deinitialized before the transport goes back down.
    #[tokio::test]
    async fn activation_rollback_deinitializes_succeeded_prefix() {
        let (handle, _control) = handle();
        let first = Arc::new(DeinitTrackingInitializer::default());
        let second = Arc::new(DeinitTrackingInitializer {
            fail: AtomicBool::new(true),
            ..Default::default()
        });
        handle
            .register_lifecycle_hook(Arc::clone(&first) as Arc<dyn CommunicationLifecycle>)
            .await
            .expect("registration must succeed");
        handle
            .register_lifecycle_hook(Arc::clone(&second) as Arc<dyn CommunicationLifecycle>)
            .await
            .expect("registration must succeed");

        assert!(matches!(
            handle.enable_and_detect().await,
            Err(CommunicationOperationFailure::InitializerFailure { .. })
        ));

        assert_eq!(
            first.deinit_calls.load(Ordering::Relaxed),
            1,
            "the already-succeeded initializer must be deinitialized on rollback"
        );
        assert_eq!(
            second.deinit_calls.load(Ordering::Relaxed),
            0,
            "the failing initializer was never successfully initialized, so it is not \
             deinitialized"
        );
    }

    // Variant detection

    struct FailingDetector {
        fail: AtomicBool,
        calls: AtomicUsize,
    }

    impl FailingDetector {
        fn new(fail: bool) -> Arc<Self> {
            Arc::new(Self {
                fail: AtomicBool::new(fail),
                calls: AtomicUsize::new(0),
            })
        }
    }

    #[async_trait]
    impl CommunicationVariantDetection for FailingDetector {
        fn name(&self) -> &'static str {
            "failing-detector"
        }
        async fn detect(&self) -> Result<(), CommControlError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if self.fail.load(Ordering::Relaxed) {
                Err(CommControlError::InitFailed("simulated failure".to_owned()))
            } else {
                Ok(())
            }
        }
    }

    struct BlockingDetector {
        entered: Notify,
        proceed: Notify,
    }
    #[async_trait]
    impl CommunicationVariantDetection for BlockingDetector {
        fn name(&self) -> &'static str {
            "blocking-detector"
        }
        async fn detect(&self) -> Result<(), CommControlError> {
            self.entered.notify_one();
            self.proceed.notified().await;
            Ok(())
        }
    }

    /// Registers a detector that always succeeds and reports its call count.
    async fn with_detector(handle: &CommunicationHandle) -> Arc<FailingDetector> {
        let detector = FailingDetector::new(false);
        handle
            .register_variant_detection(
                Arc::clone(&detector) as Arc<dyn CommunicationVariantDetection>
            )
            .await
            .expect("detector registration must succeed");
        detector
    }

    /// `enable()` brings the transport up and initializes the lifecycle hooks, but runs no detection.
    #[tokio::test]
    async fn enable_runs_lifecycle_hooks_but_not_detection() {
        let (handle, control) = handle();
        let hook = Arc::new(DeinitTrackingInitializer {
            fail: AtomicBool::new(false),
            init_calls: AtomicUsize::new(0),
            deinit_calls: AtomicUsize::new(0),
        });
        handle
            .register_lifecycle_hook(Arc::clone(&hook) as Arc<dyn CommunicationLifecycle>)
            .await
            .expect("registration must succeed");
        let detector = with_detector(&handle).await;

        assert_eq!(handle.enable().await, Ok(CommunicationState::Enabled));

        assert_eq!(control.enables.load(Ordering::Relaxed), 1);
        assert_eq!(
            hook.init_calls.load(Ordering::Relaxed),
            1,
            "a lifecycle hook follows the transport and must run on every enable"
        );
        assert_eq!(
            detector.calls.load(Ordering::Relaxed),
            0,
            "enable() must not run variant detection"
        );
        assert_eq!(
            handle.variant_detection(),
            VariantDetectionMode::Never,
            "an enable-only runtime must report that nothing will settle a variant"
        );
    }

    /// `activate()` runs all three stages, and reports that detection is live.
    #[tokio::test]
    async fn activate_runs_detection_after_hooks() {
        let (handle, control) = handle();
        let detector = with_detector(&handle).await;

        assert_eq!(
            handle.enable_and_detect().await,
            Ok(CommunicationState::Enabled)
        );
        assert_eq!(control.enables.load(Ordering::Relaxed), 1);
        assert_eq!(detector.calls.load(Ordering::Relaxed), 1);
        assert_eq!(handle.variant_detection(), VariantDetectionMode::Always);
    }

    /// `redetect` while `Enabled` runs the detector without calling
    /// `TransportControl::enable()` again or re-entering a lifecycle hook's
    /// `initialize()`.
    #[tokio::test]
    async fn redetect_runs_detector_without_reinitializing_hooks() {
        let (handle, control) = handle();
        let hook = Arc::new(DeinitTrackingInitializer {
            fail: AtomicBool::new(false),
            init_calls: AtomicUsize::new(0),
            deinit_calls: AtomicUsize::new(0),
        });
        handle
            .register_lifecycle_hook(Arc::clone(&hook) as Arc<dyn CommunicationLifecycle>)
            .await
            .expect("registration must succeed");
        let detector = with_detector(&handle).await;

        assert_eq!(
            handle.enable_and_detect().await,
            Ok(CommunicationState::Enabled)
        );
        assert_eq!(handle.redetect().await, Ok(CommunicationState::Enabled));

        assert_eq!(
            detector.calls.load(Ordering::Relaxed),
            2,
            "re-detection must run the detector again"
        );
        assert_eq!(
            hook.init_calls.load(Ordering::Relaxed),
            1,
            "re-detection must not re-initialize lifecycle hooks: there was no deinitialize \
             between, and the trait promises the calls come in pairs"
        );
        assert_eq!(
            control.enables.load(Ordering::Relaxed),
            1,
            "re-detection must never call TransportControl::enable() again"
        );
        assert_eq!(control.disables.load(Ordering::Relaxed), 0);
    }

    /// Detection is refused while an activity guard is held. That guard is the
    /// only lock spanning a whole multi-request sequence.
    #[tokio::test]
    async fn redetect_refused_while_activity_guard_held() {
        let (handle, control) = handle();
        assert_eq!(
            handle.enable_and_detect().await,
            Ok(CommunicationState::Enabled)
        );

        let guard = handle.acquire().unwrap();
        assert_eq!(
            handle.redetect().await,
            Err(CommunicationOperationFailure::GuardsHeld {
                operation: CommunicationOperation::Detect
            })
        );
        assert_eq!(handle.state(), CommunicationState::Enabled);
        drop(guard);

        // Once released, detection proceeds.
        assert_eq!(handle.redetect().await, Ok(CommunicationState::Enabled));
        assert_eq!(control.enables.load(Ordering::Relaxed), 1);
    }

    /// `redetect` is the detection stage alone, so from `Disabled` and `Error`
    /// it refuses rather than widening itself into an activation.
    #[tokio::test]
    async fn detect_rejected_when_not_enabled() {
        let (handle, control) = handle();
        let detector = with_detector(&handle).await;

        assert_eq!(
            handle.redetect().await,
            Err(CommunicationOperationFailure::TransitionFailure {
                operation: CommunicationOperation::Detect
            })
        );
        assert_eq!(
            control.enables.load(Ordering::Relaxed),
            0,
            "a refused detection must not touch the transport"
        );
        assert_eq!(detector.calls.load(Ordering::Relaxed), 0);
        assert_eq!(handle.state(), CommunicationState::Disabled);

        // Same refusal from `Error`.
        control.fail_enable.store(true, Ordering::Relaxed);
        assert!(handle.enable_and_detect().await.is_err());
        assert!(matches!(handle.state(), CommunicationState::Error(_)));
        assert_eq!(
            handle.redetect().await,
            Err(CommunicationOperationFailure::TransitionFailure {
                operation: CommunicationOperation::Detect
            })
        );
    }

    /// Concurrent detections join the in-flight attempt and observe the same
    /// result rather than claiming a second one.
    #[tokio::test]
    async fn concurrent_redetect_calls_join_one_operation_and_share_result() {
        let control = Arc::new(BlockingEnableControl {
            entered: Notify::new(),
            proceed: Notify::new(),
            completed: Notify::new(),
            enables: AtomicUsize::new(0),
            disables: AtomicUsize::new(0),
        });
        let handle = communication_handle_new(Arc::clone(&control) as Arc<dyn TransportControl>);
        // Reach Enabled first, so the blocking below comes from the slow
        // detector rather than the transport enable.
        control.proceed.notify_one();
        assert_eq!(
            handle.enable_and_detect().await,
            Ok(CommunicationState::Enabled)
        );

        let detector = Arc::new(BlockingDetector {
            entered: Notify::new(),
            proceed: Notify::new(),
        });
        handle
            .register_variant_detection(
                Arc::clone(&detector) as Arc<dyn CommunicationVariantDetection>
            )
            .await
            .expect("registration must succeed");

        let first = tokio::spawn({
            let handle = handle.clone();
            async move { handle.redetect().await }
        });
        detector.entered.notified().await;

        let joiners: Vec<_> = (0..4)
            .map(|_| {
                tokio::spawn({
                    let handle = handle.clone();
                    async move { handle.redetect().await }
                })
            })
            .collect();
        // The runtime stays `Enabled` throughout variant detection, so guards
        // keep being granted. Moving to `Enabling` would fail this acquisition.
        assert_eq!(handle.state(), CommunicationState::Enabled);
        let guard = handle
            .acquire()
            .expect("diagnostics must keep being served during a sweep");
        drop(guard);

        detector.proceed.notify_one();
        assert_eq!(first.await.unwrap(), Ok(CommunicationState::Enabled));
        for joiner in joiners {
            assert_eq!(joiner.await.unwrap(), Ok(CommunicationState::Enabled));
        }
        assert_eq!(control.enables.load(Ordering::Relaxed), 1);
    }

    /// A detector failure during a `Detect` leaves the transport enabled. The
    /// operation did not bring it up, so it does not tear it down.
    #[tokio::test]
    async fn redetect_detection_failure_leaves_runtime_enabled_and_transport_up() {
        let (handle, control) = handle();
        assert_eq!(
            handle.enable_and_detect().await,
            Ok(CommunicationState::Enabled)
        );

        let detector = FailingDetector::new(true);
        handle
            .register_variant_detection(
                Arc::clone(&detector) as Arc<dyn CommunicationVariantDetection>
            )
            .await
            .expect("registration must succeed");

        assert!(matches!(
            handle.redetect().await,
            Err(CommunicationOperationFailure::DetectionFailure { .. })
        ));
        assert_eq!(
            handle.state(),
            CommunicationState::Enabled,
            "a failed re-detection changed nothing physical, so the runtime is still enabled - \
             publishing `Error` here would claim a transport that is up is down"
        );
        assert_eq!(
            handle.variant_detection(),
            VariantDetectionMode::Never,
            "nothing is going to settle a variant now, and the readiness gate has to be able to \
             say so instead of advertising a sweep that is never coming"
        );
        assert_eq!(
            control.disables.load(Ordering::Relaxed),
            0,
            "a failed re-detection must not disable the transport it did not enable itself"
        );
        assert_eq!(control.enables.load(Ordering::Relaxed), 1);

        assert!(handle.acquire().is_ok());
        assert!(handle.acquire().is_ok());
    }

    /// A failed detection must not publish `Error(_)`. `Error` means the
    /// transport is down, so `decide` would admit a recovery activation and
    /// `run_activation` would re-run `initialize()` on hooks that are still
    /// initialized. Staying `Enabled` makes the readiness gate's
    /// `request_activate` settle as `AlreadyEnabled` instead.
    #[tokio::test]
    async fn failed_redetect_does_not_let_recovery_reinitialize_live_hooks() {
        let (handle, control) = handle();
        let hook = Arc::new(DeinitTrackingInitializer {
            fail: AtomicBool::new(false),
            init_calls: AtomicUsize::new(0),
            deinit_calls: AtomicUsize::new(0),
        });
        handle
            .register_lifecycle_hook(Arc::clone(&hook) as Arc<dyn CommunicationLifecycle>)
            .await
            .expect("registration must succeed");
        assert_eq!(
            handle.enable_and_detect().await,
            Ok(CommunicationState::Enabled)
        );
        assert_eq!(hook.init_calls.load(Ordering::Relaxed), 1);

        let detector = FailingDetector::new(true);
        handle
            .register_variant_detection(
                Arc::clone(&detector) as Arc<dyn CommunicationVariantDetection>
            )
            .await
            .expect("registration must succeed");
        assert!(handle.redetect().await.is_err());

        // What the readiness gate does on the next ECU request.
        assert_eq!(
            handle.request_enable_and_detect(),
            CommunicationState::Enabled
        );
        assert_eq!(
            handle.enable_and_detect().await,
            Ok(CommunicationState::Enabled)
        );

        assert_eq!(
            hook.init_calls.load(Ordering::Relaxed),
            1,
            "initialize() must not run a second time without a deinitialize() between - the trait \
             documents implementations as not having to be re-entrant"
        );
        assert_eq!(hook.deinit_calls.load(Ordering::Relaxed), 0);
        assert_eq!(
            control.enables.load(Ordering::Relaxed),
            1,
            "nothing was claimed, so no stage ran at all"
        );
    }

    /// A lease must not be granted while variant detection runs. The state stays
    /// `Enabled` throughout, so `decide` checks the detection slot explicitly.
    #[tokio::test]
    async fn disable_is_refused_while_a_redetection_is_in_flight() {
        // Only the detector needs to block. The lease resume at the end has to
        // be able to enable again without deadlocking.
        let (handle, control) = handle();
        assert_eq!(
            handle.enable_and_detect().await,
            Ok(CommunicationState::Enabled)
        );

        let detector = Arc::new(BlockingDetector {
            entered: Notify::new(),
            proceed: Notify::new(),
        });
        handle
            .register_variant_detection(
                Arc::clone(&detector) as Arc<dyn CommunicationVariantDetection>
            )
            .await
            .expect("registration must succeed");

        let sweep = tokio::spawn({
            let handle = handle.clone();
            async move { handle.redetect().await }
        });
        detector.entered.notified().await;

        assert!(
            matches!(
                handle.disable(DisableReason::RuntimeUpdate).await,
                Err(DisableError::InUse)
            ),
            "detection is a use of communication, so a lease must wait for it"
        );
        assert_eq!(
            control.disables.load(Ordering::Relaxed),
            0,
            "the transport must not be taken down underneath a running sweep"
        );

        detector.proceed.notify_one();
        assert_eq!(sweep.await.unwrap(), Ok(CommunicationState::Enabled));

        // Dropped rather than released. A resume would repeat the detecting
        // shape and re-enter the blocking detector with nobody left to unblock
        // it.
        let lease = handle
            .disable(DisableReason::RuntimeUpdate)
            .await
            .expect("the lease must be grantable once detection settles");
        drop(lease);
        assert_eq!(handle.state(), CommunicationState::Disabled);
    }

    /// A detector failure during a full activation unwinds all hooks and takes
    /// the transport back down, since this operation brought it up.
    #[tokio::test]
    async fn detector_failure_deinitializes_hooks_and_downs_transport() {
        let (handle, control) = handle();
        let hook = Arc::new(DeinitTrackingInitializer {
            fail: AtomicBool::new(false),
            init_calls: AtomicUsize::new(0),
            deinit_calls: AtomicUsize::new(0),
        });
        handle
            .register_lifecycle_hook(Arc::clone(&hook) as Arc<dyn CommunicationLifecycle>)
            .await
            .expect("registration must succeed");
        let detector = FailingDetector::new(true);
        handle
            .register_variant_detection(
                Arc::clone(&detector) as Arc<dyn CommunicationVariantDetection>
            )
            .await
            .expect("registration must succeed");

        assert!(matches!(
            handle.enable_and_detect().await,
            Err(CommunicationOperationFailure::DetectionFailure { .. })
        ));
        assert_eq!(hook.init_calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            hook.deinit_calls.load(Ordering::Relaxed),
            1,
            "every successfully initialized hook must be unwound when detection fails"
        );
        assert_eq!(control.disables.load(Ordering::Relaxed), 1);
    }

    /// Releasing a disable lease repeats the shape of the enable it resumes, so
    /// an enable-only runtime does not become a detecting one.
    #[tokio::test]
    async fn enable_only_runtime_resumes_without_detection() {
        let (handle, control) = handle();
        let hook = Arc::new(DeinitTrackingInitializer {
            fail: AtomicBool::new(false),
            init_calls: AtomicUsize::new(0),
            deinit_calls: AtomicUsize::new(0),
        });
        handle
            .register_lifecycle_hook(Arc::clone(&hook) as Arc<dyn CommunicationLifecycle>)
            .await
            .expect("registration must succeed");
        let detector = with_detector(&handle).await;

        assert_eq!(handle.enable().await, Ok(CommunicationState::Enabled));
        let lease = handle.disable(DisableReason::RuntimeUpdate).await.unwrap();
        assert_eq!(lease.release().await, Ok(CommunicationState::Enabled));

        assert_eq!(
            detector.calls.load(Ordering::Relaxed),
            0,
            "resuming an enable-only runtime must not start detecting behind the plugin's back"
        );
        assert_eq!(
            hook.init_calls.load(Ordering::Relaxed),
            2,
            "hooks follow the transport, so a resume re-initializes them"
        );
        assert_eq!(control.enables.load(Ordering::Relaxed), 2);
        assert_eq!(handle.variant_detection(), VariantDetectionMode::Never);
    }

    /// A lease restores the runtime it displaced, not the one that was first
    /// brought up.
    ///
    /// The resume shape is captured from the effective detection mode when the
    /// lease is granted. A lease taken after an explicit `redetect()` therefore
    /// resumes detecting rather than repeating the original `enable()`.
    #[tokio::test]
    async fn lease_granted_after_redetect_resumes_detecting() {
        let (handle, _control) = handle();
        let detector = with_detector(&handle).await;

        assert_eq!(handle.enable().await, Ok(CommunicationState::Enabled));
        assert_eq!(handle.variant_detection(), VariantDetectionMode::Never);

        assert_eq!(handle.redetect().await, Ok(CommunicationState::Enabled));
        assert_eq!(detector.calls.load(Ordering::Relaxed), 1);
        assert_eq!(handle.variant_detection(), VariantDetectionMode::Always);

        let lease = handle.disable(DisableReason::RuntimeUpdate).await.unwrap();
        assert_eq!(lease.release().await, Ok(CommunicationState::Enabled));

        assert_eq!(
            detector.calls.load(Ordering::Relaxed),
            2,
            "the lease displaced a detecting runtime, so releasing it detects again"
        );
        assert_eq!(handle.variant_detection(), VariantDetectionMode::Always);
    }

    /// Every stage runs only when the operation claims a transition. From
    /// `Enabled` there is nothing to claim, so `enable_and_detect()` runs no
    /// detector. Detection against a live transport is `redetect()`.
    #[tokio::test]
    async fn enable_and_detect_does_not_detect_an_already_enabled_runtime() {
        let (handle, _control) = handle();
        let detector = with_detector(&handle).await;

        assert_eq!(handle.enable().await, Ok(CommunicationState::Enabled));
        assert_eq!(detector.calls.load(Ordering::Relaxed), 0);
        assert_eq!(handle.variant_detection(), VariantDetectionMode::Never);

        assert_eq!(
            handle.enable_and_detect().await,
            Ok(CommunicationState::Enabled)
        );
        assert_eq!(
            detector.calls.load(Ordering::Relaxed),
            0,
            "an already-enabled runtime claims nothing, so nothing detects"
        );
        assert_eq!(
            handle.variant_detection(),
            VariantDetectionMode::Never,
            "and the reported policy still says nothing will settle a variant"
        );

        assert_eq!(handle.redetect().await, Ok(CommunicationState::Enabled));
        assert_eq!(detector.calls.load(Ordering::Relaxed), 1);
        assert_eq!(handle.variant_detection(), VariantDetectionMode::Always);
    }

    /// `VariantDetectionMode::Never` gates the detector stage of an activation
    /// only, never the transport, the lifecycle hooks or an explicit
    /// `redetect()`.
    #[tokio::test]
    async fn variant_detection_never_config_skips_detector_not_hooks() {
        let control = Arc::new(RecordingControl {
            enables: AtomicUsize::new(0),
            disables: AtomicUsize::new(0),
            fail_enable: AtomicBool::new(false),
        });
        let handle = communication_handle_with_detection_mode(
            Arc::clone(&control) as Arc<dyn TransportControl>,
            VariantDetectionMode::Never,
        );
        let hook = Arc::new(DeinitTrackingInitializer {
            fail: AtomicBool::new(false),
            init_calls: AtomicUsize::new(0),
            deinit_calls: AtomicUsize::new(0),
        });
        handle
            .register_lifecycle_hook(Arc::clone(&hook) as Arc<dyn CommunicationLifecycle>)
            .await
            .expect("registration must succeed");
        let detector = with_detector(&handle).await;

        assert_eq!(
            handle.enable_and_detect().await,
            Ok(CommunicationState::Enabled)
        );
        assert_eq!(control.enables.load(Ordering::Relaxed), 1);
        assert_eq!(
            hook.init_calls.load(Ordering::Relaxed),
            1,
            "the configured detection policy must not gate lifecycle hooks"
        );
        assert_eq!(
            detector.calls.load(Ordering::Relaxed),
            0,
            "activation must not detect automatically in Never mode"
        );
        assert_eq!(handle.variant_detection(), VariantDetectionMode::Never);

        assert_eq!(handle.redetect().await, Ok(CommunicationState::Enabled));
        assert_eq!(
            detector.calls.load(Ordering::Relaxed),
            1,
            "an explicit detection must run even where automatic detection is configured off"
        );
        assert_eq!(handle.variant_detection(), VariantDetectionMode::Always);
    }

    /// With no detector registered nothing settles a variant, whatever the
    /// configuration says, and the runtime reports `Never`.
    #[tokio::test]
    async fn variant_detection_reports_never_without_a_registered_detector() {
        let (handle, _control) = handle();
        assert_eq!(
            handle.enable_and_detect().await,
            Ok(CommunicationState::Enabled)
        );
        assert_eq!(handle.variant_detection(), VariantDetectionMode::Never);
    }
}
