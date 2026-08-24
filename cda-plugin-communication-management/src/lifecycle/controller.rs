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

//! [`CommunicationHandle`] claims lifecycle-state transitions synchronously
//! (guard acquisition and lease drop stay lock-free) and submits
//! the resulting work to the `worker` that
//! exclusively owns the physical transport and initializer list.
//! See `worker` for why the split exists.

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

/// Result of *applying* a [`LifecycleDecision`] - not a decision of its own.
///
/// [`transition::decide`] has already ruled on the transition by the time one
/// of these exists; this only says whether the caller has work to await.
enum ClaimOutcome {
    ///`Ok` with the state it settled at, `Err` with the
    /// failure to report.
    Settled(Result<CommunicationState, CommunicationOperationFailure>),
    /// An exclusive disable lease owns the state; the current state is reported, which can
    /// either be [`CommunicationState::Disabling`] or [`CommunicationState::DisabledExclusive`].
    /// Non-exclusive disable is not part of this, because it allows re-activation and no lease
    /// is owned. Reported separately because the awaiting and non-awaiting
    /// callers render it differently.
    LeaseHeld(CommunicationState),
    /// An operation was claimed (or joined); await the receiver for the result.
    ///
    /// The receiver also identifies the attempt via
    /// [`watch::Receiver::same_channel`]. The caller passes it
    /// to [`fail_closed_enabling_attempt`](CommunicationHandle::fail_closed_enabling_attempt)
    /// if the channel closes before a result is published, so that a stale
    /// finalizer cannot clobber a newer attempt.
    Pending(EnablingResultReceiver),
}

/// The capability a [`CommunicationPlugin`] implementation uses to actually
/// perform lifecycle operations. Passed to the builder in
/// [`CommunicationPluginBuilder::build`]; the resulting plugin typically
/// retains it (e.g. [`crate::plugin::default::DefaultCommunicationPlugin`] stores
/// it as `DefaultCommunicationPlugin::handle`)
/// and delegates every operation it exposes to it.
///
/// Claims lifecycle-state transitions synchronously and submits the resulting
/// physical work to the lifecycle `worker`.
///
/// It is public, so OEM implementers of communication plugins are able to use it.
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
    /// Holding a guard refuses a `disable()` - a lease must not take the
    /// transport down mid-operation - and refuses a *new* whole-vehicle
    /// re-detection, which must not land in the middle of a multi-request
    /// sequence. The converse does not hold: a sweep already in flight leaves
    /// the runtime `Enabled`, so guards keep being granted throughout one.
    ///
    /// # Errors
    ///
    /// Returns an error when communication is not enabled.
    pub fn acquire(&self) -> Result<CommunicationGuard, CommunicationError> {
        let mut state = self.state.lock();
        transition::guard_admission(&state.state)?;
        // Registration stays inside this critical section deliberately: it has
        // to be atomic with the admission check above, or a `disable()` could
        // claim `Enabled -> Disabling` in the gap and take the transport down
        // under a guard that is about to exist.
        Ok(ActiveGuard::register(&mut state, Arc::clone(&self.state)))
    }

    /// Registers a hook that runs during subsequent lifecycle transitions.
    ///
    /// Multiple hooks may be registered. They run sequentially in registration
    /// order during activation and detection, and in reverse registration order
    /// during deinitialization. Registering the same hook more than once does
    /// not deduplicate it.
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
    /// A single slot, not a list: detection is whole-vehicle by definition, so
    /// registering a second detector replaces the first rather than adding a
    /// second sweep. Until one is registered, no operation can settle any ECU's
    /// variant and [`variant_detection`](Self::variant_detection) reports
    /// `Never`.
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

    fn worker_failure(&self, operation: CommunicationOperation) -> CommunicationOperationFailure {
        if self.worker.is_shutting_down() {
            CommunicationOperationFailure::ShuttingDown { operation }
        } else {
            CommunicationOperationFailure::WorkerUnavailable { operation }
        }
    }

    /// Sends a worker command built from a fresh reply channel, mapping a
    /// send failure (mailbox closed - worker shutting down or gone) to
    /// [`worker_failure`](Self::worker_failure). Returns the reply channel
    /// un-awaited: most callers immediately await it via
    /// [`submit_and_await`](Self::submit_and_await), but a few need to handle
    /// the receive side themselves - [`run_disable_operation`](Self::run_disable_operation)
    /// to run extra local bookkeeping only on a locally-synthesized failure,
    /// and [`submit_release`](Self::submit_release) to hand the receiver on to
    /// its own caller instead of awaiting it here.
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
            .map_err(|_| self.worker_failure(operation))?;
        Ok(rx)
    }

    /// As [`submit`](Self::submit), but also awaits the reply, collapsing a
    /// closed channel (worker task panicked or was torn down mid-flight)
    /// into the same [`worker_failure`](Self::worker_failure) used for a send
    /// failure.
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
            .unwrap_or_else(|_| Err(self.worker_failure(operation)))
    }

    /// Activates communication, joining an already in-flight activation if one exists.
    ///
    /// Runs all three stages: transport, lifecycle hooks, then variant
    /// detection (the last subject to the configured
    /// [`VariantDetectionMode`]). Use [`enable`](Self::enable) instead to bring
    /// communication up without detecting.
    ///
    /// # Detection runs only when this claims a transition
    ///
    /// Called while already `Enabled`, this returns `Ok(Enabled)` immediately
    /// and **runs no detector**. That includes the case where the runtime was
    /// brought up by [`enable`](Self::enable) and no ECU variant has ever been
    /// settled: this call reports success and changes nothing.
    ///
    /// It is therefore not an "ensure detected" request. Use
    /// [`variant_detection`](Self::variant_detection) to tell whether anything
    /// is going to settle a variant, and [`redetect`](Self::redetect) to run the
    /// detector against the already-live transport. Detection concludes per ECU
    /// and asynchronously in any case, so `VariantState` - not this method's
    /// return - is the readiness signal.
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

    /// Non-awaiting activation submission: claims the transition (or joins an
    /// in-flight one) and returns immediately, driving the actual work on a
    /// handle-owned task. Safe to call from a context that must not block.
    ///
    /// A returned [`CommunicationState::Enabled`] means there was nothing to
    /// claim, so no detector ran; see
    /// [`enable_and_detect`](Self::enable_and_detect) for why, and what to call
    /// when detection is what you actually need.
    ///
    /// # Finalization is lazy if nobody joins
    ///
    /// The claimed work runs on a detached task. If that task panics or is
    /// aborted before any caller joins it, the published state is left at
    /// `Enabling(_)` indefinitely - it is only finalized (turned into
    /// `Error`) the next time some caller claims or joins the same operation
    /// and `join_in_flight` observes the dead result
    /// channel. Until then, `state()` and health consumers see a runtime that
    /// looks permanently "Enabling". This is a deliberate trade-off (no
    /// caller here to propagate a failure to, since the call is
    /// non-awaiting), not an oversight - accepted rather than adding a
    /// watchdog task purely to eagerly detect a panic nobody is waiting on.
    #[must_use]
    pub fn request_enable_and_detect(&self) -> CommunicationState {
        self.request_claimed(LifecycleRequest::EnableAndDetect)
    }

    /// Enables communication **without** running variant detection: the
    /// transport comes up and every registered lifecycle hook initializes, but
    /// nothing settles any ECU's variant.
    ///
    /// This exists for plugins that own the detection decision themselves. The
    /// framework has no `init_mode` opinion about it (or about any other
    /// operation): a replacement for the default plugin may call this in any
    /// mode, including `Disabled`.
    ///
    /// Every ECU stays `NotTested` afterwards, so variant-dependent SOVD
    /// surfaces report not-ready until something detects. That is deliberate --
    /// serving base-variant data instead would be wrong - and the readiness
    /// gate fails those requests fast rather than waiting, because
    /// [`variant_detection`](Self::variant_detection) reports `Never` for a
    /// runtime brought up this way.
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

    /// Re-runs whole-vehicle variant detection against the already-live
    /// transport.
    ///
    /// Strictly the detection stage: it touches neither the transport nor the
    /// lifecycle hooks, and is therefore valid **only** while `Enabled`. From
    /// any other state - including `Enabling(_)`, where the transport is still
    /// coming up - it fails with
    /// [`TransitionFailure`](CommunicationOperationFailure::TransitionFailure)
    /// rather than quietly enabling communication first. Whether to compose
    /// that fallback is a plugin's decision, not the framework's;
    /// [`DefaultCommunicationPlugin`](crate::plugin::default::DefaultCommunicationPlugin)
    /// decides *not* to, and passes this through unchanged.
    ///
    /// **Not a lifecycle transition.** The runtime stays `Enabled` for the whole
    /// sweep, so communication remains available and single sends keep being
    /// served throughout; only multi-request activities are held off. A failure
    /// leaves the runtime `Enabled` too - nothing physical changed, so there is
    /// nothing to report as broken beyond the returned error - and publishes
    /// [`variant_detection`](Self::variant_detection) as `Never`, since nothing
    /// is now going to settle a variant.
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

    /// Returns the *effective* detection policy for the communication runtime
    /// that is currently enabled, or currently being enabled.
    ///
    /// `Never` means nothing is *currently* going to settle any ECU's
    /// `VariantState`: automatic detection is configured off, no detector was
    /// registered, or the enable in question was an [`enable`](Self::enable).
    /// Consumers use this to tell "detection is still settling" apart from
    /// "nothing is settling this" and answer immediately in the latter case
    /// instead of waiting out a readiness timeout on every request.
    ///
    /// Not a permanent verdict: an explicit [`redetect`](Self::redetect) runs
    /// the detector regardless of configuration, and reports `Always` while it
    /// does, so a runtime reporting `Never` can still become ready.
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

    /// Applies the verdict [`transition::decide`] returns for `operation`:
    /// claims a new activation-shaped operation, joins an already-claimed one,
    /// or reports the refusal.
    ///
    /// The transition matrix is deliberately *not* restated here.
    /// [`transition::decide`] is the single authority on what each state
    /// admits, so which cell applies is answered by reading that one function
    /// rather than by reconstructing this call stack. This method only turns an
    /// admitted verdict into the corresponding state write.
    ///
    /// All joined callers observe the same final result via the returned receiver.
    fn claim_or_join(&self, request: LifecycleRequest) -> ClaimOutcome {
        let operation = request.operation();
        let mut state = self.state.lock();
        match transition::decide(&state, self.worker.is_shutting_down(), request) {
            // Detection leaves the transport and the lifecycle hooks untouched,
            // so it runs its own sequence and writes its own slot - never
            // `state.state`.
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
            // `NotEnabled` for a `Detect` against a down transport. The other
            // three are lease verdicts: `decide` produces them only for
            // `Disable` and `Resume`, neither of which is submitted here. They
            // refuse rather than panic, so a future routing mistake fails
            // closed.
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
            // `Enabling` without a result slot only happens once shutdown has
            // cleared it; nothing is left to join.
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

    /// Claims the detection slot, deliberately leaving `state.state` alone.
    ///
    /// This is the whole point of the split: the runtime is `Enabled` before
    /// this call, during the sweep, and after it, because a re-detection
    /// changes nothing physical. This also ensures diagnostic communication
    /// for non variant depended calls is still possible.
    fn spawn_redetect(
        &self,
        state: &mut std::sync::MutexGuard<'_, super::state::CommunicationStateData>,
    ) -> ClaimOutcome {
        let (tx, rx) = watch::channel(None);
        let detector = state.variant_detector();

        // Note what is *not* written here: `state.state`. The runtime is
        // `Enabled` before this call, throughout the sweep, and after it.
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

    /// Joins the re-detection already in flight.
    ///
    /// Kept apart from `join_in_flight` because the two
    /// read different slots, and because this one must never publish a
    /// lifecycle state: a dead detection task leaves the runtime `Enabled`,
    /// exactly as a failed one does.
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

        // Either the sender died without ever publishing, or the slot is unset
        // - the latter unreachable, since `decide` returned `JoinDetection`
        // under this same lock. Clear it either way so the next caller claims a
        // fresh sweep instead of joining a dead one forever, and fail closed
        // rather than panicking so a future routing mistake is a refusal.
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

    /// Runs variant re-detection on the worker (initializers only, no
    /// transport change), isolating the caller from a send/reply failure
    /// (worker shutdown mid-flight).
    async fn run_redetect_operation(
        &self,
        detector: Option<Arc<dyn CommunicationVariantDetection>>,
    ) -> Result<CommunicationState, CommunicationOperationFailure> {
        self.submit_and_await(CommunicationOperation::Detect, |reply| {
            LifecycleCommand::Redetect { detector, reply }
        })
        .await
    }

    /// Publishes the final state for a completed enabling operation
    /// claimed via [`claim_or_join`](Self::claim_or_join), and clears the
    /// enabling-result slot.
    ///
    /// Runs on a task detached from the caller, so it can race the worker's
    /// own shutdown sequence publishing its terminal state; see
    /// [`publish_enabling_result`](super::state::CommunicationStateData::publish_enabling_result)
    /// for why that race is safe.
    fn finish_enabling(
        &self,
        result: Result<CommunicationState, CommunicationOperationFailure>,
        operation: CommunicationOperation,
    ) -> Result<CommunicationState, CommunicationOperationFailure> {
        self.state.lock().publish_enabling_result(result, operation)
    }

    /// Completes an explicit detection on already-enabled communication without
    /// changing the lifecycle state: clears the detection slot and returns the
    /// result unchanged.
    ///
    /// On failure, resets the effective detection mode because no sweep remains
    /// in progress.
    fn finish_detection(
        &self,
        result: Result<CommunicationState, CommunicationOperationFailure>,
    ) -> Result<CommunicationState, CommunicationOperationFailure> {
        let mut state = self.state.lock();
        // Shutdown's own sequence clears the slot and publishes the terminal
        // state; a detection finishing alongside it must not write over that.
        // Same reasoning as `publish_enabling_result`'s guard.
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

    /// Fails the current enabling attempt with a `WorkerUnavailable` error
    /// when the watch channel closes before a result was published (the spawned
    /// task panicked without sending).
    ///
    /// The failed receiver identifies its attempt. State is changed only when
    /// the current slot belongs to the same channel, preventing a stale
    /// finalizer from clobbering a newer attempt.
    fn fail_closed_enabling_attempt(
        &self,
        operation: CommunicationOperation,
        failed: &EnablingResultReceiver,
    ) -> CommunicationOperationFailure {
        let failure = CommunicationOperationFailure::WorkerUnavailable { operation };
        let mut state = self.state.lock();
        // A re-detection publishes no lifecycle state, not even a failed one:
        // it changed nothing physical, so `Enabled` is still the truth.
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
    /// Granted from `Enabled` **and** from `Disabled`. The lease is exclusive
    /// ownership of the runtime, not an operation on the transport: a consumer
    /// that needs everything else held still (a runtime update swapping
    /// databases) needs no transport, and refusing it while communication is
    /// deferred would force a deferred deployment to bring the whole vehicle
    /// network up purely to become eligible - the opposite of what deferring
    /// is for.
    ///
    /// What differs is what the lease means afterwards, recorded in
    /// `DisableOwner::resumes_transport`: a lease taken from `Enabled`
    /// resumes on `release()`, one taken from `Disabled` returns to `Disabled`.
    /// Releasing never enables a runtime the releaser did not find enabled.
    ///
    /// `Enabling(_)`, `Disabling`, `DisabledExclusive`, and `Error(_)` are all
    /// conflicts. `Error(_)` deliberately so: its transport state is unknown,
    /// so neither resume shape can be chosen honestly.
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
                    // Both halves of "what does releasing this mean?" are
                    // decided here, in one read: whether the transport comes
                    // back, and whether it detects when it does.
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
                // lease: `Conflict` for the states that can't, and the
                // activation-shaped verdicts, which `decide` never returns for
                // a `Disable`.
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

    /// Runs on a task detached from the `disable()` caller so that cancelling
    /// the caller (e.g. aborting a task that awaits `disable()`) cannot lose
    /// the resulting `DisableLease`: constructing it here, not in `disable()`
    /// itself, means an abandoned task still finishes and, with nobody left
    /// to collect the lease, its `Drop` still runs, synchronously deferring
    /// back to `Disabled` exactly as if the caller had dropped it themselves.
    async fn run_disable_operation(
        &self,
        id: DisableLeaseId,
        reason: DisableReason,
    ) -> Result<DisableLease, CommunicationOperationFailure> {
        let operation = CommunicationOperation::Disable;
        // Uses `submit` rather than `submit_and_await`: unlike every other
        // caller, a failure here must run `finish_failed_disable_locally`
        // *only* when it was synthesized locally (send failed, or the
        // channel closed with no reply) - not when the worker's own
        // `execute_disable` already reported it (see
        // `finish_failed_disable_locally`'s doc comment for why that case is
        // already handled).
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
                let failure = self.worker_failure(operation);
                self.finish_failed_disable_locally(id, failure.clone());
                Err(failure)
            }
        }
    }

    /// Publishes a structured `Error` for a claimed disable whose outcome is
    /// indeterminate because the worker could not be reached at all (shutdown
    /// raced the claim, or the worker task itself panicked). This differs
    /// from an ordinary transport failure, which the worker's own
    /// `execute_disable` also reports as `Error` (see `finish_failed_disable`)
    /// with the transport's actual call result known. Here nothing confirms
    /// the transport's actual state, so `Error` is the conservative choice.
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
        // Set synchronously, under the state lock, before the worker does any
        // teardown work: this is what makes the worker's own terminal-state
        // write (at the end of its shutdown sequence) unambiguously the last
        // word over any task racing it (`finish_enabling`,
        // `finish_failed_disable_locally`, `defer_disable`). Every such write
        // either happens fully before this one (and so fully before the
        // worker's later write, which overwrites it) or observes
        // `shutting_down` and skips - see `shutting_down`'s doc comment for
        // why the mutex makes that exhaustive.
        self.state.lock().shutting_down = true;
        self.worker.shutdown().await;
        if let Some(task) = self.worker_task.lock().await.take()
            && let Err(error) = task.await
        {
            tracing::error!(%error, "Communication lifecycle worker terminated unexpectedly");
            let mut state = self.state.lock();
            // Label the failure with whatever the worker died holding. Only
            // `Enabling` names its own operation; from every other state the
            // teardown that just failed was the disable-shaped one.
            let operation = match state.state {
                CommunicationState::Enabling(operation) => operation,
                CommunicationState::Enabled
                | CommunicationState::Disabled
                | CommunicationState::Disabling
                | CommunicationState::DisabledExclusive
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
/// `init_mode` is passed through unchanged: the framework delivers it as a
/// typed fact, but only the plugin decides what to do with it (see ADR-006).
/// `variant_detection` is different - it is framework policy, applied by the
/// worker itself, because it describes what an activation *is* rather than who
/// is allowed to ask for one.
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

/// Public `test_utils`, so downstream plugin implementors
/// can use these utilities in their own unit tests.
/// Necessary because the constructor of [`CommunicationHandle`] is private because
/// production code should create the object through `build_communication_runtime`, to make sure
/// it is only available to the plugin and all control flow goes through that instead of having
/// direct access to the handle.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils {
    use std::sync::Arc;

    use cda_interfaces::communication_control::{
        CommunicationAccess, CommunicationError, CommunicationGuard, CommunicationState,
        TransportControl, VariantDetectionMode,
    };

    use crate::lifecycle::{
        CommunicationHandle,
        disable::{DisableError, DisableReason},
        state::CommunicationStateStore,
        worker,
    };

    /// Synchronous, all-in-one constructor for test and `test-utils`
    /// fixtures only. Production wiring goes through
    /// [`build_communication_runtime`] instead, which stages construction
    /// around the plugin-builder handshake this shortcuts.
    #[must_use]
    pub(crate) fn communication_handle_new(
        transport_control: Arc<dyn TransportControl>,
    ) -> CommunicationHandle {
        communication_handle_with_detection_mode(transport_control, VariantDetectionMode::Always)
    }

    /// As [`communication_handle_new`], but with an explicit detection policy,
    /// for fixtures that exercise `VariantDetectionMode::Never`.
    #[must_use]
    pub(crate) fn communication_handle_with_detection_mode(
        transport_control: Arc<dyn TransportControl>,
        variant_detection: VariantDetectionMode,
    ) -> CommunicationHandle {
        let resources = worker::new_resources(transport_control);
        communication_handle_from_resources(
            CommunicationState::Disabled,
            resources,
            variant_detection,
        )
    }

    fn communication_handle_from_resources(
        initial_state: CommunicationState,
        resources: worker::WorkerResources,
        variant_detection: VariantDetectionMode,
    ) -> CommunicationHandle {
        let state = Arc::new(CommunicationStateStore::new(
            initial_state,
            variant_detection,
        ));
        let (sender, receivers) = worker::channel();
        let worker_task = Arc::new(tokio::sync::Mutex::new(Some(worker::spawn(
            Arc::clone(&state),
            resources,
            receivers,
        ))));
        CommunicationHandle {
            state,
            worker: sender,
            worker_task,
        }
    }

    #[must_use]
    pub fn enabled_communication_access_for_test() -> Arc<dyn CommunicationAccess> {
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

        impl CommunicationAccess for Access {
            fn state(&self) -> CommunicationState {
                self.0.state()
            }

            fn acquire(&self) -> Result<CommunicationGuard, CommunicationError> {
                self.0.acquire()
            }

            fn request_activate(
                &self,
                _cause: cda_interfaces::communication_control::ActivationCause,
            ) -> CommunicationState {
                self.0.request_enable_and_detect()
            }

            fn variant_detection(&self) -> VariantDetectionMode {
                // Hardcoded rather than delegated, for the same reason the
                // state is: this fixture starts `Enabled` without ever running
                // an activation, so the handle's effective mode was never
                // claimed and would report a fixture artifact rather than what
                // a healthy enabled runtime looks like.
                VariantDetectionMode::Always
            }
        }

        let resources = worker::new_resources(Arc::new(TestTransport));
        Arc::new(Access(communication_handle_from_resources(
            CommunicationState::Enabled,
            resources,
            VariantDetectionMode::Always,
        )))
    }

    pub fn communication_disable_for_test(
        transport_control: Arc<dyn TransportControl>,
        initially_enabled: bool,
    ) -> Arc<dyn crate::lifecycle::disable::DisableCommunication> {
        struct Disable(CommunicationHandle);

        #[async_trait::async_trait]
        impl crate::lifecycle::disable::DisableCommunication for Disable {
            async fn disable(
                &self,
                reason: DisableReason,
            ) -> Result<Box<dyn cda_interfaces::communication_control::DisableGuard>, DisableError>
            {
                self.0.disable(reason).await.map(|lease| {
                    Box::new(lease) as Box<dyn cda_interfaces::communication_control::DisableGuard>
                })
            }
        }

        let handle = if initially_enabled {
            let resources = worker::new_resources(transport_control);
            communication_handle_from_resources(
                CommunicationState::Enabled,
                resources,
                VariantDetectionMode::Always,
            )
        } else {
            communication_handle_new(transport_control)
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

    /// Regression test: an enabling operation's detached `finish_enabling` write
    /// must never race the worker's own shutdown-sequence write. Shutdown is
    /// requested (and `shutting_down` set, synchronously) while an enabling
    /// operation is blocked inside the worker's `transport.enable()`; only then is the
    /// transport unblocked, so the detached task's `finish_enabling` can
    /// only run *after* `shutting_down` was already set. Without the
    /// `shutting_down` check this was scheduler-dependent and could leave
    /// `state == Enabled` after the transport had already been torn down by
    /// shutdown - letting `acquire()` hand out a guard on a dead transport.
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
        // Acquiring a guard on the "dead" transport must be impossible.
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

    /// A lease is exclusive ownership of the runtime, not a transport
    /// operation, so it is granted from `Disabled` too - a consumer needing
    /// mutual exclusion (a runtime update swapping databases) must not have to
    /// bring the vehicle network up to become eligible.
    ///
    /// Releasing it returns to `Disabled`: nothing was displaced, so nothing is
    /// restored. This is the load-bearing half - a release that activated would
    /// hand a consumer holding only `DisableCommunication` a way to start
    /// vehicle communication that `init_mode` never authorized.
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

        // Exclusivity still holds while it is out.
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

    /// The lifecycle hooks of a runtime that was never enabled must not be
    /// deinitialized by a lease taken over it: `deinitialize()` without a
    /// preceding `initialize()` breaks `CommunicationLifecycle`'s paired
    /// contract.
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
    /// releasing it, reached through the cancellation-safe path.
    #[tokio::test]
    async fn dropping_a_lease_from_disabled_leaves_it_disabled() {
        let (handle, control) = handle();
        let lease = handle.disable(DisableReason::RuntimeUpdate).await.unwrap();
        drop(lease);
        assert_eq!(handle.state(), CommunicationState::Disabled);
        assert_eq!(control.enables.load(Ordering::Relaxed), 0);
        assert_eq!(control.disables.load(Ordering::Relaxed), 0);
    }

    /// `Error(_)` stays a conflict: its transport state is unknown, so neither
    /// resume shape could be chosen honestly.
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

    /// A `release()` future abandoned before its first poll must still defer.
    /// `release` consumes the lease, so the un-polled future owns it and never
    /// reached the `self.id = None` that hands ownership to the worker;
    /// dropping the future therefore drops a still-owning lease and runs the
    /// same synchronous `Drop` defer as a plain `drop(lease)`. Distinct from
    /// `disable_lease_can_return_to_deferred_state` only in *how* the lease
    /// reaches `Drop`.
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

        // Asserted synchronously, not polled: an implementation that deferred
        // only after some later await point would be a regression.
        assert_eq!(handle.state(), CommunicationState::Disabled);
        assert_eq!(control.enables.load(Ordering::Relaxed), 1);
    }

    /// A release that reaches the worker after teardown has begun must refuse
    /// rather than bring the transport back up.
    ///
    /// `shutdown()` sets `shutting_down` synchronously, under the state lock,
    /// *before* the worker runs any teardown - precisely so a transition
    /// already in the mailbox observes it (see `shutting_down`'s doc comment).
    /// Setting the flag directly is the deterministic form of that race:
    /// awaiting a real `shutdown()` would also close admission, so the release
    /// would be refused at the mailbox and this path would never run.
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
        // The refused release must not publish a state of its own either:
        // shutdown's own terminal write is the authoritative last word.
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

    /// Admission backpressures instead of dropping commands: occupies the
    /// worker with a slow in-flight `Activate` so nothing drains the mailbox,
    /// fills it to exactly `LIFECYCLE_WORKER_CAPACITY`, then shows a further
    /// registration does not resolve until capacity frees up - and is then
    /// served rather than lost.
    #[tokio::test]
    async fn admission_blocks_at_capacity_instead_of_losing_commands() {
        let control = Arc::new(BlockingEnableControl::default());
        let handle = communication_handle_new(Arc::clone(&control) as Arc<dyn TransportControl>);

        // Occupy the worker with a slow Activate so the mailbox is never
        // drained while we probe admission.
        let activation = tokio::spawn({
            let handle = handle.clone();
            async move { handle.enable_and_detect().await }
        });
        control.entered.notified().await;

        // Fill the mailbox exactly to capacity. Setup deliberately uses the
        // raw sender rather than `register_lifecycle_hook`: the public call
        // also awaits the worker's reply, which never arrives while the worker
        // is blocked, so it could not be used to occupy a known number of
        // buffer slots. These sends complete purely by taking a slot.
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

        // One more admission must genuinely block: full buffer, nothing
        // draining it. This one goes through the public API, because it is the
        // handle's admission path - not the bare channel - that must
        // backpressure.
        let over_capacity = handle.register_lifecycle_hook(Arc::new(CountingInitializer));
        tokio::pin!(over_capacity);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut over_capacity)
                .await
                .is_err(),
            "admission beyond capacity must block, not be accepted immediately"
        );

        // Unblocking the worker drains the mailbox; the pending admission
        // then succeeds instead of being lost.
        control.proceed.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(5), over_capacity)
            .await
            .expect("blocked admission must be admitted once capacity frees up")
            .expect("the admitted registration must succeed");

        activation.await.unwrap().unwrap();
    }

    /// Regression test for the startup race: several concurrent `activate()`
    /// callers arriving while an activation is in flight must all join the
    /// same operation and observe the same result, instead of one of them
    /// seeing `TransitionFailure`.
    #[tokio::test]
    async fn concurrent_activate_calls_join_one_operation_and_share_result() {
        let control = Arc::new(BlockingEnableControl::default());
        let handle = communication_handle_new(Arc::clone(&control) as Arc<dyn TransportControl>);

        let first = tokio::spawn({
            let handle = handle.clone();
            async move { handle.enable_and_detect().await }
        });
        control.entered.notified().await;

        // These callers arrive while the first activation is in flight (state ==
        // Enabling). None of them may see TransitionFailure; all must join and
        // receive Enabled.
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

    /// Regression test for the dead on-demand recovery path: `request_activate`
    /// called while communication is `Error` must claim and retry, not return
    /// the stale `Error` state forever. A repeated transport failure returns to
    /// `Error`, and a later on-demand request retries again rather than getting
    /// stuck.
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

    /// Stage 3 acceptance: `disable` rejects active guards, grants exactly one
    /// exclusive lease, rejects a second concurrent lease, and blocks ordinary
    /// (`activate`) and on-demand (`request_activate`) re-activation while
    /// held. Only the matching lease may re-activate; dropping it leaves
    /// communication unowned `Disabled`.
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

    /// Shutdown must notify registered hooks before tearing down the
    /// transport, exactly as an ordinary `disable()` does, so keep-alive work
    /// started in `initialize()` doesn't outlive the transport.
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

    /// When a later initializer fails during activation, the initializers
    /// that already succeeded must be deinitialized before the transport goes
    /// back down - they were told the transport was up and may have started
    /// work depending on that.
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

    /// `redetect` while `Enabled` re-runs the detector against the already-live
    /// transport, never calls `TransportControl::enable()` a second time, and
    /// - critically - never re-enters a lifecycle hook's `initialize()`,
    /// which would break that trait's paired contract.
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

    /// Re-detection is refused while an *activity* guard is held: that guard is
    /// the only lock spanning a whole multi-request sequence, which the per-ECU
    /// transport semaphore cannot provide because it reopens between the
    /// individual requests.
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

        // Once released, re-detection proceeds normally.
        assert_eq!(handle.redetect().await, Ok(CommunicationState::Enabled));
        assert_eq!(control.enables.load(Ordering::Relaxed), 1);
    }

    /// `redetect` is the detection stage alone. From `Disabled`/`Error` there
    /// is no live transport to detect against, and it refuses rather than
    /// quietly widening itself into an activation - composing that fallback is
    /// a plugin's decision, not the framework's.
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

    /// Concurrent re-detections while one is already in flight join the same
    /// attempt and observe the same result, rather than racing to claim a
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
        let handle = communication_handle_new(Arc::clone(&control) as Arc<dyn TransportControl>);
        // Reach Enabled first: the blocking behavior below is exercised by a
        // slow detector, not the (already-unblocked) transport enable.
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
        // The runtime stays `Enabled` for the whole sweep - detection is not a
        // transition - so diagnostics keep being served throughout it. A model
        // that moved the state to `Enabling` would fail this acquisition and
        // take every diagnostic request down for the sweep's duration.
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
        // The transport was only ever enabled once (the initial activate());
        // no joined re-detection call touched it again.
        assert_eq!(control.enables.load(Ordering::Relaxed), 1);
    }

    /// A detector failure during `Redetect` publishes a structured `Error` and
    /// leaves the transport enabled - re-detection did not bring the transport
    /// up itself, so it is not authorized to tear it down on failure (unlike
    /// `run_activation`, which does).
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

        // The runtime stays usable, which is the availability half of the fix.
        assert!(handle.acquire().is_ok());
        assert!(handle.acquire().is_ok());
    }

    /// A failed re-detection must not publish `Error(_)`. Every consumer reads
    /// `Error` as "the transport is not up", and every producer of it leaves
    /// the transport that way - so `decide` admits a recovery activation from
    /// it ("both are inactive with the transport down"), and `run_activation`
    /// would re-run `initialize()` on hooks that are still initialized,
    /// breaking `CommunicationLifecycle`'s paired contract. No operator is
    /// needed to reach it: the readiness gate fires `request_activate` on the
    /// next ECU request, because it classifies `Error` as "nothing in flight".
    ///
    /// Leaving the runtime `Enabled` is what makes that request settle as
    /// `AlreadyEnabled`, running no stage at all.
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

        // Exactly what the readiness gate does on the next ECU request.
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

    /// A lease must not be granted while a sweep is running. Because the state
    /// stays `Enabled` throughout one, the `(Enabled, Disable)` cell would
    /// otherwise grant a lease and tear the transport down underneath a running
    /// detection - which is why `decide` checks the detection slot explicitly.
    #[tokio::test]
    async fn disable_is_refused_while_a_redetection_is_in_flight() {
        // `RecordingControl`, not a blocking transport: the only thing that
        // needs to block here is the detector, and the lease resume at the end
        // has to be able to enable again without deadlocking.
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

        // Once the sweep settles the lease is available again. Dropped rather
        // than released: releasing would resume, and a resume repeats the
        // detecting shape the sweep just established, re-entering the blocking
        // detector with nobody left to unblock it. Dropping defers
        // synchronously and touches no transport, which is all this needs.
        let lease = handle
            .disable(DisableReason::RuntimeUpdate)
            .await
            .expect("the lease must be grantable once detection settles");
        drop(lease);
        assert_eq!(handle.state(), CommunicationState::Disabled);
    }

    /// A detector failure during a full activation unwinds *all* hooks (every
    /// one initialized successfully before detection ran) and takes the
    /// transport back down, since this operation brought it up itself.
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

    /// Releasing a disable lease repeats the *shape* of the enable it resumes.
    /// Runtime update releases the lease, but whether this runtime detects is
    /// the communication plugin's decision, so a resume must not silently
    /// upgrade an enable-only runtime into a detecting one.
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
    /// An explicit `redetect()` makes an enable-only runtime a detecting one,
    /// so a lease granted afterwards resumes detecting. The resume shape is
    /// captured from the effective detection mode when the lease is *granted*,
    /// which is what makes this follow the redetect rather than the original
    /// `enable()`.
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
    /// detector - even on a runtime `enable()` brought up without ever settling
    /// a variant. It is a request for available communication, not an "ensure
    /// detected"; detection against a live transport is `redetect()`.
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

        // Asking for detection outright is what actually runs it.
        assert_eq!(handle.redetect().await, Ok(CommunicationState::Enabled));
        assert_eq!(detector.calls.load(Ordering::Relaxed), 1);
        assert_eq!(handle.variant_detection(), VariantDetectionMode::Always);
    }

    /// `VariantDetectionMode::Never` suppresses *automatic* detection only: it
    /// gates the detector stage of an activation, never the transport or the
    /// lifecycle hooks, and never an explicit `redetect()`.
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

        // "Never" means never *automatically*. Asking outright still works,
        // and while it runs the runtime reports that a variant is coming.
        assert_eq!(handle.redetect().await, Ok(CommunicationState::Enabled));
        assert_eq!(
            detector.calls.load(Ordering::Relaxed),
            1,
            "an explicit detection must run even where automatic detection is configured off"
        );
        assert_eq!(handle.variant_detection(), VariantDetectionMode::Always);
    }

    /// With no detector registered, nothing can settle a variant no matter what
    /// the configuration says, and the runtime says so rather than leaving
    /// consumers to wait out a readiness timeout.
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
