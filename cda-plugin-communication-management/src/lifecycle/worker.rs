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

//! Lifecycle worker.
//!
//! [`CommunicationHandle`](super::controller::CommunicationHandle) claims
//! lifecycle-state transitions synchronously (so guard acquisition and lease
//! drop stay lock-free and awaitable-free) and submits the resulting work as a
//! [`LifecycleCommand`] to this worker. The worker is the *sole* task that
//! touches the physical transport and the registered initializer list - no
//! other task reaches into those resources, so the worker's single-threaded
//! loop needs no internal synchronization over them.
//!
//! This split exists because claiming a transition must stay synchronous:
//! `DisableLease`'s drop-based defer and guard acquisition cannot `.await`,
//! so the state claim lives behind a plain `std::sync::Mutex` in
//! `controller.rs`. The physical work the claim authorizes - transport
//! enable/disable, initializers - is async, can take seconds (variant
//! detection), and must be serialized to one at a time; it cannot live in
//! that same synchronous path, so it is handed off here instead.
//!
//! The mailbox capacity bounds *admission* only: [`LifecycleCommand`]s are
//! durable once enqueued (`mpsc::Sender::send` is cancel-safe: a command is
//! either fully enqueued or not sent at all) and are always eventually
//! processed or explicitly failed, never silently dropped. Shutdown uses a
//! separate, unbounded out-of-band channel (see [`WorkerSender::shutdown`])
//! so it can never be blocked by a full command mailbox.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use cda_interfaces::{
    communication_control::{
        CommunicationLifecycle, CommunicationOperation, CommunicationOperationFailure,
        CommunicationState, CommunicationVariantDetection, TransportControl,
    },
    dlt_ctx,
};
use tokio::sync::{mpsc, oneshot, watch};

use super::{
    disable::{DisableLeaseId, DisableOwner, DisableReason},
    state::{CommunicationStateStore, detection_mode},
    transition::{self, LifecycleDecision, LifecycleRequest},
};

/// Bounded admission capacity of the lifecycle worker mailbox.
pub(crate) const LIFECYCLE_WORKER_CAPACITY: usize = 8;

/// Reply channel shared by every activation-shaped command (`Activate`,
/// `Redetect`, and `ReleaseDisableLease`'s resume).
pub(crate) type ActivationReply =
    oneshot::Sender<Result<CommunicationState, CommunicationOperationFailure>>;

/// A plugin-authorized lifecycle operation submitted to the worker.
pub(crate) enum LifecycleCommand {
    /// Runs the physical activation sequence: activate transport, run
    /// initializers in registration order.
    Activate {
        operation: CommunicationOperation,
        /// The detector to run in the final stage, or `None` to skip it.
        ///
        /// Resolved by the claiming `CommunicationHandle` in the same read that
        /// published `variant_detection`, so what a readiness consumer was told
        /// and what this command actually runs cannot disagree.
        detector: Option<Arc<dyn CommunicationVariantDetection>>,
        reply: ActivationReply,
    },
    /// Runs the registered variant detector only.
    ///
    /// Unlike `Activate` this touches neither `transport_control`, nor the
    /// lifecycle hooks: the transport is already up, this operation is not
    /// authorized to change it, and re-entering a hook's `initialize()`
    /// without an intervening `deinitialize()` would violate that trait's
    /// paired contract. Only reachable from `Enabled`
    /// (see [`transition::decide`](transition::decide)).
    Redetect {
        /// Resolved by the claiming `CommunicationHandle`, exactly as for
        /// [`Activate`](Self::Activate). `None` is a successful no-op.
        detector: Option<Arc<dyn CommunicationVariantDetection>>,
        reply: ActivationReply,
    },
    /// Runs the physical disable sequence for the exclusive lease `id`.
    ///
    /// The state claim (`Enabled -> Disabling`, setting `disable_owner`) already
    /// happened synchronously in `CommunicationHandle::disable()` before this
    /// command was enqueued. This synchronous claim is necessary because `disable()`
    /// is a public API where multiple callers could race to acquire the exclusive
    /// lease. The detached task spawned by `disable()` ensures the lease is still
    /// created even if the original caller is canceled.
    Disable {
        id: DisableLeaseId,
        reason: DisableReason,
        reply: oneshot::Sender<Result<(), CommunicationOperationFailure>>,
    },
    /// Releases an exclusive disable lease and resumes communication.
    ///
    /// Unlike dropping `DisableLease`, this enables the transport and runs
    /// post-activation initializers before replying. See `DisableLease` for
    /// examples and the semantic difference from drop-based release.
    ///
    /// The worker validates and claims the lease only when it dequeues this
    /// command. That deferred claim preserves the drop fallback if `release()`
    /// is canceled before the command enters the mailbox.
    ReleaseDisableLease {
        id: DisableLeaseId,
        reply: ActivationReply,
    },
    /// Appends a lifecycle hook to the worker-owned registration list.
    /// Ordering is exact: any `Activate` processed after this command includes
    /// it; anything processed earlier in the queue does not.
    RegisterLifecycleHook {
        initializer: Arc<dyn CommunicationLifecycle>,
        reply: oneshot::Sender<Result<(), CommunicationOperationFailure>>,
    },
    /// Installs the whole-vehicle variant detector into the shared state store.
    ///
    /// A single slot rather than a list: detection is whole-vehicle by
    /// definition so a second registration replaces the first rather than adding a
    /// second sweep.
    ///
    /// Routed through the worker even though the destination is shared state,
    /// so registration keeps the same queue position - and therefore the same
    /// ordering against `Activate` as `RegisterLifecycleHook`.
    RegisterVariantDetection {
        detector: Arc<dyn CommunicationVariantDetection>,
        reply: oneshot::Sender<Result<(), CommunicationOperationFailure>>,
    },
}

/// Durable resources exclusively owned by the lifecycle worker's task.
///
/// Constructed via [`new_resources`] and moved into the task started by
/// [`spawn`]. No other task ever touches this type.
///
/// Everything here is used through `&mut` and so must have a single owner. The
/// variant detector deliberately does *not* live here: it is used through
/// `&self`, and the claim side needs to read its presence synchronously, so it
/// lives in the shared state store and reaches the worker as a command field.
pub(crate) struct WorkerResources {
    transport_control: Arc<dyn TransportControl>,
    initializers: Vec<Arc<dyn CommunicationLifecycle>>,
}

/// Constructs the durable resources the worker will own.
pub(crate) fn new_resources(transport_control: Arc<dyn TransportControl>) -> WorkerResources {
    WorkerResources {
        transport_control,
        initializers: Vec::new(),
    }
}

/// Notifies lifecycle hooks that the transport is going (or has gone) down,
/// in reverse registration order (symmetric to `initialize`'s forward
/// order).
async fn deinitialize_all(initializers: &[Arc<dyn CommunicationLifecycle>]) {
    for initializer in initializers.iter().rev() {
        initializer.deinitialize().await;
    }
}

/// Runs the physical activation sequence shared by `Enable`, `Activate`, and
/// lease `release()`, in three ordered stages: enable the transport, initialize
/// every registered lifecycle hook in registration order, then - only when a
/// `detector` was resolved for this operation - run it.
///
/// Takes the detector as an argument rather than looking one up: the claim that
/// authorized this operation already resolved it, together with the detection
/// mode it published, so passing it through keeps the two in agreement.
///
/// The hooks always run, including for an `Enable` that detects nothing: a hook
/// follows the *transport*, not the detection policy (see
/// [`CommunicationLifecycle`]). Only the last stage is optional.
async fn run_activation(
    resources: &WorkerResources,
    operation: CommunicationOperation,
    detector: Option<Arc<dyn CommunicationVariantDetection>>,
) -> Result<CommunicationState, CommunicationOperationFailure> {
    if let Err(error) = resources.transport_control.enable().await {
        return Err(CommunicationOperationFailure::TransportFailure {
            operation,
            error: error.to_string(),
        });
    }

    for (index, initializer) in resources.initializers.iter().enumerate() {
        if let Err(error) = initializer.initialize().await {
            // Only the initializers up to `index` were told the transport is
            // up; tear those down before the transport itself goes back down.
            deinitialize_all(resources.initializers.get(..index).unwrap_or(&[])).await;
            let failure = match resources.transport_control.disable().await {
                Ok(()) => CommunicationOperationFailure::InitializerFailure {
                    initializer: initializer.name().to_owned(),
                    error: error.to_string(),
                },
                Err(cleanup_error) => CommunicationOperationFailure::InitializerCleanupFailure {
                    initializer: initializer.name().to_owned(),
                    initializer_error: error.to_string(),
                    cleanup_error: cleanup_error.to_string(),
                },
            };
            return Err(failure);
        }
    }

    if let Some(detector) = &detector
        && let Err(error) = detector.detect().await
    {
        // Every hook initialized successfully above, so unwind all of
        // them - not a prefix - before the transport goes back down.
        deinitialize_all(&resources.initializers).await;
        let failure = match resources.transport_control.disable().await {
            Ok(()) => CommunicationOperationFailure::DetectionFailure {
                detector: detector.name().to_owned(),
                error: error.to_string(),
            },
            Err(cleanup_error) => CommunicationOperationFailure::DetectionCleanupFailure {
                detector: detector.name().to_owned(),
                detection_error: error.to_string(),
                cleanup_error: cleanup_error.to_string(),
            },
        };
        return Err(failure);
    }

    Ok(CommunicationState::Enabled)
}

/// Runs the registered variant detector, and nothing else.
///
/// Deliberately touches neither `transport_control`, nor the lifecycle hooks.
/// This operation only ever runs while communication is already `Enabled`: the
/// transport is up, and it is not authorized to change it. Re-entering the hooks
/// would additionally break [`CommunicationLifecycle`]'s paired
/// initialize/deinitialize contract, since there is no `deinitialize` between.
///
/// On failure, the transport is *not* disabled: this caller didn't bring it up,
/// so it doesn't tear it down. That differs deliberately from `run_activation`,
/// which does disable the transport on failure because it enabled it itself.
///
/// With no detector registered this is a successful no-op - there is nothing
/// to re-run, and the state was already `Enabled`.
async fn run_redetection(
    detector: Option<Arc<dyn CommunicationVariantDetection>>,
) -> Result<CommunicationState, CommunicationOperationFailure> {
    if let Some(detector) = &detector
        && let Err(error) = detector.detect().await
    {
        return Err(CommunicationOperationFailure::DetectionFailure {
            detector: detector.name().to_owned(),
            error: error.to_string(),
        });
    }
    Ok(CommunicationState::Enabled)
}

/// The [`LIFECYCLE_WORKER_CAPACITY`]-capacity lifecycle worker task body.
pub(crate) struct LifecycleWorker {
    state: Arc<CommunicationStateStore>,
    resources: WorkerResources,
    commands: mpsc::Receiver<LifecycleCommand>,
    shutdown_rx: mpsc::UnboundedReceiver<oneshot::Sender<()>>,
}

/// Cloneable handle used by [`super::controller::CommunicationHandle`] to
/// submit work to the worker and to request shutdown.
#[derive(Clone)]
pub(crate) struct WorkerSender {
    commands: mpsc::Sender<LifecycleCommand>,
    shutdown_tx: mpsc::UnboundedSender<oneshot::Sender<()>>,
    /// Set the instant shutdown is requested, before the out-of-band signal is
    /// even sent, so new claims fail immediately without waiting for the
    /// worker to notice. Independent of mailbox/task state by design.
    admission_closed: Arc<AtomicBool>,
}

impl WorkerSender {
    pub(crate) fn is_shutting_down(&self) -> bool {
        self.admission_closed.load(Ordering::SeqCst)
    }

    /// Enqueues `command`, waiting for mailbox capacity if necessary.
    ///
    /// # Errors
    ///
    /// Returns the command back when admission is closed or the worker task
    /// has already exited.
    pub(crate) async fn send(
        &self,
        command: LifecycleCommand,
    ) -> Result<(), mpsc::error::SendError<LifecycleCommand>> {
        if self.is_shutting_down() {
            return Err(mpsc::error::SendError(command));
        }
        self.commands.send(command).await
    }

    /// Requests the out-of-band shutdown barrier and awaits its completion.
    ///
    /// Idempotent: closing admission twice is harmless, and every caller
    /// after the first simply awaits the same underlying teardown via its own
    /// oneshot (the worker replies to every queued shutdown request).
    pub(crate) async fn shutdown(&self) {
        self.admission_closed.store(true, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        if self.shutdown_tx.send(tx).is_ok() {
            let _ = rx.await;
        }
        // `Err` means the worker task already exited (e.g. a previous
        // shutdown completed); nothing left to wait for.
    }

    pub(crate) fn request_shutdown(&self) {
        self.admission_closed.store(true, Ordering::SeqCst);
        let (tx, _rx) = oneshot::channel();
        let _ = self.shutdown_tx.send(tx);
    }
}

/// The receiving halves paired with a [`WorkerSender`], held separately until
/// [`spawn`] actually starts the task.
///
/// Split from [`channel`] so a [`WorkerSender`] (and thus a fully functional
/// [`super::controller::CommunicationHandle`]) can exist - and be handed to a
/// plugin builder - *before* [`spawn`] runs: the builder can fail, and only
/// after it succeeds is there a plugin to hand back alongside the running
/// worker. Nothing observable happens with a `WorkerSender` until [`spawn`]
/// is called: commands just sit in the bounded mailbox.
pub(crate) struct WorkerReceivers {
    commands: mpsc::Receiver<LifecycleCommand>,
    shutdown_rx: mpsc::UnboundedReceiver<oneshot::Sender<()>>,
}

/// Creates the worker's channels without starting its task.
pub(crate) fn channel() -> (WorkerSender, WorkerReceivers) {
    let (commands_tx, commands_rx) = mpsc::channel(LIFECYCLE_WORKER_CAPACITY);
    let (shutdown_tx, shutdown_rx) = mpsc::unbounded_channel();
    (
        WorkerSender {
            commands: commands_tx,
            shutdown_tx,
            admission_closed: Arc::new(AtomicBool::new(false)),
        },
        WorkerReceivers {
            commands: commands_rx,
            shutdown_rx,
        },
    )
}

/// Spawns the lifecycle worker task over already-constructed `resources` and
/// the receiving halves from a prior [`channel`] call.
pub(crate) fn spawn(
    state: Arc<CommunicationStateStore>,
    resources: WorkerResources,
    receivers: WorkerReceivers,
) -> tokio::task::JoinHandle<()> {
    let worker = LifecycleWorker {
        state,
        resources,
        commands: receivers.commands,
        shutdown_rx: receivers.shutdown_rx,
    };
    cda_interfaces::spawn_named!("communication-lifecycle-worker", worker.run())
}

impl LifecycleWorker {
    /// Cancelling or joining active initialization
    /// work: shutdown does **not** preemptively cancel a command already
    /// being processed. `handle_command` is awaited inline in the `select!`
    /// arm below, so if shutdown arrives while, say, an `Activate` is
    /// blocked inside `transport_control.enable()`, the shutdown signal just
    /// waits in `shutdown_rx`'s buffer (unbounded, so this never blocks the
    /// *sender*) until that command finishes; only then does the next loop
    /// iteration observe and process it. Two things keep this safe rather
    /// than merely tolerable: first, because commands and shutdown share this
    /// one sequential loop, shutdown can never *race* an in-flight command's
    /// physical work the way the pre-worker detached-task design could,
    /// there is never a window where shutdowns own teardown runs
    /// concurrently with a command still touching the transport. Second,
    /// admission itself closes immediately (`CommunicationHandle::shutdown`
    /// sets `shutting_down` before this task ever sees the signal), so no
    /// *new* work can be accepted while an old command finishes.
    ///
    /// What this does not give you is bounded shutdown latency: a command
    /// stuck forever (a hung transport call, say) delays shutdown forever
    /// too. True preemptive cancellation needs a cancellable unit
    /// of work which is tracked via #490.
    async fn run(mut self) {
        loop {
            tokio::select! {
                biased;
                Some(completion) = self.shutdown_rx.recv() => {
                    self.run_shutdown_sequence().await;
                    let _ = completion.send(());
                    // Drain and reply to any further shutdown requests that
                    // raced this one; they all describe the same completed
                    // teardown.
                    while let Ok(completion) = self.shutdown_rx.try_recv() {
                        let _ = completion.send(());
                    }
                    break;
                }
                maybe_command = self.commands.recv() => {
                    if let Some(command) = maybe_command {
                        self.handle_command(command).await;
                    } else {
                        self.run_shutdown_sequence().await;
                        break;
                    }
                }
            }
        }
    }

    async fn handle_command(&mut self, command: LifecycleCommand) {
        match command {
            LifecycleCommand::Activate {
                operation,
                detector,
                reply,
            } => {
                // Unlike `ReleaseDisableLease`, the claiming `CommunicationHandle`
                // owns publishing the final state for this command (see
                // `CommunicationHandle::claim_or_join`'s detached task) - it
                // needs to run regardless of whether the *caller* of
                // `activate()`/`enable()` is later canceled, and already does
                // so independently of this reply.
                //
                // `detector` is what this activation runs, resolved by that
                // same claim and not recomputed here. Nothing about the shape
                // is remembered: a later lease release reads what it displaced
                // from its own `DisableOwner`.
                let result = run_activation(&self.resources, operation, detector).await;
                let _ = reply.send(result);
            }
            LifecycleCommand::Redetect { detector, reply } => {
                // Same ownership note as `Activate` above: the claiming
                // `CommunicationHandle` publishes the final state.
                let result = run_redetection(detector).await;
                let _ = reply.send(result);
            }
            LifecycleCommand::Disable { id, reason, reply } => {
                tracing::debug!(?reason, "Disabling communication");
                let result = self.execute_disable(id).await;
                let _ = reply.send(result);
            }
            LifecycleCommand::ReleaseDisableLease { id, reply } => {
                let result = self.execute_release(id).await;
                let _ = reply.send(result);
            }
            LifecycleCommand::RegisterLifecycleHook { initializer, reply } => {
                self.resources.initializers.push(initializer);
                let _ = reply.send(Ok(()));
            }
            LifecycleCommand::RegisterVariantDetection { detector, reply } => {
                let previous = self.state.lock().variant_detector.replace(detector);
                if let Some(previous) = previous {
                    tracing::warn!(
                        replaced = previous.name(),
                        "Variant detector replaced; only one whole-vehicle detector is used"
                    );
                }
                let _ = reply.send(Ok(()));
            }
        }
    }

    /// Publishes the final state for a completed enabling operation.
    /// See [`publish_enabling_result`](super::state::CommunicationStateData::publish_enabling_result).
    fn finish_enabling(
        &self,
        result: Result<CommunicationState, CommunicationOperationFailure>,
        operation: CommunicationOperation,
    ) -> Result<CommunicationState, CommunicationOperationFailure> {
        self.state.lock().publish_enabling_result(result, operation)
    }

    /// Validates `id` against the current disable owner and `Disabling` state
    /// *before* touching any physical resource (hooks, transport): the worker
    /// is the sole mutator of `disable_owner` while a command executes, so a
    /// stale/mismatched claim can only be detected here, never invalidated
    /// mid-flight by a race. Checking first means a rejected claim never
    /// leaves hooks deinitialized or the transport down without a matching
    /// state transition to show for it - unlike validating after the physical
    /// work, which would strand the state machine on a mismatch.
    async fn execute_disable(
        &self,
        id: DisableLeaseId,
    ) -> Result<(), CommunicationOperationFailure> {
        let was_enabled = {
            let state = self.state.lock();
            let Some(owner) = state.disable_owner.filter(|owner| owner.id == id) else {
                tracing::debug!("Disable rejected: unknown or conflicting owner");
                return Err(CommunicationOperationFailure::TransitionFailure {
                    operation: CommunicationOperation::Disable,
                });
            };
            if !matches!(state.state, CommunicationState::Disabling) {
                tracing::debug!("Disable rejected: state is no longer Disabling");
                return Err(CommunicationOperationFailure::TransitionFailure {
                    operation: CommunicationOperation::Disable,
                });
            }
            owner.resumes_transport
        };

        // A lease taken from `Disabled` has no transport to take down and no
        // initialized hooks to notify. Calling `deinitialize()` here would
        // break `CommunicationLifecycle`'s paired contract - those hooks never
        // saw an `initialize()` - and disabling an already-down transport
        // would be a physical operation this lease never authorized.
        if !was_enabled {
            let mut state = self.state.lock();
            state.state = CommunicationState::DisabledExclusive;
            return Ok(());
        }

        // Notify lifecycle hooks before the transport goes down, in reverse
        // registration order (symmetric to initialize forward order).
        deinitialize_all(&self.resources.initializers).await;

        match self.resources.transport_control.disable().await {
            Ok(()) => {
                let mut state = self.state.lock();
                state.state = CommunicationState::DisabledExclusive;
                Ok(())
            }
            Err(error) => {
                let failure = CommunicationOperationFailure::TransportFailure {
                    operation: CommunicationOperation::Disable,
                    error: error.to_string(),
                };
                self.finish_failed_disable(id, &failure);
                Err(failure)
            }
        }
    }

    fn finish_failed_disable(&self, id: DisableLeaseId, failure: &CommunicationOperationFailure) {
        let mut state = self.state.lock();
        if DisableOwner::owns(state.disable_owner, id) {
            state.disable_owner = None;
            state.state = CommunicationState::Error(failure.clone());
        }
    }

    /// Atomically claims and executes a queued release: validates `id`
    /// against the current disable owner and `DisabledExclusive` state right
    /// here (not before enqueueing), then restores what the lease displaced.
    ///
    /// *Whether* it activates at all is fixed by
    /// [`DisableOwner::resumes_transport`], recorded when the lease was
    /// granted: a lease taken from `Disabled` displaced no transport, so
    /// releasing it returns to plain `Disabled`. Releasing must never enable a
    /// runtime the releaser did not find enabled - the lease is exclusive
    /// ownership, never an activation capability.
    ///
    /// *Which shape* an actual resume repeats is likewise not the releaser's
    /// choice, and for the same reason: a lease is released by runtime update,
    /// whereas whether a runtime detects is the communication plugin's
    /// decision. Both halves were fixed when the lease was granted and travel
    /// on [`DisableOwner`].
    #[tracing::instrument(skip_all, fields(dlt_context = dlt_ctx!("COMM")))]
    async fn execute_release(
        &self,
        id: DisableLeaseId,
    ) -> Result<CommunicationState, CommunicationOperationFailure> {
        let (result_tx, result_rx) = watch::channel(None);
        let detector = {
            let mut state = self.state.lock();
            // Authority first: only the lease that owns the current disable may
            // resume it. That is a permission question, so it stays here rather
            // than in the transition matrix, which only ever asks what the
            // *state* permits.
            let Some(owner) = state.disable_owner.filter(|owner| owner.id == id) else {
                tracing::debug!("Release rejected: unknown or conflicting lease");
                return Err(super::disable::stale_resume_failure());
            };

            // Whether this release resumes at all is decided by the transition
            // matrix from `DisableOwner::resumes_transport`; *which shape* it
            // resumes with comes from the same owner.
            //
            // `worker_shutting_down` is `false` on purpose: closed admission
            // only bars *new* commands, and this one was already admitted. The
            // state flag, which `decide` checks itself, is the authority on
            // whether teardown has begun.
            match transition::decide(&state, false, LifecycleRequest::Resume) {
                LifecycleDecision::Claim(CommunicationOperation::Resume) => {
                    // This claim resolves its own detector: unlike `Activate`
                    // the claim happens here, in the worker, rather than in the
                    // handle.
                    let detector = if owner.resume_detects {
                        state.variant_detector()
                    } else {
                        None
                    };
                    state.disable_owner = None;
                    state.state = CommunicationState::Enabling(CommunicationOperation::Resume);
                    state.enabling_result = Some(result_rx);
                    state.variant_detection = detection_mode(detector.as_ref());
                    detector
                }
                // Nothing was taken down, so there is nothing to bring back up.
                // The on-demand mechanism recovers it on the next authorized
                // trigger exactly as it would have without the lease.
                LifecycleDecision::SettleDisabled => {
                    state.disable_owner = None;
                    state.state = CommunicationState::Disabled;
                    return Ok(CommunicationState::Disabled);
                }
                // Teardown has begun and already published (or is about to
                // publish) the terminal state; resuming the transport now is
                // exactly the race `shutting_down` exists to prevent.
                LifecycleDecision::ShuttingDown => {
                    return Err(CommunicationOperationFailure::ShuttingDown {
                        operation: CommunicationOperation::Resume,
                    });
                }
                // `Conflict` when this lease owns the disable but the state has
                // already moved on; the rest because `decide` does not produce
                // them for a `Resume`. All mean there is nothing to restore.
                LifecycleDecision::Conflict
                | LifecycleDecision::Claim(_)
                | LifecycleDecision::ClaimDetection
                | LifecycleDecision::Join(_)
                | LifecycleDecision::JoinDetection
                | LifecycleDecision::AlreadyEnabled
                | LifecycleDecision::ClaimDisable { .. }
                | LifecycleDecision::GuardsHeld
                | LifecycleDecision::LeaseHeld(_)
                | LifecycleDecision::NotEnabled => {
                    tracing::debug!("Release rejected: state no longer matches this lease");
                    return Err(super::disable::stale_resume_failure());
                }
            }
        };

        let result =
            run_activation(&self.resources, CommunicationOperation::Resume, detector).await;
        let result = self.finish_enabling(result, CommunicationOperation::Resume);
        let _ = result_tx.send(Some(result.clone()));
        result
    }

    /// Out-of-band shutdown barrier: closes ingress, fails
    /// every queued command deterministically, then best-effort disables the
    /// transport.
    async fn run_shutdown_sequence(&mut self) {
        self.commands.close();
        // Drain the mailbox and fail every queued command to notify about shutdown.
        while let Ok(command) = self.commands.try_recv() {
            Self::fail_queued_command(command);
        }

        // Notify lifecycle hooks before the transport goes down, exactly as
        // an ordinary disable does, so keep-alive tasks don't outlive the
        // transport through shutdown.
        deinitialize_all(&self.resources.initializers).await;

        let disable_result = self.resources.transport_control.disable().await;
        if let Err(error) = &disable_result {
            tracing::error!(%error, "Failed to disable transport during communication shutdown");
        }

        let mut state = self.state.lock();
        state.state = match disable_result {
            Ok(()) => CommunicationState::Disabled,
            Err(error) => {
                CommunicationState::Error(CommunicationOperationFailure::TransportFailure {
                    operation: CommunicationOperation::Disable,
                    error: error.to_string(),
                })
            }
        };
        state.disable_owner = None;
        state.enabling_result = None;
        state.detection_in_flight = None;
        drop(state);
    }

    fn fail_queued_command(command: LifecycleCommand) {
        match command {
            LifecycleCommand::Activate {
                operation, reply, ..
            } => {
                let _ = reply.send(Err(CommunicationOperationFailure::ShuttingDown {
                    operation,
                }));
            }
            LifecycleCommand::Redetect { reply, .. } => {
                let _ = reply.send(Err(CommunicationOperationFailure::ShuttingDown {
                    operation: CommunicationOperation::Detect,
                }));
            }
            LifecycleCommand::RegisterVariantDetection { reply, .. } => {
                let _ = reply.send(Err(CommunicationOperationFailure::ShuttingDown {
                    operation: CommunicationOperation::RegisterVariantDetection,
                }));
            }
            LifecycleCommand::Disable { reply, .. } => {
                let _ = reply.send(Err(CommunicationOperationFailure::ShuttingDown {
                    operation: CommunicationOperation::Disable,
                }));
            }
            LifecycleCommand::ReleaseDisableLease { reply, .. } => {
                let _ = reply.send(Err(CommunicationOperationFailure::ShuttingDown {
                    operation: CommunicationOperation::Resume,
                }));
            }
            LifecycleCommand::RegisterLifecycleHook { reply, .. } => {
                let _ = reply.send(Err(CommunicationOperationFailure::ShuttingDown {
                    operation: CommunicationOperation::RegisterLifecycleHook,
                }));
            }
        }
    }
}
