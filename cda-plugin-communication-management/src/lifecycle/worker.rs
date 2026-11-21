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
//! lifecycle-state transitions synchronously and submits the resulting work as a
//! [`LifecycleCommand`] to this worker. The worker is the only task touching the
//! physical transport and the registered initializer list, so its loop needs no
//! synchronization over them.
//!
//! Claiming has to stay synchronous, because `DisableLease`'s drop-based defer
//! and guard acquisition cannot `.await`. The physical work a claim authorizes
//! is async and must be serialized, so it is handed off here.
//!
//! The mailbox capacity bounds admission only. An enqueued [`LifecycleCommand`]
//! is always processed or explicitly failed, never dropped. Shutdown uses a
//! separate unbounded channel (see [`WorkerSender::shutdown`]), so a full
//! mailbox cannot block it.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use cda_interfaces::{
    communication_control::{
        CommunicationLifecycle, CommunicationOperation, CommunicationOperationFailure,
        CommunicationState, CommunicationVariantDetection, DetectionPhase, TransportControl,
    },
    dlt_ctx,
};
use tokio::sync::{mpsc, oneshot, watch};

use super::{
    disable::{DisableLeaseId, DisableOwner, DisableReason},
    state::{
        ActivationKind, CommunicationStateStore, DetectionStage, LifecyclePhase,
        OperationResultReceiver, detection_mode,
    },
    transition::{self, LifecycleDecision, LifecycleRequest},
};

/// Bounded admission capacity of the lifecycle worker mailbox.
pub(crate) const LIFECYCLE_WORKER_CAPACITY: usize = 8;

/// Reply channel for state-changing commands.
pub(crate) type ActivationReply =
    oneshot::Sender<Result<CommunicationState, CommunicationOperationFailure>>;

/// A plugin-authorized lifecycle operation submitted to the worker.
pub(crate) enum LifecycleCommand {
    /// Runs the physical activation sequence: activate transport, run
    /// initializers in registration order, then publish the result and, on
    /// success, call every hook's `on_enabled()` before replying.
    Activate {
        kind: ActivationKind,
        attempt: OperationResultReceiver,
        /// Optional detector to run after initialization.
        detector: Option<Arc<dyn CommunicationVariantDetection>>,
        reply: ActivationReply,
    },
    /// Runs the registered variant detector.
    Redetect {
        attempt: OperationResultReceiver,
        /// `None` is a successful no-op.
        detector: Option<Arc<dyn CommunicationVariantDetection>>,
        reply: ActivationReply,
    },
    /// Disables transport for the exclusive lease `id`.
    Disable {
        id: DisableLeaseId,
        reason: DisableReason,
        reply: oneshot::Sender<Result<(), CommunicationOperationFailure>>,
    },
    /// Releases an exclusive disable lease: [`LifecycleRequest::Resume`] restores
    /// what it displaced, [`LifecycleRequest::ResumeAndDetect`] hands it over to a
    /// full activation with variant detection.
    ReleaseDisableLease {
        id: DisableLeaseId,
        request: LifecycleRequest,
        reply: ActivationReply,
    },
    /// Finishes an exclusive disable lease without activating: consumes the
    /// lease and stays disabled.
    FinishDisableLease {
        id: DisableLeaseId,
        reply: oneshot::Sender<Result<(), CommunicationOperationFailure>>,
    },
    /// Registers a lifecycle hook.
    RegisterLifecycleHook {
        initializer: Arc<dyn CommunicationLifecycle>,
        reply: oneshot::Sender<Result<(), CommunicationOperationFailure>>,
    },
    /// Registers the whole-vehicle variant detector.
    RegisterVariantDetection {
        detector: Arc<dyn CommunicationVariantDetection>,
        reply: oneshot::Sender<Result<(), CommunicationOperationFailure>>,
    },
}

/// Resources owned by the lifecycle worker. The variant detector lives in the
/// shared state.
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

/// Deinitializes lifecycle hooks in reverse registration order.
async fn deinitialize_all(initializers: &[Arc<dyn CommunicationLifecycle>]) {
    for initializer in initializers.iter().rev() {
        initializer.deinitialize().await;
    }
}

/// Calls `on_enabled()` on every registered hook, in registration order.
///
/// Only called once the lifecycle state has actually been published as
/// `Enabled` (see [`LifecycleWorker::run_activation`]), so every hook's
/// `on_enabled` observes a settled `Enabled` state.
async fn on_enabled_all(initializers: &[Arc<dyn CommunicationLifecycle>]) {
    for initializer in initializers {
        initializer.on_enabled().await;
    }
}

/// Enables transport and initializes hooks, rolling back on failure.
async fn bring_up(
    resources: &WorkerResources,
    operation: CommunicationOperation,
) -> Result<(), CommunicationOperationFailure> {
    if let Err(error) = resources.transport_control.enable().await {
        return Err(CommunicationOperationFailure::TransportFailure {
            operation,
            error: error.to_string(),
        });
    }

    for (index, initializer) in resources.initializers.iter().enumerate() {
        if let Err(error) = initializer.initialize().await {
            // Tear down what already initialized.
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
    Ok(())
}

/// Runs the detection stage of an activation, tearing down hooks and transport
/// when it fails.
async fn detect_or_tear_down(
    resources: &WorkerResources,
    detector: &Arc<dyn CommunicationVariantDetection>,
) -> Result<CommunicationState, CommunicationOperationFailure> {
    let Err(error) = detector.detect(DetectionPhase::Activation).await else {
        return Ok(CommunicationState::Enabled);
    };
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
    Err(failure)
}

/// Runs the registered variant detector. No detector is a successful no-op.
async fn run_redetection(
    detector: Option<Arc<dyn CommunicationVariantDetection>>,
) -> Result<CommunicationState, CommunicationOperationFailure> {
    if let Some(detector) = &detector
        && let Err(error) = detector.detect(DetectionPhase::Redetection).await
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
    /// Blocks new commands as soon as shutdown is requested.
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

    /// Requests shutdown and waits for completion.
    pub(crate) async fn shutdown(&self) {
        self.admission_closed.store(true, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        if self.shutdown_tx.send(tx).is_ok() {
            let _ = rx.await;
        }
    }

    pub(crate) fn request_shutdown(&self) {
        self.admission_closed.store(true, Ordering::SeqCst);
        let (tx, _rx) = oneshot::channel();
        let _ = self.shutdown_tx.send(tx);
    }
}

/// Receiving halves held until the worker starts.
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

/// Spawns the lifecycle worker task.
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
    /// Shutdown is not guaranteed to execute when a command is stuck forever.
    /// Preemptive cancellation is not yet implemented (see #490).
    async fn run(mut self) {
        loop {
            tokio::select! {
                biased;
                Some(completion) = self.shutdown_rx.recv() => {
                    self.run_shutdown_sequence().await;
                    let _ = completion.send(());
                    // Complete concurrent shutdown requests.
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
                kind,
                attempt,
                detector,
                reply,
            } => {
                if let Err(failure) = self
                    .state
                    .lock()
                    .validate_attempt(kind.operation(), &attempt)
                {
                    let _ = reply.send(Err(failure));
                    return;
                }
                let result = self.run_activation(kind, &attempt, detector).await;
                let _ = reply.send(result);
            }
            LifecycleCommand::Redetect {
                detector,
                attempt,
                reply,
            } => {
                if let Err(failure) = self
                    .state
                    .lock()
                    .validate_attempt(CommunicationOperation::Detect, &attempt)
                {
                    let _ = reply.send(Err(failure));
                    return;
                }
                let result = run_redetection(detector).await;
                let _ = reply.send(result);
            }
            LifecycleCommand::Disable { id, reason, reply } => {
                tracing::debug!(?reason, "Disabling communication");
                let result = self.execute_disable(id).await;
                let _ = reply.send(result);
            }
            LifecycleCommand::ReleaseDisableLease { id, request, reply } => {
                let result = self.execute_release(id, request).await;
                let _ = reply.send(result);
            }
            LifecycleCommand::FinishDisableLease { id, reply } => {
                let result = self.execute_finish(id);
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

    /// Brings transport and hooks up, runs the detection stage the attempt
    /// requires by then, and publishes the result. On success, calls every
    /// hook's `on_enabled()` after publishing.
    async fn run_activation(
        &self,
        kind: ActivationKind,
        attempt: &OperationResultReceiver,
        detector: Option<Arc<dyn CommunicationVariantDetection>>,
    ) -> Result<CommunicationState, CommunicationOperationFailure> {
        let result = if let Err(failure) = bring_up(&self.resources, kind.operation()).await {
            self.finish_enabling(Err(failure), kind, attempt)
        } else {
            // Decided only now, so an explicit detection request that joined
            // while transport and hooks came up is still honored.
            let stage = self
                .state
                .lock()
                .enter_detection_stage(kind, attempt, detector);
            let (result, physically_up) = match stage {
                DetectionStage::Settled(result) => (result, true),
                DetectionStage::Run(detector) => {
                    let physical = detect_or_tear_down(&self.resources, &detector).await;
                    let physically_up = physical.is_ok();
                    (self.finish_enabling(physical, kind, attempt), physically_up)
                }
            };
            match result {
                // The attempt was failed closed or replaced while the worker
                // brought communication up, so the published state does not
                // claim it. Tear down to match it; shutdown tears down itself.
                Err(ref failure)
                    if physically_up
                        && !matches!(
                            failure,
                            CommunicationOperationFailure::ShuttingDown { .. }
                        ) =>
                {
                    tracing::warn!(
                        ?kind,
                        %failure,
                        "Activation completed for a stale attempt, tearing it down"
                    );
                    deinitialize_all(&self.resources.initializers).await;
                    if let Err(error) = self.resources.transport_control.disable().await {
                        tracing::error!(%error, "Tearing down a stale activation failed");
                    }
                    result
                }
                result => result,
            }
        };
        if matches!(result, Ok(CommunicationState::Enabled)) {
            on_enabled_all(&self.resources.initializers).await;
        }
        result
    }

    /// Publishes the result of an enabling operation.
    fn finish_enabling(
        &self,
        result: Result<CommunicationState, CommunicationOperationFailure>,
        kind: ActivationKind,
        attempt: &OperationResultReceiver,
    ) -> Result<CommunicationState, CommunicationOperationFailure> {
        self.state
            .lock()
            .publish_enabling_result(result, kind, attempt)
    }

    /// Disables the transport for the current lease owner.
    async fn execute_disable(
        &self,
        id: DisableLeaseId,
    ) -> Result<(), CommunicationOperationFailure> {
        let tears_down = {
            let state = self.state.lock();
            match state.phase() {
                LifecyclePhase::Disabling(owner) if owner.id == id => owner.tears_down,
                _ => {
                    tracing::debug!("Disable rejected: unknown or conflicting owner");
                    return Err(CommunicationOperationFailure::TransitionFailure {
                        operation: CommunicationOperation::Disable,
                    });
                }
            }
        };

        if !tears_down {
            return self.state.lock().publish_disable_result(id, Ok(()));
        }

        deinitialize_all(&self.resources.initializers).await;

        match self.resources.transport_control.disable().await {
            Ok(()) => self.state.lock().publish_disable_result(id, Ok(())),
            Err(error) => {
                let failure = CommunicationOperationFailure::TransportFailure {
                    operation: CommunicationOperation::Disable,
                    error: error.to_string(),
                };
                self.state.lock().publish_disable_result(id, Err(failure))
            }
        }
    }

    /// Releases a queued disable lease. [`LifecycleRequest::Resume`] restores the
    /// state it displaced; [`LifecycleRequest::ResumeAndDetect`] hands it over to a
    /// full activation with variant detection, whatever it displaced and also when
    /// automatic detection is `Never`, like an explicit detection request.
    ///
    /// Checking ownership and claiming the activation happen in one lock hold, so
    /// nothing else can bring communication up in between.
    #[tracing::instrument(skip_all, fields(dlt_context = dlt_ctx!("COMM")))]
    async fn execute_release(
        &self,
        id: DisableLeaseId,
        request: LifecycleRequest,
    ) -> Result<CommunicationState, CommunicationOperationFailure> {
        let (result_tx, result_rx) = watch::channel(None);
        let (kind, detector) = {
            let mut state = self.state.lock();
            let Some(owner) = state.disable_owner().filter(|owner| owner.id == id) else {
                tracing::debug!(?request, "Release rejected: unknown or conflicting lease");
                return Err(super::disable::stale_release_failure(request));
            };

            match transition::decide(&state, false, request) {
                LifecycleDecision::Claim(kind) => {
                    let detects =
                        request == LifecycleRequest::ResumeAndDetect || owner.resume_detects;
                    let detector = if detects {
                        state.variant_detector()
                    } else {
                        None
                    };
                    state.claim_activation_for(
                        request,
                        kind,
                        result_rx.clone(),
                        detection_mode(detector.as_ref()),
                    )?;
                    (kind, detector)
                }
                LifecycleDecision::SettleDisabled => {
                    state.settle_disabled(id);
                    return Ok(CommunicationState::Disabled);
                }
                LifecycleDecision::ShuttingDown => {
                    return Err(CommunicationOperationFailure::ShuttingDown {
                        operation: request.operation(),
                    });
                }
                LifecycleDecision::Conflict
                | LifecycleDecision::ClaimDetection
                | LifecycleDecision::Join(_)
                | LifecycleDecision::JoinDetection
                | LifecycleDecision::AlreadyEnabled
                | LifecycleDecision::ClaimDisable { .. }
                | LifecycleDecision::GuardsHeld
                | LifecycleDecision::LeaseHeld(_)
                | LifecycleDecision::NotEnabled => {
                    tracing::debug!(
                        ?request,
                        "Release rejected: state no longer matches this lease"
                    );
                    return Err(super::disable::stale_release_failure(request));
                }
            }
        };

        let result = self.run_activation(kind, &result_rx, detector).await;
        let _ = result_tx.send(Some(result.clone()));
        result
    }

    /// Finishes a disable lease without activating, staying disabled regardless
    /// of what the lease displaced.
    ///
    /// Unlike [`execute_release`](Self::execute_release), never claims
    /// [`CommunicationOperation::Resume`]: only the lease holder can call this
    /// and it consumes the lease, so no concurrent caller can join.
    fn execute_finish(&self, id: DisableLeaseId) -> Result<(), CommunicationOperationFailure> {
        // One lock hold: checking ownership and consuming the lease must be
        // atomic, or a concurrent caller could take the lease in between.
        let mut state = self.state.lock();
        if state.shutting_down {
            return Err(CommunicationOperationFailure::ShuttingDown {
                operation: CommunicationOperation::FinishDisableLease,
            });
        }
        if !DisableOwner::owns(state.disable_owner(), id) {
            tracing::debug!("Finish rejected: unknown or conflicting lease");
            return Err(super::disable::stale_finish_failure());
        }
        state.settle_disabled(id);
        Ok(())
    }

    /// Fails queued commands and disables the transport.
    async fn run_shutdown_sequence(&mut self) {
        self.commands.close();
        while let Ok(command) = self.commands.try_recv() {
            Self::fail_queued_command(command);
        }

        deinitialize_all(&self.resources.initializers).await;

        let disable_result = self.resources.transport_control.disable().await;
        if let Err(error) = &disable_result {
            tracing::error!(%error, "Failed to disable transport during communication shutdown");
        }

        let mut state = self.state.lock();
        state.publish_shutdown(disable_result.map_err(|error| {
            CommunicationOperationFailure::TransportFailure {
                operation: CommunicationOperation::Disable,
                error: error.to_string(),
            }
        }));
        drop(state);
    }

    fn fail_queued_command(command: LifecycleCommand) {
        match command {
            LifecycleCommand::Activate { kind, reply, .. } => {
                let _ = reply.send(Err(CommunicationOperationFailure::ShuttingDown {
                    operation: kind.operation(),
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
            LifecycleCommand::ReleaseDisableLease { request, reply, .. } => {
                let _ = reply.send(Err(CommunicationOperationFailure::ShuttingDown {
                    operation: request.operation(),
                }));
            }
            LifecycleCommand::FinishDisableLease { reply, .. } => {
                let _ = reply.send(Err(CommunicationOperationFailure::ShuttingDown {
                    operation: CommunicationOperation::FinishDisableLease,
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
