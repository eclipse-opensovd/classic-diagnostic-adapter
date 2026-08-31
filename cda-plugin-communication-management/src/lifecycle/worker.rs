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

/// Reply channel for state-changing commands.
pub(crate) type ActivationReply =
    oneshot::Sender<Result<CommunicationState, CommunicationOperationFailure>>;

/// A plugin-authorized lifecycle operation submitted to the worker.
pub(crate) enum LifecycleCommand {
    /// Runs the physical activation sequence: activate transport, run
    /// initializers in registration order.
    Activate {
        operation: CommunicationOperation,
        /// Optional detector to run after initialization.
        detector: Option<Arc<dyn CommunicationVariantDetection>>,
        reply: ActivationReply,
    },
    /// Runs the registered variant detector.
    Redetect {
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
    /// Releases an exclusive disable lease.
    ReleaseDisableLease {
        id: DisableLeaseId,
        reply: ActivationReply,
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

/// Enables transport, initializes hooks, then optionally runs detection.
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

    if let Some(detector) = &detector
        && let Err(error) = detector.detect().await
    {
        // The detector failed, so tear down everything already initialized.
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

/// Runs the registered variant detector. No detector is a successful no-op.
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
                operation,
                detector,
                reply,
            } => {
                let result = run_activation(&self.resources, operation, detector).await;
                let _ = reply.send(result);
            }
            LifecycleCommand::Redetect { detector, reply } => {
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

    /// Publishes the result of an enabling operation.
    fn finish_enabling(
        &self,
        result: Result<CommunicationState, CommunicationOperationFailure>,
        operation: CommunicationOperation,
    ) -> Result<CommunicationState, CommunicationOperationFailure> {
        self.state.lock().publish_enabling_result(result, operation)
    }

    /// Disables the transport for the current lease owner.
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

        if !was_enabled {
            let mut state = self.state.lock();
            state.state = CommunicationState::DisabledExclusive;
            return Ok(());
        }

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

    /// Releases a queued disable lease and restores its recorded state.
    #[tracing::instrument(skip_all, fields(dlt_context = dlt_ctx!("COMM")))]
    async fn execute_release(
        &self,
        id: DisableLeaseId,
    ) -> Result<CommunicationState, CommunicationOperationFailure> {
        let (result_tx, result_rx) = watch::channel(None);
        let detector = {
            let mut state = self.state.lock();
            let Some(owner) = state.disable_owner.filter(|owner| owner.id == id) else {
                tracing::debug!("Release rejected: unknown or conflicting lease");
                return Err(super::disable::stale_resume_failure());
            };

            match transition::decide(&state, false, LifecycleRequest::Resume) {
                LifecycleDecision::Claim(CommunicationOperation::Resume) => {
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
                LifecycleDecision::SettleDisabled => {
                    state.disable_owner = None;
                    state.state = CommunicationState::Disabled;
                    return Ok(CommunicationState::Disabled);
                }
                LifecycleDecision::ShuttingDown => {
                    return Err(CommunicationOperationFailure::ShuttingDown {
                        operation: CommunicationOperation::Resume,
                    });
                }
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
