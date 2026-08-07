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
//! touches the physical transport, the registered initializer list, and HTTP
//! protection ownership - no other task reaches into those resources, so the
//! worker's single-threaded loop needs no internal synchronization over them.
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

use cda_interfaces::communication_control::{CommunicationInitializer, TransportControl};
use tokio::sync::{mpsc, oneshot};

use super::{
    disable::DisableLeaseId,
    operation::{CommunicationOperation, CommunicationOperationFailure},
    state::{CommunicationState, CommunicationStateStore},
};
use crate::http_protection::{
    config::HttpProtectionConfig,
    owned::OwnedHttpProtection,
    registry::{HttpProtectionError, HttpProtectionRegistry},
};

/// Bounded admission capacity of the lifecycle worker mailbox.
pub(crate) const LIFECYCLE_WORKER_CAPACITY: usize = 8;

/// Reply channel shared by every activation-shaped command (`Activate`,
/// `Detect`, and `ReleaseDisableLease`'s resume).
pub(crate) type ActivationReply =
    oneshot::Sender<Result<CommunicationState, CommunicationOperationFailure>>;

/// A plugin-authorized lifecycle operation submitted to the worker.
pub(crate) enum LifecycleCommand {
    /// Runs the physical activation sequence: ensure protection, activate
    /// transport, run initializers in registration order.
    Activate {
        operation: CommunicationOperation,
        reply: ActivationReply,
    },
    /// Runs variant re-detection only: the registered initializers, in order.
    /// Unlike `Activate`, this never touches `ensure_protected` or
    /// `transport_control` -- the transport is already up and this operation
    /// is not authorized to change it. Only reachable from `Enabled` (see
    /// `CommunicationHandle::claim_or_join`).
    Redetect { reply: ActivationReply },
    /// Runs the physical disable sequence for the exclusive lease `id`, which
    /// the caller has already synchronously claimed in `CommunicationStateStore`.
    Disable {
        id: DisableLeaseId,
        reply: oneshot::Sender<Result<(), CommunicationOperationFailure>>,
    },
    /// Atomically claims and executes a queued `DisableLease::release()`.
    ///
    /// Unlike `Activate`/`Disable`, the state claim (validating `id` against
    /// the current disable owner and `DisabledExclusive` state) happens here,
    /// inside the worker, not synchronously before enqueueing. This is what
    /// makes release cancellation-safe: nothing shared changes until the
    /// worker actually dequeues this command.
    ReleaseDisableLease {
        id: DisableLeaseId,
        reply: ActivationReply,
    },
    /// Appends a post-activation initializer to the worker-owned registration
    /// list. Ordering is exact: any `Activate`/`Detect` processed after this
    /// command includes it; anything processed earlier in the queue does not.
    RegisterInitializer {
        initializer: Arc<dyn CommunicationInitializer>,
        reply: oneshot::Sender<()>,
    },
}

/// Private lifecycle-owned communication protection state.
///
/// Exclusively touched by the worker's single-threaded loop (moved here from
/// the framework-wide `CommunicationHandle` now that all physical lifecycle
/// work is worker-owned), so no internal locking is needed.
struct WorkerProtection {
    registry: HttpProtectionRegistry,
    config: HttpProtectionConfig,
    owner: Option<OwnedHttpProtection>,
}

impl WorkerProtection {
    fn new(registry: HttpProtectionRegistry, config: HttpProtectionConfig) -> Self {
        Self {
            registry,
            config,
            owner: None,
        }
    }

    /// Installs communication protection only when no prior owner exists.
    fn ensure_protected(&mut self) -> Result<(), HttpProtectionError> {
        if self.owner.is_some() {
            return Ok(());
        }
        let new_owner = self.registry.protect(self.config.clone())?;
        self.owner = Some(new_owner);
        Ok(())
    }

    /// Installs the initial protection. Asserts no owner exists yet, unlike
    /// [`ensure_protected`](Self::ensure_protected)'s silent no-op, since this
    /// is only ever called once, at startup.
    fn install_initial(&mut self) -> Result<(), HttpProtectionError> {
        assert!(
            self.owner.is_none(),
            "communication protection must not already be installed"
        );
        let new_owner = self.registry.protect(self.config.clone())?;
        self.owner = Some(new_owner);
        Ok(())
    }

    /// Lifts the current protection, leaving no active owner.
    fn deactivate(&mut self) {
        self.owner.take();
    }
}

/// Durable resources exclusively owned by the lifecycle worker's task.
///
/// Constructed via [`new_resources`] and, once installed via
/// [`install_initial_protection`], moved into the task started by [`spawn`].
/// No other task ever touches this type.
pub(crate) struct WorkerResources {
    transport_control: Arc<dyn TransportControl>,
    initializers: Vec<Arc<dyn CommunicationInitializer>>,
    protection: Option<WorkerProtection>,
}

impl WorkerResources {
    fn ensure_protected(&mut self) -> Result<(), HttpProtectionError> {
        match &mut self.protection {
            Some(protection) => protection.ensure_protected(),
            None => Ok(()),
        }
    }

    fn deactivate_protection(&mut self) {
        if let Some(protection) = &mut self.protection {
            protection.deactivate();
        }
    }
}

/// Constructs the durable resources the worker will own, without installing
/// any HTTP protection yet.
pub(crate) fn new_resources(
    transport_control: Arc<dyn TransportControl>,
    restriction_config: Option<(HttpProtectionRegistry, HttpProtectionConfig)>,
) -> WorkerResources {
    WorkerResources {
        transport_control,
        initializers: Vec::new(),
        protection: restriction_config
            .map(|(registry, config)| WorkerProtection::new(registry, config)),
    }
}

/// Installs the initial protection record before the worker starts
/// processing commands.
///
/// # Errors
///
/// Returns an error when the protection registry is unavailable or
/// `resources` was constructed without a restriction config.
pub(crate) fn install_initial_protection(
    resources: &mut WorkerResources,
) -> Result<(), CommunicationOperationFailure> {
    let protection = resources.protection.as_mut().ok_or_else(|| {
        CommunicationOperationFailure::ProtectionFailure {
            operation: CommunicationOperation::Activate,
            error: "communication protection state was not configured".to_owned(),
        }
    })?;
    protection
        .install_initial()
        .map_err(|error| CommunicationOperationFailure::ProtectionFailure {
            operation: CommunicationOperation::Activate,
            error: error.to_string(),
        })
}

/// Runs the physical activation sequence shared by `Activate`, `Detect`, and
/// lease `release()`: ensure protection, activate transport, run initializers.
///
/// Protection is deactivated **only on success**. On any failure the caller
/// (transport or an initializer) leaves protection installed so pending ECU
/// requests keep receiving the configured response until a later authorized
/// trigger retries successfully.
async fn run_activation(
    resources: &mut WorkerResources,
    operation: CommunicationOperation,
) -> Result<CommunicationState, CommunicationOperationFailure> {
    if let Err(error) = resources.ensure_protected() {
        return Err(CommunicationOperationFailure::ProtectionFailure {
            operation,
            error: error.to_string(),
        });
    }

    if let Err(error) = resources.transport_control.enable().await {
        return Err(CommunicationOperationFailure::TransportFailure {
            operation,
            error: error.to_string(),
        });
    }

    for initializer in resources.initializers.clone() {
        if let Err(error) = initializer.initialize().await {
            let failure = CommunicationOperationFailure::InitializerFailure {
                initializer: initializer.name().to_owned(),
                error: error.to_string(),
            };
            if let Err(disable_error) = resources.transport_control.disable().await {
                tracing::error!(
                    %disable_error,
                    "failed to disable transport after initializer failure"
                );
            }
            return Err(failure);
        }
    }

    resources.deactivate_protection();
    Ok(CommunicationState::Enabled)
}

/// Runs variant re-detection: the registered initializers only, in order.
///
/// Deliberately does **not** call `ensure_protected` or touch
/// `transport_control` -- unlike `run_activation`, this operation only ever
/// runs while communication is already `Enabled` (the transport is up and
/// protection is already lifted), and is not authorized to change either. On
/// failure, protection is *not* reinstalled and the transport is *not*
/// disabled: the caller (`Enabled`, re-detection) did not bring either up, so
/// it does not tear either down. This differs deliberately from
/// `run_activation`, which does disable the transport on initializer failure
/// because it brought the transport up itself.
async fn run_redetection(
    resources: &WorkerResources,
) -> Result<CommunicationState, CommunicationOperationFailure> {
    for initializer in resources.initializers.clone() {
        if let Err(error) = initializer.initialize().await {
            return Err(CommunicationOperationFailure::InitializerFailure {
                initializer: initializer.name().to_owned(),
                error: error.to_string(),
            });
        }
    }
    Ok(CommunicationState::Enabled)
}

/// The capacity-8 lifecycle worker task body.
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
}

/// The receiving halves paired with a [`WorkerSender`], held separately until
/// [`spawn`] actually starts the task.
///
/// Split from [`channel`] so a [`WorkerSender`] (and thus a fully functional
/// [`super::controller::CommunicationHandle`]) can exist -- and be handed to a
/// plugin builder -- *before* [`spawn`] runs: the builder can fail, and only
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
///
/// Callers finish preparing `resources` (installing initial protection)
/// *before* calling this, so the task never observes a resources value that
/// changes ownership mid-flight.
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
    tokio::spawn(worker.run())
}

impl LifecycleWorker {
    /// Known, documented gap (plan step 9, "cancel/join active initialization
    /// work"): shutdown does **not** preemptively cancel a command already
    /// being processed. `handle_command` is awaited inline in the `select!`
    /// arm below, so if shutdown arrives while, say, an `Activate` is
    /// blocked inside `transport_control.enable()`, the shutdown signal just
    /// waits in `shutdown_rx`'s buffer (unbounded, so this never blocks the
    /// *sender*) until that command finishes; only then does the next loop
    /// iteration observe and process it. Two things keep this safe rather
    /// than merely tolerable: first, because commands and shutdown share this
    /// one sequential loop, shutdown can never *race* an in-flight command's
    /// physical work the way the pre-worker detached-task design could --
    /// there is never a window where shutdown's own teardown runs
    /// concurrently with a command still touching the transport. Second,
    /// admission itself closes immediately (`CommunicationHandle::shutdown`
    /// sets `shutting_down` before this task ever sees the signal), so no
    /// *new* work can be accepted while an old command finishes.
    ///
    /// What this does not give you is bounded shutdown latency: a command
    /// stuck forever (a hung transport call, say) delays shutdown forever
    /// too. True preemptive cancellation needs a cancellable unit of work
    /// smaller than "one command," which needs the `VehicleRuntimeFactory`
    /// generation model this iteration does not yet have. See ADR-006.
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
                    match maybe_command {
                        Some(command) => self.handle_command(command).await,
                        None => break,
                    }
                }
            }
        }
    }

    async fn handle_command(&mut self, command: LifecycleCommand) {
        match command {
            LifecycleCommand::Activate { operation, reply } => {
                // Unlike `ReleaseDisableLease`, the claiming `CommunicationHandle`
                // owns publishing the final state for this command (see
                // `CommunicationHandle::claim_or_join`'s detached task) -- it
                // needs to run regardless of whether the *caller* of
                // `activate()`/`trigger_detection()` is later cancelled, and
                // already does so independently of this reply.
                let result = run_activation(&mut self.resources, operation).await;
                let _ = reply.send(result);
            }
            LifecycleCommand::Redetect { reply } => {
                // Same ownership note as `Activate` above: the claiming
                // `CommunicationHandle` publishes the final state.
                let result = run_redetection(&self.resources).await;
                let _ = reply.send(result);
            }
            LifecycleCommand::Disable { id, reply } => {
                let result = self.execute_disable(id).await;
                let _ = reply.send(result);
            }
            LifecycleCommand::ReleaseDisableLease { id, reply } => {
                let result = self.execute_release(id).await;
                let _ = reply.send(result);
            }
            LifecycleCommand::RegisterInitializer { initializer, reply } => {
                self.resources.initializers.push(initializer);
                let _ = reply.send(());
            }
        }
    }

    /// Publishes the final state for a completed activation-shaped operation.
    fn finish_activation(
        &self,
        result: &Result<CommunicationState, CommunicationOperationFailure>,
    ) {
        let mut state = self.state.lock();
        state.state = match result {
            Ok(new_state) => new_state.clone(),
            Err(failure) => CommunicationState::Error(failure.clone()),
        };
        state.activation_result = None;
    }

    async fn execute_disable(
        &mut self,
        id: DisableLeaseId,
    ) -> Result<(), CommunicationOperationFailure> {
        if let Err(error) = self.resources.ensure_protected() {
            self.finish_failed_disable(id);
            return Err(CommunicationOperationFailure::ProtectionFailure {
                operation: CommunicationOperation::Disable,
                error: error.to_string(),
            });
        }

        match self.resources.transport_control.disable().await {
            Ok(()) => {
                let mut state = self.state.lock();
                if state.disable_owner == Some(id) {
                    state.state = CommunicationState::DisabledExclusive;
                    Ok(())
                } else {
                    tracing::debug!(current = ?state.state, "disable rejected");
                    Err(CommunicationOperationFailure::TransitionFailure {
                        operation: CommunicationOperation::Disable,
                    })
                }
            }
            Err(error) => {
                self.finish_failed_disable(id);
                Err(CommunicationOperationFailure::TransportFailure {
                    operation: CommunicationOperation::Disable,
                    error: error.to_string(),
                })
            }
        }
    }

    fn finish_failed_disable(&mut self, id: DisableLeaseId) {
        {
            let mut state = self.state.lock();
            if state.disable_owner == Some(id) {
                state.disable_owner = None;
                state.state = CommunicationState::Enabled;
            }
        }
        self.resources.deactivate_protection();
    }

    /// Atomically claims and executes a queued release: validates `id`
    /// against the current disable owner and `DisabledExclusive` state right
    /// here (not before enqueueing), then runs the same activation sequence
    /// as `Activate`/`Detect`.
    async fn execute_release(
        &mut self,
        id: DisableLeaseId,
    ) -> Result<CommunicationState, CommunicationOperationFailure> {
        {
            let mut state = self.state.lock();
            if state.disable_owner != Some(id)
                || !matches!(state.state, CommunicationState::DisabledExclusive)
            {
                tracing::debug!(current = ?state.state, "release rejected: stale or conflicting lease");
                return Err(super::disable::stale_resume_failure());
            }
            state.disable_owner = None;
            state.state = CommunicationState::Enabling;
        }

        let result = run_activation(&mut self.resources, CommunicationOperation::Resume).await;
        self.finish_activation(&result);
        result
    }

    /// Out-of-band shutdown barrier (plan step 9): closes ingress, fails
    /// every queued command deterministically, then best-effort disables the
    /// transport while preserving protection through teardown.
    async fn run_shutdown_sequence(&mut self) {
        self.commands.close();
        while let Ok(command) = self.commands.try_recv() {
            Self::fail_queued_command(command);
        }

        if let Err(error) = self.resources.ensure_protected() {
            tracing::error!(%error, "failed to install protection during communication shutdown");
        }
        let disable_result = self.resources.transport_control.disable().await;
        if let Err(error) = &disable_result {
            tracing::error!(%error, "failed to disable transport during communication shutdown");
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
        state.activation_result = None;
        drop(state);

        // Shutdown is terminal: this task is about to exit, which would
        // otherwise drop `self.resources` and, with it, the `OwnedHttpProtection`
        // we just carefully preserved above -- undoing "preserve protection
        // through teardown" the instant it was satisfied. Nothing will ever
        // call `deactivate` again, so intentionally leak it: protection stays
        // installed until the process itself exits.
        if let Some(protection) = self.resources.protection.take() {
            std::mem::forget(protection);
        }
    }

    fn fail_queued_command(command: LifecycleCommand) {
        match command {
            LifecycleCommand::Activate { operation, reply } => {
                let _ = reply.send(Err(CommunicationOperationFailure::ShuttingDown {
                    operation,
                }));
            }
            LifecycleCommand::Redetect { reply } => {
                let _ = reply.send(Err(CommunicationOperationFailure::ShuttingDown {
                    operation: CommunicationOperation::Detect,
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
            LifecycleCommand::RegisterInitializer { reply, .. } => {
                let _ = reply.send(());
            }
        }
    }
}
