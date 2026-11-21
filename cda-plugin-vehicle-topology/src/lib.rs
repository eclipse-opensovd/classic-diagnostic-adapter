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

//! Default vehicle topology plugin: the `networkreset` operation.
//!
//! An execution clears the persisted topology and/or runs a full rediscovery,
//! depending on its flags. At most one execution exists at a time. While it runs,
//! and until a rediscovery it started has finished, the network structure endpoint
//! answers `409 Conflict`, so clients never read a partially updated topology.

use std::{
    sync::{Arc, Mutex as StdMutex, MutexGuard, PoisonError},
    time::Duration,
};

use async_trait::async_trait;
use cda_interfaces::{
    communication_control::{
        CommunicationOperationFailure,
        disable::{DisableCommunication, DisableError, DisableGuard, DisableReason},
    },
    http_protection::registry::{
        HttpMethod, HttpProtectionConfig, HttpProtectionReason, HttpProtectionRegistry,
        HttpRouteMatcher, HttpStatusCode, OwnedHttpProtection,
    },
    topology::{
        NETWORK_STRUCTURE_ROUTE, NetworkReset, NetworkResetError, NetworkResetExecution,
        NetworkResetFailure, NetworkResetFlags, NetworkResetStatus, RediscoveryWait,
        TopologyClearError, VehicleTopologyPlugin,
    },
};
use tokio::sync::{Mutex, oneshot, watch};
use tokio_util::sync::CancellationToken;

/// Everything the default plugin needs from the CDA.
pub struct VehicleTopologyDeps {
    /// Persisted topology and ECU state operations.
    pub network_reset: Arc<dyn NetworkReset>,
    /// Exclusive transport ownership for the whole execution, so no diagnostics are running
    /// and the transport is down while the topology is reset. A rediscovery hands the lease
    /// over to the bring-up with detection
    /// ([`DisableGuard::release_with_detection`]).
    pub communication_disable: Arc<dyn DisableCommunication>,
    /// Whether a clear-only execution gives communication back to the state it had before
    /// (`init_mode` `Always` or `WhenNotPersisted`, which start communication on their own).
    /// Otherwise it stays down until the `init_mode` trigger brings it up.
    pub clear_resumes_transport: bool,
    /// Registry for the `409 Conflict` protection of the network structure.
    pub http_protections: HttpProtectionRegistry,
    /// Upper bound for the bring-up of the rediscovery, including its variant
    /// detection. Settling is bounded by the network reset's ticket (see
    /// [`NetworkReset::prepare_rediscovery`]). A rediscovery that has not returned after
    /// four times this bound is given up, so it cannot keep the network structure
    /// protected forever.
    pub rediscovery_timeout: Duration,
}

/// Factory for a vehicle topology plugin.
pub trait VehicleTopologyPluginBuilder: Send {
    /// Plugin produced by this factory.
    type Plugin: VehicleTopologyPlugin;
    /// Construction error.
    type Error: std::fmt::Display + Send;

    /// Builds the plugin from the runtime dependencies.
    fn build(
        self,
        deps: VehicleTopologyDeps,
    ) -> impl Future<Output = Result<Self::Plugin, Self::Error>> + Send;
}

/// Closure adapter for [`VehicleTopologyPluginBuilder`].
pub struct VehicleTopologyPluginFn<F>(F);

/// Wraps an async closure as a [`VehicleTopologyPluginBuilder`].
pub fn vehicle_topology_plugin_fn<F>(factory: F) -> VehicleTopologyPluginFn<F> {
    VehicleTopologyPluginFn(factory)
}

impl<F, Fut, P, E> VehicleTopologyPluginBuilder for VehicleTopologyPluginFn<F>
where
    F: FnOnce(VehicleTopologyDeps) -> Fut + Send,
    Fut: Future<Output = Result<P, E>> + Send,
    P: VehicleTopologyPlugin,
    E: std::fmt::Display + Send,
{
    type Plugin = P;
    type Error = E;

    async fn build(self, deps: VehicleTopologyDeps) -> Result<P, E> {
        self.0(deps).await
    }
}

/// Factory for the default vehicle topology plugin.
#[derive(Default)]
pub struct DefaultVehicleTopologyPluginBuilder;

impl VehicleTopologyPluginBuilder for DefaultVehicleTopologyPluginBuilder {
    type Plugin = DefaultVehicleTopologyPlugin;
    type Error = std::convert::Infallible;

    fn build(
        self,
        deps: VehicleTopologyDeps,
    ) -> impl Future<Output = Result<Self::Plugin, Self::Error>> + Send {
        std::future::ready(Ok(DefaultVehicleTopologyPlugin::new(deps)))
    }
}

/// Operation id used as the reason for the exclusive leases.
const OPERATION_ID: &str = "networkreset";

/// Multiple of the rediscovery timeout after which a rediscovery that has not
/// returned is considered wedged.
///
/// The execution itself already fails after one rediscovery timeout, but the
/// rediscovery keeps running and protecting the network structure so it is not
/// read half updated. A healthy rediscovery returns well within one timeout, so
/// four times that bound leaves ample margin while still guaranteeing that a
/// hanging detector cannot keep the network structure at `409` forever.
pub(crate) const REDISCOVERY_HANG_FACTOR: u32 = 4;

struct Running {
    execution: NetworkResetExecution,
    cancel: CancellationToken,
    /// Becomes `true` when the task has finished and the entry was updated or removed.
    done: watch::Receiver<bool>,
    /// A DELETE was requested; the task removes the entry when it finishes.
    deleting: bool,
}

/// Default [`VehicleTopologyPlugin`].
/// [[ dimpl~plugin-vehicle-topology-reset, networkreset operation with persisted list control, dimpl ]]
pub struct DefaultVehicleTopologyPlugin {
    deps: Arc<VehicleTopologyDeps>,
    /// A synchronous mutex: it is never held across an await point, so publishing the
    /// execution after the lease was acquired cannot be cancelled.
    current: Arc<StdMutex<Option<Running>>>,
    /// Serializes admission, so `current` is not held while the lease is acquired.
    /// Owned by the admission task, so it is held until the execution is published,
    /// also if the request that started it is dropped.
    admission: Arc<Mutex<()>>,
}

/// Locks the execution slot. A panic while it was held leaves a consistent entry
/// (all updates are single assignments), so a poisoned lock is used as is.
fn lock_current(current: &StdMutex<Option<Running>>) -> MutexGuard<'_, Option<Running>> {
    current.lock().unwrap_or_else(PoisonError::into_inner)
}

impl DefaultVehicleTopologyPlugin {
    /// Creates the plugin.
    #[must_use]
    pub fn new(deps: VehicleTopologyDeps) -> Self {
        Self {
            deps: Arc::new(deps),
            current: Arc::new(StdMutex::new(None)),
            admission: Arc::new(Mutex::new(())),
        }
    }

    /// [[ dimpl~plugin-vehicle-topology-retrieval-protection, The network structure endpoint answers 409 while a networkreset runs, dimpl ]]
    fn protect(&self) -> Result<OwnedHttpProtection, NetworkResetError> {
        self.deps
            .http_protections
            .protect(
                HttpProtectionConfig::new(
                    HttpProtectionReason::NetworkResetInProgress,
                    HttpStatusCode::CONFLICT,
                    "A network reset is in progress",
                )
                .with_selected_routes(vec![HttpRouteMatcher::new(
                    NETWORK_STRUCTURE_ROUTE,
                    vec![HttpMethod::GET],
                )]),
            )
            .map_err(|error| NetworkResetError::Failed(error.to_string()))
    }
}

/// Maps a refused communication lease to the reset error.
///
/// A conflicting lease means communication is being enabled or disabled, or another
/// operation (e.g. a runtime update) owns it exclusively. All of these end on their
/// own, so it is a retryable condition (HTTP 409) and not a conflict with another
/// network reset execution. A failed or failed-closed communication does not
/// conflict: the lease is granted from there, so a network reset can recover it.
fn map_disable_error(error: DisableError) -> NetworkResetError {
    match error {
        DisableError::Conflict => NetworkResetError::OperationsInProgress(
            "communication is being enabled or disabled, or is exclusively owned by another \
             operation, retry later"
                .to_owned(),
        ),
        DisableError::InUse => NetworkResetError::OperationsInProgress(
            "diagnostic operations are in progress".to_owned(),
        ),
        DisableError::Failed(failure) => NetworkResetError::Failed(failure.to_string()),
    }
}

#[async_trait]
impl VehicleTopologyPlugin for DefaultVehicleTopologyPlugin {
    /// Starts an execution, see [`VehicleTopologyPlugin::start_reset`].
    ///
    /// The `timeout` starts when the request is admitted, before the exclusive
    /// communication lease is acquired, so it includes waiting for that lease.
    async fn start_reset(
        &self,
        flags: NetworkResetFlags,
        timeout: Option<Duration>,
    ) -> Result<String, NetworkResetError> {
        if !flags.clear_persisted && !flags.trigger_detection {
            return Err(NetworkResetError::InvalidRequest(
                "clear_persisted and trigger_detection are both false, nothing to do".to_owned(),
            ));
        }
        let expiry = match timeout {
            Some(timeout) if timeout.is_zero() => {
                return Err(NetworkResetError::InvalidRequest(
                    "Timeout must be greater than 0".to_owned(),
                ));
            }
            Some(timeout) => Some(
                tokio::time::Instant::now()
                    .checked_add(timeout)
                    .ok_or_else(|| {
                        NetworkResetError::InvalidRequest("timeout is too large".to_owned())
                    })?,
            ),
            None => None,
        };
        // A concurrent start is still acquiring its lease: it is the running execution.
        let Ok(admission) = Arc::clone(&self.admission).try_lock_owned() else {
            return Err(NetworkResetError::ExecutionConflict);
        };
        if lock_current(&self.current).as_ref().is_some_and(|running| {
            running.execution.status == NetworkResetStatus::Running || running.deleting
        }) {
            return Err(NetworkResetError::ExecutionConflict);
        }
        let protection = self.protect()?;
        let deps = Arc::clone(&self.deps);
        let current = Arc::clone(&self.current);
        // The execution owns the transport: no diagnostics run and nothing talks
        // to the vehicle while the topology is reset. Everything from acquiring the
        // lease to publishing and spawning the execution runs in its own task, so a
        // dropped request cannot drop a granted lease (communication would stay down
        // with no execution recorded). `current` is not held meanwhile, so status
        // queries and DELETE are not blocked.
        let admitted = cda_interfaces::spawn_named!("networkreset-admission", async move {
            let _admission = admission;
            let lease = deps
                .communication_disable
                .disable(DisableReason::Custom(OPERATION_ID.to_owned()))
                .await
                .map_err(map_disable_error)?;
            Ok(launch(
                deps, &current, flags, lease, protection, expiry, timeout,
            ))
        });
        match admitted.await {
            Ok(result) => result,
            Err(error) => {
                tracing::error!(%error, "Network reset admission task failed");
                Err(NetworkResetError::Failed("internal error".to_owned()))
            }
        }
    }

    async fn list_resets(&self) -> Vec<NetworkResetExecution> {
        lock_current(&self.current)
            .as_ref()
            .map(|running| running.execution.clone())
            .into_iter()
            .collect()
    }

    async fn get_reset(&self, id: &str) -> Option<NetworkResetExecution> {
        lock_current(&self.current)
            .as_ref()
            .filter(|running| running.execution.id == id)
            .map(|running| running.execution.clone())
    }

    async fn delete_reset(&self, id: &str) -> bool {
        let mut done = {
            let mut current = lock_current(&self.current);
            let Some(running) = current.as_mut().filter(|r| r.execution.id == id) else {
                return false;
            };
            if running.execution.status != NetworkResetStatus::Running {
                *current = None;
                return true;
            }
            // Steps already started (clearing, enabling communication) finish; only
            // the waits for the rediscovery and for it to settle are cut short. The task removes
            // the entry itself, so a dropped request does not leave it behind.
            running.cancel.cancel();
            running.deleting = true;
            running.done.clone()
        };
        // An error means the sender is gone, i.e. the task has finished as well.
        let _ = done.wait_for(|finished| *finished).await;
        true
    }
}

/// Publishes a new execution that owns `lease` and spawns it. Synchronous, so
/// the execution is always recorded once the lease was granted.
fn launch(
    deps: Arc<VehicleTopologyDeps>,
    current: &Arc<StdMutex<Option<Running>>>,
    flags: NetworkResetFlags,
    lease: Box<dyn DisableGuard>,
    protection: OwnedHttpProtection,
    expiry: Option<tokio::time::Instant>,
    timeout: Option<Duration>,
) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    let cancel = CancellationToken::new();
    let state = Arc::clone(current);
    let task_cancel = cancel.clone();
    let task_id = id.clone();
    let (done_tx, done_rx) = watch::channel(false);
    let timeout_cancel = cancel.clone();
    // Published before the task starts, so the task's final update finds it.
    *lock_current(current) = Some(Running {
        execution: NetworkResetExecution {
            id: id.clone(),
            flags,
            status: NetworkResetStatus::Running,
        },
        cancel,
        done: done_rx,
        deleting: false,
    });
    // An expiry that already passed while the lease was being granted stops the
    // execution before it starts, so it has no side effects, deterministically
    // rather than racing the timer below.
    if expiry.is_some_and(|expiry| expiry <= tokio::time::Instant::now()) {
        timeout_cancel.cancel();
    }
    // The outer task reports the end of the execution, whatever happens in the
    // inner task (including a panic). The protection goes with the inner task,
    // which hands it on to a rediscovery that outlives the execution.
    cda_interfaces::spawn_named!("networkreset", async move {
        let mut inner = cda_interfaces::spawn_named!("networkreset-run", async move {
            run(&deps, flags, lease, protection, &task_cancel).await
        });
        let expired = async move {
            match expiry {
                Some(expiry) => tokio::time::sleep_until(expiry).await,
                None => std::future::pending().await,
            }
        };
        let joined = tokio::select! {
            joined = &mut inner => joined,
            () = expired => {
                tracing::info!(id = %task_id, ?timeout, "Network reset timed out, stopping it");
                timeout_cancel.cancel();
                inner.await
            }
        };
        let status = match joined {
            Ok(status) => status,
            Err(error) if error.is_panic() => {
                tracing::error!(id = %task_id, %error, "Network reset task panicked");
                NetworkResetStatus::Failed(NetworkResetFailure::Internal)
            }
            Err(_) => NetworkResetStatus::Stopped,
        };
        tracing::info!(id = %task_id, ?status, "Network reset finished");
        {
            let mut current = lock_current(&state);
            if let Some(running) = current.as_mut()
                && running.execution.id == task_id
            {
                if running.deleting {
                    *current = None;
                } else {
                    running.execution.status = status;
                }
            }
        }
        done_tx.send_replace(true);
    });
    tracing::info!(%id, ?flags, "Network reset started");
    id
}

async fn run(
    deps: &VehicleTopologyDeps,
    flags: NetworkResetFlags,
    lease: Box<dyn DisableGuard>,
    protection: OwnedHttpProtection,
    cancel: &CancellationToken,
) -> NetworkResetStatus {
    if flags.clear_persisted
        && let Err(error) = deps.network_reset.clear_persisted().await
    {
        // Communication returns to what it was before the reset.
        release(lease).await;
        return NetworkResetStatus::Failed(match error {
            TopologyClearError::Aborted => NetworkResetFailure::ClearAborted,
            error @ TopologyClearError::Store(_) => NetworkResetFailure::Clear(error.to_string()),
        });
    }
    // The clear itself is not cancellable, so a DELETE or timeout that arrived
    // meanwhile is only seen now.
    let stopped = cancel.is_cancelled();
    if !flags.trigger_detection {
        // The clear has happened, so communication ends as after a completed clear.
        return match end_clear_only(deps, lease).await {
            NetworkResetStatus::Completed if stopped => NetworkResetStatus::Stopped,
            status => status,
        };
    }
    // A DELETE or timeout during the clear: communication returns to what it was,
    // and nothing is prepared or brought up.
    if stopped {
        release(lease).await;
        return NetworkResetStatus::Stopped;
    }

    // Once prepared (all ECUs NotTested, broadcast discovery planned), only the
    // rediscovery below restores a consistent state, so from here on a DELETE or
    // timeout no longer gives the lease back; it only ends the wait.
    let ticket = deps.network_reset.prepare_rediscovery().await;
    // The deadline bounds the bring-up, including its variant detection; the
    // settling is bounded by the network reset's own wait bound.
    let now = tokio::time::Instant::now();
    // Configuration validation rejects a timeout that does not fit; should one get
    // through anyway, the deadline is now and the execution fails at once.
    let deadline = now.checked_add(deps.rediscovery_timeout).unwrap_or(now);
    // The lease is handed over directly to the bring-up with detection, so nothing
    // else can bring communication up in between: one broadcast, one detection run.
    // It is always started, also if a DELETE or the deadline arrives meanwhile;
    // both only end the wait for it. The spawned task owns the protection until the
    // rediscovery has settled (or failed), so the network structure is not read
    // while it is still being updated.
    let hang_bound = deps
        .rediscovery_timeout
        .saturating_mul(REDISCOVERY_HANG_FACTOR);
    let (rediscovered_tx, rediscovered_rx) = oneshot::channel();
    let mut settling = cda_interfaces::spawn_named!("networkreset-rediscovery", async move {
        let _protection = protection;
        let rediscovered = tokio::time::timeout(hang_bound, lease.release_with_detection())
            .await
            .map_or_else(
                |_| {
                    tracing::warn!(
                        ?hang_bound,
                        "Rediscovery did not return, giving up its network structure protection"
                    );
                    // Past the execution's own deadline, so only the protection
                    // depends on this; no execution reports it.
                    Err(NetworkResetFailure::DeadlineElapsed(hang_bound))
                },
                |result| {
                    result.map(|_| ()).map_err(|failure| match failure {
                        // A policy decision: retrying would be refused again.
                        CommunicationOperationFailure::PermissionFailure { .. } => {
                            NetworkResetFailure::RediscoveryRefused(failure)
                        }
                        failure => NetworkResetFailure::Rediscovery(failure),
                    })
                },
            );
        let failed = rediscovered.is_err();
        // The execution may have stopped waiting; the rediscovery still settles.
        let _ = rediscovered_tx.send(rediscovered);
        if failed {
            return None;
        }
        // Bounded by the ticket's own wait bound.
        Some(ticket.wait().await)
    });
    let rediscovered = tokio::select! {
        () = cancel.cancelled() => return NetworkResetStatus::Stopped,
        () = tokio::time::sleep_until(deadline) => {
            return NetworkResetStatus::Failed(NetworkResetFailure::DeadlineElapsed(
                deps.rediscovery_timeout,
            ));
        }
        received = rediscovered_rx => received.unwrap_or_else(|_| {
            tracing::error!("Network reset rediscovery task failed");
            Err(NetworkResetFailure::RediscoveryTaskFailed)
        }),
    };
    if let Err(failure) = rediscovered {
        return NetworkResetStatus::Failed(failure);
    }
    tokio::select! {
        () = cancel.cancelled() => NetworkResetStatus::Stopped,
        settled = &mut settling => match settled {
            Ok(Some(RediscoveryWait::Settled)) => NetworkResetStatus::Completed,
            Ok(Some(RediscoveryWait::TimedOut)) => {
                NetworkResetStatus::Failed(NetworkResetFailure::SettleTimedOut)
            }
            Ok(Some(RediscoveryWait::PersistFailed(error))) => {
                NetworkResetStatus::Failed(NetworkResetFailure::Persist(error))
            }
            // Not reached: a failed rediscovery returned above.
            Ok(None) => NetworkResetStatus::Failed(NetworkResetFailure::RediscoveryTaskFailed),
            Err(error) => {
                tracing::error!(%error, "Network reset rediscovery task failed");
                NetworkResetStatus::Failed(NetworkResetFailure::RediscoveryTaskFailed)
            }
        }
    }
}

/// Ends a clear-only execution, which caused no vehicle communication. Under an
/// `init_mode` that starts communication on its own, communication returns to what
/// it was before; otherwise it stays down until the `init_mode` trigger brings it up,
/// as if no topology had ever been persisted.
async fn end_clear_only(
    deps: &VehicleTopologyDeps,
    lease: Box<dyn DisableGuard>,
) -> NetworkResetStatus {
    let ended = if deps.clear_resumes_transport {
        lease.release().await.map(|_| ())
    } else {
        lease.finish().await
    };
    match ended {
        Ok(()) => NetworkResetStatus::Completed,
        Err(error) => NetworkResetStatus::Failed(NetworkResetFailure::EndLease(error)),
    }
}

/// Gives the disable lease back, so communication returns to what it was.
async fn release(lease: Box<dyn DisableGuard>) {
    if let Err(error) = lease.release().await {
        tracing::warn!(%error, "Releasing the exclusive disable failed");
    }
}

#[cfg(test)]
mod tests;
