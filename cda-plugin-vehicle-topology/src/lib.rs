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
//! the network structure endpoint answers `409 Conflict`, so clients never read a
//! partially updated topology.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use cda_interfaces::{
    communication_control::{
        disable::{DisableCommunication, DisableError, DisableGuard, DisableReason},
        quiesce::{QuiesceCommunication, QuiesceGuard},
    },
    http_protection::registry::{
        HttpMethod, HttpProtectionConfig, HttpProtectionReason, HttpProtectionRegistry,
        HttpRouteMatcher, HttpStatusCode, OwnedHttpProtection,
    },
    runtime_update_api::LockStateProvider,
    topology::{
        NETWORK_STRUCTURE_ROUTE, NetworkResetError, NetworkResetExecution, NetworkResetFlags,
        NetworkResetStatus, RediscoveryWait, TopologyRediscovery, TopologyResetBackend,
        VehicleTopologyPlugin,
    },
};
use tokio::sync::{Mutex, watch};
use tokio_util::sync::CancellationToken;

/// Reason of the HTTP protection installed while a reset runs.
pub const NETWORK_RESET_REASON: &str = "NetworkResetInProgress";

/// Everything the default plugin needs from the CDA.
pub struct VehicleTopologyDeps {
    /// Persisted topology and ECU state operations.
    pub backend: Arc<dyn TopologyResetBackend>,
    /// Triggers the rediscovery through the communication plugin.
    pub rediscovery: Arc<dyn TopologyRediscovery>,
    /// Exclusive transport ownership for a rediscovery, to make sure no diagnostics are running.
    pub communication_disable: Arc<dyn DisableCommunication>,
    /// Exclusive pause of diagnostics for a clear-only reset, without touching the transport.
    pub communication_quiesce: Arc<dyn QuiesceCommunication>,
    /// Lock state, to refuse a reset while ECU or functional group locks exist.
    pub locks: Arc<dyn LockStateProvider>,
    /// Registry for the `409 Conflict` protection of the network structure.
    pub http_protections: HttpProtectionRegistry,
    /// Upper bound for bringing communication up for a rediscovery. Settling is bounded by the
    /// backend (see [`TopologyResetBackend::wait_rediscovered`]).
    pub rediscovery_timeout: Duration,
}

/// Operation id used as the reason for the exclusive leases.
const OPERATION_ID: &str = "networkreset";

/// The exclusive lease an execution holds while it runs.
enum Exclusive {
    /// Rediscovery: owns the transport.
    Disable(Box<dyn DisableGuard>),
    /// Clear-only: pauses diagnostics, the transport stays as it is.
    Quiesce(Box<dyn QuiesceGuard>),
}

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
    current: Arc<Mutex<Option<Running>>>,
}

impl DefaultVehicleTopologyPlugin {
    /// Creates the plugin.
    #[must_use]
    pub fn new(deps: VehicleTopologyDeps) -> Self {
        Self {
            deps: Arc::new(deps),
            current: Arc::new(Mutex::new(None)),
        }
    }

    /// [[ dimpl~plugin-vehicle-topology-retrieval-protection, The network structure endpoint answers 409 while a networkreset runs, dimpl ]]
    fn protect(&self) -> Result<OwnedHttpProtection, NetworkResetError> {
        self.deps
            .http_protections
            .protect(
                HttpProtectionConfig::new(
                    HttpProtectionReason::Custom(NETWORK_RESET_REASON.to_owned()),
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

/// Maps a refused communication lease (disable or quiesce) to the reset error.
///
/// A conflicting lease means communication is changing state, which is a retryable
/// condition (HTTP 409) and not a conflict with another network reset execution.
fn map_disable_error(error: DisableError) -> NetworkResetError {
    match error {
        DisableError::Conflict => NetworkResetError::OperationsInProgress(
            "communication is changing state, retry later".to_owned(),
        ),
        DisableError::InUse => NetworkResetError::OperationsInProgress(
            "diagnostic operations are in progress".to_owned(),
        ),
        DisableError::Failed(failure) => NetworkResetError::Failed(failure.to_string()),
    }
}

#[async_trait]
impl VehicleTopologyPlugin for DefaultVehicleTopologyPlugin {
    async fn start_reset(&self, flags: NetworkResetFlags) -> Result<String, NetworkResetError> {
        if !flags.clear_persisted && !flags.trigger_detection {
            return Err(NetworkResetError::InvalidRequest(
                "clear_persisted and trigger_detection are both false, nothing to do".to_owned(),
            ));
        }
        let mut current = self.current.lock().await;
        if current.as_ref().is_some_and(|running| {
            running.execution.status == NetworkResetStatus::Running || running.deleting
        }) {
            return Err(NetworkResetError::ExecutionConflict);
        }
        if self.deps.locks.has_non_vehicle_locks().await {
            return Err(NetworkResetError::OperationsInProgress(
                "ECU or functional group locks are held".to_owned(),
            ));
        }

        let protection = self.protect()?;
        // A rediscovery owns the transport. Clearing alone must not cause vehicle
        // traffic, so it only pauses diagnostics (quiesce) without a transport change.
        let reason = DisableReason::Custom(OPERATION_ID.to_owned());
        let lease = if flags.trigger_detection {
            Exclusive::Disable(
                self.deps
                    .communication_disable
                    .disable(reason)
                    .await
                    .map_err(map_disable_error)?,
            )
        } else {
            Exclusive::Quiesce(
                self.deps
                    .communication_quiesce
                    .quiesce(reason)
                    .await
                    .map_err(map_disable_error)?,
            )
        };

        let id = uuid::Uuid::new_v4().to_string();
        let cancel = CancellationToken::new();
        let deps = Arc::clone(&self.deps);
        let state = Arc::clone(&self.current);
        let task_cancel = cancel.clone();
        let task_id = id.clone();
        let (done_tx, done_rx) = watch::channel(false);
        // The outer task owns the protection and reports the end of the execution,
        // whatever happens in the inner task (including a panic).
        cda_interfaces::spawn_named!("networkreset", async move {
            let inner = cda_interfaces::spawn_named!("networkreset-run", async move {
                run(&deps, flags, lease, &task_cancel).await
            });
            let status = match inner.await {
                Ok(status) => status,
                Err(error) if error.is_panic() => {
                    tracing::error!(id = %task_id, %error, "Network reset task panicked");
                    NetworkResetStatus::Failed("internal error".to_owned())
                }
                Err(_) => NetworkResetStatus::Stopped,
            };
            drop(protection);
            tracing::info!(id = %task_id, ?status, "Network reset finished");
            {
                let mut current = state.lock().await;
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

        *current = Some(Running {
            execution: NetworkResetExecution {
                id: id.clone(),
                flags,
                status: NetworkResetStatus::Running,
            },
            cancel,
            done: done_rx,
            deleting: false,
        });
        tracing::info!(%id, ?flags, "Network reset started");
        Ok(id)
    }

    async fn list_resets(&self) -> Vec<NetworkResetExecution> {
        self.current
            .lock()
            .await
            .as_ref()
            .map(|running| running.execution.clone())
            .into_iter()
            .collect()
    }

    async fn get_reset(&self, id: &str) -> Option<NetworkResetExecution> {
        self.current
            .lock()
            .await
            .as_ref()
            .filter(|running| running.execution.id == id)
            .map(|running| running.execution.clone())
    }

    async fn delete_reset(&self, id: &str) -> bool {
        let mut done = {
            let mut current = self.current.lock().await;
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

async fn run(
    deps: &VehicleTopologyDeps,
    flags: NetworkResetFlags,
    lease: Exclusive,
    cancel: &CancellationToken,
) -> NetworkResetStatus {
    if flags.clear_persisted
        && let Err(error) = deps.backend.clear_persisted().await
    {
        // Communication returns to what it was before the reset.
        match lease {
            Exclusive::Disable(lease) => release(lease).await,
            Exclusive::Quiesce(guard) => drop(guard),
        }
        return NetworkResetStatus::Failed(error.to_string());
    }
    let lease = match lease {
        Exclusive::Disable(lease) => lease,
        Exclusive::Quiesce(guard) => {
            drop(guard);
            return NetworkResetStatus::Completed;
        }
    };

    let marker = deps.backend.prepare_rediscovery().await;
    // A DELETE during the clear or the preparation: communication returns to
    // what it was, and nothing is brought up.
    if cancel.is_cancelled() {
        release(lease).await;
        return NetworkResetStatus::Stopped;
    }
    // The deadline bounds only the bring-up (finishing the lease and the
    // rediscovery); the settling is bounded by the persistence's own budget.
    // Dropping the rediscovery future only drops the wait for the lifecycle
    // worker's reply; the enable itself runs on.
    let now = tokio::time::Instant::now();
    // An overflowing timeout is a misconfiguration (centuries); fail fast then.
    let deadline = now.checked_add(deps.rediscovery_timeout).unwrap_or(now);
    let deadline_message = || {
        format!(
            "Rediscovery did not complete within {:?}",
            deps.rediscovery_timeout
        )
    };
    if tokio::time::Instant::now() >= deadline {
        release(lease).await;
        return NetworkResetStatus::Failed(deadline_message());
    }
    // Ends exclusivity but keeps communication down, so the rediscovery below is
    // the only bring-up (one broadcast, one detection run).
    match tokio::time::timeout_at(deadline, lease.finish()).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            return NetworkResetStatus::Failed(format!(
                "Finishing the exclusive disable failed: {error}. Communication stays disabled; \
                 execute networkreset with trigger_detection=true to bring it up again"
            ));
        }
        Err(_) => {
            return NetworkResetStatus::Failed(format!(
                "{}. Communication stays disabled; execute networkreset with \
                 trigger_detection=true to bring it up again",
                deadline_message()
            ));
        }
    }
    let rediscovered = tokio::select! {
        () = cancel.cancelled() => return NetworkResetStatus::Stopped,
        () = tokio::time::sleep_until(deadline) => {
            return NetworkResetStatus::Failed(deadline_message());
        }
        result = deps.rediscovery.rediscover() => result,
    };
    if let Err(error) = rediscovered {
        return NetworkResetStatus::Failed(format!(
            "Rediscovery failed: {error}. Communication stays disabled; execute networkreset with \
             trigger_detection=true to bring it up again"
        ));
    }
    tokio::select! {
        () = cancel.cancelled() => NetworkResetStatus::Stopped,
        settled = deps.backend.wait_rediscovered(marker) => match settled {
            RediscoveryWait::Settled => NetworkResetStatus::Completed,
            RediscoveryWait::TimedOut => {
                NetworkResetStatus::Failed("Rediscovery did not settle in time".to_owned())
            }
            RediscoveryWait::PersistFailed(error) => NetworkResetStatus::Failed(format!(
                "Persisting the rediscovered topology failed: {error}"
            )),
        }
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
