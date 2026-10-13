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
    communication_control::disable::{DisableCommunication, DisableError, DisableReason},
    http_protection::registry::{
        HttpMethod, HttpProtectionConfig, HttpProtectionReason, HttpProtectionRegistry,
        HttpRouteMatcher, HttpStatusCode, OwnedHttpProtection,
    },
    runtime_update_api::LockStateProvider,
    topology::{
        NetworkResetError, NetworkResetExecution, NetworkResetFlags, NetworkResetStatus,
        TopologyRediscovery, TopologyResetBackend, VehicleTopologyPlugin,
    },
};
use tokio::{sync::Mutex, task::JoinHandle};
use tokio_util::sync::CancellationToken;

/// Path of the network structure endpoint, blocked while a reset runs.
pub const NETWORK_STRUCTURE_ROUTE: &str = "/vehicle/v15/apps/sovd2uds/data/networkstructure";

/// Reason of the HTTP protection installed while a reset runs.
pub const NETWORK_RESET_REASON: &str = "NetworkResetInProgress";

/// Everything the default plugin needs from the CDA.
pub struct VehicleTopologyDeps {
    /// Persisted topology and ECU state operations.
    pub backend: Arc<dyn TopologyResetBackend>,
    /// Triggers the rediscovery through the communication plugin.
    pub rediscovery: Arc<dyn TopologyRediscovery>,
    /// Exclusive transport ownership, to make sure no diagnostics are running.
    pub communication_disable: Arc<dyn DisableCommunication>,
    /// Lock state, to refuse a reset while ECU or functional group locks exist.
    pub locks: Arc<dyn LockStateProvider>,
    /// Registry for the `409 Conflict` protection of the network structure.
    pub http_protections: HttpProtectionRegistry,
    /// Upper bound for a rediscovery to settle.
    pub rediscovery_timeout: Duration,
}

struct Running {
    execution: NetworkResetExecution,
    cancel: CancellationToken,
    task: Option<JoinHandle<()>>,
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

#[async_trait]
impl VehicleTopologyPlugin for DefaultVehicleTopologyPlugin {
    async fn start_reset(&self, flags: NetworkResetFlags) -> Result<String, NetworkResetError> {
        if !flags.clear_persisted && !flags.trigger_detection {
            return Err(NetworkResetError::InvalidRequest(
                "clear_persisted and trigger_detection are both false, nothing to do".to_owned(),
            ));
        }
        let mut current = self.current.lock().await;
        if current
            .as_ref()
            .is_some_and(|running| running.execution.status == NetworkResetStatus::Running)
        {
            return Err(NetworkResetError::ExecutionConflict);
        }
        if self.deps.locks.has_non_vehicle_locks().await {
            return Err(NetworkResetError::OperationsInProgress(
                "ECU or functional group locks are held".to_owned(),
            ));
        }

        let protection = self.protect()?;
        // Clearing alone causes no vehicle traffic, so only a rediscovery needs
        // exclusive ownership of the transport.
        let lease = if flags.trigger_detection {
            Some(
                self.deps
                    .communication_disable
                    .disable(DisableReason::Custom("networkreset".to_owned()))
                    .await
                    .map_err(|error| match error {
                        DisableError::Conflict => NetworkResetError::ExecutionConflict,
                        DisableError::InUse => NetworkResetError::OperationsInProgress(
                            "diagnostic operations are in progress".to_owned(),
                        ),
                        DisableError::Failed(failure) => {
                            NetworkResetError::Failed(failure.to_string())
                        }
                    })?,
            )
        } else {
            None
        };

        let id = uuid::Uuid::new_v4().to_string();
        let cancel = CancellationToken::new();
        let deps = Arc::clone(&self.deps);
        let state = Arc::clone(&self.current);
        let task_cancel = cancel.clone();
        let task_id = id.clone();
        let task = cda_interfaces::spawn_named!("networkreset", async move {
            let status = run(&deps, flags, lease, &task_cancel).await;
            drop(protection);
            tracing::info!(id = %task_id, ?status, "Network reset finished");
            if let Some(running) = state.lock().await.as_mut()
                && running.execution.id == task_id
            {
                running.execution.status = status;
            }
        });

        *current = Some(Running {
            execution: NetworkResetExecution {
                id: id.clone(),
                flags,
                status: NetworkResetStatus::Running,
            },
            cancel,
            task: Some(task),
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
        let task = {
            let mut current = self.current.lock().await;
            let Some(running) = current.as_mut().filter(|r| r.execution.id == id) else {
                return false;
            };
            running.cancel.cancel();
            running.task.take()
        };
        // Steps already started (clearing, enabling communication) finish; only
        // the wait for the rediscovery to settle is cut short.
        if let Some(task) = task
            && let Err(error) = task.await
            && error.is_panic()
        {
            tracing::error!(%error, "Network reset task panicked");
        }
        let mut current = self.current.lock().await;
        if current.as_ref().is_some_and(|r| r.execution.id == id) {
            *current = None;
        }
        true
    }

    async fn is_running(&self) -> bool {
        self.current
            .lock()
            .await
            .as_ref()
            .is_some_and(|running| running.execution.status == NetworkResetStatus::Running)
    }
}

async fn run(
    deps: &VehicleTopologyDeps,
    flags: NetworkResetFlags,
    lease: Option<Box<dyn cda_interfaces::communication_control::disable::DisableGuard>>,
    cancel: &CancellationToken,
) -> NetworkResetStatus {
    if flags.clear_persisted
        && let Err(error) = deps.backend.clear_persisted().await
    {
        return NetworkResetStatus::Failed(error.to_string());
    }
    let Some(lease) = lease else {
        return NetworkResetStatus::Completed;
    };

    let marker = deps.backend.prepare_rediscovery().await;
    // Ends exclusivity but keeps communication down, so the rediscovery below is
    // the only bring-up (one broadcast, one detection run).
    if let Err(error) = lease.finish().await {
        return NetworkResetStatus::Failed(error.to_string());
    }
    if let Err(error) = deps.rediscovery.rediscover().await {
        return NetworkResetStatus::Failed(error);
    }
    tokio::select! {
        () = cancel.cancelled() => NetworkResetStatus::Stopped,
        settled = deps.backend.wait_rediscovered(marker, deps.rediscovery_timeout) => {
            if settled {
                NetworkResetStatus::Completed
            } else {
                NetworkResetStatus::Failed(format!(
                    "Rediscovery did not settle within {:?}",
                    deps.rediscovery_timeout
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests;
