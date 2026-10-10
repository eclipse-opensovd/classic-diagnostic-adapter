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

//! ECU list persistence: storing, restoring and reusing the detected topology.

pub mod persist;
pub mod reset;
pub mod restore;
pub mod store;

use std::{sync::Arc, time::Duration};

use cda_interfaces::{
    EcuAddresses as _, EcuManager as _, HashSet, TransportType,
    communication_control::CommunicationInitMode,
    storage_api::Storage,
    topology::{
        DisabledTopologyStore, DiscoveryPlan, EcuTopologyStore, TopologyRuntime, VamPolicy,
    },
};
use cda_plugin_security::SecurityPlugin;
pub use persist::{EcuTopologySource, TopologyPersistence};
pub use store::StorageEcuTopologyStore;

use crate::{config::configfile::Configuration, vehicle::DatabaseMap};

/// Logical addresses of the physical gateways in the databases.
async fn physical_db_gateways<S: SecurityPlugin>(databases: &DatabaseMap<S>) -> Vec<u16> {
    let mut gateways = Vec::new();
    for ecu in databases.values() {
        let ecu = ecu.read().await;
        if ecu.is_physical_ecu() && ecu.logical_address() == ecu.logical_gateway_address() {
            gateways.push(ecu.logical_address());
        }
    }
    gateways.sort_unstable();
    gateways.dedup();
    gateways
}

/// Recomputes the gateways a reconnect plan searches by broadcast from the
/// current databases, e.g. after a runtime database update added a gateway.
pub async fn refresh_reconnect_search<S: SecurityPlugin>(
    runtime: &TopologyRuntime,
    databases: &DatabaseMap<S>,
) {
    let plan = runtime.plan();
    if matches!(plan, DiscoveryPlan::Reconnect { .. }) {
        runtime.set_plan(plan.with_search_for(&physical_db_gateways(databases).await));
    }
}

/// Shared state of ECU list persistence, created once at startup.
pub struct TopologyContext {
    /// The store; a no-op store if persistence is disabled.
    pub store: Arc<dyn EcuTopologyStore>,
    /// Discovery plan and connected gateways, shared with the transport.
    pub runtime: Arc<TopologyRuntime>,
    /// Configured `init_mode`.
    pub init_mode: CommunicationInitMode,
    /// Upper bound for waiting until a detection run has settled.
    pub settle_timeout: Duration,
    persistence: std::sync::OnceLock<Arc<TopologyPersistence>>,
}

impl TopologyContext {
    /// Creates the context. With `communication.ecu_list_persistence.enabled =
    /// false`, the store never touches `storage`.
    #[must_use]
    pub fn new<S: Storage + 'static>(config: &Configuration, storage: Arc<S>) -> Arc<Self> {
        let settings = &config.communication.ecu_list_persistence;
        let store: Arc<dyn EcuTopologyStore> = if settings.enabled {
            Arc::new(StorageEcuTopologyStore::new(storage))
        } else {
            Arc::new(DisabledTopologyStore)
        };
        let runtime = TopologyRuntime::new(DiscoveryPlan::Broadcast);
        runtime.set_vam_policy(VamPolicy {
            mode: config.communication.vam_handling_mode,
            persistence_enabled: settings.enabled,
        });
        Arc::new(Self {
            store,
            runtime,
            init_mode: config.communication.init_mode,
            settle_timeout: Duration::from_secs(settings.detection_settle_timeout_seconds),
            persistence: std::sync::OnceLock::new(),
        })
    }

    /// Whether ECU list persistence is enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.store.is_enabled()
    }

    /// Whether a persisted topology is reused instead of a broadcast discovery,
    /// i.e. `init_mode` is not `Always`.
    #[must_use]
    pub fn reuses_topology(&self) -> bool {
        self.init_mode != CommunicationInitMode::Always
    }

    /// The registered persistence hook, if persistence is enabled.
    #[must_use]
    pub fn persistence(&self) -> Option<&Arc<TopologyPersistence>> {
        self.persistence.get()
    }

    /// Creates the persistence hook reading from `source`. Returns `None` if
    /// persistence is disabled or the hook already exists.
    pub fn create_persistence(
        &self,
        source: Arc<dyn EcuTopologySource>,
    ) -> Option<Arc<TopologyPersistence>> {
        if !self.is_enabled() {
            return None;
        }
        let persistence = TopologyPersistence::new(
            Arc::clone(&self.store),
            Arc::clone(&self.runtime),
            source,
            self.reuses_topology(),
            self.settle_timeout,
        );
        self.persistence
            .set(Arc::clone(&persistence))
            .ok()
            .map(|()| persistence)
    }

    /// Startup step, after the databases are loaded and before communication
    /// starts: restores the persisted ECU states and, unless `init_mode` is
    /// `Always`, plans a reconnect to the persisted gateways.
    pub async fn restore_at_startup<S: SecurityPlugin>(
        &self,
        config: &Configuration,
        databases: &DatabaseMap<S>,
    ) {
        if !self.is_enabled() {
            return;
        }
        let persisted = match self.store.load().await {
            Ok(persisted) => persisted,
            Err(error) => {
                tracing::warn!(%error, "Failed to load the persisted topology, detecting all ECUs");
                return;
            }
        };
        if persisted.is_empty() {
            tracing::info!("No persisted topology, running a full detection");
            return;
        }
        self.runtime.set_has_persisted(true);
        let can_pinned: HashSet<String> = config
            .can
            .as_ref()
            .map(|can| {
                can.transport_overrides
                    .iter()
                    .filter(|o| matches!(o.transport, TransportType::Can))
                    .map(|o| o.ecu_name.to_lowercase())
                    .collect()
            })
            .unwrap_or_default();
        let report =
            restore::restore_ecu_states(databases, &persisted, self.reuses_topology(), &can_pinned)
                .await;
        if self.reuses_topology() {
            let db_gateways = physical_db_gateways(databases).await;
            self.runtime
                .set_plan(DiscoveryPlan::for_persisted(&persisted, &db_gateways));
        }
        tracing::info!(
            gateways = persisted.gateways.len(),
            assumed_online = report.assumed_online,
            duplicates = report.duplicates,
            last_seen = report.last_seen,
            reconnect = self.reuses_topology(),
            "Restored persisted topology"
        );
    }

    /// Graceful-shutdown step: writes back `last_seen` of contacted ECUs. Bounded
    /// by [`persist::SHUTDOWN_WRITE_TIMEOUT`].
    pub async fn persist_last_seen_on_shutdown(&self) {
        let Some(persistence) = self.persistence() else {
            return;
        };
        // A topology write still running would race with this one.
        persistence.cancel_pending().await;
        if tokio::time::timeout(
            persist::SHUTDOWN_WRITE_TIMEOUT,
            persistence.persist_last_seen(),
        )
        .await
        .is_err()
        {
            tracing::warn!(
                timeout = ?persist::SHUTDOWN_WRITE_TIMEOUT,
                "Writing last_seen at shutdown timed out"
            );
        }
    }
}
