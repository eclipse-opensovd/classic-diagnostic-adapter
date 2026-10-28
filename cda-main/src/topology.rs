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
#[cfg(test)]
mod test_support;

use std::{sync::Arc, time::Duration};

use cda_interfaces::{
    EcuAddresses as _, EcuManager as _, HashSet, TransportType,
    communication_control::CommunicationInitMode,
    storage_api::Storage,
    topology::{
        DisabledTopologyStore, DiscoveryPlan, EcuTopologyStore, TopologyRuntime, VamPolicy,
        physical_gateways,
    },
};
use cda_plugin_security::SecurityPlugin;
pub use persist::{EcuTopologySource, TopologyPersistence};
pub use store::StorageEcuTopologyStore;

use crate::{config::configfile::Configuration, vehicle::DatabaseMap};

/// Logical addresses of the physical gateways in the databases.
async fn physical_db_gateways<S: SecurityPlugin>(databases: &DatabaseMap<S>) -> Vec<u16> {
    let mut ecus = Vec::new();
    for ecu in databases.values() {
        let ecu = ecu.read().await;
        if ecu.is_physical_ecu() {
            ecus.push((ecu.logical_address(), ecu.logical_gateway_address()));
        }
    }
    physical_gateways(ecus)
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
    pub(crate) store: Arc<dyn EcuTopologyStore>,
    /// Discovery plan and connected gateways, shared with the transport.
    pub(crate) runtime: Arc<TopologyRuntime>,
    /// Configured `init_mode`.
    pub(crate) init_mode: CommunicationInitMode,
    /// Upper bound for waiting until a detection run has settled.
    pub(crate) settle_timeout: Duration,
    /// Whether gateway discovery is configured; CAN-only setups have no `DoIP` discovery.
    pub(crate) doip_enabled: bool,
    persistence: std::sync::OnceLock<Arc<TopologyPersistence>>,
}

impl TopologyContext {
    /// Creates the context. With `communication.ecu_list_persistence.enabled =
    /// false` or `doip.enabled = false`, the store never touches `storage`.
    #[must_use]
    pub fn new<S: Storage + 'static>(config: &Configuration, storage: Arc<S>) -> Arc<Self> {
        let settings = &config.communication.ecu_list_persistence;
        // Only DoIP topologies are persisted; without DoIP persistence behaves as disabled.
        // [[ dimpl~ecu-list-persistence-requires-doip, ECU list persistence is only active with the doip transport, dimpl ]]
        let enabled = settings.enabled && config.doip.enabled;
        let store: Arc<dyn EcuTopologyStore> = if enabled {
            Arc::new(StorageEcuTopologyStore::new(storage))
        } else {
            Arc::new(DisabledTopologyStore)
        };
        let runtime = TopologyRuntime::new(DiscoveryPlan::Broadcast);
        runtime.set_vam_policy(VamPolicy {
            mode: config.communication.vam_handling_mode,
            persistence_enabled: enabled,
        });
        Arc::new(Self {
            store,
            runtime,
            init_mode: config.communication.init_mode,
            settle_timeout: Duration::from_secs(settings.detection_settle_timeout_seconds),
            doip_enabled: config.doip.enabled,
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

    /// Graceful-shutdown step: one final write. Detection results not written
    /// yet are written as a full snapshot (unless a detection is still running),
    /// and `last_seen` of contacted ECUs is written back. Not time-bounded, like
    /// the other shutdown steps.
    pub async fn persist_on_shutdown(&self) {
        let Some(persistence) = self.persistence() else {
            return;
        };
        persistence.persist_on_shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use cda_comm_doip::config::DoipConfig;
    use cda_interfaces::{
        HashMapExtensions as _,
        communication_control::VamHandlingMode,
        topology::{PersistedEcu, PersistedEcuState, PersistedGateway},
    };
    use cda_plugin_security::mock::TestSecurityPlugin;
    use cda_storage::LocalStorage;

    use super::*;

    fn config(persistence: bool, doip: bool) -> Configuration {
        let mut config = Configuration {
            doip: DoipConfig {
                tester_address: "10.2.1.240".to_owned(),
                enabled: doip,
                ..Default::default()
            },
            ..Configuration::default()
        };
        config.communication.ecu_list_persistence.enabled = persistence;
        config.communication.vam_handling_mode = VamHandlingMode::PersistedOnly;
        config
    }

    async fn persisted_storage() -> (Arc<LocalStorage>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("storage dir");
        let storage = Arc::new(LocalStorage::new(dir.path()).expect("storage"));
        StorageEcuTopologyStore::new(Arc::clone(&storage))
            .upsert(&[PersistedGateway {
                name: "GW".to_owned(),
                logical_address: 0x1000,
                network_address: Some("10.2.1.10".to_owned()),
                doip_protocol_version: Some(3),
                ecus: vec![PersistedEcu {
                    name: "GW".to_owned(),
                    logical_address: 0x1000,
                    variant: None,
                    state: PersistedEcuState::Online,
                    last_seen: None,
                }],
            }])
            .await
            .expect("seed topology");
        (storage, dir)
    }

    /// [[ test~ecu-list-persistence-requires-doip, ECU list persistence is only active with the doip transport, test ]]
    #[tokio::test]
    async fn persistence_without_doip_behaves_as_disabled() {
        let (storage, _dir) = persisted_storage().await;
        let databases: DatabaseMap<TestSecurityPlugin> = DatabaseMap::new();

        let context = TopologyContext::new(&config(true, false), Arc::clone(&storage));
        assert!(!context.is_enabled());
        assert!(!context.runtime.listens_for_vams());
        context
            .restore_at_startup(&config(true, false), &databases)
            .await;
        assert!(!context.runtime.has_persisted());

        // The same stored data is used once DoIP is enabled.
        let context = TopologyContext::new(&config(true, true), storage);
        assert!(context.is_enabled());
        assert!(context.runtime.listens_for_vams());
        context
            .restore_at_startup(&config(true, true), &databases)
            .await;
        assert!(context.runtime.has_persisted());
    }
}
