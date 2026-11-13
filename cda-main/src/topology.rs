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

//! Adapts the CDA databases and configuration to the topology plugin.

use std::{sync::Arc, time::SystemTime};

use async_trait::async_trait;
use cda_interfaces::{
    DiagServiceError, EcuAddresses as _, EcuManager as _, HashSet, TransportType,
    VariantDetection as _,
    component_slot::ComponentSlot,
    storage_api::Storage,
    topology::{DisabledTopologyStore, EcuTopologyEntry, EcuTopologyStore, PersistedVariant},
};
use cda_plugin_security::SecurityPlugin;
use cda_plugin_topology::{
    DatabaseEcu, PersistentEcuTopologyStore, TopologyDatabases, TopologyPlugin,
    TopologyPluginBuilder, TopologyPolicy, TopologySource,
};

use crate::{
    config::configfile::Configuration,
    error::AppError,
    vehicle::{DatabaseMap, UdsManagerType},
};

/// Derives the plugin input from the CDA configuration. ECU list persistence
/// is resolved against the transports here: it is only active with the doip
/// transport.
// [[ dimpl~ecu-list-persistence-requires-doip, ECU list persistence is only active with the doip transport, dimpl ]]
#[must_use]
pub fn topology_plugin_input(config: &Configuration) -> TopologyPolicy {
    let ecus_pinned_to_can_transport: HashSet<String> = config
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
    let mut settings = config.communication.topology;
    settings.ecu_list_persistence.enabled &= config.doip.enabled;
    TopologyPolicy {
        settings,
        init_mode: config.communication.init_mode,
        ecus_pinned_to_can_transport,
        doip_enabled: config.doip.enabled,
        deferred_retry_after: config.deferred_retry_after(),
    }
}

/// Builds the topology plugin with `builder`. The store is a no-op store if ECU
/// list persistence is disabled, so the plugin never touches `storage` then.
///
/// # Errors
/// Returns [`AppError::InitializationFailed`] if the builder fails.
pub async fn build_topology_plugin<S, B>(
    builder: B,
    config: &Configuration,
    storage: Arc<S>,
) -> Result<Arc<dyn TopologyPlugin>, AppError>
where
    S: Storage + 'static,
    B: TopologyPluginBuilder,
{
    let input = topology_plugin_input(config);
    let store: Arc<dyn EcuTopologyStore> = if input.enabled() {
        Arc::new(PersistentEcuTopologyStore::new(storage))
    } else {
        Arc::new(DisabledTopologyStore)
    };
    let plugin = builder
        .build(input, store)
        .await
        .map_err(|error| AppError::InitializationFailed(error.to_string()))?;
    Ok(Arc::new(plugin))
}

/// The loaded databases as seen by the topology plugin.
pub struct EcuDatabases<'a, S: SecurityPlugin>(pub &'a DatabaseMap<S>);

#[async_trait]
impl<S: SecurityPlugin> TopologyDatabases for EcuDatabases<'_, S> {
    async fn ecus(&self) -> Vec<DatabaseEcu> {
        let mut ecus = Vec::with_capacity(self.0.len());
        for (name, ecu) in self.0 {
            let ecu = ecu.read().await;
            ecus.push(DatabaseEcu {
                name: name.clone(),
                logical_address: ecu.logical_address(),
                gateway_address: ecu.logical_gateway_address(),
                is_physical: ecu.is_physical_ecu(),
                duplicating_ecu_names: ecu
                    .duplicating_ecu_names()
                    .map(|names| names.iter().cloned().collect())
                    .unwrap_or_default(),
            });
        }
        ecus
    }

    async fn restore_last_seen(&self, ecu: &str, at: SystemTime) {
        if let Some(ecu) = self.0.get(ecu) {
            ecu.read().await.runtime_state().restore_last_seen(at);
        }
    }

    async fn restore_variant(
        &self,
        ecu: &str,
        variant: &PersistedVariant,
    ) -> Result<bool, DiagServiceError> {
        match self.0.get(ecu) {
            Some(ecu) => ecu.write().await.restore_persisted_variant(variant).await,
            None => Ok(false),
        }
    }

    async fn restore_duplicate(&self, ecu: &str) {
        let Some(ecu) = self.0.get(ecu) else {
            return;
        };
        let mut ecu = ecu.write().await;
        ecu.mark_as_duplicate().await;
        // The losing member belongs to the restored resolution too. An
        // Offline member would invalidate the entire group on connect.
        cda_interfaces::util::std_ext::lock_write(&ecu.runtime_state().ecu_state).connectivity =
            cda_interfaces::Connectivity::AssumedOnline;
    }
}

/// Reads the live ECUs from the current UDS manager, so a manager replaced by a
/// runtime update is picked up.
pub struct UdsTopologySource<SP: SecurityPlugin> {
    pub uds_manager: ComponentSlot<UdsManagerType<SP>>,
}

#[async_trait::async_trait]
impl<SP: SecurityPlugin> TopologySource for UdsTopologySource<SP> {
    async fn ecu_topology_entries(&self) -> Vec<EcuTopologyEntry> {
        self.uds_manager.read().await.ecu_topology_entries().await
    }

    async fn detection_activity(&self) -> cda_interfaces::VariantDetectionActivity {
        self.uds_manager.read().await.detection_activity().clone()
    }

    async fn reset_ecu_states(&self, only_assumed_online: bool) {
        self.uds_manager
            .read()
            .await
            .reset_ecu_states(only_assumed_online)
            .await;
    }
}

#[cfg(test)]
mod tests {
    use cda_comm_doip::config::{DiscoveryMode, DoipConfig};
    use cda_interfaces::{
        HashMapExtensions as _,
        communication_control::{CommunicationInitMode, VamHandlingMode},
        topology::{
            EcuTopologyStore, PersistedEcu, PersistedEcuState, PersistedGateway, PersistedVariant,
        },
    };
    use cda_plugin_security::mock::TestSecurityPlugin;
    use cda_plugin_topology::{
        DefaultTopologyPlugin, DefaultTopologyPluginBuilder, topology_plugin_fn,
    };
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
        config.communication.topology.ecu_list_persistence.enabled = persistence;
        config.communication.topology.vam_handling_mode = VamHandlingMode::PersistedOnly;
        config
    }

    async fn default_plugin(
        config: &Configuration,
        storage: Arc<LocalStorage>,
    ) -> Arc<dyn TopologyPlugin> {
        build_topology_plugin(DefaultTopologyPluginBuilder, config, storage)
            .await
            .expect("topology plugin")
    }

    async fn persisted_storage() -> (Arc<LocalStorage>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("storage dir");
        let storage = Arc::new(LocalStorage::new(dir.path()).expect("storage"));
        PersistentEcuTopologyStore::new(Arc::clone(&storage))
            .persist_gateways(&[PersistedGateway {
                name: "GW".to_owned(),
                logical_address: 0x1000,
                network_address: Some("10.2.1.10".to_owned()),
                doip_protocol_version: Some(3),
                ecus: vec![PersistedEcu {
                    name: "GW".to_owned(),
                    logical_address: 0x1000,
                    variant: Some(PersistedVariant {
                        name: "App".to_owned(),
                        is_base_variant: false,
                        is_fallback: false,
                    }),
                    state: PersistedEcuState::Online,
                    last_seen: None,
                }],
            }])
            .await
            .expect("seed topology");
        (storage, dir)
    }

    /// The topology policy does not depend on the `DoIP` discovery mode: it
    /// restricts how gateways are found, not the restore.
    /// [[ test~ecu-state-restore-independent-of-discovery-mode, Persisted ECUs are restored `AssumedOnline` in every `DoIP` discovery mode, test ]]
    #[test]
    fn topology_policy_is_independent_of_discovery_mode() {
        for discovery in [
            DiscoveryMode::Full,
            DiscoveryMode::VamOnly,
            DiscoveryMode::Disabled,
        ] {
            let mut config = config(true, true);
            config.doip.discovery = discovery;
            config.communication.init_mode = CommunicationInitMode::WhenNotPersisted;
            let input = topology_plugin_input(&config);

            assert!(input.enabled(), "{discovery:?}");
            assert_eq!(input.init_mode, CommunicationInitMode::WhenNotPersisted);
            assert!(input.ecus_pinned_to_can_transport.is_empty());
        }
    }

    /// [[ test~ecu-list-persistence-requires-doip, ECU list persistence is only active with the doip transport, test ]]
    #[tokio::test]
    async fn persistence_without_doip_behaves_as_disabled() {
        let (storage, _dir) = persisted_storage().await;
        let databases: DatabaseMap<TestSecurityPlugin> = DatabaseMap::new();

        let plugin = default_plugin(&config(true, false), Arc::clone(&storage)).await;
        assert!(!plugin.is_enabled());
        assert!(!plugin.state().listens_for_vams());
        plugin
            .restore_persisted_topology(&EcuDatabases(&databases))
            .await;
        assert!(!plugin.state().persisted_topology_available());

        // The same stored data is used once DoIP is enabled.
        let plugin = default_plugin(&config(true, true), storage).await;
        assert!(plugin.is_enabled());
        assert!(plugin.state().listens_for_vams());
        plugin
            .restore_persisted_topology(&EcuDatabases(&databases))
            .await;
        assert!(plugin.state().persisted_topology_available());
    }

    /// A custom builder receives the derived configuration, and its failure aborts startup.
    #[tokio::test]
    async fn custom_builder_gets_the_config_and_can_fail() {
        let (storage, _dir) = persisted_storage().await;

        let seen = Arc::new(std::sync::Mutex::new(None));
        let recorder = Arc::clone(&seen);
        let builder = topology_plugin_fn(move |input: TopologyPolicy, store| {
            *recorder.lock().unwrap() = Some(input.enabled());
            async move { Ok::<_, std::convert::Infallible>(DefaultTopologyPlugin::new(input, store)) }
        });
        build_topology_plugin(builder, &config(true, true), Arc::clone(&storage))
            .await
            .expect("topology plugin");
        assert_eq!(*seen.lock().unwrap(), Some(true));

        let failing = topology_plugin_fn(|_input: TopologyPolicy, _store| async {
            Err::<DefaultTopologyPlugin, _>("no plugin")
        });
        let result = build_topology_plugin(failing, &config(true, true), storage).await;
        assert!(matches!(result, Err(AppError::InitializationFailed(_))));
    }
}
