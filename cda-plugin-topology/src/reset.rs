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

//! Core side of the `networkreset` operation.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use cda_interfaces::topology::{
    DiscoveryStrategy, EcuTopologyStore, RediscoveryWait, TopologyClearError, TopologyResetBackend,
    TopologyState,
};

use crate::{persist::TopologyPersistence, plugin::TopologySource};

/// [`TopologyResetBackend`] over the topology state and the live ECUs.
pub(crate) struct TopologyReset {
    pub(crate) store: Arc<dyn EcuTopologyStore>,
    pub(crate) state: Arc<TopologyState>,
    pub(crate) source: Arc<dyn TopologySource>,
    /// The persistence hook, `None` if the topology is not persisted.
    pub(crate) persistence: Option<Arc<TopologyPersistence>>,
    /// Whether gateway discovery is configured.
    pub(crate) doip_enabled: bool,
    /// Upper bound of [`wait_rediscovered`](TopologyResetBackend::wait_rediscovered).
    pub(crate) timeout: Duration,
}

#[async_trait]
impl TopologyResetBackend for TopologyReset {
    async fn clear_persisted(&self) -> Result<(), TopologyClearError> {
        let store = Arc::clone(&self.store);
        let state = Arc::clone(&self.state);
        let source = Arc::clone(&self.source);
        let clear = async move {
            let result = store.clear().await;
            if result.is_ok() {
                state.set_discovery_strategy(DiscoveryStrategy::Vir);
                state.clear_persisted_topology_available();
                // As if the topology had never been persisted: ECUs not contacted
                // since they were restored are no longer reported Online.
                source.reset_ecu_states(true).await;
            }
            result
        };
        // With the persist task stopped, so a pending write cannot bring back what
        // is cleared now, and restarted afterwards also after a failed clear.
        match &self.persistence {
            Some(persistence) => persistence.run_clear(clear).await,
            None => Ok(clear.await?),
        }
    }

    async fn prepare_rediscovery(&self) -> u64 {
        self.state.set_discovery_strategy(DiscoveryStrategy::Vir);
        self.source.reset_ecu_states(false).await;
        self.state.discovery_generation()
    }

    async fn wait_rediscovered(&self, marker: u64) -> RediscoveryWait {
        if let Some(persistence) = &self.persistence {
            return persistence.wait_rediscovered(marker, self.timeout).await;
        }
        let settled = tokio::time::timeout(self.timeout, async {
            if self.doip_enabled
                && self
                    .state
                    .settled()
                    .await
                    .is_none_or(|outcome| outcome.generation <= marker)
            {
                return false;
            }
            self.source
                .detection_activity()
                .await
                .wait_until_idle()
                .await;
            true
        })
        .await
        .unwrap_or(false);
        if settled {
            RediscoveryWait::Settled
        } else {
            RediscoveryWait::TimedOut
        }
    }
}

#[cfg(test)]
mod tests {
    use cda_interfaces::{
        HashMap, HashSet, VariantDetectionActivity,
        topology::{
            DisabledTopologyStore, EcuTopologyEntry, KnownGateway, PersistedGateway,
            PersistedTopology, TopologyStoreError,
        },
    };

    use super::*;

    struct Source(VariantDetectionActivity);

    #[async_trait]
    impl TopologySource for Source {
        async fn ecu_topology_entries(&self) -> Vec<EcuTopologyEntry> {
            Vec::new()
        }
        async fn detection_activity(&self) -> VariantDetectionActivity {
            self.0.clone()
        }
        async fn reset_ecu_states(&self, _only_assumed_online: bool) {}
    }

    /// Store whose `clear` fails.
    struct FailingClearStore;

    #[async_trait]
    impl EcuTopologyStore for FailingClearStore {
        async fn load(&self) -> Result<PersistedTopology, TopologyStoreError> {
            Ok(PersistedTopology::default())
        }
        async fn persist_gateways(
            &self,
            _gateways: &[PersistedGateway],
        ) -> Result<(), TopologyStoreError> {
            Ok(())
        }
        async fn merge_last_seen(
            &self,
            _last_seen: &HashMap<String, std::time::SystemTime>,
        ) -> Result<(), TopologyStoreError> {
            Ok(())
        }
        async fn clear(&self) -> Result<(), TopologyStoreError> {
            Err(TopologyStoreError::Serialization("disk full".to_owned()))
        }
        async fn prune_and_persist_gateways(
            &self,
            _keep: &HashMap<u16, HashSet<String>>,
            _gateways: &[PersistedGateway],
        ) -> Result<usize, TopologyStoreError> {
            Ok(0)
        }
    }

    fn reset(store: Arc<dyn EcuTopologyStore>, state: Arc<TopologyState>) -> TopologyReset {
        TopologyReset {
            store,
            state,
            source: Arc::new(Source(VariantDetectionActivity::new())),
            persistence: None,
            doip_enabled: true,
            timeout: Duration::from_millis(10),
        }
    }

    #[tokio::test]
    async fn failed_clear_keeps_the_in_memory_state() {
        let state = TopologyState::new(DiscoveryStrategy::Vir);
        let strategy = DiscoveryStrategy::Persisted {
            known: vec![KnownGateway {
                name: "gw".to_owned(),
                logical_address: 0x1000,
                network_address: Some("10.0.0.1".to_owned()),
                doip_protocol_version: Some(3),
            }],
            search: Vec::new(),
        };
        state.set_discovery_strategy(strategy.clone());
        state.set_persisted_topology_available();
        let backend = reset(Arc::new(FailingClearStore), Arc::clone(&state));

        assert!(backend.clear_persisted().await.is_err());
        assert_eq!(state.discovery_strategy(), strategy);
        assert!(state.persisted_topology_available());
    }

    /// [[ test~plugin-vehicle-topology-reset-doip-reset-requires-a-new-settled-discovery, Without persistence a `DoIP` rediscovery completes only with a new settled discovery, test ]]
    #[tokio::test]
    async fn doip_reset_requires_a_new_settled_discovery() {
        let state = TopologyState::new(DiscoveryStrategy::Vir);
        let generation = state.begin_discovery();
        state.finish_discovery(generation, true);
        let backend = reset(Arc::new(DisabledTopologyStore), Arc::clone(&state));

        let marker = backend.prepare_rediscovery().await;
        assert_eq!(
            backend.wait_rediscovered(marker).await,
            RediscoveryWait::TimedOut
        );
        let generation = state.begin_discovery();
        assert_eq!(
            backend.wait_rediscovered(marker).await,
            RediscoveryWait::TimedOut
        );
        state.finish_discovery(generation, true);
        assert_eq!(
            backend.wait_rediscovered(marker).await,
            RediscoveryWait::Settled
        );
    }
}
