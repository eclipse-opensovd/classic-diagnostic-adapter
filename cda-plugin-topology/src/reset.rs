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
use cda_interfaces::{
    topology::{
        DiscoveryStrategy, EcuStateResetScope, EcuTopologyStore, NetworkReset, RediscoveryTicket,
        RediscoveryWait, TopologyClearError, TopologyState,
    },
    util::tokio_ext::sleep_for,
};

use crate::{persist::TopologyPersistence, plugin::TopologySource};

/// How often a ticket without persistence checks whether the rediscovery's
/// discovery has started. [`TopologyState`] offers no notification for the
/// start of a discovery, only for its end.
const DISCOVERY_START_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// [`NetworkReset`] over the topology state and the live ECUs.
pub(crate) struct TopologyReset {
    pub(crate) store: Arc<dyn EcuTopologyStore>,
    pub(crate) state: Arc<TopologyState>,
    pub(crate) source: Arc<dyn TopologySource>,
    /// The persistence hook, `None` if the topology is not persisted.
    pub(crate) persistence: Option<Arc<TopologyPersistence>>,
    /// Whether gateway discovery is configured.
    pub(crate) doip_enabled: bool,
    /// Upper bound of the rediscovery ticket's wait.
    pub(crate) timeout: Duration,
}

#[async_trait]
impl NetworkReset for TopologyReset {
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
                source
                    .reset_ecu_states(EcuStateResetScope::AssumedOnlineOnly)
                    .await;
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

    async fn prepare_rediscovery(&self) -> RediscoveryTicket {
        self.state.set_discovery_strategy(DiscoveryStrategy::Vir);
        self.source
            .reset_ecu_states(EcuStateResetScope::AllPhysical)
            .await;
        if let Some(persistence) = &self.persistence {
            return persistence.rediscovery_ticket(self.timeout);
        }
        let generation = self.state.discovery_generation();
        let state = Arc::clone(&self.state);
        let source = Arc::clone(&self.source);
        let doip_enabled = self.doip_enabled;
        // Bounded by the ticket's timeout like the persistence's verdict.
        RediscoveryTicket::new(self.timeout, async move {
            if doip_enabled {
                // The rediscovery may not have started its discovery yet, so the
                // last settled one can still be an older generation: wait for a
                // newer one to start, then for it to settle.
                while state.discovery_generation() <= generation {
                    sleep_for(DISCOVERY_START_POLL_INTERVAL).await;
                }
                if state
                    .settled()
                    .await
                    .is_none_or(|outcome| outcome.generation <= generation)
                {
                    return RediscoveryWait::TimedOut;
                }
            }
            source.detection_activity().await.wait_until_idle().await;
            RediscoveryWait::Settled
        })
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
        async fn reset_ecu_states(&self, _scope: EcuStateResetScope) {}
    }

    #[derive(Default)]
    struct RecordingSource(std::sync::Mutex<Vec<EcuStateResetScope>>);

    #[async_trait]
    impl TopologySource for RecordingSource {
        async fn ecu_topology_entries(&self) -> Vec<EcuTopologyEntry> {
            Vec::new()
        }

        async fn detection_activity(&self) -> VariantDetectionActivity {
            VariantDetectionActivity::new()
        }

        async fn reset_ecu_states(&self, scope: EcuStateResetScope) {
            self.0.lock().unwrap().push(scope);
        }
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
        let network_reset = reset(Arc::new(FailingClearStore), Arc::clone(&state));

        assert!(network_reset.clear_persisted().await.is_err());
        assert_eq!(state.discovery_strategy(), strategy);
        assert!(state.persisted_topology_available());
    }

    #[tokio::test]
    async fn clear_and_rediscovery_use_the_expected_reset_scopes() {
        let state = TopologyState::new(DiscoveryStrategy::Vir);
        let source = Arc::new(RecordingSource::default());
        let mut network_reset = reset(Arc::new(DisabledTopologyStore), state);
        network_reset.source = Arc::clone(&source) as Arc<dyn TopologySource>;

        network_reset.clear_persisted().await.unwrap();
        let _ticket = network_reset.prepare_rediscovery().await;

        assert_eq!(
            *source.0.lock().unwrap(),
            [
                EcuStateResetScope::AssumedOnlineOnly,
                EcuStateResetScope::AllPhysical,
            ]
        );
    }

    /// [[ test~plugin-vehicle-topology-reset-doip-reset-requires-a-new-settled-discovery, Without persistence a `DoIP` rediscovery completes only with a new settled discovery, test ]]
    #[tokio::test]
    async fn doip_reset_requires_a_new_settled_discovery() {
        let state = TopologyState::new(DiscoveryStrategy::Vir);
        let generation = state.begin_discovery();
        state.finish_discovery(generation, true);
        let network_reset = reset(Arc::new(DisabledTopologyStore), Arc::clone(&state));

        let stale = network_reset.prepare_rediscovery().await;
        let running = network_reset.prepare_rediscovery().await;
        let completed = network_reset.prepare_rediscovery().await;
        assert_eq!(stale.wait().await, RediscoveryWait::TimedOut);
        let generation = state.begin_discovery();
        assert_eq!(running.wait().await, RediscoveryWait::TimedOut);
        state.finish_discovery(generation, true);
        assert_eq!(completed.wait().await, RediscoveryWait::Settled);
    }

    /// A ticket waited on before the rediscovery's discovery started does not
    /// take the previous settled discovery as its verdict.
    #[tokio::test(start_paused = true)]
    async fn ticket_waits_for_a_discovery_that_starts_after_waiting() {
        let state = TopologyState::new(DiscoveryStrategy::Vir);
        let previous = state.begin_discovery();
        state.finish_discovery(previous, true);
        let mut network_reset = reset(Arc::new(DisabledTopologyStore), Arc::clone(&state));
        network_reset.timeout = Duration::from_secs(5);
        let ticket = network_reset.prepare_rediscovery().await;

        let mut wait = tokio::spawn(ticket.wait());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut wait)
                .await
                .is_err(),
            "the old settled discovery must not end the wait"
        );
        let generation = state.begin_discovery();
        state.finish_discovery(generation, true);
        assert_eq!(wait.await.unwrap(), RediscoveryWait::Settled);
    }

    #[tokio::test]
    async fn ticket_without_gateway_discovery_waits_for_detection() {
        let state = TopologyState::new(DiscoveryStrategy::Vir);
        let activity = VariantDetectionActivity::new();
        let mut network_reset = reset(Arc::new(DisabledTopologyStore), state);
        network_reset.doip_enabled = false;
        network_reset.source = Arc::new(Source(activity.clone()));

        let running = network_reset.prepare_rediscovery().await;
        let completed = network_reset.prepare_rediscovery().await;
        let detection = activity.begin();
        assert_eq!(running.wait().await, RediscoveryWait::TimedOut);
        drop(detection);
        assert_eq!(completed.wait().await, RediscoveryWait::Settled);
    }

    #[tokio::test(start_paused = true)]
    async fn ticket_timeout_starts_when_waiting_not_when_preparing() {
        let state = TopologyState::new(DiscoveryStrategy::Vir);
        let network_reset = reset(Arc::new(DisabledTopologyStore), Arc::clone(&state));
        let ticket = network_reset.prepare_rediscovery().await;
        tokio::time::advance(Duration::from_secs(3600)).await;

        let generation = state.begin_discovery();
        let wait = tokio::spawn(ticket.wait());
        tokio::task::yield_now().await;
        assert!(!wait.is_finished());
        state.finish_discovery(generation, true);
        assert_eq!(wait.await.unwrap(), RediscoveryWait::Settled);
    }

    #[tokio::test]
    async fn dropping_a_ticket_does_not_cancel_rediscovery() {
        let state = TopologyState::new(DiscoveryStrategy::Vir);
        let network_reset = reset(Arc::new(DisabledTopologyStore), Arc::clone(&state));
        let dropped = network_reset.prepare_rediscovery().await;
        let retained = network_reset.prepare_rediscovery().await;
        let generation = state.begin_discovery();

        drop(dropped);
        state.finish_discovery(generation, true);
        assert_eq!(retained.wait().await, RediscoveryWait::Settled);
    }
}
