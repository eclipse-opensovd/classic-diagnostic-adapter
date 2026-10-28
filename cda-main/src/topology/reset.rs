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

use std::sync::Arc;

use async_trait::async_trait;
use cda_interfaces::topology::{
    DiscoveryPlan, PendingGateways, RediscoveryWait, TopologyClearError, TopologyResetBackend,
};

use super::{EcuTopologySource, TopologyContext};

/// [`TopologyResetBackend`] over the topology context and the live ECUs.
pub struct TopologyResetAdapter {
    context: Arc<TopologyContext>,
    source: Arc<dyn EcuTopologySource>,
    pending: Arc<dyn PendingGateways>,
}

impl TopologyResetAdapter {
    /// Creates the adapter.
    #[must_use]
    pub fn new(
        context: Arc<TopologyContext>,
        source: Arc<dyn EcuTopologySource>,
        pending: Arc<dyn PendingGateways>,
    ) -> Self {
        Self {
            context,
            source,
            pending,
        }
    }
}

#[async_trait]
impl TopologyResetBackend for TopologyResetAdapter {
    async fn clear_persisted(&self) -> Result<(), TopologyClearError> {
        let context = Arc::clone(&self.context);
        let pending = Arc::clone(&self.pending);
        let source = Arc::clone(&self.source);
        let clear = async move {
            let result = context.store.clear().await;
            if result.is_ok() {
                context.runtime.set_plan(DiscoveryPlan::Broadcast);
                // Gateways still pending after a lazy start must not connect to the
                // cleared address on first use.
                pending.forget_pending_addresses().await;
                context.runtime.set_has_persisted(false);
                // As if the topology had never been persisted: ECUs not contacted
                // since they were restored are no longer reported Online.
                source.reset_ecu_states(true).await;
            }
            result
        };
        // With the persist task stopped, so a pending write cannot bring back what
        // is cleared now, and restarted afterwards also after a failed clear.
        match self.context.persistence() {
            Some(persistence) => persistence.run_clear(clear).await,
            None => Ok(clear.await?),
        }
    }

    async fn prepare_rediscovery(&self) -> u64 {
        self.context.runtime.set_plan(DiscoveryPlan::Broadcast);
        self.source.reset_ecu_states(false).await;
        self.context.runtime.discovery_generation()
    }

    async fn wait_rediscovered(&self, marker: u64) -> RediscoveryWait {
        if let Some(persistence) = self.context.persistence() {
            return persistence.wait_rediscovered(marker).await;
        }
        let timeout = self.context.settle_timeout;
        let settled = tokio::time::timeout(timeout, async {
            if self.context.doip_enabled
                && self
                    .context
                    .runtime
                    .wait_settled(timeout)
                    .await
                    .is_none_or(|outcome| outcome.generation <= marker)
            {
                return false;
            }
            self.source
                .detection_tracker()
                .await
                .wait_idle(timeout)
                .await
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
    use std::time::Duration;

    use cda_interfaces::{
        DetectionTracker, HashMap,
        communication_control::CommunicationInitMode,
        topology::{
            EcuTopologyEntry, EcuTopologyStore, KnownGateway, PersistedGateway, PersistedTopology,
            TopologyRuntime, TopologyStoreError,
        },
    };
    use cda_storage::LocalStorage;

    use super::*;
    use crate::config::configfile::Configuration;

    struct Source(DetectionTracker);

    #[async_trait]
    impl EcuTopologySource for Source {
        async fn ecu_topology_entries(&self) -> Vec<EcuTopologyEntry> {
            Vec::new()
        }
        async fn detection_tracker(&self) -> DetectionTracker {
            self.0.clone()
        }
        async fn reset_ecu_states(&self, _only_assumed_online: bool) {}
    }

    /// Store whose `clear` fails.
    struct FailingClearStore;

    #[async_trait]
    impl EcuTopologyStore for FailingClearStore {
        fn is_enabled(&self) -> bool {
            true
        }
        async fn load(&self) -> Result<PersistedTopology, TopologyStoreError> {
            Ok(PersistedTopology::default())
        }
        async fn upsert(&self, _gateways: &[PersistedGateway]) -> Result<(), TopologyStoreError> {
            Ok(())
        }
        async fn merge_last_seen(
            &self,
            _last_seen: &HashMap<String, std::time::SystemTime>,
        ) -> Result<usize, TopologyStoreError> {
            Ok(0)
        }
        async fn clear(&self) -> Result<(), TopologyStoreError> {
            Err(TopologyStoreError::Serialization("disk full".to_owned()))
        }
        async fn prune(
            &self,
            _keep: &HashMap<u16, cda_interfaces::HashSet<String>>,
        ) -> Result<usize, TopologyStoreError> {
            Ok(0)
        }
    }

    /// The adapter bounds the wait by the context's settle budget.
    fn short_settle_timeout(context: &mut Arc<TopologyContext>) {
        Arc::get_mut(context)
            .expect("the context is not shared yet")
            .settle_timeout = Duration::from_millis(10);
    }

    #[tokio::test]
    async fn failed_clear_keeps_the_in_memory_state() {
        let context = Arc::new(TopologyContext {
            store: Arc::new(FailingClearStore),
            runtime: TopologyRuntime::new(DiscoveryPlan::Broadcast),
            init_mode: CommunicationInitMode::WhenNotPersisted,
            settle_timeout: Duration::from_secs(1),
            doip_enabled: true,
            persistence: std::sync::OnceLock::new(),
        });
        let plan = DiscoveryPlan::Reconnect {
            known: vec![KnownGateway {
                name: "gw".to_owned(),
                logical_address: 0x1000,
                network_address: Some("10.0.0.1".to_owned()),
                doip_protocol_version: Some(3),
            }],
            search: Vec::new(),
        };
        context.runtime.set_plan(plan.clone());
        context.runtime.set_has_persisted(true);
        let backend = TopologyResetAdapter::new(
            Arc::clone(&context),
            Arc::new(Source(DetectionTracker::new())),
            Arc::new(CountingPending::default()),
        );

        assert!(backend.clear_persisted().await.is_err());
        assert_eq!(context.runtime.plan(), plan);
        assert!(context.runtime.has_persisted());
    }

    /// [[ test~plugin-vehicle-topology-reset-doip-reset-requires-a-new-settled-discovery, Without persistence a `DoIP` rediscovery completes only with a new settled discovery, test ]]
    #[tokio::test]
    async fn doip_reset_requires_a_new_settled_discovery() {
        let dir = tempfile::tempdir().unwrap();
        let mut context = TopologyContext::new(
            &Configuration::default(),
            Arc::new(LocalStorage::new(dir.path()).unwrap()),
        );
        short_settle_timeout(&mut context);
        let generation = context.runtime.begin_discovery();
        context.runtime.finish_discovery(generation, true);
        let backend = TopologyResetAdapter::new(
            Arc::clone(&context),
            Arc::new(Source(DetectionTracker::new())),
            Arc::new(CountingPending::default()),
        );
        let marker = backend.prepare_rediscovery().await;
        assert_eq!(
            backend.wait_rediscovered(marker).await,
            RediscoveryWait::TimedOut
        );
        let generation = context.runtime.begin_discovery();
        assert_eq!(
            backend.wait_rediscovered(marker).await,
            RediscoveryWait::TimedOut
        );
        context.runtime.finish_discovery(generation, true);
        assert_eq!(
            backend.wait_rediscovered(marker).await,
            RediscoveryWait::Settled
        );
    }

    /// Counts the pending gateways' forget calls.
    #[derive(Default)]
    struct CountingPending(std::sync::atomic::AtomicUsize);

    #[async_trait]
    impl PendingGateways for CountingPending {
        async fn has_pending(&self) -> bool {
            false
        }
        async fn connect_all_pending(&self) {}
        async fn forget_pending_addresses(&self) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}
