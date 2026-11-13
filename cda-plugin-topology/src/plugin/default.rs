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

//! Default topology plugin: persists the detected ECU list in the storage and
//! reuses it on the next start.

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use cda_interfaces::{
    communication_control::{CommunicationInitMode, CommunicationLifecycle, TransportGate},
    topology::{
        DiscoveryStrategy, EcuTopologyStore, NetworkReset, TopologyState, physical_gateways,
    },
};

use super::{
    TopologyDatabases, TopologyPlugin, TopologyPluginBuilder, TopologyPolicy, TopologySource,
};
use crate::{REDISCOVERY_TIMEOUT, persist::TopologyPersistence, reset::TopologyReset, restore};

/// Logical addresses of the physical gateways in the databases.
async fn physical_db_gateways(databases: &dyn TopologyDatabases) -> Vec<u16> {
    physical_gateways(
        databases
            .ecus()
            .await
            .into_iter()
            .filter(|ecu| ecu.is_physical)
            .map(|ecu| (ecu.logical_address, ecu.gateway_address)),
    )
}

/// The default [`TopologyPlugin`].
///
/// With persistence disabled, the plugin only holds the shared
/// [`TopologyState`] and never touches the store.
pub struct DefaultTopologyPlugin {
    /// Topology policy: whether persistence is enabled, the init mode and the VAM policy.
    config: TopologyPolicy,
    /// Store that the detected ECU list is read from and written to.
    store: Arc<dyn EcuTopologyStore>,
    /// Discovery strategy and connected gateways, shared with the transport.
    topology_state: Arc<TopologyState>,
    /// Persistence hook, created once when the lifecycle hook is registered.
    /// Empty while persistence is disabled or not yet registered.
    persistence: OnceLock<Arc<TopologyPersistence>>,
}

impl DefaultTopologyPlugin {
    /// Creates the plugin writing to `store`. With `config.enabled()` false,
    /// pass a [`DisabledTopologyStore`], so nothing touches the storage.
    #[must_use]
    pub fn new(config: TopologyPolicy, store: Arc<dyn EcuTopologyStore>) -> Self {
        // A send or connect refused while communication is quiesced carries the
        // same retry hint as the other deferred answers.
        let state = TopologyState::with_transport_gate(
            DiscoveryStrategy::Vir,
            TransportGate::with_retry_after(config.deferred_retry_after),
        );
        state.set_vam_policy(config.vam_policy());
        Self {
            config,
            store,
            topology_state: state,
            persistence: OnceLock::new(),
        }
    }

    /// Whether a persisted topology is reused instead of a VIR discovery,
    /// i.e. `init_mode` is not `Always`.
    fn reuses_topology(&self) -> bool {
        self.config.init_mode != CommunicationInitMode::Always
    }

    /// The persistence hook, if it was created.
    #[must_use]
    pub fn persistence(&self) -> Option<&Arc<TopologyPersistence>> {
        self.persistence.get()
    }
}

#[async_trait]
impl cda_interfaces::Shutdown for DefaultTopologyPlugin {
    /// One final write. Detection results not written yet are written as a
    /// full snapshot (unless a detection is still running), and `last_seen` of
    /// contacted ECUs is written back.
    async fn shutdown(&self) {
        let Some(persistence) = self.persistence() else {
            return;
        };
        persistence.persist_on_shutdown().await;
    }
}

#[async_trait]
impl TopologyPlugin for DefaultTopologyPlugin {
    fn state(&self) -> Arc<TopologyState> {
        Arc::clone(&self.topology_state)
    }

    fn is_enabled(&self) -> bool {
        self.config.enabled()
    }

    async fn restore_persisted_topology(&self, databases: &dyn TopologyDatabases) {
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
        self.topology_state.set_persisted_topology_available();
        let report = restore::restore_ecu_states(
            databases,
            &persisted,
            self.reuses_topology(),
            &self.config.ecus_pinned_to_can_transport,
        )
        .await;
        if self.reuses_topology() {
            let db_gateways = physical_db_gateways(databases).await;
            self.topology_state
                .set_discovery_strategy(DiscoveryStrategy::for_persisted(&persisted, &db_gateways));
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

    async fn refresh_reconnect_search(&self, databases: &dyn TopologyDatabases) {
        let strategy = self.topology_state.discovery_strategy();
        if matches!(strategy, DiscoveryStrategy::Persisted { .. }) {
            // The persisted addresses may be older than the ones connected since
            // (persistence writes after the discovery settled), so the gateways
            // connected in the last discovery take precedence.
            self.topology_state.set_discovery_strategy(
                strategy
                    .with_connected(&self.topology_state.connected())
                    .with_search_for(&physical_db_gateways(databases).await),
            );
        }
    }

    fn create_lifecycle_hook(
        &self,
        source: Arc<dyn TopologySource>,
    ) -> Option<Arc<dyn CommunicationLifecycle>> {
        if !self.is_enabled() {
            return None;
        }
        let persistence = TopologyPersistence::new(
            Arc::clone(&self.store),
            Arc::clone(&self.topology_state),
            source,
            self.reuses_topology(),
        );
        self.persistence.set(Arc::clone(&persistence)).ok()?;
        Some(persistence)
    }

    fn reset_handle(&self, source: Arc<dyn TopologySource>) -> Arc<dyn NetworkReset> {
        Arc::new(TopologyReset {
            store: Arc::clone(&self.store),
            state: Arc::clone(&self.topology_state),
            source,
            persistence: self.persistence.get().cloned(),
            doip_enabled: self.config.doip_enabled,
            timeout: REDISCOVERY_TIMEOUT,
        })
    }
}

/// Factory for the default topology plugin.
#[derive(Default)]
pub struct DefaultTopologyPluginBuilder;

impl TopologyPluginBuilder for DefaultTopologyPluginBuilder {
    type Plugin = DefaultTopologyPlugin;
    type Error = std::convert::Infallible;

    fn build(
        self,
        config: TopologyPolicy,
        store: Arc<dyn EcuTopologyStore>,
    ) -> impl Future<Output = Result<Self::Plugin, Self::Error>> + Send {
        std::future::ready(Ok(DefaultTopologyPlugin::new(config, store)))
    }
}
