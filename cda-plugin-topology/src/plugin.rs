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

//! Generic topology plugin contract.

pub mod default;

use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use cda_interfaces::{
    DiagServiceError, HashSet, VariantDetectionActivity,
    communication_control::{CommunicationInitMode, CommunicationLifecycle, TopologySettings},
    topology::{
        EcuTopologyEntry, EcuTopologyStore, NetworkReset, PersistedVariant, TopologyState,
        VamPolicy,
    },
};

/// Input of a topology plugin, derived by the application from its own
/// configuration so the plugin does not depend on it.
#[derive(Debug, Clone)]
pub struct TopologyPolicy {
    /// The effective topology settings. The application has already resolved
    /// them against the transports in use, e.g. persistence is disabled if the
    /// transports cannot persist the topology.
    pub settings: TopologySettings,
    /// Configured `init_mode`.
    pub init_mode: CommunicationInitMode,
    /// Lowercase names of the ECUs pinned to the CAN transport. They are never
    /// restored as `AssumedOnline`.
    pub ecus_pinned_to_can_transport: HashSet<String>,
    /// Whether gateway discovery is configured; CAN-only setups have no `DoIP` discovery.
    pub doip_enabled: bool,
    /// The retry hint of a send or connect refused while communication is quiesced.
    pub deferred_retry_after: Duration,
}

impl TopologyPolicy {
    /// Whether the topology is persisted and restored.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.settings.ecu_list_persistence.enabled
    }

    /// The policy for spontaneous vehicle announcements.
    #[must_use]
    pub fn vam_policy(&self) -> VamPolicy {
        VamPolicy {
            mode: self.settings.vam_handling_mode,
            persistence_enabled: self.enabled(),
        }
    }
}

/// An ECU of the loaded databases, as far as the topology is concerned.
#[derive(Debug, Clone)]
pub struct DatabaseEcu {
    /// Name of the ECU, as keyed in the databases.
    pub name: String,
    /// Logical address of the ECU.
    pub logical_address: u16,
    /// Logical address of the gateway the ECU is reached through.
    pub gateway_address: u16,
    /// Whether this is a physical ECU, as opposed to a functional group.
    pub is_physical: bool,
    /// Names of the ECUs sharing this ECU's address, empty if there are none.
    pub duplicating_ecu_names: Vec<String>,
}

/// Access to the loaded databases for restoring and planning the topology,
/// independent of the concrete ECU manager type.
#[async_trait]
pub trait TopologyDatabases: Send + Sync {
    /// All ECUs of the databases.
    async fn ecus(&self) -> Vec<DatabaseEcu>;

    /// Restores the `last_seen` timestamp of `ecu`.
    async fn restore_last_seen(&self, ecu: &str, at: SystemTime);

    /// Registers `ecu` as `AssumedOnline` with `variant`. Returns `Ok(false)`,
    /// without changing anything, if the variant is not in the database.
    ///
    /// # Errors
    /// Returns an error if the database cannot be loaded or the default service
    /// states cannot be set.
    async fn restore_variant(
        &self,
        ecu: &str,
        variant: &PersistedVariant,
    ) -> Result<bool, DiagServiceError>;

    /// Registers `ecu` as the restored losing member of a duplicate group.
    async fn restore_duplicate(&self, ecu: &str);
}

/// Read access to the live ECUs, independent of the concrete UDS manager type.
#[async_trait]
pub trait TopologySource: Send + Sync + 'static {
    /// Snapshot of all physical ECUs.
    async fn ecu_topology_entries(&self) -> Vec<EcuTopologyEntry>;

    /// Tracker of the current UDS manager, idle when no detection is pending.
    async fn detection_activity(&self) -> VariantDetectionActivity;

    /// Resets ECU states to `NotTested`, keeping `last_seen`. With
    /// `only_assumed_online`, only ECUs still assumed online are reset.
    async fn reset_ecu_states(&self, only_assumed_online: bool);
}

/// A topology plugin wired into the CDA runtime: it stores, restores and plans
/// the reuse of the detected ECU topology.
///
/// The default implementation is
/// [`DefaultTopologyPlugin`](default::DefaultTopologyPlugin); others are
/// substituted via `Setup::with_topology_plugin`. Every
/// implementation must also implement [`cda_interfaces::Shutdown`], which the
/// application calls once before the communication plugin shuts down: it is the
/// last point at which the topology can still be written.
#[async_trait]
pub trait TopologyPlugin: cda_interfaces::Shutdown {
    /// Discovery plan and connected gateways, shared with the transport.
    fn state(&self) -> Arc<TopologyState>;

    /// Whether the topology is persisted and restored.
    fn is_enabled(&self) -> bool;

    /// Reads the persisted topology after the databases are loaded, restores
    /// applicable ECU state, and, unless `init_mode` is `Always`, plans a
    /// reconnect to the persisted gateways. This is a startup-only operation;
    /// runtime database updates deliberately detect ECU states anew.
    async fn restore_persisted_topology(&self, databases: &dyn TopologyDatabases);

    /// Recomputes the gateways a persisted-gateway strategy searches by VIR from
    /// the current databases, e.g. after a runtime database update added a
    /// gateway.
    async fn refresh_reconnect_search(&self, databases: &dyn TopologyDatabases);

    /// Creates the communication hook that writes the detected topology, reading
    /// from `source`. Register it after the UDS manager hooks. Returns `None` if
    /// the topology is not persisted or the hook was created already.
    fn create_lifecycle_hook(
        &self,
        source: Arc<dyn TopologySource>,
    ) -> Option<Arc<dyn CommunicationLifecycle>>;

    /// Creates the topology operations of a `networkreset`, reading from
    /// `source`. Call it after [`create_lifecycle_hook`](Self::create_lifecycle_hook),
    /// so they run with the persist task.
    fn reset_handle(&self, source: Arc<dyn TopologySource>) -> Arc<dyn NetworkReset>;
}

/// Factory for a topology plugin.
pub trait TopologyPluginBuilder: Send {
    /// Plugin produced by this factory.
    type Plugin: TopologyPlugin;
    /// Construction error.
    type Error: std::fmt::Display + Send;

    /// Builds the plugin. `store` is a no-op store if `input.enabled()` is
    /// false, so a plugin can use it unconditionally.
    fn build(
        self,
        input: TopologyPolicy,
        store: Arc<dyn EcuTopologyStore>,
    ) -> impl Future<Output = Result<Self::Plugin, Self::Error>> + Send;
}

/// Closure adapter for [`TopologyPluginBuilder`].
pub struct TopologyPluginFn<F>(F);

/// Wraps an async closure as a [`TopologyPluginBuilder`].
pub fn topology_plugin_fn<F>(factory: F) -> TopologyPluginFn<F> {
    TopologyPluginFn(factory)
}

impl<F, Fut, P, E> TopologyPluginBuilder for TopologyPluginFn<F>
where
    F: FnOnce(TopologyPolicy, Arc<dyn EcuTopologyStore>) -> Fut + Send,
    Fut: Future<Output = Result<P, E>> + Send,
    P: TopologyPlugin,
    E: std::fmt::Display + Send,
{
    type Plugin = P;
    type Error = E;

    async fn build(self, input: TopologyPolicy, store: Arc<dyn EcuTopologyStore>) -> Result<P, E> {
        self.0(input, store).await
    }
}
