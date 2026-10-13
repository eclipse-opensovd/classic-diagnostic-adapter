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

//! Persisted ECU/gateway topology.
//!
//! The detected topology is persisted so that a restart does not necessarily need a
//! full VIR/VAM discovery and variant detection again. The types here are the
//! in-memory model; the on-disk format is owned by the [`EcuTopologyStore`]
//! implementation.

use std::time::SystemTime;

use async_trait::async_trait;

use crate::{HashMap, communication_control::VamHandlingMode, storage_api::StorageError};

/// Name of the storage collection holding the persisted topology.
pub const ECU_TOPOLOGY_COLLECTION: &str = "ecu-topology";

/// Returns the storage key of a persisted gateway entry, e.g. `0x1000`.
#[must_use]
pub fn gateway_key(logical_address: u16) -> String {
    format!("{logical_address:#06x}")
}

/// The persisted topology: one entry per gateway.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PersistedTopology {
    /// All persisted gateways that could be read.
    pub gateways: Vec<PersistedGateway>,
}

impl PersistedTopology {
    /// Returns `true` if no gateway is persisted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.gateways.is_empty()
    }
}

/// A persisted gateway and the ECUs reachable through it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedGateway {
    /// Name of the gateway ECU in the diagnostic database.
    pub name: String,
    /// Logical address of the gateway.
    pub logical_address: u16,
    /// Network (IP) address the gateway was last reached at. `None` if the
    /// gateway was not found by the last full broadcast discovery, so a missing
    /// gateway does not force a new broadcast on every startup.
    pub network_address: Option<String>,
    /// `DoIP` protocol version announced by the gateway.
    pub doip_protocol_version: Option<u8>,
    /// ECUs reachable through this gateway, including the gateway ECU itself.
    pub ecus: Vec<PersistedEcu>,
}

/// A persisted ECU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedEcu {
    /// Name of the ECU in the diagnostic database.
    pub name: String,
    /// Logical address of the ECU.
    pub logical_address: u16,
    /// Last known variant, if one was detected.
    pub variant: Option<PersistedVariant>,
    /// Last known state.
    pub state: PersistedEcuState,
    /// Time of the last successful diagnostic contact.
    pub last_seen: Option<SystemTime>,
}

/// A persisted variant detection result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedVariant {
    /// Variant name.
    pub name: String,
    /// Whether the variant is the base variant.
    pub is_base_variant: bool,
    /// Whether the variant was selected as fallback.
    pub is_fallback: bool,
}

/// Last known ECU state, as reported over SOVD.
///
/// The internal `AssumedOnline` state is persisted as [`Online`](Self::Online),
/// since such an ECU has not been contacted since it was last persisted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistedEcuState {
    /// Reachable with a detected variant.
    Online,
    /// Tested, but never reached since registration.
    Offline,
    /// Variant detection not performed.
    NotTested,
    /// Reachable, but no variant matched.
    NoVariantDetected,
    /// Superseded by another ECU with the same logical address.
    Duplicate,
    /// Previously reachable, communication lost.
    Disconnected,
}

/// A gateway with a known network address, used to reconnect without a broadcast.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownGateway {
    /// Name of the gateway ECU in the diagnostic database.
    pub name: String,
    /// Logical address of the gateway.
    pub logical_address: u16,
    /// Network (IP) address. `None` if the gateway was not found by the last full
    /// broadcast discovery.
    pub network_address: Option<String>,
    /// `DoIP` protocol version announced by the gateway.
    pub doip_protocol_version: Option<u8>,
}

impl From<&PersistedGateway> for KnownGateway {
    fn from(gateway: &PersistedGateway) -> Self {
        Self {
            name: gateway.name.clone(),
            logical_address: gateway.logical_address,
            network_address: gateway.network_address.clone(),
            doip_protocol_version: gateway.doip_protocol_version,
        }
    }
}

/// How the transport discovers gateways on its next start.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum DiscoveryPlan {
    /// Full VIR/VAM broadcast discovery.
    #[default]
    Broadcast,
    /// Reconnect directly to persisted gateways, with a broadcast fallback for
    /// gateways that cannot be reached.
    Reconnect {
        /// The persisted gateways.
        known: Vec<KnownGateway>,
        /// Logical addresses of physical database gateways that are not
        /// persisted (e.g. added by a database update) and must be searched by a
        /// broadcast.
        search: Vec<u16>,
    },
}

impl DiscoveryPlan {
    /// Builds the plan for a persisted topology: [`Broadcast`](Self::Broadcast)
    /// if nothing is persisted, otherwise a reconnect to the persisted gateways.
    /// `db_gateways` are the logical addresses of all physical database gateways.
    #[must_use]
    pub fn for_persisted(topology: &PersistedTopology, db_gateways: &[u16]) -> Self {
        if topology.is_empty() {
            return Self::Broadcast;
        }
        Self::Reconnect {
            known: topology.gateways.iter().map(KnownGateway::from).collect(),
            search: Vec::new(),
        }
        .with_search_for(db_gateways)
    }

    /// Recomputes which database gateways a reconnect searches by broadcast: all
    /// of `db_gateways` that are not persisted. A [`Broadcast`](Self::Broadcast)
    /// plan is returned unchanged.
    #[must_use]
    pub fn with_search_for(self, db_gateways: &[u16]) -> Self {
        match self {
            Self::Broadcast => Self::Broadcast,
            Self::Reconnect { known, .. } => {
                let search = db_gateways
                    .iter()
                    .copied()
                    .filter(|address| !known.iter().any(|g| g.logical_address == *address))
                    .collect();
                Self::Reconnect { known, search }
            }
        }
    }
}

/// Handling of spontaneous vehicle announcements, see [`VamHandlingMode`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VamPolicy {
    /// Configured mode.
    pub mode: VamHandlingMode,
    /// Whether ECU list persistence is enabled.
    pub persistence_enabled: bool,
}

/// Result of a completed gateway discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryOutcome {
    /// Generation of the discovery, see [`TopologyRuntime::begin_discovery`].
    pub generation: u64,
    /// Whether every gateway of the databases was searched by a broadcast, so a
    /// gateway that was not found is known to be absent.
    pub full_broadcast: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiscoveryProgress {
    Idle,
    Running(u64),
    Settled(DiscoveryOutcome),
}

/// Topology state shared between the transport and topology persistence.
///
/// The transport reads the [`DiscoveryPlan`] on start and reports connected
/// gateways and the end of the initial discovery; persistence waits for that end
/// and snapshots the connected gateways.
#[derive(Debug)]
pub struct TopologyRuntime {
    plan: parking_lot::RwLock<DiscoveryPlan>,
    vam_policy: parking_lot::RwLock<VamPolicy>,
    has_persisted: std::sync::atomic::AtomicBool,
    lazy_start: std::sync::atomic::AtomicBool,
    connected: parking_lot::RwLock<HashMap<u16, KnownGateway>>,
    progress: tokio::sync::watch::Sender<DiscoveryProgress>,
    generation: std::sync::atomic::AtomicU64,
}

impl TopologyRuntime {
    /// Creates a runtime starting with `plan`.
    #[must_use]
    pub fn new(plan: DiscoveryPlan) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            plan: parking_lot::RwLock::new(plan),
            vam_policy: parking_lot::RwLock::new(VamPolicy::default()),
            has_persisted: std::sync::atomic::AtomicBool::new(false),
            lazy_start: std::sync::atomic::AtomicBool::new(false),
            connected: parking_lot::RwLock::new(HashMap::default()),
            progress: tokio::sync::watch::Sender::new(DiscoveryProgress::Idle),
            generation: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// The plan for the next transport start.
    #[must_use]
    pub fn plan(&self) -> DiscoveryPlan {
        self.plan.read().clone()
    }

    /// Replaces the plan for the next transport start.
    pub fn set_plan(&self, plan: DiscoveryPlan) {
        *self.plan.write() = plan;
    }

    /// Marks the start of a discovery and forgets previously connected gateways.
    /// Returns the generation to pass to [`finish_discovery`](Self::finish_discovery).
    pub fn begin_discovery(&self) -> u64 {
        let generation = self
            .generation
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
            .wrapping_add(1);
        self.connected.write().clear();
        self.progress
            .send_replace(DiscoveryProgress::Running(generation));
        generation
    }

    /// Records a gateway connected during or after the discovery.
    pub fn record_connected(&self, gateway: KnownGateway) {
        self.connected
            .write()
            .insert(gateway.logical_address, gateway);
    }

    /// Marks the discovery `generation` as complete. Ignored if a newer
    /// discovery has started meanwhile.
    pub fn finish_discovery(&self, generation: u64, full_broadcast: bool) {
        self.progress.send_if_modified(|progress| {
            if *progress == DiscoveryProgress::Running(generation) {
                *progress = DiscoveryProgress::Settled(DiscoveryOutcome {
                    generation,
                    full_broadcast,
                });
                true
            } else {
                false
            }
        });
    }

    /// Waits until the current discovery has completed. Returns `None` if no
    /// discovery was started or `timeout` elapsed first.
    pub async fn wait_settled(&self, timeout: std::time::Duration) -> Option<DiscoveryOutcome> {
        let mut rx = self.progress.subscribe();
        let wait = rx.wait_for(|progress| !matches!(progress, DiscoveryProgress::Running(_)));
        match tokio::time::timeout(timeout, wait).await {
            Ok(Ok(progress)) => match *progress {
                DiscoveryProgress::Settled(outcome) => Some(outcome),
                DiscoveryProgress::Idle | DiscoveryProgress::Running(_) => None,
            },
            Ok(Err(_)) | Err(_) => None,
        }
    }

    /// Configures the handling of spontaneous vehicle announcements.
    pub fn set_vam_policy(&self, policy: VamPolicy) {
        *self.vam_policy.write() = policy;
    }

    /// Records whether a persisted topology exists.
    pub fn set_has_persisted(&self, has_persisted: bool) {
        self.has_persisted
            .store(has_persisted, std::sync::atomic::Ordering::Release);
    }

    /// Whether a persisted topology exists.
    #[must_use]
    pub fn has_persisted(&self) -> bool {
        self.has_persisted
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Requests that the next transport start with a reconnect plan connects no
    /// gateway up front: each gateway connects on its first use. Used for the
    /// `OnDemand` first-diagnostic-request trigger.
    pub fn request_lazy_start(&self) {
        self.lazy_start
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Consumes a [`request_lazy_start`](Self::request_lazy_start).
    #[must_use]
    pub fn take_lazy_start(&self) -> bool {
        self.lazy_start
            .swap(false, std::sync::atomic::Ordering::AcqRel)
    }

    /// Whether the spontaneous VAM listener is started at all.
    #[must_use]
    pub fn listens_for_vams(&self) -> bool {
        let policy = *self.vam_policy.read();
        match policy.mode {
            VamHandlingMode::Always => true,
            VamHandlingMode::PersistedOnly => policy.persistence_enabled,
            VamHandlingMode::Never => false,
        }
    }

    /// Whether a spontaneous announcement is handled right now.
    #[must_use]
    pub fn accepts_vams(&self) -> bool {
        let policy = *self.vam_policy.read();
        match policy.mode {
            VamHandlingMode::Always => true,
            VamHandlingMode::PersistedOnly => policy.persistence_enabled && self.has_persisted(),
            VamHandlingMode::Never => false,
        }
    }

    /// Gateways connected since the last [`begin_discovery`](Self::begin_discovery).
    #[must_use]
    pub fn connected(&self) -> Vec<KnownGateway> {
        self.connected.read().values().cloned().collect()
    }
}

/// Live state of a physical ECU, as needed to persist the topology.
#[derive(Debug, Clone)]
pub struct EcuTopologyEntry {
    /// Name of the ECU in the diagnostic database.
    pub name: String,
    /// Logical address of the ECU.
    pub logical_address: u16,
    /// Logical address of the gateway the ECU is reached through.
    pub gateway_address: u16,
    /// Current state snapshot.
    pub state: crate::EcuState,
    /// Shared runtime state, e.g. for `last_seen`.
    pub runtime_state: crate::EcuRuntimeState,
}

/// Errors of an [`EcuTopologyStore`].
#[derive(Debug, thiserror::Error)]
pub enum TopologyStoreError {
    /// The underlying storage failed.
    #[error("Topology storage failed: {0}")]
    Storage(#[from] StorageError),
    /// An entry could not be serialized.
    #[error("Topology serialization failed: {0}")]
    Serialization(String),
}

/// Persistence of the detected ECU/gateway topology.
///
/// Every write is durable when it returns (it is committed in its own
/// transaction). Implementations must never fail the caller for a single
/// unreadable entry: [`load`](Self::load) skips it and logs a warning.
#[async_trait]
pub trait EcuTopologyStore: Send + Sync + 'static {
    /// Returns `false` for the no-op store used when persistence is disabled.
    fn is_enabled(&self) -> bool;

    /// Loads all readable gateway entries. A missing collection is an empty
    /// topology.
    ///
    /// # Errors
    /// Returns an error if the collection exists but cannot be listed.
    async fn load(&self) -> Result<PersistedTopology, TopologyStoreError>;

    /// Writes the given gateways, replacing their existing entries. Entries of
    /// other gateways are left unchanged.
    ///
    /// # Errors
    /// Returns an error if the entries cannot be written.
    async fn upsert(&self, gateways: &[PersistedGateway]) -> Result<(), TopologyStoreError>;

    /// Updates the `last_seen` timestamp of the given ECUs (keyed by lowercase
    /// ECU name) in the existing entries. Never creates entries, so ECUs of a
    /// gateway that is not persisted are ignored.
    ///
    /// Returns the number of rewritten gateway entries.
    ///
    /// # Errors
    /// Returns an error if the entries cannot be read or written.
    async fn merge_last_seen(
        &self,
        last_seen: &HashMap<String, SystemTime>,
    ) -> Result<usize, TopologyStoreError>;

    /// Removes all persisted entries.
    ///
    /// # Errors
    /// Returns an error if the entries cannot be removed.
    async fn clear(&self) -> Result<(), TopologyStoreError>;

    /// Removes what is no longer in the databases: entries of gateways not in
    /// `keep`, and ECUs not listed for their gateway (lowercase names). Entries
    /// that are only missing from the last detection run are kept. Returns the
    /// number of removed or rewritten entries; nothing is written if nothing
    /// changes.
    ///
    /// # Errors
    /// Returns an error if the entries cannot be read or written.
    async fn prune(
        &self,
        keep: &HashMap<u16, crate::HashSet<String>>,
    ) -> Result<usize, TopologyStoreError>;
}

/// Input flags of a `networkreset` execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkResetFlags {
    /// Clear the persisted topology.
    pub clear_persisted: bool,
    /// Run a full live detection (VIR/VAM discovery and variant detection).
    pub trigger_detection: bool,
}

impl Default for NetworkResetFlags {
    fn default() -> Self {
        Self {
            clear_persisted: true,
            trigger_detection: true,
        }
    }
}

/// State of a `networkreset` execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkResetStatus {
    /// The execution is running.
    Running,
    /// The execution completed successfully.
    Completed,
    /// The execution failed.
    Failed(String),
    /// The execution was terminated before it completed.
    Stopped,
}

/// A `networkreset` execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkResetExecution {
    /// Execution identifier.
    pub id: String,
    /// The requested flags.
    pub flags: NetworkResetFlags,
    /// Current state.
    pub status: NetworkResetStatus,
}

/// Errors of starting a `networkreset` execution.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NetworkResetError {
    /// The request is invalid, e.g. both flags are `false`.
    #[error("Invalid network reset request: {0}")]
    InvalidRequest(String),
    /// Another execution is running.
    #[error("A network reset is already running")]
    ExecutionConflict,
    /// Diagnostic operations or locks prevent the reset.
    #[error("Operations in progress: {0}")]
    OperationsInProgress(String),
    /// The reset could not be started.
    #[error("Network reset failed: {0}")]
    Failed(String),
}

/// The vehicle topology plugin: resets the network structure (`networkreset`).
#[async_trait]
pub trait VehicleTopologyPlugin: Send + Sync + 'static {
    /// Starts an execution and returns its identifier. The caller must hold the
    /// exclusive vehicle lock (checked by the HTTP layer).
    ///
    /// # Errors
    /// Returns an error if the flags are invalid, another execution is running,
    /// or diagnostic operations are in progress.
    async fn start_reset(&self, flags: NetworkResetFlags) -> Result<String, NetworkResetError>;

    /// The current executions (at most one).
    async fn list_resets(&self) -> Vec<NetworkResetExecution>;

    /// The execution with `id`, if any.
    async fn get_reset(&self, id: &str) -> Option<NetworkResetExecution>;

    /// Terminates the execution with `id` if it is still running and removes it.
    /// Returns `false` if there is no such execution.
    async fn delete_reset(&self, id: &str) -> bool;

    /// Returns `true` while an execution is running.
    async fn is_running(&self) -> bool;
}

/// Topology operations a `networkreset` needs from the core.
#[async_trait]
pub trait TopologyResetBackend: Send + Sync + 'static {
    /// Clears the persisted topology (a no-op if persistence is disabled). The
    /// next transport start runs a full broadcast discovery, and ECUs still
    /// assumed online from the cleared topology are no longer reported Online.
    ///
    /// # Errors
    /// Returns an error if the persisted topology cannot be cleared.
    async fn clear_persisted(&self) -> Result<(), TopologyStoreError>;

    /// Prepares a full rediscovery while communication is disabled: the next
    /// transport start broadcasts, and all ECU states are reset (keeping
    /// `last_seen`). Returns a marker for [`wait_rediscovered`](Self::wait_rediscovered).
    async fn prepare_rediscovery(&self) -> u64;

    /// Waits until the rediscovery started after `marker` has settled and, if
    /// persistence is enabled, its result is persisted. Returns `false` if
    /// `timeout` elapsed first.
    async fn wait_rediscovered(&self, marker: u64, timeout: std::time::Duration) -> bool;
}

/// Starts a full topology rediscovery through the communication plugin.
#[async_trait]
pub trait TopologyRediscovery: Send + Sync + 'static {
    /// Enables communication if needed and runs a full discovery and detection.
    ///
    /// # Errors
    /// Returns the failure reason if the communication plugin refused or failed.
    async fn rediscover(&self) -> Result<(), String>;
}

/// No-op store used when ECU list persistence is disabled: nothing is ever
/// read or written.
#[derive(Debug, Clone, Copy, Default)]
pub struct DisabledTopologyStore;

#[async_trait]
impl EcuTopologyStore for DisabledTopologyStore {
    fn is_enabled(&self) -> bool {
        false
    }

    async fn load(&self) -> Result<PersistedTopology, TopologyStoreError> {
        Ok(PersistedTopology::default())
    }

    async fn upsert(&self, _gateways: &[PersistedGateway]) -> Result<(), TopologyStoreError> {
        Ok(())
    }

    async fn merge_last_seen(
        &self,
        _last_seen: &HashMap<String, SystemTime>,
    ) -> Result<usize, TopologyStoreError> {
        Ok(0)
    }

    async fn clear(&self) -> Result<(), TopologyStoreError> {
        Ok(())
    }

    async fn prune(
        &self,
        _keep: &HashMap<u16, crate::HashSet<String>>,
    ) -> Result<usize, TopologyStoreError> {
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn known(logical_address: u16) -> KnownGateway {
        KnownGateway {
            name: format!("gw_{logical_address:x}"),
            logical_address,
            network_address: Some("10.2.1.10".to_owned()),
            doip_protocol_version: Some(3),
        }
    }

    #[tokio::test]
    async fn discovery_settles_once_finished() {
        let runtime = TopologyRuntime::new(DiscoveryPlan::Broadcast);
        assert_eq!(runtime.wait_settled(Duration::from_millis(10)).await, None);

        let generation = runtime.begin_discovery();
        runtime.record_connected(known(0x1000));
        assert_eq!(runtime.wait_settled(Duration::from_millis(10)).await, None);

        runtime.finish_discovery(generation, true);
        assert_eq!(
            runtime.wait_settled(Duration::from_millis(10)).await,
            Some(DiscoveryOutcome {
                generation,
                full_broadcast: true
            })
        );
        assert_eq!(runtime.connected(), vec![known(0x1000)]);
    }

    /// [[ test~doip-vam-handling-mode, Spontaneous VAMs are handled per `vam_handling_mode`, test ]]
    #[test]
    fn vam_policy_matrix() {
        let runtime = TopologyRuntime::new(DiscoveryPlan::Broadcast);
        for (mode, persistence_enabled, has_persisted, listens, accepts) in [
            (VamHandlingMode::Always, false, false, true, true),
            (VamHandlingMode::Never, true, true, false, false),
            (VamHandlingMode::PersistedOnly, false, true, false, false),
            (VamHandlingMode::PersistedOnly, true, false, true, false),
            (VamHandlingMode::PersistedOnly, true, true, true, true),
        ] {
            runtime.set_vam_policy(VamPolicy {
                mode,
                persistence_enabled,
            });
            runtime.set_has_persisted(has_persisted);
            assert_eq!(runtime.listens_for_vams(), listens, "{mode:?}");
            assert_eq!(runtime.accepts_vams(), accepts, "{mode:?}");
        }
    }

    /// After a database update, gateways that are not persisted are searched.
    /// [[ test~ecu-topology-reconnect-search, Gateways not persisted are searched after a database update, test ]]
    #[test]
    fn reconnect_search_follows_the_current_databases() {
        let plan = DiscoveryPlan::Reconnect {
            known: vec![known(0x1000)],
            search: vec![0x2000],
        };
        // 0x2000 was removed, 0x3000 was added by the update.
        assert_eq!(
            plan.with_search_for(&[0x1000, 0x3000]),
            DiscoveryPlan::Reconnect {
                known: vec![known(0x1000)],
                search: vec![0x3000],
            }
        );
        assert_eq!(
            DiscoveryPlan::Broadcast.with_search_for(&[0x3000]),
            DiscoveryPlan::Broadcast
        );
    }

    #[test]
    fn lazy_start_is_consumed_once() {
        let runtime = TopologyRuntime::new(DiscoveryPlan::Broadcast);
        assert!(!runtime.take_lazy_start());
        runtime.request_lazy_start();
        assert!(runtime.take_lazy_start());
        assert!(!runtime.take_lazy_start());
    }

    #[tokio::test]
    async fn stale_finish_is_ignored_and_restart_forgets_gateways() {
        let runtime = TopologyRuntime::new(DiscoveryPlan::Broadcast);
        let first = runtime.begin_discovery();
        runtime.record_connected(known(0x1000));
        let second = runtime.begin_discovery();
        assert!(runtime.connected().is_empty());

        runtime.finish_discovery(first, true);
        assert_eq!(runtime.wait_settled(Duration::from_millis(10)).await, None);
        runtime.finish_discovery(second, false);
        assert_eq!(
            runtime
                .wait_settled(Duration::from_millis(10))
                .await
                .map(|o| o.generation),
            Some(second)
        );
    }

    #[test]
    fn gateway_key_is_zero_padded_hex() {
        assert_eq!(gateway_key(0x1000), "0x1000");
        assert_eq!(gateway_key(0x0E80), "0x0e80");
        assert_eq!(gateway_key(0x7), "0x0007");
    }
}
