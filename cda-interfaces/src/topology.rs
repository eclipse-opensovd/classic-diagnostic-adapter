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
//! full VIR/VAM discovery and variant detection again. The serialized form of the
//! persisted types is the on-disk format of the storage-backed [`EcuTopologyStore`].

use std::time::SystemTime;

use async_trait::async_trait;

use crate::{
    HashMap, communication_control::VamHandlingMode, storage_api::StorageError, util::std_ext,
};

/// Returns the storage key of a persisted gateway entry, e.g. `0x1000`.
#[must_use]
pub fn logical_address_hex(logical_address: u16) -> String {
    format!("{logical_address:#06x}")
}

/// Whether an ECU with this `logical_address` behind `gateway_address` is a physical
/// gateway, i.e. its own gateway.
#[must_use]
pub fn is_physical_gateway(logical_address: u16, gateway_address: u16) -> bool {
    logical_address == gateway_address
}

/// Logical addresses of the physical gateways, sorted and deduplicated. `ecus` yields
/// `(logical_address, gateway_address)` of each physical ECU; an ECU is a gateway if
/// both are equal, see [`is_physical_gateway`].
#[must_use]
pub fn physical_gateways(ecus: impl IntoIterator<Item = (u16, u16)>) -> Vec<u16> {
    let mut gateways: Vec<u16> = ecus
        .into_iter()
        .filter(|(logical_address, gateway_address)| {
            is_physical_gateway(*logical_address, *gateway_address)
        })
        .map(|(logical_address, _)| logical_address)
        .collect();
    gateways.sort_unstable();
    gateways.dedup();
    gateways
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

/// A persisted gateway and the ECUs reachable through it. Its serialized names
/// are part of the on-disk format of the topology store.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PersistedGateway {
    /// Name of the gateway ECU in the diagnostic database.
    pub name: String,
    /// Logical address of the gateway.
    pub logical_address: u16,
    /// Network (IP) address the gateway was last reached at. `None` if the
    /// gateway was not found by the last full VIR discovery, so a missing
    /// gateway does not force a new VIR on every startup.
    #[serde(default)]
    pub network_address: Option<String>,
    /// `DoIP` protocol version announced by the gateway.
    #[serde(default)]
    pub doip_protocol_version: Option<u8>,
    /// ECUs reachable through this gateway, including the gateway ECU itself.
    #[serde(default)]
    pub ecus: Vec<PersistedEcu>,
}

/// A persisted ECU. Its serialized names are part of the on-disk format of the
/// topology store.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PersistedEcu {
    /// Name of the ECU in the diagnostic database.
    pub name: String,
    /// Logical address of the ECU.
    pub logical_address: u16,
    /// Last known variant, if one was detected.
    #[serde(default)]
    pub variant: Option<PersistedVariant>,
    /// Last known state.
    pub state: PersistedEcuState,
    /// Time of the last reply of the ECU, serialized as RFC 3339 UTC with
    /// second precision.
    #[serde(default, with = "rfc3339_opt")]
    pub last_seen: Option<SystemTime>,
}

/// Serde format of an optional [`SystemTime`] as RFC 3339 string. A timestamp that
/// cannot be represented fails deserialization instead of being dropped.
mod rfc3339_opt {
    use std::time::SystemTime;

    use serde::{Deserialize as _, Deserializer, Serialize as _, Serializer, de::Error as _};

    use crate::util::{rfc3339_to_system_time, system_time_to_rfc3339};

    #[expect(
        clippy::ref_option,
        reason = "Signature required by serde's `with` attribute"
    )]
    pub(super) fn serialize<S: Serializer>(
        time: &Option<SystemTime>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        time.map(system_time_to_rfc3339).serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<SystemTime>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|value| {
                rfc3339_to_system_time(&value)
                    .ok_or_else(|| D::Error::custom(format!("Invalid timestamp {value:?}")))
            })
            .transpose()
    }
}

/// A persisted variant detection result. Its serialized names are part of the
/// on-disk format of the topology store.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
/// Its serialized names are part of the on-disk format of the topology store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

/// A gateway with a known network address, used to reconnect without a VIR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownGateway {
    /// Name of the gateway ECU in the diagnostic database.
    pub name: String,
    /// Logical address of the gateway.
    pub logical_address: u16,
    /// Network (IP) address. `None` if the gateway was not found by the last full
    /// VIR discovery.
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
pub enum DiscoveryStrategy {
    /// Full VIR/VAM discovery.
    #[default]
    Vir,
    /// Connect directly to persisted gateways, with a VIR fallback for
    /// gateways that cannot be reached.
    Persisted {
        /// The persisted gateways.
        known: Vec<KnownGateway>,
        /// Logical addresses of physical database gateways that are not
        /// persisted (e.g. added by a database update) and must be searched by a
        /// VIR.
        search: Vec<u16>,
    },
}

impl DiscoveryStrategy {
    /// Builds the strategy for a persisted topology: [`Vir`](Self::Vir)
    /// if nothing is persisted, otherwise a reconnect to the persisted gateways.
    /// `db_gateways` are the logical addresses of all physical database gateways.
    #[must_use]
    pub fn for_persisted(topology: &PersistedTopology, db_gateways: &[u16]) -> Self {
        if topology.is_empty() {
            return Self::Vir;
        }
        Self::Persisted {
            known: topology.gateways.iter().map(KnownGateway::from).collect(),
            search: Vec::new(),
        }
        .with_search_for(db_gateways)
    }

    /// Recomputes which database gateways a reconnect searches by VIR: all
    /// of `db_gateways` that are not persisted. A [`Vir`](Self::Vir)
    /// strategy is returned unchanged.
    #[must_use]
    pub fn with_search_for(self, db_gateways: &[u16]) -> Self {
        match self {
            Self::Vir => Self::Vir,
            Self::Persisted { known, .. } => {
                let search = db_gateways
                    .iter()
                    .copied()
                    .filter(|address| !known.iter().any(|g| g.logical_address == *address))
                    .collect();
                Self::Persisted { known, search }
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
    /// Whether every gateway of the databases was searched by a VIR, so a
    /// gateway that was not found is known to be absent.
    pub full_vir_discovery: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum GatewayStatus {
    Connected(KnownGateway),
    Unreachable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiscoveryProgress {
    Idle,
    Running(u64),
    Settled(DiscoveryOutcome),
}

/// Topology state shared between the transport and topology persistence.
///
/// The transport reads the [`DiscoveryStrategy`] on start and reports connected
/// gateways and the end of the initial discovery; persistence waits for that end
/// and snapshots the connected gateways.
#[derive(Debug)]
pub struct TopologyRuntime {
    discovery_strategy: std::sync::RwLock<DiscoveryStrategy>,
    vam_policy: std::sync::RwLock<VamPolicy>,
    has_persisted: std::sync::atomic::AtomicBool,
    gateways: std::sync::RwLock<HashMap<u16, GatewayStatus>>,
    unreachable_changes: tokio::sync::watch::Sender<u64>,
    progress: tokio::sync::watch::Sender<DiscoveryProgress>,
    generation: std::sync::atomic::AtomicU64,
}

impl TopologyRuntime {
    /// Creates a runtime starting with `discovery_strategy`.
    #[must_use]
    pub fn new(discovery_strategy: DiscoveryStrategy) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            discovery_strategy: std::sync::RwLock::new(discovery_strategy),
            vam_policy: std::sync::RwLock::new(VamPolicy::default()),
            has_persisted: std::sync::atomic::AtomicBool::new(false),
            gateways: std::sync::RwLock::new(HashMap::default()),
            unreachable_changes: tokio::sync::watch::Sender::new(0),
            progress: tokio::sync::watch::Sender::new(DiscoveryProgress::Idle),
            generation: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// The discovery strategy for the next transport start.
    #[must_use]
    pub fn discovery_strategy(&self) -> DiscoveryStrategy {
        std_ext::lock_read(&self.discovery_strategy).clone()
    }

    /// Replaces the discovery strategy for the next transport start.
    pub fn set_discovery_strategy(&self, discovery_strategy: DiscoveryStrategy) {
        *std_ext::lock_write(&self.discovery_strategy) = discovery_strategy;
    }

    /// Marks the start of a discovery and forgets previously connected and
    /// unreachable gateways.
    /// Returns the generation to pass to [`finish_discovery`](Self::finish_discovery).
    pub fn begin_discovery(&self) -> u64 {
        let mut gateways = std_ext::lock_write(&self.gateways);
        let generation = self
            .generation
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
            .wrapping_add(1);
        gateways.clear();
        self.progress
            .send_replace(DiscoveryProgress::Running(generation));
        generation
    }

    /// Records a gateway connected during or after the discovery.
    /// A later connect wins over an earlier failure of the same gateway.
    pub fn record_connected(&self, gateway: KnownGateway) {
        std_ext::lock_write(&self.gateways)
            .insert(gateway.logical_address, GatewayStatus::Connected(gateway));
    }

    /// Records a gateway whose connect was attempted and failed in the current
    /// discovery generation, and wakes the subscribers of
    /// [`subscribe_unreachable`](Self::subscribe_unreachable). Gateways that
    /// were not attempted must not be recorded.
    pub fn record_unreachable(&self, logical_address: u16) {
        std_ext::lock_write(&self.gateways).insert(logical_address, GatewayStatus::Unreachable);
        self.unreachable_changes
            .send_modify(|counter| *counter = counter.wrapping_add(1));
    }

    /// Gateways whose connect failed since the last
    /// [`begin_discovery`](Self::begin_discovery).
    #[must_use]
    pub fn unreachable(&self) -> Vec<u16> {
        std_ext::lock_read(&self.gateways)
            .iter()
            .filter(|(_, status)| matches!(status, GatewayStatus::Unreachable))
            .map(|(address, _)| *address)
            .collect()
    }

    /// Receiver of a counter that changes on every
    /// [`record_unreachable`](Self::record_unreachable).
    #[must_use]
    pub fn subscribe_unreachable(&self) -> tokio::sync::watch::Receiver<u64> {
        self.unreachable_changes.subscribe()
    }

    /// Marks the discovery `generation` as complete. Ignored if a newer
    /// discovery has started meanwhile.
    pub fn finish_discovery(&self, generation: u64, full_vir_discovery: bool) {
        self.progress.send_if_modified(|progress| {
            if *progress == DiscoveryProgress::Running(generation) {
                *progress = DiscoveryProgress::Settled(DiscoveryOutcome {
                    generation,
                    full_vir_discovery,
                });
                true
            } else {
                false
            }
        });
    }

    /// Whether a discovery is currently running.
    #[must_use]
    pub fn is_discovery_running(&self) -> bool {
        matches!(*self.progress.borrow(), DiscoveryProgress::Running(_))
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
        *std_ext::lock_write(&self.vam_policy) = policy;
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

    /// Whether the spontaneous VAM listener is started at all.
    #[must_use]
    pub fn listens_for_vams(&self) -> bool {
        let policy = *std_ext::lock_read(&self.vam_policy);
        match policy.mode {
            VamHandlingMode::Always => true,
            VamHandlingMode::PersistedOnly => policy.persistence_enabled,
            VamHandlingMode::Never => false,
        }
    }

    /// Whether a spontaneous announcement is handled right now.
    /// [[ dimpl~doip-vam-handling-mode, Spontaneous VAMs are handled per `vam_handling_mode`, dimpl ]]
    #[must_use]
    pub fn accepts_vams(&self) -> bool {
        self.listens_for_vams()
            && (std_ext::lock_read(&self.vam_policy).mode != VamHandlingMode::PersistedOnly
                || self.has_persisted())
    }

    /// Whether the gateway was recorded as connected since the last
    /// [`begin_discovery`](Self::begin_discovery).
    #[must_use]
    pub fn is_connected(&self, logical_address: u16) -> bool {
        matches!(
            std_ext::lock_read(&self.gateways).get(&logical_address),
            Some(GatewayStatus::Connected(_))
        )
    }

    /// Gateways connected since the last [`begin_discovery`](Self::begin_discovery).
    #[must_use]
    pub fn connected(&self) -> Vec<KnownGateway> {
        std_ext::lock_read(&self.gateways)
            .values()
            .filter_map(|status| match status {
                GatewayStatus::Connected(gateway) => Some(gateway.clone()),
                GatewayStatus::Unreachable => None,
            })
            .collect()
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
    async fn persist_gateways(
        &self,
        gateways: &[PersistedGateway],
    ) -> Result<(), TopologyStoreError>;

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

    /// Removes what is no longer in the databases and then writes `gateways` like
    /// [`persist_gateways`](Self::persist_gateways), both in one transaction.
    ///
    /// Removed are entries of gateways not in `keep`, ECUs not listed for their
    /// gateway (lowercase names), and entries that cannot be read. Entries that
    /// are only missing from the last detection run are kept. Returns the number
    /// of entries the pruning removed or rewrote; nothing is written if nothing
    /// changes.
    ///
    /// # Errors
    /// Returns an error if the entries cannot be read or written.
    async fn prune_and_persist_gateways(
        &self,
        keep: &HashMap<u16, crate::HashSet<String>>,
        gateways: &[PersistedGateway],
    ) -> Result<usize, TopologyStoreError>;
}

/// No-op store used when ECU list persistence is disabled: nothing is ever
/// read or written.
#[derive(Debug, Clone, Copy, Default)]
pub struct DisabledTopologyStore;

#[async_trait]
impl EcuTopologyStore for DisabledTopologyStore {
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
        _last_seen: &HashMap<String, SystemTime>,
    ) -> Result<usize, TopologyStoreError> {
        Ok(0)
    }

    async fn prune_and_persist_gateways(
        &self,
        _keep: &HashMap<u16, crate::HashSet<String>>,
        _gateways: &[PersistedGateway],
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

    #[test]
    fn unreachable_gateways_are_tracked_per_discovery() {
        let runtime = TopologyRuntime::new(DiscoveryStrategy::Vir);
        let rx = runtime.subscribe_unreachable();
        assert_eq!(*rx.borrow(), 0);

        runtime.record_unreachable(0x1000);
        runtime.record_unreachable(0x2000);
        assert_eq!(*rx.borrow(), 2);
        let mut unreachable = runtime.unreachable();
        unreachable.sort_unstable();
        assert_eq!(unreachable, vec![0x1000, 0x2000]);

        runtime.record_connected(known(0x1000));
        assert_eq!(runtime.unreachable(), vec![0x2000]);

        runtime.begin_discovery();
        assert!(runtime.unreachable().is_empty());
    }

    /// [[ test~doip-vam-handling-mode, Spontaneous VAMs are handled per `vam_handling_mode`, test ]]
    #[test]
    fn vam_policy_matrix() {
        let runtime = TopologyRuntime::new(DiscoveryStrategy::Vir);
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
        let strategy = DiscoveryStrategy::Persisted {
            known: vec![known(0x1000)],
            search: vec![0x2000],
        };
        // 0x2000 was removed, 0x3000 was added by the update.
        assert_eq!(
            strategy.with_search_for(&[0x1000, 0x3000]),
            DiscoveryStrategy::Persisted {
                known: vec![known(0x1000)],
                search: vec![0x3000],
            }
        );
        assert_eq!(
            DiscoveryStrategy::Vir.with_search_for(&[0x3000]),
            DiscoveryStrategy::Vir
        );
    }

    /// A persisted topology is reconnected to directly, without a VIR;
    /// only without one a full VIR discovery is planned.
    /// [[ test~ecu-list-persistence-reuse-plan, A persisted topology is reconnected without a VIR, test ]]
    #[test]
    fn persisted_topology_plans_a_direct_reconnect() {
        assert_eq!(
            DiscoveryStrategy::for_persisted(&PersistedTopology::default(), &[0x1000]),
            DiscoveryStrategy::Vir
        );
        let topology = PersistedTopology {
            gateways: vec![PersistedGateway {
                name: "gw_1000".to_owned(),
                logical_address: 0x1000,
                network_address: Some("10.2.1.10".to_owned()),
                doip_protocol_version: Some(3),
                ecus: Vec::new(),
            }],
        };
        assert_eq!(
            DiscoveryStrategy::for_persisted(&topology, &[0x1000]),
            DiscoveryStrategy::Persisted {
                known: vec![known(0x1000)],
                search: Vec::new(),
            }
        );
    }

    #[tokio::test]
    async fn stale_finish_is_ignored_and_restart_forgets_gateways() {
        let runtime = TopologyRuntime::new(DiscoveryStrategy::Vir);
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
}
