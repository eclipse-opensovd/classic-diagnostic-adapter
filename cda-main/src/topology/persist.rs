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

//! Writes the detected topology after every detection run, and `last_seen` at
//! shutdown.

use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use cda_interfaces::{
    Connectivity, DetectionTracker, EcuState, HashMap, HashMapExtensions as _, HashSet,
    VariantState,
    communication_control::{CommControlError, CommunicationLifecycle},
    topology::{
        DiscoveryPlan, EcuTopologyEntry, EcuTopologyStore, KnownGateway, PersistedEcu,
        PersistedEcuState, PersistedGateway, PersistedTopology, PersistedVariant, TopologyRuntime,
    },
};
use tokio::{sync::Mutex, task::JoinHandle};
use tokio_util::sync::CancellationToken;

/// How long detection must stay idle before a follow-up detection run is persisted.
/// Coalesces bursts (e.g. several gateways reconnecting) into one write.
const FOLLOW_UP_DEBOUNCE: Duration = Duration::from_secs(2);

/// Upper bound for the `last_seen` write-back at shutdown. Kept short, so a
/// stuck storage cannot delay the shutdown noticeably.
pub const SHUTDOWN_WRITE_TIMEOUT: Duration = Duration::from_secs(2);

/// Read access to the live ECUs, independent of the concrete UDS manager type.
#[async_trait]
pub trait EcuTopologySource: Send + Sync + 'static {
    /// Snapshot of all physical ECUs.
    async fn ecu_topology_entries(&self) -> Vec<EcuTopologyEntry>;

    /// Tracker of the current UDS manager, idle when no detection is pending.
    async fn detection_tracker(&self) -> DetectionTracker;

    /// Resets ECU states to `NotTested`, keeping `last_seen`. With
    /// `only_assumed_online`, only ECUs still assumed online are reset.
    async fn reset_ecu_states(&self, only_assumed_online: bool);
}

/// Persists the topology after every detection run and `last_seen` at shutdown.
///
/// Registered as a communication lifecycle hook: `on_enabled` starts a task that
/// waits for the initial discovery and variant detection to settle, persists the
/// result, and then persists every follow-up detection run (explicit
/// re-detection, reconnects, newly announced gateways). `deinitialize` cancels it,
/// so nothing is written while communication is being disabled.
/// [[ dimpl~ecu-topology-persist-after-detection, Persist the topology after every detection run, dimpl ]]
pub struct TopologyPersistence {
    store: Arc<dyn EcuTopologyStore>,
    runtime: Arc<TopologyRuntime>,
    source: Arc<dyn EcuTopologySource>,
    /// Whether the persisted topology is reused on the next transport start,
    /// i.e. `init_mode` is not `Always`.
    reuse_topology: bool,
    settle_timeout: Duration,
    task: Mutex<Option<(CancellationToken, JoinHandle<()>)>>,
    /// Last written gateways without `last_seen`, to skip writes that would not
    /// change anything but the timestamps (written back at shutdown instead).
    last_written: Mutex<Option<Vec<PersistedGateway>>>,
    /// Number of completed persist runs, see [`Self::wait_persisted`].
    persisted: tokio::sync::watch::Sender<u64>,
    /// Handle to itself, to move into the task spawned by `on_enabled`.
    this: std::sync::Weak<Self>,
}

impl TopologyPersistence {
    /// Creates the hook. Register it after the UDS manager hooks.
    #[must_use]
    pub fn new(
        store: Arc<dyn EcuTopologyStore>,
        runtime: Arc<TopologyRuntime>,
        source: Arc<dyn EcuTopologySource>,
        reuse_topology: bool,
        settle_timeout: Duration,
    ) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            store,
            runtime,
            source,
            reuse_topology,
            settle_timeout,
            task: Mutex::new(None),
            last_written: Mutex::new(None),
            persisted: tokio::sync::watch::Sender::new(0),
            this: std::sync::Weak::clone(this),
        })
    }

    /// Number of completed persist runs.
    #[must_use]
    pub fn persisted_count(&self) -> u64 {
        *self.persisted.borrow()
    }

    /// Waits until more than `after` persist runs have completed. Returns `false`
    /// if `timeout` elapsed first.
    pub async fn wait_persisted(&self, after: u64, timeout: Duration) -> bool {
        let mut rx = self.persisted.subscribe();
        tokio::time::timeout(timeout, rx.wait_for(|count| *count > after))
            .await
            .is_ok_and(|result| result.is_ok())
    }

    /// Cancels a pending persist run, e.g. before the persisted topology is cleared.
    pub async fn cancel_pending(&self) {
        if let Some((cancel, task)) = self.task.lock().await.take() {
            cancel.cancel();
            if let Err(error) = task.await
                && error.is_panic()
            {
                tracing::error!(%error, "Topology persistence task panicked");
            }
        }
    }

    /// Forgets what was written last, so the next run writes unconditionally,
    /// e.g. after the persisted topology was cleared.
    pub async fn forget_last_written(&self) {
        *self.last_written.lock().await = None;
    }

    /// Writes the `last_seen` timestamps of all ECUs contacted since they were
    /// last persisted. Never creates entries.
    pub async fn persist_last_seen(&self) {
        let mut last_seen: HashMap<String, SystemTime> = HashMap::new();
        for entry in self.source.ecu_topology_entries().await {
            if let Some(time) = entry.runtime_state.take_dirty_last_seen() {
                last_seen.insert(entry.name.to_lowercase(), time);
            }
        }
        if last_seen.is_empty() {
            return;
        }
        match self.store.merge_last_seen(&last_seen).await {
            Ok(count) => tracing::debug!(count, "Persisted last_seen timestamps"),
            Err(error) => tracing::warn!(%error, "Failed to persist last_seen timestamps"),
        }
    }

    /// Restarts watching for follow-up detection runs without persisting the
    /// current state first, e.g. after the persisted topology was cleared.
    pub async fn restart_follow_up(&self) {
        self.cancel_pending().await;
        self.spawn(false).await;
    }

    async fn spawn(&self, initial: bool) {
        let Some(this) = self.this.upgrade() else {
            return;
        };
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let task = cda_interfaces::spawn_named!("ecu-topology-persistence", async move {
            tokio::select! {
                () = task_cancel.cancelled() => {}
                () = this.run(initial) => {}
            }
        });
        *self.task.lock().await = Some((cancel, task));
    }

    async fn run(self: Arc<Self>, initial: bool) {
        let tracker = self.source.detection_tracker().await;
        if initial {
            self.persist_initial(&tracker).await;
        }

        // Follow-up detection runs (explicit re-detection, reconnects, gateways
        // announced later) are persisted once detection is idle again.
        let mut pending = tracker.subscribe();
        loop {
            if pending.wait_for(|count| *count > 0).await.is_err() {
                return;
            }
            loop {
                if pending.wait_for(|count| *count == 0).await.is_err() {
                    return;
                }
                let busy_again =
                    tokio::time::timeout(FOLLOW_UP_DEBOUNCE, pending.wait_for(|count| *count > 0))
                        .await;
                if busy_again.is_err() {
                    break;
                }
            }
            self.persist(false).await;
        }
    }

    async fn persist_initial(&self, tracker: &DetectionTracker) {
        let full_broadcast =
            if let Some(outcome) = self.runtime.wait_settled(self.settle_timeout).await {
                outcome.full_broadcast
            } else {
                tracing::warn!(
                    timeout = ?self.settle_timeout,
                    "Gateway discovery did not settle in time, persisting what is connected"
                );
                false
            };
        if !tracker.wait_idle(self.settle_timeout).await {
            tracing::warn!(
                timeout = ?self.settle_timeout,
                "Variant detection did not settle in time, persisting current states"
            );
        }
        self.persist(full_broadcast).await;
    }

    async fn persist(&self, full_broadcast: bool) {
        let stored = match self.store.load().await {
            Ok(stored) => stored,
            Err(error) => {
                tracing::warn!(%error, "Failed to read the persisted topology before writing");
                PersistedTopology::default()
            }
        };
        let entries = self.source.ecu_topology_entries().await;
        if !stored.is_empty() {
            self.prune(&entries).await;
        }
        let gateways = snapshot(&entries, &self.runtime.connected(), full_broadcast, &stored);

        let without_last_seen = strip_last_seen(&gateways);
        let unchanged = self.last_written.lock().await.as_ref() == Some(&without_last_seen);
        if gateways.is_empty() || unchanged {
            tracing::debug!(
                gateways = gateways.len(),
                unchanged,
                "Nothing new to persist"
            );
        } else {
            match self.store.upsert(&gateways).await {
                Ok(()) => {
                    tracing::info!(gateways = gateways.len(), "Persisted ECU topology");
                    let persisted: HashSet<&str> = gateways
                        .iter()
                        .flat_map(|g| g.ecus.iter().map(|e| e.name.as_str()))
                        .collect();
                    for entry in &entries {
                        if persisted.contains(entry.name.as_str()) {
                            entry.runtime_state.mark_last_seen_persisted();
                        }
                    }
                    *self.last_written.lock().await = Some(without_last_seen);
                }
                Err(error) => {
                    tracing::warn!(%error, "Failed to persist ECU topology");
                    return;
                }
            }
        }

        // Also tracks whether a topology exists, for `vam_handling_mode`.
        self.update_reconnect_plan().await;
        self.persisted
            .send_modify(|count| *count = count.saturating_add(1));
    }

    /// Removes persisted gateways and ECUs that are no longer in the databases,
    /// e.g. after a database update. Writes only if something is removed.
    /// [[ dimpl~ecu-topology-prune, Prune persisted entries not in the databases, dimpl ]]
    async fn prune(&self, entries: &[EcuTopologyEntry]) {
        let mut keep: HashMap<u16, HashSet<String>> = HashMap::new();
        for gateway in physical_gateways(entries) {
            keep.insert(gateway, HashSet::default());
        }
        for entry in entries {
            if let Some(ecus) = keep.get_mut(&entry.gateway_address) {
                ecus.insert(entry.name.to_lowercase());
            }
        }
        match self.store.prune(&keep).await {
            Ok(0) => {}
            Ok(count) => tracing::info!(count, "Pruned persisted topology entries"),
            Err(error) => tracing::warn!(%error, "Failed to prune the persisted topology"),
        }
    }

    /// Records that a topology is persisted and, unless `init_mode` is `Always`,
    /// lets the next transport start (e.g. after a runtime update) reconnect to the
    /// persisted gateways instead of broadcasting.
    async fn update_reconnect_plan(&self) {
        match self.store.load().await {
            Ok(topology) if !topology.is_empty() => {
                self.runtime.set_has_persisted(true);
                if !self.reuse_topology {
                    return;
                }
                let db_gateways = physical_gateways(&self.source.ecu_topology_entries().await);
                self.runtime
                    .set_plan(DiscoveryPlan::for_persisted(&topology, &db_gateways));
            }
            Ok(_) => {}
            Err(error) => tracing::warn!(%error, "Failed to read the persisted topology"),
        }
    }
}

#[async_trait]
impl CommunicationLifecycle for TopologyPersistence {
    fn name(&self) -> &'static str {
        "ecu-topology-persistence"
    }

    async fn initialize(&self) -> Result<(), CommControlError> {
        Ok(())
    }

    async fn on_enabled(&self) {
        // `on_enabled` must return quickly; the waiting happens in the task.
        self.cancel_pending().await;
        self.spawn(true).await;
    }

    async fn deinitialize(&self) {
        self.cancel_pending().await;
    }
}

/// Builds the gateway entries to write.
///
/// - A connected gateway gets a full entry with all ECUs reached through it.
/// - After a full broadcast, a database gateway that was not found and is not
///   persisted yet gets an entry without network address, so a gateway that is
///   not fitted does not force a broadcast on every start.
/// - Any other gateway is left untouched (not part of the result).
pub(crate) fn snapshot(
    entries: &[EcuTopologyEntry],
    connected: &[KnownGateway],
    full_broadcast: bool,
    stored: &PersistedTopology,
) -> Vec<PersistedGateway> {
    let mut ecus_by_gateway: HashMap<u16, Vec<&EcuTopologyEntry>> = HashMap::new();
    for entry in entries {
        ecus_by_gateway
            .entry(entry.gateway_address)
            .or_default()
            .push(entry);
    }

    let mut gateways: Vec<PersistedGateway> = connected
        .iter()
        .map(|gateway| PersistedGateway {
            name: gateway.name.clone(),
            logical_address: gateway.logical_address,
            network_address: gateway.network_address.clone(),
            doip_protocol_version: gateway.doip_protocol_version,
            ecus: persisted_ecus(ecus_by_gateway.get(&gateway.logical_address)),
        })
        .collect();

    if full_broadcast {
        let known: HashSet<u16> = connected
            .iter()
            .map(|g| g.logical_address)
            .chain(stored.gateways.iter().map(|g| g.logical_address))
            .collect();
        for entry in entries {
            if entry.logical_address == entry.gateway_address
                && !known.contains(&entry.logical_address)
            {
                gateways.push(PersistedGateway {
                    name: entry.name.clone(),
                    logical_address: entry.logical_address,
                    network_address: None,
                    doip_protocol_version: None,
                    ecus: Vec::new(),
                });
            }
        }
    }

    gateways.sort_by_key(|gateway| gateway.logical_address);
    gateways
}

/// Logical addresses of the physical gateways among `entries`.
pub(crate) fn physical_gateways(entries: &[EcuTopologyEntry]) -> Vec<u16> {
    let mut gateways: Vec<u16> = entries
        .iter()
        .filter(|entry| entry.logical_address == entry.gateway_address)
        .map(|entry| entry.logical_address)
        .collect();
    gateways.sort_unstable();
    gateways.dedup();
    gateways
}

fn persisted_ecus(entries: Option<&Vec<&EcuTopologyEntry>>) -> Vec<PersistedEcu> {
    let mut ecus: Vec<PersistedEcu> = entries
        .into_iter()
        .flatten()
        .map(|entry| PersistedEcu {
            name: entry.name.clone(),
            logical_address: entry.logical_address,
            variant: persisted_variant(&entry.state),
            state: persisted_state(&entry.state),
            last_seen: entry.runtime_state.last_seen(),
        })
        .collect();
    ecus.sort_by(|a, b| a.name.cmp(&b.name));
    ecus
}

fn persisted_variant(state: &EcuState) -> Option<PersistedVariant> {
    match &state.variant_state {
        VariantState::Detected {
            name,
            is_base_variant,
            is_fallback,
        } => Some(PersistedVariant {
            name: name.clone(),
            is_base_variant: *is_base_variant,
            is_fallback: *is_fallback,
        }),
        VariantState::NotTested | VariantState::Duplicate | VariantState::NotDetected => None,
    }
}

/// Same mapping as the SOVD state, so `AssumedOnline` is persisted as `Online`.
fn persisted_state(state: &EcuState) -> PersistedEcuState {
    match (state.connectivity, &state.variant_state) {
        (_, VariantState::Duplicate) => PersistedEcuState::Duplicate,
        (Connectivity::Online | Connectivity::AssumedOnline, VariantState::Detected { .. }) => {
            PersistedEcuState::Online
        }
        (Connectivity::Online | Connectivity::AssumedOnline, VariantState::NotDetected) => {
            PersistedEcuState::NoVariantDetected
        }
        (Connectivity::Online | Connectivity::AssumedOnline, VariantState::NotTested) => {
            PersistedEcuState::NotTested
        }
        (Connectivity::Offline, VariantState::NotTested) => PersistedEcuState::Offline,
        (Connectivity::Offline, VariantState::Detected { .. } | VariantState::NotDetected) => {
            PersistedEcuState::Disconnected
        }
    }
}

fn strip_last_seen(gateways: &[PersistedGateway]) -> Vec<PersistedGateway> {
    gateways
        .iter()
        .cloned()
        .map(|mut gateway| {
            for ecu in &mut gateway.ecus {
                ecu.last_seen = None;
            }
            gateway
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use cda_interfaces::EcuRuntimeState;
    use cda_storage::LocalStorage;

    use super::*;
    use crate::topology::StorageEcuTopologyStore;

    struct FakeSource {
        entries: Vec<EcuTopologyEntry>,
        tracker: DetectionTracker,
    }

    #[async_trait]
    impl EcuTopologySource for FakeSource {
        async fn ecu_topology_entries(&self) -> Vec<EcuTopologyEntry> {
            self.entries.clone()
        }

        async fn detection_tracker(&self) -> DetectionTracker {
            self.tracker.clone()
        }

        async fn reset_ecu_states(&self, _only_assumed_online: bool) {}
    }

    fn detected() -> VariantState {
        VariantState::Detected {
            name: "App".to_owned(),
            is_base_variant: false,
            is_fallback: false,
        }
    }

    fn entry(
        name: &str,
        logical_address: u16,
        gateway_address: u16,
        connectivity: Connectivity,
        variant_state: VariantState,
    ) -> EcuTopologyEntry {
        EcuTopologyEntry {
            name: name.to_owned(),
            logical_address,
            gateway_address,
            state: EcuState {
                connectivity,
                variant_state,
                variant_index: None,
            },
            runtime_state: EcuRuntimeState::new(),
        }
    }

    fn known(name: &str, logical_address: u16) -> KnownGateway {
        KnownGateway {
            name: name.to_owned(),
            logical_address,
            network_address: Some("10.2.1.10".to_owned()),
            doip_protocol_version: Some(3),
        }
    }

    fn vehicle() -> Vec<EcuTopologyEntry> {
        vec![
            entry("GW", 0x1000, 0x1000, Connectivity::Online, detected()),
            entry(
                "BEHIND_GW",
                0x1001,
                0x1000,
                Connectivity::AssumedOnline,
                detected(),
            ),
            entry(
                "NOT_FITTED",
                0x2000,
                0x2000,
                Connectivity::Offline,
                VariantState::NotTested,
            ),
            entry(
                "STORED_ONLY",
                0x3000,
                0x3000,
                Connectivity::Offline,
                VariantState::NotTested,
            ),
        ]
    }

    #[test]
    fn snapshot_writes_connected_and_absent_gateways_only() {
        let mut stored_only = PersistedGateway {
            name: "STORED_ONLY".to_owned(),
            logical_address: 0x3000,
            network_address: Some("10.2.1.30".to_owned()),
            doip_protocol_version: Some(3),
            ecus: Vec::new(),
        };
        let stored = PersistedTopology {
            gateways: vec![stored_only.clone()],
        };

        let gateways = snapshot(&vehicle(), &[known("GW", 0x1000)], true, &stored);
        assert_eq!(
            gateways.len(),
            2,
            "the stored-only gateway must stay untouched"
        );

        let gw = gateways.first().unwrap();
        assert_eq!(gw.logical_address, 0x1000);
        assert_eq!(gw.network_address.as_deref(), Some("10.2.1.10"));
        let states: Vec<_> = gw.ecus.iter().map(|e| (e.name.as_str(), e.state)).collect();
        assert_eq!(
            states,
            vec![
                // AssumedOnline is persisted as Online.
                ("BEHIND_GW", PersistedEcuState::Online),
                ("GW", PersistedEcuState::Online),
            ]
        );

        let not_fitted = gateways.get(1).unwrap();
        assert_eq!(not_fitted.logical_address, 0x2000);
        assert_eq!(not_fitted.network_address, None);
        assert!(not_fitted.ecus.is_empty());

        // Without a full broadcast, a missing gateway is not known to be absent.
        stored_only.ecus.clear();
        let gateways = snapshot(&vehicle(), &[known("GW", 0x1000)], false, &stored);
        assert_eq!(gateways.len(), 1);
    }

    #[test]
    fn persisted_state_follows_sovd_mapping() {
        for (connectivity, variant, expected) in [
            (
                Connectivity::Offline,
                detected(),
                PersistedEcuState::Disconnected,
            ),
            (
                Connectivity::Offline,
                VariantState::NotTested,
                PersistedEcuState::Offline,
            ),
            (
                Connectivity::Online,
                VariantState::NotDetected,
                PersistedEcuState::NoVariantDetected,
            ),
            (
                Connectivity::AssumedOnline,
                VariantState::Duplicate,
                PersistedEcuState::Duplicate,
            ),
        ] {
            let state = EcuState {
                connectivity,
                variant_state: variant,
                variant_index: None,
            };
            assert_eq!(persisted_state(&state), expected);
        }
    }

    fn fixture(
        entries: Vec<EcuTopologyEntry>,
    ) -> (
        Arc<TopologyPersistence>,
        Arc<StorageEcuTopologyStore<LocalStorage>>,
        Arc<TopologyRuntime>,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(LocalStorage::new(dir.path()).unwrap());
        let store = Arc::new(StorageEcuTopologyStore::new(storage));
        let runtime = TopologyRuntime::new(DiscoveryPlan::Broadcast);
        let persistence = TopologyPersistence::new(
            Arc::clone(&store) as Arc<dyn EcuTopologyStore>,
            Arc::clone(&runtime),
            Arc::new(FakeSource {
                entries,
                tracker: DetectionTracker::new(),
            }),
            true,
            Duration::from_secs(5),
        );
        (persistence, store, runtime, dir)
    }

    /// [[ test~ecu-topology-persist-after-detection, The topology is persisted once discovery and detection settled, test ]]
    #[tokio::test]
    async fn persists_once_discovery_settled_and_sets_reconnect_plan() {
        let (persistence, store, runtime, _dir) = fixture(vehicle());
        let generation = runtime.begin_discovery();
        runtime.record_connected(known("GW", 0x1000));

        persistence.on_enabled().await;
        assert!(
            !persistence
                .wait_persisted(0, Duration::from_millis(50))
                .await,
            "nothing is written before discovery settled"
        );

        runtime.finish_discovery(generation, true);
        assert!(persistence.wait_persisted(0, Duration::from_secs(5)).await);
        // The connected gateway plus the two database gateways a full broadcast
        // did not find.
        assert_eq!(store.load().await.unwrap().gateways.len(), 3);
        assert!(matches!(
            runtime.plan(),
            DiscoveryPlan::Reconnect { known, search } if known.len() == 3 && search.is_empty()
        ));

        persistence.deinitialize().await;
    }

    #[tokio::test]
    async fn deinitialize_cancels_pending_persist() {
        let (persistence, store, runtime, _dir) = fixture(vehicle());
        let generation = runtime.begin_discovery();
        persistence.on_enabled().await;
        persistence.deinitialize().await;

        runtime.finish_discovery(generation, true);
        assert!(
            !persistence
                .wait_persisted(0, Duration::from_millis(100))
                .await
        );
        assert!(store.load().await.unwrap().is_empty());
    }

    /// [[ test~ecu-list-persistence-shutdown, Contacted ECUs have `last_seen` written back at shutdown, test ]]
    #[tokio::test]
    async fn last_seen_of_contacted_ecus_is_written_back() {
        let entries = vehicle();
        let gw_state = entries.first().unwrap().runtime_state.clone();
        let (persistence, store, runtime, _dir) = fixture(entries);
        let generation = runtime.begin_discovery();
        runtime.record_connected(known("GW", 0x1000));
        runtime.finish_discovery(generation, false);
        persistence.on_enabled().await;
        assert!(persistence.wait_persisted(0, Duration::from_secs(5)).await);
        persistence.deinitialize().await;

        let before = store.load().await.unwrap();
        assert_eq!(
            before
                .gateways
                .first()
                .and_then(|g| g.ecus.iter().find(|e| e.name == "GW"))
                .and_then(|e| e.last_seen),
            None
        );

        gw_state.touch_last_seen();
        persistence.persist_last_seen().await;
        let after = store.load().await.unwrap();
        let millis = |time: SystemTime| {
            time.duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        };
        // Stored with millisecond precision.
        assert_eq!(
            after
                .gateways
                .first()
                .and_then(|g| g.ecus.iter().find(|e| e.name == "GW"))
                .and_then(|e| e.last_seen)
                .map(millis),
            gw_state.last_seen().map(millis)
        );
        assert_eq!(
            gw_state.take_dirty_last_seen(),
            None,
            "written back, so no longer dirty"
        );
    }
}
