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

//! Writes the detected topology after every detection run, and the last
//! unwritten state plus `last_seen` at shutdown.

use std::{
    sync::{Arc, atomic::AtomicU64},
    time::SystemTime,
};

use async_trait::async_trait;
use cda_interfaces::{
    Connectivity, EcuState, HashMap, HashMapExtensions as _, HashSet, VariantDetectionActivity,
    VariantState,
    communication_control::{CommControlError, CommunicationLifecycle},
    topology::{
        DiscoveryStrategy, EcuTopologyEntry, EcuTopologyStore, KnownGateway, PersistedEcu,
        PersistedEcuState, PersistedGateway, PersistedTopology, PersistedVariant, TopologyState,
        TopologyStoreError,
    },
};
use tokio::{sync::Mutex, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::plugin::TopologySource;

/// The persist task and whether persistence was shut down. Guarded by one mutex,
/// so a shutdown write cannot interleave with a restart.
#[derive(Default)]
struct TaskSlot {
    task: Option<(CancellationToken, JoinHandle<()>)>,
    /// Set by the shutdown write: no task is started afterwards.
    shut_down: bool,
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
    /// Writes the topology, shared with the persist task.
    writer: Arc<TopologyWriter>,
    /// The persist task and shutdown state.
    task: Mutex<TaskSlot>,
}

/// Writes the topology to the store. Used by the persist task and the shutdown
/// write. Kept apart from the hook so the task can own a handle to it without the
/// hook referencing itself.
struct TopologyWriter {
    /// Store the topology is written to.
    store: Arc<dyn EcuTopologyStore>,
    /// Runtime state of the topology, providing the data to persist.
    state: Arc<TopologyState>,
    /// Source of the detected topology and detection progress.
    source: Arc<dyn TopologySource>,
    /// Whether the persisted topology is reused on the next transport start,
    /// i.e. `init_mode` is not `Always`.
    reuse_topology: bool,
    /// Detection generation whose results are written, see
    /// [`Self::has_unwritten_results`].
    acknowledged: AtomicU64,
    /// Number of completed persist runs.
    persisted: tokio::sync::watch::Sender<u64>,
}

impl TopologyPersistence {
    /// Creates the hook. Register it after the UDS manager hooks.
    #[must_use]
    pub fn new(
        store: Arc<dyn EcuTopologyStore>,
        runtime: Arc<TopologyState>,
        source: Arc<dyn TopologySource>,
        reuse_topology: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            writer: Arc::new(TopologyWriter {
                store,
                state: runtime,
                source,
                reuse_topology,
                acknowledged: AtomicU64::new(0),
                persisted: tokio::sync::watch::Sender::new(0),
            }),
            task: Mutex::new(TaskSlot::default()),
        })
    }

    /// Cancels a pending persist run and waits for it to stop.
    pub async fn cancel_pending(&self) {
        let mut slot = self.task.lock().await;
        Self::stop_task(&mut slot).await;
    }

    /// Writes the `last_seen` timestamps of all ECUs contacted since they were
    /// last persisted. Never creates entries.
    pub async fn persist_last_seen(&self) {
        self.writer.persist_last_seen().await;
    }

    /// Whether detection runs finished since the last write and no detection is
    /// running.
    #[must_use]
    pub fn has_unwritten_results(&self, activity: &VariantDetectionActivity) -> bool {
        self.writer.has_unwritten_results(activity)
    }

    /// Final write at shutdown. Detection results that were not written yet are
    /// written as a full snapshot, unless a detection is still running (its
    /// half-finished states are not written). `last_seen` of contacted ECUs is
    /// written back in any case.
    ///
    /// Runs under the task lock, after the running task was cancelled: a restart
    /// cannot interleave with the write, and no task is started afterwards.
    /// [[ dimpl~ecu-topology-persist-when-idle, Persist follow-up runs when idle and at shutdown, dimpl ]]
    pub async fn persist_on_shutdown(&self) {
        let mut slot = self.task.lock().await;
        Self::stop_task(&mut slot).await;
        let activity = self.writer.source.detection_activity().await;
        if self.writer.has_unwritten_results(&activity) {
            let generation = activity.generation();
            if self.writer.persist(false).await.is_ok() {
                self.writer
                    .acknowledged
                    .store(generation, std::sync::atomic::Ordering::Release);
            }
        }
        // Also covers a full write that was skipped as unchanged, which does not
        // write `last_seen`.
        self.writer.persist_last_seen().await;
        slot.shut_down = true;
    }

    /// Cancels the running task and starts a new one, atomically with respect to
    /// other callers: the `task` lock is held for the whole sequence, so no task
    /// can be orphaned or started after a later cancel.
    /// [[ dimpl~ecu-topology-persist-serialized, Persist task lifecycle and store writes are serialized, dimpl ]]
    async fn restart_task(&self) {
        let mut slot = self.task.lock().await;
        Self::stop_task(&mut slot).await;
        if !slot.shut_down {
            slot.task = Some(self.spawn_writer_task().await);
        }
    }

    /// Cancels the running task and waits for it.
    async fn stop_task(slot: &mut TaskSlot) {
        if let Some((cancel, task)) = slot.task.take() {
            cancel.cancel();
            if let Err(error) = task.await
                && error.is_panic()
            {
                tracing::error!(%error, "Topology persistence task panicked");
            }
        }
    }

    async fn spawn_writer_task(&self) -> (CancellationToken, JoinHandle<()>) {
        let writer = Arc::clone(&self.writer);
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        // Subscribe before returning to the caller so even a complete detection
        // between spawning and the task's first poll is retained.
        let activity = self.writer.source.detection_activity().await;
        let generations = activity.subscribe();
        let unreachable = self.writer.state.subscribe_unreachable();
        // What was written is not this tasks to write again; an initial run
        // writes the rest.
        let acknowledged = self
            .writer
            .acknowledged
            .load(std::sync::atomic::Ordering::Acquire);
        let task = cda_interfaces::spawn_named!("ecu-topology-persistence", async move {
            tokio::select! {
                () = task_cancel.cancelled() => {}
                () = writer.run(activity, generations, unreachable, acknowledged) => {}
            }
        });
        (cancel, task)
    }
}

impl TopologyWriter {
    /// Writes the `last_seen` timestamps of all ECUs contacted since they were
    /// last persisted. Never creates entries.
    async fn persist_last_seen(&self) {
        let mut last_seen: HashMap<String, SystemTime> = HashMap::new();
        let mut snapshots = Vec::new();
        for entry in self.source.ecu_topology_entries().await {
            let saved = entry.runtime_state.last_seen_snapshot();
            if let Some(time) = saved.at().filter(|_| saved.is_dirty()) {
                last_seen.insert(entry.name.to_lowercase(), time);
                snapshots.push((entry.runtime_state, saved));
            }
        }
        if last_seen.is_empty() {
            return;
        }
        match self.store.merge_last_seen(&last_seen).await {
            Ok(()) => {
                for (state, saved) in snapshots {
                    state.mark_last_seen_persisted(saved);
                }
                tracing::debug!("Persisted last_seen timestamps");
            }
            Err(error) => tracing::warn!(%error, "Failed to persist last_seen timestamps"),
        }
    }

    /// Whether detection runs finished since the last write and no detection is
    /// running.
    #[must_use]
    fn has_unwritten_results(&self, activity: &VariantDetectionActivity) -> bool {
        activity.is_idle()
            && activity.generation() != self.acknowledged.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Body of the persist task.
    ///
    /// First persists once the initial discovery and variant detection have
    /// settled. Then, in a loop, waits for a detection run to finish or for a
    /// gateway to be reported unreachable, and persists. A failed write is logged
    /// by `persist` and not retried until the next trigger.
    ///
    /// `acknowledged` is the last detection generation this task has attempted to
    /// write. It decides which finished run triggers the next write. The shared
    /// [`TopologyWriter::acknowledged`] is only updated after a successful write.
    ///
    /// Never returns on its own: it ends when its cancellation token fires (see
    /// `spawn_task`) or when one of the watch channels is closed.
    async fn run(
        &self,
        variant_detection_activity: VariantDetectionActivity,
        mut generations: tokio::sync::watch::Receiver<u64>,
        mut unreachable: tokio::sync::watch::Receiver<u64>,
        mut acknowledged: u64,
    ) {
        if let Ok(generation) = self
            .persist_settled(&variant_detection_activity, true)
            .await
        {
            acknowledged = generation;
            self.acknowledged
                .store(generation, std::sync::atomic::Ordering::Release);
        }

        // Follow-up detection runs (explicit re-detection, reconnects, gateways
        // announced later) are persisted as soon as detection is idle again. A
        // gateway reported unreachable is written like a detection run, but
        // does not change the detection generation.
        loop {
            let generation = tokio::select! {
                result = wait_for_detection(&variant_detection_activity, &mut generations, acknowledged) => match result {
                    Ok(generation) => Some(generation),
                    Err(_) => return,
                },
                result = unreachable.changed() => {
                    if result.is_err() {
                        return;
                    }
                    None
                }
            };
            // No debounce: written as soon as detection is idle, one write at a
            // time. Runs finishing during the write leave the generation unequal
            // to `acknowledged`, so exactly one more write follows.
            let saved = self
                .persist_settled(&variant_detection_activity, false)
                .await
                .is_ok();
            if let Some(generation) = generation {
                // Set even if the write failed, so the same run is not retried in
                // a busy loop. It is retried once another run finishes.
                acknowledged = generation;
                if saved {
                    self.acknowledged
                        .store(generation, std::sync::atomic::Ordering::Release);
                }
            }
        }
    }

    /// Waits until the gateway discovery has completed and no variant
    /// detection is running, then persists and returns the detection generation
    /// the write started from. Both waits always end: the discovery is finished
    /// by its guard, and every connect and detection is bounded by its own
    /// timeouts. A cancelled task stops waiting.
    async fn persist_settled(
        &self,
        activity: &VariantDetectionActivity,
        initial: bool,
    ) -> Result<u64, TopologyStoreError> {
        let outcome = self.state.settled().await;
        activity.wait_until_idle().await;
        let generation = activity.generation();
        self.persist(initial && outcome.is_some_and(|outcome| outcome.full_vir_discovery))
            .await?;
        Ok(generation)
    }

    async fn persist(&self, full_vir_discovery: bool) -> Result<(), TopologyStoreError> {
        let mut stored = self.store.load().await.inspect_err(|error| {
            tracing::warn!(%error, "Failed to read the persisted topology before writing");
        })?;
        let entries = self.source.ecu_topology_entries().await;
        let keep = known_ecus_by_gateway(&entries);
        let pruned = prune_stored(&keep, &mut stored);
        let saved_last_seen: HashMap<_, _> = entries
            .iter()
            .map(|entry| {
                (
                    entry.name.as_str(),
                    entry.runtime_state.last_seen_snapshot(),
                )
            })
            .collect();
        let mut gateways = snapshot(
            &entries,
            &self.state.connected(),
            &self.state.unreachable(),
            full_vir_discovery,
            &stored,
        );
        // The only place that sets `last_seen`. Without a runtime value the
        // snapshot's value (the stored one for unreachable gateways) is kept.
        for ecu in gateways.iter_mut().flat_map(|gateway| &mut gateway.ecus) {
            if let Some(time) = saved_last_seen
                .get(ecu.name.as_str())
                .and_then(cda_interfaces::LastSeen::at)
            {
                ecu.last_seen = Some(time);
            }
        }

        let total = gateways.len();
        let changed = changed_gateways(&stored, gateways);
        if changed.is_empty() && !pruned {
            tracing::debug!(gateways = total, "Nothing new to persist");
        } else {
            // One transaction, so a crash cannot leave the store pruned but not
            // updated.
            match self.store.prune_and_persist_gateways(&keep, &changed).await {
                Ok(0) => {}
                Ok(count) => tracing::info!(count, "Pruned persisted topology entries"),
                Err(error) => {
                    tracing::warn!(%error, "Failed to persist ECU topology");
                    return Err(error);
                }
            }
            tracing::info!(
                gateways = changed.len(),
                unchanged = total.saturating_sub(changed.len()),
                "Persisted ECU topology"
            );
            let persisted: HashSet<&str> = changed
                .iter()
                .flat_map(|g| g.ecus.iter().map(|e| e.name.as_str()))
                .collect();
            for entry in &entries {
                if persisted.contains(entry.name.as_str())
                    && let Some(saved) = saved_last_seen.get(entry.name.as_str())
                {
                    entry.runtime_state.mark_last_seen_persisted(*saved);
                }
            }
            merge_persisted(&mut stored, changed);
        }

        // Also tracks whether a topology exists, for `vam_handling_mode`.
        self.update_reconnect_plan(&stored, &entries);
        self.persisted
            .send_modify(|count| *count = count.saturating_add(1));
        Ok(())
    }

    /// Records that a topology is persisted and, unless `init_mode` is `Always`,
    /// lets the next transport start (e.g. after a runtime update) reconnect to the
    /// persisted gateways instead of discovering by VIR. `topology` is the content of the
    /// store after this run.
    fn update_reconnect_plan(&self, topology: &PersistedTopology, entries: &[EcuTopologyEntry]) {
        if topology.is_empty() {
            return;
        }
        self.state.set_persisted_topology_available();
        if self.reuse_topology {
            self.state
                .set_discovery_strategy(DiscoveryStrategy::for_persisted(
                    topology,
                    &physical_gateways(entries),
                ));
        }
    }
}

/// Waits until a detection generation newer than `acknowledged` exists and no
/// detection is running, then returns that generation. Generations only grow and
/// `acknowledged` never exceeds them, so the returned value is always newer.
async fn wait_for_detection(
    activity: &VariantDetectionActivity,
    generations: &mut tokio::sync::watch::Receiver<u64>,
    acknowledged: u64,
) -> Result<u64, tokio::sync::watch::error::RecvError> {
    generations
        .wait_for(|generation| *generation != acknowledged)
        .await?;
    activity.wait_until_idle().await;
    Ok(activity.generation())
}

/// What the databases still contain: the logical address of every physical gateway
/// with the lowercase names of its ECUs.
fn known_ecus_by_gateway(entries: &[EcuTopologyEntry]) -> HashMap<u16, HashSet<String>> {
    let mut keep: HashMap<u16, HashSet<String>> = HashMap::new();
    for gateway in physical_gateways(entries) {
        keep.insert(gateway, HashSet::default());
    }
    for entry in entries {
        if let Some(ecus) = keep.get_mut(&entry.gateway_address) {
            ecus.insert(entry.name.to_lowercase());
        }
    }
    keep
}

/// Removes persisted gateways and ECUs that are no longer in the databases,
/// e.g. after a database update, from the in-memory copy of the store, as the
/// store does when it prunes. Returns whether something was removed.
/// [[ dimpl~ecu-topology-prune, Prune persisted entries not in the databases, dimpl ]]
fn prune_stored(keep: &HashMap<u16, HashSet<String>>, stored: &mut PersistedTopology) -> bool {
    let ecu_count = |topology: &PersistedTopology| {
        topology
            .gateways
            .iter()
            .map(|g| g.ecus.len())
            .sum::<usize>()
    };
    let (gateways, ecus) = (stored.gateways.len(), ecu_count(stored));
    stored
        .gateways
        .retain(|gateway| keep.contains_key(&gateway.logical_address));
    for gateway in &mut stored.gateways {
        if let Some(ecus) = keep.get(&gateway.logical_address) {
            gateway
                .ecus
                .retain(|ecu| ecus.contains(&ecu.name.to_lowercase()));
        }
    }
    stored.gateways.len() != gateways || ecu_count(stored) != ecus
}

/// Applies a `persist_gateways` write of `written` to the in-memory copy of the store.
fn merge_persisted(stored: &mut PersistedTopology, written: Vec<PersistedGateway>) {
    for gateway in written {
        match stored
            .gateways
            .iter_mut()
            .find(|existing| existing.logical_address == gateway.logical_address)
        {
            Some(existing) => *existing = gateway,
            None => stored.gateways.push(gateway),
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
        self.restart_task().await;
    }

    async fn deinitialize(&self) {
        self.cancel_pending().await;
    }
}

/// Builds the gateway entries to write.
///
/// - A connected gateway gets a full entry with all ECUs reached through it.
/// - After a full VIR discovery, a database gateway that was not found and is not
///   persisted yet gets an entry without network address, so a gateway that is
///   not fitted does not force a VIR on every start.
/// - A stored gateway whose connect failed (`unreachable`) keeps its address,
///   protocol version and ECU variants, and its ECUs are written with their
///   current state. Ignored while no gateway is connected (vehicle presumably
///   asleep), for gateways that are not stored, and for gateways that are
///   connected.
/// - Any other gateway (e.g. pending until first use) is left untouched (not
///   part of the result).
///
/// [[ dimpl~ecu-topology-persist-unreachable, Persist the state of unreachable gateways, dimpl ]]
pub(crate) fn snapshot(
    entries: &[EcuTopologyEntry],
    connected: &[KnownGateway],
    unreachable: &[u16],
    full_vir_discovery: bool,
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

    if !connected.is_empty() {
        let connected_addresses: HashSet<u16> =
            connected.iter().map(|g| g.logical_address).collect();
        for stored_gateway in &stored.gateways {
            let address = stored_gateway.logical_address;
            if unreachable.contains(&address) && !connected_addresses.contains(&address) {
                gateways.push(unreachable_gateway(
                    stored_gateway,
                    ecus_by_gateway.get(&address),
                ));
            }
        }
    }

    if full_vir_discovery {
        let known: HashSet<u16> = connected
            .iter()
            .map(|g| g.logical_address)
            .chain(stored.gateways.iter().map(|g| g.logical_address))
            .collect();
        for entry in entries {
            if cda_interfaces::topology::is_physical_gateway(
                entry.logical_address,
                entry.gateway_address,
            ) && !known.contains(&entry.logical_address)
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

/// The stored entry of a gateway that could not be reached, with the current
/// state of its ECUs. ECUs without a runtime entry keep their stored entry.
/// Variants that were not detected in this run keep their stored values as the
/// last known variant, but the state is written as it is: an ECU not reached in
/// this session is `Offline`, not `Disconnected`, and is thus not restored as
/// assumed online on the next start.
fn unreachable_gateway(
    stored: &PersistedGateway,
    entries: Option<&Vec<&EcuTopologyEntry>>,
) -> PersistedGateway {
    let ecus = stored
        .ecus
        .iter()
        .map(|stored_ecu| {
            let stored_name = stored_ecu.name.to_lowercase();
            let runtime = entries
                .into_iter()
                .flatten()
                .find(|entry| entry.name.to_lowercase() == stored_name);
            match runtime {
                Some(entry) => PersistedEcu {
                    name: stored_ecu.name.clone(),
                    logical_address: stored_ecu.logical_address,
                    variant: persisted_variant(&entry.state).or_else(|| stored_ecu.variant.clone()),
                    state: persisted_state(&entry.state),
                    last_seen: stored_ecu.last_seen,
                },
                None => stored_ecu.clone(),
            }
        })
        .collect();
    PersistedGateway {
        ecus,
        ..stored.clone()
    }
}

/// Logical addresses of the physical gateways among `entries`.
pub(crate) fn physical_gateways(entries: &[EcuTopologyEntry]) -> Vec<u16> {
    cda_interfaces::topology::physical_gateways(
        entries
            .iter()
            .map(|entry| (entry.logical_address, entry.gateway_address)),
    )
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
            // Set in `persist()`.
            last_seen: None,
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

/// The gateways of `gateways` whose stored entry is missing or differs in more
/// than the `last_seen` timestamps. Compared with the store rather than the last
/// write of this process, so a restart with an unchanged topology writes nothing.
fn changed_gateways(
    stored: &PersistedTopology,
    gateways: Vec<PersistedGateway>,
) -> Vec<PersistedGateway> {
    let stored: HashMap<u16, PersistedGateway> = stored
        .gateways
        .iter()
        .map(|gateway| (gateway.logical_address, without_last_seen(gateway)))
        .collect();
    gateways
        .into_iter()
        .filter(|gateway| stored.get(&gateway.logical_address) != Some(&without_last_seen(gateway)))
        .collect()
}

fn without_last_seen(gateway: &PersistedGateway) -> PersistedGateway {
    let mut gateway = gateway.clone();
    for ecu in &mut gateway.ecus {
        ecu.last_seen = None;
    }
    gateway
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use cda_interfaces::EcuRuntimeState;
    use cda_storage::LocalStorage;

    use super::*;
    use crate::store::PersistentEcuTopologyStore;

    impl TopologyPersistence {
        /// Number of completed persist runs.
        fn persisted_count(&self) -> u64 {
            *self.writer.persisted.borrow()
        }

        /// Waits until more than `after` persist runs have completed. Returns
        /// `false` if `timeout` elapsed first.
        async fn wait_persisted(&self, after: u64, timeout: Duration) -> bool {
            let mut rx = self.writer.persisted.subscribe();
            tokio::time::timeout(timeout, rx.wait_for(|count| *count > after))
                .await
                .is_ok_and(|result| result.is_ok())
        }
    }

    struct BlockingStore {
        inner: Arc<dyn EcuTopologyStore>,
        block_next: std::sync::atomic::AtomicBool,
        started: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }

    #[async_trait]
    impl EcuTopologyStore for BlockingStore {
        async fn load(&self) -> Result<PersistedTopology, TopologyStoreError> {
            self.inner.load().await
        }

        async fn persist_gateways(
            &self,
            gateways: &[PersistedGateway],
        ) -> Result<(), TopologyStoreError> {
            self.inner.persist_gateways(gateways).await
        }

        async fn merge_last_seen(
            &self,
            last_seen: &HashMap<String, SystemTime>,
        ) -> Result<(), TopologyStoreError> {
            self.inner.merge_last_seen(last_seen).await
        }

        async fn prune_and_persist_gateways(
            &self,
            keep: &HashMap<u16, HashSet<String>>,
            gateways: &[PersistedGateway],
        ) -> Result<usize, TopologyStoreError> {
            if self
                .block_next
                .swap(false, std::sync::atomic::Ordering::AcqRel)
            {
                self.started.notify_one();
                self.release.notified().await;
            }
            self.inner.prune_and_persist_gateways(keep, gateways).await
        }
    }

    fn blocking_persistence(
        original: &TopologyPersistence,
    ) -> (Arc<TopologyPersistence>, Arc<BlockingStore>) {
        let store = Arc::new(BlockingStore {
            inner: Arc::clone(&original.writer.store),
            block_next: std::sync::atomic::AtomicBool::new(true),
            started: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        let persistence = TopologyPersistence::new(
            Arc::clone(&store) as Arc<dyn EcuTopologyStore>,
            Arc::clone(&original.writer.state),
            Arc::clone(&original.writer.source),
            true,
        );
        (persistence, store)
    }

    /// Seconds since the epoch: stored timestamps have second precision.
    fn epoch_secs(time: Option<SystemTime>) -> Option<u64> {
        time.map(|at| at.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs())
    }

    struct FakeSource {
        entries: Vec<EcuTopologyEntry>,
        activity: VariantDetectionActivity,
    }

    #[async_trait]
    impl TopologySource for FakeSource {
        async fn ecu_topology_entries(&self) -> Vec<EcuTopologyEntry> {
            self.entries.clone()
        }

        async fn detection_activity(&self) -> VariantDetectionActivity {
            self.activity.clone()
        }
    }

    struct GatedSource {
        inner: FakeSource,
        block_next: std::sync::atomic::AtomicBool,
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }

    #[async_trait]
    impl TopologySource for GatedSource {
        async fn ecu_topology_entries(&self) -> Vec<EcuTopologyEntry> {
            self.inner.ecu_topology_entries().await
        }

        async fn detection_activity(&self) -> VariantDetectionActivity {
            if self
                .block_next
                .swap(false, std::sync::atomic::Ordering::AcqRel)
            {
                self.entered.notify_one();
                self.release.notified().await;
            }
            self.inner.detection_activity().await
        }
    }

    struct GatedFixture {
        persistence: Arc<TopologyPersistence>,
        source: Arc<GatedSource>,
        runtime: Arc<TopologyState>,
        _dir: tempfile::TempDir,
    }

    /// A store in a new temporary directory.
    fn temp_store() -> (
        Arc<PersistentEcuTopologyStore<LocalStorage>>,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(LocalStorage::new(dir.path()).unwrap());
        (Arc::new(PersistentEcuTopologyStore::new(storage)), dir)
    }

    /// Persistence whose first `detection_activity()` call blocks until released.
    fn gated_persistence(entries: Vec<EcuTopologyEntry>) -> GatedFixture {
        let (store, dir) = temp_store();
        let runtime = TopologyState::new(DiscoveryStrategy::Vir);
        let source = Arc::new(GatedSource {
            inner: FakeSource {
                entries,
                activity: VariantDetectionActivity::new(),
            },
            block_next: std::sync::atomic::AtomicBool::new(true),
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        let persistence = TopologyPersistence::new(
            Arc::clone(&store) as Arc<dyn EcuTopologyStore>,
            Arc::clone(&runtime),
            Arc::clone(&source) as Arc<dyn TopologySource>,
            true,
        );
        GatedFixture {
            persistence,
            source,
            runtime,
            _dir: dir,
        }
    }

    /// After the task was cancelled, neither a settled discovery nor a detection
    /// run may be persisted.
    async fn assert_no_task_persists(
        persistence: &TopologyPersistence,
        runtime: &TopologyState,
        source: &GatedSource,
    ) {
        assert!(persistence.task.lock().await.task.is_none());
        let before = persistence.persisted_count();
        settle(runtime);
        drop(source.inner.activity.begin());
        assert!(
            !persistence
                .wait_persisted(before, Duration::from_millis(200))
                .await
        );
    }

    /// [[ test~ecu-topology-persist-serialized, A concurrent restart and cancel of the persist task leave no orphaned task, test ]]
    #[tokio::test]
    async fn concurrent_restart_and_cancel_leave_no_orphan() {
        let fixture = gated_persistence(vehicle());
        let (persistence, source) = (&fixture.persistence, &fixture.source);
        // A running task, which the restart replaces.
        source
            .block_next
            .store(false, std::sync::atomic::Ordering::Release);
        persistence.restart_task().await;
        source
            .block_next
            .store(true, std::sync::atomic::Ordering::Release);
        let restart = tokio::spawn({
            let persistence = Arc::clone(persistence);
            async move { persistence.restart_task().await }
        });
        source.entered.notified().await;
        let cancel = tokio::spawn({
            let persistence = Arc::clone(persistence);
            async move { persistence.cancel_pending().await }
        });
        // The cancel has to wait for the lock held by the restart.
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(50)).await;
        assert!(!cancel.is_finished());
        source.release.notify_one();
        restart.await.unwrap();
        cancel.await.unwrap();

        assert_no_task_persists(persistence, &fixture.runtime, source).await;
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

    /// Runs a discovery, without a full VIR discovery, that connects `GW`.
    fn settle(runtime: &TopologyState) {
        let generation = runtime.begin_discovery();
        runtime.record_connected(known("GW", 0x1000));
        runtime.finish_discovery(generation, false);
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

        let gateways = snapshot(&vehicle(), &[known("GW", 0x1000)], &[], true, &stored);
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

        // Without a full VIR discovery, a missing gateway is not known to be absent.
        stored_only.ecus.clear();
        let gateways = snapshot(&vehicle(), &[known("GW", 0x1000)], &[], false, &stored);
        assert_eq!(gateways.len(), 1);
    }

    fn stored_ecu(name: &str, logical_address: u16, state: PersistedEcuState) -> PersistedEcu {
        PersistedEcu {
            name: name.to_owned(),
            logical_address,
            variant: Some(PersistedVariant {
                name: "Stored".to_owned(),
                is_base_variant: false,
                is_fallback: false,
            }),
            state,
            last_seen: None,
        }
    }

    /// A stored gateway 0x2000 with `DOWN_GW` and `DOWN_ECU`, next to the
    /// connected 0x1000.
    fn stored_with_down_gateway() -> PersistedTopology {
        PersistedTopology {
            gateways: vec![PersistedGateway {
                name: "DOWN_GW".to_owned(),
                logical_address: 0x2000,
                network_address: Some("10.2.1.20".to_owned()),
                doip_protocol_version: Some(2),
                ecus: vec![
                    stored_ecu("DOWN_ECU", 0x2001, PersistedEcuState::Online),
                    stored_ecu("DOWN_GW", 0x2000, PersistedEcuState::Online),
                ],
            }],
        }
    }

    fn vehicle_with_down_gateway(down_variant: VariantState) -> Vec<EcuTopologyEntry> {
        vec![
            entry("GW", 0x1000, 0x1000, Connectivity::Online, detected()),
            entry(
                "DOWN_GW",
                0x2000,
                0x2000,
                Connectivity::Offline,
                down_variant.clone(),
            ),
            entry(
                "DOWN_ECU",
                0x2001,
                0x2000,
                Connectivity::Offline,
                down_variant,
            ),
        ]
    }

    fn gateway_at(gateways: &[PersistedGateway], address: u16) -> Option<&PersistedGateway> {
        gateways.iter().find(|g| g.logical_address == address)
    }

    /// An ECU of an unreachable gateway that was not reached in this session
    /// (still assumed online, or reset after it) is written `Offline`, keeping
    /// its stored variant as the last known one; an ECU lost after a contact in
    /// this session is written `Disconnected`.
    /// [[ test~ecu-list-persistence-unreachable-not-reached-is-offline, An ECU of an unreachable gateway not reached in this session is persisted as Offline, test ]]
    #[test]
    fn unreachable_gateway_writes_runtime_state() {
        for (down_variant, expected_state, expected_variant) in [
            (
                VariantState::NotTested,
                PersistedEcuState::Offline,
                "Stored",
            ),
            (detected(), PersistedEcuState::Disconnected, "App"),
        ] {
            let gateways = snapshot(
                &vehicle_with_down_gateway(down_variant),
                &[known("GW", 0x1000)],
                &[0x2000],
                false,
                &stored_with_down_gateway(),
            );
            let down = gateway_at(&gateways, 0x2000).unwrap();
            for ecu in &down.ecus {
                assert_eq!(ecu.state, expected_state, "{}", ecu.name);
                assert_eq!(
                    ecu.variant.as_ref().map(|v| v.name.as_str()),
                    Some(expected_variant),
                    "{}",
                    ecu.name
                );
            }
        }
    }

    /// [[ test~ecu-list-persistence-snapshot-name-case, ECU names are matched case-insensitively when an unreachable gateway is written, test ]]
    #[test]
    fn snapshot_matches_ecu_names_case_insensitively() {
        let mut entries = vehicle_with_down_gateway(detected());
        for entry in &mut entries {
            entry.name = entry.name.to_lowercase();
        }
        let gateways = snapshot(
            &entries,
            &[known("GW", 0x1000)],
            &[0x2000],
            false,
            &stored_with_down_gateway(),
        );
        let down = gateway_at(&gateways, 0x2000).unwrap();
        for ecu in &down.ecus {
            assert_eq!(
                ecu.variant.as_ref().map(|v| v.name.as_str()),
                Some("App"),
                "{} takes the runtime variant",
                ecu.name
            );
        }
    }

    /// [[ test~ecu-list-persistence-snapshot-leaves-pending-gateway-untouched, A gateway pending until its first use is not written, test ]]
    #[test]
    fn snapshot_leaves_pending_gateway_untouched() {
        // Offline ECUs behind a gateway that was never tried, but not reported.
        let gateways = snapshot(
            &vehicle_with_down_gateway(VariantState::NotTested),
            &[known("GW", 0x1000)],
            &[],
            false,
            &stored_with_down_gateway(),
        );
        assert_eq!(gateways.len(), 1);
        assert!(gateway_at(&gateways, 0x2000).is_none());
    }

    /// [[ test~ecu-list-persistence-persisted-state-follows-sovd-mapping, Persisted states follow the SOVD mapping and `AssumedOnline` is persisted as Online, test ]]
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
        Arc<PersistentEcuTopologyStore<LocalStorage>>,
        Arc<TopologyState>,
        tempfile::TempDir,
    ) {
        let (store, dir) = temp_store();
        let runtime = TopologyState::new(DiscoveryStrategy::Vir);
        let persistence = TopologyPersistence::new(
            Arc::clone(&store) as Arc<dyn EcuTopologyStore>,
            Arc::clone(&runtime),
            Arc::new(FakeSource {
                entries,
                activity: VariantDetectionActivity::new(),
            }),
            true,
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
        // The connected gateway plus the two database gateways a full VIR discovery
        // did not find.
        assert_eq!(store.load().await.unwrap().gateways.len(), 3);
        assert!(matches!(
            runtime.discovery_strategy(),
            DiscoveryStrategy::Persisted { known, search } if known.len() == 3 && search.is_empty()
        ));

        persistence.deinitialize().await;
    }

    /// The initial write waits for the discovery and then for the variant
    /// detection, however long they take, and keeps the full discovery result.
    /// [[ test~ecu-list-persistence-waits-for-discovery-and-detection, The initial write waits for the discovery and the variant detection without a time limit, test ]]
    #[tokio::test(start_paused = true)]
    async fn initial_write_waits_for_discovery_and_detection() {
        let (persistence, store, runtime, _dir) = fixture(vehicle());
        let generation = runtime.begin_discovery();
        runtime.record_connected(known("GW", 0x1000));
        let activity = persistence.writer.source.detection_activity().await;
        let ticket = activity.begin();

        persistence.on_enabled().await;
        tokio::time::advance(Duration::from_secs(3600)).await;
        assert_eq!(persistence.persisted_count(), 0, "the discovery is running");
        runtime.finish_discovery(generation, true);
        tokio::time::advance(Duration::from_secs(3600)).await;
        assert_eq!(persistence.persisted_count(), 0, "a detection is pending");
        drop(ticket);

        assert!(persistence.wait_persisted(0, Duration::from_secs(5)).await);
        // The connected gateway plus the two database gateways the full VIR
        // discovery did not find.
        assert_eq!(store.load().await.unwrap().gateways.len(), 3);
        persistence.deinitialize().await;
    }

    #[tokio::test]
    async fn contact_during_storage_remains_dirty_for_shutdown() {
        let entries = vehicle();
        let state = entries.first().unwrap().runtime_state.clone();
        state.update_last_seen();
        let saved = state.last_seen();
        let (original, store, runtime, _dir) = fixture(entries);
        let (persistence, blocking) = blocking_persistence(&original);
        settle(&runtime);
        persistence.on_enabled().await;
        blocking.started.notified().await;
        state.update_last_seen();
        blocking.release.notify_one();
        assert!(persistence.wait_persisted(0, Duration::from_secs(5)).await);
        persistence.deinitialize().await;
        assert!(state.last_seen_snapshot().is_dirty());
        let stored_time = |topology: PersistedTopology| {
            topology
                .gateways
                .into_iter()
                .flat_map(|gateway| gateway.ecus)
                .find(|ecu| ecu.name == "GW")
                .unwrap()
                .last_seen
        };
        assert_eq!(
            epoch_secs(stored_time(store.load().await.unwrap())),
            epoch_secs(saved)
        );
        persistence.persist_last_seen().await;
        assert_eq!(
            epoch_secs(stored_time(store.load().await.unwrap())),
            epoch_secs(state.last_seen())
        );
        assert!(!state.last_seen_snapshot().is_dirty());
    }

    /// [[ test~ecu-list-persistence-runs-during-write-coalesce-into-one-more-write, Detection runs finishing during a write are combined into one further write, test ]]
    #[tokio::test(start_paused = true)]
    async fn runs_during_write_coalesce_into_one_more_write() {
        let (original, _store, runtime, _dir) = fixture(vehicle());
        let (persistence, blocking) = blocking_persistence(&original);
        let activity = persistence.writer.source.detection_activity().await;
        settle(&runtime);
        persistence.on_enabled().await;
        blocking.started.notified().await;
        for _ in 0..3 {
            drop(activity.begin());
        }
        let start = tokio::time::Instant::now();
        blocking.release.notify_one();
        assert!(persistence.wait_persisted(1, Duration::from_secs(60)).await);
        // The further write follows right away; a debounce would advance the paused clock.
        assert!(start.elapsed() < Duration::from_millis(500));
        assert!(
            !persistence
                .wait_persisted(2, Duration::from_millis(300))
                .await,
            "three runs during the write must result in one more write only"
        );
        assert_eq!(persistence.persisted_count(), 2);
        persistence.deinitialize().await;
    }

    /// Persistence that wrote `GW` at 10.2.1.10 and whose task was cancelled
    /// since, with `GW` connected at 10.2.1.11 afterwards.
    async fn moved_after_last_write(
        entries: Vec<EcuTopologyEntry>,
    ) -> (
        Arc<TopologyPersistence>,
        Arc<PersistentEcuTopologyStore<LocalStorage>>,
        VariantDetectionActivity,
        tempfile::TempDir,
    ) {
        let (persistence, store, runtime, dir) = fixture(entries);
        settle(&runtime);
        persistence.on_enabled().await;
        assert!(persistence.wait_persisted(0, Duration::from_secs(5)).await);
        persistence.cancel_pending().await;
        let mut moved = known("GW", 0x1000);
        moved.network_address = Some("10.2.1.11".to_owned());
        runtime.record_connected(moved);
        let activity = persistence.writer.source.detection_activity().await;
        (persistence, store, activity, dir)
    }

    /// [[ test~ecu-list-persistence-shutdown-snapshot, Unwritten detection results are written at shutdown, test ]]
    #[tokio::test]
    async fn shutdown_writes_unwritten_results() {
        let (persistence, store, activity, _dir) = moved_after_last_write(vehicle()).await;
        // A run that finished right before shutdown, no task left to write it.
        drop(activity.begin());
        assert!(persistence.has_unwritten_results(&activity));

        persistence.persist_on_shutdown().await;
        assert_eq!(
            store
                .load()
                .await
                .unwrap()
                .gateways
                .first()
                .unwrap()
                .network_address
                .as_deref(),
            Some("10.2.1.11")
        );
        assert!(!persistence.has_unwritten_results(&activity));
    }

    /// [[ test~ecu-list-persistence-shutdown-with-running-detection-writes-last-seen-only, With a detection running the shutdown writes only `last_seen`, test ]]
    #[tokio::test]
    async fn shutdown_with_running_detection_writes_last_seen_only() {
        let entries = vehicle();
        let gw_state = entries.first().unwrap().runtime_state.clone();
        let (persistence, store, activity, _dir) = moved_after_last_write(entries).await;
        let _running = activity.begin();
        gw_state.update_last_seen();
        assert!(!persistence.has_unwritten_results(&activity));

        persistence.persist_on_shutdown().await;
        let stored = store.load().await.unwrap();
        let gateway = stored.gateways.first().unwrap();
        assert_eq!(
            gateway.network_address.as_deref(),
            Some("10.2.1.10"),
            "half-finished detection states are not written"
        );
        assert_eq!(
            epoch_secs(
                gateway
                    .ecus
                    .iter()
                    .find(|ecu| ecu.name == "GW")
                    .and_then(|ecu| ecu.last_seen)
            ),
            epoch_secs(gw_state.last_seen()),
            "the contact time of the ECU is written back"
        );
    }

    /// Records the logical addresses of every gateway write.
    struct RecordingStore {
        inner: Arc<dyn EcuTopologyStore>,
        persisted: std::sync::Mutex<Vec<Vec<u16>>>,
    }

    impl RecordingStore {
        fn record(&self, gateways: &[PersistedGateway]) {
            self.persisted
                .lock()
                .unwrap()
                .push(gateways.iter().map(|g| g.logical_address).collect());
        }
    }

    #[async_trait]
    impl EcuTopologyStore for RecordingStore {
        async fn load(
            &self,
        ) -> Result<PersistedTopology, cda_interfaces::topology::TopologyStoreError> {
            self.inner.load().await
        }

        async fn persist_gateways(
            &self,
            gateways: &[PersistedGateway],
        ) -> Result<(), cda_interfaces::topology::TopologyStoreError> {
            self.record(gateways);
            self.inner.persist_gateways(gateways).await
        }

        async fn merge_last_seen(
            &self,
            last_seen: &HashMap<String, SystemTime>,
        ) -> Result<(), cda_interfaces::topology::TopologyStoreError> {
            self.inner.merge_last_seen(last_seen).await
        }

        async fn prune_and_persist_gateways(
            &self,
            keep: &HashMap<u16, HashSet<String>>,
            gateways: &[PersistedGateway],
        ) -> Result<usize, cda_interfaces::topology::TopologyStoreError> {
            self.record(gateways);
            self.inner.prune_and_persist_gateways(keep, gateways).await
        }
    }

    fn two_gateways() -> Vec<EcuTopologyEntry> {
        vec![
            entry("GW", 0x1000, 0x1000, Connectivity::Online, detected()),
            entry("GW2", 0x2000, 0x2000, Connectivity::Online, detected()),
        ]
    }

    /// Runs one start of the CDA on `store`: connects `connected` (no full
    /// VIR discovery), waits for the initial write and disables communication.
    /// Returns the persisted logical addresses.
    async fn start_once(
        store: &Arc<PersistentEcuTopologyStore<LocalStorage>>,
        entries: Vec<EcuTopologyEntry>,
        connected: Vec<KnownGateway>,
    ) -> Vec<Vec<u16>> {
        let recording = Arc::new(RecordingStore {
            inner: Arc::clone(store) as Arc<dyn EcuTopologyStore>,
            persisted: std::sync::Mutex::new(Vec::new()),
        });
        let runtime = TopologyState::new(DiscoveryStrategy::Vir);
        let persistence = TopologyPersistence::new(
            Arc::clone(&recording) as Arc<dyn EcuTopologyStore>,
            Arc::clone(&runtime),
            Arc::new(FakeSource {
                entries,
                activity: VariantDetectionActivity::new(),
            }),
            true,
        );
        let generation = runtime.begin_discovery();
        for gateway in connected {
            runtime.record_connected(gateway);
        }
        runtime.finish_discovery(generation, false);
        persistence.on_enabled().await;
        assert!(persistence.wait_persisted(0, Duration::from_secs(5)).await);
        persistence.deinitialize().await;
        recording.persisted.lock().unwrap().clone()
    }

    /// [[ test~ecu-list-persistence-unchanged-restart-writes-nothing, A restart with an unchanged topology writes no gateway and only `last_seen` stays dirty for shutdown, test ]]
    #[tokio::test]
    async fn restart_with_unchanged_topology_writes_nothing() {
        let (store, _dir) = temp_store();
        let connected = vec![known("GW", 0x1000), known("GW2", 0x2000)];
        let first = start_once(&store, two_gateways(), connected.clone()).await;
        assert_eq!(first, vec![vec![0x1000, 0x2000]]);

        let entries = two_gateways();
        let gw_state = entries.first().unwrap().runtime_state.clone();
        gw_state.update_last_seen();
        let second = start_once(&store, entries, connected).await;
        assert!(second.is_empty(), "unexpected writes: {second:?}");
        assert!(
            gw_state.last_seen_snapshot().is_dirty(),
            "last_seen is left for the shutdown write-back"
        );
    }

    /// [[ test~ecu-list-persistence-only-changed-gateways-written, Only gateways whose entry changed are written, test ]]
    #[tokio::test]
    async fn only_changed_gateways_are_written() {
        let (store, _dir) = temp_store();
        let first = start_once(
            &store,
            two_gateways(),
            vec![known("GW", 0x1000), known("GW2", 0x2000)],
        )
        .await;
        assert_eq!(first, vec![vec![0x1000, 0x2000]]);

        let mut moved = known("GW2", 0x2000);
        moved.network_address = Some("10.2.1.20".to_owned());
        let second = start_once(&store, two_gateways(), vec![known("GW", 0x1000), moved]).await;
        assert_eq!(second, vec![vec![0x2000]]);
        assert_eq!(
            gateway_at(&store.load().await.unwrap().gateways, 0x2000)
                .and_then(|g| g.network_address.as_deref()),
            Some("10.2.1.20")
        );
    }
}
