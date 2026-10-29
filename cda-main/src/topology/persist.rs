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
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use cda_interfaces::{
    Connectivity, DetectionTracker, EcuState, HashMap, HashMapExtensions as _, HashSet,
    VariantState,
    communication_control::{CommControlError, CommunicationLifecycle},
    topology::{
        DiscoveryPlan, EcuTopologyEntry, EcuTopologyStore, KnownGateway, PersistedEcu,
        PersistedEcuState, PersistedGateway, PersistedTopology, PersistedVariant, RediscoveryWait,
        TopologyClearError, TopologyRuntime, TopologyStoreError,
    },
};
use tokio::{sync::Mutex, task::JoinHandle};
use tokio_util::sync::CancellationToken;

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

/// Why a persist run failed.
#[derive(Debug, thiserror::Error)]
pub enum PersistError {
    /// Reading the persisted topology failed.
    #[error("Failed to read the persisted topology: {0}")]
    Load(TopologyStoreError),
    /// Removing outdated entries failed.
    #[error("Failed to prune the persisted topology: {0}")]
    Prune(TopologyStoreError),
    /// Writing the topology failed.
    #[error("Failed to persist the ECU topology: {0}")]
    Write(TopologyStoreError),
}

/// Extra time for the write in the safety bound of
/// [`TopologyPersistence::wait_rediscovered`].
const WRITE_ALLOWANCE: Duration = Duration::from_secs(10);

/// Verdict of the persist task on a discovery generation, see
/// [`TopologyPersistence::wait_rediscovered`].
#[derive(Debug, Clone)]
struct Rediscovered {
    /// Discovery generation the verdict is for.
    generation: u64,
    verdict: RediscoveryWait,
}

/// The persist task and whether persistence was shut down. Guarded by one mutex,
/// so a shutdown write cannot interleave with a clear or a restart.
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
    store: Arc<dyn EcuTopologyStore>,
    runtime: Arc<TopologyRuntime>,
    source: Arc<dyn EcuTopologySource>,
    /// Whether the persisted topology is reused on the next transport start,
    /// i.e. `init_mode` is not `Always`.
    reuse_topology: bool,
    settle_timeout: Duration,
    task: Mutex<TaskSlot>,
    /// Last written gateways without `last_seen`, to skip writes that would not
    /// change anything but the timestamps (written back at shutdown instead).
    last_written: Mutex<Option<Vec<PersistedGateway>>>,
    /// Detection generation whose results are written (or deliberately not
    /// written, e.g. after a clear), see [`Self::has_unwritten_results`].
    acknowledged: AtomicU64,
    /// Number of completed persist runs, see [`Self::wait_persisted`].
    persisted: tokio::sync::watch::Sender<u64>,
    /// Discovery generation persisted after discovery and detection both settled.
    rediscovered: tokio::sync::watch::Sender<Rediscovered>,
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
            task: Mutex::new(TaskSlot::default()),
            last_written: Mutex::new(None),
            acknowledged: AtomicU64::new(0),
            persisted: tokio::sync::watch::Sender::new(0),
            rediscovered: tokio::sync::watch::Sender::new(Rediscovered {
                generation: 0,
                verdict: RediscoveryWait::TimedOut,
            }),
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

    /// Waits for the persist task's verdict on a discovery generation newer than
    /// `after`: settled and persisted, settled but the write failed
    /// ([`RediscoveryWait::PersistFailed`]), or timed out when the task's settle
    /// budget ran out. A best-effort timeout snapshot is never a settled verdict.
    ///
    /// Starts no settle timer of its own: the wait is bounded only by twice the
    /// settle budget plus a write allowance, against a persist task that is not
    /// running.
    pub async fn wait_rediscovered(&self, after: u64) -> RediscoveryWait {
        let bound = self
            .settle_timeout
            .saturating_mul(2)
            .saturating_add(WRITE_ALLOWANCE);
        let mut rx = self.rediscovered.subscribe();
        match tokio::time::timeout(bound, rx.wait_for(|state| state.generation > after)).await {
            Ok(Ok(state)) => state.verdict.clone(),
            Ok(Err(_)) | Err(_) => RediscoveryWait::TimedOut,
        }
    }

    /// Cancels a pending persist run, e.g. before the persisted topology is cleared.
    pub async fn cancel_pending(&self) {
        self.replace_task(None).await;
    }

    /// Writes the `last_seen` timestamps of all ECUs contacted since they were
    /// last persisted. Never creates entries.
    pub async fn persist_last_seen(&self) {
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
            Ok(count) => {
                for (state, saved) in snapshots {
                    state.mark_last_seen_persisted(saved);
                }
                tracing::debug!(count, "Persisted last_seen timestamps");
            }
            Err(error) => tracing::warn!(%error, "Failed to persist last_seen timestamps"),
        }
    }

    /// Whether detection runs finished since the last write and no detection is
    /// queued or running.
    #[must_use]
    pub fn has_unwritten_results(&self, tracker: &DetectionTracker) -> bool {
        let progress = *tracker.subscribe().borrow();
        progress.pending == 0
            && progress.generation != self.acknowledged.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Final write at shutdown. Detection results that were not written yet are
    /// written as a full snapshot, unless a detection is still queued or running
    /// (its half-finished states are not written). `last_seen` of contacted ECUs
    /// is written back in any case.
    ///
    /// Runs under the task lock, after the running task was cancelled: a clear or
    /// restart cannot interleave with the write, and no task is started
    /// afterwards. A clear arriving after the shutdown is still executed.
    /// [[ dimpl~ecu-topology-persist-when-idle, Persist follow-up runs when idle and at shutdown, dimpl ]]
    pub async fn persist_on_shutdown(&self) {
        let mut slot = self.task.lock().await;
        Self::stop_task(&mut slot).await;
        let tracker = self.source.detection_tracker().await;
        if self.has_unwritten_results(&tracker) {
            let generation = tracker.subscribe().borrow().generation;
            if self.persist(false).await.is_ok() {
                self.acknowledged
                    .store(generation, std::sync::atomic::Ordering::Release);
            }
        }
        // Also covers a full write that was skipped as unchanged, which does not
        // write `last_seen`.
        self.persist_last_seen().await;
        slot.shut_down = true;
    }

    /// Runs `clear`, which clears the persisted topology, with the persist task
    /// stopped and the task lock held, so a shutdown write cannot interleave and
    /// bring the topology back.
    ///
    /// After a successful clear the results so far count as written (they are not
    /// written back) and only later detection runs are persisted. After a failed
    /// clear the store is unchanged. In both cases, unless `clear` panics, the
    /// task state from before is restored: a running task restarts (after a
    /// failed clear with a write, so results that were not written yet are still
    /// due); without one (communication disabled) none is started, and
    /// `on_enabled` starts it later. A clear after the shutdown write is
    /// executed, but starts no task. After a panic inside `clear` the persist
    /// task stays stopped until the next `on_enabled`.
    ///
    /// The sequence runs in its own task, so a dropped caller cannot leave the
    /// persist task stopped.
    ///
    /// # Errors
    /// Returns the error of `clear` as [`TopologyClearError::Store`], or
    /// [`TopologyClearError::Aborted`] if the sequence panicked or was cancelled.
    pub async fn run_clear(
        &self,
        clear: impl Future<Output = Result<(), TopologyStoreError>> + Send + 'static,
    ) -> Result<(), TopologyClearError> {
        let Some(this) = self.this.upgrade() else {
            return Ok(clear.await?);
        };
        let sequence = cda_interfaces::spawn_named!("ecu-topology-clear", async move {
            this.clear_sequence(clear).await
        });
        match sequence.await {
            Ok(result) => Ok(result?),
            Err(error) => {
                tracing::error!(%error, "Clearing the persisted topology was aborted");
                Err(TopologyClearError::Aborted)
            }
        }
    }

    async fn clear_sequence(
        &self,
        clear: impl Future<Output = Result<(), TopologyStoreError>>,
    ) -> Result<(), TopologyStoreError> {
        let mut slot = self.task.lock().await;
        let was_running = slot.task.is_some();
        Self::stop_task(&mut slot).await;
        let result = clear.await;
        if result.is_ok() {
            // The next run writes unconditionally.
            *self.last_written.lock().await = None;
            let generation = self
                .source
                .detection_tracker()
                .await
                .subscribe()
                .borrow()
                .generation;
            self.acknowledged
                .store(generation, std::sync::atomic::Ordering::Release);
        }
        if was_running && !slot.shut_down {
            slot.task = self.spawn_task(result.is_err()).await;
        }
        result
    }

    /// Cancels the running task and, with `start = Some(initial)`, starts a new one,
    /// atomically with respect to other callers: the `task` lock is held for the
    /// whole sequence, so no task can be orphaned or started after a later cancel.
    /// [[ dimpl~ecu-topology-persist-serialized, Persist task lifecycle and store writes are serialized, dimpl ]]
    async fn replace_task(&self, start: Option<bool>) {
        let mut slot = self.task.lock().await;
        Self::stop_task(&mut slot).await;
        if let Some(initial) = start
            && !slot.shut_down
        {
            slot.task = self.spawn_task(initial).await;
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

    async fn spawn_task(&self, initial: bool) -> Option<(CancellationToken, JoinHandle<()>)> {
        let this = self.this.upgrade()?;
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        // Subscribe before returning to the caller so even a complete detection
        // between spawning and the task's first poll is retained.
        let tracker = self.source.detection_tracker().await;
        let pending = tracker.subscribe();
        let unreachable = self.runtime.subscribe_unreachable();
        // What was written (or deliberately not written, after a clear) is not
        // this task's to write again; an initial run writes the rest.
        let acknowledged = self.acknowledged.load(std::sync::atomic::Ordering::Acquire);
        let task = cda_interfaces::spawn_named!("ecu-topology-persistence", async move {
            tokio::select! {
                () = task_cancel.cancelled() => {}
                () = this.run(initial, tracker, pending, unreachable, acknowledged) => {}
            }
        });
        Some((cancel, task))
    }

    async fn run(
        self: Arc<Self>,
        initial: bool,
        tracker: DetectionTracker,
        mut pending: tokio::sync::watch::Receiver<cda_interfaces::DetectionProgress>,
        mut unreachable: tokio::sync::watch::Receiver<u64>,
        mut acknowledged: u64,
    ) {
        if initial {
            // A failure is logged by `persist` and retried by the next run. The
            // follow-up loop continues from the generation the initial run wrote,
            // so it does not write it a second time.
            if let Ok(Some(generation)) = self.persist_settled(&tracker, true).await {
                acknowledged = generation;
            }
        }

        // Follow-up detection runs (explicit re-detection, reconnects, gateways
        // announced later) are persisted as soon as detection is idle again. A
        // gateway reported unreachable is written like a detection run, but
        // does not change the detection generation.
        loop {
            let detection = pending
                .wait_for(|progress| progress.pending == 0 && progress.generation != acknowledged);
            let generation = tokio::select! {
                result = detection => {
                    match result {
                        Ok(progress) => Some(progress.generation),
                        Err(_) => return,
                    }
                }
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
            let saved = self.persist_settled(&tracker, false).await.is_ok();
            if let Some(generation) = generation {
                if saved {
                    self.acknowledged
                        .store(generation, std::sync::atomic::Ordering::Release);
                }
                // A detection during snapshot collection or storage remains pending
                // even if its entire busy/idle cycle happened while we were awaiting I/O.
                acknowledged = generation;
            }
        }
    }

    async fn persist_settled(
        &self,
        tracker: &DetectionTracker,
        initial: bool,
    ) -> Result<Option<u64>, PersistError> {
        // One budget for both waits: the second one gets what the first one left.
        let start = tokio::time::Instant::now();
        let deadline = start.checked_add(self.settle_timeout).unwrap_or(start);
        let outcome = self.runtime.wait_settled(self.settle_timeout).await;
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if outcome.is_none() {
            tracing::warn!(
                budget = ?self.settle_timeout,
                waited = ?start.elapsed(),
                ?remaining,
                "Gateway discovery did not settle in time, persisting what is connected"
            );
        }
        let idle = tracker.wait_idle(remaining).await;
        if !idle {
            tracing::warn!(
                budget = ?self.settle_timeout,
                waited = ?start.elapsed(),
                "Variant detection did not settle in time, persisting current states"
            );
        }
        let progress = *tracker.subscribe().borrow();
        let result = self
            .persist(initial && outcome.is_some_and(|outcome| outcome.full_broadcast))
            .await;
        let settled_generation = outcome
            .filter(|_| idle && progress.pending == 0)
            .map(|outcome| outcome.generation);
        if let Some(generation) = settled_generation {
            let unchanged = *tracker.subscribe().borrow() == progress
                && self.runtime.discovery_generation() == generation;
            let verdict = match &result {
                Ok(()) => RediscoveryWait::Settled,
                Err(error) => RediscoveryWait::PersistFailed(error.to_string()),
            };
            // Also when the state changed during the write: the generation waited
            // on gets its verdict, but a later generation's verdict is kept.
            self.rediscovered.send_if_modified(|state| {
                let publish =
                    generation > state.generation || (unchanged && generation == state.generation);
                if publish {
                    *state = Rediscovered {
                        generation,
                        verdict,
                    };
                }
                publish
            });
        } else if outcome.is_none() || !idle {
            // The budget ran out: the verdict on the generation waited on, unless
            // that generation has one already.
            let generation = outcome.map_or_else(
                || self.runtime.discovery_generation(),
                |outcome| outcome.generation,
            );
            self.rediscovered.send_if_modified(|state| {
                let newer = generation > state.generation;
                if newer {
                    *state = Rediscovered {
                        generation,
                        verdict: RediscoveryWait::TimedOut,
                    };
                }
                newer
            });
        }
        let acknowledged = (initial && result.is_ok() && idle && progress.pending == 0)
            .then_some(progress.generation);
        if let Some(generation) = acknowledged {
            self.acknowledged
                .store(generation, std::sync::atomic::Ordering::Release);
        }
        result.map(|()| acknowledged)
    }

    async fn persist(&self, full_broadcast: bool) -> Result<(), PersistError> {
        let mut stored = self.store.load().await.map_err(|error| {
            tracing::warn!(%error, "Failed to read the persisted topology before writing");
            PersistError::Load(error)
        })?;
        let entries = self.source.ecu_topology_entries().await;
        if !stored.is_empty() {
            self.prune(&entries, &mut stored).await?;
        }
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
            &self.runtime.connected(),
            &self.runtime.unreachable(),
            full_broadcast,
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

        let without_last_seen = strip_last_seen(&gateways);
        let unchanged = self.last_written.lock().await.as_ref() == Some(&without_last_seen);
        if gateways.is_empty() || unchanged {
            tracing::debug!(
                gateways = gateways.len(),
                unchanged,
                "Nothing new to persist"
            );
        } else {
            if let Err(error) = self.store.upsert(&gateways).await {
                tracing::warn!(%error, "Failed to persist ECU topology");
                return Err(PersistError::Write(error));
            }
            tracing::info!(gateways = gateways.len(), "Persisted ECU topology");
            let persisted: HashSet<&str> = gateways
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
            *self.last_written.lock().await = Some(without_last_seen);
            merge_upserted(&mut stored, gateways);
        }

        // Also tracks whether a topology exists, for `vam_handling_mode`.
        self.update_reconnect_plan(&stored, &entries);
        self.persisted
            .send_modify(|count| *count = count.saturating_add(1));
        Ok(())
    }

    /// Removes persisted gateways and ECUs that are no longer in the databases,
    /// e.g. after a database update, from the store and from `stored`. Writes only
    /// if something is removed.
    /// [[ dimpl~ecu-topology-prune, Prune persisted entries not in the databases, dimpl ]]
    async fn prune(
        &self,
        entries: &[EcuTopologyEntry],
        stored: &mut PersistedTopology,
    ) -> Result<(), PersistError> {
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
            Err(error) => {
                tracing::warn!(%error, "Failed to prune the persisted topology");
                return Err(PersistError::Prune(error));
            }
        }
        // Same result as in the store, without reading it again.
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
        Ok(())
    }

    /// Records that a topology is persisted and, unless `init_mode` is `Always`,
    /// lets the next transport start (e.g. after a runtime update) reconnect to the
    /// persisted gateways instead of broadcasting. `topology` is the content of the
    /// store after this run.
    fn update_reconnect_plan(&self, topology: &PersistedTopology, entries: &[EcuTopologyEntry]) {
        if topology.is_empty() {
            return;
        }
        self.runtime.set_has_persisted(true);
        if self.reuse_topology {
            self.runtime.set_plan(DiscoveryPlan::for_persisted(
                topology,
                &physical_gateways(entries),
            ));
        }
    }
}

/// Applies an upsert of `written` to the in-memory copy of the store.
fn merge_upserted(stored: &mut PersistedTopology, written: Vec<PersistedGateway>) {
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
        self.replace_task(Some(true)).await;
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

    if full_broadcast {
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
/// state of its ECUs. ECUs without a runtime entry and variants that were not
/// detected in this run keep their stored values.
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
                Some(entry) => {
                    let runtime_variant = persisted_variant(&entry.state);
                    let keeps_stored_variant = runtime_variant.is_none();
                    let state = match persisted_state(&entry.state) {
                        // The ECU has a (stored) variant it was known with, so it is
                        // disconnected, not never seen.
                        PersistedEcuState::Offline
                            if keeps_stored_variant && stored_ecu.variant.is_some() =>
                        {
                            PersistedEcuState::Disconnected
                        }
                        state => state,
                    };
                    PersistedEcu {
                        name: stored_ecu.name.clone(),
                        logical_address: stored_ecu.logical_address,
                        variant: runtime_variant.or_else(|| stored_ecu.variant.clone()),
                        state,
                        last_seen: stored_ecu.last_seen,
                    }
                }
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

    struct BlockingStore {
        inner: Arc<dyn EcuTopologyStore>,
        block_next: std::sync::atomic::AtomicBool,
        /// Makes the next `upsert` fail.
        fail_next: std::sync::atomic::AtomicBool,
        started: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }

    #[async_trait]
    impl EcuTopologyStore for BlockingStore {
        fn is_enabled(&self) -> bool {
            true
        }

        async fn load(
            &self,
        ) -> Result<PersistedTopology, cda_interfaces::topology::TopologyStoreError> {
            self.inner.load().await
        }

        async fn upsert(
            &self,
            gateways: &[PersistedGateway],
        ) -> Result<(), cda_interfaces::topology::TopologyStoreError> {
            if self
                .block_next
                .swap(false, std::sync::atomic::Ordering::AcqRel)
            {
                self.started.notify_one();
                self.release.notified().await;
            }
            if self
                .fail_next
                .swap(false, std::sync::atomic::Ordering::AcqRel)
            {
                return Err(cda_interfaces::topology::TopologyStoreError::Serialization(
                    "disk full".to_owned(),
                ));
            }
            self.inner.upsert(gateways).await
        }

        async fn merge_last_seen(
            &self,
            last_seen: &HashMap<String, SystemTime>,
        ) -> Result<usize, cda_interfaces::topology::TopologyStoreError> {
            self.inner.merge_last_seen(last_seen).await
        }

        async fn clear(&self) -> Result<(), cda_interfaces::topology::TopologyStoreError> {
            self.inner.clear().await
        }

        async fn prune(
            &self,
            keep: &HashMap<u16, HashSet<String>>,
        ) -> Result<usize, cda_interfaces::topology::TopologyStoreError> {
            self.inner.prune(keep).await
        }
    }

    fn blocking_persistence(
        original: &TopologyPersistence,
    ) -> (Arc<TopologyPersistence>, Arc<BlockingStore>) {
        let store = Arc::new(BlockingStore {
            inner: Arc::clone(&original.store),
            block_next: std::sync::atomic::AtomicBool::new(true),
            fail_next: std::sync::atomic::AtomicBool::new(false),
            started: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        let persistence = TopologyPersistence::new(
            Arc::clone(&store) as Arc<dyn EcuTopologyStore>,
            Arc::clone(&original.runtime),
            Arc::clone(&original.source),
            true,
            Duration::from_millis(20),
        );
        (persistence, store)
    }

    /// Milliseconds since the epoch: stored timestamps have millisecond precision.
    fn epoch_millis(time: Option<SystemTime>) -> Option<u128> {
        time.map(|at| {
            at.duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        })
    }

    /// Restarts the running follow-up task the way a successful clear does.
    async fn restart_follow_up(persistence: &TopologyPersistence) {
        persistence.run_clear(async { Ok(()) }).await.unwrap();
    }

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

    struct GatedSource {
        inner: FakeSource,
        block_next: std::sync::atomic::AtomicBool,
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }

    #[async_trait]
    impl EcuTopologySource for GatedSource {
        async fn ecu_topology_entries(&self) -> Vec<EcuTopologyEntry> {
            self.inner.ecu_topology_entries().await
        }

        async fn detection_tracker(&self) -> DetectionTracker {
            if self
                .block_next
                .swap(false, std::sync::atomic::Ordering::AcqRel)
            {
                self.entered.notify_one();
                self.release.notified().await;
            }
            self.inner.detection_tracker().await
        }

        async fn reset_ecu_states(&self, _only_assumed_online: bool) {}
    }

    struct GatedFixture {
        persistence: Arc<TopologyPersistence>,
        source: Arc<GatedSource>,
        store: Arc<StorageEcuTopologyStore<LocalStorage>>,
        runtime: Arc<TopologyRuntime>,
        _dir: tempfile::TempDir,
    }

    /// Persistence whose first `detection_tracker()` call blocks until released.
    fn gated_persistence(entries: Vec<EcuTopologyEntry>) -> GatedFixture {
        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(LocalStorage::new(dir.path()).unwrap());
        let store = Arc::new(StorageEcuTopologyStore::new(storage));
        let runtime = TopologyRuntime::new(DiscoveryPlan::Broadcast);
        let source = Arc::new(GatedSource {
            inner: FakeSource {
                entries,
                tracker: DetectionTracker::new(),
            },
            block_next: std::sync::atomic::AtomicBool::new(true),
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        let persistence = TopologyPersistence::new(
            Arc::clone(&store) as Arc<dyn EcuTopologyStore>,
            Arc::clone(&runtime),
            Arc::clone(&source) as Arc<dyn EcuTopologySource>,
            true,
            Duration::from_millis(20),
        );
        GatedFixture {
            persistence,
            source,
            store,
            runtime,
            _dir: dir,
        }
    }

    /// A detection run after a missing task must not be persisted.
    async fn assert_no_task_persists(
        persistence: &TopologyPersistence,
        runtime: &TopologyRuntime,
        source: &GatedSource,
        store: &StorageEcuTopologyStore<LocalStorage>,
    ) {
        assert!(persistence.task.lock().await.task.is_none());
        let generation = runtime.begin_discovery();
        runtime.record_connected(known("GW", 0x1000));
        runtime.finish_discovery(generation, false);
        drop(source.inner.tracker.begin());
        assert!(
            !persistence
                .wait_persisted(0, Duration::from_millis(200))
                .await
        );
        assert!(store.load().await.unwrap().is_empty());
    }

    /// [[ test~ecu-topology-persist-serialized, A concurrent restart and cancel of the persist task leave no orphaned task, test ]]
    #[tokio::test]
    async fn concurrent_restart_and_cancel_leave_no_orphan() {
        let GatedFixture {
            persistence,
            source,
            store,
            runtime,
            _dir,
        } = gated_persistence(vehicle());
        // A running follow-up task, which the clear restarts.
        source
            .block_next
            .store(false, std::sync::atomic::Ordering::Release);
        persistence.replace_task(Some(false)).await;
        source
            .block_next
            .store(true, std::sync::atomic::Ordering::Release);
        let restart = tokio::spawn({
            let persistence = Arc::clone(&persistence);
            async move { restart_follow_up(&persistence).await }
        });
        source.entered.notified().await;
        let cancel = tokio::spawn({
            let persistence = Arc::clone(&persistence);
            async move { persistence.cancel_pending().await }
        });
        // The cancel has to wait for the lock held by the restart.
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(50)).await;
        assert!(!cancel.is_finished());
        source.release.notify_one();
        restart.await.unwrap();
        cancel.await.unwrap();

        assert_no_task_persists(&persistence, &runtime, &source, &store).await;
    }

    #[tokio::test]
    async fn cancel_during_spawn_wins() {
        let GatedFixture {
            persistence,
            source,
            store,
            runtime,
            _dir,
        } = gated_persistence(vehicle());
        // Unsettled discovery keeps the initial run waiting, so only the cancel can end it.
        let _generation = runtime.begin_discovery();
        let enable = tokio::spawn({
            let persistence = Arc::clone(&persistence);
            async move { persistence.on_enabled().await }
        });
        source.entered.notified().await;
        let cancel = tokio::spawn({
            let persistence = Arc::clone(&persistence);
            async move { persistence.cancel_pending().await }
        });
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(50)).await;
        assert!(!cancel.is_finished());
        source.release.notify_one();
        enable.await.unwrap();
        cancel.await.unwrap();

        assert_no_task_persists(&persistence, &runtime, &source, &store).await;
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

        // Without a full broadcast, a missing gateway is not known to be absent.
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

    /// [[ test~ecu-list-persistence-settle-budget-is-shared-between-discovery-and-detection, One settle budget bounds both the discovery and the detection wait, test ]]
    #[tokio::test]
    async fn settle_budget_is_shared_between_discovery_and_detection() {
        let (original, _store, _runtime, _dir) = fixture(vehicle());
        let persistence = TopologyPersistence::new(
            Arc::clone(&original.store),
            Arc::clone(&original.runtime),
            Arc::clone(&original.source),
            true,
            Duration::from_millis(300),
        );
        // Neither the discovery nor the detection ever settles.
        let _generation = original.runtime.begin_discovery();
        let tracker = original.source.detection_tracker().await;
        let _ticket = tracker.begin();

        let start = std::time::Instant::now();
        let _ = persistence.persist_settled(&tracker, true).await;
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(300), "{elapsed:?}");
        assert!(elapsed < Duration::from_millis(550), "{elapsed:?}");
    }

    /// [[ test~ecu-list-persistence-failed-write-of-a-settled-rediscovery-is-reported, A settled rediscovery whose write failed is reported as failed, test ]]
    #[tokio::test]
    async fn failed_write_of_a_settled_rediscovery_is_reported() {
        let (original, _store, runtime, _dir) = fixture(vehicle());
        let (persistence, blocking) = blocking_persistence(&original);
        blocking
            .block_next
            .store(false, std::sync::atomic::Ordering::Release);
        blocking
            .fail_next
            .store(true, std::sync::atomic::Ordering::Release);
        let generation = runtime.begin_discovery();
        runtime.record_connected(known("GW", 0x1000));
        runtime.finish_discovery(generation, true);
        persistence.on_enabled().await;

        match persistence.wait_rediscovered(0).await {
            RediscoveryWait::PersistFailed(error) => {
                assert!(error.contains("disk full"), "{error}");
            }
            other => panic!("unexpected {other:?}"),
        }
        persistence.deinitialize().await;
    }

    /// [[ test~ecu-list-persistence-timeout-snapshot-does-not-complete-rediscovery, A best-effort snapshot after the settle budget is not a settled rediscovery, test ]]
    #[tokio::test]
    async fn timeout_snapshot_does_not_complete_rediscovery() {
        let (original, _store, runtime, _dir) = fixture(vehicle());
        let (persistence, blocking) = blocking_persistence(&original);
        blocking
            .block_next
            .store(false, std::sync::atomic::Ordering::Release);
        let tracker = persistence.source.detection_tracker().await;
        let ticket = tracker.begin();
        let generation = runtime.begin_discovery();
        runtime.record_connected(known("GW", 0x1000));
        runtime.finish_discovery(generation, true);
        persistence.on_enabled().await;
        assert!(persistence.wait_persisted(0, Duration::from_secs(5)).await);
        assert!(!tracker.is_idle());
        assert_eq!(
            persistence.wait_rediscovered(0).await,
            RediscoveryWait::TimedOut,
            "the task's verdict after its budget ran out"
        );
        drop(ticket);
        let mut verdict = persistence.rediscovered.subscribe();
        tokio::time::timeout(
            Duration::from_secs(5),
            verdict.wait_for(|state| state.verdict == RediscoveryWait::Settled),
        )
        .await
        .expect("the follow-up run settles the generation")
        .unwrap();
        persistence.deinitialize().await;
    }

    #[tokio::test]
    async fn contact_during_storage_remains_dirty_for_shutdown() {
        let entries = vehicle();
        let state = entries.first().unwrap().runtime_state.clone();
        state.touch_last_seen();
        let saved = state.last_seen();
        let (original, store, runtime, _dir) = fixture(entries);
        let (persistence, blocking) = blocking_persistence(&original);
        let generation = runtime.begin_discovery();
        runtime.record_connected(known("GW", 0x1000));
        runtime.finish_discovery(generation, false);
        persistence.on_enabled().await;
        blocking.started.notified().await;
        state.touch_last_seen();
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
        let millis = |time: Option<SystemTime>| {
            time.map(|at| {
                at.duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_millis()
            })
        };
        assert_eq!(
            millis(stored_time(store.load().await.unwrap())),
            millis(saved)
        );
        persistence.persist_last_seen().await;
        assert_eq!(
            millis(stored_time(store.load().await.unwrap())),
            millis(state.last_seen())
        );
        assert!(!state.last_seen_snapshot().is_dirty());
    }

    /// [[ test~ecu-list-persistence-runs-during-write-coalesce-into-one-more-write, Detection runs finishing during a write are combined into one further write, test ]]
    #[tokio::test(start_paused = true)]
    async fn runs_during_write_coalesce_into_one_more_write() {
        let (original, _store, runtime, _dir) = fixture(vehicle());
        let (persistence, blocking) = blocking_persistence(&original);
        let tracker = persistence.source.detection_tracker().await;
        let generation = runtime.begin_discovery();
        runtime.record_connected(known("GW", 0x1000));
        runtime.finish_discovery(generation, false);
        persistence.on_enabled().await;
        blocking.started.notified().await;
        for _ in 0..3 {
            drop(tracker.begin());
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

    /// [[ test~ecu-list-persistence-shutdown-snapshot, Unwritten detection results are written at shutdown, test ]]
    #[tokio::test]
    async fn shutdown_writes_unwritten_results() {
        let (persistence, store, runtime, _dir) = fixture(vehicle());
        let generation = runtime.begin_discovery();
        runtime.record_connected(known("GW", 0x1000));
        runtime.finish_discovery(generation, false);
        persistence.on_enabled().await;
        assert!(persistence.wait_persisted(0, Duration::from_secs(5)).await);
        persistence.cancel_pending().await;

        // A run that finished right before shutdown, no task left to write it.
        let tracker = persistence.source.detection_tracker().await;
        let mut moved = known("GW", 0x1000);
        moved.network_address = Some("10.2.1.11".to_owned());
        runtime.record_connected(moved);
        drop(tracker.begin());
        assert!(persistence.has_unwritten_results(&tracker));

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
        assert!(!persistence.has_unwritten_results(&tracker));
    }

    /// [[ test~ecu-list-persistence-shutdown-with-running-detection-writes-last-seen-only, With a detection running the shutdown writes only `last_seen`, test ]]
    #[tokio::test]
    async fn shutdown_with_running_detection_writes_last_seen_only() {
        let entries = vehicle();
        let gw_state = entries.first().unwrap().runtime_state.clone();
        let (persistence, store, runtime, _dir) = fixture(entries);
        let generation = runtime.begin_discovery();
        runtime.record_connected(known("GW", 0x1000));
        runtime.finish_discovery(generation, false);
        persistence.on_enabled().await;
        assert!(persistence.wait_persisted(0, Duration::from_secs(5)).await);
        persistence.cancel_pending().await;

        let tracker = persistence.source.detection_tracker().await;
        let mut moved = known("GW", 0x1000);
        moved.network_address = Some("10.2.1.11".to_owned());
        runtime.record_connected(moved);
        let _running = tracker.begin();
        gw_state.touch_last_seen();
        assert!(!persistence.has_unwritten_results(&tracker));

        persistence.persist_on_shutdown().await;
        let stored = store.load().await.unwrap();
        let gateway = stored.gateways.first().unwrap();
        assert_eq!(
            gateway.network_address.as_deref(),
            Some("10.2.1.10"),
            "half-finished detection states are not written"
        );
        assert_eq!(
            epoch_millis(
                gateway
                    .ecus
                    .iter()
                    .find(|ecu| ecu.name == "GW")
                    .and_then(|ecu| ecu.last_seen)
            ),
            epoch_millis(gw_state.last_seen()),
            "the contact time of the ECU is written back"
        );
    }

    /// [[ test~ecu-list-persistence-shutdown-after-clear-does-not-recreate-entries, Results up to a clear are not written back at shutdown, test ]]
    #[tokio::test]
    async fn shutdown_after_clear_does_not_recreate_entries() {
        let entries = vehicle();
        let gw_state = entries.first().unwrap().runtime_state.clone();
        let (persistence, store, runtime, _dir) = fixture(entries);
        let generation = runtime.begin_discovery();
        runtime.record_connected(known("GW", 0x1000));
        runtime.finish_discovery(generation, false);
        persistence.on_enabled().await;
        assert!(persistence.wait_persisted(0, Duration::from_secs(5)).await);
        persistence.cancel_pending().await;
        let tracker = persistence.source.detection_tracker().await;
        drop(tracker.begin());

        persistence
            .run_clear({
                let store = Arc::clone(&store);
                async move { store.clear().await }
            })
            .await
            .unwrap();
        gw_state.touch_last_seen();
        assert!(!persistence.has_unwritten_results(&tracker));

        persistence.cancel_pending().await;
        persistence.persist_on_shutdown().await;
        assert!(store.load().await.unwrap().is_empty());
    }

    /// [[ test~ecu-list-persistence-shutdown-serialized-with-clear, A clear during the shutdown write is not undone and no task starts after the shutdown, test ]]
    #[tokio::test]
    async fn clear_during_the_shutdown_write_is_not_undone() {
        let (original, store, runtime, _dir) = fixture(vehicle());
        let (persistence, blocking) = blocking_persistence(&original);
        let generation = runtime.begin_discovery();
        runtime.record_connected(known("GW", 0x1000));
        runtime.finish_discovery(generation, false);
        let tracker = persistence.source.detection_tracker().await;
        drop(tracker.begin());
        assert!(persistence.has_unwritten_results(&tracker));

        let shutdown = tokio::spawn({
            let persistence = Arc::clone(&persistence);
            async move { persistence.persist_on_shutdown().await }
        });
        // The shutdown write is inside the store, holding the task lock.
        blocking.started.notified().await;
        let clear = tokio::spawn({
            let persistence = Arc::clone(&persistence);
            let store = Arc::clone(&store);
            async move {
                persistence
                    .run_clear(async move { store.clear().await })
                    .await
            }
        });
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(50)).await;
        assert!(
            !clear.is_finished(),
            "the clear waits for the shutdown write"
        );
        blocking.release.notify_one();
        shutdown.await.unwrap();
        clear.await.unwrap().unwrap();

        assert!(store.load().await.unwrap().is_empty(), "the clear ran last");
        let slot = persistence.task.lock().await;
        assert!(slot.shut_down);
        assert!(slot.task.is_none(), "no task is started after the shutdown");
    }

    /// [[ test~ecu-list-persistence-failed-clear-keeps-unwritten, A failed clear leaves unwritten results due, test ]]
    #[tokio::test]
    async fn failed_clear_keeps_unwritten_results_due() {
        let (original, store, runtime, _dir) = fixture(vehicle());
        let generation = runtime.begin_discovery();
        runtime.record_connected(known("GW", 0x1000));
        runtime.finish_discovery(generation, false);
        original.on_enabled().await;
        assert!(original.wait_persisted(0, Duration::from_secs(5)).await);
        original.cancel_pending().await;
        let (persistence, blocking) = blocking_persistence(&original);
        blocking
            .block_next
            .store(false, std::sync::atomic::Ordering::Release);
        // A running follow-up task, as during a clear-only reset.
        persistence.replace_task(Some(false)).await;

        // A result that was not written yet; the running detection keeps the
        // follow-up task from writing it before the clear.
        let tracker = persistence.source.detection_tracker().await;
        let mut moved = known("GW", 0x1000);
        moved.network_address = Some("10.2.1.11".to_owned());
        runtime.record_connected(moved);
        let ticket = tracker.begin();

        // The detection ends during the clear, so the restarted task sees it idle.
        let cleared = persistence
            .run_clear(async move {
                drop(ticket);
                Err(TopologyStoreError::Serialization("disk full".into()))
            })
            .await;
        assert!(matches!(cleared, Err(TopologyClearError::Store(_))));
        assert!(
            persistence.wait_persisted(0, Duration::from_secs(5)).await,
            "the restarted task writes the unwritten result"
        );

        assert_eq!(
            store
                .load()
                .await
                .unwrap()
                .gateways
                .first()
                .and_then(|gateway| gateway.network_address.as_deref()),
            Some("10.2.1.11")
        );
    }

    /// [[ test~ecu-list-persistence-clear-restores-task, A clear restarts the persist task only if one was running, test ]]
    #[tokio::test]
    async fn clear_restores_the_task_state() {
        let (persistence, _store, _runtime, _dir) = fixture(vehicle());
        let fail = || async { Err(TopologyStoreError::Serialization("disk full".into())) };
        let succeed = || async { Ok(()) };

        // Communication disabled: no task, and neither clear starts one.
        assert!(persistence.run_clear(fail()).await.is_err());
        assert!(persistence.task.lock().await.task.is_none());
        assert!(persistence.run_clear(succeed()).await.is_ok());
        assert!(persistence.task.lock().await.task.is_none());

        // Communication enabled: the running task is restarted.
        persistence.replace_task(Some(false)).await;
        assert!(persistence.run_clear(fail()).await.is_err());
        assert!(persistence.task.lock().await.task.is_some());
        persistence.deinitialize().await;
    }

    #[tokio::test]
    async fn generation_change_during_the_write_settles_the_waited_generation() {
        let (original, _store, runtime, _dir) = fixture(vehicle());
        let (persistence, blocking) = blocking_persistence(&original);
        let generation = runtime.begin_discovery();
        runtime.record_connected(known("GW", 0x1000));
        runtime.finish_discovery(generation, true);
        persistence.on_enabled().await;

        blocking.started.notified().await;
        // A new discovery starts during the write and does not settle.
        let _next = runtime.begin_discovery();
        blocking.release.notify_one();

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), persistence.wait_rediscovered(0))
                .await
                .expect("the waiter gets a verdict without running into its bound"),
            RediscoveryWait::Settled
        );
        persistence.deinitialize().await;
    }

    /// [[ test~ecu-list-persistence-rediscovery-verdict, A settle near the end of the budget followed by a slow write is reported as settled, test ]]
    #[tokio::test(start_paused = true)]
    async fn late_settle_with_a_slow_write_is_settled() {
        let (original, _store, runtime, _dir) = fixture(vehicle());
        // A settle budget of 20 ms; the first write blocks until released.
        let (persistence, blocking) = blocking_persistence(&original);
        let generation = runtime.begin_discovery();
        runtime.record_connected(known("GW", 0x1000));
        persistence.on_enabled().await;
        // Lets the persist task arm its budget at t = 0. The current-thread test
        // runtime polls the spawned task once here, and nothing before its
        // settle timeout awaits, so one poll is enough. This is not asserted:
        // no existing API shows that the budget is armed.
        tokio::task::yield_now().await;
        let wait = tokio::spawn({
            let persistence = Arc::clone(&persistence);
            async move { persistence.wait_rediscovered(0).await }
        });
        // Lets the waiter subscribe and arm its own bound at t = 0 as well,
        // before time advances.
        tokio::task::yield_now().await;

        tokio::time::advance(Duration::from_millis(15)).await;
        runtime.finish_discovery(generation, true);
        blocking.started.notified().await;
        // The write outlasts the settle budget.
        tokio::time::advance(Duration::from_millis(50)).await;
        tokio::task::yield_now().await;
        assert!(
            !wait.is_finished(),
            "the wait has no settle timer of its own"
        );
        blocking.release.notify_one();

        assert_eq!(wait.await.unwrap(), RediscoveryWait::Settled);
        persistence.deinitialize().await;
    }
}
