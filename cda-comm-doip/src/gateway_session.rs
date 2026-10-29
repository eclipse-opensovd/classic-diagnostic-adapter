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

//! Gateway connect state of one transport start and the single place where a
//! gateway connect is registered: startup reconnect, broadcast fallback, first
//! use after a lazy start and spontaneous announcements all go through
//! [`DoipGatewayState::start_connect`].

use std::sync::{Arc, Mutex as StdMutex, PoisonError};

use cda_interfaces::{
    DoipComParams, EcuAddresses, EcuConnectivityHandler, HashMap, HashMapExtensions, HashSet,
    VariantDetectionRequest, VariantDetectionSender,
    topology::{KnownGateway, gateway_key},
};
use futures::FutureExt as _;
use tokio::sync::{Mutex, RwLock, watch};
use tokio_util::sync::CancellationToken;

use crate::{
    ConnectionTasks, DiscoveredGateway, DoipGatewayState, DoipTransportConfig,
    connections::{GatewayState, handle_gateway_connection},
    reconnect, spawn_connection_task,
};

/// Maps each gateway logical address to the logical addresses and the (lowercase)
/// names of the ECUs reached through it.
pub(crate) async fn gateway_ecu_maps<T: EcuAddresses>(
    ecus: &HashMap<String, RwLock<T>>,
) -> (HashMap<u16, Vec<u16>>, HashMap<u16, Vec<String>>) {
    let mut gateway_ecu_map: HashMap<u16, Vec<u16>> = HashMap::new();
    let mut gateway_ecu_name_map: HashMap<u16, Vec<String>> = HashMap::new();
    for ecu_lock in ecus.values() {
        let ecu = ecu_lock.read().await;
        gateway_ecu_map
            .entry(ecu.logical_gateway_address())
            .or_default()
            .push(ecu.logical_address());
        gateway_ecu_name_map
            .entry(ecu.logical_gateway_address())
            .or_default()
            .push(ecu.ecu_name().to_lowercase());
    }
    (gateway_ecu_map, gateway_ecu_name_map)
}

/// What to connect: a gateway with a known address, or a gateway that has to be
/// searched by a broadcast first.
#[derive(Debug, Clone)]
pub(crate) enum GatewayTarget {
    Known(DiscoveredGateway),
    Search(u16),
}

impl GatewayTarget {
    fn logical_address(&self) -> u16 {
        match self {
            Self::Known(gateway) => gateway.logical_address,
            Self::Search(logical_address) => *logical_address,
        }
    }
}

/// Gateway connect state of one transport start. Replaced on every start, so
/// work left over from an earlier start cannot change the current one.
pub(crate) struct GatewaySession {
    /// Gateways waiting for their first use (lazy start). `None`: no usable address.
    pub(crate) pending: Mutex<HashMap<u16, Option<DiscoveredGateway>>>,
    /// Connects in flight; `None` while running, `Some(outcome)` when done.
    /// A std mutex, so the entry can also be removed from a `Drop`.
    connecting: StdMutex<HashMap<u16, watch::Receiver<Option<ConnectOutcome>>>>,
    /// Gateways that triggered a fallback search from a failed direct connect
    /// and have not connected since: a failure episode. Later failures of the
    /// same gateway in the episode do not search again.
    fallback_episode: StdMutex<HashSet<u16>>,
    /// The fallback search in flight, shared by all gateways that need one.
    search_in_flight: StdMutex<Option<watch::Receiver<Option<SearchResult>>>>,
    pub(crate) transport_config: DoipTransportConfig,
    pub(crate) connection_tasks: Arc<ConnectionTasks>,
    pub(crate) cancel: CancellationToken,
    variant_detection: VariantDetectionSender,
    connectivity_handler: Arc<dyn EcuConnectivityHandler>,
}

/// Result of one fallback search.
#[derive(Clone)]
enum SearchResult {
    /// Gateways announced in answer to the search.
    Found(Arc<Vec<DiscoveredGateway>>),
    /// Nothing was searched: the transport gate was closed (or the session
    /// cancelled) when the search started.
    Skipped,
}

/// How a caller of [`DoipGatewayState::join_or_start_search`] got its result.
enum SearchJoin {
    /// It started the search.
    Started(SearchResult),
    /// It waited for a search that was already in flight.
    Joined(SearchResult),
}

impl SearchJoin {
    fn into_result(self) -> SearchResult {
        match self {
            Self::Started(result) | Self::Joined(result) => result,
        }
    }
}

/// Removes a connect from `connecting` when its task ends, also when it panics.
struct ConnectingGuard {
    session: Arc<GatewaySession>,
    logical_address: u16,
}

impl Drop for ConnectingGuard {
    fn drop(&mut self) {
        self.session.connecting_map().remove(&self.logical_address);
    }
}

/// Frees the shared search slot when the search task ends, also when it is aborted.
struct SearchGuard(Arc<GatewaySession>);

impl Drop for SearchGuard {
    fn drop(&mut self) {
        self.0
            .search_in_flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }
}

impl GatewaySession {
    pub(crate) fn new(
        transport_config: DoipTransportConfig,
        connection_tasks: Arc<ConnectionTasks>,
        cancel: CancellationToken,
        variant_detection: VariantDetectionSender,
        connectivity_handler: Arc<dyn EcuConnectivityHandler>,
    ) -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
            connecting: StdMutex::new(HashMap::new()),
            fallback_episode: StdMutex::new(HashSet::default()),
            search_in_flight: StdMutex::new(None),
            transport_config,
            connection_tasks,
            cancel,
            variant_detection,
            connectivity_handler,
        }
    }

    fn connecting_map(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<u16, watch::Receiver<Option<ConnectOutcome>>>> {
        self.connecting
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn fallback_episode(&self) -> std::sync::MutexGuard<'_, HashSet<u16>> {
        self.fallback_episode
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether `logical_address` is a gateway waiting for its first use.
    pub(crate) async fn is_pending(&self, logical_address: u16) -> bool {
        self.pending.lock().await.contains_key(&logical_address)
    }

    /// Whether a connect of `logical_address` is in flight.
    pub(crate) fn is_connecting(&self, logical_address: u16) -> bool {
        self.connecting_map().contains_key(&logical_address)
    }

    /// The target to connect for a pending gateway, `None` if it is not pending.
    pub(crate) async fn pending_target(&self, logical_address: u16) -> Option<GatewayTarget> {
        self.pending
            .lock()
            .await
            .get(&logical_address)
            .map(|entry| match entry {
                Some(gateway) => GatewayTarget::Known(gateway.clone()),
                None => GatewayTarget::Search(logical_address),
            })
    }

    /// Updates the address of a pending gateway from an announcement. Returns
    /// `true` if the gateway is pending, so it must not be connected now.
    pub(crate) async fn update_pending(&self, gateway: &DiscoveredGateway) -> bool {
        match self.pending.lock().await.get_mut(&gateway.logical_address) {
            Some(entry) => {
                *entry = Some(gateway.clone());
                true
            }
            None => false,
        }
    }
}

/// Result of one gateway connect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConnectOutcome {
    Connected,
    /// The gateway could not be connected, or the session was cancelled.
    Failed,
    /// The transport gate was closed: not a failure of the gateway. It is
    /// neither reported unreachable nor does it enter a failure episode.
    Refused,
}

/// Gateways a fallback search did not connect.
#[derive(Default)]
pub(crate) struct FallbackOutcome {
    /// Not found, or failed to connect.
    pub(crate) missing: HashSet<u16>,
    /// Refused because the transport gate was closed.
    pub(crate) refused: HashSet<u16>,
}

/// Outcome of a connect that is done, or in flight.
pub(crate) enum PendingConnect {
    Done(ConnectOutcome),
    InFlight(watch::Receiver<Option<ConnectOutcome>>),
}

impl PendingConnect {
    /// Waits for the connect. `Failed` if its task ended without a result.
    pub(crate) async fn wait(self) -> ConnectOutcome {
        match self {
            Self::Done(outcome) => outcome,
            Self::InFlight(mut receiver) => receiver
                .wait_for(Option::is_some)
                .await
                .ok()
                .and_then(|result| *result)
                .unwrap_or(ConnectOutcome::Failed),
        }
    }
}

impl<T: EcuAddresses + DoipComParams> DoipGatewayState<T> {
    /// The session of the current transport start, `None` while stopped.
    pub(crate) async fn current_session(&self) -> Option<Arc<GatewaySession>> {
        self.session.read().await.clone()
    }

    /// Connects a gateway, with a broadcast fallback if it cannot be reached.
    /// Concurrent callers for the same gateway wait for the one connect in
    /// flight, and dropping the caller does not abort it. Returns `true` if the
    /// gateway is connected.
    /// [[ dimpl~doip-gateway-connect-once, One coordinated connect per gateway, dimpl ]]
    pub(crate) async fn connect_once(
        &self,
        session: &Arc<GatewaySession>,
        target: GatewayTarget,
    ) -> bool {
        self.start_connect(session, target, true).await.wait().await == ConnectOutcome::Connected
    }

    /// Registers the connect and starts its task, without waiting for it.
    /// `fallback`: search the gateway by a broadcast if the direct connect
    /// fails, and report its ECUs unreachable if that fails as well. Without it
    /// the caller handles failures (the startup reconnect does one broadcast
    /// for all gateways that could not be reached).
    pub(crate) async fn start_connect(
        &self,
        session: &Arc<GatewaySession>,
        target: GatewayTarget,
        fallback: bool,
    ) -> PendingConnect {
        let logical_address = target.logical_address();
        if session.cancel.is_cancelled() {
            return PendingConnect::Done(ConnectOutcome::Failed);
        }
        if self
            .logical_address_to_connection
            .read()
            .await
            .contains_key(&logical_address)
        {
            return PendingConnect::Done(ConnectOutcome::Connected);
        }
        // The next use or announcement connects it.
        if !self.gate.is_open() {
            tracing::debug!(
                logical_address = %gateway_key(logical_address),
                "Communication is paused, not connecting the gateway"
            );
            return PendingConnect::Done(ConnectOutcome::Refused);
        }
        let (sender, receiver) = {
            let mut connecting = session.connecting_map();
            if let Some(receiver) = connecting.get(&logical_address) {
                return PendingConnect::InFlight(receiver.clone());
            }
            let (sender, receiver) = watch::channel(None);
            connecting.insert(logical_address, receiver.clone());
            (sender, receiver)
        };

        // Created before the spawn and moved into the task: the entry is removed
        // whichever way the task ends, also if it is aborted before it ran.
        let guard = ConnectingGuard {
            session: Arc::clone(session),
            logical_address,
        };
        let state = self.clone();
        let task_session = Arc::clone(session);
        spawn_connection_task(
            &session.connection_tasks,
            &format!("doip-gateway-connect-{}", gateway_key(logical_address)),
            async move {
                let outcome = state.run_connect(&task_session, target, fallback).await;
                // A refused gateway stays pending, as with the up-front refusal.
                if outcome != ConnectOutcome::Refused {
                    task_session.pending.lock().await.remove(&logical_address);
                }
                // Before the result is published, so a caller arriving after a
                // failure starts a new connect instead of reading the old result.
                drop(guard);
                sender.send_replace(Some(outcome));
            },
        );
        PendingConnect::InFlight(receiver)
    }

    async fn run_connect(
        &self,
        session: &Arc<GatewaySession>,
        target: GatewayTarget,
        fallback: bool,
    ) -> ConnectOutcome {
        let logical_address = target.logical_address();
        // A connect that finished between the caller's check and its registration.
        if self
            .logical_address_to_connection
            .read()
            .await
            .contains_key(&logical_address)
        {
            return ConnectOutcome::Connected;
        }
        let mut connected = false;
        if let GatewayTarget::Known(gateway) = target {
            connected = self.connect_gateway(session, gateway).await;
        }
        // One search per failure episode: a gateway that was searched already
        // and still fails only reports unreachable. `search_gateways` searches
        // nothing while the transport gate is closed.
        let searched = !connected
            && fallback
            && !session.cancel.is_cancelled()
            && session.fallback_episode().insert(logical_address);
        // The gate read after the last connect attempt (or after the search if
        // no found gateway is connected) decides: failed while the gate is
        // closed is refused, not failed. A search skipped because the gate was
        // closed is refused as well, even if the gate has opened since.
        let gate_open = if searched {
            match self.shared_search(session).await {
                SearchResult::Skipped => false,
                SearchResult::Found(found) => {
                    let mut gate_open = self.gate.is_open();
                    // The connect is registered under this address already, so the
                    // found gateway is connected directly instead of through
                    // `connect_once`.
                    for gateway in found
                        .iter()
                        .filter(|gateway| gateway.logical_address == logical_address)
                    {
                        if !gate_open || session.cancel.is_cancelled() {
                            break;
                        }
                        connected = self.connect_gateway(session, gateway.clone()).await;
                        gate_open = self.gate.is_open();
                        if connected {
                            break;
                        }
                    }
                    gate_open
                }
            }
        } else {
            self.gate.is_open()
        };
        if session.cancel.is_cancelled() {
            return ConnectOutcome::Failed;
        }
        if connected {
            return ConnectOutcome::Connected;
        }
        if !gate_open {
            if searched {
                session.fallback_episode().remove(&logical_address);
            }
            return ConnectOutcome::Refused;
        }
        if fallback {
            self.report_unreachable(session, [logical_address]).await;
        }
        ConnectOutcome::Failed
    }

    /// Whether the broadcast search may run. Not on a cancelled session, and not
    /// while the transport gate is closed: a quiesce refuses connects, it does
    /// not make gateways unreachable. It only guards the search; whether a
    /// failed connect is refused is decided by the caller's own gate read.
    fn may_fall_back(&self, session: &GatewaySession) -> bool {
        !session.cancel.is_cancelled() && self.gate.is_open()
    }

    /// The gateways announced in answer to a broadcast search for all configured
    /// gateways. At most one search is in flight per session: a gateway that
    /// needs one while another is running waits for that one's result, so
    /// gateways failing at the same time cause one broadcast. The search always
    /// asks for every configured gateway, so a joiner needs no registration. A
    /// gateway that fails after the broadcast was collected starts the next search.
    ///
    /// A joiner whose search was skipped while the gate was closed checks the
    /// gate again: still closed, the skip is its result too; open meanwhile, it
    /// starts (or joins) a fresh search.
    async fn shared_search(&self, session: &Arc<GatewaySession>) -> SearchResult {
        match self.join_or_start_search(session).await {
            SearchJoin::Joined(SearchResult::Skipped) if self.may_fall_back(session) => {
                self.join_or_start_search(session).await.into_result()
            }
            join => join.into_result(),
        }
    }

    /// Waits for the search in flight, or starts one.
    async fn join_or_start_search(&self, session: &Arc<GatewaySession>) -> SearchJoin {
        let (mut receiver, joined) = {
            let mut slot = session
                .search_in_flight
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(receiver) = slot.as_ref() {
                (receiver.clone(), true)
            } else {
                let (sender, receiver) = watch::channel(None);
                *slot = Some(receiver.clone());
                let guard = SearchGuard(Arc::clone(session));
                let state = self.clone();
                let task_session = Arc::clone(session);
                spawn_connection_task(
                    &session.connection_tasks,
                    "doip-fallback-search",
                    async move {
                        let (gateway_map, _) = gateway_ecu_maps(&state.ecus).await;
                        let wanted: HashSet<u16> = gateway_map.keys().copied().collect();
                        let result = match state.search_gateways(&task_session, &wanted).await {
                            Some(found) => SearchResult::Found(Arc::new(found)),
                            None => SearchResult::Skipped,
                        };
                        // Before the result is published, so a later failure starts a new search.
                        drop(guard);
                        sender.send_replace(Some(result));
                    },
                );
                (receiver, false)
            }
        };
        let result = receiver
            .wait_for(Option::is_some)
            .await
            .ok()
            .and_then(|result| result.clone())
            .unwrap_or_else(|| SearchResult::Found(Arc::default()));
        if joined {
            SearchJoin::Joined(result)
        } else {
            SearchJoin::Started(result)
        }
    }

    /// Searches the gateways in `wanted` by a broadcast. A failure is logged and
    /// finds nothing. `None` if the search was skipped because
    /// [`may_fall_back`](Self::may_fall_back) refused it: the transport gate is
    /// closed (or the session is cancelled).
    async fn search_gateways(
        &self,
        session: &GatewaySession,
        wanted: &HashSet<u16>,
    ) -> Option<Vec<DiscoveredGateway>> {
        if !self.may_fall_back(session) {
            return None;
        }
        tracing::info!(
            gateways = ?wanted,
            "Searching gateways not reachable at their persisted address by broadcast"
        );
        let shutdown = session.cancel.child_token().cancelled_owned().shared();
        let found = reconnect::fallback_identification(
            &session.transport_config.tester_ip,
            session.transport_config.port,
            self.netmask,
            &self.ecus,
            wanted,
            shutdown,
        )
        .await
        .unwrap_or_else(|error| {
            tracing::warn!(%error, "Fallback vehicle identification failed");
            Vec::new()
        });
        Some(found)
    }

    /// Searches the gateways in `wanted` by one broadcast and connects the ones
    /// found. While the transport gate is closed nothing is searched, and the
    /// gateways are refused, not found unreachable. Nothing is returned on a
    /// cancelled session.
    pub(crate) async fn fallback_connect(
        &self,
        session: &Arc<GatewaySession>,
        wanted: HashSet<u16>,
    ) -> FallbackOutcome {
        if session.cancel.is_cancelled() {
            return FallbackOutcome::default();
        }
        if !self.gate.is_open() {
            return FallbackOutcome {
                missing: HashSet::default(),
                refused: wanted,
            };
        }
        // Before the search: a failed announcement connect meanwhile belongs to
        // this episode and does not start a second search.
        let inserted: Vec<u16> = {
            let mut episode = session.fallback_episode();
            wanted
                .iter()
                .copied()
                .filter(|logical_address| episode.insert(*logical_address))
                .collect()
        };
        // A search skipped because the gate closed meanwhile is a refusal, as in
        // `run_connect`; on a cancelled session nothing is returned.
        let Some(found) = self.search_gateways(session, &wanted).await else {
            let mut episode = session.fallback_episode();
            for logical_address in &inserted {
                episode.remove(logical_address);
            }
            if session.cancel.is_cancelled() {
                return FallbackOutcome::default();
            }
            return FallbackOutcome {
                missing: HashSet::default(),
                refused: wanted,
            };
        };
        let mut connects = Vec::new();
        for gateway in found {
            let logical_address = gateway.logical_address;
            let connect = self
                .start_connect(session, GatewayTarget::Known(gateway), false)
                .await;
            connects.push((logical_address, connect));
        }
        let mut outcome = FallbackOutcome {
            missing: wanted,
            refused: HashSet::default(),
        };
        for (logical_address, connect) in connects {
            match connect.wait().await {
                ConnectOutcome::Connected => {}
                ConnectOutcome::Refused => {
                    outcome.refused.insert(logical_address);
                }
                ConnectOutcome::Failed => continue,
            }
            outcome.missing.remove(&logical_address);
        }
        if !self.gate.is_open() {
            // Quiesced during the search: refused, not failed.
            outcome.refused.extend(outcome.missing.drain());
        }
        let mut episode = session.fallback_episode();
        for logical_address in inserted
            .iter()
            .filter(|logical_address| outcome.refused.contains(*logical_address))
        {
            episode.remove(logical_address);
        }
        outcome
    }

    /// Marks the ECUs behind the gateways as not reachable and records the
    /// gateways as unreachable in the topology. Does nothing if the session is cancelled.
    pub(crate) async fn report_unreachable(
        &self,
        session: &GatewaySession,
        missing: impl IntoIterator<Item = u16>,
    ) {
        // A stopped or restarted session must not report failures: its connects
        // were cancelled, not refused by the vehicle.
        if session.cancel.is_cancelled() {
            return;
        }
        let (_, gateway_ecu_name_map) = gateway_ecu_maps(&self.ecus).await;
        for logical_address in missing {
            tracing::warn!(
                logical_address = %gateway_key(logical_address),
                "Gateway not found, marking its ECUs as not reachable"
            );
            if let Some(ecu_names) = gateway_ecu_name_map.get(&logical_address) {
                session
                    .connectivity_handler
                    .on_gateway_disconnected(ecu_names)
                    .await;
            }
            // After the state change: recording wakes the persistence, which
            // snapshots the ECU states.
            self.topology.record_unreachable(logical_address);
        }
    }

    /// Opens the connection to one gateway. On success it is recorded in the
    /// topology and its connection index, and variant detection is requested
    /// for its ECUs.
    async fn connect_gateway(
        &self,
        session: &Arc<GatewaySession>,
        gateway: DiscoveredGateway,
    ) -> bool {
        let (gateway_ecu_map, gateway_ecu_name_map) = gateway_ecu_maps(&self.ecus).await;
        let gateway_name = gateway.ecu_name.clone();
        let known_gateway = KnownGateway::from(&gateway);
        let gateway_ecu_names = gateway_ecu_name_map
            .get(&gateway.logical_address)
            .cloned()
            .unwrap_or_default();
        let gateway_state = GatewayState {
            doip_connections: Arc::clone(&self.doip_connections),
            ecus: Arc::clone(&self.ecus),
            gateway_ecu_map,
            connection_tasks: Arc::clone(&session.connection_tasks),
            cancel: session.cancel.clone(),
        };
        match handle_gateway_connection::<T>(
            gateway,
            &session.transport_config,
            &gateway_state,
            Arc::clone(&session.connectivity_handler),
        )
        .await
        {
            Ok(logical_address) => {
                // The index of this gateway's own connection: concurrent connects
                // push to the same list, so the last entry may belong to another.
                let connection_index = self
                    .doip_connections
                    .read()
                    .await
                    .iter()
                    .position(|connection| connection.ecus.contains_key(&logical_address));
                let Some(connection_index) = connection_index else {
                    tracing::warn!(
                        gateway = %gateway_name,
                        "Connection of the gateway not found after connecting, treating it as not connected"
                    );
                    return false;
                };
                self.logical_address_to_connection
                    .write()
                    .await
                    .insert(logical_address, connection_index);
                session.fallback_episode().remove(&logical_address);
                if session.cancel.is_cancelled() {
                    return false;
                }
                self.topology.record_connected(known_gateway);
                if let Err(error) = session
                    .variant_detection
                    .send(VariantDetectionRequest::new(gateway_ecu_names))
                    .await
                {
                    tracing::warn!(
                        gateway = %gateway_name,
                        error = ?error,
                        "Failed to trigger variant detection after gateway connection"
                    );
                }
                true
            }
            Err(error) => {
                tracing::warn!(
                    gateway = %gateway_name,
                    error = %error,
                    "Failed to connect to gateway"
                );
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use cda_interfaces::{
        EcuConnectivityHandler, HashMap, HashMapExtensions, VariantDetectionSender,
        topology::TopologyRuntime,
    };
    use doip_definitions::header::ProtocolVersion;
    use tokio::sync::{RwLock, mpsc};
    use tokio_util::sync::CancellationToken;

    use super::{ConnectOutcome, GatewaySession, GatewayTarget};
    use crate::{
        ConnectionTasks, DiscoveredGateway, DiscoveryGuard, DoipConfig, DoipDiagGateway,
        DoipGatewayOperation, DoipTransportConfig,
        test_helpers::{FakeGateway, NoopConnectivityHandler, TestEcu, wait_until},
        vir_vam::handle_announcement,
    };

    fn discovered(name: &str, logical_address: u16) -> DiscoveredGateway {
        DiscoveredGateway {
            ip: "127.0.0.1".to_owned(),
            ecu_name: name.to_owned(),
            logical_address,
            doip_protocol_version: ProtocolVersion::Iso13400_2012,
        }
    }

    async fn gateway_with_gateways(gateways: &[(&str, u16)]) -> DoipDiagGateway<TestEcu> {
        let mut ecus = HashMap::new();
        for (name, logical_address) in gateways {
            ecus.insert(
                (*name).to_owned(),
                RwLock::new(TestEcu::new(*logical_address, *logical_address)),
            );
        }
        DoipDiagGateway::<TestEcu>::new(
            &DoipConfig::default(),
            Arc::new(ecus),
            VariantDetectionSender::new(mpsc::channel(16).0),
            Arc::new(NoopConnectivityHandler),
        )
        .await
        .unwrap()
    }

    /// A session as a transport start creates it, connecting to `fake`.
    fn session_for(fake: &FakeGateway) -> Arc<GatewaySession> {
        session_with_handler(fake, Arc::new(NoopConnectivityHandler))
    }

    fn session_with_handler(
        fake: &FakeGateway,
        handler: Arc<dyn EcuConnectivityHandler>,
    ) -> Arc<GatewaySession> {
        Arc::new(GatewaySession::new(
            DoipTransportConfig {
                tester_ip: "127.0.0.1".to_owned(),
                port: fake.port(),
                tls_port: 0,
                send_diagnostic_message_ack: false,
                send_timeout: Duration::from_secs(1),
                alive_check_interval: Duration::ZERO,
            },
            Arc::new(ConnectionTasks::new()),
            CancellationToken::new(),
            VariantDetectionSender::new(mpsc::channel(16).0),
            handler,
        ))
    }

    /// Notes whether the gateway was already recorded as unreachable when its
    /// ECUs were reported disconnected.
    struct OrderRecorder {
        topology: Arc<TopologyRuntime>,
        unreachable_at_disconnect: std::sync::Mutex<Vec<bool>>,
    }

    #[async_trait::async_trait]
    impl EcuConnectivityHandler for OrderRecorder {
        async fn on_gateway_connected(&self, _ecu_names: &[String]) {}

        async fn on_gateway_disconnected(&self, _ecu_names: &[String]) {
            self.unreachable_at_disconnect
                .lock()
                .unwrap()
                .push(!self.topology.unreachable().is_empty());
        }
    }

    /// [[ test~doip-unreachable-reported-after-state-change, An unreachable gateway is recorded in the topology after its ECUs changed state, test ]]
    #[tokio::test]
    async fn unreachable_is_recorded_after_the_state_change() {
        let fake = FakeGateway::start().await;
        let gateway = gateway_with_gateways(&[("gw", 0x1000)]).await;
        let recorder = Arc::new(OrderRecorder {
            topology: Arc::clone(&gateway.state.topology),
            unreachable_at_disconnect: std::sync::Mutex::new(Vec::new()),
        });
        let session = session_with_handler(&fake, Arc::clone(&recorder) as _);

        gateway.state.report_unreachable(&session, [0x1000]).await;

        assert_eq!(
            *recorder.unreachable_at_disconnect.lock().unwrap(),
            [false],
            "the disconnect is reported before the gateway is recorded"
        );
        assert_eq!(gateway.state.topology.unreachable(), [0x1000]);
    }

    /// [[ test~doip-cancelled-connect-writes-nothing, A connect that completes after its session was cancelled writes no state, test ]]
    #[tokio::test]
    async fn cancelled_connect_writes_nothing() {
        let fake = FakeGateway::start().await;
        fake.block_connects();
        let gateway = gateway_with_gateways(&[("gw", 0x1000)]).await;
        let session = session_for(&fake);
        *gateway.state.session.write().await = Some(Arc::clone(&session));

        let connect = gateway
            .state
            .start_connect(
                &session,
                GatewayTarget::Known(discovered("gw", 0x1000)),
                false,
            )
            .await;
        wait_until(|| fake.connects() == 1).await;
        session.cancel.cancel();
        fake.release_connects();

        assert_eq!(connect.wait().await, ConnectOutcome::Failed);
        assert!(gateway.state.doip_connections.read().await.is_empty());
        assert!(
            gateway
                .state
                .logical_address_to_connection
                .read()
                .await
                .is_empty()
        );
        assert!(gateway.state.topology.connected().is_empty());
        session.connection_tasks.shutdown().await;
    }

    /// [[ test~doip-cancelled-session-reports-nothing, A failure on a cancelled session reports no disconnect and enters no failure episode, test ]]
    #[tokio::test]
    async fn cancelled_session_reports_nothing() {
        let fake = FakeGateway::start().await;
        fake.block_connects();
        let gateway = gateway_with_gateways(&[("gw", 0x1000)]).await;
        let recorder = Arc::new(OrderRecorder {
            topology: Arc::clone(&gateway.state.topology),
            unreachable_at_disconnect: std::sync::Mutex::new(Vec::new()),
        });
        let session = session_with_handler(&fake, Arc::clone(&recorder) as _);
        *gateway.state.session.write().await = Some(Arc::clone(&session));

        let connect = gateway
            .state
            .start_connect(
                &session,
                GatewayTarget::Known(discovered("gw", 0x1000)),
                true,
            )
            .await;
        wait_until(|| fake.connects() == 1).await;
        session.cancel.cancel();
        fake.release_connects();

        assert_eq!(connect.wait().await, ConnectOutcome::Failed);
        gateway.state.report_unreachable(&session, [0x1000]).await;
        assert!(
            recorder
                .unreachable_at_disconnect
                .lock()
                .unwrap()
                .is_empty()
        );
        assert!(gateway.state.topology.unreachable().is_empty());
        assert!(session.fallback_episode().is_empty());
        session.connection_tasks.shutdown().await;
    }

    /// [[ test~doip-clear-forgets-pending-addresses, Clearing makes a pending gateway use the broadcast fallback instead of its old address, test ]]
    #[tokio::test]
    async fn forgotten_pending_address_is_not_connected_directly() {
        use cda_interfaces::topology::PendingGateways as _;

        let fake = FakeGateway::start().await;
        let gateway = gateway_with_gateways(&[("gw", 0x1000)]).await;
        let session = session_for(&fake);
        session
            .pending
            .lock()
            .await
            .insert(0x1000, Some(discovered("gw", 0x1000)));
        *gateway.state.session.write().await = Some(Arc::clone(&session));

        gateway.forget_pending_addresses().await;

        assert!(!gateway.connect_pending(0x1000).await);
        assert_eq!(fake.connects(), 0, "no direct connect to the old address");
        assert!(
            session.fallback_episode().contains(&0x1000),
            "the gateway went to the broadcast fallback"
        );
        session.connection_tasks.shutdown().await;
    }

    /// [[ test~doip-address-after-clear-from-announcement, An announcement after a clear gives the pending gateway an address to connect to directly, test ]]
    #[tokio::test]
    async fn announcement_after_clear_gives_the_gateway_an_address() {
        use cda_interfaces::topology::PendingGateways as _;

        let fake = FakeGateway::start().await;
        let gateway = gateway_with_gateways(&[("gw", 0x1000)]).await;
        let session = session_for(&fake);
        session
            .pending
            .lock()
            .await
            .insert(0x1000, Some(discovered("gw", 0x1000)));
        *gateway.state.session.write().await = Some(Arc::clone(&session));

        gateway.forget_pending_addresses().await;
        assert!(matches!(
            session.pending_target(0x1000).await,
            Some(GatewayTarget::Search(0x1000))
        ));
        assert!(session.update_pending(&discovered("gw", 0x1000)).await);

        assert!(gateway.connect_pending(0x1000).await);
        assert_eq!(
            fake.connects(),
            1,
            "connected directly to the announced address"
        );
        session.connection_tasks.shutdown().await;
    }

    /// A connect of a stopped transport start must not change the pending
    /// gateways of the next start.
    /// [[ test~doip-stale-lazy-connect-does-not-touch-new-session, A connect of an earlier transport start does not change the next start, test ]]
    #[tokio::test]
    async fn stale_lazy_connect_does_not_touch_new_session() {
        let fake = FakeGateway::start().await;
        fake.block_connects();
        let gateway = gateway_with_gateways(&[("gw", 0x1000)]).await;

        let old = session_for(&fake);
        old.pending
            .lock()
            .await
            .insert(0x1000, Some(discovered("gw", 0x1000)));
        *gateway.state.session.write().await = Some(Arc::clone(&old));
        let mut operation = DoipGatewayOperation::default();
        operation.cancel = Some(old.cancel.clone());
        operation.connection_tasks = Some(Arc::clone(&old.connection_tasks));

        let caller = {
            let gateway = gateway.clone();
            tokio::spawn(async move { gateway.connect_pending(0x1000).await })
        };
        wait_until(|| fake.connects() == 1).await;

        // Stop, then a new lazy start with the same pending gateway.
        gateway.stop(&mut operation).await;
        let new = session_for(&fake);
        new.pending
            .lock()
            .await
            .insert(0x1000, Some(discovered("gw", 0x1000)));
        *gateway.state.session.write().await = Some(Arc::clone(&new));
        fake.release_connects();

        assert!(!caller.await.unwrap(), "the stale connect is abandoned");
        assert!(
            new.is_pending(0x1000).await,
            "the new session's pending entry is untouched"
        );
        assert!(gateway.state.current_session().await.is_some());
    }

    /// [[ test~doip-gateway-connect-once, A dropped caller does not start a second connect of the same gateway, test ]]
    #[tokio::test]
    async fn dropped_caller_does_not_start_a_second_connect() {
        let fake = FakeGateway::start().await;
        fake.block_connects();
        let gateway = gateway_with_gateways(&[("gw", 0x1000)]).await;
        let session = session_for(&fake);
        session
            .pending
            .lock()
            .await
            .insert(0x1000, Some(discovered("gw", 0x1000)));
        *gateway.state.session.write().await = Some(Arc::clone(&session));

        let first = {
            let gateway = gateway.clone();
            tokio::spawn(async move { gateway.connect_pending(0x1000).await })
        };
        wait_until(|| fake.connects() == 1).await;
        first.abort();
        let _ = first.await;

        let second = {
            let gateway = gateway.clone();
            tokio::spawn(async move { gateway.connect_pending(0x1000).await })
        };
        wait_until(|| session.is_connecting(0x1000)).await;
        fake.release_connects();

        assert!(second.await.unwrap(), "the second caller got the connect");
        assert_eq!(fake.connects(), 1, "exactly one connection was opened");
        session.connection_tasks.shutdown().await;
    }

    /// An announcement of a gateway the startup reconnect is connecting does not
    /// open a second connection.
    /// [[ test~doip-vam-during-reconnect-does-not-connect-twice, An announcement of a gateway being connected opens no second connection, test ]]
    #[tokio::test]
    async fn vam_during_reconnect_does_not_connect_twice() {
        let fake = FakeGateway::start().await;
        fake.block_connects();
        let gateway = gateway_with_gateways(&[("gw", 0x1000)]).await;
        let session = session_for(&fake);
        *gateway.state.session.write().await = Some(Arc::clone(&session));

        let reconnect = gateway
            .state
            .start_connect(
                &session,
                GatewayTarget::Known(discovered("gw", 0x1000)),
                false,
            )
            .await;
        wait_until(|| fake.connects() == 1).await;

        let (_, names) = super::gateway_ecu_maps(&gateway.state.ecus).await;
        tokio::time::timeout(
            Duration::from_secs(5),
            handle_announcement(
                &gateway.state,
                &session,
                discovered("gw", 0x1000),
                &names,
                &gateway.variant_detection,
            ),
        )
        .await
        .expect("an announcement must not wait for the connect in flight");

        fake.release_connects();
        assert_eq!(reconnect.wait().await, ConnectOutcome::Connected);
        assert_eq!(fake.connects(), 1, "exactly one connection was opened");
        session.connection_tasks.shutdown().await;
    }

    /// [[ test~doip-gate-refuses-connect-while-quiesced, No gateway connects while the transport gate is closed, test ]]
    #[tokio::test]
    async fn closed_gate_refuses_connects_without_reporting_a_failure() {
        use cda_interfaces::topology::PendingGateways as _;

        let fake = FakeGateway::start().await;
        let recorder = Arc::new(DisconnectRecorder::default());
        let gateway = gateway_with_gateways(&[("gw", 0x1000), ("gw2", 0x2000)]).await;
        let session = session_with_handler(&fake, Arc::clone(&recorder) as _);
        session
            .pending
            .lock()
            .await
            .insert(0x1000, Some(discovered("gw", 0x1000)));
        *gateway.state.session.write().await = Some(Arc::clone(&session));
        let (_, names) = super::gateway_ecu_maps(&gateway.state.ecus).await;

        gateway.state.gate.close();
        gateway.connect_all_pending().await;
        handle_announcement(
            &gateway.state,
            &session,
            discovered("gw2", 0x2000),
            &names,
            &gateway.variant_detection,
        )
        .await;

        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(50)).await;
        assert_eq!(fake.connects(), 0, "no connect while the gate is closed");
        assert!(
            recorder.0.lock().unwrap().is_empty(),
            "a refusal is no failure"
        );
        assert!(gateway.state.topology.unreachable().is_empty());
        assert!(session.fallback_episode().is_empty());
        assert!(
            session.is_pending(0x1000).await,
            "still waiting for its first use"
        );

        gateway.state.gate.open();
        gateway.connect_all_pending().await;
        assert_eq!(fake.connects(), 1);
        session.connection_tasks.shutdown().await;
    }

    /// [[ test~doip-vam-connect-does-not-block-listener, An announcement starts its connect in the background so the next announcement is handled meanwhile, test ]]
    #[tokio::test]
    async fn vam_connect_does_not_block_the_listener() {
        let fake = FakeGateway::start().await;
        fake.block_connects();
        let gateway = gateway_with_gateways(&[("gw1", 0x1000), ("gw2", 0x2000)]).await;
        let session = session_for(&fake);
        *gateway.state.session.write().await = Some(Arc::clone(&session));
        let (_, names) = super::gateway_ecu_maps(&gateway.state.ecus).await;

        for (name, logical_address) in [("gw1", 0x1000), ("gw2", 0x2000)] {
            tokio::time::timeout(
                Duration::from_secs(1),
                handle_announcement(
                    &gateway.state,
                    &session,
                    discovered(name, logical_address),
                    &names,
                    &gateway.variant_detection,
                ),
            )
            .await
            .expect("an announcement must not wait for its connect");
        }
        wait_until(|| fake.connects() == 2).await;

        fake.release_connects();
        wait_until(|| !session.is_connecting(0x1000) && !session.is_connecting(0x2000)).await;
        assert_eq!(
            gateway
                .state
                .logical_address_to_connection
                .read()
                .await
                .len(),
            2
        );
        session.connection_tasks.shutdown().await;
    }

    /// [[ test~doip-gate-closed-during-connect, A connect that fails after the transport gate closed is neither searched nor reported, test ]]
    #[tokio::test]
    async fn connect_failing_after_the_gate_closed_reports_nothing() {
        let fake = FakeGateway::start().await;
        fake.block_connects();
        let recorder = Arc::new(DisconnectRecorder::default());
        let gateway = gateway_with_gateways(&[("gw", 0x1000)]).await;
        let session = session_with_handler(&fake, Arc::clone(&recorder) as _);
        *gateway.state.session.write().await = Some(Arc::clone(&session));

        let connect = gateway
            .state
            .start_connect(
                &session,
                GatewayTarget::Known(discovered("gw", 0x1000)),
                true,
            )
            .await;
        wait_until(|| fake.connects() == 1).await;
        gateway.state.gate.close();
        let failed_at = std::time::Instant::now();
        // Ends the held routing activation without an answer: the TCP attempt
        // in progress finishes and fails.
        drop(fake);

        assert_eq!(connect.wait().await, ConnectOutcome::Refused);
        assert!(
            failed_at.elapsed() < Duration::from_millis(500),
            "no fallback search ran (it collects announcements for 1 s)"
        );
        assert!(
            recorder.0.lock().unwrap().is_empty(),
            "a refusal is no failure"
        );
        assert!(gateway.state.topology.unreachable().is_empty());
        assert!(
            session.fallback_episode().is_empty(),
            "no failure episode while quiesced"
        );
        session.connection_tasks.shutdown().await;
    }

    /// [[ test~doip-refused-connect-stays-pending, A pending gateway whose connect is refused while quiesced stays pending and connects on its next use, test ]]
    #[tokio::test]
    async fn refused_lazy_connect_stays_pending() {
        let fake = FakeGateway::start().await;
        fake.block_connects();
        let recorder = Arc::new(DisconnectRecorder::default());
        let gateway = gateway_with_gateways(&[("gw", 0x1000)]).await;
        let session = session_with_handler(&fake, Arc::clone(&recorder) as _);
        session
            .pending
            .lock()
            .await
            .insert(0x1000, Some(discovered("gw", 0x1000)));
        *gateway.state.session.write().await = Some(Arc::clone(&session));

        let caller = {
            let gateway = gateway.clone();
            tokio::spawn(async move { gateway.connect_pending(0x1000).await })
        };
        wait_until(|| fake.connects() == 1).await;
        gateway.state.gate.close();
        fake.set_failing(true);
        fake.release_connects();

        assert!(!caller.await.unwrap());
        assert!(
            session.is_pending(0x1000).await,
            "a refused gateway stays pending"
        );
        assert!(recorder.0.lock().unwrap().is_empty());
        assert!(gateway.state.topology.unreachable().is_empty());
        assert!(session.fallback_episode().is_empty());

        gateway.state.gate.open();
        fake.set_failing(false);
        assert!(
            gateway.connect_pending(0x1000).await,
            "the next use connects it"
        );
        assert!(!session.is_pending(0x1000).await);
        session.connection_tasks.shutdown().await;
    }

    /// A clear during the startup reconnect finds no pending gateway to forget:
    /// the refused gateways must not be added with their persisted address.
    /// [[ test~doip-refused-startup-gateways-pending, Gateways of the startup reconnect refused while quiesced become pending without an address and are searched on their first use, test ]]
    #[tokio::test]
    async fn refused_startup_reconnect_gateways_become_pending() {
        use cda_interfaces::topology::PendingGateways as _;

        let fake = FakeGateway::start().await;
        fake.block_connects();
        let recorder = Arc::new(DisconnectRecorder::default());
        let gateway =
            gateway_with_gateways(&[("gw", 0x1000), ("gw2", 0x2000), ("gw3", 0x3000)]).await;
        let session = session_with_handler(&fake, Arc::clone(&recorder) as _);
        *gateway.state.session.write().await = Some(Arc::clone(&session));

        // Refused mid-flight: the connect fails after the gate closed.
        let mid_flight = gateway
            .state
            .start_connect(
                &session,
                GatewayTarget::Known(discovered("gw", 0x1000)),
                false,
            )
            .await;
        wait_until(|| fake.connects() == 1).await;
        gateway.state.gate.close();
        gateway.forget_pending_addresses().await;
        fake.set_failing(true);
        fake.release_connects();
        let up_front = gateway
            .state
            .start_connect(
                &session,
                GatewayTarget::Known(discovered("gw2", 0x2000)),
                false,
            )
            .await;
        DoipDiagGateway::<TestEcu>::finish_reconnect(
            &gateway.state,
            &session,
            DiscoveryGuard::begin(&gateway.state.topology),
            vec![
                (discovered("gw", 0x1000), mid_flight),
                (discovered("gw2", 0x2000), up_front),
            ],
            [0x3000].into_iter().collect(),
        )
        .await;

        assert!(
            recorder.0.lock().unwrap().is_empty(),
            "a refusal is no failure"
        );
        assert!(gateway.state.topology.unreachable().is_empty());
        for logical_address in [0x1000, 0x2000, 0x3000] {
            assert!(matches!(
                session.pending_target(logical_address).await,
                Some(GatewayTarget::Search(address)) if address == logical_address
            ));
        }

        gateway.state.gate.open();
        fake.set_failing(false);
        assert!(!gateway.connect_pending(0x1000).await);
        assert_eq!(fake.connects(), 1, "no direct connect to the old address");
        assert!(
            session.fallback_episode().contains(&0x1000),
            "the first use went to the broadcast fallback"
        );

        // An announcement gives another refused gateway an address, without
        // connecting it; its first use then connects it directly.
        let (_, names) = super::gateway_ecu_maps(&gateway.state.ecus).await;
        handle_announcement(
            &gateway.state,
            &session,
            discovered("gw2", 0x2000),
            &names,
            &gateway.variant_detection,
        )
        .await;
        assert!(matches!(
            session.pending_target(0x2000).await,
            Some(GatewayTarget::Known(gateway)) if gateway.logical_address == 0x2000
        ));
        assert_eq!(fake.connects(), 1, "the announcement does not connect it");
        assert!(gateway.connect_pending(0x2000).await);
        assert_eq!(fake.connects(), 2);
        assert!(!session.is_pending(0x2000).await);
        session.connection_tasks.shutdown().await;
    }

    /// Records the ECUs reported disconnected.
    #[derive(Default)]
    struct DisconnectRecorder(std::sync::Mutex<Vec<String>>);

    #[async_trait::async_trait]
    impl EcuConnectivityHandler for DisconnectRecorder {
        async fn on_gateway_connected(&self, _ecu_names: &[String]) {}

        async fn on_gateway_disconnected(&self, ecu_names: &[String]) {
            self.0.lock().unwrap().extend(ecu_names.iter().cloned());
        }
    }
}
