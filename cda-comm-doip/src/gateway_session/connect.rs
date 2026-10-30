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

//! Connect coordination. Every connect of a gateway (startup discovery,
//! persisted reconnect, announcement, direct connect) holds the gateway's
//! connect lock of the session while it runs, so connects of one gateway
//! never overlap. A connect that gets the lock connects only if the gateway is
//! not connected by then. So a discovery connect that waited for a failed
//! direct connect connects itself, and a direct connect that finds the lock
//! taken is rejected.
//!
//! A connect does not search a gateway it could not reach: the caller decides
//! what a failure means (the persisted reconnect searches by one VIR, an
//! announcement reports the gateway unreachable). A cancelled session fails
//! the attempt, even if it connected.

use std::sync::Arc;

use cda_interfaces::{
    DoipComParams, EcuAddresses, HashMap, HashSet, VariantDetectionRequest,
    topology::{KnownGateway, logical_address_hex},
    util::std_ext::lock_mutex,
};
use tokio::sync::oneshot;

use super::{GatewaySession, gateway_ecu_maps};
use crate::{
    DiscoveredGateway, DoipGatewayState,
    connections::{ConnectControl, EcuError, GatewayState, handle_gateway_connection},
    spawn_connection_task,
};

/// Result of one gateway connect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConnectOutcome {
    Connected,
    /// The gateway could not be connected, or the session was cancelled.
    Failed,
}

/// How a gateway connect was requested.
#[derive(Clone, Copy)]
enum ConnectRequest<'a> {
    /// Announced, persisted or found by a search: recorded in the topology.
    Discovered,
    /// Requested for a given address (`doip-connect-ecu`): its handshake is
    /// bounded by `control` and it is not recorded in the topology.
    Direct(&'a ConnectControl),
}

/// Why a gateway connect failed.
#[derive(Debug)]
pub(crate) enum ConnectFailure {
    /// The session was cancelled (transport stop or restart).
    Cancelled,
    /// The connection could not be established.
    Error(EcuError),
}

/// Why a direct connect was not started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DirectRejection {
    /// The gateway is connected already.
    Connected,
    /// A connect of the gateway is in flight.
    Connecting,
}

/// The outcome of a connect started by [`DoipGatewayState::start_connect`].
pub(crate) struct PendingConnect(oneshot::Receiver<ConnectOutcome>);

impl PendingConnect {
    /// A connect that is done already.
    #[cfg(test)]
    pub(crate) fn done(outcome: ConnectOutcome) -> Self {
        let (sender, receiver) = oneshot::channel();
        let _ = sender.send(outcome);
        Self(receiver)
    }

    /// Waits for the connect. `Failed` if its task ended without a result.
    pub(crate) async fn wait(self) -> ConnectOutcome {
        self.0.await.unwrap_or(ConnectOutcome::Failed)
    }
}

impl GatewaySession {
    /// A checkpoint of a connect attempt: `false` once the transport was
    /// stopped or restarted.
    pub(super) fn is_active(&self) -> bool {
        !self.cancel_token.is_cancelled()
    }

    /// The connect lock of the gateway `logical_address`, see the module docs.
    pub(crate) fn connect_lock(&self, logical_address: u16) -> Arc<tokio::sync::Mutex<()>> {
        Arc::clone(
            lock_mutex(&self.connect_locks)
                .entry(logical_address)
                .or_default(),
        )
    }

    /// Whether a connect of `logical_address` holds its lock.
    #[cfg(test)]
    pub(crate) fn is_connecting(&self, logical_address: u16) -> bool {
        self.connect_lock(logical_address).try_lock().is_err()
    }

    /// Takes the gateways whose connect reported their ECUs connected without
    /// deciding to keep them yet, see [`Self::online_reports`].
    pub(crate) fn take_online_reports(&self) -> HashSet<u16> {
        std::mem::take(&mut *lock_mutex(&self.online_reports))
    }

    /// Gateways with an announcement waiting for their connect lock, with
    /// their newest announcement.
    pub(crate) fn announced_map(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<u16, DiscoveredGateway>> {
        lock_mutex(&self.announced)
    }
}

impl<T: EcuAddresses + DoipComParams> DoipGatewayState<T> {
    /// Starts a connect of `gateway` in a task of the session, without
    /// waiting for it.
    /// [[ dimpl~doip-discovery-connect-waits-for-direct-connect, A discovery connect waits for a direct connect in flight and connects itself if that failed, dimpl ]]
    pub(crate) fn start_connect(
        &self,
        session: &Arc<GatewaySession>,
        gateway: DiscoveredGateway,
    ) -> PendingConnect {
        let (sender, receiver) = oneshot::channel();
        let state = self.clone();
        let task_session = Arc::clone(session);
        spawn_connection_task(
            &session.connection_tasks,
            &format!(
                "doip-gateway-connect-{}",
                logical_address_hex(gateway.logical_address)
            ),
            async move {
                let lock = task_session.connect_lock(gateway.logical_address);
                let outcome = {
                    let _held = lock.lock().await;
                    state.connect_locked(&task_session, gateway).await
                };
                let _ = sender.send(outcome);
            },
        );
        PendingConnect(receiver)
    }

    /// Starts the connects of `gateways`, see [`Self::start_connect`].
    pub(crate) fn start_connects(
        &self,
        session: &Arc<GatewaySession>,
        gateways: Vec<DiscoveredGateway>,
    ) -> Vec<(DiscoveredGateway, PendingConnect)> {
        gateways
            .into_iter()
            .map(|gateway| {
                let connect = self.start_connect(session, gateway.clone());
                (gateway, connect)
            })
            .collect()
    }

    /// Whether `logical_address` is connected once no connect of it holds its lock.
    pub(crate) async fn is_connected_after_in_flight(
        &self,
        session: &GatewaySession,
        logical_address: u16,
    ) -> bool {
        let lock = session.connect_lock(logical_address);
        let _held = lock.lock().await;
        self.has_connection(logical_address).await
    }

    /// Connects `gateway` unless it is connected already. The caller holds
    /// the gateway's connect lock.
    pub(crate) async fn connect_locked(
        &self,
        session: &Arc<GatewaySession>,
        gateway: DiscoveredGateway,
    ) -> ConnectOutcome {
        if !session.is_active() {
            return ConnectOutcome::Failed;
        }
        if self.has_connection(gateway.logical_address).await {
            return ConnectOutcome::Connected;
        }
        match self
            .open_gateway(session, gateway, ConnectRequest::Discovered)
            .await
        {
            Ok(()) => ConnectOutcome::Connected,
            Err(_) => ConnectOutcome::Failed,
        }
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
        if session.cancel_token.is_cancelled() {
            return;
        }
        let (_, gateway_ecu_name_map) = gateway_ecu_maps(&self.ecus).await;
        for logical_address in missing {
            tracing::warn!(
                logical_address = %logical_address_hex(logical_address),
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

    /// Opens the connection to one gateway. On success its ECUs are reported
    /// connected, it is recorded in the topology (if discovered), and variant
    /// detection is requested for its ECUs.
    /// [[ dimpl~doip-direct-connect-not-recorded, A direct connect is not recorded in the topology, dimpl ]]
    async fn open_gateway(
        &self,
        session: &Arc<GatewaySession>,
        gateway: DiscoveredGateway,
        request: ConnectRequest<'_>,
    ) -> Result<(), ConnectFailure> {
        let (gateway_ecu_map, gateway_ecu_name_map) = gateway_ecu_maps(&self.ecus).await;
        let logical_address = gateway.logical_address;
        let gateway_name = gateway.ecu_name.clone();
        let known_gateway = KnownGateway::from(&gateway);
        let gateway_ecu_names = gateway_ecu_name_map
            .get(&logical_address)
            .cloned()
            .unwrap_or_default();
        let gateway_state = GatewayState {
            doip_connections: Arc::clone(&self.doip_connections),
            logical_address_to_connection: Arc::clone(&self.logical_address_to_connection),
            ecus: Arc::clone(&self.ecus),
            gateway_ecu_map,
            connection_tasks: Arc::clone(&session.connection_tasks),
            cancel_token: session.cancel_token.clone(),
        };
        let control = match request {
            ConnectRequest::Discovered => None,
            ConnectRequest::Direct(control) => Some(control),
        };
        let connected_ecu_names = handle_gateway_connection::<T>(
            gateway,
            &session.transport_config,
            &gateway_state,
            Arc::clone(&session.connectivity_handler),
            control,
        )
        .await
        .map_err(|error| {
            tracing::warn!(
                gateway = %gateway_name,
                error = %error,
                "Failed to connect to gateway"
            );
            if session.cancel_token.is_cancelled() {
                ConnectFailure::Cancelled
            } else {
                ConnectFailure::Error(error)
            }
        })?;
        // A cancelled session must not change the ECU states or the shared topology.
        if !session.is_active() {
            return Err(ConnectFailure::Cancelled);
        }
        // Marked before the report, so a stop that aborts it midway reverts it.
        lock_mutex(&session.online_reports).insert(logical_address);
        session
            .connectivity_handler
            .on_gateway_connected(&connected_ecu_names)
            .await;
        let cancelled = !session.is_active();
        if cancelled {
            // The stop does not reset ECU states, so revert the report here.
            // [[ dimpl~doip-cancelled-connect-reverts-ecu-states, A connect that sees the stop after reporting its ECUs connected reports them disconnected again, dimpl ]]
            session
                .connectivity_handler
                .on_gateway_disconnected(&gateway_ecu_names)
                .await;
        }
        lock_mutex(&session.online_reports).remove(&logical_address);
        if cancelled {
            return Err(ConnectFailure::Cancelled);
        }
        // A direct connect is ad hoc (e.g. ECU development): it is not
        // persisted, so the next start does not reconnect to its address.
        if matches!(request, ConnectRequest::Discovered) {
            self.topology.record_connected(known_gateway);
        }
        if let Err(error) = session
            .variant_detection
            .send(VariantDetectionRequest::new(gateway_ecu_names))
            .await
        {
            match request {
                ConnectRequest::Discovered => tracing::warn!(
                    gateway = %gateway_name,
                    error = ?error,
                    "Failed to trigger variant detection after gateway connection"
                ),
                ConnectRequest::Direct(_) => tracing::warn!(
                    gateway = %gateway_name,
                    error = ?error,
                    "Failed to trigger variant detection after direct connection"
                ),
            }
        }
        Ok(())
    }

    /// Starts a direct connect (`doip-connect-ecu`) of `gateway` in a task of
    /// the session. Rejected if a connect of the gateway holds its lock, or the
    /// gateway is connected. A connect waiting for the lock meanwhile connects
    /// itself if this one did not connect. The task goes on if the caller
    /// drops the receiver; the transport stop aborts it.
    pub(crate) async fn start_direct_connect(
        &self,
        session: &Arc<GatewaySession>,
        gateway: DiscoveredGateway,
        control: ConnectControl,
    ) -> Result<oneshot::Receiver<Result<(), ConnectFailure>>, DirectRejection> {
        let logical_address = gateway.logical_address;
        let Ok(held) = session.connect_lock(logical_address).try_lock_owned() else {
            return Err(DirectRejection::Connecting);
        };
        if self.has_connection(logical_address).await {
            return Err(DirectRejection::Connected);
        }
        let (result_sender, result_receiver) = oneshot::channel();
        let state = self.clone();
        let task_session = Arc::clone(session);
        spawn_connection_task(
            &session.connection_tasks,
            &format!(
                "doip-direct-connect-{}",
                logical_address_hex(logical_address)
            ),
            async move {
                let result = state
                    .open_gateway(&task_session, gateway, ConnectRequest::Direct(&control))
                    .await;
                // Released first, so the caller finds the gateway free.
                drop(held);
                // The caller may have given up meanwhile.
                let _ = result_sender.send(result);
            },
        );
        Ok(result_receiver)
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use super::{ConnectOutcome, GatewaySession};
    use crate::{
        DiscoveredGateway, DoipDiagGateway,
        config::DiscoveryMode,
        test_helpers::{
            FakeGateway, OrderRecorder, TestEcu, discovered, discovered_at, gateway_with_gateways,
            session_with, session_with_handler, wait_until,
        },
        vir_vam::handle_announcement,
    };

    /// A fake gateway that holds back its connects, and the gateway 0x1000
    /// with a session in `discovery` mode that reports to an [`OrderRecorder`],
    /// installed as the current one.
    async fn blocked_gateway(
        discovery: DiscoveryMode,
    ) -> (
        FakeGateway,
        DoipDiagGateway<TestEcu>,
        Arc<GatewaySession>,
        Arc<OrderRecorder>,
    ) {
        let fake = FakeGateway::start().await;
        fake.block_connects();
        let gateway = gateway_with_gateways(&[("gw", 0x1000)]).await;
        let recorder = OrderRecorder::new(&gateway.state.topology);
        let session = session_with(&fake, Arc::clone(&recorder) as _, discovery);
        *gateway.state.session.write().await = Some(Arc::clone(&session));
        (fake, gateway, session, recorder)
    }

    /// Announces `announced` while a connect of the gateway is in flight.
    async fn announce(
        gateway: &DoipDiagGateway<TestEcu>,
        session: &Arc<GatewaySession>,
        announced: DiscoveredGateway,
    ) {
        let (_, names) = super::gateway_ecu_maps(&gateway.state.ecus).await;
        tokio::time::timeout(
            Duration::from_secs(1),
            handle_announcement(
                &gateway.state,
                session,
                announced,
                &names,
                &gateway.variant_detection,
            ),
        )
        .await
        .expect("an announcement must not wait for the connect in flight");
    }

    /// [[ test~doip-unreachable-reported-after-state-change, An unreachable gateway is recorded in the topology after its ECUs changed state, test ]]
    #[tokio::test]
    async fn unreachable_is_recorded_after_the_state_change() {
        let fake = FakeGateway::start().await;
        let gateway = gateway_with_gateways(&[("gw", 0x1000)]).await;
        let recorder = OrderRecorder::new(&gateway.state.topology);
        let session = session_with_handler(&fake, Arc::clone(&recorder) as _);

        gateway.state.report_unreachable(&session, [0x1000]).await;

        assert_eq!(
            *recorder.unreachable_at_disconnect.lock().unwrap(),
            [false],
            "the disconnect is reported before the gateway is recorded"
        );
        assert_eq!(gateway.state.topology.unreachable(), [0x1000]);
    }

    /// A failed announcement connect is reported unreachable, also with VIR
    /// allowed, without trying the gateway again.
    /// [[ test~doip-failed-announcement-connect-reported, A failed announcement connect is reported unreachable without a VIR search, test ]]
    #[tokio::test]
    async fn failed_announcement_connect_is_reported_unreachable() {
        let (fake, gateway, session, _) = blocked_gateway(DiscoveryMode::Full).await;
        fake.deny_next_connect();
        fake.release_connects();

        announce(&gateway, &session, discovered("gw", 0x1000)).await;

        wait_until(async || !gateway.state.topology.unreachable().is_empty()).await;
        assert_eq!(gateway.state.topology.unreachable(), [0x1000]);
        assert_eq!(fake.connects(), 1);
        session.connection_tasks.shutdown().await;
    }

    /// A connect that completes after its session was cancelled writes no
    /// state, and reports nothing.
    /// [[ test~doip-cancelled-connect-writes-nothing, A connect that completes after its session was cancelled writes no state, test ]]
    /// [[ test~doip-cancelled-session-reports-nothing, A failure on a cancelled session reports no disconnect, test ]]
    #[tokio::test]
    async fn cancelled_connect_writes_and_reports_nothing() {
        let (fake, gateway, session, recorder) = blocked_gateway(DiscoveryMode::Full).await;

        let connect = gateway
            .state
            .start_connect(&session, discovered("gw", 0x1000));
        wait_until(async || fake.connects() == 1).await;
        session.cancel_token.cancel();
        fake.release_connects();

        assert_eq!(connect.wait().await, ConnectOutcome::Failed);
        assert!(gateway.state.doip_connections.read().await.is_empty());
        assert!(!gateway.state.has_connection(0x1000).await);
        assert!(gateway.state.topology.connected().is_empty());
        gateway.state.report_unreachable(&session, [0x1000]).await;
        assert!(
            recorder
                .unreachable_at_disconnect
                .lock()
                .unwrap()
                .is_empty()
        );
        assert!(gateway.state.topology.unreachable().is_empty());
        session.connection_tasks.shutdown().await;
    }

    /// An announcement of a gateway the startup reconnect is connecting, at
    /// the same or another address, does not open a second connection and
    /// keeps the connection of the connect in flight.
    /// [[ test~doip-vam-during-reconnect-does-not-connect-twice, An announcement of a gateway being connected opens no second connection, test ]]
    #[tokio::test]
    async fn vam_during_reconnect_does_not_connect_twice() {
        for announced_ip in ["127.0.0.1", "0.0.0.0"] {
            let (fake, gateway, session, _) = blocked_gateway(DiscoveryMode::Full).await;

            let reconnect = gateway
                .state
                .start_connect(&session, discovered("gw", 0x1000));
            wait_until(async || fake.connects() == 1).await;
            announce(
                &gateway,
                &session,
                discovered_at("gw", 0x1000, announced_ip),
            )
            .await;

            fake.release_connects();
            assert_eq!(reconnect.wait().await, ConnectOutcome::Connected);
            wait_until(async || session.announced_map().is_empty()).await;
            assert_eq!(fake.connects(), 1, "exactly one connection was opened");
            assert_eq!(
                gateway.state.connection_ip(0x1000).await.as_deref(),
                Some("127.0.0.1")
            );
            session.connection_tasks.shutdown().await;
        }
    }

    /// [[ test~doip-vam-connect-does-not-block-listener, An announcement starts its connect in the background so the next announcement is handled meanwhile, test ]]
    // Connects to `0.0.0.0`, which does not reach the fake gateway on Windows.
    #[cfg(not(windows))]
    #[tokio::test]
    async fn vam_connect_does_not_block_the_listener() {
        let fake = FakeGateway::start().await;
        fake.block_connects();
        let gateway = gateway_with_gateways(&[("gw1", 0x1000), ("gw2", 0x2000)]).await;
        let session = crate::test_helpers::session_for(&fake);
        *gateway.state.session.write().await = Some(Arc::clone(&session));

        for (name, logical_address, ip) in
            [("gw1", 0x1000, "127.0.0.1"), ("gw2", 0x2000, "0.0.0.0")]
        {
            announce(&gateway, &session, discovered_at(name, logical_address, ip)).await;
        }
        wait_until(async || fake.connects() == 2).await;

        fake.release_connects();
        wait_until(async || !session.is_connecting(0x1000) && !session.is_connecting(0x2000)).await;
        assert_eq!(
            gateway
                .state
                .logical_address_to_connection
                .read()
                .await
                .len(),
            2
        );
        // Each gateway maps to its own connection, whichever connect finished first.
        assert_eq!(
            gateway.state.connection_ip(0x1000).await.as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(
            gateway.state.connection_ip(0x2000).await.as_deref(),
            Some("0.0.0.0")
        );
        session.connection_tasks.shutdown().await;
    }

    /// An announcement during a connect that then fails connects the gateway at
    /// the announced address, whether it is the address of the failed connect
    /// or another one.
    /// [[ test~doip-vam-during-connect-connects-after-failure, An announcement during a connect in flight connects the gateway if that connect fails, test ]]
    // Connects to `0.0.0.0`, which does not reach the fake gateway on Windows.
    #[cfg(not(windows))]
    #[tokio::test]
    async fn vam_during_a_failing_connect_connects_at_the_announced_address() {
        for announced_ip in ["0.0.0.0", "127.0.0.1"] {
            let (fake, gateway, session, _) = blocked_gateway(DiscoveryMode::Full).await;
            fake.deny_next_connect();

            let first = gateway
                .state
                .start_connect(&session, discovered("gw", 0x1000));
            wait_until(async || fake.connects() == 1).await;
            announce(
                &gateway,
                &session,
                discovered_at("gw", 0x1000, announced_ip),
            )
            .await;
            assert_eq!(fake.connects(), 1, "no parallel connect");

            fake.release_connects();
            assert_eq!(first.wait().await, ConnectOutcome::Failed);
            wait_until(async || fake.connects() == 2).await;
            wait_until(async || !session.is_connecting(0x1000)).await;
            assert_eq!(
                gateway.state.connection_ip(0x1000).await.as_deref(),
                Some(announced_ip)
            );
            session.connection_tasks.shutdown().await;
        }
    }

    /// The failed connect of an announcement that waited for another connect
    /// is reported unreachable, like the connect of a new announcement.
    // Connects to `0.0.0.0`, which does not reach the fake gateway on Windows.
    #[cfg(not(windows))]
    #[tokio::test]
    async fn failed_connect_of_a_waiting_announcement_is_reported() {
        let (fake, gateway, session, _) = blocked_gateway(DiscoveryMode::Full).await;
        fake.deny_next_connect();
        fake.deny_next_connect();

        let first = gateway
            .state
            .start_connect(&session, discovered("gw", 0x1000));
        wait_until(async || fake.connects() == 1).await;
        announce(&gateway, &session, discovered_at("gw", 0x1000, "0.0.0.0")).await;

        fake.release_connects();
        assert_eq!(first.wait().await, ConnectOutcome::Failed);
        wait_until(async || fake.connects() == 2).await;
        wait_until(async || !gateway.state.topology.unreachable().is_empty()).await;
        assert_eq!(gateway.state.topology.unreachable(), [0x1000]);
        session.connection_tasks.shutdown().await;
    }

    /// Announcements while a connect holds the gateway's lock connect once,
    /// at the newest announced address, after the lock is released.
    // Connects to `0.0.0.0`, which does not reach the fake gateway on Windows.
    #[cfg(not(windows))]
    #[tokio::test]
    async fn waiting_announcements_connect_the_newest_address() {
        let (fake, gateway, session, _) = blocked_gateway(DiscoveryMode::Full).await;
        fake.release_connects();

        let held = session.connect_lock(0x1000).lock_owned().await;
        for announced_ip in ["127.0.0.1", "0.0.0.0"] {
            announce(
                &gateway,
                &session,
                discovered_at("gw", 0x1000, announced_ip),
            )
            .await;
        }
        tokio::task::yield_now().await;
        assert_eq!(fake.connects(), 0, "the announcement waits for the lock");

        drop(held);
        wait_until(async || fake.connects() == 1).await;
        wait_until(async || !session.is_connecting(0x1000)).await;
        assert_eq!(fake.connects(), 1);
        assert_eq!(
            gateway.state.connection_ip(0x1000).await.as_deref(),
            Some("0.0.0.0")
        );
        assert!(session.announced_map().is_empty());
        session.connection_tasks.shutdown().await;
    }

    /// A discovery connect (e.g. the startup VIR result) that finds a direct
    /// connect in flight waits for it, and connects itself if it failed.
    /// [[ test~doip-discovery-connect-waits-for-direct-connect, A discovery connect waits for a failed direct connect and then connects itself, test ]]
    // Connects to `0.0.0.0`, which does not reach the fake gateway on Windows.
    #[cfg(not(windows))]
    #[tokio::test]
    async fn discovery_connect_after_a_failed_direct_connect_connects_itself() {
        let (fake, gateway, session, _) = blocked_gateway(DiscoveryMode::Full).await;
        fake.deny_next_connect();
        let direct = gateway
            .state
            .start_direct_connect(
                &session,
                discovered("gw", 0x1000),
                crate::test_helpers::connect_control(&session),
            )
            .await
            .expect("the direct connect must start");
        wait_until(async || fake.connects() == 1).await;

        let discovery = gateway
            .state
            .start_connect(&session, discovered_at("gw", 0x1000, "0.0.0.0"));
        assert_eq!(fake.connects(), 1, "the discovery connect waits");

        fake.release_connects();
        assert!(direct.await.expect("the direct connect must end").is_err());
        assert_eq!(discovery.wait().await, ConnectOutcome::Connected);
        assert_eq!(fake.connects(), 2);
        assert_eq!(
            gateway.state.connection_ip(0x1000).await.as_deref(),
            Some("0.0.0.0")
        );
        assert_eq!(gateway.state.topology.connected().len(), 1);
        session.connection_tasks.shutdown().await;
    }

    /// Cancels the session as soon as the ECUs of a gateway are reported
    /// connected, and records the disconnect reports.
    #[derive(Default)]
    struct CancelOnConnect {
        cancel: std::sync::OnceLock<tokio_util::sync::CancellationToken>,
        disconnected: std::sync::Mutex<Vec<Vec<String>>>,
    }

    #[async_trait::async_trait]
    impl cda_interfaces::EcuConnectivityHandler for CancelOnConnect {
        async fn on_gateway_connected(&self, _ecu_names: &[String]) {
            if let Some(cancel) = self.cancel.get() {
                cancel.cancel();
            }
        }

        async fn on_gateway_disconnected(&self, ecu_names: &[String]) {
            self.disconnected.lock().unwrap().push(ecu_names.to_vec());
        }

        async fn on_ecu_replied(&self, _ecu_name: &str) {}
    }

    /// A connect cut short by the stop after its ECUs were reported connected
    /// reports them disconnected again.
    /// [[ test~doip-cancelled-connect-reverts-ecu-states, A connect cut short by the stop after its ECUs were reported connected reports them disconnected, test ]]
    #[tokio::test]
    async fn connect_cancelled_after_reporting_connected_reverts_the_ecu_states() {
        let fake = FakeGateway::start().await;
        let gateway = gateway_with_gateways(&[("gw", 0x1000)]).await;
        let handler = Arc::new(CancelOnConnect::default());
        let session = session_with_handler(&fake, Arc::clone(&handler) as _);
        handler.cancel.set(session.cancel_token.clone()).unwrap();

        let connect = gateway
            .state
            .start_connect(&session, discovered("gw", 0x1000));

        assert_eq!(connect.wait().await, ConnectOutcome::Failed);
        assert_eq!(
            *handler.disconnected.lock().unwrap(),
            // The names come from the test ECU fixture.
            [vec!["test".to_owned()]]
        );
        // Reverted by the connect itself: a stop must not revert it again.
        assert!(session.take_online_reports().is_empty());
        assert!(gateway.state.topology.connected().is_empty());
        session.connection_tasks.shutdown().await;
    }
}
