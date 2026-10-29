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
//! the attempt, even if it connected. While the transport gate is closed a
//! connect is refused, which says nothing about the gateway: the caller does
//! not report it.

use std::sync::Arc;

use cda_interfaces::{
    DoipComParams, EcuAddresses, VariantDetectionRequest,
    topology::{KnownGateway, TopologyState, logical_address_hex},
};
use thiserror::Error;
use tokio::sync::oneshot;

use super::{GatewaySession, ecu_addresses_by_gateway, ecu_names_by_gateway};
use crate::{
    DiscoveredGateway, DoipGatewayState,
    connections::{ConnectControl, EcuError, GatewayState, handle_gateway_connection},
    spawn_commit_task, spawn_connection_task,
};

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
#[derive(Debug, Error)]
pub(crate) enum ConnectFailure {
    /// The session was cancelled (transport stop or restart).
    #[error("Gateway connection was cancelled")]
    Cancelled,
    /// The transport gate is closed: communication is quiesced.
    #[error("Gateway connection was refused while communication is quiesced")]
    Refused,
    /// The connection could not be established.
    #[error(transparent)]
    Error(#[from] EcuError),
    /// The connect task ended without returning a result.
    #[error("Gateway connect task ended without a result")]
    TaskEnded,
}

/// Why a direct connect was not started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DirectRejection {
    /// The gateway is connected already.
    Connected,
    /// A connect of the gateway is in flight.
    Connecting,
    /// The transport gate is closed: communication is quiesced.
    Refused,
}

/// The outcome of a connect started by [`DoipGatewayState::spawn_gateway_connect`].
pub(crate) struct PendingConnect(oneshot::Receiver<Result<(), ConnectFailure>>);

impl PendingConnect {
    /// A connect whose result is delivered through `receiver`.
    pub(crate) fn new(receiver: oneshot::Receiver<Result<(), ConnectFailure>>) -> Self {
        Self(receiver)
    }

    /// Waits for the connect. Returns [`ConnectFailure::TaskEnded`] if its task
    /// ended without a result.
    pub(crate) async fn wait(self) -> Result<(), ConnectFailure> {
        self.0.await.unwrap_or(Err(ConnectFailure::TaskEnded))
    }
}

/// Proof that the connect lock of one gateway of one session is held. Only
/// [`GatewaySession::acquire_connect_guard`] and [`GatewaySession::try_acquire_connect_guard`]
/// create it, and the lock is released when it is dropped.
pub(crate) struct GatewayConnectGuard {
    pub(super) session: Arc<GatewaySession>,
    pub(super) logical_address: u16,
    pub(super) _held: tokio::sync::OwnedMutexGuard<()>,
}

impl GatewayConnectGuard {
    /// The session whose gateway lock is held.
    pub(crate) fn session(&self) -> &Arc<GatewaySession> {
        &self.session
    }
}

impl<T: EcuAddresses + DoipComParams> DoipGatewayState<T> {
    /// Spawns a connect task for `gateway` in the session, without waiting for it.
    /// [[ dimpl~doip-discovery-connect-waits-for-direct-connect, A discovery connect waits for a direct connect in flight and connects itself if that failed, dimpl ]]
    pub(crate) fn spawn_gateway_connect(
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
                let outcome = {
                    let held = task_session
                        .acquire_connect_guard(gateway.logical_address)
                        .await;
                    state.connect_locked(&held, gateway).await
                };
                let _ = sender.send(outcome);
            },
        );
        PendingConnect::new(receiver)
    }

    /// Spawns a connect task for each gateway in `gateways`.
    ///
    /// See [`Self::spawn_gateway_connect`].
    pub(crate) fn spawn_connects_for_gateways(
        &self,
        session: &Arc<GatewaySession>,
        gateways: Vec<DiscoveredGateway>,
    ) -> Vec<(DiscoveredGateway, PendingConnect)> {
        gateways
            .into_iter()
            .map(|gateway| {
                let connect = self.spawn_gateway_connect(session, gateway.clone());
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
        let lock = session.mutex_for_gateway(logical_address);
        let _held = lock.lock().await;
        self.has_connection(logical_address).await
    }

    /// Connects `gateway` unless it is connected already. `held` is the
    /// gateway's connect lock.
    pub(crate) async fn connect_locked(
        &self,
        held: &GatewayConnectGuard,
        gateway: DiscoveredGateway,
    ) -> Result<(), ConnectFailure> {
        if !held.session().is_active() {
            return Err(ConnectFailure::Cancelled);
        }
        if self.has_connection(gateway.logical_address).await {
            return Ok(());
        }
        if !self.gate.is_open() {
            return Err(ConnectFailure::Refused);
        }
        match self
            .open_gateway(held, gateway, ConnectRequest::Discovered)
            .await
        {
            // The gate closed during the connect, e.g. while the gateway is
            // going down for the reset: nothing is known about the gateway.
            Err(ConnectFailure::Error(_)) if !self.gate.is_open() => Err(ConnectFailure::Refused),
            result => result,
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
        let gateway_ecu_name_map = ecu_names_by_gateway(&self.ecus).await;
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
        held: &GatewayConnectGuard,
        gateway: DiscoveredGateway,
        request: ConnectRequest<'_>,
    ) -> Result<(), ConnectFailure> {
        debug_assert_eq!(
            held.logical_address, gateway.logical_address,
            "the connect lock held is not the one of the gateway"
        );
        let session = held.session();
        let gateway_ecu_map = ecu_addresses_by_gateway(&self.ecus).await;
        let gateway_ecu_name_map = ecu_names_by_gateway(&self.ecus).await;
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
        // The rest runs in a task a stop does not abort, so a connect cut short
        // midway cannot leave reported ECU states behind.
        let (result_sender, result_receiver) = oneshot::channel();
        let commit = Self::commit_connected(
            Arc::clone(session),
            connected_ecu_names,
            gateway_ecu_names,
            Arc::clone(&self.topology),
            known_gateway,
            matches!(request, ConnectRequest::Discovered),
            gateway_name,
        );
        spawn_commit_task(
            &session.commit_tasks,
            &format!(
                "doip-gateway-commit-{}",
                logical_address_hex(logical_address)
            ),
            async move {
                let _ = result_sender.send(commit.await);
            },
        );
        // The sender is dropped without a result if the commit panicked.
        result_receiver
            .await
            .unwrap_or(Err(ConnectFailure::TaskEnded))
    }

    /// Reports the ECUs of a connected gateway, records it in the topology (if
    /// `is_discovered`) and requests variant detection. The only place that
    /// reverts the report if the session was cancelled meanwhile.
    async fn commit_connected(
        session: Arc<GatewaySession>,
        connected_ecu_names: Vec<String>,
        gateway_ecu_names: Vec<String>,
        topology: Arc<TopologyState>,
        known_gateway: KnownGateway,
        is_discovered: bool,
        gateway_name: String,
    ) -> Result<(), ConnectFailure> {
        // A cancelled session must not change the ECU states or the shared topology.
        if !session.is_active() {
            return Err(ConnectFailure::Cancelled);
        }
        session
            .connectivity_handler
            .on_gateway_connected(&connected_ecu_names)
            .await;
        if !session.is_active() {
            // The stop does not reset ECU states, so revert the report here.
            // [[ dimpl~doip-cancelled-connect-reverts-ecu-states, A connect that sees the stop after reporting its ECUs connected reports them disconnected again; a stop lets the commit finish and the connect reverts itself, dimpl ]]
            session
                .connectivity_handler
                .on_gateway_disconnected(&gateway_ecu_names)
                .await;
            return Err(ConnectFailure::Cancelled);
        }
        // A direct connect is ad hoc (e.g. ECU development): it is not
        // persisted, so the next start does not reconnect to its address.
        if is_discovered {
            topology.record_connected(known_gateway);
        }
        if let Err(error) = session
            .variant_detection
            .send(VariantDetectionRequest::new(gateway_ecu_names))
            .await
        {
            let kind = if is_discovered { "gateway" } else { "direct" };
            tracing::warn!(
                gateway = %gateway_name,
                error = ?error,
                "Failed to trigger variant detection after {kind} connection"
            );
        }
        Ok(())
    }

    /// Starts a direct connect (`doip-connect-ecu`) of `gateway` in a task of
    /// the session. Rejected if a connect of the gateway holds its lock, the
    /// gateway is connected, or the transport gate is closed. A connect waiting
    /// for the lock meanwhile connects itself if this one did not connect. The
    /// task goes on if the caller drops the receiver; the transport stop aborts it.
    /// [[ dimpl~doip-gate-refuses-direct-connect, No direct connect starts while the transport gate is closed, dimpl ]]
    pub(crate) async fn start_direct_connect(
        &self,
        session: &Arc<GatewaySession>,
        gateway: DiscoveredGateway,
        control: ConnectControl,
    ) -> Result<oneshot::Receiver<Result<(), ConnectFailure>>, DirectRejection> {
        let logical_address = gateway.logical_address;
        let Some(held) = session.try_acquire_connect_guard(logical_address) else {
            return Err(DirectRejection::Connecting);
        };
        if self.has_connection(logical_address).await {
            return Err(DirectRejection::Connected);
        }
        if !self.gate.is_open() {
            return Err(DirectRejection::Refused);
        }
        let (result_sender, result_receiver) = oneshot::channel();
        let state = self.clone();
        spawn_connection_task(
            &session.connection_tasks,
            &format!(
                "doip-direct-connect-{}",
                logical_address_hex(logical_address)
            ),
            async move {
                let result = state
                    .open_gateway(&held, gateway, ConnectRequest::Direct(&control))
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

    use cda_interfaces::util::test_utils::wait_until;
    use tokio::sync::oneshot;

    use super::{ConnectFailure, GatewaySession};
    use crate::{
        DiscoveredGateway, DoipDiagGateway,
        config::DiscoveryMode,
        test_helpers::{
            FakeGateway, OrderRecorder, TestEcu, discovered, discovered_at, gateway_with_gateways,
            session_with, session_with_handler,
        },
        vir_vam::handle_announcement,
    };

    #[tokio::test]
    async fn pending_connect_reports_task_ended_without_result() {
        let (sender, receiver) = oneshot::channel();
        drop(sender);

        assert!(matches!(
            super::PendingConnect(receiver).wait().await,
            Err(super::ConnectFailure::TaskEnded)
        ));
    }

    /// Whether a connect of `logical_address` holds its lock.
    fn is_connecting(session: &GatewaySession, logical_address: u16) -> bool {
        session
            .mutex_for_gateway(logical_address)
            .try_lock()
            .is_err()
    }

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
        let names = super::ecu_names_by_gateway(&gateway.state.ecus).await;
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

        wait_until(
            "announcement failure to be reported unreachable",
            || async { !gateway.state.topology.unreachable().is_empty() },
        )
        .await;
        assert_eq!(gateway.state.topology.unreachable(), [0x1000]);
        assert_eq!(fake.connects(), 1);
        session.connection_tasks.shutdown().await;
    }

    /// A closed transport gate refuses a connect before it reaches the gateway,
    /// and a connected gateway stays connected.
    /// [[ test~doip-gate-refuses-connect-while-quiesced, No gateway connects while the transport gate is closed, test ]]
    #[tokio::test]
    async fn closed_gate_refuses_a_connect() {
        let (fake, gateway, session, _) = blocked_gateway(DiscoveryMode::Full).await;
        fake.release_connects();
        gateway.state.gate.close();

        let connect = gateway
            .state
            .spawn_gateway_connect(&session, discovered("gw", 0x1000));

        assert!(matches!(connect.wait().await, Err(ConnectFailure::Refused)));
        assert_eq!(fake.connects(), 0);
        session.connection_tasks.shutdown().await;
    }

    /// [[ test~doip-gate-closed-during-connect, A connect that fails after the transport gate closed is refused, test ]]
    #[tokio::test]
    async fn connect_failing_after_the_gate_closed_reports_nothing() {
        let (fake, gateway, session, _) = blocked_gateway(DiscoveryMode::Full).await;
        let connect = gateway
            .state
            .spawn_gateway_connect(&session, discovered("gw", 0x1000));
        wait_until("the connect to reach the fake gateway", || async {
            fake.connects() == 1
        })
        .await;
        gateway.state.gate.close();
        // Ends the held routing activation without an answer, so the connect fails.
        drop(fake);

        assert!(matches!(connect.wait().await, Err(ConnectFailure::Refused)));
        assert!(gateway.state.topology.unreachable().is_empty());
        session.connection_tasks.shutdown().await;
    }

    /// An announcement refused by the closed transport gate says nothing about
    /// the gateway, which is not reported unreachable.
    /// [[ test~doip-refused-announcement-not-reported, An announcement refused by the transport gate is not reported, test ]]
    #[tokio::test]
    async fn refused_announcement_is_not_reported_unreachable() {
        let (fake, gateway, session, _) = blocked_gateway(DiscoveryMode::Full).await;
        fake.release_connects();
        gateway.state.gate.close();

        announce(&gateway, &session, discovered("gw", 0x1000)).await;

        // The announcement holds the gateway's connect lock until it is done.
        assert!(
            !gateway
                .state
                .is_connected_after_in_flight(&session, 0x1000)
                .await
        );
        assert!(gateway.state.topology.unreachable().is_empty());
        assert_eq!(fake.connects(), 0);
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
            .spawn_gateway_connect(&session, discovered("gw", 0x1000));
        wait_until("cancelled connect to reach the fake gateway", || async {
            fake.connects() == 1
        })
        .await;
        session.cancel_token.cancel();
        fake.release_connects();

        assert!(connect.wait().await.is_err());
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
                .spawn_gateway_connect(&session, discovered("gw", 0x1000));
            wait_until("reconnect to reach the fake gateway", || async {
                fake.connects() == 1
            })
            .await;
            assert!(is_connecting(&session, 0x1000));
            announce(
                &gateway,
                &session,
                discovered_at("gw", 0x1000, announced_ip),
            )
            .await;

            fake.release_connects();
            assert!(reconnect.wait().await.is_ok());
            wait_until("pending announcement to be processed", || async {
                session.lock_pending_announcements().is_empty()
            })
            .await;
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
        wait_until(
            "both announcement connects to reach the fake gateway",
            || async { fake.connects() == 2 },
        )
        .await;

        fake.release_connects();
        wait_until(
            "both announcement connects to release their locks",
            || async { !is_connecting(&session, 0x1000) && !is_connecting(&session, 0x2000) },
        )
        .await;
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
                .spawn_gateway_connect(&session, discovered("gw", 0x1000));
            wait_until("initial connect to reach the fake gateway", || async {
                fake.connects() == 1
            })
            .await;
            announce(
                &gateway,
                &session,
                discovered_at("gw", 0x1000, announced_ip),
            )
            .await;
            assert_eq!(fake.connects(), 1, "no parallel connect");

            fake.release_connects();
            assert!(matches!(first.wait().await, Err(ConnectFailure::Error(_))));
            wait_until("announcement retry to reach the fake gateway", || async {
                fake.connects() == 2
            })
            .await;
            wait_until("announcement retry to release the gateway lock", || async {
                !is_connecting(&session, 0x1000)
            })
            .await;
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
            .spawn_gateway_connect(&session, discovered("gw", 0x1000));
        wait_until("initial connect to reach the fake gateway", || async {
            fake.connects() == 1
        })
        .await;
        announce(&gateway, &session, discovered_at("gw", 0x1000, "0.0.0.0")).await;

        fake.release_connects();
        assert!(first.wait().await.is_err());
        wait_until("announcement retry to reach the fake gateway", || async {
            fake.connects() == 2
        })
        .await;
        wait_until("failed announcement to be reported unreachable", || async {
            !gateway.state.topology.unreachable().is_empty()
        })
        .await;
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

        let held = session.acquire_connect_guard(0x1000).await;
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
        wait_until("waiting announcement to reach the fake gateway", || async {
            fake.connects() == 1
        })
        .await;
        wait_until(
            "waiting announcement to release the gateway lock",
            || async { !is_connecting(&session, 0x1000) },
        )
        .await;
        assert_eq!(fake.connects(), 1);
        assert_eq!(
            gateway.state.connection_ip(0x1000).await.as_deref(),
            Some("0.0.0.0")
        );
        assert!(session.lock_pending_announcements().is_empty());
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
        wait_until("direct connect to reach the fake gateway", || async {
            fake.connects() == 1
        })
        .await;

        let discovery = gateway
            .state
            .spawn_gateway_connect(&session, discovered_at("gw", 0x1000, "0.0.0.0"));
        assert_eq!(fake.connects(), 1, "the discovery connect waits");

        fake.release_connects();
        assert!(direct.await.expect("the direct connect must end").is_err());
        assert!(discovery.wait().await.is_ok());
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

    /// Reports to a [`BlockingReport`] handler, in order.
    #[derive(Default)]
    struct BlockingReport {
        /// Notified when the connected report begins.
        started: tokio::sync::Notify,
        /// Lets the connected report return.
        release: tokio::sync::Notify,
        block: bool,
        calls: std::sync::Mutex<Vec<&'static str>>,
    }

    #[async_trait::async_trait]
    impl cda_interfaces::EcuConnectivityHandler for BlockingReport {
        async fn on_gateway_connected(&self, _ecu_names: &[String]) {
            self.calls.lock().unwrap().push("connected");
            if self.block {
                self.started.notify_one();
                self.release.notified().await;
            }
        }

        async fn on_gateway_disconnected(&self, _ecu_names: &[String]) {
            self.calls.lock().unwrap().push("disconnected");
        }

        async fn on_ecu_replied(&self, _ecu_name: &str) {}
    }

    /// A stop waits for a connect that is reporting its ECUs connected, and the
    /// connect reverts that report itself, exactly once.
    #[tokio::test]
    async fn stop_waits_for_the_report_and_the_connect_reverts_it() {
        let fake = FakeGateway::start().await;
        let gateway = gateway_with_gateways(&[("gw", 0x1000)]).await;
        let handler = Arc::new(BlockingReport {
            block: true,
            ..BlockingReport::default()
        });
        let session = session_with_handler(&fake, Arc::clone(&handler) as _);
        *gateway.state.session.write().await = Some(Arc::clone(&session));
        let connect = gateway
            .state
            .spawn_gateway_connect(&session, discovered("gw", 0x1000));
        tokio::time::timeout(Duration::from_secs(5), handler.started.notified())
            .await
            .expect("the connect must start reporting");

        let mut operation = gateway.lifecycle.operation.lock().await;
        operation.connection_tasks = Some(Arc::clone(&session.connection_tasks));
        let mut stop = Box::pin(gateway.stop(&mut operation));
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut stop)
                .await
                .is_err(),
            "the stop must wait for the report in progress"
        );
        handler.release.notify_one();
        tokio::time::timeout(Duration::from_secs(5), stop)
            .await
            .expect("the stop must finish once the report returned");

        assert_eq!(
            *handler.calls.lock().unwrap(),
            ["connected", "disconnected"]
        );
        assert!(gateway.state.topology.connected().is_empty());
        assert!(connect.wait().await.is_err());
    }

    /// A stop that aborts a connect before its report leaves the ECU states alone.
    #[tokio::test]
    async fn stop_before_the_report_reports_nothing() {
        let fake = FakeGateway::start().await;
        fake.block_connects();
        let gateway = gateway_with_gateways(&[("gw", 0x1000)]).await;
        let handler = Arc::new(BlockingReport::default());
        let session = session_with_handler(&fake, Arc::clone(&handler) as _);
        *gateway.state.session.write().await = Some(Arc::clone(&session));
        let connect = gateway
            .state
            .spawn_gateway_connect(&session, discovered("gw", 0x1000));
        wait_until("connect to reach the fake gateway", || async {
            fake.connects() == 1
        })
        .await;

        let mut operation = gateway.lifecycle.operation.lock().await;
        operation.connection_tasks = Some(Arc::clone(&session.connection_tasks));
        gateway.stop(&mut operation).await;

        assert!(handler.calls.lock().unwrap().is_empty());
        assert!(gateway.state.topology.connected().is_empty());
        assert!(connect.wait().await.is_err());
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
            .spawn_gateway_connect(&session, discovered("gw", 0x1000));

        assert!(connect.wait().await.is_err());
        assert_eq!(
            *handler.disconnected.lock().unwrap(),
            // The names come from the test ECU fixture.
            [vec!["test".to_owned()]]
        );
        assert!(gateway.state.topology.connected().is_empty());
        session.connection_tasks.shutdown().await;
    }
}
