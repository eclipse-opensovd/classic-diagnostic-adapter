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

//! Gateways that wait for their first use: registered by a lazy start,
//! connected on their first request, and refreshed by their announcements
//! meanwhile.

use std::sync::Arc;

use async_trait::async_trait;
use cda_interfaces::{
    DoipComParams, EcuAddresses, HashMap, HashMapExtensions, HashSet,
    topology::{PendingGateways, logical_address_hex},
    util::std_ext::lock_mutex,
};
use tokio::sync::oneshot;

use super::{GatewayConnectGuard, GatewaySession};
use crate::{
    DiscoveredGateway, DoipDiagGateway, DoipGatewayState, reconnect, spawn_connection_task,
};

impl GatewaySession {
    /// Whether `logical_address` is a gateway waiting for its first use.
    pub(crate) fn is_pending(&self, logical_address: u16) -> bool {
        lock_mutex(&self.pending).contains_key(&logical_address)
    }

    /// Whether `logical_address` is pending and its first use can attempt a
    /// connect: it has an address, or the discovery mode allows a search.
    fn is_pending_attemptable(&self, logical_address: u16) -> bool {
        match lock_mutex(&self.pending).get(&logical_address) {
            Some(Some(_)) => true,
            Some(None) => self.discovery.sends_vir(),
            None => false,
        }
    }

    /// The usable address of a pending gateway, if it has one.
    fn pending_gateway(&self, logical_address: u16) -> Option<DiscoveredGateway> {
        lock_mutex(&self.pending)
            .get(&logical_address)
            .cloned()
            .flatten()
    }

    /// Updates the address of a pending gateway from an announcement. Returns
    /// `true` if the gateway is pending.
    pub(crate) fn update_pending(&self, gateway: &DiscoveredGateway) -> bool {
        match lock_mutex(&self.pending).get_mut(&gateway.logical_address) {
            Some(entry) => {
                *entry = Some(gateway.clone());
                true
            }
            None => false,
        }
    }

    /// Ends the pending state of a gateway whose connect ended.
    pub(crate) fn end_pending(&self, logical_address: u16) {
        lock_mutex(&self.pending).remove(&logical_address);
    }

    /// Registers the persisted gateways of `plan` as pending instead of
    /// connecting them.
    pub(crate) fn register_lazy(&self, plan: reconnect::ReconnectPlan) {
        let mut pending: HashMap<u16, Option<DiscoveredGateway>> = HashMap::new();
        for gateway in plan.unicast {
            pending.insert(gateway.logical_address, Some(gateway));
        }
        for logical_address in plan.vir_for {
            pending.entry(logical_address).or_insert(None);
        }
        tracing::info!(
            gateways = pending.len(),
            "Lazy start: each persisted gateway connects on its first request"
        );
        *lock_mutex(&self.pending) = pending;
        *lock_mutex(&self.pending_unusable) = plan.unusable;
    }

    /// The pending gateways persisted without a usable address that are still
    /// pending without one. Their pending state ends.
    fn take_unusable_pending(&self) -> Vec<u16> {
        let unusable = std::mem::take(&mut *lock_mutex(&self.pending_unusable));
        let mut pending = lock_mutex(&self.pending);
        let mut taken = Vec::new();
        for logical_address in unusable {
            if matches!(pending.get(&logical_address), Some(None)) {
                pending.remove(&logical_address);
                taken.push(logical_address);
            }
        }
        taken
    }

    /// Whether any gateway waits for its first use.
    fn has_pending(&self) -> bool {
        !lock_mutex(&self.pending).is_empty()
    }

    fn pending_addresses(&self) -> Vec<u16> {
        lock_mutex(&self.pending).keys().copied().collect()
    }

    /// Makes `logical_address` pending with `address`.
    #[cfg(test)]
    pub(crate) fn set_pending(&self, logical_address: u16, address: Option<DiscoveredGateway>) {
        lock_mutex(&self.pending).insert(logical_address, address);
    }
}

impl<T: EcuAddresses + DoipComParams> DoipGatewayState<T> {
    /// Whether `logical_address` is a gateway of the current transport start
    /// waiting for its first use.
    pub(crate) async fn gateway_pending(&self, logical_address: u16) -> bool {
        self.current_session()
            .await
            .is_some_and(|session| session.is_pending(logical_address))
    }

    /// Whether a request to an ECU behind `logical_address` is routed as
    /// pending: the gateway is pending and its first use can attempt a connect.
    /// A pending gateway without an address while no VIR is allowed waits for
    /// its announcement instead.
    pub(crate) async fn gateway_pending_attemptable(&self, logical_address: u16) -> bool {
        self.current_session()
            .await
            .is_some_and(|session| session.is_pending_attemptable(logical_address))
    }
}

impl<T: EcuAddresses + DoipComParams> DoipDiagGateway<T> {
    /// Connects a pending gateway on its first use. Concurrent callers for the
    /// same gateway wait for one connect, and a caller that is dropped does not
    /// abort it. Returns `true` if the gateway is connected.
    /// [[ dimpl~doip-lazy-gateway-connect, Connect a persisted gateway on its first request, dimpl ]]
    /// [[ dimpl~doip-gateway-connect-once, One coordinated connect per gateway, dimpl ]]
    pub(crate) async fn connect_pending(&self, logical_address: u16) -> bool {
        if self.state.has_connection(logical_address).await {
            return true;
        }
        let Some(session) = self.state.current_session().await else {
            return false;
        };
        if !session.is_pending(logical_address) {
            // A concurrent first connect may have completed since the check
            // above and ended the pending state: use its connection.
            return self.state.has_connection(logical_address).await;
        }
        tracing::info!(
            logical_address = %logical_address_hex(logical_address),
            "Connecting persisted gateway on first request"
        );
        let (sender, receiver) = oneshot::channel();
        let state = self.state.clone();
        let task_session = Arc::clone(&session);
        spawn_connection_task(
            &session.connection_tasks,
            &format!(
                "doip-first-use-connect-{}",
                logical_address_hex(logical_address)
            ),
            async move {
                let held = task_session.acquire_connect_guard(logical_address).await;
                let connected = Self::first_use_locked(&state, &held).await;
                drop(held);
                // The caller may have given up meanwhile.
                let _ = sender.send(connected);
            },
        );
        // No result if the transport stop aborted the task.
        receiver.await.unwrap_or(false)
    }

    /// Connects the pending gateway of `held` at its pending address, read here
    /// so it includes announcements that arrived while waiting for the lock. A
    /// gateway it cannot reach is searched by a VIR for this gateway alone, and
    /// reported unreachable if that fails as well. Without VIR a gateway
    /// without an address is not attempted: it is not reported and stays pending
    /// until its announcement gives it an address.
    async fn first_use_locked(state: &DoipGatewayState<T>, held: &GatewayConnectGuard) -> bool {
        let session = held.session();
        let logical_address = held.logical_address;
        if !session.is_active() {
            return false;
        }
        if state.has_connection(logical_address).await {
            session.end_pending(logical_address);
            return true;
        }
        // Not pending anymore: the first use of a concurrent caller failed.
        if !session.is_pending(logical_address) {
            return false;
        }
        let address = session.pending_gateway(logical_address);
        let searches = session.discovery.sends_vir();
        if address.is_none() && !searches {
            return false;
        }
        let mut connected = false;
        if let Some(gateway) = address {
            connected = state.connect_locked(held, gateway).await.is_ok();
        }
        if !connected && searches {
            let wanted = std::iter::once(logical_address).collect();
            let found = Self::search_gateways(state, session, &wanted).await;
            for gateway in found {
                connected = state.connect_locked(held, gateway).await.is_ok();
            }
        }
        session.end_pending(logical_address);
        if !connected {
            state.report_unreachable(session, [logical_address]).await;
        }
        connected
    }
}

/// [[ dimpl~doip-lazy-activate-all, Explicit activation connects all pending gateways, dimpl ]]
#[async_trait]
impl<T: EcuAddresses + DoipComParams> PendingGateways for DoipDiagGateway<T> {
    async fn has_pending(&self) -> bool {
        self.state
            .current_session()
            .await
            .is_some_and(|session| session.has_pending())
    }

    async fn connect_all_pending(&self) {
        let Some(session) = self.state.current_session().await else {
            return;
        };
        let addresses = session.pending_addresses();
        if addresses.is_empty() {
            return;
        }
        tracing::info!(
            gateways = addresses.len(),
            "Explicit activation connects all pending gateways"
        );
        // `connect_pending` stops on a cancelled session (stop or restart) and
        // coordinates with concurrent requests per gateway.
        futures::future::join_all(
            addresses
                .into_iter()
                .map(|logical_address| self.connect_pending(logical_address)),
        )
        .await;
        // Without VIR the persisted gateways without a usable address are not
        // attempted. Like a start without lazy start, they are reported
        // unreachable, unless an announcement connected them meanwhile.
        if !session.discovery.sends_vir() {
            let mut unreachable = HashSet::default();
            for logical_address in session.take_unusable_pending() {
                if !self
                    .state
                    .is_connected_after_in_flight(&session, logical_address)
                    .await
                {
                    unreachable.insert(logical_address);
                }
            }
            self.state.report_unreachable(&session, unreachable).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use cda_interfaces::util::test_utils::wait_until;

    #[cfg(not(windows))]
    use crate::test_helpers::discovered_at;
    use crate::{
        DoipGatewayOperation,
        config::DiscoveryMode,
        test_helpers::{
            FakeGateway, OrderRecorder, connect_control, discovered, gateway_with_gateways,
            session_for, session_with_discovery, session_with_handler,
        },
    };

    /// A gateway connected directly no longer waits for its first use; a
    /// failed direct connect leaves it pending at its persisted address.
    /// [[ test~doip-direct-connect-ends-pending, A successful direct connect ends the pending state of the gateway, test ]]
    #[tokio::test]
    async fn direct_connect_ends_pending_only_when_connected() {
        let fake = FakeGateway::start().await;
        let gateway = gateway_with_gateways(&[("gw", 0x1000)]).await;
        let session = session_for(&fake);
        session.set_pending(0x1000, Some(discovered("gw", 0x1000)));
        let direct = |ip: &str| {
            let mut target = discovered("gw", 0x1000);
            target.ip = ip.to_owned();
            let control = connect_control(&session);
            gateway
                .state
                .start_direct_connect(&session, target, control)
        };

        // TEST-NET-1 (RFC 5737) is never reachable.
        let failed = direct("192.0.2.1").await.unwrap().await.unwrap();
        assert!(failed.is_err());
        assert!(session.is_pending(0x1000), "a failure keeps it pending");

        let connected = direct("127.0.0.1").await.unwrap().await.unwrap();
        assert!(connected.is_ok(), "{connected:?}");
        assert!(!session.is_pending(0x1000));
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
        old.set_pending(0x1000, Some(discovered("gw", 0x1000)));
        *gateway.state.session.write().await = Some(Arc::clone(&old));
        let mut operation = DoipGatewayOperation::default();
        operation.cancel = Some(old.cancel_token.clone());
        operation.connection_tasks = Some(Arc::clone(&old.connection_tasks));

        let caller = {
            let gateway = gateway.clone();
            tokio::spawn(async move { gateway.connect_pending(0x1000).await })
        };
        wait_until("connect to reach the fake gateway", || async {
            fake.connects() == 1
        })
        .await;

        // Stop, then a new lazy start with the same pending gateway.
        gateway.stop(&mut operation).await;
        let new = session_for(&fake);
        new.set_pending(0x1000, Some(discovered("gw", 0x1000)));
        *gateway.state.session.write().await = Some(Arc::clone(&new));
        fake.release_connects();

        assert!(!caller.await.unwrap(), "the stale connect is abandoned");
        assert!(
            new.is_pending(0x1000),
            "the new session's pending entry is untouched"
        );
        assert!(gateway.state.current_session().await.is_some());
    }

    /// Connects every pending gateway at once. Unreachable gateways go through the
    /// broadcast fallback and their ECUs are reported disconnected. Nothing is
    /// pending afterwards, so a second call does no work.
    /// [[ test~doip-lazy-activate-all, Explicit activation connects all pending gateways, test ]]
    #[tokio::test]
    async fn connect_all_pending_connects_every_pending_gateway() {
        use cda_interfaces::topology::PendingGateways as _;

        let gateway = gateway_with_gateways(&[("gw1", 0x1000), ("gw2", 0x2000)]).await;
        assert!(!gateway.has_pending().await, "no session, nothing pending");
        gateway.connect_all_pending().await;

        let recorder = OrderRecorder::new(&gateway.state.topology);
        let fake = FakeGateway::start().await;
        let session = session_with_handler(&fake, Arc::clone(&recorder) as _);
        *gateway.state.session.write().await = Some(Arc::clone(&session));
        assert!(!gateway.has_pending().await);
        session.set_pending(0x1000, None);
        session.set_pending(0x2000, None);
        assert!(gateway.has_pending().await);

        gateway.connect_all_pending().await;

        assert!(
            !gateway.has_pending().await,
            "every pending gateway was tried"
        );
        // `TestEcu` reports the same name for every ECU, so count the reports.
        assert_eq!(
            recorder.unreachable_at_disconnect.lock().unwrap().len(),
            2,
            "the unreachable gateways' ECUs are reported disconnected"
        );
        let mut unreachable = gateway.state.topology.unreachable();
        unreachable.sort_unstable();
        assert_eq!(
            unreachable,
            [0x1000, 0x2000],
            "both are recorded as unreachable"
        );
    }

    /// Without VIR, a pending gateway without an address is not routed as
    /// pending, so a request to its ECU queues no detection; it stays pending
    /// for its announcement. With an address, or with VIR, it is routed as
    /// pending.
    #[tokio::test]
    async fn pending_gateway_without_address_and_vir_is_not_routed_as_pending() {
        use cda_interfaces::NetworkTopology as _;

        let fake = FakeGateway::start().await;
        let gateway = gateway_with_gateways(&[("gw", 0x1000)]).await;
        for (discovery, address, routed) in [
            (DiscoveryMode::VamOnly, None, false),
            (DiscoveryMode::VamOnly, Some(discovered("gw", 0x1000)), true),
            (DiscoveryMode::Full, None, true),
        ] {
            let session = session_with_discovery(&fake, discovery);
            session.set_pending(0x1000, address);
            *gateway.state.session.write().await = Some(Arc::clone(&session));

            assert_eq!(gateway.route_pending("gw").await, routed, "{discovery:?}");
            assert!(session.is_pending(0x1000), "it stays pending");
        }
    }

    /// Without VIR, the explicit activation after a lazy start reports the
    /// gateways persisted without a usable address unreachable and ends their
    /// pending state, like a start without lazy start. A gateway that is not
    /// persisted stays pending for its announcement.
    #[tokio::test]
    async fn vam_only_activation_reports_gateways_persisted_without_address() {
        use cda_interfaces::topology::PendingGateways as _;

        let fake = FakeGateway::start().await;
        let gateway = gateway_with_gateways(&[("gw2", 0x2000), ("gw3", 0x3000)]).await;
        let session = session_with_discovery(&fake, DiscoveryMode::VamOnly);
        *gateway.state.session.write().await = Some(Arc::clone(&session));
        // 0x2000 is persisted without a usable address, 0x3000 not persisted.
        session.register_lazy(crate::reconnect::ReconnectPlan {
            unicast: Vec::new(),
            vir_for: [0x2000, 0x3000].into_iter().collect(),
            unusable: std::iter::once(0x2000).collect(),
        });

        gateway.connect_all_pending().await;

        assert_eq!(gateway.state.topology.unreachable(), [0x2000]);
        assert!(!session.is_pending(0x2000));
        assert!(session.is_pending(0x3000));
        assert_eq!(
            fake.connects(),
            0,
            "nothing is attempted without an address"
        );
    }

    /// An announcement during a direct connect of a pending gateway is not
    /// lost to its first use: whichever of the first use (at the stale pending
    /// address) and the announcement's task connects first after the direct
    /// connect failed, the announced address is tried and connects.
    // Connects to `0.0.0.0`, which does not reach the fake gateway on Windows.
    #[cfg(not(windows))]
    #[tokio::test]
    async fn vam_during_a_direct_connect_is_kept_for_the_first_use() {
        let fake = FakeGateway::start().await;
        fake.block_connects();
        fake.deny_next_connect();
        let gateway = gateway_with_gateways(&[("gw", 0x1000)]).await;
        let session = session_with_discovery(&fake, DiscoveryMode::VamOnly);
        *gateway.state.session.write().await = Some(Arc::clone(&session));
        // Not an IP address: a connect to it fails at once.
        session.set_pending(0x1000, Some(discovered_at("gw", 0x1000, "stale")));
        let direct = gateway
            .state
            .start_direct_connect(
                &session,
                discovered("gw", 0x1000),
                connect_control(&session),
            )
            .await
            .expect("the direct connect must start");
        wait_until("connect to reach the fake gateway", || async {
            fake.connects() == 1
        })
        .await;
        let names = crate::gateway_session::ecu_names_by_gateway(&gateway.state.ecus).await;
        crate::vir_vam::handle_announcement(
            &gateway.state,
            &session,
            discovered_at("gw", 0x1000, "0.0.0.0"),
            &names,
            &gateway.variant_detection,
        )
        .await;
        let first_use = {
            let gateway = gateway.clone();
            tokio::spawn(async move { gateway.connect_pending(0x1000).await })
        };
        // Time for the first use to find the direct connect and wait for it.
        cda_interfaces::util::tokio_ext::sleep_for(std::time::Duration::from_millis(50)).await;
        assert_eq!(fake.connects(), 1, "both wait for the direct connect");
        fake.release_connects();

        assert!(direct.await.expect("the direct connect must end").is_err());
        first_use.await.unwrap();
        wait_until("gateway to connect at the announced address", || async {
            gateway.state.has_connection(0x1000).await
        })
        .await;
        assert_eq!(
            gateway.state.connection_ip(0x1000).await.as_deref(),
            Some("0.0.0.0")
        );
        assert!(!session.is_pending(0x1000));
        session.connection_tasks.shutdown().await;
    }

    /// The first-use connect of a pending gateway that finds a direct connect in
    /// flight waits for it, and connects the pending address if it failed.
    // Connects to `0.0.0.0`, which does not reach the fake gateway on Windows.
    #[cfg(not(windows))]
    #[tokio::test]
    async fn first_use_connect_after_a_failed_direct_connect_connects_itself() {
        let fake = FakeGateway::start().await;
        fake.block_connects();
        fake.deny_next_connect();
        let gateway = gateway_with_gateways(&[("gw", 0x1000)]).await;
        let session = session_for(&fake);
        *gateway.state.session.write().await = Some(Arc::clone(&session));
        session.set_pending(0x1000, Some(discovered_at("gw", 0x1000, "0.0.0.0")));
        let direct = gateway
            .state
            .start_direct_connect(
                &session,
                discovered("gw", 0x1000),
                connect_control(&session),
            )
            .await
            .expect("the direct connect must start");
        wait_until("connect to reach the fake gateway", || async {
            fake.connects() == 1
        })
        .await;

        let first_use = {
            let gateway = gateway.clone();
            tokio::spawn(async move { gateway.connect_pending(0x1000).await })
        };
        // Time for the first use to find the direct connect and wait for it.
        cda_interfaces::util::tokio_ext::sleep_for(std::time::Duration::from_millis(50)).await;
        assert_eq!(fake.connects(), 1, "the first use waits");
        fake.release_connects();

        assert!(direct.await.expect("the direct connect must end").is_err());
        assert!(first_use.await.unwrap(), "the first use connects itself");
        assert_eq!(fake.connects(), 2);
        assert_eq!(
            gateway.state.connection_ip(0x1000).await.as_deref(),
            Some("0.0.0.0")
        );
        assert!(!session.is_pending(0x1000));
        session.connection_tasks.shutdown().await;
    }

    /// A request that loses the race to a concurrent first connect of the same
    /// gateway uses that connection: the gateway is no longer pending when the
    /// request looks it up, but it is connected.
    // On a current-thread runtime the spawned caller runs until it blocks on
    // the session slot before the test goes on, which the test relies on.
    #[tokio::test(flavor = "current_thread")]
    async fn connect_pending_uses_a_concurrent_first_connect() {
        let fake = FakeGateway::start().await;
        let gateway = gateway_with_gateways(&[("gw", 0x1000)]).await;
        let session = session_for(&fake);
        // Holding the session slot stops the request after its connection
        // check, before it looks up the pending gateway.
        let slot = gateway.state.session.write().await;
        let caller = {
            let gateway = gateway.clone();
            tokio::spawn(async move { gateway.connect_pending(0x1000).await })
        };
        tokio::task::yield_now().await;
        assert!(!caller.is_finished());

        // The concurrent connect completed: connected and no longer pending.
        gateway
            .state
            .logical_address_to_connection
            .write()
            .await
            .insert(0x1000, 0);
        let mut slot = slot;
        *slot = Some(session);
        drop(slot);

        assert!(
            caller.await.unwrap(),
            "the request uses the concurrent connect"
        );
    }
}
