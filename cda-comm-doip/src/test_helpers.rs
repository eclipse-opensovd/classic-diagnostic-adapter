/*
 * SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 *
 * SPDX-License-Identifier: Apache-2.0
 */

use std::{
    sync::{
        Arc, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use cda_interfaces::{
    DoipComParams, EcuAddresses, EcuConnectivityHandler, HashMap, HashMapExtensions,
    VariantDetectionSender, topology::TopologyRuntime,
};
use doip_definitions::header::ProtocolVersion;
use tokio::sync::{RwLock, mpsc};
use tokio_util::sync::CancellationToken;

use crate::{
    ConnectionTasks, DiscoveredGateway, DoipConfig, DoipDiagGateway, DoipTransportConfig,
    EcuActivityReporter, config::DiscoveryMode, connections::ConnectControl,
    gateway_session::GatewaySession,
};

/// Connectivity handler that records the ECUs reported as replied.
#[derive(Default)]
pub(crate) struct RecordingConnectivityHandler {
    replied: std::sync::Mutex<Vec<String>>,
}

impl RecordingConnectivityHandler {
    /// The ECU names reported through `on_ecu_replied`, in order.
    pub(crate) fn replied(&self) -> Vec<String> {
        self.replied.lock().expect("lock replied").clone()
    }
}

#[async_trait::async_trait]
impl EcuConnectivityHandler for RecordingConnectivityHandler {
    async fn on_gateway_connected(&self, _ecu_names: &[String]) {}

    async fn on_gateway_disconnected(&self, _ecu_names: &[String]) {}

    async fn on_ecu_replied(&self, ecu_name: &str) {
        self.replied
            .lock()
            .expect("lock replied")
            .push(ecu_name.to_owned());
    }
}

/// A reply reporter that knows no ECU.
pub(crate) fn no_activity() -> EcuActivityReporter {
    activity_reporter(&Arc::new(RecordingConnectivityHandler::default()), &[])
}

/// A reply reporter for the ECUs `(logical address, name)` that records into
/// `handler`.
pub(crate) fn activity_reporter(
    handler: &Arc<RecordingConnectivityHandler>,
    ecus: &[(u16, &str)],
) -> EcuActivityReporter {
    let mut ecu_names_by_address: HashMap<u16, Vec<String>> = HashMap::new();
    for (address, name) in ecus {
        ecu_names_by_address
            .entry(*address)
            .or_default()
            .push((*name).to_owned());
    }
    let handler: Arc<dyn EcuConnectivityHandler> =
        Arc::<RecordingConnectivityHandler>::clone(handler);
    EcuActivityReporter::new(handler, ecu_names_by_address)
}

/// Lightweight ECU fixture for `DoIP` unit tests.
#[derive(Clone, Debug)]
pub(crate) struct TestEcu {
    logical_address: u16,
    gateway_address: u16,
}

impl TestEcu {
    pub(crate) const fn new(logical_address: u16, gateway_address: u16) -> Self {
        Self {
            logical_address,
            gateway_address,
        }
    }
}

impl Default for TestEcu {
    fn default() -> Self {
        Self::new(0x0E80, 0x1234)
    }
}

impl EcuAddresses for TestEcu {
    fn tester_address(&self) -> u16 {
        0x0E80
    }

    fn logical_address(&self) -> u16 {
        self.logical_address
    }

    fn logical_gateway_address(&self) -> u16 {
        self.gateway_address
    }

    fn logical_functional_address(&self) -> u16 {
        0xE400
    }

    fn ecu_name(&self) -> String {
        "test".to_owned()
    }

    fn logical_address_eq<T: EcuAddresses>(&self, other: &T) -> bool {
        self.logical_address == other.logical_address()
    }
}

impl DoipComParams for TestEcu {
    fn nack_number_of_retries(&self) -> &HashMap<u8, u32> {
        static EMPTY: OnceLock<HashMap<u8, u32>> = OnceLock::new();
        EMPTY.get_or_init(HashMap::new)
    }

    fn diagnostic_ack_timeout(&self) -> Duration {
        Duration::from_secs(2)
    }

    fn retry_period(&self) -> Duration {
        Duration::from_millis(100)
    }

    fn routing_activation_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }

    fn repeat_request_count_transmission(&self) -> u32 {
        3
    }

    fn connection_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }

    fn connection_retry_delay(&self) -> Duration {
        Duration::from_secs(1)
    }

    fn connection_retry_attempts(&self) -> u32 {
        3
    }
}

/// Polls `condition` until it holds, panics after five seconds.
pub(crate) async fn wait_until(mut condition: impl AsyncFnMut() -> bool) {
    for _ in 0..500 {
        if condition().await {
            return;
        }
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(10)).await;
    }
    panic!("condition not reached in time");
}

/// `DoIP` gateway on the loopback interface that accepts every routing activation
/// and counts the TCP connections it receives. Routing activation responses can
/// be held back to keep a connect in flight, and denied to fail a connect.
/// Connecting to `0.0.0.0` reaches it as well, as a second gateway address,
/// but not on Windows: tests connecting there are `#[cfg(not(windows))]`.
///
/// The tests need a second address that reaches the same gateway, and there
/// is no portable one. The connect uses one session-wide port and parses the
/// gateway address as an IPv4 literal, so `127.0.0.1` has a single spelling and
/// a second listener on its own port is not reachable. `127.0.0.2` is not
/// available on macOS by default. `0.0.0.0` works on Linux and macOS (it
/// connects to the local host), but Windows rejects it as a connect target.
#[cfg_attr(
    windows,
    expect(dead_code, reason = "`denials` is only read by `deny_next_connect`")
)]
pub(crate) struct FakeGateway {
    port: u16,
    connects: Arc<AtomicUsize>,
    denials: Arc<std::sync::Mutex<usize>>,
    gate: tokio::sync::watch::Sender<bool>,
    accept_task: tokio::task::JoinHandle<()>,
}

impl FakeGateway {
    pub(crate) async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake gateway");
        let port = listener.local_addr().expect("local address").port();
        let connects = Arc::new(AtomicUsize::new(0));
        let denials = Arc::new(std::sync::Mutex::new(0));
        let (gate, gate_rx) = tokio::sync::watch::channel(true);
        let accept_connects = Arc::clone(&connects);
        let accept_denials = Arc::clone(&denials);
        let accept_task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                accept_connects.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(Self::serve(
                    stream,
                    gate_rx.clone(),
                    Arc::clone(&accept_denials),
                ));
            }
        });
        Self {
            port,
            connects,
            denials,
            gate,
            accept_task,
        }
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    /// Number of TCP connections received so far.
    pub(crate) fn connects(&self) -> usize {
        self.connects.load(Ordering::SeqCst)
    }

    /// Holds back routing activation responses until `release_connects`.
    pub(crate) fn block_connects(&self) {
        self.gate.send_replace(false);
    }

    pub(crate) fn release_connects(&self) {
        self.gate.send_replace(true);
    }

    async fn serve(
        mut stream: tokio::net::TcpStream,
        mut gate: tokio::sync::watch::Receiver<bool>,
        denials: Arc<std::sync::Mutex<usize>>,
    ) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let mut header = [0u8; 8];
        if stream.read_exact(&mut header).await.is_err() {
            return;
        }
        let length = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
        let mut request = vec![0u8; usize::try_from(length).unwrap_or_default()];
        if stream.read_exact(&mut request).await.is_err() {
            return;
        }
        if gate.wait_for(|open| *open).await.is_err() {
            return;
        }
        let denied = {
            let mut denials = denials.lock().unwrap();
            let denied = *denials > 0;
            *denials = denials.saturating_sub(1);
            denied
        };
        let mut response = vec![header[0], header[1], 0x00, 0x06, 0, 0, 0, 9];
        // Tester address, entity address, "successfully activated" (or "denied,
        // unknown source address"), reserved.
        response.extend_from_slice(request.get(..2).unwrap_or(&[0, 0]));
        let code = if denied { 0x00 } else { 0x10 };
        response.extend_from_slice(&[0x00, 0x00, code, 0, 0, 0, 0]);
        if stream.write_all(&response).await.is_err() {
            return;
        }
        let mut buffer = [0u8; 256];
        while matches!(stream.read(&mut buffer).await, Ok(read) if read > 0) {}
    }
}

// Only tests connecting to `0.0.0.0` deny connects, see the type doc.
#[cfg(not(windows))]
impl FakeGateway {
    /// Denies the next routing activation it answers, so that connect fails.
    pub(crate) fn deny_next_connect(&self) {
        let mut denials = self.denials.lock().unwrap();
        *denials = denials.saturating_add(1);
    }
}

impl Drop for FakeGateway {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

pub(crate) fn discovered(name: &str, logical_address: u16) -> DiscoveredGateway {
    discovered_at(name, logical_address, "127.0.0.1")
}

/// A gateway announced at `ip`; `127.0.0.1` and `0.0.0.0` both reach a
/// [`FakeGateway`].
pub(crate) fn discovered_at(name: &str, logical_address: u16, ip: &str) -> DiscoveredGateway {
    DiscoveredGateway {
        ip: ip.to_owned(),
        ecu_name: name.to_owned(),
        logical_address,
        doip_protocol_version: ProtocolVersion::Iso13400_2012,
    }
}

pub(crate) async fn gateway_with_gateways(gateways: &[(&str, u16)]) -> DoipDiagGateway<TestEcu> {
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
        Arc::new(RecordingConnectivityHandler::default()),
    )
    .await
    .unwrap()
}

/// A session as a transport start creates it, connecting to `fake`.
pub(crate) fn session_for(fake: &FakeGateway) -> Arc<GatewaySession> {
    session_with_handler(fake, Arc::new(RecordingConnectivityHandler::default()))
}

pub(crate) fn session_with_handler(
    fake: &FakeGateway,
    handler: Arc<dyn EcuConnectivityHandler>,
) -> Arc<GatewaySession> {
    session_with(fake, handler, DiscoveryMode::Full)
}

pub(crate) fn session_with_discovery(
    fake: &FakeGateway,
    discovery: DiscoveryMode,
) -> Arc<GatewaySession> {
    session_with(
        fake,
        Arc::new(RecordingConnectivityHandler::default()),
        discovery,
    )
}

pub(crate) fn session_with(
    fake: &FakeGateway,
    handler: Arc<dyn EcuConnectivityHandler>,
    discovery: DiscoveryMode,
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
        discovery,
    ))
}

/// Notes whether the gateway was already recorded as unreachable when its
/// ECUs were reported disconnected.
pub(crate) struct OrderRecorder {
    topology: Arc<TopologyRuntime>,
    pub(crate) unreachable_at_disconnect: std::sync::Mutex<Vec<bool>>,
}

impl OrderRecorder {
    pub(crate) fn new(topology: &Arc<TopologyRuntime>) -> Arc<Self> {
        Arc::new(Self {
            topology: Arc::clone(topology),
            unreachable_at_disconnect: std::sync::Mutex::new(Vec::new()),
        })
    }
}

/// The control of a direct connect on `session`.
pub(crate) fn connect_control(session: &GatewaySession) -> ConnectControl {
    ConnectControl {
        cancel: session.cancel_token.clone(),
        headroom: Duration::from_secs(5),
    }
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

    async fn on_ecu_replied(&self, _ecu_name: &str) {}
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use cda_interfaces::{DoipComParams, EcuAddresses};

    use super::TestEcu;

    #[test]
    fn test_ecu_has_concrete_address_and_doip_comparam_values() {
        let ecu = TestEcu::new(0x110A, 0x110A);
        let other = TestEcu::new(0x110A, 0x1163);

        assert_eq!(ecu.tester_address(), 0x0E80);
        assert_eq!(ecu.logical_address(), 0x110A);
        assert_eq!(ecu.logical_gateway_address(), 0x110A);
        assert_eq!(ecu.logical_functional_address(), 0xE400);
        assert_eq!(ecu.ecu_name(), "test");
        assert!(ecu.logical_address_eq(&other));
        assert!(ecu.nack_number_of_retries().is_empty());
        assert_eq!(ecu.diagnostic_ack_timeout(), Duration::from_secs(2));
        assert_eq!(ecu.retry_period(), Duration::from_millis(100));
        assert_eq!(ecu.routing_activation_timeout(), Duration::from_secs(5));
        assert_eq!(ecu.repeat_request_count_transmission(), 3);
        assert_eq!(ecu.connection_timeout(), Duration::from_secs(5));
        assert_eq!(ecu.connection_retry_delay(), Duration::from_secs(1));
        assert_eq!(ecu.connection_retry_attempts(), 3);
    }
}
