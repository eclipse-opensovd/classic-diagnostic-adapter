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
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use cda_interfaces::{DoipComParams, EcuAddresses, HashMap, HashMapExtensions};

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

/// Connectivity handler that ignores all events.
pub(crate) struct NoopConnectivityHandler;

#[async_trait::async_trait]
impl cda_interfaces::EcuConnectivityHandler for NoopConnectivityHandler {
    async fn on_gateway_connected(&self, _ecu_names: &[String]) {}

    async fn on_gateway_disconnected(&self, _ecu_names: &[String]) {}
}

/// Polls `condition` until it holds, panics after five seconds.
pub(crate) async fn wait_until(mut condition: impl FnMut() -> bool) {
    for _ in 0..500 {
        if condition() {
            return;
        }
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(10)).await;
    }
    panic!("condition not reached in time");
}

/// `DoIP` gateway on the loopback interface that accepts every routing activation
/// and counts the TCP connections it receives. Routing activation responses can
/// be held back to keep a connect in flight, or left out to make it fail.
pub(crate) struct FakeGateway {
    port: u16,
    connects: Arc<AtomicUsize>,
    gate: tokio::sync::watch::Sender<bool>,
    failing: Arc<AtomicBool>,
    accept_task: tokio::task::JoinHandle<()>,
}

impl FakeGateway {
    pub(crate) async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake gateway");
        let port = listener.local_addr().expect("local address").port();
        let connects = Arc::new(AtomicUsize::new(0));
        let (gate, gate_rx) = tokio::sync::watch::channel(true);
        let failing = Arc::new(AtomicBool::new(false));
        let accept_connects = Arc::clone(&connects);
        let accept_failing = Arc::clone(&failing);
        let accept_task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                accept_connects.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(Self::serve(
                    stream,
                    gate_rx.clone(),
                    Arc::clone(&accept_failing),
                ));
            }
        });
        Self {
            port,
            connects,
            gate,
            failing,
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

    /// While set, a released routing activation is answered by closing the
    /// connection, so the connect fails.
    pub(crate) fn set_failing(&self, failing: bool) {
        self.failing.store(failing, Ordering::SeqCst);
    }

    async fn serve(
        mut stream: tokio::net::TcpStream,
        mut gate: tokio::sync::watch::Receiver<bool>,
        failing: Arc<AtomicBool>,
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
        if gate.wait_for(|open| *open).await.is_err() || failing.load(Ordering::SeqCst) {
            return;
        }
        let mut response = vec![header[0], header[1], 0x00, 0x06, 0, 0, 0, 9];
        // Tester address, entity address, "successfully activated", reserved.
        response.extend_from_slice(request.get(..2).unwrap_or(&[0, 0]));
        response.extend_from_slice(&[0x00, 0x00, 0x10, 0, 0, 0, 0]);
        if stream.write_all(&response).await.is_err() {
            return;
        }
        let mut buffer = [0u8; 256];
        while matches!(stream.read(&mut buffer).await, Ok(read) if read > 0) {}
    }
}

impl Drop for FakeGateway {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
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
