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

// The `can` feature alone relies on Linux SocketCAN ISO-TP sockets
// (tokio-socketcan-isotp). Off Linux it is only usable together with a
// platform-independent transport: `can-socketcand`
// (`socketcand:<host>:<port>:<bus>`). Fail early with an actionable message
// instead of letting socket creation fail at runtime with a cryptic error.
#[cfg(all(
    feature = "can",
    not(target_os = "linux"),
    not(feature = "can-socketcand")
))]
compile_error!(
    "The `can` feature requires Linux (SocketCAN/ISO-TP). On other platforms enable \
     `can-socketcand` to reach a CAN bus over a socketcand daemon."
);

pub mod config;

// The CAN transport itself is compiled only with the `can` feature; the
// single gate here lets everything inside `gateway` assume the feature is
// enabled.
#[cfg(feature = "can")]
mod gateway;
#[cfg(not(feature = "can"))]
use async_trait::async_trait;
#[cfg(not(feature = "can"))]
use cda_interfaces::{
    DiagServiceError, EcuAddresses, FunctionalTransport, HashMap, NetworkTopology,
    PhysicalTransport, RouteStatus, ServicePayload, Shutdown, TransmissionParameters,
    TransportProbe, TransportResponse,
    communication_control::{TransportControl, TransportState, error::CommControlError},
};
#[cfg(feature = "can")]
pub use gateway::{CanDiagGateway, error};

/// Stub `CanDiagGateway` when the `can` feature is disabled.
///
/// This type exists only to satisfy the `Option<CanDiagGateway>` field in
/// [`DiagnosticTransportRouter`]. It has no constructor, so a value of this type
/// can never exist in a non-`can` build: the `EcuGateway` impl below is only
/// needed for type-checking and is statically unreachable.
#[cfg(not(feature = "can"))]
#[derive(Clone)]
pub enum CanDiagGateway {}

#[cfg(not(feature = "can"))]
impl PhysicalTransport for CanDiagGateway {
    async fn send(
        &self,
        _transmission_params: TransmissionParameters,
        _message: ServicePayload,
        _response_sender: tokio::sync::mpsc::Sender<
            Result<Option<TransportResponse>, DiagServiceError>,
        >,
        _expect_uds_reply: bool,
    ) -> Result<tokio::task::JoinHandle<()>, DiagServiceError> {
        Err(DiagServiceError::EcuOffline(
            "CAN support is not enabled. Compile with the `can` feature.".to_owned(),
        ))
    }

    async fn ecu_online<E: EcuAddresses>(
        &self,
        _ecu_name: &str,
        _ecu_db: &tokio::sync::RwLock<E>,
    ) -> Result<(), DiagServiceError> {
        Err(DiagServiceError::EcuOffline(
            "CAN support is not enabled. Compile with the `can` feature.".to_owned(),
        ))
    }
}

#[cfg(not(feature = "can"))]
impl NetworkTopology for CanDiagGateway {
    async fn get_gateway_network_address(&self, _logical_address: u16) -> Option<String> {
        None
    }

    async fn get_ecu_network_address(&self, _ecu_name: &str) -> Option<String> {
        None
    }
}

#[cfg(not(feature = "can"))]
impl FunctionalTransport for CanDiagGateway {
    async fn send_functional(
        &self,
        _transmission_params: TransmissionParameters,
        _message: ServicePayload,
        _expected_ecu_logical_addrs: HashMap<u16, String>,
        _timeout: std::time::Duration,
        _expect_positive_response: bool,
    ) -> Result<HashMap<String, Result<ServicePayload, DiagServiceError>>, DiagServiceError> {
        Err(DiagServiceError::RequestNotSupported(
            "CAN functional addressing is not available because CAN support is disabled."
                .to_owned(),
        ))
    }
}

#[cfg(not(feature = "can"))]
#[async_trait]
impl TransportControl for CanDiagGateway {
    async fn enable(&self) -> Result<(), CommControlError> {
        match *self {}
    }

    async fn disable(&self) -> Result<(), CommControlError> {
        match *self {}
    }

    async fn state(&self) -> TransportState {
        match *self {}
    }
}

#[cfg(not(feature = "can"))]
impl TransportProbe for CanDiagGateway {
    async fn route_status(&self, _ecu_name: &str) -> RouteStatus {
        RouteStatus::NotConfigured
    }

    async fn probe_ecu(&self, _ecu_name: &str) -> bool {
        false
    }
}

#[cfg(not(feature = "can"))]
#[async_trait]
impl Shutdown for CanDiagGateway {
    async fn shutdown(&self) {}
}

/// CAN routing tests for `DiagnosticTransportRouter` (lives here because the
/// test helpers - `CanDiagGateway::test_instance`, `clear_discovered`,
/// `CanId`, `CanEcuConnection` - are `pub(crate)` in this crate).
#[cfg(all(test, feature = "can"))]
mod transport_routing_tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use async_trait::async_trait;
    use cda_interfaces::{
        CanId, DiagServiceError, EcuAddresses, FunctionalTransport, HashMap, NetworkTopology,
        PhysicalTransport, RouteStatus, ServicePayload, Shutdown, TransmissionParameters,
        TransportProbe, TransportResponse, TransportType,
        communication_control::{TransportControl, TransportState, error::CommControlError},
    };
    use cda_transport_router::DiagnosticTransportRouter;
    use tokio::sync::{Notify, RwLock, mpsc};

    use crate::{CanDiagGateway, gateway::connection::CanEcuConnection};

    /// `DoIP` gateway stub whose ECU knowledge can be toggled at runtime.
    #[derive(Clone)]
    struct DoipStub {
        online: Arc<AtomicBool>,
        communication_active: Arc<AtomicBool>,
        ecu_online_calls: Arc<AtomicUsize>,
        enable_calls: Arc<AtomicUsize>,
        disable_calls: Arc<AtomicUsize>,
        shutdown_calls: Arc<AtomicUsize>,
        fail_enable: Arc<AtomicBool>,
        fail_disable: Arc<AtomicBool>,
        block_enable: Arc<AtomicBool>,
        enable_started: Arc<Notify>,
        release_enable: Arc<Notify>,
    }

    impl Default for DoipStub {
        fn default() -> Self {
            Self {
                online: Arc::new(AtomicBool::new(false)),
                communication_active: Arc::new(AtomicBool::new(true)),
                ecu_online_calls: Arc::new(AtomicUsize::new(0)),
                enable_calls: Arc::new(AtomicUsize::new(0)),
                disable_calls: Arc::new(AtomicUsize::new(0)),
                shutdown_calls: Arc::new(AtomicUsize::new(0)),
                fail_enable: Arc::new(AtomicBool::new(false)),
                fail_disable: Arc::new(AtomicBool::new(false)),
                block_enable: Arc::new(AtomicBool::new(false)),
                enable_started: Arc::new(Notify::new()),
                release_enable: Arc::new(Notify::new()),
            }
        }
    }

    impl PhysicalTransport for DoipStub {
        fn send(
            &self,
            _transmission_params: TransmissionParameters,
            _message: ServicePayload,
            _response_sender: mpsc::Sender<Result<Option<TransportResponse>, DiagServiceError>>,
            _expect_uds_reply: bool,
        ) -> impl Future<Output = Result<tokio::task::JoinHandle<()>, DiagServiceError>> + Send
        {
            std::future::ready(Ok(tokio::task::spawn(std::future::ready(()))))
        }

        fn ecu_online<T: EcuAddresses>(
            &self,
            ecu_name: &str,
            _ecu_db: &RwLock<T>,
        ) -> impl Future<Output = Result<(), DiagServiceError>> + Send {
            self.ecu_online_calls.fetch_add(1, Ordering::SeqCst);
            std::future::ready(if self.online.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(DiagServiceError::EcuOffline(ecu_name.to_owned()))
            })
        }
    }

    impl FunctionalTransport for DoipStub {
        fn send_functional(
            &self,
            _transmission_params: TransmissionParameters,
            _message: ServicePayload,
            _expected_ecu_logical_addrs: HashMap<u16, String>,
            _timeout: std::time::Duration,
            _expect_positive_response: bool,
        ) -> impl Future<
            Output = Result<
                HashMap<String, Result<ServicePayload, DiagServiceError>>,
                DiagServiceError,
            >,
        > + Send {
            std::future::ready(Ok(HashMap::default()))
        }
    }

    impl NetworkTopology for DoipStub {
        fn get_gateway_network_address(
            &self,
            _logical_address: u16,
        ) -> impl Future<Output = Option<String>> + Send {
            std::future::ready(
                self.online
                    .load(Ordering::SeqCst)
                    .then(|| "1.2.3.4".to_owned()),
            )
        }
    }

    impl TransportProbe for DoipStub {
        fn route_status(&self, _ecu_name: &str) -> impl Future<Output = RouteStatus> + Send {
            std::future::ready(if self.online.load(Ordering::SeqCst) {
                RouteStatus::Ready
            } else {
                RouteStatus::Unavailable
            })
        }

        fn probe_ecu(&self, _ecu_name: &str) -> impl Future<Output = bool> + Send {
            std::future::ready(false)
        }
    }

    #[async_trait]
    impl Shutdown for DoipStub {
        async fn shutdown(&self) {
            self.shutdown_calls.fetch_add(1, Ordering::SeqCst);
            self.communication_active.store(false, Ordering::Release);
        }
    }

    #[async_trait]
    impl TransportControl for DoipStub {
        async fn enable(&self) -> Result<(), CommControlError> {
            self.enable_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_enable.load(Ordering::Acquire) {
                return Err(CommControlError::InitFailed(
                    "DoIP enable failed".to_owned(),
                ));
            }
            if self.block_enable.load(Ordering::Acquire) {
                self.enable_started.notify_one();
                self.release_enable.notified().await;
            }
            self.communication_active.store(true, Ordering::Release);
            Ok(())
        }

        async fn disable(&self) -> Result<(), CommControlError> {
            self.disable_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_disable.load(Ordering::Acquire) {
                return Err(CommControlError::InitFailed(
                    "DoIP disable failed".to_owned(),
                ));
            }
            self.communication_active.store(false, Ordering::Release);
            Ok(())
        }

        async fn state(&self) -> TransportState {
            if self.communication_active.load(Ordering::Acquire) {
                TransportState::Enabled
            } else {
                TransportState::Disabled
            }
        }
    }

    struct EcuStub;

    impl EcuAddresses for EcuStub {
        fn tester_address(&self) -> u16 {
            0x0E80
        }
        fn logical_address(&self) -> u16 {
            0x1000
        }
        fn logical_gateway_address(&self) -> u16 {
            0x1000
        }
        fn logical_functional_address(&self) -> u16 {
            0xE400
        }
        fn ecu_name(&self) -> String {
            "ecu1".to_owned()
        }
        fn logical_address_eq<T: EcuAddresses>(&self, other: &T) -> bool {
            self.logical_address() == other.logical_address()
        }
    }

    fn can_gateway_with_discovered_ecu1() -> CanDiagGateway {
        CanDiagGateway::test_instance(
            vec![(
                "ecu1",
                CanEcuConnection::new(
                    "ecu1".to_owned(),
                    "test0".to_owned(),
                    CanId::try_from(0x700).expect("valid CAN ID"),
                    CanId::try_from(0x708).expect("valid CAN ID"),
                ),
            )],
            vec!["ecu1"],
        )
    }

    #[tokio::test]
    async fn pin_beats_detection() {
        // ecu1 pinned to CAN; DoIP knows it, but the pin must win and
        // the DoIP gateway must not even be consulted.
        let doip = DoipStub::default();
        doip.online.store(true, Ordering::SeqCst);
        let overrides = [("ecu1".to_owned(), TransportType::Can)]
            .into_iter()
            .collect::<HashMap<_, _>>();
        let gw = DiagnosticTransportRouter::<_, CanDiagGateway>::new(overrides)
            .with_doip(doip.clone())
            .with_can(can_gateway_with_discovered_ecu1());
        gw.enable().await.expect("enable test router");

        let db = RwLock::new(EcuStub);
        assert!(gw.ecu_online("ECU1", &db).await.is_ok());
        assert_eq!(doip.ecu_online_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn doip_preferred_at_first_detection() {
        // Both transports know ecu1: first detection must bind DoIP.
        let doip = DoipStub::default();
        doip.online.store(true, Ordering::SeqCst);
        let gw = DiagnosticTransportRouter::<_, CanDiagGateway>::new(HashMap::default())
            .with_doip(doip)
            .with_can(can_gateway_with_discovered_ecu1());
        gw.enable().await.expect("enable test router");

        let db = RwLock::new(EcuStub);
        assert!(gw.ecu_online("ecu1", &db).await.is_ok());
    }

    #[tokio::test]
    async fn can_binding_is_sticky_and_has_no_failover() {
        // DoIP is down at first detection -> ecu1 binds CAN. When DoIP
        // comes up later the binding must not change; when CAN loses the
        // ECU it is offline (no failover to DoIP).
        let doip = DoipStub::default();
        let can = can_gateway_with_discovered_ecu1();
        let gw = DiagnosticTransportRouter::<_, CanDiagGateway>::new(HashMap::default())
            .with_doip(doip.clone())
            .with_can(can.clone());
        gw.enable().await.expect("enable test router");

        let db = RwLock::new(EcuStub);
        assert!(gw.ecu_online("ecu1", &db).await.is_ok());

        // DoIP comes up: bound ECU must stay on CAN (DoIP not consulted).
        doip.online.store(true, Ordering::SeqCst);
        let calls_before = doip.ecu_online_calls.load(Ordering::SeqCst);
        assert!(gw.ecu_online("ecu1", &db).await.is_ok());
        assert_eq!(doip.ecu_online_calls.load(Ordering::SeqCst), calls_before);

        // CAN loses the ECU: offline, even though DoIP would know it.
        can.clear_discovered().await;
        assert!(matches!(
            gw.ecu_online("ecu1", &db).await,
            Err(DiagServiceError::EcuOffline(_))
        ));
    }

    fn test_send_params() -> (TransmissionParameters, ServicePayload) {
        (
            TransmissionParameters {
                gateway_address: 0x1000,
                timeout_ack: std::time::Duration::from_millis(100),
                ecu_name: "ecu1".to_owned(),
                repeat_request_count_transmission: 0,
            },
            ServicePayload {
                data: vec![0x3E, 0x00],
                source_address: 0x0E80,
                target_address: 0x1000,
                new_session: None,
                new_security: None,
            },
        )
    }

    #[tokio::test]
    async fn send_functional_prefers_doip() {
        // With a DoIP gateway present, functional requests go to DoIP
        // (the stub returns an empty result map).
        let gw = DiagnosticTransportRouter::<_, CanDiagGateway>::new(HashMap::default())
            .with_doip(DoipStub::default());
        gw.enable().await.expect("enable test router");
        let (params, payload) = test_send_params();
        let result = gw
            .send_functional(
                params,
                payload,
                HashMap::default(),
                std::time::Duration::from_millis(100),
                false,
            )
            .await;
        assert!(result.expect("DoIP stub accepts the request").is_empty());
    }

    #[tokio::test]
    async fn send_functional_over_can_is_not_supported_yet() {
        // CAN-only operation: the request must fail honestly with
        // RequestNotSupported (see #417), not pretend every ECU is
        // offline.
        let gw = DiagnosticTransportRouter::<DoipStub, CanDiagGateway>::new(HashMap::default())
            .with_can(can_gateway_with_discovered_ecu1());
        gw.enable().await.expect("enable test router");
        let (params, payload) = test_send_params();
        let result = gw
            .send_functional(
                params,
                payload,
                HashMap::default(),
                std::time::Duration::from_millis(100),
                false,
            )
            .await;
        assert!(matches!(
            result,
            Err(DiagServiceError::RequestNotSupported(_))
        ));
    }

    #[tokio::test]
    async fn send_functional_without_transports_is_offline() {
        let gw = DiagnosticTransportRouter::<DoipStub, CanDiagGateway>::new(HashMap::default());
        gw.enable().await.expect("enable test router");
        let (params, payload) = test_send_params();
        let result = gw
            .send_functional(
                params,
                payload,
                HashMap::default(),
                std::time::Duration::from_millis(100),
                false,
            )
            .await;
        assert!(matches!(result, Err(DiagServiceError::EcuOffline(_))));
    }

    #[tokio::test]
    async fn undetected_ecu_is_offline() {
        let doip = DoipStub::default();
        let gw = DiagnosticTransportRouter::<DoipStub, CanDiagGateway>::new(HashMap::default())
            .with_doip(doip);
        gw.enable().await.expect("enable test router");

        let db = RwLock::new(EcuStub);
        assert!(matches!(
            gw.ecu_online("ecu1", &db).await,
            Err(DiagServiceError::EcuOffline(_))
        ));
    }

    #[tokio::test]
    async fn router_lifecycle_fans_out_and_supports_re_enable() {
        // enable -> disable -> enable must drive the wrapped gateway and keep
        // the aggregated state consistent.
        let doip = DoipStub::default();
        let gw = DiagnosticTransportRouter::<DoipStub, CanDiagGateway>::new(HashMap::default())
            .with_doip(doip.clone());

        assert_eq!(gw.state().await, TransportState::Disabled);

        gw.enable().await.expect("enable succeeds");
        assert_eq!(gw.state().await, TransportState::Enabled);
        assert!(doip.communication_active.load(Ordering::Acquire));

        gw.disable().await.expect("disable succeeds");
        assert_eq!(gw.state().await, TransportState::Disabled);
        assert!(!doip.communication_active.load(Ordering::Acquire));

        gw.enable().await.expect("re-enable succeeds");
        assert_eq!(gw.state().await, TransportState::Enabled);
    }

    #[tokio::test]
    async fn router_rolls_back_successful_gateway_after_partial_enable_failure() {
        // DoIP fails first, CAN enables second. CAN must be disabled again so
        // its keepalive and rediscovery tasks cannot outlive the failed router.
        let doip = DoipStub::default();
        doip.fail_enable.store(true, Ordering::Release);
        let can = can_gateway_with_discovered_ecu1();
        let gw = DiagnosticTransportRouter::<_, CanDiagGateway>::new(HashMap::default())
            .with_doip(doip.clone())
            .with_can(can.clone());

        assert!(gw.enable().await.is_err());
        assert_eq!(gw.state().await, TransportState::Failed);
        assert_eq!(can.state().await, TransportState::Disabled);
        assert_eq!(doip.disable_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn router_shutdowns_gateway_when_partial_enable_rollback_fails() {
        // CAN fails after DoIP enables. A failed normal rollback must still use
        // the gateway shutdown path to terminate DoIP background work.
        let doip = DoipStub::default();
        doip.fail_disable.store(true, Ordering::Release);
        let can = CanDiagGateway::test_instance(vec![], vec![]);
        can.disable().await.expect("disable test CAN gateway");
        let gw = DiagnosticTransportRouter::<_, CanDiagGateway>::new(HashMap::default())
            .with_doip(doip.clone())
            .with_can(can);

        assert!(gw.enable().await.is_err());
        assert_eq!(gw.state().await, TransportState::Failed);
        assert_eq!(doip.disable_calls.load(Ordering::SeqCst), 1);
        assert_eq!(doip.shutdown_calls.load(Ordering::SeqCst), 1);
        assert!(!doip.communication_active.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn router_gates_datapath_while_disabled() {
        // A disabled router must reject sends even though the wrapped gateway
        // would otherwise reach the ECU.
        let doip = DoipStub::default();
        doip.online.store(true, Ordering::SeqCst);
        let gw = DiagnosticTransportRouter::<DoipStub, CanDiagGateway>::new(HashMap::default())
            .with_doip(doip);

        let (params, payload) = test_send_params();
        let (tx, _rx) = mpsc::channel(1);
        assert!(matches!(
            gw.send(params, payload, tx, true).await,
            Err(DiagServiceError::CommunicationDisabled(_))
        ));

        gw.enable().await.expect("enable succeeds");
        let (params, payload) = test_send_params();
        let (tx, _rx) = mpsc::channel(1);
        assert!(gw.send(params, payload, tx, true).await.is_ok());
    }

    #[tokio::test]
    async fn router_clones_share_lifecycle_state() {
        // Clones handed to UDS, deferred init, and update must observe the
        // same lifecycle transitions.
        let gw = DiagnosticTransportRouter::<DoipStub, CanDiagGateway>::new(HashMap::default())
            .with_doip(DoipStub::default());
        let clone = gw.clone();

        gw.enable().await.expect("enable succeeds");
        assert_eq!(clone.state().await, TransportState::Enabled);
    }

    #[tokio::test]
    async fn concurrent_router_enables_fan_out_once() {
        let doip = DoipStub::default();
        doip.block_enable.store(true, Ordering::Release);
        let gw = DiagnosticTransportRouter::<DoipStub, CanDiagGateway>::new(HashMap::default())
            .with_doip(doip.clone());
        let first = gw.clone();
        let enable_started = doip.enable_started.notified();

        let first_enable = tokio::spawn(async move { first.enable().await });
        enable_started.await;

        let second = gw.clone();
        let second_enable = tokio::spawn(async move { second.enable().await });
        tokio::task::yield_now().await;
        assert_eq!(doip.enable_calls.load(Ordering::SeqCst), 1);

        doip.release_enable.notify_one();
        first_enable
            .await
            .expect("first task joins")
            .expect("first enable succeeds");
        second_enable
            .await
            .expect("second task joins")
            .expect("second enable succeeds");

        assert_eq!(doip.enable_calls.load(Ordering::SeqCst), 1);
        assert_eq!(gw.state().await, TransportState::Enabled);
    }
}
