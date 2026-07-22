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
pub struct CanDiagGateway {
    _unconstructable: std::convert::Infallible,
}

#[cfg(not(feature = "can"))]
impl cda_interfaces::EcuGateway for CanDiagGateway {
    async fn shutdown(&mut self) {}

    async fn get_gateway_network_address(&self, _logical_address: u16) -> Option<String> {
        None
    }

    async fn send(
        &self,
        _transmission_params: cda_interfaces::TransmissionParameters,
        _message: cda_interfaces::ServicePayload,
        _response_sender: tokio::sync::mpsc::Sender<
            Result<Option<cda_interfaces::TransportResponse>, cda_interfaces::DiagServiceError>,
        >,
        _expect_uds_reply: bool,
    ) -> Result<(), cda_interfaces::DiagServiceError> {
        Err(cda_interfaces::DiagServiceError::EcuOffline(
            "CAN support is not enabled. Compile with the `can` feature.".to_owned(),
        ))
    }

    async fn ecu_online<E: cda_interfaces::EcuAddresses>(
        &self,
        _ecu_name: &str,
        _ecu_db: &tokio::sync::RwLock<E>,
    ) -> Result<(), cda_interfaces::DiagServiceError> {
        Err(cda_interfaces::DiagServiceError::EcuOffline(
            "CAN support is not enabled. Compile with the `can` feature.".to_owned(),
        ))
    }

    async fn send_functional(
        &self,
        _transmission_params: cda_interfaces::TransmissionParameters,
        _message: cda_interfaces::ServicePayload,
        expected_ecu_logical_addrs: cda_interfaces::HashMap<u16, String>,
        _timeout: std::time::Duration,
        _expect_positive_response: bool,
    ) -> Result<
        cda_interfaces::HashMap<
            String,
            Result<cda_interfaces::ServicePayload, cda_interfaces::DiagServiceError>,
        >,
        cda_interfaces::DiagServiceError,
    > {
        Ok(expected_ecu_logical_addrs
            .into_values()
            .map(|name| {
                (
                    name,
                    Err(cda_interfaces::DiagServiceError::EcuOffline(
                        "CAN support is not enabled. Compile with the `can` feature.".to_owned(),
                    )),
                )
            })
            .collect())
    }
}

#[cfg(not(feature = "can"))]
impl cda_interfaces::EcuCanGateway for CanDiagGateway {
    async fn is_ecu_discovered_by_name(&self, _ecu_name: &str) -> bool {
        false
    }

    fn knows_ecu(&self, _ecu_name: &str) -> bool {
        false
    }

    async fn probe_ecu(&self, _ecu_name: &str) -> bool {
        false
    }
}

/// CAN routing tests for `DiagnosticTransportRouter` (lives here because the
/// test helpers - `CanDiagGateway::test_instance`, `clear_discovered`,
/// `CanId`, `CanEcuConnection` - are `pub(crate)` in this crate).
#[cfg(all(test, feature = "can"))]
mod multi_transport_routing_tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use cda_interfaces::{
        CanId, DiagServiceError, EcuAddresses, EcuGateway, HashMap, ServicePayload,
        TransmissionParameters, TransportType,
    };
    use cda_transport_orchestrator::DiagnosticTransportRouter;
    use tokio::sync::{RwLock, mpsc};

    use crate::{CanDiagGateway, gateway::connection::CanEcuConnection};

    /// `DoIP` gateway stub whose ECU knowledge can be toggled at runtime.
    #[derive(Clone, Default)]
    struct DoipStub {
        online: Arc<AtomicBool>,
        ecu_online_calls: Arc<AtomicUsize>,
    }

    impl EcuGateway for DoipStub {
        async fn get_gateway_network_address(&self, _logical_address: u16) -> Option<String> {
            self.online
                .load(Ordering::SeqCst)
                .then(|| "1.2.3.4".to_owned())
        }

        async fn send(
            &self,
            _transmission_params: TransmissionParameters,
            _message: ServicePayload,
            _response_sender: mpsc::Sender<
                Result<Option<cda_interfaces::TransportResponse>, DiagServiceError>,
            >,
            _expect_uds_reply: bool,
        ) -> Result<(), DiagServiceError> {
            Ok(())
        }

        async fn ecu_online<T: EcuAddresses>(
            &self,
            ecu_name: &str,
            _ecu_db: &RwLock<T>,
        ) -> Result<(), DiagServiceError> {
            self.ecu_online_calls.fetch_add(1, Ordering::SeqCst);
            if self.online.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(DiagServiceError::EcuOffline(ecu_name.to_owned()))
            }
        }

        async fn send_functional(
            &self,
            _transmission_params: TransmissionParameters,
            _message: ServicePayload,
            _expected_ecu_logical_addrs: HashMap<u16, String>,
            _timeout: std::time::Duration,
            _expect_positive_response: bool,
        ) -> Result<HashMap<String, Result<ServicePayload, DiagServiceError>>, DiagServiceError>
        {
            Ok(HashMap::default())
        }

        async fn shutdown(&mut self) {}
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

        let db = RwLock::new(EcuStub);
        assert!(matches!(
            gw.ecu_online("ecu1", &db).await,
            Err(DiagServiceError::EcuOffline(_))
        ));
    }
}
