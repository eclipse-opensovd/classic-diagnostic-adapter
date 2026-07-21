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

//! Multi-transport gateway that can route UDS messages over `DoIP` or CAN.
//!
//! This module provides `MultiTransportGateway` which implements the `EcuGateway`
//! trait and can route messages to ECUs over multiple transports (`DoIP` and/or CAN).
//!
//! # Routing Strategy
//!
//! 1. An explicit per-ECU **transport override** from the config is a hard
//!    pin: the ECU always uses that transport.
//! 2. Without a pin, the ECU is bound to the transport it is **first
//!    detected** on. `DoIP` is preferred when both transports know the ECU at
//!    that moment; a CAN-mapped ECU that never appeared over `DoIP` is probed
//!    on demand.
//! 3. The binding is **sticky**: `ecu_online` and all subsequent sends use
//!    the bound transport. There is no automatic failover - if the bound
//!    transport loses the ECU it is reported offline until that same
//!    transport detects it again.
//!
//! # Usage
//!
//! ```ignore
//! use cda_interfaces::HashMap;
//! let overrides = HashMap::default(); // or populate from config
//! let gateway = MultiTransportGateway::new(overrides)
//!     .with_doip(doip_gateway)
//!     .with_can(can_gateway);
//! ```

use std::sync::Arc;

use cda_interfaces::{
    DiagServiceError, EcuAddresses, EcuGateway, HashMap, ServicePayload, TransmissionParameters,
    UdsResponse,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, mpsc};

use crate::CanDiagGateway;

/// Identifies which transport is being used for an ECU.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum TransportType {
    /// Diagnostics over IP (Ethernet)
    #[serde(alias = "DoIP", alias = "DOIP")]
    DoIP,
    /// CAN bus with ISO-TP
    #[serde(alias = "CAN", alias = "Can")]
    Can,
}

/// A gateway that can route diagnostic messages over multiple transports.
///
/// This gateway wraps both `DoIP` and CAN gateways. Each ECU is either pinned
/// to a transport via config override or bound to the transport it was first
/// detected on (`DoIP` preferred); see the module docs for the full strategy.
pub struct MultiTransportGateway<D: EcuGateway> {
    /// Optional `DoIP` gateway
    doip_gateway: Option<D>,
    /// Optional CAN gateway
    can_gateway: Option<CanDiagGateway>,
    /// Per-ECU transport overrides (ECU name lowercase -> transport).
    /// ECUs not in this map are bound at first detection.
    transport_overrides: Arc<HashMap<String, TransportType>>,
    /// Transport each un-pinned ECU was first detected on (lowercase name ->
    /// transport). Entries are written once and never change at runtime, so
    /// a diagnostic session can never silently switch transports.
    ecu_bindings: Arc<RwLock<HashMap<String, TransportType>>>,
}

impl<D: EcuGateway> MultiTransportGateway<D> {
    /// Creates a new multi-transport gateway with the given per-ECU transport overrides.
    #[must_use]
    pub fn new(transport_overrides: HashMap<String, TransportType>) -> Self {
        Self {
            doip_gateway: None,
            can_gateway: None,
            transport_overrides: Arc::new(transport_overrides),
            ecu_bindings: Arc::new(RwLock::new(HashMap::default())),
        }
    }

    /// Adds a `DoIP` gateway to this multi-transport gateway.
    #[must_use]
    pub fn with_doip(mut self, gateway: D) -> Self {
        self.doip_gateway = Some(gateway);
        self
    }

    /// Adds a CAN gateway to this multi-transport gateway.
    #[must_use]
    pub fn with_can(mut self, gateway: CanDiagGateway) -> Self {
        self.can_gateway = Some(gateway);
        self
    }

    /// Returns the wrapped `DoIP` gateway, if one is configured.
    ///
    /// Used by the runtime-update reload path to hand the existing `DoIP` UDP
    /// socket over to the replacement gateway (avoiding a second socket bound
    /// to the same `DoIP` port). `None` in CAN-only operation.
    #[must_use]
    pub fn doip(&self) -> Option<&D> {
        self.doip_gateway.as_ref()
    }

    /// Returns the transport this ECU is pinned or already bound to, if any.
    async fn pinned_or_bound(&self, ecu_name: &str) -> Option<TransportType> {
        if let Some(&pinned) = self.transport_overrides.get(ecu_name) {
            return Some(pinned);
        }
        self.ecu_bindings.read().await.get(ecu_name).copied()
    }

    /// Binds the ECU to a transport, sticky: if another task bound it first,
    /// the earlier binding wins and is returned.
    async fn bind(&self, ecu_name: &str, transport: TransportType) -> TransportType {
        let bound = *self
            .ecu_bindings
            .write()
            .await
            .entry(ecu_name.to_owned())
            .or_insert(transport);
        tracing::debug!(
            ecu = %ecu_name,
            transport = ?bound,
            "ECU bound to transport (first detection)"
        );
        bound
    }

    /// The CAN gateway's network address for the ECU, behind the `can://`
    /// scheme (see `get_ecu_network_address`).
    async fn can_ecu_network_address(&self, ecu_name: &str) -> Option<String> {
        match self.can_gateway {
            Some(ref can) => can
                .get_ecu_network_address(ecu_name)
                .await
                .map(|addr| format!("can://{addr}")),
            None => None,
        }
    }

    /// Attempts to detect the ECU on the CAN bus: already discovered, or
    /// mapped and answering an on-demand probe. A CAN-mapped ECU that was
    /// offline during startup discovery is detected here on first use.
    #[cfg_attr(
        not(feature = "can"),
        allow(
            clippy::unused_async,
            unused_variables,
            reason = "in a non-can build the body is a constant `false` (the stub gateway cannot \
                      exist), but the signature must stay async for the can build"
        )
    )]
    async fn detect_on_can(&self, ecu_name: &str) -> bool {
        #[cfg(feature = "can")]
        {
            let Some(ref can) = self.can_gateway else {
                return false;
            };
            if can.is_ecu_discovered_by_name(ecu_name).await {
                return true;
            }
            if can.knows_ecu(ecu_name) {
                return can.probe_ecu(ecu_name).await;
            }
            false
        }
        #[cfg(not(feature = "can"))]
        {
            // The stub CanDiagGateway cannot be constructed, so a CAN
            // detection can never succeed in a non-can build.
            false
        }
    }
}

impl<D: EcuGateway> EcuGateway for MultiTransportGateway<D> {
    async fn shutdown(&mut self) {
        if let Some(ref mut doip) = self.doip_gateway {
            doip.shutdown().await;
        }
        if let Some(ref mut can) = self.can_gateway {
            can.shutdown().await;
        }
    }

    async fn get_gateway_network_address(&self, logical_address: u16) -> Option<String> {
        // DoIP addresses are returned verbatim (bare IP) to keep the SOVD
        // network-structure API compatible with pre-multi-transport releases.
        if let Some(ref doip) = self.doip_gateway
            && let Some(addr) = doip.get_gateway_network_address(logical_address).await
        {
            return Some(addr);
        }

        if let Some(ref can) = self.can_gateway
            && let Some(addr) = can.get_gateway_network_address(logical_address).await
        {
            return Some(format!("can://{addr}"));
        }

        None
    }

    async fn get_ecu_network_address(&self, ecu_name: &str) -> Option<String> {
        // Answer for the transport the ECU is pinned or bound to, so the
        // reported address always agrees with where send() routes (an ECU
        // can be known to both transports, e.g. a CAN mapping alongside its
        // DoIP identity). Same scheme convention as the address-based
        // lookup: DoIP addresses verbatim (the default impl yields None
        // today), CAN addresses behind a can:// scheme.
        let ecu_name = ecu_name.to_lowercase();
        match self.pinned_or_bound(&ecu_name).await {
            Some(TransportType::DoIP) => match self.doip_gateway {
                Some(ref doip) => doip.get_ecu_network_address(&ecu_name).await,
                None => None,
            },
            Some(TransportType::Can) => self.can_ecu_network_address(&ecu_name).await,
            None => {
                if let Some(ref doip) = self.doip_gateway
                    && let Some(addr) = doip.get_ecu_network_address(&ecu_name).await
                {
                    return Some(addr);
                }
                self.can_ecu_network_address(&ecu_name).await
            }
        }
    }

    #[tracing::instrument(skip_all, fields(
        ecu = %transmission_params.ecu_name,
        gateway_addr = transmission_params.gateway_address
    ))]
    async fn send(
        &self,
        transmission_params: TransmissionParameters,
        message: ServicePayload,
        response_sender: mpsc::Sender<Result<Option<UdsResponse>, DiagServiceError>>,
        expect_uds_reply: bool,
    ) -> Result<(), DiagServiceError> {
        let ecu_name = transmission_params.ecu_name.to_lowercase();

        let transport = if let Some(t) = self.pinned_or_bound(&ecu_name).await {
            t
        } else {
            // First detection binds the ECU; DoIP is preferred when it
            // already knows the ECU (an established gateway connection
            // serves its logical address).
            let doip_knows = if let Some(ref doip) = self.doip_gateway {
                doip.get_gateway_network_address(transmission_params.gateway_address)
                    .await
                    .is_some()
            } else {
                false
            };
            if doip_knows {
                self.bind(&ecu_name, TransportType::DoIP).await
            } else if self.detect_on_can(&ecu_name).await {
                self.bind(&ecu_name, TransportType::Can).await
            } else {
                return Err(DiagServiceError::EcuOffline(
                    transmission_params.ecu_name.clone(),
                ));
            }
        };

        match transport {
            TransportType::DoIP => {
                let doip = self.doip_gateway.as_ref().ok_or_else(|| {
                    DiagServiceError::EcuOffline(transmission_params.ecu_name.clone())
                })?;
                tracing::debug!(transport = "DoIP", "Routing message via DoIP");
                doip.send(
                    transmission_params,
                    message,
                    response_sender,
                    expect_uds_reply,
                )
                .await
            }
            TransportType::Can => {
                let can = self.can_gateway.as_ref().ok_or_else(|| {
                    DiagServiceError::EcuOffline(transmission_params.ecu_name.clone())
                })?;
                tracing::debug!(transport = "CAN", "Routing message via CAN");
                can.send(
                    transmission_params,
                    message,
                    response_sender,
                    expect_uds_reply,
                )
                .await
            }
        }
    }

    async fn ecu_online<E: EcuAddresses>(
        &self,
        ecu_name: &str,
        ecu_db: &RwLock<E>,
    ) -> Result<(), DiagServiceError> {
        let ecu_name = ecu_name.to_lowercase();

        match self.pinned_or_bound(&ecu_name).await {
            // Pinned or bound: online means online on THAT transport, so the
            // answer always agrees with where send() routes. No failover.
            Some(TransportType::DoIP) => match self.doip_gateway {
                Some(ref doip) => doip.ecu_online(&ecu_name, ecu_db).await,
                None => Err(DiagServiceError::EcuOffline(ecu_name.clone())),
            },
            Some(TransportType::Can) => match self.can_gateway {
                Some(ref can) => can.ecu_online(&ecu_name, ecu_db).await,
                None => Err(DiagServiceError::EcuOffline(ecu_name.clone())),
            },
            None => {
                // Not seen yet: first successful detection binds the ECU,
                // DoIP preferred.
                if let Some(ref doip) = self.doip_gateway
                    && doip.ecu_online(&ecu_name, ecu_db).await.is_ok()
                {
                    self.bind(&ecu_name, TransportType::DoIP).await;
                    return Ok(());
                }
                if self.detect_on_can(&ecu_name).await {
                    self.bind(&ecu_name, TransportType::Can).await;
                    return Ok(());
                }
                Err(DiagServiceError::EcuOffline(ecu_name.clone()))
            }
        }
    }

    async fn send_functional(
        &self,
        transmission_params: cda_interfaces::TransmissionParameters,
        message: cda_interfaces::ServicePayload,
        expected_ecu_logical_addrs: cda_interfaces::HashMap<u16, String>,
        timeout: std::time::Duration,
        expect_positive_response: bool,
    ) -> Result<
        cda_interfaces::HashMap<String, Result<cda_interfaces::UdsResponse, DiagServiceError>>,
        DiagServiceError,
    > {
        if let Some(ref doip) = self.doip_gateway {
            return doip
                .send_functional(
                    transmission_params,
                    message,
                    expected_ecu_logical_addrs,
                    timeout,
                    expect_positive_response,
                )
                .await;
        }
        if let Some(ref can) = self.can_gateway {
            return can
                .send_functional(
                    transmission_params,
                    message,
                    expected_ecu_logical_addrs,
                    timeout,
                    expect_positive_response,
                )
                .await;
        }
        Err(DiagServiceError::EcuOffline(
            "no transport configured for functional request".to_owned(),
        ))
    }
}

impl<D: EcuGateway> Clone for MultiTransportGateway<D> {
    fn clone(&self) -> Self {
        Self {
            doip_gateway: self.doip_gateway.clone(),
            can_gateway: self.can_gateway.clone(),
            transport_overrides: Arc::clone(&self.transport_overrides),
            ecu_bindings: Arc::clone(&self.ecu_bindings),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_type_debug() {
        assert_eq!(format!("{:?}", TransportType::DoIP), "DoIP");
        assert_eq!(format!("{:?}", TransportType::Can), "Can");
    }

    #[cfg(feature = "can")]
    mod routing {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        };

        use cda_interfaces::{CanId, DiagServiceError, EcuAddresses};
        use tokio::sync::RwLock;

        use super::super::*;
        use crate::gateway::connection::CanEcuConnection;

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
                _response_sender: mpsc::Sender<Result<Option<UdsResponse>, DiagServiceError>>,
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
            ) -> Result<HashMap<String, Result<UdsResponse, DiagServiceError>>, DiagServiceError>
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
            let gw = MultiTransportGateway::new(overrides)
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
            let gw = MultiTransportGateway::new(HashMap::default())
                .with_doip(doip)
                .with_can(can_gateway_with_discovered_ecu1());

            let db = RwLock::new(EcuStub);
            assert!(gw.ecu_online("ecu1", &db).await.is_ok());
            assert_eq!(
                gw.ecu_bindings.read().await.get("ecu1").copied(),
                Some(TransportType::DoIP)
            );
        }

        #[tokio::test]
        async fn can_binding_is_sticky_and_has_no_failover() {
            // DoIP is down at first detection -> ecu1 binds CAN. When DoIP
            // comes up later the binding must not change; when CAN loses the
            // ECU it is offline (no failover to DoIP).
            let doip = DoipStub::default();
            let can = can_gateway_with_discovered_ecu1();
            let gw = MultiTransportGateway::new(HashMap::default())
                .with_doip(doip.clone())
                .with_can(can.clone());

            let db = RwLock::new(EcuStub);
            assert!(gw.ecu_online("ecu1", &db).await.is_ok());
            assert_eq!(
                gw.ecu_bindings.read().await.get("ecu1").copied(),
                Some(TransportType::Can)
            );

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
            let gw = MultiTransportGateway::new(HashMap::default())
                .with_doip(DoipStub::default())
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
            assert!(result.expect("DoIP stub accepts the request").is_empty());
        }

        #[tokio::test]
        async fn send_functional_over_can_is_not_supported_yet() {
            // CAN-only operation: the request must fail honestly with
            // RequestNotSupported (see #417), not pretend every ECU is
            // offline.
            let gw = MultiTransportGateway::<DoipStub>::new(HashMap::default())
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
            let gw = MultiTransportGateway::<DoipStub>::new(HashMap::default());
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
            let gw = MultiTransportGateway::new(HashMap::default()).with_doip(doip);

            let db = RwLock::new(EcuStub);
            assert!(matches!(
                gw.ecu_online("ecu1", &db).await,
                Err(DiagServiceError::EcuOffline(_))
            ));
            assert!(gw.ecu_bindings.read().await.is_empty());
        }
    }
}
