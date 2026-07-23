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

//! Diagnostic transport router that can route UDS messages over `DoIP` or CAN.
//!
//! This module provides `DiagnosticTransportRouter` which implements the `EcuGateway`
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
//! let gateway = DiagnosticTransportRouter::new(overrides)
//!     .with_doip(doip_gateway)
//!     .with_can(can_gateway);
//! ```

use std::sync::Arc;

pub use cda_interfaces::TransportType;
use cda_interfaces::{
    DiagServiceError, EcuAddresses, EcuGateway, FunctionalTransport, HashMap, NetworkTopology,
    PhysicalTransport, RouteStatus, ServicePayload, TransmissionParameters, TransportProbe,
    TransportResponse,
};
use tokio::sync::{RwLock, mpsc};

/// A router that can route diagnostic messages over multiple transports.
///
/// This router wraps both `DoIP` and CAN gateways. Each ECU is either pinned
/// to a transport via config override or bound to the transport it was first
/// detected on (`DoIP` preferred); see the module docs for the full strategy.
#[doc(alias = "MultiTransportGateway")]
pub struct DiagnosticTransportRouter<
    D: EcuGateway + FunctionalTransport + TransportProbe,
    C: EcuGateway + TransportProbe,
> {
    /// Optional `DoIP` gateway
    doip_gateway: Option<D>,
    /// Optional CAN gateway
    can_gateway: Option<C>,
    /// Per-ECU transport overrides (ECU name lowercase -> transport).
    /// ECUs not in this map are bound at first detection.
    transport_overrides: Arc<HashMap<String, TransportType>>,
    /// Transport each un-pinned ECU was first detected on (lowercase name ->
    /// transport). Entries are written once and never change at runtime, so
    /// a diagnostic session can never silently switch transports.
    ecu_bindings: Arc<RwLock<HashMap<String, TransportType>>>,
}

/// Deprecated type alias for backwards compatibility.
///
/// Use `DiagnosticTransportRouter` instead.
#[deprecated(since = "0.1.0", note = "Use DiagnosticTransportRouter instead")]
pub type MultiTransportGateway<D, C> = DiagnosticTransportRouter<D, C>;

impl<D: EcuGateway + FunctionalTransport + TransportProbe, C: EcuGateway + TransportProbe>
    DiagnosticTransportRouter<D, C>
{
    /// Creates a new diagnostic transport router with the given per-ECU transport overrides.
    #[must_use]
    pub fn new(transport_overrides: HashMap<String, TransportType>) -> Self {
        Self {
            doip_gateway: None,
            can_gateway: None,
            transport_overrides: Arc::new(transport_overrides),
            ecu_bindings: Arc::new(RwLock::new(HashMap::default())),
        }
    }

    /// Adds a `DoIP` gateway to this diagnostic transport router.
    #[must_use]
    pub fn with_doip(mut self, gateway: D) -> Self {
        self.doip_gateway = Some(gateway);
        self
    }

    /// Adds a CAN gateway to this diagnostic transport router.
    #[must_use]
    pub fn with_can(mut self, gateway: C) -> Self {
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

    /// Returns the network address for an ECU given its bound transport type.
    async fn network_address_for_transport(
        &self,
        ecu_name: &str,
        transport: TransportType,
    ) -> Option<String> {
        match transport {
            TransportType::DoIP => match self.doip_gateway {
                Some(ref doip) => doip.get_ecu_network_address(ecu_name).await,
                None => None,
            },
            TransportType::Can => self.can_ecu_network_address(ecu_name).await,
        }
    }

    /// Tries to detect and bind an ECU on a single transport.
    async fn try_bind_transport(
        &self,
        ecu_name: &str,
        gateway: &(impl EcuGateway + TransportProbe),
        transport: TransportType,
    ) -> Option<TransportType> {
        match gateway.route_status(ecu_name).await {
            RouteStatus::Ready => Some(self.bind(ecu_name, transport).await),
            RouteStatus::ProbeRequired => {
                if gateway.probe(ecu_name).await {
                    Some(self.bind(ecu_name, transport).await)
                } else {
                    None
                }
            }
            RouteStatus::NotConfigured | RouteStatus::Unavailable => None,
        }
    }

    /// Resolves the transport for an ECU using the unified detection logic.
    ///
    /// 1. Check for explicit override
    /// 2. Check for existing binding
    /// 3. First-detection: check transports in priority order (`DoIP` first, then CAN)
    ///    - Ready: bind and return
    ///    - `ProbeRequired`: probe, then bind and return if successful
    ///    - NotConfigured/Unavailable: continue to next transport
    async fn resolve_transport(&self, ecu_name: &str) -> Result<TransportType, DiagServiceError> {
        let ecu_name_lower = ecu_name.to_lowercase();

        // 1. Check override
        if let Some(&pinned) = self.transport_overrides.get(&ecu_name_lower) {
            return Ok(pinned);
        }

        // 2. Check existing binding
        if let Some(&bound) = self.ecu_bindings.read().await.get(&ecu_name_lower) {
            return Ok(bound);
        }

        // 3. First-detection: check transports in priority order (DoIP first)
        if let Some(ref doip) = self.doip_gateway
            && let Some(transport) = self
                .try_bind_transport(&ecu_name_lower, doip, TransportType::DoIP)
                .await
        {
            return Ok(transport);
        }

        if let Some(ref can) = self.can_gateway
            && let Some(transport) = self
                .try_bind_transport(&ecu_name_lower, can, TransportType::Can)
                .await
        {
            return Ok(transport);
        }

        Err(DiagServiceError::EcuOffline(ecu_name.to_owned()))
    }
}

impl<D: EcuGateway + FunctionalTransport + TransportProbe, C: EcuGateway + TransportProbe>
    PhysicalTransport for DiagnosticTransportRouter<D, C>
{
    #[tracing::instrument(skip_all, fields(
        ecu = %transmission_params.ecu_name,
        gateway_addr = transmission_params.gateway_address
    ))]
    async fn send(
        &self,
        transmission_params: TransmissionParameters,
        message: ServicePayload,
        response_sender: mpsc::Sender<Result<Option<TransportResponse>, DiagServiceError>>,
        expect_uds_reply: bool,
    ) -> Result<(), DiagServiceError> {
        let ecu_name = transmission_params.ecu_name.to_lowercase();
        let transport = self.resolve_transport(&ecu_name).await?;

        match transport {
            TransportType::DoIP => {
                let doip = self.doip_gateway.as_ref().ok_or_else(|| {
                    DiagServiceError::EcuOffline(transmission_params.ecu_name.clone())
                })?;
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
        // resolve_transport handles: overrides -> existing bindings -> first detection
        let transport = self.resolve_transport(ecu_name).await?;

        // Online check on the resolved transport only (no failover)
        match transport {
            TransportType::DoIP => match self.doip_gateway {
                Some(ref doip) => doip.ecu_online(ecu_name, ecu_db).await,
                None => Err(DiagServiceError::EcuOffline(ecu_name.to_owned())),
            },
            TransportType::Can => match self.can_gateway {
                Some(ref can) => can.ecu_online(ecu_name, ecu_db).await,
                None => Err(DiagServiceError::EcuOffline(ecu_name.to_owned())),
            },
        }
    }

    async fn shutdown(&mut self) {
        if let Some(ref mut doip) = self.doip_gateway {
            doip.shutdown().await;
        }
        if let Some(ref mut can) = self.can_gateway {
            can.shutdown().await;
        }
    }
}

impl<D: EcuGateway + FunctionalTransport + TransportProbe, C: EcuGateway + TransportProbe>
    FunctionalTransport for DiagnosticTransportRouter<D, C>
{
    async fn send_functional(
        &self,
        transmission_params: TransmissionParameters,
        message: ServicePayload,
        expected_ecu_logical_addrs: HashMap<u16, String>,
        timeout: std::time::Duration,
        expect_positive_response: bool,
    ) -> Result<HashMap<String, Result<ServicePayload, DiagServiceError>>, DiagServiceError> {
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

        if self.can_gateway.is_some() {
            Err(DiagServiceError::RequestNotSupported(
                "CAN transport does not support functional communication".to_owned(),
            ))
        } else {
            Err(DiagServiceError::EcuOffline(
                "No transport configured for functional request".to_owned(),
            ))
        }
    }
}

impl<D: EcuGateway + FunctionalTransport + TransportProbe, C: EcuGateway + TransportProbe>
    NetworkTopology for DiagnosticTransportRouter<D, C>
{
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

        // Check override or existing binding first
        if let Some(&pinned) = self.transport_overrides.get(&ecu_name) {
            return self.network_address_for_transport(&ecu_name, pinned).await;
        }

        if let Some(&bound) = self.ecu_bindings.read().await.get(&ecu_name) {
            return self.network_address_for_transport(&ecu_name, bound).await;
        }

        // No binding yet - try DoIP first, then CAN
        if let Some(ref doip) = self.doip_gateway
            && let Some(addr) = doip.get_ecu_network_address(&ecu_name).await
        {
            return Some(addr);
        }
        self.can_ecu_network_address(&ecu_name).await
    }
}

impl<D: EcuGateway + FunctionalTransport + TransportProbe, C: EcuGateway + TransportProbe> Clone
    for DiagnosticTransportRouter<D, C>
{
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
}
