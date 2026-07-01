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
//! Transport selection is **config-driven**:
//! 1. If a per-ECU **transport override** is configured, that transport is used.
//! 2. Otherwise, **`DoIP` is preferred** when a `DoIP` gateway is available.
//! 3. If no `DoIP` gateway exists, **CAN** is used as fallback.
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
/// This gateway wraps both `DoIP` and CAN gateways and routes messages based on
/// ECU availability. `DoIP` is preferred when available due to its higher
/// bandwidth and lower latency.
pub struct MultiTransportGateway<D: EcuGateway> {
    /// Optional `DoIP` gateway
    doip_gateway: Option<D>,
    /// Optional CAN gateway
    can_gateway: Option<CanDiagGateway>,
    /// Per-ECU transport overrides (ECU name lowercase -> transport).
    /// ECUs not in this map use the default strategy (`DoIP` preferred, CAN fallback).
    transport_overrides: Arc<HashMap<String, TransportType>>,
}

impl<D: EcuGateway> MultiTransportGateway<D> {
    /// Creates a new multi-transport gateway with the given per-ECU transport overrides.
    #[must_use]
    pub fn new(transport_overrides: HashMap<String, TransportType>) -> Self {
        Self {
            doip_gateway: None,
            can_gateway: None,
            transport_overrides: Arc::new(transport_overrides),
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

    /// Returns whether `DoIP` transport is configured.
    #[must_use]
    pub fn has_doip(&self) -> bool {
        self.doip_gateway.is_some()
    }

    /// Returns whether CAN transport is configured.
    #[must_use]
    pub fn has_can(&self) -> bool {
        self.can_gateway.is_some()
    }

    /// Determines which transport to use for a given ECU.
    ///
    /// Routing strategy:
    /// 1. If there is an explicit config override for this ECU, use it.
    /// 2. Otherwise prefer `DoIP` when a `DoIP` gateway is configured.
    /// 3. Fall back to CAN if `DoIP` is not available.
    fn select_transport(&self, ecu_name: &str) -> Option<TransportType> {
        let ecu_name_lower = ecu_name.to_lowercase();

        // 1. Explicit per-ECU override from config
        if let Some(&overridden) = self.transport_overrides.get(&ecu_name_lower) {
            tracing::debug!(
                ecu = %ecu_name,
                transport = ?overridden,
                "Transport selected by config override"
            );
            return Some(overridden);
        }

        // 2. Default strategy: DoIP preferred, CAN fallback
        if self.doip_gateway.is_some() {
            tracing::debug!(
                ecu = %ecu_name,
                transport = "DoIP",
                "Selected DoIP transport (default)"
            );
            return Some(TransportType::DoIP);
        }

        if self.can_gateway.is_some() {
            tracing::debug!(
                ecu = %ecu_name,
                transport = "CAN",
                "Selected CAN transport (fallback)"
            );
            return Some(TransportType::Can);
        }

        tracing::debug!(
            ecu = %ecu_name,
            "No transport available for ECU"
        );
        None
    }

    /// Returns statistics about transport availability.
    pub async fn transport_stats(&self) -> TransportStats {
        let mut stats = TransportStats::default();

        if self.doip_gateway.is_some() {
            stats.doip_configured = true;
        }

        if let Some(ref can) = self.can_gateway {
            stats.can_configured = true;
            stats.can_connections = can.connection_count().await;
            stats.can_discovered = can.discovered_count().await;
        }

        stats
    }
}

/// Statistics about transport configuration and connectivity.
#[derive(Debug, Default, Clone)]
pub struct TransportStats {
    /// Whether `DoIP` transport is configured
    pub doip_configured: bool,
    /// Whether CAN transport is configured
    pub can_configured: bool,
    /// Number of CAN connections configured
    pub can_connections: usize,
    /// Number of CAN ECUs discovered
    pub can_discovered: usize,
}

impl<D: EcuGateway> EcuGateway for MultiTransportGateway<D> {
    fn shutdown(&self) {
        if let Some(ref doip) = self.doip_gateway {
            doip.shutdown();
        }
        if let Some(ref can) = self.can_gateway {
            can.shutdown();
        }
    }

    async fn get_gateway_network_address(&self, logical_address: u16) -> Option<String> {
        // Try DoIP first
        if let Some(ref doip) = self.doip_gateway
            && let Some(addr) = doip.get_gateway_network_address(logical_address).await
        {
            return Some(format!("doip://{addr}"));
        }

        // Try CAN
        if let Some(ref can) = self.can_gateway
            && let Some(addr) = can.get_gateway_network_address(logical_address).await
        {
            return Some(format!("can://{addr}"));
        }

        None
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
        let transport = self
            .select_transport(&transmission_params.ecu_name)
            .ok_or_else(|| DiagServiceError::EcuOffline(transmission_params.ecu_name.clone()))?;

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
        // Check DoIP first
        if let Some(ref doip) = self.doip_gateway
            && doip.ecu_online(ecu_name, ecu_db).await.is_ok()
        {
            return Ok(());
        }

        // Check CAN
        if let Some(ref can) = self.can_gateway
            && can.ecu_online(ecu_name, ecu_db).await.is_ok()
        {
            return Ok(());
        }

        Err(DiagServiceError::EcuOffline(ecu_name.to_owned()))
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
