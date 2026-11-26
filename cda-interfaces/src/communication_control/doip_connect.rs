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

//! Capability to connect an ECU's `DoIP` entity directly to an IP address.

use std::net::IpAddr;

use async_trait::async_trait;

use crate::DiagServiceError;

/// Where to reach the `DoIP` entity of an ECU, instead of discovering it via VIR/VAM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DoipEndpoint {
    /// IP address of the `DoIP` entity.
    pub address: IpAddr,
    /// Raw `DoIP` protocol version byte, e.g. `0x02` for ISO 13400-2:2012.
    pub protocol_version: u8,
}

/// Connect-only view of the diagnostic transport.
///
/// Like [`CommunicationAccess`](super::CommunicationAccess), this is deliberately
/// narrow: holders (the SOVD layer) can request a direct connection but receive
/// none of the lifecycle control of
/// [`TransportControl`](super::TransportControl).
#[async_trait]
pub trait DoipConnect: Send + Sync + 'static {
    /// Connects the given ECU directly to `endpoint`.
    ///
    /// Everything after the connection is established (routing activation, TLS
    /// upgrade, ECU identification) is identical to a discovered gateway.
    ///
    /// # Errors
    /// * `DiagServiceError::RequestNotSupported` if the ECU's transport is not `DoIP`.
    /// * `DiagServiceError::NotFound` if the ECU is unknown.
    /// * `DiagServiceError::Conflict` if the ECU is already connected.
    /// * `DiagServiceError::CommunicationDisabled` if the transport is not enabled.
    async fn connect_ecu(
        &self,
        ecu_name: &str,
        endpoint: DoipEndpoint,
    ) -> Result<(), DiagServiceError>;
}
