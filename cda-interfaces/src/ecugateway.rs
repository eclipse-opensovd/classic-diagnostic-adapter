/*
 * SPDX-FileCopyrightText: 2025 Copyright (c) Contributors to the Eclipse Foundation
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

use std::time::Duration;

use tokio::sync::{RwLock, mpsc};

use crate::{DiagServiceError, EcuAddresses, HashMap, ServicePayload, uds::TransportResponse};

/// Parameters for sending a UDS message over the network.
#[derive(Debug, Clone)]
pub struct TransmissionParameters {
    pub gateway_address: u16,
    pub timeout_ack: Duration,
    pub ecu_name: String,
    pub repeat_request_count_transmission: u32,
}

/// Physical diagnostic send - the core transport capability.
/// Every transport (`DoIP`, CAN) implements this.
pub trait PhysicalTransport: Clone + Send + Sync + 'static {
    /// Send a UDS request and stream classified responses back.
    /// The transport handles framing, retries, ACKs, pending-NRC classification,
    /// and any transport-specific keep-open/deadline side effects internally.
    /// When `expect_uds_reply` is false, emit `Ok(None)` after transport-level
    /// confirmation (`DoIP` ACK / CAN write success) and close.
    fn send(
        &self,
        transmission_params: TransmissionParameters,
        message: ServicePayload,
        response_sender: mpsc::Sender<Result<Option<TransportResponse>, DiagServiceError>>,
        expect_uds_reply: bool,
    ) -> impl Future<Output = Result<(), DiagServiceError>> + Send;

    /// Checks if an ECU is currently reachable on this transport.
    fn ecu_online<T: EcuAddresses>(
        &self,
        ecu_name: &str,
        ecu_db: &RwLock<T>,
    ) -> impl Future<Output = Result<(), DiagServiceError>> + Send;

    /// Graceful shutdown: abort background tasks, close sockets.
    // #425 is introducing a separate shutdown trait, once this is merged
    // will implement that trait instead.
    fn shutdown(&mut self) -> impl Future<Output = ()> + Send;
}

/// Functional diagnostic send (optional capability).
/// `DoIP` implements this; CAN returns `RequestNotSupported`.
pub trait FunctionalTransport: PhysicalTransport {
    /// Send a functional request to a gateway using functional addressing.
    /// The gateway will broadcast the request to all ECUs behind it.
    /// This method waits for responses from multiple ECUs within the specified timeout.
    ///
    /// # Arguments
    /// * `transmission_params` - Parameters for transmission including gateway address
    /// * `message` - The UDS message to send
    /// * `expected_ecu_logical_addrs` - Map of ECU logical addresses to their names
    ///   that are expected to respond
    /// * `timeout` - Maximum time to wait for responses
    /// * `expect_positive_response` - When `false`, the outgoing message has
    ///   `suppressPosRspMsgIndicationBit` set and ECUs are not expected to send a
    ///   positive response.  ECUs that give no response at all are **omitted** from the result
    ///   map instead of being recorded as `DiagServiceError::Timeout`.
    ///   Negative responses are still captured regardless of this flag.
    ///
    /// # Returns
    /// A map of ECU names to their responses (or timeout errors for non-responding ECUs when
    /// `expect_positive_response` is `true`)
    ///
    /// # Errors
    /// * `DiagServiceError::EcuOffline` if the gateway cannot be reached
    /// * Individual ECU errors are returned in the result map
    fn send_functional(
        &self,
        transmission_params: TransmissionParameters,
        message: ServicePayload,
        expected_ecu_logical_addrs: HashMap<u16, String>,
        timeout: Duration,
        expect_positive_response: bool,
    ) -> impl Future<
        Output = Result<
            HashMap<String, Result<ServicePayload, DiagServiceError>>,
            DiagServiceError,
        >,
    > + Send;
}

/// Network topology queries.
pub trait NetworkTopology: Send + Sync {
    /// Retrieves the network address of the gateway for a given logical address.
    /// For DOIP, this is the IP address of the gateway.
    /// This function is used to build the network structure of the ECUs.
    /// Returns `None` if the logical address cannot be resolved to a network address.
    fn get_gateway_network_address(
        &self,
        logical_address: u16,
    ) -> impl Future<Output = Option<String>> + Send;

    /// Network address of a specific ECU, looked up by name.
    ///
    /// Fallback for ECUs whose logical addresses are unresolved com-param
    /// defaults (CAN-only databases all share the fallback `0x0000`, so the
    /// address-based [`Self::get_gateway_network_address`] cannot identify
    /// them). Transports whose addressing is genuinely logical-address-based
    /// (`DoIP`) keep the default `None`.
    fn get_ecu_network_address(
        &self,
        _ecu_name: &str,
    ) -> impl Future<Output = Option<String>> + Send {
        std::future::ready(None)
    }
}

/// Core gateway supertrait: physical send + topology queries.
/// `FunctionalTransport` (functional addressing) is intentionally excluded - not
/// all transports support it (CAN does not). Callers that need functional send
/// must additionally bound on `FunctionalTransport` explicitly.
pub trait EcuGateway: PhysicalTransport + NetworkTopology {}
impl<T> EcuGateway for T where T: PhysicalTransport + NetworkTopology {}

/// Transport-neutral routing knowledge for one ECU description.
///
/// This reports whether the transport can currently be selected. It does not
/// replace `EcuState`, `Connectivity`, or `VariantState`.
pub trait TransportProbe: Send + Sync {
    /// Return this transport's current routing status for the ECU.
    fn route_status(&self, ecu_name: &str) -> impl Future<Output = RouteStatus> + Send;

    /// Resolve `ProbeRequired` by actively probing the ECU.
    /// Transports which cannot actively probe return false and should report
    /// `Unavailable`, not `ProbeRequired`, from `route_status()`.
    fn probe(&self, ecu_name: &str) -> impl Future<Output = bool> + Send;
}

/// The current routing readiness status for an ECU on a specific transport.
///
/// `RouteReadiness` is deliberately not an ECU state and must never be exposed
/// through SOVD or written into `EcuRuntimeState` directly:
///
/// - `Connectivity::{Online, Offline}` records whether the physical ECU responded to communication.
/// - `VariantState::{NotTested, Detected, Duplicate, NotDetected}` records diagnostic-database
///   identity/variant resolution.
/// - `RouteReadiness` answers only: **may the router select this transport now, or should it
///   perform an on-demand transport probe first?**
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteStatus {
    /// This transport has no resolved endpoint/addressing for the ECU and is
    /// not a route candidate.
    NotConfigured,
    /// This transport has a confirmed usable route to the ECU.
    Ready,
    /// The transport has an endpoint for the ECU and supports a bounded active
    /// probe which must succeed before the router binds to it.
    ProbeRequired,
    /// The transport has an endpoint for the ECU, but it is currently not a
    /// usable route and cannot be made usable by an on-demand probe.
    Unavailable,
}
