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

use crate::{DiagServiceError, EcuAddresses, HashMap, ServicePayload};

/// Pending-lifecycle NRC variants that signal the transport must keep its
/// connection/socket open for a follow-up response.
///
/// The transport layer classifies raw bytes into these variants via
/// [`crate::pending_nrc_from_raw`] and performs its own side effects
/// (deadline extension, socket keep-alive) before forwarding to the UDS layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingNrc {
    /// NRC 0x78 -- ECU needs more time, final response will follow.
    ResponsePending { source_address: u16 },
    /// NRC 0x21 -- ECU busy, client should retransmit.
    BusyRepeatRequest { source_address: u16 },
    /// NRC 0x94 -- Resource temporarily unavailable, retransmit.
    TemporarilyNotAvailable { source_address: u16 },
}

/// Response already classified by the transport, with transport-level
/// side effects (deadline extension, socket keep-alive) already applied.
///
/// The transport guarantees:
/// - For [`TransportResponse::Pending`]: the underlying connection/socket
///   remains open and any transport-specific timers have been extended.
/// - For [`TransportResponse::UdsResponse`]: the exchange is complete from the
///   transport's perspective. The payload is the raw UDS response bytes
///   (positive or negative response).
#[derive(Debug, Clone)]
pub enum TransportResponse {
    /// A pending-lifecycle NRC. The transport has already extended its own
    /// deadline / kept its socket open. The UDS layer decides retry policy.
    Pending(PendingNrc),
    /// A terminal response. The payload contains the raw UDS response bytes --
    /// either a positive response or a negative response with an NRC other
    /// than the three pending-lifecycle codes.
    UdsResponse(ServicePayload),
}

/// Parameters for sending a UDS message over the network.
#[derive(Debug, Clone)]
pub struct TransmissionParameters {
    pub gateway_address: u16,
    pub timeout_ack: Duration,
    pub ecu_name: String,
    pub repeat_request_count_transmission: u32,
}

/// The gateway is the communication layer between the ECUs and the CDA.
/// It handles physical transmission of messages, protocol specifics (like ACKs and NACKs for DOIP),
/// and provides information about the ECUs on the network, like their online state.
pub trait EcuGateway: Clone + Send + Sync + 'static {
    /// Retrieves the network address of the gateway for a given logical address.
    /// For DOIP, this is the IP address of the gateway.
    /// This function is used to build the network structure of the ECUs.
    /// Returns `None` if the logical address cannot be resolved to a network address.
    fn get_gateway_network_address(
        &self,
        logical_address: u16,
    ) -> impl Future<Output = Option<String>> + Send;

    /// Transmits the given UDS message to the network/bus and handles protocol specific
    /// acknowledgements and responses.
    /// The implementation will take care of assembling lower level frames into UDS messages.
    /// When the protocol is using IP, this means assembling multiple UDP/TCP packets,
    /// for simpler buses like CAN it means assembling multiple frames,
    /// especially for multi-frame messages.
    /// UDS responses are sent back to the `response_sender` channel.
    /// Multiple responses can be sent, e.g. for a request that requires multiple responses,
    /// i.e. response pending NRCs 0x78.
    /// # Errors
    /// * `DiagServiceError::EcuOffline` if the ECU cannot be reached, is not found, or is offline.
    /// * `DiagServiceError::Nack` when the ECU responds with a NACK, that cannot be
    ///   handled by the gateway.
    ///   In this case the error is informational,
    ///   and it will not be handled anymore by the UDS layer, but
    ///   will only be forwarded to i.e. SOVD to be returned to the client.
    /// * `DiagServiceError::UnexpectedResponse` if the responses are out of order or unexpected,
    ///   for example if a NACK/ACK was expected but a different response was received.
    /// * `DiagServiceError::NoResponse` if an error occurs while waiting for a response
    /// * `DiagServiceError::Timeout` if the nack/ack/response is
    ///   not received within the specified timeout.
    fn send(
        &self,
        transmission_params: TransmissionParameters,
        message: ServicePayload,
        response_sender: mpsc::Sender<Result<Option<TransportResponse>, DiagServiceError>>,
        expect_uds_reply: bool,
    ) -> impl Future<Output = Result<(), DiagServiceError>> + Send;

    /// Checks if an ECU is online.
    /// Returns an error if the ECU is not online or if the ECU cannot be reached.
    /// Otherwise, returns `Ok(())`.
    /// # Errors
    ///  `DiagServiceError::EcuOffline` if the ECU cannot be reached, is not found, or is offline.
    fn ecu_online<T: EcuAddresses>(
        &self,
        ecu_name: &str,
        ecu_db: &RwLock<T>,
    ) -> impl Future<Output = Result<(), DiagServiceError>> + Send;

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

    /// Stops the gateway, aborting its background tasks and releasing its
    /// transport resources. Completes only after the owned tasks have
    /// terminated, so callers (e.g. the runtime database reload, which reuses
    /// the `DoIP` UDP socket) can rely on the transport being quiescent.
    fn shutdown(&mut self) -> impl Future<Output = ()> + Send;

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

/// Extension trait for CAN-specific gateway operations.
///
/// Extends [`EcuGateway`] with the ECU lifecycle-detection hooks the
/// multi-transport orchestrator needs to route to a CAN transport without
/// depending on the concrete CAN gateway type.
pub trait EcuCanGateway: EcuGateway {
    /// Checks if a specific ECU was discovered (responded to a probe).
    fn is_ecu_discovered_by_name(&self, ecu_name: &str) -> impl Future<Output = bool> + Send;

    /// Returns whether this gateway has addressing for the ECU
    /// (regardless of whether the ECU answered a probe yet).
    fn knows_ecu(&self, ecu_name: &str) -> bool;

    /// Attempts to probe/detect a specific ECU on the bus.
    /// Returns `true` if the ECU responds to the probe.
    fn probe_ecu(&self, ecu_name: &str) -> impl Future<Output = bool> + Send;
}
