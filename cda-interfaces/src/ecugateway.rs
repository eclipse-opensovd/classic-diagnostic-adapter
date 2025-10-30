/*
 * Copyright (c) 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
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

use crate::{DiagServiceError, EcuAddressProvider, ServicePayload};

#[derive(Debug, Clone)]
pub enum UdsResponse {
    /// Raw UDS message response, which can be a positive or negative response.
    Message(ServicePayload),
    /// NRC 0x78 - Response pending.
    ResponsePending(u16),
    /// Tester was replied with NRC
    TesterPresentNRC(u8),
    /// NRC 0x21 - Busy repeat request.
    BusyRepeatRequest(u16),
    /// NRC 0x94 - Temporarily not available.
    TemporarilyNotAvailable(u16),
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
        response_sender: mpsc::Sender<Result<Option<UdsResponse>, DiagServiceError>>,
        expect_uds_reply: bool,
    ) -> impl Future<Output = Result<(), DiagServiceError>> + Send;

    /// Checks if an ECU is online.
    /// Returns an error if the ECU is not online or if the ECU cannot be reached.
    /// Otherwise, returns `Ok(())`.
    /// # Errors
    ///  `DiagServiceError::EcuOffline` if the ECU cannot be reached, is not found, or is offline.
    fn ecu_online<T: EcuAddressProvider>(
        &self,
        ecu_name: &str,
        ecu_db: &RwLock<T>,
    ) -> impl Future<Output = Result<(), DiagServiceError>> + Send;
}
