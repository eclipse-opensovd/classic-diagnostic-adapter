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

use std::{sync::Arc, time::Duration};

use tokio::sync::{Mutex, RwLock, mpsc};

use crate::{
    DiagServiceError, EcuAddresses, HashMap, ServicePayload, Shutdown, uds::TransportResponse,
};

/// Parameters for sending a UDS message over the network.
#[derive(Debug, Clone)]
pub struct TransmissionParameters {
    pub gateway_address: u16,
    pub timeout_ack: Duration,
    pub ecu_name: String,
    pub repeat_request_count_transmission: u32,
}

/// Physical transmission of UDS messages on a single transport.
///
/// Handles protocol specifics (like ACKs and NACKs for DOIP) and provides
/// information about the ECUs on the network, like their online state.
pub trait PhysicalTransport: Shutdown + Clone + Send + Sync + 'static {
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
    ) -> impl Future<Output = Result<tokio::task::JoinHandle<()>, DiagServiceError>> + Send;

    /// Checks if an ECU is currently reachable on this transport.
    fn ecu_online<T: EcuAddresses>(
        &self,
        ecu_name: &str,
        ecu_db: &RwLock<T>,
    ) -> impl Future<Output = Result<(), DiagServiceError>> + Send;
}

/// Functional diagnostic send.
/// `DoIP` implements this; CAN returns `RequestNotSupported` until functional
/// addressing is implemented.
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

/// An [`EcuGateway`] that may own a reusable transport resource.
///
/// Implementing this trait allows a reload handler to retrieve and hand back an existing
/// transport resource to the factory during a database reload. Gateways without a reusable
/// resource, such as CAN-only gateways, return `None`.
///
/// The associated resource type is deliberately opaque in `cda-interfaces` so that this crate
/// stays free of dependencies on concrete transport implementations.
pub trait ReusableTransportResource {
    /// Opaque reusable transport resource type (e.g. `cda_comm_doip::socket::DoIPUdpSocket`).
    type TransportResource: Send + Sync + 'static;

    /// Returns a shared, cloneable handle to the reusable transport resource when present.
    fn reusable_transport_resource(&self) -> Option<Arc<Mutex<Self::TransportResource>>>;
}

/// Core gateway supertrait: physical and functional sends + topology queries.
pub trait EcuGateway: FunctionalTransport + NetworkTopology {}
impl<T> EcuGateway for T where T: FunctionalTransport + NetworkTopology {}

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
    fn probe_ecu(&self, ecu_name: &str) -> impl Future<Output = bool> + Send;
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
