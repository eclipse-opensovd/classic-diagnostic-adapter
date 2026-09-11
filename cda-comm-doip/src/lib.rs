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

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use cda_interfaces::{
    DiagServiceError, DoipComParams, EcuAddresses, EcuConnectivityHandler, FunctionalTransport,
    HashMap, HashMapExtensions, NetworkTopology, PhysicalTransport, RouteStatus, ServicePayload,
    TransmissionParameters, TransportProbe, TransportResponse, VariantDetectionSender,
    communication_control::{
        GatewayLifecycle, TransportControl, TransportState, error::CommControlError,
    },
    dlt_ctx, pending_nrc_from_raw, uds_response_from_raw,
    util::{self, tokio_ext},
};
use doip_definitions::{
    header::ProtocolVersion,
    payload::{
        DiagnosticMessage, DiagnosticMessageNack, DoipPayload, GenericNack,
        RoutingActivationRequest,
    },
};
use futures::FutureExt;
use tokio::{
    sync::{Mutex, RwLock, broadcast, mpsc},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

pub mod config;
pub mod error;
pub use error::{ConnectionError, DoipGatewaySetupError};
mod connection_receiver;
mod connection_sender;
mod connections;
mod ecu_connection;
pub mod socket;
mod vir_vam;

use crate::{
    config::DoipConfig,
    connections::{EcuError, GatewayState},
    socket::DoIPUdpSocket,
};

/// Timeout when suppressPosRspMsgIndicationBit is set.
/// ECUs that reject a request usually respond quickly with an NRC and
/// this timeout window should be able to capture those while
/// not blocking for the full diagnostic timeout.
///
/// This constant is intentionally separate from `timeout_default` so it can be promoted to a
/// configuration entry, or a `ComParam` in a future iteration without changing the
/// surrounding logic.
const SUPPRESS_POSITIVE_RESPONSE_TIMEOUT: Duration = Duration::from_millis(500);

/// Events received on a `DoIP` connection.
///
/// `Msg` carries the raw UDS payload and its `DoIP` logical addresses. All other
/// variants are ISO 13400-2 protocol-level events that must be handled before
/// any UDS data is forwarded to the caller.
#[derive(Debug, Clone)]
enum DiagnosticResponse {
    /// A UDS payload received from an ECU, carried verbatim before classification.
    Msg {
        source_address: u16,
        target_address: u16,
        data: Vec<u8>,
    },
    /// An acknowledgment of a previously sent UDS payload, carrying the original
    /// request's logical address and data.
    Ack((u16, Vec<u8>)),
    /// A negative acknowledgment of a previously sent UDS payload, including
    /// the original Nack message struct.
    Nack(DiagnosticMessageNack),
    /// A response to a `DoIP` alive-check request, indicating that the ECU is reachable.
    AliveCheckResponse,
    /// `TesterPresent` NRC - intercepted at the decoding layer so the receiver
    /// can log-and-drop without routing it to a per-ECU channel.
    TesterPresentNRC(u8),
    /// Generic `DoIP` negative acknowledgment, carrying the `GenericNack` struct with the NACK code.
    GenericNack(GenericNack), // todo #22 -> we need the address of the ECU that sent the nack
}

impl DiagnosticResponse {
    fn matches_request(&self, request: &[u8]) -> bool {
        let Some(sid) = request.first() else {
            return false;
        };

        match self {
            Self::Ack((_, previous)) => request.starts_with(previous),
            // Positive and negative echoes both belong to the request: a
            // final NRC can overtake the ACK, and ignoring it here consumes
            // it from the receiver - the later response read then times out
            // although the ECU answered.
            Self::Msg { data, .. } => util::uds_response_matches_request_sid(*sid, data),
            _ => false,
        }
    }
}

pub(crate) struct DoipGatewayState<T: EcuAddresses + DoipComParams> {
    pub(crate) doip_connections: Arc<RwLock<Vec<Arc<DoipConnection>>>>,
    pub(crate) logical_address_to_connection: Arc<RwLock<HashMap<u16, usize>>>,
    pub(crate) ecus: Arc<HashMap<String, RwLock<T>>>,
    /// `None` until the first successful `start()` binds it. No UDP socket is
    /// created at construction time, only when an authorized activation runs.
    pub(crate) socket: Arc<Mutex<Option<DoIPUdpSocket>>>,
    pub(crate) netmask: u32,
}

/// Owns all connection tasks for one enabled lifecycle so they stop together.
pub(crate) struct ConnectionTasks(Mutex<Vec<JoinHandle<()>>>);

impl ConnectionTasks {
    fn new() -> Self {
        Self(Mutex::new(Vec::new()))
    }

    pub(crate) async fn push(&self, task: JoinHandle<()>) {
        self.0.lock().await.push(task);
    }

    async fn shutdown(&self) {
        let mut tasks = std::mem::take(&mut *self.0.lock().await);
        for task in &tasks {
            task.abort();
        }
        for task in tasks.drain(..) {
            if let Err(error) = task.await
                && error.is_panic()
            {
                tracing::error!(%error, "DoIP connection task panicked during shutdown");
            }
        }
    }
}

impl Drop for ConnectionTasks {
    fn drop(&mut self) {
        // Best effort cleanup, we cannot await the tasks in
        // here. A user should call 'shutdown' instead of relying on this.
        for task in self.0.get_mut().drain(..) {
            tracing::warn!("DoIP connection tasks dropped without `shutdown`, aborting tasks");
            task.abort();
        }
    }
}

impl<T: EcuAddresses + DoipComParams> Clone for DoipGatewayState<T> {
    fn clone(&self) -> Self {
        Self {
            doip_connections: Arc::clone(&self.doip_connections),
            logical_address_to_connection: Arc::clone(&self.logical_address_to_connection),
            ecus: Arc::clone(&self.ecus),
            socket: Arc::clone(&self.socket),
            netmask: self.netmask,
        }
    }
}

pub struct DoipDiagGateway<T: EcuAddresses + DoipComParams> {
    state: DoipGatewayState<T>,
    config: DoipConfig,
    variant_detection: VariantDetectionSender,
    connectivity_handler: Arc<dyn EcuConnectivityHandler>,
    lifecycle: Arc<GatewayLifecycle<DoipGatewayOperation>>,
}

/// Background work owned by the currently enabled lifecycle.
#[derive(Default)]
struct DoipGatewayOperation {
    cancel: Option<CancellationToken>,
    vam_listener: Option<JoinHandle<()>>,
    connection_tasks: Option<Arc<ConnectionTasks>>,
}

impl Drop for DoipGatewayOperation {
    fn drop(&mut self) {
        if self.cancel.is_some() || self.vam_listener.is_some() || self.connection_tasks.is_some() {
            tracing::warn!("DoIP gateway operation dropped without `shutdown`, aborting tasks");
        }
        self.take_and_abort();
    }
}

impl DoipGatewayOperation {
    fn take_and_abort(&mut self) -> (Option<JoinHandle<()>>, Option<Arc<ConnectionTasks>>) {
        if let Some(cancel) = self.cancel.take() {
            cancel.cancel();
        }
        let listener = self.vam_listener.take();
        if let Some(listener) = &listener {
            listener.abort();
        }
        (listener, self.connection_tasks.take())
    }

    async fn shutdown(&mut self) {
        let (listener, connection_tasks) = self.take_and_abort();
        if let Some(listener) = listener
            && let Err(error) = listener.await
            && !error.is_cancelled()
        {
            tracing::error!(%error, "DoIP VAM listener failed during shutdown");
        }
        if let Some(connection_tasks) = connection_tasks {
            connection_tasks.shutdown().await;
        }
    }
}

/// A gateway discovered on the network during `DoIP` vehicle discovery.
///
/// Contains the IP address, ECU name, and logical address obtained from a
/// `VehicleIdentificationResponse` or `EntityStatusResponse` message.
#[derive(Debug)]
pub(crate) struct DiscoveredGateway {
    pub(crate) ip: String,
    pub(crate) ecu_name: String,
    pub(crate) logical_address: u16,
    pub(crate) doip_protocol_version: ProtocolVersion,
}

/// Transport-level settings shared across all `DoIP` gateway connections.
/// Built once from `DoipConfig` in `DoipDiagGateway::new`; cloned into each
/// `GatewayDoipConfig` when a specific gateway is discovered.
#[derive(Clone)]
pub(crate) struct DoipTransportConfig {
    /// IP address of the diagnostic tester interface.
    pub(crate) tester_ip: String,
    /// TCP port for `DoIP` communication.
    pub(crate) port: u16,
    /// TCP port for `DoIP` over TLS communication.
    pub(crate) tls_port: u16,
    /// Whether to send a `DiagnosticMessageAck` upon receiving a `DiagnosticMessage`.
    pub(crate) send_diagnostic_message_ack: bool,
    /// Timeout for sending a single `DoIP` message.
    pub(crate) send_timeout: Duration,
    /// Interval between alive-check requests on idle connections (0 = disabled).
    pub(crate) alive_check_interval: Duration,
}

/// Per-gateway configuration combining the discovered gateway identity with the
/// shared transport settings.  Only constructed inside `handle_gateway_connection`
/// once a real `ip` and `name` are known - never holds placeholder values.
#[derive(Clone)]
pub(crate) struct GatewayDoipConfig {
    /// IP address of the gateway ECU.
    pub(crate) gateway_ip: String,
    /// Name of the gateway ECU.
    pub(crate) name: String,
    /// UDS address of the tester.
    pub(crate) tester_address: [u8; 2],
    /// The `DoIp` protocol version to use for this gateway connection.
    /// Set from the protocol version field in the VAM.
    pub(crate) protocol_version: ProtocolVersion,
    /// Shared transport-level settings (tester IP, ports, socket config, timeouts).
    pub(crate) transport: DoipTransportConfig,
}

/// ECU-lifecycle timeouts sourced from `EcuAddresses` / `DoipComParams` during gateway setup.
#[derive(Clone, Copy)]
pub(crate) struct EcuTimeouts {
    pub(crate) routing_activation: Duration,
    pub(crate) retry_delay: Duration,
    pub(crate) connection: Duration,
    pub(crate) max_retry_attempts: u32,
}

/// Parameters needed to (re-)establish a TCP connection to one `DoIP` gateway.
/// Cloned into the reconnect task and passed to `ecu_connection` functions;
/// does **not** carry one-time setup data such as the ECU list or variant-detection channel.
#[derive(Clone)]
pub(crate) struct GatewayConnectionConfig {
    pub(crate) doip: GatewayDoipConfig,
    pub(crate) routing_activation_request: RoutingActivationRequest,
    pub(crate) ecu_timeouts: EcuTimeouts,
}

/// One-shot setup bundle consumed by `connection_handler` when bringing up a new gateway.
/// Carries `GatewayConnectionConfig` plus the ECU list needed during initial channel creation
/// and the `ConnectivityHandler` for propagating connection events.
#[derive(Clone)]
pub(crate) struct GatewaySetup {
    pub(crate) connection: GatewayConnectionConfig,
    pub(crate) ecus: Vec<u16>,
    pub(crate) ecu_names: Vec<String>,
    pub(crate) connectivity_handler: Arc<dyn EcuConnectivityHandler>,
}

struct DoipEcu {
    sender: mpsc::Sender<DoipPayload>,
    receiver: broadcast::Receiver<Result<DiagnosticResponse, EcuError>>,
}

struct DoipConnection {
    ecus: HashMap<u16, Arc<Mutex<DoipEcu>>>,
    ip: String,
}

impl<T: EcuAddresses + DoipComParams> DoipDiagGateway<T> {
    /// Create a new `DoipDiagGateway` instance.
    ///
    /// Purely in-memory. No UDP socket is created or bound, no packet is sent
    /// and no task is started, so this is safe to call in any `init_mode`.
    ///
    /// # Errors
    /// Returns `String` if initialization fails, e.g. when the configured
    /// tester address/subnet cannot be parsed into a netmask.
    #[tracing::instrument(
        skip(doip_config, ecus, variant_detection, connectivity_handler),
        fields(
            tester_ip = doip_config.tester_address,
            gateway_port = doip_config.gateway_port,
            ecu_count = ecus.len(),
            dlt_context = dlt_ctx!("DOIP")
        )
    )]
    pub async fn new(
        doip_config: &DoipConfig,
        ecus: Arc<HashMap<String, RwLock<T>>>,
        variant_detection: VariantDetectionSender,
        connectivity_handler: Arc<dyn EcuConnectivityHandler>,
    ) -> Result<Self, DoipGatewaySetupError> {
        Ok(Self {
            state: DoipGatewayState {
                doip_connections: Arc::new(RwLock::new(Vec::new())),
                logical_address_to_connection: Arc::new(RwLock::new(HashMap::new())),
                ecus,
                socket: Arc::new(Mutex::new(None)),
                netmask: create_netmask(&doip_config.tester_address, &doip_config.tester_subnet)?,
            },
            config: doip_config.clone(),
            variant_detection,
            connectivity_handler,
            lifecycle: Arc::new(GatewayLifecycle::new(TransportState::Disabled)),
        })
    }

    async fn start(
        &self,
        operation: &mut DoipGatewayOperation,
    ) -> Result<(), DoipGatewaySetupError> {
        let mut socket_guard = self.state.socket.lock().await;
        if operation.cancel.is_some()
            || operation.vam_listener.is_some()
            || operation.connection_tasks.is_some()
            || socket_guard.is_some()
        {
            return Err(DoipGatewaySetupError::InvalidState(
                "DoIP communication is already running".to_string(),
            ));
        }

        let config = &self.config;
        let transport_config = DoipTransportConfig {
            tester_ip: config.tester_address.clone(),
            port: config.gateway_port,
            tls_port: config.tls_port,
            send_diagnostic_message_ack: config.send_diagnostic_message_ack,
            send_timeout: Duration::from_millis(config.send_timeout_ms),
            alive_check_interval: Duration::from_secs(config.alive_check_interval_secs),
        };
        let mask = self.state.netmask;
        let cancel = CancellationToken::new();
        let shutdown = cancel.child_token().cancelled_owned().shared();
        let connection_tasks = Arc::new(ConnectionTasks::new());
        operation.cancel = Some(cancel.clone());
        operation.connection_tasks = Some(Arc::clone(&connection_tasks));

        // TODO(persistence-init-mode): Implement as described in req~dt-ecu-list-persistence
        let socket = socket_guard.insert(create_udp_vir_socket(
            &config.tester_address,
            config.gateway_port,
        )?);
        let gateways = vir_vam::get_vehicle_identification::<T, _>(
            socket,
            mask,
            config.gateway_port,
            &self.state.ecus,
            shutdown.clone(),
        )
        .await
        .map_err(|error| DoipGatewaySetupError::ResourceError(error.to_string()))?;
        drop(socket_guard);

        let mut gateway_ecu_map: HashMap<u16, Vec<u16>> = HashMap::new();
        for ecu_lock in self.state.ecus.values() {
            let ecu = ecu_lock.read().await;
            gateway_ecu_map
                .entry(ecu.logical_gateway_address())
                .or_default()
                .push(ecu.logical_address());
        }
        for gateway in gateways {
            if let Ok(logical_address) = connections::handle_gateway_connection::<T>(
                gateway,
                &transport_config,
                &GatewayState {
                    doip_connections: Arc::clone(&self.state.doip_connections),
                    ecus: Arc::clone(&self.state.ecus),
                    gateway_ecu_map: gateway_ecu_map.clone(),
                    connection_tasks: Arc::clone(&connection_tasks),
                },
                Arc::clone(&self.connectivity_handler),
            )
            .await
            {
                self.state
                    .logical_address_to_connection
                    .write()
                    .await
                    .insert(
                        logical_address,
                        self.state
                            .doip_connections
                            .read()
                            .await
                            .len()
                            .saturating_sub(1),
                    );
            }
        }

        let listener = vir_vam::listen_for_vams(
            transport_config,
            mask,
            self.state.clone(),
            Arc::clone(&connection_tasks),
            self.variant_detection.clone(),
            Arc::clone(&self.connectivity_handler),
            shutdown,
        )
        .await;
        operation.vam_listener = Some(listener);
        Ok(())
    }

    async fn stop(&self, operation: &mut DoipGatewayOperation) {
        operation.shutdown().await;
        self.state.socket.lock().await.take();
        self.state.doip_connections.write().await.clear();
        self.state
            .logical_address_to_connection
            .write()
            .await
            .clear();
    }

    async fn get_doip_connection(
        &self,
        logical_address: u16,
    ) -> Result<Arc<DoipConnection>, DiagServiceError> {
        let conn_idx = *self
            .state
            .logical_address_to_connection
            .read()
            .await
            .get(&logical_address)
            .ok_or_else(|| DiagServiceError::EcuOffline(format!("[{logical_address}]")))?;

        let lock = self.state.doip_connections.read().await;
        let conn = lock
            .get(conn_idx)
            .ok_or(DiagServiceError::ConnectionClosed(format!(
                "Connection entry for address {logical_address} found, but it was already closed"
            )))?;

        Ok(Arc::clone(conn))
    }

    async fn get_ecu_mtx(
        &self,
        doip_conn: &DoipConnection,
        message: &ServicePayload,
        transmission_params: &TransmissionParameters,
    ) -> Result<Arc<Mutex<DoipEcu>>, DiagServiceError> {
        // first try looking up with the target address.
        if let Some(ecu) = doip_conn.ecus.get(&message.target_address) {
            return Ok(Arc::clone(ecu));
        }

        // if we cannot find the target address,
        // the request might be sent on the functional address
        // in that case, lookup the ecu name and check if the functional address
        // matches the given address.
        // this will be the case for tester present.
        if let Some(ecu) = self
            .state
            .ecus
            .get(&transmission_params.ecu_name.to_lowercase())
            && ecu.read().await.logical_functional_address() == message.target_address
            && let Some(gateway_ecu) = doip_conn.ecus.get(&transmission_params.gateway_address)
        {
            return Ok(Arc::clone(gateway_ecu));
        }

        Err(DiagServiceError::EcuOffline(
            transmission_params.ecu_name.clone(),
        ))
    }
}

impl<T: EcuAddresses + DoipComParams> PhysicalTransport for DoipDiagGateway<T> {
    #[tracing::instrument(skip_all,
        fields(dlt_context = dlt_ctx!("DOIP"))
    )]

    async fn send(
        &self,
        transmission_params: TransmissionParameters,
        message: ServicePayload,
        response_sender: mpsc::Sender<Result<Option<TransportResponse>, DiagServiceError>>,
        expect_uds_reply: bool,
    ) -> Result<tokio::task::JoinHandle<()>, DiagServiceError> {
        let start = Instant::now();

        let doip_conn = self
            .get_doip_connection(transmission_params.gateway_address)
            .await?;
        let ecu_mtx = self
            .get_ecu_mtx(&doip_conn, &message, &transmission_params)
            .await?;

        let doip_message = DiagnosticMessage {
            source_address: message.source_address.to_be_bytes(),
            target_address: message.target_address.to_be_bytes(),
            message: message.data,
        };

        let handle = cda_interfaces::spawn_named!(
            &format!("ecu-data-receive-{}", transmission_params.ecu_name),
            {
                async move {
                    let mut ecu = ecu_mtx.lock().await;
                    let lock_acquired = start.elapsed();
                    tracing::debug!(
                        ecu_name = %transmission_params.ecu_name,
                        locked_after = ?lock_acquired,
                        message_data = %util::tracing::print_hex(&doip_message.message, 8),
                        "Sending Message to ECU"
                    );

                    // Clear any pending messages
                    tokio_ext::clear_pending_messages(&mut ecu.receiver);
                    let receiver_flushed = start.elapsed().saturating_sub(lock_acquired);

                    let mut resend_counter = 0;
                    if let Err(e) = send_with_retries(
                        &doip_message,
                        &ecu.sender,
                        &mut resend_counter,
                        transmission_params.repeat_request_count_transmission,
                    )
                    .await
                    {
                        // failed to send the message after exhausting retries.
                        // informing receiver and giving up.
                        try_send_transport_response(&response_sender, Err(e)).await;
                        return;
                    }

                    let received_event = match wait_for_ack_or_response_until_timeout(
                        &mut ecu.receiver,
                        &transmission_params.ecu_name,
                        &doip_message,
                        transmission_params.timeout_ack,
                    )
                    .await
                    {
                        Ok(first) => first,
                        Err(e) => {
                            try_send_transport_response(&response_sender, Err(e)).await;
                            return;
                        }
                    };

                    let send_and_ackd_after = start
                        .elapsed()
                        .saturating_sub(lock_acquired)
                        .saturating_sub(receiver_flushed);

                    if !expect_uds_reply {
                        try_send_transport_response(&response_sender, Ok(None)).await;
                    }

                    // Read ECU responses as long as the sender is open.
                    // We might get multiple responses for a single request,
                    // e.g. when the ECU is busy and sends NRC 0x78.
                    read_ecu_responses(
                        &mut ecu.receiver,
                        &transmission_params.ecu_name,
                        &response_sender,
                        received_event,
                    )
                    .await;

                    let rx_done = start
                        .elapsed()
                        .saturating_sub(lock_acquired)
                        .saturating_sub(send_and_ackd_after)
                        .saturating_sub(receiver_flushed);
                    tracing::debug!(
                        ecu_name = %transmission_params.ecu_name,
                        total_duration = ?start.elapsed(),
                        lock_duration = ?lock_acquired,
                        flush_duration = ?receiver_flushed,
                        send_ack_duration = ?send_and_ackd_after,
                        response_duration = ?rx_done,
                        "Handled DOIP request timing breakdown"
                    );
                }
            }
        );

        Ok(handle)
    }

    async fn ecu_online<E: EcuAddresses>(
        &self,
        ecu_name: &str,
        ecu_db: &RwLock<E>,
    ) -> Result<(), DiagServiceError> {
        let ecu_lock = ecu_db.read().await;

        let doip_conn = self
            .get_doip_connection(ecu_lock.logical_gateway_address())
            .await?;
        doip_conn
            .ecus
            .get(&ecu_lock.logical_address())
            .ok_or_else(|| DiagServiceError::EcuOffline(ecu_name.to_owned()))?;
        Ok(())
    }
}

impl<T: EcuAddresses + DoipComParams> FunctionalTransport for DoipDiagGateway<T> {
    async fn send_functional(
        &self,
        transmission_params: TransmissionParameters,
        message: ServicePayload,
        expected_ecu_logical_addrs: HashMap<u16, String>,
        timeout: Duration,
        expect_positive_response: bool,
    ) -> Result<HashMap<String, Result<ServicePayload, DiagServiceError>>, DiagServiceError> {
        let doip_conn = self
            .get_doip_connection(transmission_params.gateway_address)
            .await?;

        // Get the gateway ECU for sending the functional request
        let gateway_ecu = doip_conn
            .ecus
            .get(&transmission_params.gateway_address)
            .ok_or_else(|| DiagServiceError::EcuOffline("Gateway ECU not found".to_string()))?;

        let doip_message = DiagnosticMessage {
            source_address: message.source_address.to_be_bytes(),
            target_address: message.target_address.to_be_bytes(),
            message: message.data,
        };

        let mut result_map = HashMap::new();
        let expected_count = expected_ecu_logical_addrs.len();

        tracing::debug!(
            gateway_address = %transmission_params.gateway_address,
            expected_ecus = expected_count,
            message_data = %util::tracing::print_hex(&doip_message.message, 8),
            "Sending functional request to gateway"
        );

        // Send the functional request once
        let mut ecu = gateway_ecu.lock().await;
        let mut ecu_mtxs = expected_ecu_logical_addrs
            .iter()
            .filter_map(|(addr, name)| {
                if *addr == transmission_params.gateway_address {
                    None
                } else {
                    doip_conn
                        .ecus
                        .get(addr)
                        .cloned()
                        .map(|ecu| (name.clone(), ecu))
                }
            })
            .collect::<Vec<_>>();

        // Clear any pending messages
        tokio_ext::clear_pending_messages(&mut ecu.receiver);

        let mut resend_counter = 0;
        send_with_retries(
            &doip_message,
            &ecu.sender,
            &mut resend_counter,
            transmission_params.repeat_request_count_transmission,
        )
        .await?;

        drop(ecu); // release lock before waiting for responses
        ecu_mtxs.push((
            transmission_params.ecu_name.to_lowercase(),
            Arc::clone(gateway_ecu),
        ));

        // Use a short window to capture any negative responses instead of the full timeout,
        // as NRCs are usually sent immediately by the ECUs.
        let response_timeout = if expect_positive_response {
            timeout
        } else {
            SUPPRESS_POSITIVE_RESPONSE_TIMEOUT
        };

        let received_responses: Arc<Mutex<HashMap<String, Result<DiagnosticMessage, EcuError>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let mut futures = Vec::new();
        for (name, ecu) in ecu_mtxs.drain(..) {
            let received_responses = Arc::clone(&received_responses);
            let fut = async move {
                let mut lock = ecu.lock().await;
                if let Some(response) = wait_for_ecu_response(&mut lock, response_timeout).await {
                    received_responses.lock().await.insert(name, response);
                }
            };
            futures.push(fut);
        }

        futures::future::join_all(futures).await;

        for (ecu_name, msg) in received_responses.lock().await.drain() {
            if !result_map.contains_key(&ecu_name) {
                match msg {
                    Ok(msg) => {
                        let source_addr = u16::from_be_bytes(msg.source_address);

                        let uds_response = ServicePayload {
                            data: msg.message,
                            source_address: source_addr,
                            target_address: u16::from_be_bytes(msg.target_address),
                            new_session: None,
                            new_security: None,
                        };

                        result_map.insert(ecu_name.clone(), Ok(uds_response));

                        tracing::debug!(
                            ecu_name = %ecu_name,
                            source_addr = source_addr,
                            "Received functional response"
                        );
                    }
                    Err(e) => {
                        tracing::debug!(
                            ecu_name = %ecu_name,
                            "Error receiving functional response: {e}"
                        );
                        result_map.insert(ecu_name.clone(), Err(e.into()));
                    }
                }
            }
        }

        // For ECUs that did not respond:
        // Insert a TimeoutError for ECUs that did not response, if
        // a positive response is expected. (suppress bit is not set)
        for (logical_addr, ecu_name) in &expected_ecu_logical_addrs {
            if !result_map.contains_key(ecu_name) && expect_positive_response {
                result_map.insert(ecu_name.clone(), Err(DiagServiceError::Timeout));
                tracing::debug!(
                    ecu_name = %ecu_name,
                    logical_addr = logical_addr,
                    "ECU did not respond to functional request"
                );
            }
        }

        Ok(result_map)
    }
}

impl<T: EcuAddresses + DoipComParams> NetworkTopology for DoipDiagGateway<T> {
    async fn get_gateway_network_address(&self, logical_address: u16) -> Option<String> {
        self.state
            .doip_connections
            .read()
            .await
            .iter()
            .find(|conn| conn.ecus.contains_key(&logical_address))
            .map(|conn| conn.ip.clone())
    }
}

impl<T: EcuAddresses + DoipComParams> TransportProbe for DoipDiagGateway<T> {
    async fn route_status(&self, ecu_name: &str) -> RouteStatus {
        let ecu_name = ecu_name.to_lowercase();
        let Some(ecu_lock) = self.state.ecus.get(&ecu_name) else {
            return RouteStatus::NotConfigured;
        };
        // Check if the gateway connection for this ECU is established
        let gateway_addr = ecu_lock.read().await.logical_gateway_address();
        if self.get_doip_connection(gateway_addr).await.is_ok() {
            RouteStatus::Ready
        } else {
            // DoIP addressing is gateway-scoped, so there is
            // no per-ECU probe to offer. Reconnecting is this transport's job
            // (VAM listener, connection-reset task), not the router's.
            RouteStatus::Unavailable
        }
    }

    fn probe_ecu(&self, _ecu_name: &str) -> impl Future<Output = bool> {
        std::future::ready(false)
    }
}
/// Waits for the `DoIP` diagnostic-message acknowledgement from the gateway,
/// with a deadline of `timeout`.
#[allow(
    clippy::needless_continue,
    reason = "Explicit continue improves readability of wait logic"
)]
async fn wait_for_ack_or_response_until_timeout(
    receiver: &mut broadcast::Receiver<Result<DiagnosticResponse, EcuError>>,
    ecu_name: &str,
    sent_message: &DiagnosticMessage,
    timeout: Duration,
) -> Result<Option<DiagnosticResponse>, DiagServiceError> {
    async fn wait_for_ack_or_response(
        receiver: &mut broadcast::Receiver<Result<DiagnosticResponse, EcuError>>,
        ecu_name: &str,
        sent_message: &DiagnosticMessage,
    ) -> Result<Option<DiagnosticResponse>, DiagServiceError> {
        loop {
            let response = match receiver.recv().await {
                Ok(Ok(response)) => response,
                Ok(Err(e)) => {
                    tracing::error!(
                        ecu_name = %ecu_name,
                        error = %e,
                        "Error while waiting for ACK/NACK"
                    );

                    return Err(DiagServiceError::NoResponse(format!(
                        "Error while waiting for ACK/NACK, {e}"
                    )));
                }
                Err(_) => {
                    tracing::error!(
                        ecu_name = %ecu_name,
                        "ECU receiver unexpectedly closed while waiting for ACK/NACK"
                    );

                    return Err(DiagServiceError::NoResponse(
                        "ECU receiver unexpectedly closed".to_owned(),
                    ));
                }
            };

            match &response {
                DiagnosticResponse::Nack(nack) => {
                    tracing::warn!(
                        ecu_name = %ecu_name,
                        nack_code = ?nack.nack_code,
                        "Received NACK"
                    );
                    return Err(DiagServiceError::Nack(u8::from(nack.nack_code)));
                }
                DiagnosticResponse::GenericNack(nack) => {
                    tracing::warn!(
                        ecu_name = %ecu_name,
                        nack_code = ?nack.nack_code,
                        "Received generic NACK"
                    );
                    return Err(DiagServiceError::Nack(u8::from(nack.nack_code)));
                }
                _ => {}
            }

            if !response.matches_request(&sent_message.message) {
                if let DiagnosticResponse::Ack((_, previous)) = &response {
                    tracing::warn!(
                        ecu_name = %ecu_name,
                        previous = %util::tracing::print_hex(previous, 8),
                        sent = %util::tracing::print_hex(&sent_message.message, 8),
                        "ACK previous message does not match sent message"
                    );
                } else {
                    tracing::debug!(
                        ecu_name = %ecu_name,
                        ?response,
                        "Received response does not match sent message. Ignoring."
                    );
                }

                continue;
            }

            return match response {
                DiagnosticResponse::Ack((_, _)) => {
                    tracing::debug!(ecu_name = %ecu_name, "Received ACK");
                    Ok(None)
                }
                response => {
                    tracing::debug!(
                        ecu_name = %ecu_name,
                        "Received diagnostic response before ACK, treating as implicit ACK"
                    );
                    Ok(Some(response))
                }
            };
        }
    }

    if let Ok(result) = tokio::time::timeout(
        timeout,
        wait_for_ack_or_response(receiver, ecu_name, sent_message),
    )
    .await
    {
        result
    } else {
        tracing::warn!(
            ecu_name = %ecu_name,
            timeout = ?timeout,
            "Timeout waiting for ACK/NACK from ECU"
        );
        Err(DiagServiceError::Timeout)
    }
}

/// Reads ECU responses from `receiver` and forwards them through
/// `response_sender` until either the sender is closed (caller no longer
/// interested) or the receiver is closed (connection dropped).
///
/// `received_message` carries an already-received response from the implicit-ACK path
/// (where the ECU skipped the ACK and sent the diagnostic reply directly).
/// Pass `None` after a normal explicit ACK.
async fn read_ecu_responses(
    receiver: &mut broadcast::Receiver<Result<DiagnosticResponse, EcuError>>,
    ecu_name: &str,
    response_sender: &mpsc::Sender<Result<Option<TransportResponse>, DiagServiceError>>,
    received_event: Option<DiagnosticResponse>,
) {
    if let Some(event) = received_event
        && !try_send_transport_response(response_sender, diagnostic_response_to_transport(event))
            .await
    {
        return;
    }
    loop {
        tokio::select! {
            // Using biased saves a bit of CPU time because tokio does not
            // have to generate a random number to select the branch.
            // Prioritizing the ECU receiver over the closed handler is fine
            // because it is unlikely that both fire at the exact same time.
            biased;
            res = receiver.recv() => {
                if let Ok(res) = res {
                    match res {
                        Ok(event) => {
                            if !try_send_transport_response(
                                response_sender,
                                diagnostic_response_to_transport(event),
                            )
                            .await
                            {
                                break;
                            }
                        }
                        Err(e) => {
                            tracing::error!(
                                ecu_name = %ecu_name,
                                error = %e,
                                "Error while waiting for response message"
                            );
                            if !try_send_transport_response(
                                response_sender,
                                Err(DiagServiceError::NoResponse(format!(
                                    "Error while waiting for message, {e}"
                                ))),
                            )
                            .await
                            {
                                break;
                            }
                        }
                    }
                } else {
                    tracing::error!(
                        ecu_name = %ecu_name,
                        "ECU receiver unexpectedly closed while waiting for response"
                    );
                    try_send_transport_response(
                        response_sender,
                        Err(DiagServiceError::NoResponse(
                            "ECU receiver unexpectedly closed".to_owned(),
                        )),
                    )
                    .await;
                    break;
                }
            }
            () = response_sender.closed() => {
                tracing::debug!(
                    ecu_name = %ecu_name,
                    "Response sender closed, aborting loop"
                );
                break;
            }
        }
    }
}

/// Converts a [`DiagnosticResponse::Msg`] to a [`TransportResponse`] result for the
/// caller channel.
///
/// Pending NRCs are classified via [`pending_nrc_from_raw`]; all other frames
/// are classified as final via [`uds_response_from_raw`].
///
/// `TesterPresentNRC` is absorbed by [`connection_receiver`] before it is
/// broadcast to any per-ECU channel -- it never reaches this function.
/// All other [`DiagnosticResponse`] variants (Ack, Nack, etc.) must be
/// handled before calling this function.
fn diagnostic_response_to_transport(
    event: DiagnosticResponse,
) -> Result<Option<TransportResponse>, DiagServiceError> {
    match event {
        DiagnosticResponse::Msg {
            data,
            source_address,
            target_address,
        } => {
            if let Some(pending) = pending_nrc_from_raw(&data, source_address) {
                Ok(Some(TransportResponse::Pending(pending)))
            } else {
                Ok(Some(TransportResponse::UdsResponse(uds_response_from_raw(
                    data,
                    source_address,
                    target_address,
                ))))
            }
        }
        _ => Err(DiagServiceError::BadPayload(
            "Unexpected DoIP event type in UDS response stream".to_owned(),
        )),
    }
}

#[allow(
    clippy::needless_continue,
    reason = "Explicit continue improves readability of complex loop logic"
)]
async fn wait_for_ecu_response(
    ecu: &mut DoipEcu,
    timeout: Duration,
) -> Option<Result<DiagnosticMessage, EcuError>> {
    tokio::time::timeout(timeout, async {
        loop {
            match ecu.receiver.recv().await {
                Ok(Ok(DiagnosticResponse::Msg {
                    source_address,
                    target_address,
                    data,
                })) => {
                    return Some(Ok(DiagnosticMessage {
                        source_address: source_address.to_be_bytes(),
                        target_address: target_address.to_be_bytes(),
                        message: data,
                    }));
                }
                Ok(Ok(_ignore)) => {
                    // Ignore other event types
                    continue;
                }
                Ok(Err(e)) => {
                    return Some(Err(e));
                }
                Err(_) => {
                    // Receiver closed
                    return None;
                }
            }
        }
    })
    .await
    .unwrap_or_default()
}

fn create_netmask(tester_ip: &str, tester_subnet: &str) -> Result<u32, DoipGatewaySetupError> {
    let ip = tester_ip.parse::<std::net::Ipv4Addr>().map_err(|e| {
        DoipGatewaySetupError::InvalidAddress(format!(
            "DoipGateway: Failed to parse tester IP address: {e:?}"
        ))
    })?;
    let subnet = tester_subnet.parse::<std::net::Ipv4Addr>().map_err(|e| {
        DoipGatewaySetupError::InvalidAddress(format!(
            "DoipGateway: Failed to parse tester subnet mask: {e:?}"
        ))
    })?;

    Ok(ip.to_bits() & subnet.to_bits())
}

/// Creates a UDP socket for `DoIP` communication.
///
/// # Errors
/// Returns errors when:
/// * The provided `tester_ip` and `gateway_port` cannot be parsed into a valid `SocketAddr`,
///   resulting in a `DoipGatewaySetupError::InvalidAddress`.
/// * The underlying system call to create a new socket fails,
///   resulting in a `DoipGatewaySetupError::SocketCreationFailed`.
/// * Setting the `SO_REUSEADDR` socket option fails,
///   resulting in a `DoipGatewaySetupError::InvalidAddress`.
/// * On Unix-like systems, setting the `SO_REUSEPORT` socket option fails,
///   resulting in a `DoipGatewaySetupError::PortBindFailed`.
/// * Setting the `SO_BROADCAST` socket option fails,
///   resulting in a `DoipGatewaySetupError::SocketCreationFailed`.
/// * Binding the socket to the specified `tester_ip` and `gateway_port` fails,
///   resulting in a `DoipGatewaySetupError::SocketCreationFailed`.
/// * The `DoIPUdpSocket` constructor fails to create the DoIP-specific socket from the standard UDP socket,
///   resulting in a `DoipGatewaySetupError::SocketCreationFailed`.
pub fn create_udp_vir_socket(
    tester_ip: &str,
    gateway_port: u16,
) -> Result<DoIPUdpSocket, DoipGatewaySetupError> {
    let tester_ip = match tester_ip {
        "127.0.0.1" => "0.0.0.0",
        _ => tester_ip,
    };
    let broadcast_addr: std::net::SocketAddr =
        format!("{tester_ip}:{gateway_port}").parse().map_err(|e| {
            DoipGatewaySetupError::InvalidAddress(format!(
                "DoipGateway: Failed to create broadcast addr: {e:?}"
            ))
        })?;

    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .map_err(|e| {
        DoipGatewaySetupError::SocketCreationFailed(format!(
            "DoipGateway: Failed to create socket: {e:?}"
        ))
    })?;

    socket.set_reuse_address(true).map_err(|e| {
        DoipGatewaySetupError::InvalidAddress(format!(
            "DoipGateway: Failed to set reuse address: {e:?}"
        ))
    })?;
    #[cfg(target_family = "unix")]
    socket.set_reuse_port(true).map_err(|e| {
        DoipGatewaySetupError::PortBindFailed(format!(
            "DoipGateway: Failed to set reuse port: {e:?}"
        ))
    })?;
    socket.set_broadcast(true).map_err(|e| {
        DoipGatewaySetupError::SocketCreationFailed(format!(
            "DoipGateway: Failed to set broadcast flag on socket: {e:?}"
        ))
    })?;
    socket.set_nonblocking(true).map_err(|e| {
        DoipGatewaySetupError::InvalidConfiguration(format!(
            "DoipGateway: Failed to set non-blocking mode: {e:?}"
        ))
    })?;

    socket.bind(&broadcast_addr.into()).map_err(|e| {
        DoipGatewaySetupError::SocketCreationFailed(format!(
            "DoipGateway: Failed to bind socket, ip {tester_ip}, port {gateway_port}: {e:?}"
        ))
    })?;

    let std_sock: std::net::UdpSocket = socket.into();
    DoIPUdpSocket::new(std_sock, ProtocolVersion::DefaultValue).map_err(|e| {
        DoipGatewaySetupError::SocketCreationFailed(format!(
            "DoipGateway: Failed to create DoIP socket from std socket: {e:?}"
        ))
    })
}

impl<T: EcuAddresses + DoipComParams> Clone for DoipDiagGateway<T> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            config: self.config.clone(),
            variant_detection: self.variant_detection.clone(),
            connectivity_handler: Arc::clone(&self.connectivity_handler),
            lifecycle: Arc::clone(&self.lifecycle),
        }
    }
}

#[async_trait]
impl<T: EcuAddresses + DoipComParams> cda_interfaces::Shutdown for DoipDiagGateway<T> {
    async fn shutdown(&self) {
        if let Err(error) = self.disable().await {
            tracing::error!(%error, "Failed to disable DoIP communication during shutdown");
        }
    }
}

#[async_trait]
impl<T: EcuAddresses + DoipComParams> TransportControl for DoipDiagGateway<T> {
    async fn enable(&self) -> Result<(), CommControlError> {
        let mut operation = self.lifecycle.operation.lock().await;
        if self.lifecycle.coordinator.active().await {
            return Ok(());
        }
        // Clean up any residual resources, usually should be a no-op
        self.stop(&mut operation).await;
        self.lifecycle
            .coordinator
            .transition(TransportState::Enabling)
            .await;
        match self.start(&mut operation).await {
            Ok(()) => {
                self.lifecycle
                    .coordinator
                    .transition(TransportState::Enabled)
                    .await;
                Ok(())
            }
            Err(error) => {
                self.stop(&mut operation).await;
                self.lifecycle
                    .coordinator
                    .transition(TransportState::Failed)
                    .await;
                Err(CommControlError::InitFailed(error.to_string()))
            }
        }
    }

    async fn disable(&self) -> Result<(), CommControlError> {
        let mut operation = self.lifecycle.operation.lock().await;
        self.lifecycle
            .coordinator
            .transition(TransportState::Disabling)
            .await;
        self.stop(&mut operation).await;
        self.lifecycle
            .coordinator
            .transition(TransportState::Disabled)
            .await;
        Ok(())
    }

    async fn state(&self) -> TransportState {
        self.lifecycle.coordinator.state().await
    }
}

async fn send_with_retries(
    msg: &DiagnosticMessage,
    sender: &mpsc::Sender<DoipPayload>,
    resend_counter: &mut u32,
    max_retries: u32,
) -> Result<(), DiagServiceError> {
    while let Err(e) = sender
        .send(DoipPayload::DiagnosticMessage(msg.clone()))
        .await
    {
        *resend_counter = resend_counter.saturating_add(1);
        if *resend_counter > max_retries {
            return Err(DiagServiceError::SendFailed(format!(
                "Failed to send message after {max_retries} attempts: {e:?}",
            )));
        }
    }
    Ok(())
}

#[tracing::instrument(skip_all,
    fields(dlt_context = dlt_ctx!("DOIP"))
)]
async fn try_send_transport_response(
    response_sender: &mpsc::Sender<Result<Option<TransportResponse>, DiagServiceError>>,
    response: Result<Option<TransportResponse>, DiagServiceError>,
) -> bool {
    if let Err(err) = response_sender.send(response).await {
        tracing::error!(error = %err, "Failed to send response");
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use std::{net::UdpSocket, sync::Arc, time::Duration};

    use cda_interfaces::{
        DiagServiceError, DoipComParams, EcuAddresses, EcuConnectivityHandler, HashMap,
        HashMapExtensions, PendingNrc, PhysicalTransport, ServicePayload, TransmissionParameters,
        TransportResponse, UDS_ID_RESPONSE_BITMASK, VariantDetectionSender,
        communication_control::{GatewayLifecycle, TransportState},
        nrc, service_ids,
    };
    use doip_definitions::{
        header::ProtocolVersion,
        payload::{DiagnosticMessage, DoipPayload},
    };
    use tokio::sync::{Mutex, RwLock, broadcast, mpsc};

    use crate::{
        DiagnosticResponse, DoIPUdpSocket, DoipConfig, DoipConnection, DoipDiagGateway, DoipEcu,
        DoipGatewayState, read_ecu_responses, wait_for_ack_or_response_until_timeout,
    };

    const ECU_ADDR: u16 = 0x0E80;
    const GATEWAY_ADDR: u16 = 0x1234;
    const TESTER_ADDR: u16 = 0x0E00;
    const PAYLOAD: [u8; 2] = [0xF1, 0x90];
    const REQUEST_DATA: [u8; 3] = [service_ids::READ_DATA_BY_IDENTIFIER, PAYLOAD[0], PAYLOAD[1]];
    const RESPONSE_DATA: [u8; 4] = [
        service_ids::READ_DATA_BY_IDENTIFIER | UDS_ID_RESPONSE_BITMASK,
        PAYLOAD[0],
        PAYLOAD[1],
        0x01,
    ];

    /// Minimal stub that satisfies the `EcuAddresses + DoipComParams` bounds on
    /// `DoipDiagGateway<T>`.  The methods are never called during `send()` once
    /// the ECU mutex has been resolved, so every body is `unimplemented!()`.
    #[derive(Clone)]
    struct TestEcu;

    struct TestConnectivityHandler;

    #[async_trait::async_trait]
    impl EcuConnectivityHandler for TestConnectivityHandler {
        async fn on_gateway_connected(&self, _ecu_names: &[String]) {}

        async fn on_gateway_disconnected(&self, _ecu_names: &[String]) {}
    }

    impl EcuAddresses for TestEcu {
        fn tester_address(&self) -> u16 {
            unimplemented!()
        }
        fn logical_address(&self) -> u16 {
            unimplemented!()
        }
        fn logical_gateway_address(&self) -> u16 {
            unimplemented!()
        }
        fn logical_functional_address(&self) -> u16 {
            unimplemented!()
        }
        fn ecu_name(&self) -> String {
            unimplemented!()
        }
        fn logical_address_eq<T: EcuAddresses>(&self, _other: &T) -> bool {
            unimplemented!()
        }
    }

    impl DoipComParams for TestEcu {
        fn nack_number_of_retries(&self) -> &HashMap<u8, u32> {
            unimplemented!()
        }
        fn diagnostic_ack_timeout(&self) -> Duration {
            unimplemented!()
        }
        fn retry_period(&self) -> Duration {
            unimplemented!()
        }
        fn routing_activation_timeout(&self) -> Duration {
            unimplemented!()
        }
        fn repeat_request_count_transmission(&self) -> u32 {
            unimplemented!()
        }
        fn connection_timeout(&self) -> Duration {
            unimplemented!()
        }
        fn connection_retry_delay(&self) -> Duration {
            unimplemented!()
        }
        fn connection_retry_attempts(&self) -> u32 {
            unimplemented!()
        }
    }

    /// Builds a minimal `DoipDiagGateway` whose single ECU is backed by the
    /// caller-supplied broadcast receiver and mpsc sender.
    ///
    /// The mpsc `_doip_payload_rx` must be kept alive by the caller for the
    /// duration of the test; `send_with_retries` writes into it and will error
    /// if the receiver is dropped before it gets a chance to send.
    fn make_gateway(
        broadcast_rx: broadcast::Receiver<Result<DiagnosticResponse, crate::connections::EcuError>>,
        doip_payload_tx: mpsc::Sender<DoipPayload>,
    ) -> DoipDiagGateway<TestEcu> {
        let ecu = Arc::new(Mutex::new(DoipEcu {
            sender: doip_payload_tx,
            receiver: broadcast_rx,
        }));

        let mut ecus = HashMap::new();
        ecus.insert(ECU_ADDR, ecu);
        let conn = Arc::new(DoipConnection {
            ecus,
            ip: "127.0.0.1".to_owned(),
        });

        // DoIPUdpSocket is never touched during send()
        let std_sock = UdpSocket::bind("127.0.0.1:0").expect("bind test socket");
        std_sock
            .set_nonblocking(true)
            .expect("set nonblocking for test socket");
        let udp_socket = DoIPUdpSocket::new(std_sock, ProtocolVersion::Iso13400_2012)
            .expect("create test DoIPUdpSocket");

        let mut addr_map: HashMap<u16, usize> = HashMap::new();
        addr_map.insert(GATEWAY_ADDR, 0);

        let state = DoipGatewayState {
            doip_connections: Arc::new(RwLock::new(vec![conn])),
            logical_address_to_connection: Arc::new(RwLock::new(addr_map)),
            ecus: Arc::new(HashMap::new()),
            socket: Arc::new(Mutex::new(Some(udp_socket))),
            netmask: 0,
        };

        DoipDiagGateway {
            state,
            config: DoipConfig::default(),
            variant_detection: VariantDetectionSender::new(mpsc::channel(1).0),
            connectivity_handler: Arc::new(TestConnectivityHandler),
            lifecycle: Arc::new(GatewayLifecycle::new(TransportState::Enabled)),
        }
    }

    /// Constructing a gateway must never create or bind a UDP socket,
    /// even though construction succeeds.
    /// The socket is created lazily inside `start()`, reached only through an
    /// authorized [`DoipDiagGateway::enable`]
    #[tokio::test]
    async fn new_never_binds_the_doip_socket() {
        let gateway = DoipDiagGateway::<TestEcu>::new(
            &DoipConfig::default(),
            Arc::new(HashMap::new()),
            VariantDetectionSender::new(mpsc::channel(1).0),
            Arc::new(TestConnectivityHandler),
        )
        .await
        .unwrap();

        assert!(
            gateway.state.socket.lock().await.is_none(),
            "DoipDiagGateway::new must not bind a socket"
        );
        assert_eq!(
            cda_interfaces::communication_control::TransportControl::state(&gateway).await,
            TransportState::Disabled
        );
    }

    fn transmission_params() -> TransmissionParameters {
        TransmissionParameters {
            gateway_address: GATEWAY_ADDR,
            timeout_ack: Duration::from_secs(1),
            ecu_name: "test-ecu".to_owned(),
            repeat_request_count_transmission: 0,
        }
    }

    fn service_payload() -> ServicePayload {
        ServicePayload {
            data: REQUEST_DATA.to_vec(),
            source_address: TESTER_ADDR,
            target_address: ECU_ADDR,
            new_session: None,
            new_security: None,
        }
    }

    fn ecu_msg_response() -> DiagnosticResponse {
        DiagnosticResponse::Msg {
            source_address: ECU_ADDR,
            target_address: TESTER_ADDR,
            data: RESPONSE_DATA.to_vec(),
        }
    }

    fn diag_msg() -> DiagnosticMessage {
        DiagnosticMessage {
            source_address: TESTER_ADDR.to_be_bytes(),
            target_address: ECU_ADDR.to_be_bytes(),
            message: REQUEST_DATA.to_vec(),
        }
    }

    type BroadcastTx = broadcast::Sender<Result<DiagnosticResponse, crate::connections::EcuError>>;

    fn make_broadcast_pair() -> (
        BroadcastTx,
        broadcast::Receiver<Result<DiagnosticResponse, crate::connections::EcuError>>,
    ) {
        broadcast::channel(16)
    }

    type ResponseChannel = (
        mpsc::Sender<Result<Option<TransportResponse>, DiagServiceError>>,
        mpsc::Receiver<Result<Option<TransportResponse>, DiagServiceError>>,
    );

    fn make_response_channel() -> ResponseChannel {
        mpsc::channel(1)
    }

    type SendResult = Result<tokio::task::JoinHandle<()>, cda_interfaces::DiagServiceError>;
    type ResponseItem = Result<Option<TransportResponse>, cda_interfaces::DiagServiceError>;

    /// Shared test harness.
    ///
    /// Owns every channel handle that must stay alive for the duration of a
    /// test:
    /// - `broadcast_tx` - injects simulated ECU responses.
    /// - `_doip_payload_rx` - keeps the mpsc sender alive so `send_with_retries`
    ///   does not error out trying to write the outgoing `DoIP` frame.
    /// - `send_handle` - join handle for the background `send()` task.
    /// - `response_rx` - receives the UDS responses forwarded by `send()`.
    struct TestHarness {
        broadcast_tx: broadcast::Sender<Result<DiagnosticResponse, crate::connections::EcuError>>,
        _doip_payload_rx: mpsc::Receiver<DoipPayload>,
        send_handle: tokio::task::JoinHandle<SendResult>,
        response_rx: mpsc::Receiver<ResponseItem>,
    }

    impl TestHarness {
        /// Creates the gateway, spawns the `send()` task, and advances it past
        /// `clear_pending_messages` to the point where it is blocked on
        /// `ecu.receiver.recv()` inside the `'ack_waiting` loop.
        ///
        /// Uses `current_thread` flavor (see test attributes) so that
        /// `yield_now()` is a reliable synchronization primitive: on a
        /// cooperative single-threaded executor each yield hands control to
        /// exactly the next scheduled task.  The spawned task must pass through
        /// the following `.await` points before reaching `recv()`:
        ///
        ///   1. `ecu_mtx.lock().await` - acquires the ECU mutex
        ///   2. `send_with_retries(...).await` - writes the outgoing `DoIP` frame
        ///   3. `tokio::time::timeout(...)` - enters the ACK-wait future
        ///   4. `ecu.receiver.recv().await` - now blocked, ready for injection
        ///
        /// Crucially, `clear_pending_messages` runs between steps 1 and 2.
        /// We must yield past it before calling `broadcast_tx.send()`, otherwise
        /// the injected message would be drained and the task would block forever.
        /// One `yield_now()` per await point, plus one safety margin = 5 total.
        async fn new() -> Self {
            let (broadcast_tx, broadcast_rx) =
                broadcast::channel::<Result<DiagnosticResponse, crate::connections::EcuError>>(1);
            let (doip_payload_tx, doip_payload_rx) = mpsc::channel::<DoipPayload>(1);

            let gateway = make_gateway(broadcast_rx, doip_payload_tx);

            let (response_tx, response_rx) = mpsc::channel::<ResponseItem>(1);
            let send_handle = tokio::spawn({
                let gateway = gateway.clone();
                async move {
                    gateway
                        .send(transmission_params(), service_payload(), response_tx, true)
                        .await
                }
            });

            for _ in 0..5 {
                tokio::task::yield_now().await;
            }

            Self {
                broadcast_tx,
                _doip_payload_rx: doip_payload_rx,
                send_handle,
                response_rx,
            }
        }

        /// Waits for the next response from the background `send()` task.
        ///
        /// Uses `tokio::time::timeout` rather than `try_recv()`, so no
        /// yield counting is needed after injecting a broadcast message.
        async fn recv_response(&mut self) -> ResponseItem {
            tokio::time::timeout(Duration::from_millis(500), self.response_rx.recv())
                .await
                .expect("timed out waiting for response from send() task")
                .expect("response channel closed unexpectedly")
        }
    }

    // current_thread: yield_now() in TestHarness::new() must be a reliable sync point.
    #[tokio::test(flavor = "current_thread")]
    async fn implicit_ack_busy_retry_then_final_response() {
        let mut harness = TestHarness::new().await;

        // ECU sends BusyRepeatRequest (NRC 0x21) via the implicit-ACK path:
        // the DiagnosticMessage arrives before the ACK, so
        // wait_for_ack_or_response_until_timeout returns it directly as the
        // seed for read_ecu_responses instead of waiting for a separate ACK.
        harness
            .broadcast_tx
            .send(Ok(DiagnosticResponse::Msg {
                source_address: ECU_ADDR,
                target_address: TESTER_ADDR,
                data: vec![
                    service_ids::NEGATIVE_RESPONSE,
                    REQUEST_DATA[0],
                    nrc::BUSY_REPEAT_REQUEST,
                ],
            }))
            .expect("Failed to sent busy repeat request");
        let first = harness.recv_response().await;
        assert!(
            matches!(
                first,
                Ok(Some(TransportResponse::Pending(
                    PendingNrc::BusyRepeatRequest { .. }
                )))
            ),
            "expected BusyRepeatRequest, got {first:?}"
        );

        // ECU sends the final Msg.
        harness
            .broadcast_tx
            .send(Ok(ecu_msg_response()))
            .expect("Failed to sent final message");
        let second = harness.recv_response().await;
        assert!(
            matches!(second, Ok(Some(TransportResponse::UdsResponse(_)))),
            "expected Message, got {second:?}"
        );

        drop(harness.response_rx);
        tokio::time::timeout(Duration::from_secs(2), harness.send_handle)
            .await
            .expect("send task did not finish")
            .expect("send task panicked")
            .expect("send() returned an error");
    }

    // current_thread: yield_now() in TestHarness::new() must be a reliable sync point.
    #[tokio::test(flavor = "current_thread")]
    async fn implicit_ack_single_response() {
        let mut harness = TestHarness::new().await;

        // ECU sends a single Msg - no ACK (implicit ACK path).
        harness
            .broadcast_tx
            .send(Ok(ecu_msg_response()))
            .expect("Failed to sent message");
        let response = harness.recv_response().await;
        assert!(
            matches!(response, Ok(Some(TransportResponse::UdsResponse(_)))),
            "expected Message, got {response:?}"
        );

        // No further messages; dropping the receiver unblocks read_ecu_responses.
        drop(harness.response_rx);
        tokio::time::timeout(Duration::from_secs(2), harness.send_handle)
            .await
            .expect("send task did not finish")
            .expect("send task panicked")
            .expect("send() returned an error");
    }
    #[tokio::test]
    async fn wait_for_ack_or_response_ok_none_on_explicit_ack() {
        let (tx, mut rx) = make_broadcast_pair();
        let msg = diag_msg();
        tx.send(Ok(DiagnosticResponse::Ack((ECU_ADDR, vec![]))))
            .expect("Failed to send ack");

        let result = wait_for_ack_or_response_until_timeout(
            &mut rx,
            "test-ecu",
            &msg,
            Duration::from_secs(1),
        )
        .await;
        assert!(
            matches!(result, Ok(None)),
            "expected Ok(None), got {result:?}"
        );
    }

    /// A `DiagnosticMessage` received before the ACK triggers the implicit-ACK
    /// path: the response is returned as `Ok(Some(_))` for the caller to seed
    /// into `read_ecu_responses`.
    #[tokio::test]
    async fn wait_for_ack_or_response_ok_some_on_diagnostic_msg() {
        let (tx, mut rx) = make_broadcast_pair();
        let msg = diag_msg();
        tx.send(Ok(ecu_msg_response()))
            .expect("Failed to send message");

        let result = wait_for_ack_or_response_until_timeout(
            &mut rx,
            "test-ecu",
            &msg,
            Duration::from_secs(1),
        )
        .await;

        assert!(
            matches!(result, Ok(Some(DiagnosticResponse::Msg { .. }))),
            "expected Ok(Some(Diagnostic)), got {result:?}"
        );
    }

    /// `BusyRepeatRequest` before the ACK also returns `Ok(Some(_))`.
    #[tokio::test]
    async fn wait_for_ack_or_response_ok_some_on_busy_repeat_request() {
        let (tx, mut rx) = make_broadcast_pair();
        let msg = diag_msg();

        tx.send(Ok(DiagnosticResponse::Msg {
            source_address: ECU_ADDR,
            target_address: TESTER_ADDR,
            data: vec![
                service_ids::NEGATIVE_RESPONSE,
                REQUEST_DATA[0],
                nrc::BUSY_REPEAT_REQUEST,
            ],
        }))
        .expect("Failed to busy repeat request");

        let result = wait_for_ack_or_response_until_timeout(
            &mut rx,
            "test-ecu",
            &msg,
            Duration::from_secs(1),
        )
        .await;

        assert!(
            matches!(result, Ok(Some(DiagnosticResponse::Msg { .. }))),
            "expected Ok(Some(Diagnostic(BusyRepeatRequest NRC))), got {result:?}"
        );
    }

    /// A `DiagnosticMessageNack` returns `Err(Nack(_))`.
    #[tokio::test]
    async fn wait_for_ack_or_response_err_on_nack() {
        use doip_definitions::payload::{DiagnosticMessageNack, DiagnosticNackCode};

        let (tx, mut rx) = make_broadcast_pair();
        let msg = diag_msg();

        tx.send(Ok(DiagnosticResponse::Nack(DiagnosticMessageNack {
            source_address: ECU_ADDR.to_be_bytes(),
            target_address: TESTER_ADDR.to_be_bytes(),
            nack_code: DiagnosticNackCode::UnknownTargetAddress,
        })))
        .expect("Failed to send nack");

        let result = wait_for_ack_or_response_until_timeout(
            &mut rx,
            "test-ecu",
            &msg,
            Duration::from_secs(1),
        )
        .await;

        assert!(
            matches!(result, Err(DiagServiceError::Nack(_))),
            "expected Nack, got {result:?}"
        );
    }

    /// A `GenericNack` returns `Err(Nack(_))`.
    #[tokio::test]
    async fn wait_for_ack_or_response_err_on_generic_nack() {
        use doip_definitions::payload::{GenericNack, NackCode};

        let (tx, mut rx) = make_broadcast_pair();
        let msg = diag_msg();

        tx.send(Ok(DiagnosticResponse::GenericNack(GenericNack {
            nack_code: NackCode::InvalidPayloadLength,
        })))
        .expect("Failed to send generic nack");

        let result = wait_for_ack_or_response_until_timeout(
            &mut rx,
            "test-ecu",
            &msg,
            Duration::from_secs(1),
        )
        .await;

        assert!(
            matches!(result, Err(DiagServiceError::Nack(_))),
            "expected Nack, got {result:?}"
        );
    }

    /// When the timeout expires with no message, `Err(Timeout)` is returned.
    #[tokio::test]
    async fn wait_for_ack_or_response_err_on_timeout() {
        let (_tx, mut rx) = make_broadcast_pair();
        let msg = diag_msg();

        let result = wait_for_ack_or_response_until_timeout(
            &mut rx,
            "test-ecu",
            &msg,
            Duration::from_millis(200),
        )
        .await;

        assert!(
            matches!(result, Err(DiagServiceError::Timeout)),
            "expected Timeout, got {result:?}"
        );
    }

    /// When the broadcast receiver is closed, `Err(NoResponse(_))` is returned.
    #[tokio::test]
    async fn wait_for_ack_or_response_err_when_receiver_closed() {
        let (tx, mut rx) = make_broadcast_pair();
        let msg = diag_msg();

        drop(tx);

        let result = wait_for_ack_or_response_until_timeout(
            &mut rx,
            "test-ecu",
            &msg,
            Duration::from_secs(1),
        )
        .await;

        assert!(
            matches!(result, Err(DiagServiceError::NoResponse(_))),
            "expected NoResponse, got {result:?}"
        );
    }

    /// An unrelated message type (e.g. `AliveCheckResponse`) must be skipped;
    /// the loop should continue until the real ACK arrives.
    #[tokio::test]
    async fn wait_for_ack_or_response_skips_unrelated_messages() {
        let (tx, mut rx) = make_broadcast_pair();
        let msg = diag_msg();

        tx.send(Ok(DiagnosticResponse::AliveCheckResponse))
            .expect("Failed to send alive check response");
        tx.send(Ok(DiagnosticResponse::Ack((ECU_ADDR, vec![]))))
            .expect("Failed to send ack");

        let result = wait_for_ack_or_response_until_timeout(
            &mut rx,
            "test-ecu",
            &msg,
            Duration::from_secs(1),
        )
        .await;

        drop(tx);
        assert!(
            matches!(result, Ok(None)),
            "expected Ok(None), got {result:?}"
        );
    }

    #[tokio::test]
    async fn read_ecu_responses_forwards_message_and_exits_on_sender_close() {
        let (tx, mut rx) = make_broadcast_pair();
        let (resp_tx, mut resp_rx) = make_response_channel();

        tx.send(Ok(ecu_msg_response()))
            .expect("Failed to send message");

        // Spawn the response reader in a separate task.
        let handle = tokio::spawn(async move {
            read_ecu_responses(&mut rx, "test-ecu", &resp_tx, None).await;
        });

        // Read the forwarded Msg.
        let item = tokio::time::timeout(Duration::from_secs(1), resp_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert!(
            matches!(item, Ok(Some(TransportResponse::UdsResponse(_)))),
            "expected Message, got {item:?}"
        );

        // Drop the receiver to close the sender; the loop should exit.
        drop(resp_rx);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("read_ecu_responses did not exit after sender closed")
            .expect("task panicked");
    }

    #[tokio::test]
    async fn read_ecu_responses_forwards_multiple_responses() {
        let (tx, mut rx) = make_broadcast_pair();
        let (resp_tx, mut resp_rx) = make_response_channel();
        tx.send(Ok(DiagnosticResponse::Msg {
            source_address: ECU_ADDR,
            target_address: TESTER_ADDR,
            data: vec![
                service_ids::NEGATIVE_RESPONSE,
                REQUEST_DATA[0],
                nrc::RESPONSE_PENDING,
            ],
        }))
        .expect("Failed to send pending response");
        tx.send(Ok(ecu_msg_response()))
            .expect("Failed to send response");
        // Keep tx alive across awaits so the channel is not closed while the
        // spawned task is reading buffered messages.
        let _tx = tx;

        let handle = tokio::spawn(async move {
            read_ecu_responses(&mut rx, "test-ecu", &resp_tx, None).await;
        });

        let first = tokio::time::timeout(Duration::from_secs(1), resp_rx.recv())
            .await
            .expect("timeout")
            .expect("closed");
        assert!(
            matches!(
                first,
                Ok(Some(TransportResponse::Pending(
                    PendingNrc::ResponsePending { .. }
                )))
            ),
            "expected ResponsePending, got {first:?}"
        );

        let second = tokio::time::timeout(Duration::from_secs(1), resp_rx.recv())
            .await
            .expect("timeout")
            .expect("closed");
        assert!(
            matches!(second, Ok(Some(TransportResponse::UdsResponse(_)))),
            "expected Message, got {second:?}"
        );

        drop(resp_rx);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("task did not exit")
            .expect("task panicked");
    }

    /// When `first` is `Some`, it is forwarded before reading from the receiver -
    /// this is the implicit-ACK seed path.
    #[tokio::test]
    async fn read_ecu_responses_forwards_first_then_receiver() {
        let (tx, mut rx) = make_broadcast_pair();
        let (resp_tx, mut resp_rx) = make_response_channel();

        let first = ecu_msg_response();
        tx.send(Ok(DiagnosticResponse::Msg {
            source_address: ECU_ADDR,
            target_address: TESTER_ADDR,
            data: vec![
                service_ids::NEGATIVE_RESPONSE,
                REQUEST_DATA[0],
                nrc::RESPONSE_PENDING,
            ],
        }))
        .expect("Failed to send pending response");
        let _tx = tx;

        let handle = tokio::spawn(async move {
            read_ecu_responses(&mut rx, "test-ecu", &resp_tx, Some(first)).await;
        });

        let first_item = tokio::time::timeout(Duration::from_secs(1), resp_rx.recv())
            .await
            .expect("timeout")
            .expect("closed");
        assert!(
            matches!(first_item, Ok(Some(TransportResponse::UdsResponse(_)))),
            "expected Message from first, got {first_item:?}"
        );

        let second_item = tokio::time::timeout(Duration::from_secs(1), resp_rx.recv())
            .await
            .expect("timeout")
            .expect("closed");
        assert!(
            matches!(
                second_item,
                Ok(Some(TransportResponse::Pending(
                    PendingNrc::ResponsePending { .. }
                )))
            ),
            "expected ResponsePending from receiver, got {second_item:?}"
        );

        drop(resp_rx);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("task did not exit")
            .expect("task panicked");
    }
}
