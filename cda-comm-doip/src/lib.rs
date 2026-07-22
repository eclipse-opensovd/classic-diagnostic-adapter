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
    future::Future,
    sync::Arc,
    time::{Duration, Instant},
};

use cda_interfaces::{
    DiagServiceError, DoipComParams, EcuAddresses, EcuConnectivityHandler, EcuGateway, HashMap,
    HashMapExtensions, ServicePayload, TransmissionParameters, TransportResponse, dlt_ctx,
    pending_nrc_from_raw, uds_response_from_raw,
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
    task::{JoinError, JoinSet},
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
    Ack((u16, Vec<u8>)),
    Nack(DiagnosticMessageNack),
    AliveCheckResponse,
    /// `TesterPresent` NRC -- intercepted at the decoding layer so the receiver
    /// can log-and-drop without routing it to a per-ECU channel.
    TesterPresentNRC(u8),
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
    pub(crate) socket: Arc<Mutex<DoIPUdpSocket>>,
    pub(crate) connection_tasks: Arc<Mutex<JoinSet<Result<(), JoinError>>>>,
}

impl<T: EcuAddresses + DoipComParams> Clone for DoipGatewayState<T> {
    fn clone(&self) -> Self {
        Self {
            doip_connections: Arc::clone(&self.doip_connections),
            logical_address_to_connection: Arc::clone(&self.logical_address_to_connection),
            ecus: Arc::clone(&self.ecus),
            socket: Arc::clone(&self.socket),
            connection_tasks: Arc::clone(&self.connection_tasks),
        }
    }
}

pub struct DoipDiagGateway<T: EcuAddresses + DoipComParams> {
    state: DoipGatewayState<T>,
    cancel_token: CancellationToken,
    vam_listener_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
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
    /// # Errors
    /// Returns `String` if initialization fails, e.g. when socket creation fails.
    #[tracing::instrument(
        skip(doip_config, ecus, variant_detection, connectivity_handler, shutdown_signal, doip_socket),
        fields(
            tester_ip = doip_config.tester_address,
            gateway_port = doip_config.gateway_port,
            ecu_count = ecus.len(),
            dlt_context = dlt_ctx!("DOIP")
        )
    )]
    pub async fn new<F>(
        doip_config: &DoipConfig,
        ecus: Arc<HashMap<String, RwLock<T>>>,
        variant_detection: mpsc::Sender<Vec<String>>,
        connectivity_handler: Arc<dyn EcuConnectivityHandler>,
        shutdown_signal: F,
        doip_socket: Arc<Mutex<DoIPUdpSocket>>,
    ) -> Result<Self, DoipGatewaySetupError>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let DoipConfig {
            tester_address: tester_ip,
            tester_subnet,
            gateway_port,
            tls_port,
            send_timeout_ms,
            send_diagnostic_message_ack,
            alive_check_interval_secs,
            ..
        } = doip_config;
        let gateway_port = *gateway_port;
        let transport_config = DoipTransportConfig {
            tester_ip: tester_ip.to_owned(),
            port: gateway_port,
            tls_port: *tls_port,
            send_diagnostic_message_ack: *send_diagnostic_message_ack,
            send_timeout: Duration::from_millis(*send_timeout_ms),
            alive_check_interval: Duration::from_secs(*alive_check_interval_secs),
        };

        tracing::info!("Initializing DoipDiagGateway");

        let mask = create_netmask(tester_ip, tester_subnet)?;

        let shared_shutdown_signal = shutdown_signal.shared();
        let gateways = vir_vam::get_vehicle_identification::<T, F>(
            &mut *doip_socket.lock().await,
            mask,
            gateway_port,
            &ecus,
            shared_shutdown_signal.clone(),
        )
        .await
        .map_err(|err| {
            DoipGatewaySetupError::ResourceError(format!(
                "Could not get vehicle identification. {err}"
            ))
        })?;

        let cancel_token = CancellationToken::new();

        let connection_tasks = Arc::new(Mutex::new(JoinSet::new()));

        let state = if gateways.is_empty() {
            DoipGatewayState {
                doip_connections: Arc::new(RwLock::new(Vec::new())),
                logical_address_to_connection: Arc::new(RwLock::new(HashMap::new())),
                ecus,
                socket: Arc::clone(&doip_socket),
                connection_tasks,
            }
        } else {
            tracing::info!(gateway_count = gateways.len(), "Gateways found");

            // create mapping gateway_logical_address -> Vec<ecu_logical_address>
            let mut gateway_ecu_map: HashMap<u16, Vec<u16>> = HashMap::new();
            let mut gateway_ecu_name_map: HashMap<u16, Vec<String>> = HashMap::new();
            for ecu_lock in ecus.values() {
                let ecu = ecu_lock.read().await;
                let addr = ecu.logical_address();
                let gateway = ecu.logical_gateway_address();
                gateway_ecu_map.entry(gateway).or_default().push(addr);
                gateway_ecu_name_map
                    .entry(gateway)
                    .or_default()
                    .push(ecu.ecu_name().to_lowercase());
            }

            let doip_connections: Arc<RwLock<Vec<Arc<DoipConnection>>>> =
                Arc::new(RwLock::new(Vec::new()));
            let mut logical_address_to_connection = HashMap::new();

            for gateway in gateways {
                if let Ok(logical_address) = connections::handle_gateway_connection::<T>(
                    gateway,
                    &transport_config,
                    &GatewayState {
                        doip_connections: Arc::clone(&doip_connections),
                        ecus: Arc::clone(&ecus),
                        gateway_ecu_map: gateway_ecu_map.clone(),
                        connection_tasks: Arc::clone(&connection_tasks),
                    },
                    Arc::clone(&connectivity_handler),
                )
                .await
                {
                    logical_address_to_connection.insert(
                        logical_address,
                        doip_connections.read().await.len().saturating_sub(1),
                    );
                }
            }

            DoipGatewayState {
                doip_connections,
                logical_address_to_connection: Arc::new(RwLock::new(logical_address_to_connection)),
                ecus,
                socket: Arc::clone(&doip_socket),
                connection_tasks,
            }
        };

        let vam_listener_handle = vir_vam::listen_for_vams(
            transport_config,
            mask,
            state.clone(),
            variant_detection,
            connectivity_handler,
            shared_shutdown_signal,
            cancel_token.child_token(),
        )
        .await;

        Ok(DoipDiagGateway {
            state,
            cancel_token,
            vam_listener_handle: Arc::new(Mutex::new(Some(vam_listener_handle))),
        })
    }

    /// Returns a clone of the UDP socket Arc for reuse in a new gateway instance.
    /// This avoids binding a second socket on the same port during reloads.
    #[must_use]
    pub fn udp_socket(&self) -> Arc<Mutex<DoIPUdpSocket>> {
        Arc::clone(&self.state.socket)
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

impl<T: EcuAddresses + DoipComParams> EcuGateway for DoipDiagGateway<T> {
    async fn shutdown(&mut self) {
        self.cancel_token.cancel();

        if let Some(vam_listener_handle) = self.vam_listener_handle.lock().await.take() {
            // Abort and await the VAM listener task so it stops reading from the
            // shared UDP socket before a new gateway reuses it.
            vam_listener_handle.abort();
            let _ = vam_listener_handle.await;
        }

        // Abort all background tasks (sender, receiver, connection-reset) for each
        // gateway connection. This immediately drops their TCP socket halves.
        let connections = self.state.doip_connections.write().await;
        let mut tasks = self.state.connection_tasks.lock().await;
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        drop(tasks);
        drop(connections);
        self.state.doip_connections.write().await.clear();
    }

    async fn get_gateway_network_address(&self, logical_address: u16) -> Option<String> {
        self.state
            .doip_connections
            .read()
            .await
            .iter()
            .find(|conn| conn.ecus.contains_key(&logical_address))
            .map(|conn| conn.ip.clone())
    }

    #[tracing::instrument(skip_all,
        fields(dlt_context = dlt_ctx!("DOIP"))
    )]

    async fn send(
        &self,
        transmission_params: TransmissionParameters,
        message: ServicePayload,
        response_sender: mpsc::Sender<Result<Option<TransportResponse>, DiagServiceError>>,
        expect_uds_reply: bool,
    ) -> Result<(), DiagServiceError> {
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

        cda_interfaces::spawn_named!(
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

        Ok(())
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
        && !try_send_transport_response(response_sender, doip_event_to_transport(event)).await
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
                                doip_event_to_transport(event),
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
fn doip_event_to_transport(
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
            cancel_token: self.cancel_token.clone(),
            vam_listener_handle: Arc::clone(&self.vam_listener_handle),
        }
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
        DiagServiceError, DoipComParams, EcuAddresses, EcuGateway, HashMap, HashMapExtensions,
        PendingNrc, ServicePayload, TransmissionParameters, TransportResponse,
        UDS_ID_RESPONSE_BITMASK, nrc, service_ids,
    };
    use doip_definitions::{
        header::ProtocolVersion,
        payload::{DiagnosticMessage, DoipPayload},
    };
    use tokio::{
        sync::{Mutex, RwLock, broadcast, mpsc},
        task::JoinSet,
    };
    use tokio_util::sync::CancellationToken;

    use crate::{
        DiagnosticResponse, DoIPUdpSocket, DoipConnection, DoipDiagGateway, DoipEcu,
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
            socket: Arc::new(Mutex::new(udp_socket)),
            connection_tasks: Arc::new(Mutex::new(JoinSet::new())),
        };

        DoipDiagGateway {
            state,
            cancel_token: CancellationToken::new(),
            vam_listener_handle: Arc::new(Mutex::new(None)),
        }
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

    type SendResult = Result<(), cda_interfaces::DiagServiceError>;
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
