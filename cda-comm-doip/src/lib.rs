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
    DiagServiceError, DoipComParams, DoipGatewaySetupError, EcuAddresses, EcuGateway, HashMap,
    HashMapExtensions, ServicePayload, TransmissionParameters, UdsResponse, dlt_ctx,
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
use thiserror::Error;
use tokio::sync::{Mutex, RwLock, broadcast, mpsc};
use tokio_util::sync::CancellationToken;

use crate::{
    config::DoipConfig,
    connections::{EcuError, GatewayState},
    socket::{DoIPUdpSocket, DoipSocketConfig},
};

pub mod config;
mod connections;
mod ecu_connection;
pub mod socket;
mod vir_vam;

/// Timeout when suppressPosRspMsgIndicationBit is set.
/// ECUs that reject a request usually respond quickly with an NRC and
/// this timeout window should be able to capture those while
/// not blocking for the full diagnostic timeout.
///
/// This constant is intentionally separate from `timeout_default` so it can be promoted to a
/// configuration entry, or a `ComParam` in a future iteration without changing the
/// surrounding logic.
const SUPPRESS_POSITIVE_RESPONSE_TIMEOUT: Duration = Duration::from_millis(500);

const NRC_BUSY_REPEAT_REQUEST: u8 = 0x21;
const NRC_RESPONSE_PENDING: u8 = 0x78;
const NRC_TEMPORARILY_NOT_AVAILABLE: u8 = 0x94;

#[derive(Debug, Clone)]
enum DiagnosticResponse {
    Msg(DiagnosticMessage),
    Pending(u16),
    Ack((u16, Vec<u8>)),
    Nack(DiagnosticMessageNack),
    AliveCheckResponse,
    TesterPresentNRC(u8),
    GenericNack(GenericNack), // todo #22 -> we need the address of the ECU that sent the nack
    BusyRepeatRequest(u16),
    TemporarilyNotAvailable(u16),
}

pub(crate) struct DoipGatewayState<T: EcuAddresses + DoipComParams> {
    pub(crate) doip_connections: Arc<RwLock<Vec<Arc<DoipConnection>>>>,
    pub(crate) logical_address_to_connection: Arc<RwLock<HashMap<u16, usize>>>,
    pub(crate) ecus: Arc<HashMap<String, RwLock<T>>>,
    pub(crate) socket: Arc<Mutex<DoIPUdpSocket>>,
}

pub struct DoipDiagGateway<T: EcuAddresses + DoipComParams> {
    state: Arc<DoipGatewayState<T>>,
    cancel_token: CancellationToken,
    vam_listener_handle: Arc<tokio::task::JoinHandle<()>>,
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
    /// `DoIP` socket-level settings (protocol version, ack behavior).
    pub(crate) socket: DoipSocketConfig,
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
/// Carries `GatewayConnectionConfig` plus the data that is only needed during initial
/// channel creation (`ecus`) and reconnection signlling (`variant_detection`).
#[derive(Clone)]
pub(crate) struct GatewaySetup {
    pub(crate) connection: GatewayConnectionConfig,
    pub(crate) ecus: Vec<u16>,
    pub(crate) variant_detection: Option<(mpsc::Sender<Vec<String>>, Vec<String>)>,
}

struct DoipEcu {
    sender: mpsc::Sender<DoipPayload>,
    receiver: broadcast::Receiver<Result<DiagnosticResponse, EcuError>>,
}

struct DoipConnection {
    ecus: HashMap<u16, Arc<Mutex<DoipEcu>>>,
    ip: String,
    task_handles: Vec<tokio::task::JoinHandle<()>>,
}

#[derive(Error, Debug, Clone)]
pub enum ConnectionError {
    #[error("Connection closed.")]
    Closed,
    #[error("Decoding error: `{0}`")]
    Decoding(String),
    #[error("Invalid message: `{0}")]
    InvalidMessage(String),
    #[error("Connection timeout: `{0}`")]
    Timeout(String),
    #[error("Connection failed: `{0}`")]
    ConnectionFailed(String),
    #[error("Routing error: `{0}`")]
    RoutingError(String),
    #[error("Send failed: `{0}`")]
    SendFailed(String),
}

impl TryFrom<DiagnosticResponse> for Option<UdsResponse> {
    type Error = DiagServiceError;

    fn try_from(value: DiagnosticResponse) -> Result<Self, Self::Error> {
        match value {
            DiagnosticResponse::Msg(msg) => Ok(Some(UdsResponse::Message(ServicePayload {
                data: msg.message,
                source_address: u16::from_be_bytes(msg.source_address),
                target_address: u16::from_be_bytes(msg.target_address),
                new_session: None,
                new_security: None,
            }))),
            DiagnosticResponse::Pending(addr) => Ok(Some(UdsResponse::ResponsePending(addr))),
            DiagnosticResponse::BusyRepeatRequest(addr) => {
                Ok(Some(UdsResponse::BusyRepeatRequest(addr)))
            }
            DiagnosticResponse::TemporarilyNotAvailable(addr) => {
                Ok(Some(UdsResponse::TemporarilyNotAvailable(addr)))
            }
            DiagnosticResponse::TesterPresentNRC(code) => {
                Ok(Some(UdsResponse::TesterPresentNRC(code)))
            }
            _ => Err(DiagServiceError::BadPayload(
                "Unexpected response type for DiagnosticResponse to UdsResponse conversion"
                    .to_owned(),
            )),
        }
    }
}

impl<T: EcuAddresses + DoipComParams> DoipDiagGateway<T> {
    /// Create a new `DoipDiagGateway` instance.
    /// # Errors
    /// Returns `String` if initialization fails, e.g. when socket creation fails.
    #[tracing::instrument(
        skip(doip_config, ecus, variant_detection, shutdown_signal, doip_socket),
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
        shutdown_signal: F,
        doip_socket: Arc<Mutex<DoIPUdpSocket>>,
    ) -> Result<Self, DoipGatewaySetupError>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let DoipConfig {
            protocol_version,
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
            socket: DoipSocketConfig {
                protocol_version: ProtocolVersion::try_from(protocol_version).map_err(|err| {
                    DoipGatewaySetupError::InvalidConfiguration(format!(
                        "Invalid DoIP protocol version: {err}"
                    ))
                })?,
                send_diagnostic_message_ack: *send_diagnostic_message_ack,
            },
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

        let state = if gateways.is_empty() {
            Arc::new(DoipGatewayState {
                doip_connections: Arc::new(RwLock::new(Vec::new())),
                logical_address_to_connection: Arc::new(RwLock::new(HashMap::new())),
                ecus,
                socket: Arc::clone(&doip_socket),
            })
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
                let ecu_names_for_gateway = gateway_ecu_name_map
                    .get(&gateway.logical_address)
                    .cloned()
                    .unwrap_or_default();

                if let Ok(logical_address) = connections::handle_gateway_connection::<T>(
                    gateway,
                    &transport_config,
                    &GatewayState {
                        doip_connections: Arc::clone(&doip_connections),
                        ecus: Arc::clone(&ecus),
                        gateway_ecu_map: gateway_ecu_map.clone(),
                    },
                    Some((variant_detection.clone(), ecu_names_for_gateway)),
                )
                .await
                {
                    logical_address_to_connection.insert(
                        logical_address,
                        doip_connections.read().await.len().saturating_sub(1),
                    );
                }
            }

            Arc::new(DoipGatewayState {
                doip_connections,
                logical_address_to_connection: Arc::new(RwLock::new(logical_address_to_connection)),
                ecus,
                socket: Arc::clone(&doip_socket),
            })
        };

        let vam_listener_handle = vir_vam::listen_for_vams(
            transport_config,
            mask,
            Arc::clone(&state),
            variant_detection,
            shared_shutdown_signal,
            cancel_token.child_token(),
        )
        .await;

        Ok(DoipDiagGateway {
            state,
            cancel_token,
            vam_listener_handle: Arc::new(vam_listener_handle),
        })
    }

    pub async fn shutdown(&mut self) {
        self.cancel_token.cancel();
        // Abort and await the VAM listener task so it stops reading from the
        // shared UDP socket before a new gateway reuses it.
        self.vam_listener_handle.abort();
        // Abort all background tasks (sender, receiver, connection-reset) for each
        // gateway connection. This immediately drops their TCP socket halves.
        let connections = self.state.doip_connections.write().await;
        for conn in connections.iter() {
            for handle in &conn.task_handles {
                handle.abort();
            }
        }
        drop(connections);
        self.state.doip_connections.write().await.clear();
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
    async fn get_gateway_network_address(&self, logical_address: u16) -> Option<String> {
        self.state
            .doip_connections
            .read()
            .await
            .iter()
            .find(|conn| conn.ecus.contains_key(&logical_address))
            .map(|conn| conn.ip.clone())
    }

    // most of this function is handling different error cases and timeouts.
    // it is easier to comprehend when kept together.
    #[tracing::instrument(skip_all,
        fields(dlt_context = dlt_ctx!("DOIP"))
    )]
    #[allow(clippy::too_many_lines)]
    async fn send(
        &self,
        transmission_params: TransmissionParameters,
        message: ServicePayload,
        response_sender: mpsc::Sender<Result<Option<UdsResponse>, DiagServiceError>>,
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
                        try_send_uds_response(&response_sender, Err(e)).await;
                        return;
                    }

                    // allow continue expression here
                    // as it makes it more clear on what exactly is happening.
                    #[allow(clippy::needless_continue)]
                    if let Ok(ack_received) =
                        tokio::time::timeout(transmission_params.timeout_ack, async {
                            'ack_waiting: loop {
                                if let Ok(result) = ecu.receiver.recv().await {
                                    match result {
                                        Ok(DiagnosticResponse::Ack((_, prev))) => {
                                            tracing::debug!(
                                                ecu_name = %transmission_params.ecu_name,
                                                "Received ACK"
                                            );
                                            if !prev.is_empty()
                                                && !doip_message.message.starts_with(&prev)
                                            {
                                                tracing::warn!(
                                                    previous = %util::tracing::print_hex(
                                                        &prev, 8
                                                    ),
                                                    sent = %util::tracing::print_hex(
                                                        &doip_message.message, 8
                                                    ),
                                                    "ACK previous message does \
                                                    not match sent message"
                                                );
                                                continue 'ack_waiting;
                                            }
                                            break 'ack_waiting true;
                                        }
                                        Ok(DiagnosticResponse::GenericNack(nack)) => {
                                            // todo #22: handle generic NACK
                                            tracing::warn!(
                                                ecu_name = %transmission_params.ecu_name,
                                                nack_code = ?nack.nack_code,
                                                "Received generic NACK"
                                            );
                                            try_send_uds_response(
                                                &response_sender,
                                                Err(DiagServiceError::Nack(u8::from(
                                                    nack.nack_code,
                                                ))),
                                            )
                                            .await;
                                        }
                                        Ok(DiagnosticResponse::Nack(nack)) => {
                                            tracing::warn!(
                                                ecu_name = %transmission_params.ecu_name,
                                                nack_code = ?nack.nack_code,
                                                "Received NACK"
                                            );
                                            try_send_uds_response(
                                                &response_sender,
                                                Err(DiagServiceError::Nack(u8::from(
                                                    nack.nack_code,
                                                ))),
                                            )
                                            .await;
                                        }
                                        Ok(msg) => {
                                            tracing::warn!(
                                                ecu_name = %transmission_params.ecu_name,
                                                "Expected ACK/NACK but received unexpected message: {:?}",
                                                msg
                                            );
                                            // any response but ACK/NACK is unexpected because
                                            // every sent message should be answered with
                                            // ACK or NACK before sending anything else.
                                            // however, we should still continue waiting
                                            // for ACK/NACK in case we get something unexpected,
                                            // as some ECUs might not follow the spec properly.
                                            continue 'ack_waiting;
                                        }
                                        Err(e) => {
                                            tracing::error!(
                                                ecu_name = %transmission_params.ecu_name,
                                                error = %e,
                                                "Error while waiting for ACK/NACK"
                                            );
                                            try_send_uds_response(
                                                &response_sender,
                                                Err(DiagServiceError::NoResponse(format!(
                                                    "Error while waiting for ACK/NACK, {e}"
                                                ))),
                                            )
                                            .await;
                                        }
                                    }
                                    // got a response but it was not an ACK,
                                    break 'ack_waiting false;
                                }
                                // did not get anything from ecu receiver, meaning it is closed.
                                tracing::error!(
                                    ecu_name = %transmission_params.ecu_name,
                                    "ECU receiver unexpectedly closed while waiting for ACK/NACK"
                                );
                                try_send_uds_response(
                                    &response_sender,
                                    Err(DiagServiceError::NoResponse(
                                        "ECU receiver unexpectedly closed".to_owned(),
                                    )),
                                )
                                .await;
                                break 'ack_waiting false;
                            }
                        })
                        .await
                    {
                        if !ack_received {
                            // no ack received, nothing furhter to do here.
                            // receiver is already informed in the branches above.
                            return;
                        }
                    } else {
                        tracing::warn!(
                            ecu_name = %transmission_params.ecu_name,
                            timeout = ?transmission_params.timeout_ack,
                            "Timeout waiting for ACK/NACK from ECU"
                        );
                        // timeout branch of tokio::select, no response received,
                        // informing receiver about timeout and giving up.
                        try_send_uds_response(&response_sender, Err(DiagServiceError::Timeout))
                            .await;
                        return;
                    }

                    let send_and_ackd_after = start
                        .elapsed()
                        .saturating_sub(lock_acquired)
                        .saturating_sub(receiver_flushed);
                    if !expect_uds_reply {
                        try_send_uds_response(&response_sender, Ok(None)).await;
                    }

                    // Read ECU responses as long as the sender is open
                    // we might get multiple responses for a single request
                    // i.e. when the ecu is busy and sends NRC 0x78
                    loop {
                        tokio::select! {
                            // Using biased saves a bit of CPU time, because tokio does not
                            // have to generate a random number to select the branch.
                            // Prioritizing the ecu.reciver over the closed handler is fine
                            // because it is unlikely that both signal at the exact same time.
                            biased;
                            res = ecu.receiver.recv() => {
                                if let Ok(res) = res { match res {
                                    Ok(response) => {
                                        if !try_send_uds_response(
                                            &response_sender, response.try_into()).await {
                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        tracing::error!(
                                            ecu_name = %transmission_params.ecu_name,
                                            error = %e,
                                            "Error while waiting for response message"
                                        );
                                        if !try_send_uds_response(
                                                &response_sender,
                                                Err(DiagServiceError::NoResponse(
                                                    format!(
                                                        "Error while waiting for message, {e}")
                                            ))).await {
                                            break;
                                        }
                                    }
                                } } else {
                                    tracing::error!(
                                        ecu_name = %transmission_params.ecu_name,
                                        "ECU receiver unexpectedly closed while waiting for response"
                                    );
                                    try_send_uds_response(&response_sender,
                                        Err(DiagServiceError::NoResponse(
                                            "ECU receiver unexpectedly closed".to_owned(),
                                    ))).await;
                                    break;
                                }
                            }
                            () = response_sender.closed() => {
                                tracing::debug!(
                                    ecu_name = %transmission_params.ecu_name,
                                    "Response sender closed, aborting loop"
                                );
                                break;
                            }
                        }
                    }

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
    ) -> Result<HashMap<String, Result<UdsResponse, DiagServiceError>>, DiagServiceError> {
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

                        let uds_response = UdsResponse::Message(ServicePayload {
                            data: msg.message,
                            source_address: source_addr,
                            target_address: u16::from_be_bytes(msg.target_address),
                            new_session: None,
                            new_security: None,
                        });

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

#[allow(clippy::needless_continue)] // allow continue as it improves readability
async fn wait_for_ecu_response(
    ecu: &mut DoipEcu,
    timeout: Duration,
) -> Option<Result<DiagnosticMessage, EcuError>> {
    tokio::time::timeout(timeout, async {
        loop {
            match ecu.receiver.recv().await {
                Ok(Ok(DiagnosticResponse::Msg(m))) => {
                    return Some(Ok(m));
                }
                Ok(Ok(_ignore)) => {
                    // Ignore other message types
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
///
/// Returns [`DoipGatewaySetupError::InvalidConfiguration`] if `protocol_version` does not map
/// to a valid [`ProtocolVersion`], or any error propagated from the underlying socket setup.
pub fn create_socket(
    tester_ip: &str,
    gateway_port: u16,
    protocol_version: u8,
) -> Result<DoIPUdpSocket, DoipGatewaySetupError> {
    let protocol_version = ProtocolVersion::try_from(&protocol_version).map_err(|err| {
        DoipGatewaySetupError::InvalidConfiguration(format!("Invalid DoIP protocol version: {err}"))
    })?;
    create_socket_with_protocol(tester_ip, gateway_port, protocol_version)
}

fn create_socket_with_protocol(
    tester_ip: &str,
    gateway_port: u16,
    protocol_version: ProtocolVersion,
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
    DoIPUdpSocket::new(std_sock, protocol_version).map_err(|e| {
        DoipGatewaySetupError::SocketCreationFailed(format!(
            "DoipGateway: Failed to create DoIP socket from std socket: {e:?}"
        ))
    })
}

impl<T: EcuAddresses + DoipComParams> Clone for DoipDiagGateway<T> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
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
async fn try_send_uds_response(
    response_sender: &mpsc::Sender<Result<Option<UdsResponse>, DiagServiceError>>,
    response: Result<Option<UdsResponse>, DiagServiceError>,
) -> bool {
    if let Err(err) = response_sender.send(response).await {
        tracing::error!(error = %err, "Failed to send response");
        return false;
    }
    true
}
