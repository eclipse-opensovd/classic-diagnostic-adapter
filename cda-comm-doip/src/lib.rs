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

use std::{
    future::Future,
    sync::Arc,
    time::{Duration, Instant},
};

use cda_interfaces::{
    DiagServiceError, DoipComParamProvider, DoipGatewaySetupError, EcuAddressProvider, EcuGateway,
    HashMap, HashMapExtensions, ServicePayload, TransmissionParameters, UdsResponse, dlt_ctx,
    util::{self, tokio_ext},
};
use doip_definitions::payload::{DiagnosticMessage, DiagnosticMessageNack, GenericNack};
use thiserror::Error;
use tokio::sync::{Mutex, RwLock, broadcast, mpsc};

use crate::{config::DoipConfig, connections::EcuError};

pub mod config;
mod connections;
mod ecu_connection;
mod vir_vam;

const SLEEP_INTERVAL: Duration = Duration::from_secs(30);

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

pub struct DoipDiagGateway<T: EcuAddressProvider + DoipComParamProvider> {
    doip_connections: Arc<RwLock<Vec<Arc<DoipConnection>>>>,
    logical_address_to_connection: Arc<RwLock<HashMap<u16, usize>>>,
    ecus: Arc<HashMap<String, RwLock<T>>>,
    socket: Arc<Mutex<doip_sockets::udp::UdpSocket>>,
}

#[derive(Debug)]
struct DoipTarget {
    ip: String,
    ecu: String,
    logical_address: u16,
}

struct DoipEcu {
    sender: mpsc::Sender<DiagnosticMessage>,
    receiver: broadcast::Receiver<Result<DiagnosticResponse, EcuError>>,
}

struct DoipConnection {
    ecus: HashMap<u16, Arc<Mutex<DoipEcu>>>,
    ip: String,
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

impl<T: EcuAddressProvider + DoipComParamProvider> DoipDiagGateway<T> {
    /// Create a new `DoipDiagGateway` instance.
    /// # Errors
    /// Returns `String` if initialization fails, e.g. when socket creation fails.
    #[tracing::instrument(
        skip(doip_config, ecus, variant_detection, shutdown_signal),
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
    ) -> Result<Self, DoipGatewaySetupError>
    where
        F: Future<Output = ()> + Clone + Send + 'static,
    {
        let DoipConfig {
            tester_address: tester_ip,
            tester_subnet,
            gateway_port,
            send_timeout_ms,
        } = doip_config;
        let gateway_port = *gateway_port;
        let send_timeout = Duration::from_millis(*send_timeout_ms);

        tracing::info!("Initializing DoipDiagGateway");

        let mut socket = create_socket(tester_ip, gateway_port)?;
        let mask = create_netmask(tester_ip, tester_subnet)?;

        let gateways = vir_vam::get_vehicle_identification::<T, F>(
            &mut socket,
            mask,
            gateway_port,
            &ecus,
            shutdown_signal.clone(),
        )
        .await
        .map_err(|err| {
            DoipGatewaySetupError::ResourceError(format!(
                "Could not get vehicle identification. {err}"
            ))
        })?;

        let gateway = if gateways.is_empty() {
            DoipDiagGateway {
                doip_connections: Arc::new(RwLock::new(Vec::new())),
                logical_address_to_connection: Arc::new(RwLock::new(HashMap::new())),
                ecus,
                socket: Arc::new(Mutex::new(socket)),
            }
        } else {
            tracing::info!(gateway_count = gateways.len(), "Gateways found");

            // create mapping gateway_logical_address -> Vec<ecu_logical_address>
            let mut gateway_ecu_map: HashMap<u16, Vec<u16>> = HashMap::new();
            for ecu_lock in ecus.values() {
                let ecu = ecu_lock.read().await;
                let addr = ecu.logical_address();
                let gateway = ecu.logical_gateway_address();
                gateway_ecu_map.entry(gateway).or_default().push(addr);
            }

            let doip_connections: Arc<RwLock<Vec<Arc<DoipConnection>>>> =
                Arc::new(RwLock::new(Vec::new()));
            let mut logical_address_to_connection = HashMap::new();

            for gateway in gateways {
                if let Ok(logical_address) = connections::handle_gateway_connection::<T>(
                    gateway,
                    &doip_connections,
                    &ecus,
                    &gateway_ecu_map,
                    send_timeout,
                )
                .await
                {
                    logical_address_to_connection.insert(
                        logical_address,
                        doip_connections.read().await.len().saturating_sub(1),
                    );
                }
            }

            DoipDiagGateway {
                doip_connections,
                logical_address_to_connection: Arc::new(RwLock::new(logical_address_to_connection)),
                ecus,
                socket: Arc::new(Mutex::new(socket)),
            }
        };

        vir_vam::listen_for_vams(
            tester_ip.to_owned(),
            gateway_port,
            mask,
            gateway.clone(),
            variant_detection,
            send_timeout,
            shutdown_signal,
        )
        .await;

        Ok(gateway)
    }

    async fn get_doip_connection(
        &self,
        conn_idx: usize,
    ) -> Result<Arc<DoipConnection>, DiagServiceError> {
        let lock = self.doip_connections.read().await;
        let conn = lock
            .get(conn_idx)
            .ok_or(DiagServiceError::ConnectionClosed)?;
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
        if let Some(ecu) = self.ecus.get(&transmission_params.ecu_name.to_lowercase())
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

impl<T: EcuAddressProvider + DoipComParamProvider> EcuGateway for DoipDiagGateway<T> {
    async fn get_gateway_network_address(&self, logical_address: u16) -> Option<String> {
        self.doip_connections
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
        let conn_idx = *self
            .logical_address_to_connection
            .read()
            .await
            .get(&transmission_params.gateway_address)
            .ok_or_else(|| DiagServiceError::EcuOffline(transmission_params.ecu_name.clone()))?;

        if conn_idx >= self.doip_connections.read().await.len() {
            return Err(DiagServiceError::ConnectionClosed);
        }

        let doip_conn = self.get_doip_connection(conn_idx).await?;
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
                                            tracing::debug!("Received ACK");
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
                                            try_send_uds_response(
                                                &response_sender,
                                                Err(DiagServiceError::Nack(u8::from(
                                                    nack.nack_code,
                                                ))),
                                            )
                                            .await;
                                        }
                                        Ok(DiagnosticResponse::Nack(nack)) => {
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
                                                "Expected ACK/NACK but received unexpected \
                                                 message: {:?}",
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
                            "Timeout waiting for ACK/NACK from ECU after {:?}",
                            transmission_params.timeout_ack
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
                            res = ecu.receiver.recv() => {
                                if let Ok(res) = res { match res {
                                    Ok(response) => {
                                        if !try_send_uds_response(
                                            &response_sender, response.try_into()).await {
                                            break;
                                        }
                                    }
                                    Err(e) => {
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
                                    try_send_uds_response(&response_sender,
                                        Err(DiagServiceError::NoResponse(
                                            "ECU receiver unexpectedly closed".to_owned(),
                                    ))).await;
                                    break;
                                }
                            }
                            () = response_sender.closed() => {
                                tracing::debug!("Response sender closed, aborting loop");
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

    async fn ecu_online<E: EcuAddressProvider>(
        &self,
        ecu_name: &str,
        ecu_db: &RwLock<E>,
    ) -> Result<(), DiagServiceError> {
        let ecu_lock = ecu_db.read().await;
        let conn_idx = *self
            .logical_address_to_connection
            .read()
            .await
            .get(&ecu_lock.logical_gateway_address())
            .ok_or_else(|| DiagServiceError::EcuOffline(ecu_name.to_owned()))?;
        let doip_conn = self.get_doip_connection(conn_idx).await?;
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
    ) -> Result<HashMap<String, Result<UdsResponse, DiagServiceError>>, DiagServiceError> {
        let conn_idx = *self
            .logical_address_to_connection
            .read()
            .await
            .get(&transmission_params.gateway_address)
            .ok_or_else(|| DiagServiceError::EcuOffline("Gateway not found".to_string()))?;

        if conn_idx >= self.doip_connections.read().await.len() {
            return Err(DiagServiceError::ConnectionClosed);
        }

        let doip_conn = self.get_doip_connection(conn_idx).await?;

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
        let received_responses: Arc<Mutex<HashMap<String, Result<DiagnosticMessage, EcuError>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let mut futures = Vec::new();
        for (name, ecu) in ecu_mtxs.drain(..) {
            let received_responses = Arc::clone(&received_responses);
            let fut = async move {
                let mut lock = ecu.lock().await;
                if let Some(response) = wait_for_ecu_response(&mut lock, timeout).await {
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

        // Mark ECUs that didn't respond as timeout errors
        for (logical_addr, ecu_name) in &expected_ecu_logical_addrs {
            if !result_map.contains_key(ecu_name) {
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

fn create_socket(
    tester_ip: &str,
    gateway_port: u16,
) -> Result<doip_sockets::udp::UdpSocket, DoipGatewaySetupError> {
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
    doip_sockets::udp::UdpSocket::from_std(std_sock).map_err(|e| {
        DoipGatewaySetupError::SocketCreationFailed(format!(
            "DoipGateway: Failed to create DoIP socket from std socket: {e:?}"
        ))
    })
}

impl<T: EcuAddressProvider + DoipComParamProvider> Clone for DoipDiagGateway<T> {
    fn clone(&self) -> Self {
        Self {
            doip_connections: Arc::clone(&self.doip_connections),
            logical_address_to_connection: Arc::clone(&self.logical_address_to_connection),
            ecus: Arc::clone(&self.ecus),
            socket: Arc::clone(&self.socket),
        }
    }
}

async fn send_with_retries(
    msg: &DiagnosticMessage,
    sender: &mpsc::Sender<DiagnosticMessage>,
    resend_counter: &mut u32,
    max_retries: u32,
) -> Result<(), DiagServiceError> {
    while let Err(e) = sender.send(msg.clone()).await {
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
