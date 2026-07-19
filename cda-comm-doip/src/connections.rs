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

use cda_interfaces::{
    DataParseError, DiagServiceError, DoipComParams, EcuAddresses, EcuConnectivityHandler, HashMap,
    HashMapExtensions, dlt_ctx, service_ids,
};
use doip_definitions::payload::{ActivationType, DoipPayload, RoutingActivationRequest};
use thiserror::Error;
use tokio::{
    sync::{Mutex, RwLock, broadcast, mpsc, watch},
    task::{JoinError, JoinSet},
};

use crate::{
    ConnectionError, DiagnosticResponse, DiscoveredGateway, DoipConnection, DoipEcu,
    DoipTransportConfig, EcuTimeouts, GatewayConnectionConfig, GatewayDoipConfig, GatewaySetup,
    NRC_BUSY_REPEAT_REQUEST, NRC_RESPONSE_PENDING, NRC_TEMPORARILY_NOT_AVAILABLE,
    connection_receiver::spawn_gateway_receiver_task,
    connection_sender::spawn_gateway_sender_task,
    connections::EcuError::EcuConnectionError,
    ecu_connection::{self, ECUConnectionRead, EcuConnectionTarget},
};

pub(crate) type ConnectionResetReason = String;

/// Runtime state for managing active gateway connections and ECU mappings.
pub(crate) struct GatewayState<T> {
    pub doip_connections: Arc<RwLock<Vec<Arc<DoipConnection>>>>,
    pub ecus: Arc<HashMap<String, RwLock<T>>>,
    pub gateway_ecu_map: HashMap<u16, Vec<u16>>,
    pub connection_tasks: Arc<Mutex<JoinSet<Result<(), JoinError>>>>,
}

struct GatewayConnectionHandles {
    sender: mpsc::Sender<DoipPayload>,
    receivers: HashMap<u16, broadcast::Receiver<Result<DiagnosticResponse, EcuError>>>,
}

/// Channels used by the gateway receiver task for bidirectional flow control.
pub(crate) struct ReceiverChannels {
    pub(crate) send_pending_rx: watch::Receiver<bool>,
    pub(crate) reset_tx: mpsc::Sender<ConnectionResetReason>,
}

#[derive(Error, Debug, Clone)]
pub enum EcuError {
    #[error("Resource not found: `{0}`")]
    ResourceNotFound(String),
    #[error("Connection error: `{0}`")]
    EcuConnectionError(ConnectionError),
}

impl From<ConnectionError> for EcuError {
    fn from(value: ConnectionError) -> Self {
        EcuConnectionError(value)
    }
}

impl From<EcuError> for DiagServiceError {
    fn from(value: EcuError) -> Self {
        match value {
            EcuError::ResourceNotFound(res) => DiagServiceError::ResourceError(res),
            EcuConnectionError(connection_error) => match connection_error {
                ConnectionError::Decoding(err) => DiagServiceError::DataError(DataParseError {
                    value: err,
                    details: String::new(),
                }),
                ConnectionError::InvalidMessage(msg) => {
                    DiagServiceError::UnexpectedResponse(Some(msg))
                }
                ConnectionError::Timeout(_) => DiagServiceError::Timeout,
                // map arbitrary connection errors to connection closed
                ConnectionError::ConnectionFailed(msg) => {
                    DiagServiceError::ConnectionClosed(format!("ConnectionFailed {msg}"))
                }
                ConnectionError::RoutingError(msg) => {
                    DiagServiceError::ConnectionClosed(format!("RoutingError {msg}"))
                }
                ConnectionError::SendFailed(msg) => {
                    DiagServiceError::ConnectionClosed(format!("SendFailed {msg}"))
                }
                ConnectionError::Closed => DiagServiceError::ConnectionClosed(String::new()),
            },
        }
    }
}

#[tracing::instrument(
    skip(transport, state, connectivity_handler),
    fields(
        tester_ip = transport.tester_ip.clone(),
        port = transport.port,
        tls_port = transport.tls_port,
        gateway_ecu = %discovered_gateway.ecu_name,
        gateway_ip = %discovered_gateway.ip,
        logical_address = %format!("{:#06x}", discovered_gateway.logical_address),
        dlt_context = dlt_ctx!("DOIP")
    )
)]
pub(crate) async fn handle_gateway_connection<T>(
    discovered_gateway: DiscoveredGateway,
    transport: &DoipTransportConfig,
    state: &GatewayState<T>,
    connectivity_handler: Arc<dyn EcuConnectivityHandler>,
) -> Result<u16, EcuError>
where
    T: EcuAddresses + DoipComParams,
{
    let tester_address = state
        .ecus
        .get(&discovered_gateway.ecu_name)
        .map(|ecu| async { ecu.read().await.tester_address() })
        .ok_or_else(|| EcuError::ResourceNotFound("ECU not found".to_owned()))?
        .await;

    let routing_activation_request = RoutingActivationRequest {
        source_address: tester_address.to_be_bytes(),
        activation_type: ActivationType::Default,
        buffer: [0, 0, 0, 0],
    };

    let ecu_ids: Vec<u16> = if let Some(ecu_ids) = state
        .gateway_ecu_map
        .get(&discovered_gateway.logical_address)
    {
        ecu_ids.clone()
    } else {
        return Err(EcuError::ResourceNotFound(format!(
            "No ECUs found for gateway address {}. Skipping, as the gateway cannot be used.",
            discovered_gateway.logical_address
        )));
    };

    // Build list of ECU names behind this gateway for notifications
    let mut ecu_names_for_gateway: Vec<String> = Vec::new();
    for (name, ecu_lock) in state.ecus.iter() {
        let ecu = ecu_lock.read().await;
        if ecu_ids.contains(&ecu.logical_address()) {
            ecu_names_for_gateway.push(name.clone());
        }
    }

    let gateway_ecu = match state.ecus.get(&discovered_gateway.ecu_name) {
        Some(ecu) => ecu.read().await,
        None => {
            return Err(EcuError::ResourceNotFound(
                "Failed to find gateway ECU".to_owned(),
            ));
        }
    };
    let routing_activation_timeout = gateway_ecu.routing_activation_timeout();
    let connection_retry_delay = gateway_ecu.connection_retry_delay();
    let connection_timeout = gateway_ecu.connection_timeout();
    let connection_retry_attempts = gateway_ecu.connection_retry_attempts();

    let gateway = GatewaySetup {
        connection: GatewayConnectionConfig {
            doip: GatewayDoipConfig {
                gateway_ip: discovered_gateway.ip.clone(),
                name: discovered_gateway.ecu_name.clone(),
                tester_address: gateway_ecu.tester_address().to_be_bytes(),
                protocol_version: discovered_gateway.doip_protocol_version,
                transport: transport.clone(),
            },
            routing_activation_request,
            ecu_timeouts: EcuTimeouts {
                routing_activation: routing_activation_timeout,
                retry_delay: connection_retry_delay,
                connection: connection_timeout,
                max_retry_attempts: connection_retry_attempts,
            },
        },
        ecus: ecu_ids.clone(),
        ecu_names: ecu_names_for_gateway.clone(),
        connectivity_handler: Arc::clone(&connectivity_handler),
    };
    let GatewayConnectionHandles { sender, receivers } =
        match connection_handler(gateway, Arc::clone(&state.connection_tasks)).await {
            Ok(handles) => handles,
            Err(e) => {
                return Err(EcuError::EcuConnectionError(
                    ConnectionError::ConnectionFailed(format!(
                        "Failed to connect to {}: {}",
                        discovered_gateway.ecu_name, e
                    )),
                ));
            }
        };

    let doip_ecus = create_ecu_receiver_map(ecu_ids, &sender, &receivers);

    tracing::info!("Connected to gateway");
    state
        .doip_connections
        .write()
        .await
        .push(Arc::new(DoipConnection {
            ecus: doip_ecus,
            ip: discovered_gateway.ip,
        }));

    // Notify connectivity handler that ECUs behind this gateway are now online.
    // This sets their state to Online so the pre-send variant detection guard works correctly.
    connectivity_handler
        .on_gateway_connected(&ecu_names_for_gateway)
        .await;

    Ok(discovered_gateway.logical_address)
}

#[tracing::instrument(skip(sender, receiver),
    fields(
        ecu_count = ecus.len(),
        dlt_context = dlt_ctx!("DOIP")
    )
)]
fn create_ecu_receiver_map(
    ecus: Vec<u16>,
    sender: &mpsc::Sender<DoipPayload>, // sender is shared between all ecus of a gateway
    receiver: &HashMap<u16, broadcast::Receiver<Result<DiagnosticResponse, EcuError>>>,
) -> HashMap<u16, Arc<Mutex<DoipEcu>>> {
    let mut doip_ecus: HashMap<u16, Arc<Mutex<DoipEcu>>> = HashMap::new();
    for logical_address in ecus {
        match receiver.get(&logical_address) {
            Some(ecu_receiver) => {
                doip_ecus.insert(
                    logical_address,
                    Arc::new(Mutex::new(DoipEcu {
                        sender: sender.clone(),
                        receiver: ecu_receiver.resubscribe(),
                    })),
                );
            }
            None => {
                tracing::warn!(logical_address = %format!("{:#06x}", logical_address),
                    "ECU not found in receiver map");
            }
        }
    }

    doip_ecus
}

#[tracing::instrument(
    skip_all,
    fields(
        gateway_ip = %gateway.connection.doip.gateway_ip,
        gateway_name = %gateway.connection.doip.name,
        ecu_count = gateway.ecus.len(),
        dlt_context = dlt_ctx!("DOIP"),
    )
)]
async fn connection_handler(
    gateway: GatewaySetup,
    connection_tasks: Arc<Mutex<JoinSet<Result<(), JoinError>>>>,
) -> Result<GatewayConnectionHandles, EcuError> {
    // channel to send messages to the gateway / ecus
    let (intx, inrx) = mpsc::channel::<DoipPayload>(50);

    // channel to receive messages from the gateway / ecus
    let mut outrx: HashMap<u16, broadcast::Receiver<Result<DiagnosticResponse, EcuError>>> =
        HashMap::new();
    // channel used by the receiver task to distribute messages to the correct ecu,
    // counterpart to outrx
    let mut outtx: HashMap<u16, broadcast::Sender<Result<DiagnosticResponse, EcuError>>> =
        HashMap::new();

    // create ecu response channels
    for &ecu in &gateway.ecus {
        let (tx, rx) = broadcast::channel::<Result<DiagnosticResponse, EcuError>>(10);

        outtx.insert(ecu, tx);
        outrx.insert(ecu, rx);
    }

    // setting up initial gateway connection
    let gateway_conn = Arc::new(
        ecu_connection::establish_ecu_connection(&gateway.connection)
            .await
            .inspect_err(|e| {
                tracing::error!(
                    "Failed to connect to gateway at {}: {e:?}",
                    gateway.connection.doip.gateway_ip
                );
            })?,
    );

    // used by receiver / sender task to reset the connection
    let (conn_reset_tx, conn_reset_rx) = mpsc::channel::<ConnectionResetReason>(1);
    // task to handle connection resets and reconnects
    let conn_reset = Arc::<EcuConnectionTarget>::clone(&gateway_conn);

    let mut tasks = connection_tasks.lock().await;
    tasks.spawn(spawn_connection_reset_task(
        gateway.clone(),
        conn_reset_rx,
        conn_reset,
    ));

    // communication between send / receiver task to unlock the connection in the receiver task
    // when sender task wants to send something
    let (send_pending_tx, send_pending_rx) = watch::channel::<bool>(false);
    tasks.spawn(spawn_gateway_sender_task(
        Arc::<EcuConnectionTarget>::clone(&gateway_conn),
        inrx,
        conn_reset_tx.clone(),
        send_pending_tx.clone(),
    ));
    tasks.spawn(spawn_gateway_receiver_task(
        gateway,
        outtx,
        Arc::<EcuConnectionTarget>::clone(&gateway_conn),
        ReceiverChannels {
            send_pending_rx,
            reset_tx: conn_reset_tx,
        },
    ));
    drop(tasks);

    // no need to wait until the connection is alive, we will reconnect automatically anyway
    Ok(GatewayConnectionHandles {
        sender: intx,
        receivers: outrx,
    })
}

#[tracing::instrument(
    skip_all,
    fields(
        dlt_context = dlt_ctx!("DOIP")
    )
)]
fn spawn_connection_reset_task(
    gateway: GatewaySetup,
    mut conn_reset_rx: mpsc::Receiver<ConnectionResetReason>,
    conn_reset: Arc<EcuConnectionTarget>,
) -> tokio::task::JoinHandle<()> {
    let gateway_ip = gateway.connection.doip.gateway_ip.clone();
    cda_interfaces::spawn_named!(
        &format!("doip-connection-reset-{gateway_ip}"),
        Box::pin(async move {
            loop {
                let mut reconnect_attempts = 0u32;
                if let Some(reason) = conn_reset_rx.recv().await {
                    tracing::info!(reason = %reason, "Resetting connection");
                    // This task owns the connectivity notifications for the
                    // gateway lifecycle: disconnected here, connected after a
                    // successful reset. Emitting them from one place keeps
                    // their order strict - notifications racing in from the
                    // dying connection's IO tasks used to arrive after the
                    // reconnect's connected and pinned healthy ECUs Offline.
                    gateway
                        .connectivity_handler
                        .on_gateway_disconnected(&gateway.ecu_names)
                        .await;
                    let mut conn_guard = conn_reset.lock_connection().await;

                    'reconnect: loop {
                        let new_connection =
                            ecu_connection::establish_ecu_connection(&gateway.connection).await;

                        match new_connection {
                            Ok(conn) => {
                                tracing::info!("Connection reset successful");
                                ecu_connection::EcuConnectionTarget::reconnect(
                                    &mut conn_guard,
                                    conn,
                                );
                                gateway
                                    .connectivity_handler
                                    .on_gateway_connected(&gateway.ecu_names)
                                    .await;
                                while !conn_reset_rx.is_empty() {
                                    // drain the receiver to avoid resetting the connection again
                                    // immediately after a reset
                                    if conn_reset_rx.recv().await.is_none() {
                                        tracing::warn!("Connection reset receiver closed");
                                        return;
                                    }
                                }
                                break 'reconnect;
                            }
                            Err(e) => {
                                tracing::error!(
                                    error = ?e,
                                    retry_delay = ?gateway.connection.ecu_timeouts.retry_delay,
                                    "Failed to reset connection, retrying"
                                );
                                cda_interfaces::util::tokio_ext::sleep_for(
                                    gateway.connection.ecu_timeouts.retry_delay,
                                )
                                .await;
                                reconnect_attempts = reconnect_attempts.saturating_add(1);
                                if reconnect_attempts
                                    >= gateway.connection.ecu_timeouts.max_retry_attempts
                                {
                                    // Do NOT end the task here: it is the only
                                    // reconnect path for this gateway, and the
                                    // outage may simply outlast the retry
                                    // budget (e.g. a restarting gateway). Keep
                                    // listening so the next reset request - a
                                    // failed send, or the pending ones already
                                    // queued - starts a fresh retry round.
                                    tracing::error!(
                                        attempts = reconnect_attempts,
                                        max_attempts =
                                            gateway.connection.ecu_timeouts.max_retry_attempts,
                                        "Max reconnect attempts reached, giving up until the next \
                                         reset request"
                                    );
                                    break 'reconnect;
                                }
                            }
                        }
                    }
                } else {
                    tracing::warn!("Connection reset receiver closed");
                    break;
                }
            }
        })
    )
}

#[tracing::instrument(
    skip_all,
    fields(dlt_context = dlt_ctx!("DOIP"))
)]
pub(crate) async fn try_read(
    timeout: Duration,
    reader: &mut impl ECUConnectionRead,
) -> Option<Result<DiagnosticResponse, ConnectionError>> {
    async fn read_response(
        reader: &mut impl ECUConnectionRead,
    ) -> Result<DiagnosticResponse, ConnectionError> {
        match reader.read().await {
            Some(Ok(msg)) => match msg.payload {
                DoipPayload::DiagnosticMessage(msg) => {
                    // handle NRCs
                    if let Some(&0x7F) = msg.message.first() {
                        let request_sid = msg.message.get(1).copied().unwrap_or(0);
                        let error_code = msg.message.get(2).copied().unwrap_or(0);

                        if request_sid == service_ids::TESTER_PRESENT {
                            return Ok(DiagnosticResponse::TesterPresentNRC(error_code));
                        }

                        let source_address = u16::from_be_bytes(msg.source_address);
                        let response = match error_code {
                            NRC_RESPONSE_PENDING => {
                                tracing::debug!(
                                    message = ?msg.message,
                                    "UDS NRC - Response pending"
                                );
                                DiagnosticResponse::Pending {
                                    source_address,
                                    request_sid,
                                }
                            }
                            NRC_BUSY_REPEAT_REQUEST => DiagnosticResponse::BusyRepeatRequest {
                                source_address,
                                request_sid,
                            },
                            NRC_TEMPORARILY_NOT_AVAILABLE => {
                                DiagnosticResponse::TemporarilyNotAvailable {
                                    source_address,
                                    request_sid,
                                }
                            }
                            _ => return Ok(DiagnosticResponse::Msg(msg)),
                        };
                        return Ok(response);
                    }
                    Ok(DiagnosticResponse::Msg(msg))
                }
                DoipPayload::DiagnosticMessageNack(nack) => Ok(DiagnosticResponse::Nack(nack)),
                DoipPayload::GenericNack(nack) => Ok(DiagnosticResponse::GenericNack(nack)),
                DoipPayload::DiagnosticMessageAck(ack) => {
                    tracing::debug!("Received diagnostic message ack");
                    Ok(DiagnosticResponse::Ack((
                        u16::from_be_bytes(ack.source_address),
                        ack.previous_message,
                    )))
                }
                DoipPayload::AliveCheckResponse(_) => Ok(DiagnosticResponse::AliveCheckResponse),
                _ => Err(ConnectionError::InvalidMessage(format!(
                    "Received non-diagnostic message: {msg:?}"
                ))),
            },
            Some(Err(e)) => Err(ConnectionError::Decoding(format!(
                "Error reading from gateway: {e:?}"
            ))),
            None => Err(ConnectionError::Closed),
        }
    }

    tokio::time::timeout(timeout, read_response(reader))
        .await
        .ok()
}
