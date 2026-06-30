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
    DataParseError, DiagServiceError, DoipComParams, EcuAddresses, HashMap, HashMapExtensions,
    dlt_ctx, service_ids,
};
use doip_definitions::payload::{
    ActivationType, AliveCheckResponse, DiagnosticAckCode, DiagnosticMessageAck, DoipPayload,
    RoutingActivationRequest,
};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{Mutex, RwLock, broadcast, mpsc, watch},
};

use crate::{
    ConnectionError, DiagnosticResponse, DiscoveredGateway, DoipConnection, DoipEcu,
    DoipTransportConfig, EcuTimeouts, GatewayConnectionConfig, GatewayDoipConfig, GatewaySetup,
    NRC_BUSY_REPEAT_REQUEST, NRC_RESPONSE_PENDING, NRC_TEMPORARILY_NOT_AVAILABLE,
    connections::EcuError::EcuConnectionError,
    ecu_connection::{self, ECUConnectionRead, ECUConnectionSend as _, EcuConnectionTarget},
};

type ConnectionResetReason = String;

/// Runtime state for managing active gateway connections and ECU mappings.
pub(crate) struct GatewayState<T> {
    pub doip_connections: Arc<RwLock<Vec<Arc<DoipConnection>>>>,
    pub ecus: Arc<HashMap<String, RwLock<T>>>,
    pub gateway_ecu_map: HashMap<u16, Vec<u16>>,
}

struct GatewayConnectionHandles {
    sender: mpsc::Sender<DoipPayload>,
    receivers: HashMap<u16, broadcast::Receiver<Result<DiagnosticResponse, EcuError>>>,
    task_handles: Vec<tokio::task::JoinHandle<()>>,
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
    skip(transport, state),
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
    variant_detection: Option<(mpsc::Sender<Vec<String>>, Vec<String>)>,
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
        variant_detection,
    };
    let GatewayConnectionHandles {
        sender,
        receivers,
        task_handles,
    } = match connection_handler(gateway).await {
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
            task_handles,
        }));

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
async fn connection_handler(gateway: GatewaySetup) -> Result<GatewayConnectionHandles, EcuError> {
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
    let connection_reset_task =
        spawn_connection_reset_task(gateway.clone(), conn_reset_rx, conn_reset);

    // communication between send / receiver task to unlock the connection in the receiver task
    // when sender task wants to send something
    let (send_pending_tx, send_pending_rx) = watch::channel::<bool>(false);
    let gateway_sender_task = spawn_gateway_sender_task(
        Arc::<EcuConnectionTarget>::clone(&gateway_conn),
        inrx,
        conn_reset_tx.clone(),
        send_pending_tx.clone(),
    );
    let gateway_receiver_task = spawn_gateway_receiver_task(
        outtx,
        Arc::<EcuConnectionTarget>::clone(&gateway_conn),
        send_pending_rx,
        conn_reset_tx,
        intx.clone(),
    );

    // no need to wait until the connection is alive, we will reconnect automatically anyway
    Ok(GatewayConnectionHandles {
        sender: intx,
        receivers: outrx,
        task_handles: vec![
            connection_reset_task,
            gateway_sender_task,
            gateway_receiver_task,
        ],
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
                                while !conn_reset_rx.is_empty() {
                                    // drain the receiver to avoid resetting the connection again
                                    // immediately after a reset
                                    if conn_reset_rx.recv().await.is_none() {
                                        tracing::warn!("Connection reset receiver closed");
                                        return;
                                    }
                                }
                                // Trigger variant detection after successful reconnection
                                // so that ECUs transition back to Online.
                                if let Some((ref vd_tx, ref ecu_names)) = gateway.variant_detection
                                {
                                    if let Err(e) = vd_tx.send(ecu_names.clone()).await {
                                        tracing::error!(
                                            error = ?e,
                                            "Failed to trigger variant detection after reconnect"
                                        );
                                    } else {
                                        tracing::info!(
                                            ecus = ?ecu_names,
                                            "Triggered variant detection after reconnect"
                                        );
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
                                    tracing::error!(
                                        attempts = reconnect_attempts,
                                        max_attempts =
                                            gateway.connection.ecu_timeouts.max_retry_attempts,
                                        "Max reconnect attempts reached, giving up"
                                    );
                                    return;
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
    fields(
        dlt_context = dlt_ctx!("DOIP")
    )
)]
fn spawn_gateway_sender_task<T>(
    gateway_connection: Arc<EcuConnectionTarget<T>>,
    mut inrx: mpsc::Receiver<DoipPayload>,
    reset_tx: mpsc::Sender<ConnectionResetReason>,
    send_pending_tx: watch::Sender<bool>,
) -> tokio::task::JoinHandle<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    cda_interfaces::spawn_named!(
        &format!(
            "doip-gateway-sender-{}",
            gateway_connection.gateway_doip_config.gateway_ip
        ),
        async move {
            fn send_pending_status(
                send_pending_tx: &watch::Sender<bool>,
                value: bool,
            ) -> Result<(), ()> {
                send_pending_tx.send(value).map_err(|_| {
                    tracing::warn!("Send pending receiver closed");
                })
            }

            let alive_check_interval = gateway_connection
                .gateway_doip_config
                .transport
                .alive_check_interval;
            let send_timeout = gateway_connection
                .gateway_doip_config
                .transport
                .send_timeout;
            let alive_check_enabled = alive_check_interval > Duration::ZERO;
            let effective_interval = if alive_check_enabled {
                alive_check_interval
            } else {
                // Use a very large duration when disabled so the interval never fires.
                // tokio::time::Instant is limited so we use ~136 years which is well
                // within the representable range.
                Duration::from_secs(u64::from(u32::MAX))
            };
            let mut alive_interval = tokio::time::interval_at(
                tokio::time::Instant::now()
                    .checked_add(effective_interval)
                    .expect("interval start overflow"),
                effective_interval,
            );
            alive_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    // Per default tokio, randomized which branch is checked first to ensure fairness.
                    // We always want to priotize sending messages over the alive check.
                    // Adding 'biased' means the selects are checked in order from top to bottom.
                    // https://docs.rs/tokio/latest/tokio/macro.select.html#fairness
                    biased;
                    msg = inrx.recv() => {
                        let Some(msg) = msg else {
                            // Channel closed - all senders dropped (gateway shut down).
                            tracing::debug!("Send channel closed, shutting down sender task");
                            break;
                        };
                        // let rx task know that we want to send something.
                        if send_pending_status(&send_pending_tx, true).is_err() {
                            break;
                        }

                        let start = std::time::Instant::now();
                        let lock_after = match gateway_connection.lock_send().await {
                            Ok(mut guard) => {
                                let conn = guard.get_sender();
                                let lock_after = start.elapsed();

                                match tokio::time::timeout(send_timeout, conn.send(msg)).await {
                                    Ok(Ok(())) => {},
                                    Ok(Err(e)) => {
                                        tracing::error!(error = ?e, "Failed to send message");
                                    }
                                    Err(e) => {
                                        tracing::error!(error = ?e, "Timeout sending message");
                                    }
                                }
                                lock_after
                            },
                            Err(_) => {
                                continue; // connection was closed
                            }
                        };

                        let send_after = start.elapsed().saturating_sub(lock_after);
                        tracing::debug!(
                            total_duration = ?start.elapsed(),
                            lock_duration = ?lock_after,
                            send_duration = ?send_after,
                            "DoIP send request timing"
                        );
                        // inform the rx task that we are done sending
                        if send_pending_status(&send_pending_tx, false).is_err() {
                            break;
                        }
                        // Reset the alive check timer so it only fires after a full
                        // interval of silence - never during active communication.
                        alive_interval.reset();
                    },

                    _ = alive_interval.tick(), if alive_check_enabled => {
                        if send_pending_status(&send_pending_tx, true).is_err() {
                            break;
                        }

                        let (alive_response, conn_gateway_name, conn_gateway_ip) = {
                            (
                                send_alive_response(&gateway_connection).await,
                                gateway_connection.gateway_doip_config.name.clone(),
                                gateway_connection.gateway_doip_config.gateway_ip.clone(),
                            )
                        };

                        if let Err(e) = alive_response {
                            tracing::error!(
                                error = ?e,
                                gateway_name = %conn_gateway_name,
                                gateway_ip = %conn_gateway_ip,
                                "Failed to send alive check request, resetting connection"
                            );
                            // no need for any 'sleep' here, the reset task holds the connection
                            // lock until the connection is ready again.
                            if let Err(e) = reset_tx
                                .send("Unable to send alive check request".to_owned())
                                .await
                            {
                                tracing::error!(
                                    error = ?e,
                                    "Failed to send connection reset request"
                                );
                                // if the reset channel is closed, we cannot reset the connection
                                // and there is no point in continuing
                                break;
                            }
                        }

                        if send_pending_status(&send_pending_tx, false).is_err() {
                            break;
                        }
                    }
                }
            }
        }
    )
}

/// allowed because there are two inline functions in here,
/// that should be kept private to this function.
#[allow(clippy::too_many_lines)]
#[tracing::instrument(
    skip(outtx, gateway_conn, send_pending_rx, reset_tx),
    fields(
        gateway_ip = %gateway_conn.gateway_doip_config.gateway_ip,
        gateway_name = %gateway_conn.gateway_doip_config.name,
        active_ecus = outtx.len(),
        dlt_context = dlt_ctx!("DOIP"),
    )
)]
fn spawn_gateway_receiver_task<T>(
    outtx: HashMap<u16, broadcast::Sender<Result<DiagnosticResponse, EcuError>>>,
    gateway_conn: Arc<EcuConnectionTarget<T>>,
    mut send_pending_rx: watch::Receiver<bool>,
    reset_tx: mpsc::Sender<ConnectionResetReason>,
    send_tx: mpsc::Sender<DoipPayload>,
) -> tokio::task::JoinHandle<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let gateway_ip = gateway_conn.gateway_doip_config.gateway_ip.clone();
    let gateway_name = gateway_conn.gateway_doip_config.name.clone();
    // note: the handlers are defined here, as rustfmt cannot format the correctly inside the
    // tokio::select! macro block
    async fn handle_send_pending(
        gateway_name: &str,
        gateway_ip: &str,
        send_pending_rx: &mut watch::Receiver<bool>,
        send_pending_result: Result<(), watch::error::RecvError>,
    ) -> Result<(), ()> {
        let request_received = std::time::Instant::now();
        if send_pending_result.is_ok() {
            tracing::debug!(
                gateway_name = %gateway_name,
                gateway_ip = %gateway_ip,
                "Received tx request, unlocking connection"
            );
            let send_pending = *send_pending_rx.borrow();
            if send_pending {
                match send_pending_rx.changed().await {
                    Ok(()) => {
                        tracing::debug!(
                            gateway_name = %gateway_name,
                            gateway_ip = %gateway_ip,
                            request_duration = ?request_received.elapsed(),
                            "Send done, continue rx await"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            gateway_name = %gateway_name,
                            gateway_ip = %gateway_ip,
                            error = ?e,
                            "Send pending receiver closed"
                        );
                        return Err(());
                    }
                }
            }
            Ok(())
        } else {
            tracing::warn!(
                gateway_name = %gateway_name,
                gateway_ip = %gateway_ip,
                "Send pending receiver closed"
            );
            Err(())
        }
    }

    #[tracing::instrument(
        skip_all,
        fields(dlt_context = dlt_ctx!("DOIP"))
    )]
    async fn handle_response(
        gateway_name: &str,
        gateway_ip: &str,
        outtx: &HashMap<u16, broadcast::Sender<Result<DiagnosticResponse, EcuError>>>,
        reset_tx: &mpsc::Sender<ConnectionResetReason>,
        ack_tx: &mpsc::Sender<DoipPayload>,
        response: Option<Result<DiagnosticResponse, ConnectionError>>,
    ) {
        match response {
            Some(Ok(response)) => {
                match response {
                    DiagnosticResponse::Ack((source_address, _)) => {
                        tracing::debug!(
                            gateway_name = %gateway_name,
                            gateway_ip = %gateway_ip,
                            source_address = %source_address,
                            "Received ACK"
                        );
                        outtx
                            .get(&source_address)
                            .map(|router| router.send(Ok(response)));
                    }
                    DiagnosticResponse::Pending(source_address)
                    | DiagnosticResponse::BusyRepeatRequest(source_address)
                    | DiagnosticResponse::TemporarilyNotAvailable(source_address) => {
                        outtx
                            .get(&source_address)
                            .map(|router| router.send(Ok(response)));
                    }
                    DiagnosticResponse::Msg(msg) => {
                        let addr = u16::from_be_bytes(msg.source_address);
                        let target_addr = u16::from_be_bytes(msg.target_address);
                        // send DoIP DiagnosticMessageAck before returning the message to the caller
                        let _ = ack_tx
                            .send(DoipPayload::DiagnosticMessageAck(DiagnosticMessageAck {
                                source_address: msg.target_address,
                                target_address: msg.source_address,
                                ack_code: DiagnosticAckCode::Acknowledged,
                                previous_message: Vec::new(), // skip optional previous payload
                            }))
                            .await
                            .inspect_err(|e| {
                                tracing::error!(
                                    error = ?e,
                                    gateway_name = %gateway_name,
                                    gateway_ip = %gateway_ip,
                                    source_address = %addr,
                                    target_address = %target_addr,
                                    "Failed to send DiagnosticMessageAck"
                                );
                            });
                        tracing::debug!("DOIP OK - Returning response from ECU {:04x}", addr);
                        outtx
                            .get(&addr)
                            .map(|router| router.send(Ok(DiagnosticResponse::Msg(msg))));
                    }
                    DiagnosticResponse::Nack(nack) => {
                        tracing::debug!(nack = ?nack, "Received NACK");
                        let addr = u16::from_be_bytes(nack.source_address);
                        outtx
                            .get(&addr)
                            .map(|router| router.send(Ok(DiagnosticResponse::Nack(nack))));
                    }
                    DiagnosticResponse::GenericNack(_) => {
                        // todo implement generic NACK handling according to spec #22
                        tracing::error!("Received Generic NACK");
                    }
                    DiagnosticResponse::AliveCheckResponse => {
                        tracing::debug!(
                            "Received Alive Check Response. Probably ECU responded too slow"
                        );
                    }
                    DiagnosticResponse::TesterPresentNRC(c) => {
                        tracing::debug!(nrc = ?c, "Received Tester Present NRC");
                    }
                }
            }
            Some(Err(err)) => {
                match err {
                    ConnectionError::Closed => {
                        if let Err(e) = reset_tx
                            .send("Connection has been closed.".to_owned())
                            .await
                        {
                            tracing::error!(error = ?e, "Failed to send connection reset request");
                        }
                    }
                    _ => {
                        // for POC purposes we just log the error and do not reset the connection
                        tracing::error!(
                            error = ?err,
                            "Error reading response, either due to timeout or decoding issue"
                        );
                    }
                }
            }
            None => {
                // No data to receive, but try_read timed out
            }
        }
    }

    cda_interfaces::spawn_named!(&format!("gateway-receiver-{gateway_ip}"), async move {
        'receive: loop {
            if outtx.iter().all(|(_, tx)| tx.receiver_count() == 0) {
                tracing::debug!("All out channels closed. Shutting down connection");
                break;
            }

            // wait for a message to be received or a send request
            // Tokio is randomizing which branch takes precedence when both are ready.
            // this is good here because it prevents send / receive starvation by
            // not prioritizing one of the branches.
            tokio::select! {
                send_pending_result = send_pending_rx.changed() => {
                    if let Err(()) = handle_send_pending(
                        &gateway_name,
                        &gateway_ip,
                        &mut send_pending_rx,
                        send_pending_result
                    ).await {
                        break 'receive;
                    }
                },

                response = async {
                    let Ok(mut conn_mtx) = gateway_conn.lock_read().await else {
                        return None;
                    };
                    let conn = conn_mtx.get_reader();

                    // we can wait without actual timeout because this will be
                    // interrupted by the send_pending_rx when someone wants to send
                    // data on the connection
                    Some(try_read(Duration::MAX, conn).await)
                } => {
                    if let Some(response) = response {
                        handle_response(
                            &gateway_name,
                            &gateway_ip,
                            &outtx,
                            &reset_tx,
                            &send_tx,
                            response
                        ).await;
                    }
                }
            }
        }
    })
}

async fn send_alive_response<T>(conn: &EcuConnectionTarget<T>) -> Result<(), ()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    async fn handle_alive_request_response<T>(conn: &EcuConnectionTarget<T>)
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if tokio::time::timeout(Duration::from_secs(1), async {
            let Ok(mut reader_mtx) = conn.lock_read().await else {
                return;
            };
            let reader = reader_mtx.get_reader();
            match try_read(Duration::from_secs(1), reader).await {
                Some(Ok(DiagnosticResponse::AliveCheckResponse)) => {
                    tracing::debug!("Alive check OK");
                }
                Some(Ok(DiagnosticResponse::Ack(_))) => {
                    tracing::debug!("Received ACK");
                    Box::pin(handle_alive_request_response(conn)).await;
                }
                Some(Ok(DiagnosticResponse::GenericNack(_))) => {
                    tracing::debug!("Received Generic NACK");
                }
                Some(Ok(msg)) => {
                    tracing::error!(msg = ?msg, "Received Unrelated msg");
                }
                Some(Err(e)) => {
                    tracing::error!(error = %e, "Error reading alive check response");
                }
                None => {
                    tracing::debug!("Timeout waiting for alive check response");
                }
            }
        })
        .await
        .is_err()
        {
            tracing::debug!("Timeout waiting for alive check response");
        }
    }

    // TODO: handle alive request errors according to spec
    let Ok(mut sender) = conn.lock_send().await else {
        return Err(());
    };
    match sender
        .get_sender()
        .send(DoipPayload::AliveCheckResponse(AliveCheckResponse {
            source_address: conn.gateway_doip_config.tester_address,
        }))
        .await
    {
        Ok(()) => {
            handle_alive_request_response(conn).await;
            Ok(())
        }
        Err(e) => {
            tracing::error!(error = ?e, "Failed to send alive check request");
            Err(())
        }
    }
}

#[tracing::instrument(
    skip_all,
    fields(dlt_context = dlt_ctx!("DOIP"))
)]
async fn try_read(
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
                                DiagnosticResponse::Pending(source_address)
                            }
                            NRC_BUSY_REPEAT_REQUEST => {
                                DiagnosticResponse::BusyRepeatRequest(source_address)
                            }
                            NRC_TEMPORARILY_NOT_AVAILABLE => {
                                DiagnosticResponse::TemporarilyNotAvailable(source_address)
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

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use doip_definitions::{
        header::ProtocolVersion,
        payload::{DoipPayload, EntityStatusRequest},
    };
    use tokio::sync::{Mutex, mpsc, watch};

    use crate::{
        DoipTransportConfig, GatewayDoipConfig,
        connections::{ConnectionResetReason, spawn_gateway_sender_task},
        ecu_connection::{EcuConnectionReadVariant, EcuConnectionSendVariant, EcuConnectionTarget},
        socket::{DoIPConnection, DoipSocketConfig},
    };

    /// Builds a duplex-backed `EcuConnectionTarget` together with the server-side
    /// `DoIPConnection` used to respond to alive checks and dummy messages.
    /// `lock_send()` succeeds and `alive_interval.reset()` is called on each
    /// message processed by the sender task.
    fn duplex_ecu_connection_target(
        alive_check_interval: Duration,
    ) -> (
        EcuConnectionTarget<tokio::io::DuplexStream>,
        DoIPConnection<tokio::io::DuplexStream>,
    ) {
        let (client, server) = tokio::io::duplex(1024);
        let config = DoipSocketConfig {
            protocol_version: ProtocolVersion::Iso13400_2010,
            send_diagnostic_message_ack: false,
        };
        let server_conn = DoIPConnection::new(server, config);
        let (read_half, write_half) = DoIPConnection::new(client, config).into_split();
        let target = EcuConnectionTarget {
            ecu_connection_rx: Mutex::new(Some(EcuConnectionReadVariant::Plain(read_half))),
            ecu_connection_tx: Mutex::new(Some(EcuConnectionSendVariant::Plain(write_half))),
            gateway_doip_config: GatewayDoipConfig {
                gateway_ip: "127.0.0.1".to_owned(),
                name: String::new(),
                tester_address: [0, 0],
                protocol_version: ProtocolVersion::Iso13400_2010,
                transport: DoipTransportConfig {
                    tester_ip: "127.0.0.1".to_owned(),
                    port: 13400,
                    tls_port: 0,
                    send_diagnostic_message_ack: false,
                    send_timeout: Duration::from_secs(5),
                    alive_check_interval,
                },
            },
        };
        (target, server_conn)
    }

    /// Shared test harness for gateway sender task tests.
    /// Creates all channels, the duplex connection, pauses time, spawns the task,
    /// and starts a background responder that simulates a real gateway on the
    /// server side of the duplex.
    ///
    /// The responder handles two types of incoming messages:
    /// - `AliveCheckRequest`: replies with `AliveCheckResponse` so the sender's
    ///   alive check completes immediately instead of timing out.
    /// - `EntityStatusRequest` (dummy diagnostic messages sent by the test):
    ///   replies with `DiagnosticMessageAck` to simulate a real gateway that
    ///   acknowledges incoming diagnostic messages. Without this, the ack would
    ///   be missing from the read buffer, which would make the test less realistic.
    ///
    /// The test then uses the returned handles to drive the scenario.
    struct GatewaySenderTestHarness {
        msg_tx: mpsc::Sender<DoipPayload>,
        reset_rx: mpsc::Receiver<ConnectionResetReason>,
        _gateway_conn: Arc<EcuConnectionTarget<tokio::io::DuplexStream>>,
        _send_pending_rx: watch::Receiver<bool>,
        task: tokio::task::JoinHandle<()>,
    }

    impl GatewaySenderTestHarness {
        fn new(alive_check_interval: Duration) -> Self {
            tokio::time::pause();

            let (msg_tx, msg_rx) = mpsc::channel::<DoipPayload>(10);
            let (reset_tx, reset_rx) = mpsc::channel::<ConnectionResetReason>(10);
            let (send_pending_tx, send_pending_rx) = watch::channel(false);
            let (gateway_target, _) = duplex_ecu_connection_target(alive_check_interval);

            let gateway_conn = Arc::new(gateway_target);

            let task = spawn_gateway_sender_task(
                Arc::clone(&gateway_conn),
                msg_rx,
                reset_tx,
                send_pending_tx,
            );

            Self {
                msg_tx,
                reset_rx,
                _gateway_conn: gateway_conn,
                _send_pending_rx: send_pending_rx,
                task,
            }
        }

        /// Sends a dummy diagnostic message through the message channel.
        ///
        /// The payload (`EntityStatusRequest`) is just a placeholder - the only
        /// thing that matters is that sending any message through `msg_tx` triggers
        /// `alive_interval.reset()` inside the sender task.  The exact variant is
        /// irrelevant for the timer behavior we are testing here.
        ///
        /// After sending, we yield once so the sender task is polled and actually
        /// processes the message.
        async fn send_dummy_message(&self) {
            self.msg_tx
                .send(DoipPayload::EntityStatusRequest(EntityStatusRequest {}))
                .await
                .unwrap();
            tokio::task::yield_now().await;
        }
    }

    /// This test validates that the alive check timer resets after each message send,
    /// ensuring the alive check only fires after a full interval of idle time.
    #[tokio::test]
    async fn alive_check_only_fires_when_idle() {
        let harness = GatewaySenderTestHarness::new(Duration::from_secs(10));

        // Sending messages before the interval elapses prevents alive check.
        // Send a message at t=4s (before 10s interval).
        tokio::time::advance(Duration::from_secs(4)).await;
        harness.send_dummy_message().await;

        // Advance another 4s (total 8s from last send, still within 10s interval).
        tokio::time::advance(Duration::from_secs(4)).await;
        harness.send_dummy_message().await;

        // Advance 9s (total 9s from last send, still within 10s interval).
        tokio::time::advance(Duration::from_secs(9)).await;
        tokio::task::yield_now().await;

        // The alive check interval has not elapsed since the last message send -
        // the sender task should still be running and no reset should have been requested.
        assert!(
            !harness.task.is_finished(),
            "Alive check should not have fired during active communication"
        );

        // Advance 2 more seconds (total 11s from last send, exceeds 10s interval).
        // The alive check fires: the responder task automatically replies with
        // AliveCheckResponse, so the request/response cycle completes without
        // waiting for any timeout.
        tokio::time::advance(Duration::from_secs(2)).await;
        // Yield twice so the sender task sends the request, the responder replies,
        // and the sender reads the response.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        // Task should still be alive after the alive check fired.
        assert!(
            !harness.task.is_finished(),
            "Task should still be running after alive check fired"
        );

        // After alive check fires, sending a message resets the timer.
        harness.send_dummy_message().await;

        // Advance 9s (within 10s interval from last send).
        tokio::time::advance(Duration::from_secs(9)).await;
        tokio::task::yield_now().await;

        assert!(
            !harness.task.is_finished(),
            "Alive check should not fire after timer reset by message send"
        );

        // Advance 2 more seconds (total 11s from last send) - alive check fires again.
        tokio::time::advance(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        assert!(
            !harness.task.is_finished(),
            "Task should still be running after second alive check fired"
        );

        // Clean up: abort the task.
        harness.task.abort();
        let _ = harness.task.await;
    }

    /// Validates that the alive check does not fire when the interval is set to zero
    /// (disabled).
    #[tokio::test]
    async fn alive_check_disabled_when_interval_zero() {
        let mut harness = GatewaySenderTestHarness::new(Duration::ZERO);

        // Advance a very long time - alive check should never fire.
        #[allow(unknown_lints, clippy::duration_suboptimal_units)]
        tokio::time::advance(Duration::from_secs(4200)).await;
        tokio::task::yield_now().await;

        assert!(
            harness.reset_rx.try_recv().is_err(),
            "Alive check should never fire when interval is zero (disabled)"
        );
        assert!(!harness.task.is_finished(), "Task should still be running");

        // Clean up: abort the task.
        harness.task.abort();
        let _ = harness.task.await;
    }

    /// Validates that when both a message and the alive check are ready simultaneously,
    /// the biased select ensures the message branch wins.
    #[tokio::test]
    async fn biased_select_prioritizes_messages_over_alive_check() {
        let mut harness = GatewaySenderTestHarness::new(Duration::from_secs(5));

        // Advance time past the alive check interval so both tick and message are ready.
        tokio::time::advance(Duration::from_secs(6)).await;
        // Send a message - both the tick and the message channel are now ready.
        harness.send_dummy_message().await;

        // Due to biased select the message branch is evaluated before the alive check
        // branch. The message is processed first, which resets the timer - so the
        // alive check does not fire this iteration and no reset is triggered.
        assert!(
            harness.reset_rx.try_recv().is_err(),
            "Biased select should process the message before the alive check,              \
             preventing an immediate reset"
        );
        assert!(!harness.task.is_finished(), "Task should still be running");

        // Clean up: abort the task.
        harness.task.abort();
        let _ = harness.task.await;
    }
}
