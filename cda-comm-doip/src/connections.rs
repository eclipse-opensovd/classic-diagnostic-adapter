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

use std::{sync::Arc, time::Duration};

use cda_interfaces::{
    DoipComParamProvider, EcuAddressProvider, TesterPresentControlMessage, TesterPresentMode,
    TesterPresentType, service_ids,
};
use doip_definitions::payload::{
    ActivationType, AliveCheckRequest, DiagnosticMessage, DoipPayload, RoutingActivationRequest,
};
use hashbrown::HashMap;
use tokio::sync::{Mutex, RwLock, broadcast, mpsc, watch};

use crate::{
    ConnectionError, DiagnosticResponse, DoipConnection, DoipEcu, DoipTarget, LOG_TARGET,
    NRC_BUSY_REPEAT_REQUEST, NRC_RESPONSE_PENDING, NRC_TEMPORARILY_NOT_AVAILABLE, SLEEP_INTERVAL,
    ecu_connection::{self, ECUConnection, EcuConnectionTarget},
};

type ConnectionResetReason = String;

struct ConnectionSettings {
    routing_activation: Duration,
    retry_delay: Duration,
    connect_timeout: Duration,
    max_retry_attempts: u32,
}

pub(crate) async fn handle_gateway_connection<T>(
    gateway: DoipTarget,
    doip_connections: &Arc<RwLock<Vec<Arc<DoipConnection>>>>,
    ecus: &Arc<HashMap<String, RwLock<T>>>,
    gateway_ecu_map: &HashMap<u16, Vec<u16>>,
    tester_present: mpsc::Sender<TesterPresentControlMessage>,
) -> Result<u16, String>
where
    T: EcuAddressProvider + DoipComParamProvider,
{
    let tester_address = ecus
        .get(&gateway.ecu)
        .map(|ecu| async { ecu.read().await.tester_address() })
        .ok_or_else(|| "ECU not found".to_owned())?
        .await;

    let routing_activation_request = RoutingActivationRequest {
        source_address: tester_address.to_be_bytes(),
        activation_type: ActivationType::Default,
        buffer: [0, 0, 0, 0],
    };

    let ecu_ids: Vec<u16> = if let Some(ecu_ids) = gateway_ecu_map.get(&gateway.logical_address) {
        ecu_ids.clone()
    } else {
        return Err(format!(
            "No ECUs found for gateway address {}. Skipping, as the gateway cannot be used.",
            gateway.logical_address
        ));
    };

    let gateway_ecu = match ecus.get(&gateway.ecu) {
        Some(ecu) => ecu.read().await,
        None => return Err("Failed to find gateway ECU".to_owned()),
    };
    let routing_activation_timeout = gateway_ecu.routing_activation_timeout();
    let connection_retry_delay = gateway_ecu.connection_retry_delay();
    let connection_timeout = gateway_ecu.connection_timeout();
    let connection_retry_attempts = gateway_ecu.connection_retry_attempts();

    let (sender, receiver) = match connection_handler(
        gateway.ip.clone(),
        gateway.ecu.clone(),
        routing_activation_request,
        tester_present,
        ecu_ids.clone(),
        ConnectionSettings {
            routing_activation: routing_activation_timeout,
            retry_delay: connection_retry_delay,
            connect_timeout: connection_timeout,
            max_retry_attempts: connection_retry_attempts,
        },
    )
    .await
    {
        Ok((sender, receiver)) => (sender, receiver),
        Err(e) => {
            return Err(format!("Failed to connect to {}: {}", gateway.ecu, e));
        }
    };

    let doip_ecus = create_ecu_receiver_map(ecu_ids, &sender, &receiver);

    log::info!(target: &gateway.ecu, "Connected to {} on logical address {:#06x}", gateway.ecu, gateway.logical_address);
    doip_connections
        .write()
        .await
        .push(Arc::new(DoipConnection {
            ecus: doip_ecus,
            ip: gateway.ip,
        }));

    Ok(gateway.logical_address)
}

fn create_ecu_receiver_map(
    ecus: Vec<u16>,
    sender: &mpsc::Sender<DiagnosticMessage>, // sender is shared between all ecus of a gateway
    receiver: &HashMap<u16, broadcast::Receiver<Result<DiagnosticResponse, String>>>,
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
                log::warn!(target: LOG_TARGET, "ECU {logical_address} not found in receiver map");
            }
        }
    }

    doip_ecus
}

async fn connection_handler(
    gateway_ip: String,
    gateway_name: String,
    routing_activation_request: RoutingActivationRequest,
    tester_present: mpsc::Sender<TesterPresentControlMessage>,
    ecus: Vec<u16>,
    connection_settings: ConnectionSettings,
) -> Result<
    (
        mpsc::Sender<DiagnosticMessage>,
        HashMap<u16, broadcast::Receiver<Result<DiagnosticResponse, String>>>,
    ),
    String,
> {
    let log_target = format!("{gateway_name} ({gateway_ip})");

    // channel to send messages to the gateway / ecus
    let (intx, inrx) = mpsc::channel::<DiagnosticMessage>(50);

    // channel to receive messages from the gateway / ecus
    let mut outrx: HashMap<u16, broadcast::Receiver<Result<DiagnosticResponse, String>>> =
        HashMap::new();
    // channel used by the receiver task to distribute messages to the correct ecu,
    // counterpart to outrx
    let mut outtx: HashMap<u16, broadcast::Sender<Result<DiagnosticResponse, String>>> =
        HashMap::new();

    // create ecu response channels
    for ecu in ecus {
        let (tx, rx) = broadcast::channel::<Result<DiagnosticResponse, String>>(10);

        outtx.insert(ecu, tx);
        outrx.insert(ecu, rx);
    }

    // setting up initial gateway connection
    let gateway_conn = Arc::new(Mutex::new(
        setup_connection(
            routing_activation_request,
            &gateway_ip,
            &log_target,
            connection_settings.connect_timeout,
            connection_settings.routing_activation,
        )
        .await?,
    ));

    // used by receiver / sender task to reset the connection
    let (conn_reset_tx, conn_reset_rx) = mpsc::channel::<ConnectionResetReason>(1);
    // task to handle connection resets and reconnects
    let conn_reset = Arc::<Mutex<EcuConnectionTarget>>::clone(&gateway_conn);
    spawn_connection_reset_task(
        gateway_ip.clone(),
        routing_activation_request,
        conn_reset_rx,
        conn_reset,
        connection_settings,
    );

    // communication between send / receiver task to unlock the connection in the receiver task
    // when sender task wants to send something
    let (send_pending_tx, send_pending_rx) = watch::channel::<bool>(false);
    let send_mtx = Arc::new(Mutex::new(()));
    spawn_gateway_sender_task(
        gateway_ip.clone(),
        inrx,
        Arc::<Mutex<EcuConnectionTarget>>::clone(&gateway_conn),
        conn_reset_tx.clone(),
        send_pending_tx.clone(),
        Arc::clone(&send_mtx),
    );
    spawn_gateway_receiver_task(
        gateway_ip.clone(),
        log_target.clone(),
        outtx,
        Arc::<Mutex<EcuConnectionTarget>>::clone(&gateway_conn),
        send_pending_rx,
        conn_reset_tx,
    );
    spawn_tester_present_task(gateway_name, log_target, tester_present, send_pending_tx);

    // no need to wait until the connection is alive, we will reconnect automatically anyway
    Ok((intx, outrx))
}

async fn setup_connection(
    routing_activation_request: RoutingActivationRequest,
    gateway_ip: &str,
    log_target: &str,
    connect_timeout: Duration,
    routing_activation_timeout: Duration,
) -> Result<EcuConnectionTarget, String> {
    ecu_connection::establish_ecu_connection(
        gateway_ip,
        routing_activation_request,
        log_target,
        connect_timeout,
        routing_activation_timeout,
    )
    .await
}

fn spawn_connection_reset_task(
    gateway_ip: String,
    routing_activation_request: RoutingActivationRequest,
    mut conn_reset_rx: mpsc::Receiver<ConnectionResetReason>,
    conn_reset: Arc<Mutex<EcuConnectionTarget>>,
    connection_timeouts: ConnectionSettings,
) {
    cda_interfaces::spawn_named!(
        &format!("doip-connection-reset-{gateway_ip}"),
        Box::pin(async move {
            loop {
                let mut reconnect_attempts = 0;
                if let Some(reason) = conn_reset_rx.recv().await {
                    let mut conn_mtx = conn_reset.lock().await;
                    let conn = &mut *conn_mtx;
                    log::info!(target: &conn.log_target, "Resetting connection due to {reason}");

                    'reconnect: loop {
                        let new_connection = setup_connection(
                            routing_activation_request,
                            &gateway_ip,
                            &conn.log_target,
                            connection_timeouts.connect_timeout,
                            connection_timeouts.routing_activation,
                        )
                        .await;

                        match new_connection {
                            Ok(conn) => {
                                log::info!(target: &conn.log_target, "Connection reset successful");
                                *conn_mtx = conn;
                                while !conn_reset_rx.is_empty() {
                                    // drain the receiver to avoid resetting the connection again
                                    // immediately after a reset
                                    if conn_reset_rx.recv().await.is_none() {
                                        log::warn!("Connection reset receiver closed");
                                        return;
                                    }
                                }
                                break 'reconnect;
                            }
                            Err(e) => {
                                log::error!(
                                    "Failed to reset connection: {e:?}, retrying in {:?}",
                                    connection_timeouts.retry_delay
                                );
                                tokio::time::sleep(connection_timeouts.retry_delay).await;
                                reconnect_attempts += 1;
                                if reconnect_attempts >= connection_timeouts.max_retry_attempts {
                                    log::error!(
                                        target: &conn.log_target,
                                        "Max reconnect attempts reached, giving up"
                                    );
                                    return;
                                }
                            }
                        }
                    }
                } else {
                    log::warn!("Connection reset receiver closed");
                    break;
                }
            }
        })
    );
}

fn spawn_gateway_sender_task(
    gateway_ip: String,
    mut inrx: mpsc::Receiver<DiagnosticMessage>,
    gateway_conn: Arc<Mutex<EcuConnectionTarget>>,
    reset_tx: mpsc::Sender<ConnectionResetReason>,
    send_pending_tx: watch::Sender<bool>,
    send_mtx: Arc<Mutex<()>>,
) {
    cda_interfaces::spawn_named!(&format!("doip-gateway-sender-{gateway_ip}"), async move {
        fn send_pending_status(
            send_pending_tx: &watch::Sender<bool>,
            value: bool,
        ) -> Result<(), ()> {
            send_pending_tx.send(value).map_err(|_| {
                log::warn!("Send pending receiver closed");
            })
        }

        loop {
            tokio::select! {
                Some(msg) = inrx.recv() => {
                    let lock = send_mtx.lock().await;
                    // let rx task know that we want to send something.
                    if send_pending_status(&send_pending_tx, true).is_err() {
                        break;
                    }

                    let start = std::time::Instant::now();
                    let mut conn_mtx = gateway_conn.lock().await;
                    let conn = &mut *conn_mtx;
                    let lock_after = start.elapsed();

                    if let Err(e) = conn
                        .ecu_connection
                        .send(DoipPayload::DiagnosticMessage(msg))
                        .await
                    {
                        log::error!(target: &conn.log_target, "Failed to send message: {e:?}");
                    }

                    let send_after = start.elapsed() - lock_after;
                    log::debug!(
                        target: LOG_TARGET, "Send request in {:?}, \
                        got conn_lock after {:?}, sent payload after {:?}",
                        start.elapsed(), lock_after, send_after
                    );
                    // inform the rx task that we are done sending
                    if send_pending_status(&send_pending_tx, false).is_err() {
                        break;
                    }
                    drop(lock);
                },
                _ = tokio::time::sleep(SLEEP_INTERVAL) => {
                    let lock = send_mtx.lock().await;
                    if send_pending_status(&send_pending_tx, true).is_err() {
                        break;
                    }

                    let (alive_response, log_target) = {
                        let mut conn_mtx = gateway_conn.lock().await;
                        let conn = &mut *conn_mtx;
                        (send_alive_request(conn).await, conn.log_target.clone())
                    };

                    if let Err(e) = alive_response {
                        log::error!(
                            target: &log_target,
                            "Failed to send alive check request: {e:?}, resetting connection"
                        );
                        // no need for any 'sleep' here, the reset task holds the connection
                        // lock until the connection is ready again.
                        if let Err(e) = reset_tx
                            .send("Unable to send alive check request".to_owned())
                            .await
                        {
                            log::error!(
                                target: &log_target,
                                "Failed to send connection reset request: {e:?}"
                            );
                            // if the reset channel is closed, we cannot reset the connection
                            // and there is no point in continuing
                            break;
                        }
                    }

                    if send_pending_status(&send_pending_tx, false).is_err() {
                        break;
                    }
                    drop(lock);
                }
            }
        }
    });
}

fn spawn_gateway_receiver_task(
    gateway_ip: String,
    log_target: String,
    outtx: HashMap<u16, broadcast::Sender<Result<DiagnosticResponse, String>>>,
    gateway_conn: Arc<Mutex<EcuConnectionTarget>>,
    mut send_pending_rx: watch::Receiver<bool>,
    reset_tx: mpsc::Sender<ConnectionResetReason>,
) {
    // note: the handlers are defined here, as rustfmt cannot format the correctly inside the
    // tokio::select! macro block

    async fn handle_send_pending(
        log_target: &str,
        send_pending_rx: &mut watch::Receiver<bool>,
        send_pending_result: Result<(), watch::error::RecvError>,
    ) -> Result<(), ()> {
        let request_received = std::time::Instant::now();
        if send_pending_result.is_ok() {
            log::debug!(target: &log_target, "Received tx request, unlocking connection");
            let send_pending = *send_pending_rx.borrow();
            if send_pending {
                match send_pending_rx.changed().await {
                    Ok(()) => {
                        log::debug!(
                            "Send done after {:?}, continue rx await",
                            request_received.elapsed()
                        );
                    }
                    Err(e) => {
                        log::warn!("Send pending receiver closed: {e:?}");
                        return Err(());
                    }
                }
            }
            Ok(())
        } else {
            log::warn!(target: log_target, "Send pending receiver closed");
            Err(())
        }
    }

    async fn handle_response(
        log_target: &str,
        outtx: &HashMap<u16, broadcast::Sender<Result<DiagnosticResponse, String>>>,
        reset_tx: &mpsc::Sender<ConnectionResetReason>,
        response: Option<Result<DiagnosticResponse, ConnectionError>>,
    ) {
        match response {
            Some(Ok(response)) => {
                match response {
                    DiagnosticResponse::Ack(source_address) => {
                        log::debug!(target: &log_target, "Received ACK");
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
                        log::debug!(target: &log_target, "UDS OK - Returning response");
                        let addr = u16::from_be_bytes(msg.source_address);
                        outtx
                            .get(&addr)
                            .map(|router| router.send(Ok(DiagnosticResponse::Msg(msg))));
                    }
                    DiagnosticResponse::Nack(nack) => {
                        log::debug!(target: &log_target, "Received NACK: {nack:?}");
                        let addr = u16::from_be_bytes(nack.source_address);
                        outtx
                            .get(&addr)
                            .map(|router| router.send(Ok(DiagnosticResponse::Nack(nack))));
                    }
                    DiagnosticResponse::GenericNack(_) => {
                        // todo implement generic NACK handling according to spec #22
                        log::error!(target: &log_target, "Received Generic NACK");
                    }
                    DiagnosticResponse::AliveCheckResponse => {
                        log::debug!(target: &log_target,
                            "Received Alive Check Response. Probably ECU responded too slow");
                    }
                    DiagnosticResponse::TesterPresentNRC(c) => {
                        log::debug!(target: &log_target, "Received Tester Present NRC: {c:?}");
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
                            log::error!(
                                target: &log_target,
                                "Failed to send connection reset request: {e:?}"
                            );
                        }
                    }
                    _ => {
                        // for POC purposes we just log the error and do not reset the connection
                        log::error!(
                            target: &log_target,
                            "Error reading response: {err:?}, \
                            either due to timeout or decoding issue"
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
                log::debug!(
                    target: &log_target,
                    "All out channels closed. Shutting down connection"
                );
                break;
            }

            // wait for a message to be received or a send request
            tokio::select! {
                send_pending_result = send_pending_rx.changed() => {
                    if let Err(()) = handle_send_pending(
                        &log_target,
                        &mut send_pending_rx,
                        send_pending_result
                    ).await {
                        break 'receive;
                    }
                },

                response = async {
                    let mut conn_mtx = gateway_conn.lock().await;
                    let conn = &mut *conn_mtx;

                    // we can wait without actual timeout because this will be
                    // interrupted by the send_pending_rx when someone wants to send
                    // data on the connection
                    try_read(Duration::MAX, &mut conn.ecu_connection).await
                } => {
                    handle_response(&log_target, &outtx, &reset_tx, response).await;
                }
            }
        }
    });
}

fn spawn_tester_present_task(
    gateway_name: String,
    log_target: String,
    tester_present: mpsc::Sender<TesterPresentControlMessage>,
    send_pending_tx: watch::Sender<bool>,
) {
    cda_interfaces::spawn_named!(
        &format!("tester-present-gateway-{gateway_name}"),
        async move {
            if tester_present
                .send(TesterPresentControlMessage {
                    mode: TesterPresentMode::Start,
                    type_: TesterPresentType::Functional,
                    ecu: gateway_name.clone(),
                    interval: None,
                })
                .await
                .is_err()
            {
                log::error!(target: &log_target,
                    "Failed to send start tester present control message");
            }

            send_pending_tx.closed().await;

            if tester_present
                .send(TesterPresentControlMessage {
                    mode: TesterPresentMode::Stop,
                    type_: TesterPresentType::Functional,
                    ecu: gateway_name,
                    interval: None,
                })
                .await
                .is_err()
            {
                log::error!(target: &log_target,
                    "Failed to send stop tester present control message");
            }
        }
    );
}

async fn send_alive_request(conn: &mut EcuConnectionTarget) -> Result<(), ()> {
    async fn handle_alive_request_response(conn: &mut EcuConnectionTarget) {
        match try_read(Duration::from_millis(1000), &mut conn.ecu_connection).await {
            Some(Ok(DiagnosticResponse::AliveCheckResponse)) => {
                log::debug!(target: &conn.log_target, "Alive check OK");
            }
            Some(Ok(DiagnosticResponse::Ack(_))) => {
                log::debug!(target: &conn.log_target, "Received ACK");
                Box::pin(handle_alive_request_response(conn)).await;
            }
            Some(Ok(DiagnosticResponse::GenericNack(_))) => {
                log::debug!(target: &conn.log_target, "Received Generic NACK");
            }
            Some(Ok(msg)) => {
                log::error!(target: &conn.log_target, "Received Unrelated msg: {msg:?}");
            }
            Some(Err(e)) => {
                log::error!(target: &conn.log_target, "Error reading alive check response: {e}");
            }
            None => {
                log::debug!(target: &conn.log_target, "Timeout waiting for alive check response");
            }
        }
    }

    // TODO: handle alive request errors according to spec
    match conn
        .ecu_connection
        .send(DoipPayload::AliveCheckRequest(AliveCheckRequest {}))
        .await
    {
        Ok(()) => {
            handle_alive_request_response(conn).await;
            Ok(())
        }
        Err(e) => {
            log::error!(target: &conn.log_target, "Failed to send alive check request: {e:?}");
            Err(())
        }
    }
}

async fn try_read(
    timeout: Duration,
    reader: &mut impl ECUConnection,
) -> Option<Result<DiagnosticResponse, ConnectionError>> {
    async fn read_response(
        reader: &mut impl ECUConnection,
    ) -> Result<DiagnosticResponse, ConnectionError> {
        match reader.read().await {
            Some(Ok(msg)) => match msg.payload {
                DoipPayload::DiagnosticMessage(msg) => {
                    // handle NRCs
                    if let Some(&0x7f) = msg.message.first() {
                        let request_sid = msg.message.get(1).copied().unwrap_or(0);
                        let error_code = msg.message.get(2).copied().unwrap_or(0);

                        if request_sid == service_ids::TESTER_PRESENT {
                            return Ok(DiagnosticResponse::TesterPresentNRC(error_code));
                        }

                        let source_address = u16::from_be_bytes(msg.source_address);
                        let response = match error_code {
                            NRC_RESPONSE_PENDING => {
                                log::debug!(
                                    target: LOG_TARGET,
                                     "UDS NRC - Response pending {:?}",
                                     msg.message);
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
                    log::debug!(target: LOG_TARGET, "Received diagnostic message ack");
                    Ok(DiagnosticResponse::Ack(u16::from_be_bytes(
                        ack.source_address,
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

    tokio::select! {
        response = read_response(reader) => Some(response),
        () = tokio::time::sleep(timeout) => None,
    }
}
