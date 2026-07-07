/*
 * SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation
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

use cda_interfaces::{EcuConnectivityHandler, HashMap, dlt_ctx};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{broadcast, mpsc, watch},
};

use crate::{
    ConnectionError, DiagnosticResponse, GatewaySetup,
    connections::{ConnectionResetReason, EcuError, ReceiverChannels, try_read},
    ecu_connection::EcuConnectionTarget,
};

/// Waits for the sender task to finish a pending transmission before the
/// receiver may resume reading.  Returns `Err(())` when the watch channel
/// has been closed and the task should exit.
pub(super) async fn handle_send_pending(
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
pub(super) fn handle_diagnostic_message_ack(
    gateway_name: &str,
    gateway_ip: &str,
    outtx: &HashMap<u16, broadcast::Sender<Result<DiagnosticResponse, EcuError>>>,
    source_address: u16,
    response: DiagnosticResponse,
) {
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

#[tracing::instrument(
        skip_all,
        fields(dlt_context = dlt_ctx!("DOIP"))
    )]
pub(super) async fn handle_diagnostic_message(
    gateway_name: &str,
    outtx: &HashMap<u16, broadcast::Sender<Result<DiagnosticResponse, EcuError>>>,
    msg: doip_definitions::payload::DiagnosticMessage,
) {
    let addr = u16::from_be_bytes(msg.source_address);
    // ISO 13400-2:2012 9.5 states that only a server should send ACKs,
    // therefore forwarding the message to the client without sending an ACK to the gateway.
    tracing::debug!(
            gateway_name = %gateway_name,
            ecu_address = %addr,
            "Received message from ECU");
    outtx
        .get(&addr)
        .map(|router| router.send(Ok(DiagnosticResponse::Msg(msg))));
}

#[tracing::instrument(
        skip_all,
        fields(dlt_context = dlt_ctx!("DOIP"))
    )]
pub(super) fn handle_alive_check_request() {
    tracing::debug!("Received Alive Check Response. Probably ECU responded too slow");
}

#[tracing::instrument(
        skip_all,
        fields(dlt_context = dlt_ctx!("DOIP"))
    )]
pub(super) fn handle_generic_nack() {
    // todo implement generic NACK handling according to spec #22
    tracing::error!("Received Generic NACK");
}

/// Dispatches a raw `DiagnosticResponse` received from the gateway.
/// Thin coordinator: delegates to `handle_ok_response` or
/// `handle_connection_error` so each branch has its own focused function.
#[tracing::instrument(
        skip_all,
        fields(dlt_context = dlt_ctx!("DOIP"))
    )]
pub(super) async fn handle_response(
    gateway_name: &str,
    gateway_ip: &str,
    outtx: &HashMap<u16, broadcast::Sender<Result<DiagnosticResponse, EcuError>>>,
    reset_tx: &mpsc::Sender<ConnectionResetReason>,
    response: Option<Result<DiagnosticResponse, ConnectionError>>,
    ecu_names: &[String],
    connectivity_handler: &Arc<dyn EcuConnectivityHandler>,
) {
    let Some(result) = response else {
        return;
    };
    match result {
        Ok(response) => {
            handle_ok_response(gateway_name, gateway_ip, outtx, response).await;
        }
        Err(err) => {
            handle_connection_error(
                gateway_name,
                gateway_ip,
                reset_tx,
                err,
                ecu_names,
                connectivity_handler,
            )
            .await;
        }
    }
}

/// Handles all variants of a successfully decoded `DiagnosticResponse`.
#[tracing::instrument(
        skip_all,
        fields(dlt_context = dlt_ctx!("DOIP"))
    )]
async fn handle_ok_response(
    gateway_name: &str,
    gateway_ip: &str,
    outtx: &HashMap<u16, broadcast::Sender<Result<DiagnosticResponse, EcuError>>>,
    response: DiagnosticResponse,
) {
    match response {
        DiagnosticResponse::Ack((source_address, _)) => {
            handle_diagnostic_message_ack(
                gateway_name,
                gateway_ip,
                outtx,
                source_address,
                response,
            );
        }
        DiagnosticResponse::Pending { source_address, .. }
        | DiagnosticResponse::BusyRepeatRequest { source_address, .. }
        | DiagnosticResponse::TemporarilyNotAvailable { source_address, .. } => {
            outtx
                .get(&source_address)
                .map(|router| router.send(Ok(response)));
        }
        DiagnosticResponse::Msg(msg) => {
            handle_diagnostic_message(gateway_name, outtx, msg).await;
        }
        DiagnosticResponse::Nack(nack) => {
            tracing::debug!(nack = ?nack, "Received NACK");
            let addr = u16::from_be_bytes(nack.source_address);
            outtx
                .get(&addr)
                .map(|router| router.send(Ok(DiagnosticResponse::Nack(nack))));
        }
        DiagnosticResponse::GenericNack(_) => {
            handle_generic_nack();
        }
        DiagnosticResponse::AliveCheckResponse => {
            handle_alive_check_request();
        }
        DiagnosticResponse::TesterPresentNRC(c) => {
            tracing::debug!(nrc = ?c, "Received Tester Present NRC");
        }
    }
}

/// Handles connection-level errors received from the gateway.
#[tracing::instrument(
        skip_all,
        fields(dlt_context = dlt_ctx!("DOIP"))
    )]
async fn handle_connection_error(
    gateway_name: &str,
    gateway_ip: &str,
    reset_tx: &mpsc::Sender<ConnectionResetReason>,
    err: ConnectionError,
    ecu_names: &[String],
    connectivity_handler: &Arc<dyn EcuConnectivityHandler>,
) {
    match err {
        ConnectionError::Closed => {
            if let Err(e) = reset_tx
                .send("Connection has been closed.".to_owned())
                .await
            {
                tracing::error!(
                    gateway_name = %gateway_name,
                    gateway_ip = %gateway_ip,
                    error = ?e,
                    "Failed to send connection reset request"
                );
            }
            // Notify UDS layer that ECUs on this connection are disconnected
            connectivity_handler
                .on_gateway_disconnected(ecu_names)
                .await;
        }
        _ => {
            // for POC purposes we just log the error and do not reset the connection
            tracing::error!(
                gateway_name = %gateway_name,
                gateway_ip = %gateway_ip,
                error = ?err,
                "Error reading response, either due to timeout or decoding issue"
            );
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "Contains receiver loop that should remain in scope"
)]
#[tracing::instrument(
    skip_all,
    fields(
        gateway_ip = %gateway_conn.gateway_doip_config.gateway_ip,
        gateway_name = %gateway_conn.gateway_doip_config.name,
        active_ecus = outtx.len(),
        dlt_context = dlt_ctx!("DOIP"),
    )
)]
pub(crate) fn spawn_gateway_receiver_task<T>(
    gateway: GatewaySetup,
    outtx: HashMap<u16, broadcast::Sender<Result<DiagnosticResponse, EcuError>>>,
    gateway_conn: Arc<EcuConnectionTarget<T>>,
    channels: ReceiverChannels,
) -> tokio::task::JoinHandle<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let gateway_id = GatewayIdentity {
        ip: gateway.connection.doip.gateway_ip,
        name: gateway.connection.doip.name,
    };
    let ReceiverChannels {
        mut send_pending_rx,
        reset_tx,
    } = channels;
    let ecu_names = gateway.ecu_names;
    let connectivity_handler = gateway.connectivity_handler;

    cda_interfaces::spawn_named!(&format!("gateway-receiver-{}", gateway_id.ip), async move {
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
                        &gateway_id.name,
                        &gateway_id.ip,
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
                            &gateway_id.name,
                            &gateway_id.ip,
                            &outtx,
                            &reset_tx,
                            response,
                            &ecu_names,
                            &connectivity_handler,
                        ).await;
                    }
                }
            }
        }
    })
}

/// Identity of a `DoIP` gateway (IP address and ECU name).
#[derive(Debug)]
struct GatewayIdentity {
    ip: String,
    name: String,
}

#[cfg(test)]
mod tests {
    use cda_interfaces::HashMapExtensions;
    use doip_definitions::payload::DiagnosticMessage;
    use tokio::sync::broadcast;

    use super::*;

    type EcuResponse = Result<DiagnosticResponse, EcuError>;
    type OutTxMap = HashMap<u16, broadcast::Sender<EcuResponse>>;
    type EcuResponseRx = broadcast::Receiver<EcuResponse>;

    fn make_outtx(addr: u16) -> (OutTxMap, EcuResponseRx) {
        let (tx, rx) = broadcast::channel(8);
        let mut map = HashMap::new();
        map.insert(addr, tx);
        (map, rx)
    }

    #[tokio::test]
    async fn diag_msg_sends_ack_and_routes_response() {
        let source: u16 = 0x0020;
        let target: u16 = 0x0001;
        let (outtx, mut ecu_rx) = make_outtx(source);

        let msg = DiagnosticMessage {
            source_address: source.to_be_bytes(),
            target_address: target.to_be_bytes(),
            message: vec![0x50, 0x01],
        };

        handle_diagnostic_message("gw", &outtx, msg).await;
        // The message must have been forwarded to the ECU channel
        let resp = ecu_rx.try_recv().expect("expected DiagnosticResponse::Msg");
        assert!(matches!(resp, Ok(DiagnosticResponse::Msg(_))));
    }

    #[tokio::test]
    async fn pending_nrc_routes_to_correct_channel() {
        let addr: u16 = 0x0030;
        let (outtx, mut rx) = make_outtx(addr);

        handle_ok_response(
            "gw",
            "1.2.3.4",
            &outtx,
            DiagnosticResponse::Pending {
                source_address: addr,
                request_sid: 0x42,
            },
        )
        .await;

        let msg = rx.try_recv().expect("expected Pending on channel");
        assert!(matches!(msg, Ok(DiagnosticResponse::Pending { .. })));
    }

    #[tokio::test]
    async fn nack_routes_to_correct_channel() {
        use doip_definitions::payload::{DiagnosticMessageNack, DiagnosticNackCode};
        let addr: u16 = 0x0040;
        let (outtx, mut rx) = make_outtx(addr);

        let nack = DiagnosticMessageNack {
            source_address: addr.to_be_bytes(),
            target_address: 0x0001u16.to_be_bytes(),
            nack_code: DiagnosticNackCode::ReservedByIso13400_00,
        };
        handle_ok_response("gw", "1.2.3.4", &outtx, DiagnosticResponse::Nack(nack)).await;

        let msg = rx.try_recv().expect("expected Nack on channel");
        assert!(matches!(msg, Ok(DiagnosticResponse::Nack(_))));
    }
}
