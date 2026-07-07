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

use cda_interfaces::dlt_ctx;
use doip_definitions::payload::{AliveCheckResponse, DoipPayload};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, watch},
    time::Interval,
};

use crate::{
    DiagnosticResponse,
    connections::{ConnectionResetReason, try_read},
    ecu_connection::{ECUConnectionSend as _, EcuConnectionTarget},
};

#[tracing::instrument(
    skip_all,
    fields(
        dlt_context = dlt_ctx!("DOIP")
    )
)]
pub(crate) fn spawn_gateway_sender_task<T>(
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
            let mut alive_interval = alive_check_enabled.then(|| {
                let mut interval = tokio::time::interval_at(
                    // If setting a huge value for the alive check this is okay to fail,
                    // as it is guarded by a config sanity check.
                    tokio::time::Instant::now()
                        .checked_add(alive_check_interval)
                        .expect("Failed to set interval, alive check value is too big"),
                    alive_check_interval,
                );
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                interval
            });
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
                       alive_interval.as_mut().map(Interval::reset);
                    },

                   _ = async {
                        match alive_interval.as_mut() {
                                Some(interval) => interval.tick().await,
                                None => std::future::pending().await,
                            }
                        }, if alive_check_enabled => {
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

    // TODO: handle alive request errors according to spec, see #430
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
        connection_sender::spawn_gateway_sender_task,
        connections::ConnectionResetReason,
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
            protocol_version: ProtocolVersion::Iso13400_2012,
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
        #[allow(
            unknown_lints,
            clippy::duration_suboptimal_units,
            reason = "Literal duration value chosen for test clarity; suboptimal units lint not \
                      available in all toolchain versions"
        )]
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
