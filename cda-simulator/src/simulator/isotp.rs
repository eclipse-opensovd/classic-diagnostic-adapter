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

//! ISO-TP CAN server for receiving requests and sending responses.

use std::{sync::Arc, time::Duration};

use cda_interfaces::util::tokio_ext::sleep_for;
use tokio_socketcan_isotp::{IsoTpBehaviour, IsoTpOptions, IsoTpSocket, StandardId};

use super::{handler::RequestHandler, state::SimulatorState};
use crate::error::SimulatorError;

/// ISO-TP server that listens for diagnostic requests and sends responses
pub struct IsoTpServer {
    interface: String,
    /// CAN ID we receive on (client's request ID)
    rx_id: u32,
    /// CAN ID we transmit on (client's expected response ID)
    tx_id: u32,
}

impl IsoTpServer {
    /// Create a new ISO-TP server
    ///
    /// # Arguments
    /// * `interface` - CAN interface name (e.g., "vxcan1")
    /// * `request_id` - CAN ID the client sends requests on (we receive on this)
    /// * `response_id` - CAN ID the client expects responses on (we transmit on this)
    pub fn new(interface: String, request_id: u32, response_id: u32) -> Self {
        Self {
            interface,
            rx_id: request_id,  // We receive what the client sends
            tx_id: response_id, // We send what the client expects to receive
        }
    }

    /// Open an ISO-TP socket for the simulator (server mode)
    fn open_socket(&self) -> Result<IsoTpSocket, SimulatorError> {
        // For simulator (server):
        // - rx_id = request ID (what we receive = what client sends)
        // - tx_id = response ID (what we transmit = what client receives)
        #[allow(clippy::cast_possible_truncation)]
        let rx_id = StandardId::new(self.rx_id as u16).ok_or_else(|| {
            SimulatorError::Socket(format!("Invalid request CAN ID: 0x{:03X}", self.rx_id))
        })?;
        #[allow(clippy::cast_possible_truncation)]
        let tx_id = StandardId::new(self.tx_id as u16).ok_or_else(|| {
            SimulatorError::Socket(format!("Invalid response CAN ID: 0x{:03X}", self.tx_id))
        })?;

        // Enable TX padding to send 8-byte CAN frames (required by many ECUs/testers)
        let isotp_opts = IsoTpOptions::new(
            IsoTpBehaviour::CAN_ISOTP_TX_PADDING,
            Duration::ZERO, // frame_txtime
            0,              // ext_address
            0x00,           // txpad_content (padding byte value)
            0x00,           // rxpad_content
            0,              // rx_ext_address
        )
        .ok();

        IsoTpSocket::open_with_opts(&self.interface, rx_id, tx_id, isotp_opts, None, None).map_err(
            |e| {
                SimulatorError::Socket(format!(
                    "Failed to open ISO-TP socket on {}: {}",
                    self.interface, e
                ))
            },
        )
    }

    /// Run the server loop, processing incoming requests
    pub async fn run(&self, state: Arc<SimulatorState>) -> Result<(), SimulatorError> {
        let handler = RequestHandler::new(Arc::clone(&state));

        tracing::info!(
            interface = %self.interface,
            rx_id = format!("0x{:03X}", self.rx_id),
            tx_id = format!("0x{:03X}", self.tx_id),
            "ISO-TP server starting"
        );

        loop {
            // Open a fresh socket for each transaction
            // ISO-TP sockets can have state issues if reused
            let socket = match self.open_socket() {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to open socket, retrying in 1s");
                    sleep_for(Duration::from_secs(1)).await;
                    continue;
                }
            };

            // Wait for a request with a long timeout.
            // Duration::from_mins is unstable on the CI-pinned Rust 1.88, and
            // newer clippy flags from_secs(60); unknown_lints keeps the allow
            // itself from tripping 1.88 (which doesn't know that lint yet).
            #[allow(unknown_lints, clippy::duration_suboptimal_units)]
            let read_timeout = Duration::from_secs(60);
            match tokio::time::timeout(read_timeout, socket.read_packet()).await {
                Ok(Ok(request)) => {
                    state.inc_requests().await;

                    tracing::debug!(
                        request_hex = %hex::encode(&request),
                        request_len = request.len(),
                        "Received request"
                    );

                    // Handle the request
                    match handler.handle_request(&request).await {
                        Ok(Some(response)) => {
                            tracing::debug!(
                                response_hex = %hex::encode(&response),
                                response_len = response.len(),
                                "Sending response"
                            );

                            // Send the response
                            if let Err(e) = socket.write_packet(&response).await {
                                tracing::error!(error = %e, "Failed to send response");
                                state.inc_errors().await;
                            } else {
                                state.inc_responses().await;
                            }
                        }
                        Ok(None) => {
                            // No response needed (e.g., TesterPresent with suppress)
                            tracing::debug!("No response needed (suppress positive response)");
                            state.inc_responses().await;
                        }
                        Err(SimulatorError::UnsupportedService(sid, sub)) => {
                            tracing::warn!(
                                sid = format!("0x{:02X}", sid),
                                sub_function = sub.map(|s| format!("0x{:02X}", s)),
                                "Unsupported service"
                            );
                            state.inc_unsupported().await;

                            // Send negative response (0x7F, SID, NRC=0x11 serviceNotSupported)
                            let nrc = vec![0x7F, sid, 0x11];
                            if let Err(e) = socket.write_packet(&nrc).await {
                                tracing::error!(error = %e, "Failed to send NRC");
                                state.inc_errors().await;
                            } else {
                                state.inc_responses().await;
                            }
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "Handler error");
                            state.inc_errors().await;

                            // Try to send a generic negative response
                            if !request.is_empty() {
                                let nrc = vec![0x7F, request[0], 0x10]; // generalReject
                                let _ = socket.write_packet(&nrc).await;
                            }
                        }
                    }
                }
                Ok(Err(e)) => {
                    // Socket read error - log and continue
                    tracing::debug!(error = %e, "Socket read error");
                }
                Err(_) => {
                    // Timeout - just continue waiting
                    tracing::trace!("Read timeout, continuing...");
                }
            }
        }
    }
}
