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

use std::time::Duration;

use tokio_socketcan_isotp::{IsoTpBehaviour, IsoTpOptions, IsoTpSocket};

use super::{can_id::CanId, error::CanError};

/// Represents a CAN connection to a single ECU using ISO-TP.
pub struct CanEcuConnection {
    /// ECU name for logging/identification
    pub ecu_name: String,
    /// Physical request CAN ID
    pub request_id: CanId,
    /// Physical response CAN ID
    pub response_id: CanId,
    /// CAN interface name
    interface: String,
}

impl CanEcuConnection {
    /// Creates a new CAN ECU connection configuration.
    #[must_use]
    pub fn new(ecu_name: String, interface: String, request_id: CanId, response_id: CanId) -> Self {
        Self {
            ecu_name,
            request_id,
            response_id,
            interface,
        }
    }

    /// Opens an ISO-TP socket for this ECU connection.
    ///
    /// Supports both 11-bit standard and 29-bit extended CAN IDs; see
    /// [`CanId`].
    fn open_socket(&self) -> Result<IsoTpSocket, CanError> {
        // Following tokio IsoTpSocket naming scheme:
        // src (ISO-TP rx_id) = what we receive on (ECU's response ID, e.g. 0x7E8)
        // dst (ISO-TP tx_id) = what we transmit on (ECU's request ID, e.g. 0x7E0)
        let src = self.response_id.to_socket_id()?;
        let dst = self.request_id.to_socket_id()?;

        // Enable TX padding to send 8-byte CAN frames (required by many ECUs)
        let isotp_opts = IsoTpOptions::new(
            IsoTpBehaviour::CAN_ISOTP_TX_PADDING,
            Duration::ZERO, // frame_txtime
            0,              // ext_address
            0x00,           // txpad_content (padding byte value)
            0x00,           // rxpad_content
            0,              // rx_ext_address
        )
        .ok();

        IsoTpSocket::open_with_opts(&self.interface, src, dst, isotp_opts, None, None).map_err(
            |e| {
                CanError::SocketError(format!(
                    "Failed to open ISO-TP socket on {}: {}",
                    self.interface, e
                ))
            },
        )
    }

    /// Verifies that an ISO-TP socket can be opened for this connection.
    ///
    /// Used at gateway setup to fail fast when the CAN interface does not
    /// exist (or the socketcand daemon is unreachable) instead of timing out
    /// on every probe and request later.
    pub(crate) fn check_open(&self) -> Result<(), CanError> {
        self.open_socket().map(|_| ())
    }

    /// Sends a UDS request and waits for a single response.
    ///
    /// Opens a fresh ISO-TP socket, sends the request, reads one response, and
    /// drops the socket. For interactions that require multiple reads on the same
    /// socket (e.g., NRC 0x78 Response Pending), use [`begin_exchange`] instead.
    pub async fn send_receive(
        &self,
        request: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, CanError> {
        let exchange = self.begin_exchange(request).await?;
        exchange.read_response(timeout).await
    }

    /// Opens an ISO-TP socket, sends the request, and returns a [`CanExchange`]
    /// that keeps the socket alive for reading follow-up responses.
    ///
    /// This is essential for handling NRC 0x78 (Response Pending): the ECU sends
    /// a pending notification and then later the real response on the same
    /// transport connection. Dropping the socket between reads would create a
    /// race where the real response arrives while no socket is listening.
    pub async fn begin_exchange(&self, request: &[u8]) -> Result<CanExchange, CanError> {
        let socket = self.open_socket()?;

        tracing::debug!(
            ecu = %self.ecu_name,
            request_id = %self.request_id,
            response_id = %self.response_id,
            data = %hex::encode(request),
            "Sending CAN request"
        );

        socket.write_packet(request).await.map_err(|e| {
            CanError::SendFailed(format!("Failed to send to {}: {}", self.ecu_name, e))
        })?;

        Ok(CanExchange {
            socket,
            ecu_name: self.ecu_name.clone(),
        })
    }

    /// Probes the ECU using the provided request payload.
    ///
    /// Any non-empty response counts as proof that the ECU is alive. This allows
    /// discovery fallbacks such as lightweight `ReadDataByIdentifier` requests.
    ///
    /// # Errors
    /// Returns an error if the request fails, times out, or the ECU sends an empty response.
    pub async fn probe_with_payload(
        &self,
        request: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, CanError> {
        let response = self.send_receive(request, timeout).await?;

        if response.is_empty() {
            Err(CanError::ReceiveFailed(format!(
                "Received empty probe response from {}",
                self.ecu_name
            )))
        } else {
            Ok(response)
        }
    }

    /// Returns a network address string for this connection.
    /// Format: "interface:request_id->response_id"
    #[must_use]
    pub fn network_address(&self) -> String {
        format!(
            "{}:{}->{}",
            self.interface, self.request_id, self.response_id
        )
    }
}

/// An in-progress ISO-TP exchange with an ECU.
///
/// Keeps the underlying socket open so that multiple responses can be read
/// from the same transport session (required for NRC 0x78 handling).
pub(crate) struct CanExchange {
    socket: IsoTpSocket,
    ecu_name: String,
}

impl CanExchange {
    /// Reads the next response from the ECU on this exchange's socket.
    pub async fn read_response(&self, timeout: Duration) -> Result<Vec<u8>, CanError> {
        let read_result = tokio::time::timeout(timeout, self.socket.read_packet()).await;

        match read_result {
            Ok(Ok(response_buf)) => {
                tracing::debug!(
                    ecu = %self.ecu_name,
                    data = %hex::encode(&response_buf),
                    len = response_buf.len(),
                    "Received CAN response"
                );
                Ok(response_buf)
            }
            Ok(Err(e)) => Err(CanError::ReceiveFailed(format!(
                "Failed to receive from {}: {}",
                self.ecu_name, e
            ))),
            Err(_) => Err(CanError::Timeout),
        }
    }
}

impl std::fmt::Debug for CanEcuConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CanEcuConnection")
            .field("ecu_name", &self.ecu_name)
            .field("interface", &self.interface)
            .field("request_id", &self.request_id.to_string())
            .field("response_id", &self.response_id.to_string())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "can-socketcand")]
    use super::*;

    /// End-to-end smoke test: a full request/response round trip using
    /// 29-bit extended IDs (ISO 15765-4 normal fixed addressing) through the
    /// socketcand backend - the same transport the CI suite uses.
    ///
    /// Requires a local socketcand on 127.0.0.1:29536 fronting vcan0, e.g.:
    /// `sudo modprobe vcan && sudo ip link add dev vcan0 type vcan && sudo ip
    /// link set up vcan0 && socketcand -n -i vcan0 -l <iface>`
    #[cfg(feature = "can-socketcand")]
    #[tokio::test]
    #[ignore = "needs a local socketcand on 127.0.0.1:29536 fronting vcan0"]
    async fn extended_id_round_trip_over_socketcand() {
        const IFACE: &str = "socketcand:127.0.0.1:29536:vcan0";
        // The socketcand backend shares one TCP connection per endpoint
        // string, and socketcand does not echo frames back to the connection
        // that sent them. Spell the ECU side's endpoint differently so the
        // two ends get separate connections, as they would in production
        // (CDA and the simulator are separate processes).
        const ECU_IFACE: &str = "socketcand:localhost:29536:vcan0";
        const REQ_ID: u32 = 0x18DA_10F1;
        const RESP_ID: u32 = 0x18DA_F110;

        // "ECU" side: receives requests on REQ_ID, answers on RESP_ID.
        let ecu_rx = CanId::try_from(REQ_ID).unwrap().to_socket_id().unwrap();
        let ecu_tx = CanId::try_from(RESP_ID).unwrap().to_socket_id().unwrap();
        let ecu_socket =
            IsoTpSocket::open(ECU_IFACE, ecu_rx, ecu_tx).expect("open ecu-side socket");
        // The socketcand handshake (`< open >` / `< rawmode >`) completes in
        // the background; give the ECU side a moment to be subscribed before
        // the tester transmits, otherwise the request frame is lost.
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(300)).await;

        let echo = tokio::spawn(async move {
            let request = ecu_socket.read_packet().await.expect("ecu-side read");
            assert_eq!(request, vec![0x3E, 0x00], "ecu should see the request");
            ecu_socket
                .write_packet(&[0x7E, 0x00])
                .await
                .expect("ecu-side write");
        });

        // Tester side: the production connection type with extended IDs.
        let conn = CanEcuConnection::new(
            "smoke".to_owned(),
            IFACE.to_owned(),
            CanId::try_from(REQ_ID).unwrap(),
            CanId::try_from(RESP_ID).unwrap(),
        );
        let response = conn
            .send_receive(&[0x3E, 0x00], Duration::from_secs(2))
            .await
            .expect("round trip over extended IDs");
        assert_eq!(response, vec![0x7E, 0x00]);

        echo.await.expect("ecu-side task");
    }
}
