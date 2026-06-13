/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 */

use std::time::Duration;

use tokio_socketcan_isotp::{IsoTpBehaviour, IsoTpOptions, IsoTpSocket, StandardId};

use crate::error::CanError;

/// Represents a CAN connection to a single ECU using ISO-TP.
pub struct CanEcuConnection {
    /// ECU name for logging/identification
    pub ecu_name: String,
    /// Physical request CAN ID
    pub request_id: u32,
    /// Physical response CAN ID
    pub response_id: u32,
    /// CAN interface name
    interface: String,
}

impl CanEcuConnection {
    /// Creates a new CAN ECU connection configuration.
    #[must_use]
    pub fn new(ecu_name: String, interface: String, request_id: u32, response_id: u32) -> Self {
        Self {
            ecu_name,
            request_id,
            response_id,
            interface,
        }
    }

    /// Opens an ISO-TP socket for this ECU connection.
    fn open_socket(&self) -> Result<IsoTpSocket, CanError> {
        // Standard CAN IDs are 11-bit (0-0x7FF), so truncation is expected for valid IDs
        // Note: ISO-TP socket uses (rx_id, tx_id) not (src, dst)
        // rx_id = what we receive on (ECU's response ID, e.g. 0x7E8)
        // tx_id = what we transmit on (ECU's request ID, e.g. 0x7E0)
        #[allow(clippy::cast_possible_truncation)]
        let rx_id = StandardId::new(self.response_id as u16).ok_or_else(|| {
            CanError::SocketError(format!(
                "Invalid response CAN ID: 0x{:03X}",
                self.response_id
            ))
        })?;
        #[allow(clippy::cast_possible_truncation)]
        let tx_id = StandardId::new(self.request_id as u16).ok_or_else(|| {
            CanError::SocketError(format!("Invalid request CAN ID: 0x{:03X}", self.request_id))
        })?;

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

        IsoTpSocket::open_with_opts(&self.interface, rx_id, tx_id, isotp_opts, None, None).map_err(
            |e| {
                CanError::SocketError(format!(
                    "Failed to open ISO-TP socket on {}: {}",
                    self.interface, e
                ))
            },
        )
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
            request_id = format!("0x{:03X}", self.request_id),
            response_id = format!("0x{:03X}", self.response_id),
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
            "{}:0x{:03X}->0x{:03X}",
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
            .field("request_id", &format!("0x{:03X}", self.request_id))
            .field("response_id", &format!("0x{:03X}", self.response_id))
            .finish()
    }
}
