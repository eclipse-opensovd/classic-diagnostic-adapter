/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 */

//! Functional broadcast `TesterPresent` keep-alive for CAN bus.
//!
//! Periodically sends a UDS `TesterPresent` (`0x3E 0x80`) on the functional
//! broadcast CAN ID `0x7DF` to prevent all ECUs from going to sleep.
//! The sub-function `0x80` sets the `suppressPositiveResponse` bit so no
//! ECU will reply, keeping the bus quiet.

use std::time::Duration;

use cda_interfaces::util::tokio_ext::sleep_for;
use tokio::task::JoinHandle;
use tokio_socketcan_isotp::{IsoTpBehaviour, IsoTpOptions, IsoTpSocket, StandardId};

use crate::error::CanError;

/// Functional broadcast CAN ID (ISO 14229 / ISO 15765-2).
const FUNCTIONAL_BROADCAST_ID: u16 = 0x7DF;

/// Dummy RX CAN ID - we never expect a response because we use
/// suppressPositiveResponse (0x80), but the ISO-TP socket API
/// requires an `rx_id`. Use an ID that won't conflict.
const DUMMY_RX_ID: u16 = 0x7FF;

/// Default keep-alive interval (2 seconds).
const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(2);

/// UDS `TesterPresent` with `suppressPositiveResponse`.
const TESTER_PRESENT_PAYLOAD: [u8; 2] = [0x3E, 0x80];

/// A handle to a running keep-alive broadcast task.
///
/// Dropping this handle (or calling [`stop`](Self::stop)) aborts the
/// background task that sends periodic `TesterPresent` frames.
pub struct KeepAliveHandle {
    task: JoinHandle<()>,
}

impl KeepAliveHandle {
    /// Stops the keep-alive broadcast.
    pub fn stop(self) {
        self.task.abort();
    }
}

impl Drop for KeepAliveHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Starts a background task that periodically sends a functional-broadcast
/// `TesterPresent` (`0x3E 0x80`) on the given CAN interface.
///
/// This keeps all ECUs on the bus awake without requiring individual
/// physical addressing.
///
/// # Arguments
/// * `interface` - CAN interface name (e.g. `"can0"`, `"vxcan0"`)
/// * `interval`  - How often to send the keep-alive. `None` uses the
///   default of 2 seconds.
///
/// # Returns
/// A [`KeepAliveHandle`] that stops the broadcast when dropped.
#[must_use]
pub fn start_keepalive_broadcast(interface: String, interval: Option<Duration>) -> KeepAliveHandle {
    let interval = interval.unwrap_or(DEFAULT_KEEPALIVE_INTERVAL);

    let task = cda_interfaces::spawn_named!("can-keepalive-broadcast", async move {
        tracing::info!(
            interface = %interface,
            interval_ms = u32::try_from(interval.as_millis()).unwrap_or(u32::MAX),
            broadcast_id = format!("0x{FUNCTIONAL_BROADCAST_ID:03X}"),
            "Starting functional broadcast TesterPresent keep-alive"
        );

        loop {
            if let Err(e) = send_tester_present_broadcast(&interface).await {
                tracing::warn!(
                    error = %e,
                    interface = %interface,
                    "Failed to send keep-alive TesterPresent broadcast"
                );
            } else {
                tracing::trace!(
                    interface = %interface,
                    "Sent TesterPresent keep-alive broadcast on 0x7DF"
                );
            }

            sleep_for(interval).await;
        }
    });

    KeepAliveHandle { task }
}

/// Sends a single functional-broadcast `TesterPresent` frame.
async fn send_tester_present_broadcast(interface: &str) -> Result<(), CanError> {
    let tx_id = StandardId::new(FUNCTIONAL_BROADCAST_ID)
        .ok_or_else(|| CanError::SocketError("Invalid functional broadcast CAN ID".into()))?;
    let rx_id = StandardId::new(DUMMY_RX_ID)
        .ok_or_else(|| CanError::SocketError("Invalid dummy RX CAN ID".into()))?;

    let isotp_opts = IsoTpOptions::new(
        IsoTpBehaviour::CAN_ISOTP_TX_PADDING,
        Duration::ZERO,
        0,
        0x00,
        0x00,
        0,
    )
    .ok();

    let socket = IsoTpSocket::open_with_opts(interface, rx_id, tx_id, isotp_opts, None, None)
        .map_err(|e| {
            CanError::SocketError(format!(
                "Failed to open keep-alive socket on {interface}: {e}"
            ))
        })?;

    socket
        .write_packet(&TESTER_PRESENT_PAYLOAD)
        .await
        .map_err(|e| CanError::SendFailed(format!("Keep-alive broadcast failed: {e}")))?;

    Ok(())
}
