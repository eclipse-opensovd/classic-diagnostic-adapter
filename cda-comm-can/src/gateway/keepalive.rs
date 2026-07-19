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

//! Functional broadcast `TesterPresent` keep-alive for CAN bus.
//!
//! Periodically sends a UDS `TesterPresent` (`0x3E 0x80`) on the functional
//! broadcast CAN ID to prevent all ECUs from going to sleep. The ID is
//! derived from the MDD com-params (`CP_CanFuncReqId`) when available and
//! defaults to `0x7DF` (ISO 15765-4). The sub-function `0x80` sets the
//! `suppressPositiveResponse` bit so no ECU will reply, keeping the bus
//! quiet.

use std::time::Duration;

use cda_interfaces::util::tokio_ext::sleep_for;
use tokio_socketcan_isotp::{IsoTpBehaviour, IsoTpOptions, IsoTpSocket};
use tokio_util::sync::CancellationToken;

use super::{background::BackgroundTask, can_id::CanId, error::CanError};

/// Default functional broadcast CAN ID (ISO 15765-4), used when the MDD
/// com-params do not define `CP_CanFuncReqId`.
pub(crate) const DEFAULT_FUNCTIONAL_BROADCAST_ID: u32 = 0x7DF;

/// Dummy RX CAN IDs - we never expect a response because we use
/// suppressPositiveResponse (0x80), but the ISO-TP socket API requires an
/// `rx_id`. Use an ID that won't conflict, matching the kind (standard or
/// extended) of the broadcast ID.
const DUMMY_RX_ID_STANDARD: u32 = 0x7FF;
const DUMMY_RX_ID_EXTENDED: u32 = 0x1FFF_FFFF;

/// Default keep-alive interval (2 seconds).
pub(crate) const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(2);

/// UDS `TesterPresent` with `suppressPositiveResponse`.
const TESTER_PRESENT_PAYLOAD: [u8; 2] = [0x3E, 0x80];

/// Starts a background task that periodically sends a functional-broadcast
/// `TesterPresent` (`0x3E 0x80`) on the given CAN interface.
///
/// This keeps all ECUs on the bus awake without requiring individual
/// physical addressing. The socket is opened once and reused across
/// iterations; it is only reopened after a send failure.
///
/// # Arguments
/// * `interface` - CAN interface name (e.g. `"can0"`, `"vxcan0"`)
/// * `functional_id` - Functional broadcast CAN ID (from com-params), 11-bit
///   standard (e.g. `0x7DF`) or 29-bit extended (e.g. `0x18DB33F1`)
/// * `interval` - How often to send the keep-alive
///
/// # Returns
/// A [`BackgroundTask`] that stops the broadcast via
/// [`BackgroundTask::shutdown`].
#[must_use]
pub(crate) fn start_keepalive_broadcast(
    interface: String,
    functional_id: CanId,
    interval: Duration,
) -> BackgroundTask {
    let cancel = CancellationToken::new();
    let task_cancel = cancel.clone();
    let task = cda_interfaces::spawn_named!("can-keepalive-broadcast", async move {
        tracing::info!(
            interface = %interface,
            interval_ms = u32::try_from(interval.as_millis()).unwrap_or(u32::MAX),
            broadcast_id = %functional_id,
            "Starting functional broadcast TesterPresent keep-alive"
        );

        let mut socket: Option<IsoTpSocket> = None;
        let mut consecutive_open_failures: u64 = 0;
        loop {
            if socket.is_none() {
                match open_broadcast_socket(&interface, functional_id) {
                    Ok(s) => {
                        if consecutive_open_failures > 0 {
                            tracing::info!(
                                interface = %interface,
                                failed_attempts = consecutive_open_failures,
                                "Keep-alive broadcast socket opened after failures"
                            );
                        }
                        consecutive_open_failures = 0;
                        socket = Some(s);
                    }
                    Err(e) => {
                        // Warn once per outage instead of on every tick: with
                        // the interface down this loop retries forever, and a
                        // 2 s warn cadence floods the log.
                        consecutive_open_failures = consecutive_open_failures.saturating_add(1);
                        if consecutive_open_failures == 1 {
                            tracing::warn!(
                                error = %e,
                                interface = %interface,
                                "Failed to open keep-alive broadcast socket, retrying each tick"
                            );
                        } else {
                            tracing::debug!(
                                error = %e,
                                interface = %interface,
                                failed_attempts = consecutive_open_failures,
                                "Keep-alive broadcast socket still unavailable"
                            );
                        }
                    }
                }
            }

            if let Some(ref s) = socket {
                tokio::select! {
                    () = task_cancel.cancelled() => break,
                    result = s.write_packet(&TESTER_PRESENT_PAYLOAD) => match result {
                        Ok(()) => {
                            tracing::trace!(
                                interface = %interface,
                                broadcast_id = %functional_id,
                                "Sent TesterPresent keep-alive broadcast"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                interface = %interface,
                                "Keep-alive broadcast failed; reopening socket on next tick"
                            );
                            socket = None;
                        }
                    }
                }
            }

            tokio::select! {
                () = task_cancel.cancelled() => break,
                () = sleep_for(interval) => {}
            }
        }
        tracing::debug!(
            interface = %interface,
            "Keep-alive broadcast stopped"
        );
    });

    BackgroundTask::new(cancel, task)
}

/// Opens the ISO-TP socket used for the functional broadcast.
fn open_broadcast_socket(interface: &str, functional_id: CanId) -> Result<IsoTpSocket, CanError> {
    let tx_id = functional_id.to_socket_id()?;
    // Match the dummy RX kind to the broadcast kind so standard and extended
    // buses both work.
    let rx_id = CanId::try_from(if functional_id.is_standard() {
        DUMMY_RX_ID_STANDARD
    } else {
        DUMMY_RX_ID_EXTENDED
    })?
    .to_socket_id()?;

    let isotp_opts = IsoTpOptions::new(
        IsoTpBehaviour::CAN_ISOTP_TX_PADDING,
        Duration::ZERO,
        0,
        0x00,
        0x00,
        0,
    )
    .ok();

    IsoTpSocket::open_with_opts(interface, rx_id, tx_id, isotp_opts, None, None).map_err(|e| {
        CanError::SocketError(format!(
            "Failed to open keep-alive socket on {interface}: {e}"
        ))
    })
}
