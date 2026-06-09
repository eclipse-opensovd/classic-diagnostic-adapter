/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 */

use thiserror::Error;

/// Errors that can occur during CAN gateway setup.
#[derive(Error, Debug, Clone)]
pub enum CanGatewaySetupError {
    #[error("Failed to open CAN interface `{0}`: {1}")]
    InterfaceOpenFailed(String, String),

    #[error("Invalid CAN configuration: {0}")]
    InvalidConfiguration(String),

    #[error("No ECU mappings available and MDD lacks CAN COM parameters")]
    NoEcuMappings,
}

/// Errors that can occur during CAN communication.
#[derive(Error, Debug, Clone)]
pub enum CanError {
    #[error("ECU not responding on CAN ID 0x{0:03X}")]
    EcuNotResponding(u32),

    #[error("ISO-TP socket error: {0}")]
    SocketError(String),

    #[error("Timeout waiting for response")]
    Timeout,

    #[error("Send failed: {0}")]
    SendFailed(String),

    #[error("Receive failed: {0}")]
    ReceiveFailed(String),

    #[error("Connection closed")]
    ConnectionClosed,
}
