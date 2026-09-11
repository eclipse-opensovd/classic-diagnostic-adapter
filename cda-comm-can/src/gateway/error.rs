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

use thiserror::Error;

/// Errors that can occur during CAN gateway setup.
#[derive(Error, Debug, Clone)]
pub enum CanGatewaySetupError {
    #[error("Failed to open CAN interface `{0}`: {1}")]
    InterfaceOpenFailed(String, String),

    #[error("Invalid CAN configuration: {0}")]
    InvalidConfiguration(String),

    #[error(
        "[can] is configured but no usable ECU addressing was found: add [[can.ecu_mappings]] \
         entries for ECUs present in the database (or provide CAN COM parameters in the MDD)"
    )]
    NoEcuMappings,
}

impl From<cda_interfaces::InvalidCanId> for CanError {
    fn from(value: cda_interfaces::InvalidCanId) -> Self {
        Self::InvalidId(value.to_string())
    }
}

/// Errors that can occur during CAN communication.
#[derive(Error, Debug, Clone)]
pub enum CanError {
    #[error("ECU not responding on CAN ID 0x{0:03X}")]
    EcuNotResponding(u32),

    #[error("Invalid CAN ID: {0}")]
    InvalidId(String),

    #[error("ISO-TP socket error: {0}")]
    SocketError(String),

    #[error("Timeout waiting for response")]
    Timeout,

    #[error("Send failed: {0}")]
    SendFailed(String),

    #[error("Receive failed: {0}")]
    ReceiveFailed(String),
}
