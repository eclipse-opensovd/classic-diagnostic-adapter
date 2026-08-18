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

//! Error types for the `DoIP` gateway.

use thiserror::Error;

/// Errors that can occur while setting up the `DoIP` gateway.
#[derive(Error, Debug)]
pub enum DoipGatewaySetupError {
    #[error("Invalid address: `{0}`")]
    InvalidAddress(String),
    #[error(
        "Received an unknown ECU in VAM (Logical Address: {logical_address}, Protocol Version: \
         {protocol_version}). Likely there is no MDD loaded for this ECU."
    )]
    UnknownECU {
        logical_address: u16,
        protocol_version: u8,
    },
    #[error("Socket error: `{0}`")]
    SocketCreationFailed(String),
    #[error("Port error: `{0}`")]
    PortBindFailed(String),
    #[error("Configuration error: `{0}`")]
    InvalidConfiguration(String),
    #[error("Resource error: `{0}`")]
    ResourceError(String),
    #[error("Server error: `{0}`")]
    ServerError(String),
}

/// Errors that can occur on an active `DoIP` connection.
#[derive(Error, Debug, Clone)]
pub enum ConnectionError {
    #[error("Connection closed.")]
    Closed,
    #[error("Decoding error: `{0}`")]
    Decoding(String),
    #[error("Invalid message: `{0}")]
    InvalidMessage(String),
    #[error("Connection timeout: `{0}`")]
    Timeout(String),
    #[error("Connection failed: `{0}`")]
    ConnectionFailed(String),
    #[error("Routing error: `{0}`")]
    RoutingError(String),
    #[error("Send failed: `{0}`")]
    SendFailed(String),
}
