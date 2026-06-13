/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 */

//! Error types for the ECU simulator.

use thiserror::Error;

/// Main error type for the simulator.
#[derive(Error, Debug)]
pub enum SimulatorError {
    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Failed to load MDD file
    #[error("Failed to load MDD file: {0}")]
    MddLoad(String),

    /// Failed to parse MDD content
    #[error("Failed to parse MDD: {0}")]
    MddParse(String),

    /// Requested variant not found in MDD
    #[error("Variant not found: {0}")]
    VariantNotFound(String),

    /// No variants available in the MDD
    #[error("No variants available in MDD")]
    NoVariants,

    /// CAN socket error
    #[error("Socket error: {0}")]
    Socket(String),

    /// Invalid diagnostic request
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    /// Service not supported
    #[error("Unsupported service: SID=0x{0:02X}, SubFunc={1:?}")]
    UnsupportedService(u8, Option<u16>),

    /// Invalid service definition in MDD
    #[error("Invalid service definition: {0}")]
    InvalidService(String),

    /// Parameter encoding error
    #[error("Parameter encoding error: {0}")]
    ParameterEncoding(String),

    /// API server error
    #[error("API server error: {0}")]
    ApiServer(String),

    /// Tracing setup error
    #[error("Tracing setup error: {0}")]
    TracingSetup(String),

    /// Service not found
    #[error("Service not found: {0}")]
    ServiceNotFound(String),

    /// Parameter not found
    #[error("Parameter not found: {0}")]
    ParameterNotFound(String),

    /// CAN ID not available (not in MDD and not provided via CLI)
    #[error("CAN ID not available: {0}. Provide via CLI or ensure MDD contains COM parameters.")]
    CanIdNotAvailable(String),
}
