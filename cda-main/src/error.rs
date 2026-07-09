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

use cda_interfaces::{
    DiagServiceError, DoipGatewaySetupError, config::ConfigSanityError,
    runtime_update_api::RuntimeUpdateError,
};
use cda_tracing::TracingSetupError;

#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error("Initialization failed `{0}`")]
    InitializationFailed(String),
    #[error("Resource error: `{0}`")]
    ResourceError(String),
    #[error("Connection error `{0}`")]
    ConnectionError(String),
    #[error("Configuration error `{0}`")]
    ConfigurationError(String),
    #[error("Data error `{0}`")]
    DataError(String),
    #[error("Error during execution `{0}`")]
    RuntimeError(String),
    #[error("Not found: `{0}`")]
    NotFound(String),
    #[error("Server error: `{0}`")]
    ServerError(String),
    #[error("Shutdown requested")]
    ShutdownRequested,
}

impl From<DiagServiceError> for AppError {
    fn from(value: DiagServiceError) -> Self {
        match value {
            DiagServiceError::RequestNotSupported(_)
            | DiagServiceError::BadPayload(_)
            | DiagServiceError::ConnectionClosed(_)
            | DiagServiceError::UnexpectedResponse(_)
            | DiagServiceError::EcuOffline(_)
            | DiagServiceError::NoResponse(_)
            | DiagServiceError::SendFailed(_)
            | DiagServiceError::InvalidAddress(_)
            | DiagServiceError::InvalidRequest(_)
            | DiagServiceError::Timeout => Self::ConnectionError(value.to_string()),

            DiagServiceError::ParameterConversionError(_)
            | DiagServiceError::UnknownOperation
            | DiagServiceError::UdsLookupError(_)
            | DiagServiceError::VariantDetectionError(_)
            | DiagServiceError::AccessDenied(_)
            | DiagServiceError::InvalidState(_)
            | DiagServiceError::Nack(_) => Self::RuntimeError(value.to_string()),

            DiagServiceError::InvalidConfiguration(_) | DiagServiceError::InvalidSecurityPlugin => {
                Self::ConfigurationError(value.to_string())
            }

            DiagServiceError::ResourceError(_) => Self::ResourceError(value.to_string()),

            DiagServiceError::NotFound(_) => Self::NotFound(value.to_string()),

            DiagServiceError::DataError(_)
            | DiagServiceError::InvalidDatabase(_)
            | DiagServiceError::AmbiguousParameters { .. }
            | DiagServiceError::InvalidParameter { .. }
            | DiagServiceError::NotEnoughData { .. } => Self::DataError(value.to_string()),
        }
    }
}

impl From<DoipGatewaySetupError> for AppError {
    fn from(value: DoipGatewaySetupError) -> Self {
        match value {
            DoipGatewaySetupError::InvalidAddress(_) => Self::ConnectionError(value.to_string()),
            DoipGatewaySetupError::SocketCreationFailed(_)
            | DoipGatewaySetupError::PortBindFailed(_) => {
                Self::InitializationFailed(value.to_string())
            }
            DoipGatewaySetupError::InvalidConfiguration(_) => {
                Self::ConfigurationError(value.to_string())
            }
            DoipGatewaySetupError::ResourceError(_) => Self::ResourceError(value.to_string()),
            DoipGatewaySetupError::ServerError(_) => Self::ServerError(value.to_string()),
            DoipGatewaySetupError::UnknownECU {
                logical_address,
                protocol_version,
            } => Self::ConfigurationError(format!(
                "Unknown ECU with logical address {logical_address} and protocol version \
                 {protocol_version}"
            )),
        }
    }
}

impl From<TracingSetupError> for AppError {
    fn from(value: TracingSetupError) -> Self {
        match value {
            TracingSetupError::ResourceCreationFailed(_) => Self::ResourceError(value.to_string()),
            TracingSetupError::SubscriberInitializationFailed(_) => {
                Self::InitializationFailed(value.to_string())
            }
        }
    }
}

impl From<ConfigSanityError> for AppError {
    fn from(value: ConfigSanityError) -> Self {
        AppError::ConfigurationError(value.to_string())
    }
}

impl From<RuntimeUpdateError> for AppError {
    fn from(value: RuntimeUpdateError) -> Self {
        AppError::InitializationFailed(value.to_string())
    }
}
