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

use std::fmt;

use cda_comm_doip::DoipGatewaySetupError;
use cda_interfaces::{
    DiagServiceError, communication_control::CommunicationOperationFailure,
    config::ConfigSanityError, runtime_update_api::RuntimeUpdateError,
};
use cda_tracing::TracingSetupError;

/// Non-exhaustive so new variants can be added without breaking embedders
/// that match on it.
#[derive(thiserror::Error)]
#[non_exhaustive]
pub enum AppError {
    #[error("Initialization failed `{0}`")]
    InitializationFailed(String),
    #[error("Resource error: `{0}`")]
    ResourceError(String),
    #[error("Connection error `{0}`")]
    ConnectionError(String),
    #[error("Configuration error `{message}`")]
    ConfigurationError {
        message: String,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
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
            | DiagServiceError::CommunicationDisabled(_)
            | DiagServiceError::CommunicationNotReady { .. }
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
                Self::ConfigurationError {
                    message: value.to_string(),
                    source: None,
                }
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
            DoipGatewaySetupError::InvalidConfiguration(_) => Self::ConfigurationError {
                message: value.to_string(),
                source: None,
            },
            DoipGatewaySetupError::ResourceError(_) => Self::ResourceError(value.to_string()),
            DoipGatewaySetupError::ServerError(_) => Self::ServerError(value.to_string()),
            DoipGatewaySetupError::UnknownECU {
                logical_address,
                protocol_version,
            } => Self::ConfigurationError {
                message: format!(
                    "Unknown ECU with logical address {logical_address} and protocol version \
                     {protocol_version}"
                ),
                source: None,
            },
        }
    }
}

#[cfg(feature = "can")]
impl From<cda_comm_can::error::CanGatewaySetupError> for AppError {
    fn from(value: cda_comm_can::error::CanGatewaySetupError) -> Self {
        use cda_comm_can::error::CanGatewaySetupError;
        match value {
            CanGatewaySetupError::InterfaceOpenFailed(_, _) => {
                Self::InitializationFailed(value.to_string())
            }
            CanGatewaySetupError::InvalidConfiguration(_) | CanGatewaySetupError::NoEcuMappings => {
                Self::ConfigurationError {
                    message: value.to_string(),
                    source: None,
                }
            }
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
        AppError::ConfigurationError {
            message: "Error while checking configuration sanity".to_string(),
            source: Some(value.into()),
        }
    }
}

impl From<RuntimeUpdateError> for AppError {
    fn from(value: RuntimeUpdateError) -> Self {
        AppError::InitializationFailed(value.to_string())
    }
}

impl From<CommunicationOperationFailure> for AppError {
    fn from(value: CommunicationOperationFailure) -> Self {
        match value {
            CommunicationOperationFailure::TransportFailure { .. }
            | CommunicationOperationFailure::InitializerFailure { .. }
            | CommunicationOperationFailure::InitializerCleanupFailure { .. }
            | CommunicationOperationFailure::DetectionFailure { .. }
            | CommunicationOperationFailure::DetectionCleanupFailure { .. } => {
                Self::InitializationFailed(value.to_string())
            }
            CommunicationOperationFailure::PermissionFailure { .. }
            | CommunicationOperationFailure::TransitionFailure { .. }
            | CommunicationOperationFailure::DisableLeaseHeld { .. }
            | CommunicationOperationFailure::GuardsHeld { .. }
            | CommunicationOperationFailure::ShuttingDown { .. }
            | CommunicationOperationFailure::WorkerUnavailable { .. }
            | CommunicationOperationFailure::ModeDisabled { .. } => {
                Self::RuntimeError(value.to_string())
            }
        }
    }
}

// Representation printed when returned from main().
impl fmt::Debug for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Error: {self}")?;

        let mut error: &dyn std::error::Error = self;

        while let Some(source) = error.source() {
            writeln!(f, "    Caused by: {source}")?;
            error = source;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_write_source_errors_in_debug_format() {
        let source = "amet, consectetur".to_string();

        let source = AppError::ConfigurationError {
            message: "dolor sit".to_string(),
            source: Some(source.into()),
        };
        let testee = AppError::ConfigurationError {
            message: "Lorem ipsum".to_string(),
            source: Some(source.into()),
        };

        let result = format!("{testee:?}");

        assert_eq!(
            result,
            "Error: Configuration error `Lorem ipsum`
    Caused by: Configuration error `dolor sit`
    Caused by: amet, consectetur
"
        );
    }
}
