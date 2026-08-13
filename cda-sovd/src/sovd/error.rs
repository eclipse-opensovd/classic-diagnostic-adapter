/*
 * SPDX-FileCopyrightText: 2025 Copyright (c) Contributors to the Eclipse Foundation
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

use aide::OperationOutput;
use axum::{
    Json,
    body::Body,
    extract::{
        Request,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Response},
};
use cda_interfaces::{
    DiagServiceError, HashMap, HashMapExtensions, HashSet,
    communication_control::CommunicationError,
    diagservices::{DiagServiceResponse, MappedNRC},
    file_manager::MddError,
};
use serde::{Deserialize, Serialize};
use serde_qs::axum::QsQueryRejection;
use sovd_interfaces::error::{ApiErrorResponse, ErrorCode};

#[allow(
    dead_code,
    reason = "Not all ApiError variants are used in all configurations"
)]
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema, thiserror::Error)]
pub enum ApiError {
    #[error("Bad Request: {0}")]
    BadRequest(String),
    #[error("Forbidden: {}", .0.as_ref().map(|m| format!(": {m}")).unwrap_or_default())]
    Forbidden(Option<String>),
    #[error("Not Found: {}", .0.as_ref().map(|m| format!(": {m}")).unwrap_or_default())]
    NotFound(Option<String>),
    #[error("Internal Server Error: {}", .0.as_ref().map(|m| format!(": {m}")).unwrap_or_default())]
    InternalServerError(Option<String>),
    #[error("Conflict: {0}")]
    Conflict(String),
    #[error("Not Responding: {0}")]
    NotResponding(String),
    #[error("Service Unavailable: {message}")]
    ServiceUnavailable {
        message: String,
        retry_after: Option<Duration>,
        error_code: ErrorCode,
        vendor_code: Option<VendorErrorCode>,
    },
    #[error("The value of the parameter is not of the allowed values")]
    InvalidParameter { possible_values: HashSet<String> },
}

impl ApiError {
    pub(crate) fn from_communication_error(
        value: CommunicationError,
        retry_after: Duration,
    ) -> Self {
        match value {
            CommunicationError::Failed(failure) => ApiError::ServiceUnavailable {
                message: failure.to_string(),
                retry_after: Some(retry_after),
                error_code: ErrorCode::SovdServerFailure,
                vendor_code: None,
            },
            value => ApiError::ServiceUnavailable {
                message: value.to_string(),
                retry_after: Some(retry_after),
                error_code: ErrorCode::VendorSpecific,
                vendor_code: Some(VendorErrorCode::CommunicationNotReady),
            },
        }
    }
    #[must_use]
    pub fn error_and_vendor_code(&self) -> (ErrorCode, Option<VendorErrorCode>) {
        match &self {
            ApiError::NotResponding(_) => (ErrorCode::NotResponding, None),
            ApiError::NotFound(_) => (ErrorCode::VendorSpecific, Some(VendorErrorCode::NotFound)),
            ApiError::BadRequest(_) => (
                ErrorCode::InvalidResponseContent,
                Some(VendorErrorCode::BadRequest),
            ),
            ApiError::Forbidden(_) => (ErrorCode::InsufficientAccessRights, None),
            ApiError::InvalidParameter { .. } => (
                ErrorCode::VendorSpecific,
                Some(VendorErrorCode::InvalidParameter),
            ),
            ApiError::ServiceUnavailable {
                error_code,
                vendor_code,
                ..
            } => (error_code.clone(), vendor_code.clone()),
            _ => (ErrorCode::SovdServerFailure, None),
        }
    }
}

impl From<DiagServiceError> for ApiError {
    fn from(value: DiagServiceError) -> Self {
        match value {
            DiagServiceError::UdsLookupError(_) | DiagServiceError::NotFound(_) => {
                ApiError::NotFound(Some(value.to_string()))
            }
            DiagServiceError::InvalidParameter { possible_values } => {
                ApiError::InvalidParameter { possible_values }
            }
            DiagServiceError::EcuOffline(_)
            | DiagServiceError::Timeout
            | DiagServiceError::NoResponse(_) => ApiError::NotResponding(value.to_string()),
            DiagServiceError::InvalidDatabase(_)
            | DiagServiceError::VariantDetectionError(_)
            | DiagServiceError::ResourceError(_)
            | DiagServiceError::ConnectionClosed(_)
            | DiagServiceError::SendFailed(_)
            | DiagServiceError::InvalidAddress(_)
            | DiagServiceError::UnexpectedResponse(_)
            | DiagServiceError::DataError(_)
            | DiagServiceError::InvalidConfiguration(_)
            | DiagServiceError::InvalidSecurityPlugin => {
                ApiError::InternalServerError(Some(value.to_string()))
            }
            DiagServiceError::NotEnoughData { expected, actual } => ApiError::BadRequest(format!(
                "Payload too short, expected at least {expected} bytes, got {actual} bytes"
            )),
            DiagServiceError::InvalidRequest(_)
            | DiagServiceError::Nack(_)
            | DiagServiceError::ParameterConversionError(_)
            | DiagServiceError::BadPayload(_)
            | DiagServiceError::InvalidState(_)
            | DiagServiceError::UnknownOperation
            | DiagServiceError::RequestNotSupported(_)
            | DiagServiceError::AmbiguousParameters { .. } => {
                ApiError::BadRequest(value.to_string())
            }
            DiagServiceError::CommunicationNotReady {
                message,
                retry_after,
            } => ApiError::ServiceUnavailable {
                message,
                retry_after: Some(retry_after),
                error_code: ErrorCode::VendorSpecific,
                vendor_code: Some(VendorErrorCode::CommunicationNotReady),
            },
            DiagServiceError::CommunicationDisabled(_) => ApiError::ServiceUnavailable {
                message: value.to_string(),
                retry_after: None,
                error_code: ErrorCode::VendorSpecific,
                vendor_code: Some(VendorErrorCode::CommunicationNotReady),
            },
            DiagServiceError::AccessDenied(_) => ApiError::Forbidden(Some(value.to_string())),
        }
    }
}

impl From<MddError> for ApiError {
    fn from(value: MddError) -> Self {
        match value {
            MddError::Io(s)
            | MddError::InvalidFormat(s)
            | MddError::Parsing(s)
            | MddError::MissingData(s) => ApiError::InternalServerError(Some(s)),
            MddError::InvalidParameter(s) => ApiError::NotFound(Some(s)),
        }
    }
}

impl From<std::io::Error> for ApiError {
    fn from(e: std::io::Error) -> Self {
        ApiError::InternalServerError(Some(format!("io::Error {e}")))
    }
}

impl From<JsonRejection> for ApiError {
    fn from(e: JsonRejection) -> Self {
        ApiError::BadRequest(e.body_text())
    }
}

impl From<QueryRejection> for ApiError {
    fn from(e: QueryRejection) -> Self {
        ApiError::BadRequest(e.body_text())
    }
}

impl From<QsQueryRejection> for ApiError {
    fn from(e: QsQueryRejection) -> Self {
        ApiError::BadRequest(e.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        ErrorWrapper {
            error: self,
            include_schema: false,
        }
        .into_response()
    }
}

pub struct ErrorWrapper {
    pub error: ApiError,
    pub include_schema: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum VendorErrorCode {
    /// The requested resource was not found.
    NotFound,
    /// The request could not be completed due to some faults with the request.
    ///
    /// eg. An unexpected request parameter was provided, or the necessary
    /// preconditions are not met.
    BadRequest,
    /// The request could not be completed within the configured time limit.
    RequestTimeout,
    /// An error occurred when trying to convert the UDS message to JSON
    ///
    /// eg. A Value received by the ECU was outside of the expected range
    ErrorInterpretingMessage,
    /// The given parameter is not valid.
    InvalidParameter,
    /// Used when a storage operation cannot be execution because a conflicting operation
    /// Already is in progress.
    StorageTransactionBusy,
    /// The provided data was not valid.
    InvalidData,
    /// A severe error occurred that needs further investigation, safe operation is still possible
    /// but this indicates an issue that should be investigated
    SevereError,
    /// ECU communication is not currently available; retry after the interval given in the
    /// `Retry-After` header.
    CommunicationNotReady,
    /// Indicates that something went terribly wrong and safe operation cannot be guaranteed at
    /// this point. The application still tries to serve requests in the best effort,
    /// but correctness may be affected by this error.
    FatalError,
}

impl OperationOutput for ErrorWrapper {
    type Inner = sovd_interfaces::error::ApiErrorResponse<VendorErrorCode>;
}

impl IntoResponse for ErrorWrapper {
    fn into_response(self) -> Response {
        let schema = if self.include_schema {
            let mut schema = crate::sovd::create_schema!(
                sovd_interfaces::error::ApiErrorResponse<VendorErrorCode>
            );
            if let Some(props) = schema.get_mut("properties") {
                crate::sovd::remove_descriptions_recursive(props);
            }
            Some(schema)
        } else {
            None
        };
        // Every variant but `ServiceUnavailable` differs only in status,
        // message, and codes, so they resolve to those parts here and share one
        // response construction below.
        let (status, message, error_code, vendor_code, parameters) = match self.error {
            ApiError::ServiceUnavailable {
                message,
                retry_after,
                error_code,
                vendor_code,
            } => {
                return service_unavailable_response(
                    message,
                    retry_after,
                    error_code,
                    vendor_code,
                    schema,
                );
            }
            ApiError::Forbidden(message) => (
                StatusCode::FORBIDDEN,
                message.unwrap_or_else(|| "Forbidden".into()),
                ErrorCode::InsufficientAccessRights,
                None,
                None,
            ),
            ApiError::NotFound(message) => (
                StatusCode::NOT_FOUND,
                message.unwrap_or_else(|| "Not Found".into()),
                ErrorCode::VendorSpecific,
                Some(VendorErrorCode::NotFound),
                None,
            ),
            ApiError::InternalServerError(message) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                message.unwrap_or_else(|| "Internal Server Error".into()),
                ErrorCode::SovdServerFailure,
                None,
                None,
            ),
            ApiError::Conflict(message) => (
                StatusCode::CONFLICT,
                message,
                ErrorCode::PreconditionsNotFulfilled,
                None,
                None,
            ),
            ApiError::BadRequest(message) => (
                StatusCode::BAD_REQUEST,
                message,
                ErrorCode::VendorSpecific,
                Some(VendorErrorCode::BadRequest),
                None,
            ),
            ApiError::NotResponding(message) => (
                StatusCode::GATEWAY_TIMEOUT,
                message,
                ErrorCode::NotResponding,
                None,
                None,
            ),
            ApiError::InvalidParameter { possible_values } => {
                let mut parameters = HashMap::new();
                parameters.insert(
                    "details".to_owned(),
                    serde_json::Value::String("value".to_owned()),
                );
                parameters.insert(
                    "possiblevalues".to_owned(),
                    serde_json::Value::Array(
                        possible_values
                            .into_iter()
                            .map(|v| serde_json::Value::String(v.to_lowercase()))
                            .collect(),
                    ),
                );
                (
                    StatusCode::BAD_REQUEST,
                    "The parameter value is not valid".to_owned(),
                    ErrorCode::VendorSpecific,
                    Some(VendorErrorCode::InvalidParameter),
                    Some(parameters),
                )
            }
        };

        (
            status,
            Json(ApiErrorResponse::<VendorErrorCode> {
                message,
                error_code,
                vendor_code,
                parameters,
                error_source: None,
                schema,
            }),
        )
            .into_response()
    }
}

/// Builds the `ServiceUnavailable` response separately, because it is the one
/// variant that cannot share `ErrorWrapper::into_response`'s common
/// construction: a plain `(StatusCode, Json<_>)` tuple can't carry the
/// `Retry-After` header, so this variant needs an extra header-insertion step
/// the others don't.
fn service_unavailable_response(
    message: String,
    retry_after: Option<Duration>,
    error_code: ErrorCode,
    vendor_code: Option<VendorErrorCode>,
    schema: Option<schemars::Schema>,
) -> Response {
    let response = (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ApiErrorResponse::<VendorErrorCode> {
            message,
            error_code,
            vendor_code,
            parameters: None,
            error_source: None,
            schema,
        }),
    )
        .into_response();
    crate::sovd::with_retry_after(response, retry_after)
}

pub(crate) fn nrc_to_api_error_response(
    nrc: MappedNRC,
    include_schema: bool,
) -> ApiErrorResponse<VendorErrorCode> {
    let mut parameters = HashMap::new();
    let mut message = String::new();
    if let Some((raw_code, ecu_msg)) = nrc.code.zip(nrc.description) {
        if let Ok(val) = serde_json::to_value(raw_code) {
            parameters.insert("NRC".to_owned(), val);
        }
        message = format!("A negative Response was received ({ecu_msg})");
    }
    if let Some(sid) = nrc.sid.and_then(|sid| serde_json::to_value(sid).ok()) {
        parameters.insert("SID".to_owned(), sid);
    }

    let schema = if include_schema {
        Some(crate::sovd::create_schema!(
            sovd_interfaces::error::ApiErrorResponse<VendorErrorCode>
        ))
    } else {
        None
    };

    sovd_interfaces::error::ApiErrorResponse::<VendorErrorCode> {
        error_code: ErrorCode::ErrorResponse,
        message,
        parameters: if parameters.is_empty() {
            None
        } else {
            Some(parameters)
        },
        error_source: Some("ECU".to_owned()),
        vendor_code: None,
        schema,
    }
}

pub(crate) fn api_error_from_diag_response(
    response: &impl DiagServiceResponse,
    include_schema: bool,
) -> Response {
    let nrc = match response.as_nrc() {
        Ok(nrc) => nrc,
        Err(e) => {
            return ErrorWrapper {
                error: ApiError::InternalServerError(Some(format!(
                    "Failed to convert response to NRC: {e}"
                ))),
                include_schema,
            }
            .into_response();
        }
    };

    let error_response = nrc_to_api_error_response(nrc, include_schema);
    (StatusCode::BAD_GATEWAY, Json(error_response)).into_response()
}

pub(crate) async fn sovd_method_not_allowed_handler(
    req: Request<Body>,
    next: Next,
) -> impl IntoResponse {
    let resp = next.run(req).await;
    let status = resp.status();
    match status {
        StatusCode::METHOD_NOT_ALLOWED => (
            StatusCode::METHOD_NOT_ALLOWED,
            Json(
                sovd_interfaces::error::ApiErrorResponse::<VendorErrorCode> {
                    message: "Method not allowed".to_string(),
                    error_code: ErrorCode::VendorSpecific,
                    vendor_code: Some(VendorErrorCode::BadRequest),
                    parameters: None,
                    error_source: None,
                    schema: None,
                },
            ),
        )
            .into_response(),
        StatusCode::REQUEST_TIMEOUT => (
            StatusCode::REQUEST_TIMEOUT,
            Json(
                sovd_interfaces::error::ApiErrorResponse::<VendorErrorCode> {
                    message: "Request timed out".to_string(),
                    error_code: ErrorCode::VendorSpecific,
                    vendor_code: Some(VendorErrorCode::RequestTimeout),
                    parameters: None,
                    error_source: None,
                    schema: None,
                },
            ),
        )
            .into_response(),
        _ => resp,
    }
}

pub(crate) async fn sovd_not_found_handler(uri: Uri) -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(
            sovd_interfaces::error::ApiErrorResponse::<VendorErrorCode> {
                message: format!("Resource not found: {uri}"),
                error_code: ErrorCode::VendorSpecific,
                vendor_code: Some(VendorErrorCode::NotFound),
                parameters: None,
                error_source: None,
                schema: None,
            },
        ),
    )
}
