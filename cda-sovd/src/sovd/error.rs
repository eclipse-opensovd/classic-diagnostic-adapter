/*
 * Copyright (c) 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
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

use std::fmt::Display;

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
use cda_interfaces::{DiagServiceError, diagservices::DiagServiceResponse, file_manager::MddError};
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};
use serde_qs::axum::QsQueryRejection;
use sovd_interfaces::error::ErrorCode;

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub enum ApiError {
    BadRequest(String),
    Forbidden(Option<String>),
    NotFound(Option<String>),
    InternalServerError(Option<String>),
    Conflict(String),
}

impl From<DiagServiceError> for ApiError {
    fn from(value: DiagServiceError) -> Self {
        match &value {
            DiagServiceError::UdsLookupError(_) | DiagServiceError::NotFound(Some(_) | None) => {
                ApiError::NotFound(Some(value.to_string()))
            }

            DiagServiceError::InvalidDatabase(_)
            | DiagServiceError::DatabaseEntryNotFound(_)
            | DiagServiceError::VariantDetectionError(_)
            | DiagServiceError::EcuOffline(_)
            | DiagServiceError::ConfigurationError(_)
            | DiagServiceError::SetupError(_)
            | DiagServiceError::ResourceError(_)
            | DiagServiceError::ConnectionClosed
            | DiagServiceError::InvalidRequest(_)
            | DiagServiceError::SendFailed(_)
            | DiagServiceError::InvalidAddress(_)
            | DiagServiceError::ParameterConversionError(_)
            | DiagServiceError::BadPayload(_)
            | DiagServiceError::NotEnoughData { .. }
            | DiagServiceError::NoResponse(_)
            | DiagServiceError::Nack(_)
            | DiagServiceError::InvalidSession(_)
            | DiagServiceError::UnknownOperation
            | DiagServiceError::UnexpectedResponse(_)
            | DiagServiceError::RequestNotSupported(_)
            | DiagServiceError::Timeout
            | DiagServiceError::DataError(_)
            | DiagServiceError::AccessDenied(_) => ApiError::BadRequest(value.to_string()),

            DiagServiceError::InvalidSecurityPlugin => {
                ApiError::InternalServerError(Some(value.to_string()))
            }
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

impl Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let (status, message) = match &self {
            ApiError::BadRequest(message) => ("Bad Request", Some(message)),
            ApiError::Forbidden(message) => ("Forbidden", message.as_ref()),
            ApiError::NotFound(message) => ("Not Found", message.as_ref()),
            ApiError::InternalServerError(message) => ("Internal Server Error", message.as_ref()),
            ApiError::Conflict(message) => ("Conflict", Some(message)),
        };
        match message {
            Some(message) => write!(f, "{status}: {message}"),
            None => write!(f, "{status}"),
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

#[derive(Serialize, schemars::JsonSchema)]
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
        match self.error {
            ApiError::Forbidden(message) => (
                StatusCode::FORBIDDEN,
                Json(
                    sovd_interfaces::error::ApiErrorResponse::<VendorErrorCode> {
                        message: message.unwrap_or_else(|| "Forbidden".into()),
                        error_code: ErrorCode::InsufficientAccessRights,
                        vendor_code: None,
                        parameters: None,
                        error_source: None,
                        schema,
                    },
                ),
            ),
            ApiError::NotFound(message) => (
                StatusCode::NOT_FOUND,
                Json(
                    sovd_interfaces::error::ApiErrorResponse::<VendorErrorCode> {
                        message: message.unwrap_or_else(|| "Not Found".into()),
                        error_code: ErrorCode::VendorSpecific,
                        vendor_code: Some(VendorErrorCode::NotFound),
                        parameters: None,
                        error_source: None,
                        schema,
                    },
                ),
            ),
            ApiError::InternalServerError(message) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    sovd_interfaces::error::ApiErrorResponse::<VendorErrorCode> {
                        message: message.unwrap_or_else(|| "Internal Server Error".into()),
                        error_code: ErrorCode::SovdServerFailure,
                        vendor_code: None,
                        parameters: None,
                        error_source: None,
                        schema,
                    },
                ),
            ),
            ApiError::Conflict(message) => (
                StatusCode::CONFLICT,
                Json(
                    sovd_interfaces::error::ApiErrorResponse::<VendorErrorCode> {
                        message,
                        error_code: ErrorCode::PreconditionsNotFulfilled,
                        vendor_code: None,
                        parameters: None,
                        error_source: None,
                        schema,
                    },
                ),
            ),
            ApiError::BadRequest(message) => (
                StatusCode::BAD_REQUEST,
                Json(
                    sovd_interfaces::error::ApiErrorResponse::<VendorErrorCode> {
                        message,
                        error_code: ErrorCode::VendorSpecific,
                        vendor_code: Some(VendorErrorCode::BadRequest),
                        parameters: None,
                        error_source: None,
                        schema,
                    },
                ),
            ),
        }
        .into_response()
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

    let error_response = sovd_interfaces::error::ApiErrorResponse::<VendorErrorCode> {
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
    };
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
