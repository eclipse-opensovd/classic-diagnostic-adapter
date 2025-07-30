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

use axum::{
    Json,
    body::Body,
    extract::{Request, rejection::JsonRejection},
    http::{StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Response},
};
use cda_interfaces::{DiagServiceError, diagservices::DiagServiceResponse, file_manager::MddError};
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
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
            DiagServiceError::UdsLookupError(_) => ApiError::NotFound(Some(value.to_string())),
            DiagServiceError::NotFound => ApiError::NotFound(None),

            DiagServiceError::InvalidDatabase(_)
            | DiagServiceError::DatabaseEntryNotFound(_)
            | DiagServiceError::VariantDetectionError(_)
            | DiagServiceError::EcuOffline(_)
            | DiagServiceError::ConnectionClosed => {
                ApiError::InternalServerError(Some(value.to_string()))
            }

            DiagServiceError::InvalidRequest(_)
            | DiagServiceError::SendFailed(_)
            | DiagServiceError::ParameterConversionError(_)
            | DiagServiceError::BadPayload(_)
            | DiagServiceError::NoResponse(_)
            | DiagServiceError::Nack(_)
            | DiagServiceError::InvalidSession(_)
            | DiagServiceError::UnknownOperation
            | DiagServiceError::UnexpectedResponse
            | DiagServiceError::RequestNotSupported
            | DiagServiceError::Timeout
            | DiagServiceError::AccessDenied(_) => ApiError::BadRequest(value.to_string()),
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

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        ErrorWrapper(self).into_response()
    }
}

pub struct ErrorWrapper(pub ApiError);

#[derive(Serialize)]
pub(super) struct ApiErrorResponse {
    message: String,
    error_code: SovdErrorCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    vendor_code: Option<SovdVendorErrorCode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<HashMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    x_errorsource: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
// allowed, so we can pre-fill this with all sovd error codes
// even though not all are used yet.
#[allow(dead_code)]
enum SovdErrorCode {
    /// Details are specified in the `vendor_code`
    VendorSpecific,

    /// The Component which handles the request (e.g., an ECU)
    /// has been queried by the SOVD server but did not respond.
    NotResponding,

    /// The Component receiving the request has answered with an
    /// error.
    /// For UDS, the message should include the service identifier
    /// (Key: ‘service’ and Value of type number) and the negative
    /// response code (Key: ‘nrc’ and Value of type number).
    ErrorResponse,

    /// The signature of the data in the payload is invalid.
    InvalidSignature,

    /// The request does not provide all information (e.g., parameter
    /// values for an operation) required to complete the method.
    /// The message should include references to the missing
    /// information.
    IncompleteRequest,

    /// The response provided by the Component contains
    /// information which could not be processed. E.g., the response
    /// of an ECU does not match the conversion information known
    /// to the SOVD server.
    /// The message should include references to the parts of the
    /// invalid response attribute as well as a reason why the
    /// attribute is invalid.
    InvalidResponseContent,

    /// The SOVD server is not configured correctly, e.g., required
    /// configuration files or other data is missing. The message
    /// should include further information about the error. A client
    /// shall assume that this error is fatal and a regular operation of
    /// the SOVD server cannot be expected.
    SovdServerMisconfigured,

    /// The SOVD server is able to answer requests, but an internal
    /// error occurred. The message should include further
    /// information about the error
    SovdServerFailure,

    ///The SOVD client does not have the right to access the
    /// resource.
    InsufficientAccessRights,

    /// The preconditions to execute the method are not fulfilled.
    PreconditionsNotFulfilled,

    /// An update is already in progress and not yet done or aborted.
    UpdateProcessInProgress,

    /// Automatic installation of update is not supported
    UpdateAutomatedNotSupported,

    /// An update is already in preparation and not yet done or
    // aborted.
    UpdatePreparationInProgress,

    /// Another update is currently executed and not yet done or
    // aborted
    UpdateExecutionInProgress,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
enum SovdVendorErrorCode {
    NotFound,
    BadRequest,
    RequestTimeout,
}

impl IntoResponse for ErrorWrapper {
    fn into_response(self) -> Response {
        match self.0 {
            ApiError::Forbidden(message) => (
                StatusCode::FORBIDDEN,
                Json(ApiErrorResponse {
                    message: message.unwrap_or_else(|| "Forbidden".into()),
                    error_code: SovdErrorCode::InsufficientAccessRights,
                    vendor_code: None,
                    parameters: None,
                    x_errorsource: None,
                }),
            ),
            ApiError::NotFound(message) => (
                StatusCode::NOT_FOUND,
                Json(ApiErrorResponse {
                    message: message.unwrap_or_else(|| "Not Found".into()),
                    error_code: SovdErrorCode::VendorSpecific,
                    vendor_code: Some(SovdVendorErrorCode::NotFound),
                    parameters: None,
                    x_errorsource: None,
                }),
            ),
            ApiError::InternalServerError(message) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiErrorResponse {
                    message: message.unwrap_or_else(|| "Internal Server Error".into()),
                    error_code: SovdErrorCode::SovdServerFailure,
                    vendor_code: None,
                    parameters: None,
                    x_errorsource: None,
                }),
            ),
            ApiError::Conflict(message) => (
                StatusCode::CONFLICT,
                Json(ApiErrorResponse {
                    message,
                    error_code: SovdErrorCode::PreconditionsNotFulfilled,
                    vendor_code: None,
                    parameters: None,
                    x_errorsource: None,
                }),
            ),
            ApiError::BadRequest(message) => (
                StatusCode::BAD_REQUEST,
                Json(ApiErrorResponse {
                    message,
                    error_code: SovdErrorCode::VendorSpecific,
                    vendor_code: Some(SovdVendorErrorCode::BadRequest),
                    parameters: None,
                    x_errorsource: None,
                }),
            ),
        }
        .into_response()
    }
}

pub(super) fn api_error_from_diag_response(response: impl DiagServiceResponse) -> Response {
    let nrc = match response.as_nrc() {
        Ok(nrc) => nrc,
        Err(e) => {
            return ApiError::InternalServerError(Some(format!(
                "Failed to convert response to NRC: {e}"
            )))
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

    let error_response = ApiErrorResponse {
        error_code: SovdErrorCode::ErrorResponse,
        message,
        parameters: if parameters.is_empty() {
            None
        } else {
            Some(parameters)
        },
        x_errorsource: Some("ECU".to_owned()),
        vendor_code: None,
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
            Json(ApiErrorResponse {
                message: "Method not allowed".to_string(),
                error_code: SovdErrorCode::VendorSpecific,
                vendor_code: Some(SovdVendorErrorCode::BadRequest),
                parameters: None,
                x_errorsource: None,
            }),
        )
            .into_response(),
        StatusCode::REQUEST_TIMEOUT => (
            StatusCode::REQUEST_TIMEOUT,
            Json(ApiErrorResponse {
                message: "Request timed out".to_string(),
                error_code: SovdErrorCode::VendorSpecific,
                vendor_code: Some(SovdVendorErrorCode::RequestTimeout),
                parameters: None,
                x_errorsource: None,
            }),
        )
            .into_response(),
        _ => resp,
    }
}

pub(crate) async fn sovd_not_found_handler(uri: Uri) -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(ApiErrorResponse {
            message: format!("Resource not found: {uri}"),
            error_code: SovdErrorCode::VendorSpecific,
            vendor_code: Some(SovdVendorErrorCode::NotFound),
            parameters: None,
            x_errorsource: None,
        }),
    )
}
