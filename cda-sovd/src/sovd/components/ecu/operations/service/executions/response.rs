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

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use cda_interfaces::{
    BinaryEncoding, DiagComm, SchemaProvider,
    diagservices::{DiagServiceJsonResponse, DiagServiceResponse},
};
use sovd_interfaces::components::ecu::operations::{AsyncGetByIdResponse, ExecutionStatus};

use crate::sovd::{
    StoredParameters, create_schema, error::VendorErrorCode, field_parse_errors_to_json,
};

/// `null` and an empty object both mean "no output parameters"; the
/// response then omits `parameters` instead of sending an empty value.
pub(super) fn is_present_value(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => false,
        serde_json::Value::Object(map) => !map.is_empty(),
        _ => true,
    }
}

pub(super) fn err_invalid_content(
    detail: String,
) -> sovd_interfaces::error::DataError<VendorErrorCode> {
    sovd_interfaces::error::DataError {
        path: "/parameters".to_owned(),
        error: sovd_interfaces::error::ApiErrorResponse {
            message: detail,
            error_code: sovd_interfaces::error::ErrorCode::InvalidResponseContent,
            vendor_code: None,
            parameters: None,
            error_source: None,
            schema: None,
        },
    }
}

/// Parses a positive, non-empty UDS response into `(parameters, errors)`.
///
/// - `Object` -> parameters map + any field-parse errors
/// - `Null`  -> empty parameters, no errors (ECU signalled no output)
/// - anything else, or a parse failure -> empty parameters, one soft `DataError`
pub(super) fn parse_json_response_params<R: DiagServiceResponse>(
    response: R,
    context: &str,
    binary_encoding: BinaryEncoding,
) -> (
    serde_json::Map<String, serde_json::Value>,
    Vec<sovd_interfaces::error::DataError<VendorErrorCode>>,
) {
    match response.into_json(binary_encoding) {
        Ok(DiagServiceJsonResponse {
            data: serde_json::Value::Object(m),
            errors,
        }) => (m, field_parse_errors_to_json(errors, "parameters")),
        Ok(DiagServiceJsonResponse {
            data: serde_json::Value::Null,
            ..
        }) => (serde_json::Map::new(), vec![]),
        Ok(v) => (
            serde_json::Map::new(),
            vec![err_invalid_content(format!(
                "Expected JSON object but got: {}",
                v.data
            ))],
        ),
        Err(e) => (
            serde_json::Map::new(),
            vec![err_invalid_content(format!(
                "Failed to parse {context} response: {e:?}"
            ))],
        ),
    }
}

pub(super) type ResponseParameters = serde_json::Map<String, serde_json::Value>;

/// Like [`parse_json_response_params`] for `binary_encoding`, additionally
/// returns the stored parameters, which map the kept response on demand
/// in the encoding of a later request.
pub(super) fn parse_json_response_params_stored<R: DiagServiceResponse>(
    response: &R,
    context: &'static str,
    binary_encoding: BinaryEncoding,
) -> (
    ResponseParameters,
    StoredParameters<ResponseParameters>,
    Vec<sovd_interfaces::error::DataError<VendorErrorCode>>,
) {
    let (parameters, errors) =
        parse_json_response_params(response.clone(), context, binary_encoding);
    let stored_response = response.clone();
    let stored = StoredParameters::from_fn(move |encoding| {
        parse_json_response_params(stored_response.clone(), context, encoding).0
    });
    (parameters, stored, errors)
}

/// Builds the `200 OK` `AsyncGetByIdResponse` body used by both the
/// `RequestResults` success path and the `suppress_service` fallback path.
/// An empty `parameters` map is serialised as `null` per the SOVD spec.
pub(super) fn get_by_id_response(
    status: ExecutionStatus,
    parameters: serde_json::Map<String, serde_json::Value>,
    error: Vec<sovd_interfaces::error::DataError<VendorErrorCode>>,
    include_schema: bool,
) -> Response {
    use sovd_interfaces::components::ecu::operations::GetByIdCapability;
    let schema = if include_schema {
        Some(create_schema!(AsyncGetByIdResponse<VendorErrorCode>))
    } else {
        None
    };
    let parameters = if parameters.is_empty() {
        None
    } else {
        Some(serde_json::Value::Object(parameters))
    };
    (
        StatusCode::OK,
        Json(AsyncGetByIdResponse::<VendorErrorCode> {
            status,
            capability: GetByIdCapability::Execute,
            parameters,
            progress: None,
            error,
            schema,
        }),
    )
        .into_response()
}

pub(super) async fn get_subschema<T: SchemaProvider>(
    ecu_name: &str,
    uds: &T,
    diag_service: &DiagComm,
    binary_encoding: BinaryEncoding,
) -> Option<schemars::Schema> {
    match uds
        .schema_for_responses(ecu_name, diag_service)
        .await
        .map(|s| s.with_binary_encoding(binary_encoding).into_schema())
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(
                error = ?e,
                diag_service = ?diag_service,
                "Failed to get schema for diag service"
            );
            None
        }
    }
}
