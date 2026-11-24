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
    body::Bytes,
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use cda_interfaces::{
    BinaryEncoding, DiagComm, DiagCommType, DynamicPlugin, SchemaProvider, UdsEcu,
    diagservices::{DiagServiceJsonResponse, DiagServiceResponse, DiagServiceResponseType},
};
use cda_plugin_security::SecurityPlugin;
use sovd_interfaces::components::ecu::operations::service::executions as sovd_executions;

use super::response::{get_subschema, is_present_value};
use crate::sovd::{
    api_error_from_diag_response, create_response_schema,
    error::{ApiError, ErrorWrapper},
    field_parse_errors_to_json,
};

#[allow(
    clippy::too_many_lines,
    reason = "Current implementation has little potential to extract smaller functions"
)]
pub(super) async fn ecu_reset_handler<T: UdsEcu + SchemaProvider + Clone>(
    service: String,
    ecu_name: &str,
    uds: &T,
    body: Bytes,
    security_plugin: Box<dyn SecurityPlugin>,
    include_schema: bool,
    binary_encoding: BinaryEncoding,
) -> Response {
    // todo: in the future we have to handle possible parameters for the reset service
    let Some(request_parameters) = serde_json::from_slice::<sovd_executions::Request>(&body)
        .ok()
        .and_then(|v| v.parameters)
    else {
        return ErrorWrapper {
            error: ApiError::BadRequest("Invalid request body".to_string()),
            include_schema,
        }
        .into_response();
    };

    let Some(value) = request_parameters.get("value") else {
        return ErrorWrapper {
            error: ApiError::BadRequest("Missing 'value' parameter in request body".to_owned()),
            include_schema,
        }
        .into_response();
    };

    let Some(value_str) = value.as_str() else {
        return ErrorWrapper {
            error: ApiError::BadRequest("The 'value' parameter must be a string".to_owned()),
            include_schema,
        }
        .into_response();
    };

    let allowed_values = uds.get_ecu_reset_services(ecu_name).await;
    let allowed_values = match allowed_values {
        Ok(v) => v,
        Err(e) => {
            return ErrorWrapper {
                error: e.into(),
                include_schema,
            }
            .into_response();
        }
    };

    if !allowed_values
        .iter()
        .any(|v| v.eq_ignore_ascii_case(value_str))
    {
        return ErrorWrapper {
            error: ApiError::BadRequest(format!(
                "Invalid value for reset service: {value_str}. Allowed values: [{}]",
                allowed_values.join(", ")
            )),
            include_schema,
        }
        .into_response();
    }

    let diag_service = DiagComm {
        name: service.clone(),
        type_: DiagCommType::Modes, // ecureset is in modes
        lookup_name: Some(value_str.to_owned()),
        subfunction_id: None,
    };

    let schema = if include_schema {
        let subschema = get_subschema(ecu_name, uds, &diag_service, binary_encoding).await;
        Some(create_response_schema!(
            sovd_executions::Response<VendorErrorCode>,
            "parameters",
            subschema
        ))
    } else {
        None
    };

    let security_plugin: DynamicPlugin = security_plugin;
    let send_result = uds
        .send(ecu_name, diag_service, &security_plugin, None, true)
        .await;
    let response = match send_result {
        Ok(v) => v,
        Err(e) => {
            return ErrorWrapper {
                error: e.into(),
                include_schema,
            }
            .into_response();
        }
    };

    match response.response_type() {
        DiagServiceResponseType::Negative => {
            api_error_from_diag_response(&response, include_schema).into_response()
        }
        DiagServiceResponseType::Positive => {
            if response.is_empty() {
                StatusCode::NO_CONTENT.into_response()
            } else {
                let (response_data, parse_errors) = match response.into_json(binary_encoding) {
                    Ok(DiagServiceJsonResponse {
                        data: serde_json::Value::Null,
                        errors,
                    }) if errors.is_empty() => {
                        return StatusCode::NO_CONTENT.into_response();
                    }
                    Ok(DiagServiceJsonResponse { data, errors }) => (data, errors),
                    Err(e) => {
                        return ErrorWrapper {
                            error: ApiError::InternalServerError(Some(format!("{e:?}"))),
                            include_schema,
                        }
                        .into_response();
                    }
                };
                let error = field_parse_errors_to_json(parse_errors, "parameters")
                    .into_iter()
                    .next();
                let parameters = is_present_value(&response_data).then_some(response_data);
                (
                    StatusCode::OK,
                    Json(sovd_executions::Response {
                        parameters,
                        error,
                        schema,
                    }),
                )
                    .into_response()
            }
        }
    }
}
