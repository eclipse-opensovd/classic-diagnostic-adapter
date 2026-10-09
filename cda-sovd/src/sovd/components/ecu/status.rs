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

//! Status resource of an ECU (ISO 17978-3 §7.19) with the restart mapped to
//! `ECUReset` (§8.7).

use aide::{UseApi, transform::TransformOperation};
use axum::{
    Json,
    extract::{OriginalUri, Query, State},
    response::{IntoResponse, Response},
};
use axum_extra::extract::WithRejection;
use cda_interfaces::{
    Connectivity, DynamicPlugin, UdsEcu,
    diagservices::{DiagServiceResponse, DiagServiceResponseType},
    file_manager::FileManager,
};
use cda_plugin_security::Secured;
use http::{StatusCode, header};
use opensovd_axum_extra::ExtractHost;
use sovd_interfaces::{
    components::ecu::status::{EntityStatus, EntityStatusResponse, get, restart},
    error::ErrorCode,
};

use crate::{
    openapi,
    sovd::{
        IntoSovd, WebserverEcuState,
        components::ecu::operations::service::executions::resolve_ecu_reset_service,
        create_schema,
        error::{ApiError, ErrorWrapper, nrc_to_api_error_response},
        locks::require_ecu_access,
    },
};

const RESTART_SEGMENT: &str = "/restart";

pub(crate) async fn get<T: UdsEcu + Clone, U: FileManager>(
    State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<T, U>>,
    WithRejection(Query(query), _): WithRejection<Query<get::Query>, ApiError>,
    UseApi(ExtractHost(host), _): UseApi<ExtractHost, String>,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let include_schema = query.include_schema;
    let ecu_state = match uds.get_ecu_state(&ecu_name).await {
        Ok(v) => v,
        Err(e) => {
            return ErrorWrapper {
                error: e.into(),
                include_schema,
            }
            .into_response();
        }
    };
    let status = match ecu_state.connectivity {
        Connectivity::Online => EntityStatus::Ready,
        Connectivity::Offline => EntityStatus::NotReady,
    };
    // Table 280 C2: the restart link is only present if the ECU supports ECUReset.
    let restart = uds
        .get_ecu_reset_services(&ecu_name)
        .await
        .is_ok_and(|services| !services.is_empty())
        .then(|| format!("http://{host}{}{RESTART_SEGMENT}", uri.path()));

    (
        StatusCode::OK,
        Json(get::Response {
            status,
            restart,
            state: ecu_state.into_sovd(),
            schema: include_schema.then(|| create_schema!(get::Response)),
        }),
    )
        .into_response()
}

pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
    op.description("Read the status of the ECU and the resources controlling it")
        .response_with::<200, Json<get::Response>, _>(|res| {
            res.example(EntityStatusResponse {
                status: EntityStatus::Ready,
                restart: Some(
                    "http://localhost:20002/vehicle/v15/components/my_ecu/status/restart"
                        .to_owned(),
                ),
                state: sovd_interfaces::components::ecu::State::Online,
                schema: None,
            })
        })
        .with(openapi::error_not_found)
        .id("ecu_status_get")
}

pub(crate) mod restart_entity {
    use axum::body::Bytes;

    use super::{
        ApiError, DiagServiceResponse, DiagServiceResponseType, DynamicPlugin, ErrorCode,
        ErrorWrapper, ExtractHost, FileManager, IntoResponse, Json, OriginalUri, RESTART_SEGMENT,
        Response, Secured, State, StatusCode, TransformOperation, UdsEcu, UseApi,
        WebserverEcuState, header, nrc_to_api_error_response, openapi, require_ecu_access,
        resolve_ecu_reset_service, restart,
    };

    // [[ dimpl~sovd-api-ecu-restart, PUT status/restart mapped to ECUReset ]]
    pub(crate) async fn put<T: UdsEcu + Clone, U: FileManager>(
        UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
        State(WebserverEcuState {
            ecu_name,
            uds,
            locks,
            ..
        }): State<WebserverEcuState<T, U>>,
        UseApi(ExtractHost(host), _): UseApi<ExtractHost, String>,
        OriginalUri(uri): OriginalUri,
        body: Bytes,
    ) -> Response {
        require_ecu_access!(write, security_plugin, &ecu_name, &locks, false);
        let err_response = |error: ApiError| {
            ErrorWrapper {
                error,
                include_schema: false,
            }
            .into_response()
        };

        let reset_type = match reset_type_from_body(&body) {
            Ok(v) => v,
            Err(e) => return err_response(e),
        };
        let diag_service = match resolve_ecu_reset_service(&ecu_name, &uds, &reset_type).await {
            Ok(v) => v,
            Err(e) => return err_response(e),
        };
        let response = match uds
            .send(
                &ecu_name,
                diag_service,
                &(security_plugin as DynamicPlugin),
                None,
                true,
            )
            .await
        {
            Ok(v) => v,
            Err(e) => return err_response(e.into()),
        };

        match response.response_type() {
            // Table 285: the ECU refusing the reset is an unsatisfied precondition.
            DiagServiceResponseType::Negative => match response.as_nrc() {
                Ok(nrc) => {
                    let mut error = nrc_to_api_error_response(nrc, false);
                    error.error_code = ErrorCode::PreconditionsNotFulfilled;
                    (StatusCode::CONFLICT, Json(error)).into_response()
                }
                Err(e) => err_response(ApiError::InternalServerError(Some(format!(
                    "Failed to convert response to NRC: {e}"
                )))),
            },
            DiagServiceResponseType::Positive => {
                let status_path = uri
                    .path()
                    .strip_suffix(RESTART_SEGMENT)
                    .unwrap_or(uri.path());
                (
                    StatusCode::ACCEPTED,
                    [(header::LOCATION, format!("http://{host}{status_path}"))],
                )
                    .into_response()
            }
        }
    }

    /// Reads the `ResetType` parameter (§8.7) from a Table 284 request body.
    fn reset_type_from_body(body: &[u8]) -> Result<String, ApiError> {
        let request: restart::put::Request = serde_json::from_slice(body)
            .map_err(|e| ApiError::BadRequest(format!("Invalid request body: {e}")))?;
        let reset_type = request
            .parameters
            .as_ref()
            .and_then(serde_json::Value::as_object)
            .and_then(|parameters| {
                parameters.iter().find_map(|(key, value)| {
                    key.eq_ignore_ascii_case(restart::put::RESET_TYPE_PARAMETER)
                        .then_some(value)
                })
            })
            .ok_or_else(|| {
                ApiError::BadRequest(format!(
                    "Missing '{}' in request parameters",
                    restart::put::RESET_TYPE_PARAMETER
                ))
            })?;
        reset_type.as_str().map(ToOwned::to_owned).ok_or_else(|| {
            ApiError::BadRequest(format!(
                "The '{}' parameter must be a string",
                restart::put::RESET_TYPE_PARAMETER
            ))
        })
    }

    pub(crate) fn docs_put(op: TransformOperation) -> TransformOperation {
        op.description(
            "Restart the ECU via ECUReset. The `ResetType` parameter selects one of the reset \
             services of the ECU.",
        )
        .input::<Json<restart::put::Request>>()
        .response_with::<202, (), _>(|res| {
            res.description(
                "Restart initiated; the `Location` header points to the status resource.",
            )
        })
        .with(openapi::error_bad_request)
        .with(openapi::error_conflict)
        .with(openapi::error_forbidden)
        .with(openapi::error_not_found)
        .id("ecu_status_restart_put")
    }

    #[cfg(test)]
    mod tests {
        use super::reset_type_from_body;

        #[test]
        fn reads_reset_type_case_insensitively() {
            assert_eq!(
                reset_type_from_body(br#"{"parameters":{"resettype":"HardReset"}}"#).unwrap(),
                "HardReset"
            );
            assert_eq!(
                reset_type_from_body(br#"{"parameters":{"ResetType":"SoftReset"}}"#).unwrap(),
                "SoftReset"
            );
        }

        #[test]
        fn rejects_missing_or_non_string_reset_type() {
            for body in [
                &br"{}"[..],
                br#"{"parameters":"HardReset"}"#,
                br#"{"parameters":{"value":"HardReset"}}"#,
                br#"{"parameters":{"ResetType":1}}"#,
                b"not json",
            ] {
                assert!(reset_type_from_body(body).is_err());
            }
        }
    }
}
