/*
 * Copyright (c) 2025-2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
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

pub(crate) mod diag_service {
    use aide::{UseApi, transform::TransformOperation};
    use axum::{
        Json,
        body::Bytes,
        extract::{Path, Query, State},
        http::{HeaderMap, StatusCode},
        response::{IntoResponse, Response},
    };
    use axum_extra::extract::WithRejection;
    use cda_interfaces::{DiagComm, DiagCommType, HashMap, UdsEcu};
    use cda_plugin_security::Secured;

    use super::super::WebserverFgState;
    use crate::{
        openapi,
        sovd::{
            components::{ecu::DiagServicePathParam, get_content_type_and_accept},
            error::{ApiError, ErrorWrapper, VendorErrorCode},
            functions::functional_groups::{handle_ecu_response, map_to_json},
            get_payload_data,
        },
    };

    pub(crate) async fn post<T: UdsEcu + Clone>(
        headers: HeaderMap,
        UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
        Path(DiagServicePathParam {
            diag_service: operation,
        }): Path<DiagServicePathParam>,
        WithRejection(Query(query), _): WithRejection<
            Query<sovd_interfaces::functions::functional_groups::operations::service::Query>,
            ApiError,
        >,
        State(WebserverFgState {
            uds,
            functional_group_name,
            ..
        }): State<WebserverFgState<T>>,
        body: Bytes,
    ) -> Response {
        let include_schema = query.include_schema;
        if operation.contains('/') {
            return ErrorWrapper {
                error: ApiError::BadRequest("Invalid path".to_owned()),
                include_schema,
            }
            .into_response();
        }

        functional_operations_request(
            DiagComm {
                name: operation,
                type_: DiagCommType::Operations,
                lookup_name: None,
            },
            &functional_group_name,
            &uds,
            headers,
            body,
            security_plugin,
            include_schema,
        )
        .await
    }

    pub(crate) fn docs_post(op: TransformOperation) -> TransformOperation {
        openapi::request_json_and_octet::<
            sovd_interfaces::functions::functional_groups::operations::service::Request,
        >(op)
        .description("Execute an operation on a functional group - sends to all ECUs in the group")
        .response_with::<200, Json<
            sovd_interfaces::functions::functional_groups::operations::service::Response<
                VendorErrorCode,
            >,
        >, _>(|res| {
            res.description(
                "Response with parameters from all ECUs in the functional group, keyed by ECU name",
            )
            .example(
                sovd_interfaces::functions::functional_groups::operations::service::Response {
                    parameters: {
                        let mut map = HashMap::default();
                        let mut ecu1_params = serde_json::Map::new();
                        ecu1_params.insert("status".to_string(), serde_json::json!("success"));
                        map.insert("ECU1".to_string(), ecu1_params);
                        map
                    },
                    errors: vec![],
                    schema: None,
                },
            )
        })
        .with(openapi::error_forbidden)
        .with(openapi::error_not_found)
        .with(openapi::error_internal_server)
        .with(openapi::error_bad_request)
        .with(openapi::error_bad_gateway)
    }

    async fn functional_operations_request<T: UdsEcu + Clone>(
        service: DiagComm,
        functional_group_name: &str,
        gateway: &T,
        headers: HeaderMap,
        body: Bytes,
        security_plugin: Box<dyn cda_plugin_security::SecurityPlugin>,
        include_schema: bool,
    ) -> Response {
        let (content_type, accept) = match get_content_type_and_accept(&headers) {
            Ok(v) => v,
            Err(e) => {
                return ErrorWrapper {
                    error: e,
                    include_schema,
                }
                .into_response();
            }
        };

        let data = match get_payload_data::<
            sovd_interfaces::functions::functional_groups::operations::service::Request,
        >(content_type.as_ref(), &headers, &body)
        {
            Ok(value) => value,
            Err(e) => {
                return ErrorWrapper {
                    error: e,
                    include_schema,
                }
                .into_response();
            }
        };

        let map_to_json = match map_to_json(include_schema, &accept) {
            Ok(value) => value,
            Err(e) => return e.into_response(),
        };

        // Send functional request to all ECUs in the group
        let results = gateway
            .send_functional_group(
                functional_group_name,
                service,
                &(security_plugin as cda_interfaces::DynamicPlugin),
                data,
                map_to_json,
            )
            .await;

        // Build response with per-ECU parameters and errors
        let mut response_data: HashMap<String, serde_json::Map<String, serde_json::Value>> =
            HashMap::default();
        let mut errors: Vec<sovd_interfaces::error::DataError<VendorErrorCode>> = Vec::new();

        for (ecu_name, result) in results {
            handle_ecu_response(
                &mut response_data,
                "parameters",
                &mut errors,
                ecu_name,
                result,
            );
        }

        let schema = if include_schema {
            Some(crate::sovd::create_schema!(
                sovd_interfaces::functions::functional_groups::operations::service::Response<
                    VendorErrorCode,
                >
            ))
        } else {
            None
        };

        (
            StatusCode::OK,
            Json(
                sovd_interfaces::functions::functional_groups::operations::service::Response {
                    parameters: response_data,
                    errors,
                    schema,
                },
            ),
        )
            .into_response()
    }
}
