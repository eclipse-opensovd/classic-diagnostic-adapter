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

pub(crate) mod comparams {

    pub(crate) mod executions {
        use std::sync::Arc;

        use aide::{UseApi, transform::TransformOperation};
        use axum::{
            Json,
            extract::{OriginalUri, Path, Query, State},
            http::{StatusCode, header},
            response::{IntoResponse as _, Response},
        };
        use axum_extra::extract::{Host, WithRejection};
        use cda_interfaces::{
            UdsEcu, diagservices::DiagServiceResponse, file_manager::FileManager,
        };
        use hashbrown::HashMap;
        use indexmap::IndexMap;
        use sovd_interfaces::components::ecu::operations::comparams as sovd_comparams;
        use tokio::sync::RwLock;
        use uuid::Uuid;

        use crate::sovd::{
            IntoSovd, WebserverEcuState, create_schema,
            error::{ApiError, ErrorWrapper},
        };

        pub(crate) async fn get<R: DiagServiceResponse, T: UdsEcu + Clone, U: FileManager>(
            WithRejection(Query(query), _): WithRejection<
                Query<sovd_comparams::executions::get::Query>,
                ApiError,
            >,
            State(WebserverEcuState {
                comparam_executions,
                ..
            }): State<WebserverEcuState<R, T, U>>,
        ) -> Response {
            handler_read(comparam_executions, query.include_schema).await
        }

        pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
            op.description("Get all comparam executions")
                .response_with::<200, Json<sovd_comparams::executions::get::Response>, _>(|res| {
                    res.description("Response with all comparam executions.")
                        .example(sovd_comparams::executions::get::Response {
                            items: vec![sovd_comparams::executions::Item {
                                id: "b7e2c1a2-3f4d-4e6a-9c8b-2a1d5e7f8c9b".to_string(),
                            }],
                            schema: None,
                        })
                })
        }

        pub(crate) async fn post<R: DiagServiceResponse, T: UdsEcu + Clone, U: FileManager>(
            WithRejection(Query(query), _): WithRejection<
                Query<sovd_comparams::executions::get::Query>,
                ApiError,
            >,
            State(WebserverEcuState {
                comparam_executions,
                ..
            }): State<WebserverEcuState<R, T, U>>,
            UseApi(Host(host), _): UseApi<Host, String>,
            OriginalUri(uri): OriginalUri,
            request_body: Option<Json<sovd_comparams::executions::update::Request>>,
        ) -> Response {
            let path = format!("http://{host}{uri}");
            let body = if let Some(Json(body)) = request_body {
                Some(body)
            } else {
                None
            };
            handler_write(comparam_executions, path, body, query.include_schema).await
        }

        pub(crate) fn docs_post(op: TransformOperation) -> TransformOperation {
            op.description("Create a new comparam execution")
                .response_with::<202, Json<sovd_comparams::executions::update::Response>, _>(
                    |res| {
                        res.description("Comparam execution created successfully.")
                            .example(sovd_comparams::executions::update::Response {
                                id: "b7e2c1a2-3f4d-4e6a-9c8b-2a1d5e7f8c9b".to_string(),
                                status: sovd_comparams::executions::Status::Running,
                                schema: None,
                            })
                    },
                )
        }

        pub(crate) async fn handler_read(
            executions: Arc<RwLock<IndexMap<Uuid, sovd_comparams::Execution>>>,
            include_schema: bool,
        ) -> Response {
            let schema = if include_schema {
                Some(create_schema!(sovd_comparams::executions::get::Response))
            } else {
                None
            };
            (
                StatusCode::OK,
                Json(sovd_comparams::executions::get::Response {
                    items: executions
                        .read()
                        .await
                        .keys()
                        .map(|id| sovd_comparams::executions::Item { id: id.to_string() })
                        .collect::<Vec<_>>(),
                    schema,
                }),
            )
                .into_response()
        }
        async fn handler_write(
            executions: Arc<RwLock<IndexMap<Uuid, sovd_comparams::Execution>>>,
            base_path: String,
            request: Option<sovd_comparams::executions::update::Request>,
            include_schema: bool,
        ) -> Response {
            // todo: not in scope for now: request can take body with
            // { timeout: INT, parameters: { ... }, proximity_response: STRING }
            let mut executions = executions.write().await;
            let id = Uuid::new_v4();
            let mut comparam_override: HashMap<String, sovd_comparams::ComParamValue> =
                HashMap::new();

            if let Some(sovd_comparams::executions::update::Request {
                parameters: Some(parameters),
                ..
            }) = request
            {
                for (k, v) in parameters {
                    comparam_override.insert(k, v);
                }
            }

            let schema = if include_schema {
                Some(create_schema!(sovd_comparams::executions::update::Response))
            } else {
                None
            };

            let create_execution_response = sovd_comparams::executions::update::Response {
                id: id.to_string(),
                status: sovd_comparams::executions::Status::Running,
                schema,
            };
            executions.insert(
                id,
                sovd_comparams::Execution {
                    capability: sovd_comparams::executions::Capability::Execute,
                    status: create_execution_response.status.clone(),
                    comparam_override,
                },
            );
            (
                StatusCode::ACCEPTED,
                [(header::LOCATION, format!("{base_path}/{id}"))],
                Json(create_execution_response),
            )
                .into_response()
        }

        pub(crate) mod id {
            use super::*;
            use crate::{openapi, sovd::components::IdPathParam};
            pub(crate) async fn get<R: DiagServiceResponse, T: UdsEcu + Clone, U: FileManager>(
                Path(id): Path<IdPathParam>,
                WithRejection(Query(query), _): WithRejection<
                    Query<sovd_comparams::executions::get::Query>,
                    ApiError,
                >,
                State(WebserverEcuState {
                    ecu_name,
                    uds,
                    comparam_executions,
                    ..
                }): State<WebserverEcuState<R, T, U>>,
            ) -> Response {
                let include_schema = query.include_schema;
                let id = match Uuid::parse_str(&id) {
                    Ok(v) => v,
                    Err(e) => {
                        return ErrorWrapper {
                            error: ApiError::BadRequest(format!("{e:?}")),
                            include_schema,
                        }
                        .into_response();
                    }
                };
                let mut executions: Vec<sovd_comparams::Execution> = Vec::new();

                let (idx, execution) = match comparam_executions
                    .read()
                    .await
                    .get_full(&id)
                    .ok_or_else(|| {
                        ApiError::NotFound(Some(format!("Execution with id {id} not found")))
                    }) {
                    Ok((idx, _, v)) => (idx, v.clone()),
                    Err(e) => {
                        return ErrorWrapper {
                            error: e,
                            include_schema,
                        }
                        .into_response();
                    }
                };
                let capability = execution.capability.clone();
                let status = execution.status.clone();

                // put in all executions with lower index than this one
                for (_, v) in &comparam_executions.read().await.as_slice()[..idx] {
                    executions.push(v.clone());
                }
                executions.push(execution);

                let mut parameters = match uds.get_comparams(&ecu_name).await {
                    Ok(v) => v.into_sovd(),
                    Err(e) => {
                        return ErrorWrapper {
                            error: ApiError::BadRequest(e),
                            include_schema,
                        }
                        .into_response();
                    }
                };

                for (k, v) in executions.into_iter().flat_map(|e| e.comparam_override) {
                    parameters.insert(k, v);
                }

                let schema = if include_schema {
                    Some(create_schema!(
                        sovd_comparams::executions::id::get::Response
                    ))
                } else {
                    None
                };

                (
                    StatusCode::OK,
                    Json(sovd_comparams::executions::id::get::Response {
                        capability,
                        parameters,
                        status,
                        schema,
                    }),
                )
                    .into_response()
            }

            pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
                op.description("Get a specific comparam execution")
                    .response_with::<200, Json<sovd_comparams::executions::id::get::Response>, _>(
                        |res| {
                            res.description("Response with comparam execution details.")
                                .example(sovd_comparams::executions::id::get::Response {
                                    capability: sovd_comparams::executions::Capability::Execute,
                                    parameters: HashMap::new(),
                                    status: sovd_comparams::executions::Status::Running,
                                    schema: None,
                                })
                        },
                    )
                    .with(openapi::comparam_execution_errors)
            }

            pub(crate) async fn delete<
                R: DiagServiceResponse,
                T: UdsEcu + Clone,
                U: FileManager,
            >(
                Path(id): Path<IdPathParam>,
                State(WebserverEcuState {
                    comparam_executions,
                    ..
                }): State<WebserverEcuState<R, T, U>>,
            ) -> Response {
                let id = match Uuid::parse_str(&id) {
                    Ok(v) => v,
                    Err(e) => {
                        return ErrorWrapper {
                            error: ApiError::BadRequest(format!("{e:?}")),
                            include_schema: false,
                        }
                        .into_response();
                    }
                };
                let mut executions = comparam_executions.write().await;
                if executions.shift_remove(&id).is_none() {
                    return ErrorWrapper {
                        error: ApiError::NotFound(Some(format!(
                            "Execution with id {id} not found"
                        ))),
                        include_schema: false,
                    }
                    .into_response();
                }
                StatusCode::NO_CONTENT.into_response()
            }

            pub(crate) fn docs_delete(op: TransformOperation) -> TransformOperation {
                op.description("Delete a specific comparam execution")
                    .response_with::<204, (), _>(|res| {
                        res.description("Comparam execution deleted successfully.")
                    })
                    .with(openapi::comparam_execution_errors)
            }

            pub(crate) async fn put<R: DiagServiceResponse, T: UdsEcu + Clone, U: FileManager>(
                Path(id): Path<IdPathParam>,
                WithRejection(Query(query), _): WithRejection<
                    Query<sovd_comparams::executions::update::Query>,
                    ApiError,
                >,
                State(WebserverEcuState {
                    comparam_executions,
                    ..
                }): State<WebserverEcuState<R, T, U>>,
                UseApi(Host(host), _): UseApi<Host, String>,
                OriginalUri(uri): OriginalUri,
                WithRejection(Json(request), _): WithRejection<
                    Json<sovd_comparams::executions::update::Request>,
                    ApiError,
                >,
            ) -> Response {
                let include_schema = query.include_schema;
                let id = match Uuid::parse_str(&id) {
                    Ok(v) => v,
                    Err(e) => {
                        return ErrorWrapper {
                            error: ApiError::BadRequest(format!("{e:?}")),
                            include_schema,
                        }
                        .into_response();
                    }
                };
                let path = format!("http://{host}{uri}");
                // todo: (out of scope for now) handle timout and capability

                // todo: validate that the passed in CP is actually a valid CP for the ECU
                // let mut comparams = match uds.get_comparams(&ecu_name).await {
                //     Ok(v) => v,
                //     Err(e) => return ErrorWrapper(ApiError::BadRequest(e)).into_response(),
                // };

                let mut executions_lock = comparam_executions.write().await;
                let execution: &mut sovd_comparams::Execution =
                    match executions_lock.get_mut(&id).ok_or_else(|| {
                        ApiError::NotFound(Some(format!("Execution with id {id} not found")))
                    }) {
                        Ok(v) => v,
                        Err(e) => {
                            return ErrorWrapper {
                                error: e,
                                include_schema,
                            }
                            .into_response();
                        }
                    };

                if let Some(comparam_values) = request.parameters {
                    for (k, v) in comparam_values {
                        execution.comparam_override.insert(k, v);
                    }
                }

                let schema = if include_schema {
                    Some(create_schema!(sovd_comparams::executions::update::Response))
                } else {
                    None
                };

                (
                    StatusCode::ACCEPTED,
                    [(header::LOCATION, path)],
                    Json(sovd_comparams::executions::update::Response {
                        id: id.to_string(),
                        status: execution.status.clone(),
                        schema,
                    }),
                )
                    .into_response()
            }

            pub(crate) fn docs_put(op: TransformOperation) -> TransformOperation {
                op.description("Update a specific comparam execution")
                    .response_with::<202, Json<sovd_comparams::executions::update::Response>, _>(
                        |res| {
                            res.description("Comparam execution updated successfully.")
                                .example(sovd_comparams::executions::update::Response {
                                    id: "example_id".to_string(),
                                    status: sovd_comparams::executions::Status::Running,
                                    schema: None,
                                })
                        },
                    )
                    .with(openapi::comparam_execution_errors)
            }
        }
    }
}

pub(crate) mod service {
    pub(crate) mod executions {
        use aide::transform::TransformOperation;
        use axum::{
            Json,
            body::Bytes,
            extract::{Path, Query, State},
            http::{HeaderMap, StatusCode},
            response::{IntoResponse as _, Response},
        };
        use axum_extra::extract::WithRejection;
        use cda_interfaces::{
            DiagComm, DiagCommAction, DiagCommType, SchemaProvider, UdsEcu,
            diagservices::{DiagServiceJsonResponse, DiagServiceResponse, DiagServiceResponseType},
            file_manager::FileManager,
        };
        use sovd_interfaces::components::ecu::operations::service::executions as sovd_executions;

        use crate::{
            openapi,
            sovd::{
                self, WebserverEcuState, api_error_from_diag_response,
                components::{field_parse_errors_to_json, get_content_type_and_accept},
                create_response_schema, create_schema,
                error::{ApiError, ErrorWrapper, VendorErrorCode},
            },
        };

        openapi::aide_helper::gen_path_param!(OperationServicePathParam service String);

        pub(crate) async fn get<
            R: DiagServiceResponse,
            T: UdsEcu + SchemaProvider + Clone,
            U: FileManager,
        >(
            Path(OperationServicePathParam { service }): Path<OperationServicePathParam>,
            WithRejection(Query(query), _): WithRejection<Query<sovd_executions::Query>, ApiError>,
            State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
            headers: HeaderMap,
        ) -> Response {
            ecu_operation_handler::<T>(
                Op::Read,
                service,
                &ecu_name,
                &uds,
                headers,
                None,
                query.include_schema,
            )
            .await
        }

        pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
            op.description("Get all executions")
                .response_with::<200, Json<sovd_interfaces::Items<String>>, _>(|res| {
                    res.description("List of all comparam executions.").example(
                        sovd_interfaces::Items {
                            items: vec!["e7a1c2b2-4f3a-4c8e-9b2a-8d6e2f7c1a5b".to_string()],
                            schema: None,
                        },
                    )
                })
        }

        pub(crate) async fn post<
            R: DiagServiceResponse,
            T: UdsEcu + SchemaProvider + Clone,
            U: FileManager,
        >(
            Path(OperationServicePathParam { service }): Path<OperationServicePathParam>,
            WithRejection(Query(query), _): WithRejection<Query<sovd_executions::Query>, ApiError>,
            State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
            headers: HeaderMap,
            body: Bytes,
        ) -> Response {
            ecu_operation_handler::<T>(
                Op::Write,
                service,
                &ecu_name,
                &uds,
                headers,
                Some(body),
                query.include_schema,
            )
            .await
        }

        pub(crate) fn docs_post(op: TransformOperation) -> TransformOperation {
            openapi::request_json_and_octet::<sovd_executions::Request>(op)
                .description("Create a new execution")
                .response_with::<200, Json<sovd_executions::Response<VendorErrorCode>>, _>(|res| {
                    let mut res = res
                        .description(
                            "Comparam execution created successfully without response content.",
                        )
                        .example(sovd_executions::Response {
                            parameters: serde_json::Map::from_iter([(
                                "example_param".to_string(),
                                serde_json::Value::String("example_value".to_string()),
                            )]),
                            errors: vec![],
                            schema: None,
                        });
                    res.inner().content.insert(
                        "application/octet-stream".to_owned(),
                        aide::openapi::MediaType {
                            example: Some(serde_json::json!([0xabu8, 0xcd, 0xef, 0x00])),
                            ..Default::default()
                        },
                    );
                    res
                })
                .response_with::<204, (), _>(|res| {
                    res.description(
                        "Comparam execution created successfully without response content.",
                    )
                })
                .with(openapi::error_bad_request)
                .with(openapi::error_not_found)
                .with(openapi::error_internal_server)
                .with(openapi::error_bad_gateway)
        }

        async fn ecu_operation_handler<T: UdsEcu + SchemaProvider + Clone>(
            op: Op,
            service: String,
            ecu_name: &str,
            uds: &T,
            headers: HeaderMap,
            body: Option<Bytes>,
            include_schema: bool,
        ) -> Response {
            match op {
                Op::Read => {
                    // todo: this should return the actual executions.
                    // and also the correct schema in that case
                    let schema = if include_schema {
                        Some(create_schema!(sovd_interfaces::Items<String>))
                    } else {
                        None
                    };
                    (
                        StatusCode::OK,
                        Json(sovd_interfaces::Items::<String> {
                            items: Vec::new(),
                            schema,
                        }),
                    )
                        .into_response()
                }
                Op::Write => {
                    let Some(body) = body else {
                        return ErrorWrapper {
                            error: ApiError::BadRequest("Missing request body".to_owned()),
                            include_schema,
                        }
                        .into_response();
                    };
                    if service == "reset" {
                        return ecu_reset_handler::<T>(
                            service,
                            ecu_name,
                            uds,
                            body,
                            include_schema,
                        )
                        .await;
                    }

                    let content_type_and_accept = match get_content_type_and_accept(&headers) {
                        Ok(v) => v,
                        Err(e) => {
                            return ErrorWrapper {
                                error: e,
                                include_schema,
                            }
                            .into_response();
                        }
                    };

                    let (Some(content_type), accept) = content_type_and_accept else {
                        return ErrorWrapper {
                            error: ApiError::BadRequest("Missing Content-Type".to_owned()),
                            include_schema,
                        }
                        .into_response();
                    };

                    let diag_service = DiagComm {
                        name: service.clone(),
                        action: DiagCommAction::Start,
                        type_: DiagCommType::Operations,
                        lookup_name: None,
                    };

                    let data = match sovd::get_payload_data::<sovd_executions::Request>(
                        Some(&content_type),
                        &headers,
                        &body,
                    ) {
                        Ok(v) => v,
                        Err(e) => {
                            return ErrorWrapper {
                                error: e,
                                include_schema,
                            }
                            .into_response();
                        }
                    };

                    if accept != mime::APPLICATION_OCTET_STREAM && accept != mime::APPLICATION_JSON
                    {
                        return ErrorWrapper {
                            error: ApiError::BadRequest(format!(
                                "Unsupported Accept header: {accept:?}"
                            )),
                            include_schema,
                        }
                        .into_response();
                    }

                    let map_to_json = accept == mime::APPLICATION_JSON;

                    let schema = if map_to_json && include_schema {
                        let subschema = match uds
                            .schema_for_responses(ecu_name, &diag_service)
                            .await
                            .map(|desc| desc.into_schema())
                        {
                            Ok(v) => v,
                            Err(e) => {
                                log::error!(
                                    "Failed to get schema for diag service {diag_service:?}: {e:?}"
                                );
                                None
                            }
                        };
                        Some(create_response_schema!(
                            sovd_executions::Response<VendorErrorCode>,
                            "parameters",
                            subschema
                        ))
                    } else {
                        None
                    };

                    let response = match uds.send(ecu_name, diag_service, data, map_to_json).await {
                        Ok(v) => v,
                        Err(e) => {
                            return ErrorWrapper {
                                error: e.into(),
                                include_schema,
                            }
                            .into_response();
                        }
                    };

                    if let DiagServiceResponseType::Negative = response.response_type() {
                        return api_error_from_diag_response(response, include_schema)
                            .into_response();
                    }

                    if response.is_empty() {
                        return StatusCode::NO_CONTENT.into_response();
                    }

                    if map_to_json {
                        let (mapped_data, errors) = match response.into_json() {
                            Ok(DiagServiceJsonResponse {
                                data: serde_json::Value::Object(mapped_data),
                                errors,
                            }) => (mapped_data, errors),
                            Ok(v) => {
                                return ErrorWrapper {
                                    error: ApiError::InternalServerError(Some(format!(
                                        "Expected JSON object but got: {}",
                                        v.data
                                    ))),
                                    include_schema,
                                }
                                .into_response();
                            }
                            Err(e) => {
                                return ErrorWrapper {
                                    error: ApiError::InternalServerError(Some(format!("{e:?}"))),
                                    include_schema,
                                }
                                .into_response();
                            }
                        };
                        (
                            StatusCode::OK,
                            Json(sovd_executions::Response {
                                parameters: mapped_data,
                                errors: field_parse_errors_to_json(errors, "parameters"),
                                schema,
                            }),
                        )
                            .into_response()
                    } else {
                        let data = response.get_raw().to_vec();
                        (StatusCode::OK, Bytes::from_owner(data)).into_response()
                    }
                }
            }
        }

        async fn ecu_reset_handler<T: UdsEcu + SchemaProvider + Clone>(
            service: String,
            ecu_name: &str,
            uds: &T,
            body: Bytes,
            include_schema: bool,
        ) -> Response {
            // todo: in the future we have to handle possible parameters for the reset service
            let request_parameters = match serde_json::from_slice::<sovd_executions::Request>(&body)
                .ok()
                .and_then(|v| v.parameters)
            {
                Some(v) => v,
                None => {
                    return ErrorWrapper {
                        error: ApiError::BadRequest("Invalid request body".to_string()),
                        include_schema,
                    }
                    .into_response();
                }
            };

            let Some(value) = request_parameters.get("value") else {
                return ErrorWrapper {
                    error: ApiError::BadRequest(
                        "Missing 'value' parameter in request body".to_owned(),
                    ),
                    include_schema,
                }
                .into_response();
            };

            let Some(value_str) = value.as_str() else {
                return ErrorWrapper {
                    error: ApiError::BadRequest(
                        "The 'value' parameter must be a string".to_owned(),
                    ),
                    include_schema,
                }
                .into_response();
            };

            let allowed_values = match uds.get_ecu_reset_services(ecu_name).await {
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
                action: DiagCommAction::Start,
                type_: DiagCommType::Modes, // ecureset is in modes
                lookup_name: Some(value_str.to_owned()),
            };

            let schema = if include_schema {
                let subschema = match uds
                    .schema_for_responses(ecu_name, &diag_service)
                    .await
                    .map(|desc| desc.into_schema())
                {
                    Ok(v) => v,
                    Err(e) => {
                        log::error!(
                            "Failed to get schema for diag service {diag_service:?}: {e:?}"
                        );
                        None
                    }
                };
                Some(create_response_schema!(
                    sovd_executions::Response<VendorErrorCode>,
                    "parameters",
                    subschema
                ))
            } else {
                None
            };

            let response = match uds.send(ecu_name, diag_service, None, true).await {
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
                    api_error_from_diag_response(response, include_schema).into_response()
                }
                DiagServiceResponseType::Positive => {
                    if response.is_empty() {
                        StatusCode::NO_CONTENT.into_response()
                    } else {
                        let (response_data, errors) = match response.into_json() {
                            Ok(DiagServiceJsonResponse {
                                data: serde_json::Value::Object(mapped_data),
                                errors,
                            }) => (mapped_data, errors),
                            Ok(DiagServiceJsonResponse {
                                data: serde_json::Value::Null,
                                errors,
                            }) => {
                                if errors.is_empty() {
                                    return StatusCode::NO_CONTENT.into_response();
                                }
                                (serde_json::Map::new(), errors)
                            }
                            Ok(v) => {
                                return ErrorWrapper {
                                    error: ApiError::InternalServerError(Some(format!(
                                        "Expected JSON object but got: {}",
                                        v.data
                                    ))),
                                    include_schema,
                                }
                                .into_response();
                            }
                            Err(e) => {
                                return ErrorWrapper {
                                    error: ApiError::InternalServerError(Some(format!("{e:?}"))),
                                    include_schema,
                                }
                                .into_response();
                            }
                        };
                        (
                            StatusCode::OK,
                            Json(sovd_executions::Response {
                                parameters: response_data,
                                errors: field_parse_errors_to_json(errors, "parameters"),
                                schema,
                            }),
                        )
                            .into_response()
                    }
                }
            }
        }

        enum Op {
            Read,
            Write,
        }
    }
}

#[cfg(test)]
mod tests {
    use sovd_interfaces::components::ecu::operations::comparams::ComParamSimpleValue;

    #[test]
    fn com_param_simple_deserialization() {
        let json_data_string = "\"example_value\"";
        let deserialized_string: ComParamSimpleValue =
            serde_json::from_str(json_data_string).unwrap();
        assert_eq!(deserialized_string.value, "example_value");
        assert!(deserialized_string.unit.is_none());

        let json_data_struct = r#"{
        "value": "test",
        "unit": {
            "factor_to_si_unit": 1.0,
            "offset_to_si_unit": 0.0
        }
        }"#;
        let deserialized_struct: ComParamSimpleValue =
            serde_json::from_str(json_data_struct).unwrap();
        assert_eq!(deserialized_struct.value, "test");
        let unit = deserialized_struct.unit.unwrap();
        assert_eq!(unit.factor_to_si_unit.unwrap(), 1.0);
        assert_eq!(unit.offset_to_si_unit.unwrap(), 0.0);

        let json_data_struct = r#"{
        "value": "test",
        "unit": {
            "factor_to_si_unit": 1.0
        }
        }"#;
        let deserialized_struct: ComParamSimpleValue =
            serde_json::from_str(json_data_struct).unwrap();
        assert_eq!(deserialized_struct.value, "test");
        let unit = deserialized_struct.unit.unwrap();
        assert_eq!(unit.factor_to_si_unit.unwrap(), 1.0);
        assert!(unit.offset_to_si_unit.is_none());

        let json_data_struct = r#"{"value": "test"}"#;
        let deserialized_struct: ComParamSimpleValue =
            serde_json::from_str(json_data_struct).unwrap();
        assert_eq!(deserialized_struct.value, "test");
        assert!(deserialized_struct.unit.is_none());

        let json_data_struct = r#"{"unit": {"factor_to_si_unit": 1.0}}"#;
        assert!(serde_json::from_str::<ComParamSimpleValue>(json_data_struct).is_err());
    }
}
