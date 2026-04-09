/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

use aide::{UseApi, transform::TransformOperation};
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use axum_extra::extract::WithRejection;
use cda_interfaces::{
    SchemaProvider, UdsEcu, diagservices::DiagServiceResponse, file_manager::FileManager,
};
use cda_plugin_security::Secured;
use sovd_interfaces::components::ecu::operations::OperationCollectionItem;

use crate::sovd::{
    WebserverEcuState, create_schema,
    error::{ApiError, ErrorWrapper},
};

pub(crate) async fn get<
    R: DiagServiceResponse,
    T: UdsEcu + SchemaProvider + Clone,
    U: FileManager,
>(
    UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
    WithRejection(Query(query), _): WithRejection<
        Query<sovd_interfaces::IncludeSchemaQuery>,
        ApiError,
    >,
    State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
) -> Response {
    use cda_interfaces::DynamicPlugin;
    let security_plugin: DynamicPlugin = security_plugin;
    match uds
        .get_components_operations_info(&ecu_name, &security_plugin)
        .await
    {
        Ok(items) => {
            let schema = if query.include_schema {
                Some(create_schema!(
                    sovd_interfaces::Items<OperationCollectionItem>
                ))
            } else {
                None
            };
            (
                StatusCode::OK,
                Json(sovd_interfaces::Items {
                    items: items
                        .into_iter()
                        .map(|info| OperationCollectionItem {
                            id: info.id,
                            name: info.name,
                            proximity_proof_required: false,
                            asynchronous_execution: info.has_stop || info.has_request_results,
                        })
                        .collect(),
                    schema,
                }),
            )
                .into_response()
        }
        Err(e) => ErrorWrapper {
            error: e.into(),
            include_schema: query.include_schema,
        }
        .into_response(),
    }
}

pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
    op.description("Get all available operations for this ECU component")
        .response_with::<200, Json<sovd_interfaces::Items<OperationCollectionItem>>, _>(|res| {
            res.description("List of operations available on this ECU.")
        })
}

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
            HashMap, HashMapExtensions, UdsEcu, diagservices::DiagServiceResponse,
            file_manager::FileManager,
        };
        use indexmap::IndexMap;
        use sovd_interfaces::components::ecu::operations::comparams as sovd_comparams;
        use tokio::sync::RwLock;
        use uuid::Uuid;

        use crate::sovd::{
            IntoSovd, WebserverEcuState, create_schema,
            error::{ApiError, ErrorWrapper},
        };

        fn parse_exec_uuid(id: &str, include_schema: bool) -> Result<Uuid, ErrorWrapper> {
            Uuid::parse_str(id).map_err(|e| ErrorWrapper {
                error: ApiError::BadRequest(format!("{e:?}")),
                include_schema,
            })
        }

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
                let id = match parse_exec_uuid(&id, include_schema) {
                    Ok(v) => v,
                    Err(e) => return e.into_response(),
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
                            error: e.into(),
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
                let id = match parse_exec_uuid(&id, false) {
                    Ok(v) => v,
                    Err(e) => return e.into_response(),
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
                let id = match parse_exec_uuid(&id, include_schema) {
                    Ok(v) => v,
                    Err(e) => return e.into_response(),
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
        use aide::{UseApi, transform::TransformOperation};
        use axum::{
            Json,
            body::Bytes,
            extract::{OriginalUri, Path, Query, State},
            http::{HeaderMap, StatusCode, header},
            response::{IntoResponse as _, Response},
        };
        use axum_extra::extract::{Host, WithRejection};
        use cda_interfaces::{
            DiagComm, DiagCommType, DynamicPlugin, SchemaProvider, UdsEcu,
            diagservices::{DiagServiceJsonResponse, DiagServiceResponse, DiagServiceResponseType},
            file_manager::FileManager,
            subfunction_ids,
        };
        use cda_plugin_security::{Secured, SecurityPlugin};
        use sovd_interfaces::components::ecu::operations::{
            AsyncGetByIdResponse, AsyncPostResponse, ExecutionStatus, OperationDeleteQuery,
            OperationQuery, service::executions as sovd_executions,
        };
        use uuid::Uuid;

        use crate::{
            openapi,
            sovd::{
                self, ServiceExecution, WebserverEcuState, api_error_from_diag_response,
                components::{field_parse_errors_to_json, get_content_type_and_accept},
                create_response_schema, create_schema,
                error::{ApiError, ErrorWrapper, VendorErrorCode},
                locks::validate_lock,
            },
        };

        openapi::aide_helper::gen_path_param!(OperationServicePathParam service String);

        /// Options forwarded from the HTTP layer into `ecu_operation_write_handler`.
        pub(crate) struct WriteHandlerOptions {
            pub include_schema: bool,
            pub suppress_service: bool,
            pub base_path: String,
        }

        /// Request data forwarded from the HTTP layer into `ecu_operation_write_handler`.
        pub(crate) struct WriteHandlerRequest {
            pub service: String,
            pub headers: HeaderMap,
            pub body: Bytes,
        }

        pub(crate) async fn get<
            R: DiagServiceResponse,
            T: UdsEcu + SchemaProvider + Clone,
            U: FileManager,
        >(
            UseApi(Secured(_security_plugin), _): UseApi<Secured, ()>,
            WithRejection(Query(query), _): WithRejection<Query<sovd_executions::Query>, ApiError>,
            State(WebserverEcuState {
                service_executions, ..
            }): State<WebserverEcuState<R, T, U>>,
        ) -> Response {
            let schema = if query.include_schema {
                Some(create_schema!(sovd_interfaces::Items<String>))
            } else {
                None
            };
            let ids: Vec<String> = service_executions
                .read()
                .await
                .keys()
                .map(ToString::to_string)
                .collect();
            (
                StatusCode::OK,
                Json(sovd_interfaces::Items { items: ids, schema }),
            )
                .into_response()
        }

        pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
            op.description("List all active service operation executions")
                .response_with::<200, Json<sovd_interfaces::Items<String>>, _>(|res| {
                    res.description("List of active execution ids.")
                })
        }

        // cannot simply combine the axum extractors without creating a new custom extractor.
        #[allow(clippy::too_many_arguments)]
        pub(crate) async fn post<
            R: DiagServiceResponse,
            T: UdsEcu + SchemaProvider + Clone,
            U: FileManager,
        >(
            UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
            Path(OperationServicePathParam { service }): Path<OperationServicePathParam>,
            WithRejection(Query(query), _): WithRejection<Query<OperationQuery>, ApiError>,
            State(WebserverEcuState {
                ecu_name,
                uds,
                locks,
                service_executions,
                ..
            }): State<WebserverEcuState<R, T, U>>,
            UseApi(Host(host), _): UseApi<Host, String>,
            OriginalUri(uri): OriginalUri,
            headers: HeaderMap,
            body: Bytes,
        ) -> Response {
            let claims = security_plugin.as_auth_plugin().claims();
            if let Some(response) =
                validate_lock(&claims, &ecu_name, &locks, query.include_schema).await
            {
                return response;
            }
            ecu_operation_write_handler::<T>(
                WriteHandlerRequest {
                    service,
                    headers,
                    body,
                },
                &ecu_name,
                &uds,
                service_executions,
                security_plugin,
                WriteHandlerOptions {
                    include_schema: query.include_schema,
                    suppress_service: query.suppress_service,
                    base_path: format!("http://{host}{uri}"),
                },
            )
            .await
        }

        pub(crate) fn docs_post(op: TransformOperation) -> TransformOperation {
            openapi::request_json_and_octet::<sovd_executions::Request>(op)
                .description("Start a new operation execution (Start subfunction)")
                .response_with::<200, Json<sovd_executions::Response<VendorErrorCode>>, _>(|res| {
                    let mut res = res
                        .description("Execution started, synchronous result.")
                        .example(sovd_executions::Response {
                            parameters: Some(serde_json::Map::from_iter([(
                                "example_param".to_string(),
                                serde_json::Value::String("example_value".to_string()),
                            )])),
                            error: None,
                            schema: None,
                        });
                    res.inner().content.insert(
                        "application/octet-stream".to_owned(),
                        aide::openapi::MediaType {
                            example: Some(serde_json::json!([0xABu8, 0xCD, 0xEF, 0x00])),
                            ..Default::default()
                        },
                    );
                    res
                })
                .response_with::<202, Json<AsyncPostResponse>, _>(|res| {
                    res.description(
                        "Execution started asynchronously. Use the returned id for GET/DELETE on \
                         /executions/{id}.",
                    )
                })
                .with(openapi::error_bad_request)
                .with(openapi::error_not_found)
                .with(openapi::error_forbidden)
                .with(openapi::error_internal_server)
                .with(openapi::error_bad_gateway)
        }

        pub(crate) async fn ecu_operation_write_handler<T: UdsEcu + SchemaProvider + Clone>(
            req: WriteHandlerRequest,
            ecu_name: &str,
            uds: &T,
            service_executions: std::sync::Arc<
                tokio::sync::RwLock<indexmap::IndexMap<Uuid, ServiceExecution>>,
            >,
            security_plugin: Box<dyn SecurityPlugin>,
            opts: WriteHandlerOptions,
        ) -> Response {
            let WriteHandlerRequest {
                service,
                headers,
                body,
            } = req;
            let WriteHandlerOptions {
                include_schema,
                suppress_service,
                base_path,
            } = opts;
            if service == "reset" {
                return ecu_reset_handler::<T>(
                    service,
                    ecu_name,
                    uds,
                    body,
                    security_plugin,
                    include_schema,
                )
                .await;
            }

            let security_plugin: DynamicPlugin = security_plugin;
            let is_async = if suppress_service {
                // suppress service is always treated as async
                true
            } else {
                // Determine whether this routine has async sub-functions
                let subfunctions = match uds
                    .get_routine_subfunctions(ecu_name, &service, &security_plugin)
                    .await
                {
                    Ok(sf) => sf,
                    Err(e) => {
                        return ErrorWrapper {
                            error: e.into(),
                            include_schema,
                        }
                        .into_response();
                    }
                };
                subfunctions.has_stop || subfunctions.has_request_results
            };

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
                type_: DiagCommType::Operations,
                lookup_name: None,
                subfunction_id: Some(subfunction_ids::routine::START),
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

            if accept != mime::APPLICATION_OCTET_STREAM && accept != mime::APPLICATION_JSON {
                return ErrorWrapper {
                    error: ApiError::BadRequest(format!("Unsupported Accept header: {accept:?}")),
                    include_schema,
                }
                .into_response();
            }

            let map_to_json = accept == mime::APPLICATION_JSON;
            let response = if suppress_service {
                None
            } else {
                match send_start_request(
                    uds,
                    ecu_name,
                    diag_service.clone(),
                    &security_plugin,
                    data,
                    map_to_json,
                    include_schema,
                )
                .await
                {
                    Ok(r) => r,
                    Err(e) => return e,
                }
            };

            if is_async {
                handle_async_post::<T>(
                    response,
                    map_to_json,
                    include_schema,
                    base_path,
                    service_executions,
                )
                .await
            } else {
                handle_sync_post::<T>(
                    response,
                    map_to_json,
                    include_schema,
                    ecu_name,
                    uds,
                    &diag_service,
                )
                .await
            }
        }

        /// Sends the Start subfunction request and returns the positive response, or
        /// `Err(Response)` if the UDS call failed or returned a negative response.
        async fn send_start_request<T: UdsEcu>(
            uds: &T,
            ecu_name: &str,
            diag_service: DiagComm,
            security_plugin: &DynamicPlugin,
            data: Option<cda_interfaces::diagservices::UdsPayloadData>,
            map_to_json: bool,
            include_schema: bool,
        ) -> Result<Option<T::Response>, Response> {
            let response = match uds
                .send(ecu_name, diag_service, security_plugin, data, map_to_json)
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    return Err(ErrorWrapper {
                        error: e.into(),
                        include_schema,
                    }
                    .into_response());
                }
            };
            if let DiagServiceResponseType::Negative = response.response_type() {
                return Err(api_error_from_diag_response(&response, include_schema).into_response());
            }
            Ok(Some(response))
        }

        fn err_invalid_content(
            detail: String,
        ) -> sovd_interfaces::error::DataError<VendorErrorCode> {
            sovd_interfaces::error::DataError {
                path: String::new(),
                error: sovd_interfaces::error::ApiErrorResponse {
                    message: detail,
                    error_code: sovd_interfaces::error::ErrorCode::InvalidResponseContent,
                    vendor_code: Some(VendorErrorCode::ErrorInterpretingMessage),
                    parameters: None,
                    error_source: None,
                    schema: None,
                },
            }
        }

        /// Parses a positive, non-empty UDS response into `(parameters, errors)`.
        ///
        /// - `Object` → parameters map + any field-parse errors
        /// - `Null`   → empty parameters, no errors (ECU signalled no output)
        /// - anything else, or a parse failure → empty parameters, one soft `DataError`
        fn parse_json_response_params<R: DiagServiceResponse>(
            response: R,
            context: &str,
        ) -> (
            serde_json::Map<String, serde_json::Value>,
            Vec<sovd_interfaces::error::DataError<VendorErrorCode>>,
        ) {
            match response.into_json() {
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

        fn parse_exec_uuid(id: &str, include_schema: bool) -> Result<Uuid, ErrorWrapper> {
            Uuid::parse_str(id).map_err(|e| ErrorWrapper {
                error: ApiError::BadRequest(format!("{e:?}")),
                include_schema,
            })
        }

        /// Acquires a write lock on `service_executions`, looks up `exec_id`, marks it
        /// `in_flight = true`, and returns a clone of the execution.  Returns
        /// `Err(Response)` (with the lock released) on not-found or in-flight conflict.
        async fn guard_execution(
            service_executions: &tokio::sync::RwLock<indexmap::IndexMap<Uuid, ServiceExecution>>,
            exec_id: Uuid,
            include_schema: bool,
            conflict_msg: &str,
        ) -> Result<ServiceExecution, Response> {
            let mut guard = service_executions.write().await;
            match guard.get_mut(&exec_id) {
                None => Err(ErrorWrapper {
                    error: ApiError::NotFound(Some(format!(
                        "Execution with id {exec_id} not found"
                    ))),
                    include_schema,
                }
                .into_response()),
                Some(exec) if exec.in_flight => Err(ErrorWrapper {
                    error: ApiError::Conflict(conflict_msg.to_owned()),
                    include_schema,
                }
                .into_response()),
                Some(exec) => {
                    exec.in_flight = true;
                    Ok(exec.clone())
                }
            }
        }

        /// Builds the `200 OK` `AsyncGetByIdResponse` body used by both the
        /// `RequestResults` success path and the `suppress_service` fallback path.
        /// An empty `parameters` map is serialised as `null` per the SOVD spec.
        fn get_by_id_response(
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
                Some(parameters)
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

        /// Handles the async (Stop/RequestResults) POST path: registers the execution,
        /// returns 202 Accepted with only `id` and `status` per spec Table 184.
        /// The Start response parameters are stored internally for later GET retrieval.
        async fn handle_async_post<T: UdsEcu>(
            response: Option<T::Response>,
            map_to_json: bool,
            _include_schema: bool,
            base_path: String,
            service_executions: std::sync::Arc<
                tokio::sync::RwLock<indexmap::IndexMap<Uuid, ServiceExecution>>,
            >,
        ) -> Response {
            let parameters = match response {
                Some(r) if map_to_json && !r.is_empty() => match r.into_json() {
                    Ok(DiagServiceJsonResponse {
                        data: serde_json::Value::Object(m),
                        ..
                    }) => m,
                    _ => serde_json::Map::new(),
                },
                _ => serde_json::Map::new(),
            };
            let id = Uuid::new_v4();
            service_executions.write().await.insert(
                id,
                ServiceExecution {
                    parameters,
                    status: ExecutionStatus::Running,
                    in_flight: false,
                },
            );
            (
                StatusCode::ACCEPTED,
                [(header::LOCATION, format!("{base_path}/{id}"))],
                Json(AsyncPostResponse {
                    id: id.to_string(),
                    status: Some(ExecutionStatus::Running),
                }),
            )
                .into_response()
        }

        /// Handles the synchronous (no Stop/RequestResults) POST path: returns 200 OK
        /// with the mapped response parameters, or raw bytes if the accept header
        /// requested octet-stream.
        async fn handle_sync_post<T: UdsEcu + SchemaProvider>(
            response: Option<T::Response>,
            map_to_json: bool,
            include_schema: bool,
            ecu_name: &str,
            uds: &T,
            diag_service: &DiagComm,
        ) -> Response {
            let schema = if map_to_json && include_schema {
                let subschema = get_subschema(ecu_name, uds, diag_service).await;
                Some(create_response_schema!(
                    sovd_executions::Response<VendorErrorCode>,
                    "parameters",
                    subschema
                ))
            } else {
                None
            };

            if map_to_json {
                let (mapped_data, parse_errors) =
                    match response.and_then(|r| (!r.is_empty()).then(|| r.into_json())) {
                        None => (serde_json::Map::new(), vec![]),
                        Some(Ok(DiagServiceJsonResponse {
                            data: serde_json::Value::Object(mapped_data),
                            errors,
                        })) => (mapped_data, errors),
                        Some(Ok(v)) => {
                            return ErrorWrapper {
                                error: ApiError::InternalServerError(Some(format!(
                                    "Expected JSON object but got: {}",
                                    v.data
                                ))),
                                include_schema,
                            }
                            .into_response();
                        }
                        Some(Err(e)) => {
                            return ErrorWrapper {
                                error: ApiError::InternalServerError(Some(format!("{e:?}"))),
                                include_schema,
                            }
                            .into_response();
                        }
                    };
                // Spec Table 183: `error` is singular (first parse error wins).
                let error = field_parse_errors_to_json(parse_errors, "parameters")
                    .into_iter()
                    .next();
                let parameters = if mapped_data.is_empty() {
                    None
                } else {
                    Some(mapped_data)
                };
                (
                    StatusCode::OK,
                    Json(sovd_executions::Response {
                        parameters,
                        error,
                        schema,
                    }),
                )
                    .into_response()
            } else {
                let data = response.map_or(vec![], |r| r.get_raw().to_vec());
                (StatusCode::OK, Bytes::from_owner(data)).into_response()
            }
        }

        // allowed for now, the current implementation does not contain a lot of
        // potential to extract smaller functions
        #[allow(clippy::too_many_lines)]
        async fn ecu_reset_handler<T: UdsEcu + SchemaProvider + Clone>(
            service: String,
            ecu_name: &str,
            uds: &T,
            body: Bytes,
            security_plugin: Box<dyn SecurityPlugin>,
            include_schema: bool,
        ) -> Response {
            // todo: in the future we have to handle possible parameters for the reset service
            let Some(request_parameters) =
                serde_json::from_slice::<sovd_executions::Request>(&body)
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
                type_: DiagCommType::Modes, // ecureset is in modes
                lookup_name: Some(value_str.to_owned()),
                subfunction_id: None,
            };

            let schema = if include_schema {
                let subschema = get_subschema(ecu_name, uds, &diag_service).await;
                Some(create_response_schema!(
                    sovd_executions::Response<VendorErrorCode>,
                    "parameters",
                    subschema
                ))
            } else {
                None
            };

            let response = match uds
                .send(
                    ecu_name,
                    diag_service,
                    &(security_plugin as DynamicPlugin),
                    None,
                    true,
                )
                .await
            {
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
                        let (response_data, parse_errors) = match response.into_json() {
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
                        let error = field_parse_errors_to_json(parse_errors, "parameters")
                            .into_iter()
                            .next();
                        let parameters = if response_data.is_empty() {
                            None
                        } else {
                            Some(response_data)
                        };
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

        async fn get_subschema<T: SchemaProvider>(
            ecu_name: &str,
            uds: &T,
            diag_service: &DiagComm,
        ) -> Option<schemars::Schema> {
            match uds
                .schema_for_responses(ecu_name, diag_service)
                .await
                .map(cda_interfaces::SchemaDescription::into_schema)
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

        pub(crate) mod id {
            use super::*;

            #[derive(serde::Deserialize, schemars::JsonSchema)]
            pub(crate) struct ServiceAndIdPathParam {
                pub service: String,
                pub id: String,
            }

            /// Process a successful UDS `RequestResults` response: parse it, update stored
            /// execution state, and return the `200 OK` response body.
            async fn get_operations_response<T: UdsEcu>(
                response: T::Response,
                exec_id: Uuid,
                service_executions: &tokio::sync::RwLock<
                    indexmap::IndexMap<Uuid, ServiceExecution>,
                >,
                include_schema: bool,
            ) -> Response {
                if let DiagServiceResponseType::Negative = response.response_type() {
                    tracing::warn!(
                        exec_id = %exec_id,
                        "RequestResults subfunction returned negative response"
                    );
                    return api_error_from_diag_response(&response, include_schema).into_response();
                }

                let (parameters, error_list) = if response.is_empty() {
                    (serde_json::Map::new(), vec![])
                } else {
                    parse_json_response_params::<T::Response>(response, "RequestResults")
                };

                if let Some(stored_mut) = service_executions.write().await.get_mut(&exec_id) {
                    stored_mut.parameters.clone_from(&parameters);
                }

                get_by_id_response(
                    ExecutionStatus::Completed,
                    parameters,
                    error_list,
                    include_schema,
                )
            }

            pub(crate) async fn get<
                R: DiagServiceResponse,
                T: UdsEcu + SchemaProvider + Clone,
                U: FileManager,
            >(
                UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
                Path(ServiceAndIdPathParam { service, id }): Path<ServiceAndIdPathParam>,
                WithRejection(Query(query), _): WithRejection<Query<OperationQuery>, ApiError>,
                State(WebserverEcuState {
                    ecu_name,
                    uds,
                    service_executions,
                    ..
                }): State<WebserverEcuState<R, T, U>>,
            ) -> Response {
                let include_schema = query.include_schema;
                let exec_id = match parse_exec_uuid(&id, include_schema) {
                    Ok(v) => v,
                    Err(e) => return e.into_response(),
                };

                let stored = match guard_execution(
                    &service_executions,
                    exec_id,
                    include_schema,
                    &format!("Execution {exec_id} is already in progress"),
                )
                .await
                {
                    Ok(v) => v,
                    Err(e) => return e,
                };

                // suppress_service: skip the UDS send, return stored state directly
                if query.suppress_service {
                    if let Some(exec) = service_executions.write().await.get_mut(&exec_id) {
                        exec.in_flight = false;
                    }
                    return get_by_id_response(
                        stored.status,
                        stored.parameters,
                        vec![],
                        include_schema,
                    );
                }

                // Try to send RequestResults (subfunction 0x03)
                let diag_service = DiagComm {
                    name: service.clone(),
                    type_: DiagCommType::Operations,
                    lookup_name: None,
                    subfunction_id: Some(subfunction_ids::routine::REQUEST_RESULTS),
                };
                let uds_result = uds
                    .send(
                        &ecu_name,
                        diag_service,
                        &(security_plugin as DynamicPlugin),
                        None,
                        true,
                    )
                    .await;

                if let Some(exec) = service_executions.write().await.get_mut(&exec_id) {
                    exec.in_flight = false;
                }

                match uds_result {
                    Err(e) => {
                        tracing::warn!(
                            error = ?e,
                            service = %service,
                            exec_id = %exec_id,
                            "RequestResults subfunction failed"
                        );
                        ErrorWrapper {
                            error: e.into(),
                            include_schema,
                        }
                        .into_response()
                    }
                    Ok(response) => {
                        get_operations_response::<T>(
                            response,
                            exec_id,
                            &service_executions,
                            include_schema,
                        )
                        .await
                    }
                }
            }

            pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
                op.description(
                    "Get the result of an async operation execution (RequestResults subfunction)",
                )
                .response_with::<200, Json<AsyncGetByIdResponse<VendorErrorCode>>, _>(|res| {
                    res.description("Execution result retrieved successfully.")
                })
                .with(openapi::error_not_found)
                .with(openapi::error_bad_request)
                .with(openapi::error_bad_gateway)
            }

            pub(crate) async fn delete<
                R: DiagServiceResponse,
                T: UdsEcu + SchemaProvider + Clone,
                U: FileManager,
            >(
                UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
                Path(ServiceAndIdPathParam { service, id }): Path<ServiceAndIdPathParam>,
                WithRejection(Query(query), _): WithRejection<
                    Query<OperationDeleteQuery>,
                    ApiError,
                >,
                State(WebserverEcuState {
                    ecu_name,
                    uds,
                    locks,
                    service_executions,
                    ..
                }): State<WebserverEcuState<R, T, U>>,
            ) -> Response {
                let include_schema = query.include_schema;
                let claims = security_plugin.as_auth_plugin().claims();
                if let Some(response) =
                    validate_lock(&claims, &ecu_name, &locks, include_schema).await
                {
                    return response;
                }
                let exec_id = match parse_exec_uuid(&id, include_schema) {
                    Ok(v) => v,
                    Err(e) => return e.into_response(),
                };

                if let Err(e) = guard_execution(
                    &service_executions,
                    exec_id,
                    include_schema,
                    &format!("Execution {exec_id} is already being stopped"),
                )
                .await
                {
                    return e;
                }

                let diag_service = DiagComm {
                    name: service.clone(),
                    type_: DiagCommType::Operations,
                    lookup_name: None,
                    subfunction_id: Some(subfunction_ids::routine::STOP),
                };
                let uds_result = uds
                    .send(
                        &ecu_name,
                        diag_service,
                        &(security_plugin as DynamicPlugin),
                        None,
                        true,
                    )
                    .await;

                if let Some(exec) = service_executions.write().await.get_mut(&exec_id) {
                    exec.in_flight = false;
                }

                match uds_result {
                    Ok(r) if matches!(r.response_type(), DiagServiceResponseType::Positive) => {
                        service_executions.write().await.shift_remove(&exec_id);
                        if r.is_empty() {
                            StatusCode::NO_CONTENT.into_response()
                        } else {
                            let (parameters, error_list) =
                                parse_json_response_params::<T::Response>(r, "Stop");
                            get_by_id_response(
                                ExecutionStatus::Stopped,
                                parameters,
                                error_list,
                                include_schema,
                            )
                        }
                    }
                    Err(cda_interfaces::DiagServiceError::NotFound(_))
                        if query.suppress_service =>
                    {
                        tracing::warn!(
                            service = %service,
                            exec_id = %exec_id,
                            "Stop service not found (suppress_service=true), removing execution"
                        );
                        service_executions.write().await.shift_remove(&exec_id);
                        StatusCode::NO_CONTENT.into_response()
                    }
                    result => {
                        if let Err(e) = &result {
                            tracing::warn!(
                                error = ?e,
                                service = %service,
                                exec_id = %exec_id,
                                "Stop subfunction failed"
                            );
                        } else {
                            tracing::warn!(
                                service = %service,
                                exec_id = %exec_id,
                                "Stop subfunction returned negative response"
                            );
                        }
                        if query.force {
                            service_executions.write().await.shift_remove(&exec_id);
                            return StatusCode::NO_CONTENT.into_response();
                        }
                        match result {
                            Err(e) => ErrorWrapper {
                                error: e.into(),
                                include_schema,
                            }
                            .into_response(),
                            Ok(r) => {
                                api_error_from_diag_response(&r, include_schema).into_response()
                            }
                        }
                    }
                }
            }

            pub(crate) fn docs_delete(op: TransformOperation) -> TransformOperation {
                op.description(
                    "Stop an async operation execution (Stop subfunction). Use \
                     ?x-sovd2uds-force=true to remove even on ECU error.",
                )
                .response_with::<204, (), _>(|res| {
                    res.description("Execution stopped and removed (no response data from ECU).")
                })
                .response_with::<200, Json<AsyncGetByIdResponse<VendorErrorCode>>, _>(|res| {
                    res.description(
                        "Execution stopped and removed. The ECU returned response data (non-spec \
                         extension).",
                    )
                })
                .with(openapi::error_not_found)
                .with(openapi::error_bad_request)
                .with(openapi::error_bad_gateway)
                .with(openapi::error_forbidden)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use sovd_interfaces::components::ecu::operations::comparams::ComParamSimpleValue;

    #[test]
    // allowing float comparison because we actually want to test exact values here
    #[allow(clippy::float_cmp)]
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

    mod ecu_operations_collection {
        use aide::UseApi;
        use axum::{extract::State, http::StatusCode};
        use axum_extra::extract::WithRejection;
        use cda_interfaces::{
            datatypes::ComponentOperationsInfo, diagservices::mock::MockDiagServiceResponse,
            file_manager::mock::MockFileManager, mock::MockUdsEcu,
        };
        use cda_plugin_security::{Secured, mock::TestSecurityPlugin};
        use sovd_interfaces::components::ecu::operations::OperationCollectionItem;

        use super::super::*;
        use crate::sovd::tests::create_test_webserver_state;

        #[tokio::test]
        async fn test_get_operations_returns_empty_list() {
            let ecu_name = "TestECU".to_string();
            let mut mock_uds = MockUdsEcu::new();
            let mock_file_manager = MockFileManager::new();

            mock_uds
                .expect_get_components_operations_info()
                .withf(|ecu, _| ecu == "TestECU")
                .times(1)
                .returning(|_, _| Ok(vec![]));

            let state = create_test_webserver_state::<
                MockDiagServiceResponse,
                MockUdsEcu,
                MockFileManager,
            >(ecu_name, mock_uds, mock_file_manager);

            let response = get::<MockDiagServiceResponse, MockUdsEcu, MockFileManager>(
                UseApi(
                    Secured(Box::new(TestSecurityPlugin)),
                    std::marker::PhantomData,
                ),
                WithRejection(
                    axum::extract::Query(sovd_interfaces::IncludeSchemaQuery {
                        include_schema: false,
                    }),
                    std::marker::PhantomData,
                ),
                State(state),
            )
            .await;

            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let result: sovd_interfaces::Items<OperationCollectionItem> =
                serde_json::from_slice(&body).unwrap();
            assert!(result.items.is_empty());
            assert!(result.schema.is_none());
        }

        #[tokio::test]
        async fn test_get_operations_returns_items() {
            let ecu_name = "TestECU".to_string();
            let mut mock_uds = MockUdsEcu::new();
            let mock_file_manager = MockFileManager::new();

            mock_uds
                .expect_get_components_operations_info()
                .withf(|ecu, _| ecu == "TestECU")
                .times(1)
                .returning(|_, _| {
                    Ok(vec![
                        ComponentOperationsInfo {
                            id: "CalibrateSensor".to_string(),
                            name: "Calibrate Sensor".to_string(),
                            has_stop: true,
                            has_request_results: true,
                        },
                        ComponentOperationsInfo {
                            id: "RunSelfTest".to_string(),
                            name: "Run Self Test".to_string(),
                            has_stop: false,
                            has_request_results: false,
                        },
                    ])
                });

            let state = create_test_webserver_state::<
                MockDiagServiceResponse,
                MockUdsEcu,
                MockFileManager,
            >(ecu_name, mock_uds, mock_file_manager);

            let response = get::<MockDiagServiceResponse, MockUdsEcu, MockFileManager>(
                UseApi(
                    Secured(Box::new(TestSecurityPlugin)),
                    std::marker::PhantomData,
                ),
                WithRejection(
                    axum::extract::Query(sovd_interfaces::IncludeSchemaQuery {
                        include_schema: false,
                    }),
                    std::marker::PhantomData,
                ),
                State(state),
            )
            .await;

            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let result: sovd_interfaces::Items<OperationCollectionItem> =
                serde_json::from_slice(&body).unwrap();
            assert_eq!(result.items.len(), 2);

            let first = result.items.first().expect("Expected at least one item");
            assert_eq!(first.id, "CalibrateSensor");
            assert_eq!(first.name, "Calibrate Sensor");
            assert!(!first.proximity_proof_required);
            assert!(first.asynchronous_execution);

            let second = result.items.get(1).expect("Expected a second item");
            assert_eq!(second.id, "RunSelfTest");
            assert!(!second.proximity_proof_required);
            assert!(!second.asynchronous_execution);
        }

        #[tokio::test]
        async fn test_get_operations_with_schema() {
            let ecu_name = "TestECU".to_string();
            let mut mock_uds = MockUdsEcu::new();
            let mock_file_manager = MockFileManager::new();

            mock_uds
                .expect_get_components_operations_info()
                .times(1)
                .returning(|_, _| Ok(vec![]));

            let state = create_test_webserver_state::<
                MockDiagServiceResponse,
                MockUdsEcu,
                MockFileManager,
            >(ecu_name, mock_uds, mock_file_manager);

            let response = get::<MockDiagServiceResponse, MockUdsEcu, MockFileManager>(
                UseApi(
                    Secured(Box::new(TestSecurityPlugin)),
                    std::marker::PhantomData,
                ),
                WithRejection(
                    axum::extract::Query(sovd_interfaces::IncludeSchemaQuery {
                        include_schema: true,
                    }),
                    std::marker::PhantomData,
                ),
                State(state),
            )
            .await;

            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let result: sovd_interfaces::Items<OperationCollectionItem> =
                serde_json::from_slice(&body).unwrap();
            assert!(
                result.schema.is_some(),
                "Schema should be included when requested"
            );
        }
    }

    mod service_executions {
        use std::sync::Arc;

        use aide::UseApi;
        use axum::{
            extract::{Path, Query, State},
            http::StatusCode,
        };
        use axum_extra::extract::WithRejection;
        use cda_interfaces::{
            DiagCommType, DiagServiceError,
            diagservices::{
                DiagServiceJsonResponse, DiagServiceResponseType, mock::MockDiagServiceResponse,
            },
            file_manager::mock::MockFileManager,
            mock::MockUdsEcu,
        };
        use cda_plugin_security::{Secured, mock::TestSecurityPlugin};
        use sovd_interfaces::components::ecu::operations::ExecutionStatus;

        use super::super::service::{executions as handlers, executions::id as id_handlers};
        use crate::sovd::{
            ServiceExecution, locks::insert_test_ecu_lock, tests::create_test_webserver_state,
        };

        fn make_json_response(data: serde_json::Value) -> MockDiagServiceResponse {
            let mut resp = MockDiagServiceResponse::new();
            resp.expect_response_type()
                .returning(|| DiagServiceResponseType::Positive);
            resp.expect_is_empty().returning(|| false);
            resp.expect_into_json().return_once(move || {
                Ok(DiagServiceJsonResponse {
                    data,
                    errors: vec![],
                })
            });
            resp
        }

        fn make_empty_positive_response() -> MockDiagServiceResponse {
            let mut resp = MockDiagServiceResponse::new();
            resp.expect_response_type()
                .returning(|| DiagServiceResponseType::Positive);
            resp.expect_is_empty().returning(|| true);
            resp
        }

        fn make_negative_response() -> MockDiagServiceResponse {
            let mut resp = MockDiagServiceResponse::new();
            resp.expect_response_type()
                .returning(|| DiagServiceResponseType::Negative);
            resp.expect_is_empty().returning(|| false);
            resp.expect_as_nrc().returning(|| {
                Ok(cda_interfaces::diagservices::MappedNRC {
                    code: Some(0x22),
                    description: Some("conditionsNotCorrect".to_string()),
                    sid: None,
                })
            });
            resp
        }

        #[tokio::test]
        async fn test_list_executions_empty() {
            let ecu_name = "TestECU".to_string();
            let mock_uds = MockUdsEcu::new();
            let mock_file_manager = MockFileManager::new();
            let state = create_test_webserver_state::<
                MockDiagServiceResponse,
                MockUdsEcu,
                MockFileManager,
            >(ecu_name, mock_uds, mock_file_manager);

            let response = handlers::get::<MockDiagServiceResponse, MockUdsEcu, MockFileManager>(
                UseApi(
                    Secured(Box::new(TestSecurityPlugin)),
                    std::marker::PhantomData,
                ),
                WithRejection(
                    Query(
                        sovd_interfaces::components::ecu::operations::service::executions::Query {
                            include_schema: false,
                        },
                    ),
                    std::marker::PhantomData,
                ),
                State(state),
            )
            .await;

            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let result: sovd_interfaces::Items<String> = serde_json::from_slice(&body).unwrap();
            assert!(result.items.is_empty());
        }

        #[tokio::test]
        async fn test_list_executions_shows_tracked_id() {
            let ecu_name = "TestECU".to_string();
            let mock_uds = MockUdsEcu::new();
            let mock_file_manager = MockFileManager::new();
            let state = create_test_webserver_state::<
                MockDiagServiceResponse,
                MockUdsEcu,
                MockFileManager,
            >(ecu_name, mock_uds, mock_file_manager);

            // Pre-populate an execution
            let exec_id = uuid::Uuid::new_v4();
            state.service_executions.write().await.insert(
                exec_id,
                ServiceExecution {
                    parameters: serde_json::Map::new(),
                    status: ExecutionStatus::Running,
                    in_flight: false,
                },
            );

            let response = handlers::get::<MockDiagServiceResponse, MockUdsEcu, MockFileManager>(
                UseApi(
                    Secured(Box::new(TestSecurityPlugin)),
                    std::marker::PhantomData,
                ),
                WithRejection(
                    Query(
                        sovd_interfaces::components::ecu::operations::service::executions::Query {
                            include_schema: false,
                        },
                    ),
                    std::marker::PhantomData,
                ),
                State(state),
            )
            .await;

            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let result: sovd_interfaces::Items<String> = serde_json::from_slice(&body).unwrap();
            assert_eq!(result.items.len(), 1);
            assert_eq!(
                result.items.first().expect("Expected at least one item"),
                &exec_id.to_string()
            );
        }

        // ── GET /operations/{service}/executions/{id} – RequestResults ────────

        #[tokio::test]
        async fn test_get_execution_by_id_not_found() {
            let ecu_name = "TestECU".to_string();
            let mock_uds = MockUdsEcu::new();
            let mock_file_manager = MockFileManager::new();
            let state = create_test_webserver_state::<
                MockDiagServiceResponse,
                MockUdsEcu,
                MockFileManager,
            >(ecu_name, mock_uds, mock_file_manager);

            let unknown_id = uuid::Uuid::new_v4().to_string();
            let response =
                id_handlers::get::<MockDiagServiceResponse, MockUdsEcu, MockFileManager>(
                    UseApi(
                        Secured(Box::new(TestSecurityPlugin)),
                        std::marker::PhantomData,
                    ),
                    Path(id_handlers::ServiceAndIdPathParam {
                        service: "CalibrateSensor".to_string(),
                        id: unknown_id,
                    }),
                    WithRejection(
                        Query(
                            sovd_interfaces::components::ecu::operations::OperationQuery {
                                include_schema: false,
                                suppress_service: false,
                            },
                        ),
                        std::marker::PhantomData,
                    ),
                    State(state),
                )
                .await;

            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn test_get_execution_by_id_calls_request_results() {
            let ecu_name = "TestECU".to_string();
            let mut mock_uds = MockUdsEcu::new();
            let mock_file_manager = MockFileManager::new();

            // Expect send with subfunction_id = REQUEST_RESULTS (0x03)
            mock_uds
                .expect_send()
                .withf(|ecu, service, _, payload, map_to_json| {
                    ecu == "TestECU"
                        && service.type_ == DiagCommType::Operations
                        && service.subfunction_id
                            == Some(cda_interfaces::subfunction_ids::routine::REQUEST_RESULTS)
                        && service.lookup_name.is_none()
                        && payload.is_none()
                        && *map_to_json
                })
                .times(1)
                .returning(|_, _, _, _, _| {
                    Ok(make_json_response(serde_json::json!({
                        "result": "ok"
                    })))
                });

            let state = create_test_webserver_state::<
                MockDiagServiceResponse,
                MockUdsEcu,
                MockFileManager,
            >(ecu_name, mock_uds, mock_file_manager);

            let exec_id = uuid::Uuid::new_v4();
            state.service_executions.write().await.insert(
                exec_id,
                ServiceExecution {
                    parameters: serde_json::Map::new(),
                    status: ExecutionStatus::Running,
                    in_flight: false,
                },
            );

            let response =
                id_handlers::get::<MockDiagServiceResponse, MockUdsEcu, MockFileManager>(
                    UseApi(
                        Secured(Box::new(TestSecurityPlugin)),
                        std::marker::PhantomData,
                    ),
                    Path(id_handlers::ServiceAndIdPathParam {
                        service: "CalibrateSensor".to_string(),
                        id: exec_id.to_string(),
                    }),
                    WithRejection(
                        Query(
                            sovd_interfaces::components::ecu::operations::OperationQuery {
                                include_schema: false,
                                suppress_service: false,
                            },
                        ),
                        std::marker::PhantomData,
                    ),
                    State(state),
                )
                .await;

            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(
                result.get("status").expect("missing status"),
                &serde_json::json!("completed")
            );
            assert_eq!(
                result.get("capability").expect("missing capability"),
                &serde_json::json!("execute")
            );
            assert_eq!(
                result
                    .get("parameters")
                    .expect("missing parameters")
                    .get("result")
                    .expect("missing result"),
                &serde_json::json!("ok")
            );
        }

        #[tokio::test]
        async fn test_get_execution_suppress_service_skips_send_returns_stored() {
            let ecu_name = "TestECU".to_string();
            let mut mock_uds = MockUdsEcu::new();
            let mock_file_manager = MockFileManager::new();

            // suppress_service=true must skip the UDS send entirely
            mock_uds.expect_send().times(0);

            let state = create_test_webserver_state::<
                MockDiagServiceResponse,
                MockUdsEcu,
                MockFileManager,
            >(ecu_name, mock_uds, mock_file_manager);

            let exec_id = uuid::Uuid::new_v4();
            let stored_params = {
                let mut m = serde_json::Map::new();
                m.insert("stored".to_string(), serde_json::json!("value"));
                m
            };
            state.service_executions.write().await.insert(
                exec_id,
                ServiceExecution {
                    parameters: stored_params,
                    status: ExecutionStatus::Running,
                    in_flight: false,
                },
            );

            let response =
                id_handlers::get::<MockDiagServiceResponse, MockUdsEcu, MockFileManager>(
                    UseApi(
                        Secured(Box::new(TestSecurityPlugin)),
                        std::marker::PhantomData,
                    ),
                    Path(id_handlers::ServiceAndIdPathParam {
                        service: "CalibrateSensor".to_string(),
                        id: exec_id.to_string(),
                    }),
                    WithRejection(
                        Query(
                            sovd_interfaces::components::ecu::operations::OperationQuery {
                                include_schema: false,
                                suppress_service: true,
                            },
                        ),
                        std::marker::PhantomData,
                    ),
                    State(state),
                )
                .await;

            // suppress_service=true → should return 200 with stored params, no UDS send
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(
                result.get("status").expect("missing status"),
                &serde_json::json!("running")
            );
            assert_eq!(
                result
                    .get("parameters")
                    .expect("missing parameters")
                    .get("stored")
                    .expect("missing stored"),
                &serde_json::json!("value")
            );
        }

        #[tokio::test]
        async fn test_get_execution_not_found_without_suppress_returns_error() {
            let ecu_name = "TestECU".to_string();
            let mut mock_uds = MockUdsEcu::new();
            let mock_file_manager = MockFileManager::new();

            mock_uds.expect_send().times(1).returning(|_, _, _, _, _| {
                Err(DiagServiceError::NotFound(
                    "CalibrateSensor_RequestResults not found".to_string(),
                ))
            });

            let state = create_test_webserver_state::<
                MockDiagServiceResponse,
                MockUdsEcu,
                MockFileManager,
            >(ecu_name, mock_uds, mock_file_manager);

            let exec_id = uuid::Uuid::new_v4();
            state.service_executions.write().await.insert(
                exec_id,
                ServiceExecution {
                    parameters: serde_json::Map::new(),
                    status: ExecutionStatus::Running,
                    in_flight: false,
                },
            );

            let response =
                id_handlers::get::<MockDiagServiceResponse, MockUdsEcu, MockFileManager>(
                    UseApi(
                        Secured(Box::new(TestSecurityPlugin)),
                        std::marker::PhantomData,
                    ),
                    Path(id_handlers::ServiceAndIdPathParam {
                        service: "CalibrateSensor".to_string(),
                        id: exec_id.to_string(),
                    }),
                    WithRejection(
                        Query(
                            sovd_interfaces::components::ecu::operations::OperationQuery {
                                include_schema: false,
                                suppress_service: false,
                            },
                        ),
                        std::marker::PhantomData,
                    ),
                    State(state),
                )
                .await;

            // suppress_service=false → NotFound from UDS should propagate as error
            assert!(response.status().is_client_error() || response.status().is_server_error());
        }

        // ── DELETE /operations/{service}/executions/{id} – Stop ───────────────

        #[tokio::test]
        async fn test_delete_execution_not_found() {
            let ecu_name = "TestECU".to_string();
            let mock_uds = MockUdsEcu::new();
            let mock_file_manager = MockFileManager::new();
            let state = create_test_webserver_state::<
                MockDiagServiceResponse,
                MockUdsEcu,
                MockFileManager,
            >(ecu_name.clone(), mock_uds, mock_file_manager);
            insert_test_ecu_lock(&state.locks, &ecu_name).await;

            let unknown_id = uuid::Uuid::new_v4().to_string();
            let response =
                id_handlers::delete::<MockDiagServiceResponse, MockUdsEcu, MockFileManager>(
                    UseApi(
                        Secured(Box::new(TestSecurityPlugin)),
                        std::marker::PhantomData,
                    ),
                    Path(id_handlers::ServiceAndIdPathParam {
                        service: "CalibrateSensor".to_string(),
                        id: unknown_id,
                    }),
                    WithRejection(
                        Query(
                            sovd_interfaces::components::ecu::operations::OperationDeleteQuery {
                                include_schema: false,
                                suppress_service: false,
                                force: false,
                            },
                        ),
                        std::marker::PhantomData,
                    ),
                    State(state),
                )
                .await;

            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn test_delete_execution_calls_stop() {
            let ecu_name = "TestECU".to_string();
            let mut mock_uds = MockUdsEcu::new();
            let mock_file_manager = MockFileManager::new();

            // Expect send with subfunction_id = STOP (0x02)
            mock_uds
                .expect_send()
                .withf(|ecu, service, _, _, _| {
                    ecu == "TestECU"
                        && service.type_ == DiagCommType::Operations
                        && service.subfunction_id
                            == Some(cda_interfaces::subfunction_ids::routine::STOP)
                        && service.lookup_name.is_none()
                })
                .times(1)
                .returning(|_, _, _, _, _| Ok(make_empty_positive_response()));

            let state = create_test_webserver_state::<
                MockDiagServiceResponse,
                MockUdsEcu,
                MockFileManager,
            >(ecu_name, mock_uds, mock_file_manager);
            insert_test_ecu_lock(&state.locks, "TestECU").await;

            let exec_id = uuid::Uuid::new_v4();
            state.service_executions.write().await.insert(
                exec_id,
                ServiceExecution {
                    parameters: serde_json::Map::new(),
                    status: ExecutionStatus::Running,
                    in_flight: false,
                },
            );

            // Keep a reference to service_executions so we can verify after consuming state
            let service_executions_ref = Arc::clone(&state.service_executions);

            let response =
                id_handlers::delete::<MockDiagServiceResponse, MockUdsEcu, MockFileManager>(
                    UseApi(
                        Secured(Box::new(TestSecurityPlugin)),
                        std::marker::PhantomData,
                    ),
                    Path(id_handlers::ServiceAndIdPathParam {
                        service: "CalibrateSensor".to_string(),
                        id: exec_id.to_string(),
                    }),
                    WithRejection(
                        Query(
                            sovd_interfaces::components::ecu::operations::OperationDeleteQuery {
                                include_schema: false,
                                suppress_service: false,
                                force: false,
                            },
                        ),
                        std::marker::PhantomData,
                    ),
                    State(state),
                )
                .await;

            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            // Verify execution was removed
            assert!(service_executions_ref.read().await.is_empty());
        }

        #[tokio::test]
        async fn test_delete_execution_stop_with_data_returns_200_stopped() {
            let ecu_name = "TestECU".to_string();
            let mut mock_uds = MockUdsEcu::new();
            let mock_file_manager = MockFileManager::new();

            // ECU returns a non-empty positive response from Stop
            mock_uds
                .expect_send()
                .withf(|ecu, service, _, _, map_to_json| {
                    ecu == "TestECU"
                        && service.subfunction_id
                            == Some(cda_interfaces::subfunction_ids::routine::STOP)
                        && *map_to_json
                })
                .times(1)
                .returning(|_, _, _, _, _| {
                    Ok(make_json_response(serde_json::json!({
                        "stop_result": "ok"
                    })))
                });

            let state = create_test_webserver_state::<
                MockDiagServiceResponse,
                MockUdsEcu,
                MockFileManager,
            >(ecu_name, mock_uds, mock_file_manager);
            insert_test_ecu_lock(&state.locks, "TestECU").await;

            let exec_id = uuid::Uuid::new_v4();
            state.service_executions.write().await.insert(
                exec_id,
                ServiceExecution {
                    parameters: serde_json::Map::new(),
                    status: ExecutionStatus::Running,
                    in_flight: false,
                },
            );

            let service_executions_ref = Arc::clone(&state.service_executions);

            let response =
                id_handlers::delete::<MockDiagServiceResponse, MockUdsEcu, MockFileManager>(
                    UseApi(
                        Secured(Box::new(TestSecurityPlugin)),
                        std::marker::PhantomData,
                    ),
                    Path(id_handlers::ServiceAndIdPathParam {
                        service: "CalibrateSensor".to_string(),
                        id: exec_id.to_string(),
                    }),
                    WithRejection(
                        Query(
                            sovd_interfaces::components::ecu::operations::OperationDeleteQuery {
                                include_schema: false,
                                suppress_service: false,
                                force: false,
                            },
                        ),
                        std::marker::PhantomData,
                    ),
                    State(state),
                )
                .await;

            // ECU returned data → 200 with status=stopped and the parameters
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(
                result.get("status").expect("missing status"),
                &serde_json::json!("stopped")
            );
            assert_eq!(
                result
                    .get("parameters")
                    .expect("missing parameters")
                    .get("stop_result")
                    .expect("missing stop_result"),
                &serde_json::json!("ok")
            );
            // Execution must be removed regardless
            assert!(service_executions_ref.read().await.is_empty());
        }

        #[tokio::test]
        async fn test_delete_execution_stop_with_null_json_returns_200_empty_parameters() {
            // Stop maps to JSON Null → 200 with empty parameters (user-requested extension)
            let ecu_name = "TestECU".to_string();
            let mut mock_uds = MockUdsEcu::new();
            let mock_file_manager = MockFileManager::new();

            mock_uds
                .expect_send()
                .withf(|ecu, service, _, _, map_to_json| {
                    ecu == "TestECU"
                        && service.subfunction_id
                            == Some(cda_interfaces::subfunction_ids::routine::STOP)
                        && *map_to_json
                })
                .times(1)
                .returning(|_, _, _, _, _| Ok(make_json_response(serde_json::Value::Null)));

            let state = create_test_webserver_state::<
                MockDiagServiceResponse,
                MockUdsEcu,
                MockFileManager,
            >(ecu_name, mock_uds, mock_file_manager);
            insert_test_ecu_lock(&state.locks, "TestECU").await;

            let exec_id = uuid::Uuid::new_v4();
            state.service_executions.write().await.insert(
                exec_id,
                ServiceExecution {
                    parameters: serde_json::Map::new(),
                    status: ExecutionStatus::Running,
                    in_flight: false,
                },
            );

            let service_executions_ref = Arc::clone(&state.service_executions);

            let response =
                id_handlers::delete::<MockDiagServiceResponse, MockUdsEcu, MockFileManager>(
                    UseApi(
                        Secured(Box::new(TestSecurityPlugin)),
                        std::marker::PhantomData,
                    ),
                    Path(id_handlers::ServiceAndIdPathParam {
                        service: "CalibrateSensor".to_string(),
                        id: exec_id.to_string(),
                    }),
                    WithRejection(
                        Query(
                            sovd_interfaces::components::ecu::operations::OperationDeleteQuery {
                                include_schema: false,
                                suppress_service: false,
                                force: false,
                            },
                        ),
                        std::marker::PhantomData,
                    ),
                    State(state),
                )
                .await;

            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(
                result.get("status").expect("missing status"),
                &serde_json::json!("stopped")
            );
            // parameters: None when empty → field is omitted from JSON
            assert!(
                result.get("parameters").is_none(),
                "parameters should be absent when Stop returns Null"
            );
            assert!(service_executions_ref.read().await.is_empty());
        }

        #[tokio::test]
        async fn test_delete_execution_stop_non_object_json_returns_200_stopped_with_error() {
            // Stop maps to a non-object JSON value (e.g. a string) → 200 stopped, error surfaced
            let ecu_name = "TestECU".to_string();
            let mut mock_uds = MockUdsEcu::new();
            let mock_file_manager = MockFileManager::new();

            mock_uds
                .expect_send()
                .withf(|ecu, service, _, _, map_to_json| {
                    ecu == "TestECU"
                        && service.subfunction_id
                            == Some(cda_interfaces::subfunction_ids::routine::STOP)
                        && *map_to_json
                })
                .times(1)
                .returning(|_, _, _, _, _| {
                    Ok(make_json_response(serde_json::json!("unexpected_string")))
                });

            let state = create_test_webserver_state::<
                MockDiagServiceResponse,
                MockUdsEcu,
                MockFileManager,
            >(ecu_name, mock_uds, mock_file_manager);
            insert_test_ecu_lock(&state.locks, "TestECU").await;

            let exec_id = uuid::Uuid::new_v4();
            state.service_executions.write().await.insert(
                exec_id,
                ServiceExecution {
                    parameters: serde_json::Map::new(),
                    status: ExecutionStatus::Running,
                    in_flight: false,
                },
            );

            let service_executions_ref = Arc::clone(&state.service_executions);

            let response =
                id_handlers::delete::<MockDiagServiceResponse, MockUdsEcu, MockFileManager>(
                    UseApi(
                        Secured(Box::new(TestSecurityPlugin)),
                        std::marker::PhantomData,
                    ),
                    Path(id_handlers::ServiceAndIdPathParam {
                        service: "CalibrateSensor".to_string(),
                        id: exec_id.to_string(),
                    }),
                    WithRejection(
                        Query(
                            sovd_interfaces::components::ecu::operations::OperationDeleteQuery {
                                include_schema: false,
                                suppress_service: false,
                                force: false,
                            },
                        ),
                        std::marker::PhantomData,
                    ),
                    State(state),
                )
                .await;

            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(
                result.get("status").expect("missing status"),
                &serde_json::json!("stopped")
            );
            // error list (field name "error" per AsyncGetByIdResponse) must be non-empty
            let errors = result.get("error").expect("missing error field");
            assert!(errors.is_array() && !errors.as_array().unwrap().is_empty());
            assert!(service_executions_ref.read().await.is_empty());
        }

        #[tokio::test]
        async fn test_delete_execution_stop_into_json_error_returns_200_stopped_with_error() {
            // Stop response cannot be parsed (into_json fails) → 200 stopped, error surfaced
            let ecu_name = "TestECU".to_string();
            let mut mock_uds = MockUdsEcu::new();
            let mock_file_manager = MockFileManager::new();

            mock_uds
                .expect_send()
                .withf(|ecu, service, _, _, map_to_json| {
                    ecu == "TestECU"
                        && service.subfunction_id
                            == Some(cda_interfaces::subfunction_ids::routine::STOP)
                        && *map_to_json
                })
                .times(1)
                .returning(|_, _, _, _, _| {
                    let mut resp = MockDiagServiceResponse::new();
                    resp.expect_response_type()
                        .returning(|| DiagServiceResponseType::Positive);
                    resp.expect_is_empty().returning(|| false);
                    resp.expect_into_json().return_once(|| {
                        Err(DiagServiceError::BadPayload(
                            "simulated Stop parse failure".to_string(),
                        ))
                    });
                    Ok(resp)
                });

            let state = create_test_webserver_state::<
                MockDiagServiceResponse,
                MockUdsEcu,
                MockFileManager,
            >(ecu_name, mock_uds, mock_file_manager);
            insert_test_ecu_lock(&state.locks, "TestECU").await;

            let exec_id = uuid::Uuid::new_v4();
            state.service_executions.write().await.insert(
                exec_id,
                ServiceExecution {
                    parameters: serde_json::Map::new(),
                    status: ExecutionStatus::Running,
                    in_flight: false,
                },
            );

            let service_executions_ref = Arc::clone(&state.service_executions);

            let response =
                id_handlers::delete::<MockDiagServiceResponse, MockUdsEcu, MockFileManager>(
                    UseApi(
                        Secured(Box::new(TestSecurityPlugin)),
                        std::marker::PhantomData,
                    ),
                    Path(id_handlers::ServiceAndIdPathParam {
                        service: "CalibrateSensor".to_string(),
                        id: exec_id.to_string(),
                    }),
                    WithRejection(
                        Query(
                            sovd_interfaces::components::ecu::operations::OperationDeleteQuery {
                                include_schema: false,
                                suppress_service: false,
                                force: false,
                            },
                        ),
                        std::marker::PhantomData,
                    ),
                    State(state),
                )
                .await;

            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(
                result.get("status").expect("missing status"),
                &serde_json::json!("stopped")
            );
            let errors = result.get("error").expect("missing error field");
            assert!(errors.is_array() && !errors.as_array().unwrap().is_empty());
            assert!(service_executions_ref.read().await.is_empty());
        }

        #[tokio::test]
        async fn test_delete_execution_force_removes_on_uds_error() {
            let ecu_name = "TestECU".to_string();
            let mut mock_uds = MockUdsEcu::new();
            let mock_file_manager = MockFileManager::new();

            // UDS returns an error (non-NotFound)
            mock_uds.expect_send().times(1).returning(|_, _, _, _, _| {
                Err(DiagServiceError::SendFailed("timeout".to_string()))
            });

            let state = create_test_webserver_state::<
                MockDiagServiceResponse,
                MockUdsEcu,
                MockFileManager,
            >(ecu_name, mock_uds, mock_file_manager);
            insert_test_ecu_lock(&state.locks, "TestECU").await;

            let exec_id = uuid::Uuid::new_v4();
            state.service_executions.write().await.insert(
                exec_id,
                ServiceExecution {
                    parameters: serde_json::Map::new(),
                    status: ExecutionStatus::Running,
                    in_flight: false,
                },
            );

            // Keep a reference to service_executions so we can verify after consuming state
            let service_executions_ref = Arc::clone(&state.service_executions);

            let response =
                id_handlers::delete::<MockDiagServiceResponse, MockUdsEcu, MockFileManager>(
                    UseApi(
                        Secured(Box::new(TestSecurityPlugin)),
                        std::marker::PhantomData,
                    ),
                    Path(id_handlers::ServiceAndIdPathParam {
                        service: "CalibrateSensor".to_string(),
                        id: exec_id.to_string(),
                    }),
                    WithRejection(
                        Query(
                            sovd_interfaces::components::ecu::operations::OperationDeleteQuery {
                                include_schema: false,
                                suppress_service: false,
                                force: true,
                            },
                        ),
                        std::marker::PhantomData,
                    ),
                    State(state),
                )
                .await;

            // force=true → removes execution even on error
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            assert!(service_executions_ref.read().await.is_empty());
        }

        #[tokio::test]
        async fn test_delete_execution_force_removes_on_negative_response() {
            let ecu_name = "TestECU".to_string();
            let mut mock_uds = MockUdsEcu::new();
            let mock_file_manager = MockFileManager::new();

            mock_uds
                .expect_send()
                .times(1)
                .returning(|_, _, _, _, _| Ok(make_negative_response()));

            let state = create_test_webserver_state::<
                MockDiagServiceResponse,
                MockUdsEcu,
                MockFileManager,
            >(ecu_name, mock_uds, mock_file_manager);
            insert_test_ecu_lock(&state.locks, "TestECU").await;

            let exec_id = uuid::Uuid::new_v4();
            state.service_executions.write().await.insert(
                exec_id,
                ServiceExecution {
                    parameters: serde_json::Map::new(),
                    status: ExecutionStatus::Running,
                    in_flight: false,
                },
            );

            let service_executions_ref = Arc::clone(&state.service_executions);

            let response =
                id_handlers::delete::<MockDiagServiceResponse, MockUdsEcu, MockFileManager>(
                    UseApi(
                        Secured(Box::new(TestSecurityPlugin)),
                        std::marker::PhantomData,
                    ),
                    Path(id_handlers::ServiceAndIdPathParam {
                        service: "CalibrateSensor".to_string(),
                        id: exec_id.to_string(),
                    }),
                    WithRejection(
                        Query(
                            sovd_interfaces::components::ecu::operations::OperationDeleteQuery {
                                include_schema: false,
                                suppress_service: false,
                                force: true,
                            },
                        ),
                        std::marker::PhantomData,
                    ),
                    State(state),
                )
                .await;

            // force=true → removes execution even on negative ECU response
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            assert!(service_executions_ref.read().await.is_empty());
        }

        #[tokio::test]
        async fn test_delete_execution_without_force_returns_error_on_uds_failure() {
            let ecu_name = "TestECU".to_string();
            let mut mock_uds = MockUdsEcu::new();
            let mock_file_manager = MockFileManager::new();

            mock_uds.expect_send().times(1).returning(|_, _, _, _, _| {
                Err(DiagServiceError::SendFailed("timeout".to_string()))
            });

            let state = create_test_webserver_state::<
                MockDiagServiceResponse,
                MockUdsEcu,
                MockFileManager,
            >(ecu_name, mock_uds, mock_file_manager);
            insert_test_ecu_lock(&state.locks, "TestECU").await;

            let exec_id = uuid::Uuid::new_v4();
            state.service_executions.write().await.insert(
                exec_id,
                ServiceExecution {
                    parameters: serde_json::Map::new(),
                    status: ExecutionStatus::Running,
                    in_flight: false,
                },
            );

            // Keep a reference to service_executions so we can verify after consuming state
            let service_executions_ref = Arc::clone(&state.service_executions);

            let response =
                id_handlers::delete::<MockDiagServiceResponse, MockUdsEcu, MockFileManager>(
                    UseApi(
                        Secured(Box::new(TestSecurityPlugin)),
                        std::marker::PhantomData,
                    ),
                    Path(id_handlers::ServiceAndIdPathParam {
                        service: "CalibrateSensor".to_string(),
                        id: exec_id.to_string(),
                    }),
                    WithRejection(
                        Query(
                            sovd_interfaces::components::ecu::operations::OperationDeleteQuery {
                                include_schema: false,
                                suppress_service: false,
                                force: false,
                            },
                        ),
                        std::marker::PhantomData,
                    ),
                    State(state),
                )
                .await;

            // force=false → error should be returned, execution should remain
            assert!(response.status().is_client_error() || response.status().is_server_error());
            assert_eq!(service_executions_ref.read().await.len(), 1);
        }

        #[tokio::test]
        async fn test_delete_execution_negative_response_resets_in_flight() {
            let ecu_name = "TestECU".to_string();
            let mut mock_uds = MockUdsEcu::new();
            let mock_file_manager = MockFileManager::new();

            mock_uds
                .expect_send()
                .times(1)
                .returning(|_, _, _, _, _| Ok(make_negative_response()));

            let state = create_test_webserver_state::<
                MockDiagServiceResponse,
                MockUdsEcu,
                MockFileManager,
            >(ecu_name, mock_uds, mock_file_manager);
            insert_test_ecu_lock(&state.locks, "TestECU").await;

            let exec_id = uuid::Uuid::new_v4();
            state.service_executions.write().await.insert(
                exec_id,
                ServiceExecution {
                    parameters: serde_json::Map::new(),
                    status: ExecutionStatus::Running,
                    in_flight: false,
                },
            );

            let service_executions_ref = Arc::clone(&state.service_executions);

            let response =
                id_handlers::delete::<MockDiagServiceResponse, MockUdsEcu, MockFileManager>(
                    UseApi(
                        Secured(Box::new(TestSecurityPlugin)),
                        std::marker::PhantomData,
                    ),
                    Path(id_handlers::ServiceAndIdPathParam {
                        service: "CalibrateSensor".to_string(),
                        id: exec_id.to_string(),
                    }),
                    WithRejection(
                        Query(
                            sovd_interfaces::components::ecu::operations::OperationDeleteQuery {
                                include_schema: false,
                                suppress_service: false,
                                force: false,
                            },
                        ),
                        std::marker::PhantomData,
                    ),
                    State(state),
                )
                .await;

            // Negative ECU response without force → error returned, in_flight reset
            assert!(response.status().is_client_error() || response.status().is_server_error());
            let guard = service_executions_ref.read().await;
            let exec = guard.get(&exec_id).expect("execution should still exist");
            assert!(!exec.in_flight, "in_flight should be reset to false");
        }

        #[tokio::test]
        async fn test_delete_execution_suppress_service_removes_on_not_found() {
            let ecu_name = "TestECU".to_string();
            let mut mock_uds = MockUdsEcu::new();
            let mock_file_manager = MockFileManager::new();

            mock_uds.expect_send().times(1).returning(|_, _, _, _, _| {
                Err(DiagServiceError::NotFound(
                    "CalibrateSensor_Stop not found".to_string(),
                ))
            });

            let state = create_test_webserver_state::<
                MockDiagServiceResponse,
                MockUdsEcu,
                MockFileManager,
            >(ecu_name, mock_uds, mock_file_manager);
            insert_test_ecu_lock(&state.locks, "TestECU").await;

            let exec_id = uuid::Uuid::new_v4();
            state.service_executions.write().await.insert(
                exec_id,
                ServiceExecution {
                    parameters: serde_json::Map::new(),
                    status: ExecutionStatus::Running,
                    in_flight: false,
                },
            );

            // Keep a reference to service_executions so we can verify after consuming state
            let service_executions_ref = Arc::clone(&state.service_executions);

            let response =
                id_handlers::delete::<MockDiagServiceResponse, MockUdsEcu, MockFileManager>(
                    UseApi(
                        Secured(Box::new(TestSecurityPlugin)),
                        std::marker::PhantomData,
                    ),
                    Path(id_handlers::ServiceAndIdPathParam {
                        service: "CalibrateSensor".to_string(),
                        id: exec_id.to_string(),
                    }),
                    WithRejection(
                        Query(
                            sovd_interfaces::components::ecu::operations::OperationDeleteQuery {
                                include_schema: false,
                                suppress_service: true,
                                force: false,
                            },
                        ),
                        std::marker::PhantomData,
                    ),
                    State(state),
                )
                .await;

            // suppress_service=true on NotFound → removes execution, returns 204
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            assert!(service_executions_ref.read().await.is_empty());
        }

        #[tokio::test]
        async fn test_get_execution_in_flight_returns_conflict() {
            let ecu_name = "TestECU".to_string();
            let mock_uds = MockUdsEcu::new();
            let mock_file_manager = MockFileManager::new();
            let state = create_test_webserver_state::<
                MockDiagServiceResponse,
                MockUdsEcu,
                MockFileManager,
            >(ecu_name, mock_uds, mock_file_manager);

            let exec_id = uuid::Uuid::new_v4();
            state.service_executions.write().await.insert(
                exec_id,
                ServiceExecution {
                    parameters: serde_json::Map::new(),
                    status: ExecutionStatus::Running,
                    in_flight: true,
                },
            );

            let response =
                id_handlers::get::<MockDiagServiceResponse, MockUdsEcu, MockFileManager>(
                    UseApi(
                        Secured(Box::new(TestSecurityPlugin)),
                        std::marker::PhantomData,
                    ),
                    Path(id_handlers::ServiceAndIdPathParam {
                        service: "CalibrateSensor".to_string(),
                        id: exec_id.to_string(),
                    }),
                    WithRejection(
                        Query(
                            sovd_interfaces::components::ecu::operations::OperationQuery {
                                include_schema: false,
                                suppress_service: false,
                            },
                        ),
                        std::marker::PhantomData,
                    ),
                    State(state),
                )
                .await;

            assert_eq!(response.status(), StatusCode::CONFLICT);
        }

        #[tokio::test]
        async fn test_delete_execution_in_flight_returns_conflict() {
            let ecu_name = "TestECU".to_string();
            let mock_uds = MockUdsEcu::new();
            let mock_file_manager = MockFileManager::new();
            let state = create_test_webserver_state::<
                MockDiagServiceResponse,
                MockUdsEcu,
                MockFileManager,
            >(ecu_name.clone(), mock_uds, mock_file_manager);
            insert_test_ecu_lock(&state.locks, &ecu_name).await;

            let exec_id = uuid::Uuid::new_v4();
            state.service_executions.write().await.insert(
                exec_id,
                ServiceExecution {
                    parameters: serde_json::Map::new(),
                    status: ExecutionStatus::Running,
                    in_flight: true,
                },
            );

            let response =
                id_handlers::delete::<MockDiagServiceResponse, MockUdsEcu, MockFileManager>(
                    UseApi(
                        Secured(Box::new(TestSecurityPlugin)),
                        std::marker::PhantomData,
                    ),
                    Path(id_handlers::ServiceAndIdPathParam {
                        service: "CalibrateSensor".to_string(),
                        id: exec_id.to_string(),
                    }),
                    WithRejection(
                        Query(
                            sovd_interfaces::components::ecu::operations::OperationDeleteQuery {
                                include_schema: false,
                                suppress_service: false,
                                force: false,
                            },
                        ),
                        std::marker::PhantomData,
                    ),
                    State(state),
                )
                .await;

            assert_eq!(response.status(), StatusCode::CONFLICT);
        }

        // ── POST /operations/{service}/executions – Start ─────────────────────

        fn make_post_headers() -> axum::http::HeaderMap {
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("application/json"),
            );
            headers.insert(
                axum::http::header::ACCEPT,
                axum::http::HeaderValue::from_static("application/json"),
            );
            headers
        }

        #[tokio::test]
        async fn test_post_operation_service_not_found_returns_404() {
            let ecu_name = "TestECU".to_string();
            let mut mock_uds = MockUdsEcu::new();
            let mock_file_manager = MockFileManager::new();

            mock_uds
                .expect_get_routine_subfunctions()
                .withf(|ecu, svc, _p| ecu == "TestECU" && svc == "CalibrateSensor")
                .times(1)
                .returning(|_, _, _| {
                    Err(DiagServiceError::NotFound(
                        "Routine 'CalibrateSensor' not found in ECU description".to_string(),
                    ))
                });

            let state = create_test_webserver_state::<
                MockDiagServiceResponse,
                MockUdsEcu,
                MockFileManager,
            >(ecu_name.clone(), mock_uds, mock_file_manager);

            let response = handlers::ecu_operation_write_handler::<MockUdsEcu>(
                handlers::WriteHandlerRequest {
                    service: "CalibrateSensor".to_string(),
                    headers: make_post_headers(),
                    body: axum::body::Bytes::from_static(b"{\"parameters\":{}}"),
                },
                &ecu_name,
                &state.uds,
                Arc::clone(&state.service_executions),
                Box::new(cda_plugin_security::mock::TestSecurityPlugin),
                handlers::WriteHandlerOptions {
                    include_schema: false,
                    suppress_service: false,
                    base_path: "http://localhost/operations/CalibrateSensor/executions".to_string(),
                },
            )
            .await;

            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn test_post_operation_sync_returns_200_on_empty_response() {
            let ecu_name = "TestECU".to_string();
            let mut mock_uds = MockUdsEcu::new();
            let mock_file_manager = MockFileManager::new();

            mock_uds
                .expect_get_routine_subfunctions()
                .times(1)
                .returning(|_, _, _| {
                    Ok(cda_interfaces::datatypes::RoutineSubfunctions {
                        has_stop: false,
                        has_request_results: false,
                    })
                });
            mock_uds
                .expect_send()
                .times(1)
                .returning(|_, _, _, _, _| Ok(make_empty_positive_response()));

            let state = create_test_webserver_state::<
                MockDiagServiceResponse,
                MockUdsEcu,
                MockFileManager,
            >(ecu_name.clone(), mock_uds, mock_file_manager);

            let response = handlers::ecu_operation_write_handler::<MockUdsEcu>(
                handlers::WriteHandlerRequest {
                    service: "CalibrateSensor".to_string(),
                    headers: make_post_headers(),
                    body: axum::body::Bytes::from_static(b"{\"parameters\":{}}"),
                },
                &ecu_name,
                &state.uds,
                Arc::clone(&state.service_executions),
                Box::new(cda_plugin_security::mock::TestSecurityPlugin),
                handlers::WriteHandlerOptions {
                    include_schema: false,
                    suppress_service: false,
                    base_path: "http://localhost/operations/CalibrateSensor/executions".to_string(),
                },
            )
            .await;

            assert_eq!(response.status(), StatusCode::OK);
        }

        #[tokio::test]
        async fn test_post_operation_async_returns_202_and_tracks_execution() {
            let ecu_name = "TestECU".to_string();
            let mut mock_uds = MockUdsEcu::new();
            let mock_file_manager = MockFileManager::new();

            mock_uds
                .expect_get_routine_subfunctions()
                .times(1)
                .returning(|_, _, _| {
                    Ok(cda_interfaces::datatypes::RoutineSubfunctions {
                        has_stop: true,
                        has_request_results: true,
                    })
                });
            mock_uds
                .expect_send()
                .times(1)
                .returning(|_, _, _, _, _| Ok(make_empty_positive_response()));

            let state = create_test_webserver_state::<
                MockDiagServiceResponse,
                MockUdsEcu,
                MockFileManager,
            >(ecu_name.clone(), mock_uds, mock_file_manager);

            let service_executions_ref = Arc::clone(&state.service_executions);

            let response = handlers::ecu_operation_write_handler::<MockUdsEcu>(
                handlers::WriteHandlerRequest {
                    service: "CalibrateSensor".to_string(),
                    headers: make_post_headers(),
                    body: axum::body::Bytes::from_static(b"{\"parameters\":{}}"),
                },
                &ecu_name,
                &state.uds,
                Arc::clone(&state.service_executions),
                Box::new(cda_plugin_security::mock::TestSecurityPlugin),
                handlers::WriteHandlerOptions {
                    include_schema: false,
                    suppress_service: false,
                    base_path: "http://localhost/operations/CalibrateSensor/executions".to_string(),
                },
            )
            .await;

            assert_eq!(response.status(), StatusCode::ACCEPTED);
            assert_eq!(service_executions_ref.read().await.len(), 1);
        }

        #[tokio::test]
        async fn test_post_operation_suppress_service_async_skips_send_returns_202_and_tracks() {
            let ecu_name = "TestECU".to_string();
            let mut mock_uds = MockUdsEcu::new();
            let mock_file_manager = MockFileManager::new();

            mock_uds.expect_get_routine_subfunctions().times(0);
            // send must NOT be called when suppress_service=true
            mock_uds.expect_send().times(0);

            let state = create_test_webserver_state::<
                MockDiagServiceResponse,
                MockUdsEcu,
                MockFileManager,
            >(ecu_name.clone(), mock_uds, mock_file_manager);

            let service_executions_ref = Arc::clone(&state.service_executions);

            let response = handlers::ecu_operation_write_handler::<MockUdsEcu>(
                handlers::WriteHandlerRequest {
                    service: "CalibrateSensor".to_string(),
                    headers: make_post_headers(),
                    body: axum::body::Bytes::from_static(b"{\"parameters\":{}}"),
                },
                &ecu_name,
                &state.uds,
                Arc::clone(&state.service_executions),
                Box::new(cda_plugin_security::mock::TestSecurityPlugin),
                handlers::WriteHandlerOptions {
                    include_schema: false,
                    suppress_service: true,
                    base_path: "http://localhost/operations/CalibrateSensor/executions".to_string(),
                },
            )
            .await;

            assert_eq!(response.status(), StatusCode::ACCEPTED);
            // execution still tracked even though UDS was not called
            assert_eq!(service_executions_ref.read().await.len(), 1);
        }

        #[tokio::test]
        async fn test_post_operation_async_into_json_error_surfaces_in_errors_not_500() {
            let ecu_name = "TestECU".to_string();
            let mut mock_uds = MockUdsEcu::new();
            let mock_file_manager = MockFileManager::new();

            mock_uds
                .expect_get_routine_subfunctions()
                .times(1)
                .returning(|_, _, _| {
                    Ok(cda_interfaces::datatypes::RoutineSubfunctions {
                        has_stop: true,
                        has_request_results: true,
                    })
                });
            // send returns a response whose into_json() fails
            mock_uds.expect_send().times(1).returning(|_, _, _, _, _| {
                let mut resp = MockDiagServiceResponse::new();
                resp.expect_response_type()
                    .returning(|| DiagServiceResponseType::Positive);
                resp.expect_is_empty().returning(|| false);
                resp.expect_into_json().return_once(|| {
                    Err(DiagServiceError::BadPayload(
                        "simulated parse failure".to_string(),
                    ))
                });
                Ok(resp)
            });

            let state = create_test_webserver_state::<
                MockDiagServiceResponse,
                MockUdsEcu,
                MockFileManager,
            >(ecu_name.clone(), mock_uds, mock_file_manager);

            let service_executions_ref = Arc::clone(&state.service_executions);

            let response = handlers::ecu_operation_write_handler::<MockUdsEcu>(
                handlers::WriteHandlerRequest {
                    service: "CalibrateSensor".to_string(),
                    headers: make_post_headers(),
                    body: axum::body::Bytes::from_static(b"{\"parameters\":{}}"),
                },
                &ecu_name,
                &state.uds,
                Arc::clone(&state.service_executions),
                Box::new(cda_plugin_security::mock::TestSecurityPlugin),
                handlers::WriteHandlerOptions {
                    include_schema: false,
                    suppress_service: false,
                    base_path: "http://localhost/operations/CalibrateSensor/executions".to_string(),
                },
            )
            .await;

            // Must be 202, not 500 — spec Table 184 body has only id + status
            assert_eq!(response.status(), StatusCode::ACCEPTED);
            // Execution must still be tracked
            assert_eq!(service_executions_ref.read().await.len(), 1);
            // Body must contain id and status, no errors field
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(result.get("id").is_some(), "202 body must have id");
            assert!(result.get("status").is_some(), "202 body must have status");
            assert!(
                result.get("errors").is_none(),
                "202 body must not contain errors per spec Table 184"
            );
        }

        #[tokio::test]
        async fn test_post_operation_async_non_object_json_surfaces_in_errors_not_500() {
            let ecu_name = "TestECU".to_string();
            let mut mock_uds = MockUdsEcu::new();
            let mock_file_manager = MockFileManager::new();

            mock_uds
                .expect_get_routine_subfunctions()
                .times(1)
                .returning(|_, _, _| {
                    Ok(cda_interfaces::datatypes::RoutineSubfunctions {
                        has_stop: true,
                        has_request_results: true,
                    })
                });
            // send returns a response whose into_json() gives a non-Object JSON value
            mock_uds.expect_send().times(1).returning(|_, _, _, _, _| {
                let mut resp = MockDiagServiceResponse::new();
                resp.expect_response_type()
                    .returning(|| DiagServiceResponseType::Positive);
                resp.expect_is_empty().returning(|| false);
                resp.expect_into_json().return_once(|| {
                    Ok(DiagServiceJsonResponse {
                        data: serde_json::Value::String("unexpected_string".to_string()),
                        errors: vec![],
                    })
                });
                Ok(resp)
            });

            let state = create_test_webserver_state::<
                MockDiagServiceResponse,
                MockUdsEcu,
                MockFileManager,
            >(ecu_name.clone(), mock_uds, mock_file_manager);

            let service_executions_ref = Arc::clone(&state.service_executions);

            let response = handlers::ecu_operation_write_handler::<MockUdsEcu>(
                handlers::WriteHandlerRequest {
                    service: "CalibrateSensor".to_string(),
                    headers: make_post_headers(),
                    body: axum::body::Bytes::from_static(b"{\"parameters\":{}}"),
                },
                &ecu_name,
                &state.uds,
                Arc::clone(&state.service_executions),
                Box::new(cda_plugin_security::mock::TestSecurityPlugin),
                handlers::WriteHandlerOptions {
                    include_schema: false,
                    suppress_service: false,
                    base_path: "http://localhost/operations/CalibrateSensor/executions".to_string(),
                },
            )
            .await;

            // Must be 202, not 500 — spec Table 184 body has only id + status
            assert_eq!(response.status(), StatusCode::ACCEPTED);
            assert_eq!(service_executions_ref.read().await.len(), 1);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(result.get("id").is_some(), "202 body must have id");
            assert!(result.get("status").is_some(), "202 body must have status");
            assert!(
                result.get("errors").is_none(),
                "202 body must not contain errors per spec Table 184"
            );
        }

        #[tokio::test]
        async fn test_request_results_into_json_error_surfaces_in_errors_field() {
            let ecu_name = "TestECU".to_string();
            let mut mock_uds = MockUdsEcu::new();
            let mock_file_manager = MockFileManager::new();

            // RequestResults returns a non-empty response whose into_json() fails
            mock_uds.expect_send().times(1).returning(|_, _, _, _, _| {
                let mut resp = MockDiagServiceResponse::new();
                resp.expect_response_type()
                    .returning(|| DiagServiceResponseType::Positive);
                resp.expect_is_empty().returning(|| false);
                resp.expect_into_json().return_once(|| {
                    Err(DiagServiceError::BadPayload(
                        "simulated parse failure".to_string(),
                    ))
                });
                Ok(resp)
            });

            let state = create_test_webserver_state::<
                MockDiagServiceResponse,
                MockUdsEcu,
                MockFileManager,
            >(ecu_name, mock_uds, mock_file_manager);

            let exec_id = uuid::Uuid::new_v4();
            state.service_executions.write().await.insert(
                exec_id,
                ServiceExecution {
                    parameters: serde_json::Map::new(),
                    status: ExecutionStatus::Running,
                    in_flight: false,
                },
            );

            let response =
                id_handlers::get::<MockDiagServiceResponse, MockUdsEcu, MockFileManager>(
                    UseApi(
                        Secured(Box::new(TestSecurityPlugin)),
                        std::marker::PhantomData,
                    ),
                    Path(id_handlers::ServiceAndIdPathParam {
                        service: "CalibrateSensor".to_string(),
                        id: exec_id.to_string(),
                    }),
                    WithRejection(
                        Query(
                            sovd_interfaces::components::ecu::operations::OperationQuery {
                                include_schema: false,
                                suppress_service: false,
                            },
                        ),
                        std::marker::PhantomData,
                    ),
                    State(state),
                )
                .await;

            // Must be 200, not 500
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
            // Spec Table 189: field is named `error` (singular key, array value)
            let errors = result.get("error").expect("missing error field");
            assert!(
                errors.as_array().is_some_and(|a| !a.is_empty()),
                "error should be non-empty when RequestResults into_json fails"
            );
        }
    }
}
