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
    response::{IntoResponse, Response},
};
use axum_extra::extract::WithRejection;
use cda_interfaces::{DynamicPlugin, UdsEcu};
use cda_plugin_security::Secured;
use http::StatusCode;
use sovd_interfaces::functions::functional_groups::operations::OperationCollectionItem;

use super::WebserverFgState;
use crate::sovd::{
    create_schema,
    error::{ApiError, ErrorWrapper},
};

pub(crate) async fn get<T: UdsEcu + Clone>(
    UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
    WithRejection(Query(query), _): WithRejection<
        Query<sovd_interfaces::functions::functional_groups::operations::get::Query>,
        ApiError,
    >,
    State(WebserverFgState {
        uds,
        functional_group_name,
        ..
    }): State<WebserverFgState<T>>,
) -> Response {
    let security_plugin: DynamicPlugin = security_plugin;
    match uds
        .get_functional_group_operations_info(&security_plugin, &functional_group_name)
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
    op.description("Get all available operations for this functional group")
        .response_with::<200, Json<sovd_interfaces::Items<OperationCollectionItem>>, _>(|res| {
            res.description("List of operations available in this functional group.")
        })
}

pub(crate) mod get_by_name {
    use aide::{UseApi, transform::TransformOperation};
    use axum::{
        Json,
        extract::{Path, Query, State},
        response::{IntoResponse, Response},
    };
    use axum_extra::extract::WithRejection;
    use cda_interfaces::{DiagComm, DiagCommType, SchemaProvider, UdsEcu, subfunction_ids};
    use cda_plugin_security::Secured;
    use http::StatusCode;
    use sovd_interfaces::common::operations::OperationDetailResponse;

    use super::super::WebserverFgState;
    use crate::{
        openapi,
        sovd::{
            create_schema,
            error::{ApiError, ErrorWrapper},
        },
    };

    openapi::aide_helper::gen_path_param!(FgOperationNamePathParam service String);

    /// `GET /operations/{service}` -- return the parameter schema for a specific
    /// functional-group operation.
    pub(crate) async fn get<T: UdsEcu + SchemaProvider + Clone>(
        UseApi(Secured(_security_plugin), _): UseApi<Secured, ()>,
        Path(FgOperationNamePathParam { service }): Path<FgOperationNamePathParam>,
        WithRejection(Query(query), _): WithRejection<
            Query<sovd_interfaces::IncludeSchemaQuery>,
            ApiError,
        >,
        State(WebserverFgState {
            uds,
            functional_group_name,
            ..
        }): State<WebserverFgState<T>>,
    ) -> Response {
        let include_schema = query.include_schema;

        let diag_service = DiagComm {
            name: service.clone(),
            type_: DiagCommType::Operations,
            lookup_name: None,
            subfunction_id: Some(subfunction_ids::routine::START),
        };

        let schema_desc = match uds
            .schema_for_fg_request(&diag_service, &functional_group_name)
            .await
        {
            Ok(desc) => desc,
            Err(e) => {
                return ErrorWrapper {
                    error: e.into(),
                    include_schema,
                }
                .into_response();
            }
        };

        let parameters = schema_desc
            .into_schema()
            .and_then(|s| {
                let obj = serde_json::Value::from(s);
                obj.as_object()
                    .and_then(|o| o.get("properties"))
                    .and_then(|p| p.as_object())
                    .cloned()
            })
            .unwrap_or_default();

        let schema = if include_schema {
            Some(create_schema!(OperationDetailResponse))
        } else {
            None
        };

        (
            StatusCode::OK,
            Json(OperationDetailResponse {
                id: service,
                parameters,
                schema,
            }),
        )
            .into_response()
    }

    pub(crate) fn docs(op: TransformOperation) -> TransformOperation {
        op.description("Get the parameter schema for a specific operation on this functional group")
            .response_with::<200, Json<OperationDetailResponse>, _>(|res| {
                res.description("Parameter definitions for the operation's START request.")
            })
            .with(openapi::error_not_found)
    }
}

pub(crate) mod diag_service {
    use aide::{UseApi, transform::TransformOperation};
    use axum::{
        Json,
        body::Bytes,
        extract::{OriginalUri, Path, Query, State},
        http::{HeaderMap, StatusCode, Uri, header},
        response::{IntoResponse, Response},
    };
    use axum_extra::extract::{Host, WithRejection};
    use cda_interfaces::{DiagComm, DiagCommType, DynamicPlugin, HashMap, UdsEcu, subfunction_ids};
    use cda_plugin_security::Secured;
    use indexmap::IndexMap;
    use sovd_interfaces::components::ecu::operations::{AsyncPostResponse, ExecutionStatus};
    use tokio::sync::RwLock;
    use uuid::Uuid;

    use super::super::WebserverFgState;
    use crate::{
        create_schema, openapi,
        sovd::{
            FgServiceExecution, check_running_execution_conflict,
            components::{ecu::DiagServicePathParam, get_content_type_and_accept},
            error::{ApiError, ErrorWrapper, VendorErrorCode},
            functions::functional_groups::{handle_ecu_response, map_to_json},
            get_payload_data,
            locks::validate_fg_lock,
        },
    };

    /// Path parameter for `DELETE /operations/{operation}/executions/{id}`.
    #[derive(serde::Deserialize, schemars::JsonSchema)]
    pub(crate) struct OperationAndIdPathParam {
        pub operation: String,
        pub id: String,
    }

    /// Builds a `200 OK` response containing per-ECU operation results and errors.
    ///
    /// Used by POST (sync execution) and by DELETE when Stop encounters errors: either to
    /// surface them while keeping the execution alive (`force=false`) or after forcibly
    /// removing it (`force=true`).
    fn build_operation_response(
        response_data: HashMap<String, serde_json::Map<String, serde_json::Value>>,
        errors: Vec<sovd_interfaces::error::DataError<VendorErrorCode>>,
        include_schema: bool,
    ) -> axum::response::Response {
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

    /// Registers an async execution entry and builds the `202 Accepted` response.
    async fn build_async_response(
        fg_executions: &RwLock<HashMap<String, IndexMap<Uuid, FgServiceExecution>>>,
        operation: &str,
        response_data: HashMap<String, serde_json::Map<String, serde_json::Value>>,
        host: &str,
        uri: &Uri,
        include_schema: bool,
    ) -> Response {
        let id = Uuid::new_v4();
        let operation = operation.to_lowercase();
        fg_executions
            .write()
            .await
            .entry(operation)
            .or_default()
            .insert(
                id,
                FgServiceExecution {
                    parameters: response_data,
                    status: ExecutionStatus::Running,
                    in_flight: false,
                },
            );

        let exec_url = format!("http://{host}{uri}/executions/{id}");
        let schema = if include_schema {
            Some(create_schema!(AsyncPostResponse))
        } else {
            None
        };
        (
            StatusCode::ACCEPTED,
            [(header::LOCATION, exec_url)],
            Json(AsyncPostResponse {
                id: id.to_string(),
                status: Some(ExecutionStatus::Running),
                schema,
            }),
        )
            .into_response()
    }

    pub(crate) mod executions {
        use aide::{UseApi, transform::TransformOperation};
        use axum::{
            Json,
            extract::{Path, Query, State},
            response::{IntoResponse, Response},
        };
        use axum_extra::extract::WithRejection;
        use cda_interfaces::UdsEcu;
        use cda_plugin_security::Secured;
        use http::StatusCode;
        use sovd_interfaces::common::operations::OperationIdItem;

        use super::super::super::WebserverFgState;
        use crate::sovd::{components::ecu::DiagServicePathParam, create_schema, error::ApiError};

        pub(crate) async fn get<T: UdsEcu + Clone>(
            UseApi(Secured(_security_plugin), _): UseApi<Secured, ()>,
            WithRejection(Query(query), _): WithRejection<
                Query<sovd_interfaces::IncludeSchemaQuery>,
                ApiError,
            >,
            Path(DiagServicePathParam { service: operation }): Path<DiagServicePathParam>,
            State(WebserverFgState { fg_executions, .. }): State<WebserverFgState<T>>,
        ) -> Response {
            let operation = operation.to_lowercase();
            let schema = if query.include_schema {
                Some(create_schema!(sovd_interfaces::Items<String>))
            } else {
                None
            };
            let executions = fg_executions.read().await;

            let ids: Vec<_> = executions
                .get(&operation)
                .map(|op_map| {
                    op_map
                        .keys()
                        .map(|key| OperationIdItem {
                            id: key.to_string(),
                        })
                        .collect()
                })
                .unwrap_or_default();
            (
                StatusCode::OK,
                Json(sovd_interfaces::Items { items: ids, schema }),
            )
                .into_response()
        }

        pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
            op.description("List all active executions for this functional group operation")
                .response_with::<200, Json<sovd_interfaces::Items<String>>, _>(|res| {
                    res.description("List of active execution ids.")
                })
        }
    }

    // cannot easily combine the axum extractors without creating a new custom extractor.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn post<T: UdsEcu + Clone>(
        headers: HeaderMap,
        UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
        UseApi(Host(host), _): UseApi<Host, String>,
        OriginalUri(uri): OriginalUri,
        Path(DiagServicePathParam { service: operation }): Path<DiagServicePathParam>,
        WithRejection(Query(query), _): WithRejection<
            Query<sovd_interfaces::functions::functional_groups::operations::service::Query>,
            ApiError,
        >,
        State(WebserverFgState {
            uds,
            locks,
            functional_group_name,
            fg_executions,
            ..
        }): State<WebserverFgState<T>>,
        body: Bytes,
    ) -> Response {
        let include_schema = query.include_schema;
        let suppress_service = query.suppress_service;
        if let Some(err_response) = validate_fg_lock(
            &security_plugin.claims(),
            &functional_group_name,
            &locks,
            include_schema,
        )
        .await
        {
            return err_response;
        }

        let security_plugin: DynamicPlugin = security_plugin;

        if operation.contains('/') {
            return ErrorWrapper {
                error: ApiError::BadRequest("Invalid path".to_owned()),
                include_schema,
            }
            .into_response();
        }

        // Reject if there is already a running execution for this operation.
        if let Some(err) = check_running_execution_conflict(
            &fg_executions,
            &operation.to_lowercase(),
            &operation,
            include_schema,
        )
        .await
        {
            return err.into_response();
        }

        let is_async = if suppress_service {
            // suppress service is always treated as async
            true
        } else {
            match check_if_async(
                &uds,
                &security_plugin,
                &functional_group_name,
                &operation,
                include_schema,
            )
            .await
            {
                Ok(is_async) => is_async,
                Err(e) => return e.into_response(),
            }
        };

        let (content_type, _) = match get_content_type_and_accept(&headers) {
            Ok(v) => v,
            Err(e) => {
                return ErrorWrapper {
                    error: e,
                    include_schema,
                }
                .into_response();
            }
        };
        let accept = mime::APPLICATION_JSON;

        let data = if suppress_service {
            None
        } else {
            match get_payload_data::<
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
            }
        };

        let map_to_json = match map_to_json(include_schema, &accept) {
            Ok(value) => value,
            Err(e) => return e.into_response(),
        };

        // Send START to all ECUs (unless suppressed).
        let results: HashMap<String, Result<T::Response, cda_interfaces::DiagServiceError>> =
            if suppress_service {
                HashMap::default()
            } else {
                uds.send_functional_group(
                    &functional_group_name,
                    DiagComm {
                        name: operation.clone(),
                        type_: DiagCommType::Operations,
                        lookup_name: None,
                        subfunction_id: Some(subfunction_ids::routine::START),
                    },
                    &(security_plugin as DynamicPlugin),
                    data,
                    map_to_json,
                )
                .await
            };

        // Collect per-ECU parameters
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

        if is_async {
            build_async_response(
                &fg_executions,
                &operation,
                response_data,
                &host,
                &uri,
                include_schema,
            )
            .await
        } else {
            build_operation_response(response_data, errors, include_schema)
        }
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
                "Synchronous execution: response with parameters from all ECUs, keyed by ECU name",
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
        .response_with::<202, Json<AsyncPostResponse>, _>(|res| {
            res.description(
                "Asynchronous execution started. Use DELETE \
                 /operations/{operation}/executions/{id} to stop.",
            )
        })
        .with(openapi::error_forbidden)
        .with(openapi::error_not_found)
        .with(openapi::error_conflict)
        .with(openapi::error_internal_server)
        .with(openapi::error_bad_request)
        .with(openapi::error_bad_gateway)
    }

    pub(crate) async fn delete<T: UdsEcu + Clone>(
        UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
        Path(OperationAndIdPathParam { operation, id }): Path<OperationAndIdPathParam>,
        WithRejection(Query(query), _): WithRejection<
            Query<sovd_interfaces::components::ecu::operations::OperationDeleteQuery>,
            ApiError,
        >,
        State(WebserverFgState {
            uds,
            locks,
            functional_group_name,
            fg_executions,
            ..
        }): State<WebserverFgState<T>>,
    ) -> Response {
        let include_schema = query.include_schema;
        let suppress_service = query.suppress_service;

        let claims = security_plugin.as_auth_plugin().claims();
        if let Some(response) =
            validate_fg_lock(&claims, &functional_group_name, &locks, include_schema).await
        {
            return response;
        }

        let exec_id = match Uuid::parse_str(&id) {
            Ok(v) => v,
            Err(e) => {
                return ErrorWrapper {
                    error: ApiError::BadRequest(format!("{e:?}")),
                    include_schema,
                }
                .into_response();
            }
        };

        // Guard: mark execution in_flight (replaces shared guard_execution for nested map).
        {
            let mut guard = fg_executions.write().await;
            let Some(op_map) = guard.get_mut(&operation) else {
                return ErrorWrapper {
                    error: ApiError::NotFound(Some(format!(
                        "Execution with id {exec_id} not found"
                    ))),
                    include_schema,
                }
                .into_response();
            };
            match op_map.get_mut(&exec_id) {
                None => {
                    return ErrorWrapper {
                        error: ApiError::NotFound(Some(format!(
                            "Execution with id {exec_id} not found"
                        ))),
                        include_schema,
                    }
                    .into_response();
                }
                Some(exec) if exec.in_flight => {
                    return ErrorWrapper {
                        error: ApiError::Conflict(format!(
                            "Execution {exec_id} is already in flight"
                        )),
                        include_schema,
                    }
                    .into_response();
                }
                Some(exec) => {
                    exec.in_flight = true;
                }
            }
        }

        // If suppress_service, skip sending STOP to ECUs - just remove and return 204.
        if suppress_service {
            tracing::warn!(
                operation = %operation,
                exec_id = %exec_id,
                "Stop skipped (suppress_service=true), removing execution"
            );
            if let Some(op_map) = fg_executions.write().await.get_mut(&operation) {
                op_map.shift_remove(&exec_id);
            }
            return StatusCode::NO_CONTENT.into_response();
        }

        // Send STOP to all ECUs in the functional group.
        let results = uds
            .send_functional_group(
                &functional_group_name,
                DiagComm {
                    name: operation.clone(),
                    type_: DiagCommType::Operations,
                    lookup_name: None,
                    subfunction_id: Some(subfunction_ids::routine::STOP),
                },
                &(security_plugin as DynamicPlugin),
                None,
                true,
            )
            .await;

        // Collect per-ECU results before deciding whether to remove the execution.
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

        if errors.is_empty() {
            // All ECUs succeeded - remove execution and return 204.
            if let Some(op_map) = fg_executions.write().await.get_mut(&operation) {
                op_map.shift_remove(&exec_id);
            }
            StatusCode::NO_CONTENT.into_response()
        } else if query.force {
            // force=true - remove execution even though Stop had errors, return 200 with errors.
            if let Some(op_map) = fg_executions.write().await.get_mut(&operation) {
                op_map.shift_remove(&exec_id);
            }
            build_operation_response(response_data, errors, include_schema)
        } else {
            // force=false and Stop had errors - reset in_flight, keep execution alive for retry.
            if let Some(op_map) = fg_executions.write().await.get_mut(&operation)
                && let Some(exec) = op_map.get_mut(&exec_id)
            {
                exec.in_flight = false;
            }
            build_operation_response(response_data, errors, include_schema)
        }
    }

    pub(crate) fn docs_delete(op: TransformOperation) -> TransformOperation {
        op.description(
            "Stop an async functional group operation execution (Stop subfunction). Sends Stop to \
             all ECUs. Returns 204 if all ECUs succeeded. On partial failure: if \
             x-sovd2uds-force=true, removes the execution and returns 200 with errors; if \
             x-sovd2uds-force=false (default), keeps the execution alive for retry and returns \
             200 with errors.",
        )
        .response_with::<204, (), _>(|res| {
            res.description("Execution stopped and removed on all ECUs.")
        })
        .response_with::<200, Json<
            sovd_interfaces::functions::functional_groups::operations::service::Response<
                VendorErrorCode,
            >,
        >, _>(|res| {
            res.description("Stop completed with partial failures. See errors for per-ECU details.")
        })
        .with(openapi::error_not_found)
        .with(openapi::error_bad_request)
        .with(openapi::error_forbidden)
        .with(openapi::error_conflict)
    }

    async fn check_if_async<T: UdsEcu>(
        uds: &T,
        security_plugin: &DynamicPlugin,
        functional_group_name: &str,
        service_name: &str,
        include_schema: bool,
    ) -> Result<bool, ErrorWrapper> {
        // Determine whether this operation is async (has_stop) and validate it exists.
        let subfunctions = match uds
            .get_functional_group_routine_subfunctions(
                security_plugin,
                functional_group_name,
                service_name,
            )
            .await
        {
            Ok(sf) => sf,
            Err(cda_interfaces::DiagServiceError::NotFound(_)) => {
                return Err(ErrorWrapper {
                    error: ApiError::NotFound(Some(format!(
                        "Operation '{service_name}' not found in functional group \
                         '{functional_group_name}'"
                    ))),
                    include_schema,
                });
            }
            Err(e) => {
                return Err(ErrorWrapper {
                    error: e.into(),
                    include_schema,
                });
            }
        };

        Ok(subfunctions.has_stop || subfunctions.has_request_results)
    }

    pub(crate) mod id {
        use aide::{UseApi, transform::TransformOperation};
        use axum::{
            Json,
            extract::{Path, Query, State},
            response::{IntoResponse, Response},
        };
        use axum_extra::extract::WithRejection;
        use cda_interfaces::{
            DiagComm, DiagCommType, DynamicPlugin, HashMap, UdsEcu, subfunction_ids,
        };
        use cda_plugin_security::Secured;
        use http::StatusCode;
        use indexmap::IndexMap;
        use sovd_interfaces::{
            components::ecu::operations::{ExecutionStatus, GetByIdCapability, OperationQuery},
            functions::functional_groups::operations::FgAsyncGetByIdResponse,
        };
        use tokio::sync::RwLock;
        use uuid::Uuid;

        use super::{super::super::WebserverFgState, OperationAndIdPathParam};
        use crate::{
            create_schema, openapi,
            sovd::{
                FgServiceExecution,
                error::{ApiError, ErrorWrapper, VendorErrorCode},
                functions::functional_groups::handle_ecu_response,
                locks::validate_fg_lock,
            },
        };

        /// Builds the `200 OK` `FgAsyncGetByIdResponse` body.
        fn fg_get_by_id_response(
            status: ExecutionStatus,
            parameters: HashMap<String, serde_json::Map<String, serde_json::Value>>,
            errors: Vec<sovd_interfaces::error::DataError<VendorErrorCode>>,
            include_schema: bool,
        ) -> Response {
            let schema = if include_schema {
                Some(create_schema!(FgAsyncGetByIdResponse<VendorErrorCode>))
            } else {
                None
            };
            (
                StatusCode::OK,
                Json(FgAsyncGetByIdResponse::<VendorErrorCode> {
                    status,
                    capability: GetByIdCapability::Execute,
                    parameters,
                    errors,
                    schema,
                }),
            )
                .into_response()
        }

        pub(crate) async fn get<T: UdsEcu + Clone>(
            UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
            Path(OperationAndIdPathParam { operation, id }): Path<OperationAndIdPathParam>,
            WithRejection(Query(query), _): WithRejection<Query<OperationQuery>, ApiError>,
            State(WebserverFgState {
                uds,
                locks,
                functional_group_name,
                fg_executions,
                ..
            }): State<WebserverFgState<T>>,
        ) -> Response {
            let include_schema = query.include_schema;

            if let Some(err_response) = validate_fg_lock(
                &security_plugin.claims(),
                &functional_group_name,
                &locks,
                include_schema,
            )
            .await
            {
                return err_response;
            }

            let exec_id = match Uuid::parse_str(&id) {
                Ok(v) => v,
                Err(e) => {
                    return ErrorWrapper {
                        error: ApiError::BadRequest(format!("{e:?}")),
                        include_schema,
                    }
                    .into_response();
                }
            };

            // Guard: look up execution and mark in_flight.
            let stored = {
                let mut guard = fg_executions.write().await;
                let Some(op_map) = guard.get_mut(&operation) else {
                    return ErrorWrapper {
                        error: ApiError::NotFound(Some(format!(
                            "Execution with id {exec_id} not found"
                        ))),
                        include_schema,
                    }
                    .into_response();
                };
                match op_map.get_mut(&exec_id) {
                    None => {
                        return ErrorWrapper {
                            error: ApiError::NotFound(Some(format!(
                                "Execution with id {exec_id} not found"
                            ))),
                            include_schema,
                        }
                        .into_response();
                    }
                    Some(exec) if exec.in_flight => {
                        return ErrorWrapper {
                            error: ApiError::Conflict(format!(
                                "Execution {exec_id} is already in flight"
                            )),
                            include_schema,
                        }
                        .into_response();
                    }
                    Some(exec) => {
                        exec.in_flight = true;
                        exec.clone()
                    }
                }
            };

            // suppress_service: skip UDS send, return stored state directly.
            if query.suppress_service {
                if let Some(op_map) = fg_executions.write().await.get_mut(&operation)
                    && let Some(exec) = op_map.get_mut(&exec_id)
                {
                    exec.in_flight = false;
                }
                return fg_get_by_id_response(
                    stored.status,
                    stored.parameters,
                    vec![],
                    include_schema,
                );
            }

            let security_plugin: DynamicPlugin = security_plugin;

            // Check whether the operation defines a RequestResults subfunction.
            let has_request_results = match uds
                .get_functional_group_routine_subfunctions(
                    &security_plugin,
                    &functional_group_name,
                    &operation,
                )
                .await
            {
                Ok(sf) => sf.has_request_results,
                Err(e) => {
                    if let Some(op_map) = fg_executions.write().await.get_mut(&operation)
                        && let Some(exec) = op_map.get_mut(&exec_id)
                    {
                        exec.in_flight = false;
                    }
                    return ErrorWrapper {
                        error: e.into(),
                        include_schema,
                    }
                    .into_response();
                }
            };

            // When there is no RequestResults subfunction, return the stored
            // execution state together with an error entry.
            if !has_request_results {
                if let Some(op_map) = fg_executions.write().await.get_mut(&operation)
                    && let Some(exec) = op_map.get_mut(&exec_id)
                {
                    exec.in_flight = false;
                }
                return fg_get_by_id_response(
                    stored.status,
                    stored.parameters,
                    vec![sovd_interfaces::error::DataError {
                        path: "/".to_owned(),
                        error: sovd_interfaces::error::ApiErrorResponse {
                            message: format!(
                                "Operation '{operation}' does not support RequestResults"
                            ),
                            error_code: sovd_interfaces::error::ErrorCode::VendorSpecific,
                            vendor_code: Some(VendorErrorCode::BadRequest),
                            parameters: None,
                            error_source: None,
                            schema: None,
                        },
                    }],
                    include_schema,
                );
            }

            send_request_results(
                &uds,
                &security_plugin,
                &functional_group_name,
                &operation,
                exec_id,
                &fg_executions,
                include_schema,
            )
            .await
        }

        /// Sends `REQUEST_RESULTS` to the functional group, collects
        /// per-ECU responses, updates the stored execution state, and returns the
        /// aggregated `FgAsyncGetByIdResponse`.
        async fn send_request_results<T: UdsEcu + Clone>(
            uds: &T,
            security_plugin: &DynamicPlugin,
            functional_group_name: &str,
            operation: &str,
            exec_id: Uuid,
            fg_executions: &RwLock<HashMap<String, IndexMap<Uuid, FgServiceExecution>>>,
            include_schema: bool,
        ) -> Response {
            let results = uds
                .send_functional_group(
                    functional_group_name,
                    DiagComm {
                        name: operation.to_owned(),
                        type_: DiagCommType::Operations,
                        lookup_name: None,
                        subfunction_id: Some(subfunction_ids::routine::REQUEST_RESULTS),
                    },
                    security_plugin,
                    None,
                    true,
                )
                .await;

            // Collect per-ECU results.
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

            // Update stored execution state.
            let status = if errors.is_empty() {
                ExecutionStatus::Completed
            } else {
                ExecutionStatus::Running
            };
            {
                let mut guard = fg_executions.write().await;
                if let Some(op_map) = guard.get_mut(operation)
                    && let Some(exec) = op_map.get_mut(&exec_id)
                {
                    exec.parameters.clone_from(&response_data);
                    exec.status = status.clone();
                    exec.in_flight = false;
                }
            }

            fg_get_by_id_response(status, response_data, errors, include_schema)
        }

        pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
            op.description(
                "Get the result of an async functional group operation execution (RequestResults \
                 subfunction). Sends RequestResults to all ECUs in the group and returns \
                 aggregated per-ECU responses.",
            )
            .response_with::<200, Json<FgAsyncGetByIdResponse<VendorErrorCode>>, _>(|res| {
                res.description("Execution result retrieved successfully.")
            })
            .with(openapi::error_not_found)
            .with(openapi::error_bad_request)
            .with(openapi::error_forbidden)
            .with(openapi::error_conflict)
            .with(openapi::error_bad_gateway)
        }
    }

    #[cfg(test)]
    mod tests {
        use std::sync::Arc;

        use aide::UseApi;
        use axum::{body::Bytes, extract::State, http::StatusCode};
        use axum_extra::extract::WithRejection;
        use cda_interfaces::{
            DiagServiceError,
            datatypes::RoutineSubfunctions,
            diagservices::{DiagServiceJsonResponse, mock::MockDiagServiceResponse},
            mock::MockUdsEcu,
            subfunction_ids,
        };
        use cda_plugin_security::{Secured, mock::TestSecurityPlugin};
        use http::HeaderMap;
        use indexmap::IndexMap;
        use sovd_interfaces::components::ecu::operations::ExecutionStatus;
        use tokio::sync::RwLock;

        use super::*;
        use crate::sovd::{
            FgServiceExecution, functions::functional_groups::tests::create_test_fg_state,
            locks::insert_test_fg_lock,
        };

        fn make_post_headers() -> HeaderMap {
            let mut headers = HeaderMap::new();
            headers.insert(
                http::header::CONTENT_TYPE,
                "application/json".parse().unwrap(),
            );
            headers.insert(http::header::ACCEPT, "application/json".parse().unwrap());
            headers
        }

        fn make_empty_json_response() -> MockDiagServiceResponse {
            let mut mock = MockDiagServiceResponse::new();
            mock.expect_response_type()
                .returning(|| cda_interfaces::diagservices::DiagServiceResponseType::Positive);
            mock.expect_into_json().returning(|| {
                Ok(DiagServiceJsonResponse {
                    data: serde_json::Value::Object(serde_json::Map::new()),
                    errors: vec![],
                })
            });
            mock
        }

        fn make_query(
            include_schema: bool,
            suppress_service: bool,
        ) -> sovd_interfaces::functions::functional_groups::operations::service::Query {
            sovd_interfaces::functions::functional_groups::operations::service::Query {
                include_schema,
                suppress_service,
            }
        }

        fn make_delete_query(
            suppress_service: bool,
        ) -> sovd_interfaces::components::ecu::operations::OperationDeleteQuery {
            sovd_interfaces::components::ecu::operations::OperationDeleteQuery {
                include_schema: false,
                suppress_service,
                force: false,
            }
        }

        #[tokio::test]
        async fn test_fg_post_sync_operation_uses_start_and_returns_200() {
            let mut mock_uds = MockUdsEcu::new();

            mock_uds
                .expect_get_functional_group_routine_subfunctions()
                .withf(|_, fg, op| fg == "AllECUs" && op == "BrakeSelfTest")
                .times(1)
                .returning(|_, _, _| {
                    Ok(RoutineSubfunctions {
                        has_stop: false,
                        has_request_results: false,
                    })
                });

            mock_uds
                .expect_send_functional_group()
                .withf(|fg, service, _, _, _| {
                    fg == "AllECUs"
                        && service.subfunction_id == Some(subfunction_ids::routine::START)
                        && service.name == "BrakeSelfTest"
                })
                .times(1)
                .returning(|_, _, _, _, _| {
                    let mut results = cda_interfaces::HashMap::default();
                    results.insert("ECU1".to_string(), Ok(make_empty_json_response()));
                    results
                });

            let state = create_test_fg_state(mock_uds, "AllECUs".to_string());
            insert_test_fg_lock(&state.locks, "AllECUs").await;

            let response = post::<MockUdsEcu>(
                make_post_headers(),
                UseApi(
                    Secured(Box::new(TestSecurityPlugin)),
                    std::marker::PhantomData,
                ),
                UseApi(
                    axum_extra::extract::Host("localhost".to_string()),
                    std::marker::PhantomData,
                ),
                axum::extract::OriginalUri(
                    "/functions/functionalgroups/AllECUs/operations/BrakeSelfTest"
                        .parse()
                        .unwrap(),
                ),
                axum::extract::Path(crate::sovd::components::ecu::DiagServicePathParam {
                    service: "BrakeSelfTest".to_string(),
                }),
                WithRejection(
                    axum::extract::Query(make_query(false, false)),
                    std::marker::PhantomData,
                ),
                State(state),
                Bytes::from_static(b"{\"parameters\":{}}"),
            )
            .await;

            assert_eq!(response.status(), StatusCode::OK);
        }

        #[tokio::test]
        async fn test_fg_post_async_operation_returns_202_and_tracks_execution() {
            let mut mock_uds = MockUdsEcu::new();

            mock_uds
                .expect_get_functional_group_routine_subfunctions()
                .times(1)
                .returning(|_, _, _| {
                    Ok(RoutineSubfunctions {
                        has_stop: true,
                        has_request_results: false,
                    })
                });

            mock_uds
                .expect_send_functional_group()
                .times(1)
                .returning(|_, _, _, _, _| {
                    let mut results = cda_interfaces::HashMap::default();
                    results.insert("ECU1".to_string(), Ok(make_empty_json_response()));
                    results
                });

            let state = create_test_fg_state(mock_uds, "AllECUs".to_string());
            let fg_executions_ref = Arc::clone(&state.fg_executions);
            insert_test_fg_lock(&state.locks, "AllECUs").await;

            let response = post::<MockUdsEcu>(
                make_post_headers(),
                UseApi(
                    Secured(Box::new(TestSecurityPlugin)),
                    std::marker::PhantomData,
                ),
                UseApi(
                    axum_extra::extract::Host("localhost".to_string()),
                    std::marker::PhantomData,
                ),
                axum::extract::OriginalUri(
                    "/functions/functionalgroups/AllECUs/operations/BrakeSelfTest"
                        .parse()
                        .unwrap(),
                ),
                axum::extract::Path(crate::sovd::components::ecu::DiagServicePathParam {
                    service: "BrakeSelfTest".to_string(),
                }),
                WithRejection(
                    axum::extract::Query(make_query(false, false)),
                    std::marker::PhantomData,
                ),
                State(state),
                Bytes::from_static(b"{\"parameters\":{}}"),
            )
            .await;

            assert_eq!(response.status(), StatusCode::ACCEPTED);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(result.get("id").is_some(), "202 body must have id");
            assert_eq!(result.get("status"), Some(&serde_json::json!("running")));
            assert_eq!(
                fg_executions_ref
                    .read()
                    .await
                    .get("brakeselftest")
                    .map_or(0, IndexMap::len),
                1
            );
        }

        #[tokio::test]
        async fn test_fg_post_suppress_service_async_returns_202_without_uds_send() {
            let mut mock_uds = MockUdsEcu::new();

            mock_uds
                .expect_get_functional_group_routine_subfunctions()
                .times(0);
            // send_functional_group must NOT be called when suppress_service=true
            mock_uds.expect_send_functional_group().times(0);

            let state = create_test_fg_state(mock_uds, "AllECUs".to_string());
            let fg_executions_ref = Arc::clone(&state.fg_executions);
            insert_test_fg_lock(&state.locks, "AllECUs").await;

            let response = post::<MockUdsEcu>(
                make_post_headers(),
                UseApi(
                    Secured(Box::new(TestSecurityPlugin)),
                    std::marker::PhantomData,
                ),
                UseApi(
                    axum_extra::extract::Host("localhost".to_string()),
                    std::marker::PhantomData,
                ),
                axum::extract::OriginalUri(
                    "/functions/functionalgroups/AllECUs/operations/BrakeSelfTest"
                        .parse()
                        .unwrap(),
                ),
                axum::extract::Path(crate::sovd::components::ecu::DiagServicePathParam {
                    service: "BrakeSelfTest".to_string(),
                }),
                WithRejection(
                    axum::extract::Query(make_query(false, true)),
                    std::marker::PhantomData,
                ),
                State(state),
                Bytes::from_static(b"{\"parameters\":{}}"),
            )
            .await;

            assert_eq!(response.status(), StatusCode::ACCEPTED);
            assert_eq!(
                fg_executions_ref
                    .read()
                    .await
                    .get("brakeselftest")
                    .map_or(0, IndexMap::len),
                1
            );
        }

        #[tokio::test]
        async fn test_fg_post_operation_not_found_returns_error() {
            let mut mock_uds = MockUdsEcu::new();

            mock_uds
                .expect_get_functional_group_routine_subfunctions()
                .times(1)
                .returning(|_, _, op| {
                    Err(DiagServiceError::NotFound(format!(
                        "Routine '{op}' not found"
                    )))
                });

            // send_functional_group must NOT be called
            mock_uds.expect_send_functional_group().times(0);

            let state = create_test_fg_state(mock_uds, "AllECUs".to_string());
            insert_test_fg_lock(&state.locks, "AllECUs").await;

            let response = post::<MockUdsEcu>(
                make_post_headers(),
                UseApi(
                    Secured(Box::new(TestSecurityPlugin)),
                    std::marker::PhantomData,
                ),
                UseApi(
                    axum_extra::extract::Host("localhost".to_string()),
                    std::marker::PhantomData,
                ),
                axum::extract::OriginalUri(
                    "/functions/functionalgroups/AllECUs/operations/Unknown"
                        .parse()
                        .unwrap(),
                ),
                axum::extract::Path(crate::sovd::components::ecu::DiagServicePathParam {
                    service: "Unknown".to_string(),
                }),
                WithRejection(
                    axum::extract::Query(make_query(false, false)),
                    std::marker::PhantomData,
                ),
                State(state),
                Bytes::from_static(b"{\"parameters\":{}}"),
            )
            .await;

            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn test_fg_post_operation_returns_ecu_keyed_parameters() {
            let mut mock_uds = MockUdsEcu::new();

            mock_uds
                .expect_get_functional_group_routine_subfunctions()
                .times(1)
                .returning(|_, _, _| {
                    Ok(RoutineSubfunctions {
                        has_stop: false,
                        has_request_results: false,
                    })
                });

            mock_uds
                .expect_send_functional_group()
                .times(1)
                .returning(|_, _, _, _, _| {
                    let mut params = serde_json::Map::new();
                    params.insert("status".to_string(), serde_json::json!("ok"));
                    let mut mock = MockDiagServiceResponse::new();
                    mock.expect_response_type().returning(|| {
                        cda_interfaces::diagservices::DiagServiceResponseType::Positive
                    });
                    mock.expect_into_json().returning(move || {
                        Ok(DiagServiceJsonResponse {
                            data: serde_json::Value::Object(params.clone()),
                            errors: vec![],
                        })
                    });
                    let mut results = cda_interfaces::HashMap::default();
                    results.insert("ECU1".to_string(), Ok(mock));
                    results
                });

            let state = create_test_fg_state(mock_uds, "Safety".to_string());
            insert_test_fg_lock(&state.locks, "Safety").await;

            let response = post::<MockUdsEcu>(
                make_post_headers(),
                UseApi(
                    Secured(Box::new(TestSecurityPlugin)),
                    std::marker::PhantomData,
                ),
                UseApi(
                    axum_extra::extract::Host("localhost".to_string()),
                    std::marker::PhantomData,
                ),
                axum::extract::OriginalUri(
                    "/functions/functionalgroups/Safety/operations/BrakeSelfTest"
                        .parse()
                        .unwrap(),
                ),
                axum::extract::Path(crate::sovd::components::ecu::DiagServicePathParam {
                    service: "BrakeSelfTest".to_string(),
                }),
                WithRejection(
                    axum::extract::Query(make_query(false, false)),
                    std::marker::PhantomData,
                ),
                State(state),
                Bytes::from_static(b"{\"parameters\":{}}"),
            )
            .await;

            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(
                result
                    .get("errors")
                    .and_then(serde_json::Value::as_array)
                    .is_none_or(Vec::is_empty),
                "Expected no errors"
            );
            assert_eq!(
                result
                    .get("parameters")
                    .and_then(|p| p.get("ECU1"))
                    .and_then(|e| e.get("status")),
                Some(&serde_json::json!("ok"))
            );
        }

        #[tokio::test]
        async fn test_fg_post_operation_ecu_error_surfaces_in_errors() {
            let mut mock_uds = MockUdsEcu::new();

            mock_uds
                .expect_get_functional_group_routine_subfunctions()
                .times(1)
                .returning(|_, _, _| {
                    Ok(RoutineSubfunctions {
                        has_stop: false,
                        has_request_results: false,
                    })
                });

            mock_uds
                .expect_send_functional_group()
                .times(1)
                .returning(|_, _, _, _, _| {
                    let mut results = cda_interfaces::HashMap::default();
                    results.insert(
                        "ECU1".to_string(),
                        Err(DiagServiceError::NotFound("BrakeSelfTest".to_string())),
                    );
                    results
                });

            let state = create_test_fg_state(mock_uds, "AllECUs".to_string());
            insert_test_fg_lock(&state.locks, "AllECUs").await;

            let response = post::<MockUdsEcu>(
                make_post_headers(),
                UseApi(
                    Secured(Box::new(TestSecurityPlugin)),
                    std::marker::PhantomData,
                ),
                UseApi(
                    axum_extra::extract::Host("localhost".to_string()),
                    std::marker::PhantomData,
                ),
                axum::extract::OriginalUri(
                    "/functions/functionalgroups/AllECUs/operations/BrakeSelfTest"
                        .parse()
                        .unwrap(),
                ),
                axum::extract::Path(crate::sovd::components::ecu::DiagServicePathParam {
                    service: "BrakeSelfTest".to_string(),
                }),
                WithRejection(
                    axum::extract::Query(make_query(false, false)),
                    std::marker::PhantomData,
                ),
                State(state),
                Bytes::from_static(b"{\"parameters\":{}}"),
            )
            .await;

            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(
                result
                    .get("errors")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|e| !e.is_empty()),
                "Expected errors for ECU failure"
            );
            assert!(
                result
                    .get("parameters")
                    .and_then(serde_json::Value::as_object)
                    .is_none_or(serde_json::Map::is_empty)
            );
        }

        async fn insert_async_execution(
            fg_executions: &Arc<
                RwLock<cda_interfaces::HashMap<String, IndexMap<Uuid, FgServiceExecution>>>,
            >,
            operation: &str,
        ) -> Uuid {
            insert_async_execution_with_params(fg_executions, operation, HashMap::default()).await
        }

        async fn insert_async_execution_with_params(
            fg_executions: &Arc<
                RwLock<cda_interfaces::HashMap<String, IndexMap<Uuid, FgServiceExecution>>>,
            >,
            operation: &str,
            parameters: HashMap<String, serde_json::Map<String, serde_json::Value>>,
        ) -> Uuid {
            let id = Uuid::new_v4();
            fg_executions
                .write()
                .await
                .entry(operation.to_owned())
                .or_default()
                .insert(
                    id,
                    FgServiceExecution {
                        parameters,
                        status: ExecutionStatus::Running,
                        in_flight: false,
                    },
                );
            id
        }

        #[tokio::test]
        async fn test_fg_delete_no_lock_returns_forbidden() {
            let mock_uds = MockUdsEcu::new();
            // state has no lock set up
            let state = create_test_fg_state(mock_uds, "AllECUs".to_string());
            let exec_id = insert_async_execution(&state.fg_executions, "BrakeSelfTest").await;

            let response = delete::<MockUdsEcu>(
                UseApi(
                    Secured(Box::new(TestSecurityPlugin)),
                    std::marker::PhantomData,
                ),
                axum::extract::Path(OperationAndIdPathParam {
                    operation: "BrakeSelfTest".to_string(),
                    id: exec_id.to_string(),
                }),
                WithRejection(
                    axum::extract::Query(make_delete_query(false)),
                    std::marker::PhantomData,
                ),
                State(state),
            )
            .await;

            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }

        #[tokio::test]
        async fn test_fg_delete_execution_not_found_returns_404() {
            let mock_uds = MockUdsEcu::new();
            let state = create_test_fg_state(mock_uds, "AllECUs".to_string());
            insert_test_fg_lock(&state.locks, "AllECUs").await;

            let unknown_id = Uuid::new_v4();
            let response = delete::<MockUdsEcu>(
                UseApi(
                    Secured(Box::new(TestSecurityPlugin)),
                    std::marker::PhantomData,
                ),
                axum::extract::Path(OperationAndIdPathParam {
                    operation: "BrakeSelfTest".to_string(),
                    id: unknown_id.to_string(),
                }),
                WithRejection(
                    axum::extract::Query(make_delete_query(false)),
                    std::marker::PhantomData,
                ),
                State(state),
            )
            .await;

            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn test_fg_delete_all_ecus_succeed_returns_204() {
            let mut mock_uds = MockUdsEcu::new();

            mock_uds
                .expect_send_functional_group()
                .withf(|fg, service, _, _, _| {
                    fg == "AllECUs"
                        && service.subfunction_id == Some(subfunction_ids::routine::STOP)
                        && service.name == "BrakeSelfTest"
                })
                .times(1)
                .returning(|_, _, _, _, _| {
                    let mut results = cda_interfaces::HashMap::default();
                    results.insert("ECU1".to_string(), Ok(make_empty_json_response()));
                    results.insert("ECU2".to_string(), Ok(make_empty_json_response()));
                    results
                });

            let state = create_test_fg_state(mock_uds, "AllECUs".to_string());
            insert_test_fg_lock(&state.locks, "AllECUs").await;
            let exec_id = insert_async_execution(&state.fg_executions, "BrakeSelfTest").await;
            let fg_executions_ref = Arc::clone(&state.fg_executions);

            let response = delete::<MockUdsEcu>(
                UseApi(
                    Secured(Box::new(TestSecurityPlugin)),
                    std::marker::PhantomData,
                ),
                axum::extract::Path(OperationAndIdPathParam {
                    operation: "BrakeSelfTest".to_string(),
                    id: exec_id.to_string(),
                }),
                WithRejection(
                    axum::extract::Query(make_delete_query(false)),
                    std::marker::PhantomData,
                ),
                State(state),
            )
            .await;

            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            assert!(
                fg_executions_ref
                    .read()
                    .await
                    .get("BrakeSelfTest")
                    .is_none_or(IndexMap::is_empty),
                "execution should be removed"
            );
        }

        #[tokio::test]
        async fn test_fg_delete_partial_failure_force_true_removes_and_returns_200() {
            // force=true: even with partial failure the execution is removed and 200 returned
            let mut mock_uds = MockUdsEcu::new();

            mock_uds
                .expect_send_functional_group()
                .times(1)
                .returning(|_, _, _, _, _| {
                    let mut results = cda_interfaces::HashMap::default();
                    results.insert("ECU1".to_string(), Ok(make_empty_json_response()));
                    results.insert(
                        "ECU2".to_string(),
                        Err(DiagServiceError::SendFailed("timeout".to_string())),
                    );
                    results
                });

            let state = create_test_fg_state(mock_uds, "AllECUs".to_string());
            insert_test_fg_lock(&state.locks, "AllECUs").await;
            let exec_id = insert_async_execution(&state.fg_executions, "BrakeSelfTest").await;
            let fg_executions_ref = Arc::clone(&state.fg_executions);

            let response = delete::<MockUdsEcu>(
                UseApi(
                    Secured(Box::new(TestSecurityPlugin)),
                    std::marker::PhantomData,
                ),
                axum::extract::Path(OperationAndIdPathParam {
                    operation: "BrakeSelfTest".to_string(),
                    id: exec_id.to_string(),
                }),
                WithRejection(
                    axum::extract::Query(make_delete_query_with_force(false, true)),
                    std::marker::PhantomData,
                ),
                State(state),
            )
            .await;

            // force=true + partial failure -> 200 with errors, execution removed
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(
                result
                    .get("errors")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|e| !e.is_empty()),
                "Expected errors in partial failure response"
            );
            assert!(
                fg_executions_ref
                    .read()
                    .await
                    .get("BrakeSelfTest")
                    .is_none_or(IndexMap::is_empty),
                "execution should be removed"
            );
        }

        #[tokio::test]
        async fn test_fg_delete_suppress_service_returns_204_without_uds_send() {
            let mut mock_uds = MockUdsEcu::new();
            // send_functional_group must NOT be called
            mock_uds.expect_send_functional_group().times(0);

            let state = create_test_fg_state(mock_uds, "AllECUs".to_string());
            insert_test_fg_lock(&state.locks, "AllECUs").await;
            let exec_id = insert_async_execution(&state.fg_executions, "BrakeSelfTest").await;
            let fg_executions_ref = Arc::clone(&state.fg_executions);

            let response = delete::<MockUdsEcu>(
                UseApi(
                    Secured(Box::new(TestSecurityPlugin)),
                    std::marker::PhantomData,
                ),
                axum::extract::Path(OperationAndIdPathParam {
                    operation: "BrakeSelfTest".to_string(),
                    id: exec_id.to_string(),
                }),
                WithRejection(
                    axum::extract::Query(make_delete_query(true)),
                    std::marker::PhantomData,
                ),
                State(state),
            )
            .await;

            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            assert!(
                fg_executions_ref
                    .read()
                    .await
                    .get("BrakeSelfTest")
                    .is_none_or(IndexMap::is_empty),
                "execution should be removed"
            );
        }

        #[tokio::test]
        async fn test_fg_post_async_via_request_results_only_returns_202() {
            // has_stop=false, has_request_results=true -> must be treated as async (202)
            let mut mock_uds = MockUdsEcu::new();

            mock_uds
                .expect_get_functional_group_routine_subfunctions()
                .times(1)
                .returning(|_, _, _| {
                    Ok(RoutineSubfunctions {
                        has_stop: false,
                        has_request_results: true,
                    })
                });

            mock_uds
                .expect_send_functional_group()
                .times(1)
                .returning(|_, _, _, _, _| {
                    let mut results = cda_interfaces::HashMap::default();
                    results.insert("ECU1".to_string(), Ok(make_empty_json_response()));
                    results
                });

            let state = create_test_fg_state(mock_uds, "AllECUs".to_string());
            let fg_executions_ref = Arc::clone(&state.fg_executions);
            insert_test_fg_lock(&state.locks, "AllECUs").await;

            let response = post::<MockUdsEcu>(
                make_post_headers(),
                UseApi(
                    Secured(Box::new(TestSecurityPlugin)),
                    std::marker::PhantomData,
                ),
                UseApi(
                    axum_extra::extract::Host("localhost".to_string()),
                    std::marker::PhantomData,
                ),
                axum::extract::OriginalUri(
                    "/functions/functionalgroups/AllECUs/operations/SomeDiag"
                        .parse()
                        .unwrap(),
                ),
                axum::extract::Path(crate::sovd::components::ecu::DiagServicePathParam {
                    service: "SomeDiag".to_string(),
                }),
                WithRejection(
                    axum::extract::Query(make_query(false, false)),
                    std::marker::PhantomData,
                ),
                State(state),
                Bytes::from_static(b"{\"parameters\":{}}"),
            )
            .await;

            assert_eq!(response.status(), StatusCode::ACCEPTED);
            assert_eq!(
                fg_executions_ref
                    .read()
                    .await
                    .get("somediag")
                    .map_or(0, IndexMap::len),
                1,
                "execution should be tracked"
            );
        }

        #[tokio::test]
        async fn test_fg_post_conflict_when_running_execution_exists() {
            let mock_uds = MockUdsEcu::new();
            // No UDS expectations needed - conflict is checked before any UDS call.

            let state = create_test_fg_state(mock_uds, "AllECUs".to_string());
            insert_test_fg_lock(&state.locks, "AllECUs").await;

            // Pre-populate a running execution for BrakeSelfTest
            insert_async_execution(&state.fg_executions, "brakeselftest").await;

            let response = post::<MockUdsEcu>(
                make_post_headers(),
                UseApi(
                    Secured(Box::new(TestSecurityPlugin)),
                    std::marker::PhantomData,
                ),
                UseApi(
                    axum_extra::extract::Host("localhost".to_string()),
                    std::marker::PhantomData,
                ),
                axum::extract::OriginalUri(
                    "/functions/functionalgroups/AllECUs/operations/BrakeSelfTest"
                        .parse()
                        .unwrap(),
                ),
                axum::extract::Path(crate::sovd::components::ecu::DiagServicePathParam {
                    service: "BrakeSelfTest".to_string(),
                }),
                WithRejection(
                    axum::extract::Query(make_query(false, false)),
                    std::marker::PhantomData,
                ),
                State(state),
                Bytes::from_static(b"{\"parameters\":{}}"),
            )
            .await;

            assert_eq!(response.status(), StatusCode::CONFLICT);
        }

        #[tokio::test]
        async fn test_fg_post_no_conflict_for_different_operation() {
            // A running execution for OperationA must NOT block OperationB
            let mut mock_uds = MockUdsEcu::new();

            mock_uds
                .expect_get_functional_group_routine_subfunctions()
                .times(1)
                .returning(|_, _, _| {
                    Ok(RoutineSubfunctions {
                        has_stop: false,
                        has_request_results: false,
                    })
                });

            mock_uds
                .expect_send_functional_group()
                .times(1)
                .returning(|_, _, _, _, _| {
                    let mut results = cda_interfaces::HashMap::default();
                    let mut mock = MockDiagServiceResponse::new();
                    mock.expect_response_type().returning(|| {
                        cda_interfaces::diagservices::DiagServiceResponseType::Positive
                    });
                    mock.expect_into_json().returning(|| {
                        Ok(DiagServiceJsonResponse {
                            data: serde_json::Value::Object(serde_json::Map::new()),
                            errors: vec![],
                        })
                    });
                    results.insert("ECU1".to_string(), Ok(mock));
                    results
                });

            let state = create_test_fg_state(mock_uds, "AllECUs".to_string());
            insert_test_fg_lock(&state.locks, "AllECUs").await;

            // Pre-populate a running execution for a DIFFERENT operation
            insert_async_execution(&state.fg_executions, "otherservice").await;

            let response = post::<MockUdsEcu>(
                make_post_headers(),
                UseApi(
                    Secured(Box::new(TestSecurityPlugin)),
                    std::marker::PhantomData,
                ),
                UseApi(
                    axum_extra::extract::Host("localhost".to_string()),
                    std::marker::PhantomData,
                ),
                axum::extract::OriginalUri(
                    "/functions/functionalgroups/AllECUs/operations/BrakeSelfTest"
                        .parse()
                        .unwrap(),
                ),
                axum::extract::Path(crate::sovd::components::ecu::DiagServicePathParam {
                    service: "BrakeSelfTest".to_string(),
                }),
                WithRejection(
                    axum::extract::Query(make_query(false, false)),
                    std::marker::PhantomData,
                ),
                State(state),
                Bytes::from_static(b"{\"parameters\":{}}"),
            )
            .await;

            // Different operation -> no conflict, should succeed
            assert_eq!(response.status(), StatusCode::OK);
        }

        fn make_delete_query_with_force(
            suppress_service: bool,
            force: bool,
        ) -> sovd_interfaces::components::ecu::operations::OperationDeleteQuery {
            sovd_interfaces::components::ecu::operations::OperationDeleteQuery {
                include_schema: false,
                suppress_service,
                force,
            }
        }

        #[tokio::test]
        async fn test_fg_delete_partial_failure_force_false_keeps_execution() {
            // force=false and Stop fails on one ECU -> execution NOT removed, 200 with errors
            let mut mock_uds = MockUdsEcu::new();

            mock_uds
                .expect_send_functional_group()
                .times(1)
                .returning(|_, _, _, _, _| {
                    let mut results = cda_interfaces::HashMap::default();
                    results.insert("ECU1".to_string(), Ok(make_empty_json_response()));
                    results.insert(
                        "ECU2".to_string(),
                        Err(DiagServiceError::SendFailed("timeout".to_string())),
                    );
                    results
                });

            let state = create_test_fg_state(mock_uds, "AllECUs".to_string());
            insert_test_fg_lock(&state.locks, "AllECUs").await;
            let exec_id = insert_async_execution(&state.fg_executions, "BrakeSelfTest").await;
            let fg_executions_ref = Arc::clone(&state.fg_executions);

            let response = delete::<MockUdsEcu>(
                UseApi(
                    Secured(Box::new(TestSecurityPlugin)),
                    std::marker::PhantomData,
                ),
                axum::extract::Path(OperationAndIdPathParam {
                    operation: "BrakeSelfTest".to_string(),
                    id: exec_id.to_string(),
                }),
                WithRejection(
                    axum::extract::Query(make_delete_query_with_force(false, false)),
                    std::marker::PhantomData,
                ),
                State(state),
            )
            .await;

            // force=false -> execution must survive for retry
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(
                result
                    .get("errors")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|e| !e.is_empty()),
                "Expected errors in response"
            );
            let guard = fg_executions_ref.read().await;
            let op_map = guard
                .get("BrakeSelfTest")
                .expect("operation map must exist");
            assert!(
                !op_map.is_empty(),
                "execution must NOT be removed when force=false and Stop fails"
            );
            // in_flight must be reset so the execution can be retried
            assert!(
                !op_map.get(&exec_id).unwrap().in_flight,
                "in_flight must be reset to false"
            );
        }

        #[tokio::test]
        async fn test_fg_delete_partial_failure_force_true_removes_execution() {
            // force=true and Stop fails on one ECU -> execution IS removed, 200 with errors
            let mut mock_uds = MockUdsEcu::new();

            mock_uds
                .expect_send_functional_group()
                .times(1)
                .returning(|_, _, _, _, _| {
                    let mut results = cda_interfaces::HashMap::default();
                    results.insert("ECU1".to_string(), Ok(make_empty_json_response()));
                    results.insert(
                        "ECU2".to_string(),
                        Err(DiagServiceError::SendFailed("timeout".to_string())),
                    );
                    results
                });

            let state = create_test_fg_state(mock_uds, "AllECUs".to_string());
            insert_test_fg_lock(&state.locks, "AllECUs").await;
            let exec_id = insert_async_execution(&state.fg_executions, "BrakeSelfTest").await;
            let fg_executions_ref = Arc::clone(&state.fg_executions);

            let response = delete::<MockUdsEcu>(
                UseApi(
                    Secured(Box::new(TestSecurityPlugin)),
                    std::marker::PhantomData,
                ),
                axum::extract::Path(OperationAndIdPathParam {
                    operation: "BrakeSelfTest".to_string(),
                    id: exec_id.to_string(),
                }),
                WithRejection(
                    axum::extract::Query(make_delete_query_with_force(false, true)),
                    std::marker::PhantomData,
                ),
                State(state),
            )
            .await;

            // force=true -> execution removed, errors still surfaced
            assert_eq!(response.status(), StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(
                result
                    .get("errors")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|e| !e.is_empty()),
                "Expected errors in response"
            );
            assert!(
                fg_executions_ref
                    .read()
                    .await
                    .get("BrakeSelfTest")
                    .is_none_or(IndexMap::is_empty),
                "execution must be removed when force=true"
            );
        }

        fn make_get_query(
            include_schema: bool,
            suppress_service: bool,
        ) -> sovd_interfaces::common::operations::OperationQuery {
            sovd_interfaces::common::operations::OperationQuery {
                include_schema,
                suppress_service,
            }
        }

        #[tokio::test]
        async fn test_fg_get_by_id_sends_request_results_and_returns_200() {
            let mut mock_uds = MockUdsEcu::new();

            mock_uds
                .expect_get_functional_group_routine_subfunctions()
                .times(1)
                .returning(|_, _, _| {
                    Ok(RoutineSubfunctions {
                        has_stop: true,
                        has_request_results: true,
                    })
                });

            mock_uds
                .expect_send_functional_group()
                .withf(|fg, service, _, _, _| {
                    fg == "AllECUs"
                        && service.subfunction_id == Some(subfunction_ids::routine::REQUEST_RESULTS)
                        && service.name == "BrakeSelfTest"
                })
                .times(1)
                .returning(|_, _, _, _, _| {
                    let mut params = serde_json::Map::new();
                    params.insert("result".to_string(), serde_json::json!("pass"));
                    let mut mock = MockDiagServiceResponse::new();
                    mock.expect_response_type().returning(|| {
                        cda_interfaces::diagservices::DiagServiceResponseType::Positive
                    });
                    mock.expect_into_json().returning(move || {
                        Ok(DiagServiceJsonResponse {
                            data: serde_json::Value::Object(params.clone()),
                            errors: vec![],
                        })
                    });
                    let mut results = cda_interfaces::HashMap::default();
                    results.insert("ECU1".to_string(), Ok(mock));
                    results
                });

            let state = create_test_fg_state(mock_uds, "AllECUs".to_string());
            insert_test_fg_lock(&state.locks, "AllECUs").await;
            let exec_id = insert_async_execution(&state.fg_executions, "BrakeSelfTest").await;
            let fg_executions_ref = Arc::clone(&state.fg_executions);

            let response = id::get::<MockUdsEcu>(
                UseApi(
                    Secured(Box::new(TestSecurityPlugin)),
                    std::marker::PhantomData,
                ),
                axum::extract::Path(OperationAndIdPathParam {
                    operation: "BrakeSelfTest".to_string(),
                    id: exec_id.to_string(),
                }),
                WithRejection(
                    axum::extract::Query(make_get_query(false, false)),
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
            assert_eq!(result.get("status"), Some(&serde_json::json!("completed")));
            assert_eq!(
                result
                    .get("parameters")
                    .and_then(|p| p.get("ECU1"))
                    .and_then(|e| e.get("result")),
                Some(&serde_json::json!("pass"))
            );
            // Verify stored execution was updated to Completed
            let guard = fg_executions_ref.read().await;
            let exec = guard
                .get("BrakeSelfTest")
                .and_then(|m| m.get(&exec_id))
                .expect("execution must still exist");
            assert_eq!(exec.status, ExecutionStatus::Completed);
            assert!(!exec.in_flight, "in_flight must be reset");
            // Verify stored parameters are ECU-keyed
            assert_eq!(
                exec.parameters.get("ECU1").and_then(|m| m.get("result")),
                Some(&serde_json::json!("pass")),
                "stored params must be ECU-keyed after RequestResults"
            );
        }

        #[tokio::test]
        async fn test_fg_get_by_id_suppress_service_returns_stored_state() {
            let mock_uds = MockUdsEcu::new();
            // send_functional_group must NOT be called
            // (MockUdsEcu has no expectation set, so it would panic if called)

            let state = create_test_fg_state(mock_uds, "AllECUs".to_string());
            insert_test_fg_lock(&state.locks, "AllECUs").await;

            // Seed with real ECU-keyed parameters so we can assert round-trip.
            let mut ecu1_params = serde_json::Map::new();
            ecu1_params.insert("speed".to_string(), serde_json::json!(42));
            let mut ecu2_params = serde_json::Map::new();
            ecu2_params.insert("temp".to_string(), serde_json::json!(90));
            let mut params = HashMap::default();
            params.insert("ECU1".to_string(), ecu1_params);
            params.insert("ECU2".to_string(), ecu2_params);

            let exec_id =
                insert_async_execution_with_params(&state.fg_executions, "BrakeSelfTest", params)
                    .await;

            let response = id::get::<MockUdsEcu>(
                UseApi(
                    Secured(Box::new(TestSecurityPlugin)),
                    std::marker::PhantomData,
                ),
                axum::extract::Path(OperationAndIdPathParam {
                    operation: "BrakeSelfTest".to_string(),
                    id: exec_id.to_string(),
                }),
                WithRejection(
                    axum::extract::Query(make_get_query(false, true)),
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
                result.get("status"),
                Some(&serde_json::json!("running")),
                "suppress_service should return current stored status"
            );
            // Verify ECU-keyed parameters round-trip correctly.
            assert_eq!(
                result
                    .get("parameters")
                    .and_then(|p| p.get("ECU1"))
                    .and_then(|e| e.get("speed")),
                Some(&serde_json::json!(42)),
                "ECU1 stored params must round-trip"
            );
            assert_eq!(
                result
                    .get("parameters")
                    .and_then(|p| p.get("ECU2"))
                    .and_then(|e| e.get("temp")),
                Some(&serde_json::json!(90)),
                "ECU2 stored params must round-trip"
            );
        }

        #[tokio::test]
        async fn test_fg_get_by_id_not_found_returns_404() {
            let mock_uds = MockUdsEcu::new();
            let state = create_test_fg_state(mock_uds, "AllECUs".to_string());
            insert_test_fg_lock(&state.locks, "AllECUs").await;

            let unknown_id = Uuid::new_v4();
            let response = id::get::<MockUdsEcu>(
                UseApi(
                    Secured(Box::new(TestSecurityPlugin)),
                    std::marker::PhantomData,
                ),
                axum::extract::Path(OperationAndIdPathParam {
                    operation: "BrakeSelfTest".to_string(),
                    id: unknown_id.to_string(),
                }),
                WithRejection(
                    axum::extract::Query(make_get_query(false, false)),
                    std::marker::PhantomData,
                ),
                State(state),
            )
            .await;

            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn test_fg_get_by_id_partial_errors_keeps_running() {
            let mut mock_uds = MockUdsEcu::new();

            mock_uds
                .expect_get_functional_group_routine_subfunctions()
                .times(1)
                .returning(|_, _, _| {
                    Ok(RoutineSubfunctions {
                        has_stop: true,
                        has_request_results: true,
                    })
                });

            mock_uds
                .expect_send_functional_group()
                .times(1)
                .returning(|_, _, _, _, _| {
                    let mut results = cda_interfaces::HashMap::default();
                    results.insert("ECU1".to_string(), Ok(make_empty_json_response()));
                    results.insert(
                        "ECU2".to_string(),
                        Err(DiagServiceError::SendFailed("timeout".to_string())),
                    );
                    results
                });

            let state = create_test_fg_state(mock_uds, "AllECUs".to_string());
            insert_test_fg_lock(&state.locks, "AllECUs").await;
            let exec_id = insert_async_execution(&state.fg_executions, "BrakeSelfTest").await;
            let fg_executions_ref = Arc::clone(&state.fg_executions);

            let response = id::get::<MockUdsEcu>(
                UseApi(
                    Secured(Box::new(TestSecurityPlugin)),
                    std::marker::PhantomData,
                ),
                axum::extract::Path(OperationAndIdPathParam {
                    operation: "BrakeSelfTest".to_string(),
                    id: exec_id.to_string(),
                }),
                WithRejection(
                    axum::extract::Query(make_get_query(false, false)),
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
            // Partial errors -> status stays running (retryable)
            assert_eq!(
                result.get("status"),
                Some(&serde_json::json!("running")),
                "partial ECU errors should keep status as running"
            );
            assert!(
                result
                    .get("errors")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|e| !e.is_empty()),
                "Expected errors for ECU2 failure"
            );
            // Verify stored execution is still Running and in_flight is reset
            let guard = fg_executions_ref.read().await;
            let exec = guard
                .get("BrakeSelfTest")
                .and_then(|m| m.get(&exec_id))
                .expect("execution must still exist");
            assert_eq!(exec.status, ExecutionStatus::Running);
            assert!(!exec.in_flight, "in_flight must be reset");
            // Verify stored params contain the successful ECU's data (ECU-keyed)
            assert!(
                exec.parameters.contains_key("ECU1"),
                "successful ECU1 params must be stored"
            );
        }

        #[tokio::test]
        async fn test_fg_get_by_id_no_request_results_returns_status_with_error() {
            let mut mock_uds = MockUdsEcu::new();

            mock_uds
                .expect_get_functional_group_routine_subfunctions()
                .withf(|_, fg, op| fg == "AllECUs" && op == "BrakeSelfTest")
                .times(1)
                .returning(|_, _, _| {
                    Ok(RoutineSubfunctions {
                        has_stop: true,
                        has_request_results: false,
                    })
                });

            // send_functional_group must NOT be called
            mock_uds.expect_send_functional_group().times(0);

            let state = create_test_fg_state(mock_uds, "AllECUs".to_string());
            insert_test_fg_lock(&state.locks, "AllECUs").await;
            let exec_id = insert_async_execution(&state.fg_executions, "BrakeSelfTest").await;
            let fg_executions_ref = Arc::clone(&state.fg_executions);

            let response = id::get::<MockUdsEcu>(
                UseApi(
                    Secured(Box::new(TestSecurityPlugin)),
                    std::marker::PhantomData,
                ),
                axum::extract::Path(OperationAndIdPathParam {
                    operation: "BrakeSelfTest".to_string(),
                    id: exec_id.to_string(),
                }),
                WithRejection(
                    axum::extract::Query(make_get_query(false, false)),
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

            // Must include execution status
            assert_eq!(
                result.get("status"),
                Some(&serde_json::json!("running")),
                "response must include execution status"
            );

            // Must include an errors array with a DataError at path "/"
            let errors = result
                .get("errors")
                .and_then(serde_json::Value::as_array)
                .expect("response must contain 'errors' array");
            assert_eq!(errors.len(), 1, "expected exactly one error entry");
            let data_error = errors.first().expect("error entry must exist");
            assert_eq!(
                data_error.get("path"),
                Some(&serde_json::json!("/")),
                "error path must be '/'"
            );
            let message = data_error
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            assert!(
                message.contains("RequestResults"),
                "Error message should mention RequestResults, got: {message}"
            );

            // Verify in_flight was reset so the execution is still usable
            let guard = fg_executions_ref.read().await;
            let exec = guard
                .get("BrakeSelfTest")
                .and_then(|m| m.get(&exec_id))
                .expect("execution must still exist");
            assert!(!exec.in_flight, "in_flight must be reset");
        }
    }
}

#[cfg(test)]
mod tests {
    use aide::UseApi;
    use axum::{extract::State, http::StatusCode};
    use axum_extra::extract::WithRejection;
    use cda_interfaces::{datatypes::ComponentOperationsInfo, mock::MockUdsEcu};
    use cda_plugin_security::{Secured, mock::TestSecurityPlugin};
    use sovd_interfaces::functions::functional_groups::operations::OperationCollectionItem;

    use super::*;
    use crate::sovd::functions::functional_groups::tests::create_test_fg_state;

    #[tokio::test]
    async fn test_get_fg_operations_empty() {
        let mut mock_uds = MockUdsEcu::new();

        mock_uds
            .expect_get_functional_group_operations_info()
            .withf(|_, fg| fg == "AllECUs")
            .times(1)
            .returning(|_, _| Ok(vec![]));

        let state = create_test_fg_state(mock_uds, "AllECUs".to_string());

        let response = get::<MockUdsEcu>(
            UseApi(
                Secured(Box::new(TestSecurityPlugin)),
                std::marker::PhantomData,
            ),
            WithRejection(
                axum::extract::Query(
                    sovd_interfaces::functions::functional_groups::operations::get::Query {
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
        let result: sovd_interfaces::Items<OperationCollectionItem> =
            serde_json::from_slice(&body).unwrap();
        assert!(result.items.is_empty());
        assert!(result.schema.is_none());
    }

    #[tokio::test]
    async fn test_get_fg_operations_returns_items() {
        let mut mock_uds = MockUdsEcu::new();

        mock_uds
            .expect_get_functional_group_operations_info()
            .times(1)
            .returning(|_, _| {
                Ok(vec![
                    ComponentOperationsInfo {
                        id: "BrakeSelfTest".to_string(),
                        name: "Brake Self Test".to_string(),
                        has_stop: true,
                        has_request_results: true,
                    },
                    ComponentOperationsInfo {
                        id: "AirbagDeploy".to_string(),
                        name: "Airbag Deploy Test".to_string(),
                        has_stop: false,
                        has_request_results: false,
                    },
                ])
            });

        let state = create_test_fg_state(mock_uds, "Safety".to_string());

        let response = get::<MockUdsEcu>(
            UseApi(
                Secured(Box::new(TestSecurityPlugin)),
                std::marker::PhantomData,
            ),
            WithRejection(
                axum::extract::Query(
                    sovd_interfaces::functions::functional_groups::operations::get::Query {
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
        let result: sovd_interfaces::Items<OperationCollectionItem> =
            serde_json::from_slice(&body).unwrap();
        assert_eq!(result.items.len(), 2);
        assert_eq!(
            result.items.first().expect("Expected BrakeSelfTest").id,
            "BrakeSelfTest"
        );
        assert_eq!(
            result.items.first().expect("Expected BrakeSelfTest").name,
            "Brake Self Test"
        );
        assert_eq!(
            result.items.get(1).expect("Expected AirbagDeploy").id,
            "AirbagDeploy"
        );
    }

    #[tokio::test]
    async fn test_get_fg_operations_with_schema() {
        let mut mock_uds = MockUdsEcu::new();

        mock_uds
            .expect_get_functional_group_operations_info()
            .times(1)
            .returning(|_, _| Ok(vec![]));

        let state = create_test_fg_state(mock_uds, "Powertrain".to_string());

        let response = get::<MockUdsEcu>(
            UseApi(
                Secured(Box::new(TestSecurityPlugin)),
                std::marker::PhantomData,
            ),
            WithRejection(
                axum::extract::Query(
                    sovd_interfaces::functions::functional_groups::operations::get::Query {
                        include_schema: true,
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
        let result: sovd_interfaces::Items<OperationCollectionItem> =
            serde_json::from_slice(&body).unwrap();
        assert!(
            result.schema.is_some(),
            "Schema should be present when requested"
        );
    }
}
