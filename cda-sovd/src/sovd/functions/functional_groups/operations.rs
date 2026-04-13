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
            ServiceExecution,
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
        fg_executions: &RwLock<IndexMap<Uuid, ServiceExecution>>,
        response_data: HashMap<String, serde_json::Map<String, serde_json::Value>>,
        host: &str,
        uri: &Uri,
        include_schema: bool,
    ) -> Response {
        // Flatten all per-ECU START parameters into a single map for storage.
        let stored_params: serde_json::Map<String, serde_json::Value> =
            response_data.into_values().flatten().collect();

        let id = Uuid::new_v4();
        fg_executions.write().await.insert(
            id,
            ServiceExecution {
                parameters: stored_params,
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

    // cannot easily combine the axum extractors without creating a new custom extractor.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn post<T: UdsEcu + Clone>(
        headers: HeaderMap,
        UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
        UseApi(Host(host), _): UseApi<Host, String>,
        OriginalUri(uri): OriginalUri,
        Path(DiagServicePathParam {
            diag_service: operation,
        }): Path<DiagServicePathParam>,
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
            build_async_response(&fg_executions, response_data, &host, &uri, include_schema).await
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

        {
            let mut guard = fg_executions.write().await;
            match guard.get_mut(&exec_id) {
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
                Some(exec) => exec.in_flight = true,
            }
        }

        // If suppress_service, skip sending STOP to ECUs — just remove and return 204.
        if suppress_service {
            tracing::warn!(
                operation = %operation,
                exec_id = %exec_id,
                "Stop skipped (suppress_service=true), removing execution"
            );
            fg_executions.write().await.shift_remove(&exec_id);
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
            // All ECUs succeeded — remove execution and return 204.
            fg_executions.write().await.shift_remove(&exec_id);
            StatusCode::NO_CONTENT.into_response()
        } else if query.force {
            // force=true — remove execution even though Stop had errors, return 200 with errors.
            fg_executions.write().await.shift_remove(&exec_id);
            build_operation_response(response_data, errors, include_schema)
        } else {
            // force=false and Stop had errors — reset in_flight, keep execution alive for retry.
            if let Some(exec) = fg_executions.write().await.get_mut(&exec_id) {
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
            ServiceExecution, functions::functional_groups::tests::create_test_fg_state,
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
                    diag_service: "BrakeSelfTest".to_string(),
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
                    diag_service: "BrakeSelfTest".to_string(),
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
            assert_eq!(fg_executions_ref.read().await.len(), 1);
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
                    diag_service: "BrakeSelfTest".to_string(),
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
            assert_eq!(fg_executions_ref.read().await.len(), 1);
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
                    diag_service: "Unknown".to_string(),
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
                    diag_service: "BrakeSelfTest".to_string(),
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
                    diag_service: "BrakeSelfTest".to_string(),
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

        // ── DELETE: Stop ──────────────────────────────────────────────────────

        async fn seed_execution_async(
            fg_executions: &Arc<RwLock<IndexMap<Uuid, ServiceExecution>>>,
        ) -> Uuid {
            let id = Uuid::new_v4();
            fg_executions.write().await.insert(
                id,
                ServiceExecution {
                    parameters: serde_json::Map::new(),
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
            let exec_id = seed_execution_async(&state.fg_executions).await;

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
            let exec_id = seed_execution_async(&state.fg_executions).await;
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
                fg_executions_ref.read().await.is_empty(),
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
            let exec_id = seed_execution_async(&state.fg_executions).await;
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
                fg_executions_ref.read().await.is_empty(),
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
            let exec_id = seed_execution_async(&state.fg_executions).await;
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
                fg_executions_ref.read().await.is_empty(),
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
                    diag_service: "SomeDiag".to_string(),
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
                fg_executions_ref.read().await.len(),
                1,
                "execution should be tracked"
            );
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
            let exec_id = seed_execution_async(&state.fg_executions).await;
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
            assert!(
                !fg_executions_ref.read().await.is_empty(),
                "execution must NOT be removed when force=false and Stop fails"
            );
            // in_flight must be reset so the execution can be retried
            assert!(
                !fg_executions_ref
                    .read()
                    .await
                    .get(&exec_id)
                    .unwrap()
                    .in_flight,
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
            let exec_id = seed_execution_async(&state.fg_executions).await;
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
                fg_executions_ref.read().await.is_empty(),
                "execution must be removed when force=true"
            );
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
