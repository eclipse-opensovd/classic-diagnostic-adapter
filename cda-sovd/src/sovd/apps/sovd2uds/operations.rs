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

pub(crate) mod runtimefilesupdate {
    use aide::UseApi;
    use axum::{
        Json,
        extract::State,
        http::{StatusCode, header::LOCATION},
        response::IntoResponse,
    };
    use cda_interfaces::{
        http_protection::registry::{HttpMethod, HttpRouteMatcher},
        runtime_update_api::{LockStateProvider, RuntimeFilesUpdatePlugin},
    };
    use cda_plugin_security::Secured;
    use opensovd_axum_extra::ExtractHost;
    use sovd_interfaces::{
        apps::sovd2uds::operations::runtimefilesupdate::ExecutionRequest,
        common::operations::{ExecutionCreatedResponse, ExecutionListResponse},
    };

    use crate::sovd::apps::sovd2uds::bulk_data::runtimefiles::{
        DbUpdateErrorResponse, RuntimeUpdateRouteState, require_vehicle_lock,
    };

    /// Name of the operation in the operations collection.
    pub(crate) const OPERATION_ID: &str = "runtimefilesupdate";

    /// Display name in the operations collection.
    pub(crate) const COLLECTION_NAME: &str = "Runtime files update";

    const EXECUTIONS_ROUTE: &str =
        "/vehicle/v15/apps/sovd2uds/operations/runtimefilesupdate/executions";
    const EXECUTIONS_ID_ROUTE: &str =
        "/vehicle/v15/apps/sovd2uds/operations/runtimefilesupdate/executions/{id}";

    pub(crate) async fn get<P: RuntimeFilesUpdatePlugin, L: LockStateProvider>(
        State(route_state): State<RuntimeUpdateRouteState<P, L>>,
    ) -> impl IntoResponse {
        let items = route_state
            .plugin
            .list_executions()
            .await
            .into_iter()
            .map(|exec| sovd_interfaces::common::operations::OperationIdItem { id: exec.id })
            .collect();
        (StatusCode::OK, Json(ExecutionListResponse { items })).into_response()
    }

    pub(crate) async fn post<P: RuntimeFilesUpdatePlugin, L: LockStateProvider>(
        State(route_state): State<RuntimeUpdateRouteState<P, L>>,
        UseApi(ExtractHost(host), _): UseApi<ExtractHost, String>,
        Secured(sec_plugin): Secured,
        Json(body): Json<ExecutionRequest>,
    ) -> impl IntoResponse {
        let claims = sec_plugin.as_auth_plugin().claims();
        if let Err(resp) = require_vehicle_lock(
            &*route_state.vehicle_lock_states,
            *claims,
            route_state.retry_after,
        )
        .await
        {
            return resp.into_response();
        }

        route_state
            .plugin
            .start_execution(body.parameters.mode)
            .await
            .map_or_else(
                |e| DbUpdateErrorResponse::new(e, route_state.retry_after).into_response(),
                |id| {
                    let location = format!("http://{host}{EXECUTIONS_ROUTE}/{id}");
                    (
                        StatusCode::ACCEPTED,
                        [(LOCATION, location)],
                        Json(ExecutionCreatedResponse { id }),
                    )
                        .into_response()
                },
            )
    }

    pub(crate) mod id {
        use axum::{
            Json,
            extract::{Path, Query, State},
            http::StatusCode,
            response::IntoResponse,
        };
        use axum_extra::extract::WithRejection;
        use cda_interfaces::runtime_update_api::{LockStateProvider, RuntimeFilesUpdatePlugin};
        use sovd_interfaces::apps::sovd2uds::operations::runtimefilesupdate::ExecutionResponse;

        use crate::sovd::{
            apps::sovd2uds::bulk_data::runtimefiles::RuntimeUpdateRouteState, error::ApiError,
        };

        pub(crate) async fn get<P: RuntimeFilesUpdatePlugin, L: LockStateProvider>(
            State(route_state): State<RuntimeUpdateRouteState<P, L>>,
            Path(id): Path<String>,
            WithRejection(Query(query), _): WithRejection<
                Query<sovd_interfaces::IncludeSchemaQuery>,
                ApiError,
            >,
        ) -> impl IntoResponse {
            match route_state.plugin.get_execution_status(&id).await {
                Some(exec) => {
                    let mut resp = ExecutionResponse::from(exec);
                    if query.include_schema {
                        resp.schema = Some(crate::create_schema!(ExecutionResponse));
                    }
                    (StatusCode::OK, Json(resp)).into_response()
                }
                None => StatusCode::NOT_FOUND.into_response(),
            }
        }
    }

    pub fn routes<
        S: cda_plugin_security::SecurityPluginLoader,
        P: RuntimeFilesUpdatePlugin,
        L: LockStateProvider,
    >(
        state: RuntimeUpdateRouteState<P, L>,
    ) -> axum::Router {
        axum::Router::new()
            .route(
                EXECUTIONS_ROUTE,
                axum::routing::get(get::<P, L>).post(post::<P, L>),
            )
            .route(EXECUTIONS_ID_ROUTE, axum::routing::get(id::get::<P, L>))
            .layer(axum::middleware::from_fn(
                cda_plugin_security::security_plugin_middleware::<S>,
            ))
            .with_state(state)
    }

    /// Returns the [`HttpRouteMatcher`]s that must remain accessible while an update
    /// execution owns the transport disable lease.
    pub fn routes_accessible_during_update() -> Vec<HttpRouteMatcher> {
        vec![
            HttpRouteMatcher::new("/health", vec![HttpMethod::GET]),
            HttpRouteMatcher::new("/vehicle/v15/data/version", vec![HttpMethod::GET]),
            HttpRouteMatcher::new(
                "/vehicle/v15/authorize",
                vec![HttpMethod::GET, HttpMethod::POST],
            ),
            // Locks may be created, listed and extended but not deleted, so a
            // client cannot drop its lock mid-flash.
            HttpRouteMatcher::new(
                "/vehicle/v15/locks",
                vec![HttpMethod::GET, HttpMethod::POST, HttpMethod::PUT],
            ),
            HttpRouteMatcher {
                prefix: EXECUTIONS_ROUTE.to_string(),
                methods: vec![HttpMethod::GET],
            },
        ]
    }
}

/// `networkreset`: reset the vehicle network structure.
pub(crate) mod networkreset {
    use std::{sync::Arc, time::Duration};

    use aide::{
        UseApi,
        axum::{
            ApiRouter,
            routing::{delete_with, get_with, post_with},
        },
        openapi::{Operation, PathItem, ReferenceOr},
    };
    use axum::{
        Json,
        extract::{Path, Query, State},
        http::{StatusCode, header::LOCATION},
        response::{IntoResponse, Response},
    };
    use axum_extra::extract::WithRejection;
    use cda_interfaces::{
        runtime_update_api::LockStateProvider,
        topology::{NetworkResetError, VehicleTopologyPlugin},
    };
    use cda_plugin_security::Secured;
    use opensovd_axum_extra::ExtractHost;
    use sovd_interfaces::{
        apps::sovd2uds::operations::networkreset::{
            ExecutionRequest, ExecutionResponse, OperationResponse,
        },
        common::operations::{ExecutionCreatedResponse, ExecutionListResponse},
        error::{ApiErrorResponse, ErrorCode},
    };

    use crate::sovd::{
        apps::sovd2uds::bulk_data::runtimefiles::require_vehicle_lock,
        docs,
        error::{ApiError, api_error_response},
    };

    /// Name of the operation in the operations collection.
    pub(crate) const OPERATION_ID: &str = "networkreset";
    const OPERATION_ROUTE: &str = "/vehicle/v15/apps/sovd2uds/operations/networkreset";
    const EXECUTIONS_ROUTE: &str = "/vehicle/v15/apps/sovd2uds/operations/networkreset/executions";
    const EXECUTIONS_ID_ROUTE: &str =
        "/vehicle/v15/apps/sovd2uds/operations/networkreset/executions/{id}";

    /// Display name in the operations collection.
    pub(crate) const COLLECTION_NAME: &str = "Network reset";

    const NO_VEHICLE_LOCK: &str = "The caller does not hold the exclusive vehicle lock";
    const INVALID_BODY: &str = "Invalid request body (non-JSON content type, invalid JSON, \
                                unknown field or wrong type); nothing is executed";
    const NO_SUCH_EXECUTION: &str = "There is no execution with this id";

    /// State of the `networkreset` routes.
    #[derive(Clone)]
    pub struct VehicleTopologyRouteState {
        pub plugin: Arc<dyn VehicleTopologyPlugin>,
        pub locks: Arc<dyn LockStateProvider>,
        pub retry_after: Duration,
    }

    fn error_doc(description: &str) -> ReferenceOr<aide::openapi::Response> {
        docs::json_response(
            description,
            crate::create_schema!(ApiErrorResponse<crate::VendorErrorCode>),
        )
    }

    fn capability_schema() -> PathItem {
        PathItem {
            post: Some(Operation {
                summary: Some("Reset the vehicle network structure".to_owned()),
                request_body: Some(docs::json_request_body(crate::create_schema!(
                    ExecutionRequest
                ))),
                responses: Some(docs::responses(vec![
                    (
                        202,
                        docs::json_response(
                            "Execution accepted",
                            crate::create_schema!(ExecutionCreatedResponse),
                        ),
                    ),
                    (400, error_doc(INVALID_BODY)),
                    (403, error_doc(NO_VEHICLE_LOCK)),
                    (
                        409,
                        error_doc(
                            "An execution exists, ECU or functional group locks are held, or \
                             diagnostic operations or a communication change are in progress",
                        ),
                    ),
                ])),
                extensions: indexmap::IndexMap::from([(
                    sovd_interfaces::docs::X_SOVD_ASYNCHRONOUS_EXECUTION.to_owned(),
                    serde_json::Value::Bool(true),
                )]),
                ..Default::default()
            }),
            get: Some(Operation {
                summary: Some("Read execution status".to_owned()),
                responses: Some(docs::responses(vec![
                    (
                        200,
                        docs::json_response(
                            "Execution status",
                            crate::create_schema!(ExecutionResponse),
                        ),
                    ),
                    (404, docs::empty_response(NO_SUCH_EXECUTION)),
                ])),
                ..Default::default()
            }),
            delete: Some(Operation {
                summary: Some("Terminate and remove the execution".to_owned()),
                responses: Some(docs::responses(vec![
                    (204, docs::empty_response("Execution removed")),
                    (403, error_doc(NO_VEHICLE_LOCK)),
                    (404, docs::empty_response(NO_SUCH_EXECUTION)),
                ])),
                ..Default::default()
            }),
            extensions: indexmap::IndexMap::from([(
                sovd_interfaces::docs::X_SOVD_PROXIMITY_PROOF_REQUIRED.to_owned(),
                serde_json::Value::Bool(false),
            )]),
            ..Default::default()
        }
    }

    pub(crate) async fn details(
        WithRejection(Query(query), _): WithRejection<
            Query<sovd_interfaces::IncludeSchemaQuery>,
            ApiError,
        >,
    ) -> Response {
        let schema = if query.include_schema {
            match serde_json::to_value(capability_schema()) {
                Ok(schema) => Some(schema),
                Err(error) => {
                    return ApiError::InternalServerError(Some(error.to_string())).into_response();
                }
            }
        } else {
            None
        };
        Json(OperationResponse {
            item: super::collection::item(OPERATION_ID, COLLECTION_NAME),
            schema,
        })
        .into_response()
    }

    fn error_response(error: &NetworkResetError) -> Response {
        let (status, error_code, vendor_code) = match error {
            NetworkResetError::InvalidRequest(_) => (
                StatusCode::BAD_REQUEST,
                ErrorCode::VendorSpecific,
                Some(crate::VendorErrorCode::InvalidData),
            ),
            NetworkResetError::ExecutionConflict | NetworkResetError::OperationsInProgress(_) => (
                StatusCode::CONFLICT,
                ErrorCode::PreconditionsNotFulfilled,
                None,
            ),
            NetworkResetError::Failed(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::SovdServerFailure,
                None,
            ),
        };
        api_error_response(status, error_code, vendor_code, error.to_string())
    }

    pub(crate) async fn get(State(state): State<VehicleTopologyRouteState>) -> Response {
        let items = state
            .plugin
            .list_resets()
            .await
            .into_iter()
            .map(|exec| sovd_interfaces::common::operations::OperationIdItem { id: exec.id })
            .collect();
        (StatusCode::OK, Json(ExecutionListResponse { items })).into_response()
    }

    /// The optional JSON body of an execution request, documented as the request body.
    type ExecutionRequestBody = UseApi<
        WithRejection<Option<Json<ExecutionRequest>>, ApiError>,
        Option<Json<ExecutionRequest>>,
    >;

    /// [[ dimpl~plugin-vehicle-topology-reset-http, networkreset SOVD operation endpoints, dimpl ]]
    pub(crate) async fn post(
        State(state): State<VehicleTopologyRouteState>,
        UseApi(ExtractHost(host), _): UseApi<ExtractHost, String>,
        UseApi(Secured(sec_plugin), _): UseApi<Secured, ()>,
        UseApi(WithRejection(body, _), _): ExecutionRequestBody,
    ) -> Response {
        let claims = sec_plugin.as_auth_plugin().claims();
        if let Err(response) = require_vehicle_lock(&*state.locks, *claims, state.retry_after).await
        {
            return response.into_response();
        }
        // Without a body (no `Content-Type`) both flags default to `true`.
        let request = body.map(|Json(request)| request).unwrap_or_default();
        match state.plugin.start_reset(request.parameters.flags()).await {
            Ok(id) => {
                let location = format!("http://{host}{EXECUTIONS_ROUTE}/{id}");
                (
                    StatusCode::ACCEPTED,
                    [(LOCATION, location)],
                    Json(ExecutionCreatedResponse { id }),
                )
                    .into_response()
            }
            Err(error) => error_response(&error),
        }
    }

    pub(crate) async fn get_id(
        State(state): State<VehicleTopologyRouteState>,
        Path(id): Path<String>,
        WithRejection(Query(query), _): WithRejection<
            Query<sovd_interfaces::IncludeSchemaQuery>,
            ApiError,
        >,
    ) -> Response {
        match state.plugin.get_reset(&id).await {
            Some(exec) => {
                let mut response = ExecutionResponse::from(exec);
                if query.include_schema {
                    response.schema = Some(crate::create_schema!(ExecutionResponse));
                }
                (StatusCode::OK, Json(response)).into_response()
            }
            None => StatusCode::NOT_FOUND.into_response(),
        }
    }

    pub(crate) async fn delete_id(
        State(state): State<VehicleTopologyRouteState>,
        UseApi(Secured(sec_plugin), _): UseApi<Secured, ()>,
        Path(id): Path<String>,
    ) -> Response {
        let claims = sec_plugin.as_auth_plugin().claims();
        if let Err(response) = require_vehicle_lock(&*state.locks, *claims, state.retry_after).await
        {
            return response.into_response();
        }
        if state.plugin.delete_reset(&id).await {
            StatusCode::NO_CONTENT.into_response()
        } else {
            StatusCode::NOT_FOUND.into_response()
        }
    }

    pub fn routes<S: cda_plugin_security::SecurityPluginLoader>(
        state: VehicleTopologyRouteState,
    ) -> ApiRouter {
        ApiRouter::new()
            .api_route(
                OPERATION_ROUTE,
                get_with(details, |op| {
                    op.description("Retrieve network reset details and supported capabilities")
                        .response::<200, Json<OperationResponse>>()
                }),
            )
            .api_route(
                EXECUTIONS_ROUTE,
                get_with(get, |op| {
                    op.description("List network reset executions")
                        .response::<200, Json<ExecutionListResponse>>()
                })
                .merge(post_with(post, |op| {
                    op.description(
                        "Reset the vehicle network structure. The reset deadline covers the \
                         bring-up of the rediscovery, the persistence's settle budget its \
                         settling; DELETE interrupts both, steps already started (clearing, the \
                         lifecycle worker's enable) complete in the background. If the \
                         rediscovery fails after the exclusive disable was finished, \
                         communication stays disabled; a new networkreset with \
                         trigger_detection=true brings it up in every init_mode.",
                    )
                    .response::<202, Json<ExecutionCreatedResponse>>()
                    .response_with::<400, Json<ApiErrorResponse<crate::VendorErrorCode>>, _>(
                        |res| res.description(INVALID_BODY),
                    )
                    .response_with::<403, Json<ApiErrorResponse<crate::VendorErrorCode>>, _>(
                        |res| res.description(NO_VEHICLE_LOCK),
                    )
                    .response_with::<409, Json<ApiErrorResponse<crate::VendorErrorCode>>, _>(
                        |res| {
                            res.description(
                                "An execution exists, ECU or functional group locks are held, or \
                                 diagnostic operations or a communication change are in progress",
                            )
                        },
                    )
                })),
            )
            .api_route(
                EXECUTIONS_ID_ROUTE,
                get_with(get_id, |op| {
                    op.description("Read network reset execution status")
                        .response::<200, Json<ExecutionResponse>>()
                        .response_with::<404, (), _>(|res| res.description(NO_SUCH_EXECUTION))
                })
                .merge(delete_with(delete_id, |op| {
                    op.description(
                        "Terminate and remove a network reset execution. Requires the caller's \
                         exclusive vehicle lock.",
                    )
                    .response::<204, ()>()
                    .response_with::<403, Json<ApiErrorResponse<crate::VendorErrorCode>>, _>(
                        |res| res.description(NO_VEHICLE_LOCK),
                    )
                    .response_with::<404, (), _>(|res| res.description(NO_SUCH_EXECUTION))
                })),
            )
            .layer(axum::middleware::from_fn(
                cda_plugin_security::security_plugin_middleware::<S>,
            ))
            .with_state(state)
    }

    #[cfg(test)]
    mod tests {
        use std::sync::Mutex;

        use axum::{
            body::Body,
            http::{Request, header::CONTENT_TYPE},
        };
        use cda_interfaces::{
            http_protection::registry::{
                HttpMethod, HttpProtectionConfig, HttpProtectionReason, HttpProtectionRegistry,
                HttpRouteMatcher, HttpStatusCode, OwnedHttpProtection,
            },
            topology::{NETWORK_STRUCTURE_ROUTE, NetworkResetExecution, NetworkResetFlags},
        };
        use cda_plugin_security::mock::TestSecurityPlugin;
        use tower::ServiceExt;

        use super::*;
        use crate::sovd::request_guard::HttpRestrictionLayer;

        #[derive(Default)]
        struct StubPlugin {
            started: Mutex<Vec<NetworkResetFlags>>,
            deleted: Mutex<Vec<String>>,
            /// Answer of `start_reset`, as the real plugin would give it.
            start_error: Mutex<Option<NetworkResetError>>,
            /// Protection held while an execution "runs".
            protection: Mutex<Option<OwnedHttpProtection>>,
            protections: Option<HttpProtectionRegistry>,
        }

        impl StubPlugin {
            /// Ends the running execution and releases its protection.
            fn finish(&self) {
                self.protection.lock().unwrap().take();
            }
        }

        #[async_trait::async_trait]
        impl VehicleTopologyPlugin for StubPlugin {
            async fn start_reset(
                &self,
                flags: NetworkResetFlags,
            ) -> Result<String, NetworkResetError> {
                if !flags.clear_persisted && !flags.trigger_detection {
                    return Err(NetworkResetError::InvalidRequest(
                        "both flags are false".to_owned(),
                    ));
                }
                if let Some(error) = self.start_error.lock().unwrap().clone() {
                    return Err(error);
                }
                if let Some(registry) = &self.protections {
                    // Same protection the default plugin installs while it runs.
                    let protection = registry
                        .protect(
                            HttpProtectionConfig::new(
                                HttpProtectionReason::Custom("NetworkResetInProgress".to_owned()),
                                HttpStatusCode::CONFLICT,
                                "A network reset is in progress",
                            )
                            .with_selected_routes(vec![
                                HttpRouteMatcher::new(
                                    NETWORK_STRUCTURE_ROUTE,
                                    vec![HttpMethod::GET],
                                ),
                            ]),
                        )
                        .unwrap();
                    *self.protection.lock().unwrap() = Some(protection);
                }
                self.started.lock().unwrap().push(flags);
                Ok("exec-1".to_owned())
            }
            async fn list_resets(&self) -> Vec<NetworkResetExecution> {
                Vec::new()
            }
            async fn get_reset(&self, _id: &str) -> Option<NetworkResetExecution> {
                None
            }
            async fn delete_reset(&self, id: &str) -> bool {
                self.deleted.lock().unwrap().push(id.to_owned());
                true
            }
        }

        /// The vehicle lock owner; `TestSecurityPlugin` authenticates as `test_user`.
        struct StubLocks(Option<&'static str>);

        #[async_trait::async_trait]
        impl LockStateProvider for StubLocks {
            async fn vehicle_lock_owner_sub(&self) -> Option<String> {
                self.0.map(str::to_owned)
            }
            async fn has_non_vehicle_locks(&self) -> bool {
                false
            }
        }

        fn app(owner: Option<&'static str>) -> (axum::Router, Arc<StubPlugin>) {
            let plugin = Arc::new(StubPlugin::default());
            let state = VehicleTopologyRouteState {
                plugin: Arc::clone(&plugin) as Arc<dyn VehicleTopologyPlugin>,
                locks: Arc::new(StubLocks(owner)),
                retry_after: Duration::from_secs(1),
            };
            (
                axum::Router::from(routes::<TestSecurityPlugin>(state)),
                plugin,
            )
        }

        async fn post(body: Option<(&str, Option<&str>)>) -> (StatusCode, Vec<NetworkResetFlags>) {
            let (router, plugin) = app(Some("test_user"));
            let mut builder = Request::builder()
                .method("POST")
                .uri(EXECUTIONS_ROUTE)
                .header("host", "localhost");
            let body = match body {
                Some((content, content_type)) => {
                    if let Some(content_type) = content_type {
                        builder = builder.header(CONTENT_TYPE, content_type);
                    }
                    Body::from(content.to_owned())
                }
                None => Body::empty(),
            };
            let response = router.oneshot(builder.body(body).unwrap()).await.unwrap();
            let status = response.status();
            if status != StatusCode::ACCEPTED {
                let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap();
                let value: serde_json::Value = serde_json::from_slice(&bytes)
                    .expect("Error responses must be ApiErrorResponse JSON");
                assert!(value.get("message").is_some());
                assert!(value.get("error_code").is_some());
            }
            let started = plugin.started.lock().unwrap().clone();
            (status, started)
        }

        const JSON: Option<&str> = Some("application/json");
        const BOTH: NetworkResetFlags = NetworkResetFlags {
            clear_persisted: true,
            trigger_detection: true,
        };

        /// [[ test~plugin-vehicle-topology-reset-request-body, Omitted fields and a request without body use the defaults, test ]]
        #[tokio::test]
        async fn omitted_fields_use_the_defaults() {
            for body in [
                None,
                Some(("", None)),
                Some(("  \n", None)),
                Some(("{}", JSON)),
                Some((r#"{"parameters": {}}"#, JSON)),
                Some((
                    r#"{"parameters": {}}"#,
                    Some("application/json; charset=utf-8"),
                )),
                // Without a `Content-Type` the standard extractor does not read the body.
                Some((r#"{"parameters": {"clear_persisted": false}}"#, None)),
            ] {
                let (status, started) = post(body).await;
                assert_eq!(status, StatusCode::ACCEPTED, "{body:?}");
                assert_eq!(started, vec![BOTH], "{body:?}");
            }
        }

        /// [[ test~plugin-vehicle-topology-reset-http-misunderstood-bodies-are-rejected-without-executing, A misunderstood networkreset body is rejected and nothing is executed, test ]]
        #[tokio::test]
        async fn misunderstood_bodies_are_rejected_without_executing() {
            for (body, expected) in [
                (
                    Some((r#"{"clear_persisted": false}"#, JSON)),
                    StatusCode::BAD_REQUEST,
                ),
                (
                    Some((r#"{"parameters": {"clear_persited": false}}"#, JSON)),
                    StatusCode::BAD_REQUEST,
                ),
                (
                    Some((r#"{"parameters": {"clear_persisted": "no"}}"#, JSON)),
                    StatusCode::BAD_REQUEST,
                ),
                (Some(("{not json", JSON)), StatusCode::BAD_REQUEST),
                (Some(("", JSON)), StatusCode::BAD_REQUEST),
                (
                    Some((
                        r#"{"parameters": {"clear_persisted": false}}"#,
                        Some("text/plain"),
                    )),
                    StatusCode::BAD_REQUEST,
                ),
            ] {
                let (status, started) = post(body).await;
                assert_eq!(status, expected, "{body:?}");
                assert!(started.is_empty(), "{body:?}");
            }
        }

        async fn delete(owner: Option<&'static str>) -> (StatusCode, Vec<String>) {
            let (router, plugin) = app(owner);
            let response = router
                .oneshot(
                    Request::builder()
                        .method("DELETE")
                        .uri(EXECUTIONS_ID_ROUTE.replace("{id}", "exec-1"))
                        .header("host", "localhost")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let deleted = plugin.deleted.lock().unwrap().clone();
            (response.status(), deleted)
        }

        /// [[ test~plugin-vehicle-topology-reset-delete-lock, networkreset DELETE requires the caller's vehicle lock, test ]]
        #[tokio::test]
        async fn delete_requires_the_callers_vehicle_lock() {
            let (status, deleted) = delete(None).await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert!(deleted.is_empty());

            let (status, deleted) = delete(Some("someone_else")).await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert!(deleted.is_empty());

            let (status, deleted) = delete(Some("test_user")).await;
            assert_eq!(status, StatusCode::NO_CONTENT);
            assert_eq!(deleted, vec!["exec-1".to_owned()]);
        }

        /// POSTs `body` as the caller `test_user` with the given vehicle lock owner and
        /// the plugin's `start_reset` answering with `start_error`.
        async fn post_expecting(
            owner: Option<&'static str>,
            start_error: Option<NetworkResetError>,
            body: &'static str,
        ) -> (StatusCode, Vec<NetworkResetFlags>) {
            let (router, plugin) = app(owner);
            *plugin.start_error.lock().unwrap() = start_error;
            let response = router
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(EXECUTIONS_ROUTE)
                        .header("host", "localhost")
                        .header(CONTENT_TYPE, "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let started = plugin.started.lock().unwrap().clone();
            (status, started)
        }

        /// [[ test~plugin-vehicle-topology-reset-http-post-maps-plugin-conflicts-to-409, networkreset POST answers 409 for a running execution or operations in progress, test ]]
        #[tokio::test]
        async fn post_maps_plugin_conflicts_to_409() {
            for error in [
                // An ECU lock or a diagnostic operation in progress.
                NetworkResetError::OperationsInProgress("ECU lock held".to_owned()),
                NetworkResetError::OperationsInProgress("diagnostics in progress".to_owned()),
                // A running execution.
                NetworkResetError::ExecutionConflict,
            ] {
                let (status, started) =
                    post_expecting(Some("test_user"), Some(error.clone()), "{}").await;
                assert_eq!(status, StatusCode::CONFLICT, "{error}");
                assert!(started.is_empty(), "{error}");
            }
        }

        /// The state is cloned per request, so every clone carries the expectations.
        fn mock_uds() -> cda_interfaces::mock::MockUdsEcu {
            let mut uds = cda_interfaces::mock::MockUdsEcu::default();
            uds.expect_clone().returning(mock_uds);
            uds.expect_get_network_structure().returning(|| {
                cda_interfaces::datatypes::NetworkStructure {
                    functional_groups: Vec::new(),
                    gateways: Vec::new(),
                }
            });
            uds
        }

        async fn get_status(router: &axum::Router, uri: &str) -> StatusCode {
            router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(uri)
                        .header("host", "localhost")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
                .status()
        }

        /// While a reset holds its protection, the network structure answers 409.
        /// [[ test~networkstructure-conflict-during-reset, The network structure endpoint answers 409 while a networkreset runs, test ]]
        #[tokio::test]
        async fn networkstructure_conflicts_while_a_reset_runs() {
            let registry = HttpProtectionRegistry::new();
            let plugin = Arc::new(StubPlugin {
                protections: Some(registry.clone()),
                ..Default::default()
            });
            let state = VehicleTopologyRouteState {
                plugin: Arc::clone(&plugin) as Arc<dyn VehicleTopologyPlugin>,
                locks: Arc::new(StubLocks(Some("test_user"))),
                retry_after: Duration::from_secs(1),
            };
            let uds = mock_uds();
            let router = axum::Router::from(routes::<TestSecurityPlugin>(state))
                .merge(
                    axum::Router::new()
                        .route(
                            NETWORK_STRUCTURE_ROUTE,
                            axum::routing::get(
                                crate::sovd::apps::sovd2uds::data::networkstructure::get::<
                                    cda_interfaces::mock::MockUdsEcu,
                                >,
                            ),
                        )
                        .with_state(uds),
                )
                .layer(HttpRestrictionLayer::new(Arc::new(registry)));

            assert_eq!(
                get_status(&router, NETWORK_STRUCTURE_ROUTE).await,
                StatusCode::OK
            );

            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(EXECUTIONS_ROUTE)
                        .header("host", "localhost")
                        .header(CONTENT_TYPE, "application/json")
                        .body(Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::ACCEPTED);

            assert_eq!(
                get_status(&router, NETWORK_STRUCTURE_ROUTE).await,
                StatusCode::CONFLICT
            );

            plugin.finish();
            assert_eq!(
                get_status(&router, NETWORK_STRUCTURE_ROUTE).await,
                StatusCode::OK
            );
        }
    }
}

/// `GET /apps/sovd2uds/operations`: the operations offered by the CDA itself.
pub(crate) mod collection {
    use std::sync::Arc;

    use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
    use sovd_interfaces::{Items, components::ecu::operations::OperationCollectionItem};

    use crate::dynamic_router::DynamicRouter;

    const OPERATIONS_ROUTE: &str = "/vehicle/v15/apps/sovd2uds/operations";

    /// The registered operations, in registration order, and whether the
    /// collection route is mounted.
    #[derive(Default)]
    struct Registered {
        /// `(id, name)`.
        items: Vec<(&'static str, &'static str)>,
        mounted: bool,
    }

    type RegisteredOperations = Arc<tokio::sync::Mutex<Registered>>;

    pub(super) fn item(id: &str, name: &str) -> OperationCollectionItem {
        OperationCollectionItem {
            id: id.to_owned(),
            name: name.to_owned(),
            proximity_proof_required: false,
            asynchronous_execution: true,
        }
    }

    /// The operations offered by the CDA itself. Every plugin that mounts an
    /// operation registers it on its route setup; the collection route is mounted
    /// with the first registration and lists exactly the registered operations.
    #[derive(Clone, Default)]
    pub(crate) struct OperationsCollection {
        registered: RegisteredOperations,
    }

    impl OperationsCollection {
        /// Adds the operation to the collection (once per id) and mounts the
        /// collection route if it is not mounted yet.
        pub(crate) async fn register<S: cda_plugin_security::SecurityPluginLoader>(
            &self,
            dynamic_router: &DynamicRouter,
            id: &'static str,
            name: &'static str,
        ) {
            let mut registered = self.registered.lock().await;
            if !registered.items.iter().any(|(existing, _)| *existing == id) {
                registered.items.push((id, name));
            }
            if !registered.mounted {
                let _ = dynamic_router.add_routes(self.routes::<S>().into()).await;
                registered.mounted = true;
            }
        }

        fn routes<S: cda_plugin_security::SecurityPluginLoader>(&self) -> axum::Router {
            axum::Router::new()
                .route(
                    OPERATIONS_ROUTE,
                    axum::routing::get(
                        |State(registered): State<RegisteredOperations>| async move {
                            let items = registered
                                .lock()
                                .await
                                .items
                                .iter()
                                .map(|(id, name)| item(id, name))
                                .collect();
                            (
                                StatusCode::OK,
                                Json(Items {
                                    items,
                                    schema: None,
                                }),
                            )
                                .into_response()
                        },
                    ),
                )
                .with_state(Arc::clone(&self.registered))
                .layer(axum::middleware::from_fn(
                    cda_plugin_security::security_plugin_middleware::<S>,
                ))
        }
    }
}
