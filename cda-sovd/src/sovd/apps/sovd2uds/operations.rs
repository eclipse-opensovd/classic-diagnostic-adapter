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

/// [[ dimpl~plugin-vehicle-topology-connect-ecu, Connect ECU directly operation, dimpl ]]
///
/// Connects a gateway ECU directly to an IP address, bypassing VIR/VAM discovery.
///
/// Only available in builds with the `doip-direct-connect` feature, and only offered
/// if `doip.direct_connect_enabled` is set. Requires the vehicle lock.
///
/// Modelled as an operation with a synchronous execution, as specified for
/// `POST /{entity-path}/operations/{operation-id}/executions` (ISO 17978-3, 7.14.6).
///
/// Preliminary: connecting ECUs belongs to the topology plugin. This operation is
/// a stopgap in the SOVD layer and is expected to be replaced by what the topology
/// plugin provides.
#[cfg(feature = "doip-direct-connect")]
pub(crate) mod doip_connect_ecu {
    use aide::{
        UseApi,
        axum::{ApiRouter, routing},
        openapi::OpenApi,
        transform::TransformOperation,
    };
    use axum::{
        Json,
        extract::{Query, State},
        http::StatusCode,
        response::{IntoResponse as _, Response},
    };
    use axum_extra::extract::WithRejection;
    use cda_interfaces::{UdsEcu, communication_control::DoipEndpoint};
    use sovd_interfaces::apps::sovd2uds::operations::doip_connect_ecu::{
        ExecutionParameters, ExecutionRequest, ExecutionResponse, ExecutionResponseParameters,
        OperationResponse,
    };

    use crate::{
        openapi,
        sovd::{
            WebserverState, acquire_communication_activity, create_schema,
            error::{ApiError, ErrorWrapper},
            locks::{VehicleLockRequirement, validate_vehicle_write},
        },
    };

    pub(crate) const PATH: &str = "/vehicle/v15/apps/sovd2uds/operations/doip-connect-ecu";
    /// Base path of the operation in its capability description, relative to the
    /// SOVD base URI like the ECU operation docs.
    const DOCS_BASE_PATH: &str = "/apps/sovd2uds/operations/doip-connect-ecu";
    pub(crate) const EXECUTIONS_ROUTE: &str =
        "/vehicle/v15/apps/sovd2uds/operations/doip-connect-ecu/executions";
    pub(crate) const DOCS_ROUTE: &str =
        "/vehicle/v15/apps/sovd2uds/operations/doip-connect-ecu/docs";

    /// Name of the operation in the operations collection.
    pub(crate) const OPERATION_ID: &str = "doip-connect-ecu";

    /// Lists the operation in the operations collection, only if `doip_connect` is
    /// set (the same condition as [`add_routes`]).
    pub(crate) async fn register_operation(
        dynamic_router: &crate::dynamic_router::DynamicRouter,
        doip_connect: Option<
            &std::sync::Arc<dyn cda_interfaces::communication_control::DoipConnect>,
        >,
    ) {
        if doip_connect.is_some() {
            dynamic_router.register_operation(PATH, false).await;
        }
    }

    /// Mounts the operation resource, its capability description and its executions
    /// route, only if `doip_connect` is set (the same condition as its collection
    /// entry).
    pub(crate) fn add_routes<T: UdsEcu + Clone>(
        router: ApiRouter<WebserverState<T>>,
        state: &WebserverState<T>,
    ) -> ApiRouter<WebserverState<T>> {
        if state.doip_connect.is_none() {
            return router;
        }
        router
            .api_route(PATH, routing::get_with(details, docs_get))
            .api_route(
                DOCS_ROUTE,
                routing::get_with(docs_endpoint, docs_endpoint_transform),
            )
            .api_route(EXECUTIONS_ROUTE, routing::post_with(post::<T>, docs_post))
    }

    /// The operation resource: its collection entry, and with `include-schema`
    /// the JSON schema of the response.
    pub(crate) async fn details(
        WithRejection(Query(query), _): WithRejection<
            Query<sovd_interfaces::IncludeSchemaQuery>,
            ApiError,
        >,
    ) -> Json<OperationResponse> {
        Json(OperationResponse {
            item: super::operation_item(OPERATION_ID, false),
            schema: query
                .include_schema
                .then(|| create_schema!(OperationResponse)),
        })
    }

    pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
        op.description("Retrieve the doip-connect-ecu operation.")
            .response_with::<200, Json<OperationResponse>, _>(|res| {
                res.description("The operation, with a synchronous execution.")
            })
    }

    /// `GET .../operations/doip-connect-ecu/docs`: the online capability description
    /// of the operation, a self-contained `OpenAPI` document.
    pub(crate) async fn docs_endpoint() -> Json<OpenApi> {
        super::operation_docs(
            OPERATION_ID,
            DOCS_BASE_PATH,
            false,
            create_schema!(ExecutionParameters),
            create_schema!(ExecutionResponseParameters),
        )
    }

    pub(crate) fn docs_endpoint_transform(op: TransformOperation) -> TransformOperation {
        super::operation_docs_transform(op, OPERATION_ID)
    }

    // Requires the vehicle lock instead of an ECU lock: the ECU is usually offline
    // when this is called, so there is no ECU lock to hold. But changing the set of
    // connected ECUs must not happen while another client works on the vehicle.
    #[tracing::instrument(
        skip(security_plugin, state, query),
        fields(ecu = %request_body.parameters.ecu, ip = %request_body.parameters.ip)
    )]
    pub(crate) async fn post<T: UdsEcu + Clone>(
        UseApi(cda_plugin_security::Secured(security_plugin), _): UseApi<
            cda_plugin_security::Secured,
            (),
        >,
        WithRejection(Query(query), _): WithRejection<
            Query<sovd_interfaces::IncludeSchemaQuery>,
            ApiError,
        >,
        State(state): State<WebserverState<T>>,
        WithRejection(Json(request_body), _): WithRejection<Json<ExecutionRequest>, ApiError>,
    ) -> Response {
        let include_schema = query.include_schema;
        let parameters = request_body.parameters;

        if let Err(response) = validate_vehicle_write(
            &security_plugin.as_auth_plugin().claims(),
            &state.locks,
            include_schema,
            VehicleLockRequirement::Any,
        )
        .await
        {
            return response.into_response();
        }

        // The route is only registered if direct connect is enabled, so this is not
        // reachable through the router.
        let Some(doip_connect) = &state.doip_connect else {
            return ErrorWrapper {
                error: ApiError::InternalServerError(Some(
                    "Direct connect is not available".to_owned(),
                )),
                include_schema,
            }
            .into_response();
        };

        let address = match parameters.ip.parse() {
            Ok(address) => address,
            Err(e) => {
                return ErrorWrapper {
                    error: ApiError::BadRequest(format!(
                        "Invalid IP address '{}': {e}",
                        parameters.ip
                    )),
                    include_schema,
                }
                .into_response();
            }
        };

        // Held for the duration of the connect, so communication cannot be
        // disabled underneath it. Also starts on-demand activation when needed.
        let _communication_guard =
            match acquire_communication_activity(&*state.communication_access) {
                Ok(guard) => guard,
                Err(error) => {
                    return ErrorWrapper {
                        error,
                        include_schema,
                    }
                    .into_response();
                }
            };

        match doip_connect
            .connect_ecu(
                &parameters.ecu,
                DoipEndpoint {
                    address,
                    protocol_version: parameters.protocol_version,
                },
            )
            .await
        {
            Ok(()) => {
                let schema = include_schema.then(|| create_schema!(ExecutionResponse));
                (
                    StatusCode::OK,
                    Json(ExecutionResponse {
                        parameters: ExecutionResponseParameters {
                            ecu: parameters.ecu,
                            ip: address.to_string(),
                        },
                        schema,
                    }),
                )
                    .into_response()
            }
            Err(e) => ErrorWrapper {
                error: ApiError::from(e),
                include_schema,
            }
            .into_response(),
        }
    }

    pub(crate) fn docs_post(op: TransformOperation) -> TransformOperation {
        type ErrorResponse =
            Json<sovd_interfaces::error::ApiErrorResponse<crate::sovd::error::VendorErrorCode>>;

        op.description(
            "Connect a gateway ECU directly to an IP address, bypassing vehicle discovery \
             (VIR/VAM). Requires the vehicle lock.",
        )
        .input::<Json<ExecutionRequest>>()
        .response_with::<200, Json<ExecutionResponse>, _>(|res| res.description("ECU connected."))
        .with(openapi::error_bad_request)
        .with(openapi::error_forbidden)
        .with(openapi::error_not_found)
        .response_with::<409, ErrorResponse, _>(|res| {
            res.description(
                "Conflict: The vehicle lock is not held by the client, the ECU is already \
                 connected, or a connection to it is currently being established.",
            )
        })
        .response_with::<423, ErrorResponse, _>(|res| {
            res.description("Locked: The vehicle lock is held by another client.")
        })
        .with(openapi::error_internal_server)
        .response_with::<503, ErrorResponse, _>(|res| {
            res.description("Service Unavailable: DoIP communication is not enabled or not ready.")
        })
        .response_with::<504, ErrorResponse, _>(|res| {
            res.description("Gateway Timeout: The ECU could not be reached in time.")
        })
    }

    #[cfg(test)]
    mod tests {
        use std::sync::Arc;

        use axum::http::StatusCode;
        use cda_interfaces::{
            DiagServiceError, HashMap, datatypes::ComponentsConfig, mock::MockUdsEcu,
        };
        use cda_plugin_communication_management::lifecycle::enabled_communication_access_for_test;
        use cda_plugin_security::{Secured, mock::TestSecurityPlugin};
        use tokio::sync::RwLock;

        use super::*;
        use crate::sovd::{Locks, locks::insert_test_vehicle_lock};

        struct FakeDoipConnect(Result<(), DiagServiceError>);

        #[async_trait::async_trait]
        impl cda_interfaces::communication_control::DoipConnect for FakeDoipConnect {
            async fn connect_ecu(
                &self,
                _ecu_name: &str,
                _endpoint: DoipEndpoint,
            ) -> Result<(), DiagServiceError> {
                self.0.clone()
            }
        }

        fn state(doip_connect: Option<Result<(), DiagServiceError>>) -> WebserverState<MockUdsEcu> {
            state_with_locks(doip_connect, Arc::new(Locks::new()))
        }

        async fn state_with_vehicle_lock(
            doip_connect: Option<Result<(), DiagServiceError>>,
            owner: &str,
        ) -> WebserverState<MockUdsEcu> {
            let locks = Arc::new(Locks::new());
            insert_test_vehicle_lock(&locks, owner).await;
            state_with_locks(doip_connect, locks)
        }

        fn state_with_locks(
            doip_connect: Option<Result<(), DiagServiceError>>,
            locks: Arc<Locks>,
        ) -> WebserverState<MockUdsEcu> {
            WebserverState {
                uds: MockUdsEcu::new(),
                locks,
                flash_data: Arc::new(RwLock::new(sovd_interfaces::sovd2uds::FileList {
                    files: Vec::new(),
                    path: None,
                    schema: None,
                })),
                flash_functional_class_default: Arc::from("flash_download_upload"),
                components_config: Arc::new(RwLock::new(ComponentsConfig {
                    additional_fields: HashMap::default(),
                })),
                communication_access: enabled_communication_access_for_test(),
                doip_connect: doip_connect.map(|result| {
                    Arc::new(FakeDoipConnect(result))
                        as Arc<dyn cda_interfaces::communication_control::DoipConnect>
                }),
            }
        }

        /// The operations collection lists `doip-connect-ecu`, with a synchronous
        /// execution, only if its route is mounted.
        #[tokio::test]
        async fn collection_lists_the_operation_only_if_its_route_is_mounted() {
            use tower::ServiceExt as _;

            for mounted in [false, true] {
                let dynamic_router = crate::dynamic_router::DynamicRouter::new();
                let doip_connect = mounted.then(|| {
                    Arc::new(FakeDoipConnect(Ok(())))
                        as Arc<dyn cda_interfaces::communication_control::DoipConnect>
                });
                register_operation(&dynamic_router, doip_connect.as_ref()).await;
                dynamic_router
                    .add_routes(ApiRouter::new().api_route(
                        crate::sovd::apps::sovd2uds::OPERATIONS_PATH,
                        routing::get(crate::sovd::apps::sovd2uds::operations_get),
                    ))
                    .await;

                let response = dynamic_router
                    .get_router()
                    .await
                    .oneshot(
                        axum::http::Request::builder()
                            .uri("/vehicle/v15/apps/sovd2uds/operations")
                            .header("host", "127.0.0.1:20002")
                            .body(axum::body::Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();

                assert_eq!(response.status(), StatusCode::OK);
                let collection: sovd_interfaces::Items<
                    sovd_interfaces::components::ecu::operations::OperationCollectionItem,
                > = crate::test_utils::axum_response_into(response)
                    .await
                    .unwrap();
                let item = collection.items.iter().find(|item| item.id == OPERATION_ID);
                assert_eq!(item.is_some(), mounted);
                if let Some(item) = item {
                    assert!(!item.asynchronous_execution);
                }
            }
        }

        /// The routes of the operation, mounted only if direct connect is wired.
        fn mounted_router(mounted: bool) -> ApiRouter {
            // The router clones the state for every request.
            fn cloneable_uds() -> MockUdsEcu {
                let mut uds = MockUdsEcu::new();
                uds.expect_clone().returning(cloneable_uds);
                uds
            }

            let mut state = state(mounted.then_some(Ok(())));
            state.uds = cloneable_uds();
            add_routes(ApiRouter::new(), &state).with_state(state)
        }

        /// `GET .../operations/doip-connect-ecu` is mounted under the same
        /// condition as its executions route and describes a synchronous
        /// execution.
        #[tokio::test]
        async fn operation_resource_is_mounted_with_its_executions_route() {
            use tower::ServiceExt as _;

            for mounted in [false, true] {
                let router = mounted_router(mounted);
                let get = |uri: &str| {
                    axum::http::Request::builder()
                        .uri(uri)
                        .body(axum::body::Body::empty())
                        .unwrap()
                };

                let response = router.clone().oneshot(get(PATH)).await.unwrap();
                let executions = router
                    .oneshot(
                        axum::http::Request::builder()
                            .method("POST")
                            .uri(EXECUTIONS_ROUTE)
                            .body(axum::body::Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();

                if !mounted {
                    assert_eq!(response.status(), StatusCode::NOT_FOUND);
                    assert_eq!(executions.status(), StatusCode::NOT_FOUND);
                    continue;
                }
                assert_ne!(executions.status(), StatusCode::NOT_FOUND);
                assert_eq!(response.status(), StatusCode::OK);
                let body: serde_json::Value = crate::test_utils::axum_response_into(response)
                    .await
                    .unwrap();
                assert_eq!(
                    body.pointer("/item/id").and_then(serde_json::Value::as_str),
                    Some(OPERATION_ID)
                );
                assert_eq!(
                    body.pointer("/item/asynchronous_execution")
                        .and_then(serde_json::Value::as_bool),
                    Some(false)
                );
            }
        }

        /// With `include-schema`, the operation resource carries the JSON schema of
        /// its response body, as the other operation resources.
        #[tokio::test]
        async fn details_schema_is_the_response_schema() {
            for include_schema in [false, true] {
                let Json(body) = details(WithRejection(
                    Query(sovd_interfaces::IncludeSchemaQuery { include_schema }),
                    std::marker::PhantomData,
                ))
                .await;
                assert_eq!(body.schema.is_some(), include_schema);
                let Some(schema) = body.schema else { continue };
                assert_eq!(schema, create_schema!(OperationResponse));
                assert!(schema.pointer("/properties/item").is_some());
            }
        }

        /// `GET .../operations/doip-connect-ecu/docs` is mounted under the same
        /// condition as the other routes of the operation and returns an `OpenAPI`
        /// document describing a synchronous execution.
        #[tokio::test]
        async fn docs_route_is_mounted_with_the_operation() {
            use tower::ServiceExt as _;

            for mounted in [false, true] {
                let router = mounted_router(mounted);
                let response = router
                    .oneshot(
                        axum::http::Request::builder()
                            .uri(DOCS_ROUTE)
                            .body(axum::body::Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();

                if !mounted {
                    assert_eq!(response.status(), StatusCode::NOT_FOUND);
                    continue;
                }
                assert_eq!(response.status(), StatusCode::OK);
                let doc: serde_json::Value = crate::test_utils::axum_response_into(response)
                    .await
                    .unwrap();
                let paths = doc.get("paths").expect("OpenAPI document must have paths");
                let executions = paths
                    .get(format!("{DOCS_BASE_PATH}/executions"))
                    .expect("executions path missing");
                assert!(
                    executions
                        .pointer(
                            "/post/requestBody/content/application~1json/schema/properties/\
                             parameters/properties/ip"
                        )
                        .is_some()
                );
                assert!(
                    executions
                        .pointer(
                            "/post/responses/200/content/application~1json/schema/properties/\
                             parameters/properties/ecu"
                        )
                        .is_some()
                );
                assert!(
                    executions
                        .pointer("/post/x-sovd-asynchronous-execution")
                        .is_none()
                );
                assert!(
                    paths
                        .get(format!("{DOCS_BASE_PATH}/executions/{{execution-id}}"))
                        .is_none()
                );
            }
        }

        async fn execute(state: WebserverState<MockUdsEcu>, ip: &str) -> axum::response::Response {
            post::<MockUdsEcu>(
                UseApi(
                    Secured(Box::new(TestSecurityPlugin)),
                    std::marker::PhantomData,
                ),
                WithRejection(
                    Query(sovd_interfaces::IncludeSchemaQuery {
                        include_schema: false,
                    }),
                    std::marker::PhantomData,
                ),
                State(state),
                WithRejection(
                    Json(ExecutionRequest {
                        parameters: sovd_interfaces::apps::sovd2uds::operations::doip_connect_ecu::ExecutionParameters {
                            ecu: "my_ecu".to_owned(),
                            ip: ip.to_owned(),
                            protocol_version: 0x02,
                        },
                    }),
                    std::marker::PhantomData,
                ),
            )
            .await
        }

        #[tokio::test]
        async fn connects_the_ecu() {
            let state = state_with_vehicle_lock(Some(Ok(())), "test_user").await;
            let response = execute(state, "10.0.0.5").await;
            assert_eq!(response.status(), StatusCode::OK);
        }

        #[tokio::test]
        async fn already_connected_ecu_is_a_conflict() {
            let state = state_with_vehicle_lock(
                Some(Err(DiagServiceError::Conflict(
                    "ECU 'my_ecu' is already connected on 10.0.0.5".to_owned(),
                ))),
                "test_user",
            )
            .await;
            let response = execute(state, "10.0.0.9").await;
            assert_eq!(response.status(), StatusCode::CONFLICT);
        }

        #[tokio::test]
        async fn invalid_ip_is_a_bad_request() {
            let state = state_with_vehicle_lock(Some(Ok(())), "test_user").await;
            let response = execute(state, "not-an-ip").await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn missing_vehicle_lock_is_rejected() {
            let response = execute(state(Some(Ok(()))), "10.0.0.5").await;
            assert_eq!(response.status(), StatusCode::CONFLICT);
        }

        #[tokio::test]
        async fn vehicle_lock_of_another_client_is_rejected() {
            let state = state_with_vehicle_lock(Some(Ok(())), "someone_else").await;
            let response = execute(state, "10.0.0.5").await;
            assert_eq!(response.status(), StatusCode::LOCKED);
        }

        #[tokio::test]
        async fn unwired_direct_connect_is_an_internal_error() {
            let state = state_with_vehicle_lock(None, "test_user").await;
            let response = execute(state, "10.0.0.5").await;
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        }
    }
}

pub(crate) mod runtimefilesupdate {
    use aide::UseApi;
    use axum::{Json, extract::State, response::IntoResponse};
    use cda_interfaces::{
        http_protection::registry::{HttpMethod, HttpRouteMatcher},
        runtime_update_api::{LockStateProvider, RuntimeFilesUpdatePlugin},
    };
    use cda_plugin_security::Secured;
    use opensovd_axum_extra::ExtractHost;
    use sovd_interfaces::apps::sovd2uds::operations::runtimefilesupdate::ExecutionRequest;

    use crate::sovd::apps::sovd2uds::bulk_data::runtimefiles::{
        DbUpdateErrorResponse, RuntimeUpdateRouteState, require_vehicle_lock,
    };

    pub(crate) const PATH: &str = "/vehicle/v15/apps/sovd2uds/operations/runtimefilesupdate";
    const EXECUTIONS_ROUTE: &str =
        "/vehicle/v15/apps/sovd2uds/operations/runtimefilesupdate/executions";
    const EXECUTIONS_ID_ROUTE: &str =
        "/vehicle/v15/apps/sovd2uds/operations/runtimefilesupdate/executions/{id}";

    pub(crate) async fn get<P: RuntimeFilesUpdatePlugin, L: LockStateProvider>(
        State(route_state): State<RuntimeUpdateRouteState<P, L>>,
    ) -> impl IntoResponse {
        super::execution_list_response(
            route_state
                .plugin
                .list_executions()
                .await
                .into_iter()
                .map(|exec| exec.id),
        )
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
                |id| super::execution_created_response(&host, EXECUTIONS_ROUTE, id),
            )
    }

    pub(crate) mod id {
        use axum::{
            extract::{Path, Query, State},
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
            super::super::execution_status_response(
                route_state
                    .plugin
                    .get_execution_status(&id)
                    .await
                    .map(ExecutionResponse::from),
                query.include_schema,
            )
        }
    }

    impl super::ExecutionStatusBody
        for sovd_interfaces::apps::sovd2uds::operations::runtimefilesupdate::ExecutionResponse
    {
        fn set_schema(&mut self, schema: schemars::Schema) {
            self.schema = Some(schema);
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
                "/vehicle/v15/apps/sovd2uds/data/version",
                vec![HttpMethod::GET],
            ),
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

    #[cfg(test)]
    mod tests {
        use std::{
            sync::{Arc, Mutex},
            time::{Duration, SystemTime},
        };

        use axum::{
            body::Body,
            http::{Request, StatusCode, header::CONTENT_TYPE},
        };
        use cda_interfaces::runtime_update_api::{
            BulkDataCreatedList, BulkDataList, ExecutionMode, RuntimeFilesQuery,
            RuntimeUpdateError, UpdateExecution, UploadFile,
        };
        use cda_plugin_security::mock::TestSecurityPlugin;
        use tower::ServiceExt as _;

        use super::*;
        use crate::sovd::{Locks, SovdLockStateProvider, locks::insert_test_vehicle_lock_with};

        /// Records started executions; the other requests are not used by these tests.
        #[derive(Default)]
        struct StubPlugin {
            started: Mutex<Vec<String>>,
        }

        #[async_trait::async_trait]
        impl RuntimeFilesUpdatePlugin for StubPlugin {
            async fn list_current(
                &self,
                _query: &RuntimeFilesQuery,
            ) -> Result<BulkDataList, RuntimeUpdateError> {
                unimplemented!("not used by these tests")
            }
            async fn list_nextupdate(
                &self,
                _query: &RuntimeFilesQuery,
            ) -> Result<BulkDataList, RuntimeUpdateError> {
                unimplemented!("not used by these tests")
            }
            async fn list_backup(
                &self,
                _query: &RuntimeFilesQuery,
            ) -> Result<BulkDataList, RuntimeUpdateError> {
                unimplemented!("not used by these tests")
            }
            async fn upload(
                &self,
                _files: Vec<UploadFile>,
            ) -> Result<BulkDataCreatedList, RuntimeUpdateError> {
                unimplemented!("not used by these tests")
            }
            async fn delete_nextupdate(&self) -> Result<Vec<String>, RuntimeUpdateError> {
                unimplemented!("not used by these tests")
            }
            async fn delete_nextupdate_by_id(
                &self,
                _file_id: &str,
            ) -> Result<(), RuntimeUpdateError> {
                unimplemented!("not used by these tests")
            }
            async fn delete_backup(&self) -> Result<Vec<String>, RuntimeUpdateError> {
                unimplemented!("not used by these tests")
            }
            async fn start_execution(
                &self,
                mode: ExecutionMode,
            ) -> Result<String, RuntimeUpdateError> {
                self.started.lock().unwrap().push(format!("{mode:?}"));
                Ok("exec-1".to_owned())
            }
            async fn list_executions(&self) -> Vec<UpdateExecution> {
                Vec::new()
            }
            async fn get_execution_status(&self, _execution_id: &str) -> Option<UpdateExecution> {
                None
            }
        }

        async fn post_apply(expires_at: SystemTime) -> (StatusCode, Vec<String>) {
            let locks = Arc::new(Locks::new());
            // `TestSecurityPlugin` authenticates as `test_user`.
            insert_test_vehicle_lock_with(&locks, "test_user", true, expires_at).await;
            let plugin = Arc::new(StubPlugin::default());
            let state = RuntimeUpdateRouteState {
                plugin: Arc::clone(&plugin),
                vehicle_lock_states: Arc::new(SovdLockStateProvider::new(locks)),
                retry_after: Duration::from_secs(1),
            };
            let response = routes::<TestSecurityPlugin, _, _>(state)
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(EXECUTIONS_ROUTE)
                        .header("host", "localhost")
                        .header(CONTENT_TYPE, "application/json")
                        .body(Body::from(r#"{"parameters": {"mode": "apply"}}"#))
                        .unwrap(),
                )
                .await
                .unwrap();
            let started = plugin.started.lock().unwrap().clone();
            (response.status(), started)
        }

        /// The vehicle lock owner can start an execution until its lock expires. A lock
        /// past its expiration that the expiration task has not removed yet grants
        /// nothing, so its owner gets the response for a missing vehicle lock.
        #[tokio::test]
        async fn expired_vehicle_lock_of_the_owner_is_a_missing_lock() {
            let unexpired = SystemTime::now()
                .checked_add(Duration::from_secs(300))
                .expect("test expiration should be representable");
            let (status, started) = post_apply(unexpired).await;
            assert_eq!(status, StatusCode::ACCEPTED);
            assert_eq!(started.len(), 1);

            let expired = SystemTime::now()
                .checked_sub(Duration::from_secs(1))
                .expect("now is after the epoch");
            let (status, started) = post_apply(expired).await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert!(started.is_empty());
        }
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
        openapi::OpenApi,
        transform::{TransformOperation, TransformResponse},
    };
    use axum::{
        Json,
        body::Bytes,
        extract::{FromRequest, Path, Query, Request, State},
        http::{StatusCode, header::CONTENT_TYPE},
        response::{IntoResponse, Response},
    };
    use axum_extra::extract::WithRejection;
    use cda_interfaces::topology::{NetworkResetError, VehicleTopologyPlugin};
    use cda_plugin_security::{Claims, Secured};
    use opensovd_axum_extra::ExtractHost;
    use sovd_interfaces::{
        apps::sovd2uds::operations::networkreset::{
            ExecutionParameters, ExecutionRequest, ExecutionResponseParameters, OperationResponse,
        },
        common::operations::{ExecutionCreatedResponse, ExecutionListResponse},
        error::{ApiErrorResponse, ErrorCode},
    };

    use crate::{
        openapi,
        sovd::{
            SovdLockStateProvider,
            error::{ApiError, ErrorWrapper, VendorErrorCode, api_error_response},
            locks::{VehicleLockRequirement, validate_vehicle_write},
            with_retry_after,
        },
    };

    /// Name of the operation in the operations collection.
    pub(crate) const OPERATION_ID: &str = "networkreset";
    pub(crate) const PATH: &str = "/vehicle/v15/apps/sovd2uds/operations/networkreset";
    /// Base path of the operation in its capability description, relative to the
    /// SOVD base URI like the ECU operation docs.
    const DOCS_BASE_PATH: &str = "/apps/sovd2uds/operations/networkreset";
    const EXECUTIONS_ROUTE: &str = "/vehicle/v15/apps/sovd2uds/operations/networkreset/executions";
    const EXECUTIONS_ID_ROUTE: &str =
        "/vehicle/v15/apps/sovd2uds/operations/networkreset/executions/{id}";
    const DOCS_ROUTE: &str = "/vehicle/v15/apps/sovd2uds/operations/networkreset/docs";

    /// The status of an execution, with the vendor specific error codes of the CDA.
    type ExecutionResponse =
        sovd_interfaces::apps::sovd2uds::operations::networkreset::ExecutionResponse<
            VendorErrorCode,
        >;

    const INVALID_BODY: &str = "Bad Request: Invalid request body (a non-empty body without a \
                                JSON Content-Type, a non-JSON Content-Type, invalid JSON, an \
                                unknown field or a wrong type), invalid flags, or a timeout of 0 \
                                or too large to represent; nothing is executed";
    const MISSING_CONTENT_TYPE: &str =
        "A request body requires the Content-Type application/json; send no body for the defaults";
    const ZERO_TIMEOUT: &str = "The timeout must be at least 1 second";
    const TIMEOUT_TOO_LARGE: &str = "The timeout is too large";
    const NOTHING_TO_DO: &str =
        "clear_persisted and trigger_detection are both false, nothing to do";
    const LOCK_CONFLICT: &str = "Conflict: The caller holds no exclusive vehicle lock, or its \
                                 vehicle lock expired or is not exclusive (vendor_code \
                                 lock-required), or the caller's vehicle lock was broken \
                                 (error_code lock-broken)";
    const POST_CONFLICT: &str =
        "Conflict: The caller holds no exclusive vehicle lock, or its vehicle lock expired or is \
         not exclusive (vendor_code lock-required); the caller's vehicle lock was broken \
         (error_code lock-broken), also when it was lost after admission (the execution is then \
         cancelled, but the persisted topology may already have been cleared); an execution \
         exists, or diagnostic operations or a communication change are in progress (error_code \
         preconditions-not-fulfilled, with Retry-After); or a runtime update is in progress \
         (error_code update-process-in-progress, with Retry-After)";
    const LOCKED: &str = "Locked: The vehicle lock is held by another client, also when it was \
                          taken over after admission (the execution is then cancelled, but the \
                          persisted topology may already have been cleared)";
    const POST_DESCRIPTION: &str =
        "Reset the vehicle network structure: clear the persisted ECU topology and/or run a new \
         ECU detection. Requires the caller's exclusive vehicle lock. Without a body (no \
         Content-Type, empty or whitespace only body) both flags default to true; both flags \
         false is rejected. The body is validated before the vehicle lock. The optional timeout \
         stops an execution that is still running (status stopped); it counts from the request, \
         including the wait until communication is handed over to the reset. DELETE of the \
         execution stops it early; steps already started, such as clearing the persisted topology \
         or re-enabling communication, still complete. If the ECU detection fails, communication \
         with the ECUs may stay disabled; a new networkreset with trigger_detection=true enables \
         it again. If the caller's vehicle lock is lost while the execution is being admitted, \
         the execution is cancelled and the error response is only sent once steps already \
         started have finished.";
    /// Appended to the lock error of a lock lost after admission.
    const LOCK_LOST_NOTE: &str = "The network reset was admitted, then cancelled; the persisted \
                                  topology may already have been cleared";
    const RESET_FAILED: &str = "The network reset could not be started due to an internal error";

    /// State of the `networkreset` routes.
    #[derive(Clone)]
    pub struct VehicleTopologyRouteState {
        pub plugin: Arc<dyn VehicleTopologyPlugin>,
        pub locks: Arc<SovdLockStateProvider>,
        /// Sent as `Retry-After` when a conflicting execution or operation prevents a reset.
        pub retry_after: Duration,
    }

    /// The JSON body of an execution request. Without a body, i.e. an empty or whitespace
    /// only body without `Content-Type`, the defaults apply. A body is only read with a
    /// JSON `Content-Type`, so a non-empty body without one is rejected instead of
    /// silently selecting the destructive defaults.
    pub(crate) struct ExecutionRequestBody(ExecutionRequest);

    impl<S: Send + Sync> FromRequest<S> for ExecutionRequestBody {
        type Rejection = ApiError;

        async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
            let body = if request.headers().contains_key(CONTENT_TYPE) {
                let Json(body) = Json::<ExecutionRequest>::from_request(request, state).await?;
                body
            } else {
                let bytes = Bytes::from_request(request, state)
                    .await
                    .map_err(|error| ApiError::BadRequest(error.body_text()))?;
                if !bytes.iter().all(u8::is_ascii_whitespace) {
                    return Err(ApiError::BadRequest(MISSING_CONTENT_TYPE.to_owned()));
                }
                ExecutionRequest::default()
            };
            // Checked here and not only by the plugin, so an invalid body is rejected
            // with 400 before the vehicle lock is checked. The plugin checks again.
            match body.timeout() {
                Some(timeout) if timeout.is_zero() => {
                    return Err(ApiError::BadRequest(ZERO_TIMEOUT.to_owned()));
                }
                Some(timeout) if std::time::Instant::now().checked_add(timeout).is_none() => {
                    return Err(ApiError::BadRequest(TIMEOUT_TOO_LARGE.to_owned()));
                }
                _ => {}
            }
            let flags = body.parameters.flags();
            if !flags.clear_persisted && !flags.trigger_detection {
                return Err(ApiError::BadRequest(NOTHING_TO_DO.to_owned()));
            }
            Ok(Self(body))
        }
    }

    /// The operation resource: its collection entry, and with `include-schema` the JSON
    /// schema of the response.
    pub(crate) async fn details(
        WithRejection(Query(query), _): WithRejection<
            Query<sovd_interfaces::IncludeSchemaQuery>,
            ApiError,
        >,
    ) -> Json<OperationResponse> {
        Json(OperationResponse {
            item: super::operation_item(OPERATION_ID, true),
            schema: query
                .include_schema
                .then(|| crate::create_schema!(OperationResponse)),
        })
    }

    /// `GET .../operations/networkreset/docs`: the online capability description of the
    /// operation, a self-contained `OpenAPI` document.
    async fn docs_endpoint() -> Json<OpenApi> {
        super::operation_docs(
            OPERATION_ID,
            DOCS_BASE_PATH,
            true,
            crate::create_schema!(ExecutionParameters),
            crate::create_schema!(ExecutionResponseParameters),
        )
    }

    fn docs_endpoint_transform(op: TransformOperation) -> TransformOperation {
        super::operation_docs_transform(op, OPERATION_ID)
    }

    fn error_response(error: &NetworkResetError, retry_after: Duration) -> Response {
        let (status, error_code, vendor_code, retry_after) = match error {
            NetworkResetError::InvalidRequest(_) => (
                StatusCode::BAD_REQUEST,
                ErrorCode::VendorSpecific,
                Some(VendorErrorCode::InvalidData),
                None,
            ),
            NetworkResetError::ExecutionConflict | NetworkResetError::OperationsInProgress(_) => (
                StatusCode::CONFLICT,
                ErrorCode::PreconditionsNotFulfilled,
                None,
                Some(retry_after),
            ),
            NetworkResetError::Failed(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::SovdServerFailure,
                None,
                None,
            ),
        };
        with_retry_after(
            api_error_response(status, error_code, vendor_code, error.to_string()),
            retry_after,
        )
    }

    /// Requires the caller's effective exclusive vehicle lock, as for `doip-connect-ecu`
    /// but exclusive: 409 (`lock-required` or `lock-broken`) or 423 (foreign lock).
    async fn require_exclusive_vehicle_lock(
        state: &VehicleTopologyRouteState,
        claims: &impl Claims,
    ) -> Result<(), ErrorWrapper> {
        let locks = state.locks.current_locks().await;
        validate_vehicle_write(claims, &locks, false, VehicleLockRequirement::Exclusive).await
    }

    fn with_lock_lost_note(error: ApiError) -> ApiError {
        let noted = |message: String| format!("{message}. {LOCK_LOST_NOTE}");
        match error {
            ApiError::LockRequired(message) => ApiError::LockRequired(noted(message)),
            ApiError::Locked(message) => ApiError::Locked(noted(message)),
            ApiError::LockBroken {
                message,
                parameters,
            } => ApiError::LockBroken {
                message: noted(message),
                parameters,
            },
            error => error,
        }
    }

    pub(crate) async fn get(State(state): State<VehicleTopologyRouteState>) -> Response {
        super::execution_list_response(
            state
                .plugin
                .list_resets()
                .await
                .into_iter()
                .map(|exec| exec.id),
        )
    }

    /// [[ dimpl~plugin-vehicle-topology-reset-http, networkreset SOVD operation endpoints, dimpl ]]
    pub(crate) async fn post(
        State(state): State<VehicleTopologyRouteState>,
        UseApi(ExtractHost(host), _): UseApi<ExtractHost, String>,
        UseApi(Secured(sec_plugin), _): UseApi<Secured, ()>,
        UseApi(ExecutionRequestBody(request), _): UseApi<
            ExecutionRequestBody,
            Option<Json<ExecutionRequest>>,
        >,
    ) -> Response {
        let claims = sec_plugin.as_auth_plugin().claims();
        if let Err(response) = require_exclusive_vehicle_lock(&state, &claims).await {
            return response.into_response();
        }
        match state
            .plugin
            .start_reset(request.parameters.flags(), request.timeout())
            .await
        {
            Ok(id) => {
                // The lock provider offers snapshots, not a reservation. Recheck after
                // admission and request deletion if the lock was lost, but this is not
                // rollback: the default plugin may clear the topology even after deletion,
                // and started steps finish. Loss and reacquisition by the same owner,
                // or loss after this check, also remain undetected.
                if let Err(lock_error) = require_exclusive_vehicle_lock(&state, &claims).await {
                    tracing::warn!(
                        execution = %id,
                        error = %lock_error.error,
                        "Vehicle lock lost during network reset admission, cancelling execution"
                    );
                    if !state.plugin.delete_reset(&id).await {
                        tracing::warn!(
                            execution = %id,
                            "Admitted network reset to cancel was not found, it may still run"
                        );
                    }
                    // The lock error itself (lock-broken, lock-required or locked), as for
                    // any other request, with a note on what admission may have done.
                    return ErrorWrapper {
                        error: with_lock_lost_note(lock_error.error),
                        include_schema: false,
                    }
                    .into_response();
                }
                super::execution_created_response(&host, EXECUTIONS_ROUTE, id)
            }
            Err(error) => error_response(&error, state.retry_after),
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
        super::execution_status_response(
            state
                .plugin
                .get_reset(&id)
                .await
                .map(ExecutionResponse::from),
            query.include_schema,
        )
    }

    impl super::ExecutionStatusBody for ExecutionResponse {
        fn set_schema(&mut self, schema: schemars::Schema) {
            self.schema = Some(schema);
        }
    }

    pub(crate) async fn delete_id(
        State(state): State<VehicleTopologyRouteState>,
        UseApi(Secured(sec_plugin), _): UseApi<Secured, ()>,
        Path(id): Path<String>,
    ) -> Response {
        let claims = sec_plugin.as_auth_plugin().claims();
        if let Err(response) = require_exclusive_vehicle_lock(&state, &claims).await {
            return response.into_response();
        }
        if state.plugin.delete_reset(&id).await {
            StatusCode::NO_CONTENT.into_response()
        } else {
            super::no_such_execution_response(false)
        }
    }

    type ErrorBody = Json<ApiErrorResponse<VendorErrorCode>>;

    fn lock_docs(op: TransformOperation) -> TransformOperation {
        op.response_with::<409, ErrorBody, _>(|res| res.description(LOCK_CONFLICT))
            .response_with::<423, ErrorBody, _>(|res| res.description(LOCKED))
    }

    fn docs_post(op: TransformOperation) -> TransformOperation {
        op.description(POST_DESCRIPTION)
            .response_with::<202, Json<ExecutionCreatedResponse>, _>(
                |mut res: TransformResponse<'_, ExecutionCreatedResponse>| {
                    res.inner().headers.insert(
                        "Location".to_owned(),
                        openapi::location_header(
                            "URI of the created execution.",
                            "http://localhost:20002/vehicle/v15/apps/sovd2uds/operations/\
                             networkreset/executions/550e8400-e29b-41d4-a716-446655440000",
                        ),
                    );
                    res.description("Execution accepted")
                },
            )
            .response_with::<400, ErrorBody, _>(|res| res.description(INVALID_BODY))
            .response_with::<409, ErrorBody, _>(|mut res| {
                res.inner()
                    .headers
                    .insert("Retry-After".to_owned(), openapi::retry_after_header());
                res.description(POST_CONFLICT)
            })
            .response_with::<423, ErrorBody, _>(|res| res.description(LOCKED))
            .response_with::<500, ErrorBody, _>(|res| res.description(RESET_FAILED))
    }

    pub fn routes<S: cda_plugin_security::SecurityPluginLoader>(
        state: VehicleTopologyRouteState,
    ) -> ApiRouter {
        ApiRouter::new()
            .api_route(
                PATH,
                get_with(details, |op| {
                    op.description("Retrieve network reset details and supported capabilities")
                        .response::<200, Json<OperationResponse>>()
                }),
            )
            .api_route(DOCS_ROUTE, get_with(docs_endpoint, docs_endpoint_transform))
            .api_route(
                EXECUTIONS_ROUTE,
                get_with(get, |op| {
                    op.description("List network reset executions")
                        .response::<200, Json<ExecutionListResponse>>()
                })
                .merge(post_with(post, docs_post)),
            )
            .api_route(
                EXECUTIONS_ID_ROUTE,
                get_with(get_id, |op| {
                    op.description("Read network reset execution status")
                        .response::<200, Json<ExecutionResponse>>()
                        .response_with::<404, ErrorBody, _>(|res| {
                            res.description(super::NO_SUCH_EXECUTION)
                        })
                })
                .merge(delete_with(delete_id, |op| {
                    op.description(
                        "Terminate and remove a network reset execution. Requires the caller's \
                         exclusive vehicle lock.",
                    )
                    .response::<204, ()>()
                    .response_with::<404, ErrorBody, _>(|res| {
                        res.description(super::NO_SUCH_EXECUTION)
                    })
                    .with(lock_docs)
                })),
            )
            .layer(axum::middleware::from_fn(
                cda_plugin_security::security_plugin_middleware::<S>,
            ))
            .with_state(state)
    }

    #[cfg(test)]
    mod tests {
        use std::{
            sync::Mutex,
            time::{Duration, SystemTime},
        };

        use axum::{
            body::Body,
            http::{
                Request,
                header::{LOCATION, RETRY_AFTER},
            },
        };
        use cda_interfaces::{
            http_protection::registry::{
                HttpMethod, HttpProtectionConfig, HttpProtectionReason, HttpProtectionRegistry,
                HttpRouteMatcher, HttpStatusCode, OwnedHttpProtection,
            },
            topology::{
                NETWORK_STRUCTURE_ROUTE, NetworkResetExecution, NetworkResetFlags,
                NetworkResetStatus,
            },
        };
        use cda_plugin_security::mock::TestSecurityPlugin;
        use tower::ServiceExt;

        use super::*;
        use crate::sovd::{
            Locks,
            locks::{
                break_test_vehicle_lock, insert_test_vehicle_lock, insert_test_vehicle_lock_with,
                remove_test_vehicle_lock,
            },
            request_guard::HttpRestrictionLayer,
        };

        #[derive(Default)]
        struct StubPlugin {
            started: Mutex<Vec<NetworkResetFlags>>,
            /// The timeout of every started execution.
            timeouts: Mutex<Vec<Option<Duration>>>,
            deleted: Mutex<Vec<String>>,
            /// Answer of `start_reset`, as the real plugin would give it.
            start_error: Mutex<Option<NetworkResetError>>,
            /// Executions reported by `list_resets` and `get_reset`.
            executions: Vec<NetworkResetExecution>,
            /// Protection held while an execution "runs".
            protection: Mutex<Option<OwnedHttpProtection>>,
            protections: Option<HttpProtectionRegistry>,
            admission_gate: Option<Arc<AdmissionGate>>,
            /// Holds `delete_reset` until resumed, like steps that are still running.
            delete_gate: Option<Arc<AdmissionGate>>,
        }

        #[derive(Default)]
        struct AdmissionGate {
            entered: tokio::sync::Notify,
            resume: tokio::sync::Notify,
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
                timeout: Option<Duration>,
            ) -> Result<String, NetworkResetError> {
                if !flags.clear_persisted && !flags.trigger_detection {
                    return Err(NetworkResetError::InvalidRequest(
                        "both flags are false".to_owned(),
                    ));
                }
                if let Some(error) = self.start_error.lock().unwrap().clone() {
                    return Err(error);
                }
                if let Some(gate) = &self.admission_gate {
                    gate.entered.notify_one();
                    gate.resume.notified().await;
                }
                if let Some(registry) = &self.protections {
                    // Same protection the default plugin installs while it runs.
                    let protection = registry
                        .protect(
                            HttpProtectionConfig::new(
                                HttpProtectionReason::NetworkResetInProgress,
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
                self.timeouts.lock().unwrap().push(timeout);
                Ok("exec-1".to_owned())
            }
            async fn list_resets(&self) -> Vec<NetworkResetExecution> {
                self.executions.clone()
            }
            async fn get_reset(&self, id: &str) -> Option<NetworkResetExecution> {
                self.executions.iter().find(|exec| exec.id == id).cloned()
            }
            async fn delete_reset(&self, id: &str) -> bool {
                if let Some(gate) = &self.delete_gate {
                    gate.entered.notify_one();
                    gate.resume.notified().await;
                }
                self.deleted.lock().unwrap().push(id.to_owned());
                id == "exec-1"
            }
        }

        /// How the vehicle lock is held; `TestSecurityPlugin` authenticates as `test_user`.
        #[derive(Clone, Copy, Debug)]
        enum Lock {
            None,
            Exclusive(&'static str),
            NonExclusive(&'static str),
            Expired(&'static str),
            /// `test_user`'s exclusive vehicle lock, preempted by another client.
            Broken,
        }

        async fn locks(lock: Lock) -> Arc<SovdLockStateProvider> {
            let locks = Arc::new(Locks::new());
            let in_five_minutes = SystemTime::now()
                .checked_add(Duration::from_secs(300))
                .expect("test expiration should be representable");
            match lock {
                Lock::None => {}
                Lock::Exclusive(owner) => insert_test_vehicle_lock(&locks, owner).await,
                Lock::NonExclusive(owner) => {
                    insert_test_vehicle_lock_with(&locks, owner, false, in_five_minutes).await;
                }
                Lock::Expired(owner) => {
                    let expired = SystemTime::now()
                        .checked_sub(Duration::from_secs(1))
                        .expect("now is after the epoch");
                    insert_test_vehicle_lock_with(&locks, owner, true, expired).await;
                }
                Lock::Broken => {
                    insert_test_vehicle_lock(&locks, "test_user").await;
                    break_test_vehicle_lock(&locks, "someone_else").await;
                }
            }
            Arc::new(SovdLockStateProvider::new(locks))
        }

        async fn state(plugin: &Arc<StubPlugin>, lock: Lock) -> VehicleTopologyRouteState {
            VehicleTopologyRouteState {
                plugin: Arc::clone(plugin) as Arc<dyn VehicleTopologyPlugin>,
                locks: locks(lock).await,
                retry_after: Duration::from_secs(1),
            }
        }

        async fn app_with(plugin: StubPlugin, lock: Lock) -> (axum::Router, Arc<StubPlugin>) {
            let plugin = Arc::new(plugin);
            let state = state(&plugin, lock).await;
            (
                axum::Router::from(routes::<TestSecurityPlugin>(state)),
                plugin,
            )
        }

        async fn app(lock: Lock) -> (axum::Router, Arc<StubPlugin>) {
            app_with(StubPlugin::default(), lock).await
        }

        fn request(method: &str, uri: &str) -> axum::http::request::Builder {
            Request::builder()
                .method(method)
                .uri(uri)
                .header("host", "localhost")
        }

        async fn json(response: Response) -> serde_json::Value {
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            serde_json::from_slice(&bytes).expect("Response bodies must be JSON")
        }

        /// The status and, for an error, the `error_code`, `vendor_code` and `message`.
        async fn outcome(response: Response) -> (StatusCode, serde_json::Value) {
            let status = response.status();
            if status.is_success() {
                return (status, serde_json::Value::Null);
            }
            let body = json(response).await;
            (
                status,
                serde_json::json!({
                    "error_code": body.get("error_code"),
                    "vendor_code": body.get("vendor_code"),
                    "message": body.get("message"),
                }),
            )
        }

        fn error(error_code: &str, vendor_code: Option<&str>, message: &str) -> serde_json::Value {
            serde_json::json!({
                "error_code": error_code,
                "vendor_code": vendor_code,
                "message": message,
            })
        }

        fn lock_required(message: &str) -> serde_json::Value {
            error("vendor-specific", Some("lock-required"), message)
        }

        fn locked() -> serde_json::Value {
            error(
                "vendor-specific",
                Some("lock-owned-by-another-client"),
                "Vehicle lock is held by another client",
            )
        }

        fn lock_broken() -> serde_json::Value {
            error("lock-broken", None, "Client lock was broken")
        }

        async fn post(body: Option<(&str, Option<&str>)>) -> (StatusCode, Vec<NetworkResetFlags>) {
            let (router, plugin) = app(Lock::Exclusive("test_user")).await;
            let mut builder = request("POST", EXECUTIONS_ROUTE);
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
                let value = json(response).await;
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
            ] {
                let (status, started) = post(body).await;
                assert_eq!(status, StatusCode::ACCEPTED, "{body:?}");
                assert_eq!(started, vec![BOTH], "{body:?}");
            }
        }

        /// [[ test~plugin-vehicle-topology-reset-http-timeout, The SOVD execution timeout is passed to the plugin, test ]]
        #[tokio::test]
        async fn execution_timeout_is_passed_to_the_plugin() {
            for (body, expected) in [
                (r#"{"timeout": 30}"#, Some(Duration::from_secs(30))),
                (r#"{"timeout": 1}"#, Some(Duration::from_secs(1))),
                (r#"{"timeout": null}"#, None),
                ("{}", None),
            ] {
                let (router, plugin) = app(Lock::Exclusive("test_user")).await;
                let response = router
                    .oneshot(
                        request("POST", EXECUTIONS_ROUTE)
                            .header(CONTENT_TYPE, "application/json")
                            .body(Body::from(body))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::ACCEPTED, "{body}");
                assert_eq!(*plugin.timeouts.lock().unwrap(), vec![expected], "{body}");
            }
        }

        /// [[ test~plugin-vehicle-topology-reset-http-misunderstood-bodies-are-rejected-without-executing, A misunderstood networkreset body is rejected and nothing is executed, test ]]
        #[tokio::test]
        async fn misunderstood_bodies_are_rejected_without_executing() {
            for body in [
                Some((r#"{"clear_persisted": false}"#, JSON)),
                Some((r#"{"parameters": {"clear_persited": false}}"#, JSON)),
                Some((r#"{"parameters": {"clear_persisted": "no"}}"#, JSON)),
                Some(("{not json", JSON)),
                Some(("", JSON)),
                Some((
                    r#"{"parameters": {"clear_persisted": false}}"#,
                    Some("text/plain"),
                )),
                // Without a `Content-Type` a body would not be understood, so it is
                // rejected instead of silently selecting the destructive defaults.
                Some((r#"{"parameters": {"clear_persisted": false}}"#, None)),
                Some(("{}", None)),
                // A timeout of 0 would stop the execution right away.
                Some((r#"{"timeout": 0}"#, JSON)),
                // Too large to represent as a deadline.
                Some((r#"{"timeout": 18446744073709551615}"#, JSON)),
                // Nothing to do.
                Some((
                    r#"{"parameters": {"clear_persisted": false, "trigger_detection": false}}"#,
                    JSON,
                )),
            ] {
                let (status, started) = post(body).await;
                assert_eq!(status, StatusCode::BAD_REQUEST, "{body:?}");
                assert!(started.is_empty(), "{body:?}");
            }
        }

        /// The body is checked before the vehicle lock: a caller without the lock gets
        /// 400 for an invalid body, not 409.
        #[tokio::test]
        async fn invalid_body_is_rejected_before_the_vehicle_lock() {
            for body in [
                r#"{"timeout": 0}"#,
                r#"{"timeout": 18446744073709551615}"#,
                r#"{"parameters": {"clear_persisted": false, "trigger_detection": false}}"#,
                "{not json",
            ] {
                for lock in [Lock::None, Lock::Exclusive("someone_else")] {
                    let (response, started) = post_expecting(lock, None, body).await;
                    assert_eq!(
                        response.status(),
                        StatusCode::BAD_REQUEST,
                        "{body} {lock:?}"
                    );
                    assert!(started.is_empty(), "{body} {lock:?}");
                }
            }
        }

        async fn delete(lock: Lock, id: &str) -> ((StatusCode, serde_json::Value), Vec<String>) {
            let (router, plugin) = app(lock).await;
            let response = router
                .oneshot(
                    request("DELETE", &EXECUTIONS_ID_ROUTE.replace("{id}", id))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let deleted = plugin.deleted.lock().unwrap().clone();
            (outcome(response).await, deleted)
        }

        /// [[ test~plugin-vehicle-topology-reset-delete-lock, networkreset DELETE requires the caller's vehicle lock, test ]]
        #[tokio::test]
        async fn delete_requires_the_callers_vehicle_lock() {
            for (lock, expected) in [
                (
                    Lock::None,
                    (
                        StatusCode::CONFLICT,
                        lock_required("Exclusive vehicle lock required"),
                    ),
                ),
                (
                    Lock::Exclusive("someone_else"),
                    (StatusCode::LOCKED, locked()),
                ),
                (
                    Lock::NonExclusive("test_user"),
                    (
                        StatusCode::CONFLICT,
                        lock_required("Exclusive vehicle lock required"),
                    ),
                ),
                (
                    Lock::Expired("test_user"),
                    (StatusCode::CONFLICT, lock_required("Vehicle lock expired")),
                ),
                (Lock::Broken, (StatusCode::CONFLICT, lock_broken())),
            ] {
                let (outcome, deleted) = delete(lock, "exec-1").await;
                assert_eq!(outcome, expected, "{lock:?}");
                assert!(deleted.is_empty(), "{lock:?}");
            }

            let ((status, _), deleted) = delete(Lock::Exclusive("test_user"), "exec-1").await;
            assert_eq!(status, StatusCode::NO_CONTENT);
            assert_eq!(deleted, vec!["exec-1".to_owned()]);

            let (outcome, _) = delete(Lock::Exclusive("test_user"), "exec-2").await;
            assert_eq!(
                outcome,
                (
                    StatusCode::NOT_FOUND,
                    error(
                        "vendor-specific",
                        Some("not-found"),
                        super::super::NO_SUCH_EXECUTION
                    )
                )
            );
        }

        /// POSTs `body` as the caller `test_user` with the given vehicle lock and the
        /// plugin's `start_reset` answering with `start_error`.
        async fn post_expecting(
            lock: Lock,
            start_error: Option<NetworkResetError>,
            body: &'static str,
        ) -> (Response, Vec<NetworkResetFlags>) {
            let (router, plugin) = app(lock).await;
            *plugin.start_error.lock().unwrap() = start_error;
            let response = router
                .oneshot(
                    request("POST", EXECUTIONS_ROUTE)
                        .header(CONTENT_TYPE, "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            let started = plugin.started.lock().unwrap().clone();
            (response, started)
        }

        /// [[ test~plugin-vehicle-topology-reset-post-lock, networkreset POST requires the caller's exclusive vehicle lock, test ]]
        #[tokio::test]
        async fn post_requires_the_callers_exclusive_vehicle_lock() {
            for (lock, expected) in [
                (
                    Lock::None,
                    (
                        StatusCode::CONFLICT,
                        lock_required("Exclusive vehicle lock required"),
                    ),
                ),
                (
                    Lock::Exclusive("someone_else"),
                    (StatusCode::LOCKED, locked()),
                ),
                (
                    Lock::NonExclusive("test_user"),
                    (
                        StatusCode::CONFLICT,
                        lock_required("Exclusive vehicle lock required"),
                    ),
                ),
                // Past its expiration but not removed by the expiration task yet.
                (
                    Lock::Expired("test_user"),
                    (StatusCode::CONFLICT, lock_required("Vehicle lock expired")),
                ),
                (Lock::Broken, (StatusCode::CONFLICT, lock_broken())),
            ] {
                let (response, started) = post_expecting(lock, None, "{}").await;
                assert_eq!(outcome(response).await, expected, "{lock:?}");
                assert!(started.is_empty(), "{lock:?}");
            }

            let (response, started) =
                post_expecting(Lock::Exclusive("test_user"), None, "{}").await;
            assert_eq!(response.status(), StatusCode::ACCEPTED);
            assert_eq!(
                response
                    .headers()
                    .get(LOCATION)
                    .and_then(|value| value.to_str().ok()),
                Some(format!("http://localhost{EXECUTIONS_ROUTE}/exec-1").as_str())
            );
            assert_eq!(json(response).await, serde_json::json!({ "id": "exec-1" }));
            assert_eq!(started, vec![BOTH]);
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
                let (response, started) =
                    post_expecting(Lock::Exclusive("test_user"), Some(error.clone()), "{}").await;
                assert_eq!(response.status(), StatusCode::CONFLICT, "{error}");
                assert_eq!(
                    response
                        .headers()
                        .get(RETRY_AFTER)
                        .and_then(|value| value.to_str().ok()),
                    Some("1"),
                    "{error}"
                );
                assert!(started.is_empty(), "{error}");
            }
        }

        /// [[ test~plugin-vehicle-topology-reset-post-admission-lock, A lost vehicle lock requests deletion of an admitted reset, test ]]
        #[tokio::test]
        async fn lock_lost_during_admission_requests_deletion() {
            #[derive(Debug)]
            enum Loss {
                Released,
                TakenOver,
                Broken,
            }
            for loss in [Loss::Released, Loss::TakenOver, Loss::Broken] {
                let gate = Arc::new(AdmissionGate::default());
                let plugin = Arc::new(StubPlugin {
                    admission_gate: Some(Arc::clone(&gate)),
                    ..Default::default()
                });
                let state = state(&plugin, Lock::Exclusive("test_user")).await;
                let locks = state.locks.current_locks().await;
                let request = request("POST", EXECUTIONS_ROUTE)
                    .body(Body::empty())
                    .expect("valid request");
                let task = tokio::spawn(async move {
                    axum::Router::from(routes::<TestSecurityPlugin>(state))
                        .oneshot(request)
                        .await
                        .expect("router response")
                });
                gate.entered.notified().await;
                match loss {
                    Loss::Released => remove_test_vehicle_lock(&locks).await,
                    Loss::TakenOver => {
                        remove_test_vehicle_lock(&locks).await;
                        insert_test_vehicle_lock(&locks, "someone_else").await;
                    }
                    Loss::Broken => break_test_vehicle_lock(&locks, "someone_else").await,
                }
                gate.resume.notify_one();
                let response = task.await.expect("request task completes");
                let expected = match loss {
                    Loss::Released => (
                        StatusCode::CONFLICT,
                        lock_required(&format!(
                            "Exclusive vehicle lock required. {LOCK_LOST_NOTE}"
                        )),
                    ),
                    Loss::TakenOver => (
                        StatusCode::LOCKED,
                        error(
                            "vendor-specific",
                            Some("lock-owned-by-another-client"),
                            &format!("Vehicle lock is held by another client. {LOCK_LOST_NOTE}"),
                        ),
                    ),
                    Loss::Broken => (
                        StatusCode::CONFLICT,
                        error(
                            "lock-broken",
                            None,
                            &format!("Client lock was broken. {LOCK_LOST_NOTE}"),
                        ),
                    ),
                };
                assert_eq!(outcome(response).await, expected, "{loss:?}");
                assert_eq!(*plugin.started.lock().expect("started lock"), vec![BOTH]);
                assert_eq!(
                    *plugin.deleted.lock().expect("deleted lock"),
                    vec!["exec-1".to_owned()]
                );
            }
        }

        /// When the lock is lost after admission, POST answers only once `delete_reset`
        /// returned, i.e. once steps already started have finished.
        #[tokio::test]
        async fn lock_lost_during_admission_waits_for_the_deletion() {
            let admission = Arc::new(AdmissionGate::default());
            let deletion = Arc::new(AdmissionGate::default());
            let plugin = Arc::new(StubPlugin {
                admission_gate: Some(Arc::clone(&admission)),
                delete_gate: Some(Arc::clone(&deletion)),
                ..Default::default()
            });
            let state = state(&plugin, Lock::Exclusive("test_user")).await;
            let locks = state.locks.current_locks().await;
            let request = request("POST", EXECUTIONS_ROUTE)
                .body(Body::empty())
                .expect("valid request");
            let task = tokio::spawn(async move {
                axum::Router::from(routes::<TestSecurityPlugin>(state))
                    .oneshot(request)
                    .await
                    .expect("router response")
            });
            admission.entered.notified().await;
            remove_test_vehicle_lock(&locks).await;
            admission.resume.notify_one();

            deletion.entered.notified().await;
            assert!(!task.is_finished(), "POST must wait for the deletion");
            deletion.resume.notify_one();
            let response = task.await.expect("request task completes");
            assert_eq!(response.status(), StatusCode::CONFLICT);
            assert_eq!(
                *plugin.deleted.lock().expect("deleted lock"),
                vec!["exec-1".to_owned()]
            );
        }

        /// [[ test~plugin-vehicle-topology-reset-http-errors, Invalid reset requests and internal failures return their documented status, test ]]
        #[tokio::test]
        async fn post_maps_invalid_requests_and_failures() {
            for (error, expected) in [
                (
                    NetworkResetError::InvalidRequest("timeout is too large".to_owned()),
                    StatusCode::BAD_REQUEST,
                ),
                (
                    NetworkResetError::Failed("admission failed".to_owned()),
                    StatusCode::INTERNAL_SERVER_ERROR,
                ),
            ] {
                let (response, started) =
                    post_expecting(Lock::Exclusive("test_user"), Some(error), "{}").await;
                assert_eq!(response.status(), expected);
                assert!(response.headers().get(RETRY_AFTER).is_none());
                assert!(started.is_empty());
            }
        }

        /// `GET .../networkreset` describes the asynchronous operation under its id, and
        /// with `include-schema` adds the JSON schema of the response.
        #[tokio::test]
        async fn details_describe_the_operation() {
            for include_schema in [false, true] {
                let (router, _) = app(Lock::None).await;
                let response = router
                    .oneshot(
                        request("GET", &format!("{PATH}?include-schema={include_schema}"))
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                let body = json(response).await;
                assert_eq!(
                    body.get("item"),
                    Some(&serde_json::json!({
                        "id": OPERATION_ID,
                        "name": OPERATION_ID,
                        "proximity_proof_required": false,
                        "asynchronous_execution": true,
                    }))
                );
                let schema = body.get("schema");
                assert_eq!(schema.is_some(), include_schema);
                if let Some(schema) = schema {
                    assert_eq!(
                        schema,
                        &serde_json::Value::from(crate::create_schema!(OperationResponse))
                    );
                    assert!(schema.pointer("/properties/item").is_some());
                }
            }
        }

        /// `GET .../networkreset/docs` returns an `OpenAPI` document describing the
        /// asynchronous execution, with the request and response parameters.
        #[tokio::test]
        async fn docs_describe_the_executions() {
            let (router, _) = app(Lock::None).await;
            let response = router
                .oneshot(request("GET", DOCS_ROUTE).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let doc = json(response).await;
            let paths = doc.get("paths").expect("OpenAPI document must have paths");
            let executions = paths
                .get(format!("{DOCS_BASE_PATH}/executions"))
                .expect("executions path missing");
            assert_eq!(
                executions.pointer("/post/x-sovd-asynchronous-execution"),
                Some(&serde_json::Value::Bool(true))
            );
            for name in ["clear_persisted", "trigger_detection"] {
                assert_eq!(
                    executions
                        .pointer(&format!(
                            "/post/requestBody/content/application~1json/schema/properties/\
                             parameters/properties/{name}/default"
                        ))
                        .and_then(serde_json::Value::as_bool),
                    Some(true),
                    "{name}"
                );
            }
            let execution = paths
                .get(format!("{DOCS_BASE_PATH}/executions/{{execution-id}}"))
                .expect("execution path missing");
            assert!(
                execution
                    .pointer(
                        "/get/responses/200/content/application~1json/schema/properties/\
                         parameters/properties/clear_persisted"
                    )
                    .is_some()
            );
            assert!(execution.get("delete").is_some());
        }

        /// `GET .../executions` lists the ids of the executions.
        #[tokio::test]
        async fn list_returns_the_execution_ids() {
            let (router, _) = app_with(
                StubPlugin {
                    executions: vec![NetworkResetExecution {
                        id: "exec-1".to_owned(),
                        flags: BOTH,
                        status: NetworkResetStatus::Running,
                    }],
                    ..Default::default()
                },
                Lock::None,
            )
            .await;
            let response = router
                .oneshot(
                    request("GET", EXECUTIONS_ROUTE)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                json(response).await,
                serde_json::json!({ "items": [{ "id": "exec-1" }] })
            );
        }

        /// `GET .../executions/{id}` maps the execution status, and reports a failure
        /// both in `error` and in `parameters.reason`.
        #[tokio::test]
        async fn get_id_maps_the_execution_status() {
            let (router, _) = app_with(
                StubPlugin {
                    executions: vec![
                        NetworkResetExecution {
                            id: "failed".to_owned(),
                            flags: NetworkResetFlags {
                                clear_persisted: true,
                                trigger_detection: false,
                            },
                            status: NetworkResetStatus::Failed(
                                cda_interfaces::topology::NetworkResetFailure::SettleTimedOut,
                            ),
                        },
                        NetworkResetExecution {
                            id: "completed".to_owned(),
                            flags: BOTH,
                            status: NetworkResetStatus::Completed,
                        },
                    ],
                    ..Default::default()
                },
                Lock::None,
            )
            .await;
            let get = |id: &str| {
                router.clone().oneshot(
                    request("GET", &EXECUTIONS_ID_ROUTE.replace("{id}", id))
                        .body(Body::empty())
                        .unwrap(),
                )
            };

            let response = get("failed").await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                json(response).await,
                serde_json::json!({
                    "status": "failed",
                    "capability": "execute",
                    "parameters": {
                        "clear_persisted": true,
                        "trigger_detection": false,
                        "reason": "Rediscovery did not settle in time",
                    },
                    "error": [{
                        "path": "/",
                        "error": {
                            "message": "Rediscovery did not settle in time",
                            "error_code": "sovd-server-failure",
                        },
                    }],
                })
            );

            let response = get("completed").await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                json(response).await,
                serde_json::json!({
                    "status": "completed",
                    "capability": "execute",
                    "parameters": { "clear_persisted": true, "trigger_detection": true },
                })
            );

            let (status, error_body) = outcome(get("unknown").await.unwrap()).await;
            assert_eq!(status, StatusCode::NOT_FOUND);
            assert_eq!(
                error_body,
                error(
                    "vendor-specific",
                    Some("not-found"),
                    super::super::NO_SUCH_EXECUTION
                )
            );
        }

        /// [[ test~plugin-vehicle-topology-reset-openapi-failure, The networkreset route documentation lists internal failure responses, test ]]
        #[tokio::test]
        async fn reset_openapi_documents_internal_server_errors() {
            let plugin = Arc::new(StubPlugin::default());
            let state = state(&plugin, Lock::None).await;
            let mut api = aide::openapi::OpenApi::default();
            let _router = routes::<TestSecurityPlugin>(state).finish_api(&mut api);
            let document = serde_json::to_value(api).expect("OpenAPI document");
            let paths = document.get("paths").expect("paths");
            let path = paths.get(EXECUTIONS_ROUTE).expect("executions path");
            assert!(
                path.pointer("/post/responses/500/content/application~1json/schema")
                    .is_some()
            );
            assert_eq!(
                path.pointer("/post/responses/500/description")
                    .and_then(serde_json::Value::as_str),
                Some(RESET_FAILED)
            );
            assert!(
                path.pointer("/post/responses/202/headers/Location")
                    .is_some()
            );
            assert!(
                path.pointer("/post/responses/409/headers/Retry-After")
                    .is_some()
            );
            let id_path = paths.get(EXECUTIONS_ID_ROUTE).expect("execution path");
            for method in ["get", "delete"] {
                assert!(
                    id_path
                        .pointer(&format!(
                            "/{method}/responses/404/content/application~1json/schema"
                        ))
                        .is_some(),
                    "{method}"
                );
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
                .oneshot(request("GET", uri).body(Body::empty()).unwrap())
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
            let state = state(&plugin, Lock::Exclusive("test_user")).await;
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
                    request("POST", EXECUTIONS_ROUTE)
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

/// Describes a built-in operation in its operation resource. Its name is its id, as in
/// the operations collection.
fn operation_item(
    id: &str,
    asynchronous_execution: bool,
) -> sovd_interfaces::common::operations::OperationCollectionItem {
    sovd_interfaces::common::operations::OperationCollectionItem {
        id: id.to_owned(),
        name: id.to_owned(),
        proximity_proof_required: false,
        asynchronous_execution,
    }
}

const NO_SUCH_EXECUTION: &str = "There is no execution with this id";

/// Response of `GET .../executions` of a built-in operation: the ids of its executions.
fn execution_list_response(ids: impl Iterator<Item = String>) -> axum::response::Response {
    use axum::response::IntoResponse as _;

    let items = ids
        .map(|id| sovd_interfaces::common::operations::OperationIdItem { id })
        .collect();
    (
        axum::http::StatusCode::OK,
        axum::Json(sovd_interfaces::common::operations::ExecutionListResponse { items }),
    )
        .into_response()
}

/// Response of an accepted `POST .../executions` of a built-in operation: 202 with the
/// execution id and its URI in `Location`.
fn execution_created_response(
    host: &str,
    executions_route: &str,
    id: String,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;

    let location = format!("http://{host}{executions_route}/{id}");
    (
        axum::http::StatusCode::ACCEPTED,
        [(axum::http::header::LOCATION, location)],
        axum::Json(sovd_interfaces::common::operations::ExecutionCreatedResponse { id }),
    )
        .into_response()
}

/// The status body of an execution of a built-in operation.
trait ExecutionStatusBody: serde::Serialize + schemars::JsonSchema {
    /// Sets the schema of the body, requested with `include-schema=true`.
    fn set_schema(&mut self, schema: schemars::Schema);
}

/// Response of `GET .../executions/{id}` of a built-in operation: 200 with the status of
/// the execution, 404 if there is no such execution.
fn execution_status_response<R: ExecutionStatusBody>(
    execution: Option<R>,
    include_schema: bool,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;

    match execution {
        Some(mut response) => {
            if include_schema {
                response.set_schema(crate::create_schema!(R));
            }
            (axum::http::StatusCode::OK, axum::Json(response)).into_response()
        }
        None => no_such_execution_response(include_schema),
    }
}

/// 404 with a SOVD error body, for an unknown execution id.
fn no_such_execution_response(include_schema: bool) -> axum::response::Response {
    use axum::response::IntoResponse as _;

    crate::sovd::error::ErrorWrapper {
        error: crate::sovd::error::ApiError::NotFound(Some(NO_SUCH_EXECUTION.to_owned())),
        include_schema,
    }
    .into_response()
}

/// The online capability description of an app operation (`GET .../docs`): a
/// self-contained `OpenAPI` document, built like the ECU and functional-group
/// operation docs.
fn operation_docs(
    id: &str,
    base_path: &str,
    is_async: bool,
    request_params_schema: schemars::Schema,
    response_params_schema: schemars::Schema,
) -> axum::Json<aide::openapi::OpenApi> {
    let meta = crate::sovd::docs::operations::OperationDocsMeta {
        name: id.to_owned(),
        is_async,
        request_params_schema: Some(request_params_schema),
        response_params_schema: Some(response_params_schema),
    };
    let path_items = crate::sovd::docs::operations::build_path_items(base_path, &meta);
    axum::Json(crate::sovd::docs::build_openapi_doc(
        &format!("Operation: {id}"),
        path_items,
    ))
}

/// The route documentation of [`operation_docs`].
fn operation_docs_transform<'a>(
    op: aide::transform::TransformOperation<'a>,
    id: &str,
) -> aide::transform::TransformOperation<'a> {
    op.description(&format!(
        "Online capability description of the {id} operation (ISO 17978-3 Section 7.5). Returns a \
         self-contained OpenAPI specification."
    ))
    .response_with::<200, axum::Json<aide::openapi::OpenApi>, _>(|res| {
        res.description("Self-contained OpenAPI 3.1 specification for this operation.")
    })
}
