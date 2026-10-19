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

/// [[ dimpl~plugin-vehicle-topology-connect-ecu, Connect ECU directly operation, dimpl, req~plugin-vehicle-topology-connect-ecu; arch~plugin-vehicle-topology-connect-ecu ]]
///
/// Connects an ECU directly to an IP address, bypassing VIR/VAM discovery.
///
/// Modelled as an operation with a synchronous execution, as specified for
/// `POST /{entity-path}/operations/{operation-id}/executions` (ISO 17978-3, 7.14.6).
///
/// Preliminary: connecting ECUs belongs to the topology plugin. This operation is
/// a stopgap in the SOVD layer and is expected to be replaced by what the topology
/// plugin provides.
pub(crate) mod doip_connect_ecu {
    use aide::{UseApi, transform::TransformOperation};
    use axum::{
        Json,
        extract::{Query, State},
        http::StatusCode,
        response::{IntoResponse as _, Response},
    };
    use axum_extra::extract::WithRejection;
    use cda_interfaces::{UdsEcu, communication_control::DoipEndpoint};
    use sovd_interfaces::apps::sovd2uds::operations::doip_connect_ecu::{
        ExecutionRequest, ExecutionResponse, ExecutionResponseParameters,
    };

    use crate::sovd::{
        WebserverState, acquire_communication_activity, create_schema,
        error::{ApiError, ErrorWrapper},
    };

    pub(crate) const EXECUTIONS_ROUTE: &str =
        "/vehicle/v15/apps/sovd2uds/operations/doip-connect-ecu/executions";

    // Deliberately requires no ECU lock: the ECU is usually offline when this is
    // called, and nothing is sent to it that a lock would need to protect. The
    // request still has to be authenticated.
    #[tracing::instrument(
        skip(state, query),
        fields(ecu = %request_body.parameters.ecu, ip = %request_body.parameters.ip)
    )]
    pub(crate) async fn post<T: UdsEcu + Clone>(
        UseApi(cda_plugin_security::Secured(_), _): UseApi<cda_plugin_security::Secured, ()>,
        WithRejection(Query(query), _): WithRejection<
            Query<sovd_interfaces::IncludeSchemaQuery>,
            ApiError,
        >,
        State(state): State<WebserverState<T>>,
        WithRejection(Json(request_body), _): WithRejection<Json<ExecutionRequest>, ApiError>,
    ) -> Response {
        let include_schema = query.include_schema;
        let parameters = request_body.parameters;

        let Some(doip_connect) = &state.doip_connect else {
            return ErrorWrapper {
                error: ApiError::NotFound(Some("Direct connect is not enabled".to_owned())),
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
        op.description(
            "Connect an ECU directly to an IP address, bypassing vehicle discovery (VIR/VAM).",
        )
        .input::<Json<ExecutionRequest>>()
        .response_with::<200, Json<ExecutionResponse>, _>(|res| res.description("ECU connected."))
        .response_with::<409, Json<sovd_interfaces::error::ApiErrorResponse<
            crate::sovd::error::VendorErrorCode,
        >>, _>(|res| res.description("ECU is already connected."))
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
        use crate::sovd::Locks;

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
            WebserverState {
                uds: MockUdsEcu::new(),
                locks: Arc::new(Locks::new()),
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
            let response = execute(state(Some(Ok(()))), "10.0.0.5").await;
            assert_eq!(response.status(), StatusCode::OK);
        }

        #[tokio::test]
        async fn already_connected_ecu_is_a_conflict() {
            let response = execute(
                state(Some(Err(DiagServiceError::Conflict(
                    "ECU 'my_ecu' is already connected on 10.0.0.5".to_owned(),
                )))),
                "10.0.0.9",
            )
            .await;
            assert_eq!(response.status(), StatusCode::CONFLICT);
        }

        #[tokio::test]
        async fn invalid_ip_is_a_bad_request() {
            let response = execute(state(Some(Ok(()))), "not-an-ip").await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn disabled_direct_connect_is_not_found() {
            let response = execute(state(None), "10.0.0.5").await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
    }
}

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
    use sovd_interfaces::apps::sovd2uds::operations::runtimefilesupdate::{
        ExecutionCreatedResponse, ExecutionListResponse, ExecutionRequest,
    };

    use crate::sovd::apps::sovd2uds::bulk_data::runtimefiles::{
        DbUpdateErrorResponse, RuntimeUpdateRouteState, require_vehicle_lock,
    };

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
