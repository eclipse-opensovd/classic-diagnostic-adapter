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

/// `networkreset`: reset the vehicle network structure.
pub(crate) mod networkreset {
    use std::{sync::Arc, time::Duration};

    use aide::UseApi;
    use axum::{
        Json,
        extract::{Path, State},
        http::{StatusCode, header::LOCATION},
        response::{IntoResponse, Response},
    };
    use cda_interfaces::{
        runtime_update_api::LockStateProvider,
        topology::{NetworkResetError, VehicleTopologyPlugin},
    };
    use cda_plugin_security::Secured;
    use opensovd_axum_extra::ExtractHost;
    use sovd_interfaces::{
        apps::sovd2uds::operations::networkreset::{
            ExecutionCreatedResponse, ExecutionListResponse, ExecutionRequest, ExecutionResponse,
        },
        error::{ApiErrorResponse, ErrorCode},
    };

    use crate::sovd::apps::sovd2uds::bulk_data::runtimefiles::require_vehicle_lock;

    /// Name of the operation in the operations collection.
    pub(crate) const OPERATION_ID: &str = "networkreset";
    const EXECUTIONS_ROUTE: &str = "/vehicle/v15/apps/sovd2uds/operations/networkreset/executions";
    const EXECUTIONS_ID_ROUTE: &str =
        "/vehicle/v15/apps/sovd2uds/operations/networkreset/executions/{id}";

    /// State of the `networkreset` routes.
    #[derive(Clone)]
    pub struct VehicleTopologyRouteState {
        pub plugin: Arc<dyn VehicleTopologyPlugin>,
        pub locks: Arc<dyn LockStateProvider>,
        pub retry_after: Duration,
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
        (
            status,
            Json(ApiErrorResponse {
                message: error.to_string(),
                error_code,
                vendor_code,
                parameters: None,
                error_source: None,
                schema: None,
            }),
        )
            .into_response()
    }

    pub(crate) async fn get(State(state): State<VehicleTopologyRouteState>) -> impl IntoResponse {
        let items = state
            .plugin
            .list_resets()
            .await
            .into_iter()
            .map(|exec| sovd_interfaces::common::operations::OperationIdItem { id: exec.id })
            .collect();
        (StatusCode::OK, Json(ExecutionListResponse { items })).into_response()
    }

    /// [[ dimpl~plugin-vehicle-topology-reset-http, networkreset SOVD operation endpoints, dimpl ]]
    pub(crate) async fn post(
        State(state): State<VehicleTopologyRouteState>,
        UseApi(ExtractHost(host), _): UseApi<ExtractHost, String>,
        Secured(sec_plugin): Secured,
        body: Option<Json<ExecutionRequest>>,
    ) -> impl IntoResponse {
        let claims = sec_plugin.as_auth_plugin().claims();
        if let Err(response) = require_vehicle_lock(&*state.locks, *claims, state.retry_after).await
        {
            return response.into_response();
        }
        let flags = body
            .map(|Json(request)| request.parameters.flags())
            .unwrap_or_default();
        match state.plugin.start_reset(flags).await {
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
    ) -> impl IntoResponse {
        match state.plugin.get_reset(&id).await {
            Some(exec) => (StatusCode::OK, Json(ExecutionResponse::from(exec))).into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        }
    }

    pub(crate) async fn delete_id(
        State(state): State<VehicleTopologyRouteState>,
        Path(id): Path<String>,
    ) -> impl IntoResponse {
        if state.plugin.delete_reset(&id).await {
            StatusCode::NO_CONTENT
        } else {
            StatusCode::NOT_FOUND
        }
    }

    pub fn routes<S: cda_plugin_security::SecurityPluginLoader>(
        state: VehicleTopologyRouteState,
    ) -> axum::Router {
        axum::Router::new()
            .route(EXECUTIONS_ROUTE, axum::routing::get(get).post(post))
            .route(
                EXECUTIONS_ID_ROUTE,
                axum::routing::get(get_id).delete(delete_id),
            )
            .layer(axum::middleware::from_fn(
                cda_plugin_security::security_plugin_middleware::<S>,
            ))
            .with_state(state)
    }
}

/// `GET /apps/sovd2uds/operations`: the operations offered by the CDA itself.
pub(crate) mod collection {
    use axum::{Json, http::StatusCode, response::IntoResponse};
    use sovd_interfaces::{Items, components::ecu::operations::OperationCollectionItem};

    const OPERATIONS_ROUTE: &str = "/vehicle/v15/apps/sovd2uds/operations";

    fn item(id: &str, name: &str) -> OperationCollectionItem {
        OperationCollectionItem {
            id: id.to_owned(),
            name: name.to_owned(),
            proximity_proof_required: false,
            asynchronous_execution: true,
        }
    }

    fn items(with_runtime_update: bool) -> Vec<OperationCollectionItem> {
        let mut items = vec![item(super::networkreset::OPERATION_ID, "Network reset")];
        if with_runtime_update {
            items.push(item("runtimefilesupdate", "Runtime files update"));
        }
        items
    }

    pub fn routes<S: cda_plugin_security::SecurityPluginLoader>(
        with_runtime_update: bool,
    ) -> axum::Router {
        axum::Router::new()
            .route(
                OPERATIONS_ROUTE,
                axum::routing::get(move || async move {
                    let items = items(with_runtime_update);
                    (
                        StatusCode::OK,
                        Json(Items {
                            items,
                            schema: None,
                        }),
                    )
                        .into_response()
                }),
            )
            .layer(axum::middleware::from_fn(
                cda_plugin_security::security_plugin_middleware::<S>,
            ))
    }
}
