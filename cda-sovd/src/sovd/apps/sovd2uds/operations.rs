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
