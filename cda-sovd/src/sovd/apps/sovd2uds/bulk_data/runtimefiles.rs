/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

use std::sync::Arc;

use axum::{
    Json,
    http::{HeaderValue, StatusCode, header::RETRY_AFTER},
    response::{IntoResponse, Response},
};
use cda_plugin_runtime_update::{LockStateProvider, RuntimeUpdateError};
use sovd_interfaces::error::{ApiErrorResponse, ErrorCode};

use crate::sovd::update_guard::ExemptRoute;

const EXECUTIONS_ROUTE: &str =
    "/vehicle/v15/apps/sovd2uds/bulk-data/runtimefiles-nextupdate/executions";
const EXECUTIONS_ID_ROUTE: &str =
    "/vehicle/v15/apps/sovd2uds/bulk-data/runtimefiles-nextupdate/executions/{id}";

#[derive(Clone)]
pub struct RuntimeUpdateRouteState {
    pub plugin: Arc<dyn cda_plugin_runtime_update::RuntimeFilesUpdatePlugin>,
    pub lock_state: Arc<dyn LockStateProvider>,
    pub retry_after_seconds: u64,
}

struct DbUpdateErrorResponse {
    error: RuntimeUpdateError,
    retry_after_seconds: u64,
}

impl DbUpdateErrorResponse {
    fn new(error: RuntimeUpdateError, retry_after_seconds: u64) -> Self {
        Self {
            error,
            retry_after_seconds,
        }
    }
}

impl IntoResponse for DbUpdateErrorResponse {
    fn into_response(self) -> Response {
        let (status, error_code, message) = match &self.error {
            RuntimeUpdateError::OperationsInProgress => (
                StatusCode::CONFLICT,
                ErrorCode::UpdateProcessInProgress,
                self.error.to_string(),
            ),
            RuntimeUpdateError::ExecutionConflict => (
                StatusCode::CONFLICT,
                ErrorCode::UpdateExecutionInProgress,
                self.error.to_string(),
            ),
            RuntimeUpdateError::TransactionBusy => {
                let mut resp = (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(ApiErrorResponse::<String> {
                        message: self.error.to_string(),
                        error_code: ErrorCode::UpdateProcessInProgress,
                        vendor_code: None,
                        parameters: None,
                        error_source: None,
                        schema: None,
                    }),
                )
                    .into_response();
                resp.headers_mut().insert(
                    RETRY_AFTER,
                    HeaderValue::from_str(&self.retry_after_seconds.to_string())
                        .expect("numeric retry-after is always valid"),
                );
                return resp;
            }
            RuntimeUpdateError::NoPendingUpdate
            | RuntimeUpdateError::NoBackup
            | RuntimeUpdateError::FileNotFound(_) => (
                StatusCode::NOT_FOUND,
                ErrorCode::VendorSpecific,
                self.error.to_string(),
            ),
            RuntimeUpdateError::InvalidMddFile(_)
            | RuntimeUpdateError::InvalidConfig(_)
            | RuntimeUpdateError::InvalidFileType(_)
            | RuntimeUpdateError::ValidationFailed(_) => (
                StatusCode::BAD_REQUEST,
                ErrorCode::VendorSpecific,
                self.error.to_string(),
            ),
            RuntimeUpdateError::StorageError(_) | RuntimeUpdateError::ReloadFailed(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::SovdServerMisconfigured,
                self.error.to_string(),
            ),
            RuntimeUpdateError::NoLock | RuntimeUpdateError::LockNotOwned => (
                StatusCode::FORBIDDEN,
                ErrorCode::InsufficientAccessRights,
                self.error.to_string(),
            ),
        };

        (
            status,
            Json(ApiErrorResponse::<String> {
                message,
                error_code,
                vendor_code: None,
                parameters: None,
                error_source: None,
                schema: None,
            }),
        )
            .into_response()
    }
}

fn bulk_data_list_response(
    mut list: sovd_interfaces::apps::sovd2uds::bulk_data::BulkDataList,
    include_schema: bool,
) -> Response {
    if include_schema {
        list.schema = Some(crate::sovd::create_schema!(
            sovd_interfaces::apps::sovd2uds::bulk_data::BulkDataList
        ));
    }
    (StatusCode::OK, Json(list)).into_response()
}

async fn require_vehicle_lock(
    lock_state: &dyn LockStateProvider,
    claims: &dyn cda_plugin_security::Claims,
    retry_after_seconds: u64,
) -> Result<(), Response> {
    match lock_state.is_vehicle_lock_owned().await {
        None => Err(
            DbUpdateErrorResponse::new(RuntimeUpdateError::NoLock, retry_after_seconds)
                .into_response(),
        ),
        Some(owner) if owner != claims.sub() => Err(DbUpdateErrorResponse::new(
            RuntimeUpdateError::LockNotOwned,
            retry_after_seconds,
        )
        .into_response()),
        Some(_) => Ok(()),
    }
}

pub(crate) mod current {
    use axum::{
        extract::{Query, State},
        response::{IntoResponse, Response},
    };
    use cda_plugin_security::Secured;

    use super::{DbUpdateErrorResponse, RuntimeUpdateRouteState, require_vehicle_lock};

    pub(crate) async fn get(
        State(route_state): State<RuntimeUpdateRouteState>,
        Secured(sec_plugin): Secured,
        Query(query): Query<
            sovd_interfaces::apps::sovd2uds::bulk_data::runtimefiles::RuntimeFilesQuery,
        >,
    ) -> Response {
        let claims = sec_plugin.as_auth_plugin().claims();
        if let Err(resp) = require_vehicle_lock(
            &*route_state.lock_state,
            *claims,
            route_state.retry_after_seconds,
        )
        .await
        {
            return resp;
        }
        route_state
            .plugin
            .list_current(&query)
            .await
            .map_or_else(
                |e| DbUpdateErrorResponse::new(e, route_state.retry_after_seconds).into_response(),
                |list| super::bulk_data_list_response(list, query.include_schema),
            )
    }
}

pub(crate) mod nextupdate {
    use axum::{
        Json,
        extract::{Query, State},
        http::StatusCode,
        response::{IntoResponse, Response},
    };
    use cda_plugin_runtime_update::{RuntimeUpdateError, UploadFile};
    use cda_plugin_security::Secured;

    use super::{DbUpdateErrorResponse, RuntimeUpdateRouteState, require_vehicle_lock};

    pub(crate) async fn get(
        State(route_state): State<RuntimeUpdateRouteState>,
        Secured(sec_plugin): Secured,
        Query(query): Query<
            sovd_interfaces::apps::sovd2uds::bulk_data::runtimefiles::RuntimeFilesQuery,
        >,
    ) -> Response {
        let claims = sec_plugin.as_auth_plugin().claims();
        if let Err(resp) = require_vehicle_lock(
            &*route_state.lock_state,
            *claims,
            route_state.retry_after_seconds,
        )
        .await
        {
            return resp;
        }
        route_state
            .plugin
            .list_nextupdate(&query)
            .await
            .map_or_else(
                |e| DbUpdateErrorResponse::new(e, route_state.retry_after_seconds).into_response(),
                |list| super::bulk_data_list_response(list, query.include_schema),
            )
    }

    pub(crate) async fn post(
        State(route_state): State<RuntimeUpdateRouteState>,
        Secured(sec_plugin): Secured,
        mut multipart: axum::extract::Multipart,
    ) -> impl IntoResponse {
        let claims = sec_plugin.as_auth_plugin().claims();
        if let Err(resp) = require_vehicle_lock(
            &*route_state.lock_state,
            *claims,
            route_state.retry_after_seconds,
        )
        .await
        {
            return resp.into_response();
        }

        let mut files = Vec::new();
        while let Ok(Some(field)) = multipart.next_field().await {
            let Some(filename) = field.file_name().map(str::to_owned) else {
                continue;
            };
            match field.bytes().await {
                Ok(data) => files.push(UploadFile { filename, data }),
                Err(e) => {
                    return DbUpdateErrorResponse::new(
                        RuntimeUpdateError::ValidationFailed(e.to_string()),
                        route_state.retry_after_seconds,
                    )
                    .into_response();
                }
            }
        }

        route_state.plugin.upload(files).await.map_or_else(
            |e| DbUpdateErrorResponse::new(e, route_state.retry_after_seconds).into_response(),
            |result| (StatusCode::CREATED, Json(result)).into_response(),
        )
    }

    pub(crate) async fn delete(
        State(route_state): State<RuntimeUpdateRouteState>,
        Secured(sec_plugin): Secured,
    ) -> impl IntoResponse {
        let claims = sec_plugin.as_auth_plugin().claims();
        if let Err(resp) = require_vehicle_lock(
            &*route_state.lock_state,
            *claims,
            route_state.retry_after_seconds,
        )
        .await
        {
            return resp.into_response();
        }
        route_state.plugin.delete_nextupdate().await.map_or_else(
            |e| DbUpdateErrorResponse::new(e, route_state.retry_after_seconds).into_response(),
            |()| StatusCode::NO_CONTENT.into_response(),
        )
    }

    pub(crate) mod id {
        use axum::{
            extract::{Path, State},
            http::StatusCode,
            response::IntoResponse,
        };
        use cda_plugin_security::Secured;

        use super::super::{DbUpdateErrorResponse, RuntimeUpdateRouteState, require_vehicle_lock};

        pub(crate) async fn delete(
            State(route_state): State<RuntimeUpdateRouteState>,
            Secured(sec_plugin): Secured,
            Path(id): Path<String>,
        ) -> impl IntoResponse {
            let claims = sec_plugin.as_auth_plugin().claims();
            if let Err(resp) = require_vehicle_lock(
                &*route_state.lock_state,
                *claims,
                route_state.retry_after_seconds,
            )
            .await
            {
                return resp.into_response();
            }
            route_state
                .plugin
                .delete_nextupdate_by_id(&id)
                .await
                .map_or_else(
                    |e| {
                        DbUpdateErrorResponse::new(e, route_state.retry_after_seconds)
                            .into_response()
                    },
                    |()| StatusCode::NO_CONTENT.into_response(),
                )
        }
    }
}

pub(crate) mod backup {
    use axum::{
        extract::{Query, State},
        http::StatusCode,
        response::{IntoResponse, Response},
    };
    use cda_plugin_security::Secured;

    use super::{DbUpdateErrorResponse, RuntimeUpdateRouteState, require_vehicle_lock};

    pub(crate) async fn get(
        State(route_state): State<RuntimeUpdateRouteState>,
        Secured(sec_plugin): Secured,
        Query(query): Query<
            sovd_interfaces::apps::sovd2uds::bulk_data::runtimefiles::RuntimeFilesQuery,
        >,
    ) -> Response {
        let claims = sec_plugin.as_auth_plugin().claims();
        if let Err(resp) = require_vehicle_lock(
            &*route_state.lock_state,
            *claims,
            route_state.retry_after_seconds,
        )
        .await
        {
            return resp;
        }
        route_state
            .plugin
            .list_backup(&query)
            .await
            .map_or_else(
                |e| DbUpdateErrorResponse::new(e, route_state.retry_after_seconds).into_response(),
                |list| super::bulk_data_list_response(list, query.include_schema),
            )
    }

    pub(crate) async fn delete(
        State(route_state): State<RuntimeUpdateRouteState>,
        Secured(sec_plugin): Secured,
    ) -> impl IntoResponse {
        let claims = sec_plugin.as_auth_plugin().claims();
        if let Err(resp) = require_vehicle_lock(
            &*route_state.lock_state,
            *claims,
            route_state.retry_after_seconds,
        )
        .await
        {
            return resp.into_response();
        }
        route_state.plugin.delete_backup().await.map_or_else(
            |e| DbUpdateErrorResponse::new(e, route_state.retry_after_seconds).into_response(),
            |()| StatusCode::NO_CONTENT.into_response(),
        )
    }
}

pub(crate) mod executions {
    use axum::{
        Json,
        extract::{Path, State},
        http::StatusCode,
        response::IntoResponse,
    };
    use cda_plugin_security::Secured;

    use super::{DbUpdateErrorResponse, RuntimeUpdateRouteState, require_vehicle_lock};

    pub(crate) async fn post(
        State(route_state): State<RuntimeUpdateRouteState>,
        Secured(sec_plugin): Secured,
        Json(body): Json<
            sovd_interfaces::apps::sovd2uds::bulk_data::runtimefiles::ExecutionRequest,
        >,
    ) -> impl IntoResponse {
        let claims = sec_plugin.as_auth_plugin().claims();
        if let Err(resp) = require_vehicle_lock(
            &*route_state.lock_state,
            *claims,
            route_state.retry_after_seconds,
        )
        .await
        {
            return resp.into_response();
        }
        route_state
            .plugin
            .start_execution(body.mode)
            .await
            .map_or_else(
                |e| DbUpdateErrorResponse::new(e, route_state.retry_after_seconds).into_response(),
                |id| (StatusCode::ACCEPTED, Json(serde_json::json!({ "id": id }))).into_response(),
            )
    }

    pub(crate) async fn get(
        State(route_state): State<RuntimeUpdateRouteState>,
        Path(id): Path<String>,
    ) -> impl IntoResponse {
        match route_state.plugin.get_execution_status(&id).await {
            Some(exec) => (
                StatusCode::OK,
                Json(serde_json::json!({
                    "id": exec.id,
                    "mode": format!("{:?}", exec.mode),
                    "status": format!("{:?}", exec.status),
                })),
            )
                .into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        }
    }
}

pub fn routes<S: cda_plugin_security::SecurityPluginLoader>(
    state: RuntimeUpdateRouteState,
    upload_limit: usize,
) -> axum::Router {
    axum::Router::new()
        .route(
            "/vehicle/v15/apps/sovd2uds/bulk-data/runtimefiles-current",
            axum::routing::get(current::get),
        )
        .route(
            "/vehicle/v15/apps/sovd2uds/bulk-data/runtimefiles-nextupdate",
            axum::routing::get(nextupdate::get)
                .post(nextupdate::post)
                .layer(axum::extract::DefaultBodyLimit::max(upload_limit))
                .delete(nextupdate::delete),
        )
        .route(
            "/vehicle/v15/apps/sovd2uds/bulk-data/runtimefiles-nextupdate/{id}",
            axum::routing::delete(nextupdate::id::delete),
        )
        .route(
            "/vehicle/v15/apps/sovd2uds/bulk-data/runtimefiles-backup",
            axum::routing::get(backup::get).delete(backup::delete),
        )
        .route(EXECUTIONS_ROUTE, axum::routing::post(executions::post))
        .route(EXECUTIONS_ID_ROUTE, axum::routing::get(executions::get))
        .route(
            "/vehicle/v15/apps/sovd2uds/operations/diagnostic-database-update",
            axum::routing::post(executions::post),
        )
        .layer(axum::middleware::from_fn(
            cda_plugin_security::security_plugin_middleware::<S>,
        ))
        .with_state(state)
}

/// Returns the [`ExemptRoute`]s that must remain accessible during a database update.
pub fn update_exempt_routes() -> Vec<ExemptRoute> {
    vec![ExemptRoute {
        prefix: EXECUTIONS_ROUTE.to_string(),
        methods: vec![http::Method::GET],
    }]
}
