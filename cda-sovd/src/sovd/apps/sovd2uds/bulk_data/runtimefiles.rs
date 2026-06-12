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
use cda_interfaces::runtime_update_api::{
    LockStateProvider, RuntimeFilesUpdatePlugin, RuntimeUpdateError,
};
use sovd_interfaces::error::{ApiErrorResponse, ErrorCode};

use crate::{VendorErrorCode, sovd::update_guard::ExemptRoute};

const EXECUTIONS_ROUTE: &str =
    "/vehicle/v15/apps/sovd2uds/bulk-data/runtimefiles-nextupdate/executions";
const EXECUTIONS_ID_ROUTE: &str =
    "/vehicle/v15/apps/sovd2uds/bulk-data/runtimefiles-nextupdate/executions/{id}";

pub struct RuntimeUpdateRouteState<P, L> {
    pub plugin: Arc<P>,
    pub vehicle_lock_states: Arc<L>,
    pub retry_after_seconds: u64,
}

impl<P, L> Clone for RuntimeUpdateRouteState<P, L> {
    fn clone(&self) -> Self {
        Self {
            plugin: Arc::clone(&self.plugin),
            vehicle_lock_states: Arc::clone(&self.vehicle_lock_states),
            retry_after_seconds: self.retry_after_seconds,
        }
    }
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
        // Helper function to construct the API error response
        let build_api_error_response =
            |status_code: StatusCode,
             error_code: ErrorCode,
             vendor_code: Option<VendorErrorCode>,
             retry_after_seconds: Option<u64>| {
                let mut resp = (
                    status_code,
                    Json(ApiErrorResponse {
                        message: self.error.to_string(),
                        error_code,
                        vendor_code,
                        parameters: None,
                        error_source: None,
                        schema: None,
                    }),
                )
                    .into_response();

                if let Some(seconds) = retry_after_seconds {
                    resp.headers_mut().insert(
                        RETRY_AFTER,
                        HeaderValue::from_str(&seconds.to_string())
                            .expect("numeric retry-after is always valid"),
                    );
                }
                resp
            };

        match &self.error {
            RuntimeUpdateError::OperationsInProgress(_) | RuntimeUpdateError::LockConflict(_) => {
                build_api_error_response(
                    StatusCode::CONFLICT,
                    ErrorCode::PreconditionsNotFulfilled,
                    None,
                    None,
                )
            }
            RuntimeUpdateError::ExecutionConflict => build_api_error_response(
                StatusCode::CONFLICT,
                ErrorCode::UpdateProcessInProgress,
                None,
                None,
            ),
            RuntimeUpdateError::TransactionBusy => build_api_error_response(
                StatusCode::CONFLICT,
                ErrorCode::VendorSpecific,
                Some(VendorErrorCode::StorageTransactionBusy),
                Some(self.retry_after_seconds),
            ),
            RuntimeUpdateError::NoPendingUpdate
            | RuntimeUpdateError::NoBackup
            | RuntimeUpdateError::FileNotFound(_) => build_api_error_response(
                StatusCode::NOT_FOUND,
                ErrorCode::VendorSpecific,
                Some(VendorErrorCode::NotFound),
                None,
            ),
            RuntimeUpdateError::InvalidMddFile(_)
            | RuntimeUpdateError::InvalidConfig(_)
            | RuntimeUpdateError::InvalidFileType(_)
            | RuntimeUpdateError::ValidationFailed(_) => build_api_error_response(
                StatusCode::BAD_REQUEST,
                ErrorCode::VendorSpecific,
                Some(VendorErrorCode::InvalidData),
                None,
            ),
            RuntimeUpdateError::StorageError(_) | RuntimeUpdateError::ReloadFailed(_) => {
                build_api_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorCode::SovdServerFailure,
                    None,
                    None,
                )
            }
            RuntimeUpdateError::NoLock(_) => build_api_error_response(
                StatusCode::FORBIDDEN,
                ErrorCode::InsufficientAccessRights,
                None,
                None,
            ),
            RuntimeUpdateError::SevereError(_) => build_api_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::VendorSpecific,
                Some(VendorErrorCode::SevereError),
                None,
            ),
            RuntimeUpdateError::FatalError(_) => build_api_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::VendorSpecific,
                Some(VendorErrorCode::FatalError),
                None,
            ),
        }
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
        None => Err(DbUpdateErrorResponse::new(
            RuntimeUpdateError::NoLock("Vehicle lock is missing".to_owned()),
            retry_after_seconds,
        )
        .into_response()),
        Some(owner) if owner != claims.sub() => Err(DbUpdateErrorResponse::new(
            RuntimeUpdateError::NoLock("Vehicle lock is owned by another user".to_owned()),
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
    use cda_interfaces::runtime_update_api::{LockStateProvider, RuntimeFilesUpdatePlugin};
    use cda_plugin_security::Secured;

    use super::{DbUpdateErrorResponse, RuntimeUpdateRouteState};

    pub(crate) async fn get<P: RuntimeFilesUpdatePlugin, L: LockStateProvider>(
        State(route_state): State<RuntimeUpdateRouteState<P, L>>,
        Secured(_sec_plugin): Secured,
        Query(query): Query<
            sovd_interfaces::apps::sovd2uds::bulk_data::runtimefiles::RuntimeFilesQuery,
        >,
    ) -> Response {
        route_state.plugin.list_current(&query).await.map_or_else(
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
    use cda_interfaces::runtime_update_api::{
        LockStateProvider, RuntimeFilesUpdatePlugin, RuntimeUpdateError, UploadFile,
    };
    use cda_plugin_security::Secured;

    use super::{DbUpdateErrorResponse, RuntimeUpdateRouteState, require_vehicle_lock};

    pub(crate) async fn get<P: RuntimeFilesUpdatePlugin, L: LockStateProvider>(
        State(route_state): State<RuntimeUpdateRouteState<P, L>>,
        Secured(_sec_plugin): Secured,
        Query(query): Query<
            sovd_interfaces::apps::sovd2uds::bulk_data::runtimefiles::RuntimeFilesQuery,
        >,
    ) -> Response {
        route_state
            .plugin
            .list_nextupdate(&query)
            .await
            .map_or_else(
                |e| DbUpdateErrorResponse::new(e, route_state.retry_after_seconds).into_response(),
                |list| super::bulk_data_list_response(list, query.include_schema),
            )
    }

    pub(crate) async fn post<P: RuntimeFilesUpdatePlugin, L: LockStateProvider>(
        State(route_state): State<RuntimeUpdateRouteState<P, L>>,
        Secured(sec_plugin): Secured,
        mut multipart: axum::extract::Multipart,
    ) -> impl IntoResponse {
        // The plugin takes care about rejecting new uploads during an active apply
        let claims = sec_plugin.as_auth_plugin().claims();
        if let Err(resp) = require_vehicle_lock(
            &*route_state.vehicle_lock_states,
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

    pub(crate) async fn delete<P: RuntimeFilesUpdatePlugin, L: LockStateProvider>(
        State(route_state): State<RuntimeUpdateRouteState<P, L>>,
        Secured(sec_plugin): Secured,
    ) -> impl IntoResponse {
        let claims = sec_plugin.as_auth_plugin().claims();
        if let Err(resp) = require_vehicle_lock(
            &*route_state.vehicle_lock_states,
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
        use cda_interfaces::runtime_update_api::{LockStateProvider, RuntimeFilesUpdatePlugin};
        use cda_plugin_security::Secured;

        use super::super::{DbUpdateErrorResponse, RuntimeUpdateRouteState, require_vehicle_lock};

        pub(crate) async fn delete<P: RuntimeFilesUpdatePlugin, L: LockStateProvider>(
            State(route_state): State<RuntimeUpdateRouteState<P, L>>,
            Secured(sec_plugin): Secured,
            Path(id): Path<String>,
        ) -> impl IntoResponse {
            let claims = sec_plugin.as_auth_plugin().claims();
            if let Err(resp) = require_vehicle_lock(
                &*route_state.vehicle_lock_states,
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
    use cda_interfaces::runtime_update_api::{LockStateProvider, RuntimeFilesUpdatePlugin};
    use cda_plugin_security::Secured;

    use super::{DbUpdateErrorResponse, RuntimeUpdateRouteState, require_vehicle_lock};

    pub(crate) async fn get<P: RuntimeFilesUpdatePlugin, L: LockStateProvider>(
        State(route_state): State<RuntimeUpdateRouteState<P, L>>,
        Secured(_sec_plugin): Secured,
        Query(query): Query<
            sovd_interfaces::apps::sovd2uds::bulk_data::runtimefiles::RuntimeFilesQuery,
        >,
    ) -> Response {
        route_state.plugin.list_backup(&query).await.map_or_else(
            |e| DbUpdateErrorResponse::new(e, route_state.retry_after_seconds).into_response(),
            |list| super::bulk_data_list_response(list, query.include_schema),
        )
    }

    pub(crate) async fn delete<P: RuntimeFilesUpdatePlugin, L: LockStateProvider>(
        State(route_state): State<RuntimeUpdateRouteState<P, L>>,
        Secured(sec_plugin): Secured,
    ) -> impl IntoResponse {
        let claims = sec_plugin.as_auth_plugin().claims();
        if let Err(resp) = require_vehicle_lock(
            &*route_state.vehicle_lock_states,
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
    use cda_interfaces::runtime_update_api::{LockStateProvider, RuntimeFilesUpdatePlugin};
    use cda_plugin_security::Secured;

    use super::{DbUpdateErrorResponse, RuntimeUpdateRouteState, require_vehicle_lock};

    pub(crate) async fn post<P: RuntimeFilesUpdatePlugin, L: LockStateProvider>(
        State(route_state): State<RuntimeUpdateRouteState<P, L>>,
        Secured(sec_plugin): Secured,
        Json(body): Json<
            sovd_interfaces::apps::sovd2uds::bulk_data::runtimefiles::ExecutionRequest,
        >,
    ) -> impl IntoResponse {
        let claims = sec_plugin.as_auth_plugin().claims();
        if let Err(resp) = require_vehicle_lock(
            &*route_state.vehicle_lock_states,
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
                |id| {
                    (
                        StatusCode::ACCEPTED,
                        Json(
                            sovd_interfaces::apps::sovd2uds::bulk_data::runtimefiles::ExecutionCreatedResponse { id },
                        ),
                    )
                        .into_response()
                },
            )
    }

    pub(crate) async fn get<P: RuntimeFilesUpdatePlugin, L: LockStateProvider>(
        State(route_state): State<RuntimeUpdateRouteState<P, L>>,
        Path(id): Path<String>,
    ) -> impl IntoResponse {
        match route_state.plugin.get_execution_status(&id).await {
            Some(exec) => (
                StatusCode::OK,
                Json(
                    sovd_interfaces::apps::sovd2uds::bulk_data::runtimefiles::ExecutionResponse::from(exec),
                ),
            )
                .into_response(),
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
    upload_limit: usize,
) -> axum::Router {
    axum::Router::new()
        .route(
            "/vehicle/v15/apps/sovd2uds/bulk-data/runtimefiles-current",
            axum::routing::get(current::get::<P, L>),
        )
        .route(
            "/vehicle/v15/apps/sovd2uds/bulk-data/runtimefiles-nextupdate",
            axum::routing::get(nextupdate::get::<P, L>)
                .post(nextupdate::post::<P, L>)
                .layer(axum::extract::DefaultBodyLimit::max(upload_limit))
                .delete(nextupdate::delete::<P, L>),
        )
        .route(
            "/vehicle/v15/apps/sovd2uds/bulk-data/runtimefiles-nextupdate/{id}",
            axum::routing::delete(nextupdate::id::delete::<P, L>),
        )
        .route(
            "/vehicle/v15/apps/sovd2uds/bulk-data/runtimefiles-backup",
            axum::routing::get(backup::get::<P, L>).delete(backup::delete::<P, L>),
        )
        .route(
            EXECUTIONS_ROUTE,
            axum::routing::post(executions::post::<P, L>),
        )
        .route(
            EXECUTIONS_ID_ROUTE,
            axum::routing::get(executions::get::<P, L>),
        )
        .route(
            "/vehicle/v15/apps/sovd2uds/operations/diagnostic-database-update",
            axum::routing::post(executions::post::<P, L>),
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
