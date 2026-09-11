/*
 * SPDX-FileCopyrightText: 2025 Copyright (c) Contributors to the Eclipse Foundation
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

use aide::{UseApi, transform::TransformOperation};
use axum::{
    Json,
    extract::{Path, Query, State},
    response::{IntoResponse, Response},
};
use axum_extra::extract::WithRejection;
use cda_interfaces::{UdsEcu, lock_priority_api::LockScope};
use cda_plugin_security::{Claims, Secured};

use super::super::{
    ApiError, ErrorWrapper, LockContext, LockCoverage, LockPathParam, LockTarget,
    LockUpdateContext, delete_handler, get_handler, get_id_handler, post_handler, put_handler,
    rollback_preemption, validate_vehicle_children,
};
use crate::{openapi, sovd::WebserverState};

pub(crate) mod lock {
    use cda_interfaces::UdsEcu;

    use super::{
        ApiError, Json, LockPathParam, LockScope, LockTarget, LockUpdateContext, Path, Query,
        Response, Secured, State, TransformOperation, UseApi, WebserverState, WithRejection,
        delete_handler, get_id_handler, openapi, put_handler,
    };

    pub(crate) async fn delete<T: UdsEcu + Clone>(
        Path(lock): Path<LockPathParam>,
        UseApi(sec_plugin, _): UseApi<Secured, ()>,
        State(state): State<WebserverState<T>>,
        Query(query): Query<sovd_interfaces::IncludeSchemaQuery>,
    ) -> Response {
        let claims = sec_plugin.as_auth_plugin().claims();
        delete_handler(
            &state.locks,
            LockTarget::Vehicle,
            LockScope::Vehicle,
            &lock,
            &claims,
            None,
            query.include_schema,
        )
        .await
    }

    pub(crate) fn docs_delete(op: TransformOperation) -> TransformOperation {
        openapi::lock_responses(op)
            .description("Delete a vehicle lock")
            .response_with::<204, (), _>(|res| res.description("Lock deleted."))
            .with(openapi::lock_not_found)
            .with(openapi::lock_not_owned)
    }

    pub(crate) async fn put<T: UdsEcu + Clone>(
        Path(lock): Path<LockPathParam>,
        UseApi(sec_plugin, _): UseApi<Secured, ()>,
        State(state): State<WebserverState<T>>,
        Query(query): Query<sovd_interfaces::IncludeSchemaQuery>,
        WithRejection(Json(body), _): WithRejection<
            Json<sovd_interfaces::locking::UpdateRequest>,
            ApiError,
        >,
    ) -> Response {
        let claims = sec_plugin.as_auth_plugin().claims();
        put_handler(
            LockUpdateContext {
                all_locks: &state.locks,
                lock: LockTarget::Vehicle,
                scope: LockScope::Vehicle,
            },
            &lock,
            &claims,
            None,
            body,
            query.include_schema,
        )
        .await
    }

    pub(crate) fn docs_put(op: TransformOperation) -> TransformOperation {
        openapi::lock_responses(op)
            .description("Extend a vehicle lock's expiration")
            .response_with::<204, (), _>(|res| res.description("Lock updated successfully."))
            .with(openapi::lock_not_found)
            .with(openapi::lock_not_owned)
    }

    pub(crate) async fn get<T: UdsEcu + Clone>(
        Path(lock): Path<LockPathParam>,
        UseApi(_sec_plugin, _): UseApi<Secured, ()>,
        State(state): State<WebserverState<T>>,
        Query(query): Query<sovd_interfaces::IncludeSchemaQuery>,
    ) -> Response {
        get_id_handler(
            &state.locks,
            LockTarget::Vehicle,
            LockScope::Vehicle,
            &lock,
            None,
            query.include_schema,
        )
        .await
    }

    pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
        openapi::lock_responses(op)
            .description("Get a specific vehicle lock")
            .response_with::<200, Json<sovd_interfaces::locking::id::get::Response>, _>(|res| {
                res.description("Response with the lock details.")
                    .example(openapi::lock_details_example())
            })
            .with(openapi::lock_not_found)
            .with(openapi::lock_not_owned)
    }
}

pub(crate) async fn post<T: UdsEcu + Clone>(
    UseApi(Secured(sec_plugin), _): UseApi<Secured, ()>,
    State(state): State<WebserverState<T>>,
    Query(query): Query<sovd_interfaces::IncludeSchemaQuery>,
    WithRejection(Json(body), _): WithRejection<Json<sovd_interfaces::locking::Request>, ApiError>,
) -> Response {
    let claims = sec_plugin.as_auth_plugin().claims();
    let (acquisition, pending, request) = match state
        .locks
        .evaluate_acquisition(LockScope::Vehicle, LockCoverage::vehicle(), &body, &claims)
        .await
    {
        Ok(pending) => pending,
        Err(error) => {
            return ErrorWrapper {
                error,
                include_schema: query.include_schema,
            }
            .into_response();
        }
    };
    let active = state.locks.open_locks().await;
    let preempted_roots = pending
        .as_ref()
        .map_or(&[][..], |pending| pending.root_lock_ids.as_slice());
    if let Err(error) = validate_vehicle_children(&active, preempted_roots, claims.sub()) {
        rollback_preemption(pending, &state.locks).await;
        acquisition.finish().await;
        return ErrorWrapper {
            error,
            include_schema: query.include_schema,
        }
        .into_response();
    }
    post_handler(
        &state.uds,
        LockContext {
            lock: LockTarget::Vehicle,
            all_locks: &state.locks,
            acquisition,
            pending,
            converted_lock_ids: Vec::new(),
            coverage: LockCoverage::vehicle(),
        },
        None,
        request,
        query.include_schema,
        sec_plugin,
    )
    .await
}

pub(crate) fn docs_post(op: TransformOperation) -> TransformOperation {
    openapi::lock_responses(op)
        .description("Create a vehicle lock")
        .response_with::<201, Json<sovd_interfaces::locking::post_put::Response>, _>(|res| {
            res.example(openapi::lock_created_example())
                .description("Lock created successfully.")
        })
        .with(openapi::lock_not_owned)
}

pub(crate) async fn get<T: UdsEcu + Clone>(
    UseApi(sec_plugin, _): UseApi<Secured, ()>,
    State(state): State<WebserverState<T>>,
    Query(query): Query<sovd_interfaces::IncludeSchemaQuery>,
) -> Response {
    let claims = sec_plugin.as_auth_plugin().claims();
    get_handler(
        &state.locks,
        LockTarget::Vehicle,
        LockScope::Vehicle,
        &claims,
        None,
        query.include_schema,
    )
    .await
}

pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
    openapi::lock_responses(op)
        .description("Get all vehicle locks")
        .response_with::<200, Json<sovd_interfaces::locking::get::Response>, _>(|res| {
            res.example(openapi::lock_list_example())
                .description("List of vehicle locks.")
        })
}
