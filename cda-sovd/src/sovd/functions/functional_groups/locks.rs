/*
 * Copyright (c) 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
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
use cda_interfaces::UdsEcu;
use cda_plugin_security::Secured;

use super::{
    ApiError, ErrorWrapper, IntoResponse, Json, Path, Response, State, WebserverFgState,
    WithRejection,
};
use crate::{
    openapi,
    sovd::locks::{
        LockContext, LockPathParam, LockType, delete_handler, delete_lock, get_handler,
        get_id_handler, post_handler, put_handler, vehicle_read_lock,
    },
};

pub(crate) mod lock {
    use cda_interfaces::UdsEcu;

    use super::{
        ApiError, Json, LockPathParam, Path, Response, Secured, State, TransformOperation, UseApi,
        WebserverFgState, WithRejection, delete_handler, get_id_handler, openapi, put_handler,
    };

    pub(crate) async fn delete<T: UdsEcu + Clone>(
        Path(LockPathParam { lock }): Path<LockPathParam>,
        State(state): State<WebserverFgState<T>>,
        UseApi(sec_plugin, _): UseApi<Secured, ()>,
    ) -> Response {
        let claims = sec_plugin.as_auth_plugin().claims();
        delete_handler(
            &state.locks.functional_group,
            &lock,
            &claims,
            Some(&state.functional_group_name),
            false,
        )
        .await
    }

    pub(crate) fn docs_delete(op: TransformOperation) -> TransformOperation {
        op.description("Delete a functional group lock")
            .response_with::<204, (), _>(|res| res.description("Lock deleted successfully."))
            .with(openapi::lock_not_found)
            .with(openapi::lock_not_owned)
    }

    pub(crate) async fn put<T: UdsEcu + Clone>(
        Path(LockPathParam { lock }): Path<LockPathParam>,
        State(state): State<WebserverFgState<T>>,
        UseApi(sec_plugin, _): UseApi<Secured, ()>,
        WithRejection(Json(body), _): WithRejection<
            Json<sovd_interfaces::locking::Request>,
            ApiError,
        >,
    ) -> Response {
        let claims = sec_plugin.as_auth_plugin().claims();
        put_handler(
            &state.locks.functional_group,
            &lock,
            &claims,
            Some(&state.functional_group_name),
            body,
            false,
        )
        .await
    }

    pub(crate) fn docs_put(op: TransformOperation) -> TransformOperation {
        op.description("Update a functional group lock")
            .response_with::<204, (), _>(|res| res.description("Lock updated successfully."))
            .with(openapi::lock_not_found)
            .with(openapi::lock_not_owned)
    }

    pub(crate) async fn get<T: UdsEcu + Clone>(
        Path(LockPathParam { lock }): Path<LockPathParam>,
        UseApi(_sec_plugin, _): UseApi<Secured, ()>,
        State(state): State<WebserverFgState<T>>,
    ) -> Response {
        get_id_handler(
            &state.locks.functional_group,
            &lock,
            Some(&state.functional_group_name),
            false,
        )
        .await
    }

    pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
        op.description("Get a specific functional group lock")
            .response_with::<200, Json<sovd_interfaces::locking::id::get::Response>, _>(|res| {
                res.description("Response with the lock details.").example(
                    sovd_interfaces::locking::id::get::Response {
                        lock_expiration: "2025-01-01T00:00:00Z".to_string(),
                    },
                )
            })
            .with(openapi::lock_not_found)
            .with(openapi::lock_not_owned)
    }
}

pub(crate) async fn post<T: UdsEcu + Clone>(
    UseApi(Secured(sec_plugin), _): UseApi<Secured, ()>,
    State(state): State<WebserverFgState<T>>,
    WithRejection(Json(body), _): WithRejection<Json<sovd_interfaces::locking::Request>, ApiError>,
) -> Response {
    let claims = sec_plugin.as_ref().as_auth_plugin().claims();
    let vehicle_ro_lock = vehicle_read_lock(&state.locks, &claims).await;
    if let Err(e) = vehicle_ro_lock {
        return ErrorWrapper {
            error: e,
            include_schema: false,
        }
        .into_response();
    }

    match &state.locks.ecu {
        LockType::Ecu(eculocks) => {
            let mut functionalgroup_ecus = Vec::new();
            for (ecu, lock_info) in eculocks.read().await.iter() {
                let ecu_functional_groups = match state
                    .uds
                    .ecu_functional_groups(ecu)
                    .await
                    .map_err(ApiError::from)
                {
                    Ok(groups) => groups,
                    Err(e) => {
                        return ErrorWrapper {
                            error: e,
                            include_schema: false,
                        }
                        .into_response();
                    }
                };
                if !ecu_functional_groups.contains(&state.functional_group_name) {
                    continue;
                }
                if let Some(lock_info) = lock_info {
                    if !lock_info.is_owned_by(claims.sub()) {
                        return ErrorWrapper {
                            error: ApiError::Conflict(format!(
                                "ECU {ecu} is locked by different user. This prevents setting \
                                 functional group lock"
                            )),
                            include_schema: false,
                        }
                        .into_response();
                    }
                    functionalgroup_ecus.push((ecu.clone(), lock_info.id().to_owned()));
                }
            }
            for (ecu, id) in functionalgroup_ecus {
                if let Err(e) = delete_lock(&state.locks.ecu, &id, &claims, Some(&ecu)).await {
                    return ErrorWrapper {
                        error: e,
                        include_schema: false,
                    }
                    .into_response();
                }
            }
        }
        _ => unreachable!(),
    }

    post_handler(
        &state.uds,
        LockContext {
            lock: &state.locks.functional_group,
            all_locks: &state.locks,
            rw_lock: None,
        },
        Some(&state.functional_group_name),
        body,
        false,
        sec_plugin,
    )
    .await
}

pub(crate) fn docs_post(op: TransformOperation) -> TransformOperation {
    op.description("Create a functional group lock")
        .response_with::<200, Json<sovd_interfaces::locking::post_put::Response>, _>(|res| {
            res.example(sovd_interfaces::locking::post_put::Response {
                id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                owned: Some(true),
            })
            .description("Functional group lock created successfully.")
        })
        .with(openapi::lock_not_owned)
}

pub(crate) async fn get<T: UdsEcu + Clone>(
    UseApi(sec_plugin, _): UseApi<Secured, ()>,
    State(state): State<WebserverFgState<T>>,
) -> Response {
    let claims = sec_plugin.as_auth_plugin().claims();
    get_handler(
        &state.locks.functional_group,
        &claims,
        Some(&state.functional_group_name),
    )
    .await
}

pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
    op.description("Get all functional group locks")
        .response_with::<200, Json<sovd_interfaces::locking::get::Response>, _>(|res| {
            res.example(sovd_interfaces::locking::get::Response {
                items: vec![sovd_interfaces::locking::Lock {
                    id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                    owned: Some(true),
                }],
                schema: None,
            })
            .description("List of functional group locks.")
        })
}
