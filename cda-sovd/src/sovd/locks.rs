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

use std::{fmt, option::Option, sync::Arc, time::Duration};

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use axum_extra::extract::WithRejection;
use cda_interfaces::{UdsEcu, diagservices::DiagServiceResponse, file_manager::FileManager};
use chrono::{DateTime, SecondsFormat, Utc};
use hashbrown::HashMap;
use tokio::{
    sync::{RwLock, RwLockReadGuard, RwLockWriteGuard},
    task::{self, JoinHandle},
    time::{Instant, sleep_until},
};
use uuid::Uuid;

use crate::{
    openapi,
    sovd::{
        IntoSovd, WebserverEcuState, WebserverState,
        auth::Claims,
        error::{ApiError, ErrorWrapper},
    },
};

// later this likely will be a Vector of locks to support non exclusive locks
pub(crate) type LockHashMap = HashMap<String, Option<Lock>>;
pub(crate) type LockOption = Option<Lock>;

#[derive(Debug)]
pub(crate) struct Lock {
    sovd: sovd_interfaces::locking::Lock,
    expiration: DateTime<Utc>,
    owner: String,
    deletion_task: JoinHandle<()>,
}

pub(crate) struct Locks {
    pub vehicle: LockType,
    pub ecu: LockType,
    pub functional_group: LockType,
}

#[derive(Clone, Debug)]
pub(crate) enum LockType {
    Vehicle(Arc<RwLock<LockOption>>),
    Ecu(Arc<RwLock<LockHashMap>>),
    FunctionalGroup(Arc<RwLock<LockHashMap>>),
}

impl fmt::Display for LockType {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        let type_name = match self {
            LockType::Vehicle(_) => "Vehicle",
            LockType::Ecu(_) => "ECU",
            LockType::FunctionalGroup(_) => "FunctionalGroup",
        };
        write!(formatter, "{type_name}")
    }
}

pub(crate) enum ReadLock<'a> {
    HashMapLock(RwLockReadGuard<'a, LockHashMap>),
    OptionLock(RwLockReadGuard<'a, LockOption>),
}
pub(crate) enum WriteLock<'a> {
    HashMapLock(RwLockWriteGuard<'a, LockHashMap>),
    OptionLock(RwLockWriteGuard<'a, LockOption>),
}

impl ReadLock<'_> {
    fn get(&self, key: Option<&String>, lock_id: Option<&String>) -> Option<&Lock> {
        match self {
            ReadLock::HashMapLock(l) => {
                if let Some(k) = key {
                    l.get(k)
                        .and_then(|l| l.as_ref())
                        .filter(|l| lock_id.is_none_or(|id| *id == l.sovd.id))
                } else {
                    None
                }
            }
            ReadLock::OptionLock(l) => l.as_ref(),
        }
    }

    fn is_any_locked(&self) -> bool {
        match self {
            ReadLock::HashMapLock(l) => !l.is_empty(),
            ReadLock::OptionLock(l) => !l.is_none(),
        }
    }
}

impl WriteLock<'_> {
    fn get_mut(&mut self, entity_id: Option<&String>) -> Result<&mut Option<Lock>, ApiError> {
        match self {
            WriteLock::HashMapLock(l) => {
                if let Some(key) = entity_id {
                    Ok(l.entry_ref(key).or_insert(None))
                } else {
                    Err(ApiError::NotFound(Some("lock does not exist".to_owned())))
                }
            }
            WriteLock::OptionLock(l) => Ok(l),
        }
    }

    pub(crate) fn delete(&mut self, entity_name: Option<&String>) -> Result<(), ApiError> {
        match self {
            WriteLock::HashMapLock(l) => {
                let entity_name = entity_name.ok_or_else(|| {
                    ApiError::BadRequest("cannot delete, no entity name provided".to_owned())
                })?;
                if l.remove(entity_name).is_none() {
                    return Err(ApiError::NotFound(Some(format!(
                        "cannot delete, no entity {entity_name} is not locked",
                    ))));
                }
                Ok(())
            }
            WriteLock::OptionLock(l) => {
                **l = None;
                Ok(())
            }
        }
    }
}

impl LockType {
    pub(crate) async fn lock_ro(&self) -> ReadLock<'_> {
        match self {
            LockType::Vehicle(v) => ReadLock::OptionLock(v.read().await),
            LockType::Ecu(l) | LockType::FunctionalGroup(l) => {
                ReadLock::HashMapLock(l.read().await)
            }
        }
    }

    pub(crate) async fn lock_rw(&self) -> WriteLock<'_> {
        match self {
            LockType::Vehicle(v) => WriteLock::OptionLock(v.write().await),
            LockType::Ecu(l) | LockType::FunctionalGroup(l) => {
                WriteLock::HashMapLock(l.write().await)
            }
        }
    }
}

openapi::aide_helper::gen_path_param!(LockPathParam lock String);

pub(crate) mod ecu {
    use aide::{UseApi, axum::IntoApiResponse, transform::TransformOperation};

    use super::*;
    use crate::sovd;

    pub(crate) mod lock {
        use super::*;
        use crate::openapi;
        pub(crate) async fn delete<R: DiagServiceResponse, T: UdsEcu + Clone, U: FileManager>(
            Path(lock): Path<LockPathParam>,
            UseApi(claims, _): UseApi<Claims, ()>,
            State(WebserverEcuState {
                ecu_name, locks, ..
            }): State<WebserverEcuState<R, T, U>>,
        ) -> Response {
            delete_handler(&locks.ecu, &lock, claims, Some(&ecu_name)).await
        }

        pub(crate) fn docs_delete(op: TransformOperation) -> TransformOperation {
            op.description("Delete a specific lock.")
                .response_with::<204, (), _>(|res| res.description("Lock deleted successfully."))
                .with(openapi::lock_not_found)
                .with(openapi::lock_not_owned)
        }

        pub(crate) async fn put<R: DiagServiceResponse, T: UdsEcu + Clone, U: FileManager>(
            Path(lock): Path<LockPathParam>,
            UseApi(claims, _): UseApi<Claims, ()>,
            State(WebserverEcuState {
                ecu_name, locks, ..
            }): State<WebserverEcuState<R, T, U>>,
            WithRejection(Json(body), _): WithRejection<
                Json<sovd_interfaces::locking::Request>,
                ApiError,
            >,
        ) -> Response {
            put_handler(&locks.ecu, &lock, claims, Some(&ecu_name), body).await
        }

        pub(crate) fn docs_put(op: TransformOperation) -> TransformOperation {
            op.description("Update a specific lock.")
                .response_with::<204, (), _>(|res| res.description("Lock updated successfully."))
                .with(openapi::lock_not_found)
                .with(openapi::lock_not_owned)
        }

        pub(crate) async fn get<R: DiagServiceResponse, T: UdsEcu + Clone, U: FileManager>(
            Path(lock): Path<LockPathParam>,
            _: UseApi<Claims, ()>,
            State(state): State<WebserverEcuState<R, T, U>>,
        ) -> Response {
            get_id_handler(&state.locks.ecu, &lock, None).await
        }

        pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
            op.description("Get a specific lock.")
                .response_with::<200, Json<sovd_interfaces::locking::id::get::Response>, _>(|res| {
                    res.description("Response with the lock details.").example(
                        sovd_interfaces::locking::id::get::Response {
                            lock_expiration: "2025-01-01T00:00:00Z".to_string(),
                        },
                    )
                })
                .with(openapi::lock_not_found)
        }
    }

    pub(crate) async fn post<R: DiagServiceResponse, T: UdsEcu + Clone, U: FileManager>(
        UseApi(claims, _): UseApi<Claims, ()>,
        State(WebserverEcuState {
            ecu_name, locks, ..
        }): State<WebserverEcuState<R, T, U>>,
        WithRejection(Json(body), _): WithRejection<
            Json<sovd_interfaces::locking::Request>,
            ApiError,
        >,
    ) -> impl IntoApiResponse {
        let vehicle_ro_lock = vehicle_read_lock(&locks, &claims).await;
        if let Err(e) = vehicle_ro_lock {
            return ErrorWrapper(e).into_response();
        }

        // only for POC, later we have to check if ecu is in the functional group
        let functional_lock = locks.functional_group.lock_ro().await;
        if functional_lock.is_any_locked() {
            return ErrorWrapper(ApiError::Conflict(
                "functional lock prevents setting ecu lock".to_owned(),
            ))
            .into_response();
        }

        post_handler(&locks.ecu, &claims, Some(&ecu_name), body, None).await
    }

    pub(crate) fn docs_post(op: TransformOperation) -> TransformOperation {
        op.description("Create a lock for an ECU")
            .response_with::<200, Json<sovd_interfaces::locking::post_put::Response>, _>(|res| {
                res.example(sovd_interfaces::locking::post_put::Response {
                    id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                    owned: Some(true),
                })
                .description("Lock created successfully.")
            })
            .response_with::<
                403,
                Json<sovd_interfaces::error::ApiErrorResponse::<sovd::error::VendorErrorCode>>,
                 _>(|res| {
                res.description("Lock is already owned by someone else.")
            })
            .response_with::<
            409,
            Json<sovd_interfaces::error::ApiErrorResponse::<sovd::error::VendorErrorCode>>,
            _>(|res| {
                res.description("Functional lock prevents setting lock.")
            })
    }

    pub(crate) async fn get<R: DiagServiceResponse, T: UdsEcu + Clone, U: FileManager>(
        UseApi(claims, _): UseApi<Claims, ()>,
        State(WebserverEcuState {
            ecu_name, locks, ..
        }): State<WebserverEcuState<R, T, U>>,
    ) -> Response {
        get_handler(&locks.ecu, claims, Some(&ecu_name)).await
    }

    pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
        op.description("Get all locks")
            .response_with::<200, Json<sovd_interfaces::locking::get::Response>, _>(|res| {
                res.example(sovd_interfaces::locking::get::Response {
                    items: vec![sovd_interfaces::locking::Lock {
                        id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                        owned: Some(true),
                    }],
                    schema: None,
                })
                .description("List of ECU locks.")
            })
    }
}

pub(crate) mod vehicle {
    use aide::{UseApi, transform::TransformOperation};

    use super::*;
    use crate::openapi;

    pub(crate) mod lock {
        use aide::transform::TransformOperation;

        use super::*;
        use crate::openapi;

        pub(crate) async fn delete(
            Path(lock): Path<LockPathParam>,
            UseApi(claims, _): UseApi<Claims, ()>,
            State(state): State<WebserverState>,
        ) -> Response {
            delete_handler(&state.locks.vehicle, &lock, claims, None).await
        }

        pub(crate) fn docs_delete(op: TransformOperation) -> TransformOperation {
            op.description("Delete a vehicle lock")
                .response_with::<201, (), _>(|res| res.description("Lock deleted."))
                .with(openapi::lock_not_found)
                .with(openapi::lock_not_owned)
        }

        pub(crate) async fn put(
            Path(lock): Path<LockPathParam>,
            UseApi(claims, _): UseApi<Claims, ()>,
            State(state): State<WebserverState>,
            WithRejection(Json(body), _): WithRejection<
                Json<sovd_interfaces::locking::Request>,
                ApiError,
            >,
        ) -> Response {
            put_handler(&state.locks.vehicle, &lock, claims, None, body).await
        }

        pub(crate) fn docs_put(op: TransformOperation) -> TransformOperation {
            op.description("Update a vehicle lock")
                .response_with::<201, (), _>(|res| res.description("Lock updated successfully."))
                .with(openapi::lock_not_found)
                .with(openapi::lock_not_owned)
        }

        pub(crate) async fn get(
            Path(lock): Path<LockPathParam>,
            UseApi(_, _): UseApi<Claims, ()>,
            State(state): State<WebserverState>,
        ) -> Response {
            get_id_handler(&state.locks.vehicle, &lock, None).await
        }

        pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
            op.description("Get a specific vehicle lock")
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

    pub(crate) async fn post(
        UseApi(claims, _): UseApi<Claims, ()>,
        State(state): State<WebserverState>,
        WithRejection(Json(body), _): WithRejection<
            Json<sovd_interfaces::locking::Request>,
            ApiError,
        >,
    ) -> Response {
        let mut vehicle_rw_lock = state.locks.vehicle.lock_rw().await;
        let vehicle_lock = match vehicle_rw_lock.get_mut(None) {
            Ok(lock) => lock,
            Err(e) => return ErrorWrapper(e).into_response(),
        };

        if let Err(e) = validate_claim(None, &claims, vehicle_lock.as_ref()) {
            return ErrorWrapper(e).into_response();
        }

        let ecu_locks = state.locks.ecu.lock_ro().await;
        if let Err(e) = all_locks_owned(&ecu_locks, &claims) {
            return ErrorWrapper(e).into_response();
        }

        let functional_locks = state.locks.functional_group.lock_ro().await;
        if let Err(e) = all_locks_owned(&functional_locks, &claims) {
            return ErrorWrapper(e).into_response();
        }

        post_handler(
            &state.locks.vehicle,
            &claims,
            None,
            body,
            Some(vehicle_rw_lock),
        )
        .await
    }

    pub(crate) fn docs_post(op: TransformOperation) -> TransformOperation {
        op.description("Create a vehicle lock")
            .response_with::<200, Json<sovd_interfaces::locking::post_put::Response>, _>(|res| {
                res.example(sovd_interfaces::locking::post_put::Response {
                    id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                    owned: Some(true),
                })
                .description("Vehicle lock created successfully.")
            })
            .with(openapi::lock_not_owned)
    }

    pub(crate) async fn get(
        UseApi(claims, _): UseApi<Claims, ()>,
        State(state): State<WebserverState>,
    ) -> Response {
        get_handler(&state.locks.vehicle, claims, None).await
    }

    pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
        op.description("Get all vehicle locks")
            .response_with::<200, Json<sovd_interfaces::locking::get::Response>, _>(|res| {
                res.example(sovd_interfaces::locking::get::Response {
                    items: vec![sovd_interfaces::locking::Lock {
                        id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                        owned: Some(true),
                    }],
                    schema: None,
                })
                .description("List of vehicle locks.")
            })
    }
}

pub(crate) mod functional_group {
    use aide::{UseApi, transform::TransformOperation};

    use super::*;
    use crate::openapi;

    openapi::aide_helper::gen_path_param!(FunctionalGroupLockPathParam group String);

    pub(crate) mod lock {
        use super::*;

        openapi::aide_helper::gen_path_param!(FunctionalGroupLockWithIdPathParam group String lock String);

        pub(crate) async fn delete(
            Path(FunctionalGroupLockWithIdPathParam { group, lock }): Path<
                FunctionalGroupLockWithIdPathParam,
            >,
            State(state): State<WebserverState>,
            UseApi(claims, _): UseApi<Claims, ()>,
        ) -> Response {
            delete_handler(&state.locks.functional_group, &lock, claims, Some(&group)).await
        }

        pub(crate) fn docs_delete(op: TransformOperation) -> TransformOperation {
            op.description("Delete a functional group lock")
                .response_with::<204, (), _>(|res| res.description("Lock deleted successfully."))
                .with(openapi::lock_not_found)
                .with(openapi::lock_not_owned)
        }

        pub(crate) async fn put(
            Path(FunctionalGroupLockWithIdPathParam { group, lock }): Path<
                FunctionalGroupLockWithIdPathParam,
            >,
            State(state): State<WebserverState>,
            UseApi(claims, _): UseApi<Claims, ()>,
            WithRejection(Json(body), _): WithRejection<
                Json<sovd_interfaces::locking::Request>,
                ApiError,
            >,
        ) -> Response {
            put_handler(
                &state.locks.functional_group,
                &lock,
                claims,
                Some(&group),
                body,
            )
            .await
        }

        pub(crate) fn docs_put(op: TransformOperation) -> TransformOperation {
            op.description("Update a functional group lock")
                .response_with::<204, (), _>(|res| res.description("Lock updated successfully."))
                .with(openapi::lock_not_found)
                .with(openapi::lock_not_owned)
        }

        pub(crate) async fn get(
            Path(FunctionalGroupLockWithIdPathParam { group, lock }): Path<
                FunctionalGroupLockWithIdPathParam,
            >,
            UseApi(_, _): UseApi<Claims, ()>,
            State(state): State<WebserverState>,
        ) -> Response {
            get_id_handler(&state.locks.functional_group, &lock, Some(&group)).await
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

    pub(crate) async fn post(
        Path(group): Path<FunctionalGroupLockPathParam>,
        UseApi(claims, _): UseApi<Claims, ()>,
        State(state): State<WebserverState>,
        WithRejection(Json(body), _): WithRejection<
            Json<sovd_interfaces::locking::Request>,
            ApiError,
        >,
    ) -> Response {
        let vehicle_ro_lock = vehicle_read_lock(&state.locks, &claims).await;
        if let Err(e) = vehicle_ro_lock {
            return ErrorWrapper(e).into_response();
        }

        // todo (out of scope for poc) check if any of the ecus is already locked]
        post_handler(
            &state.locks.functional_group,
            &claims,
            Some(&group),
            body,
            None,
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

    pub(crate) async fn get(
        Path(group): Path<FunctionalGroupLockPathParam>,
        UseApi(claims, _): UseApi<Claims, ()>,
        State(state): State<WebserverState>,
    ) -> Response {
        get_handler(&state.locks.functional_group, claims, Some(&group)).await
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
}

fn create_lock(
    claims: &Claims,
    expiration: sovd_interfaces::locking::Request,
    lock_type: &LockType,
    entity_name: Option<&String>,
) -> Result<Lock, ApiError> {
    let utc_expiration: DateTime<Utc> = expiration.into();
    if utc_expiration < Utc::now() {
        return Err(ApiError::BadRequest(
            "Expiration date is in the past".to_owned(),
        ));
    }

    let id = Uuid::new_v4();
    let token_deletion_task = schedule_token_deletion(
        entity_name.map(std::borrow::ToOwned::to_owned),
        id.to_string(),
        lock_type.clone(),
        utc_expiration,
    )?;

    // setting owned to none here, because the SOVD specification states describes
    // the return value w/o the owned field
    let sovd_lock = sovd_interfaces::locking::Lock {
        id: id.to_string(),
        owned: None,
    };
    Ok(Lock {
        owner: claims.sub.clone(),
        sovd: sovd_lock,
        expiration: utc_expiration,
        deletion_task: token_deletion_task,
    })
}

fn update_lock(
    lock_id: &str,
    claim: &Claims,
    entity_lock: &mut Option<Lock>,
    expiration: sovd_interfaces::locking::Request,
    entity_name: Option<&String>,
    lock: &LockType,
) -> Result<sovd_interfaces::locking::post_put::Response, ApiError> {
    validate_claim(Some(lock_id), claim, entity_lock.as_ref())?;
    match entity_lock {
        Some(entity_lock) => {
            let expiration_utc: DateTime<Utc> = expiration.into();
            entity_lock.deletion_task.abort();
            entity_lock.deletion_task = schedule_token_deletion(
                entity_name.map(std::borrow::ToOwned::to_owned),
                entity_lock.sovd.id.clone(),
                lock.clone(),
                expiration_utc,
            )?;

            entity_lock.expiration = expiration_utc;
            Ok(entity_lock.sovd.clone())
        }
        None => Err(ApiError::Conflict("No lock found".to_owned())),
    }
}

pub(crate) fn get_locks(
    claims: &Claims,
    locks: &ReadLock,
    entity_name: Option<&String>,
) -> sovd_interfaces::locking::get::Response {
    match locks {
        ReadLock::HashMapLock(l) => sovd_interfaces::locking::get::Response {
            items: l
                .iter()
                .filter(|(map_key, _)| entity_name == Some(*map_key))
                .filter_map(|(_, lock_opt)| lock_opt.as_ref().map(|l| l.to_sovd_lock(claims)))
                .collect(),
            schema: None,
        },
        ReadLock::OptionLock(l) => sovd_interfaces::locking::get::Response {
            items: l
                .as_ref()
                .map(|lock| lock.to_sovd_lock(claims))
                .into_iter()
                .collect(),
            schema: None,
        },
    }
}

pub(crate) async fn validate_lock(
    claims: &Claims,
    ecu_name: &String,
    locks: Arc<Locks>,
) -> Option<Response> {
    let ecu_lock = locks.ecu.lock_ro().await;
    let ecu_locks = get_locks(claims, &ecu_lock, Some(ecu_name));

    let vehicle_lock = locks.vehicle.lock_ro().await;
    let vehicle_locks = get_locks(claims, &vehicle_lock, None);
    // todo once functional locks are _actually_ locking the ecu, checking the vehicle lock is
    // not needed anymore
    if ecu_locks.items.is_empty() && vehicle_locks.items.is_empty() {
        return Some(
            ApiError::Forbidden(Some("Required ECU lock is missing".to_string())).into_response(),
        );
    }

    if let Err(e) = all_locks_owned(&ecu_lock, claims) {
        return Some(e.into_response());
    }
    None
}

#[tracing::instrument(
    skip(lock, claims),
    fields(
        lock_id,
        lock_type = %lock,
        entity_name = ?entity_name
    )
)]
async fn delete_handler(
    lock: &LockType,
    lock_id: &str,
    claims: Claims,
    entity_name: Option<&String>,
) -> Response {
    tracing::info!("Attempting to delete lock");

    let mut rw_lock = lock.lock_rw().await;
    let entity_lock = match rw_lock.get_mut(entity_name) {
        Ok(lock) => lock,
        Err(e) => return ErrorWrapper(e).into_response(),
    };

    if let Err(e) = validate_claim(Some(lock_id), &claims, entity_lock.as_ref()) {
        return ErrorWrapper(e).into_response();
    }

    if let Some(l) = entity_lock {
        l.deletion_task.abort();
        if let Err(e) = rw_lock.delete(entity_name) {
            return ErrorWrapper(e).into_response();
        }
        StatusCode::NO_CONTENT.into_response()
    } else {
        ApiError::NotFound(Some("No lock found".to_owned())).into_response()
    }
}

#[tracing::instrument(
    skip(lock, claims, rw_lock, expiration),
    fields(
        lock_type = %lock,
        entity_name = ?entity_name,
        lock_expiration = %expiration.lock_expiration
    )
)]
async fn post_handler(
    lock: &LockType,
    claims: &Claims,
    entity_name: Option<&String>,
    expiration: sovd_interfaces::locking::Request,
    rw_lock: Option<WriteLock<'_>>,
) -> Response {
    tracing::info!("Attempting to create lock");

    let mut rw_lock = match rw_lock {
        Some(lock) => lock,
        None => lock.lock_rw().await,
    };

    let lock_opt = match rw_lock.get_mut(entity_name) {
        Ok(lock) => lock,
        Err(e) => return ErrorWrapper(e).into_response(),
    };

    if lock_opt.is_some() {
        // if the lock is already set, try to update it, update_lock is validating ownership
        match update_lock(
            // needs to be cloned, because we can either borrow lock mutably or non mutably
            &lock_opt.as_ref().unwrap().sovd.id.clone(),
            claims,
            lock_opt,
            expiration,
            entity_name,
            lock,
        ) {
            Ok(lock) => (StatusCode::CREATED, Json(lock)).into_response(),
            Err(e) => ErrorWrapper(e).into_response(),
        }
    } else {
        match create_lock(claims, expiration, lock, entity_name) {
            Ok(new_lock) => {
                *lock_opt = Some(new_lock);
                (StatusCode::CREATED, Json(&lock_opt.as_ref().unwrap().sovd)).into_response()
            }
            Err(e) => ErrorWrapper(e).into_response(),
        }
    }
}

#[tracing::instrument(
    skip(lock, claims, expiration),
    fields(
        lock_id,
        lock_type = %lock,
        entity_name = ?entity_name,
        lock_expiration = %expiration.lock_expiration
    )
)]
async fn put_handler(
    lock: &LockType,
    lock_id: &str,
    claims: Claims,
    entity_name: Option<&String>,
    expiration: sovd_interfaces::locking::Request,
) -> Response {
    tracing::info!("Attempting to update lock");

    let mut rw_lock = lock.lock_rw().await;
    let entity_lock = match rw_lock.get_mut(entity_name) {
        Ok(lock) => lock,
        Err(e) => return ErrorWrapper(e).into_response(),
    };

    match update_lock(lock_id, &claims, entity_lock, expiration, entity_name, lock) {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => ErrorWrapper(e).into_response(),
    }
}

#[tracing::instrument(
    skip(lock, claims),
    fields(
        lock_type = %lock,
        entity_name = ?entity_name
    )
)]
async fn get_handler(lock: &LockType, claims: Claims, entity_name: Option<&String>) -> Response {
    tracing::info!("Getting locks");
    let ro_lock = lock.lock_ro().await;
    let locks = get_locks(&claims, &ro_lock, entity_name);
    (StatusCode::OK, Json(&locks)).into_response()
}

#[tracing::instrument(
    skip(lock),
    fields(
        lock_id = %lock_id,
        lock_type = %lock,
        entity_name = ?entity_name
    )
)]
async fn get_id_handler(
    lock: &LockType,
    lock_id: &String,
    entity_name: Option<&String>,
) -> Response {
    tracing::info!("Getting active lock by ID");
    let ro_lock = lock.lock_ro().await;
    if let Some(entity_lock) = ro_lock.get(entity_name, Some(lock_id)) {
        let sovd_lock_info: sovd_interfaces::locking::id::get::Response = entity_lock.into_sovd();

        (StatusCode::OK, Json(&sovd_lock_info)).into_response()
    } else {
        ErrorWrapper(ApiError::NotFound(Some(format!(
            "no lock found with id {lock_id}"
        ))))
        .into_response()
    }
}

fn validate_claim(
    lock_id: Option<&str>,
    claim: &Claims,
    lock_opt: Option<&Lock>,
) -> Result<(), ApiError> {
    if let Some(lock) = lock_opt
        && (claim.sub != lock.owner || lock_id.is_some_and(|id| id != lock.sovd.id))
    {
        return Err(ApiError::Forbidden(Some(
            "lock validation failed".to_owned(),
        )));
    }

    Ok(())
}

async fn vehicle_read_lock<'a>(
    locks: &'a Locks,
    claims: &'a Claims,
) -> Result<ReadLock<'a>, ApiError> {
    // hold the read lock until we have the ecu lock
    let vehicle_ro_lock = locks.vehicle.lock_ro().await;
    let vehicle_lock = vehicle_ro_lock.get(None, None);
    match validate_claim(None, claims, vehicle_lock) {
        Ok(()) => Ok(vehicle_ro_lock),
        Err(e) => Err(e),
    }
}

fn schedule_token_deletion(
    entity: Option<String>,
    lock_id: String,
    lock: LockType,
    expiration: DateTime<Utc>,
) -> Result<JoinHandle<()>, ApiError> {
    let now = Utc::now();
    let duration_until_target = expiration.signed_duration_since(now);

    if duration_until_target < chrono::Duration::zero() {
        return Err(ApiError::BadRequest(
            "expiration date is in the past".to_owned(),
        ));
    }

    let secs = duration_until_target
        .to_std()
        .map(|std_duration| std_duration.as_secs())
        .unwrap_or(0);

    let target_instant = Instant::now() + Duration::from_secs(secs);

    let join_handle = task::spawn(async move {
        sleep_until(target_instant).await; // cancellation point when task is aborted
        tracing::debug!(
            lock_id = %lock_id,
            lock_type = %lock,
            "Deletion task woke up, attempting to delete lock"
        );

        let mut rw_lock = lock.lock_rw().await;
        let entity_lock_result = rw_lock.get_mut(entity.as_ref());
        match entity_lock_result {
            Ok(entity_lock) => {
                if let Some(current_lock) = entity_lock {
                    if current_lock.sovd.id == lock_id {
                        *entity_lock = None;
                    } else {
                        tracing::warn!(
                            expected_id = %lock_id,
                            actual_id = %current_lock.sovd.id,
                            "Lock ID has changed before deletion"
                        );
                    }
                } else {
                    tracing::warn!(lock_id = %lock_id, "Lock not found for deletion");
                }
            }
            Err(e) => {
                tracing::error!(
                    lock_id = %lock_id,
                    error = %e,
                    "Failed to delete lock"
                );
            }
        }
    });
    Ok(join_handle)
}
pub(crate) fn all_locks_owned(locks: &ReadLock, claims: &Claims) -> Result<(), ApiError> {
    match locks {
        ReadLock::HashMapLock(l) => {
            for lock in l.values() {
                validate_claim(None, claims, lock.as_ref())?;
            }
            Ok(())
        }
        ReadLock::OptionLock(l) => validate_claim(None, claims, l.as_ref()),
    }
}

impl IntoSovd for &Lock {
    type SovdType = sovd_interfaces::locking::id::get::Response;

    fn into_sovd(self) -> Self::SovdType {
        Self::SovdType {
            lock_expiration: self.expiration.to_rfc3339_opts(SecondsFormat::Secs, true),
        }
    }
}

impl Lock {
    fn to_sovd_lock(&self, claims: &Claims) -> sovd_interfaces::locking::Lock {
        sovd_interfaces::locking::Lock {
            id: self.sovd.id.clone(),
            owned: Some(claims.sub == self.owner),
        }
    }
}
