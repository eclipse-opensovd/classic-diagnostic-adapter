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
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{RwLock, RwLockReadGuard, RwLockWriteGuard},
    task::{self, JoinHandle},
    time::{Instant, sleep_until},
};
use uuid::Uuid;

use crate::sovd::{
    WebserverEcuState, WebserverState,
    auth::Claims,
    error::{ApiError, ErrorWrapper},
};

// later this likely will be a Vector of locks to support non exclusive locks
pub(crate) type LockHashMap = HashMap<String, Option<Lock>>;
pub(crate) type LockOption = Option<Lock>;

#[derive(Debug)]
pub(crate) struct Lock {
    sovd: SovdLock,
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
            LockType::FunctionalGroup(_) => "FuctionalGroup",
        };
        write!(formatter, "{type_name}")
    }
}

pub(in crate::sovd) enum ReadLock<'a> {
    HashMapLock(RwLockReadGuard<'a, LockHashMap>),
    OptionLock(RwLockReadGuard<'a, LockOption>),
}
pub(in crate::sovd) enum WriteLock<'a> {
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
    pub(in crate::sovd) async fn lock_ro(&self) -> ReadLock<'_> {
        match self {
            LockType::Vehicle(v) => ReadLock::OptionLock(v.read().await),
            LockType::Ecu(l) | LockType::FunctionalGroup(l) => {
                ReadLock::HashMapLock(l.read().await)
            }
        }
    }

    pub(in crate::sovd) async fn lock_rw(&self) -> WriteLock<'_> {
        match self {
            LockType::Vehicle(v) => WriteLock::OptionLock(v.write().await),
            LockType::Ecu(l) | LockType::FunctionalGroup(l) => {
                WriteLock::HashMapLock(l.write().await)
            }
        }
    }
}

pub(crate) async fn post_vehicle_lock_handler(
    claims: Claims,
    State(state): State<WebserverState>,
    WithRejection(Json(body), _): WithRejection<Json<SovdLockExpiration>, ApiError>,
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

    post_lock_handler(
        &state.locks.vehicle,
        &claims,
        None,
        body,
        Some(vehicle_rw_lock),
    )
    .await
}

pub(crate) async fn delete_vehicle_lock_handler(
    Path(lock): Path<String>,
    claims: Claims,
    State(state): State<WebserverState>,
) -> Response {
    delete_lock_handler(&state.locks.vehicle, &lock, claims, None).await
}

pub(crate) async fn put_vehicle_lock_handler(
    Path(lock): Path<String>,
    claims: Claims,
    State(state): State<WebserverState>,
    WithRejection(Json(body), _): WithRejection<Json<SovdLockExpiration>, ApiError>,
) -> Response {
    put_lock_handler(&state.locks.vehicle, &lock, claims, None, body).await
}

pub(crate) async fn get_vehicle_locks_handler(
    claims: Claims,
    State(state): State<WebserverState>,
) -> Response {
    get_locks_handler(&state.locks.vehicle, claims, None).await
}

pub(crate) async fn get_vehicle_active_lock(
    Path(lock): Path<String>,
    _: Claims,
    State(state): State<WebserverState>,
) -> Response {
    get_active_lock_handler(&state.locks.vehicle, &lock, None).await
}

pub(crate) async fn post_ecu_locks_handler<
    R: DiagServiceResponse + Send + Sync,
    T: UdsEcu + Send + Sync + Clone,
    U: FileManager + Send + Sync + Clone,
>(
    claims: Claims,
    State(WebserverEcuState {
        ecu_name, locks, ..
    }): State<WebserverEcuState<R, T, U>>,
    WithRejection(Json(body), _): WithRejection<Json<SovdLockExpiration>, ApiError>,
) -> Response {
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

    post_lock_handler(&locks.ecu, &claims, Some(&ecu_name), body, None).await
}

pub(crate) async fn delete_ecu_lock_handler<
    R: DiagServiceResponse + Send + Sync,
    T: UdsEcu + Send + Sync + Clone,
    U: FileManager + Send + Sync + Clone,
>(
    Path(lock): Path<String>,
    claims: Claims,
    State(WebserverEcuState {
        ecu_name, locks, ..
    }): State<WebserverEcuState<R, T, U>>,
) -> Response {
    delete_lock_handler(&locks.ecu, &lock, claims, Some(&ecu_name)).await
}

pub(crate) async fn put_ecu_lock_handler<
    R: DiagServiceResponse + Send + Sync,
    T: UdsEcu + Send + Sync + Clone,
    U: FileManager + Send + Sync + Clone,
>(
    Path(lock): Path<String>,
    claims: Claims,
    State(WebserverEcuState {
        ecu_name, locks, ..
    }): State<WebserverEcuState<R, T, U>>,
    WithRejection(Json(body), _): WithRejection<Json<SovdLockExpiration>, ApiError>,
) -> Response {
    put_lock_handler(&locks.ecu, &lock, claims, Some(&ecu_name), body).await
}

pub(crate) async fn get_ecu_locks_handler<
    R: DiagServiceResponse + Send + Sync,
    T: UdsEcu + Send + Sync + Clone,
    U: FileManager + Send + Sync + Clone,
>(
    claims: Claims,
    State(WebserverEcuState {
        ecu_name, locks, ..
    }): State<WebserverEcuState<R, T, U>>,
) -> Response {
    get_locks_handler(&locks.ecu, claims, Some(&ecu_name)).await
}

pub(crate) async fn get_ecu_active_lock<
    R: DiagServiceResponse + Send + Sync,
    T: UdsEcu + Send + Sync + Clone,
    U: FileManager + Send + Sync + Clone,
>(
    Path(lock): Path<String>,
    _: Claims,
    State(WebserverEcuState {
        ecu_name, locks, ..
    }): State<WebserverEcuState<R, T, U>>,
) -> Response {
    get_active_lock_handler(&locks.ecu, &lock, Some(&ecu_name)).await
}

pub(crate) async fn post_functionalgroup_locks_handler(
    Path(group): Path<String>,
    claims: Claims,
    State(state): State<WebserverState>,
    WithRejection(Json(body), _): WithRejection<Json<SovdLockExpiration>, ApiError>,
) -> Response {
    let vehicle_ro_lock = vehicle_read_lock(&state.locks, &claims).await;
    if let Err(e) = vehicle_ro_lock {
        return ErrorWrapper(e).into_response();
    }

    // todo (out of scope for poc) check if any of the ecus is already locked]
    post_lock_handler(
        &state.locks.functional_group,
        &claims,
        Some(&group),
        body,
        None,
    )
    .await
}

pub(crate) async fn delete_functionalgroup_lock_handler(
    Path((group, lock)): Path<(String, String)>,
    State(state): State<WebserverState>,
    claims: Claims,
) -> Response {
    delete_lock_handler(&state.locks.functional_group, &lock, claims, Some(&group)).await
}

pub(crate) async fn put_functionalgroup_lock_handler(
    Path((group, lock)): Path<(String, String)>,
    State(state): State<WebserverState>,
    claims: Claims,
    WithRejection(Json(body), _): WithRejection<Json<SovdLockExpiration>, ApiError>,
) -> Response {
    put_lock_handler(
        &state.locks.functional_group,
        &lock,
        claims,
        Some(&group),
        body,
    )
    .await
}

pub(crate) async fn get_functionalgroup_active_lock(
    Path((group, lock)): Path<(String, String)>,
    _: Claims,
    State(state): State<WebserverState>,
) -> Response {
    get_active_lock_handler(&state.locks.functional_group, &lock, Some(&group)).await
}

pub(crate) async fn get_functionalgroup_lock_handler(
    Path(group): Path<String>,
    State(state): State<WebserverState>,
    claims: Claims,
) -> Response {
    get_locks_handler(&state.locks.functional_group, claims, Some(&group)).await
}

async fn post_lock_handler(
    lock: &LockType,
    claims: &Claims,
    entity_name: Option<&String>,
    expiration: SovdLockExpiration,
    rw_lock: Option<WriteLock<'_>>,
) -> Response {
    log::info!(
        "trying to lock {} {} for {}s",
        lock,
        entity_name.map_or(String::new(), |s| format!("on entity {s} ")),
        expiration.lock_expiration
    );

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

async fn delete_lock_handler(
    lock: &LockType,
    lock_id: &str,
    claims: Claims,
    entity_name: Option<&String>,
) -> Response {
    log::info!("trying to delete lock {lock_id} from {lock}");

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

async fn put_lock_handler(
    lock: &LockType,
    lock_id: &str,
    claims: Claims,
    entity_name: Option<&String>,
    expiration: SovdLockExpiration,
) -> Response {
    log::info!("trying to update lock {lock_id} from {lock}");

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

async fn get_locks_handler(
    lock: &LockType,
    claims: Claims,
    entity_name: Option<&String>,
) -> Response {
    log::info!("getting locks from {entity_name:?} with id {lock}");
    let ro_lock = lock.lock_ro().await;
    let locks = get_locks(&claims, &ro_lock, entity_name);
    (StatusCode::OK, Json(&locks)).into_response()
}

async fn get_active_lock_handler(
    lock: &LockType,
    lock_id: &String,
    entity_name: Option<&String>,
) -> Response {
    log::info!("getting active lock from {entity_name:?} with id {lock}");
    let ro_lock = lock.lock_ro().await;
    if let Some(entity_lock) = ro_lock.get(entity_name, Some(lock_id)) {
        let sovd_lock_info = SovdActiveLockInfo::from_lock(entity_lock);
        (StatusCode::OK, Json(&sovd_lock_info)).into_response()
    } else {
        ErrorWrapper(ApiError::NotFound(Some(format!(
            "no lock found with id {lock_id}"
        ))))
        .into_response()
    }
}
fn create_lock(
    claims: &Claims,
    expiration: SovdLockExpiration,
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

    let sovd_lock = SovdLock { id: id.to_string() };
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
    expiration: SovdLockExpiration,
    entity_name: Option<&String>,
    lock: &LockType,
) -> Result<SovdLock, ApiError> {
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

pub(in crate::sovd) fn get_locks(
    claim: &Claims,
    locks: &ReadLock,
    entity_name: Option<&String>,
) -> SovdLockList {
    match locks {
        ReadLock::HashMapLock(l) => SovdLockList {
            items: l
                .iter()
                .filter(|(map_key, _)| {
                    if let Some(name) = entity_name {
                        *map_key == name
                    } else {
                        true
                    }
                })
                .map(|(_, lock_opt)| SovdLockList::from_lock(claim, lock_opt.as_ref()))
                .flat_map(|lock| lock.items)
                .collect(),
        },
        ReadLock::OptionLock(l) => SovdLockList::from_lock(claim, l.as_ref()),
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
        log::debug!("Deletion task woke up, trying to delete lock {lock_id} from {lock}");

        let mut rw_lock = lock.lock_rw().await;
        let entity_lock_result = rw_lock.get_mut(entity.as_ref());
        match entity_lock_result {
            Ok(entity_lock) => {
                if let Some(current_lock) = entity_lock {
                    if current_lock.sovd.id == lock_id {
                        *entity_lock = None;
                    } else {
                        log::warn!("Lock id has changed before deletion");
                    }
                } else {
                    log::warn!("Lock not found for deletion");
                }
            }
            Err(e) => {
                log::error!("Failed to delete lock: {e}");
            }
        }
    });
    Ok(join_handle)
}
pub(in crate::sovd) fn all_locks_owned(locks: &ReadLock, claims: &Claims) -> Result<(), ApiError> {
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

impl From<SovdLockExpiration> for DateTime<Utc> {
    fn from(value: SovdLockExpiration) -> Self {
        Utc::now() + Duration::from_secs(value.lock_expiration)
    }
}

impl SovdLockList {
    fn from_lock(claims: &Claims, lock: Option<&Lock>) -> SovdLockList {
        lock.as_ref()
            .map_or(SovdLockList { items: vec![] }, |lock| SovdLockList {
                items: vec![SovdLockInfo {
                    id: lock.sovd.id.clone(),
                    owned: claims.sub == lock.owner,
                }],
            })
    }
}

impl SovdActiveLockInfo {
    // not implementing Into<T> trait because clippy expects us to implement
    // From<T> trait instead and the reverse conversion is not possible
    fn from_lock(lock: &Lock) -> SovdActiveLockInfo {
        SovdActiveLockInfo {
            lock_expiration: lock.expiration.to_rfc3339_opts(SecondsFormat::Secs, true),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct SovdActiveLockInfo {
    lock_expiration: String,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct SovdLockInfo {
    id: String,

    /// If true, the SOVD client which
    /// performed the request owns the
    /// lock. The value is always false
    /// if the entity is not locked
    owned: bool,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct SovdLockExpiration {
    lock_expiration: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct SovdLock {
    id: String,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct SovdLockList {
    pub(in crate::sovd) items: Vec<SovdLockInfo>,
}
