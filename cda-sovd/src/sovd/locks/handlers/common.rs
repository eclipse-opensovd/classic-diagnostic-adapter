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

use std::{collections::BTreeSet, option::Option, sync::Arc, time::SystemTime};

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use cda_interfaces::{
    TesterPresentType, UdsEcu,
    lock_priority_api::{
        LockLifecycleEvent, LockPriorityPolicy, LockRequest, LockScope, LockSnapshot,
    },
};
use cda_plugin_security::{Claims, SecurityPlugin};
use chrono::{DateTime, SecondsFormat, Utc};
use tokio::{sync::oneshot, task, time::Instant};

use super::super::{
    AcquisitionGuard, ActiveLock, ApiError, DefunctLock, ErrorWrapper, LockCleanupFnHelper,
    LockCoverage, LockState, LockTarget, Locks, PendingPreemption, ScopeKey, StateError,
    active_snapshot, create_lock, map_state_error, rollback_preemption, validate_claim,
};
use crate::sovd::locks::cleanup::{run_cleanups, take_cleanups};

pub(in crate::sovd::locks) struct ValidatedLockRequest {
    pub(in crate::sovd::locks) metadata: serde_json::Map<String, serde_json::Value>,
    pub(in crate::sovd::locks) requested_exclusive: Option<bool>,
    pub(in crate::sovd::locks) expires_at: SystemTime,
}

pub(in crate::sovd::locks) fn validated_expiration(
    request: &sovd_interfaces::locking::Request,
) -> Result<ValidatedLockRequest, ApiError> {
    let metadata = request.metadata.clone();
    let exclusive = request.x_sovd2uds_isexclusive;
    let expires_at = validated_expiration_duration(request.lock_expiration)?;
    Ok(ValidatedLockRequest {
        metadata,
        requested_exclusive: exclusive,
        expires_at,
    })
}

fn validated_expiration_duration(lock_expiration: u64) -> Result<SystemTime, ApiError> {
    if lock_expiration == 0 {
        return Err(ApiError::BadRequest(
            "Lock expiration must be greater than zero".to_owned(),
        ));
    }
    let expiration = Utc::now()
        .checked_add_signed(chrono::TimeDelta::seconds(
            lock_expiration.try_into().unwrap_or(i64::MAX),
        ))
        .unwrap_or_else(Utc::now);
    if expiration < Utc::now() {
        return Err(ApiError::BadRequest(
            "Expiration date is in the past".to_owned(),
        ));
    }
    Ok(SystemTime::from(expiration))
}

impl LockTarget {
    pub(in crate::sovd::locks) fn scope(
        self,
        entity_name: Option<&String>,
    ) -> Result<LockScope, ApiError> {
        match self {
            Self::Vehicle => Ok(LockScope::Vehicle),
            Self::Ecu => entity_name
                .cloned()
                .map(|name| LockScope::Ecu { name })
                .ok_or_else(|| ApiError::BadRequest("No ECU name provided".to_owned())),
            Self::FunctionalGroup => entity_name
                .cloned()
                .map(|name| LockScope::FunctionalGroup { name })
                .ok_or_else(|| {
                    ApiError::BadRequest("No functional group name provided".to_owned())
                }),
        }
    }
}

#[tracing::instrument(
    skip(locks, lock, claims),
    fields(
        lock_id,
        lock_type = %lock,
        entity_name = ?entity_name
    )
)]
pub(crate) async fn delete_handler(
    locks: &Locks,
    lock: LockTarget,
    scope: LockScope,
    lock_id: &str,
    claims: &impl Claims,
    entity_name: Option<&String>,
    include_schema: bool,
) -> Response {
    tracing::info!("Attempting to delete lock");
    let reservation = locks.reserve_transition().await;

    match locks.delete_defunct(lock_id, &scope, claims).await {
        Ok(true) => {
            reservation.finish().await;
            return StatusCode::NO_CONTENT.into_response();
        }
        Err(error) => {
            reservation.finish().await;
            return ErrorWrapper {
                error,
                include_schema,
            }
            .into_response();
        }
        Ok(false) => {}
    }
    let removed = {
        let mut store = locks.store.lock().await;
        let active = store
            .state
            .active_for_scope(&ScopeKey::from(&scope))
            .cloned();
        if let Err(error) = validate_claim(Some(lock_id), claims, active.as_ref()) {
            drop(store);
            reservation.finish().await;
            return ErrorWrapper {
                error,
                include_schema,
            }
            .into_response();
        }
        let Some(active) = active else {
            drop(store);
            reservation.finish().await;
            return ErrorWrapper {
                error: ApiError::NotFound(Some("No lock found".to_owned())),
                include_schema,
            }
            .into_response();
        };
        match store.state.delete(&active.id) {
            Ok(removed) => {
                let cleanups = take_cleanups(&mut store.cleanups, &removed);
                (removed, cleanups)
            }
            Err(error) => {
                drop(store);
                reservation.finish().await;
                return ErrorWrapper {
                    error: map_state_error(&error),
                    include_schema,
                }
                .into_response();
            }
        }
    };
    let (removed, cleanups) = removed;
    let policy = Arc::clone(&locks.priority_policy);
    let events: Vec<_> = removed
        .iter()
        .map(|lock| LockLifecycleEvent::Released {
            lock: active_snapshot(lock),
        })
        .collect();
    let sender = locks.lifecycle_sender.clone();
    let (completion_sender, completion_receiver) = oneshot::channel();
    // Keep cleanup and reservation release alive if the HTTP request is cancelled.
    task::spawn(async move {
        run_cleanups(cleanups).await;
        reservation.finish().await;
        for event in events {
            super::super::enqueue_lock_event(&sender, Arc::clone(&policy), event);
        }
        let _ = completion_sender.send(());
    });
    let _ = completion_receiver.await;
    StatusCode::NO_CONTENT.into_response()
}

pub(crate) struct LockContext<'a> {
    pub(crate) lock: LockTarget,
    pub(crate) all_locks: &'a Arc<Locks>,
    pub(crate) acquisition: AcquisitionGuard,
    pub(crate) pending: Option<PendingPreemption>,
    pub(crate) converted_lock_ids: Vec<String>,
    pub(crate) coverage: LockCoverage,
}

pub(crate) struct LockUpdateContext<'a> {
    pub(crate) all_locks: &'a Locks,
    pub(crate) lock: LockTarget,
    pub(crate) scope: LockScope,
}

fn commit_new_lock(
    state: &mut LockState,
    converted_lock_ids: &[String],
    pending: Option<&PendingPreemption>,
    new_lock: &ActiveLock,
) -> Result<Vec<ActiveLock>, StateError> {
    if let Some(pending) = pending {
        state.commit_replacement(
            &pending.root_lock_ids,
            converted_lock_ids,
            new_lock.clone(),
            &pending.broken_by,
            pending.broken_at,
        )
    } else if converted_lock_ids.is_empty() {
        if new_lock.scope == ScopeKey::Vehicle {
            let child_ids = state
                .active()
                .filter(|lock| lock.principal.subject == new_lock.principal.subject)
                .map(|lock| lock.id.clone())
                .collect::<Vec<_>>();
            state
                .insert_vehicle(new_lock.clone(), &child_ids)
                .map(|()| Vec::new())
        } else {
            state.insert_active(new_lock.clone()).map(|()| Vec::new())
        }
    } else {
        state.commit_replacement(
            &[],
            converted_lock_ids,
            new_lock.clone(),
            &new_lock.principal.subject,
            SystemTime::now(),
        )
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "Each argument transfers distinct transaction state into this async task. A \
              parameter struct would add indirection without creating a reusable abstraction"
)]
pub(in crate::sovd::locks) async fn run_acquisition_transaction<T: UdsEcu>(
    uds: T,
    locks: Arc<Locks>,
    acquisition: AcquisitionGuard,
    mut pending: Option<PendingPreemption>,
    converted_lock_ids: Vec<String>,
    new_lock: ActiveLock,
    cleanup: LockCleanupFnHelper,
    tester_present: Option<TesterPresentType>,
    expiration_target: Instant,
) -> Result<String, ApiError> {
    let evaluation_id = acquisition.evaluation_id.clone();
    let policy = Arc::clone(&acquisition.policy);
    let started_tester_present = if let Some(type_) = &tester_present {
        if uds.check_tester_present_active(type_).await {
            None
        } else {
            if let Err(error) = uds.start_tester_present(type_.clone()).await {
                if let Some(pending) = pending.take() {
                    pending.rollback();
                }
                acquisition.finish().await;
                return Err(ApiError::from(error));
            }
            Some(type_.clone())
        }
    } else {
        None
    };
    let converted = converted_lock_ids;

    let committed = {
        let mut store = locks.store.lock().await;
        if store.transition == Some(acquisition.transition_id()) {
            commit_new_lock(&mut store.state, &converted, pending.as_ref(), &new_lock).map(
                |removed| {
                    store.cleanups.insert(new_lock.id.clone(), cleanup);
                    let converted_ids: BTreeSet<&str> =
                        converted.iter().map(String::as_str).collect();
                    let (converted_locks, preempted_locks): (Vec<_>, Vec<_>) = removed
                        .into_iter()
                        .partition(|lock| converted_ids.contains(lock.id.as_str()));
                    for lock in &converted_locks {
                        store.cleanups.remove(&lock.id);
                    }
                    let cleanups = take_cleanups(&mut store.cleanups, &preempted_locks);
                    (converted_locks, preempted_locks, cleanups)
                },
            )
        } else {
            Err(StateError::Invariant(
                "Lock transition reservation was lost".to_owned(),
            ))
        }
    };
    let (converted_locks, preempted_locks, cleanups) = match committed {
        Ok(committed) => committed,
        Err(error) => {
            tracing::error!(%error, "Preflighted lock acquisition failed to commit");
            if let Some(pending) = pending.take() {
                pending.rollback();
            }
            if let Some(type_) = started_tester_present
                && let Err(stop_error) = uds.stop_tester_present(type_).await
            {
                tracing::error!(%stop_error, "Failed to stop tester present after lock commit failure");
            }
            acquisition.finish().await;
            return Err(map_state_error(&error));
        }
    };
    if let Some(pending) = &mut pending {
        pending.disarm();
    }
    for lock in &converted_locks {
        let tester_present = match &lock.scope {
            ScopeKey::Ecu(name) => Some(TesterPresentType::Ecu(name.clone())),
            ScopeKey::FunctionalGroup(name) => Some(TesterPresentType::Functional(name.clone())),
            ScopeKey::Vehicle => None,
        };
        if let Some(tester_present) = tester_present
            && let Err(error) = uds.stop_tester_present(tester_present).await
        {
            tracing::error!(%error, lock_id = %lock.id, "Failed to stop tester present for converted lock");
        }
    }
    run_cleanups(cleanups).await;
    for lock in &preempted_locks {
        if let Err(error) = locks.schedule_defunct_expiration(lock.expires_at) {
            tracing::error!(%error, lock_id = %lock.id, "Failed to schedule defunct lock expiration");
        }
    }
    acquisition.finish().await;
    finish_acquisition_transaction(
        &locks,
        &new_lock,
        expiration_target,
        pending.as_ref(),
        &preempted_locks,
        &converted_locks,
        evaluation_id,
        policy,
    )
    .await;
    Ok(new_lock.id)
}

/// Schedules the new lock's expiration and notifies the registered policy of the
/// committed `Created`/`Preempted` transition. Split out of
/// [`run_acquisition_transaction`] to keep that function within the workspace's
/// maximum-lines lint.
#[allow(
    clippy::too_many_arguments,
    reason = "This one-use finalizer consumes distinct transaction outputs. Wrapping them in a \
              struct would add an artificial type used only to satisfy the argument-count lint"
)]
async fn finish_acquisition_transaction(
    locks: &Locks,
    new_lock: &ActiveLock,
    expiration_target: Instant,
    pending: Option<&PendingPreemption>,
    preempted: &[ActiveLock],
    converted: &[ActiveLock],
    evaluation_id: Option<String>,
    policy: Arc<dyn LockPriorityPolicy>,
) {
    locks.schedule_expiration(new_lock, expiration_target).await;
    if let Some(pending) = pending {
        locks.notify_lock_event(
            Arc::clone(&pending.policy),
            LockLifecycleEvent::Preempted {
                evaluation_id: pending.evaluation_id.clone(),
                replacement: active_snapshot(new_lock),
                broken_by: pending.broken_by.clone(),
                defunct_lock_ids: preempted.iter().map(|lock| lock.id.clone()).collect(),
            },
        );
    } else if !converted.is_empty() {
        locks.notify_lock_event(
            policy,
            LockLifecycleEvent::Converted {
                replacement: active_snapshot(new_lock),
                converted_lock_ids: converted.iter().map(|lock| lock.id.clone()).collect(),
            },
        );
    } else {
        locks.notify_lock_event(
            policy,
            LockLifecycleEvent::Created {
                evaluation_id,
                lock: active_snapshot(new_lock),
            },
        );
    }
}

#[tracing::instrument(
    skip(uds, context, request, security_plugin),
    fields(
        lock_type = %context.lock,
        entity_name = ?entity_name,
        expires_at = ?request.expires_at
    )
)]
pub(crate) async fn post_handler<T: UdsEcu + Clone>(
    uds: &T,
    context: LockContext<'_>,
    entity_name: Option<&String>,
    request: LockRequest,
    include_schema: bool,
    security_plugin: Box<dyn SecurityPlugin>,
) -> Response {
    tracing::info!("Attempting to create lock");
    let scope = match context.lock.scope(entity_name) {
        Ok(scope) => scope,
        Err(error) => {
            return ErrorWrapper {
                error,
                include_schema,
            }
            .into_response();
        }
    };
    let existing = context.all_locks.active_for_scope(&scope).await;
    let existing_is_preempted = existing.as_ref().is_some_and(|lock| {
        context
            .pending
            .as_ref()
            .is_some_and(|pending| pending.root_lock_ids.contains(&lock.id))
    });
    if let Some(existing) = existing.filter(|_| !existing_is_preempted) {
        return renew_existing_lock(
            context,
            existing,
            request,
            include_schema,
            security_plugin.as_auth_plugin().claims().sub(),
        )
        .await;
    }
    let locks = Arc::clone(context.all_locks);
    let acquisition = context.acquisition;
    let pending = context.pending;
    let converted_lock_ids = context.converted_lock_ids;
    let coverage = context.coverage;
    let lock_type = context.lock;
    let entity_name = entity_name.cloned();
    let uds = uds.clone();
    let (sender, receiver) = oneshot::channel();
    // Own transaction guards in a detached task so request cancellation cannot
    // interrupt commit, rollback, or reservation release.
    task::spawn(async move {
        let result = match create_lock(
            &uds,
            request,
            lock_type,
            &locks,
            entity_name.as_ref(),
            coverage,
            security_plugin,
        )
        .await
        {
            Ok((new_lock, cleanup, tester_present)) => {
                let expiration_target = match Locks::expiration_target(&new_lock) {
                    Ok(target) => target,
                    Err(error) => {
                        rollback_preemption(pending, &locks).await;
                        acquisition.finish().await;
                        let _ = sender.send(Err(error));
                        return;
                    }
                };
                run_acquisition_transaction(
                    uds,
                    locks,
                    acquisition,
                    pending,
                    converted_lock_ids,
                    new_lock,
                    cleanup,
                    tester_present,
                    expiration_target,
                )
                .await
            }
            Err(error) => {
                rollback_preemption(pending, &locks).await;
                acquisition.finish().await;
                Err(error)
            }
        };
        let _ = sender.send(result);
    });
    match receiver.await.unwrap_or_else(|_| {
        Err(ApiError::InternalServerError(Some(
            "Lock acquisition transaction stopped unexpectedly".to_owned(),
        )))
    }) {
        Ok(lock_id) => (
            StatusCode::CREATED,
            Json(sovd_lock_response(&lock_id, include_schema)),
        )
            .into_response(),
        Err(error) => ErrorWrapper {
            error,
            include_schema,
        }
        .into_response(),
    }
}

async fn renew_existing_lock(
    mut context: LockContext<'_>,
    existing: ActiveLock,
    request: LockRequest,
    include_schema: bool,
    subject: &str,
) -> Response {
    let pending = context.pending.take();
    let error = if !context.converted_lock_ids.is_empty() {
        Some(ApiError::Conflict(
            "Cannot renew a lock while converting child locks".to_owned(),
        ))
    } else if existing.principal.subject != subject {
        Some(ApiError::Locked(
            "Lock is owned by another client".to_owned(),
        ))
    } else if existing.expires_at <= SystemTime::now() {
        Some(ApiError::Conflict("Lock has expired".to_owned()))
    } else {
        None
    };
    rollback_preemption(pending, context.all_locks).await;
    if let Some(error) = error {
        return ErrorWrapper {
            error,
            include_schema,
        }
        .into_response();
    }
    let existing_id = existing.id.clone();
    let evaluation_id = context.acquisition.evaluation_id.clone();
    let policy = Arc::clone(&context.acquisition.policy);
    let result = renew_lock(
        context.all_locks,
        &existing_id,
        request.expires_at,
        existing,
    )
    .await;
    context.acquisition.finish().await;
    match result {
        Ok(lock) => {
            context.all_locks.notify_lock_event(
                policy,
                LockLifecycleEvent::Renewed {
                    evaluation_id,
                    lock,
                },
            );
            (
                StatusCode::CREATED,
                Json(sovd_lock_response(&existing_id, include_schema)),
            )
                .into_response()
        }
        Err(error) => ErrorWrapper {
            error,
            include_schema,
        }
        .into_response(),
    }
}

#[tracing::instrument(
    skip(context, claims, expiration),
    fields(
        lock_id,
        lock_type = %context.lock,
        entity_name = ?entity_name,
        lock_expiration = %expiration.lock_expiration
    )
)]
pub(crate) async fn put_handler(
    context: LockUpdateContext<'_>,
    lock_id: &str,
    claims: &impl Claims,
    entity_name: Option<&String>,
    expiration: sovd_interfaces::locking::UpdateRequest,
    include_schema: bool,
) -> Response {
    tracing::info!("Attempting to update lock");
    let policy = Arc::clone(&context.all_locks.priority_policy);
    let reservation = context.all_locks.reserve_transition().await;

    if let Some(defunct) = context
        .all_locks
        .defunct_by_id(lock_id, &context.scope)
        .await
    {
        if defunct.principal.subject != claims.sub() {
            reservation.finish().await;
            return ErrorWrapper {
                error: ApiError::Forbidden(Some("lock validation failed".to_owned())),
                include_schema,
            }
            .into_response();
        }
        let current_holder = context.all_locks.current_holder(&defunct).await;
        reservation.finish().await;
        return ErrorWrapper {
            error: defunct.broken_error(&current_holder),
            include_schema,
        }
        .into_response();
    }

    let expires_at = match validated_expiration_duration(expiration.lock_expiration) {
        Ok(expires_at) => expires_at,
        Err(error) => {
            reservation.finish().await;
            return ErrorWrapper {
                error,
                include_schema,
            }
            .into_response();
        }
    };
    let active = context.all_locks.active_for_scope(&context.scope).await;
    if let Err(error) = validate_claim(Some(lock_id), claims, active.as_ref()) {
        reservation.finish().await;
        return ErrorWrapper {
            error,
            include_schema,
        }
        .into_response();
    }
    let Some(active) = active else {
        reservation.finish().await;
        return ErrorWrapper {
            error: ApiError::NotFound(Some("No lock found".to_owned())),
            include_schema,
        }
        .into_response();
    };
    if active.expires_at <= SystemTime::now() {
        reservation.finish().await;
        return ErrorWrapper {
            error: ApiError::Conflict("Lock has expired".to_owned()),
            include_schema,
        }
        .into_response();
    }
    let result = renew_lock(context.all_locks, lock_id, expires_at, active).await;
    reservation.finish().await;
    match result {
        Ok(lock) => {
            context.all_locks.notify_lock_event(
                policy,
                LockLifecycleEvent::Renewed {
                    evaluation_id: None,
                    lock,
                },
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => ErrorWrapper {
            error: e,
            include_schema,
        }
        .into_response(),
    }
}

async fn renew_lock(
    locks: &Locks,
    lock_id: &str,
    expires_at: SystemTime,
    active: ActiveLock,
) -> Result<LockSnapshot, ApiError> {
    Locks::expiration_target_at(expires_at)?;
    locks
        .store
        .lock()
        .await
        .state
        .renew(lock_id, expires_at)
        .map_err(|error| {
            if error == StateError::RenewalNotExtension {
                ApiError::BadRequest(error.to_string())
            } else {
                map_state_error(&error)
            }
        })?;
    let renewed = ActiveLock {
        expires_at,
        ..active
    };
    Ok(active_snapshot(&renewed))
}

#[tracing::instrument(
    skip(all_locks, lock, claims),
    fields(
        lock_type = %lock,
        entity_name = ?entity_name
    )
)]
pub(crate) async fn get_handler(
    all_locks: &Locks,
    lock: LockTarget,
    scope: LockScope,
    claims: &impl Claims,
    entity_name: Option<&str>,
    include_schema: bool,
) -> Response {
    tracing::info!("Getting locks");
    let key = ScopeKey::from(&scope);
    let mut store = all_locks.lock_idle().await;
    let state = &mut store.state;
    if let Err(error) = state.expire_defunct(SystemTime::now()) {
        tracing::error!(%error, "Failed to expire defunct locks");
    }
    let mut locks = sovd_interfaces::locking::get::Response {
        items: state
            .defunct()
            .filter(|lock| lock.scope == key)
            .map(|lock| defunct_to_sovd(lock, state, claims))
            .collect(),
        schema: include_schema
            .then(|| crate::sovd::create_schema!(sovd_interfaces::locking::get::Response)),
    };
    locks.items.extend(
        state
            .active_for_scope(&key)
            .map(|active| active_to_sovd(active, claims)),
    );
    (StatusCode::OK, Json(&locks)).into_response()
}

#[tracing::instrument(
    skip(all_locks, lock),
    fields(
        lock_id = %lock_id,
        lock_type = %lock,
        entity_name = ?entity_name
    )
)]
pub(crate) async fn get_id_handler(
    all_locks: &Locks,
    lock: LockTarget,
    scope: LockScope,
    lock_id: &String,
    entity_name: Option<&String>,
    include_schema: bool,
) -> Response {
    tracing::info!("Getting active lock by ID");
    let mut store = all_locks.lock_idle().await;
    let state = &mut store.state;
    if let Err(error) = state.expire_defunct(SystemTime::now()) {
        tracing::error!(%error, "Failed to expire defunct locks");
    }
    if let Some(active) = state
        .active_by_id(lock_id)
        .filter(|active| active.scope == ScopeKey::from(&scope))
    {
        let mut response = active_details(active);
        response.schema = lock_details_schema(include_schema);
        (StatusCode::OK, Json(response)).into_response()
    } else if let Some(defunct) = state
        .defunct_by_id(lock_id)
        .filter(|defunct| defunct.scope == ScopeKey::from(&scope))
    {
        let mut response = defunct_details(defunct, state);
        response.schema = lock_details_schema(include_schema);
        (StatusCode::OK, Json(response)).into_response()
    } else {
        ErrorWrapper {
            error: ApiError::NotFound(Some(format!("no lock found with id {lock_id}"))),
            include_schema,
        }
        .into_response()
    }
}

fn sovd_lock(id: &str) -> sovd_interfaces::locking::Lock {
    sovd_interfaces::locking::Lock {
        id: id.to_owned(),
        lock_expiration: None,
        owned: Some(true),
        x_sovd2uds_broken_by: None,
        x_sovd2uds_broken_at: None,
        x_sovd2uds_current_holder: None,
        schema: None,
    }
}

pub(in crate::sovd::locks) fn sovd_lock_response(
    id: &str,
    include_schema: bool,
) -> sovd_interfaces::locking::Lock {
    let mut response = sovd_lock(id);
    response.schema = include_schema
        .then(|| crate::sovd::create_schema!(sovd_interfaces::locking::post_put::Response));
    response
}

fn lock_details_schema(include_schema: bool) -> Option<schemars::Schema> {
    include_schema.then(|| crate::sovd::create_schema!(sovd_interfaces::locking::id::get::Response))
}

fn active_to_sovd(lock: &ActiveLock, claims: &impl Claims) -> sovd_interfaces::locking::Lock {
    let mut response = sovd_lock(&lock.id);
    response.lock_expiration =
        Some(DateTime::<Utc>::from(lock.expires_at).to_rfc3339_opts(SecondsFormat::Secs, true));
    response.owned = Some(lock.principal.subject == claims.sub());
    response
}

fn defunct_to_sovd(
    lock: &DefunctLock,
    state: &LockState,
    claims: &impl Claims,
) -> sovd_interfaces::locking::Lock {
    let mut response = lock.to_sovd_lock(claims);
    response.lock_expiration = Some(
        DateTime::<Utc>::from(lock.original_expires_at).to_rfc3339_opts(SecondsFormat::Secs, true),
    );
    response.x_sovd2uds_current_holder = Some(state.current_holder(lock).to_owned());
    response
}

fn active_details(lock: &ActiveLock) -> sovd_interfaces::locking::id::get::Response {
    sovd_interfaces::locking::id::get::Response {
        lock_expiration: DateTime::<Utc>::from(lock.expires_at)
            .to_rfc3339_opts(SecondsFormat::Secs, true),
        x_sovd2uds_broken_by: None,
        x_sovd2uds_broken_at: None,
        x_sovd2uds_current_holder: None,
        schema: None,
    }
}

fn defunct_details(
    lock: &DefunctLock,
    state: &LockState,
) -> sovd_interfaces::locking::id::get::Response {
    let mut response = lock.details();
    response.x_sovd2uds_current_holder = Some(state.current_holder(lock).to_owned());
    response
}
