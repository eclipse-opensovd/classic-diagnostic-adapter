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

use std::{option::Option, time::SystemTime};

use cda_interfaces::{UdsEcu, lock_priority_api::LockScope};
use cda_plugin_security::Claims;

use super::{ActiveLock, ApiError, ErrorWrapper, LockCoverage, LockState, Locks, ScopeKey};

pub(super) fn validate_vehicle_children(
    active: &[ActiveLock],
    preempted_roots: &[String],
    subject: &str,
) -> Result<(), ApiError> {
    let is_preempted = |lock: &ActiveLock| {
        preempted_roots.iter().any(|root| {
            lock.id == *root
                || lock
                    .parent_vehicle
                    .as_ref()
                    .is_some_and(|parent| parent == root)
        })
    };
    if active
        .iter()
        .any(|lock| !is_preempted(lock) && lock.principal.subject != subject)
    {
        return Err(ApiError::Locked(
            "A child lock is held by another client".to_owned(),
        ));
    }
    Ok(())
}
pub(crate) async fn validate_defunct_lock(
    claims: &impl Claims,
    ecu_name: &str,
    locks: &Locks,
    include_schema: bool,
) -> Result<(), ErrorWrapper> {
    let mut store = locks.lock_idle().await;
    let state = &mut store.state;
    if let Err(error) = state.expire_defunct(SystemTime::now()) {
        tracing::error!(%error, "Failed to expire defunct locks");
    }
    let key = ScopeKey::Ecu(ecu_name.to_ascii_lowercase());
    if let Some(lock) = state
        .defunct()
        .find(|lock| {
            lock.principal.subject == claims.sub()
                && (lock.scope == ScopeKey::Vehicle
                    || lock.scope == key
                    || lock.coverage.contains_ecu(ecu_name))
        })
        .cloned()
    {
        let current_holder = state.current_holder(&lock).to_owned();
        return Err(ErrorWrapper {
            error: lock.broken_error(&current_holder),
            include_schema,
        });
    }
    Ok(())
}

pub(crate) async fn validate_ecu_read(
    claims: &impl Claims,
    ecu_name: &str,
    locks: &Locks,
    include_schema: bool,
) -> Result<(), ErrorWrapper> {
    validate_ecu_access(claims, ecu_name, locks, include_schema, false).await
}

pub(crate) async fn validate_ecu_write(
    claims: &impl Claims,
    ecu_name: &str,
    locks: &Locks,
    include_schema: bool,
) -> Result<(), ErrorWrapper> {
    validate_ecu_access(claims, ecu_name, locks, include_schema, true).await
}

async fn validate_ecu_access(
    claims: &impl Claims,
    ecu_name: &str,
    locks: &Locks,
    include_schema: bool,
    write: bool,
) -> Result<(), ErrorWrapper> {
    validate_defunct_lock(claims, ecu_name, locks, include_schema).await?;

    let store = locks.lock_idle().await;
    let state = &store.state;
    let now = SystemTime::now();
    let target_scope = ScopeKey::Ecu(ecu_name.to_ascii_lowercase());
    validate_active_locks(
        claims.sub(),
        state.active().filter(|lock| {
            active_lock_is_effective(state, lock, now)
                && (lock.scope == ScopeKey::Vehicle
                    || lock.scope == target_scope
                    || lock.coverage.contains_ecu(ecu_name))
        }),
        write,
    )
    .map_err(|error| ErrorWrapper {
        error,
        include_schema,
    })
}

pub(crate) async fn validate_defunct_fg_lock<T: UdsEcu>(
    claims: &impl Claims,
    functional_group_name: &str,
    uds: &T,
    locks: &Locks,
    include_schema: bool,
) -> Result<(), ErrorWrapper> {
    let target_coverage = LockCoverage::new(
        uds.ecus_for_functional_group(functional_group_name, false)
            .await,
    );
    let target_scope = ScopeKey::FunctionalGroup(functional_group_name.to_ascii_lowercase());
    let mut store = locks.lock_idle().await;
    let state = &mut store.state;
    if let Err(error) = state.expire_defunct(SystemTime::now()) {
        tracing::error!(%error, "Failed to expire defunct locks");
    }
    if let Some(lock) = state
        .defunct()
        .find(|lock| {
            lock.principal.subject == claims.sub()
                && (lock.scope == ScopeKey::Vehicle
                    || lock.scope == target_scope
                    || lock.coverage.overlaps(&target_coverage))
        })
        .cloned()
    {
        let current_holder = state.current_holder(&lock).to_owned();
        return Err(ErrorWrapper {
            error: lock.broken_error(&current_holder),
            include_schema,
        });
    }
    Ok(())
}

pub(crate) async fn validate_fg_read<T: UdsEcu>(
    claims: &impl Claims,
    functional_group_name: &str,
    uds: &T,
    locks: &Locks,
    include_schema: bool,
) -> Result<(), ErrorWrapper> {
    validate_defunct_fg_lock(claims, functional_group_name, uds, locks, include_schema).await?;

    validate_active_fg_locks(
        claims,
        functional_group_name,
        uds,
        locks,
        include_schema,
        false,
    )
    .await
}

pub(crate) async fn validate_fg_write<T: UdsEcu>(
    claims: &impl Claims,
    functional_group_name: &str,
    uds: &T,
    locks: &Locks,
    include_schema: bool,
) -> Result<(), ErrorWrapper> {
    validate_defunct_fg_lock(claims, functional_group_name, uds, locks, include_schema).await?;

    validate_active_fg_locks(
        claims,
        functional_group_name,
        uds,
        locks,
        include_schema,
        true,
    )
    .await
}

async fn validate_active_fg_locks<T: UdsEcu>(
    claims: &impl Claims,
    functional_group_name: &str,
    uds: &T,
    locks: &Locks,
    include_schema: bool,
    write: bool,
) -> Result<(), ErrorWrapper> {
    let target_coverage = LockCoverage::new(
        uds.ecus_for_functional_group(functional_group_name, false)
            .await,
    );
    let target_scope = ScopeKey::FunctionalGroup(functional_group_name.to_ascii_lowercase());
    let store = locks.lock_idle().await;
    let state = &store.state;
    let now = SystemTime::now();
    validate_active_locks(
        claims.sub(),
        state.active().filter(|lock| {
            active_lock_is_effective(state, lock, now)
                && (lock.scope == ScopeKey::Vehicle
                    || lock.scope == target_scope
                    || lock.coverage.overlaps(&target_coverage))
        }),
        write,
    )
    .map_err(|error| ErrorWrapper {
        error,
        include_schema,
    })
}

fn active_lock_is_effective(state: &LockState, lock: &ActiveLock, now: SystemTime) -> bool {
    lock.expires_at > now
        && lock.parent_vehicle.as_deref().is_none_or(|parent_id| {
            state
                .active_by_id(parent_id)
                .is_some_and(|parent| parent.expires_at > now)
        })
}

pub(super) fn validate_active_locks<'a>(
    subject: &str,
    active_locks: impl Iterator<Item = &'a ActiveLock>,
    write: bool,
) -> Result<(), ApiError> {
    let active_locks = active_locks.collect::<Vec<_>>();
    if write && active_locks.is_empty() {
        return Err(ApiError::Conflict("Required lock is missing".to_owned()));
    }
    if active_locks
        .iter()
        .any(|lock| lock.principal.subject != subject && (write || lock.exclusive))
    {
        return Err(ApiError::Locked(
            "Lock is owned by another client".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn validate_claim(
    lock_id: Option<&str>,
    claim: &impl Claims,
    lock_opt: Option<&ActiveLock>,
) -> Result<(), ApiError> {
    if let Some(lock) = lock_opt
        && (claim.sub() != lock.principal.subject || lock_id.is_some_and(|id| id != lock.id))
    {
        return Err(ApiError::Forbidden(Some(
            "lock validation failed".to_owned(),
        )));
    }

    Ok(())
}

pub(crate) async fn validate_vehicle_owner(
    locks: &Locks,
    claims: &impl Claims,
) -> Result<(), ApiError> {
    let vehicle = locks.active_for_scope(&LockScope::Vehicle).await;
    if vehicle
        .as_ref()
        .is_some_and(|lock| lock.principal.subject != claims.sub())
    {
        return Err(ApiError::Conflict(
            "Vehicle lock is held by another client".to_owned(),
        ));
    }
    Ok(())
}
