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

use std::{option::Option, time::SystemTime};

use cda_interfaces::{UdsEcu, lock_config::LockAcquisitionPolicy, lock_priority_api::LockId};
use cda_plugin_security::Claims;

use super::{ActiveLock, ApiError, ErrorWrapper, LockCoverage, LockState, Locks, ScopeKey};

pub(super) fn validate_vehicle_children(
    active: &[ActiveLock],
    preempted_roots: &[LockId],
    subject: &str,
) -> Result<(), ApiError> {
    let is_preempted = |lock: &ActiveLock| {
        preempted_roots.iter().any(|root| {
            lock.id == *root
                || lock
                    .parent_vehicle_lock_id
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
    let key = ScopeKey::Ecu(ecu_name.to_ascii_lowercase());
    let now = SystemTime::now();
    locks
        .core
        .read_store(|store| {
            let state = &store.state;
            if let Some(lock) = state
                .defunct()
                .find(|lock| {
                    lock.original_expires_at > now
                        && lock.principal.subject == claims.sub()
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
        })
        .await
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

    let now = SystemTime::now();
    let target_scope = ScopeKey::Ecu(ecu_name.to_ascii_lowercase());
    locks
        .core
        .read_store(|store| {
            let state = &store.state;
            validate_active_locks(
                claims.sub(),
                state.active().filter(|lock| {
                    state.is_effective(lock, now)
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
        })
        .await
}

pub(crate) fn validate_defunct_fg_lock_in_state(
    claims: &impl Claims,
    target_scope: &ScopeKey,
    target_coverage: &LockCoverage,
    state: &LockState,
    include_schema: bool,
) -> Result<(), ErrorWrapper> {
    let now = SystemTime::now();
    if let Some(lock) = state
        .defunct()
        .find(|lock| {
            lock.original_expires_at > now
                && lock.principal.subject == claims.sub()
                && (lock.scope == ScopeKey::Vehicle
                    || &lock.scope == target_scope
                    || lock.coverage.overlaps(target_coverage))
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
    validate_fg_access(
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
    validate_fg_access(
        claims,
        functional_group_name,
        uds,
        locks,
        include_schema,
        true,
    )
    .await
}

async fn validate_fg_access<T: UdsEcu>(
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
    let now = SystemTime::now();
    locks
        .core
        .read_store(|store| {
            let state = &store.state;
            validate_defunct_fg_lock_in_state(
                claims,
                &target_scope,
                &target_coverage,
                state,
                include_schema,
            )?;
            validate_active_locks(
                claims.sub(),
                state.active().filter(|lock| {
                    state.is_effective(lock, now)
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
        })
        .await
}

pub(super) fn validate_active_locks<'a>(
    subject: &str,
    active_locks: impl Iterator<Item = &'a ActiveLock>,
    write: bool,
) -> Result<(), ApiError> {
    let active_locks = active_locks.collect::<Vec<_>>();
    if write && active_locks.is_empty() {
        return Err(ApiError::LockRequired(
            "Required lock is missing".to_owned(),
        ));
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
        && (claim.sub() != lock.principal.subject
            || lock_id.is_some_and(|id| id != lock.id.as_str()))
    {
        return Err(ApiError::Forbidden(Some(
            "lock validation failed".to_owned(),
        )));
    }

    Ok(())
}

/// Which vehicle lock a vehicle-wide write requires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VehicleLockRequirement {
    /// An exclusive or non-exclusive vehicle lock of the caller.
    #[cfg_attr(
        not(any(test, feature = "doip-direct-connect")),
        expect(
            dead_code,
            reason = "Used only by the doip-connect-ecu route, which exists only with the \
                      doip-direct-connect feature"
        )
    )]
    Any,
    /// An exclusive vehicle lock of the caller.
    Exclusive,
}

/// Requires the caller to hold the effective vehicle lock.
///
/// Used by operations that change the vehicle topology and therefore must not run
/// while any other client works on the vehicle. Fails with `LockBroken` (409) if the
/// caller's vehicle lock was preempted, `Locked` (423) if another client holds an
/// effective vehicle lock, and `LockRequired` (409) if the caller holds no vehicle lock,
/// its vehicle lock has expired or, for [`VehicleLockRequirement::Exclusive`], it is not
/// exclusive.
pub(crate) async fn validate_vehicle_write(
    claims: &impl Claims,
    locks: &Locks,
    include_schema: bool,
    requirement: VehicleLockRequirement,
) -> Result<(), ErrorWrapper> {
    let now = SystemTime::now();
    let exclusive = requirement == VehicleLockRequirement::Exclusive;
    locks
        .core
        .read_store(|store| {
            let state = &store.state;
            if let Some(lock) = state
                .defunct()
                .find(|lock| {
                    lock.original_expires_at > now
                        && lock.principal.subject == claims.sub()
                        && lock.scope == ScopeKey::Vehicle
                })
                .cloned()
            {
                let current_holder = state.current_holder(&lock).to_owned();
                return Err(lock.broken_error(&current_holder));
            }
            match state.active_for_scope(&ScopeKey::Vehicle) {
                Some(lock)
                    if lock.principal.subject != claims.sub() && state.is_effective(lock, now) =>
                {
                    Err(ApiError::Locked(
                        "Vehicle lock is held by another client".to_owned(),
                    ))
                }
                Some(lock)
                    if lock.principal.subject == claims.sub() && !state.is_effective(lock, now) =>
                {
                    Err(ApiError::LockRequired("Vehicle lock expired".to_owned()))
                }
                Some(lock)
                    if lock.principal.subject == claims.sub() && exclusive && !lock.exclusive =>
                {
                    Err(ApiError::LockRequired(
                        "Exclusive vehicle lock required".to_owned(),
                    ))
                }
                Some(lock) if lock.principal.subject == claims.sub() => Ok(()),
                _ if exclusive => Err(ApiError::LockRequired(
                    "Exclusive vehicle lock required".to_owned(),
                )),
                _ => Err(ApiError::LockRequired("Vehicle lock required".to_owned())),
            }
        })
        .await
        .map_err(|error| ErrorWrapper {
            error,
            include_schema,
        })
}

/// Validates that an ECU or functional-group lock may be acquired with respect to the
/// vehicle lock: the configured acquisition policy and blocking by a foreign vehicle lock.
///
/// [[ dimpl~sovd-api-lock-acquisition-policy, Child lock acquisition checks the configured vehicle lock precondition, dimpl ]]
pub(crate) async fn validate_vehicle_owner(
    locks: &Locks,
    claims: &impl Claims,
) -> Result<(), ApiError> {
    let now = SystemTime::now();
    locks
        .core
        .read_store(|store| {
            let state = &store.state;
            match state.active_for_scope(&ScopeKey::Vehicle) {
                // A foreign lock blocks until it is removed, also once it has expired.
                Some(owned) if owned.principal.subject != claims.sub() => Err(ApiError::Conflict(
                    "Vehicle lock is held by another client".to_owned(),
                )),
                // An expired own lock grants nothing, also before the expiration task
                // removed it.
                owned
                    if locks.config.lock_acquisition_policy
                        == LockAcquisitionPolicy::VehicleLockRequired
                        && owned.is_none_or(|owned| !state.is_effective(owned, now)) =>
                {
                    Err(ApiError::Conflict(
                        "An active vehicle lock is required to acquire this lock".to_owned(),
                    ))
                }
                _ => Ok(()),
            }
        })
        .await
}
