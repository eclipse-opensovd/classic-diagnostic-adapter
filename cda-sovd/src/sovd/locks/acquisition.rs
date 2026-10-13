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

use std::sync::Arc;

use cda_interfaces::{
    DynamicPlugin, TesterPresentType, UdsEcu,
    lock_priority_api::{LockRequest, LockScope},
};
use cda_plugin_security::SecurityPlugin;
use uuid::Uuid;

use super::{
    ActiveLock, ApiError, LockCoverage, Locks, ScopeKey,
    cleanup::{LockCleanupFnHelper, reset_ecu_session_and_security},
};

pub(super) async fn create_lock<T: UdsEcu + Clone>(
    uds: &T,
    request: LockRequest,
    locks: &Arc<Locks>,
    coverage: LockCoverage,
    security_plugin: Box<dyn SecurityPlugin>,
) -> Result<(ActiveLock, LockCleanupFnHelper, Option<TesterPresentType>), ApiError> {
    let id = Uuid::new_v4().to_string();
    let principal = request.principal.clone();
    let scope = request.scope.clone();
    let parent_vehicle_lock_id = if scope == LockScope::Vehicle {
        None
    } else {
        locks
            .core
            .read_store(|store| {
                store
                    .state
                    .active_for_scope(&ScopeKey::Vehicle)
                    .filter(|lock| lock.principal.subject == principal.subject)
                    .map(|lock| lock.id.clone())
            })
            .await
    };
    let scope_key = ScopeKey::from(&scope);
    // Decided from the lock state, so a component lock under a functional-group
    // lock of the same client starts no physical tester present (see
    // `LockState::tester_present_for`). Releasing, expiring, or preempting
    // that functional-group lock releases the component lock too (see
    // `LockState::covered_narrow_locks`), and releasing the component lock on
    // its own while the functional-group lock survives skips its cleanup.
    let tester_present = locks
        .core
        .read_store(|store| {
            store
                .state
                .tester_present_for(&principal.subject, &scope_key)
        })
        .await;
    let cleanup_fn = match &scope_key {
        ScopeKey::Ecu(ecu_name) => {
            let ecu_name = ecu_name.clone();
            let tp_type = TesterPresentType::Ecu(ecu_name.clone());
            let uds = (*uds).clone();
            let locks = Arc::clone(locks);
            LockCleanupFnHelper::new(async move || {
                stop_tester_present_unless_needed(&uds, &locks, tp_type).await;
                reset_ecu_session_and_security(
                    &uds,
                    &ecu_name,
                    "ECU lock cleanup",
                    &(security_plugin as DynamicPlugin),
                )
                .await;
            })
        }
        ScopeKey::FunctionalGroup(group) => {
            let tp_type = TesterPresentType::Functional(group.clone());
            let covered_ecus = coverage.covered_ecus();
            let uds = (*uds).clone();
            let locks = Arc::clone(locks);
            LockCleanupFnHelper::new(async move || {
                stop_tester_present_unless_needed(&uds, &locks, tp_type).await;
                let sec = &(security_plugin as DynamicPlugin);
                for ecu in covered_ecus {
                    reset_ecu_session_and_security(
                        &uds,
                        &ecu,
                        "functional group lock cleanup",
                        sec,
                    )
                    .await;
                }
            })
        }
        ScopeKey::Vehicle => {
            let uds = (*uds).clone();
            LockCleanupFnHelper::new(async move || {
                let sec = &(security_plugin as DynamicPlugin);
                for ecu in uds.get_ecus().await {
                    reset_ecu_session_and_security(&uds, &ecu, "vehicle lock cleanup", sec).await;
                }
            })
        }
    };
    Ok((
        ActiveLock {
            id: id.into(),
            scope: scope_key,
            coverage,
            principal,
            metadata: request.metadata,
            exclusive: request.exclusive,
            expires_at: request.expires_at,
            parent_vehicle_lock_id,
        },
        cleanup_fn,
        tester_present,
    ))
}

/// Stops `type_` for a lock's cleanup, unless an active lock still needs it.
///
/// The cleanup runs after the state change that removed its lock, so after a
/// preemption on the same scope the new lock already needs `type_`: its tester
/// present is handed over, running or suspended, instead of being stopped and
/// restarted.
pub(super) async fn stop_tester_present_unless_needed<T: UdsEcu>(
    uds: &T,
    locks: &Locks,
    type_: TesterPresentType,
) {
    if locks
        .core
        .read_store(|store| store.state.tester_present_needed(&type_))
        .await
    {
        tracing::info!(
            ?type_,
            "Tester present still needed by an active lock; handing it over"
        );
        return;
    }
    if let Err(e) = uds.stop_tester_present(type_).await {
        tracing::error!("Failed to stop tester present for lock cleanup: {e}");
    } else {
        tracing::info!("Tester present stopped for lock cleanup");
    }
}
