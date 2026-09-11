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

use std::sync::Arc;

use cda_interfaces::{
    DynamicPlugin, TesterPresentType, UdsEcu,
    lock_priority_api::{LockRequest, LockScope},
};
use cda_plugin_security::SecurityPlugin;
use uuid::Uuid;

use super::{
    ActiveLock, ApiError, LockCoverage, LockTarget, Locks, ScopeKey,
    cleanup::{LockCleanupFnHelper, reset_ecu_session_and_security},
};

pub(super) async fn create_lock<T: UdsEcu + Clone>(
    uds: &T,
    request: LockRequest,
    lock_type: LockTarget,
    locks: &Arc<Locks>,
    entity_name: Option<&String>,
    coverage: LockCoverage,
    security_plugin: Box<dyn SecurityPlugin>,
) -> Result<(ActiveLock, LockCleanupFnHelper, Option<TesterPresentType>), ApiError> {
    let id = Uuid::new_v4().to_string();
    let principal = request.principal.clone();
    let scope = lock_type.scope(entity_name)?;
    let parent_vehicle = if scope == LockScope::Vehicle {
        None
    } else {
        locks
            .store
            .lock()
            .await
            .state
            .active_for_scope(&ScopeKey::Vehicle)
            .filter(|lock| lock.principal.subject == principal.subject)
            .map(|lock| lock.id.clone())
    };
    let (tester_present, cleanup_fn) = match lock_type {
        LockTarget::Ecu => {
            let ecu_name = entity_name
                .ok_or_else(|| ApiError::BadRequest("No ECU name provided".to_owned()))?
                .to_lowercase();
            let tp_type = TesterPresentType::Ecu(ecu_name.clone());
            let cleanup_tp_type = tp_type.clone();
            let uds = (*uds).clone();
            let cleanup = LockCleanupFnHelper::new(async move || {
                if let Err(e) = uds.stop_tester_present(cleanup_tp_type).await {
                    tracing::error!("Failed to stop tester present for lock cleanup: {e}");
                } else {
                    tracing::info!("Tester present stopped for ECU lock cleanup");
                }
                reset_ecu_session_and_security(
                    &uds,
                    &ecu_name,
                    "ECU lock cleanup",
                    &(security_plugin as DynamicPlugin),
                )
                .await;
            });
            (Some(tp_type), cleanup)
        }
        LockTarget::FunctionalGroup => {
            let functional_group_name = entity_name
                .ok_or_else(|| {
                    ApiError::BadRequest("No functional group name provided".to_owned())
                })?
                .to_lowercase();
            let tp_type = TesterPresentType::Functional(functional_group_name.clone());
            let covered_ecus = coverage.covered_ecus();
            let cleanup_tp_type = tp_type.clone();
            let uds = (*uds).clone();
            let cleanup = LockCleanupFnHelper::new(async move || {
                if let Err(e) = uds.stop_tester_present(cleanup_tp_type).await {
                    tracing::error!("Failed to stop tester present for lock cleanup: {e}");
                }
                tracing::info!("Tester present stopped for functional group lock cleanup");
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
            });
            (Some(tp_type), cleanup)
        }
        LockTarget::Vehicle => {
            let uds = (*uds).clone();
            let cleanup = LockCleanupFnHelper::new(async move || {
                let sec = &(security_plugin as DynamicPlugin);
                for ecu in uds.get_ecus().await {
                    reset_ecu_session_and_security(&uds, &ecu, "vehicle lock cleanup", sec).await;
                }
            });
            (None, cleanup)
        }
    };
    Ok((
        ActiveLock {
            id,
            scope: ScopeKey::from(&scope),
            coverage,
            principal,
            metadata: request.metadata,
            exclusive: request.exclusive,
            expires_at: request.expires_at,
            parent_vehicle,
        },
        cleanup_fn,
        tester_present,
    ))
}
