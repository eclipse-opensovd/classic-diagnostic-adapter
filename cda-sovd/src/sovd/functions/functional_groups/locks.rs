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
use cda_interfaces::{UdsEcu, lock_priority_api::LockScope};
use cda_plugin_security::Secured;

use super::{
    ApiError, ErrorWrapper, IntoResponse, Json, Path, Query, Response, State, WebserverFgState,
    WithRejection,
};
use crate::{
    openapi,
    sovd::{
        lock_state::{self, ActiveLock, LockCoverage, ScopeKey},
        locks::{
            LockContext, LockPathParam, LockTarget, LockUpdateContext, delete_handler, get_handler,
            get_id_handler, post_handler, put_handler, rollback_preemption, validate_vehicle_owner,
        },
    },
};

pub(crate) mod lock {
    use cda_interfaces::UdsEcu;

    use super::{
        ApiError, Json, LockPathParam, LockScope, LockTarget, LockUpdateContext, Path, Query,
        Response, Secured, State, TransformOperation, UseApi, WebserverFgState, WithRejection,
        delete_handler, get_id_handler, openapi, put_handler,
    };

    pub(crate) async fn delete<T: UdsEcu + Clone>(
        Path(LockPathParam { lock }): Path<LockPathParam>,
        State(state): State<WebserverFgState<T>>,
        UseApi(sec_plugin, _): UseApi<Secured, ()>,
        Query(query): Query<sovd_interfaces::IncludeSchemaQuery>,
    ) -> Response {
        let claims = sec_plugin.as_auth_plugin().claims();
        delete_handler(
            &state.locks,
            LockTarget::FunctionalGroup,
            LockScope::FunctionalGroup {
                name: state.functional_group_name.clone(),
            },
            &lock,
            &claims,
            Some(&state.functional_group_name),
            query.include_schema,
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
                lock: LockTarget::FunctionalGroup,
                scope: LockScope::FunctionalGroup {
                    name: state.functional_group_name.clone(),
                },
            },
            &lock,
            &claims,
            Some(&state.functional_group_name),
            body,
            query.include_schema,
        )
        .await
    }

    pub(crate) fn docs_put(op: TransformOperation) -> TransformOperation {
        op.description("Extend a functional group lock's expiration")
            .response_with::<204, (), _>(|res| res.description("Lock updated successfully."))
            .with(openapi::lock_not_found)
            .with(openapi::lock_not_owned)
    }

    pub(crate) async fn get<T: UdsEcu + Clone>(
        Path(LockPathParam { lock }): Path<LockPathParam>,
        UseApi(_sec_plugin, _): UseApi<Secured, ()>,
        State(state): State<WebserverFgState<T>>,
        Query(query): Query<sovd_interfaces::IncludeSchemaQuery>,
    ) -> Response {
        get_id_handler(
            &state.locks,
            LockTarget::FunctionalGroup,
            LockScope::FunctionalGroup {
                name: state.functional_group_name.clone(),
            },
            &lock,
            Some(&state.functional_group_name),
            query.include_schema,
        )
        .await
    }

    pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
        op.description("Get a specific functional group lock")
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
    State(state): State<WebserverFgState<T>>,
    Query(query): Query<sovd_interfaces::IncludeSchemaQuery>,
    WithRejection(Json(body), _): WithRejection<Json<sovd_interfaces::locking::Request>, ApiError>,
) -> Response {
    let claims = sec_plugin.as_ref().as_auth_plugin().claims();
    let coverage = lock_state::LockCoverage::new(
        state
            .uds
            .ecus_for_functional_group(&state.functional_group_name, false)
            .await,
    );
    let (acquisition, pending, request) = match state
        .locks
        .evaluate_acquisition(
            LockScope::FunctionalGroup {
                name: state.functional_group_name.clone(),
            },
            coverage.clone(),
            &body,
            &claims,
        )
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
    if let Err(error) = validate_vehicle_owner(&state.locks, &claims).await {
        rollback_preemption(pending, &state.locks).await;
        acquisition.finish().await;
        return ErrorWrapper {
            error,
            include_schema: query.include_schema,
        }
        .into_response();
    }
    let owned_ecu_lock_ids =
        match select_same_owner_ecu_locks(&state.locks.open_locks().await, &coverage, claims.sub())
        {
            Ok(lock_ids) => lock_ids,
            Err(error) => {
                rollback_preemption(pending, &state.locks).await;
                acquisition.finish().await;
                return ErrorWrapper {
                    error,
                    include_schema: query.include_schema,
                }
                .into_response();
            }
        };
    post_handler(
        &state.uds,
        LockContext {
            lock: LockTarget::FunctionalGroup,
            all_locks: &state.locks,
            acquisition,
            pending,
            converted_lock_ids: owned_ecu_lock_ids,
            coverage,
        },
        Some(&state.functional_group_name),
        request,
        query.include_schema,
        sec_plugin,
    )
    .await
}

pub(crate) fn docs_post(op: TransformOperation) -> TransformOperation {
    op.description("Create a functional group lock")
        .response_with::<201, Json<sovd_interfaces::locking::post_put::Response>, _>(|res| {
            res.example(openapi::lock_created_example())
                .description("Functional group lock created successfully.")
        })
        .with(openapi::lock_not_owned)
}

pub(crate) async fn get<T: UdsEcu + Clone>(
    UseApi(sec_plugin, _): UseApi<Secured, ()>,
    State(state): State<WebserverFgState<T>>,
    Query(query): Query<sovd_interfaces::IncludeSchemaQuery>,
) -> Response {
    let claims = sec_plugin.as_auth_plugin().claims();
    get_handler(
        &state.locks,
        LockTarget::FunctionalGroup,
        LockScope::FunctionalGroup {
            name: state.functional_group_name.clone(),
        },
        &claims,
        Some(&state.functional_group_name),
        query.include_schema,
    )
    .await
}

pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
    op.description("Get all functional group locks")
        .response_with::<200, Json<sovd_interfaces::locking::get::Response>, _>(|res| {
            res.example(openapi::lock_list_example())
                .description("List of functional group locks.")
        })
}

/// Selects open ECU locks whose coverage overlaps the functional group coverage.
///
/// Overlapping locks owned by the requesting subject are returned for
/// conversion; an overlapping lock held by a different subject is a conflict.
fn select_same_owner_ecu_locks(
    open_locks: &[ActiveLock],
    coverage: &LockCoverage,
    subject: &str,
) -> Result<Vec<String>, ApiError> {
    let mut owned_ecu_lock_ids = Vec::new();
    for lock in open_locks {
        let ScopeKey::Ecu(name) = &lock.scope else {
            continue;
        };
        if lock.coverage.overlaps(coverage) {
            if lock.principal.subject != subject {
                return Err(ApiError::Conflict(format!(
                    "ECU {name} is locked by different user. This prevents setting functional \
                     group lock"
                )));
            }
            owned_ecu_lock_ids.push(lock.id.clone());
        }
    }
    Ok(owned_ecu_lock_ids)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use cda_interfaces::lock_priority_api::LockPrincipal;

    use super::*;

    fn ecu_lock(id: &str, ecu_name: &str, subject: &str) -> ActiveLock {
        ActiveLock {
            id: id.to_owned(),
            scope: ScopeKey::Ecu(ecu_name.to_owned()),
            coverage: LockCoverage::new([ecu_name.to_owned()]),
            principal: LockPrincipal {
                subject: subject.to_owned(),
                claims: serde_json::Map::new(),
            },
            metadata: serde_json::Map::new(),
            exclusive: true,
            expires_at: SystemTime::now()
                .checked_add(Duration::from_secs(300))
                .expect("Test expiration should be representable"),
            parent_vehicle: None,
        }
    }

    #[test]
    fn owned_ecu_lock_with_different_casing_is_converted() {
        let locks = vec![ecu_lock("owned-lock", "Engine_ECU", "owner")];
        let coverage = LockCoverage::new(["ENGINE_ecu".to_owned()]);

        let converted = select_same_owner_ecu_locks(&locks, &coverage, "owner")
            .expect("Owned overlapping ECU lock must be converted, not conflict");

        assert_eq!(converted, ["owned-lock"]);
    }

    #[test]
    fn foreign_owned_overlapping_ecu_lock_conflicts() {
        let locks = vec![ecu_lock("foreign-lock", "engine_ecu", "other")];
        let coverage = LockCoverage::new(["Engine_ECU".to_owned()]);

        let error = select_same_owner_ecu_locks(&locks, &coverage, "owner")
            .expect_err("Foreign overlapping ECU lock must conflict");

        assert!(matches!(error, ApiError::Conflict(_)));
    }

    #[test]
    fn non_overlapping_ecu_lock_is_ignored() {
        let locks = vec![ecu_lock("other-lock", "brake_ecu", "owner")];
        let coverage = LockCoverage::new(["engine_ecu".to_owned()]);

        let converted = select_same_owner_ecu_locks(&locks, &coverage, "owner")
            .expect("Non-overlapping ECU lock must not conflict");

        assert!(converted.is_empty());
    }
}
