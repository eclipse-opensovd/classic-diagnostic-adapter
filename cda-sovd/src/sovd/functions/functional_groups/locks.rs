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
        lock_state::{self, ActiveLock, LockCoverage},
        locks::{
            LockContext, LockPathParam, LockUpdateContext, delete_handler, get_handler,
            get_id_handler, post_handler, put_handler, rollback_preemption, validate_vehicle_owner,
        },
    },
};

pub(crate) mod lock {
    use cda_interfaces::UdsEcu;

    use super::{
        ApiError, Json, LockPathParam, LockScope, LockUpdateContext, Path, Query, Response,
        Secured, State, TransformOperation, UseApi, WebserverFgState, WithRejection,
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
            LockScope::FunctionalGroup {
                name: state.functional_group_name.clone(),
            },
            &lock,
            &claims,
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
                scope: LockScope::FunctionalGroup {
                    name: state.functional_group_name.clone(),
                },
            },
            &lock,
            &claims,
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
            LockScope::FunctionalGroup {
                name: state.functional_group_name.clone(),
            },
            &lock,
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
    if let Err(error) =
        validate_functional_group_overlap(&state.locks.open_locks().await, &coverage, claims.sub())
    {
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
            all_locks: &state.locks,
            acquisition,
            pending,
            coverage,
        },
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
        LockScope::FunctionalGroup {
            name: state.functional_group_name.clone(),
        },
        &claims,
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

/// Rejects functional-group coverage that overlaps a lock held by another client.
fn validate_functional_group_overlap(
    open_locks: &[ActiveLock],
    coverage: &LockCoverage,
    subject: &str,
) -> Result<(), ApiError> {
    if let Some(lock) = open_locks.iter().find(|lock| {
        lock.parent_vehicle_lock_id.is_none()
            && lock.coverage.overlaps(coverage)
            && lock.principal.subject != subject
    }) {
        return Err(ApiError::Conflict(format!(
            "Lock {} is owned by another client and overlaps the functional group",
            lock.id
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use cda_interfaces::lock_priority_api::LockPrincipal;

    use super::*;
    use crate::sovd::lock_state::ScopeKey;

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
            parent_vehicle_lock_id: None,
        }
    }

    #[test]
    fn owned_ecu_lock_with_different_casing_can_coexist() {
        let locks = vec![ecu_lock("owned-lock", "Engine_ECU", "owner")];
        let coverage = LockCoverage::new(["ENGINE_ecu".to_owned()]);

        validate_functional_group_overlap(&locks, &coverage, "owner")
            .expect("Owned overlapping ECU lock must coexist");
    }

    #[test]
    fn foreign_owned_overlapping_ecu_lock_conflicts() {
        let locks = vec![ecu_lock("foreign-lock", "engine_ecu", "other")];
        let coverage = LockCoverage::new(["Engine_ECU".to_owned()]);

        let error = validate_functional_group_overlap(&locks, &coverage, "owner")
            .expect_err("Foreign overlapping ECU lock must conflict");

        assert!(matches!(error, ApiError::Conflict(_)));
    }

    #[test]
    fn non_overlapping_ecu_lock_is_ignored() {
        let locks = vec![ecu_lock("other-lock", "brake_ecu", "owner")];
        let coverage = LockCoverage::new(["engine_ecu".to_owned()]);

        validate_functional_group_overlap(&locks, &coverage, "owner")
            .expect("Non-overlapping ECU lock must not conflict");
    }

    #[test]
    fn owned_overlapping_functional_lock_can_coexist() {
        let mut lock = ecu_lock("owned-lock", "engine", "owner");
        lock.scope = ScopeKey::FunctionalGroup("existing-group".to_owned());
        let coverage = LockCoverage::new(["engine".to_owned()]);

        validate_functional_group_overlap(&[lock], &coverage, "owner")
            .expect("Owned overlapping functional lock must coexist");
    }

    #[test]
    fn foreign_overlapping_functional_lock_conflicts() {
        let mut lock = ecu_lock("foreign-lock", "engine", "other");
        lock.scope = ScopeKey::FunctionalGroup("existing-group".to_owned());
        let coverage = LockCoverage::new(["engine".to_owned()]);

        assert!(matches!(
            validate_functional_group_overlap(&[lock], &coverage, "owner"),
            Err(ApiError::Conflict(_))
        ));
    }
}
