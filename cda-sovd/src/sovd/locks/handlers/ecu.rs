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

use aide::{UseApi, axum::IntoApiResponse, transform::TransformOperation};
use axum::{
    Json,
    extract::{OriginalUri, Path, Query},
    response::{IntoResponse, Response},
};
use axum_extra::extract::WithRejection;
use cda_interfaces::{UdsEcu, lock_priority_api::LockScope};
use cda_plugin_security::{Claims, Secured};

use super::super::{
    ActiveLock, ApiError, ErrorWrapper, LockContext, LockCoverage, LockPathParam,
    LockUpdateContext, ScopeKey, delete_handler, get_handler, get_id_handler, post_handler,
    put_handler, rollback_preemption, validate_vehicle_owner,
};
use crate::{
    openapi,
    sovd::{self, EcuContext, WebserverEcuState},
};

pub(crate) mod lock {
    use super::{
        ApiError, EcuContext, Json, LockPathParam, LockScope, LockUpdateContext, Path, Query,
        Response, Secured, TransformOperation, UdsEcu, UseApi, WebserverEcuState, WithRejection,
        delete_handler, get_id_handler, put_handler,
    };
    use crate::openapi;
    pub(crate) async fn delete<T: UdsEcu + Clone>(
        Path(lock): Path<LockPathParam>,
        UseApi(sec_plugin, _): UseApi<Secured, ()>,
        EcuContext(WebserverEcuState {
            ecu_name, locks, ..
        }): EcuContext<T>,
        Query(query): Query<sovd_interfaces::IncludeSchemaQuery>,
    ) -> Response {
        let claims = sec_plugin.as_auth_plugin().claims();

        delete_handler(
            &locks,
            LockScope::Ecu {
                name: ecu_name.clone(),
            },
            &lock,
            &claims,
            query.include_schema,
        )
        .await
    }

    pub(crate) fn docs_delete(op: TransformOperation) -> TransformOperation {
        op.description("Delete a specific lock.")
            .response_with::<204, (), _>(|res| res.description("Lock deleted successfully."))
            .with(openapi::lock_not_found)
            .with(openapi::lock_not_owned)
    }

    pub(crate) async fn put<T: UdsEcu + Clone>(
        Path(lock): Path<LockPathParam>,
        UseApi(sec_plugin, _): UseApi<Secured, ()>,
        EcuContext(WebserverEcuState {
            ecu_name, locks, ..
        }): EcuContext<T>,
        Query(query): Query<sovd_interfaces::IncludeSchemaQuery>,
        WithRejection(Json(body), _): WithRejection<
            Json<sovd_interfaces::locking::UpdateRequest>,
            ApiError,
        >,
    ) -> Response {
        let claims = sec_plugin.as_auth_plugin().claims();
        put_handler(
            LockUpdateContext {
                all_locks: &locks,
                scope: LockScope::Ecu {
                    name: ecu_name.clone(),
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
        op.description("Extend a specific lock's expiration.")
            .response_with::<204, (), _>(|res| res.description("Lock updated successfully."))
            .with(openapi::lock_not_found)
            .with(openapi::lock_not_owned)
    }

    pub(crate) async fn get<T: UdsEcu + Clone>(
        Path(lock): Path<LockPathParam>,
        UseApi(sec_plugin, _): UseApi<Secured, ()>,
        EcuContext(WebserverEcuState {
            ecu_name, locks, ..
        }): EcuContext<T>,
        Query(query): Query<sovd_interfaces::IncludeSchemaQuery>,
    ) -> Response {
        let claims = sec_plugin.as_auth_plugin().claims();
        get_id_handler(
            &locks,
            LockScope::Ecu {
                name: ecu_name.clone(),
            },
            &lock,
            &claims,
            query.include_schema,
        )
        .await
    }

    pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
        op.description("Get a specific lock.")
            .response_with::<200, Json<sovd_interfaces::locking::id::get::Response>, _>(|res| {
                res.description("Response with the lock details.")
                    .example(openapi::lock_details_example())
            })
            .with(openapi::lock_not_found)
    }
}

pub(crate) async fn post<T: UdsEcu + Clone>(
    UseApi(Secured(sec_plugin), _): UseApi<Secured, ()>,
    EcuContext(WebserverEcuState {
        ecu_name,
        locks,
        uds,
        ..
    }): EcuContext<T>,
    Query(query): Query<sovd_interfaces::IncludeSchemaQuery>,
    OriginalUri(uri): OriginalUri,
    WithRejection(Json(body), _): WithRejection<Json<sovd_interfaces::locking::Request>, ApiError>,
) -> impl IntoApiResponse {
    let claims = sec_plugin.as_auth_plugin().claims();
    let (acquisition, pending, request) = match locks
        .evaluate_acquisition(
            cda_interfaces::lock_priority_api::LockScope::Ecu {
                name: ecu_name.clone(),
            },
            LockCoverage::new([ecu_name.clone()]),
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
    if let Err(error) = validate_vehicle_owner(&locks, &claims).await {
        rollback_preemption(pending, &locks).await;
        acquisition.finish();
        return ErrorWrapper {
            error,
            include_schema: query.include_schema,
        }
        .into_response();
    }

    if functional_lock_blocks_ecu(&locks.open_locks().await, &ecu_name, claims.sub()) {
        rollback_preemption(pending, &locks).await;
        acquisition.finish();
        return ErrorWrapper {
            error: ApiError::Conflict("functional lock prevents setting ecu lock".to_owned()),
            include_schema: query.include_schema,
        }
        .into_response();
    }

    post_handler(
        &uds,
        LockContext {
            all_locks: &locks,
            acquisition,
            pending,
            coverage: LockCoverage::new([ecu_name.clone()]),
        },
        request,
        uri.path(),
        query.include_schema,
        sec_plugin,
    )
    .await
}

fn functional_lock_blocks_ecu(open_locks: &[ActiveLock], ecu_name: &str, subject: &str) -> bool {
    open_locks.iter().any(|lock| {
        matches!(lock.scope, ScopeKey::FunctionalGroup(_))
            && lock.coverage.contains_ecu(ecu_name)
            && lock.principal.subject != subject
    })
}

pub(crate) fn docs_post(op: TransformOperation) -> TransformOperation {
    op.description("Create a lock for an ECU")
            .response_with::<200, Json<sovd_interfaces::locking::post_put::Response>, _>(|res| {
                res.example(openapi::lock_created_example()).description(
                    "Existing caller-owned lock renewed for compatibility. Use PUT on the lock \
                     resource to modify its expiration.",
                )
            })
            .response_with::<201, Json<sovd_interfaces::locking::post_put::Response>, _>(|res| {
                res.example(openapi::lock_created_example())
                .description("Lock created successfully.")
                .with(openapi::lock_created_response)
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

pub(crate) async fn get<T: UdsEcu + Clone>(
    UseApi(sec_plugin, _): UseApi<Secured, ()>,
    EcuContext(WebserverEcuState {
        ecu_name, locks, ..
    }): EcuContext<T>,
    Query(query): Query<sovd_interfaces::IncludeSchemaQuery>,
) -> Response {
    let claims = sec_plugin.as_auth_plugin().claims();
    get_handler(
        &locks,
        LockScope::Ecu {
            name: ecu_name.clone(),
        },
        &claims,
        query.include_schema,
    )
    .await
}

pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
    op.description("Get all locks")
        .response_with::<200, Json<sovd_interfaces::locking::get::Response>, _>(|res| {
            res.example(openapi::lock_list_example())
                .description("List of ECU locks.")
        })
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use cda_interfaces::lock_priority_api::LockPrincipal;

    use super::*;

    fn functional_lock(subject: &str) -> ActiveLock {
        ActiveLock {
            id: "functional-lock".into(),
            scope: ScopeKey::FunctionalGroup("powertrain".to_owned()),
            coverage: LockCoverage::new(["engine".to_owned()]),
            principal: LockPrincipal {
                subject: subject.to_owned(),
                claims: serde_json::Map::new(),
            },
            metadata: serde_json::Map::new(),
            exclusive: true,
            expires_at: SystemTime::now(),
            parent_vehicle_lock_id: None,
        }
    }

    #[test]
    fn owned_functional_lock_does_not_block_ecu_lock() {
        assert!(!functional_lock_blocks_ecu(
            &[functional_lock("owner")],
            "ENGINE",
            "owner"
        ));
    }

    #[test]
    fn foreign_functional_lock_blocks_ecu_lock() {
        assert!(functional_lock_blocks_ecu(
            &[functional_lock("other")],
            "ENGINE",
            "owner"
        ));
    }
}
