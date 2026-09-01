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

use aide::{
    axum::{ApiRouter as Router, routing},
    transform::TransformOperation,
};
use axum::{
    Json,
    extract::{FromRequestParts, Path, Query},
    response::{IntoResponse, Response},
};
use axum_extra::extract::WithRejection;
use cda_interfaces::{
    HashMap, SchemaProvider, UdsEcu,
    communication_control::{CommunicationAccess, CommunicationGuard},
    diagservices::{DiagServiceResponse, DiagServiceResponseType},
};
use http::{StatusCode, Uri};
use indexmap::IndexMap;
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

use crate::{
    create_schema,
    sovd::{
        FgServiceExecution, ResolvedLocks, WebserverState,
        error::{
            ApiError, ErrorWrapper, VendorErrorCode, not_found_response, nrc_to_api_error_response,
        },
        field_parse_errors_to_json,
    },
};

pub(crate) mod data;
pub(crate) mod locks;
pub(crate) mod modes;
pub(crate) mod operations;

#[derive(Clone)]
pub(crate) struct WebserverFgState<T: UdsEcu + Clone> {
    uds: T,
    locks: ResolvedLocks,
    lock_provider: Arc<crate::sovd::SovdLockStateView>,
    functional_group_name: String,
    fg_executions: Arc<RwLock<HashMap<String, IndexMap<Uuid, FgServiceExecution>>>>,
    communication_activities: Arc<tokio::sync::Mutex<HashMap<Uuid, CommunicationGuard>>>,
    communication_access: Arc<dyn CommunicationAccess>,
}

/// Per-group execution state retained while the same database stays live.
#[derive(Default)]
pub(crate) struct FgRegistryEntry {
    fg_executions: Arc<RwLock<HashMap<String, IndexMap<Uuid, FgServiceExecution>>>>,
    communication_activities: Arc<Mutex<HashMap<Uuid, CommunicationGuard>>>,
}

/// Extracts live per-functional-group state for the templated group route.
pub(crate) struct FgContext<T: UdsEcu + Clone>(pub(crate) WebserverFgState<T>);

#[derive(serde::Deserialize)]
struct FunctionalGroupIdParam {
    functional_group_id: String,
}

/// Rejection returned when `functional_group_id` names no currently
/// effective group. Mirrors [`crate::sovd::error::sovd_not_found_handler`].
pub(crate) enum FgContextRejection {
    NotFound(Uri),
}

impl IntoResponse for FgContextRejection {
    fn into_response(self) -> Response {
        match self {
            Self::NotFound(uri) => not_found_response(&uri),
        }
    }
}

// No-op body: `functional_group_id` is an artifact of routing, not part of the
// documented operation, which emits one concrete path per group.
impl<T: UdsEcu + Clone> aide::OperationInput for FgContext<T> {}

impl<T: UdsEcu + Clone> FromRequestParts<WebserverState<T>> for FgContext<T> {
    type Rejection = FgContextRejection;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        state: &WebserverState<T>,
    ) -> Result<Self, Self::Rejection> {
        let request_uri = parts
            .extensions
            .get::<axum::extract::OriginalUri>()
            .map_or_else(|| parts.uri.clone(), |uri| uri.0.clone());
        // A named field, not `Path<String>`: nesting composes path params from every
        // nest boundary a request crosses, so more than one may be in scope.
        let Path(FunctionalGroupIdParam {
            functional_group_id,
        }) = Path::<FunctionalGroupIdParam>::from_request_parts(parts, state)
            .await
            .map_err(|_| FgContextRejection::NotFound(request_uri.clone()))?;
        let route_name = functional_group_id.to_lowercase();
        let locks = state.lock_provider.current_locks().await;
        let Some((functional_group_name, entry)) =
            state.registry.resolve_functional_group(&route_name)
        else {
            return Err(FgContextRejection::NotFound(request_uri));
        };
        Ok(FgContext(WebserverFgState {
            uds: state.uds.clone(),
            locks,
            lock_provider: Arc::clone(&state.lock_provider),
            functional_group_name,
            fg_executions: Arc::clone(&entry.fg_executions),
            communication_activities: Arc::clone(&entry.communication_activities),
            communication_access: Arc::clone(&state.communication_access),
        }))
    }
}

/// The templated route is nested unconditionally; [`FgContext`] validates an ID
/// against the live normalized index. An empty index therefore makes every
/// instance ID unavailable while retaining the collection endpoint.
pub(crate) fn create_functional_group_routes<T: UdsEcu + SchemaProvider + Clone>(
    state: WebserverState<T>,
) -> Router {
    let functions_router = Router::new().api_route(
        "/",
        routing::get_with(functions_description, docs_functions),
    );

    let registry = state.registry.clone();
    // Registered unconditionally: an empty effective list yields an empty listing
    // rather than an absent route.
    let functional_groups_router: Router = functions_router.api_route(
        "/functionalgroups",
        routing::get_with(
            move |WithRejection(Query(query), _): WithRejection<
                Query<sovd_interfaces::IncludeSchemaQuery>,
                ApiError,
            >| {
                let registry = registry.clone();
                async move {
                    let live = registry.live();
                    let groups = live
                        .functional_groups
                        .values()
                        .map(|group| group.database_name.clone())
                        .collect();
                    functional_groups_description(query.include_schema, groups)
                }
            },
            docs_functionalgroups,
        ),
    );
    functional_groups_router.nest_api_service(
        "/functionalgroups/{functional_group_id}",
        create_functional_group_route::<T>(state),
    )
}

/// [`FgContext`] resolves `{functional_group_id}` per request, so this route
/// table is identical for every group and is built once. `nest_api_service`
/// requires a fully resolved router, so `state` is applied here.
fn create_functional_group_route<T: UdsEcu + SchemaProvider + Clone>(
    state: WebserverState<T>,
) -> Router {
    Router::new()
        .api_route(
            "/",
            routing::get_with(functional_group_description, docs_functional_group),
        )
        .api_route(
            "/locks",
            routing::post_with(locks::post, locks::docs_post).get_with(locks::get, locks::docs_get),
        )
        .api_route(
            "/locks/{lock}",
            routing::get_with(locks::lock::get, locks::lock::docs_get)
                .put_with(locks::lock::put, locks::lock::docs_put)
                .delete_with(locks::lock::delete, locks::lock::docs_delete),
        )
        .api_route("/data", routing::get_with(data::get, data::docs_get))
        .api_route(
            "/data/{service}",
            routing::get_with(data::diag_service::get, data::diag_service::docs_get)
                .put_with(data::diag_service::put, data::diag_service::docs_put),
        )
        .api_route(
            "/operations",
            routing::get_with(operations::get, operations::docs_get),
        )
        .api_route(
            "/operations/{service}/docs",
            routing::get_with(
                operations::docs_endpoint::get,
                operations::docs_endpoint::docs_transform,
            ),
        )
        .api_route(
            "/operations/{service}/executions",
            routing::get_with(
                operations::diag_service::executions::get,
                operations::diag_service::executions::docs_get,
            )
            .post_with(
                operations::diag_service::post,
                operations::diag_service::docs_post,
            ),
        )
        .api_route(
            "/operations/{operation}/executions/{id}",
            routing::get_with(
                operations::diag_service::id::get,
                operations::diag_service::id::docs_get,
            )
            .delete_with(
                operations::diag_service::delete,
                operations::diag_service::docs_delete,
            ),
        )
        .api_route("/modes", routing::get_with(modes::get, modes::docs_get))
        .api_route(
            &format!("/modes/{}", sovd_interfaces::common::modes::COMM_CONTROL_ID),
            routing::get_with(modes::commctrl::get, modes::commctrl::docs_get)
                .put_with(modes::commctrl::put, modes::commctrl::docs_put),
        )
        .api_route(
            &format!("/modes/{}", sovd_interfaces::common::modes::DTC_SETTING_ID),
            routing::get_with(modes::dtcsetting::get, modes::dtcsetting::docs_get)
                .put_with(modes::dtcsetting::put, modes::dtcsetting::docs_put),
        )
        .api_route(
            &format!("/modes/{}", sovd_interfaces::common::modes::SESSION_ID),
            routing::get_with(modes::session::get, modes::session::docs_get)
                .put_with(modes::session::put, modes::session::docs_put),
        )
        .with_state(state)
}

async fn functions_description(
    WithRejection(Query(query), _): WithRejection<
        Query<sovd_interfaces::IncludeSchemaQuery>,
        ApiError,
    >,
) -> Response {
    let schema = if query.include_schema {
        Some(crate::sovd::create_schema!(
            sovd_interfaces::ResourceResponse
        ))
    } else {
        None
    };
    (
        StatusCode::OK,
        Json(sovd_interfaces::ResourceResponse {
            items: vec![sovd_interfaces::Resource {
                href: "http://localhost:20002/vehicle/v15/functions/functionalgroups".to_owned(),
                id: None,
                name: "functionalgroups".to_owned(),
            }],
            schema,
        }),
    )
        .into_response()
}

fn docs_functions(op: TransformOperation) -> TransformOperation {
    op.description("Get a list of available subresources in the functions collection")
}

fn functional_groups_description(include_schema: bool, functional_groups: Vec<String>) -> Response {
    let schema = if include_schema {
        Some(crate::sovd::create_schema!(
            sovd_interfaces::ResourceResponse
        ))
    } else {
        None
    };
    (
        StatusCode::OK,
        Json(sovd_interfaces::ResourceResponse {
            items: functional_groups
                .into_iter()
                .map(|group| sovd_interfaces::Resource {
                    href: format!(
                        "http://localhost:20002/vehicle/v15/functions/functionalgroups/{group}"
                    ),
                    id: Some(group.to_lowercase()),
                    name: group,
                })
                .collect::<Vec<_>>(),
            schema,
        }),
    )
        .into_response()
}

fn docs_functionalgroups(op: TransformOperation) -> TransformOperation {
    op.description("Get a list of available functional groups with their paths")
        .response_with::<200, Json<sovd_interfaces::ResourceResponse>, _>(|res| {
            res.example(sovd_interfaces::ResourceResponse {
                items: vec![sovd_interfaces::Resource {
                    href: "http://localhost:20002/vehicle/v15/functions/functionalgroups/group_a"
                        .into(),
                    id: Some("group_a".into()),
                    name: "Group_A".into(),
                }],
                schema: None,
            })
        })
}

async fn functional_group_description<T: UdsEcu + Clone>(
    FgContext(WebserverFgState {
        functional_group_name,
        ..
    }): FgContext<T>,
    WithRejection(Query(query), _): WithRejection<
        Query<sovd_interfaces::IncludeSchemaQuery>,
        ApiError,
    >,
) -> Response {
    let base_path = format!(
        "http://localhost:20002/vehicle/v15/functions/functionalgroups/{functional_group_name}"
    );
    let schema = if query.include_schema {
        Some(create_schema!(
            sovd_interfaces::functions::functional_groups::get::Response
        ))
    } else {
        None
    };

    (
        StatusCode::OK,
        Json(
            sovd_interfaces::functions::functional_groups::get::Response {
                id: functional_group_name.to_lowercase(),
                locks: format!("{base_path}/locks"),
                operations: format!("{base_path}/operations"),
                data: format!("{base_path}/data"),
                modes: format!("{base_path}/modes"),
                schema,
            },
        ),
    )
        .into_response()
}

fn docs_functional_group(op: TransformOperation) -> TransformOperation {
    op.description("Get functional group details")
        .response_with::<
            200,
            Json<sovd_interfaces::functions::functional_groups::FunctionalGroup
            >, _>(|res| {
            res.example(sovd_interfaces::functions::functional_groups::FunctionalGroup {
                id: "group_a".into(),
                locks:
                "http://localhost:20002/vehicle/v15/functions/functionalgroups/group_a/locks"
                    .into(),
                operations:
                "http://localhost:20002/vehicle/v15/functions/\
                        functionalgroups/group_a/operations".into(),
                data:
                "http://localhost:20002/vehicle/v15/functions/functionalgroups/group_a/data"
                    .into(),
                modes:
                "http://localhost:20002/vehicle/v15/functions/functionalgroups/group_a/modes"
                    .into(),
                schema: None,
            })
        })
}

fn handle_ecu_response<R: DiagServiceResponse>(
    response_data: &mut HashMap<String, serde_json::Map<String, serde_json::Value>>,
    data_tag: &str,
    errors: &mut Vec<sovd_interfaces::error::DataError<VendorErrorCode>>,
    ecu_name: String,
    result: Result<R, cda_interfaces::DiagServiceError>,
) {
    match result {
        Ok(response) => {
            if response.response_type() == DiagServiceResponseType::Positive {
                // Extract data from the response into JSON format
                match response.into_json() {
                    Ok(json_response) => {
                        if let serde_json::Value::Object(data_map) = json_response.data {
                            response_data.insert(ecu_name, data_map);
                        }
                        if !json_response.errors.is_empty() {
                            let mut parse_errors =
                                field_parse_errors_to_json(json_response.errors, data_tag);
                            errors.append(&mut parse_errors);
                        }
                    }
                    Err(e) => {
                        // Add error for JSON conversion failure
                        errors.push(sovd_interfaces::error::DataError {
                            path: format!("/{data_tag}/{ecu_name}"),
                            error: sovd_interfaces::error::ApiErrorResponse {
                                message: format!("Failed to convert response to JSON: {e}"),
                                error_code: sovd_interfaces::error::ErrorCode::VendorSpecific,
                                vendor_code: Some(VendorErrorCode::ErrorInterpretingMessage),
                                parameters: None,
                                // todo: x-ecu-name: Some(ecu_name)
                                error_source: Some("ecu".to_owned()),
                                schema: None,
                            },
                        });
                    }
                }
            } else {
                // Map negative response to API error and add to errors list
                match response.as_nrc() {
                    Ok(nrc) => {
                        errors.push(sovd_interfaces::error::DataError {
                            path: format!("/{data_tag}/{ecu_name}"),
                            error: nrc_to_api_error_response(nrc, false),
                        });
                    }
                    Err(_) => {
                        errors.push(sovd_interfaces::error::DataError {
                            path: format!("/{data_tag}/{ecu_name}"),
                            error: sovd_interfaces::error::ApiErrorResponse {
                                message: "Failed to interpret negative response".to_owned(),
                                error_code: sovd_interfaces::error::ErrorCode::VendorSpecific,
                                vendor_code: Some(VendorErrorCode::ErrorInterpretingMessage),
                                parameters: None,
                                error_source: Some("ecu".to_owned()),
                                schema: None,
                            },
                        });
                    }
                }
            }
        }
        Err(e) => {
            // Add error with JSON pointer to the ECU entry
            let api_error: ApiError = e.into();
            let (error_code, vendor_code) = api_error.error_and_vendor_code();
            errors.push(sovd_interfaces::error::DataError {
                path: format!("/{data_tag}/{ecu_name}"),
                error: sovd_interfaces::error::ApiErrorResponse {
                    message: api_error.to_string(),
                    error_code,
                    vendor_code,
                    parameters: None,
                    error_source: Some("ecu".to_owned()),
                    schema: None,
                },
            });
        }
    }
}

fn map_to_json(include_schema: bool, accept: &mime::Mime) -> Result<bool, ErrorWrapper> {
    Ok(match (accept.type_(), accept.subtype()) {
        (mime::APPLICATION, mime::JSON) => true,
        (mime::APPLICATION, mime::OCTET_STREAM) => {
            return Err(ErrorWrapper {
                error: ApiError::BadRequest(
                    "application/octet-stream not supported for functional communication responses"
                        .to_string(),
                ),
                include_schema,
            });
        }
        unsupported => {
            return Err(ErrorWrapper {
                error: ApiError::BadRequest(format!("Unsupported Accept: {unsupported:?}")),
                include_schema,
            });
        }
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;

    use cda_interfaces::UdsEcu;
    use cda_plugin_communication_management::lifecycle::enabled_communication_access_for_test;
    use tokio::sync::RwLock;
    use uuid::Uuid;

    use super::WebserverFgState;
    use crate::sovd::{
        FgServiceExecution, HashMap, ResolvedLocks, SovdRegistry,
        locks::{LockType, Locks},
    };

    #[tokio::test]
    async fn functional_group_execution_survives_only_continuous_identity() {
        let registry = SovdRegistry::default();
        let group_names = || {
            [("group".to_owned(), "Group".to_owned())]
                .into_iter()
                .collect()
        };
        registry.apply(HashMap::default(), group_names());
        let state = registry.functional_group("group").unwrap();
        let execution_id = Uuid::new_v4();
        state.fg_executions.write().await.insert(
            "routine".to_owned(),
            [(
                execution_id,
                FgServiceExecution {
                    parameters: HashMap::default(),
                    status:
                        sovd_interfaces::components::ecu::operations::ExecutionStatus::Completed,
                    in_flight: false,
                    is_created: true,
                },
            )]
            .into_iter()
            .collect(),
        );

        registry.apply(HashMap::default(), group_names());
        assert!(
            registry
                .functional_group("group")
                .unwrap()
                .fg_executions
                .read()
                .await
                .get("routine")
                .is_some_and(|executions| executions.contains_key(&execution_id))
        );

        registry.apply(HashMap::default(), HashMap::default());
        assert!(registry.functional_group("group").is_none());
        registry.apply(HashMap::default(), group_names());
        let readded = registry.functional_group("group").unwrap();
        assert!(!Arc::ptr_eq(&state, &readded));
        assert!(
            registry
                .functional_group("group")
                .unwrap()
                .fg_executions
                .read()
                .await
                .is_empty()
        );
    }

    pub fn create_test_fg_state<T: UdsEcu + Clone>(
        uds: T,
        functional_group_name: String,
    ) -> WebserverFgState<T> {
        WebserverFgState {
            uds,
            locks: ResolvedLocks::untracked(Arc::new(Locks {
                vehicle: LockType::Vehicle(Arc::new(RwLock::new(None))),
                ecu: LockType::Ecu(Arc::new(RwLock::new(HashMap::default()))),
                functional_group: LockType::FunctionalGroup(Arc::new(RwLock::new(
                    HashMap::default(),
                ))),
            })),
            lock_provider: Arc::new(crate::sovd::SovdLockStateProvider::new(Vec::new()).view()),
            functional_group_name,
            fg_executions: Arc::new(RwLock::new(HashMap::default())),
            communication_activities: Arc::new(tokio::sync::Mutex::new(HashMap::default())),
            communication_access: enabled_communication_access_for_test(),
        }
    }
}
