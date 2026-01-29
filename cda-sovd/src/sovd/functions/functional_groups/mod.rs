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

use std::sync::Arc;

use aide::{
    axum::{ApiRouter as Router, routing},
    transform::TransformOperation,
};
use axum::{
    Json,
    extract::{Path, Query, State},
    response::{IntoResponse, Response},
};
use axum_extra::extract::WithRejection;
use cda_interfaces::{
    FunctionalDescriptionConfig, HashMap, UdsEcu, diagservices::DiagServiceResponse,
};
use http::StatusCode;

use crate::{
    create_schema,
    sovd::{
        WebserverState,
        error::{ApiError, ErrorWrapper, VendorErrorCode},
        locks::Locks,
    },
};

pub(crate) mod data;
pub(crate) mod locks;
pub(crate) mod modes;
pub(crate) mod operations;

#[derive(Clone)]
pub(crate) struct WebserverFgState<T: UdsEcu + Clone> {
    uds: T,
    locks: Arc<Locks>,
    functional_group_name: String,
}

pub(crate) async fn create_functional_group_routes<T: UdsEcu + Clone>(
    state: WebserverState<T>,
    functional_group_config: FunctionalDescriptionConfig,
) -> Router {
    let functions_router = Router::new().api_route(
        "/",
        routing::get_with(functions_description, docs_functions),
    );

    if !state
        .uds
        .get_ecus()
        .await
        .iter()
        .any(|ecu| ecu.eq_ignore_ascii_case(&functional_group_config.description_database))
    {
        return create_error_fallback_route(
            functions_router,
            format!(
                "Functional Description Database '{}' is missing from loaded databases.",
                functional_group_config.description_database
            ),
        );
    }

    let groups = match state
        .uds
        .ecu_functional_groups(&functional_group_config.description_database)
        .await
    {
        Ok(groups) => groups,
        Err(e) => {
            return create_error_fallback_route(
                functions_router,
                format!(
                    "Failed to get functional groups from functional description database: {e}"
                ),
            );
        }
    };

    // Filter groups based on config if enabled_functional_groups is set
    let filtered_groups =
        if let Some(enabled_groups) = &functional_group_config.enabled_functional_groups {
            groups
                .into_iter()
                .filter(|group| enabled_groups.contains(group))
                .collect::<Vec<_>>()
        } else {
            groups
        };

    if filtered_groups.is_empty() {
        if let Some(filter) = functional_group_config.enabled_functional_groups {
            return create_error_fallback_route(
                functions_router,
                format!(
                    "No functional groups found in functional description database with given \
                     filter: [{filter:?}]",
                ),
            );
        }
        return create_error_fallback_route(
            functions_router,
            "No functional groups found in the functional description database".to_owned(),
        );
    }

    let groups_resource = filtered_groups.clone();
    let mut functional_groups_router: Router = functions_router.api_route(
        "/functionalgroups",
        routing::get_with(
            |WithRejection(Query(query), _): WithRejection<
                Query<sovd_interfaces::IncludeSchemaQuery>,
                ApiError,
            >| async move {
                functional_groups_description(query.include_schema, groups_resource)
            },
            docs_functionalgroups,
        ),
    );
    for group in filtered_groups {
        let fg_state = WebserverFgState {
            uds: state.uds.clone(),
            locks: Arc::clone(&state.locks),
            functional_group_name: group.clone(),
        };
        functional_groups_router = functional_groups_router.nest_api_service(
            &format!("/functionalgroups/{group}"),
            create_functional_group_route(fg_state),
        );
    }
    functional_groups_router
}

fn create_functional_group_route<T: UdsEcu + Clone>(fg_state: WebserverFgState<T>) -> Router {
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
        .api_route(
            "/data/{diag_service}",
            routing::get_with(data::diag_service::get, data::diag_service::docs_get)
                .put_with(data::diag_service::put, data::diag_service::docs_put),
        )
        .api_route(
            "/operations/{operation}",
            routing::post_with(
                operations::diag_service::post,
                operations::diag_service::docs_post,
            ),
        )
        .api_route("/modes", routing::get_with(modes::get, modes::docs_get))
        .api_route(
            &format!("/modes/{}", modes::COMM_CONTROL_ID),
            routing::put_with(modes::commctrl::put, modes::commctrl::docs_put),
        )
        .with_state(fg_state)
}

fn create_error_fallback_route(router: Router, reason: String) -> Router {
    router.api_route(
        "/functionalgroups/{*subpath}",
        routing::get(|| async move {
            let error = ApiError::InternalServerError(Some(reason));
            ErrorWrapper {
                error,
                include_schema: false,
            }
            .into_response()
        }),
    )
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
    State(WebserverFgState {
        functional_group_name,
        ..
    }): State<WebserverFgState<T>>,
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
            // Extract data from the response into JSON format
            match response.into_json() {
                Ok(json_response) => {
                    if let serde_json::Value::Object(data_map) = json_response.data {
                        response_data.insert(ecu_name, data_map);
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
        }
        Err(e) => {
            // Add error with JSON pointer to the ECU entry
            let api_error: ApiError = e.into();
            let (error_code, vendor_code) = api_error.error_and_vendor_code();
            errors.push(sovd_interfaces::error::DataError {
                path: format!("/data/{ecu_name}"),
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
