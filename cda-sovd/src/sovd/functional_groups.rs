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

pub(crate) mod locks {
    use aide::{UseApi, transform::TransformOperation};
    use cda_interfaces::UdsEcu;
    use cda_plugin_security::Secured;

    use super::{
        ApiError, ErrorWrapper, IntoResponse, Json, Path, Response, State, WebserverFgState,
        WithRejection,
    };
    use crate::{
        openapi,
        sovd::locks::{
            LockContext, LockPathParam, LockType, delete_handler, delete_lock, get_handler,
            get_id_handler, post_handler, put_handler, vehicle_read_lock,
        },
    };

    pub(crate) mod lock {
        use cda_interfaces::UdsEcu;

        use super::{
            ApiError, Json, LockPathParam, Path, Response, Secured, State, TransformOperation,
            UseApi, WebserverFgState, WithRejection, delete_handler, get_id_handler, openapi,
            put_handler,
        };

        pub(crate) async fn delete<T: UdsEcu + Clone>(
            Path(LockPathParam { lock }): Path<LockPathParam>,
            State(state): State<WebserverFgState<T>>,
            UseApi(sec_plugin, _): UseApi<Secured, ()>,
        ) -> Response {
            let claims = sec_plugin.as_auth_plugin().claims();
            delete_handler(
                &state.locks.functional_group,
                &lock,
                &claims,
                Some(&state.functional_group_name),
                false,
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
            WithRejection(Json(body), _): WithRejection<
                Json<sovd_interfaces::locking::Request>,
                ApiError,
            >,
        ) -> Response {
            let claims = sec_plugin.as_auth_plugin().claims();
            put_handler(
                &state.locks.functional_group,
                &lock,
                &claims,
                Some(&state.functional_group_name),
                body,
                false,
            )
            .await
        }

        pub(crate) fn docs_put(op: TransformOperation) -> TransformOperation {
            op.description("Update a functional group lock")
                .response_with::<204, (), _>(|res| res.description("Lock updated successfully."))
                .with(openapi::lock_not_found)
                .with(openapi::lock_not_owned)
        }

        pub(crate) async fn get<T: UdsEcu + Clone>(
            Path(LockPathParam { lock }): Path<LockPathParam>,
            UseApi(_sec_plugin, _): UseApi<Secured, ()>,
            State(state): State<WebserverFgState<T>>,
        ) -> Response {
            get_id_handler(
                &state.locks.functional_group,
                &lock,
                Some(&state.functional_group_name),
                false,
            )
            .await
        }

        pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
            op.description("Get a specific functional group lock")
                .response_with::<200, Json<sovd_interfaces::locking::id::get::Response>, _>(|res| {
                    res.description("Response with the lock details.").example(
                        sovd_interfaces::locking::id::get::Response {
                            lock_expiration: "2025-01-01T00:00:00Z".to_string(),
                        },
                    )
                })
                .with(openapi::lock_not_found)
                .with(openapi::lock_not_owned)
        }
    }

    pub(crate) async fn post<T: UdsEcu + Clone>(
        UseApi(Secured(sec_plugin), _): UseApi<Secured, ()>,
        State(state): State<WebserverFgState<T>>,
        WithRejection(Json(body), _): WithRejection<
            Json<sovd_interfaces::locking::Request>,
            ApiError,
        >,
    ) -> Response {
        let claims = sec_plugin.as_ref().as_auth_plugin().claims();
        let vehicle_ro_lock = vehicle_read_lock(&state.locks, &claims).await;
        if let Err(e) = vehicle_ro_lock {
            return ErrorWrapper {
                error: e,
                include_schema: false,
            }
            .into_response();
        }

        match &state.locks.ecu {
            LockType::Ecu(eculocks) => {
                let mut functionalgroup_ecus = Vec::new();
                for (ecu, lock_info) in eculocks.read().await.iter() {
                    let ecu_functional_groups = match state
                        .uds
                        .ecu_functional_groups(ecu)
                        .await
                        .map_err(ApiError::from)
                    {
                        Ok(groups) => groups,
                        Err(e) => {
                            return ErrorWrapper {
                                error: e,
                                include_schema: false,
                            }
                            .into_response();
                        }
                    };
                    if !ecu_functional_groups.contains(&state.functional_group_name) {
                        continue;
                    }
                    if let Some(lock_info) = lock_info {
                        if !lock_info.is_owned_by(claims.sub()) {
                            return ErrorWrapper {
                                error: ApiError::Conflict(format!(
                                    "ECU {ecu} is locked by different user. This prevents setting \
                                     functional group lock"
                                )),
                                include_schema: false,
                            }
                            .into_response();
                        }
                        functionalgroup_ecus.push((ecu.clone(), lock_info.id().to_owned()));
                    }
                }
                for (ecu, id) in functionalgroup_ecus {
                    if let Err(e) = delete_lock(&state.locks.ecu, &id, &claims, Some(&ecu)).await {
                        return ErrorWrapper {
                            error: e,
                            include_schema: false,
                        }
                        .into_response();
                    }
                }
            }
            _ => unreachable!(),
        }

        post_handler(
            &state.uds,
            LockContext {
                lock: &state.locks.functional_group,
                all_locks: &state.locks,
                rw_lock: None,
            },
            Some(&state.functional_group_name),
            body,
            false,
            sec_plugin,
        )
        .await
    }

    pub(crate) fn docs_post(op: TransformOperation) -> TransformOperation {
        op.description("Create a functional group lock")
            .response_with::<200, Json<sovd_interfaces::locking::post_put::Response>, _>(|res| {
                res.example(sovd_interfaces::locking::post_put::Response {
                    id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                    owned: Some(true),
                })
                .description("Functional group lock created successfully.")
            })
            .with(openapi::lock_not_owned)
    }

    pub(crate) async fn get<T: UdsEcu + Clone>(
        UseApi(sec_plugin, _): UseApi<Secured, ()>,
        State(state): State<WebserverFgState<T>>,
    ) -> Response {
        let claims = sec_plugin.as_auth_plugin().claims();
        get_handler(
            &state.locks.functional_group,
            &claims,
            Some(&state.functional_group_name),
        )
        .await
    }

    pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
        op.description("Get all functional group locks")
            .response_with::<200, Json<sovd_interfaces::locking::get::Response>, _>(|res| {
                res.example(sovd_interfaces::locking::get::Response {
                    items: vec![sovd_interfaces::locking::Lock {
                        id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                        owned: Some(true),
                    }],
                    schema: None,
                })
                .description("List of functional group locks.")
            })
    }
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

pub(crate) mod data {
    pub(crate) mod diag_service {
        use aide::{UseApi, transform::TransformOperation};
        use axum::{
            Json,
            body::Bytes,
            extract::{Path, Query, State},
            http::{HeaderMap, StatusCode},
            response::{IntoResponse, Response},
        };
        use axum_extra::extract::WithRejection;
        use cda_interfaces::{DiagComm, DiagCommType, HashMap, UdsEcu};
        use cda_plugin_security::Secured;

        use crate::{
            openapi,
            sovd::{
                components::{ecu::DiagServicePathParam, get_content_type_and_accept},
                error::{ApiError, ErrorWrapper, VendorErrorCode},
                functional_groups::{WebserverFgState, handle_ecu_response, map_to_json},
                get_payload_data,
            },
        };

        pub(crate) async fn get<T: UdsEcu + Clone>(
            headers: HeaderMap,
            UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
            Path(DiagServicePathParam { diag_service }): Path<DiagServicePathParam>,
            WithRejection(Query(query), _): WithRejection<
                Query<sovd_interfaces::functions::functional_groups::data::service::Query>,
                ApiError,
            >,
            State(WebserverFgState {
                uds,
                functional_group_name,
                ..
            }): State<WebserverFgState<T>>,
        ) -> Response {
            let include_schema = query.include_schema;
            if diag_service.contains('/') {
                return ErrorWrapper {
                    error: ApiError::BadRequest("Invalid path".to_owned()),
                    include_schema,
                }
                .into_response();
            }

            functional_data_request(
                DiagComm {
                    name: diag_service,
                    type_: DiagCommType::Data,
                    lookup_name: None,
                },
                &functional_group_name,
                &uds,
                headers,
                None,
                security_plugin,
                include_schema,
            )
            .await
        }

        pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
            op.description(
                "Get data from a functional group service - returns data for all ECUs in the group",
            )
            .response_with::<200, Json<
                sovd_interfaces::functions::functional_groups::data::service::Response<
                    VendorErrorCode,
                >,
            >, _>(|res| {
                res.description(
                    "Response with data from all ECUs in the functional group, keyed by ECU name",
                )
                .example(
                    sovd_interfaces::functions::functional_groups::data::service::Response {
                        data: {
                            let mut map = HashMap::default();
                            let mut ecu1_data = serde_json::Map::new();
                            ecu1_data.insert("temperature".to_string(), serde_json::json!(25.5));
                            map.insert("ECU1".to_string(), ecu1_data);
                            map
                        },
                        errors: vec![],
                        schema: None,
                    },
                )
            })
            .with(openapi::error_forbidden)
            .with(openapi::error_not_found)
            .with(openapi::error_internal_server)
            .with(openapi::error_bad_request)
            .with(openapi::error_bad_gateway)
        }

        pub(crate) async fn put<T: UdsEcu + Clone>(
            headers: HeaderMap,
            UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
            Path(DiagServicePathParam {
                diag_service: service,
            }): Path<DiagServicePathParam>,
            WithRejection(Query(query), _): WithRejection<
                Query<sovd_interfaces::functions::functional_groups::data::service::Query>,
                ApiError,
            >,
            State(WebserverFgState {
                uds,
                functional_group_name,
                ..
            }): State<WebserverFgState<T>>,
            body: Bytes,
        ) -> Response {
            let include_schema = query.include_schema;
            if service.contains('/') {
                return ErrorWrapper {
                    error: ApiError::BadRequest("Invalid path".to_owned()),
                    include_schema,
                }
                .into_response();
            }

            functional_data_request(
                DiagComm {
                    name: service,
                    type_: DiagCommType::Configurations,
                    lookup_name: None,
                },
                &functional_group_name,
                &uds,
                headers,
                Some(body),
                security_plugin,
                include_schema,
            )
            .await
        }

        pub(crate) fn docs_put(op: TransformOperation) -> TransformOperation {
            openapi::request_json_and_octet::<
                sovd_interfaces::functions::functional_groups::data::DataRequestPayload,
            >(op)
            .description(
                "Update data for a functional group service - sends to all ECUs in the group",
            )
            .response_with::<200, Json<
                sovd_interfaces::functions::functional_groups::data::service::Response<
                    VendorErrorCode,
                >,
            >, _>(|res| {
                res.description("Response with results from all ECUs in the functional group")
            })
            .with(openapi::error_forbidden)
            .with(openapi::error_not_found)
            .with(openapi::error_internal_server)
            .with(openapi::error_bad_request)
            .with(openapi::error_bad_gateway)
        }

        async fn functional_data_request<T: UdsEcu + Clone>(
            service: DiagComm,
            functional_group_name: &str,
            gateway: &T,
            headers: HeaderMap,
            body: Option<Bytes>,
            security_plugin: Box<dyn cda_plugin_security::SecurityPlugin>,
            include_schema: bool,
        ) -> Response {
            let (content_type, accept) = match get_content_type_and_accept(&headers) {
                Ok(v) => v,
                Err(e) => {
                    return ErrorWrapper {
                        error: e,
                        include_schema,
                    }
                    .into_response();
                }
            };

            let data = if let Some(body) = body {
                match get_payload_data::<
                    sovd_interfaces::functions::functional_groups::data::DataRequestPayload,
                >(content_type.as_ref(), &headers, &body)
                {
                    Ok(value) => value,
                    Err(e) => {
                        return ErrorWrapper {
                            error: e,
                            include_schema,
                        }
                        .into_response();
                    }
                }
            } else {
                None
            };

            let map_to_json = match map_to_json(include_schema, &accept) {
                Ok(value) => value,
                Err(e) => return e.into_response(),
            };

            if !map_to_json && include_schema {
                return ErrorWrapper {
                    error: ApiError::BadRequest(
                        "Cannot use include-schema with non-JSON response".to_string(),
                    ),
                    include_schema,
                }
                .into_response();
            }

            // Send functional request to all ECUs in the group
            let results = gateway
                .send_functional_group(
                    functional_group_name,
                    service,
                    &(security_plugin as cda_interfaces::DynamicPlugin),
                    data,
                    map_to_json,
                )
                .await;

            // Build response with per-ECU data and errors
            let mut response_data: HashMap<String, serde_json::Map<String, serde_json::Value>> =
                HashMap::default();
            let mut errors: Vec<sovd_interfaces::error::DataError<VendorErrorCode>> = Vec::new();

            for (ecu_name, result) in results {
                handle_ecu_response(&mut response_data, "data", &mut errors, ecu_name, result);
            }

            let schema = if include_schema {
                Some(crate::sovd::create_schema!(
                    sovd_interfaces::functions::functional_groups::data::service::Response<
                        VendorErrorCode,
                    >
                ))
            } else {
                None
            };

            (
                StatusCode::OK,
                Json(
                    sovd_interfaces::functions::functional_groups::data::service::Response {
                        data: response_data,
                        errors,
                        schema,
                    },
                ),
            )
                .into_response()
        }
    }
}

pub(crate) mod operations {
    pub(crate) mod diag_service {
        use aide::{UseApi, transform::TransformOperation};
        use axum::{
            Json,
            body::Bytes,
            extract::{Path, Query, State},
            http::{HeaderMap, StatusCode},
            response::{IntoResponse, Response},
        };
        use axum_extra::extract::WithRejection;
        use cda_interfaces::{DiagComm, DiagCommType, HashMap, UdsEcu};
        use cda_plugin_security::Secured;

        use super::super::WebserverFgState;
        use crate::{
            openapi,
            sovd::{
                components::{ecu::DiagServicePathParam, get_content_type_and_accept},
                error::{ApiError, ErrorWrapper, VendorErrorCode},
                functional_groups::{handle_ecu_response, map_to_json},
                get_payload_data,
            },
        };

        pub(crate) async fn post<T: UdsEcu + Clone>(
            headers: HeaderMap,
            UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
            Path(DiagServicePathParam {
                diag_service: operation,
            }): Path<DiagServicePathParam>,
            WithRejection(Query(query), _): WithRejection<
                Query<sovd_interfaces::functions::functional_groups::operations::service::Query>,
                ApiError,
            >,
            State(WebserverFgState {
                uds,
                functional_group_name,
                ..
            }): State<WebserverFgState<T>>,
            body: Bytes,
        ) -> Response {
            let include_schema = query.include_schema;
            if operation.contains('/') {
                return ErrorWrapper {
                    error: ApiError::BadRequest("Invalid path".to_owned()),
                    include_schema,
                }
                .into_response();
            }

            functional_operations_request(
                DiagComm {
                    name: operation,
                    type_: DiagCommType::Operations,
                    lookup_name: None,
                },
                &functional_group_name,
                &uds,
                headers,
                body,
                security_plugin,
                include_schema,
            )
            .await
        }

        pub(crate) fn docs_post(op: TransformOperation) -> TransformOperation {
            openapi::request_json_and_octet::<
                sovd_interfaces::functions::functional_groups::operations::service::Request,
            >(op)
            .description(
                "Execute an operation on a functional group - sends to all ECUs in the group",
            )
            .response_with::<200, Json<
                sovd_interfaces::functions::functional_groups::operations::service::Response<
                    VendorErrorCode,
                >,
            >, _>(|res| {
                res.description(
                    "Response with parameters from all ECUs in the functional group, keyed by ECU \
                     name",
                )
                .example(
                    sovd_interfaces::functions::functional_groups::operations::service::Response {
                        parameters: {
                            let mut map = HashMap::default();
                            let mut ecu1_params = serde_json::Map::new();
                            ecu1_params.insert("status".to_string(), serde_json::json!("success"));
                            map.insert("ECU1".to_string(), ecu1_params);
                            map
                        },
                        errors: vec![],
                        schema: None,
                    },
                )
            })
            .with(openapi::error_forbidden)
            .with(openapi::error_not_found)
            .with(openapi::error_internal_server)
            .with(openapi::error_bad_request)
            .with(openapi::error_bad_gateway)
        }

        async fn functional_operations_request<T: UdsEcu + Clone>(
            service: DiagComm,
            functional_group_name: &str,
            gateway: &T,
            headers: HeaderMap,
            body: Bytes,
            security_plugin: Box<dyn cda_plugin_security::SecurityPlugin>,
            include_schema: bool,
        ) -> Response {
            let (content_type, accept) = match get_content_type_and_accept(&headers) {
                Ok(v) => v,
                Err(e) => {
                    return ErrorWrapper {
                        error: e,
                        include_schema,
                    }
                    .into_response();
                }
            };

            let data = match get_payload_data::<
                sovd_interfaces::functions::functional_groups::operations::service::Request,
            >(content_type.as_ref(), &headers, &body)
            {
                Ok(value) => value,
                Err(e) => {
                    return ErrorWrapper {
                        error: e,
                        include_schema,
                    }
                    .into_response();
                }
            };

            let map_to_json = match map_to_json(include_schema, &accept) {
                Ok(value) => value,
                Err(e) => return e.into_response(),
            };

            // Send functional request to all ECUs in the group
            let results = gateway
                .send_functional_group(
                    functional_group_name,
                    service,
                    &(security_plugin as cda_interfaces::DynamicPlugin),
                    data,
                    map_to_json,
                )
                .await;

            // Build response with per-ECU parameters and errors
            let mut response_data: HashMap<String, serde_json::Map<String, serde_json::Value>> =
                HashMap::default();
            let mut errors: Vec<sovd_interfaces::error::DataError<VendorErrorCode>> = Vec::new();

            for (ecu_name, result) in results {
                handle_ecu_response(
                    &mut response_data,
                    "parameters",
                    &mut errors,
                    ecu_name,
                    result,
                );
            }

            let schema = if include_schema {
                Some(crate::sovd::create_schema!(
                    sovd_interfaces::functions::functional_groups::operations::service::Response<
                        VendorErrorCode,
                    >
                ))
            } else {
                None
            };

            (
                StatusCode::OK,
                Json(
                    sovd_interfaces::functions::functional_groups::operations::service::Response {
                        parameters: response_data,
                        errors,
                        schema,
                    },
                ),
            )
                .into_response()
        }
    }
}

pub(crate) mod modes {
    use aide::transform::TransformOperation;
    use axum::{
        Json,
        extract::Query,
        response::{IntoResponse, Response},
    };
    use axum_extra::extract::WithRejection;
    use cda_interfaces::UdsEcu;
    use http::StatusCode;

    use crate::{create_schema, sovd::error::ApiError};
    const COMM_CONTROL_NAME: &str = "Communication control";
    pub(crate) const COMM_CONTROL_ID: &str = "commctrl";

    pub(crate) async fn get(
        WithRejection(Query(query), _): WithRejection<
            Query<sovd_interfaces::functions::functional_groups::modes::Query>,
            ApiError,
        >,
    ) -> Response {
        use sovd_interfaces::functions::functional_groups::modes::get::{Response, ResponseItem};
        let schema = if query.include_schema {
            Some(create_schema!(Response))
        } else {
            None
        };
        (
            StatusCode::OK,
            Json(Response {
                items: vec![ResponseItem {
                    id: COMM_CONTROL_ID.to_owned(),
                    name: Some(COMM_CONTROL_NAME.to_owned()),
                    translation_id: None,
                }],
                schema,
            }),
        )
            .into_response()
    }

    pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
        use sovd_interfaces::functions::functional_groups::modes::get::{Response, ResponseItem};
        op.description("Get the available modes for the ECU")
            .response_with::<200, Json<Response>, _>(|res| {
                res.description("Available modes for the ECU")
                    .example(Response {
                        items: vec![ResponseItem {
                            id: COMM_CONTROL_ID.to_owned(),
                            name: Some(COMM_CONTROL_NAME.to_string()),
                            translation_id: None,
                        }],
                        schema: None,
                    })
            })
    }

    pub(crate) mod commctrl {
        use aide::UseApi;
        use axum::extract::State;
        use cda_interfaces::{HashMap, diagservices::DiagServiceResponse};
        use cda_plugin_security::Secured;
        use sovd_interfaces::{
            error::ErrorCode,
            functions::functional_groups::modes::{
                self as sovd_modes, commctrl::put::ResponseElement,
            },
        };

        use super::{
            ApiError, COMM_CONTROL_ID, IntoResponse, Json, Query, Response, StatusCode,
            TransformOperation, UdsEcu, WithRejection, create_schema,
        };
        use crate::{
            openapi,
            sovd::{
                error::{ErrorWrapper, VendorErrorCode},
                functional_groups::WebserverFgState,
                locks::validate_lock,
            },
        };

        pub(crate) async fn put<T: UdsEcu + Clone>(
            UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
            WithRejection(Query(query), _): WithRejection<Query<sovd_modes::Query>, ApiError>,
            State(WebserverFgState {
                functional_group_name,
                uds,
                locks,
                ..
            }): State<WebserverFgState<T>>,
            WithRejection(Json(request_body), _): WithRejection<
                Json<sovd_modes::commctrl::put::Request>,
                ApiError,
            >,
        ) -> Response {
            let claims = security_plugin.as_auth_plugin().claims();
            let include_schema = query.include_schema;
            if let Some(response) =
                validate_lock(&claims, &functional_group_name, &locks, include_schema).await
            {
                return response;
            }

            let results = match uds
                .set_functional_comm_ctrl(
                    &functional_group_name,
                    &(security_plugin as cda_interfaces::DynamicPlugin),
                    &request_body.value,
                    request_body.parameters,
                )
                .await
            {
                Ok(results) => results,
                Err(e) => {
                    return ErrorWrapper {
                        error: ApiError::from(e),
                        include_schema,
                    }
                    .into_response();
                }
            };

            // Build response with per-ECU data and errors
            let mut response_data: HashMap<String, ResponseElement> = HashMap::default();
            let mut errors: Vec<sovd_interfaces::error::ApiErrorResponse<VendorErrorCode>> =
                Vec::new();
            for (ecu_name, result) in results {
                match result {
                    Ok(response) => {
                        // Extract data from the response into JSON format
                        if response.response_type()
                            == cda_interfaces::diagservices::DiagServiceResponseType::Positive
                        {
                            response_data.insert(
                                ecu_name,
                                ResponseElement {
                                    id: COMM_CONTROL_ID.to_owned(),
                                    value: request_body.value.clone(),
                                    schema: None,
                                },
                            );
                        } else {
                            errors.push(sovd_interfaces::error::ApiErrorResponse {
                                message: "Received negative result from ecu".to_owned(),
                                error_code: ErrorCode::ErrorResponse,
                                vendor_code: None,
                                parameters: None,
                                error_source: Some("ecu".to_owned()),
                                schema: None,
                            });
                        }
                    }
                    Err(e) => {
                        let api_error: ApiError = e.into();
                        let (error_code, vendor_code) = api_error.error_and_vendor_code();
                        errors.push(sovd_interfaces::error::ApiErrorResponse {
                            message: api_error.to_string(),
                            error_code,
                            vendor_code,
                            parameters: None,
                            error_source: Some("ecu".to_owned()),
                            schema: None,
                        });
                    }
                }
            }
            let schema = if include_schema {
                Some(create_schema!(
                    sovd_interfaces::functions::functional_groups::modes::commctrl::put::Response<
                        VendorErrorCode,
                    >
                ))
            } else {
                None
            };

            (
                StatusCode::OK,
                Json(
                    sovd_interfaces::functions::functional_groups::modes::commctrl::put::Response {
                        modes: response_data,
                        errors,
                        schema,
                    },
                ),
            )
                .into_response()
        }

        pub(crate) fn docs_put(op: TransformOperation) -> TransformOperation {
            openapi::request_json_and_octet::<
                sovd_interfaces::functions::functional_groups::data::DataRequestPayload,
            >(op)
            .description("Set communication control mode- sends to all ECUs in the group")
            .response_with::<200, Json<
                sovd_interfaces::functions::functional_groups::modes::commctrl::put::Response<
                    VendorErrorCode,
                >,
            >, _>(|res| {
                res.description("Response with results from all ECUs in the functional group")
            })
            .with(openapi::error_forbidden)
            .with(openapi::error_not_found)
            .with(openapi::error_internal_server)
            .with(openapi::error_bad_request)
            .with(openapi::error_bad_gateway)
        }
    }
}
