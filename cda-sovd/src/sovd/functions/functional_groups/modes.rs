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
        functions::functional_groups::modes::{self as sovd_modes, commctrl::put::ResponseElement},
    };

    use super::{
        ApiError, COMM_CONTROL_ID, IntoResponse, Json, Query, Response, StatusCode,
        TransformOperation, UdsEcu, WithRejection, create_schema,
    };
    use crate::{
        openapi,
        sovd::{
            error::{ErrorWrapper, VendorErrorCode},
            functions::functional_groups::WebserverFgState,
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
        let mut errors: Vec<sovd_interfaces::error::ApiErrorResponse<VendorErrorCode>> = Vec::new();
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
