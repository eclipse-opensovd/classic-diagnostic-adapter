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
use cda_interfaces::{DiagServiceError, HashMap, UdsEcu, diagservices::DiagServiceResponse};
use http::StatusCode;
use sovd_interfaces::{
    common::modes::{COMM_CONTROL_ID, COMM_CONTROL_NAME, DTC_SETTING_ID, DTC_SETTING_NAME},
    error::ErrorCode,
};

use crate::{
    create_schema,
    sovd::error::{ApiError, VendorErrorCode},
};

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
            items: vec![
                ResponseItem {
                    id: COMM_CONTROL_ID.to_owned(),
                    name: Some(COMM_CONTROL_NAME.to_owned()),
                    translation_id: None,
                },
                ResponseItem {
                    id: DTC_SETTING_ID.to_owned(),
                    name: Some(DTC_SETTING_NAME.to_owned()),
                    translation_id: None,
                },
            ],
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

async fn handle_mode_change<T: UdsEcu + Clone>(
    state: &crate::sovd::functions::functional_groups::WebserverFgState<T>,
    security_plugin: Box<dyn cda_plugin_security::SecurityPlugin>,
    service_id: u8,
    id: &str,
    value: &str,
    parameters: Option<HashMap<String, serde_json::Value>>,
    include_schema: bool,
) -> Response {
    let claims = security_plugin.as_auth_plugin().claims();
    if let Some(response) = crate::sovd::locks::validate_lock(
        &claims,
        &state.functional_group_name,
        &state.locks,
        include_schema,
    )
    .await
    {
        return response;
    }

    let results = match state
        .uds
        .call_functional_service_by_sid_and_name(
            &state.functional_group_name,
            &(security_plugin as cda_interfaces::DynamicPlugin),
            service_id,
            value,
            parameters,
            false,
        )
        .await
    {
        Ok(results) => results,
        Err(e) => {
            return crate::sovd::error::ErrorWrapper {
                error: ApiError::from(e),
                include_schema,
            }
            .into_response();
        }
    };

    let (response_data, errors) = build_mode_response::<T>(id, value, results);
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

fn build_mode_response<T: UdsEcu>(
    id: &str,
    value: &str,
    results: HashMap<String, Result<T::Response, DiagServiceError>>,
) -> (
    HashMap<String, sovd_interfaces::common::modes::put::Response<String>>,
    Vec<sovd_interfaces::error::ApiErrorResponse<VendorErrorCode>>,
) {
    // Build response with per-ECU data and errors
    let mut response_data: HashMap<_, _> = HashMap::default();
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
                        sovd_interfaces::common::modes::put::Response {
                            id: id.to_owned(),
                            value: value.to_owned(),
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
    (response_data, errors)
}

pub(crate) mod commctrl {
    use aide::UseApi;
    use axum::extract::State;
    use cda_interfaces::service_ids;
    use cda_plugin_security::Secured;
    use sovd_interfaces::{
        common::modes::COMM_CONTROL_ID,
        functions::functional_groups::modes::{self as sovd_modes},
    };

    use super::{
        ApiError, Json, Query, Response, TransformOperation, UdsEcu, WithRejection,
        handle_mode_change,
    };
    use crate::{
        openapi,
        sovd::{error::VendorErrorCode, functions::functional_groups::WebserverFgState},
    };

    pub(crate) async fn put<T: UdsEcu + Clone>(
        UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
        WithRejection(Query(query), _): WithRejection<Query<sovd_modes::Query>, ApiError>,
        State(state): State<WebserverFgState<T>>,
        WithRejection(Json(request_body), _): WithRejection<
            Json<sovd_modes::commctrl::put::Request>,
            ApiError,
        >,
    ) -> Response {
        handle_mode_change(
            &state,
            security_plugin,
            service_ids::COMMUNICATION_CONTROL,
            COMM_CONTROL_ID,
            &request_body.value,
            request_body.parameters,
            query.include_schema,
        )
        .await
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

pub(crate) mod dtcsetting {
    use aide::UseApi;
    use axum::extract::State;
    use cda_interfaces::service_ids;
    use cda_plugin_security::Secured;
    use sovd_interfaces::{
        common::modes::DTC_SETTING_ID,
        functions::functional_groups::modes::{self as sovd_modes},
    };

    use super::{
        ApiError, Json, Query, Response, TransformOperation, UdsEcu, WithRejection,
        handle_mode_change,
    };
    use crate::{
        openapi,
        sovd::{error::VendorErrorCode, functions::functional_groups::WebserverFgState},
    };

    pub(crate) async fn put<T: UdsEcu + Clone>(
        UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
        WithRejection(Query(query), _): WithRejection<Query<sovd_modes::Query>, ApiError>,
        State(state): State<WebserverFgState<T>>,
        WithRejection(Json(request_body), _): WithRejection<
            Json<sovd_modes::dtcsetting::put::Request>,
            ApiError,
        >,
    ) -> Response {
        handle_mode_change(
            &state,
            security_plugin,
            service_ids::CONTROL_DTC_SETTING,
            DTC_SETTING_ID,
            &request_body.value,
            request_body.parameters,
            query.include_schema,
        )
        .await
    }

    pub(crate) fn docs_put(op: TransformOperation) -> TransformOperation {
        openapi::request_json_and_octet::<
            sovd_interfaces::functions::functional_groups::data::DataRequestPayload,
        >(op)
        .description("Set the DTC setting mode - sends to all ECUs in the group")
        .response_with::<200, Json<
            sovd_interfaces::functions::functional_groups::modes::dtcsetting::put::Response<
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
