/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

use std::time::Duration;

use aide::transform::TransformOperation;
use axum::{
    Json,
    extract::Query,
    response::{IntoResponse, Response},
};
use axum_extra::extract::WithRejection;
use cda_interfaces::{DiagServiceError, HashMap, UdsEcu, diagservices::DiagServiceResponse};
use http::StatusCode;
use serde::Serialize;
use sovd_interfaces::{
    common::modes::{
        COMM_CONTROL_ID, COMM_CONTROL_NAME, DTC_SETTING_ID, DTC_SETTING_NAME, SESSION_ID,
        SESSION_NAME,
    },
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
                ResponseItem {
                    id: SESSION_ID.to_owned(),
                    name: Some(SESSION_NAME.to_owned()),
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

// there is not much benefit in passing a structure here,
#[allow(clippy::too_many_arguments)]
async fn handle_mode_change<T: UdsEcu + Clone>(
    state: &crate::sovd::functions::functional_groups::WebserverFgState<T>,
    security_plugin: Box<dyn cda_plugin_security::SecurityPlugin>,
    service_id: u8,
    id: &str,
    value: &str,
    parameters: Option<HashMap<String, serde_json::Value>>,
    expiration: Option<Duration>,
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
        .set_functional_state(
            &state.functional_group_name,
            &(security_plugin as cda_interfaces::DynamicPlugin),
            service_id,
            value,
            parameters,
            expiration,
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

async fn handle_mode_get<
    T: UdsEcu + Clone,
    ResponseElementType: schemars::JsonSchema + Serialize,
>(
    state: &crate::sovd::functions::functional_groups::WebserverFgState<T>,
    service_id: u8,
    include_schema: bool,
    create_response_element_callback: fn(value: String) -> ResponseElementType,
) -> Response {
    let ecu_names = state
        .uds
        .ecus_for_functional_group(&state.functional_group_name, false)
        .await;

    // Query each ECU for its service state
    let mut response_data: HashMap<String, ResponseElementType> = HashMap::default();
    let mut errors: Vec<sovd_interfaces::error::ApiErrorResponse<VendorErrorCode>> = Vec::new();

    for ecu_name in ecu_names {
        match state.uds.get_ecu_service_state(&ecu_name, service_id).await {
            Ok(value) => {
                response_data.insert(ecu_name, create_response_element_callback(value));
            }
            Err(e) => {
                let api_error: ApiError = e.into();
                let (error_code, vendor_code) = api_error.error_and_vendor_code();
                errors.push(sovd_interfaces::error::ApiErrorResponse {
                    message: api_error.to_string(),
                    error_code,
                    vendor_code,
                    parameters: None,
                    error_source: Some(ecu_name),
                    schema: None,
                });
            }
        }
    }

    let schema = if include_schema {
        Some(create_schema!(
            sovd_interfaces::functions::functional_groups::modes::DataResponse<
                VendorErrorCode,ResponseElementType
            >
        ))
    } else {
        None
    };

    (
        StatusCode::OK,
        Json(
            sovd_interfaces::functions::functional_groups::modes::DataResponse {
                modes: response_data,
                errors,
                schema,
            },
        ),
    )
        .into_response()
}

pub(crate) mod commctrl {
    use aide::UseApi;
    use axum::extract::State;
    use cda_interfaces::service_ids;
    use cda_plugin_security::Secured;
    use sovd_interfaces::{
        common::modes::{COMM_CONTROL_ID, COMM_CONTROL_NAME},
        functions::{
            functional_groups,
            functional_groups::modes::{self as sovd_modes},
        },
    };

    use super::{
        ApiError, Json, Query, Response, TransformOperation, UdsEcu, WithRejection,
        handle_mode_change, handle_mode_get,
    };
    use crate::{
        openapi,
        sovd::{error::VendorErrorCode, functions::functional_groups::WebserverFgState},
    };

    pub(crate) async fn get<T: UdsEcu + Clone>(
        UseApi(Secured(_security_plugin), _): UseApi<Secured, ()>,
        WithRejection(Query(query), _): WithRejection<Query<sovd_modes::Query>, ApiError>,
        State(state): State<WebserverFgState<T>>,
    ) -> Response {
        handle_mode_get(
            &state,
            service_ids::COMMUNICATION_CONTROL,
            query.include_schema,
            |value| functional_groups::modes::commctrl::get::ResponseElement {
                name: Some(COMM_CONTROL_NAME.to_owned()),
                translation_id: None,
                value: Some(value),
                schema: None,
            },
        )
        .await
    }

    pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
        op.description(
            "Retrieve the active communication control for all ECUs in the functional group",
        )
        .response_with::<200, Json<
            functional_groups::modes::commctrl::get::Response<
                VendorErrorCode,
            >,
        >, _>(|res| {
            res.description(
                "Current communication control value for all ECUs in the functional group",
            )
        })
        .with(openapi::error_not_found)
    }

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
            None,
            query.include_schema,
        )
        .await
    }

    pub(crate) fn docs_put(op: TransformOperation) -> TransformOperation {
        openapi::request_json_and_octet::<
            functional_groups::data::DataRequestPayload,
        >(op)
        .description("Set communication control mode- sends to all ECUs in the group")
        .response_with::<200, Json<
            functional_groups::modes::commctrl::put::Response<
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
        common::modes::{DTC_SETTING_ID, DTC_SETTING_NAME},
        functions::{
            functional_groups,
            functional_groups::modes::{self as sovd_modes},
        },
    };

    use super::{
        ApiError, Json, Query, Response, TransformOperation, UdsEcu, WithRejection,
        handle_mode_change, handle_mode_get,
    };
    use crate::{
        openapi,
        sovd::{error::VendorErrorCode, functions::functional_groups::WebserverFgState},
    };

    pub(crate) async fn get<T: UdsEcu + Clone>(
        UseApi(Secured(_security_plugin), _): UseApi<Secured, ()>,
        WithRejection(Query(query), _): WithRejection<Query<sovd_modes::Query>, ApiError>,
        State(state): State<WebserverFgState<T>>,
    ) -> Response {
        handle_mode_get(
            &state,
            service_ids::CONTROL_DTC_SETTING,
            query.include_schema,
            |value| functional_groups::modes::dtcsetting::get::ResponseElement {
                name: Some(DTC_SETTING_NAME.to_owned()),
                translation_id: None,
                value: Some(value),
                schema: None,
            },
        )
        .await
    }

    pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
        op.description("Retrieve the active DTC setting for all ECUs in the functional group")
            .response_with::<200, Json<
                functional_groups::modes::dtcsetting::get::ResponseElement,
            >, _>(|res| {
                res.description("Current DTC setting value for all ECUs in the functional group")
            })
            .with(openapi::error_not_found)
    }

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
            None,
            query.include_schema,
        )
        .await
    }

    pub(crate) fn docs_put(op: TransformOperation) -> TransformOperation {
        openapi::request_json_and_octet::<
            functional_groups::data::DataRequestPayload,
        >(op)
        .description("Set the DTC setting mode - sends to all ECUs in the group")
        .response_with::<200, Json<
            functional_groups::modes::dtcsetting::put::Response<
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

pub(crate) mod session {
    use std::time::Duration;

    use aide::UseApi;
    use axum::extract::State;
    use cda_interfaces::service_ids;
    use cda_plugin_security::Secured;
    use sovd_interfaces::functions::functional_groups::{self, modes as sovd_modes};

    use super::{
        ApiError, Json, Query, Response, SESSION_ID, SESSION_NAME, TransformOperation, UdsEcu,
        WithRejection, handle_mode_change, handle_mode_get,
    };
    use crate::{
        openapi,
        sovd::{error::VendorErrorCode, functions::functional_groups::WebserverFgState},
    };

    pub(crate) async fn get<T: UdsEcu + Clone>(
        UseApi(Secured(_security_plugin), _): UseApi<Secured, ()>,
        WithRejection(Query(query), _): WithRejection<Query<sovd_modes::Query>, ApiError>,
        State(state): State<WebserverFgState<T>>,
    ) -> Response {
        handle_mode_get(
            &state,
            service_ids::SESSION_CONTROL,
            query.include_schema,
            |value| sovd_modes::session::get::ResponseElement {
                name: Some(SESSION_NAME.to_owned()),
                translation_id: None,
                value: Some(value),
                schema: None,
            },
        )
        .await
    }

    pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
        op.description("Retrieve the active session mode for all ECUs in the functional group")
            .response_with::<200, Json<sovd_modes::session::get::ResponseElement>, _>(|res| {
                res.description("Current session value for all ECUs in the functional group")
            })
            .with(openapi::error_not_found)
    }

    pub(crate) async fn put<T: UdsEcu + Clone>(
        UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
        WithRejection(Query(query), _): WithRejection<Query<sovd_modes::Query>, ApiError>,
        State(state): State<WebserverFgState<T>>,
        WithRejection(Json(request_body), _): WithRejection<
            Json<sovd_modes::session::put::Request>,
            ApiError,
        >,
    ) -> Response {
        handle_mode_change(
            &state,
            security_plugin,
            service_ids::SESSION_CONTROL,
            SESSION_ID,
            &request_body.value,
            None,
            request_body.mode_expiration.map(Duration::from_secs),
            query.include_schema,
        )
        .await
    }

    pub(crate) fn docs_put(op: TransformOperation) -> TransformOperation {
        openapi::request_json_and_octet::<functional_groups::data::DataRequestPayload>(op)
            .description("Set the Session mode - sends to all ECUs in the group")
            .response_with::<200, Json<sovd_modes::session::put::Response<VendorErrorCode>>, _>(
                |res| {
                    res.description("Response with results from all ECUs in the functional group")
                },
            )
            .with(openapi::error_forbidden)
            .with(openapi::error_not_found)
            .with(openapi::error_internal_server)
            .with(openapi::error_bad_request)
            .with(openapi::error_bad_gateway)
    }
}
