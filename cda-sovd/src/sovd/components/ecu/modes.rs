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

use std::time::Duration;

use aide::transform::TransformOperation;
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use axum_extra::extract::WithRejection;
use cda_interfaces::{
    HashMap, UdsEcu,
    diagservices::{DiagServiceResponse, DiagServiceResponseType},
    file_manager::FileManager,
};
use sovd_interfaces::components::ecu::modes::{self as sovd_modes};

use crate::sovd::{
    WebserverEcuState, create_schema,
    error::{ApiError, api_error_from_diag_response},
    locks::validate_lock,
};

const SESSION_NAME: &str = "Diagnostic session";
pub(crate) const SESSION_ID: &str = "session";
const SECURITY_NAME: &str = "Security access";
pub(crate) const SECURITY_ID: &str = "security";
const COMM_CONTROL_NAME: &str = "Communication control";
pub(crate) const COMM_CONTROL_ID: &str = "commctrl";

pub(crate) async fn get(
    WithRejection(Query(query), _): WithRejection<Query<sovd_modes::Query>, ApiError>,
) -> Response {
    let schema = if query.include_schema {
        Some(create_schema!(sovd_modes::get::Response))
    } else {
        None
    };
    (
        StatusCode::OK,
        Json(sovd_modes::get::Response {
            items: vec![
                sovd_modes::get::ResponseItem {
                    id: SESSION_ID.to_owned(),
                    name: Some(SESSION_NAME.to_owned()),
                    translation_id: None,
                },
                sovd_modes::get::ResponseItem {
                    id: SECURITY_ID.to_owned(),
                    name: Some(SECURITY_NAME.to_owned()),
                    translation_id: None,
                },
                sovd_modes::get::ResponseItem {
                    id: COMM_CONTROL_ID.to_owned(),
                    name: Some(COMM_CONTROL_NAME.to_owned()),
                    translation_id: None,
                },
            ],
            schema,
        }),
    )
        .into_response()
}

pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
    op.description("Get the available modes for the ECU")
        .response_with::<200, Json<sovd_modes::get::Response>, _>(|res| {
            res.description("Available modes for the ECU")
                .example(sovd_modes::get::Response {
                    items: vec![
                        sovd_modes::get::ResponseItem {
                            id: SESSION_ID.to_owned(),
                            name: Some(SESSION_NAME.to_string()),
                            translation_id: None,
                        },
                        sovd_modes::get::ResponseItem {
                            id: SECURITY_ID.to_owned(),
                            name: Some(SECURITY_NAME.to_string()),
                            translation_id: None,
                        },
                        sovd_modes::get::ResponseItem {
                            id: COMM_CONTROL_ID.to_owned(),
                            name: Some(COMM_CONTROL_NAME.to_string()),
                            translation_id: None,
                        },
                    ],
                    schema: None,
                })
        })
}

pub(crate) mod session {
    use aide::UseApi;
    use cda_interfaces::{DynamicPlugin, SchemaProvider};
    use cda_plugin_security::Secured;

    use super::*;
    use crate::{openapi, sovd::error::ErrorWrapper};

    #[tracing::instrument(
        skip(locks, uds, security_plugin),
        fields(
            ecu_name = %ecu_name,
            session_value = %request_body.value,
            mode_expiration = ?request_body.mode_expiration
        )
    )]
    pub(crate) async fn put<R: DiagServiceResponse, T: UdsEcu + Clone, U: FileManager>(
        UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
        WithRejection(Query(query), _): WithRejection<Query<sovd_modes::Query>, ApiError>,
        State(WebserverEcuState {
            ecu_name,
            uds,
            locks,
            ..
        }): State<WebserverEcuState<R, T, U>>,
        WithRejection(Json(request_body), _): WithRejection<
            Json<sovd_modes::security_and_session::put::Request>,
            ApiError,
        >,
    ) -> Response {
        let claims = security_plugin.as_auth_plugin().claims();
        let include_schema = query.include_schema;
        if let Some(response) = validate_lock(&claims, &ecu_name, &locks, include_schema).await {
            return response;
        }
        let schema = if include_schema {
            Some(create_schema!(
                sovd_modes::security_and_session::put::Response<String>
            ))
        } else {
            None
        };
        tracing::info!("Setting ECU session mode");
        match uds
            .set_ecu_session(
                &ecu_name,
                &request_body.value,
                &(security_plugin as DynamicPlugin),
                request_body.mode_expiration.map(Duration::from_secs),
            )
            .await
        {
            Ok(response) => match response.response_type() {
                DiagServiceResponseType::Positive => {
                    let value = match uds.ecu_session(&ecu_name).await {
                        Ok(session) => session,
                        Err(e) => {
                            return ErrorWrapper {
                                error: ApiError::from(e),
                                include_schema,
                            }
                            .into_response();
                        }
                    };
                    (
                        StatusCode::OK,
                        Json(sovd_modes::security_and_session::put::Response {
                            id: SESSION_ID.to_owned(),
                            value,
                            schema,
                        }),
                    )
                        .into_response()
                }
                DiagServiceResponseType::Negative => api_error_from_diag_response(&response, false),
            },
            Err(e) => ErrorWrapper {
                error: ApiError::from(e),
                include_schema,
            }
            .into_response(),
        }
    }

    pub(crate) fn docs_put(op: TransformOperation) -> TransformOperation {
        op.description("Change the active session.")
            .input::<Json<sovd_modes::security_and_session::put::Request>>()
            .response_with::<200, Json<sovd_modes::security_and_session::put::Response<String>>, _>(
                |res| {
                    res.description("Session updated successfully").example(
                        sovd_modes::security_and_session::put::Response {
                            id: SESSION_ID.to_owned(),
                            value: "default".to_owned(),
                            schema: None,
                        },
                    )
                },
            )
            .with(openapi::error_not_found)
            .with(openapi::error_forbidden)
            .with(openapi::error_bad_request)
            .with(openapi::error_internal_server)
            .with(openapi::error_bad_gateway)
    }

    pub(crate) async fn get<
        R: DiagServiceResponse,
        T: UdsEcu + SchemaProvider + Clone,
        U: FileManager,
    >(
        UseApi(Secured(_security_plugin), _): UseApi<Secured, ()>,
        WithRejection(Query(query), _): WithRejection<Query<sovd_modes::Query>, ApiError>,
        State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
    ) -> Response {
        let include_schema = query.include_schema;
        let schema = if include_schema {
            Some(create_schema!(
                sovd_modes::security_and_session::get::Response
            ))
        } else {
            None
        };
        match uds.ecu_session(&ecu_name).await {
            Ok(security_mode) => (
                StatusCode::OK,
                Json(&sovd_modes::security_and_session::get::Response {
                    name: Some(SESSION_NAME.to_owned()),
                    value: Some(security_mode),
                    translation_id: None,
                    schema,
                }),
            )
                .into_response(),
            Err(e) => ErrorWrapper {
                error: ApiError::from(e),
                include_schema,
            }
            .into_response(),
        }
    }

    pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
        op.description("Retrieve the active session.")
            .response_with::<200, Json<sovd_modes::security_and_session::get::Response>, _>(|res| {
                res.description("Current session value for the ECU")
                    .example(sovd_modes::security_and_session::get::Response {
                        name: Some(SESSION_NAME.to_owned()),
                        translation_id: None,
                        value: Some("default".to_owned()),
                        schema: None,
                    })
            })
            .with(openapi::error_not_found)
    }
}

pub(crate) mod security {
    use aide::UseApi;
    use cda_interfaces::{
        DynamicPlugin, HashMapExtensions, SchemaProvider, SecurityAccess,
        diagservices::UdsPayloadData,
    };
    use cda_plugin_security::Secured;
    use sovd_interfaces::components::ecu::modes::security_and_session::put::{
        RequestSeedResponse, SovdSeed,
    };

    use super::*;
    use crate::{openapi, sovd::error::ErrorWrapper};

    pub(crate) async fn get<
        R: DiagServiceResponse,
        T: UdsEcu + SchemaProvider + Clone,
        U: FileManager,
    >(
        UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
        WithRejection(Query(query), _): WithRejection<Query<sovd_modes::Query>, ApiError>,
        State(WebserverEcuState {
            ecu_name,
            uds,
            locks,
            ..
        }): State<WebserverEcuState<R, T, U>>,
    ) -> Response {
        let claims = security_plugin.as_auth_plugin().claims();
        let include_schema = query.include_schema;
        if let Some(value) = validate_lock(&claims, &ecu_name, &locks, include_schema).await {
            return value;
        }
        let schema = if include_schema {
            Some(create_schema!(
                sovd_modes::security_and_session::get::Response
            ))
        } else {
            None
        };

        match uds.ecu_security_access(&ecu_name).await {
            Ok(security_mode) => (
                StatusCode::OK,
                Json(&sovd_modes::security_and_session::get::Response {
                    name: Some(SECURITY_NAME.to_owned()),
                    value: Some(security_mode),
                    translation_id: None,
                    schema,
                }),
            )
                .into_response(),
            Err(e) => ErrorWrapper {
                error: ApiError::from(e),
                include_schema,
            }
            .into_response(),
        }
    }

    pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
        op.description("Retrieve the active security access.")
            .response_with::<200, Json<sovd_modes::security_and_session::get::Response>, _>(|res| {
                res.description("Current security value for the ECU")
                    .example(sovd_modes::security_and_session::get::Response {
                        name: Some(SECURITY_NAME.to_owned()),
                        translation_id: None,
                        value: Some("locked".to_owned()),
                        schema: None,
                    })
            })
            .with(openapi::error_not_found)
    }

    pub(crate) async fn put<R: DiagServiceResponse, T: UdsEcu + Clone, U: FileManager>(
        UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
        WithRejection(Query(query), _): WithRejection<Query<sovd_modes::Query>, ApiError>,
        State(WebserverEcuState {
            ecu_name,
            uds,
            locks,
            ..
        }): State<WebserverEcuState<R, T, U>>,
        WithRejection(Json(request_body), _): WithRejection<
            Json<sovd_modes::security_and_session::put::Request>,
            ApiError,
        >,
    ) -> Response {
        fn split_at_last_underscore(input: &str) -> (String, Option<String>) {
            let parts: Vec<&str> = input.split('_').collect();

            if parts.len() > 2 {
                let last_part = parts.last().map(|s| (*s).to_string());
                let remaining = parts
                    .get(..parts.len().saturating_sub(1))
                    .map_or_else(|| input.to_string(), |slice| slice.join("_"));
                (remaining, last_part)
            } else {
                (input.to_string(), None)
            }
        }

        let claims = security_plugin.as_auth_plugin().claims();
        let include_schema = query.include_schema;

        if let Some(value) = validate_lock(&claims, &ecu_name, &locks, include_schema).await {
            return value;
        }

        let (level, request_seed_service) = split_at_last_underscore(&request_body.value);
        let key = request_body.key.map(|k| k.send_key);

        if request_seed_service.is_some() && key.is_some() {
            return ErrorWrapper {
                error: ApiError::BadRequest(
                    "RequestSeed and SendKey cannot be used at the same time.".to_string(),
                ),
                include_schema,
            }
            .into_response();
        }
        if request_seed_service.is_none() && key.is_none() {
            return ErrorWrapper {
                error: ApiError::BadRequest(
                    "RequestSeed is not set but no key is given.".to_string(),
                ),
                include_schema,
            }
            .into_response();
        }

        let payload = if let Some(key) = key {
            let mut data = HashMap::new();
            let Ok(value) = serde_json::to_value(&key) else {
                return ErrorWrapper {
                    error: ApiError::BadRequest("Failed to serialize key".to_string()),
                    include_schema,
                }
                .into_response();
            };

            let param_name = match uds.get_send_key_param_name(&ecu_name, &level).await {
                Ok(n) => n,
                Err(e) => {
                    return ErrorWrapper {
                        error: ApiError::from(e),
                        include_schema,
                    }
                    .into_response();
                }
            };

            data.insert(param_name, value);
            let payload = UdsPayloadData::ParameterMap(data);
            Some(payload)
        } else {
            None
        };

        match uds
            .set_ecu_security_access(
                &ecu_name,
                &level,
                request_seed_service.as_ref(),
                payload,
                &(security_plugin as DynamicPlugin),
                request_body.mode_expiration.map(Duration::from_secs),
            )
            .await
        {
            Ok((security_access, response)) => match response.response_type() {
                DiagServiceResponseType::Positive => match security_access {
                    SecurityAccess::RequestSeed(_) => {
                        let schema = if query.include_schema {
                            Some(create_schema!(RequestSeedResponse))
                        } else {
                            None
                        };
                        let seed = response
                            .get_raw()
                            .iter()
                            .map(|byte| format!("0x{byte:02x}"))
                            .collect::<Vec<String>>()
                            .join(" ");

                        (
                            StatusCode::OK,
                            Json(RequestSeedResponse {
                                id: SECURITY_ID.to_owned(),
                                seed: SovdSeed { request_seed: seed },
                                schema,
                            }),
                        )
                            .into_response()
                    }

                    SecurityAccess::SendKey(_) => {
                        let schema = if query.include_schema {
                            Some(create_schema!(
                                sovd_modes::security_and_session::put::Response<String>
                            ))
                        } else {
                            None
                        };
                        (
                            StatusCode::OK,
                            Json(sovd_modes::security_and_session::put::Response {
                                id: SECURITY_ID.to_owned(),
                                value: request_body.value.clone(),
                                schema,
                            }),
                        )
                            .into_response()
                    }
                },
                DiagServiceResponseType::Negative => {
                    api_error_from_diag_response(&response, include_schema)
                }
            },
            Err(e) => ErrorWrapper {
                error: ApiError::from(e),
                include_schema,
            }
            .into_response(),
        }
    }

    pub(crate) fn docs_put(op: TransformOperation) -> TransformOperation {
        op.description("Change the security Level.")
            .input::<Json<sovd_modes::security_and_session::put::Request>>()
            .response_with::<200, Json<sovd_modes::security_and_session::put::Response<String>>, _>(
                |res| {
                    res.description("Security level updated successfully")
                        .example(sovd_modes::security_and_session::put::Response {
                            id: SECURITY_ID.to_owned(),
                            value: "default".to_owned(),
                            schema: None,
                        })
                },
            )
            .with(openapi::error_not_found)
            .with(openapi::error_forbidden)
            .with(openapi::error_bad_request)
            .with(openapi::error_internal_server)
            .with(openapi::error_bad_gateway)
    }
}

pub(crate) mod commctrl {
    use aide::UseApi;
    use cda_plugin_security::Secured;

    use super::*;
    use crate::{openapi, sovd::error::ErrorWrapper};

    pub(crate) async fn put<R: DiagServiceResponse, T: UdsEcu + Clone, U: FileManager>(
        UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
        WithRejection(Query(query), _): WithRejection<Query<sovd_modes::Query>, ApiError>,
        State(WebserverEcuState {
            ecu_name,
            uds,
            locks,
            ..
        }): State<WebserverEcuState<R, T, U>>,
        WithRejection(Json(request_body), _): WithRejection<
            Json<sovd_modes::commctrl::put::Request>,
            ApiError,
        >,
    ) -> Response {
        let claims = security_plugin.as_auth_plugin().claims();
        let include_schema = query.include_schema;
        if let Some(response) = validate_lock(&claims, &ecu_name, &locks, include_schema).await {
            return response;
        }

        match uds
            .set_ecu_comm_ctrl(
                &ecu_name,
                &(security_plugin as cda_interfaces::DynamicPlugin),
                &request_body.value,
                request_body.parameters,
            )
            .await
        {
            Ok(response) => match response.response_type() {
                DiagServiceResponseType::Positive => {
                    let schema = if query.include_schema {
                        Some(create_schema!(sovd_modes::commctrl::put::Response))
                    } else {
                        None
                    };
                    (
                        StatusCode::OK,
                        Json(sovd_modes::commctrl::put::Response {
                            id: COMM_CONTROL_ID.to_owned(),
                            value: request_body.value,
                            schema,
                        }),
                    )
                        .into_response()
                }
                DiagServiceResponseType::Negative => {
                    api_error_from_diag_response(&response, include_schema)
                }
            },
            Err(e) => ErrorWrapper {
                error: ApiError::from(e),
                include_schema,
            }
            .into_response(),
        }
    }

    pub(crate) fn docs_put(op: TransformOperation) -> TransformOperation {
        op.description("Change the communication mode.")
            .input::<Json<sovd_modes::commctrl::put::Request>>()
            .response_with::<200, Json<sovd_modes::commctrl::put::Response>, _>(|res| {
                res.description("Communication mode updated").example(
                    sovd_modes::commctrl::put::Response {
                        id: COMM_CONTROL_ID.to_owned(),
                        value: "DisableRxAndDisableTx".to_owned(),
                        schema: None,
                    },
                )
            })
            .with(openapi::error_not_found)
            .with(openapi::error_forbidden)
            .with(openapi::error_bad_request)
            .with(openapi::error_internal_server)
            .with(openapi::error_bad_gateway)
    }
}
