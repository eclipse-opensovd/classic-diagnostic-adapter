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
    datatypes::semantics,
    diagservices::{DiagServiceResponse, DiagServiceResponseType},
    file_manager::FileManager,
};
use sovd_interfaces::components::ecu::modes::{self as sovd_modes, ModeType};

use crate::sovd::{
    WebserverEcuState, create_schema,
    error::{ApiError, api_error_from_diag_response},
    locks::validate_lock,
};

const SESSION_NAME: &str = "Diagnostic session";
const SECURITY_NAME: &str = "Security access";

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
                sovd_modes::Mode {
                    id: Some(ModeType::Session.to_string()),
                    name: Some(SESSION_NAME.to_string()),
                    translation_id: None,
                    value: None,
                    // we do not include the subschemas as the complete schema
                    // included in the root of the response already contains them
                    schema: None,
                },
                sovd_modes::Mode {
                    id: Some(ModeType::Security.to_string()),
                    name: Some(SECURITY_NAME.to_string()),
                    translation_id: None,
                    value: None,
                    schema: None,
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
                        sovd_modes::Mode {
                            id: Some(ModeType::Session.to_string()),
                            name: Some(SESSION_NAME.to_string()),
                            translation_id: None,
                            value: None,
                            schema: None,
                        },
                        sovd_modes::Mode {
                            id: Some(ModeType::Security.to_string()),
                            name: Some(SECURITY_NAME.to_string()),
                            translation_id: None,
                            value: None,
                            schema: None,
                        },
                    ],
                    schema: None,
                })
        })
}

pub(crate) mod id {
    use std::str::FromStr as _;

    use aide::UseApi;
    use axum::extract::Path;
    use cda_plugin_security::Secured;

    use super::*;
    use crate::{openapi, sovd::error::ErrorWrapper};

    fn deserialize_mode(mode_str: &str, include_schema: bool) -> Result<ModeType, ErrorWrapper> {
        ModeType::from_str(mode_str).map_err(|e| ErrorWrapper {
            error: ApiError::BadRequest(format!("Invalid mode type '{mode_str}': {e}")),
            include_schema,
        })
    }

    pub(crate) async fn get<R: DiagServiceResponse, T: UdsEcu + Clone, U: FileManager>(
        UseApi(Secured(sec_plugin), _): UseApi<Secured, ()>,
        WithRejection(Query(query), _): WithRejection<Query<sovd_modes::Query>, ApiError>,
        State(state): State<WebserverEcuState<R, T, U>>,
        Path(mode_str): Path<String>,
    ) -> Response {
        let mode = match deserialize_mode(&mode_str, query.include_schema) {
            Ok(m) => m,
            Err(e) => return e.into_response(),
        };
        match mode {
            ModeType::Session => session::get(query, state).await,
            ModeType::Security => security::get(sec_plugin, query, state).await,
        }
    }

    pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
        op.description("Get the current value of the given mode for the ECU")
            .response_with::<200, Json<sovd_modes::Mode<String>>, _>(|res| {
                res.description("Current mode value for the ECU")
                    .example(sovd_modes::Mode {
                        id: None,
                        name: Some(SESSION_NAME.to_string()),
                        translation_id: None,
                        value: Some("default".to_string()),
                        schema: None,
                    })
            })
            .with(openapi::error_not_found)
    }

    pub(crate) async fn put<R: DiagServiceResponse, T: UdsEcu + Clone, U: FileManager>(
        UseApi(Secured(sec_plugin), _): UseApi<Secured, ()>,
        WithRejection(Query(query), _): WithRejection<Query<sovd_modes::Query>, ApiError>,
        State(state): State<WebserverEcuState<R, T, U>>,
        Path(mode_str): Path<String>,
        WithRejection(Json(request_body), _): WithRejection<
            Json<sovd_modes::put::Request>,
            ApiError,
        >,
    ) -> Response {
        let mode = match deserialize_mode(&mode_str, query.include_schema) {
            Ok(m) => m,
            Err(e) => return e.into_response(),
        };
        match mode {
            ModeType::Session => {
                session::put(mode_str, sec_plugin, query, state, request_body).await
            }
            ModeType::Security => {
                security::put(mode_str, sec_plugin, query, state, request_body).await
            }
        }
    }

    pub(crate) fn docs_put(op: TransformOperation) -> TransformOperation {
        op.description("update the mode with a new value")
            .input::<Json<sovd_modes::put::Request>>()
            .response_with::<200, Json<sovd_modes::put::Response<String>>, _>(|res| {
                res.description("Mode updated successfully")
                    .example(sovd_modes::put::Response {
                        id: ModeType::Session.to_string(),
                        value: "default".to_string(),
                        schema: None,
                    })
            })
            .with(openapi::error_not_found)
            .with(openapi::error_forbidden)
            .with(openapi::error_bad_request)
            .with(openapi::error_internal_server)
            .with(openapi::error_bad_gateway)
    }
}

pub(crate) mod session {
    use cda_interfaces::DynamicPlugin;
    use cda_plugin_security::SecurityPlugin;

    use super::*;
    use crate::sovd::error::ErrorWrapper;

    #[tracing::instrument(
        skip(locks, uds, security_plugin),
        fields(
            ecu_name = %ecu_name,
            session_value = %request_body.value,
            mode_expiration = ?request_body.mode_expiration
        )
    )]
    pub(crate) async fn put<R: DiagServiceResponse, T: UdsEcu + Clone, U: FileManager>(
        id: String,
        security_plugin: Box<dyn SecurityPlugin>,
        query: sovd_modes::Query,
        WebserverEcuState {
            locks,
            uds,
            ecu_name,
            ..
        }: WebserverEcuState<R, T, U>,
        request_body: sovd_modes::put::Request,
    ) -> Response {
        let claims = security_plugin.as_auth_plugin().claims();
        let include_schema = query.include_schema;
        if let Some(response) = validate_lock(&claims, &ecu_name, &locks, include_schema).await {
            return response;
        }
        let schema = if include_schema {
            Some(create_schema!(sovd_modes::put::Response::<String>))
        } else {
            None
        };
        tracing::info!("Setting ECU session mode");
        match uds
            .set_ecu_session(
                &ecu_name,
                &request_body.value,
                &(security_plugin as DynamicPlugin),
                Duration::from_secs(request_body.mode_expiration.unwrap_or(u64::MAX)),
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
                        Json(sovd_modes::put::Response { id, value, schema }),
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

    pub(crate) async fn get<R: DiagServiceResponse, T: UdsEcu + Clone, U: FileManager>(
        query: sovd_modes::Query,
        WebserverEcuState { uds, ecu_name, .. }: WebserverEcuState<R, T, U>,
    ) -> Response {
        let include_schema = query.include_schema;
        let schema = if include_schema {
            Some(create_schema!(sovd_modes::Mode<String>))
        } else {
            None
        };
        match uds.ecu_session(&ecu_name).await {
            Ok(security_mode) => (
                StatusCode::OK,
                Json(&sovd_modes::Mode {
                    id: None,
                    name: Some(ModeType::Session.to_string()),
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
}

pub(crate) mod security {
    use cda_interfaces::{
        DynamicPlugin, HashMapExtensions, SecurityAccess, diagservices::UdsPayloadData,
    };
    use cda_plugin_security::SecurityPlugin;
    use sovd_interfaces::components::ecu::modes::put::{RequestSeedResponse, SovdSeed};

    use super::*;
    use crate::sovd::error::ErrorWrapper;

    pub(crate) async fn get<R: DiagServiceResponse, T: UdsEcu + Clone, U: FileManager>(
        sec_plugin: Box<dyn SecurityPlugin>,
        query: sovd_modes::Query,
        WebserverEcuState {
            ecu_name,
            locks,
            uds,
            ..
        }: WebserverEcuState<R, T, U>,
    ) -> Response {
        let claims = sec_plugin.as_auth_plugin().claims();
        let include_schema = query.include_schema;
        if let Some(value) = validate_lock(&claims, &ecu_name, &locks, include_schema).await {
            return value;
        }
        let schema = if include_schema {
            Some(create_schema!(sovd_modes::Mode<String>))
        } else {
            None
        };

        match uds.ecu_security_access(&ecu_name).await {
            Ok(security_mode) => (
                StatusCode::OK,
                Json(&sovd_modes::Mode {
                    id: None,
                    name: Some(ModeType::Security.to_string()),
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

    pub(crate) async fn put<R: DiagServiceResponse, T: UdsEcu + Clone, U: FileManager>(
        id: String,
        security_plugin: Box<dyn SecurityPlugin>,
        query: sovd_modes::Query,
        WebserverEcuState {
            uds,
            ecu_name,
            locks,
            ..
        }: WebserverEcuState<R, T, U>,
        request_body: sovd_modes::put::Request,
    ) -> Response {
        fn split_at_last_underscore(input: &str) -> (String, Option<String>) {
            let parts: Vec<&str> = input.split('_').collect();

            if parts.len() > 2 {
                let last_part = parts.last().map(|s| (*s).to_string());
                let remaining = parts
                    .get(..parts.len() - 1)
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
                Duration::from_secs(request_body.mode_expiration.unwrap_or(u64::MAX)),
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
                                id: semantics::SECURITY.to_owned(),
                                seed: SovdSeed { request_seed: seed },
                                schema,
                            }),
                        )
                            .into_response()
                    }

                    SecurityAccess::SendKey(_) => {
                        let schema = if query.include_schema {
                            Some(create_schema!(sovd_modes::put::Response<String>))
                        } else {
                            None
                        };
                        (
                            StatusCode::OK,
                            Json(sovd_modes::put::Response {
                                id,
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
}
