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
use std::time::Duration;

use aide::{UseApi, transform::TransformOperation};
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use axum_extra::extract::WithRejection;
use cda_interfaces::{
    BinaryEncoding, HashMap, UdsEcu,
    diagservices::{DiagServiceResponse, DiagServiceResponseType, UdsPayloadData},
    file_manager::FileManager,
};
use schemars::Schema;
use serde::Serialize;
use sovd_interfaces::{
    common::modes::{
        AUTHENTICATION_ID, AUTHENTICATION_NAME, COMM_CONTROL_ID, COMM_CONTROL_NAME, DTC_SETTING_ID,
        DTC_SETTING_NAME, SECURITY_ID, SECURITY_NAME, SESSION_ID, SESSION_NAME,
    },
    components::ecu::modes as sovd_modes,
};

use crate::{
    Locks,
    sovd::{
        WebserverEcuState,
        binary_encoding::BinaryEncodingParam,
        create_schema,
        error::{ApiError, ErrorWrapper, api_error_from_diag_response},
        locks::require_ecu_access,
    },
};

pub(crate) async fn get<T: UdsEcu + Clone, U: FileManager>(
    UseApi(cda_plugin_security::Secured(security_plugin), _): UseApi<
        cda_plugin_security::Secured,
        (),
    >,
    WithRejection(Query(query), _): WithRejection<Query<sovd_modes::Query>, ApiError>,
    State(WebserverEcuState {
        ecu_name,
        uds,
        locks,
        ..
    }): State<WebserverEcuState<T, U>>,
) -> Response {
    require_ecu_access!(
        read,
        security_plugin,
        &ecu_name,
        &locks,
        query.include_schema
    );
    let schema = if query.include_schema {
        Some(create_schema!(sovd_modes::get::Response))
    } else {
        None
    };
    let mut items = vec![
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
        sovd_modes::get::ResponseItem {
            id: DTC_SETTING_ID.to_owned(),
            name: Some(DTC_SETTING_NAME.to_owned()),
            translation_id: None,
        },
    ];
    if uds.has_authentication_services(&ecu_name).await {
        items.push(sovd_modes::get::ResponseItem {
            id: AUTHENTICATION_ID.to_owned(),
            name: Some(AUTHENTICATION_NAME.to_owned()),
            translation_id: None,
        });
    }
    (
        StatusCode::OK,
        Json(sovd_modes::get::Response { items, schema }),
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

#[allow(
    clippy::too_many_arguments,
    reason = "Struct would not improve readability here"
)]
async fn handle_mode_change<T: UdsEcu + Clone>(
    uds: &T,
    ecu_name: &str,
    security_plugin: Box<dyn cda_plugin_security::SecurityPlugin>,
    locks: &Locks,
    service_id: u8,
    value: &str,
    parameters: Option<HashMap<String, serde_json::Value>>,
    mode_id: &str,
    include_schema: bool,
    binary_encoding: BinaryEncoding,
) -> Response {
    require_ecu_access!(write, security_plugin, ecu_name, locks, include_schema);
    match uds
        .set_ecu_state(
            ecu_name,
            &(security_plugin as cda_interfaces::DynamicPlugin),
            service_id,
            value,
            parameters.map(|p| UdsPayloadData::ParameterMap(p, binary_encoding)),
            false,
        )
        .await
    {
        Ok(response) => match response.response_type() {
            DiagServiceResponseType::Positive => {
                let schema = if include_schema {
                    Some(create_schema!(sovd_modes::commctrl::put::Response))
                } else {
                    None
                };
                (
                    StatusCode::OK,
                    Json(sovd_modes::commctrl::put::Response {
                        id: mode_id.to_owned(),
                        value: value.to_owned(),
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

async fn handle_mode_get<T: UdsEcu + Clone, R: schemars::JsonSchema + Serialize>(
    uds: &T,
    ecu_name: &str,
    service_id: u8,
    locks: &Locks,
    security_plugin: Box<dyn cda_plugin_security::SecurityPlugin>,
    include_schema: bool,
    create_response_type_callback: fn(value: String, schema: Option<Schema>) -> R,
) -> Response {
    require_ecu_access!(read, security_plugin, ecu_name, locks, include_schema);
    {
        let schema = if include_schema {
            Some(create_schema!(R))
        } else {
            None
        };

        match uds.get_ecu_service_state(ecu_name, service_id).await {
            Ok(value) => (
                StatusCode::OK,
                Json(&create_response_type_callback(value, schema)),
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

pub(crate) mod session {
    use aide::UseApi;
    use cda_interfaces::{DynamicPlugin, SchemaProvider, service_ids};
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
    pub(crate) async fn put<T: UdsEcu + Clone, U: FileManager>(
        UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
        WithRejection(Query(query), _): WithRejection<Query<sovd_modes::Query>, ApiError>,
        State(WebserverEcuState {
            ecu_name,
            uds,
            locks,
            ..
        }): State<WebserverEcuState<T, U>>,
        WithRejection(Json(request_body), _): WithRejection<
            Json<sovd_modes::security_and_session::put::SessionRequest>,
            ApiError,
        >,
    ) -> Response {
        let include_schema = query.include_schema;
        require_ecu_access!(write, security_plugin, &ecu_name, &locks, include_schema);
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
                    let value = match uds
                        .get_ecu_service_state(&ecu_name, service_ids::SESSION_CONTROL)
                        .await
                    {
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
        op.description("Change the active session.")
            .input::<Json<sovd_modes::security_and_session::put::SessionRequest>>()
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

    pub(crate) async fn get<T: UdsEcu + SchemaProvider + Clone, U: FileManager>(
        UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
        WithRejection(Query(query), _): WithRejection<Query<sovd_modes::Query>, ApiError>,
        State(WebserverEcuState {
            ecu_name,
            uds,
            locks,
            ..
        }): State<WebserverEcuState<T, U>>,
    ) -> Response {
        handle_mode_get(
            &uds,
            &ecu_name,
            service_ids::SESSION_CONTROL,
            &locks,
            security_plugin,
            query.include_schema,
            |value, schema| sovd_modes::security_and_session::get::Response {
                name: Some(SESSION_NAME.to_owned()),
                value: Some(value),
                translation_id: None,
                schema,
            },
        )
        .await
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
        diagservices::{DiagServiceResponse, UdsPayloadData},
        service_ids,
    };
    use cda_plugin_security::Secured;
    use sovd_interfaces::components::ecu::modes::security_and_session::put::{
        RequestSeedResponse, SovdSeed,
    };

    use super::*;
    use crate::{openapi, sovd::error::ErrorWrapper};

    pub(crate) async fn get<T: UdsEcu + SchemaProvider + Clone, U: FileManager>(
        UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
        WithRejection(Query(query), _): WithRejection<Query<sovd_modes::Query>, ApiError>,
        State(WebserverEcuState {
            ecu_name,
            uds,
            locks,
            ..
        }): State<WebserverEcuState<T, U>>,
    ) -> Response {
        handle_mode_get(
            &uds,
            &ecu_name,
            service_ids::SECURITY_ACCESS,
            &locks,
            security_plugin,
            query.include_schema,
            |value, schema| sovd_modes::security_and_session::get::Response {
                name: Some(SECURITY_NAME.to_owned()),
                value: Some(value),
                translation_id: None,
                schema,
            },
        )
        .await
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

    fn is_request_seed_value(input: &str) -> bool {
        let parts: Vec<&str> = input.split('_').collect();
        let last_is_request_seed = parts
            .last()
            .is_some_and(|last| last.eq_ignore_ascii_case("RequestSeed"));
        parts.len() >= 2 && last_is_request_seed
    }

    fn level_from_value(input: &str) -> String {
        let parts: Vec<&str> = input.split('_').collect();
        let last_is_request_seed = parts
            .last()
            .is_some_and(|last| last.eq_ignore_ascii_case("RequestSeed"));
        if parts.len() >= 2 && last_is_request_seed {
            parts
                .get(..parts.len().saturating_sub(1))
                .map_or_else(|| input.to_string(), |slice| slice.join("_"))
        } else {
            input.to_string()
        }
    }

    pub(crate) async fn put<T: UdsEcu + Clone, U: FileManager>(
        UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
        WithRejection(Query(query), _): WithRejection<Query<sovd_modes::Query>, ApiError>,
        BinaryEncodingParam(binary_encoding): BinaryEncodingParam,
        State(WebserverEcuState {
            ecu_name,
            uds,
            locks,
            ..
        }): State<WebserverEcuState<T, U>>,
        WithRejection(Json(request_body), _): WithRejection<
            Json<sovd_modes::security_and_session::put::Request>,
            ApiError,
        >,
    ) -> Response {
        let include_schema = query.include_schema;

        require_ecu_access!(write, security_plugin, &ecu_name, &locks, include_schema);

        let level = level_from_value(&request_body.value);
        let key = request_body.key.map(|k| k.send_key);
        let is_request_seed = is_request_seed_value(&request_body.value);
        let invalid_request = match (
            is_request_seed,
            key.is_some(),
            request_body.parameters.is_some(),
        ) {
            (true, true, _) => Some("RequestSeed and SendKey cannot be used at the same time."),
            (false, false, _) => Some("RequestSeed is not set but no key is given."),
            (false, _, true) => Some("RequestSeed parameters cannot be used with SendKey."),
            _ => None,
        };
        if let Some(message) = invalid_request {
            return ErrorWrapper {
                error: ApiError::BadRequest(message.to_owned()),
                include_schema,
            }
            .into_response();
        }
        let (seed_payload, key_payload) = if let Some(key) = key {
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
            (
                None,
                Some(UdsPayloadData::ParameterMap(data, binary_encoding)),
            )
        } else {
            let seed_payload = request_body
                .parameters
                .map(|p| UdsPayloadData::ParameterMap(p.into_iter().collect(), binary_encoding));
            (seed_payload, None)
        };

        match uds
            .set_ecu_security_access(
                &ecu_name,
                &level,
                key_payload,
                seed_payload,
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
                        let seed = binary_encoding.encode(response.get_raw());

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
            .input::<Json<sovd_modes::security_and_session::put::SecurityRequest>>()
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

pub(crate) mod authentication {

    use aide::UseApi;
    use cda_interfaces::{
        Connectivity, DynamicPlugin,
        authentication::{AuthenticationState, AuthenticationSubFunction},
        diagservices::{DiagServiceJsonResponse, UdsPayloadData},
    };
    use cda_plugin_security::Secured;

    use super::*;
    use crate::{
        openapi,
        sovd::{error::ErrorWrapper, timestamp::system_time_to_rfc3339},
    };

    const OFFLINE: &str = "offline";

    fn error_response(error: ApiError, include_schema: bool) -> Response {
        ErrorWrapper {
            error,
            include_schema,
        }
        .into_response()
    }

    /// Builds the GET response from the tracked state.
    pub(crate) fn get_response(
        state: &AuthenticationState,
        offline: bool,
        schema: Option<Schema>,
    ) -> sovd_modes::authentication::get::Response {
        sovd_modes::authentication::get::Response {
            id: AUTHENTICATION_ID.to_owned(),
            name: Some(AUTHENTICATION_NAME.to_owned()),
            value: if offline {
                OFFLINE.to_owned()
            } else {
                state.status.name().to_owned()
            },
            last_subfunction: state.last_subfunction.map(|sf| sf.name().to_owned()),
            expires_at: state.expires_at.map(system_time_to_rfc3339),
            schema,
        }
    }

    pub(crate) async fn get<T: UdsEcu + Clone, U: FileManager>(
        UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
        WithRejection(Query(query), _): WithRejection<Query<sovd_modes::Query>, ApiError>,
        State(WebserverEcuState {
            ecu_name,
            uds,
            locks,
            ..
        }): State<WebserverEcuState<T, U>>,
    ) -> Response {
        let include_schema = query.include_schema;
        require_ecu_access!(read, security_plugin, &ecu_name, &locks, include_schema);

        let offline = match uds.get_ecu_state(&ecu_name).await {
            Ok(state) => state.connectivity == Connectivity::Offline,
            Err(e) => return error_response(ApiError::from(e), include_schema),
        };
        let state = match uds.get_ecu_authentication_state(&ecu_name).await {
            Ok(state) => state,
            Err(e) => return error_response(ApiError::from(e), include_schema),
        };
        let schema = if include_schema {
            Some(create_schema!(sovd_modes::authentication::get::Response))
        } else {
            None
        };
        (StatusCode::OK, Json(get_response(&state, offline, schema))).into_response()
    }

    pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
        op.description(
            "Retrieve the authentication state (UDS 0x29) of the ECU as tracked by the CDA: \
             `authenticated`, `deAuthenticated` or `offline`.",
        )
        .response_with::<200, Json<sovd_modes::authentication::get::Response>, _>(|res| {
            res.description("Authentication state of the ECU").example(
                sovd_modes::authentication::get::Response {
                    id: AUTHENTICATION_ID.to_owned(),
                    name: Some(AUTHENTICATION_NAME.to_owned()),
                    value: "authenticated".to_owned(),
                    last_subfunction: Some(
                        AuthenticationSubFunction::VerifyProofOfOwnershipBidirectional
                            .name()
                            .to_owned(),
                    ),
                    expires_at: Some("2026-10-09T12:00:00Z".to_owned()),
                    schema: None,
                },
            )
        })
        .with(openapi::error_not_found)
    }

    /// Extracts the decoded response parameters.
    fn response_parameters<R: DiagServiceResponse>(
        response: R,
        binary_encoding: BinaryEncoding,
    ) -> Result<serde_json::Map<String, serde_json::Value>, ApiError> {
        if response.is_empty() {
            return Ok(serde_json::Map::new());
        }
        match response.into_json(binary_encoding) {
            Ok(DiagServiceJsonResponse { data, errors }) => {
                if !errors.is_empty() {
                    tracing::warn!(
                        ?errors,
                        "Failed to decode some authentication response fields"
                    );
                }
                match data {
                    serde_json::Value::Object(map) => Ok(map),
                    serde_json::Value::Null => Ok(serde_json::Map::new()),
                    other => Err(ApiError::InternalServerError(Some(format!(
                        "Expected JSON object but got: {other}"
                    )))),
                }
            }
            Err(e) => Err(ApiError::from(e)),
        }
    }

    #[tracing::instrument(
        skip(locks, uds, security_plugin, request_body),
        fields(
            ecu_name = %ecu_name,
            value = %request_body.value,
            mode_expiration = ?request_body.mode_expiration
        )
    )]
    pub(crate) async fn put<T: UdsEcu + Clone, U: FileManager>(
        UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
        WithRejection(Query(query), _): WithRejection<Query<sovd_modes::Query>, ApiError>,
        BinaryEncodingParam(binary_encoding): BinaryEncodingParam,
        State(WebserverEcuState {
            ecu_name,
            uds,
            locks,
            ..
        }): State<WebserverEcuState<T, U>>,
        WithRejection(Json(request_body), _): WithRejection<
            Json<sovd_modes::authentication::put::Request>,
            ApiError,
        >,
    ) -> Response {
        let include_schema = query.include_schema;
        let authentication_guard = match locks
            .authentication_write_guard(
                &security_plugin.as_auth_plugin().claims(),
                &ecu_name,
                include_schema,
            )
            .await
        {
            Ok(guard) => guard,
            Err(error) => return error.into_response(),
        };
        // Keep the UDS operation and its state update alive if the HTTP request
        // is cancelled after transmission. Cleanup waits for this guard.
        let task = cda_interfaces::spawn_named!("ecu-authentication", async move {
            let _authentication_guard = authentication_guard;
            execute_put(
                &uds,
                &ecu_name,
                security_plugin as DynamicPlugin,
                request_body,
                include_schema,
                binary_encoding,
            )
            .await
        });
        match task.await {
            Ok(response) => response,
            Err(error) => {
                tracing::error!(%error, "Authentication task failed");
                error_response(
                    ApiError::InternalServerError(Some("Authentication task failed".to_owned())),
                    include_schema,
                )
            }
        }
    }

    /// Executes an authorized `PUT /modes/authentication`.
    pub(crate) async fn execute_put<T: UdsEcu>(
        uds: &T,
        ecu_name: &str,
        security_plugin: DynamicPlugin,
        request_body: sovd_modes::authentication::put::Request,
        include_schema: bool,
        binary_encoding: BinaryEncoding,
    ) -> Response {
        let sub_function = match request_body.value.parse::<AuthenticationSubFunction>() {
            Ok(sf) => sf,
            Err(e) => return error_response(ApiError::from(e), include_schema),
        };
        if sub_function == AuthenticationSubFunction::DeAuthenticate
            && request_body.mode_expiration.is_some()
        {
            return error_response(
                ApiError::BadRequest("mode_expiration must not be set for deAuthenticate".into()),
                include_schema,
            );
        }

        let parameters = request_body
            .parameters
            .map(|p| UdsPayloadData::ParameterMap(p.into_iter().collect(), binary_encoding));

        let response = match uds
            .authenticate(
                ecu_name,
                sub_function,
                parameters,
                &security_plugin,
                request_body.mode_expiration.map(Duration::from_secs),
            )
            .await
        {
            Ok(response) => response,
            Err(e) => return error_response(ApiError::from(e), include_schema),
        };

        if response.response_type() == DiagServiceResponseType::Negative {
            return api_error_from_diag_response(&response, include_schema);
        }

        let parameters = match response_parameters(response, binary_encoding) {
            Ok(p) => p,
            Err(e) => return error_response(e, include_schema),
        };
        let schema = if include_schema {
            Some(create_schema!(sovd_modes::authentication::put::Response))
        } else {
            None
        };
        (
            StatusCode::OK,
            Json(sovd_modes::authentication::put::Response {
                id: AUTHENTICATION_ID.to_owned(),
                value: sub_function.name().to_owned(),
                parameters,
                schema,
            }),
        )
            .into_response()
    }

    pub(crate) fn docs_put(op: TransformOperation) -> TransformOperation {
        op.description(
            "Send one UDS Authentication (0x29) request. `value` is the sub-function name of ISO \
             14229-1 Table 74, `parameters` the request parameters. Multi-step procedures are \
             orchestrated by the client.",
        )
        .input::<Json<sovd_modes::authentication::put::Request>>()
        .response_with::<200, Json<sovd_modes::authentication::put::Response>, _>(|res| {
            res.description("Positive response of the ECU with decoded parameters")
                .example(sovd_modes::authentication::put::Response {
                    id: AUTHENTICATION_ID.to_owned(),
                    value: AuthenticationSubFunction::RequestChallengeForAuthentication
                        .name()
                        .to_owned(),
                    parameters: serde_json::Map::new(),
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

pub(crate) mod commctrl {
    use aide::{UseApi, transform::TransformOperation};
    use axum::{
        Json,
        extract::{Query, State},
        response::Response,
    };
    use axum_extra::extract::WithRejection;
    use cda_interfaces::{SchemaProvider, UdsEcu, file_manager::FileManager, service_ids};
    use cda_plugin_security::Secured;
    use sovd_interfaces::{
        common::modes::{COMM_CONTROL_ID, COMM_CONTROL_NAME},
        components::ecu::modes as sovd_modes,
    };

    use crate::{
        openapi,
        sovd::{
            WebserverEcuState,
            binary_encoding::BinaryEncodingParam,
            components::ecu::modes::{handle_mode_change, handle_mode_get},
            error::ApiError,
        },
    };

    pub(crate) async fn get<T: UdsEcu + SchemaProvider + Clone, U: FileManager>(
        UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
        WithRejection(Query(query), _): WithRejection<Query<sovd_modes::Query>, ApiError>,
        State(WebserverEcuState {
            ecu_name,
            uds,
            locks,
            ..
        }): State<WebserverEcuState<T, U>>,
    ) -> Response {
        handle_mode_get(
            &uds,
            &ecu_name,
            service_ids::COMMUNICATION_CONTROL,
            &locks,
            security_plugin,
            query.include_schema,
            |value, schema| sovd_modes::commctrl::get::Response {
                name: Some(COMM_CONTROL_NAME.to_owned()),
                value: Some(value),
                translation_id: None,
                schema,
            },
        )
        .await
    }

    pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
        op.description("Retrieve the active communication control.")
            .response_with::<200, Json<sovd_modes::security_and_session::get::Response>, _>(|res| {
                res.description("Current comm control value for the ECU")
                    .example(sovd_modes::security_and_session::get::Response {
                        name: Some(COMM_CONTROL_NAME.to_owned()),
                        translation_id: None,
                        value: Some("locked".to_owned()),
                        schema: None,
                    })
            })
            .with(openapi::error_not_found)
    }

    pub(crate) async fn put<T: UdsEcu + Clone, U: FileManager>(
        UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
        WithRejection(Query(query), _): WithRejection<Query<sovd_modes::Query>, ApiError>,
        BinaryEncodingParam(binary_encoding): BinaryEncodingParam,
        State(WebserverEcuState {
            ecu_name,
            uds,
            locks,
            ..
        }): State<WebserverEcuState<T, U>>,
        WithRejection(Json(request_body), _): WithRejection<
            Json<sovd_modes::commctrl::put::Request>,
            ApiError,
        >,
    ) -> Response {
        handle_mode_change::<T>(
            &uds,
            &ecu_name,
            security_plugin,
            &locks,
            service_ids::COMMUNICATION_CONTROL,
            &request_body.value,
            request_body.parameters,
            COMM_CONTROL_ID,
            query.include_schema,
            binary_encoding,
        )
        .await
    }

    pub(crate) fn docs_put(op: TransformOperation) -> TransformOperation {
        op.description("Change the communication mode.")
            .input::<Json<sovd_modes::commctrl::put::Request>>()
            .response_with::<200, Json<sovd_modes::commctrl::put::Response>, _>(|res| {
                res.description("Communication mode updated").example(
                    sovd_modes::commctrl::put::Response {
                        id: COMM_CONTROL_ID.to_owned(),
                        value: "off".to_owned(),
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

pub(crate) mod dtcsetting {
    use aide::{UseApi, transform::TransformOperation};
    use axum::{
        Json,
        extract::{Query, State},
        response::Response,
    };
    use axum_extra::extract::WithRejection;
    use cda_interfaces::{SchemaProvider, UdsEcu, file_manager::FileManager, service_ids};
    use cda_plugin_security::Secured;
    use sovd_interfaces::{
        common::modes::{DTC_SETTING_ID, DTC_SETTING_NAME},
        components::ecu::modes as sovd_modes,
    };

    use crate::{
        openapi,
        sovd::{
            WebserverEcuState,
            binary_encoding::BinaryEncodingParam,
            components::ecu::modes::{handle_mode_change, handle_mode_get},
            error::ApiError,
        },
    };

    pub(crate) async fn get<T: UdsEcu + SchemaProvider + Clone, U: FileManager>(
        UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
        WithRejection(Query(query), _): WithRejection<Query<sovd_modes::Query>, ApiError>,
        State(WebserverEcuState {
            ecu_name,
            uds,
            locks,
            ..
        }): State<WebserverEcuState<T, U>>,
    ) -> Response {
        handle_mode_get(
            &uds,
            &ecu_name,
            service_ids::CONTROL_DTC_SETTING,
            &locks,
            security_plugin,
            query.include_schema,
            |value, schema| sovd_modes::dtcsetting::get::Response {
                name: Some(DTC_SETTING_NAME.to_owned()),
                value: Some(value),
                translation_id: None,
                schema,
            },
        )
        .await
    }

    pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
        op.description("Retrieve the active dtc setting")
            .response_with::<200, Json<sovd_modes::dtcsetting::get::Response>, _>(|res| {
                res.description("Current comm control value for the ECU")
                    .example(sovd_modes::security_and_session::get::Response {
                        name: Some(DTC_SETTING_ID.to_owned()),
                        translation_id: None,
                        value: Some("enablerxandenabletx".to_owned()),
                        schema: None,
                    })
            })
            .with(openapi::error_not_found)
    }

    pub(crate) async fn put<T: UdsEcu + Clone, U: FileManager>(
        UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
        WithRejection(Query(query), _): WithRejection<Query<sovd_modes::Query>, ApiError>,
        BinaryEncodingParam(binary_encoding): BinaryEncodingParam,
        State(WebserverEcuState {
            ecu_name,
            uds,
            locks,
            ..
        }): State<WebserverEcuState<T, U>>,
        WithRejection(Json(request_body), _): WithRejection<
            Json<sovd_modes::dtcsetting::put::Request>,
            ApiError,
        >,
    ) -> Response {
        handle_mode_change::<T>(
            &uds,
            &ecu_name,
            security_plugin,
            &locks,
            service_ids::CONTROL_DTC_SETTING,
            &request_body.value,
            request_body.parameters,
            DTC_SETTING_ID,
            query.include_schema,
            binary_encoding,
        )
        .await
    }

    pub(crate) fn docs_put(op: TransformOperation) -> TransformOperation {
        op.description("Change the dtc setting mode.")
            .input::<Json<sovd_modes::commctrl::put::Request>>()
            .response_with::<200, Json<sovd_modes::commctrl::put::Response>, _>(|res| {
                res.description("Dtc setting mode updated").example(
                    sovd_modes::commctrl::put::Response {
                        id: DTC_SETTING_ID.to_owned(),
                        value: "true".to_owned(),
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

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use aide::UseApi;
    use axum::{
        Json,
        extract::{Query, State},
        http::StatusCode,
    };
    use axum_extra::extract::WithRejection;
    use cda_interfaces::{
        Connectivity, DiagServiceError, EcuState,
        authentication::{AuthenticationState, AuthenticationStatus, AuthenticationSubFunction},
        diagservices::{
            DiagServiceJsonResponse, DiagServiceResponseType, mock::MockDiagServiceResponse,
        },
        file_manager::mock::MockFileManager,
        mock::{MockUdsEcu, mock_ecu_state_online_variant_detected},
    };
    use cda_plugin_security::{Secured, mock::TestSecurityPlugin};
    use sovd_interfaces::components::ecu::modes as sovd_modes;

    use super::authentication;
    use crate::sovd::tests::create_test_webserver_state;

    const ECU: &str = "TestECU";

    fn request(
        value: &str,
        mode_expiration: Option<u64>,
    ) -> sovd_modes::authentication::put::Request {
        sovd_modes::authentication::put::Request {
            value: value.to_owned(),
            mode_expiration,
            parameters: None,
        }
    }

    async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    async fn put(
        uds: &MockUdsEcu,
        body: sovd_modes::authentication::put::Request,
    ) -> axum::response::Response {
        authentication::execute_put(
            uds,
            ECU,
            Box::new(()),
            body,
            false,
            cda_interfaces::BinaryEncoding::Hex,
        )
        .await
    }

    fn positive_response() -> MockDiagServiceResponse {
        let mut response = MockDiagServiceResponse::new();
        response
            .expect_response_type()
            .returning(|| DiagServiceResponseType::Positive);
        response.expect_is_empty().returning(|| false);
        response.expect_into_json().returning(|_| {
            Ok(DiagServiceJsonResponse {
                data: serde_json::json!({"challengeServer": "0x01 0x02"}),
                errors: vec![],
            })
        });
        response
    }

    #[tokio::test]
    async fn put_unknown_subfunction_is_bad_request() {
        let uds = MockUdsEcu::new();
        let response = put(&uds, request("foo", None)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn put_deauthenticate_with_expiration_is_bad_request() {
        let uds = MockUdsEcu::new();
        let response = put(&uds, request("deAuthenticate", Some(10))).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn put_missing_service_is_not_found() {
        let mut uds = MockUdsEcu::new();
        uds.expect_authenticate()
            .returning(|_, _, _, _, _| Err(DiagServiceError::NotFound("none".to_owned())));
        let response = put(&uds, request("transmitCertificate", None)).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn put_negative_response_is_bad_gateway() {
        let mut uds = MockUdsEcu::new();
        uds.expect_authenticate().returning(|_, _, _, _, _| {
            let mut response = MockDiagServiceResponse::new();
            response
                .expect_response_type()
                .returning(|| DiagServiceResponseType::Negative);
            response.expect_as_nrc().returning(|| {
                Ok(cda_interfaces::diagservices::MappedNRC {
                    code: Some(0x58),
                    description: Some("invalidSignature".to_owned()),
                    sid: Some(0x29),
                })
            });
            Ok(response)
        });
        let response = put(&uds, request("verifyProofOfOwnershipBidirectional", None)).await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn put_positive_returns_parameters_and_passes_expiration() {
        let mut uds = MockUdsEcu::new();
        uds.expect_authenticate()
            .withf(|ecu, sf, _, _, expiration| {
                ecu == ECU
                    && *sf == AuthenticationSubFunction::RequestChallengeForAuthentication
                    && *expiration == Some(Duration::from_secs(30))
            })
            .times(1)
            .returning(|_, _, _, _, _| Ok(positive_response()));

        let response = put(&uds, request("REQUESTCHALLENGEFORAUTHENTICATION", Some(30))).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(
            body.pointer("/id").and_then(serde_json::Value::as_str),
            Some("authentication")
        );
        assert_eq!(
            body.pointer("/value").and_then(serde_json::Value::as_str),
            Some("requestChallengeForAuthentication")
        );
        assert_eq!(
            body.pointer("/parameters/challengeServer")
                .and_then(serde_json::Value::as_str),
            Some("0x01 0x02")
        );
    }

    #[test]
    fn get_response_reports_state_and_extensions() {
        let state = AuthenticationState {
            status: AuthenticationStatus::Authenticated,
            last_subfunction: Some(AuthenticationSubFunction::ProofOfOwnership),
            expires_at: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(60)),
        };
        let value =
            serde_json::to_value(authentication::get_response(&state, false, None)).unwrap();
        assert_eq!(
            value.pointer("/value").and_then(serde_json::Value::as_str),
            Some("authenticated")
        );
        assert_eq!(
            value
                .pointer("/x-sovd2uds-last-subfunction")
                .and_then(serde_json::Value::as_str),
            Some("proofOfOwnership")
        );
        assert_eq!(
            value
                .pointer("/x-sovd2uds-expires-at")
                .and_then(serde_json::Value::as_str),
            Some("1970-01-01T00:01:00Z")
        );

        let value = serde_json::to_value(authentication::get_response(
            &AuthenticationState::default(),
            true,
            None,
        ))
        .unwrap();
        assert_eq!(
            value.pointer("/value").and_then(serde_json::Value::as_str),
            Some("offline")
        );
        assert!(value.get("x-sovd2uds-last-subfunction").is_none());
        assert!(value.get("x-sovd2uds-expires-at").is_none());
    }

    #[tokio::test]
    async fn get_handler_reports_offline() {
        let mut uds = MockUdsEcu::new();
        uds.expect_get_ecu_state().returning(|_| {
            Ok(EcuState {
                connectivity: Connectivity::Offline,
                ..mock_ecu_state_online_variant_detected()
            })
        });
        uds.expect_get_ecu_authentication_state()
            .returning(|_| Ok(AuthenticationState::default()));
        let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
            ECU.to_owned(),
            uds,
            MockFileManager::new(),
        );

        let response = authentication::get::<MockUdsEcu, MockFileManager>(
            UseApi(
                Secured(Box::new(TestSecurityPlugin)),
                std::marker::PhantomData,
            ),
            WithRejection(
                Query(sovd_modes::Query {
                    include_schema: false,
                }),
                std::marker::PhantomData,
            ),
            State(state),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            body_json(response)
                .await
                .pointer("/value")
                .and_then(serde_json::Value::as_str),
            Some("offline")
        );
    }

    #[tokio::test]
    async fn put_handler_requires_lock() {
        let state = create_test_webserver_state::<MockUdsEcu, MockFileManager>(
            ECU.to_owned(),
            MockUdsEcu::new(),
            MockFileManager::new(),
        );

        let response = authentication::put::<MockUdsEcu, MockFileManager>(
            UseApi(
                Secured(Box::new(TestSecurityPlugin)),
                std::marker::PhantomData,
            ),
            WithRejection(
                Query(sovd_modes::Query {
                    include_schema: false,
                }),
                std::marker::PhantomData,
            ),
            crate::sovd::binary_encoding::BinaryEncodingParam(cda_interfaces::BinaryEncoding::Hex),
            State(state),
            WithRejection(
                Json(request("deAuthenticate", None)),
                std::marker::PhantomData,
            ),
        )
        .await;

        assert!(
            response.status() == StatusCode::CONFLICT || response.status() == StatusCode::LOCKED,
            "unexpected status {}",
            response.status()
        );
    }
}
