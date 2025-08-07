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

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use axum_extra::extract::WithRejection;
use cda_interfaces::{
    UdsEcu,
    datatypes::semantics,
    diagservices::{DiagServiceResponse, DiagServiceResponseType},
    file_manager::FileManager,
};
use hashbrown::HashMap;
use serde::Serialize;
use sovd_interfaces::components::ecu::modes as sovd_modes;

use crate::sovd::{
    WebserverEcuState,
    auth::Claims,
    error::{ApiError, api_error_from_diag_response},
    locks::validate_lock,
};

const SESSION_NAME: &str = "Diagnostic session";
const SECURITY_NAME: &str = "Security access";

pub(crate) async fn get() -> Response {
    (
        StatusCode::OK,
        Json(sovd_modes::get::Response {
            items: vec![
                sovd_modes::Mode {
                    id: Some(semantics::SESSION.to_owned()),
                    name: Some(SESSION_NAME.to_string()),
                    translation_id: None,
                    value: None,
                },
                sovd_modes::Mode {
                    id: Some(semantics::SECURITY.to_owned()),
                    name: Some(SECURITY_NAME.to_string()),
                    translation_id: None,
                    value: None,
                },
            ],
        }),
    )
        .into_response()
}

pub(crate) mod session {
    use super::*;

    pub(crate) async fn put<
        R: DiagServiceResponse + Send + Sync,
        T: UdsEcu + Send + Sync + Clone,
        U: FileManager + Send + Sync + Clone,
    >(
        claims: Claims,
        State(WebserverEcuState {
            locks,
            uds,
            ecu_name,
            ..
        }): State<WebserverEcuState<R, T, U>>,
        WithRejection(Json(request_body), _): WithRejection<
            Json<sovd_modes::put::Request>,
            ApiError,
        >,
    ) -> Response {
        if let Some(response) = validate_lock(&claims, &ecu_name, locks).await {
            return response;
        }
        log::info!("sovd set session to {}", request_body.value);
        match uds
            .set_ecu_session(
                &ecu_name,
                &request_body.value,
                Duration::from_secs(request_body.mode_expiration.unwrap_or(u64::MAX)),
            )
            .await
        {
            Ok(response) => match response.response_type() {
                DiagServiceResponseType::Positive => (
                    StatusCode::OK,
                    Json(sovd_modes::put::Response {
                        id: semantics::SECURITY.to_owned(),
                        value: request_body.value.clone(),
                    }),
                )
                    .into_response(),
                DiagServiceResponseType::Negative => api_error_from_diag_response(response),
            },
            Err(e) => ApiError::from(e).into_response(),
        }
    }

    pub(crate) async fn get<
        R: DiagServiceResponse + Send + Sync,
        T: UdsEcu + Send + Sync + Clone,
        U: FileManager + Send + Sync + Clone,
    >(
        State(WebserverEcuState { uds, ecu_name, .. }): State<WebserverEcuState<R, T, U>>,
    ) -> Response {
        match uds.ecu_session(&ecu_name).await {
            Ok(security_mode) => (
                StatusCode::OK,
                Json(&sovd_modes::Mode {
                    id: None,
                    name: Some(semantics::SESSION.to_owned()),
                    value: Some(security_mode),
                    translation_id: None,
                }),
            )
                .into_response(),
            Err(e) => {
                let api_error: ApiError = e.into();
                api_error.into_response()
            }
        }
    }
}

pub(crate) mod security {
    use cda_interfaces::{SecurityAccess, diagservices::UdsPayloadData};

    use super::*;

    #[derive(Serialize)]
    struct SovdSeed {
        #[serde(rename = "Request_Seed")]
        request_seed: String,
    }

    #[derive(Serialize)]
    struct SovdRequestSeedResponse {
        id: String,
        seed: SovdSeed,
    }

    pub(crate) async fn get<
        R: DiagServiceResponse + Send + Sync,
        T: UdsEcu + Send + Sync + Clone,
        U: FileManager + Send + Sync + Clone,
    >(
        claims: Claims,
        State(WebserverEcuState {
            ecu_name,
            locks,
            uds,
            ..
        }): State<WebserverEcuState<R, T, U>>,
    ) -> Response {
        if let Some(value) = validate_lock(&claims, &ecu_name, locks).await {
            return value;
        }

        match uds.ecu_security_access(&ecu_name).await {
            Ok(security_mode) => (
                StatusCode::OK,
                Json(&sovd_modes::Mode {
                    id: None,
                    name: Some(semantics::SECURITY.to_owned()),
                    value: Some(security_mode),
                    translation_id: None,
                }),
            )
                .into_response(),
            Err(e) => {
                let api_error: ApiError = e.into();
                api_error.into_response()
            }
        }
    }

    pub(crate) async fn put<
        R: DiagServiceResponse + Send + Sync,
        T: UdsEcu + Send + Sync + Clone,
        U: FileManager + Send + Sync + Clone,
    >(
        claims: Claims,
        State(WebserverEcuState {
            uds,
            ecu_name,
            locks,
            ..
        }): State<WebserverEcuState<R, T, U>>,
        WithRejection(Json(request_body), _): WithRejection<
            Json<sovd_modes::put::Request>,
            ApiError,
        >,
    ) -> Response {
        fn split_at_last_underscore(input: &str) -> (String, Option<String>) {
            let parts: Vec<&str> = input.split('_').collect();

            if parts.len() > 2 {
                let last_part = (*parts.last().unwrap()).to_string();
                let remaining = parts[..parts.len() - 1].join("_");
                (remaining, Some(last_part))
            } else {
                (input.to_string(), None)
            }
        }

        if let Some(value) = validate_lock(&claims, &ecu_name, locks).await {
            return value;
        }

        let (level, request_seed_service) = split_at_last_underscore(&request_body.value);
        let key = request_body.key.map(|k| k.send_key);

        if request_seed_service.is_some() && key.is_some() {
            return ApiError::BadRequest(
                "RequestSeed and SendKey cannot be used at the same time.".to_string(),
            )
            .into_response();
        }
        if request_seed_service.is_none() && key.is_none() {
            return ApiError::BadRequest("RequestSeed is not set but no key is given.".to_string())
                .into_response();
        }

        let payload = if let Some(key) = key {
            let mut data = HashMap::new();
            let Ok(value) = serde_json::to_value(&key) else {
                return ApiError::BadRequest("Failed to serialize key".to_string()).into_response();
            };

            data.insert("Send_Key".to_string(), value);
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
                Duration::from_secs(request_body.mode_expiration.unwrap_or(u64::MAX)),
            )
            .await
        {
            Ok((security_access, response)) => match response.response_type() {
                DiagServiceResponseType::Positive => match security_access {
                    SecurityAccess::RequestSeed(_) => {
                        let seed = response
                            .get_raw()
                            .iter()
                            .map(|byte| format!("0x{byte:02x}"))
                            .collect::<Vec<String>>()
                            .join(" ");

                        (
                            StatusCode::OK,
                            Json(SovdRequestSeedResponse {
                                id: semantics::SECURITY.to_owned(),
                                seed: SovdSeed { request_seed: seed },
                            }),
                        )
                            .into_response()
                    }

                    SecurityAccess::SendKey(_) => (
                        StatusCode::OK,
                        Json(sovd_modes::put::Response {
                            id: semantics::SECURITY.to_owned(),
                            value: request_body.value.clone(),
                        }),
                    )
                        .into_response(),
                },
                DiagServiceResponseType::Negative => api_error_from_diag_response(response),
            },
            Err(e) => ApiError::from(e).into_response(),
        }
    }
}
