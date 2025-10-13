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

use std::sync::LazyLock;

use aide::axum::IntoApiResponse;
use async_trait::async_trait;
use axum::{Json, RequestPartsExt, body::Bytes, http::StatusCode, response::IntoResponse};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};
use http::request::Parts;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sovd_interfaces::error::{ApiErrorResponse, ErrorCode};

use crate::{
    AuthApi, AuthError, AuthorizationRequestHandler, Claims as ClaimsTrait, SecurityApi,
    SecurityPlugin, SecurityPluginInitializer, SecurityPluginLoader,
};

// allowed because the variant for enabled auth needs the Result
#[allow(clippy::unnecessary_wraps)]
#[cfg(not(feature = "auth"))]
#[tracing::instrument(skip(_payload))]
fn check_auth_payload(_payload: &AuthPayload) -> Result<(), AuthError> {
    tracing::debug!("Skipping auth payload check, ignoring credentials");
    Ok(())
}

#[cfg(feature = "auth")]
fn check_auth_payload(payload: &AuthPayload) -> Result<(), AuthError> {
    // Check if the user sent the credentials
    if payload.client_id.is_empty() || payload.client_secret.is_empty() {
        return Err(AuthError::MissingCredentials);
    }

    if payload.client_secret != "secret" {
        return Err(AuthError::WrongCredentials);
    }

    Ok(())
}

impl AuthBody {
    pub fn new(access_token: String, expires_in: usize) -> Self {
        Self {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in,
        }
    }
}

#[cfg(feature = "auth")]
fn validation() -> Validation {
    Validation::default()
}

#[cfg(not(feature = "auth"))]
fn validation() -> Validation {
    let mut validation = Validation::default();
    validation.insecure_disable_signature_validation();
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.validate_nbf = false;
    validation
}

impl ClaimsTrait for Claims {
    fn sub(&self) -> &str {
        &self.sub
    }

    fn exp(&self) -> usize {
        self.exp
    }
}

pub struct DefaultSecurityPluginData {
    claims: Claims,
}

#[derive(Default)]
pub struct DefaultSecurityPlugin;
impl SecurityPluginLoader for DefaultSecurityPlugin {}

#[async_trait]
impl AuthorizationRequestHandler for DefaultSecurityPlugin {
    async fn authorize(body_bytes: Bytes) -> impl IntoApiResponse {
        let payload = match axum::extract::Json::<AuthPayload>::from_bytes(&body_bytes) {
            Ok(payload) => payload.0,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to parse auth payload");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ApiErrorResponse::<String> {
                        message: e.to_string(),
                        error_code: ErrorCode::VendorSpecific,
                        vendor_code: Some("bad-request".to_string()),
                        parameters: None,
                        error_source: None,
                        schema: None,
                    }),
                )
                    .into_response();
            }
        };

        // Check if the user sent the credentials
        if let Err(e) = check_auth_payload(&payload) {
            return (
                StatusCode::FORBIDDEN,
                Json(ApiErrorResponse::<()> {
                    message: e.to_string(),
                    error_code: ErrorCode::InsufficientAccessRights,
                    vendor_code: None,
                    parameters: None,
                    error_source: None,
                    schema: None,
                }),
            )
                .into_response();
        }

        let claims = Claims {
            sub: payload.client_id,
            exp: 2_000_000_000, // May 2033
        };
        // Create the authorization token
        let token = match encode(&Header::default(), &claims, &KEYS.encoding) {
            Ok(token) => token,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiErrorResponse::<()> {
                        message: "Internal server error".to_string(),
                        error_code: ErrorCode::SovdServerFailure,
                        vendor_code: None,
                        parameters: None,
                        error_source: None,
                        schema: None,
                    }),
                )
                    .into_response();
            }
        };

        // Send the authorized token
        (StatusCode::OK, Json(AuthBody::new(token, claims.exp))).into_response()
    }
}

#[async_trait]
impl SecurityPluginInitializer for DefaultSecurityPlugin {
    async fn initialize_from_request_parts(
        &self,
        parts: &mut Parts,
    ) -> Result<Box<dyn SecurityPlugin>, AuthError> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "Failed to extract token");
                AuthError::NoTokenProvided
            })?;
        // Decode the user data
        let token_data =
            decode::<Claims>(bearer.token(), &KEYS.decoding, &validation()).map_err(|e| {
                tracing::warn!(error = %e, "Failed to decode token");
                AuthError::InvalidToken {
                    details: "Token could not be decoded".to_string(),
                }
            })?;

        Ok(Box::new(DefaultSecurityPluginData {
            claims: token_data.claims,
        }))
    }
}

impl AuthApi for DefaultSecurityPluginData {
    fn claims(&self) -> Box<&dyn ClaimsTrait> {
        Box::new(&self.claims)
    }
}

impl SecurityApi for DefaultSecurityPluginData {
    fn validate_service(
        &self,
        _service: &cda_database::datatypes::DiagService,
    ) -> Result<(), cda_interfaces::DiagServiceError> {
        Ok(())
    }
}

impl SecurityPlugin for DefaultSecurityPluginData {
    fn as_auth_plugin(&self) -> &dyn AuthApi {
        self
    }

    fn as_security_plugin(&self) -> &dyn SecurityApi {
        self
    }
}

struct Keys {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl Keys {
    fn new(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Claims {
    // dummy implementation for now
    // must be filled with remaining fields
    // once we are using a proper auth provider
    sub: String,
    exp: usize,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct AuthBody {
    access_token: String,
    token_type: String,
    expires_in: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AuthPayload {
    client_id: String,
    // allowing unused because client_secret
    // will not be used when auth feature is disabled
    #[allow(unused)]
    client_secret: String,
}

static KEYS: LazyLock<Keys> = LazyLock::new(|| {
    // todo, set up proper secret when adding jwt provider in
    Keys::new("secret".as_bytes())
});
