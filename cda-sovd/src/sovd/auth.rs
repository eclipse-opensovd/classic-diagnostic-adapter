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
use axum::{Json, RequestPartsExt, http::StatusCode, response::IntoResponse};
use axum_extra::{
    TypedHeader,
    extract::WithRejection,
    headers::{Authorization, authorization::Bearer},
};
use http::request::Parts;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    plugins::{
        AuthApi, AuthError, Claims as ClaimsTrait, SecurityApi, SecurityPlugin,
        SecurityPluginInitializer, SecurityPluginType,
    },
    sovd::error::{ApiError, ErrorWrapper},
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

pub(crate) async fn authorize(
    WithRejection(Json(payload), _): WithRejection<Json<AuthPayload>, ApiError>,
) -> impl IntoApiResponse {
    // Check if the user sent the credentials
    if let Err(e) = check_auth_payload(&payload) {
        return ErrorWrapper {
            error: ApiError::Forbidden(Some(format!("{e:?}"))),
            include_schema: false,
        }
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
            return ErrorWrapper {
                error: ApiError::InternalServerError(None),
                include_schema: false,
            }
            .into_response();
        }
    };

    // Send the authorized token
    (StatusCode::OK, Json(AuthBody::new(token, claims.exp))).into_response()
}

impl AuthBody {
    fn new(access_token: String, expires_in: usize) -> Self {
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

pub struct DefaultAuthPlugin {
    claims: Claims,
}

#[derive(Default)]
pub struct DefaultAuthPluginInitializer;
impl SecurityPluginType for DefaultAuthPluginInitializer {}

#[async_trait]
impl SecurityPluginInitializer for DefaultAuthPluginInitializer {
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

        Ok(Box::new(DefaultAuthPlugin {
            claims: token_data.claims,
        }))
    }
}

impl AuthApi for DefaultAuthPlugin {
    fn claims(&self) -> Box<&dyn ClaimsTrait> {
        Box::new(&self.claims)
    }
}

impl SecurityApi for DefaultAuthPlugin {}

impl SecurityPlugin for DefaultAuthPlugin {
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
pub(crate) struct Claims {
    // dummy implementation for now
    // must be filled with remaining fields
    // once we are using a proper auth provider
    pub(crate) sub: String,
    exp: usize,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct AuthBody {
    access_token: String,
    token_type: String,
    expires_in: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct AuthPayload {
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
