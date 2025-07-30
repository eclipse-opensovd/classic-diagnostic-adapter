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

use axum::{
    Json, RequestPartsExt,
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use axum_extra::{
    TypedHeader,
    extract::WithRejection,
    headers::{Authorization, authorization::Bearer},
};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::sovd::error::ApiError;

// allowed because the variant for enabled auth needs the Result
#[allow(clippy::unnecessary_wraps)]
#[cfg(not(feature = "auth"))]
fn check_auth_payload(_payload: &AuthPayload) -> Result<(), AuthError> {
    log::debug!("Skipping auth payload check, ignoring credentials");
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
) -> Result<Json<AuthBody>, AuthError> {
    // Check if the user sent the credentials
    check_auth_payload(&payload)?;

    let claims = Claims {
        sub: payload.client_id,
        exp: 2_000_000_000, // May 2033
    };
    // Create the authorization token
    let token = encode(&Header::default(), &claims, &KEYS.encoding)
        .map_err(|_| AuthError::TokenCreation)?;

    // Send the authorized token
    Ok(Json(AuthBody::new(token, claims.exp)))
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

impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|e| {
                log::warn!("Failed to extract token: {e}");
                AuthError::InvalidToken
            })?;
        // Decode the user data
        let token_data =
            decode::<Claims>(bearer.token(), &KEYS.decoding, &validation()).map_err(|e| {
                log::warn!("Failed to decode token: {e}");
                AuthError::InvalidToken
            })?;
        Ok(token_data.claims)
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::WrongCredentials => (StatusCode::UNAUTHORIZED, "Wrong credentials"),
            AuthError::MissingCredentials => (StatusCode::BAD_REQUEST, "Missing credentials"),
            AuthError::TokenCreation => (StatusCode::INTERNAL_SERVER_ERROR, "Token creation error"),
            AuthError::InvalidToken => (StatusCode::BAD_REQUEST, "Invalid token"),
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
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

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Claims {
    // dummy implementation for now
    // must be filled with remaining fields
    // once we are using token master
    pub(crate) sub: String,
    exp: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct AuthBody {
    access_token: String,
    token_type: String,
    expires_in: usize,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AuthPayload {
    client_id: String,
    // allowing unused because client_secret
    // will not be used when auth feature is disabled
    #[allow(unused)]
    client_secret: String,
}

// allowing dead code because WrongCredentials and MissingCredentials
// are only used when the auth feature is enabled
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum AuthError {
    WrongCredentials,
    MissingCredentials,
    TokenCreation,
    InvalidToken,
}

static KEYS: LazyLock<Keys> = LazyLock::new(|| {
    // todo, set up proper secret when adding token master in
    Keys::new("secret".as_bytes())
});
