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
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::sovd::error::{ApiError, ErrorWrapper};

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
        Ok(token_data.claims)
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        // If auth header was missing return 401 without body,
        // else return sovd error with 403 and the error message
        // see SOVD 6.15.6 Request Header for Access-Restricted Resources
        let error_message = match &self {
            AuthError::NoTokenProvided => return StatusCode::UNAUTHORIZED.into_response(),
            error => error.to_string(),
        };
        ErrorWrapper {
            error: ApiError::Forbidden(Some(error_message)),
            include_schema: false,
        }
        .into_response()
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

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
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

// allowing dead code because WrongCredentials and MissingCredentials
// are only used when the auth feature is enabled
#[allow(dead_code)]
#[derive(Error, Debug)]
pub(crate) enum AuthError {
    #[error("No token provided in the request")]
    NoTokenProvided,
    #[error("Wrong credentials provided in the request")]
    WrongCredentials,
    #[error("No credentials provided in the request")]
    MissingCredentials,
    #[error("Invalid token: {details}")]
    InvalidToken { details: String },
}

static KEYS: LazyLock<Keys> = LazyLock::new(|| {
    // todo, set up proper secret when adding jwt provider in
    Keys::new("secret".as_bytes())
});
