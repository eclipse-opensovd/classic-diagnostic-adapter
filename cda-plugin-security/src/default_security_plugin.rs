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

//! # Default Security Plugin Implementation
//!
//! This module provides the default security plugin implementation that demonstrates
//! the security plugin architecture and provides a functional JWT-based authentication
//! system for development and production use.
//!
//! ## JWT-Based Authentication
//!
//! The default implementation uses JSON Web Tokens (JWT) for stateless authentication:
//! - Supports configurable token expiration
//! - Implements Bearer token authentication for API requests
//! - Provides secure token validation with signature verification
//!
//! ## Feature-Based Security
//!
//! The default plugin supports conditional compilation features:
//! - **auth feature disabled**: Bypasses credential validation (development/testing)
//! - **auth feature enabled**: Enforces proper credential validation (production)
//!
//! ## Authorization Endpoint Example
//!
//! The implementation provides an example authorization endpoint that:
//! - Accepts client credentials (`client_id`, `client_secret`)
//! - Validates credentials against a simple authentication mechanism
//! - Returns JWT access tokens for subsequent API requests
//! - Handles authentication errors with appropriate HTTP status codes
//!
//! ## Token Validation
//!
//! Token validation includes:
//! - Extraction of Bearer tokens from Authorization headers
//! - JWT signature validation (when auth feature is enabled)
//! - Token expiration checking
//! - User claims extraction for downstream services

use std::sync::LazyLock;

use aide::axum::IntoApiResponse;
use async_trait::async_trait;
use axum::{Json, RequestPartsExt, body::Bytes, http::StatusCode, response::IntoResponse};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};
use http::{HeaderMap, request::Parts};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, encode};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
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

#[cfg(not(feature = "auth"))]
fn decode_token<T: DeserializeOwned>(
    token: &str,
    _key: &DecodingKey,
) -> Result<TokenData<T>, AuthError> {
    decode_token_impl(jsonwebtoken::dangerous::insecure_decode::<T>(token))
}

#[cfg(feature = "auth")]
fn decode_token<T: DeserializeOwned>(
    token: &str,
    key: &DecodingKey,
) -> Result<TokenData<T>, AuthError> {
    decode_token_impl(jsonwebtoken::decode::<T>(
        token,
        key,
        &jsonwebtoken::Validation::default(),
    ))
}

fn decode_token_impl<T>(
    result: Result<TokenData<T>, jsonwebtoken::errors::Error>,
) -> Result<TokenData<T>, AuthError> {
    result.map_err(|e| {
        tracing::warn!(error = %e, "Failed to decode token");
        AuthError::InvalidToken {
            details: "Token could not be decoded".to_string(),
        }
    })
}

impl ClaimsTrait for Claims {
    fn sub(&self) -> &str {
        &self.sub
    }
}

/// Default security plugin data containing validated user claims.
///
/// This struct represents an initialized security plugin instance that contains
/// validated JWT claims. It implements both [`AuthApi`] and [`SecurityApi`] to
/// provide complete authentication and authorization capabilities.
pub struct DefaultSecurityPluginData {
    claims: Claims,
}

/// Default security plugin implementation.
///
/// This is the default security plugin that provides JWT-based authentication
/// and basic authorization capabilities. It serves as both a functional
/// implementation for development/production use and as an example for
/// custom security plugin implementations.
///
/// ## Features
///
/// - JWT token generation and validation
/// - Bearer token authentication
/// - Feature-based credential validation
/// - SOVD-compliant error responses
/// - Integration with authorization endpoint
///
/// ### Feature flags
/// The default plugin supports conditional compilation features:
/// - **auth feature disabled**: Bypasses credential validation (development/testing)
/// - **auth feature enabled**: Enforces proper credential validation (production)
///
#[derive(Default)]
pub struct DefaultSecurityPlugin;
impl SecurityPluginLoader for DefaultSecurityPlugin {}

#[async_trait]
impl AuthorizationRequestHandler for DefaultSecurityPlugin {
    async fn authorize(_headers: HeaderMap, body_bytes: Bytes) -> impl IntoApiResponse {
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
        let Ok(token) = encode(&Header::default(), &claims, &KEYS.encoding) else {
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
        let token_data = decode_token::<Claims>(bearer.token(), &KEYS.decoding)?;

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

/// JWT claims structure for the default security plugin.
///
/// This struct represents the claims contained within JWT tokens issued by
/// the default security plugin. It includes standard JWT claims for user
/// identification and token validation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Claims {
    // dummy implementation for now
    // must be filled with remaining fields
    // once we are using a proper auth provider
    /// Subject (user identifier) of the token
    sub: String,
    /// Expiration time as Unix timestamp
    exp: usize,
}

/// Authorization response body containing access token information.
///
/// This struct represents the successful response from the authorization endpoint,
/// containing the access token and related metadata according to OAuth 2.0 standards.
#[derive(Debug, Serialize, JsonSchema)]
pub struct AuthBody {
    /// The access token string (JWT)
    access_token: String,
    /// The type of token (always "Bearer")
    token_type: String,
    /// Token expiration time in seconds from epoch
    expires_in: usize,
}

/// Authorization request payload containing client credentials.
///
/// This struct represents the request body for the authorization endpoint,
/// containing the client credentials required for authentication.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct AuthPayload {
    /// Client identifier for authentication
    client_id: String,
    /// Client secret for authentication
    // allowing unused because client_secret
    // will not be used when auth feature is disabled
    #[allow(unused)]
    client_secret: String,
}

static KEYS: LazyLock<Keys> = LazyLock::new(|| {
    // todo, set up proper secret when adding jwt provider in
    Keys::new("secret".as_bytes())
});
