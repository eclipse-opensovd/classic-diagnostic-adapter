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

//! # Default Security Plugin Implementation
//!
//! This module provides the default security plugin implementation that demonstrates
//! the security plugin architecture and provides a functional JWT-based authentication
//! system for development and testing. It is not production security infrastructure.
//! Production deployments must provide a security plugin appropriate for their threat model.
//!
//! ## JWT-Based Authentication
//!
//! The default implementation uses JSON Web Tokens (JWT) for stateless authentication:
//! - Supports configurable token expiration
//! - Implements Bearer token authentication for API requests
//! - Provides secure token validation with signature verification
//!
//! ## Externally Issued Tokens
//!
//! When a JWKS file is configured, the plugin verifies tokens from an external issuer and does
//! not issue tokens itself. This applies to every build, regardless of the features below. It is
//! still development and test grade: keys are only read at startup and there is no HTTP fetching.
//!
//! - `CDA_AUTH_JWKS_FILE`: JWKS file with the issuer's public keys. Unset or empty disables this
//!   mode.
//! - `CDA_AUTH_ISSUER`: Required `iss`, mandatory when a JWKS file is set.
//! - `CDA_AUTH_AUDIENCE`: Accepted `aud` values, comma-separated. Unset accepts any `aud`.
//!
//! A broken configuration stops the CDA at startup, see [`DefaultSecurityPlugin`]. Every key must
//! have a `kid` and an `alg`, and symmetric keys are refused.
//!
//! ## Feature-Based Security
//!
//! Without a JWKS file, the default plugin supports conditional compilation features:
//! - **auth feature disabled**: Bypasses credential validation and does not verify token
//!   signatures (development/testing)
//! - **auth feature enabled**: Demonstrates credential validation (development/testing)
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
//! - JWT signature validation (when a JWKS file is configured or the auth feature is enabled)
//! - Token expiration checking
//! - User claims extraction for downstream services

use std::{collections::HashMap, sync::LazyLock};

use aide::axum::IntoApiResponse;
use async_trait::async_trait;
use axum::{Json, RequestPartsExt, body::Bytes, http::StatusCode, response::IntoResponse};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};
use http::{HeaderMap, request::Parts};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation, decode, decode_header,
    encode,
    jwk::{AlgorithmParameters, JwkSet},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sovd_interfaces::error::{ApiErrorResponse, ErrorCode};

use crate::{
    AuthApi, AuthError, AuthorizationRequestHandler, Claims as ClaimsTrait, SecurityApi,
    SecurityPlugin, SecurityPluginInitializer, SecurityPluginLoader,
};

#[allow(
    clippy::unnecessary_wraps,
    reason = "Return type must match the feature-enabled auth variant signature"
)]
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
fn decode_builtin_token<T: DeserializeOwned>(
    token: &str,
    _key: &DecodingKey,
) -> Result<TokenData<T>, AuthError> {
    decode_token_impl(jsonwebtoken::dangerous::insecure_decode::<T>(token))
}

#[cfg(feature = "auth")]
fn decode_builtin_token<T: DeserializeOwned>(
    token: &str,
    key: &DecodingKey,
) -> Result<TokenData<T>, AuthError> {
    decode_token_impl(decode::<T>(token, key, &Validation::default()))
}

fn invalid_token() -> AuthError {
    AuthError::InvalidToken {
        details: "Token could not be decoded".to_string(),
    }
}

fn decode_token_impl<T>(
    result: Result<TokenData<T>, jsonwebtoken::errors::Error>,
) -> Result<TokenData<T>, AuthError> {
    result.map_err(|e| {
        tracing::warn!(error = %e, "Failed to decode token");
        invalid_token()
    })
}

fn decode_token<T: DeserializeOwned>(
    token: &str,
    key: &DecodingKey,
) -> Result<TokenData<T>, AuthError> {
    decode_token_with(&EXTERNAL_KEYS, token, key)
}

fn decode_token_with<T: DeserializeOwned>(
    external_keys: &ExternalKeyState,
    token: &str,
    builtin_key: &DecodingKey,
) -> Result<TokenData<T>, AuthError> {
    match external_keys {
        Ok(Some(keys)) => keys.verify(token),
        Ok(None) => decode_builtin_token(token, builtin_key),
        // Falling back here would turn a broken JWKS into no verification at all.
        Err(e) => {
            tracing::error!(error = %e, "Rejecting token, external key configuration is invalid");
            Err(invalid_token())
        }
    }
}

/// Public keys of an external token issuer, loaded from a JWKS.
struct ExternalKeys {
    keys: HashMap<String, (DecodingKey, Validation)>,
    issuer: String,
}

impl ExternalKeys {
    fn new(set: &JwkSet, issuer: &str, audience: &[String]) -> Result<Self, String> {
        let mut keys = HashMap::new();
        for jwk in &set.keys {
            let kid = jwk
                .common
                .key_id
                .clone()
                .ok_or("JWKS key without kid".to_owned())?;
            if matches!(jwk.algorithm, AlgorithmParameters::OctetKey(_)) {
                return Err(format!("JWKS key {kid} is symmetric"));
            }
            let alg: Algorithm = jwk
                .common
                .key_algorithm
                .ok_or_else(|| format!("JWKS key {kid} without alg"))?
                .to_string()
                .parse()
                .map_err(|e| format!("JWKS key {kid} has an unsupported alg: {e}"))?;
            let key = DecodingKey::from_jwk(jwk)
                .map_err(|e| format!("JWKS key {kid} is invalid: {e}"))?;
            if key.family() != alg.family() {
                return Err(format!("JWKS key {kid} does not match its alg {alg:?}"));
            }
            // One algorithm per key, taken from the JWKS and never from the token header.
            // Otherwise a forged HS256 token could use public key material as its secret.
            let mut validation = Validation::new(alg);
            validation.validate_nbf = true;
            validation.set_issuer(&[issuer]);
            if audience.is_empty() {
                // `Validation::new` checks `aud` by default, which would refuse every token that
                // has one when no audience is configured.
                validation.validate_aud = false;
                validation.set_required_spec_claims(&["exp", "iss", "sub"]);
            } else {
                validation.set_audience(audience);
                validation.set_required_spec_claims(&["exp", "iss", "sub", "aud"]);
            }
            if keys.insert(kid.clone(), (key, validation)).is_some() {
                return Err(format!("JWKS key {kid} appears twice"));
            }
        }
        if keys.is_empty() {
            return Err("JWKS holds no key".to_owned());
        }
        Ok(Self {
            keys,
            issuer: issuer.to_owned(),
        })
    }

    fn verify<T: DeserializeOwned>(&self, token: &str) -> Result<TokenData<T>, AuthError> {
        let header = decode_header(token).map_err(|e| {
            tracing::warn!(error = %e, "Failed to decode token header");
            invalid_token()
        })?;
        let Some((key, validation)) = header.kid.as_ref().and_then(|kid| self.keys.get(kid)) else {
            tracing::warn!(kid = ?header.kid, "Token has no known key id");
            return Err(invalid_token());
        };
        decode_token_impl(decode::<T>(token, key, validation))
    }
}

/// `Ok(None)` means no JWKS is configured, `Err` that the configured one is unusable.
type ExternalKeyState = Result<Option<ExternalKeys>, String>;

fn load_external_keys(
    jwks_file: Option<&str>,
    issuer: Option<&str>,
    audience: Option<&str>,
) -> ExternalKeyState {
    let Some(jwks_file) = jwks_file.filter(|file| !file.is_empty()) else {
        return Ok(None);
    };
    let issuer = issuer
        .filter(|issuer| !issuer.is_empty())
        .ok_or(format!("{ENV_ISSUER} is required with {ENV_JWKS_FILE}"))?;
    let audience: Vec<String> = audience
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|aud| !aud.is_empty())
        .map(str::to_owned)
        .collect();
    let jwks = std::fs::read_to_string(jwks_file)
        .map_err(|e| format!("Failed to read JWKS file {jwks_file}: {e}"))?;
    let set: JwkSet = serde_json::from_str(&jwks)
        .map_err(|e| format!("Failed to parse JWKS file {jwks_file}: {e}"))?;
    ExternalKeys::new(&set, issuer, &audience).map(Some)
}

// `std::env::var` is used for its error: a value that is not valid unicode must not read as unset,
// as that would silently disable verification.
fn env_setting(name: &str) -> Result<Option<String>, String> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(e) => Err(format!("{name}: {e}")),
    }
}

fn load_external_keys_from_env() -> ExternalKeyState {
    load_external_keys(
        env_setting(ENV_JWKS_FILE)?.as_deref(),
        env_setting(ENV_ISSUER)?.as_deref(),
        env_setting(ENV_AUDIENCE)?.as_deref(),
    )
}

/// The refusal of `/authorize` while tokens are issued externally. The plugin would otherwise
/// hand out tokens that it does not accept itself.
fn external_issuer_refusal(external_keys: &ExternalKeyState) -> Option<axum::response::Response> {
    (!matches!(external_keys, Ok(None))).then(|| {
        (
            StatusCode::FORBIDDEN,
            Json(ApiErrorResponse::<()> {
                message: "Tokens are issued externally".to_string(),
                error_code: ErrorCode::InsufficientAccessRights,
                vendor_code: None,
                parameters: None,
                error_source: None,
                schema: None,
            }),
        )
            .into_response()
    })
}

impl ClaimsTrait for Claims {
    fn sub(&self) -> &str {
        &self.sub
    }

    fn attributes(&self) -> serde_json::Map<String, serde_json::Value> {
        let mut attributes = self.additional.clone();
        attributes.insert("sub".to_string(), self.sub.clone().into());
        attributes.insert("exp".to_string(), self.exp.into());
        attributes
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
/// Both are overridden by a configured JWKS file, see the module documentation.
///
#[derive(Default)]
pub struct DefaultSecurityPlugin;

impl SecurityPluginLoader for DefaultSecurityPlugin {
    fn check_config() -> Result<(), String> {
        match &*EXTERNAL_KEYS {
            Ok(Some(keys)) => {
                tracing::info!(
                    issuer = %keys.issuer,
                    key_count = keys.keys.len(),
                    "Verifying externally issued tokens"
                );
                Ok(())
            }
            Ok(None) => {
                tracing::info!("No JWKS configured, using built-in token handling");
                Ok(())
            }
            Err(e) => Err(format!("Invalid external token configuration: {e}")),
        }
    }
}

#[async_trait]
impl AuthorizationRequestHandler for DefaultSecurityPlugin {
    async fn authorize(_headers: HeaderMap, body_bytes: Bytes) -> impl IntoApiResponse {
        if let Some(refusal) = external_issuer_refusal(&EXTERNAL_KEYS) {
            return refusal;
        }

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
            additional: serde_json::Map::new(),
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
    /// Subject (user identifier) of the token
    sub: String,
    /// Expiration time as Unix timestamp
    exp: usize,
    /// Additional verified JWT claims exposed to downstream policy plugins.
    #[serde(flatten)]
    additional: serde_json::Map<String, serde_json::Value>,
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
    #[allow(
        unused,
        reason = "client_secret is only used when the auth feature is enabled"
    )]
    client_secret: String,
}

static KEYS: LazyLock<Keys> = LazyLock::new(|| {
    // todo, set up proper secret when adding jwt provider in
    Keys::new("secret".as_bytes())
});

const ENV_JWKS_FILE: &str = "CDA_AUTH_JWKS_FILE";
const ENV_ISSUER: &str = "CDA_AUTH_ISSUER";
const ENV_AUDIENCE: &str = "CDA_AUTH_AUDIENCE";

static EXTERNAL_KEYS: LazyLock<ExternalKeyState> = LazyLock::new(load_external_keys_from_env);

#[cfg(test)]
mod tests {
    use jsonwebtoken::errors::ErrorKind;
    use serde_json::{Value, json};

    use super::*;

    #[test]
    fn decoded_token_preserves_arbitrary_claims() {
        let encoded = encode(
            &Header::default(),
            &json!({
                "sub": "cda-client",
                "exp": 2_000_000_000u64,
                "application": "cda",
                "roles": ["diagnostics", "priority"],
                "context": { "use_case": "recovery" }
            }),
            &KEYS.encoding,
        )
        .expect("test token should encode");

        let decoded = decode_token::<Claims>(&encoded, &KEYS.decoding)
            .expect("test token should decode")
            .claims;
        let attributes = ClaimsTrait::attributes(&decoded);

        assert_eq!(decoded.sub(), "cda-client");
        assert_eq!(attributes.get("application"), Some(&json!("cda")));
        assert_eq!(
            attributes.get("roles"),
            Some(&json!(["diagnostics", "priority"]))
        );
        assert_eq!(
            attributes.get("context"),
            Some(&json!({ "use_case": "recovery" }))
        );
        assert_eq!(attributes.get("sub"), Some(&json!("cda-client")));
        assert_eq!(attributes.get("exp"), Some(&json!(2_000_000_000u64)));
    }

    const ISSUER: &str = "dev-stack";
    const KID: &str = "dev";
    const FAR_FUTURE: u64 = 4_000_000_000;

    // Throwaway Ed25519 keys for these tests only: PKCS#8 body and raw public key.
    const SIGNING_KEY: &str = "MC4CAQAwBQYDK2VwBCIEIFI9raEeVM0BGfxw77astmUbOecjbKrSYLS65C8Oehvy"; // gitleaks:allow
    const PUBLIC_KEY: &str = "BEKRneFdlEvRAlOa_Ga0zG5if1e1yMydbK1LMXbyYPs";
    const OTHER_SIGNING_KEY: &str =
        "MC4CAQAwBQYDK2VwBCIEIJC6TyxDLSQcFR2G0aWqn8ZNxbG8lPJWKmm3DYZpssch"; // gitleaks:allow

    fn ed_key(body: &str) -> EncodingKey {
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n");
        EncodingKey::from_ed_pem(pem.as_bytes()).unwrap()
    }

    fn jwk(kid: &str) -> Value {
        json!({"kty": "OKP", "crv": "Ed25519", "x": PUBLIC_KEY, "kid": kid, "alg": "EdDSA"})
    }

    fn jwks(keys: &[Value]) -> JwkSet {
        serde_json::from_value(json!({ "keys": keys })).unwrap()
    }

    fn keys_with_audience(audience: &[&str]) -> ExternalKeys {
        let audience: Vec<String> = audience.iter().map(|aud| (*aud).to_owned()).collect();
        ExternalKeys::new(&jwks(&[jwk(KID)]), ISSUER, &audience).unwrap()
    }

    fn keys() -> ExternalKeys {
        keys_with_audience(&[])
    }

    fn load_error(keys: &[Value]) -> String {
        match ExternalKeys::new(&jwks(keys), ISSUER, &[]) {
            Ok(_) => panic!("JWKS should be refused"),
            Err(e) => e,
        }
    }

    fn claims() -> Value {
        json!({"sub": "tester", "iss": ISSUER, "exp": FAR_FUTURE})
    }

    fn eddsa_token(claims: &Value, kid: Option<&str>, key: &EncodingKey) -> String {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = kid.map(str::to_owned);
        encode(&header, claims, key).unwrap()
    }

    fn valid_token(claims: &Value) -> String {
        eddsa_token(claims, Some(KID), &ed_key(SIGNING_KEY))
    }

    // Skips `verify` to see why a token is refused, which `AuthError` deliberately hides.
    fn refusal_reason(keys: &ExternalKeys, token: &str) -> ErrorKind {
        let (key, validation) = keys.keys.get(KID).unwrap();
        decode::<Claims>(token, key, validation)
            .unwrap_err()
            .into_kind()
    }

    fn assert_invalid(result: &Result<TokenData<Claims>, AuthError>) {
        assert!(matches!(result, Err(AuthError::InvalidToken { .. })));
    }

    #[test]
    fn valid_token_is_accepted() {
        let token = valid_token(&claims());

        let decoded = keys().verify::<Claims>(&token).unwrap().claims;

        assert_eq!(decoded.sub(), "tester");
        assert_eq!(
            ClaimsTrait::attributes(&decoded).get("iss"),
            Some(&json!(ISSUER))
        );
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let token = valid_token(&claims());
        let forged = valid_token(&json!({"sub": "admin", "iss": ISSUER, "exp": FAR_FUTURE}));
        let mut parts = token.split('.');
        let (header, _, signature) = (parts.next(), parts.next(), parts.next());
        let payload = forged.split('.').nth(1).unwrap();
        let tampered = format!("{}.{payload}.{}", header.unwrap(), signature.unwrap());

        assert_invalid(&keys().verify(&tampered));
        assert_eq!(
            refusal_reason(&keys(), &tampered),
            ErrorKind::InvalidSignature
        );
    }

    #[test]
    fn token_signed_with_other_key_is_rejected() {
        let token = eddsa_token(&claims(), Some(KID), &ed_key(OTHER_SIGNING_KEY));

        assert_invalid(&keys().verify(&token));
        assert_eq!(refusal_reason(&keys(), &token), ErrorKind::InvalidSignature);
    }

    #[test]
    fn wrong_issuer_is_rejected() {
        let token = valid_token(&json!({"sub": "tester", "iss": "other", "exp": FAR_FUTURE}));

        assert_invalid(&keys().verify(&token));
        assert_eq!(refusal_reason(&keys(), &token), ErrorKind::InvalidIssuer);
    }

    #[test]
    fn missing_issuer_is_rejected() {
        let token = valid_token(&json!({"sub": "tester", "exp": FAR_FUTURE}));

        assert_invalid(&keys().verify(&token));
    }

    #[test]
    fn hs256_token_is_rejected() {
        let header = Header {
            kid: Some(KID.to_owned()),
            ..Header::default()
        };
        for secret in [b"secret".as_slice(), PUBLIC_KEY.as_bytes()] {
            let token = encode(&header, &claims(), &EncodingKey::from_secret(secret)).unwrap();

            assert_invalid(&keys().verify(&token));
            assert_eq!(refusal_reason(&keys(), &token), ErrorKind::InvalidAlgorithm);
        }
    }

    #[test]
    fn unsigned_token_is_rejected() {
        let token = valid_token(&claims());
        let payload = token.split('.').nth(1).unwrap();
        // base64url of {"alg":"none","kid":"dev","typ":"JWT"}
        let unsigned = format!("eyJhbGciOiJub25lIiwia2lkIjoiZGV2IiwidHlwIjoiSldUIn0.{payload}.");

        assert_invalid(&keys().verify(&unsigned));
    }

    #[test]
    fn audience_outside_the_configured_ones_is_rejected() {
        let keys = keys_with_audience(&["cda", "gateway"]);
        let token = valid_token(&json!({
            "sub": "tester", "iss": ISSUER, "exp": FAR_FUTURE, "aud": "other"
        }));

        assert_invalid(&keys.verify(&token));
        assert_eq!(refusal_reason(&keys, &token), ErrorKind::InvalidAudience);
    }

    #[test]
    fn configured_audience_is_accepted_and_required() {
        let keys = keys_with_audience(&["cda", "gateway"]);
        let token = valid_token(&json!({
            "sub": "tester", "iss": ISSUER, "exp": FAR_FUTURE, "aud": "gateway"
        }));

        assert!(keys.verify::<Claims>(&token).is_ok());
        assert_invalid(&keys.verify(&valid_token(&claims())));
    }

    #[test]
    fn token_with_audience_is_accepted_without_configured_audience() {
        let token = valid_token(&json!({
            "sub": "tester", "iss": ISSUER, "exp": FAR_FUTURE, "aud": "anything"
        }));

        assert!(keys().verify::<Claims>(&token).is_ok());
    }

    #[test]
    fn expired_token_is_rejected() {
        let token = valid_token(&json!({"sub": "tester", "iss": ISSUER, "exp": 1_000}));

        assert_invalid(&keys().verify(&token));
        assert_eq!(refusal_reason(&keys(), &token), ErrorKind::ExpiredSignature);
    }

    #[test]
    fn token_before_nbf_is_rejected() {
        let token = valid_token(&json!({
            "sub": "tester", "iss": ISSUER, "exp": FAR_FUTURE, "nbf": FAR_FUTURE
        }));

        assert_invalid(&keys().verify(&token));
        assert_eq!(
            refusal_reason(&keys(), &token),
            ErrorKind::ImmatureSignature
        );
    }

    #[test]
    fn unknown_or_missing_kid_is_rejected() {
        let key = ed_key(SIGNING_KEY);

        assert_invalid(&keys().verify(&eddsa_token(&claims(), Some("other"), &key)));
        assert_invalid(&keys().verify(&eddsa_token(&claims(), None, &key)));
    }

    #[test]
    fn malformed_token_is_rejected() {
        assert_invalid(&keys().verify("not-a-token"));
    }

    #[test]
    fn jwks_is_refused_at_load() {
        let without = |field: &str| {
            let mut key = jwk(KID);
            key.as_object_mut().unwrap().remove(field);
            key
        };
        let symmetric = json!({"kty": "oct", "k": "c2VjcmV0", "kid": KID, "alg": "HS256"});
        let mismatched_alg = {
            let mut key = jwk(KID);
            key.as_object_mut()
                .unwrap()
                .insert("alg".to_owned(), json!("RS256"));
            key
        };

        assert!(load_error(&[]).contains("no key"));
        assert!(load_error(&[without("kid")]).contains("without kid"));
        assert!(load_error(&[without("alg")]).contains("without alg"));
        assert!(load_error(&[symmetric]).contains("symmetric"));
        assert!(load_error(&[mismatched_alg]).contains("does not match"));
        assert!(load_error(&[jwk(KID), jwk(KID)]).contains("twice"));
    }

    #[test]
    fn invalid_configuration_rejects_every_token_without_fallback() {
        let state: ExternalKeyState = Err("broken".to_owned());
        let token = encode(&Header::default(), &claims(), &KEYS.encoding).unwrap();

        assert_invalid(&decode_token_with(&state, &token, &KEYS.decoding));
    }

    #[test]
    fn configured_keys_do_not_accept_builtin_tokens() {
        let state: ExternalKeyState = Ok(Some(keys()));
        let token = encode(&Header::default(), &claims(), &KEYS.encoding).unwrap();

        assert_invalid(&decode_token_with(&state, &token, &KEYS.decoding));
    }

    #[test]
    fn no_configuration_uses_builtin_handling() {
        let state: ExternalKeyState = Ok(None);
        let token = encode(&Header::default(), &claims(), &KEYS.encoding).unwrap();

        let decoded = decode_token_with::<Claims>(&state, &token, &KEYS.decoding).unwrap();

        assert_eq!(decoded.claims.sub(), "tester");
    }

    #[test]
    fn authorize_is_refused_unless_tokens_are_handled_locally() {
        let refused = [Ok(Some(keys())), Err("broken".to_owned())];

        for state in &refused {
            let response = external_issuer_refusal(state).unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
        assert!(external_issuer_refusal(&Ok(None)).is_none());
    }

    #[test]
    fn unset_or_empty_jwks_file_disables_external_keys() {
        assert!(matches!(load_external_keys(None, None, None), Ok(None)));
        assert!(matches!(
            load_external_keys(Some(""), Some(ISSUER), None),
            Ok(None)
        ));
    }

    fn with_jwks_file(name: &str, content: &str, check: impl FnOnce(&str)) {
        let path = std::env::temp_dir().join(format!("cda-{}-{name}", std::process::id()));
        std::fs::write(&path, content).unwrap();
        check(path.to_str().unwrap());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn jwks_file_requires_an_issuer() {
        for issuer in [None, Some("")] {
            assert!(load_external_keys(Some("/unused"), issuer, None).is_err());
        }
    }

    #[test]
    fn unreadable_or_invalid_jwks_file_is_an_error() {
        assert!(load_external_keys(Some("/does/not/exist"), Some(ISSUER), None).is_err());
        with_jwks_file("invalid.json", "not json", |file| {
            assert!(load_external_keys(Some(file), Some(ISSUER), None).is_err());
        });
    }

    #[test]
    fn jwks_file_is_loaded_with_a_comma_separated_audience() {
        let content = json!({ "keys": [jwk(KID)] }).to_string();
        with_jwks_file("valid.json", &content, |file| {
            let keys = load_external_keys(Some(file), Some(ISSUER), Some(" cda, ,gateway "))
                .unwrap()
                .unwrap();
            let accepted = valid_token(&json!({
                "sub": "tester", "iss": ISSUER, "exp": FAR_FUTURE, "aud": "gateway"
            }));

            assert!(keys.verify::<Claims>(&accepted).is_ok());
            assert_invalid(&keys.verify(&valid_token(&claims())));
        });
    }
}
