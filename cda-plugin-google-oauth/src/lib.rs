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

//! # Google OAuth Plugin Integration
//!
//! This crate provides the complete Google OAuth 2.0 security plugin implementation
//! that integrates with Google's authentication services and the CDA web server (SOVD).
//!
//! ## OAuth 2.0 Desktop Flow
//!
//! The plugin implements the OAuth 2.0 desktop/installed application flow:
//! - User authenticates directly with Google in their browser
//! - User copies the authorization code from the browser
//! - Application exchanges authorization code for access tokens
//! - Validates tokens for API requests
//!
//! ## Configuration
//!
//! The plugin reads configuration from environment variables:
//! - `GOOGLE_CLIENT_ID`: OAuth client ID from Google Cloud Console
//! - `GOOGLE_CLIENT_SECRET`: OAuth client secret from Google Cloud Console
//!
//! Note: This implementation uses the desktop flow without redirect URIs.

use std::sync::{LazyLock, OnceLock};

use aide::axum::IntoApiResponse;
use async_trait::async_trait;
use axum::{Json, RequestPartsExt, body::Bytes, http::StatusCode, response::IntoResponse};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};
use http::{HeaderMap, request::Parts};
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation, Algorithm};
use reqwest::Client;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sovd_interfaces::error::{ApiErrorResponse, ErrorCode};

use cda_plugin_security::{
    AuthApi, AuthError, AuthorizationRequestHandler, Claims as ClaimsTrait, SecurityApi,
    SecurityPlugin, SecurityPluginInitializer, SecurityPluginLoader,
};
use cda_sovd::dynamic_router::DynamicRouter;

/// JWKS (JSON Web Key Set) response from Google
#[derive(Debug, Deserialize)]
struct JwksResponse {
    keys: Vec<Jwk>,
}

/// JSON Web Key
#[derive(Debug, Deserialize, Clone)]
struct Jwk {
    kid: String,
    #[serde(rename = "use")]
    #[allow(dead_code)]
    key_use: String,
    #[allow(dead_code)]
    kty: String,
    #[allow(dead_code)]
    alg: String,
    n: String,
    e: String,
}

/// Cached JWKS keys
struct JwksCache {
    keys: Vec<Jwk>,
    cached_at: std::time::Instant,
}

/// Error type for OAuth plugin initialization failures
#[derive(Debug, thiserror::Error)]
pub enum OAuthPluginError {
    #[error("Missing OAuth configuration: {0}")]
    MissingConfiguration(String),
    #[error("OAuth plugin initialization failed: {0}")]
    InitializationFailed(String),
}

/// Google OAuth configuration loaded from environment variables
#[derive(Clone)]
pub struct GoogleOAuthConfig {
    pub client_id: String,
    pub client_secret: String,
}

impl GoogleOAuthConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self, String> {
        let client_id = std::env::var("GOOGLE_CLIENT_ID")
            .map_err(|_| "GOOGLE_CLIENT_ID environment variable not set".to_string())?;
        let client_secret = std::env::var("GOOGLE_CLIENT_SECRET")
            .map_err(|_| "GOOGLE_CLIENT_SECRET environment variable not set".to_string())?;

        Ok(Self {
            client_id,
            client_secret,
        })
    }
}

static OAUTH_CONFIG: OnceLock<GoogleOAuthConfig> = OnceLock::new();
static HTTP_CLIENT: LazyLock<Client> = LazyLock::new(Client::new);
static JWKS_CACHE: std::sync::Mutex<Option<JwksCache>> = std::sync::Mutex::new(None);

// Google OAuth endpoints
const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const GOOGLE_JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";
#[allow(dead_code)]
const GOOGLE_USERINFO_URL: &str = "https://www.googleapis.com/oauth2/v3/userinfo";

// Cache JWKS for 1 hour (Google recommends caching for at least 1 hour)
const JWKS_CACHE_DURATION: std::time::Duration = std::time::Duration::from_secs(3600);

/// JWT claims from Google ID token
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GoogleClaims {
    /// Subject (user identifier)
    pub sub: String,
    /// Email address
    pub email: String,
    /// Email verified flag
    pub email_verified: bool,
    /// Issuer
    pub iss: String,
    /// Audience (client ID)
    pub aud: String,
    /// Issued at timestamp
    pub iat: i64,
    /// Expiration timestamp
    pub exp: usize,
}

impl ClaimsTrait for GoogleClaims {
    fn sub(&self) -> &str {
        &self.sub
    }
}

/// Authorization request payload for initiating OAuth flow
#[derive(Debug, Deserialize, JsonSchema)]
pub struct OAuthAuthorizationRequest {
    /// Optional state parameter for CSRF protection
    pub state: Option<String>,
    /// Optional scopes to request (defaults to profile and email)
    pub scopes: Option<Vec<String>>,
}

/// Authorization response containing the redirect URL
#[derive(Debug, Serialize, JsonSchema)]
pub struct OAuthAuthorizationResponse {
    /// URL to redirect the user to for Google authentication
    pub authorization_url: String,
    /// State parameter for verification
    pub state: String,
}

/// OAuth callback request containing the authorization code
#[derive(Debug, Deserialize, JsonSchema)]
pub struct OAuthCallbackRequest {
    /// Authorization code from Google
    pub code: String,
    /// State parameter for CSRF verification
    pub state: String,
}

/// Token response from Google
#[derive(Debug, Deserialize)]
pub struct GoogleTokenResponse {
    pub access_token: String,
    pub id_token: String,
    pub expires_in: i64,
    pub token_type: String,
}

/// Access token response for the client
#[derive(Debug, Serialize, JsonSchema)]
pub struct AccessTokenResponse {
    /// The access token (ID token from Google)
    pub access_token: String,
    /// Token type (Bearer)
    pub token_type: String,
    /// Token expiration in seconds
    pub expires_in: i64,
}

/// Google OAuth security plugin data containing validated user claims
pub struct GoogleOAuthSecurityPluginData {
    claims: GoogleClaims,
}

/// Google OAuth security plugin implementation
///
/// This plugin provides Google OAuth 2.0 based authentication and authorization.
/// It integrates with Google's identity platform to provide secure user authentication.
#[derive(Default)]
pub struct GoogleOAuthSecurityPlugin;

impl SecurityPluginLoader for GoogleOAuthSecurityPlugin {}

impl GoogleOAuthSecurityPlugin {
    /// Initialize the OAuth configuration
    fn init() -> Result<(), String> {
        let config = GoogleOAuthConfig::from_env()?;
        OAUTH_CONFIG
            .set(config)
            .map_err(|_| "OAuth config already initialized".to_string())?;
        Ok(())
    }

    /// Get the OAuth configuration
    fn config() -> Result<&'static GoogleOAuthConfig, AuthError> {
        OAUTH_CONFIG.get().ok_or(AuthError::Internal)
    }

    /// Generate authorization URL for OAuth flow
    pub fn generate_auth_url(state: &str, scopes: &[String]) -> Result<String, AuthError> {
        let config = Self::config()?;

        let scope = if scopes.is_empty() {
            "openid email profile".to_string()
        } else {
            scopes.join(" ")
        };

        // Use urn:ietf:wg:oauth:2.0:oob for desktop/installed applications
        // This tells Google to display the authorization code in the browser for manual copying
        let auth_url = format!(
            "{}?client_id={}&redirect_uri=urn:ietf:wg:oauth:2.0:oob&response_type=code&scope={}&state={}",
            GOOGLE_AUTH_URL,
            urlencoding::encode(&config.client_id),
            urlencoding::encode(&scope),
            urlencoding::encode(state)
        );

        Ok(auth_url)
    }

    /// Exchange authorization code for tokens
    pub async fn exchange_code(code: &str) -> Result<GoogleTokenResponse, AuthError> {
        let config = Self::config()?;

        // Use urn:ietf:wg:oauth:2.0:oob for desktop/installed applications
        let params = [
            ("code", code),
            ("client_id", &config.client_id),
            ("client_secret", &config.client_secret),
            ("redirect_uri", "urn:ietf:wg:oauth:2.0:oob"),
            ("grant_type", "authorization_code"),
        ];

        let response = HTTP_CLIENT
            .post(GOOGLE_TOKEN_URL)
            .form(&params)
            .send()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to exchange code for token");
                AuthError::Custom {
                    http_status: StatusCode::INTERNAL_SERVER_ERROR,
                    message: "Failed to exchange authorization code".to_string(),
                    error_code: ErrorCode::SovdServerFailure,
                    vendor_code: Some("oauth-exchange-failed".to_string()),
                    parameters: None,
                }
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            tracing::error!(
                status = %status,
                error = %error_text,
                "Token exchange failed"
            );
            return Err(AuthError::Custom {
                http_status: StatusCode::UNAUTHORIZED,
                message: "Failed to obtain access token".to_string(),
                error_code: ErrorCode::InsufficientAccessRights,
                vendor_code: Some("oauth-token-failed".to_string()),
                parameters: None,
            });
        }

        response.json::<GoogleTokenResponse>().await.map_err(|e| {
            tracing::error!(error = %e, "Failed to parse token response");
            AuthError::Custom {
                http_status: StatusCode::INTERNAL_SERVER_ERROR,
                message: "Failed to parse token response".to_string(),
                error_code: ErrorCode::SovdServerFailure,
                vendor_code: Some("oauth-parse-failed".to_string()),
                parameters: None,
            }
        })
    }

    /// Fetch Google's JWKS (JSON Web Key Set)
    async fn fetch_jwks() -> Result<Vec<Jwk>, AuthError> {
        let response = HTTP_CLIENT
            .get(GOOGLE_JWKS_URL)
            .send()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to fetch JWKS");
                AuthError::Custom {
                    http_status: StatusCode::INTERNAL_SERVER_ERROR,
                    message: "Failed to fetch signing keys".to_string(),
                    error_code: ErrorCode::SovdServerFailure,
                    vendor_code: Some("jwks-fetch-failed".to_string()),
                    parameters: None,
                }
            })?;

        let jwks = response.json::<JwksResponse>().await.map_err(|e| {
            tracing::error!(error = %e, "Failed to parse JWKS");
            AuthError::Custom {
                http_status: StatusCode::INTERNAL_SERVER_ERROR,
                message: "Failed to parse signing keys".to_string(),
                error_code: ErrorCode::SovdServerFailure,
                vendor_code: Some("jwks-parse-failed".to_string()),
                parameters: None,
            }
        })?;

        Ok(jwks.keys)
    }

    /// Get JWKS keys (from cache or fetch if needed)
    async fn get_jwks() -> Result<Vec<Jwk>, AuthError> {
        // Check cache first
        {
            let cache = JWKS_CACHE.lock().map_err(|_| {
                tracing::error!("Failed to acquire JWKS cache lock");
                AuthError::Internal
            })?;

            // Check if we have cached keys that are still valid
            if let Some(cached) = cache.as_ref() {
                if cached.cached_at.elapsed() < JWKS_CACHE_DURATION {
                    tracing::debug!("Using cached JWKS keys");
                    return Ok(cached.keys.clone());
                }
            }
        } // Mutex guard is dropped here

        // Fetch fresh keys (outside the mutex lock)
        tracing::debug!("Fetching fresh JWKS keys from Google");
        let keys = Self::fetch_jwks().await?;
        
        // Update cache
        {
            let mut cache = JWKS_CACHE.lock().map_err(|_| {
                tracing::error!("Failed to acquire JWKS cache lock");
                AuthError::Internal
            })?;
            
            *cache = Some(JwksCache {
                keys: keys.clone(),
                cached_at: std::time::Instant::now(),
            });
        } // Mutex guard is dropped here

        Ok(keys)
    }

    /// Find the appropriate JWK for a given key ID
    fn find_jwk<'a>(keys: &'a [Jwk], kid: &str) -> Option<&'a Jwk> {
        keys.iter().find(|key| key.kid == kid)
    }

    /// Convert JWK to DecodingKey
    fn jwk_to_decoding_key(jwk: &Jwk) -> Result<DecodingKey, AuthError> {
        DecodingKey::from_rsa_components(&jwk.n, &jwk.e).map_err(|e| {
            tracing::error!(error = %e, "Failed to create decoding key from JWK");
            AuthError::InvalidToken {
                details: "Invalid signing key format".to_string(),
            }
        })
    }

    /// Verify and decode Google ID token with proper signature verification
    async fn verify_id_token(id_token: &str) -> Result<GoogleClaims, AuthError> {
        // Decode header to get the key ID (kid)
        let header = decode_header(id_token).map_err(|e| {
            tracing::error!(error = %e, "Failed to decode token header");
            AuthError::InvalidToken {
                details: "Invalid token format".to_string(),
            }
        })?;

        let kid = header.kid.ok_or_else(|| {
            tracing::error!("Token header missing kid (key ID)");
            AuthError::InvalidToken {
                details: "Token missing key ID".to_string(),
            }
        })?;

        tracing::debug!(algorithm = ?header.alg, kid = %kid, "Decoding token with key ID");

        // Fetch JWKS keys
        let keys = Self::get_jwks().await?;

        // Find the matching key
        let jwk = Self::find_jwk(&keys, &kid).ok_or_else(|| {
            tracing::error!(kid = %kid, "Key ID not found in JWKS");
            AuthError::InvalidToken {
                details: "Signing key not found".to_string(),
            }
        })?;

        // Create decoding key from JWK
        let decoding_key = Self::jwk_to_decoding_key(jwk)?;

        // Set up validation parameters
        let mut validation = Validation::new(Algorithm::RS256);
        let config = Self::config()?;
        validation.set_audience(&[config.client_id.clone()]);
        validation.set_issuer(&["https://accounts.google.com", "accounts.google.com"]);

        // Verify and decode the token
        let token_data = decode::<GoogleClaims>(id_token, &decoding_key, &validation).map_err(|e| {
            tracing::error!(error = %e, "Token verification failed");
            match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    AuthError::InvalidToken {
                        details: "Token has expired".to_string(),
                    }
                }
                jsonwebtoken::errors::ErrorKind::InvalidIssuer => {
                    AuthError::InvalidToken {
                        details: "Invalid token issuer".to_string(),
                    }
                }
                jsonwebtoken::errors::ErrorKind::InvalidAudience => {
                    AuthError::InvalidToken {
                        details: "Invalid token audience".to_string(),
                    }
                }
                jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                    AuthError::InvalidToken {
                        details: "Invalid token signature".to_string(),
                    }
                }
                _ => {
                    AuthError::InvalidToken {
                        details: format!("Token validation failed: {e}"),
                    }
                }
            }
        })?;

        Ok(token_data.claims)
    }
}

#[async_trait]
impl AuthorizationRequestHandler for GoogleOAuthSecurityPlugin {
    async fn authorize(_headers: HeaderMap, body_bytes: Bytes) -> impl IntoApiResponse {
        // Parse the authorization request
        let request = match axum::extract::Json::<OAuthAuthorizationRequest>::from_bytes(&body_bytes) {
            Ok(req) => req.0,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to parse authorization request");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ApiErrorResponse::<String> {
                        message: "Invalid request payload".to_string(),
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

        // Generate a random state for CSRF protection
        let state = request.state.unwrap_or_else(|| {
            use rand::Rng;
            let random_bytes: [u8; 16] = rand::rng().random();
            hex::encode(random_bytes)
        });

        let scopes = request.scopes.unwrap_or_else(|| {
            vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ]
        });

        // Generate authorization URL
        match Self::generate_auth_url(&state, &scopes) {
            Ok(auth_url) => {
                (
                    StatusCode::OK,
                    Json(OAuthAuthorizationResponse {
                        authorization_url: auth_url,
                        state,
                    }),
                )
                    .into_response()
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to generate auth URL");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiErrorResponse::<()> {
                        message: "Failed to initialize OAuth flow".to_string(),
                        error_code: ErrorCode::SovdServerFailure,
                        vendor_code: None,
                        parameters: None,
                        error_source: None,
                        schema: None,
                    }),
                )
                    .into_response()
            }
        }
    }
}

#[async_trait]
impl SecurityPluginInitializer for GoogleOAuthSecurityPlugin {
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

        // Verify and decode the Google ID token
        let claims = Self::verify_id_token(bearer.token()).await?;

        Ok(Box::new(GoogleOAuthSecurityPluginData { claims }))
    }
}

impl AuthApi for GoogleOAuthSecurityPluginData {
    fn claims(&self) -> Box<&dyn ClaimsTrait> {
        Box::new(&self.claims)
    }
}

impl SecurityApi for GoogleOAuthSecurityPluginData {
    fn validate_service(
        &self,
        _service: &cda_database::datatypes::DiagService,
    ) -> Result<(), cda_interfaces::DiagServiceError> {
        // Default implementation allows all services
        // Override this method to implement custom authorization logic
        Ok(())
    }
}

impl SecurityPlugin for GoogleOAuthSecurityPluginData {
    fn as_auth_plugin(&self) -> &dyn AuthApi {
        self
    }

    fn as_security_plugin(&self) -> &dyn SecurityApi {
        self
    }
}

/// Handler for exchanging authorization code for tokens
///
/// This endpoint is used in the desktop OAuth flow where the user
/// manually copies the authorization code from their browser and
/// submits it to exchange for access tokens.
pub async fn oauth_callback_handler(
    Json(callback_request): Json<OAuthCallbackRequest>,
) -> impl IntoResponse {
    tracing::info!("Received OAuth code exchange request");

    // Exchange authorization code for tokens
    match GoogleOAuthSecurityPlugin::exchange_code(&callback_request.code).await {
        Ok(token_response) => {
            // Return the access token to the client
            (
                StatusCode::OK,
                Json(AccessTokenResponse {
                    access_token: token_response.id_token,
                    token_type: token_response.token_type,
                    expires_in: token_response.expires_in,
                }),
            )
                .into_response()
        }
        Err(e) => e.into_response(),
    }
}

/// Initializes the Google OAuth security plugin and registers the OAuth callback route.
///
/// This function performs two operations:
/// 1. Initializes the Google OAuth plugin configuration from environment variables
/// 2. Registers the `/vehicle/v15/oauth/callback` endpoint to the dynamic router
///
/// # Errors
/// Returns an error if the Google OAuth plugin configuration cannot be loaded from
/// environment variables (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET must be set).
pub async fn init_google_oauth_plugin(
    dynamic_router: &DynamicRouter,
) -> Result<(), OAuthPluginError> {
    // Initialize OAuth configuration from environment variables
    GoogleOAuthSecurityPlugin::init()
        .map_err(|e| OAuthPluginError::InitializationFailed(e))?;
    
    // Register the OAuth callback route
    add_oauth_callback_route(dynamic_router).await;
    
    Ok(())
}

/// Adds the OAuth callback route to the dynamic router.
///
/// This function registers the `/vehicle/v15/oauth/callback` endpoint which is used
/// to exchange authorization codes for access tokens in OAuth 2.0 flows.
///
/// This is a private helper function used internally by the OAuth plugin integration.
async fn add_oauth_callback_route(dynamic_router: &DynamicRouter) {
    dynamic_router
        .update_router(|router| {
            router.route(
                "/vehicle/v15/oauth/callback",
                axum::routing::post(oauth_callback_handler),
            )
        })
        .await;
    tracing::debug!("OAuth callback route added to webserver");
}
