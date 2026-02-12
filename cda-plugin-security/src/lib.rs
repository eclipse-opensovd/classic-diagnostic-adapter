/*
 * Copyright (c) 2025-2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
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

//! # Security Plugin System
//!
//! The security plugin system provides extensible authentication and authorization
//! capabilities for the Classic Diagnostic Adapter (CDA). It enables customization
//! of security mechanisms while maintaining compatibility with the SOVD standard.
//!
//! ## Middleware Integration
//!
//! The security plugin integrates with the Axum web framework through middleware.
//! The [`security_plugin_middleware`] function:
//! - Creates a plugin initializer instance
//! - Injects it into the request extensions
//! - Passes control to the next middleware/handler
//! - Ensures plugin availability throughout the request lifecycle
//!
//! The middleware is applied to protected routes in the SOVD module:
//!
//! ```rust,ignore
//! .layer(middleware::from_fn(security_plugin_middleware::<S>))
//! ```
//!
//! ## Authorization Endpoint
//!
//! The plugin system allows for providing a standardized authorization endpoint
//! at `/vehicle/v15/authorize` through the [`AuthorizationRequestHandler`] trait.
//!
//! ## Configuration
//!
//! ### Runtime Integration
//! Security plugins are integrated into the main application through a type parameter:
//!
//! ```rust,ignore
//! pub async fn launch_webserver<F, R, T, M, S>(
//!     // ... other parameters
//! ) -> Result<(), String>
//! where
//!     S: SecurityPluginLoader,
//! ```
//!
//! ## Default Implementation
//!
//! See [`default_security_plugin::DefaultSecurityPlugin`] for details.
//!
//! ## Extension Points
//!
//! The plugin system provides several extension points for custom implementations:
//!
//! ### Custom Authentication Providers
//! Implement [`AuthorizationRequestHandler`] to support:
//! - OAuth 2.0 / `OpenID` Connect integration
//! - LDAP/Active Directory authentication
//! - Custom token validation mechanisms
//! - Multi-factor authentication
//!
//! ### Custom Authorization Logic
//! Implement [`SecurityApi`] to support:
//! - Role-based access control (RBAC)
//! - Attribute-based access control (ABAC)
//! - Fine-grained service permissions
//! - Dynamic policy evaluation
//!
//! ### Error Handling
//! Custom error types and HTTP responses through:
//! - [`AuthError`] enumeration
//! - SOVD-compliant error responses
//! - Vendor-specific error codes
//!
//! ## Security Considerations
//!
//! ### Token Security
//! - JWT secrets should be properly managed in production environments
//! - Token expiration should be configured appropriately for the use case
//! - Secure transmission of tokens over HTTPS is recommended
//!
//! ### Plugin Isolation
//! - Plugins operate within the main application process
//! - Memory safety is ensured through Rust's ownership system
//! - Plugin failures are contained and reported appropriately
//!
//! ### Audit and Logging
//! - Authentication events are logged through the tracing framework
//! - Failed authentication attempts are recorded
//! - Security-related errors include appropriate detail levels
//!
//! ## Implementation Guidelines
//!
//! When implementing custom security plugins:
//!
//! 1. **Trait Implementation**: Implement all required traits for your use case
//! 2. **Error Handling**: Use appropriate error types and status codes (Follow SOVD standard)
//! 3. **Performance**: Minimize overhead in middleware operations
//! 4. **Testing**: Provide comprehensive test coverage for security logic
//! 5. **Documentation**: Document any vendor-specific behavior or requirements

use std::{any::Any, ops::Deref, sync::Arc};

use aide::axum::IntoApiResponse;
use async_trait::async_trait;
use axum::{
    Json,
    body::Bytes,
    extract::{FromRequestParts, Request},
    middleware::Next,
    response::{IntoResponse, Response},
};
use cda_interfaces::{DiagServiceError, HashMap};
use http::{HeaderMap, StatusCode, request::Parts};
use sovd_interfaces::error::{ApiErrorResponse, ErrorCode};
use thiserror::Error;

mod default_security_plugin;
pub use default_security_plugin::{DefaultSecurityPlugin, DefaultSecurityPluginData};

/// Represents JWT claims that provide user identity and token metadata.
///
/// This trait abstracts the claims contained within authentication tokens,
/// providing access to essential user information and token validation data.
pub trait Claims: Send + Sync {
    /// Returns the subject (user identifier) of the token.
    fn sub(&self) -> &str;
}

/// Provides access to authentication information and user claims.
///
/// This trait handles authentication-related operations and provides access to
/// user claims extracted from authentication tokens. It serves as the authentication
/// component of the security plugin system.
pub trait AuthApi: Send + Sync + 'static {
    /// Returns the user claims associated with the current authentication context.
    ///
    /// The claims provide access to user identity information and token metadata
    /// such as expiration times and subject identifiers.
    fn claims(&self) -> Box<&dyn Claims>;
}

/// Validates diagnostic service requests based on security policies.
///
/// This trait provides the authorization component of the security plugin system,
/// allowing custom implementations to enforce access control policies for
/// diagnostic services. It enables fine-grained control over which services
/// can be executed based on the current security context.
pub trait SecurityApi: Send + Sync + 'static {
    /// Validates whether a diagnostic service can be executed.
    ///
    /// This method is called before executing diagnostic services to ensure
    /// the current security context has sufficient permissions. Custom
    /// implementations can enforce role-based access control (RBAC),
    /// attribute-based access control (ABAC), or other authorization policies.
    ///
    /// # Arguments
    /// * `service` - The diagnostic service to validate
    ///
    /// # Returns
    /// * `Ok(())` if the service execution is authorized
    ///
    /// # Errors
    /// * `DiagServiceError` if the service execution is denied
    fn validate_service(
        &self,
        service: &cda_database::datatypes::DiagService,
    ) -> Result<(), DiagServiceError>;
}

impl AuthApi for Box<dyn AuthApi> {
    fn claims(&self) -> Box<&dyn Claims> {
        (**self).claims()
    }
}

/// The main security plugin trait that combines authentication and authorization capabilities.
///
/// This trait represents a complete security plugin implementation that provides both
/// authentication services (via [`AuthApi`]) and authorization services (via [`SecurityApi`]).
/// It follows the plugin lifecycle during request processing:
///
/// 1. **Plugin Initialization**: Extract authentication information from request headers
/// 2. **Request Processing**: Make the initialized plugin instance available to route handlers
/// 3. **Service Validation**: Validate diagnostic services against security policies before
///    execution
///
/// Custom security plugins should implement this trait to provide vendor-specific
/// authentication and authorization logic.
pub trait SecurityPlugin: Any + SecurityApi + AuthApi {
    /// Returns a reference to the authentication API.
    fn as_auth_plugin(&self) -> &dyn AuthApi;

    /// Returns a reference to the security API.
    fn as_security_plugin(&self) -> &dyn SecurityApi;
}

impl Claims for Box<dyn Claims> {
    fn sub(&self) -> &str {
        (**self).sub()
    }
}

impl Claims for Box<&dyn Claims> {
    fn sub(&self) -> &str {
        (**self).sub()
    }
}

/// Authentication and authorization errors that can occur during security plugin operations.
///
/// This enum provides comprehensive error handling for authentication and authorization
/// failures, with support for SOVD-compliant error responses and vendor-specific error codes.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum AuthError {
    /// No authentication token was provided in the request.
    ///
    /// This error results in a 401 Unauthorized response without a body,
    /// as specified in SOVD 7.23.6 Request Header for Access-Restricted Resources.
    #[error("No token provided in the request")]
    NoTokenProvided,
    /// Wrong credentials were provided in the authentication request.
    #[error("Wrong credentials provided in the request")]
    WrongCredentials,
    /// No credentials were provided in the authentication request.
    #[error("No credentials provided in the request")]
    MissingCredentials,
    /// The provided token is invalid or malformed.
    #[error("Invalid token: {details}")]
    InvalidToken { details: String },
    /// Internal misconfiguration of the Security Plugin.
    #[error("Misconfiguration of Security Plugin")]
    Internal,
    /// Custom authentication error with detailed information.
    ///
    /// This variant allows for vendor-specific error handling with custom
    /// HTTP status codes, error messages, and SOVD-compliant error codes.
    #[error("Authentication error: {message}")]
    Custom {
        http_status: StatusCode,
        message: String,
        error_code: ErrorCode,
        vendor_code: Option<String>,
        parameters: Option<HashMap<String, serde_json::Value>>,
    },
}

/// Initializes security plugin instances from HTTP request data.
///
/// This trait handles the extraction of authentication information from HTTP requests
/// and creates initialized security plugin instances. It is called during the middleware
/// phase to prepare the security context for request processing.
#[async_trait]
pub trait SecurityPluginInitializer: Send + Sync {
    /// Initializes a security plugin instance from request parts.
    ///
    /// This method extracts authentication information (such as Bearer tokens)
    /// from the HTTP request headers and creates a fully initialized security
    /// plugin instance that can be used for the duration of the request.
    ///
    /// # Arguments
    /// * `parts` - Mutable reference to the HTTP request parts containing headers
    ///
    /// # Returns
    /// * `Ok(Box<dyn SecurityPlugin>)` - Successfully initialized plugin instance
    /// * `Err(AuthError)` - Authentication failure or initialization error
    async fn initialize_from_request_parts(
        &self,
        parts: &mut Parts,
    ) -> Result<Box<dyn SecurityPlugin>, AuthError>;
}

/// Handles authorization requests at the `/vehicle/v15/authorize` endpoint.
///
/// This trait provides the implementation for the authorization endpoint
#[async_trait]
pub trait AuthorizationRequestHandler: Send + Sync {
    /// This method initiates an authorization flow that, depending on the
    /// flow returns an access token or other forms of authentication data.
    ///
    /// # Arguments
    /// * `headers` - The HTTP request headers
    /// * `body_bytes` - The raw request body containing client credentials
    ///
    /// # Should Return
    /// An HTTP response containing either:
    /// - Success: An access token or other authentication data of some form
    /// - Error: SOVD-compliant error response with appropriate status code
    async fn authorize(headers: HeaderMap, body_bytes: Bytes) -> impl IntoApiResponse;
}

/// Complete security plugin loader that combines initialization and authorization capabilities.
///
/// This trait represents a complete security plugin implementation that can both
/// initialize plugin instances from requests and handle authorization requests.
/// It is used as the main interface for integrating security plugins into the
/// web server framework.
pub trait SecurityPluginLoader:
    SecurityPluginInitializer + AuthorizationRequestHandler + Default + 'static
{
}

type SecurityPluginInitializerType = Arc<dyn SecurityPluginInitializer>;

/// Security plugin middleware for Axum web framework integration.
///
/// This middleware function integrates security plugins with the Axum web framework
/// and handles the plugin lifecycle during request processing. It is applied to
/// protected routes to ensure authentication and authorization are enforced.
///
/// ## Middleware Behavior
///
/// The middleware:
/// - Creates a plugin initializer instance
/// - Injects it into the request extensions
/// - Passes control to the next middleware/handler
/// - Ensures plugin availability throughout the request lifecycle
///
/// ## Usage
///
/// Apply this middleware to protected routes:
///
/// ```rust,ignore
/// .layer(middleware::from_fn(security_plugin_middleware::<S>))
/// ```
///
/// # Type Parameters
/// * `A` - The security plugin loader type that implements [`SecurityPluginLoader`]
///
/// # Arguments
/// * `req` - The incoming HTTP request
/// * `next` - The next middleware or handler in the chain
///
/// # Returns
/// The HTTP response from the downstream middleware/handler
pub async fn security_plugin_middleware<A: SecurityPluginLoader>(
    mut req: Request,
    next: Next,
) -> Response {
    let security_plugin = Arc::new(A::default()) as SecurityPluginInitializerType;
    req.extensions_mut().insert(security_plugin);
    next.run(req).await
}

/// Type alias for boxed security plugin instances.
pub type SecurityPluginData = Box<dyn SecurityPlugin>;

/// Axum extractor for security plugin instances.
///
/// This struct provides access to initialized security plugin instances within
/// Axum route handlers. It implements the [`FromRequestParts`] trait to automatically
/// extract the security plugin from request extensions populated by the middleware.
///
/// ## Usage in Route Handlers
///
/// ```rust,ignore
/// async fn protected_route(Secured(security_plugin): Secured) -> Response {
///     let claims = security_plugin.claims();
///     // Use the security plugin for authorization checks
/// }
/// ```
///
/// The extractor will return an [`AuthError`] if no security plugin is available
/// in the request extensions, indicating a middleware configuration issue.
pub struct Secured(pub SecurityPluginData);

impl Deref for Secured {
    type Target = dyn SecurityPlugin;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl<S> FromRequestParts<S> for Secured
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let initializer = parts
            .extensions
            .remove::<SecurityPluginInitializerType>()
            .ok_or(AuthError::Internal)?;

        let plugin = initializer.initialize_from_request_parts(parts).await?;
        Ok(Secured(plugin))
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        // If auth header was missing return 401 without body,
        // else return sovd error with 403 and the error message
        // see SOVD 6.15.6 Request Header for Access-Restricted Resources
        let error_message = match self {
            AuthError::NoTokenProvided => return StatusCode::UNAUTHORIZED.into_response(),
            i if i == AuthError::Internal => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiErrorResponse::<String> {
                        message: i.to_string(),
                        error_code: ErrorCode::SovdServerMisconfigured,
                        vendor_code: None,
                        parameters: None,
                        error_source: None,
                        schema: None,
                    }),
                )
                    .into_response();
            }
            AuthError::Custom {
                http_status,
                message,
                vendor_code,
                error_code,
                parameters,
            } => {
                return (
                    http_status,
                    Json(ApiErrorResponse::<String> {
                        message,
                        error_code,
                        vendor_code,
                        parameters,
                        error_source: None,
                        schema: None,
                    }),
                )
                    .into_response();
            }
            error => error.to_string(),
        };
        (
            StatusCode::FORBIDDEN,
            Json(ApiErrorResponse::<String> {
                message: error_message,
                error_code: ErrorCode::InsufficientAccessRights,
                vendor_code: None,
                parameters: None,
                error_source: None,
                schema: None,
            }),
        )
            .into_response()
    }
}

#[cfg(feature = "test-utils")]
pub mod mock {
    use aide::axum::IntoApiResponse;
    use async_trait::async_trait;
    use axum::{Json, body::Bytes, http::StatusCode};
    use cda_interfaces::DiagServiceError;
    use http::{HeaderMap, request::Parts};

    use crate::{
        AuthApi, AuthError, AuthorizationRequestHandler, Claims, SecurityApi, SecurityPlugin,
        SecurityPluginInitializer, SecurityPluginLoader,
    };

    mockall::mock! {
        pub Claims {}
        impl Claims for Claims {
            fn sub(&self) -> &'static str;
        }
    }

    mockall::mock! {
        pub AuthApi {}

        impl AuthApi for AuthApi {
            fn claims(&self) -> Box<&'static dyn Claims>;
        }
    }

    mockall::mock! {
        pub SecurityApi {}

        impl SecurityApi for SecurityApi {
            fn validate_service<'a>(
                &self,
                service: &cda_database::datatypes::DiagService<'a>,
            ) -> Result<(), DiagServiceError>;
        }
    }

    mockall::mock! {
        pub SecurityPlugin {}

        impl Clone for SecurityPlugin {
            fn clone(&self) -> Self;
        }

        impl AuthApi for SecurityPlugin {
            fn claims(&self) -> Box<&'static dyn Claims>;
        }

        impl SecurityApi for SecurityPlugin {
            fn validate_service<'a>(
                &self,
                service: &cda_database::datatypes::DiagService<'a>,
            ) -> Result<(), DiagServiceError>;
        }

        impl SecurityPlugin for SecurityPlugin {
            fn as_auth_plugin(&self) -> &dyn AuthApi;
            fn as_security_plugin(&self) -> &dyn SecurityApi;
        }
    }

    /// A simple test security plugin that always allows access.
    ///
    /// This struct provides a concrete implementation of the `SecurityPlugin` trait
    /// that can be used in tests without requiring mock expectations. It always
    /// returns successful results and provides a default test user.
    #[derive(Clone)]
    pub struct TestSecurityPlugin;

    /// Test claims implementation with a fixed test user.
    pub struct TestClaims;

    impl Claims for TestClaims {
        fn sub(&self) -> &'static str {
            "test_user"
        }
    }

    impl AuthApi for TestSecurityPlugin {
        fn claims(&self) -> Box<&dyn Claims> {
            Box::new(&TestClaims)
        }
    }

    impl SecurityApi for TestSecurityPlugin {
        fn validate_service(
            &self,
            _service: &cda_database::datatypes::DiagService<'_>,
        ) -> Result<(), DiagServiceError> {
            Ok(())
        }
    }

    impl SecurityPlugin for TestSecurityPlugin {
        fn as_auth_plugin(&self) -> &dyn AuthApi {
            self
        }

        fn as_security_plugin(&self) -> &dyn SecurityApi {
            self
        }
    }

    impl Default for TestSecurityPlugin {
        fn default() -> Self {
            Self
        }
    }

    #[async_trait]
    impl SecurityPluginInitializer for TestSecurityPlugin {
        async fn initialize_from_request_parts(
            &self,
            _parts: &mut Parts,
        ) -> Result<Box<dyn SecurityPlugin>, AuthError> {
            Ok(Box::new(Self))
        }
    }

    #[async_trait]
    impl AuthorizationRequestHandler for TestSecurityPlugin {
        async fn authorize(_headers: HeaderMap, _body_bytes: Bytes) -> impl IntoApiResponse {
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "access_token": "test_token",
                    "token_type": "Bearer",
                    "expires_in": 3600
                })),
            )
        }
    }

    impl SecurityPluginLoader for TestSecurityPlugin {}
}
