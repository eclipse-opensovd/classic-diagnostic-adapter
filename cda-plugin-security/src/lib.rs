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
use cda_database::datatypes::DiagnosticService;
use cda_interfaces::DiagServiceError;
use hashbrown::HashMap;
use http::{StatusCode, request::Parts};
use sovd_interfaces::error::{ApiErrorResponse, ErrorCode};
use thiserror::Error;

mod default_security_plugin;
pub use default_security_plugin::{DefaultSecurityPlugin, DefaultSecurityPluginData};

pub trait Claims: Send + Sync {
    fn sub(&self) -> &str;
    fn exp(&self) -> usize;
}

pub trait AuthApi: Send + Sync + 'static {
    fn claims(&self) -> Box<&dyn Claims>;
}

pub trait SecurityApi: Send + Sync + 'static {
    fn validate_service(&self, service: &DiagnosticService) -> Result<(), DiagServiceError>;
}

impl AuthApi for Box<dyn AuthApi> {
    fn claims(&self) -> Box<&dyn Claims> {
        (**self).claims()
    }
}

pub trait SecurityPlugin: Any + SecurityApi + AuthApi {
    fn as_auth_plugin(&self) -> &dyn AuthApi;

    fn as_security_plugin(&self) -> &dyn SecurityApi;
}

impl Claims for Box<dyn Claims> {
    fn sub(&self) -> &str {
        (**self).sub()
    }

    fn exp(&self) -> usize {
        (**self).exp()
    }
}

impl Claims for Box<&dyn Claims> {
    fn sub(&self) -> &str {
        (**self).sub()
    }

    fn exp(&self) -> usize {
        (**self).exp()
    }
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum AuthError {
    #[error("No token provided in the request")]
    NoTokenProvided,
    #[error("Wrong credentials provided in the request")]
    WrongCredentials,
    #[error("No credentials provided in the request")]
    MissingCredentials,
    #[error("Invalid token: {details}")]
    InvalidToken { details: String },
    #[error("Misconfiguration of Security Plugin")]
    Internal,
    #[error("Authentication error: {message}")]
    Custom {
        http_status: StatusCode,
        message: String,
        error_code: ErrorCode,
        vendor_code: Option<String>,
        parameters: Option<HashMap<String, serde_json::Value>>,
    },
}

#[async_trait]
pub trait SecurityPluginInitializer: Send + Sync {
    async fn initialize_from_request_parts(
        &self,
        parts: &mut Parts,
    ) -> Result<Box<dyn SecurityPlugin>, AuthError>;
}

#[async_trait]
pub trait AuthorizationRequestHandler: Send + Sync {
    async fn authorize(body_bytes: Bytes) -> impl IntoApiResponse;
}

pub trait SecurityPluginLoader:
    SecurityPluginInitializer + AuthorizationRequestHandler + Default + 'static
{
}

type SecurityPluginInitializerType = Arc<dyn SecurityPluginInitializer>;

pub async fn security_plugin_middleware<A: SecurityPluginLoader>(
    mut req: Request,
    next: Next,
) -> Response {
    let security_plugin = Arc::new(A::default()) as SecurityPluginInitializerType;
    req.extensions_mut().insert(security_plugin);
    next.run(req).await
}

pub type SecurityPluginData = Box<dyn SecurityPlugin>;
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
