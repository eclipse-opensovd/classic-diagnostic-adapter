use std::{ops::Deref, sync::Arc};

use async_trait::async_trait;
use axum::{
    extract::{FromRequestParts, Request},
    middleware::Next,
    response::{IntoResponse, Response},
};
use http::{StatusCode, request::Parts};
use thiserror::Error;

use crate::sovd::error::{ApiError, ErrorWrapper};

// allowing dead code because WrongCredentials and MissingCredentials
// are only used when the auth feature is enabled
#[allow(dead_code)]
#[derive(Error, Debug)]
pub enum AuthError {
    #[error("No token provided in the request")]
    NoTokenProvided,
    #[error("Wrong credentials provided in the request")]
    WrongCredentials,
    #[error("No credentials provided in the request")]
    MissingCredentials,
    #[error("Invalid token: {details}")]
    InvalidToken { details: String },
    #[error("Internal error during authentication")]
    Internal,
}

pub trait Claims: Send + Sync {
    fn sub(&self) -> &str;
    fn exp(&self) -> usize;
}

#[async_trait]
pub trait AuthApi: Send + Sync + 'static {
    async fn validate_token(
        &mut self,
        parts: &mut axum::http::request::Parts,
    ) -> Result<(), AuthError>;

    fn claims(&self) -> Result<Box<&dyn Claims>, AuthError>;
}

pub trait SecurityApi: Send + Sync + 'static {
    // todo: add methods for security plugin
}

pub trait SecurityPlugin: SecurityApi + AuthApi {
    fn as_auth_plugin(&self) -> &dyn AuthApi;

    fn as_security_plugin(&self) -> &dyn SecurityApi;
}

pub trait SecurityPluginType: SecurityPlugin + Default + Clone {}

#[async_trait]
impl AuthApi for Box<dyn AuthApi> {
    async fn validate_token(
        &mut self,
        parts: &mut axum::http::request::Parts,
    ) -> Result<(), AuthError> {
        (**self).validate_token(parts).await
    }

    fn claims(&self) -> Result<Box<&dyn Claims>, AuthError> {
        (**self).claims()
    }
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

pub type SecurityPluginData = Arc<dyn SecurityPlugin>;

pub async fn auth_middleware<A: SecurityPluginType>(req: Request, next: Next) -> Response {
    let (mut parts, body) = req.into_parts();

    let mut auth_state = A::default();
    match auth_state.validate_token(&mut parts).await {
        Ok(()) => {
            let auth_state = Arc::new(auth_state);
            let Ok(claims) = auth_state.claims() else {
                tracing::warn!("Auth plugin did not return claims after successful validation");
                return AuthError::Internal.into_response();
            };
            tracing::debug!(sub = %claims.sub(), exp = %claims.exp(), "Authorized request");
            let mut req = axum::http::Request::from_parts(parts, body);
            let shared_plugin = auth_state as SecurityPluginData;
            req.extensions_mut().insert(shared_plugin);
            next.run(req).await
        }
        Err(e) => {
            tracing::warn!(error = ?e, "Unauthorized request");
            e.into_response()
        }
    }
}

pub struct SecurityPluginExtractor(SecurityPluginData);

impl Deref for SecurityPluginExtractor {
    type Target = dyn SecurityPlugin;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl<S> FromRequestParts<S> for SecurityPluginExtractor
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let auth_state = parts
            .extensions
            .remove::<SecurityPluginData>()
            .ok_or(AuthError::Internal)?;
        Ok(SecurityPluginExtractor(auth_state))
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
