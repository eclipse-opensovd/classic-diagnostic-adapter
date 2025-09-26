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

pub trait AuthApi: Send + Sync + 'static {
    fn claims(&self) -> Box<&dyn Claims>;
}

pub trait SecurityApi: Send + Sync + 'static {
    // todo: add methods for security plugin
}

pub trait SecurityPlugin: SecurityApi + AuthApi {
    fn as_auth_plugin(&self) -> &dyn AuthApi;

    fn as_security_plugin(&self) -> &dyn SecurityApi;
}

#[async_trait]
pub trait SecurityPluginInitializer: Send + Sync {
    async fn initialize_from_request_parts(
        &self,
        parts: &mut Parts,
    ) -> Result<Box<dyn SecurityPlugin>, AuthError>;
}

pub trait SecurityPluginType: SecurityPluginInitializer + Default + 'static {}

impl AuthApi for Box<dyn AuthApi> {
    fn claims(&self) -> Box<&dyn Claims> {
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

pub type SecurityPluginData = Box<dyn SecurityPlugin>;
pub type SecurityPluginInitializerType = Arc<dyn SecurityPluginInitializer>;

pub async fn security_plugin_middleware<A: SecurityPluginType>(
    mut req: Request,
    next: Next,
) -> Response {
    let security_plugin = Arc::new(A::default()) as SecurityPluginInitializerType;
    req.extensions_mut().insert(security_plugin);
    next.run(req).await
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
        let initializer = parts
            .extensions
            .remove::<SecurityPluginInitializerType>()
            .ok_or(AuthError::Internal)?;

        let plugin = initializer.initialize_from_request_parts(parts).await?;
        Ok(SecurityPluginExtractor(plugin))
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        // If auth header was missing return 401 without body,
        // else return sovd error with 403 and the error message
        // see SOVD 6.15.6 Request Header for Access-Restricted Resources
        let error_message = match &self {
            AuthError::NoTokenProvided => return StatusCode::UNAUTHORIZED.into_response(),
            AuthError::Internal => {
                return ApiError::InternalServerError(Some(
                    "Misconfiguration of Security Plugin".to_string(),
                ))
                .into_response();
            }
            error => error.to_string(),
        };
        ErrorWrapper {
            error: ApiError::Forbidden(Some(error_message)),
            include_schema: false,
        }
        .into_response()
    }
}
