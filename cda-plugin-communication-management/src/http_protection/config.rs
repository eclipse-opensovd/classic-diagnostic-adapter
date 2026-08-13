/*
 * SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation
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

//! HTTP protection configuration types.

use std::time::Duration;

pub use http::{Method as HttpMethod, StatusCode as HttpStatusCode};

/// Path prefix and HTTP method set used to match HTTP requests.
///
/// A route matches a request when the request path starts with [`prefix`](Self::prefix) at
/// a boundary (exact match or `/` separator) **and** the request method is in
/// [`methods`](Self::methods).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpRouteMatcher {
    /// Path prefix used for boundary-aware matching.
    pub prefix: String,
    /// HTTP methods accepted by this route.
    pub methods: Vec<HttpMethod>,
}

impl HttpRouteMatcher {
    /// Creates a new route matcher from a path prefix and method list.
    #[must_use]
    pub fn new(prefix: impl Into<String>, methods: Vec<HttpMethod>) -> Self {
        Self {
            prefix: prefix.into(),
            methods,
        }
    }

    /// Returns `true` when `path` matches [`prefix`](Self::prefix) and `method` is
    /// in [`methods`](Self::methods).
    #[must_use]
    pub fn matches(&self, path: &str, method: &HttpMethod) -> bool {
        http_path_prefix_matches(path, &self.prefix) && (self.methods.contains(method))
    }
}

/// Stable identifier for why an HTTP request restriction is active.
///
/// Used in logs, metrics, and structured denial responses to communicate
/// the reason for the restriction without embedding free-form strings.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HttpProtectionReason {
    /// Communication is not ready to process diagnostic requests.
    CommunicationNotReady,
    /// A runtime update is currently in progress.
    UpdateInProgress,
    /// A caller-defined restriction reason.
    Custom(String),
}

impl std::fmt::Display for HttpProtectionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CommunicationNotReady => write!(f, "CommunicationNotReady"),
            Self::UpdateInProgress => write!(f, "UpdateInProgress"),
            Self::Custom(reason) => write!(f, "{reason}"),
        }
    }
}

/// Complete configuration for one active HTTP request restriction.
///
/// Scope of an HTTP restriction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HttpProtectionScope {
    /// Deny every route except the listed exemptions.
    GlobalWithExemptions(Vec<HttpRouteMatcher>),
    /// Deny only requests matching one of the listed routes.
    SelectedRoutes(Vec<HttpRouteMatcher>),
}

/// Describes the HTTP denial response, its route scope, and an optional retry hint.
#[derive(Clone, Debug)]
pub struct HttpProtectionConfig {
    /// Identifier describing why requests are restricted.
    pub reason: HttpProtectionReason,
    /// HTTP status code returned for denied requests.
    pub status: HttpStatusCode,
    /// Human-readable denial message included in the response body.
    pub message: String,
    /// Routes to deny or exempt, depending on the selected scope.
    pub scope: HttpProtectionScope,
    /// Optional `Retry-After` duration included in denial responses.
    pub retry_after: Option<Duration>,
}

impl HttpProtectionConfig {
    /// Creates a minimal configuration with no exempt routes and no retry hint.
    #[must_use]
    pub fn new(
        reason: HttpProtectionReason,
        status: HttpStatusCode,
        message: impl Into<String>,
    ) -> Self {
        Self {
            reason,
            status,
            message: message.into(),
            scope: HttpProtectionScope::GlobalWithExemptions(Vec::new()),
            retry_after: None,
        }
    }

    /// Sets the routes that are exempt from this restriction, replacing any previous value.
    #[must_use]
    pub fn with_exempt_routes(mut self, routes: Vec<HttpRouteMatcher>) -> Self {
        self.scope = HttpProtectionScope::GlobalWithExemptions(routes);
        self
    }

    /// Limits this restriction to the supplied routes.
    #[must_use]
    pub fn with_selected_routes(mut self, routes: Vec<HttpRouteMatcher>) -> Self {
        self.scope = HttpProtectionScope::SelectedRoutes(routes);
        self
    }

    /// Sets the optional `Retry-After` hint returned in denial responses.
    #[must_use]
    pub const fn with_retry_after(mut self, retry_after: Duration) -> Self {
        self.retry_after = Some(retry_after);
        self
    }
}

impl cda_interfaces::config::ConfigSanity for HttpProtectionConfig {
    fn validate_sanity(&self) -> Result<(), cda_interfaces::config::ConfigSanityError> {
        use cda_interfaces::config::ConfigSanityError;

        if !self.status.is_client_error() && !self.status.is_server_error() {
            return Err(ConfigSanityError::InvalidValue {
                field: "status".to_owned(),
                reason: "must be a client or server error status".to_owned(),
            });
        }
        if self.message.trim().is_empty() {
            return Err(ConfigSanityError::InvalidValue {
                field: "message".to_owned(),
                reason: "must not be blank".to_owned(),
            });
        }
        let routes = match &self.scope {
            HttpProtectionScope::GlobalWithExemptions(routes)
            | HttpProtectionScope::SelectedRoutes(routes) => routes,
        };
        for route in routes {
            if !route.prefix.starts_with('/') {
                return Err(ConfigSanityError::InvalidValue {
                    field: "scope.routes.prefix".to_owned(),
                    reason: "must be a nonblank absolute path prefix".to_owned(),
                });
            }
            if route.methods.is_empty() {
                return Err(ConfigSanityError::InvalidValue {
                    field: "scope.routes.methods".to_owned(),
                    reason: "must contain at least one HTTP method".to_owned(),
                });
            }
        }
        Ok(())
    }
}

/// Checks whether `path` starts with `prefix` at a path boundary.
///
/// A boundary is either an exact match or the remainder of the path starting with `/`.
/// This prevents a prefix of `/vehicle` from matching `/vehicle-extras`.
pub(crate) fn http_path_prefix_matches(path: &str, prefix: &str) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|remainder| prefix.ends_with('/') || remainder.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use cda_interfaces::config::ConfigSanity;

    use super::*;

    #[test]
    fn custom_reason_displays_its_value() {
        assert_eq!(
            HttpProtectionReason::Custom("maintenance window".to_owned()).to_string(),
            "maintenance window"
        );
    }

    #[test]
    fn rejects_invalid_response_and_route_data() {
        let status = HttpProtectionConfig::new(
            HttpProtectionReason::CommunicationNotReady,
            HttpStatusCode::OK,
            "not ready",
        );
        assert!(status.validate_sanity().is_err());

        let blank = HttpProtectionConfig::new(
            HttpProtectionReason::CommunicationNotReady,
            HttpStatusCode::SERVICE_UNAVAILABLE,
            "  ",
        );
        assert!(blank.validate_sanity().is_err());

        let route = HttpProtectionConfig::new(
            HttpProtectionReason::CommunicationNotReady,
            HttpStatusCode::SERVICE_UNAVAILABLE,
            "not ready",
        )
        .with_selected_routes(vec![HttpRouteMatcher::new("vehicle", vec![])]);
        assert!(route.validate_sanity().is_err());
    }

    #[test]
    fn rejects_empty_route_prefix() {
        // "" matches every path, which would silently defeat the route scope.
        assert!(http_path_prefix_matches("/vehicle/v15", ""));

        let empty = HttpProtectionConfig::new(
            HttpProtectionReason::CommunicationNotReady,
            HttpStatusCode::SERVICE_UNAVAILABLE,
            "not ready",
        )
        .with_exempt_routes(vec![HttpRouteMatcher::new("", vec![HttpMethod::GET])]);
        assert!(empty.validate_sanity().is_err());
    }
}
