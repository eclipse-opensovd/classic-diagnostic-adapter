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
#[derive(Debug, Clone, PartialEq, Eq, Hash, strum_macros::Display)]
pub enum HttpProtectionReason {
    /// A runtime update is currently in progress.
    UpdateInProgress,
    /// A caller-defined restriction reason.
    Custom(String),
}

/// Complete configuration for one active HTTP request restriction.
///
/// Describes the HTTP denial response, the routes exempt from it, and an
/// optional retry hint. The restriction itself applies to every route except
/// its exemptions - there is no way to scope it to a subset of routes.
#[derive(Clone, Debug)]
pub struct HttpProtectionConfig {
    /// Identifier describing why requests are restricted.
    pub reason: HttpProtectionReason,
    /// HTTP status code returned for denied requests.
    pub status: HttpStatusCode,
    /// Human-readable denial message included in the response body.
    pub message: String,
    /// Routes that are exempt from this restriction.
    pub exempt_routes: Vec<HttpRouteMatcher>,
    /// Optional `Retry-After` value in seconds included in denial responses.
    pub retry_after_seconds: Option<u64>,
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
            exempt_routes: Vec::new(),
            retry_after_seconds: None,
        }
    }

    /// Sets the routes that are exempt from this restriction, replacing any previous value.
    #[must_use]
    pub fn with_exempt_routes(mut self, routes: Vec<HttpRouteMatcher>) -> Self {
        self.exempt_routes = routes;
        self
    }

    /// Sets the optional `Retry-After` hint returned in denial responses.
    #[must_use]
    pub const fn with_retry_after(mut self, seconds: u64) -> Self {
        self.retry_after_seconds = Some(seconds);
        self
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
