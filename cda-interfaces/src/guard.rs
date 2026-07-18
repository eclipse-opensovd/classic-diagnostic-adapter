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

//! Core guard types for request gating and update management.
//!
//! This module provides the fundamental guard abstractions used by:
//! - Update guards (blocking requests during database updates)
//! - Deferred initialization guards (blocking requests until ECU communication is ready)
//!
//! These types are defined in cda-interfaces to avoid circular dependencies between
//! cda-sovd, cda-plugin-runtime-update, and cda-plugin-deferred-init.

use std::{future::Future, pin::Pin};

/// HTTP methods for exempt route matching.
#[derive(Clone, Debug, PartialEq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
}

/// A route prefix and set of HTTP methods that are allowed to bypass a guard.
#[derive(Clone, Debug)]
pub struct ExemptRoute {
    pub prefix: String,
    pub methods: Vec<HttpMethod>,
}

impl ExemptRoute {
    /// Creates a new exempt route for the given prefix and methods.
    #[must_use]
    pub fn new(prefix: impl Into<String>, methods: Vec<HttpMethod>) -> Self {
        Self {
            prefix: prefix.into(),
            methods,
        }
    }
}

/// HTTP status codes for guard denials.
#[derive(Clone, Copy, Debug)]
pub struct StatusCode(pub u16);

impl StatusCode {
    pub const CONFLICT: Self = Self(409);
    pub const SERVICE_UNAVAILABLE: Self = Self(503);
}

/// Decision returned by a guard's evaluation.
#[derive(Debug)]
pub enum GuardDecision {
    /// Allow the request to proceed.
    Pass,
    /// Deny the request with the given details.
    Deny(GuardDenial),
}

/// Details for a denied request.
#[derive(Debug)]
pub struct GuardDenial {
    /// HTTP status code.
    pub status: StatusCode,
    /// Human-readable message.
    pub message: String,
    /// SOVD error code (from `sovd_interfaces::error::ErrorCode`).
    /// `ErrorCode::UpdateProcessInProgress` = 4096
    pub error_code: u16,
    /// Optional Retry-After header value in seconds.
    pub retry_after_seconds: Option<u64>,
}

/// Core trait for request guards.
///
/// Implementations must be cheaply cloneable (Arc-based) and thread-safe.
pub trait RequestGuard: Send + Sync + Clone + 'static {
    /// Fast-path check: returns true if the guard is active and requests should be evaluated.
    fn is_active(&self) -> bool;

    /// Evaluate whether a specific request should be allowed.
    fn evaluate<'a>(
        &'a self,
        path: &'a str,
        method: HttpMethod,
    ) -> Pin<Box<dyn Future<Output = GuardDecision> + Send + 'a>>;
}

/// Trait for guards that support exempt routes.
///
/// This is typically implemented by update guards that need to allow
/// certain routes through even when blocking is active.
pub trait ExemptRoutes: RequestGuard {
    /// Register multiple exempt routes.
    fn extend_exempt<'a>(
        &'a self,
        routes: Vec<ExemptRoute>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
}

/// Path prefixes that indicate a request requires `DoIP` communication.
pub const DIAGNOSTIC_PATH_PREFIXES: &[&str] = &[
    "/vehicle/v15/components/",
    "/vehicle/v15/functions/functionalgroups/",
];

/// Returns true if the given path requires `DoIP` communication.
#[must_use]
pub fn requires_doip_communication(path: &str) -> bool {
    DIAGNOSTIC_PATH_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_doip_communication_gates_individual_ecu_paths() {
        assert!(requires_doip_communication(
            "/vehicle/v15/components/ecu1/data/svc"
        ));
        assert!(requires_doip_communication(
            "/vehicle/v15/components/ecu1/operations/svc/executions"
        ));
        assert!(requires_doip_communication(
            "/vehicle/v15/components/flxc1000/faults"
        ));
        assert!(requires_doip_communication(
            "/vehicle/v15/functions/functionalgroups/AllECUs/operations/BrakeSelfTest"
        ));
    }

    #[test]
    fn requires_doip_communication_does_not_gate_listing_paths() {
        assert!(!requires_doip_communication("/vehicle/v15/components"));
        assert!(!requires_doip_communication(
            "/vehicle/v15/functions/functionalgroups"
        ));
        assert!(!requires_doip_communication("/vehicle/v15/functions"));
    }

    #[test]
    fn requires_doip_communication_does_not_gate_non_diagnostic_paths() {
        assert!(!requires_doip_communication("/health"));
        assert!(!requires_doip_communication("/health/ready"));
        assert!(!requires_doip_communication("/vehicle/v15/data/version"));
        assert!(!requires_doip_communication(
            "/vehicle/v15/apps/sovd2uds/data/version"
        ));
        assert!(!requires_doip_communication("/vehicle/v15/locks"));
        assert!(!requires_doip_communication(
            "/vehicle/v15/locks/some-lock-id"
        ));
        assert!(!requires_doip_communication("/vehicle/v15/apps"));
        assert!(!requires_doip_communication(
            "/vehicle/v15/apps/sovd2uds/bulk-data/flashfiles"
        ));
        assert!(!requires_doip_communication("/vehicle/v15/authorize"));
    }
}
