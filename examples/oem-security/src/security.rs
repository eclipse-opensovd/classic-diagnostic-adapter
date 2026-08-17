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

//! The security plugin itself.
//!
//! Two types make up the extension point, and the split matters:
//!
//! - [`OemSecurityData`] is the *per-request* context. It answers who the caller
//!   is ([`Claims`]) and whether a diagnostic service may run ([`SecurityApi`]).
//! - [`OemSecurityLoader`] builds one per request and serves `/authorize`.
//!
//! Every other layer - SOVD handlers, the runtime-update policy - receives the
//! per-request instance and *asks* it, instead of reading claims and deciding
//! for itself. Replacing the plugin therefore changes access decisions
//! everywhere at once, including who the update path considers the caller.
//!
//! Authentication is stubbed here: a real integration validates a token in
//! [`initialize_from_request_parts`](SecurityPluginInitializer::initialize_from_request_parts)
//! and returns `Err(AuthError::NoTokenProvided)` to reject the request.

use aide::axum::IntoApiResponse;
use async_trait::async_trait;
use axum::http::request::Parts;
use cda_interfaces::DiagServiceError;
use cda_plugin_security::{
    AuthApi, AuthError, AuthorizationRequestHandler, Claims, SecurityApi, SecurityPlugin,
    SecurityPluginInitializer, SecurityPluginLoader,
};

/// Per-request security context: the identity plus whatever policy inputs go with it.
pub struct OemSecurityData {
    subject: String,
}

impl Claims for OemSecurityData {
    fn sub(&self) -> &str {
        &self.subject
    }
}

impl AuthApi for OemSecurityData {
    fn claims(&self) -> Box<&dyn Claims> {
        Box::new(self)
    }
}

impl SecurityApi for OemSecurityData {
    fn validate_service(
        &self,
        _service: &cda_database::datatypes::DiagService,
    ) -> Result<(), DiagServiceError> {
        // A real policy would check the service against this caller's roles and
        // return `DiagServiceError` to refuse it.
        Ok(())
    }
}

impl SecurityPlugin for OemSecurityData {
    fn as_auth_plugin(&self) -> &dyn AuthApi {
        self
    }

    fn as_security_plugin(&self) -> &dyn SecurityApi {
        self
    }
}

/// Builds an [`OemSecurityData`] per request and serves the authorize endpoint.
#[derive(Default)]
pub struct OemSecurityLoader;

#[async_trait]
impl SecurityPluginInitializer for OemSecurityLoader {
    async fn initialize_from_request_parts(
        &self,
        _parts: &mut Parts,
    ) -> Result<Box<dyn SecurityPlugin>, AuthError> {
        Ok(Box::new(OemSecurityData {
            subject: "example-oem-user".to_owned(),
        }))
    }
}

#[async_trait]
impl AuthorizationRequestHandler for OemSecurityLoader {
    async fn authorize(
        _headers: axum::http::HeaderMap,
        _body_bytes: bytes::Bytes,
    ) -> impl IntoApiResponse {
        // Where an integration would exchange credentials for a token.
        axum::http::StatusCode::NOT_IMPLEMENTED
    }
}

impl SecurityPluginLoader for OemSecurityLoader {}
