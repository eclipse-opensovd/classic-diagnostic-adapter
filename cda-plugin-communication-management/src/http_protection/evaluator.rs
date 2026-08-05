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

//! Synchronous HTTP request guard trait and decision types.

/// Outcome of evaluating an HTTP request against the active restriction state.
#[derive(Debug)]
pub enum HttpRestrictionDecision {
    /// The request may proceed.
    Pass,
    /// The request is denied with structured information for the response.
    Deny(HttpRestrictionDenial),
}

/// HTTP response information for a denied request.
///
/// Contains the HTTP status, human-readable message, and an optional retry hint.
#[derive(Debug)]
pub struct HttpRestrictionDenial {
    /// HTTP status code to return.
    pub status: http::StatusCode,
    /// Human-readable denial message to include in the response body.
    pub message: String,
    /// Optional `Retry-After` value in seconds to include in the response headers.
    pub retry_after_seconds: Option<u64>,
}

/// Domain-neutral interface for evaluating HTTP requests.
///
/// Implementors expose a cheap atomic fast-path check via [`is_active`](Self::is_active)
/// and a full evaluation via [`evaluate`](Self::evaluate). The Tower middleware uses
/// `is_active` to skip evaluation entirely when no restrictions are active.
pub trait HttpRestrictionGuard: Send + Sync + 'static {
    /// Returns `true` when at least one restriction is active.
    ///
    /// This must remain a single atomic read; no locking or async work is permitted,
    /// because this is used for the 'fast path' in the http handler and will be called
    /// for every http request.
    fn is_active(&self) -> bool;

    /// Evaluates whether the given path and method may proceed.
    fn evaluate(&self, path: &str, method: &http::Method) -> HttpRestrictionDecision;
}
