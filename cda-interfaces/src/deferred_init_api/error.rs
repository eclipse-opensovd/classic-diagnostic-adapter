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

//! Error types for deferred initialization.
//!
//! Provides structured error types for the deferred initialization plugin system,
//! enabling proper error handling and propagation throughout the initialization lifecycle.

/// Errors that can occur during deferred initialization.
///
/// Only variants that the pipeline can actually produce are included.
/// Additional variants can be re-added via `#[non_exhaustive]` when
/// there is a concrete producer for them.
#[derive(Debug, Clone, PartialEq, strum::Display)]
#[non_exhaustive]
pub enum DeferredInitError {
    /// Communication initialization failed (wraps `CommControlError` message).
    InitFailed(String),

    /// Initialization timed out.
    Timeout {
        /// The duration after which initialization was aborted.
        elapsed_secs: u64,
    },

    /// Initialization was cancelled (e.g., during shutdown).
    Cancelled,
}

impl std::error::Error for DeferredInitError {}
