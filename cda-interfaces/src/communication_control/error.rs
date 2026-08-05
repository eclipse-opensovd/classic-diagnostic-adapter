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

//! Error types for communication control and policies.

use thiserror::Error;

/// Errors that can occur during communication control operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CommControlError {
    /// Communication initialization failed.
    #[error("Communication initialization failed: {0}")]
    InitFailed(String),

    /// Communication initialization failed for multiple components.
    #[error("Communication initialization failed for multiple components: {0:?}")]
    InitFailedMultipleComponents(Vec<String>),
}
