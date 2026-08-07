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

//! Error types for communication management.

/// Error returned by communication guard acquisition.
///
/// This is a minimal enum containing only the states that can prevent
/// guard acquisition. Lifecycle operation failures are reported via
/// the `Result` returned by `enable()` and `DisableLease::release()`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommunicationError {
    /// Communication is currently disabled; new guards cannot be acquired.
    #[error("communication is disabled")]
    Disabled,
    /// Communication is currently being enabled.
    #[error("communication is being enabled")]
    Enabling,
    /// Communication is currently being disabled.
    #[error("communication is being disabled")]
    Disabling,
    /// Communication is disabled and exclusively owned by a disable lease.
    #[error("communication is exclusively disabled")]
    DisabledExclusive,
    /// Communication has failed and cannot be used.
    #[error("communication has failed: {0}")]
    Failed(super::operation::CommunicationOperationFailure),
}
