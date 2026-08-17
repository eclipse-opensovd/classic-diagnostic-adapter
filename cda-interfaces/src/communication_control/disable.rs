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

//! Exclusive, consuming transport-disable ownership.
//!
//! The contract lives here rather than in the communication plugin so that
//! consumers needing exclusive transport ownership - the runtime-update plugin,
//! chiefly - depend only on this crate. The authoritative implementation stays in
//! the plugin, which is the only thing that can actually take the transport down.

use async_trait::async_trait;

use crate::communication_control::{CommunicationOperationFailure, CommunicationState};

/// Reason supplied by the owner who is taking the communication offline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisableReason {
    /// A runtime file update needs exclusive transport ownership.
    RuntimeUpdate,
    /// An application-defined disable reason.
    Custom(String),
}

/// Failure to acquire the exclusive disable lease.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DisableError {
    /// Diagnostics are currently using communication.
    #[error("Communication is in use")]
    InUse,
    /// Disabling is unavailable in the current lifecycle state.
    #[error("Cannot disable in the current lifecycle state")]
    Conflict,
    /// Disabling the physical transport failed.
    #[error("Disabling communication failed: {0}")]
    Failed(CommunicationOperationFailure),
}

/// Exclusive ownership of disabled communication.
///
/// Finish with one of two deliberately different outcomes:
///
/// * **[`release`](Self::release)** restores what the guard displaced. A guard
///   taken from an enabled runtime awaits transport enablement and
///   post-activation initialization; one taken from an already-disabled runtime
///   returns to disabled. A release can never enable a runtime the releaser did
///   not find enabled - otherwise a holder of only [`DisableCommunication`]
///   could start vehicle communication that `init_mode` never authorized.
///
/// * **drop** relinquishes exclusivity but leaves communication disabled. This is
///   the cancellation- and panic-safe fallback: being synchronous, it cannot
///   resume the async transport itself. A later authorized on-demand activation
///   may resume it.
#[async_trait]
pub trait DisableGuard: Send + Sync + std::fmt::Debug {
    /// Consumes this guard and restores what it displaced.
    ///
    /// # Errors
    /// Returns an error when re-activating the transport or an initializer
    /// fails, this guard is stale (already released), or the lifecycle worker is
    /// shutting down.
    async fn release(self: Box<Self>) -> Result<CommunicationState, CommunicationOperationFailure>;
}

/// Exclusive transport-disable capability.
///
/// Only one guard can be active at a time.
#[async_trait]
pub trait DisableCommunication: Send + Sync + 'static {
    /// Disables communication to the ECUs until the guard is released or dropped.
    /// Does not stop communication to SOVD.
    ///
    /// # Errors
    /// Returns [`DisableError`] when the lease cannot be acquired.
    async fn disable(&self, reason: DisableReason) -> Result<Box<dyn DisableGuard>, DisableError>;
}
