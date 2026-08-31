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

//! The narrow, diagnostic-use communication contract.
//!
//! [[ dimpl~communication-control-access, Capability-limited diagnostic communication access, dimpl, req~dt-deferred-initialization; arch~dt-deferred-initialization ]]
//!
//! Defined here rather than in the default communication plugin's crate, so that
//! transport crates and replacement plugins can depend on the contract without
//! coupling to that implementation.
use std::time::Duration;

use super::{
    DEFAULT_DEFERRED_RETRY_AFTER, VariantDetectionMode,
    operation::{ActivationCause, CommunicationOperation, CommunicationOperationFailure},
};

/// Authoritative communication lifecycle state.
///
/// [`CommunicationState::Enabling`] identifies the lifecycle operation in
/// progress, while [`CommunicationState::Error`] retains the structured failure
/// from the latest lifecycle operation. Use this type when callers need the
/// complete current state or failure details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommunicationState {
    /// Communication has not been enabled, the state is not owned and can be enabled by anyone.
    Disabled,
    /// An enabling lifecycle operation is in progress.
    Enabling(CommunicationOperation),
    /// Transport is enabled and every stage the claiming operation called for
    /// has completed.
    ///
    /// Which stages those were depends on the operation. An
    /// [`Enable`](CommunicationOperation::Enable) reaches `Enabled` with no
    /// variant detected. `Enabled` does not mean detection concluded. Detection
    /// settles per ECU and asynchronously, so per-ECU `VariantState` is the
    /// readiness signal.
    Enabled,
    /// Transport disablement is in progress.
    Disabling,
    /// Transport is physically disabled and exclusively owned by a `DisableLease`.
    DisabledExclusive,
    /// The latest lifecycle operation failed.
    Error(CommunicationOperationFailure),
}

/// Error returned by communication guard acquisition.
///
/// This is a minimal enum containing only the states that can prevent
/// guard acquisition. Lifecycle operation failures should be reported via
/// the `Result` returned by a communication plugin's `enable()` and
/// `DisableLease::release()`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommunicationError {
    /// Communication is currently disabled. No new guards can be acquired.
    #[error("Communication is disabled")]
    Disabled,
    /// Communication is currently being enabled.
    #[error("Communication is being enabled")]
    Enabling,
    /// Communication is currently being disabled.
    #[error("Communication is being disabled")]
    Disabling,
    /// Communication is disabled and exclusively owned by a disable lease.
    #[error("Communication is exclusively disabled")]
    DisabledExclusive,
    /// Communication has failed and cannot be used.
    #[error("Communication has failed: {0}")]
    Failed(CommunicationOperationFailure),
}

/// Opaque RAII guard marking communication as in use, so it cannot be
/// disabled (e.g. by a runtime update) while diagnostic activity is ongoing.
///
/// The implementation is owned by whichever [`CommunicationAccess`] minted it
/// via [`CommunicationGuard::new`]. This type only stores it type-erased and
/// drops it. Communication is free again once the last guard is dropped.
#[must_use = "The guard must be held for the complete diagnostic-activity lifetime. Communication \
              is marked as 'free' once the last guard is dropped. As long as any guard lives, \
              communication cannot be disabled."]
pub struct CommunicationGuard {
    _inner: Box<dyn Send + Sync>,
}

impl CommunicationGuard {
    /// Wraps an implementation-defined guard so that its concrete type stays
    /// private to the [`CommunicationAccess`] implementation that minted it.
    pub fn new(inner: impl Send + Sync + 'static) -> Self {
        Self {
            _inner: Box::new(inner),
        }
    }
}

/// Narrow capability that does not expose full lifecycle control.
///
/// Consumers can inspect state, hold communication active for an operation and
/// request activation, but cannot disable it, run explicit whole-vehicle
/// (re-)detection, or otherwise administer the underlying plugin.
pub trait CommunicationAccess: Send + Sync + 'static {
    /// Returns the authoritative lifecycle state.
    fn state(&self) -> CommunicationState;

    /// Acquires diagnostic communication if it is enabled.
    /// The returned guard prevents the communication from being shut down while it is alive.
    ///
    /// # Errors
    ///
    /// Returns an error when communication is not enabled.
    fn acquire(&self) -> Result<CommunicationGuard, CommunicationError>;

    /// Requests activation without blocking.
    ///
    /// Callers must check [`state`](Self::state) before using communication.
    fn request_activate(&self, cause: ActivationCause) -> CommunicationState;

    /// Returns the retry hint for requests deferred while communication starts.
    ///
    /// The default preserves compatibility for custom access implementations
    /// that do not expose configuration-owned retry timing.
    fn retry_after(&self) -> Duration {
        DEFAULT_DEFERRED_RETRY_AFTER
    }

    /// Returns the effective detection policy for the currently enabled (or
    /// currently being enabled) communication runtime.
    ///
    /// Lets a consumer waiting on its own readiness signal distinguish
    /// "detection is still settling" from "nothing will ever settle this".
    fn variant_detection(&self) -> VariantDetectionMode;
}
