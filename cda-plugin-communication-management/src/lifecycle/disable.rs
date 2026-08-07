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

use std::sync::Arc;

use async_trait::async_trait;

use super::{
    controller::CommunicationHandle,
    operation::{CommunicationOperation, CommunicationOperationFailure},
    state::CommunicationState,
};
use crate::plugin::CommunicationPlugin;

/// Reason supplied by the owner who is taking the communication offline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisableReason {
    /// A runtime file update needs exclusive transport ownership.
    RuntimeUpdate,
    /// An application-defined disable reason.
    Custom(String),
}

/// Exclusive transport-disable capability.
/// Only one own `DisableLease` can be active at a time.
#[async_trait]
pub trait DisableCommunication: Send + Sync + 'static {
    /// Disables communication to the ECUs until the lease is released.
    /// Does stop communication to SOVD.
    async fn disable(&self, reason: DisableReason) -> Result<DisableLease, DisableError>;
}

/// Cloneable narrow disable view forwarding to the authoritative plugin.
/// This adapter lets diagnostic consumers depend on [`CommunicationDisableView`]
/// without receiving the full [`CommunicationPlugin`] lifecycle authority.
#[derive(Clone)]
pub struct CommunicationDisableView {
    plugin: Arc<dyn CommunicationPlugin>,
}

impl CommunicationDisableView {
    /// Creates a disable-only view over the selected communication plugin.
    #[must_use]
    pub fn new(plugin: Arc<dyn CommunicationPlugin>) -> Self {
        Self { plugin }
    }
}

#[async_trait]
impl DisableCommunication for CommunicationDisableView {
    async fn disable(&self, reason: DisableReason) -> Result<DisableLease, DisableError> {
        self.plugin.disable(reason).await
    }
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

/// Private identity used to prevent stale leases from resuming after a later disable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DisableLeaseId(uuid::Uuid);

impl DisableLeaseId {
    pub(crate) fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}

/// Exclusive ownership of a disabled communication transport.
///
/// The lease is deliberately non-cloneable. Two operations release exclusive ownership:
///
/// * **[`release`]`.await`** - submits the release to the lifecycle worker, which
///   eagerly resumes the transport and runs all post-activation initializers
///   before replying. Use this in async contexts when callers need to confirm
///   that communication is back up.
///
///   Release is cancellation-safe: dropping the `release()` future *before* the
///   worker has durably accepted the request (i.e. before the underlying
///   `send` to the bounded lifecycle mailbox completes) falls back to the
///   synchronous defer-on-drop behavior below, exactly as if `release` had
///   never been called. Once accepted, the worker owns the release and
///   finishes it regardless of what the caller's task does afterward.
///
/// * **`drop(lease)` / going out of scope** -- releases exclusive ownership
///   synchronously without resuming the transport. State transitions to unowned
///   `Disabled` and the HTTP protection stays active. The next inbound diagnostic
///   request triggers on-demand recovery through `request_activate`. This is the
///   right choice when the caller does not need to await re-activation.
///
/// In both cases the disable-lease owner identity is cleared so no stale lease can
/// interfere with a subsequent disable cycle.
#[must_use = "dropping an unreleased lease releases exclusivity; transport stays Disabled until \
              on-demand recovery"]
pub struct DisableLease {
    handle: CommunicationHandle,
    id: Option<DisableLeaseId>,
}

impl std::fmt::Debug for DisableLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DisableLease")
            .finish_non_exhaustive()
    }
}

impl DisableLease {
    pub(crate) fn new(handle: CommunicationHandle, id: DisableLeaseId) -> Self {
        Self {
            handle,
            id: Some(id),
        }
    }

    /// Consumes this lease and awaits the worker-owned resume sequence.
    ///
    /// Returns `Ok(CommunicationState::Enabled)` when re-activation succeeds, or
    /// `Err` when re-activating the transport or an initializer fails.
    ///
    /// # Errors
    ///
    /// Returns an error when re-activating the transport or an initializer
    /// fails, this lease is stale (already released), or the lifecycle worker
    /// is shutting down.
    pub async fn release(mut self) -> Result<CommunicationState, CommunicationOperationFailure> {
        let Some(id) = self.id else {
            return Err(stale_resume_failure());
        };
        let reply = match self.handle.submit_release(id).await {
            Ok(reply) => reply,
            // Not accepted into the worker mailbox (shutdown). `self.id` stays
            // `Some`, so returning here lets `self`'s normal `Drop` perform the
            // synchronous defer, exactly as if `release` had never been called.
            Err(failure) => return Err(failure),
        };
        // Accepted: the worker now owns this release and will finish it even if
        // our own task is cancelled while awaiting `reply` below. Clear `id` so
        // a `Drop` racing that cancellation becomes a no-op instead of racing
        // the worker's own state transition.
        self.id = None;
        reply.await.unwrap_or_else(|_| Err(stale_resume_failure()))
    }

    #[cfg(test)]
    pub(crate) fn identity(&self) -> Option<DisableLeaseId> {
        self.id
    }
}

/// Dropping a lease without calling [`release`] releases exclusive disable
/// ownership synchronously. State transitions to unowned `Disabled` and HTTP
/// protection remains active. The on-demand mechanism (`request_activate`)
/// recovers on the next inbound diagnostic request.
impl Drop for DisableLease {
    fn drop(&mut self) {
        let Some(id) = self.id.take() else {
            return;
        };
        // Drop cannot propagate errors. A permission failure here would mean
        // this lease is already stale (id mismatch), which is harmless -- the
        // state is already owned by a newer cycle. Ignore the result.
        let _ = self.handle.defer_disable(id);
    }
}

pub(crate) fn stale_resume_failure() -> CommunicationOperationFailure {
    CommunicationOperationFailure::TransitionFailure {
        operation: CommunicationOperation::Resume,
    }
}
