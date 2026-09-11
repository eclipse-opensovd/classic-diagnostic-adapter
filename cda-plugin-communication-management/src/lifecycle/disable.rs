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
// `DisableLease` below is the authoritative implementation of `DisableGuard`.
pub use cda_interfaces::communication_control::disable::{
    DisableCommunication, DisableError, DisableGuard, DisableReason,
};
use cda_interfaces::communication_control::{
    CommunicationOperation, CommunicationOperationFailure, CommunicationState,
};

use super::controller::CommunicationHandle;
use crate::plugin::CommunicationPlugin;

/// Cloneable narrow disable view forwarding to the authoritative plugin, so
/// consumers can depend on [`DisableCommunication`] without receiving the full
/// [`CommunicationPlugin`] lifecycle authority.
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
    async fn disable(&self, reason: DisableReason) -> Result<Box<dyn DisableGuard>, DisableError> {
        self.plugin
            .disable(reason)
            .await
            .map(|lease| Box::new(lease) as Box<dyn DisableGuard>)
    }
}

/// Identity used to prevent stale leases from resuming after a later disable.
///
/// A newtype rather than a type alias, so the UUID stays an implementation
/// detail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DisableLeaseId(uuid::Uuid);

impl DisableLeaseId {
    pub(crate) fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}

/// Exclusive disable owner and the state restored when its lease is released.
///
/// These values are captured atomically when the lease is granted so each
/// disable generation restores only the state it displaced.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DisableOwner {
    pub(crate) id: DisableLeaseId,
    /// Whether the transport was enabled when this lease was granted.
    ///
    /// If false, releasing the lease returns to `Disabled` without activating
    /// communication.
    pub(crate) resumes_transport: bool,
    /// Whether resuming the displaced runtime runs variant detection.
    ///
    /// Captured from the effective
    /// [`variant_detection`](crate::lifecycle::state::CommunicationStateData::variant_detection)
    /// when the lease is granted.
    pub(crate) resume_detects: bool,
}

impl DisableOwner {
    pub(crate) fn owns(owner: Option<Self>, id: DisableLeaseId) -> bool {
        owner.is_some_and(|owner| owner.id == id)
    }
}

/// Exclusive ownership of disabled communication.
///
/// The authoritative [`DisableGuard`] implementation. See that trait for the
/// `release` and drop semantics, and [`CommunicationHandle::disable`] for which
/// states grant a lease.
///
/// # Examples
///
/// Resume communication before continuing:
///
/// ```ignore
/// let lease = communication.disable(DisableReason::RuntimeUpdate).await?;
/// update_runtime_files().await?;
/// lease.release().await?; // transport is enabled and initializers completed
/// ```
///
/// Leave communication disabled for later on-demand recovery:
///
/// ```ignore
/// let lease = communication.disable(DisableReason::RuntimeUpdate).await?;
/// update_runtime_files().await?;
/// drop(lease); // releases exclusivity only, transport remains disabled
/// ```
#[must_use = "Dropping an unreleased lease releases exclusivity; transport stays Disabled until \
              (on-demand) recovery"]
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
    /// Inherent rather than only via [`DisableGuard`] so callers holding a
    /// concrete lease need no boxing.
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
            // `Some`, so `Drop` performs the synchronous defer.
            Err(failure) => return Err(failure),
        };
        // The worker now owns this release and finishes it even if this task is
        // canceled below, so clear `id` to make a racing `Drop` a no-op.
        self.id = None;
        reply.await.unwrap_or_else(|_| Err(stale_resume_failure()))
    }

    /// Exposes the opaque ID to tests that verify a stale lease cannot release a
    /// later disable cycle.
    #[cfg(test)]
    pub(crate) fn identity(&self) -> Option<DisableLeaseId> {
        self.id
    }
}

#[async_trait]
impl DisableGuard for DisableLease {
    async fn release(self: Box<Self>) -> Result<CommunicationState, CommunicationOperationFailure> {
        DisableLease::release(*self).await
    }
}

/// Dropping a lease without calling [`release`](DisableLease::release) releases exclusive disable
/// ownership synchronously. State transitions to unowned `Disabled`, and
/// `request_activate` recovers on the next inbound diagnostic request.
impl Drop for DisableLease {
    fn drop(&mut self) {
        let Some(id) = self.id.take() else {
            return;
        };
        // A permission failure means this lease is stale, so the state is
        // already owned by a newer cycle. Drop cannot propagate it anyway.
        let _ = self.handle.defer_disable(id);
    }
}

pub(crate) fn stale_resume_failure() -> CommunicationOperationFailure {
    CommunicationOperationFailure::TransitionFailure {
        operation: CommunicationOperation::Resume,
    }
}
