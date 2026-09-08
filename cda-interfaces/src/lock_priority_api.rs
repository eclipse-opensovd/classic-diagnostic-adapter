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

//! Vendor-neutral policy interface for lock acquisition and preemption.

use std::time::SystemTime;

use async_trait::async_trait;
use serde_json::{Map, Value};
use thiserror::Error;

/// Entity protected by a lock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LockScope {
    /// Whole vehicle.
    Vehicle,
    /// One ECU component.
    Ecu { name: String },
    /// One functional group.
    FunctionalGroup { name: String },
}

/// Owned caller identity available to lock policy implementations.
#[derive(Clone, Debug, PartialEq)]
pub struct LockPrincipal {
    /// Stable subject used by CDA as authoritative lock-owner identity.
    ///
    /// This value comes from the security plugin's `Claims::sub`, not from an entry in `claims`.
    pub subject: String,
    /// Complete verified claim attributes exposed by the security plugin.
    ///
    /// Policy implementations must not treat a `sub` entry in this map as authoritative; use
    /// `subject` for ownership decisions.
    pub claims: Map<String, Value>,
}

/// Requested lock and policy inputs supplied by the client.
#[derive(Clone, Debug, PartialEq)]
pub struct LockRequest {
    /// Requested lock scope.
    pub scope: LockScope,
    /// Requesting principal.
    pub principal: LockPrincipal,
    /// Absolute requested expiration time.
    pub expires_at: SystemTime,
    /// Whether the client requested breaking conflicting locks.
    pub break_lock: bool,
    /// Resolved exclusivity after applying CDA configuration defaults.
    pub exclusive: bool,
    /// Vendor extension values from the request body.
    pub metadata: Map<String, Value>,
}

/// Immutable view of an existing active lock.
#[derive(Clone, Debug, PartialEq)]
pub struct LockSnapshot {
    /// SOVD lock identifier.
    pub id: String,
    /// Protected entity.
    pub scope: LockScope,
    /// Principal which acquired the lock.
    pub principal: LockPrincipal,
    /// Vendor extension values supplied during acquisition.
    pub metadata: Map<String, Value>,
    /// Whether this lock excludes read communication by other clients.
    pub exclusive: bool,
    /// Parent vehicle-lock ID for an adopted child lock.
    pub parent_vehicle_lock_id: Option<String>,
    /// Absolute expiration time.
    pub expires_at: SystemTime,
}

/// One revision-aware priority-policy evaluation.
#[derive(Clone, Debug, PartialEq)]
pub struct LockPriorityEvaluation {
    /// Identifier for correlating this evaluation with lifecycle events and logs.
    pub evaluation_id: String,
    /// Lock operation being evaluated.
    pub operation: LockPriorityOperation,
    /// Requested lock and caller context.
    pub request: LockRequest,
    /// State revision against which the decision will be validated.
    pub revision: u64,
    /// Time at which CDA captured this evaluation state.
    pub captured_at: SystemTime,
    /// Active locks in deterministic scope-and-ID order.
    pub active_locks: Vec<LockSnapshot>,
    /// Lock IDs which this request may preempt.
    pub preemption_candidates: Vec<String>,
}

/// Operation presented to a revision-aware priority policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LockPriorityOperation {
    /// Acquire a new lock.
    Acquire,
    /// Renew an existing lock through `POST` by its current owner.
    PostRenew {
        /// Existing lock ID that would be renewed.
        ///
        /// The full prior [`LockSnapshot`] for this lock is not provided
        /// denormalized here; look it up in
        /// `evaluation.active_locks` by matching this `lock_id`.
        lock_id: String,
    },
}

/// Result of evaluating a lock acquisition.
#[derive(Clone, Debug, PartialEq)]
pub enum LockPriorityDecision {
    /// Permit acquisition without preempting locks.
    Allow,
    /// Reject acquisition.
    Deny {
        /// Human-readable denial reason.
        reason: String,
        /// Optional response parameters.
        parameters: Map<String, Value>,
    },
    /// Permit acquisition and preempt selected active locks.
    Preempt {
        /// Existing lock IDs selected by policy.
        lock_ids: Vec<String>,
        /// Identity recorded on defunct locks.
        broken_by: String,
    },
}

/// Failure while evaluating lock policy.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum LockPriorityError {
    /// Request metadata or claims do not satisfy the policy schema.
    #[error("Invalid lock priority context: {0}")]
    InvalidContext(String),
    /// Policy service is temporarily unavailable.
    #[error("Lock priority policy unavailable: {0}")]
    Unavailable(String),
    /// Policy implementation failed.
    #[error("Lock priority policy failed: {0}")]
    Internal(String),
}

/// A committed lock lifecycle transition.
#[derive(Clone, Debug, PartialEq)]
pub enum LockLifecycleEvent {
    /// A new lock was created.
    Created {
        /// Evaluation ID when creation followed a vehicle policy evaluation.
        evaluation_id: Option<String>,
        /// The newly active lock.
        lock: LockSnapshot,
    },
    /// An existing lock was renewed (its expiration extended) by its owner.
    Renewed {
        /// Evaluation ID when renewal followed a vehicle policy evaluation.
        evaluation_id: Option<String>,
        /// The renewed lock.
        lock: LockSnapshot,
    },
    /// A lock was explicitly released (`DELETE`) by its owner.
    ///
    /// Deleting a vehicle lock emits one event for each removed child and one for the vehicle
    /// lock itself.
    Released {
        /// The lock as it existed immediately before release.
        lock: LockSnapshot,
    },
    /// A lock reached its expiration deadline and was removed.
    ///
    /// Expiring a vehicle lock emits one event for each removed child and one for the vehicle
    /// lock itself.
    Expired {
        /// The lock as it existed immediately before expiration.
        lock: LockSnapshot,
    },
    /// A preemption was committed: one or more existing locks became defunct and a
    /// replacement lock was created.
    Preempted {
        /// Evaluation ID shared with the corresponding `evaluate` call.
        evaluation_id: String,
        /// The newly active replacement lock.
        replacement: LockSnapshot,
        /// Identity recorded as the preemptor.
        broken_by: String,
        /// Identifiers of the locks that became defunct as part of this preemption.
        defunct_lock_ids: Vec<String>,
    },
    /// Same-owner locks were converted into a replacement lock without becoming defunct.
    Converted {
        /// The newly active replacement lock.
        replacement: LockSnapshot,
        /// Identifiers of locks consumed by the conversion.
        converted_lock_ids: Vec<String>,
    },
}

/// Revision-aware vendor policy used for every lock acquisition.
#[async_trait]
pub trait LockPriorityPolicy: Send + Sync + 'static {
    /// Evaluates one request against a revisioned snapshot and candidate set.
    ///
    /// Implementations must offload blocking or CPU-intensive work, for example with
    /// `tokio::task::spawn_blocking`; this future runs on CDA's asynchronous request runtime.
    async fn evaluate(
        &self,
        evaluation: &LockPriorityEvaluation,
    ) -> Result<LockPriorityDecision, LockPriorityError>;

    /// Best-effort notification after a lock lifecycle transition is committed.
    ///
    /// The default implementation does nothing. CDA contains and logs callback timeouts
    /// and panics; delivery never affects the triggering HTTP response and is not retried.
    /// Implementations must not perform synchronous blocking work. Offload blocking or
    /// CPU-intensive work, for example with `tokio::task::spawn_blocking`. A timeout can
    /// only interrupt callback futures that yield to the asynchronous runtime.
    async fn on_lock_event(&self, _event: &LockLifecycleEvent) {}
}
