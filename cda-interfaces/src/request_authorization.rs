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

//! Context handed to a security plugin immediately before a UDS request is transmitted.
//!
//! The checkpoint runs after the request is fully resolved, for requests triggered by a caller.
//! CDA-internal traffic (variant detection, tester present, session and security resets) is
//! not subject to it.

use async_trait::async_trait;

use crate::ServicePayload;

/// The diagnostic entity a request is addressed to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UdsRequestTarget {
    /// A single physical ECU.
    Ecu {
        /// Name of the ECU as used in the diagnostic description.
        name: String,
        /// Names of the configured `/components` additional fields the ECU currently belongs
        /// to, sorted. Empty if none are configured or the ECU belongs to none.
        additional_fields: Vec<String>,
    },
    /// A functional (broadcast) request to a functional group.
    FunctionalGroup {
        /// Name of the functional group.
        name: String,
        /// Names of the ECUs expected to answer on the gateway this transmission goes to,
        /// sorted.
        ecus: Vec<String>,
    },
}

/// Snapshot of the lock relevant to a request target.
///
/// Owned, so no lock state is held while the security plugin runs.
#[derive(Clone, Debug, PartialEq)]
pub struct RequestLockContext {
    /// Subject that holds the lock.
    pub holder: String,
    /// Verified claims of the holder at the time the lock was acquired.
    pub claims: serde_json::Map<String, serde_json::Value>,
    /// Vendor metadata supplied when the lock was acquired.
    pub metadata: serde_json::Map<String, serde_json::Value>,
}

/// Everything known about a request that is about to be transmitted.
#[derive(Clone, Debug)]
pub struct UdsRequestSendContext<'a> {
    /// Entity the request is addressed to.
    pub target: UdsRequestTarget,
    /// The complete request, including addressing and any pending session or security
    /// transition.
    pub payload: &'a ServicePayload,
    /// The most specific effective lock for the target, if any.
    pub lock: Option<RequestLockContext>,
}

/// Provides the current lock for a request target.
#[async_trait]
pub trait RequestLockProvider: Send + Sync + 'static {
    /// Returns the most specific effective lock for `target`, or `None` if it is not locked.
    ///
    /// A physical target prefers its own lock, then a functional-group lock covering it, then
    /// a vehicle lock. A functional target prefers its group's lock, then a vehicle lock.
    async fn current_lock(&self, target: &UdsRequestTarget) -> Option<RequestLockContext>;
}

/// [`RequestLockProvider`] for setups without lock state: nothing is ever locked.
#[derive(Default)]
pub struct NoRequestLockProvider;

#[async_trait]
impl RequestLockProvider for NoRequestLockProvider {
    async fn current_lock(&self, _target: &UdsRequestTarget) -> Option<RequestLockContext> {
        None
    }
}
