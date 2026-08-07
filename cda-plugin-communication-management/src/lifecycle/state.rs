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

//! Authoritative lifecycle state tracking for the communication framework.

use cda_interfaces::HashSet;

use super::{
    disable::DisableLeaseId, guard::CommunicationGuardId, operation::CommunicationOperationFailure,
};

/// Authoritative communication lifecycle state.
///
/// This type retains the structured failure in [`CommunicationState::Error`].
/// Use it when callers need the complete current state or failure details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommunicationState {
    /// Communication has not been enabled; unowned and re-enablable.
    Disabled,
    /// Transport enablement or initialization is in progress.
    Enabling,
    /// Transport is enabled and all initializers have completed.
    Enabled,
    /// Transport disablement is in progress.
    Disabling,
    /// Transport is physically disabled and exclusively owned by a `DisableLease`.
    DisabledExclusive,
    /// The latest lifecycle operation failed.
    Error(CommunicationOperationFailure),
}

/// Slot carrying the eventual outcome of an in-flight activation-shaped
/// operation (`Activate`, `Detect`, or a lease `Resume`).
///
/// `None` while the operation is still running; `Some` once it finalizes.
/// Present in [`CommunicationStateData`] only while `state` is
/// [`CommunicationState::Enabling`], so joining callers can await the same result.
pub(crate) type ActivationResultReceiver =
    tokio::sync::watch::Receiver<Option<Result<CommunicationState, CommunicationOperationFailure>>>;

/// State that must change atomically during communication lifecycle transitions.
#[derive(Debug)]
pub(crate) struct CommunicationStateData {
    pub(crate) state: CommunicationState,
    pub(crate) active_guards: HashSet<CommunicationGuardId>,
    pub(crate) disable_owner: Option<DisableLeaseId>,
    /// Set while an activation-shaped operation claimed via
    /// [`crate::lifecycle::controller::CommunicationHandle::activate`],
    /// `request_activate`, or `trigger_detection` is in flight, so concurrent
    /// callers join the same operation instead of racing to claim the transition
    /// themselves.
    pub(crate) activation_result: Option<ActivationResultReceiver>,
    /// Set synchronously by [`crate::lifecycle::controller::CommunicationHandle::shutdown`]
    /// *before* it asks the worker to run its shutdown sequence, and never
    /// cleared. A task detached from the state-store mutex (an in-flight
    /// `claim_or_join` activation, a stale-lease failure path, or a dropped
    /// `DisableLease`'s synchronous defer) must check this, under the same
    /// lock, before publishing its own result: shutdown's own final write is
    /// the authoritative last word, and without this check the two writes
    /// race with scheduler-dependent outcome, including the state going back
    /// to `Enabled` after the transport has already been torn down.
    pub(crate) shutting_down: bool,
}

/// Synchronized state shared by the communication manager and its guards.
///
/// A synchronous mutex is intentional: critical sections are short, never span
/// an await, and communication guards must release state synchronously in `Drop`.
#[derive(Debug)]
pub(crate) struct CommunicationStateStore {
    state: std::sync::Mutex<CommunicationStateData>,
}

impl CommunicationStateStore {
    /// Creates a state store with the given initial lifecycle state.
    #[must_use]
    pub(crate) fn new(initial: CommunicationState) -> Self {
        Self {
            state: std::sync::Mutex::new(CommunicationStateData {
                state: initial,
                active_guards: HashSet::default(),
                disable_owner: None,
                activation_result: None,
                shutting_down: false,
            }),
        }
    }

    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, CommunicationStateData> {
        self.state.lock().unwrap_or_else(|poisoned| {
            tracing::error!("state mutex poisoned; recovering");
            poisoned.into_inner()
        })
    }
}
