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

use std::sync::Arc;

use cda_interfaces::{
    HashSet,
    communication_control::{
        CommunicationOperation, CommunicationOperationFailure, CommunicationState,
        CommunicationVariantDetection, VariantDetectionMode,
    },
    util::std_ext,
};

use super::{disable::DisableOwner, guard::CommunicationGuardId};

/// Slot carrying the eventual outcome of an in-flight enabling operation
/// (`Enable`, `Detect`, or a lease `Resume`).
///
/// `None` while the operation is still running. Present in
/// [`CommunicationStateData`] only while `state` is
/// [`CommunicationState::Enabling`], so joining callers await the same result.
pub(crate) type EnablingResultReceiver =
    tokio::sync::watch::Receiver<Option<Result<CommunicationState, CommunicationOperationFailure>>>;

/// The detection mode to publish for a resolved detector. A missing
/// registration reports `Never`, like a disabled policy.
pub(crate) fn detection_mode(
    detector: Option<&Arc<dyn CommunicationVariantDetection>>,
) -> VariantDetectionMode {
    if detector.is_some() {
        VariantDetectionMode::Always
    } else {
        VariantDetectionMode::Never
    }
}

/// State that must change atomically during communication lifecycle transitions.
pub(crate) struct CommunicationStateData {
    pub(crate) state: CommunicationState,
    pub(crate) active_guards: HashSet<CommunicationGuardId>,
    /// The current exclusive disable owner, carrying both its identity and
    /// whether releasing it re-enables the transport (see [`DisableOwner`]).
    pub(crate) disable_owner: Option<DisableOwner>,
    /// Set while a claimed enabling operation is in flight, so concurrent
    /// callers join it instead of claiming a transition of their own.
    /// [`transition::decide`](crate::lifecycle::transition::decide) decides
    /// which of the two they do.
    pub(crate) enabling_result: Option<EnablingResultReceiver>,
    /// Set while a whole-vehicle variant detection is running, so concurrent
    /// callers join it instead of starting another one.
    ///
    /// Detection is not a lifecycle state. `state` stays `Enabled` throughout,
    /// so guards keep being admitted, and a failure reports through the
    /// caller's `Result` rather than as [`CommunicationState::Error`]. Kept
    /// separate from `enabling_result`, so that a `Detect` cannot observe an
    /// enabling operation's outcome as its own.
    pub(crate) detection_in_flight: Option<EnablingResultReceiver>,
    /// The configured detection policy, fixed for the process lifetime.
    pub(crate) configured_variant_detection: VariantDetectionMode,
    /// The registered whole-vehicle variant detector. While it is `None`, no
    /// operation can settle a variant, whatever the configuration says.
    ///
    /// Lives here rather than in the worker's `WorkerResources`, because the
    /// claim side has to resolve it synchronously, together with the detection
    /// mode it publishes (see [`Self::variant_detector`]).
    pub(crate) variant_detector: Option<Arc<dyn CommunicationVariantDetection>>,
    /// The effective detection policy for the runtime that is currently
    /// enabled, or being enabled.
    ///
    /// Differs from `configured_variant_detection` in both directions. An
    /// [`enable`](crate::lifecycle::controller::CommunicationHandle::enable)
    /// reports `Never` where the configuration says `Always`, and a
    /// [`redetect`](crate::lifecycle::controller::CommunicationHandle::redetect)
    /// reports `Always` where it says `Never`.
    ///
    /// Written at claim time, so a reader during `Enabling(_)` already learns
    /// whether anything will settle a variant.
    pub(crate) variant_detection: VariantDetectionMode,
    /// Set synchronously by
    /// [`crate::lifecycle::controller::CommunicationHandle::shutdown`] before
    /// the worker runs its shutdown sequence, and never cleared.
    ///
    /// Every detached task that publishes a state must check this under the same
    /// lock. Otherwise it can race shutdown's terminal write and put the state
    /// back to `Enabled` after the transport was torn down.
    pub(crate) shutting_down: bool,
}

impl CommunicationStateData {
    /// Whether an *automatic* activation for `operation` runs the detection
    /// stage: the operation's own shape, gated by the configured policy.
    ///
    /// An explicit [`CommunicationOperation::Detect`] never goes through here.
    /// `VariantDetectionMode::Never` suppresses automatic detection only.
    pub(crate) fn runs_detection_for(&self, operation: CommunicationOperation) -> bool {
        operation.runs_detection()
            && self.configured_variant_detection == VariantDetectionMode::Always
    }

    /// The registered variant detector, or `None` if nothing has
    /// registered one.
    ///
    /// Resolved in the same locked read that publishes
    /// [`variant_detection`](Self::variant_detection), so the detector handed to
    /// the worker and the policy readiness consumers see cannot disagree.
    pub(crate) fn variant_detector(&self) -> Option<Arc<dyn CommunicationVariantDetection>> {
        self.variant_detector.as_ref().map(Arc::clone)
    }

    /// Publishes the final state for a completed enabling operation
    /// and clears the enabling-result slot.
    ///
    /// A no-op once `shutting_down` is set, so it cannot overwrite shutdown's
    /// terminal-state write. Both share this lock.
    pub(crate) fn publish_enabling_result(
        &mut self,
        result: Result<CommunicationState, CommunicationOperationFailure>,
        operation: CommunicationOperation,
    ) -> Result<CommunicationState, CommunicationOperationFailure> {
        if self.shutting_down {
            return Err(CommunicationOperationFailure::ShuttingDown { operation });
        }
        self.state = match &result {
            Ok(new_state) => new_state.clone(),
            Err(failure) => CommunicationState::Error(failure.clone()),
        };
        self.enabling_result = None;
        result
    }
}

/// Synchronized state shared by the communication manager and its guards.
///
/// A synchronous mutex: critical sections are short, never span an await, and
/// communication guards must release state synchronously in `Drop`.
pub(crate) struct CommunicationStateStore {
    state: std::sync::Mutex<CommunicationStateData>,
}

impl CommunicationStateStore {
    /// Creates a state store with the given initial lifecycle state and
    /// configured detection policy.
    ///
    /// The effective policy starts at `Never`. Nothing has been enabled and no
    /// detector has registered yet, so nothing is going to settle a variant.
    #[must_use]
    pub(crate) fn new(
        initial: CommunicationState,
        configured_variant_detection: VariantDetectionMode,
    ) -> Self {
        Self {
            state: std::sync::Mutex::new(CommunicationStateData {
                state: initial,
                active_guards: HashSet::default(),
                disable_owner: None,
                enabling_result: None,
                detection_in_flight: None,
                configured_variant_detection,
                variant_detector: None,
                variant_detection: VariantDetectionMode::Never,
                shutting_down: false,
            }),
        }
    }

    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, CommunicationStateData> {
        std_ext::lock_mutex(&self.state)
    }
}
