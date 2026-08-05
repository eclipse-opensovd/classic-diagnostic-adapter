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
/// `None` while the operation is still running; `Some` once it finalizes.
/// Present in [`CommunicationStateData`] only while `state` is
/// [`CommunicationState::Enabling`], so joining callers can await the same result.
pub(crate) type EnablingResultReceiver =
    tokio::sync::watch::Receiver<Option<Result<CommunicationState, CommunicationOperationFailure>>>;

/// Sender half of the enabling-result watch channel.
///
/// Stored in [`CommunicationStateData`] for the duration of one enabling
/// attempt. [`tokio::sync::watch::Sender::same_channel`] gives free
/// channel-identity comparison: a panic-recovery finalizer that holds a clone
/// of this sender can verify, under the state lock, that its channel is still
/// the current one before writing an error state. See
/// [`CommunicationStateData::is_current_attempt`].
pub(crate) type EnablingAttemptSender =
    tokio::sync::watch::Sender<Option<Result<CommunicationState, CommunicationOperationFailure>>>;

/// Resolves the detection mode to publish for a resolved detector.
///
/// A missing registration reads the same to consumers as a disabled policy: in
/// both cases a reader waiting on `VariantState` would wait forever, so both
/// report `Never`.
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
    /// Set while an enabling operation claimed via
    /// [`crate::lifecycle::controller::CommunicationHandle::enable`],
    /// `request_activate`, or `redetect` is in flight, so concurrent
    /// callers join the same operation instead of racing to claim the transition
    /// themselves. Whether they join or claim is decided by
    /// [`transition::decide`](crate::lifecycle::transition::decide).
    pub(crate) enabling_result: Option<EnablingResultReceiver>,
    /// Attempt identity for the current in-flight enabling operation.
    ///
    /// The sender half of the same watch channel as `enabling_result`.
    /// A second clone is kept by the finalizer path in
    /// [`fail_closed_enabling_attempt`](crate::lifecycle::controller::CommunicationHandle::fail_closed_enabling_attempt)
    /// to detect whether it still belongs to the current attempt before
    /// writing an error state. The check uses
    /// [`tokio::sync::watch::Sender::same_channel`], which compares the
    /// underlying shared state by pointer without any additional allocation.
    ///
    /// Cleared together with `enabling_result` once the operation finalizes,
    /// so any surviving finalizer clone finds `None` here and skips the write.
    pub(crate) enabling_attempt: Option<EnablingAttemptSender>,
    /// Set while an explicit whole-vehicle re-detection is running against an
    /// already-live transport, so concurrent callers join it instead of racing
    /// a second sweep. `None` whenever no detection is in flight.
    ///
    /// **Deliberately not a lifecycle state.** Re-detection changes nothing
    /// physical - not the transport, not the lifecycle hooks - so it is an
    /// operation that runs *inside* [`CommunicationState::Enabled`] rather than
    /// *between* states, and `state` stays `Enabled` for its whole duration.
    ///
    /// Two properties depend on that. Guard admission reads the state, so
    /// diagnostics keep being served throughout a sweep - the transport is up,
    /// and the state says so. And a failed sweep has an honest place to land:
    /// it reports through its caller's `Result` rather than through
    /// [`Self::publish_enabling_result`], whose only failure exit is
    /// [`CommunicationState::Error`] - a state every consumer reads as "the
    /// transport is not up", which for a re-detection is false.
    ///
    /// Lives beside `enabling_result` rather than reusing it: the two are
    /// joined by different requests and must not be conflated, or a `Detect`
    /// would observe an enabling operation's outcome as its own.
    pub(crate) detection_in_flight: Option<EnablingResultReceiver>,
    /// Attempt identity for the current in-flight re-detection, mirroring
    /// [`Self::enabling_attempt`] for the detection slot. Cleared together with
    /// `detection_in_flight`.
    pub(crate) detection_attempt: Option<EnablingAttemptSender>,
    /// The configured detection policy, fixed for the process lifetime.
    pub(crate) configured_variant_detection: VariantDetectionMode,
    /// The registered whole-vehicle variant detector, or `None` while none has
    /// been registered in which case no operation can settle a variant, no
    /// matter what the configuration says.
    ///
    /// Lives here rather than in the worker's otherwise exclusively owned
    /// `WorkerResources` because the claim side needs it: an operation resolves
    /// both the detector it will run and the detection mode it publishes in one
    /// read under this lock (see [`Self::variant_detector`]). That read is
    /// synchronous `claim_or_join` holds this mutex and `request_activate`
    /// must not block, so asking the worker instead is not an option: its
    /// reply would queue behind whatever physical operation is in flight.
    /// Sharing is safe because a detector is used through `&self` only; the
    /// resources that need `&mut` stay worker-owned.
    pub(crate) variant_detector: Option<Arc<dyn CommunicationVariantDetection>>,
    /// The *effective* detection policy for the currently enabled (or
    /// currently being enabled) communication runtime.
    ///
    /// Distinct from `configured_variant_detection` in both directions: a
    /// plugin may enable communication without detection via
    /// [`CommunicationHandle::enable`](crate::lifecycle::controller::CommunicationHandle::enable)
    /// where the configuration says `Always`, and an explicit
    /// [`redetect`](crate::lifecycle::controller::CommunicationHandle::redetect)
    /// reports `Always` while it runs even where the configuration says
    /// `Never` - that setting suppresses automatic detection only.
    ///
    /// Written at *claim* time rather than on completion, so a reader during
    /// `Enabling(_)` already learns whether anything will settle a variant --
    /// which is exactly the window `cda-comm-uds`' readiness gate has to decide
    /// about.
    pub(crate) variant_detection: VariantDetectionMode,
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

impl CommunicationStateData {
    /// Whether an *automatic* activation for `operation` runs the detection
    /// stage: the operation's own shape, gated by the configured policy.
    ///
    /// An explicit [`CommunicationOperation::Detect`] never goes through here.
    /// `VariantDetectionMode::Never` means "never automatically", not "never":
    /// asking for detection outright is precisely what it still permits, so
    /// gating that on the configuration would make the setting unrecoverable.
    pub(crate) fn runs_detection_for(&self, operation: CommunicationOperation) -> bool {
        operation.runs_detection()
            && self.configured_variant_detection == VariantDetectionMode::Always
    }

    /// The registered variant detector, or `None` if nothing has
    /// registered one.
    ///
    /// Callers resolve this in the same locked read that publishes
    /// [`variant_detection`](Self::variant_detection), so the detector handed
    /// to the worker and the policy reported to readiness consumers cannot
    /// disagree: a registration landing right after the read affects the
    /// *next* operation, never the one being claimed.
    pub(crate) fn variant_detector(&self) -> Option<Arc<dyn CommunicationVariantDetection>> {
        self.variant_detector.as_ref().map(Arc::clone)
    }

    /// Returns `true` if `attempt` is the sender for the current in-flight
    /// enabling operation.
    ///
    /// Used by the panic-recovery finalizer in
    /// [`fail_closed_enabling_attempt`](crate::lifecycle::controller::CommunicationHandle::fail_closed_enabling_attempt)
    /// to ensure a stale finalizer cannot clobber a newer attempt that was
    /// claimed for the same operation shape before the finalizer ran.
    ///
    /// The check delegates to [`tokio::sync::watch::Sender::same_channel`],
    /// which compares the underlying shared state by pointer. Each
    /// `watch::channel` call allocates a fresh shared state object, so two
    /// senders from different spawns never compare equal. No extra allocation
    /// is needed beyond the sender the spawned task already holds.
    pub(crate) fn is_current_attempt(&self, attempt: &EnablingAttemptSender) -> bool {
        self.enabling_attempt
            .as_ref()
            .is_some_and(|stored| stored.same_channel(attempt))
    }

    /// The detection counterpart of [`Self::is_current_attempt`], guarding the
    /// detection slot against the same stale-finalizer clobber.
    ///
    /// A separate slot needs a separate check: a re-detection and an enabling
    /// operation are tracked independently, so one's finalizer must never
    /// decide anything about the other's.
    pub(crate) fn is_current_detection_attempt(&self, attempt: &EnablingAttemptSender) -> bool {
        self.detection_attempt
            .as_ref()
            .is_some_and(|stored| stored.same_channel(attempt))
    }

    /// Publishes the final state for a completed enabling operation
    /// and clears the enabling-result slot.
    ///
    /// A no-op once `shutting_down` is set: a write that raced shutdown's own
    /// terminal-state write must never overwrite it. `shutting_down` and this
    /// write share one lock, so shutdown's own later write is always the last
    /// word once it has started (see `shutting_down`'s doc comment above).
    /// Shared by the worker's own `finish_enabling` (which cannot actually
    /// race shutdown, since both run on the worker's single sequential loop)
    /// and [`CommunicationHandle`](crate::lifecycle::controller::CommunicationHandle)'s
    /// `finish_enabling` (a detached `claim_or_join` task, which can): the
    /// worker's call pays the guard for nothing, but that costs less than
    /// carrying two copies of this logic that could drift apart.
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
        self.enabling_attempt = None;
        result
    }
}

/// Synchronized state shared by the communication manager and its guards.
///
/// A synchronous mutex is intentional: critical sections are short, never span
/// an await, and communication guards must release state synchronously in `Drop`.
pub(crate) struct CommunicationStateStore {
    state: std::sync::Mutex<CommunicationStateData>,
}

impl CommunicationStateStore {
    /// Creates a state store with the given initial lifecycle state and
    /// configured detection policy.
    ///
    /// The effective policy starts at `Never`: nothing has been enabled and no
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
                enabling_attempt: None,
                detection_in_flight: None,
                detection_attempt: None,
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
