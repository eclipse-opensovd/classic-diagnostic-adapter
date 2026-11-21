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

use super::{
    disable::{DisableError, DisableLeaseId, DisableOwner},
    guard::CommunicationGuardId,
    transition::{LifecycleDecision, LifecycleRequest, decide},
};

/// Shared outcome of one activation or detection attempt. `None` means pending.
pub(crate) type OperationResultReceiver =
    tokio::sync::watch::Receiver<Option<Result<CommunicationState, CommunicationOperationFailure>>>;

/// Only these operations may own an activation attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActivationKind {
    Enable,
    EnableAndDetect,
    Resume,
}

impl ActivationKind {
    pub(crate) const fn operation(self) -> CommunicationOperation {
        match self {
            Self::Enable => CommunicationOperation::Enable,
            Self::EnableAndDetect => CommunicationOperation::EnableAndDetect,
            Self::Resume => CommunicationOperation::Resume,
        }
    }

    /// The lifecycle request that claims this activation.
    pub(crate) const fn request(self) -> LifecycleRequest {
        match self {
            Self::Enable => LifecycleRequest::Enable,
            Self::EnableAndDetect => LifecycleRequest::EnableAndDetect,
            Self::Resume => LifecycleRequest::Resume,
        }
    }
}

/// The mandatory payload of an enabling phase, including its attempt identity.
#[derive(Debug)]
pub(crate) struct ActivationAttempt {
    pub(crate) kind: ActivationKind,
    pub(crate) result: OperationResultReceiver,
    /// Whether this attempt runs the detection stage.
    ///
    /// Set at claim time when a detector was resolved for it. An explicit
    /// detection request that joins the attempt raises it (see
    /// [`CommunicationStateData::request_activation_detection`]), so the joined
    /// result already covers detection. Retrying detection after the attempt
    /// settled instead would be refused by any guard taken in between.
    pub(crate) detects: bool,
}

/// What the worker does once an activation has brought the transport up and
/// initialized every hook.
pub(crate) enum DetectionStage {
    /// Run this detector, then publish the attempt's result.
    Run(Arc<dyn CommunicationVariantDetection>),
    /// The attempt runs no detection and its result is already published.
    Settled(Result<CommunicationState, CommunicationOperationFailure>),
}

/// Detection preserves public `Enabled`, but has its own admission rules.
#[derive(Debug)]
pub(crate) enum EnabledActivity {
    Idle,
    Detecting(OperationResultReceiver),
}

/// Coupled lifecycle state and ownership. No phase can carry another phase's
/// owner or result receiver. The public state is derived, never stored separately.
#[derive(Debug)]
pub(crate) enum LifecyclePhase {
    Disabled,
    Enabled(EnabledActivity),
    Enabling(ActivationAttempt),
    Disabling(DisableOwner),
    DisabledExclusive(DisableOwner),
    RecoveryRequired(CommunicationOperationFailure),
    Error(CommunicationOperationFailure),
    /// Terminal shutdown with its outcome. It owns no operation or lease.
    Stopped(Result<(), CommunicationOperationFailure>),
}

impl LifecyclePhase {
    pub(crate) fn state(&self) -> CommunicationState {
        match self {
            Self::Disabled | Self::Stopped(Ok(())) => CommunicationState::Disabled,
            Self::Enabled(_) => CommunicationState::Enabled,
            Self::Enabling(attempt) => CommunicationState::Enabling(attempt.kind.operation()),
            Self::Disabling(_) => CommunicationState::Disabling,
            Self::DisabledExclusive(_) => CommunicationState::DisabledExclusive,
            Self::RecoveryRequired(failure) => {
                CommunicationState::RecoveryRequired(failure.clone())
            }
            Self::Error(failure) | Self::Stopped(Err(failure)) => {
                CommunicationState::Error(failure.clone())
            }
        }
    }
}

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
    phase: LifecyclePhase,
    /// IDs of guards currently holding communication in use. Each ID is removed
    /// when its guard is dropped; active guards prevent disabling.
    pub(crate) active_guards: HashSet<CommunicationGuardId>,
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
    pub(crate) fn new(
        phase: LifecyclePhase,
        configured_variant_detection: VariantDetectionMode,
    ) -> Self {
        Self {
            phase,
            active_guards: HashSet::default(),
            configured_variant_detection,
            variant_detector: None,
            variant_detection: VariantDetectionMode::Never,
            shutting_down: false,
        }
    }

    pub(crate) fn phase(&self) -> &LifecyclePhase {
        &self.phase
    }

    pub(crate) fn state(&self) -> CommunicationState {
        self.phase.state()
    }

    pub(crate) fn activation(&self) -> Option<&ActivationAttempt> {
        match &self.phase {
            LifecyclePhase::Enabling(attempt) => Some(attempt),
            _ => None,
        }
    }

    pub(crate) fn detection(&self) -> Option<&OperationResultReceiver> {
        match &self.phase {
            LifecyclePhase::Enabled(EnabledActivity::Detecting(attempt)) => Some(attempt),
            _ => None,
        }
    }

    pub(crate) fn disable_owner(&self) -> Option<DisableOwner> {
        match self.phase {
            LifecyclePhase::Disabling(owner) | LifecyclePhase::DisabledExclusive(owner) => {
                Some(owner)
            }
            _ => None,
        }
    }

    /// Both worker execution and publication must still belong to this attempt.
    pub(crate) fn validate_attempt(
        &self,
        operation: CommunicationOperation,
        attempt: &OperationResultReceiver,
    ) -> Result<(), CommunicationOperationFailure> {
        if self.shutting_down {
            return Err(CommunicationOperationFailure::ShuttingDown { operation });
        }
        let owns = match &self.phase {
            LifecyclePhase::Enabling(current) => {
                current.kind.operation() == operation && current.result.same_channel(attempt)
            }
            LifecyclePhase::Enabled(EnabledActivity::Detecting(current)) => {
                operation == CommunicationOperation::Detect && current.same_channel(attempt)
            }
            _ => false,
        };
        if owns {
            Ok(())
        } else {
            Err(CommunicationOperationFailure::TransitionFailure { operation })
        }
    }

    /// Applies an admitted activation, consuming any displaced disable owner.
    ///
    /// The caller must have obtained `LifecycleDecision::Claim` from
    /// `transition::decide` under the same lock. Overwriting any other phase
    /// would drop its owner, e.g. a disable lease whose release would be lost.
    /// An inadmissible phase is rejected without changing the state; admission
    /// is checked by `decide` itself, so there is one table of admitted phases.
    pub(crate) fn claim_activation(
        &mut self,
        kind: ActivationKind,
        result: OperationResultReceiver,
        mode: VariantDetectionMode,
    ) -> Result<(), CommunicationOperationFailure> {
        self.claim_activation_for(kind.request(), kind, result, mode)
    }

    /// Like [`claim_activation`](Self::claim_activation), for a `request` other
    /// than the one of `kind` that claims it, such as
    /// [`LifecycleRequest::ResumeAndDetect`] claiming `EnableAndDetect`.
    pub(crate) fn claim_activation_for(
        &mut self,
        request: LifecycleRequest,
        kind: ActivationKind,
        result: OperationResultReceiver,
        mode: VariantDetectionMode,
    ) -> Result<(), CommunicationOperationFailure> {
        if decide(self, false, request) != LifecycleDecision::Claim(kind) {
            return Err(CommunicationOperationFailure::TransitionFailure {
                operation: kind.operation(),
            });
        }
        self.phase = LifecyclePhase::Enabling(ActivationAttempt {
            kind,
            result,
            // `mode` is `Always` exactly when the claim resolved a detector.
            detects: mode == VariantDetectionMode::Always,
        });
        self.variant_detection = mode;
        Ok(())
    }

    /// Makes the in-flight activation run the detection stage, for an explicit
    /// detection request that joins it.
    ///
    /// Has no effect once the attempt settled. The worker decides the detection
    /// stage under this lock (see [`Self::enter_detection_stage`]), so a request
    /// either lands before that decision and is honored, or finds the attempt
    /// already detecting or already published.
    pub(crate) fn request_activation_detection(&mut self) {
        let mode = detection_mode(self.variant_detector.as_ref());
        if let LifecyclePhase::Enabling(attempt) = &mut self.phase
            && !attempt.detects
        {
            attempt.detects = true;
            // Readers during `Enabling(_)` learn at once that a variant will
            // be settled.
            self.variant_detection = mode;
        }
    }

    /// Decides the detection stage of `attempt` after transport and hooks are
    /// up. When it runs no detection, the success is published under the same
    /// lock, so no joining detection request can slip in between.
    ///
    /// `claimed` is the detector resolved at claim time. A detection requested
    /// by a joiner resolves the registered detector now.
    pub(crate) fn enter_detection_stage(
        &mut self,
        kind: ActivationKind,
        attempt: &OperationResultReceiver,
        claimed: Option<Arc<dyn CommunicationVariantDetection>>,
    ) -> DetectionStage {
        if let Err(failure) = self.validate_attempt(kind.operation(), attempt) {
            return DetectionStage::Settled(Err(failure));
        }
        let requested = self.activation().is_some_and(|current| current.detects);
        let detector = match claimed {
            Some(detector) => Some(detector),
            None if requested => {
                let resolved = self.variant_detector();
                self.variant_detection = detection_mode(resolved.as_ref());
                resolved
            }
            None => None,
        };
        match detector {
            Some(detector) => DetectionStage::Run(detector),
            None => DetectionStage::Settled(self.publish_enabling_result(
                Ok(CommunicationState::Enabled),
                kind,
                attempt,
            )),
        }
    }

    /// Applies an admitted detection. Like
    /// [`claim_activation`](Self::claim_activation), only valid after `decide`
    /// admitted it under the same lock.
    pub(crate) fn claim_detection(
        &mut self,
        result: OperationResultReceiver,
        mode: VariantDetectionMode,
    ) -> Result<(), CommunicationOperationFailure> {
        if decide(self, false, LifecycleRequest::Detect) != LifecycleDecision::ClaimDetection {
            return Err(CommunicationOperationFailure::TransitionFailure {
                operation: CommunicationOperation::Detect,
            });
        }
        self.phase = LifecyclePhase::Enabled(EnabledActivity::Detecting(result));
        self.variant_detection = mode;
        Ok(())
    }

    /// Applies an admitted disable. Like
    /// [`claim_activation`](Self::claim_activation), only valid after `decide`
    /// admitted it under the same lock.
    pub(crate) fn claim_disable(&mut self, owner: DisableOwner) -> Result<(), DisableError> {
        if !matches!(
            decide(self, false, LifecycleRequest::Disable),
            LifecycleDecision::ClaimDisable { .. }
        ) {
            return Err(DisableError::Conflict);
        }
        self.phase = LifecyclePhase::Disabling(owner);
        Ok(())
    }

    /// Settles only the matching disable generation; late drops are harmless.
    pub(crate) fn settle_disabled(&mut self, id: DisableLeaseId) {
        if !self.shutting_down && DisableOwner::owns(self.disable_owner(), id) {
            self.phase = LifecyclePhase::Disabled;
        }
    }

    pub(crate) fn publish_disable_result(
        &mut self,
        id: DisableLeaseId,
        result: Result<(), CommunicationOperationFailure>,
    ) -> Result<(), CommunicationOperationFailure> {
        if self.shutting_down {
            return Err(CommunicationOperationFailure::ShuttingDown {
                operation: CommunicationOperation::Disable,
            });
        }
        let owner = match self.phase {
            LifecyclePhase::Disabling(owner) if owner.id == id => owner,
            _ => {
                return Err(CommunicationOperationFailure::TransitionFailure {
                    operation: CommunicationOperation::Disable,
                });
            }
        };
        self.phase = match &result {
            Ok(()) => LifecyclePhase::DisabledExclusive(owner),
            Err(failure) => LifecyclePhase::Error(failure.clone()),
        };
        result
    }

    /// Shutdown discards any in-flight attempt or owner.
    pub(crate) fn publish_shutdown(&mut self, outcome: Result<(), CommunicationOperationFailure>) {
        self.shutting_down = true;
        self.phase = LifecyclePhase::Stopped(outcome);
    }

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

    /// Atomically consumes the matching attempt and publishes its final phase.
    /// Failed resume is never exposed as a retryable ordinary error.
    pub(crate) fn publish_enabling_result(
        &mut self,
        result: Result<CommunicationState, CommunicationOperationFailure>,
        kind: ActivationKind,
        attempt: &OperationResultReceiver,
    ) -> Result<CommunicationState, CommunicationOperationFailure> {
        self.validate_attempt(kind.operation(), attempt)?;
        self.phase = match &result {
            Ok(_) => LifecyclePhase::Enabled(EnabledActivity::Idle),
            Err(failure) if kind == ActivationKind::Resume => {
                LifecyclePhase::RecoveryRequired(failure.clone())
            }
            Err(failure) => LifecyclePhase::Error(failure.clone()),
        };
        // A failed activation detects nothing, so readiness waiters fail fast
        // instead of waiting for a detection that will not run.
        if result.is_err() {
            self.variant_detection = VariantDetectionMode::Never;
        }
        result
    }

    pub(crate) fn publish_detection_result(
        &mut self,
        result: Result<CommunicationState, CommunicationOperationFailure>,
        attempt: &OperationResultReceiver,
    ) -> Result<CommunicationState, CommunicationOperationFailure> {
        self.validate_attempt(CommunicationOperation::Detect, attempt)?;
        self.phase = LifecyclePhase::Enabled(EnabledActivity::Idle);
        if result.is_err() {
            self.variant_detection = VariantDetectionMode::Never;
        }
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
        initial: LifecyclePhase,
        configured_variant_detection: VariantDetectionMode,
    ) -> Self {
        Self {
            state: std::sync::Mutex::new(CommunicationStateData::new(
                initial,
                configured_variant_detection,
            )),
        }
    }

    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, CommunicationStateData> {
        std_ext::lock_mutex(&self.state)
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::watch;

    use super::*;
    use crate::lifecycle::transition::{self, LifecycleDecision, LifecycleRequest};

    fn failure() -> CommunicationOperationFailure {
        CommunicationOperationFailure::WorkerUnavailable {
            operation: CommunicationOperation::Resume,
        }
    }

    fn data() -> CommunicationStateData {
        data_in(LifecyclePhase::Disabled)
    }

    fn data_in(phase: LifecyclePhase) -> CommunicationStateData {
        CommunicationStateData::new(phase, VariantDetectionMode::Always)
    }

    /// A phase `decide` admits `kind` from.
    fn activation_source(kind: ActivationKind) -> LifecyclePhase {
        match kind {
            ActivationKind::Resume => LifecyclePhase::DisabledExclusive(owner()),
            ActivationKind::Enable | ActivationKind::EnableAndDetect => LifecyclePhase::Disabled,
        }
    }

    fn owner() -> DisableOwner {
        DisableOwner {
            id: DisableLeaseId::new(),
            resumes_transport: true,
            tears_down: true,
            resume_detects: false,
        }
    }

    fn claim_sources() -> Vec<LifecyclePhase> {
        vec![
            LifecyclePhase::Disabled,
            LifecyclePhase::Enabled(EnabledActivity::Idle),
            LifecyclePhase::Enabled(EnabledActivity::Detecting(watch::channel(None).1)),
            LifecyclePhase::Enabling(ActivationAttempt {
                kind: ActivationKind::Enable,
                result: watch::channel(None).1,
                detects: false,
            }),
            LifecyclePhase::Disabling(owner()),
            LifecyclePhase::DisabledExclusive(owner()),
            LifecyclePhase::RecoveryRequired(failure()),
            LifecyclePhase::Error(failure()),
            LifecyclePhase::Stopped(Ok(())),
        ]
    }

    #[test]
    fn claims_validate_the_phase_without_displacing_existing_owners() {
        for kind in [
            ActivationKind::Enable,
            ActivationKind::EnableAndDetect,
            ActivationKind::Resume,
        ] {
            for phase in claim_sources() {
                let mut state = data_in(phase);
                let admitted =
                    decide(&state, false, kind.request()) == LifecycleDecision::Claim(kind);
                let before = format!("{:?}", state.phase());
                let result = state.claim_activation(
                    kind,
                    watch::channel(None).1,
                    VariantDetectionMode::Always,
                );
                if admitted {
                    assert_eq!(result, Ok(()), "{kind:?} from {before}");
                    assert_eq!(state.activation().map(|attempt| attempt.kind), Some(kind));
                    assert_eq!(state.variant_detection, VariantDetectionMode::Always);
                } else {
                    assert_eq!(
                        result,
                        Err(CommunicationOperationFailure::TransitionFailure {
                            operation: kind.operation()
                        }),
                        "{before}"
                    );
                    assert_eq!(format!("{:?}", state.phase()), before);
                    assert_eq!(state.variant_detection, VariantDetectionMode::Never);
                }
            }
        }

        for phase in claim_sources() {
            let mut state = data_in(phase);
            let admitted = decide(&state, false, LifecycleRequest::Detect)
                == LifecycleDecision::ClaimDetection;
            let before = format!("{:?}", state.phase());
            let result =
                state.claim_detection(watch::channel(None).1, VariantDetectionMode::Always);
            if admitted {
                assert_eq!(result, Ok(()));
                assert!(state.detection().is_some());
                assert_eq!(state.variant_detection, VariantDetectionMode::Always);
            } else {
                assert_eq!(
                    result,
                    Err(CommunicationOperationFailure::TransitionFailure {
                        operation: CommunicationOperation::Detect
                    }),
                    "{before}"
                );
                assert_eq!(format!("{:?}", state.phase()), before);
                assert_eq!(state.variant_detection, VariantDetectionMode::Never);
            }
        }

        for phase in claim_sources() {
            let mut state = data_in(phase);
            let admitted = matches!(
                decide(&state, false, LifecycleRequest::Disable),
                LifecycleDecision::ClaimDisable { .. }
            );
            let before = format!("{:?}", state.phase());
            let new_owner = owner();
            let result = state.claim_disable(new_owner);
            if admitted {
                assert!(result.is_ok(), "{before}");
                assert!(DisableOwner::owns(state.disable_owner(), new_owner.id));
            } else {
                assert!(matches!(result, Err(DisableError::Conflict)), "{before}");
                assert_eq!(format!("{:?}", state.phase()), before);
            }
        }
    }

    #[test]
    fn every_phase_projects_to_the_existing_public_state() {
        let cases = [
            (LifecyclePhase::Disabled, CommunicationState::Disabled),
            (
                LifecyclePhase::Enabled(EnabledActivity::Idle),
                CommunicationState::Enabled,
            ),
            (
                LifecyclePhase::Enabled(EnabledActivity::Detecting(watch::channel(None).1)),
                CommunicationState::Enabled,
            ),
            (
                LifecyclePhase::Disabling(owner()),
                CommunicationState::Disabling,
            ),
            (
                LifecyclePhase::DisabledExclusive(owner()),
                CommunicationState::DisabledExclusive,
            ),
            (
                LifecyclePhase::RecoveryRequired(failure()),
                CommunicationState::RecoveryRequired(failure()),
            ),
            (
                LifecyclePhase::Error(failure()),
                CommunicationState::Error(failure()),
            ),
            (
                LifecyclePhase::Stopped(Ok(())),
                CommunicationState::Disabled,
            ),
            (
                LifecyclePhase::Stopped(Err(failure())),
                CommunicationState::Error(failure()),
            ),
        ];
        for (phase, expected) in cases {
            assert_eq!(phase.state(), expected, "phase {phase:?}");
        }
        for kind in [
            ActivationKind::Enable,
            ActivationKind::EnableAndDetect,
            ActivationKind::Resume,
        ] {
            let phase = LifecyclePhase::Enabling(ActivationAttempt {
                kind,
                result: watch::channel(None).1,
                detects: false,
            });
            assert_eq!(
                phase.state(),
                CommunicationState::Enabling(kind.operation())
            );
        }
    }

    #[test]
    fn failed_resume_publication_is_already_fail_closed_before_reply() {
        let mut state = data_in(activation_source(ActivationKind::Resume));
        let (_tx, rx) = watch::channel(None);
        state
            .claim_activation(
                ActivationKind::Resume,
                rx.clone(),
                VariantDetectionMode::Always,
            )
            .unwrap();

        assert_eq!(
            state.publish_enabling_result(Err(failure()), ActivationKind::Resume, &rx),
            Err(failure()),
        );
        // This is the publication boundary that previously exposed retryable Error.
        assert_eq!(
            state.state(),
            CommunicationState::RecoveryRequired(failure())
        );
        assert!(state.activation().is_none());
        assert!(state.disable_owner().is_none());
        for request in [LifecycleRequest::Enable, LifecycleRequest::EnableAndDetect] {
            assert_eq!(
                transition::decide(&state, false, request),
                LifecycleDecision::Conflict
            );
        }
        assert!(
            state
                .publish_enabling_result(
                    Ok(CommunicationState::Enabled),
                    ActivationKind::Resume,
                    &rx,
                )
                .is_err()
        );
        assert_eq!(
            state.state(),
            CommunicationState::RecoveryRequired(failure())
        );
    }

    #[test]
    fn failed_activation_resets_the_variant_detection_mode() {
        for kind in [ActivationKind::Enable, ActivationKind::Resume] {
            let mut state = data_in(activation_source(kind));
            let (_tx, rx) = watch::channel(None);
            state
                .claim_activation(kind, rx.clone(), VariantDetectionMode::Always)
                .unwrap();
            assert_eq!(state.variant_detection, VariantDetectionMode::Always);

            assert_eq!(
                state.publish_enabling_result(Err(failure()), kind, &rx),
                Err(failure())
            );
            assert_eq!(
                state.variant_detection,
                VariantDetectionMode::Never,
                "{kind:?}"
            );
        }
    }

    #[test]
    fn stale_activation_cannot_publish_over_a_new_attempt_or_settled_state() {
        let mut state = data();
        let (_old_tx, old) = watch::channel(None);
        let (_new_tx, new) = watch::channel(None);
        state
            .claim_activation(
                ActivationKind::Enable,
                old.clone(),
                VariantDetectionMode::Never,
            )
            .unwrap();
        state
            .publish_enabling_result(Err(failure()), ActivationKind::Enable, &old)
            .unwrap_err();
        state
            .claim_activation(
                ActivationKind::Enable,
                new.clone(),
                VariantDetectionMode::Always,
            )
            .unwrap();

        for stale_result in [Ok(CommunicationState::Enabled), Err(failure())] {
            assert!(
                state
                    .publish_enabling_result(stale_result, ActivationKind::Enable, &old)
                    .is_err()
            );
            assert!(state.activation().unwrap().result.same_channel(&new));
            assert_eq!(state.variant_detection, VariantDetectionMode::Always);
        }
        assert_eq!(
            state.publish_enabling_result(
                Ok(CommunicationState::Enabled),
                ActivationKind::Enable,
                &new,
            ),
            Ok(CommunicationState::Enabled)
        );
        assert!(
            state
                .publish_enabling_result(Err(failure()), ActivationKind::Enable, &old)
                .is_err()
        );
        assert_eq!(state.state(), CommunicationState::Enabled);
    }

    #[test]
    fn stale_detection_cannot_clear_a_new_sweep_or_its_policy() {
        let mut state = data_in(LifecyclePhase::Enabled(EnabledActivity::Idle));
        let (_old_tx, old) = watch::channel(None);
        let (_new_tx, new) = watch::channel(None);
        state
            .claim_detection(old.clone(), VariantDetectionMode::Always)
            .unwrap();
        state
            .publish_detection_result(Ok(CommunicationState::Enabled), &old)
            .unwrap();
        state
            .claim_detection(new.clone(), VariantDetectionMode::Always)
            .unwrap();

        assert!(
            state
                .publish_detection_result(Err(failure()), &old)
                .is_err()
        );
        assert!(state.detection().unwrap().same_channel(&new));
        assert_eq!(state.variant_detection, VariantDetectionMode::Always);
        state
            .publish_detection_result(Err(failure()), &new)
            .unwrap_err();
        assert!(state.detection().is_none());
        assert_eq!(state.variant_detection, VariantDetectionMode::Never);
        assert_eq!(state.state(), CommunicationState::Enabled);
    }

    #[test]
    fn shutdown_wins_over_activation_and_detection_completion() {
        for outcome in [Ok(()), Err(failure())] {
            for kind in [ActivationKind::Enable, ActivationKind::Resume] {
                let mut state = data_in(activation_source(kind));
                let (_tx, rx) = watch::channel(None);
                state
                    .claim_activation(kind, rx.clone(), VariantDetectionMode::Always)
                    .unwrap();
                state.publish_shutdown(outcome.clone());
                let terminal = state.state();
                for result in [Ok(CommunicationState::Enabled), Err(failure())] {
                    assert_eq!(
                        state.publish_enabling_result(result, kind, &rx),
                        Err(CommunicationOperationFailure::ShuttingDown {
                            operation: kind.operation()
                        })
                    );
                    assert_eq!(state.state(), terminal);
                }
                assert!(state.activation().is_none());
            }
            let mut state = data_in(LifecyclePhase::Enabled(EnabledActivity::Idle));
            let (_tx, rx) = watch::channel(None);
            state
                .claim_detection(rx.clone(), VariantDetectionMode::Always)
                .unwrap();
            state.publish_shutdown(outcome);
            let terminal = state.state();
            assert!(state.publish_detection_result(Err(failure()), &rx).is_err());
            assert_eq!(state.state(), terminal);
            assert!(state.detection().is_none());
        }
    }

    #[test]
    fn stale_disable_completion_and_drop_cannot_replace_the_current_owner() {
        let mut state = data();
        let old = owner();
        let current = owner();
        state.claim_disable(current).unwrap();
        for result in [Ok(()), Err(failure())] {
            assert!(state.publish_disable_result(old.id, result).is_err());
            state.settle_disabled(old.id);
            assert!(DisableOwner::owns(state.disable_owner(), current.id));
            assert_eq!(state.state(), CommunicationState::Disabling);
        }
        state.publish_disable_result(current.id, Ok(())).unwrap();
        assert_eq!(state.state(), CommunicationState::DisabledExclusive);
        state.settle_disabled(current.id);
        assert_eq!(state.state(), CommunicationState::Disabled);
    }
}
