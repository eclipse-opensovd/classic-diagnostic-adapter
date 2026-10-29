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

//! Lifecycle transition rules.
//!
//! [`decide`] is the single place that determines whether the current state
//! permits a lifecycle request. It decides state admission only, and only reads
//! [`CommunicationStateData`]. Callers apply the returned
//! [`LifecycleDecision`], publish the outcome and check caller authority.

use cda_interfaces::communication_control::{
    CommunicationError, CommunicationOperation, CommunicationState,
};

use super::state::{ActivationKind, CommunicationStateData, EnabledActivity, LifecyclePhase};

/// A lifecycle transition a caller can ask the state machine to admit.
///
/// This excludes operations that only use [`CommunicationOperation`] as an
/// error label and do not cause a lifecycle transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LifecycleRequest {
    /// Transport up and lifecycle hooks initialized, without variant detection.
    Enable,
    /// Transport up, hooks initialized, then variant detection.
    EnableAndDetect,
    /// Variant detection only, without touching transport or hooks.
    Detect,
    /// Ensure transport is up and run explicit variant detection.
    EnsureDetected,
    /// Take the sole exclusive disable lease.
    Disable,
    /// Re-activate after an exclusive disable lease is released.
    ///
    /// The caller verifies that its lease owns the current disable.
    Resume,
    /// Hand an exclusive disable lease over directly to a full activation with
    /// variant detection, whatever the lease displaced.
    ///
    /// The caller verifies that its lease owns the current disable.
    ResumeAndDetect,
}

impl LifecycleRequest {
    /// The operation recorded in failures and [`CommunicationState::Enabling`].
    pub(crate) const fn operation(self) -> CommunicationOperation {
        match self {
            Self::Enable => CommunicationOperation::Enable,
            Self::EnableAndDetect | Self::EnsureDetected | Self::ResumeAndDetect => {
                CommunicationOperation::EnableAndDetect
            }
            Self::Detect => CommunicationOperation::Detect,
            Self::Disable => CommunicationOperation::Disable,
            Self::Resume => CommunicationOperation::Resume,
        }
    }
}

/// The result of a lifecycle request. Callers perform the corresponding state
/// update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LifecycleDecision {
    /// Claim `Enabling` for this activation kind and run its sequence.
    Claim(ActivationKind),
    /// Claim `Enabled(Detecting)`, leaving the public state `Enabled`.
    ClaimDetection,
    /// Join an in-flight detection instead of starting another one.
    JoinDetection,
    /// Join an in-flight activation. The kind identifies the activation
    /// being joined, not the operation that requested the join.
    Join(ActivationKind),
    /// Communication is already enabled, so no stage runs. Use
    /// [`Detect`](CommunicationOperation::Detect) to detect.
    AlreadyEnabled,
    /// Claim `Disabling` and grant the lease. `resumes_transport` records
    /// whether releasing the lease must restore the transport, `tears_down`
    /// whether granting it must take hooks and transport down first.
    ClaimDisable {
        resumes_transport: bool,
        tears_down: bool,
    },
    /// The released lease displaced no transport, so settle straight back to
    /// `Disabled` without activating anything.
    SettleDisabled,
    /// Refused: communication guards are currently held.
    GuardsHeld,
    /// Refused: an exclusive disable lease owns the state. Carries the current
    /// state, which is either `Disabling` or `DisabledExclusive`.
    LeaseHeld(CommunicationState),
    /// Refused: detection was requested while communication was not enabled.
    /// Detection never brings a transport up.
    NotEnabled,
    /// Refused because this state cannot perform the requested operation.
    Conflict,
    /// Refused: the lifecycle is shutting down.
    ShuttingDown,
}

/// Decides whether `request` is admitted from the current lifecycle state.
///
/// The caller applies the returned decision while holding the same lock. The
/// match is exhaustive, so every state/request combination needs an explicit
/// decision.
pub(crate) fn decide(
    state: &CommunicationStateData,
    worker_shutting_down: bool,
    request: LifecycleRequest,
) -> LifecycleDecision {
    // Reject all new requests once shutdown begins. `publish_shutdown` sets
    // `shutting_down` before entering `Stopped`, so this covers that phase too.
    if worker_shutting_down || state.shutting_down {
        return LifecycleDecision::ShuttingDown;
    }

    let guards_held = !state.active_guards.is_empty();

    // Guards and in-flight detection prevent disable, so the transport cannot
    // be torn down underneath them.
    if request == LifecycleRequest::Disable && (guards_held || state.detection().is_some()) {
        return LifecycleDecision::GuardsHeld;
    }

    match (state.phase(), request) {
        // Already satisfied, and they do not trigger detection.
        (
            LifecyclePhase::Enabled(_),
            LifecycleRequest::Enable | LifecycleRequest::EnableAndDetect,
        ) => LifecycleDecision::AlreadyEnabled,
        // Detection has its own in-flight slot and leaves the state enabled.
        (
            LifecyclePhase::Enabled(EnabledActivity::Detecting(_)),
            LifecycleRequest::Detect | LifecycleRequest::EnsureDetected,
        ) => LifecycleDecision::JoinDetection,
        (
            LifecyclePhase::Enabled(EnabledActivity::Idle),
            LifecycleRequest::Detect | LifecycleRequest::EnsureDetected,
        ) => {
            if guards_held {
                LifecycleDecision::GuardsHeld
            } else {
                LifecycleDecision::ClaimDetection
            }
        }
        // Releasing this lease restores the live transport.
        (LifecyclePhase::Enabled(EnabledActivity::Idle), LifecycleRequest::Disable) => {
            LifecycleDecision::ClaimDisable {
                resumes_transport: true,
                tears_down: true,
            }
        }
        // Releasing a lease from a disabled or fail-closed runtime remains disabled.
        (
            LifecyclePhase::Disabled | LifecyclePhase::RecoveryRequired(_),
            LifecycleRequest::Disable,
        ) => LifecycleDecision::ClaimDisable {
            resumes_transport: false,
            tears_down: false,
        },
        // A failed activation may have left hooks or transport partially up, so
        // the lease tears down defensively and releasing it settles to `Disabled`.
        // Without this, an exclusive owner (e.g. a network reset) could never
        // recover communication from an ordinary error.
        (LifecyclePhase::Error(_), LifecycleRequest::Disable) => LifecycleDecision::ClaimDisable {
            resumes_transport: false,
            tears_down: true,
        },
        // Recovery from an ordinary error starts a new activation.
        (LifecyclePhase::Disabled | LifecyclePhase::Error(_), LifecycleRequest::Enable) => {
            LifecycleDecision::Claim(ActivationKind::Enable)
        }
        (
            LifecyclePhase::Disabled | LifecyclePhase::Error(_),
            LifecycleRequest::EnableAndDetect | LifecycleRequest::EnsureDetected,
        ) => LifecycleDecision::Claim(ActivationKind::EnableAndDetect),
        // Detection needs an enabled transport and never brings one up.
        (
            LifecyclePhase::Disabled
            | LifecyclePhase::RecoveryRequired(_)
            | LifecyclePhase::Error(_)
            | LifecyclePhase::Enabling(_),
            LifecycleRequest::Detect,
        ) => LifecycleDecision::NotEnabled,
        // Activation requests join the in-flight activation.
        (
            LifecyclePhase::Enabling(attempt),
            LifecycleRequest::Enable
            | LifecycleRequest::EnableAndDetect
            | LifecycleRequest::EnsureDetected,
        ) => LifecycleDecision::Join(attempt.kind),
        // The exclusive disable lease blocks activation and detection.
        (
            current @ (LifecyclePhase::Disabling(_) | LifecyclePhase::DisabledExclusive(_)),
            LifecycleRequest::Enable
            | LifecycleRequest::EnableAndDetect
            | LifecycleRequest::Detect
            | LifecycleRequest::EnsureDetected,
        ) => LifecycleDecision::LeaseHeld(current.state()),
        // The disable owner determines whether release resumes the transport.
        (LifecyclePhase::DisabledExclusive(owner), LifecycleRequest::Resume) => {
            if owner.resumes_transport {
                LifecycleDecision::Claim(ActivationKind::Resume)
            } else {
                LifecycleDecision::SettleDisabled
            }
        }
        // The lease ends only as the activation starts, so nothing else can bring
        // communication up in between. A failure is an ordinary failed activation.
        (LifecyclePhase::DisabledExclusive(_), LifecycleRequest::ResumeAndDetect) => {
            LifecycleDecision::Claim(ActivationKind::EnableAndDetect)
        }
        // Only for exhaustiveness: the early return already rejects `Stopped`.
        (LifecyclePhase::Stopped(_), _) => LifecycleDecision::ShuttingDown,
        // No activation, unrelated lease, or resume can escape fail-closed recovery.
        (
            LifecyclePhase::RecoveryRequired(_),
            LifecycleRequest::Enable
            | LifecycleRequest::EnableAndDetect
            | LifecycleRequest::EnsureDetected,
        )
        | (
            LifecyclePhase::Enabling(_)
            | LifecyclePhase::Disabling(_)
            | LifecyclePhase::DisabledExclusive(_)
            | LifecyclePhase::Enabled(EnabledActivity::Detecting(_)),
            LifecycleRequest::Disable,
        )
        | (
            LifecyclePhase::Enabled(_)
            | LifecyclePhase::Disabled
            | LifecyclePhase::RecoveryRequired(_)
            | LifecyclePhase::Enabling(_)
            | LifecyclePhase::Disabling(_)
            | LifecyclePhase::Error(_),
            LifecycleRequest::Resume | LifecycleRequest::ResumeAndDetect,
        ) => LifecycleDecision::Conflict,
    }
}

/// Whether a diagnostic communication guard may be acquired right now.
///
/// Guard acquisition is separate from lifecycle transitions. Variant detection
/// does not affect guard admission, because communication remains enabled while
/// it runs.
pub(crate) fn guard_admission(phase: &LifecyclePhase) -> Result<(), CommunicationError> {
    match phase.state() {
        CommunicationState::Enabled => Ok(()),
        CommunicationState::Disabled => Err(CommunicationError::Disabled),
        CommunicationState::Enabling(_) => Err(CommunicationError::Enabling),
        CommunicationState::Disabling => Err(CommunicationError::Disabling),
        CommunicationState::DisabledExclusive => Err(CommunicationError::DisabledExclusive),
        CommunicationState::RecoveryRequired(failure) | CommunicationState::Error(failure) => {
            Err(CommunicationError::Failed(failure))
        }
    }
}

#[cfg(test)]
mod tests {
    use cda_interfaces::communication_control::{
        CommunicationOperationFailure, VariantDetectionMode,
    };

    use super::{
        super::{guard::CommunicationGuardId, state::ActivationAttempt},
        *,
    };

    /// A default lifecycle state with no active guards, detection, or lease.
    fn data(phase: LifecyclePhase) -> CommunicationStateData {
        CommunicationStateData::new(phase, VariantDetectionMode::Always)
    }

    fn enabling(kind: ActivationKind) -> LifecyclePhase {
        LifecyclePhase::Enabling(ActivationAttempt {
            kind,
            result: tokio::sync::watch::channel(None).1,
            detects: false,
        })
    }

    fn owner() -> super::super::disable::DisableOwner {
        super::super::disable::DisableOwner {
            id: super::super::disable::DisableLeaseId::new(),
            resumes_transport: true,
            tears_down: true,
            resume_detects: false,
        }
    }

    fn assert_decisions(phase: LifecyclePhase, expected: [LifecycleDecision; 5]) {
        let state = data(phase);
        let actual = [
            LifecycleRequest::Enable,
            LifecycleRequest::EnableAndDetect,
            LifecycleRequest::Detect,
            LifecycleRequest::Disable,
            LifecycleRequest::Resume,
        ]
        .map(|request| decide(&state, false, request));
        for (actual, expected) in actual.into_iter().zip(expected) {
            assert_eq!(actual, expected, "phase {:?}", state.phase());
        }
        for request in [
            LifecycleRequest::Enable,
            LifecycleRequest::Detect,
            LifecycleRequest::Disable,
        ] {
            assert_eq!(
                decide(&state, true, request),
                LifecycleDecision::ShuttingDown
            );
        }
    }

    #[test]
    fn enabled_activity_admission_matrix() {
        use LifecycleDecision::*;

        assert_decisions(
            LifecyclePhase::Enabled(EnabledActivity::Idle),
            [
                AlreadyEnabled,
                AlreadyEnabled,
                ClaimDetection,
                ClaimDisable {
                    resumes_transport: true,
                    tears_down: true,
                },
                Conflict,
            ],
        );
        assert_decisions(
            LifecyclePhase::Enabled(EnabledActivity::Detecting(
                tokio::sync::watch::channel(None).1,
            )),
            [
                AlreadyEnabled,
                AlreadyEnabled,
                JoinDetection,
                GuardsHeld,
                Conflict,
            ],
        );
    }

    /// [[ test~communication-ensure-detection-admission, Explicit detection admission follows lifecycle state, test ]]
    #[test]
    fn ensure_detected_admission() {
        use LifecycleDecision::*;

        let cases = [
            (
                LifecyclePhase::Disabled,
                Claim(ActivationKind::EnableAndDetect),
            ),
            (
                LifecyclePhase::Enabled(EnabledActivity::Idle),
                ClaimDetection,
            ),
            (
                LifecyclePhase::Enabled(EnabledActivity::Detecting(
                    tokio::sync::watch::channel(None).1,
                )),
                JoinDetection,
            ),
            (
                enabling(ActivationKind::Enable),
                Join(ActivationKind::Enable),
            ),
            (
                LifecyclePhase::DisabledExclusive(owner()),
                LeaseHeld(CommunicationState::DisabledExclusive),
            ),
        ];
        for (phase, expected) in cases {
            let state = data(phase);
            assert_eq!(
                decide(&state, false, LifecycleRequest::EnsureDetected),
                expected
            );
        }
        let mut guarded = data(LifecyclePhase::Enabled(EnabledActivity::Idle));
        guarded
            .active_guards
            .insert(CommunicationGuardId(uuid::Uuid::new_v4()));
        assert_eq!(
            decide(&guarded, false, LifecycleRequest::EnsureDetected),
            GuardsHeld
        );
    }

    /// Only the lease holder's own `DisabledExclusive` phase hands over to an
    /// activation with detection, whatever the lease displaced.
    /// [[ test~communication-resume-and-detect-admission, A hand-over with detection is admitted only from the exclusive lease, test ]]
    #[test]
    fn resume_and_detect_admission() {
        use LifecycleDecision::*;

        for resumes_transport in [true, false] {
            let state = data(LifecyclePhase::DisabledExclusive(
                super::super::disable::DisableOwner {
                    resumes_transport,
                    ..owner()
                },
            ));
            assert_eq!(
                decide(&state, false, LifecycleRequest::ResumeAndDetect),
                Claim(ActivationKind::EnableAndDetect),
                "resumes_transport {resumes_transport}"
            );
            assert_eq!(
                decide(&state, true, LifecycleRequest::ResumeAndDetect),
                ShuttingDown
            );
        }
        let failure = CommunicationOperationFailure::WorkerUnavailable {
            operation: CommunicationOperation::EnableAndDetect,
        };
        for phase in [
            LifecyclePhase::Disabled,
            LifecyclePhase::Enabled(EnabledActivity::Idle),
            enabling(ActivationKind::Enable),
            LifecyclePhase::Disabling(owner()),
            LifecyclePhase::Error(failure.clone()),
            LifecyclePhase::RecoveryRequired(failure.clone()),
        ] {
            let state = data(phase);
            assert_eq!(
                decide(&state, false, LifecycleRequest::ResumeAndDetect),
                Conflict,
                "phase {:?}",
                state.phase()
            );
        }
    }

    #[test]
    fn disabled_and_failure_admission_matrix() {
        use LifecycleDecision::*;

        let failure = CommunicationOperationFailure::WorkerUnavailable {
            operation: CommunicationOperation::Resume,
        };
        assert_decisions(
            LifecyclePhase::Disabled,
            [
                Claim(ActivationKind::Enable),
                Claim(ActivationKind::EnableAndDetect),
                NotEnabled,
                ClaimDisable {
                    resumes_transport: false,
                    tears_down: false,
                },
                Conflict,
            ],
        );
        assert_decisions(
            LifecyclePhase::RecoveryRequired(failure.clone()),
            [
                Conflict,
                Conflict,
                NotEnabled,
                ClaimDisable {
                    resumes_transport: false,
                    tears_down: false,
                },
                Conflict,
            ],
        );
        assert_decisions(
            LifecyclePhase::Error(failure),
            [
                Claim(ActivationKind::Enable),
                Claim(ActivationKind::EnableAndDetect),
                NotEnabled,
                ClaimDisable {
                    resumes_transport: false,
                    tears_down: true,
                },
                Conflict,
            ],
        );
    }

    #[test]
    fn activation_and_exclusive_lease_admission_matrix() {
        use LifecycleDecision::*;

        for kind in [
            ActivationKind::Enable,
            ActivationKind::EnableAndDetect,
            ActivationKind::Resume,
        ] {
            assert_decisions(
                enabling(kind),
                [Join(kind), Join(kind), NotEnabled, Conflict, Conflict],
            );
        }
        assert_decisions(
            LifecyclePhase::Disabling(owner()),
            [
                LeaseHeld(CommunicationState::Disabling),
                LeaseHeld(CommunicationState::Disabling),
                LeaseHeld(CommunicationState::Disabling),
                Conflict,
                Conflict,
            ],
        );
        for resumes_transport in [true, false] {
            let resume = if resumes_transport {
                Claim(ActivationKind::Resume)
            } else {
                SettleDisabled
            };
            assert_decisions(
                LifecyclePhase::DisabledExclusive(super::super::disable::DisableOwner {
                    resumes_transport,
                    ..owner()
                }),
                [
                    LeaseHeld(CommunicationState::DisabledExclusive),
                    LeaseHeld(CommunicationState::DisabledExclusive),
                    LeaseHeld(CommunicationState::DisabledExclusive),
                    Conflict,
                    resume,
                ],
            );
        }
    }

    // These tests cover matrix cells not already exercised by controller tests.

    #[test]
    fn held_guards_refuse_disable_from_every_state() {
        let states = [
            LifecyclePhase::Enabled(EnabledActivity::Idle),
            LifecyclePhase::Disabled,
            enabling(ActivationKind::Enable),
            LifecyclePhase::Disabling(owner()),
            LifecyclePhase::DisabledExclusive(owner()),
            LifecyclePhase::RecoveryRequired(CommunicationOperationFailure::TransitionFailure {
                operation: CommunicationOperation::Resume,
            }),
            LifecyclePhase::Error(CommunicationOperationFailure::TransitionFailure {
                operation: CommunicationOperation::Enable,
            }),
        ];

        for state in states {
            let mut guarded = data(state);
            guarded
                .active_guards
                .insert(CommunicationGuardId(uuid::Uuid::new_v4()));
            assert_eq!(
                decide(&guarded, false, LifecycleRequest::Disable),
                LifecycleDecision::GuardsHeld,
                "state {:?}",
                guarded.phase()
            );
        }
    }

    #[test]
    fn diagnostic_guards_require_settled_enabled_state() {
        assert!(guard_admission(&LifecyclePhase::Enabled(EnabledActivity::Idle)).is_ok());
        assert!(guard_admission(&LifecyclePhase::Disabled).is_err());
        assert!(guard_admission(&enabling(ActivationKind::EnableAndDetect)).is_err());
        assert!(guard_admission(&LifecyclePhase::Disabling(owner())).is_err());
        assert!(guard_admission(&LifecyclePhase::DisabledExclusive(owner())).is_err());
    }

    #[test]
    fn disable_conflicts_with_an_in_flight_activation() {
        let enabling = data(enabling(ActivationKind::Enable));
        assert_eq!(
            decide(&enabling, false, LifecycleRequest::Disable),
            LifecycleDecision::Conflict
        );
    }

    /// Detection requires a live transport, so it cannot join an activation.
    #[test]
    fn detect_is_refused_while_an_activation_is_in_flight() {
        for in_flight in [
            ActivationKind::Enable,
            ActivationKind::EnableAndDetect,
            ActivationKind::Resume,
        ] {
            assert_eq!(
                decide(&data(enabling(in_flight)), false, LifecycleRequest::Detect),
                LifecycleDecision::NotEnabled,
                "in flight {in_flight:?}"
            );
        }
    }

    /// Guards block new detection, but detection does not block new guards.
    #[test]
    fn a_sweep_in_flight_still_admits_guards() {
        let mut held = data(LifecyclePhase::Enabled(EnabledActivity::Idle));
        held.active_guards
            .insert(CommunicationGuardId(uuid::Uuid::new_v4()));
        assert_eq!(
            decide(&held, false, LifecycleRequest::Detect),
            LifecycleDecision::GuardsHeld,
            "a held guard must still hold off a new sweep"
        );

        let sweeping = data(LifecyclePhase::Enabled(EnabledActivity::Detecting(
            tokio::sync::watch::channel(None).1,
        )));
        assert_eq!(
            guard_admission(sweeping.phase()),
            Ok(()),
            "a sweep must not close the diagnostic surface over a live transport"
        );
        assert_eq!(
            decide(&sweeping, false, LifecycleRequest::Disable),
            LifecycleDecision::GuardsHeld,
            "but a lease must not tear the transport down underneath one"
        );
    }
}
