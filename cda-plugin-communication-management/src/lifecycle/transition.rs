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

use super::state::CommunicationStateData;

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
    /// Take the sole exclusive disable lease.
    Disable,
    /// Re-activate after an exclusive disable lease is released.
    ///
    /// The caller verifies that its lease owns the current disable.
    Resume,
}

impl LifecycleRequest {
    /// The operation recorded in failures and [`CommunicationState::Enabling`].
    pub(crate) const fn operation(self) -> CommunicationOperation {
        match self {
            Self::Enable => CommunicationOperation::Enable,
            Self::EnableAndDetect => CommunicationOperation::EnableAndDetect,
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
    /// Claim `Enabling(operation)` and run that activation sequence.
    Claim(CommunicationOperation),
    /// Claim the detection slot while leaving the state `Enabled`.
    ClaimDetection,
    /// Join an in-flight detection instead of starting another one.
    JoinDetection,
    /// Join an in-flight activation. The operation identifies the operation
    /// being joined, not the operation that requested the join.
    Join(CommunicationOperation),
    /// Communication is already enabled, so no stage runs. Use
    /// [`Detect`](CommunicationOperation::Detect) to detect.
    AlreadyEnabled,
    /// Claim `Disabling` and grant the lease. `resumes_transport` records
    /// whether releasing the lease must restore the transport.
    ClaimDisable { resumes_transport: bool },
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
    // Reject all new requests once shutdown begins.
    if worker_shutting_down || state.shutting_down {
        return LifecycleDecision::ShuttingDown;
    }

    let guards_held = !state.active_guards.is_empty();

    // Guards and in-flight detection prevent disable from every state.
    if request == LifecycleRequest::Disable && (guards_held || state.detection_in_flight.is_some())
    {
        return LifecycleDecision::GuardsHeld;
    }

    match (&state.state, request) {
        // Already satisfied, and they do not trigger detection.
        (
            CommunicationState::Enabled,
            LifecycleRequest::Enable | LifecycleRequest::EnableAndDetect,
        ) => LifecycleDecision::AlreadyEnabled,
        // Detection uses its own in-flight slot and leaves the state enabled.
        (CommunicationState::Enabled, LifecycleRequest::Detect) => {
            if state.detection_in_flight.is_some() {
                LifecycleDecision::JoinDetection
            } else if guards_held {
                LifecycleDecision::GuardsHeld
            } else {
                LifecycleDecision::ClaimDetection
            }
        }
        // Releasing this lease restores the live transport.
        (CommunicationState::Enabled, LifecycleRequest::Disable) => claim_disable(state, true),

        // Releasing a lease from `Disabled` remains `Disabled`.
        (CommunicationState::Disabled, LifecycleRequest::Disable) => claim_disable(state, false),

        // Recovery from an error starts a new activation.
        (CommunicationState::Disabled | CommunicationState::Error(_), LifecycleRequest::Enable) => {
            LifecycleDecision::Claim(CommunicationOperation::Enable)
        }
        (
            CommunicationState::Disabled | CommunicationState::Error(_),
            LifecycleRequest::EnableAndDetect,
        ) => LifecycleDecision::Claim(CommunicationOperation::EnableAndDetect),
        // Detection needs an enabled transport and never brings one up.
        (
            CommunicationState::Disabled
            | CommunicationState::Error(_)
            | CommunicationState::Enabling(_),
            LifecycleRequest::Detect,
        ) => LifecycleDecision::NotEnabled,

        // Activation requests join the in-flight activation.
        (
            CommunicationState::Enabling(in_flight),
            LifecycleRequest::Enable | LifecycleRequest::EnableAndDetect,
        ) => LifecycleDecision::Join(*in_flight),

        // Disabling / DisabledExclusive:
        (
            current @ (CommunicationState::Disabling | CommunicationState::DisabledExclusive),
            LifecycleRequest::Enable | LifecycleRequest::EnableAndDetect | LifecycleRequest::Detect,
        ) => LifecycleDecision::LeaseHeld(current.clone()),

        // The disable owner determines whether release resumes the transport.
        (CommunicationState::DisabledExclusive, LifecycleRequest::Resume) => {
            match state.disable_owner {
                Some(owner) if owner.resumes_transport => {
                    LifecycleDecision::Claim(CommunicationOperation::Resume)
                }
                Some(_) => LifecycleDecision::SettleDisabled,
                None => LifecycleDecision::Conflict,
            }
        }

        // No lease can be granted or resumed from these states.
        (
            CommunicationState::Error(_)
            | CommunicationState::Enabling(_)
            | CommunicationState::Disabling
            | CommunicationState::DisabledExclusive,
            LifecycleRequest::Disable,
        )
        | (
            CommunicationState::Enabled
            | CommunicationState::Disabled
            | CommunicationState::Enabling(_)
            | CommunicationState::Disabling
            | CommunicationState::Error(_),
            LifecycleRequest::Resume,
        ) => LifecycleDecision::Conflict,
    }
}

/// The `Disable` cell shared by `Enabled` and `Disabled`, which differ only in
/// what releasing the resulting lease means.
///
/// [`decide`] has already rejected held guards, so only exclusivity is left to
/// check.
fn claim_disable(state: &CommunicationStateData, resumes_transport: bool) -> LifecycleDecision {
    if state.disable_owner.is_some() {
        LifecycleDecision::Conflict
    } else {
        LifecycleDecision::ClaimDisable { resumes_transport }
    }
}

/// Whether a diagnostic communication guard may be acquired right now.
///
/// Guard acquisition is separate from lifecycle transitions. Variant detection
/// does not affect guard admission, because communication remains enabled while
/// it runs.
pub(crate) fn guard_admission(state: &CommunicationState) -> Result<(), CommunicationError> {
    match state {
        CommunicationState::Enabled => Ok(()),
        CommunicationState::Disabled => Err(CommunicationError::Disabled),
        CommunicationState::Enabling(_) => Err(CommunicationError::Enabling),
        CommunicationState::Disabling => Err(CommunicationError::Disabling),
        CommunicationState::DisabledExclusive => Err(CommunicationError::DisabledExclusive),
        CommunicationState::Error(failure) => Err(CommunicationError::Failed(failure.clone())),
    }
}

#[cfg(test)]
mod tests {
    use cda_interfaces::{
        HashSet,
        communication_control::{CommunicationOperationFailure, VariantDetectionMode},
    };

    use super::{super::guard::CommunicationGuardId, *};

    /// A default lifecycle state with no active guards, detection, or lease.
    fn data(state: CommunicationState) -> CommunicationStateData {
        CommunicationStateData {
            state,
            active_guards: HashSet::default(),
            disable_owner: None,
            enabling_result: None,
            detection_in_flight: None,
            configured_variant_detection: VariantDetectionMode::Always,
            variant_detector: None,
            variant_detection: VariantDetectionMode::Never,
            shutting_down: false,
        }
    }

    // These tests cover matrix cells not already exercised by controller tests.

    #[test]
    fn held_guards_refuse_disable_from_every_state() {
        let states = [
            CommunicationState::Enabled,
            CommunicationState::Disabled,
            CommunicationState::Enabling(CommunicationOperation::Enable),
            CommunicationState::Disabling,
            CommunicationState::DisabledExclusive,
            CommunicationState::Error(CommunicationOperationFailure::TransitionFailure {
                operation: CommunicationOperation::Enable,
            }),
        ];

        for state in states {
            let mut guarded = data(state.clone());
            guarded
                .active_guards
                .insert(CommunicationGuardId(uuid::Uuid::new_v4()));
            assert_eq!(
                decide(&guarded, false, LifecycleRequest::Disable),
                LifecycleDecision::GuardsHeld,
                "state {state:?}"
            );
        }
    }

    #[test]
    fn disable_conflicts_with_an_in_flight_activation() {
        let enabling = data(CommunicationState::Enabling(CommunicationOperation::Enable));
        assert_eq!(
            decide(&enabling, false, LifecycleRequest::Disable),
            LifecycleDecision::Conflict
        );
    }

    /// Detection requires a live transport, so it cannot join an activation.
    #[test]
    fn detect_is_refused_while_an_activation_is_in_flight() {
        for in_flight in [
            CommunicationOperation::Enable,
            CommunicationOperation::EnableAndDetect,
            CommunicationOperation::Resume,
        ] {
            assert_eq!(
                decide(
                    &data(CommunicationState::Enabling(in_flight)),
                    false,
                    LifecycleRequest::Detect
                ),
                LifecycleDecision::NotEnabled,
                "in flight {in_flight:?}"
            );
        }
    }

    /// Guards block new detection, but detection does not block new guards.
    #[test]
    fn a_sweep_in_flight_still_admits_guards() {
        let mut held = data(CommunicationState::Enabled);
        held.active_guards
            .insert(CommunicationGuardId(uuid::Uuid::new_v4()));
        assert_eq!(
            decide(&held, false, LifecycleRequest::Detect),
            LifecycleDecision::GuardsHeld,
            "a held guard must still hold off a new sweep"
        );

        let mut sweeping = data(CommunicationState::Enabled);
        sweeping.detection_in_flight = Some(tokio::sync::watch::channel(None).1);
        assert_eq!(
            guard_admission(&sweeping.state),
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
