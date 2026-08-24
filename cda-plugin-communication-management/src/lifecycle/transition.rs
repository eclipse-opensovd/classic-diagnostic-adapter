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

//! The authoritative lifecycle transition matrix.
//!
//! [`decide`] is the single place in this crate that answers "is this
//! transition admitted from this state?". It is pure - it reads
//! [`CommunicationStateData`] and writes nothing - so the verdict for any cell
//! is readable in one place instead of reconstructed from a call stack, and a
//! state that cannot serve an operation says so in its own arm rather than
//! having a wildcard absorb it.
//!
//! The three claim sites - `CommunicationHandle::claim_or_join`,
//! `CommunicationHandle::disable`, and the worker's `execute_release` - all ask
//! this function first and then *apply* the returned [`LifecycleDecision`].
//! Applying stays site-local because the state writes and the error types
//! differ; deciding does not.
//!
//! Two things are deliberately *not* modeled here:
//!
//! * **Outcomes.** Publishing the result of an already-admitted transition
//!   belongs to `publish_enabling_result` and the `finish_*` helpers.
//!   Admission and outcome are different questions.
//! * **Authority.** Whether a caller may ask - `init_mode` policy, or whether a
//!   [`DisableLease`](super::disable::DisableLease) is the one that owns the
//!   current disable - is the caller's business, exactly as ADR-006's authority
//!   model has it. This matrix only ever asks what the *state* permits.

use cda_interfaces::communication_control::{
    CommunicationError, CommunicationOperation, CommunicationState,
};

use super::state::CommunicationStateData;

/// A lifecycle transition a caller can ask the state machine to admit.
///
/// The transition subset of [`CommunicationOperation`]. It exists so the matrix
/// only ever rules on things that *are* transitions: `RegisterLifecycleHook`
/// and `RegisterVariantDetection` borrow `CommunicationOperation` purely as
/// failure labels, and giving them cells here - and a verdict for those cells -
/// would push a nonsense value out to every consumer of the result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LifecycleRequest {
    /// Transport up and lifecycle hooks initialized, without variant detection.
    Enable,
    /// Transport up, hooks initialized, then variant detection.
    EnableAndDetect,
    /// Variant detection only, against an already-live transport.
    Detect,
    /// Take the sole exclusive disable lease.
    Disable,
    /// Re-activate after an exclusive disable lease is released.
    ///
    /// Whether the asking lease actually owns the current disable is the
    /// caller's check, not this matrix's - see the module docs on authority.
    Resume,
}

impl LifecycleRequest {
    /// The operation this request is recorded and reported as: the label on a
    /// resulting failure, and the payload of
    /// [`CommunicationState::Enabling`].
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

/// What the state machine admits for a request, with no side effect
/// attached: the caller performs the corresponding state write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LifecycleDecision {
    /// Claim `Enabling(operation)` and run that activation sequence.
    Claim(CommunicationOperation),
    /// Claim the detection slot and run the detector against the live
    /// transport.
    ///
    /// Deliberately distinct from [`Claim`](Self::Claim): applying this writes
    /// [`detection_in_flight`](super::state::CommunicationStateData::detection_in_flight)
    /// and leaves `state` at [`CommunicationState::Enabled`], because a
    /// re-detection changes nothing physical and so is not a transition. Only
    /// reachable from `Enabled` - detection runs against a live transport and
    /// never brings one up.
    ClaimDetection,
    /// A re-detection is already in flight; join its result instead of
    /// claiming a second sweep.
    ///
    /// Separate from [`Join`](Self::Join) for the same reason `ClaimDetection`
    /// is separate from `Claim`: the two are joined through different slots,
    /// and conflating them would let a `Detect` report an activation's outcome
    /// as its own.
    JoinDetection,
    /// An activation-shaped operation is already in flight; join its result
    /// instead of claiming a second one.
    ///
    /// Carries the in-flight operation, not the requested one: a joiner
    /// observes whatever the claiming operation does. Only the two activation
    /// requests reach this - a `Detect` asked for during an activation is
    /// refused with [`NotEnabled`](Self::NotEnabled) rather than joining it,
    /// which would report `Enabled` without any detector having run.
    Join(CommunicationOperation),
    /// Communication is already enabled; there is nothing to claim and
    /// therefore **no stage runs** - not the transport, not the hooks, and not
    /// the detector.
    ///
    /// So an [`EnableAndDetect`](CommunicationOperation::EnableAndDetect) that
    /// lands here detects nothing, including when the runtime was brought up by
    /// a plain `Enable` and no variant has ever been settled. Detection against
    /// an already-live transport is a separate request
    /// ([`Detect`](CommunicationOperation::Detect)); this verdict never
    /// escalates into one, because "communication is available" is what the
    /// caller asked for and re-sweeping the vehicle on every such request would
    /// be ruinous.
    AlreadyEnabled,
    /// Claim `Disabling` and grant the lease. `resumes_transport` records
    /// whether the transport was up, which fixes what releasing means (see
    /// [`DisableOwner::resumes_transport`](super::disable::DisableOwner)).
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
    /// Detection runs against a live transport and never brings one up.
    NotEnabled,
    /// Refused: this state cannot serve this operation - it cannot grant a
    /// lease, or the resume it was asked for belongs to a disable cycle that is
    /// no longer current.
    Conflict,
    /// Refused: the lifecycle is shutting down; no new transition may start.
    ShuttingDown,
}

/// Decides whether `request` is admitted from the current lifecycle state.
///
/// Pure: reads `state`, writes nothing, spawns nothing. The caller applies the
/// returned [`LifecycleDecision`] under the same lock it used to call this.
///
/// The match below is the state machine. It is exhaustive over both axes with
/// no wildcard arm on either, so adding a [`CommunicationState`] or a
/// [`LifecycleRequest`] variant fails to compile here until every new cell has
/// been decided explicitly.
pub(crate) fn decide(
    state: &CommunicationStateData,
    worker_shutting_down: bool,
    request: LifecycleRequest,
) -> LifecycleDecision {
    // Shutdown short-circuits every operation from every state. Both flags are
    // checked here so all shutdown reasoning lives in this function: the worker
    // flag closes admission before the worker's own sequence starts, and
    // `state.shutting_down` is the one that is set under this lock.
    if worker_shutting_down || state.shutting_down {
        return LifecycleDecision::ShuttingDown;
    }

    let guards_held = !state.active_guards.is_empty();

    // For 'disable', held guards outrank the state: "communication is in use"
    // is the more specific answer, and reporting it from every state - not just
    // the two that could otherwise grant a lease.
    // Detection's own guard check is state-specific and stays in its arm below.
    //
    // An in-flight re-detection counts as use here, and this half is
    // load-bearing rather than cosmetic: a sweep leaves the state at `Enabled`,
    // so without it the `(Enabled, Disable)` cell would grant a lease and tear
    // the transport down underneath a running detection.
    if request == LifecycleRequest::Disable && (guards_held || state.detection_in_flight.is_some())
    {
        return LifecycleDecision::GuardsHeld;
    }

    match (&state.state, request) {
        // Enabled:
        // Both are satisfied by the current state, so neither claims anything
        // and no stage runs. `EnableAndDetect` in particular does not detect
        // here - it is a request for available communication, not a request to
        // re-sweep the vehicle. See `LifecycleDecision::AlreadyEnabled`.
        (
            CommunicationState::Enabled,
            LifecycleRequest::Enable | LifecycleRequest::EnableAndDetect,
        ) => LifecycleDecision::AlreadyEnabled,
        // The one cell that claims without transitioning: applying it writes
        // the detection slot and leaves `state` at `Enabled`. A sweep already
        // in flight is joined rather than duplicated.
        (CommunicationState::Enabled, LifecycleRequest::Detect) => {
            if state.detection_in_flight.is_some() {
                LifecycleDecision::JoinDetection
            } else if guards_held {
                LifecycleDecision::GuardsHeld
            } else {
                LifecycleDecision::ClaimDetection
            }
        }
        // A lease taken from `Enabled` displaces a live transport, so releasing
        // it brings that transport back.
        (CommunicationState::Enabled, LifecycleRequest::Disable) => claim_disable(state, true),

        // Disabled:
        // Nothing to take down, and correspondingly nothing to bring back up:
        // releasing returns to plain `Disabled`, so a lease can never become an
        // activation path.
        (CommunicationState::Disabled, LifecycleRequest::Disable) => claim_disable(state, false),

        // Disabled / Error:
        // Both are inactive with the transport down, so both admit the same
        // activations: recovery from `Error` *is* an activation, claimed again
        // from scratch.
        (CommunicationState::Disabled | CommunicationState::Error(_), LifecycleRequest::Enable) => {
            LifecycleDecision::Claim(CommunicationOperation::Enable)
        }
        (
            CommunicationState::Disabled | CommunicationState::Error(_),
            LifecycleRequest::EnableAndDetect,
        ) => LifecycleDecision::Claim(CommunicationOperation::EnableAndDetect),
        // Detection runs against a live transport and never brings one up, so
        // every state without one refuses it identically - including
        // `Enabling(_)`, where an activation is still bringing the transport up.
        //
        // `Enabling(_)` is refused rather than joined for a reason: a `Detect`
        // that joined a plain `Enable` would report `Enabled` while no detector
        // ever ran, a silent success for a caller that explicitly asked to
        // re-read the vehicle. ADR-006's `trigger_detection()` table and the
        // default plugin's module docs both specify "re-detect while `Enabled`,
        // refused otherwise"; this arm is what makes that true.
        (
            CommunicationState::Disabled
            | CommunicationState::Error(_)
            | CommunicationState::Enabling(_),
            LifecycleRequest::Detect,
        ) => LifecycleDecision::NotEnabled,

        // Enabling:
        // Only the two activation requests join; `Detect` is refused above.
        (
            CommunicationState::Enabling(in_flight),
            LifecycleRequest::Enable | LifecycleRequest::EnableAndDetect,
        ) => LifecycleDecision::Join(*in_flight),

        // Disabling / DisabledExclusive:
        (
            current @ (CommunicationState::Disabling | CommunicationState::DisabledExclusive),
            LifecycleRequest::Enable | LifecycleRequest::EnableAndDetect | LifecycleRequest::Detect,
        ) => LifecycleDecision::LeaseHeld(current.clone()),

        // Resume:
        // Only an exclusively-owned transport can be resumed, and *whether* it
        // resumes is fixed by the lease that displaced it, never by the
        // releaser. Whether the asking lease is the current owner is the
        // caller's check, not this matrix's.
        (CommunicationState::DisabledExclusive, LifecycleRequest::Resume) => {
            match state.disable_owner {
                Some(owner) if owner.resumes_transport => {
                    LifecycleDecision::Claim(CommunicationOperation::Resume)
                }
                Some(_) => LifecycleDecision::SettleDisabled,
                None => LifecycleDecision::Conflict,
            }
        }

        // No lease to grant, and no resume to make:
        // For `Disable`: `Error` because the transport's actual state is
        // unknown there, so neither resume shape could be chosen honestly, and
        // the rest because a transition is already under way or a lease is
        // already held. For `Resume`: nothing in these states was displaced by
        // a lease, so there is nothing to restore.
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
/// Guards have already been rejected by [`decide`] at this point; only
/// exclusivity is left to check.
fn claim_disable(state: &CommunicationStateData, resumes_transport: bool) -> LifecycleDecision {
    if state.disable_owner.is_some() {
        LifecycleDecision::Conflict
    } else {
        LifecycleDecision::ClaimDisable { resumes_transport }
    }
}

/// Whether a diagnostic communication guard may be acquired right now.
///
/// A second, deliberately separate table: acquiring a guard is not a lifecycle
/// transition - it claims nothing and moves nothing - so it answers a different
/// question, with its own error type, and does not belong among [`decide`]'s
/// cells. It lives in this module so that *every* reading of
/// [`CommunicationState`] is in one place rather than one table here and
/// another in the controller.
///
/// Deliberately unaware of re-detection. A sweep leaves the state at `Enabled`,
/// so guards keep being admitted throughout one and diagnostics keep being
/// served - the runtime genuinely is usable, and per-ECU `VariantState` already
/// governs the requests that actually depend on a settled variant. The reverse
/// direction (a held guard refusing a *new* sweep) is a `decide` cell, not this
/// table's business.
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

    /// A default state: no guards, no detection in flight, no lease owner, not
    /// shutting down.
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

    // Only cells with no behavioral coverage are pinned here. The rest of the
    // matrix is already exercised end-to-end by the `controller` tests -
    // `redetect_refused_while_guard_held`, `detect_rejected_when_not_enabled`,
    // `lease_refused_from_error`, `lease_from_disabled_*`, the join tests, and
    // the shutdown tests - and asserting the same cells again against `decide`
    // would restate the match rather than test it.

    /// Held guards refuse a disable from *every* state, outranking whatever the
    /// state itself would have said.
    ///
    /// The behavioural test (`disable_rejects_active_guards_and_blocks_activate_while_leased`)
    /// only ever holds a guard while `Enabled`, so this precedence - the guard
    /// check sitting ahead of the state match rather than inside the two arms
    /// that could otherwise grant a lease - is pinned only here.
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

    /// A disable racing an in-flight activation is refused outright rather than
    /// waiting behind it. No behavioural test reaches this cell.
    #[test]
    fn disable_conflicts_with_an_in_flight_activation() {
        let enabling = data(CommunicationState::Enabling(CommunicationOperation::Enable));
        assert_eq!(
            decide(&enabling, false, LifecycleRequest::Disable),
            LifecycleDecision::Conflict
        );
    }

    /// A detect asked for while an activation is bringing the transport up is
    /// refused, not joined: there is no live transport to detect against yet.
    ///
    /// Pinned for every in-flight shape. Joining would be a silent success for
    /// a caller that explicitly asked to re-read the vehicle, and it would be
    /// wrong in a way that varies by shape - accurate by luck when the
    /// activation happens to detect, a plain lie when it does not.
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

    /// The exclusion between guards and detection runs one way only.
    ///
    /// A held guard refuses a *new* sweep, per ADR-006: a guard is the only
    /// lock spanning a multi-request sequence, and detection must not land in
    /// the middle of one. The converse does not hold: a sweep in flight leaves
    /// the state at `Enabled`, so guards keep being admitted and diagnostics
    /// keep being served for its duration. Blocking them would close the
    /// diagnostic surface over a working transport for seconds and buy nothing,
    /// since per-ECU `VariantState` already governs the requests that depend on
    /// a settled variant.
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
