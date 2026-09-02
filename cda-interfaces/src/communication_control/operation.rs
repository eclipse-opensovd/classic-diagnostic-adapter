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

//! Authoritative communication lifecycle operations and failures.
//!
//! [[ dimpl~communication-control-operations, Authoritative communication lifecycle operations, dimpl, req~dt-deferred-initialization; arch~dt-deferred-initialization ]]
//!
//! Part of the communication-access contract (with [`super::access`]), defined
//! here so that transport crates and replacement communication plugins can
//! depend on it without coupling to the default plugin's crate.

/// Why authoritative communication activation was requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationCause {
    /// Startup requires communication to be available immediately (`Always` mode).
    Startup,
    /// A diagnostic UDS operation needed communication while it was not ready.
    DiagnosticRequest,
    /// An application or custom plugin explicitly requested activation.
    Explicit,
    /// An exclusive disable lease was released.
    DisableRelease,
}

/// Why whole-vehicle (re-)detection was requested via a communication
/// plugin's `trigger_detection`.
///
/// The framework attaches no authorization meaning to a cause. Which ones are
/// admitted in a given
/// [`CommunicationInitMode`](crate::communication_control::CommunicationInitMode)
/// is the selected plugin's policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionCause {
    /// An application or custom plugin explicitly requested (re-)detection.
    Explicit,
    // TODO(networkreset-endpoint, #490): add TopologyRediscovery variant for
    // the `networkreset(trigger_detection=true)` request once the endpoint
    // exists.
}

/// A lifecycle operation controlled by the communication framework.
///
/// An activation prepares every registered lifecycle reconfiguration
/// participant and hook, publishes their state through one synchronous commit
/// barrier, enables the transport, initializes the hooks, then runs
/// [`CommunicationVariantDetection`](super::CommunicationVariantDetection).
/// Activation-shaped operations differ only in which stages they run:
///
/// | Operation | Prepare + commit | Transport | `initialize` | Detector |
/// |-----------|------------------|-----------|--------------|----------|
/// | `Enable` | yes | enable | yes | no |
/// | `EnableAndDetect` | yes | enable | yes | yes, subject to `VariantDetectionMode` |
/// | `Detect` | untouched | untouched | untouched | yes |
/// | `Resume` | yes | restore displaced state | if enabled | whatever the enable it resumes did |
///
/// Which of them a caller may request in a given `init_mode` is the selected
/// communication plugin's policy.
///
/// # Stages run only on a transition
///
/// Every row above applies only when the operation claims a transition. From
/// [`Enabled`](super::access::CommunicationState::Enabled), `Enable` and
/// `EnableAndDetect` succeed without running any stage. Detecting from there
/// requires a separate [`Detect`](Self::Detect).
/// `VariantState` remains the readiness signal, because detection settles per
/// ECU and asynchronously.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommunicationOperation {
    /// Activate physical transport and run lifecycle hooks, but *not* variant
    /// detection. For plugins that own the detection decision themselves.
    Enable,
    /// Activate physical transport, run lifecycle hooks, then run variant
    /// detection.
    EnableAndDetect,
    /// Register a lifecycle hook with the communication worker.
    RegisterLifecycleHook,
    /// Register the whole-vehicle variant detector with the communication worker.
    RegisterVariantDetection,
    /// Disable physical transport under an exclusive lease.
    Disable,
    /// Resume physical transport after a disable lease is released.
    Resume,
    /// Finalize pending lifecycle reconfiguration while remaining disabled.
    FinishDisableLease,
    /// Run whole-vehicle variant detection against an already-live transport.
    ///
    /// Touches neither the transport nor the lifecycle hooks, and is therefore
    /// valid only from
    /// [`CommunicationState::Enabled`](super::access::CommunicationState::Enabled).
    /// From any other state it is refused with
    /// [`CommunicationOperationFailure::TransitionFailure`].
    Detect,
}

impl CommunicationOperation {
    /// Whether this operation's activation sequence runs variant detection
    /// after the transport and the lifecycle hooks are up.
    ///
    /// Only meaningful for the operations that reach the activation sequence.
    /// `Resume` never consults this. It repeats the shape of the enable it
    /// resumes, which only the worker knows.
    #[must_use]
    pub const fn runs_detection(self) -> bool {
        !matches!(self, Self::Enable)
    }
}

/// A structured failure of an authoritative lifecycle operation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommunicationOperationFailure {
    #[error(
        "Permission denied for {operation:?}. Likely the operation was protected by a different \
         owner."
    )]
    PermissionFailure {
        /// Lifecycle operation that was rejected.
        operation: CommunicationOperation,
    },

    /// The physical transport operation failed.
    #[error("Transport {operation:?} failed: {error}")]
    TransportFailure {
        /// Lifecycle operation that invoked the transport.
        operation: CommunicationOperation,
        /// Transport error description.
        error: String,
    },
    /// A post-activation initializer failed.
    #[error("Communication initializer {initializer} failed: {error}")]
    InitializerFailure {
        /// Initializer name.
        initializer: String,
        /// Initializer error description.
        error: String,
    },
    /// An initializer failed and transport cleanup failed as well.
    #[error(
        "Communication initializer {initializer} failed: {initializer_error}; transport cleanup \
         failed: {cleanup_error}"
    )]
    InitializerCleanupFailure {
        /// Initializer name.
        initializer: String,
        /// Initializer error description.
        initializer_error: String,
        /// Transport cleanup error description.
        cleanup_error: String,
    },
    /// Variant detection failed.
    #[error("Variant detection {detector} failed: {error}")]
    DetectionFailure {
        /// Detector name.
        detector: String,
        /// Detection error description.
        error: String,
    },
    /// Variant detection failed and transport cleanup failed as well.
    #[error(
        "Variant detection {detector} failed: {detection_error}; transport cleanup failed: \
         {cleanup_error}"
    )]
    DetectionCleanupFailure {
        /// Detector name.
        detector: String,
        /// Detection error description.
        detection_error: String,
        /// Transport cleanup error description.
        cleanup_error: String,
    },

    /// The operation was invalid for the current authoritative lifecycle state.
    ///
    /// Notably returned for a [`CommunicationOperation::Detect`] requested
    /// while communication is not `Enabled`. Detection runs against a live
    /// transport and never brings one up itself.
    #[error("Cannot {operation:?} in the current lifecycle state")]
    TransitionFailure {
        /// Requested operation.
        operation: CommunicationOperation,
    },

    /// The operation was rejected because an exclusive disable lease currently owns the state.
    /// Only the matching lease may re-activate communication.
    #[error("Cannot {operation:?}: an exclusive disable lease is currently held")]
    DisableLeaseHeld {
        /// Requested operation.
        operation: CommunicationOperation,
    },

    /// Variant detection was rejected because active communication guards are
    /// held.
    ///
    /// A [`CommunicationGuard`](super::access::CommunicationGuard) is the only
    /// lock that spans a whole multi-request sequence (e.g. a flash transfer's
    /// `TransferData` blocks). The per-ECU transport semaphore reopens between
    /// individual requests, so a detection request could otherwise land between
    /// two requests of that sequence.
    ///
    /// Detection is refused rather than made to wait, so that the decision stays
    /// synchronous and a minutes-long sequence cannot block it.
    #[error("Cannot {operation:?}: communication guards are currently held")]
    GuardsHeld {
        /// Requested operation.
        operation: CommunicationOperation,
    },

    /// The lifecycle worker is shutting down. No new operation may start.
    #[error("Cannot {operation:?}: the communication framework is shutting down")]
    ShuttingDown {
        /// Requested operation.
        operation: CommunicationOperation,
    },

    /// The lifecycle worker exited unexpectedly and cannot process the request.
    #[error("Cannot {operation:?}: the communication worker is unavailable")]
    WorkerUnavailable {
        /// Requested operation.
        operation: CommunicationOperation,
    },

    /// `init_mode` does not authorize this operation.
    ///
    /// Returned by a communication plugin applying its own policy, never by the
    /// framework's lifecycle handle.
    #[error(
        "init_mode does not authorize {operation:?}; communication must be enabled out of band"
    )]
    ModeDisabled {
        /// Requested operation.
        operation: CommunicationOperation,
    },
}
