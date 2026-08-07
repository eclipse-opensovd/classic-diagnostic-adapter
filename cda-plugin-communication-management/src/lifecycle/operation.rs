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

/// Why whole-vehicle (re-)detection was requested via
/// [`CommunicationPlugin::trigger_detection`](crate::plugin::CommunicationPlugin::trigger_detection).
///
/// Authorized in all three [`CommunicationInitMode`](cda_interfaces::communication_control::CommunicationInitMode)s,
/// including `Disabled`, where it is the *only* operation permitted to initialize communication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionCause {
    /// An application or custom plugin explicitly requested (re-)detection.
    Explicit,
    /// A `networkreset(trigger_detection=true)` request.
    ///
    // TODO(networkreset-endpoint): wire this cause to the `networkreset`
    // endpoint once it exists.
    TopologyRediscovery,
}

/// A lifecycle operation controlled by the communication framework.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommunicationOperation {
    /// Activate physical transport and run initializers.
    Activate,
    /// Disable physical transport under an exclusive lease.
    Disable,
    /// Resume physical transport after a disable lease is released.
    Resume,
    /// (Re-)detect whole-vehicle communication; the only operation authorized
    /// while `Disabled`.
    Detect,
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
    #[error("transport {operation:?} failed: {error}")]
    TransportFailure {
        /// Lifecycle operation that invoked the transport.
        operation: CommunicationOperation,
        /// Transport error description.
        error: String,
    },
    /// A post-activation initializer failed.
    #[error("communication initializer {initializer} failed: {error}")]
    InitializerFailure {
        /// Initializer name.
        initializer: String,
        /// Initializer error description.
        error: String,
    },
    /// Installing the HTTP protection required by the lifecycle operation failed.
    #[error("HTTP protection for {operation:?} failed: {error}")]
    ProtectionFailure {
        /// Lifecycle operation requiring HTTP protection.
        operation: CommunicationOperation,
        /// HTTP protection error description.
        error: String,
    },
    /// The operation was invalid for the current authoritative lifecycle state.
    #[error("cannot {operation:?} in the current lifecycle state")]
    TransitionFailure {
        /// Requested operation.
        operation: CommunicationOperation,
    },

    /// The operation was rejected because an exclusive disable lease currently owns the state.
    /// Only the matching lease may re-activate communication.
    #[error("cannot {operation:?}: an exclusive disable lease is currently held")]
    DisableLeaseHeld {
        /// Requested operation.
        operation: CommunicationOperation,
    },

    /// Variant re-detection was rejected because active communication guards
    /// are held: the per-ECU request semaphore only serializes single
    /// requests, not a whole multi-request sequence (e.g. a flash transfer),
    /// so a detection request could otherwise land between two requests of
    /// that sequence.
    #[error("cannot {operation:?}: communication guards are currently held")]
    GuardsHeld {
        /// Requested operation.
        operation: CommunicationOperation,
    },

    /// The requested lifecycle capability is not yet implemented for this cause.
    #[error("{operation:?} is not implemented for this cause")]
    NotImplemented {
        /// Requested operation.
        operation: CommunicationOperation,
    },

    /// The lifecycle worker is shutting down; no new operation may start.
    #[error("cannot {operation:?}: the communication framework is shutting down")]
    ShuttingDown {
        /// Requested operation.
        operation: CommunicationOperation,
    },

    /// `init_mode` does not authorize this operation.
    ///
    /// Returned by the default communication plugin, never by
    /// [`CommunicationHandle`](crate::lifecycle::controller::CommunicationHandle)
    /// itself: the handle has no policy opinion (see ADR-006's authority model).
    #[error("init_mode does not authorize {operation:?} without an explicit trigger_detection()")]
    ModeDisabled {
        /// Requested operation.
        operation: CommunicationOperation,
    },
}
