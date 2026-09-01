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

//! Shared contracts for managed diagnostic communication lifecycle control.
//!
//! [[ dimpl~communication-control-contracts, Communication lifecycle contracts, dimpl, req~dt-deferred-initialization; arch~dt-deferred-initialization ]]
pub mod access;
pub mod error;
pub mod operation;

use std::time::Duration;

pub mod disable;

pub use access::{CommunicationAccess, CommunicationError, CommunicationGuard, CommunicationState};
use async_trait::async_trait;
pub use disable::{DisableCommunication, DisableError, DisableGuard, DisableReason};
pub use error::CommControlError;
pub use operation::{
    ActivationCause, CommunicationOperation, CommunicationOperationFailure, DetectionCause,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

/// Physical diagnostic transport state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportState {
    /// Communication is disabled (connections torn down, no traffic).
    Disabled,
    /// Communication is being enabled (gateway sequence in progress).
    Enabling,
    /// Communication is active and operational.
    Enabled,
    /// Communication is being disabled (connections being torn down).
    Disabling,
    /// Communication initialization or runtime failed.
    Failed,
}

/// Tracks the transport status.
///
/// # Ownership model
///
/// Each composed transport layer owns an unshared tracker. When a parent calls a
/// child's `enable`, both transition their own tracker. External consumers
/// observe only the outermost [`TransportControl`] implementation.
///
/// A child transport's tracker serves its `enable` idempotency short-circuit and
/// remains its source of truth when it is used independently.
///
/// This type only tracks state. Serializing a complete lifecycle operation is
/// the job of the operation mutex each layer already owns.
pub struct TransportStateTracker {
    state: RwLock<TransportState>,
}

impl TransportStateTracker {
    /// Creates a tracker initialized to `state`.
    #[must_use]
    pub fn new(state: TransportState) -> Self {
        Self {
            state: RwLock::new(state),
        }
    }

    /// Updates the communication state.
    pub async fn transition(&self, state: TransportState) {
        *self.state.write().await = state;
    }

    /// Returns the current communication state.
    pub async fn state(&self) -> TransportState {
        *self.state.read().await
    }

    /// Returns whether communication is enabled.
    pub async fn active(&self) -> bool {
        self.state().await == TransportState::Enabled
    }
}

/// Restartable-transport lifecycle scaffolding shared by gateway
/// implementations (`DoipDiagGateway`, `CanDiagGateway`): one mutex serializing
/// `enable`/`disable` transitions and holding the transport-specific
/// background-task state `Operation`, alongside a [`TransportStateTracker`].
pub struct GatewayLifecycle<Operation> {
    /// Serializes lifecycle transitions and protects `Operation`'s background-task handles.
    pub operation: Mutex<Operation>,
    /// Transport-state tracker. See [`TransportStateTracker`].
    pub coordinator: TransportStateTracker,
}

impl<Operation: Default> GatewayLifecycle<Operation> {
    /// Creates lifecycle scaffolding starting at `initial`, with a
    /// default-initialized (empty) `Operation`.
    #[must_use]
    pub fn new(initial: TransportState) -> Self {
        Self {
            operation: Mutex::new(Operation::default()),
            coordinator: TransportStateTracker::new(initial),
        }
    }
}

/// Controls when diagnostic transport network activation begins.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
pub enum CommunicationInitMode {
    /// Whole-vehicle communication is initialized immediately during startup.
    #[default]
    Always,
    /// Communication stays uninitialized at startup. HTTP/SOVD start first, and
    /// the first qualifying ECU diagnostic request, or an explicit
    /// `CommunicationPlugin::activate()` call, triggers one whole-vehicle
    /// initialization.
    OnDemand,
    /// Communication stays uninitialized at startup and ordinary activation
    /// (startup, plugin `activate()`, ECU diagnostic requests) is rejected
    /// without any vehicle-network activity.
    ///
    /// Plugin policy, not a framework invariant. The default plugin implements
    /// this mode by rejecting `activate()` and `request_activate()`. A custom
    /// plugin may choose a different policy.
    Disabled,
}

/// Controls whether whole-vehicle variant detection runs *automatically* when
/// communication is enabled.
///
/// Independent of [`CommunicationInitMode`], which decides *when* communication
/// comes up. Gates only the registered [`CommunicationVariantDetection`]
/// implementation, never the transport or the [`CommunicationLifecycle`] hooks.
///
/// Neither value disables detection outright. An explicit
/// `CommunicationPlugin::trigger_detection()` runs the detector in both.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
pub enum VariantDetectionMode {
    /// The registered detector runs as the last stage of every activation.
    #[default]
    Always,
    /// Activation brings the transport and the lifecycle hooks up only.
    ///
    /// Nothing settles [`VariantState`](crate::ecumanager::VariantState) on its
    /// own, so variant-dependent surfaces (resource listings under an ECU,
    /// request/response schemas) report not-ready until detection is triggered
    /// explicitly. Intended for deployments whose communication plugin owns the
    /// detection decision itself.
    Never,
}

/// Controls transport finalization after an operation that held exclusive
/// disabled ownership.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum PostUpdateCommunicationMode {
    /// Restore communication after the operation. Resumes displaced transport
    /// state and requests activation when policy permits.
    #[default]
    Enabled,
    /// Finalize the operation while leaving transport disabled until a later
    /// activation.
    Deferred,
}

/// Default retry hint for requests deferred while communication starts.
pub const DEFAULT_DEFERRED_RETRY_AFTER: Duration = Duration::from_secs(30);

/// Transport initialization and runtime settings.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq, schemars::JsonSchema)]
pub struct CommunicationSettings {
    /// Controls when diagnostic transport network activation begins:
    /// - "Always": whole-vehicle communication initializes eagerly at startup (default).
    /// - "OnDemand": HTTP/SOVD starts first. The first qualifying ECU diagnostic
    ///   request, or an explicit `activate()` call, triggers initialization.
    /// - "Disabled": HTTP/SOVD starts first. The default communication plugin
    ///   provides no activation path, and `trigger_detection()` needs an
    ///   already-enabled transport.
    pub init_mode: CommunicationInitMode,
    /// Controls whether enabling communication also runs whole-vehicle variant
    /// detection:
    /// - "Always": the registered detector runs as the last stage of every
    ///   activation (default).
    /// - "Never": activation brings the transport and its lifecycle hooks up
    ///   only, so variant-dependent surfaces report not-ready until detection is
    ///   triggered explicitly.
    pub variant_detection: VariantDetectionMode,
    /// Controls transport behavior after an operation held exclusive disabled
    /// ownership:
    /// - "Enabled": restore displaced transport state and request activation
    ///   when policy permits (default).
    /// - "Deferred": remain disabled until a later activation.
    pub post_update_mode: PostUpdateCommunicationMode,
    /// The value (in seconds) for the HTTP `Retry-After` header returned when a
    /// diagnostic request arrives while initialization is still pending.
    pub deferred_retry_after_seconds: u64,
}

impl Default for CommunicationSettings {
    fn default() -> Self {
        Self {
            init_mode: CommunicationInitMode::default(),
            variant_detection: VariantDetectionMode::default(),
            post_update_mode: PostUpdateCommunicationMode::default(),
            deferred_retry_after_seconds: DEFAULT_DEFERRED_RETRY_AFTER.as_secs(),
        }
    }
}

/// Trait for controlling the diagnostic transport lifecycle.
///
/// # Layered implementations
///
/// The intended call chain is:
///
/// ```text
/// lifecycle coordinator -> outer TransportControl -> child transports
/// ```
///
/// The coordinator calls `state()` on the outermost implementor to populate
/// operation results. It never reaches through to query child transport state.
#[async_trait]
pub trait TransportControl: Send + Sync + 'static {
    /// Start the diagnostic transport sequence.
    /// This must be idempotent.
    ///
    /// Implementations must prevent concurrent `enable` and `disable` calls
    /// from racing. For example, they may serialize the complete operations
    /// behind a single mutex, or `disable` may cancel an in-flight `enable`
    /// before tearing down any resources it created.
    async fn enable(&self) -> Result<(), CommControlError>;

    /// Tear down all connections and disable transport.
    /// This must be idempotent.
    ///
    /// Implementations must prevent this operation from racing with
    /// [`enable`](Self::enable). See that method for one possible strategy.
    async fn disable(&self) -> Result<(), CommControlError>;

    /// Returns the current communication state of **this** layer's tracker.
    ///
    /// When called on the router, this reflects the router-level lifecycle state.
    /// Individual gateway states are not visible through this method.
    async fn state(&self) -> TransportState;
}

/// Application-level hook into the communication transport lifecycle.
///
/// Registered implementations run in registration order when the transport is
/// enabled, and in reverse order when it is disabled.
///
/// [`initialize`](Self::initialize) and [`deinitialize`](Self::deinitialize) are
/// a matched pair. The framework never calls `initialize` twice without a
/// `deinitialize` in between, so implementations need not be re-entrant.
#[async_trait]
pub trait CommunicationLifecycle: Send + Sync + 'static {
    /// Stable name used in diagnostics.
    fn name(&self) -> &str;

    /// Called after the transport is successfully enabled.
    async fn initialize(&self) -> Result<(), CommControlError>;

    /// Called before the transport is disabled.
    ///
    /// Implementations should stop any work that requires an active transport
    /// (e.g. tester-present keep-alive tasks) and snapshot enough state to
    /// restart it in [`initialize`](Self::initialize).
    ///
    /// Defaults to a no-op.
    async fn deinitialize(&self) {}
}

/// Whole-vehicle variant detection: the last stage of an activation, and the
/// only thing an explicit detection request runs.
///
/// Separate from [`CommunicationLifecycle`], because the two have different
/// lifetimes. A hook runs on every enable and has a matching teardown, while
/// detection is optional (see [`VariantDetectionMode`]), repeatable, and has no
/// teardown counterpart. That lets an enable skip detection, and a detection run
/// without re-entering any hook's
/// [`initialize`](CommunicationLifecycle::initialize).
#[async_trait]
pub trait CommunicationVariantDetection: Send + Sync + 'static {
    /// Stable name used in diagnostics.
    fn name(&self) -> &str;

    /// Runs whole-vehicle variant detection against the live transport.
    ///
    /// Called after every registered [`CommunicationLifecycle`] hook has
    /// initialized, so implementations may rely on the transport and on hook
    /// state being up.
    ///
    /// # Errors
    ///
    /// Returns an error when detection cannot be started or completed. The
    /// framework treats this as an activation failure: hooks are deinitialized
    /// and the transport is taken back down.
    async fn detect(&self) -> Result<(), CommControlError>;
}
