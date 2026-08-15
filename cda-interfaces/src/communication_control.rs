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
pub mod disable;
pub mod error;
pub mod operation;
// Private: `SwappableGateway` inside is minted only via `ComponentSlot::transport_control`,
// which owning the slot requires. See its doc comment for the capability-boundary rationale.
mod swappable_gateway;

use std::time::Duration;

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
/// Each layer in the transport stack owns its own independent tracker:
///
/// - The diagnostic transport router owns one tracker.
/// - Each gateway (`DoipDiagGateway`, `CanDiagGateway`) owns its own tracker.
///
/// These trackers are **not shared**. When the router calls `gateway.enable()`,
/// the gateway transitions its own tracker internally, and the router transitions
/// its own tracker based on the result. The communication manager only ever
/// observes the outermost tracker (the router's, via the transport-control view
/// minted from `ComponentSlot::transport_control`).
///
/// Gateway-level trackers exist solely for:
/// - **Idempotency**: the gateway's `enable()` short-circuits if its own tracker
///   already reports active.
/// - **Standalone use**: when a gateway is used without a router (tests, shutdown),
///   its tracker is the only source of truth.
///
/// When a gateway is embedded inside a router, the **router's tracker is
/// authoritative** for all external consumers (coordinator, HTTP guards, policies).
/// The gateway's tracker is an internal implementation detail invisible to them.
///
/// This type only tracks state. Serializing a *complete* lifecycle operation
/// (status check, work, final transition) is a separate concern: gateways
/// already own a private operation mutex that also carries their operation
/// data, and the router owns its own dedicated lock for the same purpose
/// (see `DiagnosticTransportRouter`'s `operation_lock`). A single shared type
/// would leave that lock unused wherever an operation-data mutex already
/// does the job.
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
/// implementations (`DoipDiagGateway`, `CanDiagGateway`): one mutex
/// serializing `enable`/`disable` transitions and holding the
/// transport-specific background-task state `Operation`, alongside the
/// [`TransportStateTracker`] external consumers observe.
///
/// Gateway-local lifecycle state. When a gateway using this is embedded
/// inside a `DiagnosticTransportRouter`, [`coordinator`](Self::coordinator)
/// is an internal detail - the router's own tracker is authoritative for
/// external consumers. It still serves the gateway's `enable()` idempotency
/// guard.
pub struct GatewayLifecycle<Operation> {
    /// Serializes lifecycle transitions and protects `Operation`'s background-task handles.
    pub operation: Mutex<Operation>,
    /// Transport-state tracker; see the type-level docs.
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
    ///
    /// This is the current eager-startup behavior and remains the default.
    #[default]
    Always,
    /// Communication stays uninitialized at startup. HTTP/SOVD start first;
    /// the first qualifying ECU diagnostic request, or an explicit
    /// `CommunicationPlugin::activate()` call, triggers one whole-vehicle
    /// initialization.
    OnDemand,
    /// Communication stays uninitialized at startup and ordinary activation
    /// (startup, plugin `activate()`, ECU diagnostic requests) is rejected
    /// without any vehicle-network activity.
    ///
    /// This is a *plugin policy* value, not a framework invariant: the
    /// lifecycle framework never inspects `init_mode` to decide whether an
    /// operation is authorized. The default plugin implements this mode by
    /// rejecting `activate()`/`request_activate()`. Its explicit
    /// `CommunicationPlugin::trigger_detection()` can re-detect only while
    /// communication is already enabled; a custom startup-selected plugin may
    /// implement a different policy.
    Disabled,
}

/// Controls whether whole-vehicle variant detection runs *automatically* when
/// communication is enabled.
///
/// Independent of [`CommunicationInitMode`], which decides *when* communication
/// comes up: this decides whether bringing it up also settles every ECU's
/// variant. It gates only the registered [`CommunicationVariantDetection`] implementation,
/// never the transport itself and never the registered
/// [`CommunicationLifecycle`] hooks.
///
/// Neither value ever disables detection outright: an explicit
/// `CommunicationPlugin::trigger_detection()` runs the detector in both.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
pub enum VariantDetectionMode {
    /// The registered detector runs as the last stage of every activation.
    ///
    /// This is the current behavior and remains the default.
    #[default]
    Always,
    /// Activation brings the transport and the lifecycle hooks up only.
    ///
    /// Nothing settles [`VariantState`](crate::ecumanager::VariantState) *on its
    /// own*, so variant-dependent surfaces (resource listings under an ECU,
    /// request/response schemas) report not-ready until detection is triggered
    /// explicitly - which stays available in this mode, and is how a runtime
    /// configured this way becomes ready. Intended for deployments whose
    /// communication plugin owns the detection decision itself.
    Never,
}

/// Controls behavior of diagnostic transport after a runtime database update.
///
/// An update always takes the exclusive disable lease, so communication is
/// unavailable for its duration regardless; this decides only what happens to
/// the lease once the update finishes.
///
/// See ADR-006, "Decision"
/// (`docs/04_adr/06_deferred_initialization.rst`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum PostUpdateCommunicationMode {
    /// After update, have communication up: resume the transport the update
    /// displaced, and request activation if it started from a deferred runtime.
    /// The request is subject to `init_mode`, so under `Disabled` communication
    /// stays down regardless.
    #[default]
    Enabled,
    /// After update, leave communication deferred - the transport stays down
    /// until triggered - even if the update displaced an enabled one.
    Deferred,
}

/// Default retry hint for requests deferred while communication starts.
pub const DEFAULT_DEFERRED_RETRY_AFTER: Duration = Duration::from_secs(30);

/// Transport initialization and runtime settings.
///
/// Controls when diagnostic transport network activation begins, how transport behaves after
/// database updates, and retry behavior for deferred initialization.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq, schemars::JsonSchema)]
pub struct CommunicationSettings {
    /// Controls when diagnostic transport network activation begins:
    /// - "Always": whole-vehicle communication initializes eagerly at startup (default).
    /// - "OnDemand": HTTP/SOVD starts first; the first qualifying ECU diagnostic
    ///   request, or an explicit `activate()` call, triggers initialization.
    /// - "Disabled": HTTP/SOVD starts first; the default communication plugin
    ///   provides no activation path. `trigger_detection()` can only re-detect an
    ///   already-live transport and does not activate communication.
    pub init_mode: CommunicationInitMode,
    /// Controls whether enabling communication also runs whole-vehicle variant
    /// detection. Independent of `init_mode`, which decides *when* communication
    /// comes up; this decides whether bringing it up also settles every ECU's
    /// variant:
    /// - "Always": the registered detector runs as the last stage of every
    ///   activation (default).
    /// - "Never": activation brings the transport and its lifecycle hooks up only.
    ///   Nothing settles a variant on its own, so variant-dependent surfaces
    ///   (resource listings under an ECU, request/response schemas) report not-ready
    ///   until detection is triggered. For deployments whose communication plugin
    ///   owns the detection decision itself.
    ///
    /// Neither value disables detection outright: an explicit `trigger_detection()`
    /// runs the detector in both.
    pub variant_detection: VariantDetectionMode,
    /// Controls transport behavior after a runtime database update:
    /// - "Enabled": resume the transport the update displaced, requesting
    ///   activation if it started from a deferred runtime, subject to `init_mode`
    ///   (default).
    /// - "Deferred": leave communication deferred - the transport stays down until
    ///   triggered - even if the update displaced an enabled one.
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
/// CommunicationHandle -> SwappableGateway -> DiagnosticTransportRouter -> Gateways
/// ```
///
/// The coordinator calls `state()` on the outermost implementor to populate
/// operation results. It never reaches through to query individual gateway state.
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
    /// [`enable`](Self::enable); see that method for one possible strategy.
    async fn disable(&self) -> Result<(), CommControlError>;

    /// Returns the current communication state of **this** layer's tracker.
    ///
    /// When called on the router, this reflects the router-level lifecycle state.
    /// Individual gateway states are not visible through this method.
    async fn state(&self) -> TransportState;
}

/// Application-level hook into the communication transport lifecycle.
///
/// Registered implementations run in registration order on every transport
/// enable and in reverse order on every transport disable.
/// A lifecycle's job is to follow the *transport*, not the
/// detection policy.
///
/// [`initialize`](Self::initialize) and [`deinitialize`](Self::deinitialize)
/// are a matched pair. The framework never calls `initialize` twice without a
/// `deinitialize` in between, so implementations do not have to be re-entrant.
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
    /// The default implementation is a no-op so existing implementors do not
    /// need to be updated unless they have disable-time teardown to perform.
    async fn deinitialize(&self) {}
}

/// Whole-vehicle variant detection: the last stage of an activation, and the
/// only thing an explicit re-detection re-runs.
///
/// Deliberately separate from [`CommunicationLifecycle`], because the two have
/// different lifetimes. A lifecycle hook is coupled to the transport: it runs
/// on every enable and has a matching teardown. Detection is optional (see
/// [`VariantDetectionMode`]), repeatable against an already-live transport, and
/// has no teardown counterpart, there is nothing to undo about having learned
/// which variant an ECU is.
///
/// Keeping them apart is what lets an enable bring the transport and its hooks
/// up without detecting, and lets a re-detection run without re-entering any
/// hook's [`initialize`](CommunicationLifecycle::initialize).
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
