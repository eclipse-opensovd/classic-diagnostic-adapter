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

pub mod error;
pub mod swappable_gateway;

use async_trait::async_trait;
pub use error::CommControlError;
use serde::{Deserialize, Serialize};
pub use swappable_gateway::SwappableGateway;
use tokio::sync::{Mutex, MutexGuard, RwLock};

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

/// Tracks the transport status and serializes lifecycle operations.
///
/// # Ownership model
///
/// Each layer in the transport stack owns its own independent tracker:
///
/// - The diagnostic transport router owns one tracker (the **authoritative** one).
/// - Each gateway (`DoipDiagGateway`, `CanDiagGateway`) owns its own tracker.
///
/// These trackers are **not shared**. When the router calls `gateway.enable()`,
/// the gateway transitions its own tracker internally, and the router transitions
/// its own tracker based on the result. The communication manager only ever
/// observes the outermost tracker (the router's, via [`SwappableGateway`]).
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
pub struct TransportStateTracker {
    state: RwLock<TransportState>,
    lifecycle: Mutex<()>,
}

impl TransportStateTracker {
    /// Creates a tracker initialized to `state`.
    #[must_use]
    pub fn new(state: TransportState) -> Self {
        Self {
            state: RwLock::new(state),
            lifecycle: Mutex::new(()),
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

    /// Serializes a complete lifecycle operation for this tracker.
    ///
    /// Callers retain this guard across their status check, lifecycle work, and
    /// final transition. Status reads remain available while the operation runs.
    pub async fn lifecycle_guard(&self) -> MutexGuard<'_, ()> {
        self.lifecycle.lock().await
    }
}

#[cfg(test)]
mod tests {
    use super::{TransportState, TransportStateTracker};

    #[tokio::test]
    async fn active_reflects_communication_state() {
        let tracker = TransportStateTracker::new(TransportState::Disabled);

        assert!(!tracker.active().await);

        tracker.transition(TransportState::Enabling).await;
        assert!(!tracker.active().await);

        tracker.transition(TransportState::Enabled).await;
        assert!(tracker.active().await);

        tracker.transition(TransportState::Failed).await;
        assert!(!tracker.active().await);
    }

    #[tokio::test]
    async fn lifecycle_guard_is_exclusive() {
        let tracker = TransportStateTracker::new(TransportState::Disabled);
        let guard = tracker.lifecycle_guard().await;

        assert!(tracker.lifecycle.try_lock().is_err());

        drop(guard);
        assert!(tracker.lifecycle.try_lock().is_ok());
    }
}

/// Controls when diagnostic transport gateway creation begins.
///
/// See ADR-006 (`docs/04_adr/06_deferred_initialization.rst`) for the full
/// authority model and the persistence-dependent follow-up work each mode
/// anticipates.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
pub enum CommunicationInitMode {
    /// Whole-vehicle communication is initialized immediately during startup.
    ///
    /// This is the current eager-startup behavior and remains the default.
    #[default]
    #[serde(alias = "Enabled")]
    Always,
    /// Communication stays uninitialized at startup. HTTP/SOVD start first;
    /// the first qualifying ECU diagnostic request, or an explicit
    /// `CommunicationPlugin::activate()` call, triggers one whole-vehicle
    /// initialization.
    OnDemand,
    /// Communication stays uninitialized at startup and ordinary activation
    /// (startup, plugin `activate()`, ECU diagnostic requests) is rejected
    /// without any vehicle-network activity. Only an explicit
    /// `CommunicationPlugin::trigger_detection()` call may initialize
    /// communication.
    Disabled,
}

/// Controls behavior of diagnostic transport after a runtime database update.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum PostUpdateCommunicationMode {
    /// After update, reconnect immediately.
    #[default]
    Enabled,
    /// After update, return to deferred state - transport stays down until triggered.
    Deferred,
    /// After update, maintain the status transport was in before the update started.
    ///
    /// If transport was deferred (not yet triggered), it remains deferred.
    /// If transport was active, it reconnects immediately.
    Last,
}

/// Transport initialization and runtime settings.
///
/// Controls when gateway creation begins, how transport behaves after
/// database updates, and retry behavior for deferred initialization.
#[derive(Deserialize, Serialize, Clone, Debug, schemars::JsonSchema)]
pub struct CommunicationSettings {
    /// Controls when gateway creation and ECU communication begins.
    pub init_mode: CommunicationInitMode,
    /// Controls transport behavior after a runtime database update.
    pub post_update_mode: PostUpdateCommunicationMode,
    /// The value (in seconds) for the HTTP `Retry-After` header returned when a
    /// diagnostic request arrives while initialization is still pending.
    pub deferred_retry_after_seconds: u64,
}

impl Default for CommunicationSettings {
    fn default() -> Self {
        Self {
            init_mode: CommunicationInitMode::default(),
            post_update_mode: PostUpdateCommunicationMode::default(),
            deferred_retry_after_seconds: 30,
        }
    }
}

/// Trait for controlling the diagnostic transport lifecycle.
///
/// # Layered implementations
///
/// The production call chain is:
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
    async fn enable(&self) -> Result<(), CommControlError>;

    /// Tear down all connections and disable transport.
    /// This must be idempotent.
    async fn disable(&self) -> Result<(), CommControlError>;

    /// Returns the current communication state of **this** layer's tracker.
    ///
    /// When called on the router, this reflects the router-level lifecycle state.
    /// Individual gateway states are not visible through this method.
    async fn state(&self) -> TransportState;
}

/// Performs application-specific setup after diagnostic transport is enabled.
///
/// Initializers run in registration order after a successful transport enable and
/// before framework initializers declare communication ready.
#[async_trait]
pub trait CommunicationInitializer: Send + Sync + 'static {
    /// Stable name used in diagnostics when initialization fails.
    fn name(&self) -> &str;

    /// Performs the initialization work.
    async fn initialize(&self) -> Result<(), CommControlError>;
}
