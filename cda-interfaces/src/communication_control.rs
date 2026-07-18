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

//! Communication Control API
//!
//! Provides a trait for controlling the lifecycle of diagnostic communication
//! (enable, disable) and querying the current state.
//! Also contains configuration types for communication initialization mode
//! and post-update behavior.

use std::sync::{Arc, atomic::AtomicBool};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// State of the communication subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, strum::Display)]
pub enum CommState {
    /// Communication is disabled (connections torn down, no traffic).
    Disabled,
    /// Communication is being initialized (transport sequence in progress).
    Initializing,
    /// Communication is active and operational.
    Active,
    /// Communication initialization or runtime failed.
    Failed,
}

/// Errors that can occur during communication control operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CommControlError {
    /// Communication initialization failed.
    #[error("communication initialization failed: {0}")]
    InitFailed(String),

    /// Communication is already in the requested state.
    #[error("communication already in requested state")]
    AlreadyInState,
}

/// Controls when diagnostic communication gateway creation and ECU communication begins.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum CommunicationInitMode {
    /// Gateway is created immediately during startup.
    #[default]
    Enabled,
    /// Gateway creation is deferred until the first diagnostic HTTP request
    /// to a communicating endpoint, or an explicit trigger via the
    /// [`crate::InitializationPlugin`] API.
    Deferred,
}

/// Controls behavior of diagnostic communication after a runtime database update.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum PostUpdateCommunicationMode {
    /// After update, reconnect immediately.
    #[default]
    Enabled,
    /// After update, return to deferred state - communication stays down until triggered.
    Deferred,
    /// After update, maintain the state communication was in before the update started.
    ///
    /// If communication was deferred (not yet triggered), it remains deferred.
    /// If communication was active, it reconnects immediately.
    Last,
}

/// Communication initialization and lifecycle settings for diagnostic communication.
///
/// Controls when gateway creation begins, how communication behaves after
/// database updates, and retry behavior for deferred initialization.
#[derive(Deserialize, Serialize, Clone, Debug, schemars::JsonSchema)]
pub struct CommunicationSettings {
    /// Controls when gateway creation and ECU communication begins.
    ///
    /// Defaults to [`CommunicationInitMode::Enabled`], which preserves the
    /// existing startup behavior.
    pub init_mode: CommunicationInitMode,
    /// Controls communication behavior after a runtime database update.
    ///
    /// Defaults to [`PostUpdateCommunicationMode::Enabled`], which reconnects
    /// immediately after each update (existing behavior).
    pub post_update_mode: PostUpdateCommunicationMode,
    /// The value (in seconds) for the HTTP `Retry-After` header returned when a
    /// diagnostic request arrives while initialization is still pending.
    ///
    /// This gives the client a hint for how long to wait before retrying.
    /// Defaults to 30s, which allows time for variant detection to complete.
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

/// Trait for atomically installing a freshly-built gateway into a communication handle.
///
/// Decouples the reload plugin from the concrete `DoipDiagGateway` type: the plugin
/// works in terms of its own `Gateway` type parameter, and the `Into<DoipDiagGateway>`
/// conversion is absorbed by the implementation on [`DoipCommHandle`].
///
/// - `activate = true`  -> transitions to [`CommState::Active`] immediately.
/// - `activate = false` -> installs the gateway but stays [`CommState::Disabled`];
///   the `DeferredInitGuard` will call `enable()` on the next diagnostic request.
#[async_trait]
pub trait GatewayInstall<G>: Send + Sync + 'static {
    /// Installs `gateway` and optionally activates communication.
    async fn install_gateway(&self, gateway: G, activate: bool);
}

/// Trait for controlling the lifecycle of diagnostic communication.
///
/// Implementations manage the full connection lifecycle: starting the
/// communication sequence, tearing down connections, and providing a shared flag
/// that middleware can check on the fast path without awaiting.
#[async_trait]
pub trait CommunicationControl: Send + Sync + 'static {
    /// Start the diagnostic communication sequence.
    ///
    /// Transitions from `Disabled` -> `Initializing` -> `Active`.
    /// Returns an error if initialization fails or communication is already active.
    async fn enable(&self) -> Result<(), CommControlError>;

    /// Tear down all connections and disable communication.
    ///
    /// Transitions from `Active` or `Initializing` -> `Disabled`.
    /// Returns an error if already disabled.
    async fn disable(&self) -> Result<(), CommControlError>;

    /// Returns the current communication state.
    async fn state(&self) -> CommState;

    /// Returns a shared atomic flag indicating whether communication is active.
    ///
    /// This flag is intended for middleware fast-path checks to avoid
    /// awaiting or locking when determining if requests can be forwarded.
    /// The flag is `true` when state is `Active`, `false` otherwise.
    fn active(&self) -> Arc<AtomicBool>;
}
