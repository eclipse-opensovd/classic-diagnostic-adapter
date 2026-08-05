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

//! Generic communication plugin contract.

pub mod default;

use std::{future::Future, sync::Arc};

use async_trait::async_trait;
use cda_interfaces::communication_control::{CommunicationInitMode, CommunicationInitializer};

// Re-export CommunicationHandle for plugin builders
pub use crate::lifecycle::controller::CommunicationHandle;
use crate::lifecycle::{
    disable::{DisableError, DisableLease, DisableReason},
    error::CommunicationError,
    guard::CommunicationGuard,
    operation::{ActivationCause, CommunicationOperationFailure, DetectionCause},
    state::CommunicationState,
};

/// A replaceable communication plugin wired into the CDA runtime.
///
/// The default implementation is
/// [`DefaultCommunicationPlugin`](default::DefaultCommunicationPlugin), which
/// applies `init_mode` policy per ADR-006's required mode semantics. The
/// framework itself never inspects `init_mode` to initiate communication
/// except for the `Always`-mode startup call; every other decision is the
/// plugin's alone. Diagnostic operations request activation directly via
/// [`CommunicationAccess::request_activate`](crate::lifecycle::access::CommunicationAccess::request_activate)
/// at the point they need communication, rather than the framework routing an
/// event to the plugin on their behalf.
///
/// Every implementation must also implement [`cda_interfaces::Shutdown`]. The
/// framework calls it once, at the existing communication cleanup point, before
/// any other runtime task cleanup; implementations decide what "shut down"
/// means (the default plugin disables the transport and leaves HTTP
/// protection installed).
#[async_trait]
pub trait CommunicationPlugin: cda_interfaces::Shutdown {
    /// Returns the authoritative lifecycle state.
    fn state(&self) -> CommunicationState;

    /// Acquires diagnostic communication while it is enabled.
    /// The returned [`CommunicationGuard`] ensures that communication remains
    /// enabled for the duration of its lifetime.
    ///
    /// # Errors
    ///
    /// Returns an error when communication is not enabled.
    fn acquire(&self) -> Result<CommunicationGuard, CommunicationError>;

    /// Activates communication or attempts recovery from an error.
    ///
    /// Returns `Ok(CommunicationState::Enabled)` on success (including when
    /// communication was already enabled)
    ///
    /// # Errors
    /// `Err` when the transport or an
    /// initializer fails, or `init_mode` does not authorize this cause.
    async fn activate(
        &self,
        cause: ActivationCause,
    ) -> Result<CommunicationState, CommunicationOperationFailure>;

    /// Non-blocking activation request: claims the transition (or joins an
    /// in-flight one) and returns immediately, driving the actual work in the
    /// background. Honors `init_mode` exactly as [`activate`](Self::activate)
    /// does, but never awaits the result, so a caller that cannot afford to
    /// block through a full activation sequence (which can take seconds due
    /// to variant detection) can trigger it and immediately report "not
    /// ready" to its own caller instead.
    ///
    /// Returns the current state: `Enabled` when nothing needed to be done,
    /// `Enabling` once a (new or joined) activation has been submitted, or
    /// the pre-existing state unchanged when `init_mode` does not authorize
    /// this cause.
    fn request_activate(&self, cause: ActivationCause) -> CommunicationState;

    /// Requests whole-vehicle (re-)detection.
    ///
    /// Authorized in every `init_mode`, including `Disabled`, where it is the
    /// *only* operation that may initialize communication. Implementations
    /// must not gate this call behind `init_mode` the way [`activate`](Self::activate) is gated.
    ///
    /// # Errors
    ///
    /// Returns an error when the transport or an initializer fails.
    async fn trigger_detection(
        &self,
        cause: DetectionCause,
    ) -> Result<CommunicationState, CommunicationOperationFailure>;

    /// Acquires exclusive disable ownership, which makes sure the communication cannot
    /// be re-enabled as long as the [`DisableLease`] is held.
    ///
    /// # Errors
    ///
    /// Returns an error when communication is in use, a disable lease is
    /// already held, or disabling the transport fails.
    async fn disable(&self, reason: DisableReason) -> Result<DisableLease, DisableError>;

    /// Registers framework-enforced post-activation work.
    async fn register_initializer(&self, initializer: Arc<dyn CommunicationInitializer>);
}

/// Factory for a communication plugin that needs the authoritative handle.
pub trait CommunicationPluginBuilder: Send {
    /// Plugin produced by this factory.
    type Plugin: CommunicationPlugin;
    /// Construction error.
    type Error: std::fmt::Display + Send;

    /// Builds the plugin after the passive transport and communication handle exist.
    fn build(
        self,
        handle: CommunicationHandle,
        mode: CommunicationInitMode,
    ) -> impl Future<Output = Result<Self::Plugin, Self::Error>> + Send;
}

/// Closure adapter for [`CommunicationPluginBuilder`].
pub struct CommunicationPluginFn<F>(F);

/// Wraps an async closure as a [`CommunicationPluginBuilder`].
pub fn communication_plugin_fn<F>(factory: F) -> CommunicationPluginFn<F> {
    CommunicationPluginFn(factory)
}

impl<F, Fut, P, E> CommunicationPluginBuilder for CommunicationPluginFn<F>
where
    F: FnOnce(CommunicationHandle, CommunicationInitMode) -> Fut + Send,
    Fut: Future<Output = Result<P, E>> + Send,
    P: CommunicationPlugin,
    E: std::fmt::Display + Send,
{
    type Plugin = P;
    type Error = E;

    async fn build(self, handle: CommunicationHandle, mode: CommunicationInitMode) -> Result<P, E> {
        self.0(handle, mode).await
    }
}
