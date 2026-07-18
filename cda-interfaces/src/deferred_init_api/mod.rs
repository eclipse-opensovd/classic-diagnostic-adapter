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

//! Deferred Initialization Plugin API
//!
//! Provides the interface definitions for deferred ECU communication initialization,
//! enabling plugins to control when and how diagnostic communication is established.
//!
//! # Architecture Overview
//!
//! The deferred initialization system allows ECU communication to be established
//! on-demand rather than at startup. This is useful for scenarios where:
//!
//! - Network configuration is not available at startup
//! - Security credentials must be obtained before communication
//! - Resource constraints require delaying initialization
//! - Initialization should be triggered by external events
//!
//! # Core Components
//!
//! - [`InitializationPlugin`]: The main trait that plugins implement to control
//!   initialization timing and behavior.
//!
//! - [`CommunicationControl`](crate::communication_control::CommunicationControl):
//!   Handle given to plugins for proactively triggering initialization and querying
//!   status via `enable()`, `disable()`, and `state()`.
//!
//! - [`InitializationContext`]: Context passed to [`InitializationPlugin::can_initialize`]
//!   containing information about the current initialization attempt.
//!
//! - [`TriggerReason`]: Enum representing why initialization was triggered.
//!
//! # Example: Custom Initialization Plugin
//!
//! ```rust,ignore
//! use cda_interfaces::deferred_init_api::{
//!     InitializationPlugin, InitializationContext,
//!     TriggerReason, BoxFuture,
//! };
//! use cda_interfaces::communication_control::CommunicationControl;
//! use cda_interfaces::deferred_init_api::DeferredInitError;
//! use std::sync::Arc;
//!
//! struct SecurityAwareInitPlugin;
//!
//! impl InitializationPlugin for SecurityAwareInitPlugin {
//!     fn on_ready(&self, comm: Arc<dyn CommunicationControl>) -> BoxFuture<'_, ()> {
//!         Box::pin(async move {
//!             // Wait for security unlock before triggering
//!             wait_for_security_unlock().await;
//!             let _ = comm.enable().await;
//!         })
//!     }
//!
//!     fn can_initialize(&self, context: &InitializationContext) -> BoxFuture<'_, bool> {
//!         Box::pin(async move {
//!             // Only allow plugin-requested initialization, block on-demand
//!             matches!(context.reason, TriggerReason::PluginRequested)
//!         })
//!     }
//!
//!     fn on_initialized<'a>(&'a self, result: &'a Result<(), DeferredInitError>) -> BoxFuture<'a, ()> {
//!         Box::pin(async move {
//!             if result.is_ok() {
//!                 tracing::info!("ECU communication established");
//!             } else {
//!                 tracing::error!("Failed to establish ECU communication: {:?}", result);
//!             }
//!         })
//!     }
//! }
//! ```
//!
//! # Error Handling
//!
//! The API uses structured error types defined in [`error`]:
//!
//! - [`DeferredInitError`]: Structured errors for initialization failures

pub mod builder;
pub mod error;

use std::sync::Arc;

pub use builder::{InitPluginBuilder, InitPluginFn, init_plugin_fn};
pub use error::DeferredInitError;

use crate::communication_control::CommunicationControl;

/// A type-erased, heap-allocated future for use in trait objects.
///
/// Used by [`InitializationPlugin`] methods that must remain object-safe.
/// `Pin<Box<dyn Future>>` provides a concrete, sized return type enabling
/// dynamic dispatch - the same pattern used by Tower's `Service` trait.
pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The reason why deferred initialization was triggered.
///
/// This enum provides structured information about what caused an
/// initialization attempt, allowing plugins to make informed decisions
/// about whether to proceed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, strum::Display)]
#[non_exhaustive]
pub enum TriggerReason {
    /// Triggered by an incoming HTTP diagnostic request.
    ///
    /// This is the default on-demand path - when a request arrives for an
    /// ECU communication endpoint and initialization is still pending,
    /// the system asks the plugin whether to start initialization.
    OnDemand,

    /// The plugin proactively requested initialization.
    ///
    /// This occurs when the plugin calls [`CommunicationControl::enable`]
    /// from its [`InitializationPlugin::on_ready`] callback or from
    /// external event handlers.
    PluginRequested,
}

/// Context information passed to [`InitializationPlugin::can_initialize`].
///
/// This struct provides plugins with information about the current
/// initialization attempt, allowing them to make informed decisions.
#[derive(Debug, Clone)]
pub struct InitializationContext {
    /// The reason why initialization was triggered.
    pub reason: TriggerReason,

    /// The number of initialization attempts made so far (including this one).
    pub attempt_count: u32,
}

impl InitializationContext {
    /// Creates a new initialization context.
    #[must_use]
    pub const fn new(reason: TriggerReason, attempt_count: u32) -> Self {
        Self {
            reason,
            attempt_count,
        }
    }
}

/// Plugin contract for controlling deferred ECU communication initialization.
///
/// The plugin's primary purpose is to **decide** when initialization should
/// begin, based on application-specific conditions (e.g., security unlock,
/// session establishment, or explicit user action). A plugin may:
///
/// - Allow on-demand initialization by returning `true` from
///   [`can_initialize`](Self::can_initialize).
/// - Block initialization by returning `false` until preconditions are met.
/// - Trigger initialization proactively via [`CommunicationControl::enable`]
///   on the handle passed to [`on_ready`](Self::on_ready).
///
/// # Lifecycle
///
/// 1. [`on_ready`](Self::on_ready) is called once the deferred initialization
///    pipeline is armed and ready to accept triggers (at startup, and again
///    after every post-update re-deferral).
/// 2. [`can_initialize`](Self::can_initialize) is consulted on each
///    diagnostic HTTP request that arrives while initialization is still pending.
///    If it returns `true`, initialization begins asynchronously and the request
///    receives HTTP 503 with a `Retry-After` header.
/// 3. [`on_initialized`](Self::on_initialized) is called once after each
///    initialization cycle completes (success or failure).
///
/// # Example
///
/// ```rust,ignore
/// use cda_interfaces::deferred_init_api::{
///     InitializationPlugin, InitializationContext,
///     TriggerReason, BoxFuture, DeferredInitError,
/// };
/// use cda_interfaces::communication_control::CommunicationControl;
/// use std::sync::Arc;
///
/// struct MyPlugin;
///
/// impl InitializationPlugin for MyPlugin {
///     fn on_ready(&self, comm: Arc<dyn CommunicationControl>) -> BoxFuture<'_, ()> {
///         Box::pin(async move {
///             // Plugin can trigger initialization proactively
///             let _ = comm.enable().await;
///         })
///     }
///
///     fn can_initialize(&self, context: &InitializationContext) -> BoxFuture<'_, bool> {
///         Box::pin(async move {
///             // Decide whether to allow initialization
///             true
///         })
///     }
///
///     fn on_initialized<'a>(&'a self, result: &'a Result<(), DeferredInitError>) -> BoxFuture<'a, ()> {
///         Box::pin(async move {
///             // Handle completion
///         })
///     }
/// }
/// ```
pub trait InitializationPlugin: Send + Sync + 'static {
    /// Called once the deferred initialization pipeline is armed.
    ///
    /// The plugin receives a `CommunicationControl` handle that it can store
    /// for proactive initialization (e.g., after a security unlock). Called at
    /// startup, and again after every post-update re-deferral.
    fn on_ready(&self, comm: Arc<dyn CommunicationControl>) -> BoxFuture<'_, ()>;

    /// Consulted when a diagnostic request arrives while initialization is pending.
    ///
    /// Return `true` to permit initialization to begin asynchronously.
    /// Return `false` to keep initialization deferred (request receives HTTP 503).
    fn can_initialize(&self, context: &InitializationContext) -> BoxFuture<'_, bool>;

    /// Called once after each initialization cycle completes (success or failure).
    fn on_initialized<'a>(&'a self, result: &'a Result<(), DeferredInitError>)
    -> BoxFuture<'a, ()>;
}

/// Default implementation: always triggers initialization on the first
/// diagnostic request (on-demand mode).
#[derive(Debug, Clone, Copy, Default)]
pub struct OnDemandInitPlugin;

impl OnDemandInitPlugin {
    /// Creates a new on-demand initialization plugin.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl InitializationPlugin for OnDemandInitPlugin {
    fn on_ready(&self, _comm: Arc<dyn CommunicationControl>) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }

    fn can_initialize(&self, _context: &InitializationContext) -> BoxFuture<'_, bool> {
        Box::pin(async { true })
    }

    fn on_initialized<'a>(
        &'a self,
        _result: &'a Result<(), DeferredInitError>,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn on_demand_plugin_always_triggers_initialization() {
        let plugin = OnDemandInitPlugin;
        let context = InitializationContext::new(TriggerReason::OnDemand, 1);
        let result = plugin.can_initialize(&context).await;
        assert!(result, "OnDemandInitPlugin must always return true");
    }
}
