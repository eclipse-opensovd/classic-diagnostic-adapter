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

//! Deferred ECU communication initialization plugin.
//!
//! Provides the guard infrastructure and re-exports the core plugin types from
//! [`cda_interfaces::deferred_init_api`] so that downstream crates can depend
//! solely on this crate without also depending on `cda-interfaces` directly.
//!
//! # Design
//!
//! The core [`InitializationPlugin`] trait and supporting types live in
//! [`cda_interfaces::deferred_init_api`] so that plugin authors can depend
//! solely on the lightweight interfaces crate. This crate provides:
//!
//! - [`DeferredInitGuard`] - the request guard that gates diagnostic endpoints
//! - Re-exports of all plugin API types for convenience
//! - Test utilities (behind `#[cfg(any(test, feature = "test-utils"))]`)
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use cda_plugin_deferred_init::{OnDemandInitPlugin, DeferredInitGuard};
//! use std::sync::Arc;
//!
//! let plugin = Arc::new(OnDemandInitPlugin::new());
//! // pass plugin and comm_control to DeferredInitGuard::new(...)
//! ```
//!
//! # Vendored Plugins
//!
//! Vendored plugins can depend directly on `cda-interfaces` and implement
//! [`InitializationPlugin`](cda_interfaces::deferred_init_api::InitializationPlugin)
//! without depending on this crate. See the `deferred_init_api` module
//! documentation for details.

pub mod guard;

// Re-export core types from cda-interfaces for convenience
pub use cda_interfaces::deferred_init_api::{
    BoxFuture, DeferredInitError, InitPluginBuilder, InitPluginFn, InitializationContext,
    InitializationPlugin, OnDemandInitPlugin, TriggerReason, init_plugin_fn,
};
pub use guard::DeferredInitGuard;

/// Shared test utilities for deferred initialization plugin tests.
///
/// This module provides mock implementations and test helpers for testing
/// custom deferred initialization plugins.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils {
    use std::sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    };

    use cda_interfaces::{
        communication_control::CommunicationControl,
        deferred_init_api::{
            BoxFuture, DeferredInitError, InitializationContext, InitializationPlugin,
            TriggerReason,
        },
    };

    /// A mock deferred initialization plugin for testing.
    ///
    /// Tracks method calls and allows controlling initialization behavior.
    #[derive(Debug)]
    pub struct MockInitPlugin {
        can_init: bool,
        on_ready_calls: Arc<AtomicU32>,
        can_initialize_calls: Arc<AtomicU32>,
        on_initialized_calls: Arc<AtomicU32>,
    }

    impl MockInitPlugin {
        /// Creates a new mock plugin.
        #[must_use]
        pub fn new(can_init: bool) -> Self {
            Self {
                can_init,
                on_ready_calls: Arc::new(AtomicU32::new(0)),
                can_initialize_calls: Arc::new(AtomicU32::new(0)),
                on_initialized_calls: Arc::new(AtomicU32::new(0)),
            }
        }

        /// Returns the number of times `on_ready` was called.
        #[must_use]
        pub fn on_ready_calls(&self) -> u32 {
            self.on_ready_calls.load(Ordering::SeqCst)
        }

        /// Returns the number of times `can_initialize` was called.
        #[must_use]
        pub fn can_initialize_calls(&self) -> u32 {
            self.can_initialize_calls.load(Ordering::SeqCst)
        }

        /// Returns the number of times `on_initialized` was called.
        #[must_use]
        pub fn on_initialized_calls(&self) -> u32 {
            self.on_initialized_calls.load(Ordering::SeqCst)
        }
    }

    impl InitializationPlugin for MockInitPlugin {
        fn on_ready(&self, _comm: Arc<dyn CommunicationControl>) -> BoxFuture<'_, ()> {
            self.on_ready_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {})
        }

        fn can_initialize(&self, _context: &InitializationContext) -> BoxFuture<'_, bool> {
            self.can_initialize_calls.fetch_add(1, Ordering::SeqCst);
            let allowed = self.can_init;
            Box::pin(async move { allowed })
        }

        fn on_initialized<'a>(
            &'a self,
            _result: &'a Result<(), DeferredInitError>,
        ) -> BoxFuture<'a, ()> {
            self.on_initialized_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {})
        }
    }

    /// Creates a test context for an on-demand trigger.
    #[must_use]
    pub fn on_demand_context() -> InitializationContext {
        InitializationContext::new(TriggerReason::OnDemand, 1)
    }

    /// Creates a test context for a plugin-requested trigger.
    #[must_use]
    pub fn plugin_requested_context() -> InitializationContext {
        InitializationContext::new(TriggerReason::PluginRequested, 1)
    }
}
