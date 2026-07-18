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

//! Default deferred initialization plugin implementation.
//!
//! Provides [`DefaultDeferredInitPlugin`], a more configurable version of
//! [`OnDemandInitPlugin`] that supports timeouts, retries, and custom
//! initialization triggers.

use std::sync::Arc;

use cda_interfaces::{
    communication_control::CommunicationControl,
    deferred_init_api::{
        BoxFuture, DeferredInitError, InitializationContext, InitializationPlugin, OnDemandInitPlugin,
        TriggerReason,
    },
};
use tracing;

use crate::config::DeferredInitConfig;

/// Default implementation of the deferred initialization plugin.
///
/// This plugin provides configurable initialization behavior with support for:
///
/// - On-demand initialization (triggered by HTTP requests)
/// - Automatic initialization on startup (optional)
/// - Timeout handling
/// - Retry logic with configurable intervals
/// - Custom initialization predicates
///
/// # Example
///
/// ```rust,ignore
/// use cda_plugin_deferred_init::{
///     DefaultDeferredInitPlugin,
///     config::OnDemandInitConfig,
/// };
///
/// let config = OnDemandInitConfig {
///     timeout_secs: 120,
///     max_retries: 5,
///     auto_init: true,
///     ..Default::default()
/// };
///
/// let plugin = DefaultDeferredInitPlugin::with_config(config);
/// ```
#[derive(Debug)]
pub struct DefaultDeferredInitPlugin<C: DeferredInitConfig> {
    config: C,
    inner: OnDemandInitPlugin,
}

impl<C: DeferredInitConfig> DefaultDeferredInitPlugin<C> {
    /// Creates a new plugin with the given configuration.
    #[must_use]
    pub fn with_config(config: C) -> Self {
        Self {
            config,
            inner: OnDemandInitPlugin::new(),
        }
    }

    /// Returns a reference to the configuration.
    #[must_use]
    pub fn config(&self) -> &C {
        &self.config
    }

    /// Returns the timeout duration in seconds.
    #[must_use]
    pub fn timeout_secs(&self) -> u64 {
        self.config.timeout_secs()
    }

    /// Returns the maximum number of retry attempts.
    #[must_use]
    pub fn max_retries(&self) -> u32 {
        self.config.max_retries()
    }
}

impl<C: DeferredInitConfig> InitializationPlugin for DefaultDeferredInitPlugin<C> {
    fn on_ready(&self, comm: Arc<dyn CommunicationControl>) -> BoxFuture<'_, ()> {
        if self.config.auto_init() {
            let timeout = std::time::Duration::from_secs(self.config.timeout_secs());
            Box::pin(async move {
                tracing::info!("Auto-init enabled, triggering initialization");
                match tokio::time::timeout(timeout, comm.enable()).await {
                    Ok(Ok(())) => {
                        tracing::info!("Auto-init completed successfully");
                    }
                    Ok(Err(e)) => {
                        tracing::error!("Auto-init failed: {}", e);
                    }
                    Err(_) => {
                        tracing::error!("Auto-init timed out after {:?}", timeout);
                    }
                }
            })
        } else {
            // Use default behavior (do nothing)
            self.inner.on_ready(comm)
        }
    }

    fn on_trigger_requested(&self, context: &InitializationContext) -> BoxFuture<'_, bool> {
        tracing::debug!(
            "Trigger requested: reason={}, attempt={}",
            context.reason,
            context.attempt_count
        );

        // Check if we've exceeded max retries
        let max_retries = self.config.max_retries();
        if max_retries > 0 && context.attempt_count > max_retries {
            tracing::warn!("Max retries ({}) exceeded, rejecting trigger", max_retries);
            return Box::pin(async { false });
        }

        Box::pin(async { true })
    }

    fn should_initialize(&self, context: &InitializationContext) -> BoxFuture<'_, bool> {
        tracing::debug!(
            "Checking should_initialize: reason={}, attempt={}",
            context.reason,
            context.attempt_count
        );

        // For OnDemand triggers, always allow (this is the default behavior)
        // For other triggers, use the inner plugin's logic
        match context.reason {
            TriggerReason::OnDemand => Box::pin(async { true }),
            _ => self.inner.should_initialize(context),
        }
    }

    fn on_initialization_started(&self, context: &InitializationContext) -> BoxFuture<'_, ()> {
        tracing::info!(
            "Initialization started: reason={}, attempt={}",
            context.reason,
            context.attempt_count
        );
        Box::pin(async {})
    }

    fn on_initialized<'a>(&'a self, result: &'a Result<(), DeferredInitError>) -> BoxFuture<'a, ()> {
        match result {
            Ok(()) => {
                tracing::info!("Initialization completed successfully");
            }
            Err(e) => {
                tracing::error!("Initialization failed: {}", e);
            }
        }
        Box::pin(async {})
    }

    fn on_initialization_timeout(&self) -> BoxFuture<'_, ()> {
        let timeout = self.config.timeout_secs();
        tracing::error!("Initialization timed out after {} seconds", timeout);
        Box::pin(async {})
    }

    /// The default plugin always allows re-deferral after a runtime update.
    ///
    /// Custom plugins may override this to prevent re-deferral after persistent
    /// failures, e.g., returning `false` if `result.is_err()` and the error is
    /// not recoverable.
    #[allow(unused_variables, reason = "default implementation ignores result")]
    fn can_defer_again(&self, result: &Result<(), DeferredInitError>) -> BoxFuture<'_, bool> {
        // The default plugin always returns true. This is intentional: the
        // default "on-demand" behavior defers to runtime update plugin's
        // decision for post-update behavior. The runtime update plugin
        // controls whether to disable or keep communication enabled
        // via its `post_update_communication` configuration.
        Box::pin(async { true })
    }
}

impl DefaultDeferredInitPlugin<crate::config::OnDemandInitConfig> {
    /// Creates a new plugin with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(crate::config::OnDemandInitConfig::default())
    }
}

impl Default for DefaultDeferredInitPlugin<crate::config::OnDemandInitConfig> {
    fn default() -> Self {
        Self::new()
    }
}
