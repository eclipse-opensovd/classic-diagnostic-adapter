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

//! Builder pattern for deferred initialization plugins.
//!
//! Provides the [`InitPluginBuilder`] trait and helper types for constructing
//! deferred initialization plugins. Unlike the update plugin builder, this
//! builder does not require runtime context since vehicle components don't
//! exist yet in deferred mode.
//!
//! # Example
//!
//! ```rust,ignore
//! use cda_interfaces::deferred_init_api::{InitPluginBuilder, init_plugin_fn};
//!
//! // Using a closure
//! let builder = init_plugin_fn(|| async {
//!     Ok(MyPlugin::new())
//! });
//!
//! // Or implementing the trait directly
//! struct MyPluginBuilder;
//!
//! impl InitPluginBuilder for MyPluginBuilder {
//!     type Plugin = MyPlugin;
//!
//!     async fn build(self) -> Result<Self::Plugin, AppError> {
//!         Ok(MyPlugin::new())
//!     }
//! }
//! ```

use super::InitializationPlugin;

/// Builder for deferred initialization plugins.
///
/// # Example
///
/// ```rust,ignore
/// use cda_interfaces::deferred_init_api::InitPluginBuilder;
///
/// struct MyPluginBuilder {
///     config: MyConfig,
/// }
///
/// impl InitPluginBuilder for MyPluginBuilder {
///     type Plugin = MyPlugin;
///     type Error = MyError;
///
///     async fn build(self) -> Result<Self::Plugin, Self::Error> {
///         Ok(MyPlugin::from_config(self.config))
///     }
/// }
/// ```
pub trait InitPluginBuilder: Send {
    /// The concrete plugin type this builder produces.
    type Plugin: InitializationPlugin;

    /// The error type returned by the build operation.
    type Error;

    /// Build the plugin.
    ///
    /// This is called once at startup (or after re-deferral) to create the
    /// plugin instance. The plugin is then given a trigger handle via
    /// [`InitializationPlugin::on_ready`].
    ///
    /// # Errors
    ///
    /// Returns an error if the plugin cannot be constructed (e.g., invalid
    /// configuration, missing dependencies).
    fn build(self) -> impl Future<Output = Result<Self::Plugin, Self::Error>> + Send;
}

/// Wrapper that adapts an async closure into an [`InitPluginBuilder`].
///
/// Created via [`init_plugin_fn`].
pub struct InitPluginFn<F>(F);

impl<F> InitPluginFn<F> {
    /// Creates a new plugin builder from a closure.
    #[must_use]
    pub const fn new(f: F) -> Self {
        Self(f)
    }
}

/// Wrap an async closure as an [`InitPluginBuilder`].
///
/// # Example
///
/// ```rust,ignore
/// use cda_interfaces::deferred_init_api::init_plugin_fn;
///
/// Setup::new().with_init_plugin(init_plugin_fn(|| async {
///     Ok(MyPlugin::new())
/// }))
/// ```
pub fn init_plugin_fn<F, Fut, P, E>(f: F) -> InitPluginFn<F>
where
    F: FnOnce() -> Fut + Send,
    Fut: Future<Output = Result<P, E>> + Send,
    P: InitializationPlugin,
{
    InitPluginFn(f)
}

impl<F, Fut, P, E> InitPluginBuilder for InitPluginFn<F>
where
    F: FnOnce() -> Fut + Send,
    Fut: Future<Output = Result<P, E>> + Send,
    P: InitializationPlugin,
{
    type Plugin = P;
    type Error = E;

    async fn build(self) -> Result<P, E> {
        self.0().await
    }
}

/// No-op implementation for unit type.
///
/// This allows `Setup::new()` without an init plugin to work correctly,
/// defaulting to the standard [`OnDemandInitPlugin`](super::OnDemandInitPlugin).
impl InitPluginBuilder for () {
    type Plugin = super::OnDemandInitPlugin;
    type Error = std::convert::Infallible;

    async fn build(self) -> Result<Self::Plugin, Self::Error> {
        Ok(super::OnDemandInitPlugin::new())
    }
}
