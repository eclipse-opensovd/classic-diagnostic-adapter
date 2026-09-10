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
use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use cda_interfaces::{
    communication_control::{DisableError, PostUpdateCommunicationMode},
    lifecycle::LifecycleError,
    runtime_update_api::{
        AcceptedUpdate, ExclusiveRuntimePlugin, ExecutionFailure, ExecutionMode, RecoveryError,
        ReloadError, RuntimeFileInspector, RuntimeFilesUpdatePlugin, RuntimeUpdateError,
        UpdateDispatcher,
    },
    storage_api::Storage,
};
use cda_lifecycle::{
    CdaEvent, EcuDataReload, ReloadExecutionMode, UpdateHttpProtection, WeakLifecycleHandle,
};
use cda_plugin_runtime_update::{DefaultRuntimeUpdatePlugin, DefaultUpdatePolicy};
use cda_plugin_security::SecurityPluginLoader;
use cda_sovd::SovdLockStateView;

use crate::AppError;

/// Runs an execution as a staged lifecycle dispatch.
///
/// The mode is all the plugin knows; which stages it visits, which guards it
/// takes and what the transport looks like afterwards are decided here.
pub(crate) struct LifecycleUpdateDispatcher {
    /// Weak: the plugin holding this is itself owned by a component the manager
    /// dispatches over, so a strong handle here would keep the actor alive for
    /// as long as itself.
    lifecycle: WeakLifecycleHandle<CdaEvent>,
    protection: UpdateHttpProtection,
    post_update_mode: PostUpdateCommunicationMode,
}

impl LifecycleUpdateDispatcher {
    pub(crate) fn new(
        lifecycle: WeakLifecycleHandle<CdaEvent>,
        protection: UpdateHttpProtection,
        post_update_mode: PostUpdateCommunicationMode,
    ) -> Self {
        Self {
            lifecycle,
            protection,
            post_update_mode,
        }
    }

    fn event(&self, mode: ExecutionMode) -> CdaEvent {
        let reload = |mode| {
            CdaEvent::ReloadEcuData(EcuDataReload::new(
                mode,
                self.post_update_mode.clone(),
                self.protection.clone(),
            ))
        };
        match mode {
            ExecutionMode::Apply => reload(ReloadExecutionMode::Apply),
            ExecutionMode::Rollback => reload(ReloadExecutionMode::Rollback),
            // Touches no database, so it visits no reload stage, but it takes
            // the same guards and so still serializes against an execution.
            ExecutionMode::Cleanup => CdaEvent::CleanupFiles(self.protection.clone()),
        }
    }
}

#[async_trait]
impl UpdateDispatcher for LifecycleUpdateDispatcher {
    async fn dispatch(&self, mode: ExecutionMode) -> Result<AcceptedUpdate, RuntimeUpdateError> {
        let accepted = self
            .lifecycle
            .accept(self.event(mode))
            .await
            .map_err(refusal)?;
        Ok(AcceptedUpdate {
            completion: Box::pin(async move {
                match accepted.completion.await {
                    Ok(result) => result.map_err(execution_failure),
                    // The dispatch task ended without reporting, which only a
                    // panic does, so whether the swap completed is unknown.
                    Err(_) => Err(ExecutionFailure::AbnormalTermination),
                }
            }),
        })
    }
}

/// Why the runtime would not admit the dispatch, in the terms a client answers
/// on.
fn refusal(error: LifecycleError) -> RuntimeUpdateError {
    match error {
        LifecycleError::LeaseUnavailable(DisableError::Conflict) => {
            RuntimeUpdateError::ExecutionConflict
        }
        LifecycleError::LeaseUnavailable(DisableError::InUse) => {
            RuntimeUpdateError::OperationsInProgress(
                "another operation is running (i.e. flash transfer)".to_owned(),
            )
        }
        LifecycleError::LeaseUnavailable(DisableError::Failed(failure)) => {
            RuntimeUpdateError::CommunicationFailure(failure.to_string())
        }
        other => RuntimeUpdateError::UpdateStartError(other.to_string()),
    }
}

/// How the dispatch ended, in the terms the execution status uses.
fn execution_failure(error: LifecycleError) -> ExecutionFailure {
    match error {
        // Every stage that had run was reverted, so what is live is what was
        // live before the execution started.
        LifecycleError::Component { .. }
        | LifecycleError::GuardsUnavailable(_)
        | LifecycleError::LeaseUnavailable(_)
        | LifecycleError::Resource(_) => ExecutionFailure::RuntimeUnchanged(Arc::new(
            RuntimeUpdateError::ReplacementFailure(error.to_string()),
        )),
        // The previous databases could not be put back, so neither the
        // candidate nor the state before it can be trusted.
        LifecycleError::RevertFailed { component, source } => ExecutionFailure::RecoveryFailed {
            original: ReloadError::General(
                "A stage of the runtime update failed; see the log for which".to_owned(),
            ),
            recovery: RecoveryError::PersistentRestore(ReloadError::General(format!(
                "{component}: {source}"
            ))),
        },
        LifecycleError::LeaseUnsettled(failure) => {
            ExecutionFailure::CommunicationFinalizationFailed {
                preceding: None,
                failure,
            }
        }
    }
}

/// The capabilities an update plugin is granted, one field per capability.
///
/// Everything else the application owns stays with it: no aggregate writable
/// vehicle-data handle, no router, no communication lifecycle authority.
pub struct UpdatePluginResources<S> {
    /// The storage the plugin writes through, opened by the application at the
    /// stage that builds the plugin.
    pub storage: Arc<S>,
    /// Runs the runtime transition an execution asks for. The guards it takes,
    /// the stages it visits and the transport it leaves behind belong to the
    /// application's lifecycle, so an update plugin asks for the transition
    /// rather than assembling it.
    pub update_dispatcher: Arc<dyn UpdateDispatcher>,
    /// The injected inspector for the application's database format. The single
    /// instance: an OEM that supplies its own is never bypassed.
    pub file_inspector: Arc<dyn RuntimeFileInspector>,
    /// Read-only lock topology view; update plugins receive no publication authority.
    pub lock_provider: Arc<SovdLockStateView>,
}

/// Trait for async plugin builders that produce a [`RuntimeFilesUpdatePlugin`].
///
/// Implement this trait (or use a closure via [`update_plugin_fn`]) to provide a
/// custom update plugin to [`crate::Setup::with_update_plugin`].
pub trait UpdatePluginBuilder<S: Storage>: Send {
    /// The concrete plugin type this builder produces.
    type Plugin: RuntimeFilesUpdatePlugin;

    /// Build the plugin from the capabilities it is granted.
    fn build(
        self,
        resources: UpdatePluginResources<S>,
    ) -> impl Future<Output = Result<Self::Plugin, AppError>> + Send;
}

/// Wrapper that adapts an async closure into an [`UpdatePluginBuilder`].
///
/// Created via [`update_plugin_fn`].
pub struct UpdatePluginFn<F>(F);

/// Wrap an async closure as an [`UpdatePluginBuilder`].
///
/// # Example
/// ```rust,ignore
/// use opensovd_cda_lib::{Setup, update::update_plugin_fn};
///
/// let setup = Setup::new().with_update_plugin(update_plugin_fn(|resources| async move {
///     Ok(MyPlugin::new(resources))
/// }));
/// ```
pub fn update_plugin_fn<S, F, Fut, P>(f: F) -> UpdatePluginFn<F>
where
    S: Storage,
    F: FnOnce(UpdatePluginResources<S>) -> Fut + Send,
    Fut: Future<Output = Result<P, AppError>> + Send,
    P: RuntimeFilesUpdatePlugin,
{
    UpdatePluginFn(f)
}

impl<S, F, Fut, P> UpdatePluginBuilder<S> for UpdatePluginFn<F>
where
    S: Storage,
    F: FnOnce(UpdatePluginResources<S>) -> Fut + Send,
    Fut: Future<Output = Result<P, AppError>> + Send,
    P: RuntimeFilesUpdatePlugin,
{
    type Plugin = P;

    async fn build(self, resources: UpdatePluginResources<S>) -> Result<P, AppError> {
        self.0(resources).await
    }
}

/// Registers the runtime update routes on the dynamic router using the provided plugin.
///
/// The plugin arrives already wrapped in [`ExclusiveRuntimePlugin`] for
/// read/write mutual exclusion, because the `DatabaseFiles` stage runs the file
/// transaction of that same instance. Mounts the HTTP endpoints by delegating to
/// [`cda_sovd::add_runtime_update_routes`].
pub async fn add_runtime_update_routes<S, P>(
    dynamic_router: &cda_sovd::dynamic_router::DynamicRouter,
    plugin: Arc<ExclusiveRuntimePlugin<P>>,
    lock_provider: Arc<SovdLockStateView>,
    upload_body_limit_bytes: usize,
    update_retry_after: Duration,
) where
    S: SecurityPluginLoader,
    P: RuntimeFilesUpdatePlugin,
{
    cda_sovd::add_runtime_update_routes::<S, _, SovdLockStateView>(
        dynamic_router,
        plugin,
        lock_provider,
        upload_body_limit_bytes,
        update_retry_after,
    )
    .await;
}

/// Creates the default runtime update plugin using the standard CDA components.
///
/// This helper function eliminates code duplication between `run()` and `run_with_config()`.
/// It builds a fully configured `DefaultRuntimeUpdatePlugin` with all the standard
/// CDA infrastructure components.
///
/// # Arguments
/// - `resources`: The capabilities the application grants an update plugin
///
/// # Errors
/// Returns [`AppError::RuntimeUpdateError`] if plugin initialization fails.
pub async fn create_default_update_plugin<S>(
    resources: UpdatePluginResources<S>,
) -> Result<impl RuntimeFilesUpdatePlugin, AppError>
where
    S: Storage + 'static,
{
    // The application supplies the database format; the plugin stays agnostic.
    let file_inspector = resources.file_inspector;

    Ok(DefaultRuntimeUpdatePlugin::new(
        resources.storage,
        resources.update_dispatcher,
        Arc::new(DefaultUpdatePolicy::new(Arc::clone(&file_inspector))),
        resources.lock_provider,
        file_inspector,
    ))
}
