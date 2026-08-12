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
use std::sync::Arc;

use cda_comm_can::MultiTransportGateway;
use cda_comm_doip::DoipDiagGateway;
use cda_core::EcuManager;
use cda_interfaces::runtime_update_api::RuntimeFilesUpdatePlugin;
use cda_plugin_runtime_update::{
    DefaultRuntimeUpdatePlugin, DefaultUpdateSecurityHandler,
    default_runtime_reloader_plugin::{
        DefaultReloadContext as ReloaderContext, DefaultRuntimeReloaderPlugin,
    },
};
use cda_plugin_security::{SecurityPlugin, SecurityPluginLoader};
use cda_sovd::{SovdLockStateProvider, UpdateGuardState};
use cda_storage::LocalStorage;
use tokio::sync::Mutex;

use crate::{
    AppError, UdsManagerType, cda_factory::CdaMainVehicleFactory,
    config::configfile::Configuration, setup::CdaRuntime,
};

/// Trait for async plugin builders that produce a [`RuntimeFilesUpdatePlugin`].
///
/// Implement this trait (or use a closure via [`update_plugin_fn`]) to provide a
/// custom update plugin to [`crate::Setup::with_update_plugin`].
pub trait UpdatePluginBuilder<SP: SecurityPlugin>: Send {
    /// The concrete plugin type this builder produces.
    type Plugin: RuntimeFilesUpdatePlugin;

    /// Build the plugin from the given runtime context.
    fn build(
        self,
        infra: CdaRuntime<SP>,
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
/// let setup = Setup::new().with_update_plugin(update_plugin_fn(|infra| async move {
///     Ok(MyPlugin::new(infra))
/// }));
/// ```
pub fn update_plugin_fn<SP, F, Fut, P>(f: F) -> UpdatePluginFn<F>
where
    SP: SecurityPlugin,
    F: FnOnce(CdaRuntime<SP>) -> Fut + Send,
    Fut: Future<Output = Result<P, AppError>> + Send,
    P: RuntimeFilesUpdatePlugin,
{
    UpdatePluginFn(f)
}

impl<SP, F, Fut, P> UpdatePluginBuilder<SP> for UpdatePluginFn<F>
where
    SP: SecurityPlugin,
    F: FnOnce(CdaRuntime<SP>) -> Fut + Send,
    Fut: Future<Output = Result<P, AppError>> + Send,
    P: RuntimeFilesUpdatePlugin,
{
    type Plugin = P;

    async fn build(self, infra: CdaRuntime<SP>) -> Result<P, AppError> {
        self.0(infra).await
    }
}

/// Registers the runtime update routes on the dynamic router using the provided plugin.
///
/// Wraps the plugin in
/// [`ExclusiveRuntimePlugin`](cda_interfaces::runtime_update_api::ExclusiveRuntimePlugin) for
/// read/write mutual exclusion and
/// mounts the HTTP endpoints by delegating to [`cda_sovd::add_runtime_update_routes`].
/// The caller is responsible for constructing the plugin before calling this function.
pub async fn add_runtime_update_routes<S, P>(
    dynamic_router: &cda_sovd::dynamic_router::DynamicRouter,
    plugin: P,
    lock_provider: Arc<SovdLockStateProvider>,
    update_guard: &UpdateGuardState,
    upload_body_limit_bytes: usize,
    retry_after_seconds: u64,
) where
    S: SecurityPluginLoader,
    P: RuntimeFilesUpdatePlugin,
{
    let service = Arc::new(plugin.with_exclusive_access());
    cda_sovd::add_runtime_update_routes::<S, _, SovdLockStateProvider>(
        dynamic_router,
        service,
        lock_provider,
        update_guard,
        upload_body_limit_bytes,
        retry_after_seconds,
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
/// - `infra`: The runtime infrastructure containing all CDA components
///
/// # Errors
/// Returns [`AppError::RuntimeUpdateError`] if plugin initialization fails.
pub(crate) async fn create_default_update_plugin<SP, SL>(
    infra: CdaRuntime<SP>,
) -> Result<impl RuntimeFilesUpdatePlugin, AppError>
where
    SP: SecurityPlugin,
    SL: SecurityPluginLoader,
{
    let health_for_factory = infra.health.clone();
    let shutdown_signal = infra.shutdown_signal.clone();
    let factory = Arc::new(CdaMainVehicleFactory::<SP>::new(
        shutdown_signal,
        health_for_factory,
    ));

    let storage = Arc::new(LocalStorage::new(&infra.storage_dir).map_err(|e| {
        AppError::InitializationFailed(format!("Failed to init storage, error={e:?}"))
    })?);

    let reloader_infra = ReloaderContext {
        config: infra.config,
        dynamic_router: infra.dynamic_router,
        vehicle_route_handle: infra.vehicle_route_handle,
        flash_files_path: infra.flash_files_path,
        components_config: infra.components_config,
        lock_provider: Arc::clone(&infra.lock_provider),
        shutdown_signal: infra.shutdown_signal,
        uds_manager: infra.uds_manager,
        diagnostic_gateway: infra.gateway,
        update_guard: infra.update_guard,
        ecu_execution_registry: infra.ecu_execution_registry.clone(),
        health: infra.health,
        variant_detection_handle: Mutex::new(infra.variant_detection_handle.lock().await.take()),
        storage_dir: infra.storage_dir.clone(),
        mdd_decompress: infra.mdd_decompress,
        storage: Arc::clone(&storage),
    };

    let reloader_config =
        cda_plugin_runtime_update::RuntimeReloaderConfig::new(reloader_infra, factory);

    let reloader_plugin = Arc::new(DefaultRuntimeReloaderPlugin::<
        UdsManagerType<SP>,
        MultiTransportGateway<DoipDiagGateway<EcuManager<SP>>>,
        Configuration,
        SL,
        _,
        LocalStorage,
    >::new(reloader_config));

    Ok(DefaultRuntimeUpdatePlugin::new(
        storage,
        reloader_plugin,
        Arc::new(DefaultUpdateSecurityHandler::new(
            Arc::clone(&infra.lock_provider),
            vec![
                Box::new(infra.flash_transfer_guard),
                Box::new(infra.ecu_execution_registry.clone()),
            ],
        )),
        Arc::clone(&infra.lock_provider),
        infra.mdd_decompress,
        Arc::clone(&infra.update_in_progress),
    ))
}
