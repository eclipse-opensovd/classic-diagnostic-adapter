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
use std::{path::PathBuf, sync::Arc};

use async_trait::async_trait;
use cda_comm_doip::{DoipDiagGateway, comm_handle::DoipCommHandle};
use cda_core::EcuManager;
use cda_interfaces::{
    CommunicationControl, ShutdownSignal,
    runtime_update_api::{
        ReloadError, RuntimeFilesUpdatePlugin, VehicleComponentFactory, VehicleComponents,
    },
};
use cda_plugin_runtime_update::{
    DefaultRuntimeUpdatePlugin, DefaultUpdateSecurityHandler,
    default_runtime_reloader_plugin::DefaultRuntimeReloaderPlugin,
};
use cda_plugin_security::{
    DefaultSecurityPlugin, DefaultSecurityPluginData, SecurityPlugin, SecurityPluginLoader,
};
use cda_sovd::SovdLockStateProvider;
use tokio::sync::Mutex;

use crate::{
    AppError, UdsManagerType, UpdateGuard,
    config::configfile::{Configuration, ConfigurationValidator},
    setup::CdaRuntime,
};

/// Setup configuration for CDA runtime initialization.
///
/// Trait for async plugin builders that produce a [`RuntimeFilesUpdatePlugin`].
///
/// Implement this trait (or use a closure via [`update_plugin_fn`]) to provide a
/// custom update plugin to [`Setup::with_update_plugin`].
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
/// Setup::new().with_update_plugin(update_plugin_fn(|infra| async move {
///     Ok(MyPlugin::new(infra))
/// }))
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

/// Concrete [`VehicleComponentFactory`] that delegates to
/// [`crate::create_vehicle_components`].
///
/// Stored on [`cda_plugin_runtime_update::asd::DefaultRuntimeFileReloadHandler`]
/// and called every time the diagnostic databases are reloaded.
pub struct CdaMainVehicleFactory<SP>
where
    SP: SecurityPlugin,
{
    #[expect(
        dead_code,
        reason = "shutdown_signal is stored for potential future use"
    )]
    shutdown_signal: ShutdownSignal,
    _phantom: std::marker::PhantomData<SP>,
}

impl<SP> CdaMainVehicleFactory<SP>
where
    SP: SecurityPlugin,
{
    #[must_use]
    pub fn new(shutdown_signal: ShutdownSignal) -> Self {
        Self {
            shutdown_signal,
            _phantom: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<SP> VehicleComponentFactory<Configuration, UdsManagerType<SP>, DoipDiagGateway<EcuManager<SP>>>
    for CdaMainVehicleFactory<SP>
where
    SP: SecurityPlugin,
{
    type FileManager = cda_database::FileManager;

    async fn create(
        &self,
        config: &Configuration,
        mdd_paths: &[PathBuf],
        update_in_progress: Arc<std::sync::atomic::AtomicBool>,
        existing_udp_socket: Arc<Mutex<cda_comm_doip::socket::DoIPUdpSocket>>,
    ) -> Result<
        VehicleComponents<UdsManagerType<SP>, DoipDiagGateway<EcuManager<SP>>, Self::FileManager>,
        ReloadError,
    > {
        // Build the vehicle stack, reusing the existing UDP socket so the DoIP port
        // is never double-bound between the old and new actors.
        // Wrap the incoming Arc<AtomicBool> in an UpdateGuard so it threads through
        // build_vehicle_stack while keeping the original flag connected.
        let guard = UpdateGuard::from_arc(Arc::clone(&update_in_progress));
        let stack = crate::build_vehicle_stack::<SP>(
            config,
            mdd_paths,
            None,
            guard,
            Some(existing_udp_socket),
        )
        .await
        .map_err(|e| ReloadError(format!("Failed to create vehicle components: {e}")))?;

        // Enable communication on the new temporary actor (start the DoIP sequence
        // so the new gateway is fully connected before we extract it).
        stack
            .comm_handle
            .enable()
            .await
            .map_err(|e| ReloadError(format!("Failed to enable DoIP communication: {e}")))?;

        // Extract the gateway from the slot for the VehicleComponents.
        // After enable() this slot is guaranteed to be Some.
        let deferred_gateway = stack.comm_handle.deferred_gateway();
        let diagnostic_gateway = {
            let slot_guard = deferred_gateway.slot().read().await;
            slot_guard
                .as_ref()
                .ok_or_else(|| ReloadError("Gateway should be active after enable".to_string()))?
                .clone()
        };

        Ok(VehicleComponents {
            uds_manager: stack.uds_manager,
            diagnostic_gateway,
            file_managers: stack.file_managers,
            variant_detection_handle: stack.variant_detection_handle,
            functional_group_config: config.functional_description.clone(),
        })
    }
}

/// Registers the runtime update routes on the dynamic router using the provided plugin.
///
/// Wraps the plugin in [`ExclusiveRuntimePlugin`] for read/write mutual exclusion and
/// mounts the HTTP endpoints by delegating to [`cda_sovd::add_runtime_update_routes`].
/// The caller is responsible for constructing the plugin before calling this function.
pub async fn add_runtime_update_routes<S, P>(
    dynamic_router: &cda_sovd::dynamic_router::DynamicRouter,
    plugin: P,
    lock_provider: Arc<SovdLockStateProvider>,
    update_guard: &UpdateGuard,
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
pub(crate) async fn create_default_update_plugin(
    infra: CdaRuntime<DefaultSecurityPluginData>,
) -> Result<impl RuntimeFilesUpdatePlugin, AppError> {
    let shutdown_signal = infra.shutdown_signal.clone();
    let factory = Arc::new(CdaMainVehicleFactory::<DefaultSecurityPluginData>::new(
        shutdown_signal,
    ));

    let post_update_mode = infra.post_update_mode.clone();
    let init_plugin = infra.init_plugin.clone();

    let reloader_infra = cda_plugin_runtime_update::DefaultReloadContext {
        config: infra.config,
        dynamic_router: infra.dynamic_router,
        vehicle_route_handle: infra.vehicle_route_handle,
        flash_files_path: infra.flash_files_path,
        components_config: infra.components_config,
        lock_provider: Arc::clone(&infra.lock_provider),
        shutdown_signal: infra.shutdown_signal,
        uds_manager: infra.uds_manager,
        comm_handle: infra.comm_handle,
        update_guard: infra.update_guard,
        ecu_execution_registry: infra.ecu_execution_registry.clone(),
        health: infra.health,
        variant_detection_handle: Mutex::new(infra.variant_detection_handle.lock().await.take()),
        storage_dir: infra.storage_dir.clone(),
        mdd_decompress: infra.mdd_decompress,
        post_update_mode,
        init_plugin,
        _gateway: std::marker::PhantomData,
    };

    let reloader_config =
        cda_plugin_runtime_update::RuntimeReloaderConfig::new(reloader_infra, factory);

    let reloader_plugin = Arc::new(DefaultRuntimeReloaderPlugin::<
        UdsManagerType<DefaultSecurityPluginData>,
        DoipDiagGateway<EcuManager<DefaultSecurityPluginData>>,
        Configuration,
        DefaultSecurityPlugin,
        _,
        DoipCommHandle<EcuManager<DefaultSecurityPluginData>>,
    >::new(reloader_config));

    let storage = cda_storage::LocalStorage::new(&infra.storage_dir)
        .map_err(|e| AppError::InitializationFailed(format!("Failed to create storage: {e}")))?;

    let plugin = DefaultRuntimeUpdatePlugin::new(
        Arc::new(storage),
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
        ConfigurationValidator::new(),
    );

    Ok(plugin)
}
