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

use std::{future::Future, sync::Arc};

use cda_interfaces::{CommunicationControl, ShutdownSignal};
use cda_plugin_runtime_update::UpdateGuard;
use cda_plugin_security::{SecurityPlugin, SecurityPluginLoader};
use tokio::sync::{Mutex, RwLock};

use crate::{
    UdsManagerType, build_vehicle_stack, config::configfile::Configuration, error::AppError,
    resolve_mdd_paths_from_config, update,
};

/// Type-erased boxed update plugin factory for deferred-init mode.
///
/// Called once during deferred setup to register runtime-update routes
/// (same as the Enabled startup path). Boxed so the setup function
/// remains generic over `SP` only.
pub type DeferredUpdatePluginFn<SP> = Box<
    dyn FnOnce(
            CdaRuntime<SP>,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            Box<dyn cda_interfaces::runtime_update_api::RuntimeFilesUpdatePlugin>,
                            AppError,
                        >,
                    > + Send,
            >,
        > + Send,
>;

pub use cda_interfaces::deferred_init_api::{InitPluginBuilder, InitPluginFn, init_plugin_fn};

use crate::setup::CdaRuntime;

/// Configuration for deferred vehicle route setup.
///
/// Groups related parameters to reduce the argument count of
/// [`setup_deferred_vehicle_routes`].
pub struct DeferredSetupConfig<'a> {
    /// Application configuration
    pub config: Configuration,
    /// Dynamic router for route registration
    pub dynamic_router: &'a cda_sovd::dynamic_router::DynamicRouter,
    /// Web server configuration for route setup
    pub webserver_config: &'a cda_sovd::WebServerConfig,
    /// Optional health state for health checks
    pub health_state: Option<&'a cda_health::HealthState>,
    /// Shutdown signal for graceful shutdown
    pub shutdown_signal: ShutdownSignal,
    /// Cancellation token for shutdown coordination (unused but required for API compatibility)
    pub shutdown_cancel: tokio_util::sync::CancellationToken,
}

/// Adapter to make `cda_interfaces::InitPluginBuilder` work with cda-main's `AppError`
///
/// This trait is implemented for all types that implement the cda-interfaces
/// `InitPluginBuilder`, adapting the error type to `AppError`.
pub trait AppInitPluginBuilder<SP: SecurityPlugin>: Send {
    type Plugin: cda_interfaces::InitializationPlugin;
    fn build(self) -> impl Future<Output = Result<Self::Plugin, AppError>> + Send;
}

/// Adapter implementation for types implementing cda-interfaces `InitPluginBuilder`.
///
/// This bridges the cda-interfaces `InitPluginBuilder` (which uses its own error type)
/// with cda-main's `AppInitPluginBuilder` (which uses `AppError`).
impl<T, SP> AppInitPluginBuilder<SP> for T
where
    T: cda_interfaces::deferred_init_api::InitPluginBuilder + Send,
    T::Plugin: cda_interfaces::InitializationPlugin,
    T::Error: std::fmt::Debug,
    SP: SecurityPlugin,
{
    type Plugin = T::Plugin;

    async fn build(self) -> Result<Self::Plugin, AppError> {
        cda_interfaces::deferred_init_api::InitPluginBuilder::build(self)
            .await
            .map_err(|e| AppError::RuntimeError(format!("Failed to build init plugin: {e:?}")))
    }
}

/// Sets up the CDA in deferred-initialization mode.
///
/// Builds the complete vehicle stack using `DoipCommActor` and `DeferredGateway`,
/// registers real vehicle routes immediately, installs the deferred-init guard
/// middleware, and hands the plugin a [`cda_interfaces::CommunicationControl`]
/// via [`cda_interfaces::InitializationPlugin::on_ready`]. The `DoIP` gateway
/// is created in a disabled state; communication is enabled via the
/// `CommunicationControl` handle when the init trigger fires.
///
/// # Errors
/// Returns [`AppError`] if database loading, socket creation, or route setup fails.
pub async fn setup_deferred_vehicle_routes<SP: SecurityPlugin, SL: SecurityPluginLoader>(
    setup_config: DeferredSetupConfig<'_>,
    init_plugin: Arc<dyn cda_interfaces::InitializationPlugin>,
    update_plugin_fn: Option<DeferredUpdatePluginFn<SP>>,
) -> Result<(), AppError> {
    tracing::info!("Starting in deferred ECU communication mode");

    let DeferredSetupConfig {
        config,
        dynamic_router,
        webserver_config,
        health_state,
        shutdown_signal,
        shutdown_cancel: _,
    } = setup_config;

    let mdd_paths = resolve_mdd_paths_from_config(&config).await?;

    // Create database health provider before building the stack so load_databases
    // can report status live. Keep health_state for later registration.
    let db_health: Option<Arc<cda_health::StatusHealthProvider>> = health_state.map(|_| {
        Arc::new(cda_health::StatusHealthProvider::new(
            cda_health::Status::Starting,
        ))
    });

    let update_guard = UpdateGuard::new();

    // Build the complete vehicle stack (DoipCommActor + DeferredGateway + UdsManager)
    // The actor starts in disabled state - communication is not yet enabled.
    let stack =
        build_vehicle_stack::<SP>(&config, &mdd_paths, db_health.clone(), update_guard, None)
            .await?;

    // Register health providers now that the comm_handle is available.
    if let (Some(hs), Some(db)) = (health_state, db_health.as_ref()) {
        let doip_health = Arc::new(stack.comm_handle.health_provider());
        hs.register_provider(
            crate::DOIP_HEALTH_COMPONENT_KEY,
            doip_health as Arc<dyn cda_interfaces::health::HealthStatus>,
        )
        .await
        .map_err(|e| AppError::InitializationFailed(e.to_string()))?;
        hs.register_provider(
            crate::mdd::DB_HEALTH_COMPONENT_KEY,
            Arc::clone(db) as Arc<dyn cda_interfaces::health::HealthStatus>,
        )
        .await
        .map_err(|e| AppError::InitializationFailed(e.to_string()))?;
    }

    if stack.databases.is_empty() && config.database.exit_no_database_loaded {
        return Err(AppError::ResourceError(
            "No database loaded, exiting as configured".to_string(),
        ));
    }

    // Get the locks from the lock provider
    let locks = stack.lock_provider.current_locks().await;

    // Register real vehicle routes immediately.
    // The DeferredInitGuard will gate diagnostic requests until communication is enabled.
    let (ecu_execution_registry, vehicle_route_handle) =
        cda_sovd::add_vehicle_routes::<UdsManagerType<SP>, cda_database::FileManager, SL>(
            dynamic_router,
            cda_sovd::VehicleConfig {
                flash_files_path: config.flash_files_path.clone(),
                functional_group_config: config.functional_description.clone(),
                components_config: config.components.clone(),
            },
            cda_sovd::VehicleResources {
                ecu_uds: stack.uds_manager.clone(),
                file_managers: stack.file_managers.clone(),
                locks,
                update_in_progress: stack.update_guard.busy_handle(),
            },
        )
        .await
        .map_err(|e| AppError::InitializationFailed(e.to_string()))?;

    let retry_after = config.communication.deferred_retry_after_seconds;

    // Create the deferred init guard using the comm handle as CommunicationControl.
    // The guard checks if communication is active; if not, it uses the plugin
    // to decide whether to trigger initialization.
    let comm_handle = stack.comm_handle;
    let active_flag = comm_handle.active();
    // Clone comm_handle: one goes to the guard (wrapped in Arc<dyn CommunicationControl>),
    // the other goes to CdaRuntime for the reloader to drive disable/enable.
    let comm_handle_for_runtime = comm_handle.clone();
    let comm_control: Arc<dyn CommunicationControl> = Arc::new(comm_handle);
    let deferred_guard = cda_plugin_deferred_init::guard::DeferredInitGuard::new(
        active_flag,
        Arc::clone(&comm_control),
        Arc::clone(&init_plugin),
        retry_after,
    );

    // Install deferred init guard BEFORE update guard - update guard must be outermost layer.
    cda_sovd::install_guard(dynamic_router, deferred_guard).await;

    // Set up OpenAPI routes.
    cda_sovd::add_openapi_routes(dynamic_router, webserver_config).await;

    // Install update guard as outermost layer.
    cda_sovd::install_guard(dynamic_router, stack.update_guard.clone()).await;

    // Build CdaRuntime for the update plugin (if provided).
    let variant_detection_handle = stack.variant_detection_handle;

    // Hand the plugin a CommunicationControl handle so it can proactively initialize.
    init_plugin.on_ready(Arc::clone(&comm_control)).await;

    // If an update plugin was provided, build and register it now.
    if let Some(build_plugin) = update_plugin_fn {
        let flash_transfer_guard = stack.uds_manager.flash_transfer_guard();
        let lock_provider_clone = Arc::clone(&stack.lock_provider);
        let post_update_mode = config.communication.post_update_mode.clone();
        let health_map = if let Some(ref db) = db_health {
            let mut map = cda_interfaces::HashMap::default();
            map.insert(
                crate::DOIP_HEALTH_COMPONENT_KEY.to_owned(),
                Arc::new(comm_handle_for_runtime.health_provider())
                    as Arc<dyn cda_interfaces::health::HealthStatus>,
            );
            map.insert(
                crate::mdd::DB_HEALTH_COMPONENT_KEY.to_owned(),
                Arc::clone(db) as Arc<dyn cda_interfaces::health::HealthStatus>,
            );
            Some(map)
        } else {
            None
        };
        let cda_runtime = CdaRuntime {
            config: Arc::new(RwLock::new(config.clone())),
            uds_manager: Arc::new(RwLock::new(stack.uds_manager)),
            // Pass the comm_handle directly - the slot is empty (disabled) but that
            // is correct: the reloader will call disable()+replace_gateway() on each
            // reload, and on first reload enable() will have been triggered by a guard.
            comm_handle: comm_handle_for_runtime,
            dynamic_router: dynamic_router.clone(),
            vehicle_route_handle,
            lock_provider: stack.lock_provider,
            ecu_execution_registry,
            update_guard: stack.update_guard.clone(),
            update_in_progress: stack.update_guard.busy_handle(),
            flash_files_path: config.flash_files_path.clone(),
            components_config: config.components.clone(),
            variant_detection_handle: Mutex::new(Some(variant_detection_handle)),
            health: health_map,
            flash_transfer_guard,
            storage_dir: config.runtime_update_config.storage_dir.clone(),
            mdd_decompress: config.flat_buf.mdd_decompress,
            shutdown_signal,
            post_update_mode,
            init_plugin: Some(Arc::clone(&init_plugin)),
        };

        let update_plugin = build_plugin(cda_runtime).await?;
        update::add_runtime_update_routes::<SL, _>(
            dynamic_router,
            update_plugin,
            lock_provider_clone,
            &stack.update_guard,
            config.runtime_update_config.upload_body_limit_bytes,
            config.runtime_update_config.retry_after_seconds,
        )
        .await;
    }

    tracing::info!("Deferred mode: HTTP server ready, ECU communication pending trigger");
    Ok(())
}
