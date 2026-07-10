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

use cda_comm_doip::DoipDiagGateway;
use cda_comm_uds::FlashTransferObserver;
use cda_core::EcuManager;
use cda_interfaces::{HashMap, ShutdownSignal, health::HealthProvider};
use cda_plugin_security::{SecurityPlugin, SecurityPluginLoader};
use cda_sovd::UpdateGuardState;
use futures::future::BoxFuture;
use tokio::sync::{Mutex, RwLock};

use crate::{
    UdsManagerType, VehicleData, WebserverState,
    config::configfile::Configuration,
    error::AppError,
    update::{UpdatePluginBuilder, add_runtime_update_routes},
};

pub(crate) async fn setup_runtime_routes<SP, SL, UPB>(
    config: Configuration,
    vehicle_data: VehicleData<SP>,
    ws: &WebserverState,
    build_update_plugin: Option<UPB>,
) -> Result<(), AppError>
where
    SP: SecurityPlugin,
    SL: SecurityPluginLoader,
    UPB: UpdatePluginBuilder<SP>,
{
    let mdd_decompress = config.flat_buf.mdd_decompress;
    let flash_files_path = config.flash_files_path.clone();
    let components_config = config.components.clone();
    let runtime_update_config = config.runtime_update_config.clone();

    let (ecu_execution_registry, vehicle_route_handle) = cda_sovd::add_vehicle_routes::<_, _, SL>(
        &ws.dynamic_router,
        cda_sovd::VehicleConfig {
            flash_files_path: config.flash_files_path.clone(),
            functional_group_config: config.functional_description.clone(),
            components_config: config.components.clone(),
        },
        cda_sovd::VehicleResources {
            ecu_uds: vehicle_data.uds_manager.clone(),
            file_manager: vehicle_data.file_managers,
            locks: Arc::clone(&vehicle_data.locks),
            update_in_progress: vehicle_data.update_guard.busy_handle(),
        },
    )
    .await?;

    let lock_provider: Arc<cda_sovd::SovdLockStateProvider> = Arc::new(
        cda_sovd::SovdLockStateProvider::new(Arc::clone(&vehicle_data.locks)),
    );

    let flash_transfer_guard = vehicle_data.uds_manager.flash_transfer_guard();

    // Build the runtime infrastructure
    let config_arc = Arc::new(RwLock::new(config));
    let infra = CdaRuntime {
        config: Arc::clone(&config_arc),
        uds_manager: Arc::new(RwLock::new(vehicle_data.uds_manager)),
        doip_gateway: Arc::new(RwLock::new(vehicle_data.diagnostic_gateway)),
        dynamic_router: ws.dynamic_router.clone(),
        vehicle_route_handle,
        lock_provider: Arc::clone(&lock_provider),
        ecu_execution_registry: ecu_execution_registry.clone(),
        update_guard: vehicle_data.update_guard.clone(),
        update_in_progress: vehicle_data.update_guard.busy_handle(),
        flash_files_path,
        components_config,
        variant_detection_handle: Mutex::new(Some(vehicle_data.variant_detection_handle)),
        health: vehicle_data.health_providers,
        flash_transfer_guard,
        storage_dir: runtime_update_config.storage_dir,
        mdd_decompress,
        shutdown_signal: ws.shutdown_signal.clone(),
    };

    // Build and install update plugin using the callback if provided
    if let Some(builder) = build_update_plugin {
        let runtime_update_plugin = builder.build(infra).await?;

        add_runtime_update_routes::<SL, _>(
            &ws.dynamic_router,
            runtime_update_plugin,
            lock_provider,
            &vehicle_data.update_guard,
            runtime_update_config.upload_body_limit_bytes,
            runtime_update_config.retry_after_seconds,
        )
        .await;
    }

    cda_sovd::add_openapi_routes(
        &ws.dynamic_router,
        &vehicle_data.update_guard,
        &ws.webserver_config,
    )
    .await;

    cda_sovd::install_update_guard(&ws.dynamic_router, vehicle_data.update_guard.clone()).await;

    Ok(())
}

/// Runtime context produced during CDA initialization, made available to the update plugin callback.
///
/// This struct contains all the components needed to build a runtime update plugin.
/// It is passed to the `build_update_plugin` callback in `Setup`.
pub struct CdaRuntime<SP: SecurityPlugin> {
    /// Application configuration
    pub config: Arc<RwLock<Configuration>>,

    /// Vehicle diagnostic manager
    pub uds_manager: Arc<RwLock<UdsManagerType<SP>>>,

    /// `DoIP` diagnostic gateway
    pub doip_gateway: Arc<RwLock<DoipDiagGateway<EcuManager<SP>>>>,

    /// Dynamic router for hot-swapping routes
    pub dynamic_router: cda_sovd::dynamic_router::DynamicRouter,

    /// Handle for vehicle route registration/replacement
    pub vehicle_route_handle: cda_sovd::RouteHandle,

    /// Lock state provider for SOVD locks
    pub lock_provider: Arc<cda_sovd::SovdLockStateProvider>,

    /// ECU execution registry for tracking in-flight operations
    pub ecu_execution_registry: cda_sovd::EcuExecutionRegistry,

    /// Update guard state
    pub update_guard: UpdateGuardState,

    /// Flag indicating whether an update is in progress
    pub update_in_progress: Arc<std::sync::atomic::AtomicBool>,

    /// Path for flash files
    pub flash_files_path: String,

    /// Component configuration
    pub components_config: cda_interfaces::datatypes::ComponentsConfig,

    /// Handle for variant detection background task
    pub variant_detection_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,

    /// Health providers for monitoring
    pub health: Option<HashMap<String, Arc<dyn HealthProvider>>>,

    /// Guard that signals whether a flash transfer is in progress
    pub flash_transfer_guard: FlashTransferObserver,

    /// Storage directory for runtime update files
    pub storage_dir: String,

    /// Whether to decompress MDD files after apply
    pub mdd_decompress: bool,

    /// Shutdown signal for graceful termination
    pub shutdown_signal: ShutdownSignal,
}

/// Setup configuration for CDA runtime initialization.
///
/// This struct allows customization of the CDA startup process through a builder pattern.
/// Use `Setup::new()` to create a default setup with no custom configuration, then chain
/// methods to add customization:
///
/// # Example
/// ```rust,ignore
/// let setup = Setup::<MySecurityPlugin, MySecurityLoader>::new()
///     .with_pre_load(|router| async move {
///         register_version_endpoints(router).await
///     })
///     .with_update_plugin(update_plugin_fn(|infra| async move {
///         let plugin = MyCustomPlugin::new(infra);
///         Ok(plugin)
///     }));
/// ```
pub(crate) type PreLoadHook = Box<
    dyn FnOnce(cda_sovd::dynamic_router::DynamicRouter) -> BoxFuture<'static, Result<(), AppError>>
        + Send,
>;

pub struct Setup<SP: SecurityPlugin, SL: SecurityPluginLoader, UpdatePluginBuilder = ()> {
    _phantom: std::marker::PhantomData<(SP, SL)>,

    /// Optional callback run before vehicle data is loaded.
    /// Receives the dynamic router to register early routes.
    /// If not set, no preload hook is executed.
    pub(crate) pre_load: Option<PreLoadHook>,

    /// Plugin builder. Set via [`Setup::with_update_plugin`].
    /// When `UpdatePluginBuilder = ()` (the default), no update plugin is registered.
    pub(crate) build_update_plugin: Option<UpdatePluginBuilder>,
}

impl<SP: SecurityPlugin, SL: SecurityPluginLoader> Default for Setup<SP, SL> {
    fn default() -> Self {
        Self::new()
    }
}

impl<SP: SecurityPlugin, SL: SecurityPluginLoader> Setup<SP, SL> {
    /// Creates a new Setup with no custom configuration.
    ///
    /// Use `with_preload()` to optionally add a preload hook that runs after the webserver
    /// starts but before vehicle data is loaded.
    ///
    /// Use `with_update_plugin()` to provide a custom update plugin builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
            pre_load: None,
            build_update_plugin: None,
        }
    }
}

impl<SP: SecurityPlugin, SL: SecurityPluginLoader, UPB> Setup<SP, SL, UPB> {
    /// Sets the preload hook callback.
    ///
    /// This callback is called after the webserver starts but before vehicle data is loaded.
    /// It can be used to register additional routes that should be available during database loading.
    ///
    /// If not set, no preload hook is executed.
    #[must_use]
    pub fn with_preload<F, Fut>(mut self, f: F) -> Self
    where
        F: FnOnce(cda_sovd::dynamic_router::DynamicRouter) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), AppError>> + Send + 'static,
    {
        self.pre_load = Some(Box::new(|router| Box::pin(f(router))));
        self
    }

    /// Sets the update plugin builder.
    ///
    /// This builder is called after vehicle data is loaded with the complete `CdaRuntime`.
    /// It should return a `RuntimeFilesUpdatePlugin` implementation.
    ///
    /// Use [`update_plugin_fn`] to wrap an async closure as a builder.
    pub fn with_update_plugin<UPB2>(self, builder: UPB2) -> Setup<SP, SL, UPB2> {
        Setup {
            _phantom: self._phantom,
            pre_load: self.pre_load,
            build_update_plugin: Some(builder),
        }
    }
}
