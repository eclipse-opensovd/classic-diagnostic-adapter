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

use cda_comm_doip::comm_handle::DoipCommHandle;
use cda_comm_uds::FlashTransferObserver;
use cda_core::EcuManager;
use cda_interfaces::{
    HashMap, InitializationPlugin, ShutdownSignal,
    communication_control::PostUpdateCommunicationMode, health::HealthStatus,
};
use cda_plugin_runtime_update::UpdateGuard;
use cda_plugin_security::{SecurityPlugin, SecurityPluginLoader};
use futures::future::BoxFuture;
use tokio::sync::{Mutex, RwLock};

use crate::{
    VehicleStack,
    config::configfile::Configuration,
    error::AppError,
    update::{UpdatePluginBuilder, add_runtime_update_routes},
};

/// Sets up vehicle routes with the given resources.
///
/// This helper function consolidates the common route setup logic used in both
/// Enabled and Deferred initialization modes.
///
/// # Errors
/// Returns [`AppError`] if route registration fails.
pub(crate) async fn setup_vehicle_routes<SP, SL>(
    dynamic_router: &cda_sovd::dynamic_router::DynamicRouter,
    config: &Configuration,
    uds_manager: &crate::UdsManagerType<SP>,
    file_managers: crate::FileManagerMap,
    locks: Arc<cda_sovd::Locks>,
    update_in_progress: Arc<std::sync::atomic::AtomicBool>,
) -> Result<
    (
        Arc<cda_sovd::SovdLockStateProvider>,
        cda_sovd::RouteHandle,
        cda_sovd::EcuExecutionRegistry,
    ),
    AppError,
>
where
    SP: SecurityPlugin,
    SL: SecurityPluginLoader,
{
    let (ecu_execution_registry, vehicle_route_handle) = cda_sovd::add_vehicle_routes::<_, _, SL>(
        dynamic_router,
        cda_sovd::VehicleConfig {
            flash_files_path: config.flash_files_path.clone(),
            functional_group_config: config.functional_description.clone(),
            components_config: config.components.clone(),
        },
        cda_sovd::VehicleResources {
            ecu_uds: uds_manager.clone(),
            file_managers,
            locks: Arc::clone(&locks),
            update_in_progress,
        },
    )
    .await?;

    let lock_provider: Arc<cda_sovd::SovdLockStateProvider> =
        Arc::new(cda_sovd::SovdLockStateProvider::new(Arc::clone(&locks)));

    Ok((lock_provider, vehicle_route_handle, ecu_execution_registry))
}

/// Sets up runtime routes for Enabled mode.
///
/// This function consolidates the Enabled-mode route setup logic:
/// - Sets up vehicle routes
/// - Builds `CdaRuntime`
/// - Registers update plugin (if provided)
/// - Registers `OpenAPI` routes
/// - Installs update guard
/// - Calls [`InitializationPlugin::on_ready`] on the init plugin (if provided)
///   with the active [`CommunicationControl`] handle
///
/// # Errors
/// Returns [`AppError`] if route registration or plugin setup fails.
pub(crate) async fn setup_runtime_routes<SP, SL, UPB>(
    config: Configuration,
    stack: VehicleStack<SP>,
    dynamic_router: &cda_sovd::dynamic_router::DynamicRouter,
    webserver_config: &cda_sovd::WebServerConfig,
    shutdown_signal: ShutdownSignal,
    build_update_plugin: Option<UPB>,
    init_plugin: Option<Arc<dyn InitializationPlugin>>,
) -> Result<(), AppError>
where
    SP: SecurityPlugin,
    SL: SecurityPluginLoader,
    UPB: UpdatePluginBuilder<SP>,
{
    use cda_interfaces::communication_control::CommunicationControl;

    let runtime_update_config = config.runtime_update_config.clone();

    let locks = stack.lock_provider.current_locks().await;

    let (lock_provider, vehicle_route_handle, ecu_execution_registry) =
        setup_vehicle_routes::<SP, SL>(
            dynamic_router,
            &config,
            &stack.uds_manager,
            stack.file_managers.clone(),
            locks,
            stack.update_guard.busy_handle(),
        )
        .await?;

    let flash_transfer_guard = stack.uds_manager.flash_transfer_guard();

    let post_update_mode = config.communication.post_update_mode.clone();

    // Obtain a CommunicationControl handle before comm_handle is moved into the runtime.
    let comm_control: Arc<dyn CommunicationControl> = Arc::new(stack.comm_handle.clone());

    // Build the runtime infrastructure
    let infra = build_cda_runtime(
        config,
        stack.uds_manager,
        stack.comm_handle,
        dynamic_router.clone(),
        vehicle_route_handle,
        &lock_provider,
        ecu_execution_registry,
        &stack.update_guard,
        stack.variant_detection_handle,
        stack.health_providers.as_ref(),
        flash_transfer_guard,
        shutdown_signal,
        post_update_mode,
        init_plugin.clone(),
    );

    // Build and install update plugin using the callback if provided
    if let Some(builder) = build_update_plugin {
        let runtime_update_plugin = builder.build(infra).await?;

        add_runtime_update_routes::<SL, _>(
            dynamic_router,
            runtime_update_plugin,
            lock_provider,
            &stack.update_guard,
            runtime_update_config.upload_body_limit_bytes,
            runtime_update_config.retry_after_seconds,
        )
        .await;
    }

    cda_sovd::add_openapi_routes(dynamic_router, webserver_config).await;

    cda_sovd::install_guard(dynamic_router, stack.update_guard.clone()).await;

    // Notify the init plugin that communication is active so it can perform
    // any post-activation work (e.g., registering proactive trigger callbacks).
    if let Some(plugin) = init_plugin {
        plugin.on_ready(comm_control).await;
    }

    Ok(())
}

/// Builds a `CdaRuntime` instance from the given components.
///
/// This helper function consolidates the runtime construction logic used in both
/// Enabled mode and deferred initialization (via `deferred_init.rs`).
#[allow(
    clippy::too_many_arguments,
    reason = "Runtime construction requires many components"
)] // todo alexmohr refactor this
pub(crate) fn build_cda_runtime<SP: SecurityPlugin>(
    config: Configuration,
    uds_manager: crate::UdsManagerType<SP>,
    comm_handle: DoipCommHandle<EcuManager<SP>>,
    dynamic_router: cda_sovd::dynamic_router::DynamicRouter,
    vehicle_route_handle: cda_sovd::RouteHandle,
    lock_provider: &Arc<cda_sovd::SovdLockStateProvider>,
    ecu_execution_registry: cda_sovd::EcuExecutionRegistry,
    update_guard: &UpdateGuard,
    variant_detection_handle: tokio::task::JoinHandle<()>,
    health_providers: Option<&crate::HealthProviders>,
    flash_transfer_guard: cda_comm_uds::FlashTransferObserver,
    shutdown_signal: ShutdownSignal,
    post_update_mode: PostUpdateCommunicationMode,
    init_plugin: Option<Arc<dyn InitializationPlugin>>,
) -> CdaRuntime<SP> {
    let health_map = health_providers.map(crate::HealthProviders::to_health_map);

    // Extract fields before moving config into Arc
    let flash_files_path = config.flash_files_path.clone();
    let components_config = config.components.clone();
    let storage_dir = config.runtime_update_config.storage_dir.clone();
    let mdd_decompress = config.flat_buf.mdd_decompress;

    CdaRuntime {
        config: Arc::new(RwLock::new(config)),
        uds_manager: Arc::new(RwLock::new(uds_manager)),
        comm_handle,
        dynamic_router,
        vehicle_route_handle,
        lock_provider: Arc::clone(lock_provider),
        ecu_execution_registry,
        update_guard: update_guard.clone(),
        update_in_progress: update_guard.busy_handle(),
        flash_files_path,
        components_config,
        variant_detection_handle: Mutex::new(Some(variant_detection_handle)),
        health: health_map,
        flash_transfer_guard,
        storage_dir,
        mdd_decompress,
        shutdown_signal,
        post_update_mode,
        init_plugin,
    }
}

/// Runtime context produced during CDA initialization, made available to the update plugin callback.
///
/// This struct contains all the components needed to build a runtime update plugin.
/// It is passed to the `build_update_plugin` callback in `Setup`.
pub struct CdaRuntime<SP: SecurityPlugin> {
    /// Application configuration
    pub config: Arc<RwLock<Configuration>>,

    /// Vehicle diagnostic manager
    pub uds_manager: Arc<RwLock<crate::UdsManagerType<SP>>>,

    /// Handle to the `DoIP` communication actor.
    ///
    /// Used by the runtime-update reload path to disable the old connection,
    /// install the freshly-built gateway, and re-activate communication.
    /// Also provides access to the reserved UDP socket via [`DoipCommHandle::socket`]
    /// so the `VehicleComponentFactory` can reuse the bound port.
    pub comm_handle: DoipCommHandle<EcuManager<SP>>,

    /// Dynamic router for hot-swapping routes
    pub dynamic_router: cda_sovd::dynamic_router::DynamicRouter,

    /// Handle for vehicle route registration/replacement
    pub vehicle_route_handle: cda_sovd::RouteHandle,

    /// Lock state provider for SOVD locks
    pub lock_provider: Arc<cda_sovd::SovdLockStateProvider>,

    /// ECU execution registry for tracking in-flight operations
    pub ecu_execution_registry: cda_sovd::EcuExecutionRegistry,

    /// Update guard
    pub update_guard: UpdateGuard,

    /// Flag indicating whether an update is in progress
    pub update_in_progress: Arc<std::sync::atomic::AtomicBool>,

    /// Path for flash files
    pub flash_files_path: String,

    /// Component configuration
    pub components_config: cda_interfaces::datatypes::ComponentsConfig,

    /// Handle for variant detection background task
    pub variant_detection_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,

    /// Health providers for monitoring
    pub health: Option<HashMap<String, Arc<dyn HealthStatus>>>,

    /// Guard that signals whether a flash transfer is in progress
    pub flash_transfer_guard: FlashTransferObserver,

    /// Storage directory for runtime update files
    pub storage_dir: String,

    /// Whether to decompress MDD files after apply
    pub mdd_decompress: bool,

    /// Shutdown signal for graceful termination
    pub shutdown_signal: ShutdownSignal,

    /// Controls communication behavior after a runtime database update.
    ///
    /// Threaded from `config.communication.post_update_mode` at setup time so
    /// the update plugin builder doesn't need to re-read the config.
    pub post_update_mode: PostUpdateCommunicationMode,

    /// Optional initialization plugin.
    ///
    /// In deferred mode this is set at startup. In enabled mode it is set so
    /// the plugin receives the `on_ready` callback once communication is active.
    /// The reloader also calls `on_ready` after installing a new gateway in
    /// deferred mode so the plugin can re-arm its trigger.
    pub init_plugin: Option<Arc<dyn InitializationPlugin>>,
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
///     }))
///     .with_init_plugin(deferred_init::init_plugin_fn(|| async move {
///         Ok(MyInitPlugin::new())
///     }));
/// ```
#[allow(
    clippy::type_complexity,
    reason = "closure type is dictated by the dynamic router API"
)]
pub(crate) type PreLoadHook = Box<
    dyn FnOnce(cda_sovd::dynamic_router::DynamicRouter) -> BoxFuture<'static, Result<(), AppError>>
        + Send,
>;

pub struct Setup<SP: SecurityPlugin, SL: SecurityPluginLoader, UPB = (), IPB = ()> {
    _phantom: std::marker::PhantomData<(SP, SL)>,

    /// Optional callback run before vehicle data is loaded.
    /// Receives the dynamic router to register early routes.
    /// If not set, no preload hook is executed.
    pub(crate) pre_load: Option<PreLoadHook>,

    /// Update plugin builder. Set via [`Setup::with_update_plugin`].
    /// When `UPB = ()` (the default), no update plugin is registered.
    pub(crate) build_update_plugin: Option<UPB>,

    /// Init plugin builder. Set via [`Setup::with_init_plugin`].
    /// When `IPB = ()` (the default), `OnDemandInitPlugin` is used.
    /// In `CommunicationInitMode::Deferred`, gates diagnostic requests until triggered.
    /// In `CommunicationInitMode::Enabled`, receives `on_ready` once communication is active.
    pub(crate) build_init_plugin: Option<IPB>,
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
    ///
    /// Use `with_init_plugin()` to provide a custom deferred-init plugin builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
            pre_load: None,
            build_update_plugin: None,
            build_init_plugin: None,
        }
    }
}

impl<SP, SL, UPB, IPB> Setup<SP, SL, UPB, IPB>
where
    SP: SecurityPlugin,
    SL: SecurityPluginLoader,
{
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
    #[must_use]
    pub fn with_update_plugin<UPB2>(self, builder: UPB2) -> Setup<SP, SL, UPB2, IPB>
    where
        UPB2: UpdatePluginBuilder<SP>,
    {
        Setup {
            _phantom: self._phantom,
            pre_load: self.pre_load,
            build_update_plugin: Some(builder),
            build_init_plugin: self.build_init_plugin,
        }
    }

    /// Sets the deferred-initialization plugin builder.
    ///
    /// The builder is called with no runtime context (vehicle components do not exist yet
    /// in deferred mode) and returns an [`InitializationPlugin`](cda_interfaces::InitializationPlugin).
    /// It is only consulted when `config.communication.init_mode` is set to `Deferred`.
    ///
    /// If not set, [`OnDemandInitPlugin`](cda_interfaces::OnDemandInitPlugin) is used by default,
    /// which triggers initialization on the first diagnostic HTTP request.
    ///
    /// Use [`init_plugin_fn`](cda_interfaces::deferred_init_api::init_plugin_fn) to wrap an async closure as a builder.
    #[must_use]
    pub fn with_init_plugin<IPB2>(self, builder: IPB2) -> Setup<SP, SL, UPB, IPB2>
    where
        IPB2: crate::deferred_init::AppInitPluginBuilder<SP>,
    {
        Setup {
            _phantom: self._phantom,
            pre_load: self.pre_load,
            build_update_plugin: self.build_update_plugin,
            build_init_plugin: Some(builder),
        }
    }
}
