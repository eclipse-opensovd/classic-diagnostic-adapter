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

//! CDA startup builder.
//!
//! [`Setup`] is the public entry-point for applications that need to customize how the CDA
//! boots. The default startup path uses [`Setup::new`] with the standard update plugin; a
//! custom path calls [`Setup::with_update_plugin`] to inject any [`RuntimeFilesUpdatePlugin`]
//! implementation and [`Setup::with_communication_plugin`] to replace the default
//! `init_mode`-aware communication plugin, before handing the `Setup` to one of the
//! `run_*` functions.
//!
//! [`RuntimeFilesUpdatePlugin`]: cda_interfaces::runtime_update_api::RuntimeFilesUpdatePlugin

use std::{future::Future, sync::Arc, time::Duration};

use cda_comm_can::CanDiagGateway;
use cda_comm_doip::DoipDiagGateway;
use cda_core::EcuManager;
use cda_interfaces::{
    ShutdownSignal,
    communication_control::{
        ActivationCause, CommunicationAccess, CommunicationInitMode, CommunicationLifecycle,
        CommunicationVariantDetection, DisableCommunication, PostUpdateCommunicationMode,
        VariantDetectionMode, error::CommControlError,
    },
    component_slot::ComponentSlot,
    http_protection::registry::{HttpProtectionRegistry, HttpRouteMatcher},
};
use cda_plugin_communication_management::{
    lifecycle::{
        CommunicationRuntime, access::CommunicationAccessView, build_communication_runtime,
        disable::CommunicationDisableView,
    },
    plugin::{
        CommunicationPlugin, CommunicationPluginBuilder, default::DefaultCommunicationPluginBuilder,
    },
};
use cda_plugin_security::{SecurityPlugin, SecurityPluginLoader};
use cda_transport_router::DiagnosticTransportRouter;
use futures::future::BoxFuture;
use tokio::sync::RwLock;

use crate::{
    ApplicationState,
    config::configfile::Configuration,
    error::AppError,
    update::{UpdatePluginBuilder, add_runtime_update_routes},
    vehicle::{UdsManagerType, VehicleData, finish_vehicle_components},
};

// Type alias

/// Boxed async callback executed after the webserver starts but **before** vehicle data is
/// loaded. Receives the dynamic router so it can register early routes.
pub(crate) type PreLoadHook = Box<
    dyn FnOnce(cda_sovd::dynamic_router::DynamicRouter) -> BoxFuture<'static, Result<(), AppError>>
        + Send,
>;

pub(crate) type ExtensionHook = Box<
    dyn FnOnce(crate::extensions::ExtensionContext) -> BoxFuture<'static, Result<(), AppError>>
        + Send,
>;

/// Narrow capabilities exposed to runtime-update plugin builders.
///
/// Non-exhaustive: capabilities are added over time, and the context is only ever
/// constructed by `cda-main`. Plugin builders read the fields they need.
#[non_exhaustive]
pub struct UpdatePluginContext {
    pub reloader: Arc<dyn cda_interfaces::runtime_update_api::RuntimeReloaderPlugin>,
    pub lock_state: Arc<UpdateLockState>,
    pub storage_dir: String,
    pub mdd_decompress: bool,
    /// Transport behavior to restore after a runtime database update completes.
    pub post_update_mode: PostUpdateCommunicationMode,
    /// Narrow handle used by update plugins to request activation without
    /// gaining the full [`CommunicationPlugin`](CommunicationPlugin) lifecycle authority.
    pub communication_access: Arc<dyn CommunicationAccess>,
    /// Narrow handle used by update plugins to take exclusive ownership of
    /// communication for the duration of a runtime file update.
    pub communication_disable: Arc<dyn DisableCommunication>,
    /// Shared registry of HTTP request restrictions installed by update plugins.
    pub http_protections: HttpProtectionRegistry,
    /// Retry hint surfaced on the HTTP `Retry-After` header while a runtime
    /// update holds communication exclusively.
    pub update_retry_after: Duration,
    pub update_exempt_routes: Vec<HttpRouteMatcher>,
}

/// Names a [`LockStateProvider`] trait object as a concrete type.
///
/// Not a redundant wrapper: `RuntimeUpdateSecurityPlugin<L, C>` is generic over a
/// sized `L`, and `Arc<dyn LockStateProvider>` does not itself implement the trait.
/// This gives implementations something to name for `L` while the application
/// keeps choosing the provider at runtime.
///
/// [`LockStateProvider`]: cda_interfaces::runtime_update_api::LockStateProvider
pub struct UpdateLockState {
    inner: Arc<dyn cda_interfaces::runtime_update_api::LockStateProvider>,
}

impl UpdateLockState {
    #[must_use]
    pub fn new(inner: Arc<dyn cda_interfaces::runtime_update_api::LockStateProvider>) -> Self {
        Self { inner }
    }
}

#[async_trait::async_trait]
impl cda_interfaces::runtime_update_api::LockStateProvider for UpdateLockState {
    async fn vehicle_lock_owner_id(&self) -> Option<String> {
        self.inner.vehicle_lock_owner_id().await
    }

    async fn has_non_vehicle_locks(&self) -> bool {
        self.inner.has_non_vehicle_locks().await
    }
}

/// Adapter that bridges the `RwLock`-wrapped `UdsManager` to the two
/// communication-framework hook traits.
///
/// One struct, two traits, registered through both paths: the `UdsManager`
/// implements each half itself (the VAM-discovery listener as a
/// transport-coupled lifecycle hook, the whole-vehicle sweep as variant
/// detection), and this only forwards through the lock.
struct UdsCommunicationHooks<SP: SecurityPlugin> {
    uds_manager: ComponentSlot<UdsManagerType<SP>>,
}

#[async_trait::async_trait]
impl<SP: SecurityPlugin> CommunicationLifecycle for UdsCommunicationHooks<SP> {
    fn name(&self) -> &'static str {
        "variant-detection-listener"
    }

    async fn initialize(&self) -> Result<(), CommControlError> {
        self.uds_manager.read().await.initialize().await
    }

    async fn deinitialize(&self) {
        self.uds_manager.read().await.deinitialize().await;
    }
}

#[async_trait::async_trait]
impl<SP: SecurityPlugin> CommunicationVariantDetection for UdsCommunicationHooks<SP> {
    fn name(&self) -> &'static str {
        "variant-detection"
    }

    async fn detect(&self) -> Result<(), CommControlError> {
        self.uds_manager.read().await.detect().await
    }
}

/// Builder for customizing the CDA startup sequence.
///
/// Use [`Setup::new`] to start with the defaults and then chain optional
/// configuration methods:
///
/// ```rust,ignore
/// use opensovd_cda_lib::{
///     setup::Setup,
///     update::update_plugin_fn,
/// };
///
/// let setup = Setup::<MySecurityPlugin, MySecurityLoader>::new()
///     .with_preload(|router| async move {
///         // register additional routes before databases load
///         Ok(())
///     })
///     .with_update_plugin(update_plugin_fn(|infra| async move {
///         Ok(MyCustomUpdatePlugin::new(infra))
///     }))
///     .with_communication_plugin(MyCommunicationPluginBuilder);
///
/// opensovd_cda_lib::run_with_ext_from_config(config, setup).await?;
/// ```
///
/// When no update plugin is configured (`UpdatePluginBuilder = ()`) the runtime-update routes
/// are **not** mounted. Pass a builder, typically via [`update_plugin_fn`] or by implementing
/// [`UpdatePluginBuilder`], to enable them.
///
/// [`update_plugin_fn`]: crate::update::update_plugin_fn
/// [`UpdatePluginBuilder`]: UpdatePluginBuilder
///
/// Type parameters:
/// - `SP`: security plugin
/// - `SL`: security plugin loader
/// - `UPB`: update plugin builder, defaults to `()`
/// - `CPB`: communication plugin builder, defaults to [`DefaultCommunicationPluginBuilder`]
pub struct Setup<
    SP: SecurityPlugin,
    SL: SecurityPluginLoader,
    UPB = (),
    CPB = DefaultCommunicationPluginBuilder,
> {
    pub(crate) _phantom: std::marker::PhantomData<(SP, SL)>,
    /// Optional callback run after the webserver starts but before vehicle data is loaded.
    pub(crate) pre_load: Option<PreLoadHook>,
    /// Extensions run in registration order; empty when none are configured.
    pub(crate) extensions: Vec<ExtensionHook>,
    /// Optional update-plugin builder. When `None` (or `UPB = ()`) the runtime-update
    /// routes are not registered.
    pub(crate) build_update_plugin: Option<UPB>,
    pub(crate) build_communication_plugin: CPB,
    pub(crate) initialize_tracing: bool,
    pub(crate) shutdown_signal: Option<ShutdownSignal>,
}

impl<SP: SecurityPlugin, SL: SecurityPluginLoader> Default for Setup<SP, SL> {
    fn default() -> Self {
        Self::new()
    }
}

impl<SP: SecurityPlugin, SL: SecurityPluginLoader> Setup<SP, SL> {
    /// Creates a new `Setup` with no preload hook and no custom update plugin.
    #[must_use]
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
            pre_load: None,
            extensions: Vec::new(),
            build_update_plugin: None,
            build_communication_plugin: DefaultCommunicationPluginBuilder,
            initialize_tracing: true,
            shutdown_signal: None,
        }
    }
}

impl<SP: SecurityPlugin, SL: SecurityPluginLoader, UPB, CPB> Setup<SP, SL, UPB, CPB> {
    /// Uses the tracing subscriber already installed by the embedding process.
    #[must_use]
    pub fn with_existing_tracing(mut self) -> Self {
        self.initialize_tracing = false;
        self
    }

    /// Uses an externally managed shutdown signal instead of process signals.
    #[must_use]
    pub fn with_shutdown_signal(mut self, shutdown_signal: ShutdownSignal) -> Self {
        self.shutdown_signal = Some(shutdown_signal);
        self
    }

    /// Registers a preload hook.
    ///
    /// The hook is called after the webserver starts, health state and sd-notify are
    /// configured, but **before** vehicle data (MDD databases) are loaded.  Use it to
    /// mount additional routes that should be reachable during the (potentially slow)
    /// database load.
    ///
    /// The hook must return `Ok(())` to allow startup to continue; returning `Err` aborts
    /// the entire startup.
    #[must_use]
    pub fn with_preload<F, Fut>(mut self, f: F) -> Self
    where
        F: FnOnce(cda_sovd::dynamic_router::DynamicRouter) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), AppError>> + Send + 'static,
    {
        self.pre_load = Some(Box::new(|router| Box::pin(f(router))));
        self
    }

    /// Registers an OEM extension after vehicle components and standard routes are ready.
    ///
    /// The context exposes only stable route-registration, diagnostic-service and
    /// health-registration capabilities.
    ///
    /// Can be called more than once; extensions run in registration order and each
    /// receives its own context. The first one to return `Err` aborts startup.
    #[must_use]
    pub fn with_extension<F, Fut>(mut self, extension: F) -> Self
    where
        F: FnOnce(crate::extensions::ExtensionContext) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), AppError>> + Send + 'static,
    {
        self.extensions
            .push(Box::new(|context| Box::pin(extension(context))));
        self
    }

    /// Configures a custom runtime update plugin.
    ///
    /// `builder` will be called after vehicle data is loaded and routes are registered. It
    /// receives an [`UpdatePluginContext`] containing only update capabilities.
    ///
    /// The returned plugin is wrapped in [`ExclusiveRuntimePlugin`] (read/write mutual
    /// exclusion) and mounted on the standard runtime-update HTTP endpoints automatically.
    ///
    /// Use [`update_plugin_fn`] to wrap a plain async closure without implementing the trait
    /// manually:
    ///
    /// ```rust,ignore
    /// setup.with_update_plugin(update_plugin_fn(|infra| async move {
    ///     Ok(MyPlugin::new(infra))
    /// }))
    /// ```
    ///
    /// [`ExclusiveRuntimePlugin`]: cda_plugin_runtime_update::ExclusiveRuntimePlugin
    /// [`update_plugin_fn`]: crate::update::update_plugin_fn
    pub fn with_update_plugin<UPB2: UpdatePluginBuilder>(
        self,
        builder: UPB2,
    ) -> Setup<SP, SL, UPB2, CPB> {
        Setup {
            _phantom: self._phantom,
            pre_load: self.pre_load,
            extensions: self.extensions,
            build_update_plugin: Some(builder),
            build_communication_plugin: self.build_communication_plugin,
            initialize_tracing: self.initialize_tracing,
            shutdown_signal: self.shutdown_signal,
        }
    }

    /// Replaces the default communication plugin factory.
    ///
    /// The factory is invoked after the passive transport and authoritative manager exist.
    pub fn with_communication_plugin<CPB2: CommunicationPluginBuilder>(
        self,
        plugin: CPB2,
    ) -> Setup<SP, SL, UPB, CPB2> {
        Setup {
            _phantom: self._phantom,
            pre_load: self.pre_load,
            extensions: self.extensions,
            build_update_plugin: self.build_update_plugin,
            build_communication_plugin: plugin,
            initialize_tracing: self.initialize_tracing,
            shutdown_signal: self.shutdown_signal,
        }
    }
}

/// Installs the global HTTP protection guard, builds the authoritative communication plugin
/// runtime, and derives a narrow access view for UDS manager construction.
///
/// Diagnostic operations request activation directly at the point they need communication
/// (see `CommunicationAccess::request_activate`), so no HTTP-layer restriction is installed
/// here; `http_protections` remains for the runtime-update plugin's own protection.
async fn build_communication_runtime_and_access<SP, CPB>(
    ws: &ApplicationState,
    gateway: ComponentSlot<
        DiagnosticTransportRouter<DoipDiagGateway<EcuManager<SP>>, CanDiagGateway>,
    >,
    communication_plugin: CPB,
    init_mode: CommunicationInitMode,
    variant_detection: VariantDetectionMode,
    retry_after: Duration,
    http_protections: &HttpProtectionRegistry,
) -> Result<(CommunicationRuntime, Arc<dyn CommunicationAccess>), AppError>
where
    SP: SecurityPlugin,
    CPB: CommunicationPluginBuilder,
{
    cda_sovd::install_http_restriction_guard(
        &ws.dynamic_router,
        Arc::new(http_protections.clone()),
    )
    .await;

    let transport_control = gateway.transport_control();
    let communication_runtime = build_communication_runtime(
        communication_plugin,
        transport_control,
        init_mode,
        variant_detection,
    )
    .await
    .map_err(|error| AppError::InitializationFailed(error.to_string()))?;

    let communication_access: Arc<dyn CommunicationAccess> = Arc::new(
        CommunicationAccessView::new(Arc::clone(&communication_runtime.plugin), retry_after),
    );

    Ok((communication_runtime, communication_access))
}

/// Registers the UDS managers two communication hooks through the full
/// authoritative plugin, which delegates through its private controller.
///
/// Both halves come from one adapter but register separately, because the
/// framework treats them differently: the listener runs on every transport
/// enable, while the detection is the optional last stage that
/// `trigger_detection()` re-runs on its own.
async fn register_communication_hooks<SP>(
    plugin: &Arc<dyn CommunicationPlugin>,
    uds_manager: &ComponentSlot<UdsManagerType<SP>>,
) -> Result<(), AppError>
where
    SP: SecurityPlugin,
{
    let hooks = Arc::new(UdsCommunicationHooks {
        uds_manager: uds_manager.clone(),
    });
    plugin
        .register_lifecycle_hook(Arc::clone(&hooks) as Arc<dyn CommunicationLifecycle>)
        .await
        .map_err(|error| AppError::InitializationFailed(error.to_string()))?;
    plugin
        .register_variant_detection(hooks as Arc<dyn CommunicationVariantDetection>)
        .await
        .map_err(|error| AppError::InitializationFailed(error.to_string()))
}

/// `Always` initializes whole-vehicle communication eagerly at startup and propagates failure
/// according to existing application-start semantics. `OnDemand` and `Disabled` keep
/// communication uninitialized; HTTP/SOVD is already available via the routes registered
/// beforehand. In `OnDemand`, explicit `activate()` or a qualifying ECU request initializes
/// communication. The default plugin provides no activation path in `Disabled`.
async fn activate_communication_per_init_mode(
    plugin: &Arc<dyn CommunicationPlugin>,
    init_mode: CommunicationInitMode,
) -> Result<(), AppError> {
    match init_mode {
        CommunicationInitMode::Always => plugin
            .activate(ActivationCause::Startup)
            .await
            .map(|_| ())
            .map_err(AppError::from),
        CommunicationInitMode::OnDemand | CommunicationInitMode::Disabled => Ok(()),
    }
}

/// Builds the caller-supplied update plugin, if any, and mounts its HTTP routes.
async fn setup_update_plugin<SL, UPB>(
    ws: &ApplicationState,
    build_update_plugin: Option<UPB>,
    context: UpdatePluginContext,
    upload_body_limit_bytes: usize,
    update_retry_after: Duration,
) -> Result<(), AppError>
where
    SL: SecurityPluginLoader,
    UPB: UpdatePluginBuilder,
{
    let Some(builder) = build_update_plugin else {
        return Ok(());
    };

    // The builder owns its error type so implementations need not depend on
    // `AppError`; surface it verbatim.
    let plugin = builder.build(context).await.map_err(|error| {
        AppError::InitializationFailed(format!("Failed to build update plugin: {error}"))
    })?;
    add_runtime_update_routes::<SL, _>(
        &ws.dynamic_router,
        plugin,
        upload_body_limit_bytes,
        update_retry_after,
    )
    .await;

    Ok(())
}

/// Registers all SOVD routes, the runtime-update plugin, `OpenAPI` routes, and the update guard.
///
/// This is called after vehicle data has been loaded. The `build_update_plugin` optional
/// builder is consumed here; when `None` the runtime-update endpoints are simply not mounted.
pub(crate) async fn setup_runtime_routes<SP, SL, UPB, CPB>(
    config: Configuration,
    vehicle_data: VehicleData<SP>,
    ws: &ApplicationState,
    build_update_plugin: Option<UPB>,
    communication_plugin: CPB,
    extensions: Vec<ExtensionHook>,
) -> Result<CommunicationRuntime, AppError>
where
    SP: SecurityPlugin,
    SL: SecurityPluginLoader,
    UPB: UpdatePluginBuilder,
    CPB: CommunicationPluginBuilder,
{
    let flash_files_path = config.flash_files_path.clone();
    let components_config = config.components.clone();
    let mdd_decompress = config.flat_buf.mdd_decompress;

    let runtime_update_config = config.runtime_update_config.clone();
    let update_retry_after = Duration::from_secs(runtime_update_config.retry_after_seconds);
    let communication_retry_after =
        Duration::from_secs(config.communication.deferred_retry_after_seconds);
    let post_update_mode = config.communication.post_update_mode.clone();

    let lock_provider: Arc<cda_sovd::SovdLockStateProvider> = Arc::new(
        cda_sovd::SovdLockStateProvider::new(Arc::clone(&vehicle_data.locks)),
    );

    let gateway = vehicle_data.diagnostic_gateway.clone();
    let http_protections = HttpProtectionRegistry::new();

    let (communication_runtime, communication_access) = build_communication_runtime_and_access(
        ws,
        vehicle_data.diagnostic_gateway.clone(),
        communication_plugin,
        config.communication.init_mode,
        config.communication.variant_detection,
        communication_retry_after,
        &http_protections,
    )
    .await?;
    let plugin = Arc::clone(&communication_runtime.plugin);

    let components = finish_vehicle_components(
        vehicle_data.prepared,
        &config,
        Arc::clone(&communication_access),
    );
    let uds_manager = ComponentSlot::new(components.uds_manager);
    let file_managers = components.file_managers;

    register_communication_hooks(&plugin, &uds_manager).await?;

    let communication_disable: Arc<dyn DisableCommunication> =
        Arc::new(CommunicationDisableView::new(Arc::clone(&plugin)));

    // Routes are published only after the plugin, initializers, and narrow views are ready.
    let vehicle_route_handle = cda_sovd::add_vehicle_routes::<_, _, SL>(
        &ws.dynamic_router,
        cda_sovd::VehicleConfig {
            flash_files_path: config.flash_files_path.clone(),
            functional_group_config: config.functional_description.clone(),
            components_config: config.components.clone(),
        },
        cda_sovd::VehicleResources {
            ecu_uds: uds_manager.read().await.clone(),
            file_managers,
            locks: Arc::clone(&vehicle_data.locks),
            communication_access: Arc::clone(&communication_access),
        },
    )
    .await?;

    // Extensions run in registration order, each with its own context. Routes they
    // register land after the standard vehicle routes, and survive a later runtime
    // database update because the diagnostics capability holds the component slot
    // rather than a snapshot of it.
    let oem_config = Arc::new(config.oem.clone());
    for extension in extensions {
        extension(crate::extensions::ExtensionContext::new(
            ws.dynamic_router.clone(),
            uds_manager.clone(),
            Arc::clone(&vehicle_data.locks),
            ws.health_state.clone(),
            Arc::clone(&oem_config),
        ))
        .await?;
    }

    activate_communication_per_init_mode(&plugin, config.communication.init_mode).await?;

    let config = Arc::new(RwLock::new(config));
    let factory = Arc::new(crate::cda_factory::CdaMainVehicleFactory::<SP>::new(
        vehicle_data.health_providers,
        Arc::clone(&communication_access),
    ));
    let publisher = Arc::new(crate::update::CdaVehicleComponentPublisher::<SP, SL>::new(
        uds_manager,
        gateway,
        ws.dynamic_router.clone(),
        vehicle_route_handle,
        flash_files_path,
        components_config,
        Arc::clone(&lock_provider),
        Arc::clone(&communication_access),
    ));
    let reloader = Arc::new(
        cda_plugin_runtime_update::DefaultRuntimeReloaderPlugin::new(config, factory, publisher),
    );
    let context = UpdatePluginContext {
        reloader,
        lock_state: Arc::new(UpdateLockState::new(Arc::clone(&lock_provider)
            as Arc<dyn cda_interfaces::runtime_update_api::LockStateProvider>)),
        post_update_mode,
        communication_access,
        communication_disable,
        http_protections,
        update_retry_after,
        update_exempt_routes: cda_sovd::routes_accessible_during_update(),
        storage_dir: runtime_update_config.storage_dir.clone(),
        mdd_decompress,
    };

    setup_update_plugin::<SL, _>(
        ws,
        build_update_plugin,
        context,
        runtime_update_config.upload_body_limit_bytes,
        update_retry_after,
    )
    .await?;

    cda_sovd::add_openapi_routes(&ws.dynamic_router).await;

    Ok(communication_runtime)
}

#[cfg(test)]
mod tests {
    use cda_interfaces::runtime_update_api::{
        ExecutionMode, FileListOptions, RuntimeFile, RuntimeFileCatalog, RuntimeFileStore,
        RuntimeUpdateError, RuntimeUpdateExecutor, UpdateExecution,
    };
    use cda_plugin_security::{DefaultSecurityPlugin, DefaultSecurityPluginData};

    use super::*;
    use crate::update::{UpdatePluginFn, update_plugin_fn};

    // Minimal no-op plugin for type-checking.
    struct NoOpPlugin;

    #[async_trait::async_trait]
    impl RuntimeFileCatalog for NoOpPlugin {
        async fn list_current(
            &self,
            _options: FileListOptions,
        ) -> Result<Vec<RuntimeFile>, RuntimeUpdateError> {
            Ok(Vec::new())
        }

        async fn list_nextupdate(
            &self,
            _options: FileListOptions,
        ) -> Result<Vec<RuntimeFile>, RuntimeUpdateError> {
            Ok(Vec::new())
        }

        async fn list_backup(
            &self,
            _options: FileListOptions,
        ) -> Result<Vec<RuntimeFile>, RuntimeUpdateError> {
            Ok(Vec::new())
        }
    }

    #[async_trait::async_trait]
    impl RuntimeFileStore for NoOpPlugin {
        async fn authorize_mutation(
            &self,
            _security: &cda_interfaces::DynamicPlugin,
        ) -> Result<(), RuntimeUpdateError> {
            Ok(())
        }

        async fn upload(
            &self,
            _files: Vec<cda_interfaces::runtime_update_api::UploadFile>,
            _security: &cda_interfaces::DynamicPlugin,
        ) -> Result<Vec<String>, RuntimeUpdateError> {
            Ok(Vec::new())
        }

        async fn delete_nextupdate(
            &self,
            _security: &cda_interfaces::DynamicPlugin,
        ) -> Result<Vec<String>, RuntimeUpdateError> {
            Ok(vec![])
        }

        async fn delete_nextupdate_by_id(
            &self,
            _id: &str,
            _security: &cda_interfaces::DynamicPlugin,
        ) -> Result<(), RuntimeUpdateError> {
            Ok(())
        }

        async fn delete_backup(
            &self,
            _security: &cda_interfaces::DynamicPlugin,
        ) -> Result<Vec<String>, RuntimeUpdateError> {
            Ok(vec![])
        }
    }

    #[async_trait::async_trait]
    impl RuntimeUpdateExecutor for NoOpPlugin {
        async fn start_execution(
            &self,
            _mode: ExecutionMode,
            _security: &cda_interfaces::DynamicPlugin,
        ) -> Result<String, RuntimeUpdateError> {
            Ok(String::new())
        }

        async fn list_executions(&self) -> Vec<UpdateExecution> {
            vec![]
        }

        async fn get_execution_status(&self, _id: &str) -> Option<UpdateExecution> {
            None
        }
    }

    type TestSetup = Setup<DefaultSecurityPluginData, DefaultSecurityPlugin>;

    #[test]
    fn documented_public_api_type_checks() {
        let _: Option<UpdatePluginContext> = None;
    }

    #[test]
    fn new_has_no_preload_and_no_plugin() {
        let s = TestSetup::new();
        assert!(
            s.pre_load.is_none(),
            "fresh Setup must have no preload hook"
        );
        assert!(
            s.build_update_plugin.is_none(),
            "fresh Setup must have no update plugin"
        );
    }

    #[test]
    fn with_preload_stores_hook() {
        let s = TestSetup::new().with_preload(|_router| async { Ok(()) });
        assert!(
            s.pre_load.is_some(),
            "with_preload must store the provided hook"
        );
    }

    #[test]
    fn with_update_plugin_stores_builder() {
        // Use `update_plugin_fn` as a convenient closure adapter.
        let builder: UpdatePluginFn<_> =
            update_plugin_fn(|_infra: UpdatePluginContext| async { Ok::<_, AppError>(NoOpPlugin) });

        let s: Setup<DefaultSecurityPluginData, DefaultSecurityPlugin, _> =
            TestSetup::new().with_update_plugin(builder);

        assert!(
            s.build_update_plugin.is_some(),
            "with_update_plugin must store the provided builder"
        );
    }

    #[test]
    fn chaining_preload_then_plugin_retains_both() {
        let builder: UpdatePluginFn<_> =
            update_plugin_fn(|_infra: UpdatePluginContext| async { Ok::<_, AppError>(NoOpPlugin) });

        let s = TestSetup::new()
            .with_preload(|_| async { Ok(()) })
            .with_update_plugin(builder);

        assert!(s.pre_load.is_some(), "preload hook must survive chaining");
        assert!(
            s.build_update_plugin.is_some(),
            "plugin builder must be stored after chaining"
        );
    }

    #[test]
    fn chaining_plugin_then_preload_retains_both() {
        let builder: UpdatePluginFn<_> =
            update_plugin_fn(|_infra: UpdatePluginContext| async { Ok::<_, AppError>(NoOpPlugin) });

        let s = TestSetup::new()
            .with_update_plugin(builder)
            .with_preload(|_| async { Ok(()) });

        assert!(s.pre_load.is_some(), "preload hook must survive chaining");
        assert!(
            s.build_update_plugin.is_some(),
            "plugin builder must survive chaining"
        );
    }

    #[test]
    fn setup_without_an_update_plugin_is_accepted_by_the_run_functions() {
        // The docs say leaving `UPB = ()` mounts no runtime-update routes. That was
        // previously unreachable: `()` had no `UpdatePluginBuilder` impl, while every
        // `run_*` bounds `UPB: UpdatePluginBuilder`, so a default `Setup` could not be
        // passed to any of them. This pins the documented path down.
        fn accepts<SP, SL, UPB, CPB>(_setup: Setup<SP, SL, UPB, CPB>)
        where
            SP: SecurityPlugin,
            SL: SecurityPluginLoader,
            UPB: UpdatePluginBuilder,
            CPB: CommunicationPluginBuilder,
        {
        }

        let setup = TestSetup::new();
        assert!(
            setup.build_update_plugin.is_none(),
            "a default Setup must configure no update plugin"
        );
        accepts(setup);
    }

    #[test]
    fn extensions_compose_instead_of_overwriting() {
        let s = TestSetup::new()
            .with_extension(|_context| async { Ok(()) })
            .with_extension(|_context| async { Ok(()) });

        assert_eq!(
            s.extensions.len(),
            2,
            "a second with_extension must not discard the first"
        );
    }
}
