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
    HashMap, ShutdownSignal,
    communication_control::{
        ActivationCause, CommunicationAccess, CommunicationInitMode, CommunicationLifecycle,
        CommunicationVariantDetection, PostUpdateCommunicationMode, VariantDetectionMode,
        error::CommControlError,
    },
    component_slot::{ComponentSlot, ReplaceComponent},
    health::HealthProvider,
    http_protection::registry::HttpProtectionRegistry,
};
use cda_plugin_communication_management::{
    lifecycle::{
        CommunicationRuntime,
        access::CommunicationAccessView,
        build_communication_runtime,
        disable::{CommunicationDisableView, DisableCommunication},
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
    ApplicationState, UdsManagerType, VehicleData,
    config::configfile::Configuration,
    error::AppError,
    update::{UpdatePluginBuilder, add_runtime_update_routes},
};

// Type alias

/// Boxed async callback executed after the webserver starts but **before** vehicle data is
/// loaded. Receives the dynamic router so it can register early routes.
pub(crate) type PreLoadHook = Box<
    dyn FnOnce(cda_sovd::dynamic_router::DynamicRouter) -> BoxFuture<'static, Result<(), AppError>>
        + Send,
>;

/// Runtime context produced during CDA initialization and provided to update-plugin builders.
///
/// `gateway_replacer` and `uds_manager_replacer` are replace-only. An update plugin can
/// install a freshly built component, but has no read access, and therefore no operational
/// authority, over the live gateway or UDS manager.
pub struct CdaRuntime<SP: SecurityPlugin> {
    pub config: Arc<RwLock<Configuration>>,
    pub uds_manager_replacer: Arc<dyn ReplaceComponent<UdsManagerType<SP>>>,
    pub gateway_replacer: Arc<
        dyn ReplaceComponent<
            DiagnosticTransportRouter<DoipDiagGateway<EcuManager<SP>>, CanDiagGateway>,
        >,
    >,
    pub dynamic_router: cda_sovd::dynamic_router::DynamicRouter,
    pub vehicle_route_handle: cda_sovd::RouteHandle,
    pub lock_provider: Arc<cda_sovd::SovdLockStateProvider>,
    pub flash_files_path: String,
    pub components_config: cda_interfaces::datatypes::ComponentsConfig,
    pub health: Option<HashMap<String, Arc<dyn HealthProvider>>>,
    pub storage_dir: String,
    pub mdd_decompress: bool,
    pub shutdown_signal: ShutdownSignal,
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
}

/// Bridges the `RwLock`-wrapped `UdsManager` to both communication-framework
/// hook traits. The `UdsManager` implements each half itself, so this only
/// forwards through the lock.
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

    /// Configures a custom runtime update plugin.
    ///
    /// `builder` will be called after vehicle data is loaded and routes are registered. It
    /// receives the complete [`CdaRuntime`] context so it can access the UDS manager, `DoIP`
    /// gateway, storage directory, lock provider, and every other piece of infrastructure it
    /// needs.
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
    /// [`ExclusiveRuntimePlugin`]: cda_interfaces::runtime_update_api::ExclusiveRuntimePlugin
    /// [`update_plugin_fn`]: crate::update::update_plugin_fn
    pub fn with_update_plugin<UPB2: UpdatePluginBuilder<SP>>(
        self,
        builder: UPB2,
    ) -> Setup<SP, SL, UPB2, CPB> {
        Setup {
            _phantom: self._phantom,
            pre_load: self.pre_load,
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
/// Diagnostic operations request activation directly (see
/// `CommunicationAccess::request_activate`), so `http_protections` is left to the
/// runtime-update plugin's own protection.
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

/// Registers the UDS manager's two communication hooks through the authoritative
/// plugin.
///
/// Both halves come from one adapter but register separately. The listener runs
/// on every transport enable, while detection is the optional last stage that
/// `trigger_detection()` can run on its own.
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

/// `Always` initializes whole-vehicle communication eagerly at startup and propagates
/// failure according to existing application-start semantics. `OnDemand` and `Disabled`
/// leave it uninitialized, with HTTP/SOVD already served by the routes registered
/// beforehand. Under `OnDemand` an explicit `activate()` or a qualifying ECU request
/// initializes it. The default plugin offers no activation path under `Disabled`.
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
async fn setup_update_plugin<SP, SL, UPB>(
    ws: &ApplicationState,
    build_update_plugin: Option<UPB>,
    infra: CdaRuntime<SP>,
    lock_provider: Arc<cda_sovd::SovdLockStateProvider>,
    upload_body_limit_bytes: usize,
    update_retry_after: Duration,
) -> Result<(), AppError>
where
    SP: SecurityPlugin,
    SL: SecurityPluginLoader,
    UPB: UpdatePluginBuilder<SP>,
{
    let Some(builder) = build_update_plugin else {
        return Ok(());
    };

    let plugin = builder.build(infra).await?;
    add_runtime_update_routes::<SL, _>(
        &ws.dynamic_router,
        plugin,
        lock_provider,
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
) -> Result<CommunicationRuntime, AppError>
where
    SP: SecurityPlugin,
    SL: SecurityPluginLoader,
    UPB: UpdatePluginBuilder<SP>,
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

    let shutdown_signal = cda_interfaces::shutdown_signal(ws.shutdown_signal.clone());
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

    let components = crate::finish_vehicle_components(
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

    activate_communication_per_init_mode(&plugin, config.communication.init_mode).await?;

    let infra = CdaRuntime {
        config: Arc::new(RwLock::new(config)),
        dynamic_router: ws.dynamic_router.clone(),
        vehicle_route_handle,
        flash_files_path,
        components_config,
        lock_provider: Arc::clone(&lock_provider),
        shutdown_signal,
        post_update_mode,
        communication_access,
        communication_disable,
        http_protections,
        update_retry_after,
        uds_manager_replacer: uds_manager.replacer(),
        gateway_replacer: gateway.replacer(),
        health: vehicle_data.health_providers,
        storage_dir: runtime_update_config.storage_dir.clone(),
        mdd_decompress,
    };

    setup_update_plugin::<SP, SL, _>(
        ws,
        build_update_plugin,
        infra,
        lock_provider,
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
        BulkDataCreatedList, BulkDataList, ExecutionMode, RuntimeFilesQuery,
        RuntimeFilesUpdatePlugin, RuntimeUpdateError, UpdateExecution,
    };
    use cda_plugin_security::{DefaultSecurityPlugin, DefaultSecurityPluginData};

    use super::*;
    use crate::update::{UpdatePluginFn, update_plugin_fn};

    // Minimal no-op plugin for type-checking.
    struct NoOpPlugin;

    #[async_trait::async_trait]
    impl RuntimeFilesUpdatePlugin for NoOpPlugin {
        async fn list_current(
            &self,
            _q: &RuntimeFilesQuery,
        ) -> Result<BulkDataList, RuntimeUpdateError> {
            Ok(BulkDataList::default())
        }

        async fn list_nextupdate(
            &self,
            _q: &RuntimeFilesQuery,
        ) -> Result<BulkDataList, RuntimeUpdateError> {
            Ok(BulkDataList::default())
        }

        async fn list_backup(
            &self,
            _q: &RuntimeFilesQuery,
        ) -> Result<BulkDataList, RuntimeUpdateError> {
            Ok(BulkDataList::default())
        }

        async fn upload(
            &self,
            _files: Vec<cda_interfaces::runtime_update_api::UploadFile>,
        ) -> Result<BulkDataCreatedList, RuntimeUpdateError> {
            Ok(BulkDataCreatedList::default())
        }

        async fn delete_nextupdate(&self) -> Result<Vec<String>, RuntimeUpdateError> {
            Ok(vec![])
        }

        async fn delete_nextupdate_by_id(&self, _id: &str) -> Result<(), RuntimeUpdateError> {
            Ok(())
        }

        async fn delete_backup(&self) -> Result<Vec<String>, RuntimeUpdateError> {
            Ok(vec![])
        }

        async fn start_execution(
            &self,
            _mode: ExecutionMode,
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
        let _: Option<CdaRuntime<DefaultSecurityPluginData>> = None;
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
            update_plugin_fn(|_infra: CdaRuntime<DefaultSecurityPluginData>| async {
                Ok(NoOpPlugin)
            });

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
            update_plugin_fn(|_infra: CdaRuntime<DefaultSecurityPluginData>| async {
                Ok(NoOpPlugin)
            });

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
            update_plugin_fn(|_infra: CdaRuntime<DefaultSecurityPluginData>| async {
                Ok(NoOpPlugin)
            });

        let s = TestSetup::new()
            .with_update_plugin(builder)
            .with_preload(|_| async { Ok(()) });

        assert!(s.pre_load.is_some(), "preload hook must survive chaining");
        assert!(
            s.build_update_plugin.is_some(),
            "plugin builder must survive chaining"
        );
    }
}
