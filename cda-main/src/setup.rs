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
//! implementation before handing the `Setup` to one of the `run_*` functions.
//!
//! [`RuntimeFilesUpdatePlugin`]: cda_interfaces::runtime_update_api::RuntimeFilesUpdatePlugin

use std::{future::Future, sync::Arc};

use cda_comm_can::CanDiagGateway;
use cda_comm_doip::DoipDiagGateway;
use cda_comm_uds::FlashTransferObserver;
use cda_core::EcuManager;
use cda_interfaces::{HashMap, ShutdownSignal, health::HealthProvider};
use cda_plugin_security::{SecurityPlugin, SecurityPluginLoader};
use cda_transport_orchestrator::DiagnosticTransportRouter;
use futures::future::BoxFuture;
use tokio::sync::{Mutex, RwLock};

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
pub struct CdaRuntime<SP: SecurityPlugin> {
    pub config: Arc<RwLock<Configuration>>,
    pub uds_manager: Arc<RwLock<UdsManagerType<SP>>>,
    pub gateway:
        Arc<RwLock<DiagnosticTransportRouter<DoipDiagGateway<EcuManager<SP>>, CanDiagGateway>>>,
    pub dynamic_router: cda_sovd::dynamic_router::DynamicRouter,
    pub vehicle_route_handle: cda_sovd::RouteHandle,
    pub lock_provider: Arc<cda_sovd::SovdLockStateProvider>,
    pub ecu_execution_registry: cda_sovd::EcuExecutionRegistry,
    pub update_guard: cda_sovd::UpdateGuardState,
    pub update_in_progress: Arc<std::sync::atomic::AtomicBool>,
    pub flash_files_path: String,
    pub components_config: cda_interfaces::datatypes::ComponentsConfig,
    pub variant_detection_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
    pub health: Option<HashMap<String, Arc<dyn HealthProvider>>>,
    pub flash_transfer_guard: FlashTransferObserver,
    pub storage_dir: String,
    pub mdd_decompress: bool,
    pub shutdown_signal: ShutdownSignal,
}

// Setup

/// Builder for customising the CDA startup sequence.
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
///     }));
///
/// opensovd_cda_lib::run_with_ext_from_config(config, setup).await?;
/// ```
///
/// When no update plugin is configured (`UpdatePluginBuilder = ()`) the runtime-update routes
/// are **not** mounted. Pass a builder, typically via [`update_plugin_fn`] or by implementing
/// [`UpdatePluginBuilder`], to enable them.
///
/// [`update_plugin_fn`]: crate::update::update_plugin_fn
/// [`UpdatePluginBuilder`]: crate::update::UpdatePluginBuilder
pub struct Setup<SP: SecurityPlugin, SL: SecurityPluginLoader, UPB = ()> {
    pub(crate) _phantom: std::marker::PhantomData<(SP, SL)>,

    /// Optional callback run after the webserver starts but before vehicle data is loaded.
    pub(crate) pre_load: Option<PreLoadHook>,

    /// Optional update-plugin builder. When `None` (or `UPB = ()`) the runtime-update
    /// routes are not registered.
    pub(crate) build_update_plugin: Option<UPB>,
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
        }
    }
}

impl<SP: SecurityPlugin, SL: SecurityPluginLoader, UPB> Setup<SP, SL, UPB> {
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
    ) -> Setup<SP, SL, UPB2> {
        Setup {
            _phantom: self._phantom,
            pre_load: self.pre_load,
            build_update_plugin: Some(builder),
        }
    }
}

// Route setup

/// Registers all SOVD routes, the runtime-update plugin, `OpenAPI` routes, and the update guard.
///
/// This is called after vehicle data has been loaded. The `build_update_plugin` optional
/// builder is consumed here; when `None` the runtime-update endpoints are simply not mounted.
pub(crate) async fn setup_runtime_routes<SP, SL, UPB>(
    config: Configuration,
    vehicle_data: VehicleData<SP>,
    ws: &ApplicationState,
    build_update_plugin: Option<UPB>,
) -> Result<(), AppError>
where
    SP: SecurityPlugin,
    SL: SecurityPluginLoader,
    UPB: UpdatePluginBuilder<SP>,
{
    let flash_files_path = config.flash_files_path.clone();
    let components_config = config.components.clone();
    let runtime_update_config = config.runtime_update_config.clone();
    let mdd_decompress = config.flat_buf.mdd_decompress;

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
    let update_in_progress = vehicle_data.update_guard.busy_handle();

    let shutdown_signal = cda_interfaces::shutdown_signal(ws.shutdown_signal.clone());

    // Build the CdaRuntime context for the update plugin builder.
    let infra = CdaRuntime {
        config: Arc::new(RwLock::new(config)),
        dynamic_router: ws.dynamic_router.clone(),
        vehicle_route_handle,
        flash_files_path,
        components_config,
        lock_provider: Arc::clone(&lock_provider),
        update_guard: vehicle_data.update_guard.clone(),
        shutdown_signal,
        uds_manager: Arc::new(RwLock::new(vehicle_data.uds_manager)),
        gateway: Arc::new(RwLock::new(vehicle_data.diagnostic_gateway)),
        ecu_execution_registry: ecu_execution_registry.clone(),
        health: vehicle_data.health_providers,
        variant_detection_handle: Mutex::new(Some(vehicle_data.variant_detection_handle)),
        storage_dir: runtime_update_config.storage_dir.clone(),
        mdd_decompress,
        flash_transfer_guard,
        update_in_progress,
    };

    // Invoke the builder (if any) and mount the update plugin.
    if let Some(builder) = build_update_plugin {
        let plugin = builder.build(infra).await?;
        add_runtime_update_routes::<SL, _>(
            &ws.dynamic_router,
            plugin,
            lock_provider,
            &vehicle_data.update_guard,
            runtime_update_config.upload_body_limit_bytes,
            runtime_update_config.retry_after_seconds,
        )
        .await;
    }

    cda_sovd::add_openapi_routes(&ws.dynamic_router, &vehicle_data.update_guard).await;
    cda_sovd::install_update_guard(&ws.dynamic_router, vehicle_data.update_guard.clone()).await;

    Ok(())
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
