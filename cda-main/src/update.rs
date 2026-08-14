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

use cda_comm_can::CanDiagGateway;
use cda_comm_doip::DoipDiagGateway;
use cda_core::EcuManager;
use cda_interfaces::{
    Shutdown, UdsQuery,
    communication_control::CommunicationAccess,
    component_slot::ReplaceComponent,
    datatypes::ComponentsConfig,
    runtime_update_api::{
        ReloadError, RuntimeFilesUpdatePlugin, VehicleComponentPublisher, VehicleComponents,
    },
};
use cda_plugin_runtime_update::{
    DefaultRuntimeReloaderPlugin, DefaultRuntimeUpdatePlugin, WithExclusiveAccess,
};
use cda_plugin_security::{SecurityPlugin, SecurityPluginLoader};
use cda_sovd::SovdLockStateProvider;
use cda_storage::LocalStorage;
use cda_transport_router::DiagnosticTransportRouter;

use crate::{
    AppError, cda_factory::CdaMainVehicleFactory, config::configfile::Configuration,
    setup::CdaRuntime, update_security::DefaultUpdateSecurityHandler, vehicle::UdsManagerType,
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
/// [`ExclusiveRuntimePlugin`](cda_plugin_runtime_update::ExclusiveRuntimePlugin) for
/// read/write mutual exclusion and
/// mounts the HTTP endpoints by delegating to [`cda_sovd::add_runtime_update_routes`].
/// The caller is responsible for constructing the plugin before calling this function.
type GatewayType<SP> = DiagnosticTransportRouter<DoipDiagGateway<EcuManager<SP>>, CanDiagGateway>;

/// Publishes a freshly built component generation into the live runtime.
///
/// This is the half of a reload that needs `cda-sovd`: rebuilding the vehicle
/// routes over the new components. Keeping it here is what lets the update
/// plugin orchestrate reloads without depending on the HTTP layer.
pub(crate) struct CdaVehicleComponentPublisher<SP, SL>
where
    SP: SecurityPlugin,
    SL: SecurityPluginLoader,
{
    uds_manager: Arc<dyn ReplaceComponent<UdsManagerType<SP>>>,
    gateway: Arc<dyn ReplaceComponent<GatewayType<SP>>>,
    dynamic_router: cda_sovd::dynamic_router::DynamicRouter,
    vehicle_route_handle: cda_sovd::RouteHandle,
    flash_files_path: String,
    components_config: ComponentsConfig,
    lock_provider: Arc<SovdLockStateProvider>,
    communication_access: Arc<dyn CommunicationAccess>,
    _security_loader: std::marker::PhantomData<SL>,
}

impl<SP, SL> CdaVehicleComponentPublisher<SP, SL>
where
    SP: SecurityPlugin,
    SL: SecurityPluginLoader,
{
    #[allow(
        clippy::too_many_arguments,
        reason = "Application composition boundary"
    )]
    pub(crate) fn new(
        uds_manager: Arc<dyn ReplaceComponent<UdsManagerType<SP>>>,
        gateway: Arc<dyn ReplaceComponent<GatewayType<SP>>>,
        dynamic_router: cda_sovd::dynamic_router::DynamicRouter,
        vehicle_route_handle: cda_sovd::RouteHandle,
        flash_files_path: String,
        components_config: ComponentsConfig,
        lock_provider: Arc<SovdLockStateProvider>,
        communication_access: Arc<dyn CommunicationAccess>,
    ) -> Self {
        Self {
            uds_manager,
            gateway,
            dynamic_router,
            vehicle_route_handle,
            flash_files_path,
            components_config,
            lock_provider,
            communication_access,
            _security_loader: std::marker::PhantomData,
        }
    }
}

#[async_trait::async_trait]
impl<SP, SL>
    VehicleComponentPublisher<UdsManagerType<SP>, GatewayType<SP>, cda_database::FileManager>
    for CdaVehicleComponentPublisher<SP, SL>
where
    SP: SecurityPlugin,
    SL: SecurityPluginLoader,
{
    async fn publish(
        &self,
        components: VehicleComponents<
            UdsManagerType<SP>,
            GatewayType<SP>,
            cda_database::FileManager,
        >,
    ) -> Result<(), ReloadError> {
        let VehicleComponents {
            uds_manager: new_uds,
            diagnostic_gateway: new_gateway,
            file_managers,
            functional_group_config,
        } = components;

        let ecu_names = new_uds.get_physical_ecus().await;
        if let Err(e) = self.lock_provider.update_entries(ecu_names).await {
            // The freshly built components never went live; shut them down here,
            // or they keep holding their transport resources until process exit.
            new_gateway.shutdown().await;
            new_uds.shutdown().await;
            return Err(ReloadError::General(format!(
                "Failed to update runtime locks: {e}"
            )));
        }
        let current_locks = self.lock_provider.current_locks().await;

        let vehicle_router = cda_sovd::build_vehicle_routes::<_, _, SL>(
            cda_sovd::VehicleConfig {
                flash_files_path: self.flash_files_path.clone(),
                functional_group_config,
                components_config: self.components_config.clone(),
            },
            cda_sovd::VehicleResources {
                ecu_uds: new_uds.clone(),
                file_managers,
                locks: current_locks,
                communication_access: Arc::clone(&self.communication_access),
            },
        )
        .await;

        if let Err(e) = self
            .dynamic_router
            .replace_routes(&self.vehicle_route_handle, vehicle_router)
            .await
        {
            new_gateway.shutdown().await;
            new_uds.shutdown().await;
            return Err(ReloadError::ReplacementFailure(format!(
                "Failed to replace vehicle routes: {e}"
            )));
        }

        // Only now swap the live components: the routes just installed already
        // hold their own clone of the new UDS manager, so the old one can go.
        self.gateway.replace(new_gateway).await;
        self.uds_manager.replace(new_uds).await;
        Ok(())
    }
}

pub async fn add_runtime_update_routes<S, P>(
    dynamic_router: &cda_sovd::dynamic_router::DynamicRouter,
    plugin: P,
    upload_body_limit_bytes: usize,
    update_retry_after: Duration,
) where
    S: SecurityPluginLoader,
    P: RuntimeFilesUpdatePlugin,
{
    let service = Arc::new(WithExclusiveAccess::with_exclusive_access(plugin));
    cda_sovd::add_runtime_update_routes::<S, _>(
        dynamic_router,
        service,
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
/// - `infra`: The runtime infrastructure containing all CDA components
///
/// # Errors
/// Returns [`AppError::RuntimeUpdateError`] if plugin initialization fails.
pub async fn create_default_update_plugin<SP, SL>(
    infra: CdaRuntime<SP>,
) -> Result<impl RuntimeFilesUpdatePlugin, AppError>
where
    SP: SecurityPlugin,
    SL: SecurityPluginLoader,
{
    let health_for_factory = infra.health.clone();
    let factory = Arc::new(CdaMainVehicleFactory::<SP>::new(
        health_for_factory,
        Arc::clone(&infra.communication_access),
    ));

    let storage = Arc::new(LocalStorage::new(&infra.storage_dir).map_err(|e| {
        AppError::InitializationFailed(format!("Failed to init storage, error={e:?}"))
    })?);

    // The application supplies the database format; the plugin stays agnostic.
    let file_inspector: Arc<dyn cda_interfaces::runtime_update_api::RuntimeFileInspector> =
        Arc::new(crate::mdd_inspector::MddFileInspector);

    let publisher = Arc::new(CdaVehicleComponentPublisher::<SP, SL>::new(
        infra.uds_manager_replacer,
        infra.gateway_replacer,
        infra.dynamic_router,
        infra.vehicle_route_handle,
        infra.flash_files_path,
        infra.components_config,
        Arc::clone(&infra.lock_provider),
        Arc::clone(&infra.communication_access),
    ));

    let reloader_plugin = Arc::new(DefaultRuntimeReloaderPlugin::new(
        infra.config,
        factory,
        publisher,
    ));

    Ok(DefaultRuntimeUpdatePlugin::new(
        storage,
        reloader_plugin,
        Arc::new(DefaultUpdateSecurityHandler::<_, SP>::new(Arc::clone(
            &file_inspector,
        ))),
        Arc::clone(&infra.lock_provider),
        infra.mdd_decompress,
        Arc::clone(&file_inspector),
        infra.communication_disable,
        Arc::clone(&infra.communication_access),
        infra.http_protections,
        // The set of routes that stay reachable while an update holds its
        // protection is a SOVD fact, so the application supplies it.
        cda_sovd::routes_accessible_during_update(),
        infra.update_retry_after,
        infra.post_update_mode,
    ))
}
