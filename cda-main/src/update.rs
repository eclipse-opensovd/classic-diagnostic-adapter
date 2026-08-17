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
use cda_comm_can::CanDiagGateway;
use cda_comm_doip::DoipDiagGateway;
use cda_core::EcuManager;
use cda_interfaces::{
    Shutdown, UdsQuery,
    communication_control::CommunicationAccess,
    component_slot::ComponentSlot,
    datatypes::ComponentsConfig,
    runtime_update_api::{
        ExecutionMode, FileListOptions, ReloadError, RuntimeFile, RuntimeFileCatalog,
        RuntimeFileInspector, RuntimeFileStore, RuntimeFilesUpdatePlugin, RuntimeUpdateError,
        RuntimeUpdateExecutor, RuntimeUpdateSecurityPlugin, UpdateExecution, UploadFile,
        VehicleComponentPublisher, VehicleComponents,
    },
};
use cda_plugin_runtime_update::{
    DefaultRuntimeUpdatePlugin, WithExclusiveAccess,
    default_runtime_update_plugin::RuntimeUpdatePluginParts,
};
use cda_plugin_security::{SecurityPlugin, SecurityPluginLoader};
use cda_sovd::SovdLockStateProvider;
use cda_storage::LocalStorage;
use cda_transport_router::DiagnosticTransportRouter;

use crate::{
    AppError,
    mdd_inspector::MddFileInspector,
    setup::{UpdateLockState, UpdatePluginContext},
    update_security::DefaultUpdateSecurityHandler,
    vehicle::UdsManagerType,
};

/// Builds the runtime-update plugin during startup.
///
/// Implementors are handed an [`UpdatePluginContext`] carrying only update
/// capabilities - no router, no live components, no security plugin type.
///
/// The associated [`Error`](Self::Error) means an implementation is not forced to
/// depend on `cda-main`'s [`AppError`]; startup reports it via [`Display`].
///
/// [`Display`]: std::fmt::Display
pub trait UpdatePluginBuilder: Send {
    type Plugin: RuntimeFilesUpdatePlugin;

    /// Reported verbatim by startup when [`build`](Self::build) fails.
    type Error: std::fmt::Display;

    fn build(
        self,
        context: UpdatePluginContext,
    ) -> impl Future<Output = Result<Self::Plugin, Self::Error>> + Send;
}

/// Uninhabited stand-in for "this `Setup` mounts no runtime-update routes".
///
/// [`Setup`](crate::Setup) defaults its builder parameter to `()`, and `()` builds
/// this. Having no values at all means every trait method below is unreachable by
/// construction rather than by a runtime assertion.
pub enum NoUpdatePlugin {}

#[async_trait::async_trait]
impl RuntimeFileCatalog for NoUpdatePlugin {
    async fn list_current(
        &self,
        _: FileListOptions,
    ) -> Result<Vec<RuntimeFile>, RuntimeUpdateError> {
        match *self {}
    }

    async fn list_nextupdate(
        &self,
        _: FileListOptions,
    ) -> Result<Vec<RuntimeFile>, RuntimeUpdateError> {
        match *self {}
    }

    async fn list_backup(
        &self,
        _: FileListOptions,
    ) -> Result<Vec<RuntimeFile>, RuntimeUpdateError> {
        match *self {}
    }
}

#[async_trait::async_trait]
impl RuntimeFileStore for NoUpdatePlugin {
    async fn authorize_mutation(
        &self,
        _: &cda_interfaces::DynamicPlugin,
    ) -> Result<(), RuntimeUpdateError> {
        match *self {}
    }

    async fn upload(
        &self,
        _: Vec<UploadFile>,
        _: &cda_interfaces::DynamicPlugin,
    ) -> Result<Vec<String>, RuntimeUpdateError> {
        match *self {}
    }

    async fn delete_nextupdate(
        &self,
        _: &cda_interfaces::DynamicPlugin,
    ) -> Result<Vec<String>, RuntimeUpdateError> {
        match *self {}
    }

    async fn delete_nextupdate_by_id(
        &self,
        _: &str,
        _: &cda_interfaces::DynamicPlugin,
    ) -> Result<(), RuntimeUpdateError> {
        match *self {}
    }

    async fn delete_backup(
        &self,
        _: &cda_interfaces::DynamicPlugin,
    ) -> Result<Vec<String>, RuntimeUpdateError> {
        match *self {}
    }
}

#[async_trait::async_trait]
impl RuntimeUpdateExecutor for NoUpdatePlugin {
    async fn start_execution(
        &self,
        _: ExecutionMode,
        _: &cda_interfaces::DynamicPlugin,
    ) -> Result<String, RuntimeUpdateError> {
        match *self {}
    }

    async fn list_executions(&self) -> Vec<UpdateExecution> {
        match *self {}
    }

    async fn get_execution_status(&self, _: &str) -> Option<UpdateExecution> {
        match *self {}
    }
}

/// Satisfies `Setup`'s default builder parameter so a `Setup` that configures no
/// update plugin can still be passed to the `run_*` functions.
///
/// [`Setup`](crate::Setup) leaves `build_update_plugin` as `None` in that case, so
/// startup skips the update routes without ever calling `build`.
impl UpdatePluginBuilder for () {
    type Plugin = NoUpdatePlugin;
    type Error = AppError;

    fn build(
        self,
        _context: UpdatePluginContext,
    ) -> impl Future<Output = Result<NoUpdatePlugin, AppError>> + Send {
        // Only reachable if `()` was passed to `with_update_plugin` explicitly.
        std::future::ready(Err(AppError::InitializationFailed(
            "`()` is the marker for `no runtime-update plugin`; omit `with_update_plugin` instead \
             of passing `()` to it"
                .to_owned(),
        )))
    }
}

pub struct UpdatePluginFn<F>(F);

/// Wraps a closure as an [`UpdatePluginBuilder`].
pub fn update_plugin_fn<F, Fut, P, E>(f: F) -> UpdatePluginFn<F>
where
    F: FnOnce(UpdatePluginContext) -> Fut + Send,
    Fut: Future<Output = Result<P, E>> + Send,
    P: RuntimeFilesUpdatePlugin,
    E: std::fmt::Display,
{
    UpdatePluginFn(f)
}

impl<F, Fut, P, E> UpdatePluginBuilder for UpdatePluginFn<F>
where
    F: FnOnce(UpdatePluginContext) -> Fut + Send,
    Fut: Future<Output = Result<P, E>> + Send,
    P: RuntimeFilesUpdatePlugin,
    E: std::fmt::Display,
{
    type Plugin = P;
    type Error = E;

    async fn build(self, context: UpdatePluginContext) -> Result<P, E> {
        self.0(context).await
    }
}

type GatewayType<SP> = DiagnosticTransportRouter<DoipDiagGateway<EcuManager<SP>>, CanDiagGateway>;

pub(crate) struct CdaVehicleComponentPublisher<SP, SL>
where
    SP: SecurityPlugin,
    SL: SecurityPluginLoader,
{
    uds_manager: ComponentSlot<UdsManagerType<SP>>,
    gateway: ComponentSlot<GatewayType<SP>>,
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
        uds_manager: ComponentSlot<UdsManagerType<SP>>,
        gateway: ComponentSlot<GatewayType<SP>>,
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

#[async_trait]
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
            uds_manager,
            diagnostic_gateway,
            file_managers,
            functional_group_config,
        } = components;
        let ecu_names = uds_manager.get_physical_ecus().await;
        let locks = self.lock_provider.current_locks();
        let previous_ecu_names = locks.ecu_names().await;
        let routes = cda_sovd::build_vehicle_routes::<_, _, SL>(
            cda_sovd::VehicleConfig {
                flash_files_path: self.flash_files_path.clone(),
                functional_group_config,
                components_config: self.components_config.clone(),
            },
            cda_sovd::VehicleResources {
                ecu_uds: uds_manager.clone(),
                file_managers,
                locks,
                communication_access: Arc::clone(&self.communication_access),
            },
        )
        .await;

        if let Err(error) = self.lock_provider.update_entries(ecu_names).await {
            uds_manager.shutdown().await;
            diagnostic_gateway.shutdown().await;
            return Err(ReloadError::ReplacementFailure(error.to_string()));
        }
        if let Err(error) = self
            .dynamic_router
            .replace_routes(&self.vehicle_route_handle, routes)
            .await
        {
            let rollback = self.lock_provider.update_entries(previous_ecu_names).await;
            uds_manager.shutdown().await;
            diagnostic_gateway.shutdown().await;
            rollback.map_err(|rollback_error| {
                ReloadError::ReplacementFailure(format!(
                    "Failed to publish routes: {error}; failed to restore lock topology: \
                     {rollback_error}"
                ))
            })?;
            return Err(ReloadError::ReplacementFailure(error.to_string()));
        }

        self.gateway.replacer().replace(diagnostic_gateway).await;
        self.uds_manager.replacer().replace(uds_manager).await;
        Ok(())
    }
}

/// Mounts the runtime-update routes over `plugin`.
///
/// No lock provider is threaded through: the HTTP layer transports the request
/// and renders the plugin's verdict, and the plugin decides authorization
/// through its configured [`RuntimeUpdateSecurityPlugin`]. The provider still
/// reaches that policy, via [`UpdatePluginContext::lock_state`].
///
/// [`UpdatePluginContext::lock_state`]: crate::setup::UpdatePluginContext::lock_state
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

/// Creates the standard runtime-file update plugin from narrow update capabilities.
///
/// Uses [`LocalStorage`], the default update-security handler and the MDD file
/// inspector. To keep the standard plugin but swap any of those - the storage
/// backend, the security policy, or the database format - use
/// [`create_update_plugin_with`] instead of reimplementing this.
///
/// # Errors
/// Returns [`AppError`] when persistent update storage cannot be initialized.
pub async fn create_default_update_plugin<SP: SecurityPlugin>(
    context: UpdatePluginContext,
) -> Result<impl RuntimeFilesUpdatePlugin, AppError> {
    let storage = Arc::new(LocalStorage::new(&context.storage_dir).map_err(|error| {
        AppError::InitializationFailed(format!("Failed to init storage, error={error:?}"))
    })?);
    let inspector: Arc<dyn RuntimeFileInspector> = Arc::new(MddFileInspector);
    let security = Arc::new(DefaultUpdateSecurityHandler::<UpdateLockState, SP>::new(
        Arc::clone(&inspector),
    ));

    Ok(create_update_plugin_with(
        context, storage, security, inspector,
    ))
}

/// Builds the standard runtime-file update plugin over caller-supplied
/// collaborators.
///
/// This is the composition point for the extension points listed in issue #504:
/// a custom `Storage` backend, a custom [`RuntimeUpdateSecurityPlugin`] policy, or
/// a non-MDD database format via [`RuntimeFileInspector`] - without reimplementing
/// the staging, apply, rollback and cleanup logic.
pub fn create_update_plugin_with<Store, Security>(
    context: UpdatePluginContext,
    storage: Arc<Store>,
    security_handler: Arc<Security>,
    file_inspector: Arc<dyn RuntimeFileInspector>,
) -> impl RuntimeFilesUpdatePlugin
where
    Store: cda_interfaces::storage_api::Storage + Send + Sync + 'static,
    Security: RuntimeUpdateSecurityPlugin<UpdateLockState, Store::CollectionHandle>,
{
    DefaultRuntimeUpdatePlugin::new(RuntimeUpdatePluginParts {
        storage,
        reloader_plugin: context.reloader,
        security_handler,
        lock_provider: context.lock_state,
        file_inspector,
        decompress_after_apply: context.mdd_decompress,
        communication_disable: context.communication_disable,
        communication_access: context.communication_access,
        http_protections: context.http_protections,
        update_exempt_routes: context.update_exempt_routes,
        update_retry_after: context.update_retry_after,
        post_update_mode: context.post_update_mode,
    })
}
