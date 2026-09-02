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
use cda_interfaces::{
    HashMap, SchemaProvider, Shutdown, ShutdownSignal, UdsEcu,
    communication_control::CommunicationAccess,
    component_slot::ReplaceComponent,
    datatypes::ComponentsConfig,
    health::HealthProvider,
    runtime_update_api::{
        ReloadError, RuntimeReloaderPlugin, VehicleComponentFactory, VehicleComponents,
    },
    storage_api::Storage,
};
use cda_plugin_security::SecurityPluginLoader;
use cda_sovd::{SovdLockStateProvider, dynamic_router::DynamicRouter};
use tokio::sync::RwLock;

/// Context for the runtime reload operation.
///
/// This struct contains all the components needed to reload runtime databases
/// and configuration. It bundles the infrastructure required by the reloader plugin.
///
/// `uds_manager` and `diagnostic_gateway` are replace-only capabilities. This plugin can
/// install a freshly built component but has no read access to the live one, and therefore
/// no operational authority over it.
pub struct DefaultReloadContext<Uds, Gateway, Config, S>
where
    Uds: UdsEcu + SchemaProvider + Clone + Shutdown + Send + Sync + 'static,
    Gateway: Shutdown,
    Config: Clone + serde::de::DeserializeOwned + Send + Sync + 'static,
    S: Storage + Send + Sync + 'static,
{
    /// Application configuration
    pub config: Arc<RwLock<Config>>,

    /// Replace-only capability over the vehicle diagnostic manager
    pub uds_manager: Arc<dyn ReplaceComponent<Uds>>,

    /// Replace-only capability over the diagnostic gateway across all configured transports
    pub diagnostic_gateway: Arc<dyn ReplaceComponent<Gateway>>,

    /// Dynamic router for hot-swapping routes
    pub dynamic_router: DynamicRouter,

    /// Handle for vehicle route registration/replacement
    pub vehicle_route_handle: cda_sovd::RouteHandle,

    /// Lock state provider for SOVD locks
    pub lock_provider: Arc<SovdLockStateProvider>,

    /// Path for flash files
    pub flash_files_path: String,

    /// Component configuration
    pub components_config: ComponentsConfig,

    /// Health providers for monitoring
    pub health: Option<HashMap<String, Arc<dyn HealthProvider>>>,

    /// Whether to decompress MDD files after apply
    pub mdd_decompress: bool,

    /// Shutdown signal for graceful termination
    pub shutdown_signal: ShutdownSignal,

    /// Shared coordinator used by rebuilt SOVD routes.
    pub communication_access: Arc<dyn CommunicationAccess>,

    /// Persistent storage used to execute automatic rollback when installing the
    /// newly built components fails.
    pub storage: Arc<S>,
}

/// Shared state for installing vehicle routes.
///
/// Contains exactly the fields needed for route installation, allowing both
/// [`DefaultRuntimeReloaderPlugin`] and rollback handlers to share a single
/// implementation of `install_routes` without duplicating logic or fields.
pub struct RouteInstallState<Uds, Gateway>
where
    Uds: UdsEcu + SchemaProvider + Clone + Shutdown + Send + Sync + 'static,
    Gateway: Shutdown,
{
    lock_provider: Arc<SovdLockStateProvider>,
    dynamic_router: DynamicRouter,
    vehicle_route_handle: cda_sovd::RouteHandle,
    flash_files_path: String,
    components_config: ComponentsConfig,
    communication_access: Arc<dyn CommunicationAccess>,
    uds_manager: Arc<dyn ReplaceComponent<Uds>>,
    diagnostic_gateway: Arc<dyn ReplaceComponent<Gateway>>,
}

impl<Uds, Gateway> RouteInstallState<Uds, Gateway>
where
    Uds: UdsEcu + SchemaProvider + Clone + Shutdown + Send + Sync + 'static,
    Gateway: Shutdown,
{
    async fn install_routes<M, SecurityLoader>(
        &self,
        components: VehicleComponents<Uds, Gateway, M>,
    ) -> Result<(), ReloadError>
    where
        M: cda_interfaces::file_manager::FileManager,
        SecurityLoader: SecurityPluginLoader,
    {
        let VehicleComponents {
            uds_manager: new_uds,
            diagnostic_gateway: new_gateway,
            file_managers,
            functional_group_config,
        } = components;

        let ecu_names = new_uds.get_physical_ecus().await;
        if let Err(e) = self.lock_provider.update_entries(ecu_names).await {
            // These never went live, and would hold their transport resources
            // until process exit.
            new_gateway.shutdown().await;
            new_uds.shutdown().await;
            return Err(ReloadError::General(format!(
                "Failed to update runtime locks: {e}"
            )));
        }
        let current_locks = self.lock_provider.current_locks().await;

        let vehicle_router = cda_sovd::build_vehicle_routes::<_, _, SecurityLoader>(
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

        // Swapped only now. The routes installed above already hold their own
        // clone of the new `uds_manager`, so the old one can be shut down. Doing
        // this before `replace_routes` would leave the still-installed old
        // routes, among them update-exempt ones like `POST /vehicle/v15/locks`,
        // holding an already shut-down component.
        self.diagnostic_gateway.replace(new_gateway).await;
        self.uds_manager.replace(new_uds).await;

        Ok(())
    }
}

/// Default reload handler for runtime database updates.
///
/// Implements [`RuntimeReloaderPlugin`] by:
/// - Delegating component creation to a [`VehicleComponentFactory`]
/// - Replacing running routes via the [`DynamicRouter`]
/// - Rolling back from the persistent backup when installation fails
///
/// Transport disable/enable is owned by `start_execution` in the runtime-update
/// plugin. `reload_databases` only replaces components.
pub struct DefaultRuntimeReloaderPlugin<Uds, Gateway, Config, SecurityLoader, VehicleFactory, S>
where
    Uds: UdsEcu + SchemaProvider + Clone + Shutdown + Send + Sync + 'static,
    Gateway: Shutdown,
    Config: Clone + serde::de::DeserializeOwned + Send + Sync + 'static,
    SecurityLoader: SecurityPluginLoader,
    VehicleFactory: VehicleComponentFactory<Config, Uds, Gateway>,
    S: Storage + Send + Sync + 'static,
{
    config: Arc<RwLock<Config>>,
    route_state: Arc<RouteInstallState<Uds, Gateway>>,
    factory: Arc<VehicleFactory>,
    storage: Arc<S>,
    _phantom: std::marker::PhantomData<SecurityLoader>,
}

/// Configuration for creating a [`DefaultRuntimeReloaderPlugin`].
///
/// This bundles the [`DefaultReloadContext`] with a [`VehicleComponentFactory`]
/// to simplify plugin construction.
pub struct RuntimeReloaderConfig<Uds, Gateway, Config, VehicleFactory, S>
where
    Uds: UdsEcu + SchemaProvider + Clone + Shutdown + Send + Sync + 'static,
    Gateway: Shutdown,
    Config: Clone + serde::de::DeserializeOwned + Send + Sync + 'static,
    VehicleFactory: VehicleComponentFactory<Config, Uds, Gateway>,
    S: Storage + Send + Sync + 'static,
{
    /// Runtime context containing all CDA components.
    pub infrastructure: DefaultReloadContext<Uds, Gateway, Config, S>,
    /// Factory for creating vehicle components on reload.
    pub factory: Arc<VehicleFactory>,
}

impl<Uds, Gateway, Config, VehicleFactory, S>
    RuntimeReloaderConfig<Uds, Gateway, Config, VehicleFactory, S>
where
    Uds: UdsEcu + SchemaProvider + Clone + Shutdown + Send + Sync + 'static,
    Gateway: Shutdown,
    Config: Clone + serde::de::DeserializeOwned + Send + Sync + 'static,
    VehicleFactory: VehicleComponentFactory<Config, Uds, Gateway>,
    S: Storage + Send + Sync + 'static,
{
    /// Creates a new [`RuntimeReloaderConfig`] from context and a factory.
    #[must_use]
    pub fn new(
        infrastructure: DefaultReloadContext<Uds, Gateway, Config, S>,
        factory: Arc<VehicleFactory>,
    ) -> Self {
        Self {
            infrastructure,
            factory,
        }
    }
}

impl<Uds, Gateway, Config, SecurityLoader, VehicleFactory, S>
    DefaultRuntimeReloaderPlugin<Uds, Gateway, Config, SecurityLoader, VehicleFactory, S>
where
    Uds: UdsEcu + SchemaProvider + Clone + Shutdown + Send + Sync + 'static,
    Gateway: Shutdown,
    Config: Clone + serde::de::DeserializeOwned + Send + Sync + 'static,
    SecurityLoader: SecurityPluginLoader,
    VehicleFactory: VehicleComponentFactory<Config, Uds, Gateway>,
    S: Storage + Send + Sync + 'static,
{
    /// Creates a new [`DefaultRuntimeReloaderPlugin`] from a [`RuntimeReloaderConfig`].
    #[must_use]
    pub fn new(config: RuntimeReloaderConfig<Uds, Gateway, Config, VehicleFactory, S>) -> Self {
        let route_state = Arc::new(RouteInstallState {
            lock_provider: config.infrastructure.lock_provider,
            dynamic_router: config.infrastructure.dynamic_router,
            vehicle_route_handle: config.infrastructure.vehicle_route_handle,
            flash_files_path: config.infrastructure.flash_files_path,
            components_config: config.infrastructure.components_config,
            communication_access: config.infrastructure.communication_access,
            uds_manager: config.infrastructure.uds_manager,
            diagnostic_gateway: config.infrastructure.diagnostic_gateway,
        });

        Self {
            config: config.infrastructure.config,
            route_state,
            factory: config.factory,
            storage: config.infrastructure.storage,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Creates new vehicle components, installs them, and makes them live.
    ///
    /// Nothing is torn down before the new components exist, so a failure here
    /// leaves the live runtime untouched. The caller still rolls back, because
    /// it already switched the persisted files.
    async fn install_new_runtime(
        &self,
        cfg: Config,
        mdd_paths: &[PathBuf],
    ) -> Result<(), ReloadError> {
        let components = self.factory.create(&cfg, mdd_paths).await?;

        self.route_state
            .install_routes::<_, SecurityLoader>(components)
            .await
    }
}

#[async_trait]
impl<Uds, Gateway, Config, SecurityLoader, VehicleFactory, S> RuntimeReloaderPlugin
    for DefaultRuntimeReloaderPlugin<Uds, Gateway, Config, SecurityLoader, VehicleFactory, S>
where
    Uds: UdsEcu + SchemaProvider + Clone + Shutdown + Send + Sync + 'static,
    Gateway: Shutdown,
    Config: Clone + serde::de::DeserializeOwned + Send + Sync + 'static,
    SecurityLoader: SecurityPluginLoader,
    VehicleFactory: VehicleComponentFactory<Config, Uds, Gateway>,
    S: Storage + Send + Sync + 'static,
{
    async fn reload_databases(&self, mdd_paths: Vec<PathBuf>) -> Result<(), ReloadError> {
        let cfg = self.config.read().await.clone();
        let result = self.install_new_runtime(cfg, &mdd_paths).await;

        if let Err(ref install_err) = result {
            // The apply/rollback already switched the persisted files to
            // `mdd_paths`, which would boot the failed runtime on the next start.
            tracing::error!(
                error = %install_err,
                "Runtime installation failed; rolling back from persistent backup"
            );

            let rollback_handler = RollbackHandler {
                config: Arc::clone(&self.config),
                factory: Arc::clone(&self.factory),
                route_state: Arc::clone(&self.route_state),
                _phantom: std::marker::PhantomData::<SecurityLoader>,
            };
            match crate::operations::rollback::execute_rollback(&*self.storage, &rollback_handler)
                .await
            {
                Ok(()) => tracing::info!("Automatic rollback completed successfully"),
                Err(rollback_err) => tracing::error!(
                    rollback_error = %rollback_err,
                    "Automatic rollback also failed; CDA is degraded and requires a restart"
                ),
            }
        }

        result
    }
}

/// Reload handler used for the automatic rollback triggered by a failed install.
///
/// Identical to the install path of [`DefaultRuntimeReloaderPlugin`], but without
/// its rollback-on-failure branch. This prevents infinite recursion during rollback.
struct RollbackHandler<Uds, Gateway, Config, SecurityLoader, VehicleFactory>
where
    Uds: UdsEcu + SchemaProvider + Clone + Shutdown + Send + Sync + 'static,
    Gateway: Shutdown,
    Config: Clone + serde::de::DeserializeOwned + Send + Sync + 'static,
    SecurityLoader: SecurityPluginLoader,
    VehicleFactory: VehicleComponentFactory<Config, Uds, Gateway>,
{
    config: Arc<RwLock<Config>>,
    factory: Arc<VehicleFactory>,
    route_state: Arc<RouteInstallState<Uds, Gateway>>,
    _phantom: std::marker::PhantomData<SecurityLoader>,
}

#[async_trait]
impl<Uds, Gateway, Config, SecurityLoader, VehicleFactory> RuntimeReloaderPlugin
    for RollbackHandler<Uds, Gateway, Config, SecurityLoader, VehicleFactory>
where
    Uds: UdsEcu + SchemaProvider + Clone + Shutdown + Send + Sync + 'static,
    Gateway: Shutdown,
    Config: Clone + serde::de::DeserializeOwned + Send + Sync + 'static,
    SecurityLoader: SecurityPluginLoader,
    VehicleFactory: VehicleComponentFactory<Config, Uds, Gateway>,
{
    async fn reload_databases(&self, mdd_paths: Vec<PathBuf>) -> Result<(), ReloadError> {
        let cfg = self.config.read().await.clone();
        let components = self.factory.create(&cfg, &mdd_paths).await.map_err(|e| {
            ReloadError::ReplacementFailure(format!(
                "Failed to create runtime during rollback: {e}"
            ))
        })?;

        self.route_state
            .install_routes::<_, SecurityLoader>(components)
            .await
    }
}
