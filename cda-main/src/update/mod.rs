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

use std::{future::Future, path::PathBuf, sync::Arc};

use async_trait::async_trait;
use cda_comm_can::MultiTransportGateway;
use cda_comm_doip::DoipDiagGateway;
use cda_core::EcuManager;
use cda_interfaces::{
    EcuGateway, UdsEcu,
    datatypes::ComponentsConfig,
    runtime_update_api::{ReloadError, RuntimeFilesUpdateSecurityHandler},
};
use cda_plugin_security::{SecurityPlugin, SecurityPluginLoader};
use tokio::sync::RwLock;

use crate::{AppError, UdsManagerType};

pub mod security;

pub struct ReloadHandlerDeps<S, F>
where
    S: SecurityPlugin,
    F: Future<Output = ()> + Clone + Send + Sync + 'static,
{
    pub config: Arc<RwLock<crate::config::configfile::Configuration>>,
    pub dynamic_router: cda_sovd::dynamic_router::DynamicRouter,
    pub vehicle_route_handle: cda_sovd::RouteHandle,
    pub flash_files_path: String,
    pub components_config: ComponentsConfig,
    pub lock_provider: Arc<cda_sovd::SovdLockStateProvider>,
    pub shutdown_signal: F,
    pub uds_manager: RwLock<UdsManagerType<S>>,
    pub doip_gateway: RwLock<MultiTransportGateway<DoipDiagGateway<EcuManager<S>>>>,
    pub ecu_execution_registry: cda_sovd::EcuExecutionRegistry,
    pub update_guard: cda_sovd::UpdateGuardState,
    pub health: Option<crate::HealthProviders>,
    pub variant_detection_handle: tokio::sync::Mutex<tokio::task::JoinHandle<()>>,
}

pub struct DefaultRuntimeFileReloadHandler<S, F, P>
where
    S: SecurityPlugin,
    F: Future<Output = ()> + Clone + Send + Sync + 'static,
    P: SecurityPluginLoader,
{
    config: Arc<RwLock<crate::config::configfile::Configuration>>,
    dynamic_router: cda_sovd::dynamic_router::DynamicRouter,
    vehicle_route_handle: cda_sovd::RouteHandle,
    flash_files_path: String,
    components_config: ComponentsConfig,
    lock_provider: Arc<cda_sovd::SovdLockStateProvider>,
    shutdown_signal: F,
    uds_manager: RwLock<UdsManagerType<S>>,
    doip_gateway: RwLock<MultiTransportGateway<DoipDiagGateway<EcuManager<S>>>>,
    update_guard: cda_sovd::UpdateGuardState,
    ecu_execution_registry: cda_sovd::EcuExecutionRegistry,
    health: Option<crate::HealthProviders>,
    variant_detection_handle: tokio::sync::Mutex<tokio::task::JoinHandle<()>>,
    _phantom: std::marker::PhantomData<P>,
}

impl<S, F, P> DefaultRuntimeFileReloadHandler<S, F, P>
where
    S: SecurityPlugin,
    F: Future<Output = ()> + Clone + Send + Sync + 'static,
    P: SecurityPluginLoader,
{
    #[must_use]
    pub fn new(deps: ReloadHandlerDeps<S, F>) -> Self {
        Self {
            config: deps.config,
            dynamic_router: deps.dynamic_router,
            vehicle_route_handle: deps.vehicle_route_handle,
            flash_files_path: deps.flash_files_path,
            components_config: deps.components_config,
            lock_provider: deps.lock_provider,
            shutdown_signal: deps.shutdown_signal,
            uds_manager: deps.uds_manager,
            doip_gateway: deps.doip_gateway,
            update_guard: deps.update_guard,
            ecu_execution_registry: deps.ecu_execution_registry,
            health: deps.health,
            variant_detection_handle: deps.variant_detection_handle,
            _phantom: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<S, F, P> cda_interfaces::runtime_update_api::RuntimeFileReloadHandler
    for DefaultRuntimeFileReloadHandler<S, F, P>
where
    S: SecurityPlugin,
    F: Future<Output = ()> + Clone + Send + Sync + 'static,
    P: SecurityPluginLoader,
{
    async fn reload_databases(&self, mdd_paths: Vec<PathBuf>) -> Result<(), ReloadError> {
        let cfg = self.config.read().await.clone();

        let new_components = crate::create_vehicle_components::<F, S>(
            &cfg,
            &mdd_paths,
            self.shutdown_signal.clone(),
            self.health.as_ref(),
            self.update_guard.busy_handle(),
        )
        .await
        .map_err(|e| ReloadError(format!("Failed to create vehicle components: {e}")))?;

        let mut variant_detection_handle = self.variant_detection_handle.lock().await;
        variant_detection_handle.abort();
        *variant_detection_handle = new_components.variant_detection_handle;
        drop(variant_detection_handle);

        // Shutdown old components and replace with new ones
        let mut uds_manager_rw = self.uds_manager.write().await;
        uds_manager_rw.shutdown().await;
        *uds_manager_rw = new_components.uds_manager.clone();
        drop(uds_manager_rw);

        let mut doip_gateway_rw = self.doip_gateway.write().await;
        doip_gateway_rw.shutdown();
        *doip_gateway_rw = new_components.diagnostic_gateway;
        drop(doip_gateway_rw);

        // Update lock entries, to make sure new ECUs or removed ECUs are updated.
        let ecu_names = new_components.uds_manager.get_physical_ecus().await;
        self.lock_provider
            .update_entries(ecu_names)
            .await
            .map_err(|e| ReloadError(e.to_string()))?;
        let current_locks = self.lock_provider.current_locks().await;

        // Build and replace vehicle routes
        let (vehicle_router, new_registry) = cda_sovd::build_vehicle_routes::<_, _, P>(
            cda_sovd::VehicleConfig {
                flash_files_path: self.flash_files_path.clone(),
                functional_group_config: cfg.functional_description.clone(),
                components_config: self.components_config.clone(),
            },
            cda_sovd::VehicleResources {
                ecu_uds: new_components.uds_manager,
                file_manager: new_components.file_managers,
                locks: current_locks,
                update_in_progress: self.update_guard.busy_handle(),
            },
        )
        .await;
        self.ecu_execution_registry.replace(&new_registry).await;
        self.dynamic_router
            .replace_routes(&self.vehicle_route_handle, vehicle_router)
            .await
            .map_err(|e| ReloadError(format!("Failed to replace vehicle routes: {e}")))?;

        Ok(())
    }

    async fn reload_configuration(&self, config_path: PathBuf) -> Result<(), ReloadError> {
        reload_configuration_from_path(&self.config, config_path).await
    }
}

/// Reads, parses, and applies a TOML [`Configuration`] from `config_path` into `config`.
///
/// Extracted as a free function so that it can be unit-tested without constructing
/// the full [`DefaultRuntimeFileReloadHandler`].
async fn reload_configuration_from_path(
    config: &Arc<RwLock<crate::config::configfile::Configuration>>,
    config_path: PathBuf,
) -> Result<(), ReloadError> {
    let content = tokio::fs::read_to_string(&config_path)
        .await
        .map_err(|e| ReloadError(format!("Failed to read config: {e}")))?;
    let parsed = toml::from_str(&content)
        .map_err(|e| ReloadError(format!("Failed to parse config: {e}")))?;
    *config.write().await = parsed;
    Ok(())
}

pub struct RuntimeUpdateContext<
    S: SecurityPlugin,
    F,
    T: RuntimeFilesUpdateSecurityHandler<
            cda_sovd::SovdLockStateProvider,
            cda_storage::LocalCollection,
        >,
> {
    pub dynamic_router: cda_sovd::dynamic_router::DynamicRouter,
    pub vehicle_route_handle: cda_sovd::RouteHandle,
    pub config: crate::config::configfile::Configuration,
    pub flash_files_path: String,
    pub components_config: ComponentsConfig,
    pub lock_provider: Arc<cda_sovd::SovdLockStateProvider>,
    pub update_guard: cda_sovd::UpdateGuardState,
    pub shutdown_signal: F,
    pub runtime_update_config: cda_plugin_runtime_update::config::RuntimeUpdateConfig,
    pub security_handler: Arc<T>,
    pub ecu_execution_registry: cda_sovd::EcuExecutionRegistry,
    pub uds_manager: UdsManagerType<S>,
    pub doip_gateway: MultiTransportGateway<DoipDiagGateway<EcuManager<S>>>,
    pub health: Option<crate::HealthProviders>,
    pub variant_detection_handle: tokio::task::JoinHandle<()>,
}

/// Registers the runtime update routes on the dynamic router using the provided plugin.
///
/// Wraps the plugin in [`ExclusiveRuntimePlugin`] for read/write mutual exclusion and
/// mounts the HTTP endpoints by delegating to [`cda_sovd::add_runtime_update_routes`].
/// The caller is responsible for constructing the plugin (e.g. via
/// [`init_default_runtime_update_plugin`]) before calling this function.
pub async fn add_runtime_update_routes<S, P>(
    dynamic_router: &cda_sovd::dynamic_router::DynamicRouter,
    plugin: P,
    lock_provider: Arc<cda_sovd::SovdLockStateProvider>,
    update_guard: &cda_sovd::UpdateGuardState,
    upload_body_limit_bytes: usize,
    retry_after_seconds: u64,
) where
    S: SecurityPluginLoader,
    P: cda_interfaces::runtime_update_api::RuntimeFilesUpdatePlugin,
{
    let service = Arc::new(plugin.with_exclusive_access());
    cda_sovd::add_runtime_update_routes::<S, _, cda_sovd::SovdLockStateProvider>(
        dynamic_router,
        service,
        lock_provider,
        update_guard,
        upload_body_limit_bytes,
        retry_after_seconds,
    )
    .await;
}

/// Initializes the default runtime update plugin.
///
/// Creates the reload handler, storage backend, and returns a configured
/// [`cda_plugin_runtime_update::DefaultRuntimeFilesUpdatePlugin`] instance.
/// The returned plugin is not wrapped in Arc; the caller should apply Arc wrapping
/// if needed.
///
/// # Errors
/// Returns [`AppError`] if storage initialization fails.
pub async fn init_default_runtime_update_plugin<S, F, P>(
    // Boxed to keep the async future size within Clippy's `large_futures` limit;
    // the context is heap-allocated so its fields don't bloat the state machine.
    ctx: Box<
        RuntimeUpdateContext<
            S,
            F,
            impl RuntimeFilesUpdateSecurityHandler<
                cda_sovd::SovdLockStateProvider,
                cda_storage::LocalCollection,
            >,
        >,
    >,
) -> Result<
    cda_plugin_runtime_update::DefaultRuntimeFilesUpdatePlugin<
        cda_storage::LocalStorage,
        DefaultRuntimeFileReloadHandler<S, F, P>,
        impl RuntimeFilesUpdateSecurityHandler<
            cda_sovd::SovdLockStateProvider,
            cda_storage::LocalCollection,
        >,
        cda_sovd::SovdLockStateProvider,
    >,
    AppError,
>
where
    S: SecurityPlugin,
    F: Future<Output = ()> + Clone + Send + Sync + 'static,
    P: SecurityPluginLoader,
{
    // Move out of the box so the large context fields are consumed into
    // heap-backed Arcs before the first await, keeping the future small.
    let ctx = *ctx;
    let config = Arc::new(RwLock::new(ctx.config));
    let reload_handler = Arc::new(DefaultRuntimeFileReloadHandler::<S, F, P>::new(
        ReloadHandlerDeps {
            config: Arc::clone(&config),
            dynamic_router: ctx.dynamic_router.clone(),
            vehicle_route_handle: ctx.vehicle_route_handle,
            flash_files_path: ctx.flash_files_path,
            components_config: ctx.components_config,
            lock_provider: Arc::clone(&ctx.lock_provider),
            shutdown_signal: ctx.shutdown_signal,
            uds_manager: RwLock::new(ctx.uds_manager),
            doip_gateway: RwLock::new(ctx.doip_gateway),
            update_guard: ctx.update_guard.clone(),
            ecu_execution_registry: ctx.ecu_execution_registry,
            health: ctx.health,
            variant_detection_handle: tokio::sync::Mutex::new(ctx.variant_detection_handle),
        },
    ));
    let storage = Arc::new(
        cda_storage::LocalStorage::new(&ctx.runtime_update_config.storage_dir)
            .map_err(|e| AppError::InitializationFailed(format!("DbUpdate storage: {e}")))?,
    );
    let mdd_decompress = config.read().await.flat_buf.mdd_decompress;

    let update_plugin = cda_plugin_runtime_update::DefaultRuntimeFilesUpdatePlugin::new(
        storage,
        reload_handler,
        ctx.security_handler,
        ctx.lock_provider,
        mdd_decompress,
        ctx.update_guard.busy_handle(),
    );
    Ok(update_plugin)
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, sync::Arc};

    use tokio::sync::RwLock;

    use super::reload_configuration_from_path;
    use crate::config::configfile::Configuration;

    fn default_config() -> Arc<RwLock<Configuration>> {
        Arc::new(RwLock::new(Configuration::default()))
    }

    #[tokio::test]
    async fn reload_configuration_fails_when_file_does_not_exist() {
        let config = default_config();
        let result =
            reload_configuration_from_path(&config, PathBuf::from("/nonexistent/path/config.toml"))
                .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.0.contains("Failed to read config"),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn reload_configuration_fails_on_invalid_toml() {
        let config = default_config();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, "this is {{ not valid toml").unwrap();

        let result = reload_configuration_from_path(&config, path).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.0.contains("Failed to parse config"),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn reload_configuration_fails_on_valid_toml_with_wrong_schema() {
        let config = default_config();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wrong_schema.toml");
        std::fs::write(&path, "[unknown_section]\nfoo = 42\n").unwrap();

        let result = reload_configuration_from_path(&config, path).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.0.contains("Failed to parse config"),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn reload_configuration_updates_config_on_valid_file() {
        let original = Configuration::default();
        let config = Arc::new(RwLock::new(original));

        let new_cfg = Configuration::default();
        let toml_str = toml::to_string(&new_cfg).expect("default config must serialize");

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("valid.toml");
        std::fs::write(&path, &toml_str).unwrap();

        let result = reload_configuration_from_path(&config, path).await;
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[tokio::test]
    async fn reload_configuration_does_not_mutate_config_on_read_error() {
        let config = default_config();
        let original_flash_path = config.read().await.flash_files_path.clone();

        let _ = reload_configuration_from_path(&config, PathBuf::from("/nonexistent/config.toml"))
            .await;

        assert_eq!(
            config.read().await.flash_files_path,
            original_flash_path,
            "config must not be mutated when file read fails"
        );
    }

    #[tokio::test]
    async fn reload_configuration_does_not_mutate_config_on_parse_error() {
        let config = default_config();
        let original_flash_path = config.read().await.flash_files_path.clone();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, "not = {{{ toml").unwrap();

        let _ = reload_configuration_from_path(&config, path).await;

        assert_eq!(
            config.read().await.flash_files_path,
            original_flash_path,
            "config must not be mutated when TOML parsing fails"
        );
    }
}
