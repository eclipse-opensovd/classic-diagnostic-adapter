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
    EcuGateway, EcuGatewaySockets, GatewayInstall, HashMap, InitializationPlugin, SchemaProvider,
    Shutdown, ShutdownSignal, SocketProvider, UdsEcu,
    communication_control::{CommState, CommunicationControl, PostUpdateCommunicationMode},
    datatypes::ComponentsConfig,
    health::HealthStatus,
    runtime_update_api::{
        ReloadError, RuntimeReloaderPlugin, VehicleComponentFactory, VehicleComponents,
    },
};
use cda_plugin_security::SecurityPluginLoader;
use cda_sovd::{SovdLockStateProvider, dynamic_router::DynamicRouter};
use tokio::sync::{Mutex, RwLock};

use crate::UpdateGuard;

/// Context for the runtime reload operation.
///
/// This struct contains all the components needed to reload runtime databases
/// and configuration. It bundles the infrastructure required by the reloader plugin.
///
/// The `C` type parameter is any control-plane handle implementing:
/// - [`CommunicationControl`][]: enable/disable/state
/// - [`GatewayInstall<Gateway>`]: atomically swap in a new gateway
/// - [`SocketProvider`]: provide the reusable UDP socket to the factory
/// - [`Clone`]: allow sharing across async boundaries
pub struct DefaultReloadContext<Uds, Gateway, Config, C>
where
    Uds: UdsEcu + SchemaProvider + Clone + Shutdown + Send + Sync + 'static,
    Gateway: EcuGatewaySockets + Shutdown,
    Config: Clone + serde::de::DeserializeOwned + Send + Sync + 'static,
    C: CommunicationControl
        + GatewayInstall<Gateway>
        + SocketProvider
        + Clone
        + Send
        + Sync
        + 'static,
{
    /// Application configuration
    pub config: Arc<RwLock<Config>>,

    /// Vehicle diagnostic manager
    pub uds_manager: Arc<RwLock<Uds>>,

    /// Handle to the communication actor.
    ///
    /// Used during reload to disable the live connection, install a new gateway,
    /// and re-activate communication - all while reusing the reserved UDP socket
    /// so the port is never released between reloads.
    pub comm_handle: C,

    /// Dynamic router for hot-swapping routes
    pub dynamic_router: DynamicRouter,

    /// Handle for vehicle route registration/replacement
    pub vehicle_route_handle: cda_sovd::RouteHandle,

    /// Lock state provider for SOVD locks
    pub lock_provider: Arc<SovdLockStateProvider>,

    /// ECU execution registry for tracking in-flight operations
    pub ecu_execution_registry: cda_sovd::EcuExecutionRegistry,

    /// Update guard
    pub update_guard: UpdateGuard,

    /// Path for flash files
    pub flash_files_path: String,

    /// Component configuration
    pub components_config: ComponentsConfig,

    /// Handle for variant detection background task
    pub variant_detection_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,

    /// Health providers for monitoring
    pub health: Option<HashMap<String, Arc<dyn HealthStatus>>>,

    /// Storage directory for runtime update files
    pub storage_dir: String,

    /// Whether to decompress MDD files after apply
    pub mdd_decompress: bool,

    /// Shutdown signal for graceful termination
    pub shutdown_signal: ShutdownSignal,

    /// Controls communication behavior after a runtime database update.
    pub post_update_mode: PostUpdateCommunicationMode,

    /// Initialization plugin to call `on_ready` when re-entering deferred mode.
    ///
    /// Only used when `post_update_mode` is `Deferred` or `Last` (and comm was inactive).
    pub init_plugin: Option<Arc<dyn InitializationPlugin>>,

    /// Phantom data to carry the `Gateway` type parameter.
    pub _gateway: std::marker::PhantomData<Gateway>,
}

/// Default reload handler for runtime database and configuration updates.
///
/// Implements [`RuntimeReloaderPlugin`] by:
/// - Disabling communication via `C: CommunicationControl` (tears down gateway, keeps socket)
/// - Delegating component creation to a [`VehicleComponentFactory`] (reuses socket via
///   `C: SocketProvider`)
/// - Installing the new gateway via `C: GatewayInstall<Gateway>` with `activate` resolved
///   from [`PostUpdateCommunicationMode`]
/// - Replacing running routes via the [`DynamicRouter`]
pub struct DefaultRuntimeReloaderPlugin<Uds, Gateway, Config, SecurityLoader, VehicleFactory, C>
where
    Uds: UdsEcu + SchemaProvider + Clone + Shutdown + Send + Sync + 'static,
    Gateway: EcuGatewaySockets + Shutdown,
    Config: Clone + serde::de::DeserializeOwned + Send + Sync + 'static,
    SecurityLoader: SecurityPluginLoader,
    VehicleFactory: VehicleComponentFactory<Config, Uds, Gateway>,
    C: CommunicationControl
        + GatewayInstall<Gateway>
        + SocketProvider
        + Clone
        + Send
        + Sync
        + 'static,
{
    config: Arc<RwLock<Config>>,
    dynamic_router: DynamicRouter,
    vehicle_route_handle: cda_sovd::RouteHandle,
    flash_files_path: String,
    components_config: ComponentsConfig,
    lock_provider: Arc<SovdLockStateProvider>,
    uds_manager: Arc<RwLock<Uds>>,
    comm_handle: C,
    update_guard: UpdateGuard,
    ecu_execution_registry: cda_sovd::EcuExecutionRegistry,
    variant_detection_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
    factory: Arc<VehicleFactory>,
    post_update_mode: PostUpdateCommunicationMode,
    init_plugin: Option<Arc<dyn InitializationPlugin>>,
    _phantom: std::marker::PhantomData<(SecurityLoader, Gateway)>,
}

/// Configuration for creating a [`DefaultRuntimeReloaderPlugin`].
///
/// This bundles the [`DefaultReloadContext`] with a [`VehicleComponentFactory`]
/// to simplify plugin construction.
pub struct RuntimeReloaderConfig<Uds, Gateway, Config, VehicleFactory, C>
where
    Uds: UdsEcu + SchemaProvider + Clone + Shutdown + Send + Sync + 'static,
    Gateway: EcuGatewaySockets + Shutdown,
    Config: Clone + serde::de::DeserializeOwned + Send + Sync + 'static,
    VehicleFactory: VehicleComponentFactory<Config, Uds, Gateway>,
    C: CommunicationControl
        + GatewayInstall<Gateway>
        + SocketProvider
        + Clone
        + Send
        + Sync
        + 'static,
{
    /// Runtime context containing all CDA components.
    pub infrastructure: DefaultReloadContext<Uds, Gateway, Config, C>,
    /// Factory for creating vehicle components on reload.
    pub factory: Arc<VehicleFactory>,
}

impl<Uds, Gateway, Config, VehicleFactory, C>
    RuntimeReloaderConfig<Uds, Gateway, Config, VehicleFactory, C>
where
    Uds: UdsEcu + SchemaProvider + Clone + Shutdown + Send + Sync + 'static,
    Gateway: EcuGatewaySockets + Shutdown,
    Config: Clone + serde::de::DeserializeOwned + Send + Sync + 'static,
    VehicleFactory: VehicleComponentFactory<Config, Uds, Gateway>,
    C: CommunicationControl
        + GatewayInstall<Gateway>
        + SocketProvider
        + Clone
        + Send
        + Sync
        + 'static,
{
    /// Creates a new [`RuntimeReloaderConfig`] from context and a factory.
    #[must_use]
    pub fn new(
        infrastructure: DefaultReloadContext<Uds, Gateway, Config, C>,
        factory: Arc<VehicleFactory>,
    ) -> Self {
        Self {
            infrastructure,
            factory,
        }
    }
}

impl<Uds, Gateway, Config, SecurityLoader, VehicleFactory, C>
    DefaultRuntimeReloaderPlugin<Uds, Gateway, Config, SecurityLoader, VehicleFactory, C>
where
    Uds: UdsEcu + SchemaProvider + Clone + Shutdown + Send + Sync + 'static,
    Gateway: EcuGateway + EcuGatewaySockets + Shutdown,
    Config: Clone + serde::de::DeserializeOwned + Send + Sync + 'static,
    SecurityLoader: SecurityPluginLoader,
    VehicleFactory: VehicleComponentFactory<Config, Uds, Gateway>,
    C: CommunicationControl
        + GatewayInstall<Gateway>
        + SocketProvider
        + Clone
        + Send
        + Sync
        + 'static,
{
    /// Creates a new [`DefaultRuntimeReloaderPlugin`] from a [`RuntimeReloaderConfig`].
    #[must_use]
    pub fn new(config: RuntimeReloaderConfig<Uds, Gateway, Config, VehicleFactory, C>) -> Self {
        Self {
            config: config.infrastructure.config,
            dynamic_router: config.infrastructure.dynamic_router,
            vehicle_route_handle: config.infrastructure.vehicle_route_handle,
            flash_files_path: config.infrastructure.flash_files_path,
            components_config: config.infrastructure.components_config,
            lock_provider: config.infrastructure.lock_provider,
            uds_manager: config.infrastructure.uds_manager,
            comm_handle: config.infrastructure.comm_handle,
            update_guard: config.infrastructure.update_guard,
            ecu_execution_registry: config.infrastructure.ecu_execution_registry,
            variant_detection_handle: config.infrastructure.variant_detection_handle,
            factory: config.factory,
            post_update_mode: config.infrastructure.post_update_mode,
            init_plugin: config.infrastructure.init_plugin,
            _phantom: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<Uds, Gateway, Config, SecurityLoader, VehicleFactory, C> RuntimeReloaderPlugin
    for DefaultRuntimeReloaderPlugin<Uds, Gateway, Config, SecurityLoader, VehicleFactory, C>
where
    Uds: UdsEcu + SchemaProvider + Clone + Shutdown + Send + Sync + 'static,
    Gateway: EcuGateway + EcuGatewaySockets<Socket = C::Socket> + Shutdown,
    Config: Clone + serde::de::DeserializeOwned + Send + Sync + 'static,
    SecurityLoader: SecurityPluginLoader,
    VehicleFactory: VehicleComponentFactory<Config, Uds, Gateway>,
    C: CommunicationControl
        + GatewayInstall<Gateway>
        + SocketProvider
        + Clone
        + Send
        + Sync
        + 'static,
{
    async fn reload_databases(&self, mdd_paths: Vec<PathBuf>) -> Result<(), ReloadError> {
        let cfg = self.config.read().await.clone();

        // 1. Abort the variant-detection task so the old channel is drained.
        if let Some(handle) = self.variant_detection_handle.lock().await.take() {
            handle.abort();
            let _ = handle.await;
        }

        // 2. Shut down the UDS manager (stops all in-flight UDS tasks).
        self.uds_manager.write().await.shutdown().await;

        // 3. Capture whether communication was active before disabling it.
        //    Used by `PostUpdateCommunicationMode::Last` to restore the prior state.
        let was_active = self.comm_handle.state().await == CommState::Active;

        // 4. Disable communication: tears down the live gateway, clears the
        //    shared slot and active_flag. The reserved UDP socket stays bound.
        //    Ignore AlreadyInState - if actor is already disabled, that's fine.
        let _ = self.comm_handle.disable().await;

        // 5. Build new components.
        //    The factory receives the actor's reserved socket so it can build the new
        //    gateway without binding a second socket to the same port.
        let socket = self.comm_handle.socket();
        let VehicleComponents {
            uds_manager,
            diagnostic_gateway,
            file_managers: file_manager,
            variant_detection_handle,
            functional_group_config,
        } = self
            .factory
            .create(&cfg, &mdd_paths, self.update_guard.busy_handle(), socket)
            .await?;

        // 6. Resolve post-update policy to a concrete activate flag, then install.
        let activate = match self.post_update_mode {
            PostUpdateCommunicationMode::Enabled => true,
            PostUpdateCommunicationMode::Deferred => false,
            PostUpdateCommunicationMode::Last => was_active,
        };
        self.comm_handle
            .install_gateway(diagnostic_gateway, activate)
            .await;
        let use_deferred = !activate;

        // 7. Replace variant-detection handle and UDS manager in shared state.
        *self.variant_detection_handle.lock().await = Some(variant_detection_handle);
        *self.uds_manager.write().await = uds_manager.clone();

        // 8. Update lock entries (handles added/removed ECUs).
        let ecu_names = uds_manager.get_physical_ecus().await;
        self.lock_provider
            .update_entries(ecu_names)
            .await
            .map_err(|e| ReloadError(e.to_string()))?;
        let current_locks = self.lock_provider.current_locks().await;

        // 9. Build and hot-swap vehicle routes.
        let (vehicle_router, new_registry) =
            cda_sovd::build_vehicle_routes::<_, _, SecurityLoader>(
                cda_sovd::VehicleConfig {
                    flash_files_path: self.flash_files_path.clone(),
                    functional_group_config,
                    components_config: self.components_config.clone(),
                },
                cda_sovd::VehicleResources {
                    ecu_uds: uds_manager,
                    file_managers: file_manager,
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

        // 10. If we installed in deferred mode, call on_ready so the init plugin
        //     knows it can trigger (re-)initialization via the comm handle.
        if use_deferred && let Some(ref plugin) = self.init_plugin {
            let comm_control: Arc<dyn cda_interfaces::CommunicationControl> =
                Arc::new(self.comm_handle.clone());
            plugin.on_ready(comm_control).await;
        }

        Ok(())
    }

    async fn reload_configuration(&self, config_path: PathBuf) -> Result<(), ReloadError> {
        reload_configuration_from_path(&self.config, config_path).await
    }
}

/// Reads, parses, and applies a TOML configuration from `config_path` into `config`.
///
/// Extracted as a free function so that it can be unit-tested without constructing
/// the full [`DefaultRuntimeReloaderPlugin`].
pub(crate) async fn reload_configuration_from_path<C>(
    config: &Arc<RwLock<C>>,
    config_path: PathBuf,
) -> Result<(), ReloadError>
where
    C: serde::de::DeserializeOwned + Send + Sync + 'static,
{
    let content = tokio::fs::read_to_string(&config_path)
        .await
        .map_err(|e| ReloadError(format!("Failed to read config: {e}")))?;
    let parsed = toml::from_str(&content)
        .map_err(|e| ReloadError(format!("Failed to parse config: {e}")))?;
    *config.write().await = parsed;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, sync::Arc};

    use serde::{Deserialize, Serialize};
    use tokio::sync::RwLock;

    use super::reload_configuration_from_path;

    /// Minimal config stub for testing `reload_configuration_from_path`.
    #[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
    struct StubConfig {
        marker: Option<String>,
    }

    fn default_config() -> Arc<RwLock<StubConfig>> {
        Arc::new(RwLock::new(StubConfig::default()))
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
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Strict {
            #[allow(dead_code, reason = "field used only in deserialization")]
            known: String,
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wrong_schema.toml");
        // StubConfig only has `marker: Option<String>` - deny_unknown_fields would
        // reject this, but our stub doesn't use it; use a strict type to force failure.
        let strict_config: Arc<RwLock<Strict>> = Arc::new(RwLock::new(Strict {
            known: String::new(),
        }));
        std::fs::write(&path, "[unknown_section]\nfoo = 42\n").unwrap();

        let result = reload_configuration_from_path(&strict_config, path).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.0.contains("Failed to parse config"),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn reload_configuration_updates_config_on_valid_file() {
        let config = default_config();
        let new_cfg = StubConfig {
            marker: Some("hello".to_string()),
        };
        let toml_str = toml::to_string(&new_cfg).expect("StubConfig must serialize");

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("valid.toml");
        std::fs::write(&path, &toml_str).unwrap();

        let result = reload_configuration_from_path(&config, path).await;
        assert!(result.is_ok(), "expected Ok, got {result:?}");
        assert_eq!(config.read().await.marker, Some("hello".to_string()));
    }

    #[tokio::test]
    async fn reload_configuration_does_not_mutate_config_on_read_error() {
        let config = default_config();
        let original = config.read().await.clone();

        let _ = reload_configuration_from_path(&config, PathBuf::from("/nonexistent/config.toml"))
            .await;

        assert_eq!(
            *config.read().await,
            original,
            "config must not be mutated when file read fails"
        );
    }

    #[tokio::test]
    async fn reload_configuration_does_not_mutate_config_on_parse_error() {
        let config = default_config();
        let original = config.read().await.clone();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, "not = {{{ toml").unwrap();

        let _ = reload_configuration_from_path(&config, path).await;

        assert_eq!(
            *config.read().await,
            original,
            "config must not be mutated when TOML parsing fails"
        );
    }
}
