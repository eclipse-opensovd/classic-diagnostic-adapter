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
    EcuGateway, EcuGatewaySockets, HashMap, SchemaProvider, Shutdown, ShutdownSignal, UdsEcu,
    datatypes::ComponentsConfig,
    health::HealthProvider,
    runtime_update_api::{
        ReloadError, RuntimeReloaderPlugin, VehicleComponentFactory, VehicleComponents,
    },
};
use cda_plugin_security::SecurityPluginLoader;
use cda_sovd::{SovdLockStateProvider, UpdateGuardState, dynamic_router::DynamicRouter};
use tokio::sync::{Mutex, RwLock};

/// Context for the runtime reload operation.
///
/// This struct contains all the components needed to reload runtime databases
/// and configuration. It bundles the infrastructure required by the reloader plugin.
pub struct DefaultReloadContext<Uds, Gateway, Config>
where
    Uds: UdsEcu + SchemaProvider + Clone + Shutdown + Send + Sync + 'static,
    Gateway: EcuGatewaySockets + Shutdown,
    Config: Clone + serde::de::DeserializeOwned + Send + Sync + 'static,
{
    /// Application configuration
    pub config: Arc<RwLock<Config>>,

    /// Vehicle diagnostic manager
    pub uds_manager: Arc<RwLock<Uds>>,

    /// `DoIP` diagnostic gateway
    pub doip_gateway: Arc<RwLock<Gateway>>,

    /// Dynamic router for hot-swapping routes
    pub dynamic_router: DynamicRouter,

    /// Handle for vehicle route registration/replacement
    pub vehicle_route_handle: cda_sovd::RouteHandle,

    /// Lock state provider for SOVD locks
    pub lock_provider: Arc<SovdLockStateProvider>,

    /// ECU execution registry for tracking in-flight operations
    pub ecu_execution_registry: cda_sovd::EcuExecutionRegistry,

    /// Update guard state
    pub update_guard: UpdateGuardState,

    /// Path for flash files
    pub flash_files_path: String,

    /// Component configuration
    pub components_config: ComponentsConfig,

    /// Handle for variant detection background task
    pub variant_detection_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,

    /// Health providers for monitoring
    pub health: Option<HashMap<String, Arc<dyn HealthProvider>>>,

    // /// Guard that signals whether a flash transfer is in progress
    // pub flash_transfer_guard: cda_comm_uds::FlashTransferObserver,
    /// Storage directory for runtime update files
    pub storage_dir: String,

    /// Whether to decompress MDD files after apply
    pub mdd_decompress: bool,

    /// Shutdown signal for graceful termination
    pub shutdown_signal: ShutdownSignal,
}

/// Default reload handler for runtime database and configuration updates.
///
/// Implements [`RuntimeReloaderPlugin`] by:
/// - Shutting down existing UDS and `DoIP` components
/// - Delegating component creation to a [`VehicleComponentFactory`]
/// - Replacing running routes via the [`DynamicRouter`]
pub struct DefaultRuntimeReloaderPlugin<Uds, Gateway, Config, SecurityLoader, VehicleFactory>
where
    Uds: UdsEcu + SchemaProvider + Clone + Shutdown + Send + Sync + 'static,
    Gateway: EcuGatewaySockets + Shutdown,
    Config: Clone + serde::de::DeserializeOwned + Send + Sync + 'static,
    SecurityLoader: SecurityPluginLoader,
    VehicleFactory: VehicleComponentFactory<Config, Uds, Gateway>,
{
    config: Arc<RwLock<Config>>,
    dynamic_router: DynamicRouter,
    vehicle_route_handle: cda_sovd::RouteHandle,
    flash_files_path: String,
    components_config: ComponentsConfig,
    lock_provider: Arc<SovdLockStateProvider>,
    uds_manager: Arc<RwLock<Uds>>,
    doip_gateway: Arc<RwLock<Gateway>>,
    update_guard: UpdateGuardState,
    ecu_execution_registry: cda_sovd::EcuExecutionRegistry,
    variant_detection_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
    factory: Arc<VehicleFactory>,
    _phantom: std::marker::PhantomData<SecurityLoader>,
}

/// Configuration for creating a [`DefaultRuntimeReloaderPlugin`].
///
/// This bundles the [`ReloadContext`] with a [`VehicleComponentFactory`]
/// to simplify plugin construction.
pub struct RuntimeReloaderConfig<Uds, Gateway, Config, VehicleFactory>
where
    Uds: UdsEcu + SchemaProvider + Clone + Shutdown + Send + Sync + 'static,
    Gateway: EcuGatewaySockets + Shutdown,
    Config: Clone + serde::de::DeserializeOwned + Send + Sync + 'static,
    VehicleFactory: VehicleComponentFactory<Config, Uds, Gateway>,
{
    /// Runtime context containing all CDA components.
    pub infrastructure: DefaultReloadContext<Uds, Gateway, Config>,
    /// Factory for creating vehicle components on reload.
    pub factory: Arc<VehicleFactory>,
}

impl<Uds, Gateway, Config, VehicleFactory>
    RuntimeReloaderConfig<Uds, Gateway, Config, VehicleFactory>
where
    Uds: UdsEcu + SchemaProvider + Clone + Shutdown + Send + Sync + 'static,
    Gateway: EcuGatewaySockets + Shutdown,
    Config: Clone + serde::de::DeserializeOwned + Send + Sync + 'static,
    VehicleFactory: VehicleComponentFactory<Config, Uds, Gateway>,
{
    /// Creates a new [`RuntimeReloaderConfig`] from context and a factory.
    #[must_use]
    pub fn new(
        infrastructure: DefaultReloadContext<Uds, Gateway, Config>,
        factory: Arc<VehicleFactory>,
    ) -> Self {
        Self {
            infrastructure,
            factory,
        }
    }
}

impl<Uds, Gateway, Config, SecurityLoader, VehicleFactory>
    DefaultRuntimeReloaderPlugin<Uds, Gateway, Config, SecurityLoader, VehicleFactory>
where
    Uds: UdsEcu + SchemaProvider + Clone + Shutdown + Send + Sync + 'static,
    Gateway: EcuGateway + EcuGatewaySockets + Shutdown,
    Config: Clone + serde::de::DeserializeOwned + Send + Sync + 'static,
    SecurityLoader: SecurityPluginLoader,
    VehicleFactory: VehicleComponentFactory<Config, Uds, Gateway>,
{
    /// Creates a new [`DefaultRuntimeReloaderPlugin`] from a [`RuntimeReloaderConfig`].
    #[must_use]
    pub fn new(config: RuntimeReloaderConfig<Uds, Gateway, Config, VehicleFactory>) -> Self {
        Self {
            config: config.infrastructure.config,
            dynamic_router: config.infrastructure.dynamic_router,
            vehicle_route_handle: config.infrastructure.vehicle_route_handle,
            flash_files_path: config.infrastructure.flash_files_path,
            components_config: config.infrastructure.components_config,
            lock_provider: config.infrastructure.lock_provider,
            uds_manager: config.infrastructure.uds_manager,
            doip_gateway: config.infrastructure.doip_gateway,
            update_guard: config.infrastructure.update_guard,
            ecu_execution_registry: config.infrastructure.ecu_execution_registry,
            variant_detection_handle: config.infrastructure.variant_detection_handle,
            factory: config.factory,
            _phantom: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<Uds, Gateway, Config, SecurityLoader, VehicleFactory> RuntimeReloaderPlugin
    for DefaultRuntimeReloaderPlugin<Uds, Gateway, Config, SecurityLoader, VehicleFactory>
where
    Uds: UdsEcu + SchemaProvider + Clone + Shutdown + Send + Sync + 'static,
    Gateway: EcuGateway + EcuGatewaySockets + Shutdown,
    Config: Clone + serde::de::DeserializeOwned + Send + Sync + 'static,
    SecurityLoader: SecurityPluginLoader,
    VehicleFactory: VehicleComponentFactory<Config, Uds, Gateway>,
{
    async fn reload_databases(&self, mdd_paths: Vec<PathBuf>) -> Result<(), ReloadError> {
        let cfg = self.config.read().await.clone();

        // Shut down old components BEFORE creating new ones to avoid port/socket
        // conflicts. Reuse the existing UDP socket so that there is never a second
        // socket bound to the same DoIP port (which would cause non-deterministic
        // VAM delivery between old and new listeners).
        if let Some(variant_detection_handle) = self.variant_detection_handle.lock().await.take() {
            variant_detection_handle.abort();
            let _ = variant_detection_handle.await;
        }

        self.uds_manager.write().await.shutdown().await;
        let doip_socket = {
            let mut gw = self.doip_gateway.write().await;
            let socket = gw.upd_socket();
            gw.shutdown().await;
            socket
        };

        let VehicleComponents {
            uds_manager,
            diagnostic_gateway,
            file_managers: file_manager,
            variant_detection_handle,
            functional_group_config,
        } = self
            .factory
            .create(
                &cfg,
                &mdd_paths,
                self.update_guard.busy_handle(),
                doip_socket,
            )
            .await?;

        // Replace with new components
        *self.variant_detection_handle.lock().await = Some(variant_detection_handle);
        *self.uds_manager.write().await = uds_manager.clone();
        *self.doip_gateway.write().await = diagnostic_gateway;

        // Update lock entries, to make sure new ECUs or removed ECUs are updated.
        let ecu_names = uds_manager.get_physical_ecus().await;
        self.lock_provider
            .update_entries(ecu_names)
            .await
            .map_err(|e| ReloadError(e.to_string()))?;
        let current_locks = self.lock_provider.current_locks().await;

        // Build and replace vehicle routes
        let (vehicle_router, new_registry) =
            cda_sovd::build_vehicle_routes::<_, _, SecurityLoader>(
                cda_sovd::VehicleConfig {
                    flash_files_path: self.flash_files_path.clone(),
                    functional_group_config,
                    components_config: self.components_config.clone(),
                },
                cda_sovd::VehicleResources {
                    ecu_uds: uds_manager,
                    file_manager,
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
