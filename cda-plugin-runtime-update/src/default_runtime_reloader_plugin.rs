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

// Type aliases for backward compatibility in this file
use TransportControl as CommunicationControl;
use async_trait::async_trait;
use cda_interfaces::{
    EcuGateway, HashMap, ReusableTransportResource, SchemaProvider, Shutdown, ShutdownSignal,
    UdsEcu,
    communication_control::TransportControl,
    datatypes::ComponentsConfig,
    health::HealthProvider,
    runtime_update_api::{
        ReloadError, RuntimeReloaderPlugin, VehicleComponentFactory, VehicleComponents,
    },
};
use cda_plugin_communication_management::lifecycle::access::CommunicationAccess;
use cda_plugin_security::SecurityPluginLoader;
use cda_sovd::{SovdLockStateProvider, dynamic_router::DynamicRouter};
use tokio::sync::{Mutex, RwLock};

/// Context for the runtime reload operation.
///
/// This struct contains all the components needed to reload runtime databases
/// and configuration. It bundles the infrastructure required by the reloader plugin.
pub struct DefaultReloadContext<Uds, Gateway, Config>
where
    Uds: UdsEcu + SchemaProvider + Clone + Shutdown + Send + Sync + 'static,
    Gateway: CommunicationControl + ReusableTransportResource + Shutdown,
    Config: Clone + serde::de::DeserializeOwned + Send + Sync + 'static,
{
    /// Application configuration
    pub config: Arc<RwLock<Config>>,

    /// Vehicle diagnostic manager
    pub uds_manager: Arc<RwLock<Uds>>,

    /// Diagnostic gateway across all configured transports
    pub diagnostic_gateway: Arc<Mutex<Gateway>>,

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

    /// Storage directory for runtime update files
    pub storage_dir: String,

    /// Whether to decompress MDD files after apply
    pub mdd_decompress: bool,

    /// Shutdown signal for graceful termination
    pub shutdown_signal: ShutdownSignal,

    /// Shared coordinator used by rebuilt SOVD routes.
    pub communication_access: Arc<dyn CommunicationAccess>,
}

/// Default reload handler for runtime database and configuration updates.
///
/// Implements [`RuntimeReloaderPlugin`] by:
/// - Delegating component creation to a [`VehicleComponentFactory`]
/// - Replacing running routes via the [`DynamicRouter`]
///
/// Transport disable/enable is now owned by `start_execution` in the runtime-update
/// plugin; `reload_databases` is purely a component-replacement operation.
pub struct DefaultRuntimeReloaderPlugin<Uds, Gateway, Config, SecurityLoader, VehicleFactory>
where
    Uds: UdsEcu + SchemaProvider + Clone + Shutdown + Send + Sync + 'static,
    Gateway: CommunicationControl + ReusableTransportResource + Shutdown,
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
    diagnostic_gateway: Arc<Mutex<Gateway>>,
    factory: Arc<VehicleFactory>,
    communication_access: Arc<dyn CommunicationAccess>,
    _phantom: std::marker::PhantomData<SecurityLoader>,
}

/// Configuration for creating a [`DefaultRuntimeReloaderPlugin`].
///
/// This bundles the [`ReloadContext`] with a [`VehicleComponentFactory`]
/// to simplify plugin construction.
pub struct RuntimeReloaderConfig<Uds, Gateway, Config, VehicleFactory>
where
    Uds: UdsEcu + SchemaProvider + Clone + Shutdown + Send + Sync + 'static,
    Gateway: CommunicationControl + ReusableTransportResource + Shutdown,
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
    Gateway: CommunicationControl + ReusableTransportResource + Shutdown,
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
    Gateway: EcuGateway + CommunicationControl + ReusableTransportResource + Shutdown,
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
            diagnostic_gateway: config.infrastructure.diagnostic_gateway,
            factory: config.factory,
            communication_access: config.infrastructure.communication_access,
            _phantom: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<Uds, Gateway, Config, SecurityLoader, VehicleFactory> RuntimeReloaderPlugin
    for DefaultRuntimeReloaderPlugin<Uds, Gateway, Config, SecurityLoader, VehicleFactory>
where
    Uds: UdsEcu + SchemaProvider + Clone + Shutdown + Send + Sync + 'static,
    Gateway: EcuGateway + CommunicationControl + ReusableTransportResource + Shutdown,
    Config: Clone + serde::de::DeserializeOwned + Send + Sync + 'static,
    SecurityLoader: SecurityPluginLoader,
    VehicleFactory: VehicleComponentFactory<Config, Uds, Gateway>,
{
    async fn reload_databases(&self, mdd_paths: Vec<PathBuf>) -> Result<(), ReloadError> {
        let cfg = self.config.read().await.clone();

        let reusable_transport_resource = self
            .diagnostic_gateway
            .lock()
            .await
            .reusable_transport_resource();

        let components = self
            .factory
            .create(&cfg, &mdd_paths, reusable_transport_resource)
            .await?;

        let VehicleComponents {
            uds_manager,
            diagnostic_gateway,
            file_managers,
            functional_group_config,
        } = components;

        {
            let mut gateway = self.diagnostic_gateway.lock().await;
            let old_gateway = std::mem::replace(&mut *gateway, diagnostic_gateway);
            // Shut down the old gateway outside the lock to avoid holding it during I/O.
            drop(gateway);
            old_gateway.shutdown().await;
        }

        let old_uds_manager = {
            let mut current_uds_manager = self.uds_manager.write().await;
            std::mem::replace(&mut *current_uds_manager, uds_manager.clone())
        };
        old_uds_manager.shutdown().await;

        let ecu_names = uds_manager.get_physical_ecus().await;
        self.lock_provider
            .update_entries(ecu_names)
            .await
            .map_err(|e| ReloadError::General(e.to_string()))?;
        let current_locks = self.lock_provider.current_locks().await;

        let vehicle_router = cda_sovd::build_vehicle_routes::<_, _, SecurityLoader>(
            cda_sovd::VehicleConfig {
                flash_files_path: self.flash_files_path.clone(),
                functional_group_config,
                components_config: self.components_config.clone(),
            },
            cda_sovd::VehicleResources {
                ecu_uds: uds_manager,
                file_managers,
                locks: current_locks,
                communication_access: Arc::clone(&self.communication_access),
            },
        )
        .await;
        self.dynamic_router
            .replace_routes(&self.vehicle_route_handle, vehicle_router)
            .await
            .map_err(|e| ReloadError::ReplacementFailure(e.to_string()))?;

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
        .map_err(|e| ReloadError::General(format!("Failed to read config: {e}")))?;
    let parsed = toml::from_str(&content)
        .map_err(|e| ReloadError::General(format!("Failed to parse config: {e}")))?;
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
            err.to_string().contains("Failed to read config"),
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
            err.to_string().contains("Failed to parse config"),
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
            err.to_string().contains("Failed to parse config"),
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
