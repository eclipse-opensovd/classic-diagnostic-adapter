/*
 * SPDX-FileCopyrightText: 2025 Copyright (c) Contributors to the Eclipse Foundation
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

use cda_comm_doip::{DoipDiagGateway, config::DoipConfig};
use cda_comm_uds::UdsManager;
use cda_core::EcuManager;
use cda_database::FileManager;
use cda_interfaces::{
    DiagServiceError, DoipGatewaySetupError, FunctionalDescriptionConfig, HashMap, UdsQuery,
    UdsVariant,
    config::{ConfigSanity, ConfigSanityError},
    datatypes::{ComParams, FaultConfig},
    dlt_ctx,
};
use cda_plugin_security::{
    DefaultSecurityPlugin, DefaultSecurityPluginData, SecurityPlugin, SecurityPluginLoader,
};
use cda_sovd::Locks;
use cda_tracing::{OtelGuard, TracingSetupError, TracingWorkerGuard};
use clap::{Parser, Subcommand};
use figment::{
    Figment,
    providers::{Format, Serialized, Toml},
};
use futures::future::FutureExt;
use tokio::sync::{Mutex, RwLock, mpsc};
use tracing_subscriber::layer::SubscriberExt;

use crate::{
    config::configfile::Configuration,
    mdd::{load_databases, resolve_mdd_paths},
    update::{RuntimeUpdateContext, security::UpdateSecurityHandler},
};

pub mod config;
pub mod mdd;
pub mod update;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const DOIP_HEALTH_COMPONENT_KEY: &str = "doip";

#[cfg(feature = "health")]
const MAIN_HEALTH_COMPONENT_KEY: &str = "main";

pub type DatabaseMap<S> = HashMap<String, RwLock<EcuManager<S>>>;
pub type FileManagerMap = HashMap<String, FileManager>;

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Generate a reference TOML configuration file with all fields commented out
    GenerateConfig {
        /// Output file path (defaults to opensovd-cda.toml). Use "-" for stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct AppArgs {
    #[arg(short, long, env = "CDA_CONFIG_FILE")]
    pub config: Option<String>,

    #[command(subcommand)]
    pub command: Option<Command>,

    #[arg(short, long)]
    pub databases_path: Option<String>,

    #[arg(short, long)]
    pub tester_address: Option<String>,

    #[arg(long)]
    pub tester_subnet: Option<String>,

    #[arg(long)]
    pub gateway_port: Option<u16>,

    /// Protocol name used for com-param lookups
    /// in the diagnostic database (matched case-insensitively).
    /// Examples: `UDS_Ethernet_DoIP`, `UDS_Ethernet_DoIP_DOBT`
    #[arg(long)]
    pub protocol_name: Option<String>,

    #[arg(long)]
    pub listen_address: Option<String>,

    #[arg(long)]
    pub listen_port: Option<u16>,

    #[arg(short, long)]
    pub flash_files_path: Option<String>,

    #[arg(long)]
    pub file_logging: Option<bool>,

    #[arg(long)]
    pub log_file_dir: Option<String>,

    #[arg(long)]
    pub log_file_name: Option<String>,

    #[arg(long)]
    pub exit_no_database_loaded: Option<bool>,

    #[arg(long)]
    pub fallback_to_base_variant: Option<bool>,

    /// Set to true, to rewrite mdd files without compression, which
    /// reduces memory usage due to mmap significantly.
    // Could use Action::SetFalse here, as the default is false but then we would have
    // two different ways to set booleans (with and without `true`)
    #[arg(long)]
    pub mdd_decompress: Option<bool>,
}

pub struct VehicleData<S: SecurityPlugin> {
    pub file_managers: FileManagerMap,
    pub uds_manager: UdsManagerType<S>,
    pub diagnostic_gateway: DoipDiagGateway<EcuManager<S>>,
    pub locks: Arc<cda_sovd::Locks>,
    pub update_guard: cda_sovd::UpdateGuardState,
    pub databases: Arc<DatabaseMap<S>>,
    pub variant_detection_handle: tokio::task::JoinHandle<()>,
    pub health_providers: Option<HealthProviders>,
}

pub struct VehicleComponents<S: SecurityPlugin> {
    pub uds_manager: UdsManagerType<S>,
    pub diagnostic_gateway: DoipDiagGateway<EcuManager<S>>,
    pub databases: Arc<DatabaseMap<S>>,
    pub file_managers: FileManagerMap,
    pub variant_detection_handle: tokio::task::JoinHandle<()>,
}

#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error("Initialization failed `{0}`")]
    InitializationFailed(String),
    #[error("Resource error: `{0}`")]
    ResourceError(String),
    #[error("Connection error `{0}`")]
    ConnectionError(String),
    #[error("Configuration error `{0}`")]
    ConfigurationError(String),
    #[error("Data error `{0}`")]
    DataError(String),
    #[error("Error during execution `{0}`")]
    RuntimeError(String),
    #[error("Not found: `{0}`")]
    NotFound(String),
    #[error("Server error: `{0}`")]
    ServerError(String),
    #[error("Shutdown requested")]
    ShutdownRequested,
}

impl From<DiagServiceError> for AppError {
    fn from(value: DiagServiceError) -> Self {
        match value {
            DiagServiceError::RequestNotSupported(_)
            | DiagServiceError::BadPayload(_)
            | DiagServiceError::ConnectionClosed(_)
            | DiagServiceError::UnexpectedResponse(_)
            | DiagServiceError::EcuOffline(_)
            | DiagServiceError::NoResponse(_)
            | DiagServiceError::SendFailed(_)
            | DiagServiceError::InvalidAddress(_)
            | DiagServiceError::InvalidRequest(_)
            | DiagServiceError::Timeout => Self::ConnectionError(value.to_string()),

            DiagServiceError::ParameterConversionError(_)
            | DiagServiceError::UnknownOperation
            | DiagServiceError::UdsLookupError(_)
            | DiagServiceError::VariantDetectionError(_)
            | DiagServiceError::AccessDenied(_)
            | DiagServiceError::InvalidState(_)
            | DiagServiceError::Nack(_) => Self::RuntimeError(value.to_string()),

            DiagServiceError::InvalidConfiguration(_) | DiagServiceError::InvalidSecurityPlugin => {
                Self::ConfigurationError(value.to_string())
            }

            DiagServiceError::ResourceError(_) => Self::ResourceError(value.to_string()),

            DiagServiceError::NotFound(_) => Self::NotFound(value.to_string()),

            DiagServiceError::DataError(_)
            | DiagServiceError::InvalidDatabase(_)
            | DiagServiceError::AmbiguousParameters { .. }
            | DiagServiceError::InvalidParameter { .. }
            | DiagServiceError::NotEnoughData { .. } => Self::DataError(value.to_string()),
        }
    }
}

impl From<DoipGatewaySetupError> for AppError {
    fn from(value: DoipGatewaySetupError) -> Self {
        match value {
            DoipGatewaySetupError::InvalidAddress(_) => Self::ConnectionError(value.to_string()),
            DoipGatewaySetupError::SocketCreationFailed(_)
            | DoipGatewaySetupError::PortBindFailed(_) => {
                Self::InitializationFailed(value.to_string())
            }
            DoipGatewaySetupError::InvalidConfiguration(_) => {
                Self::ConfigurationError(value.to_string())
            }
            DoipGatewaySetupError::ResourceError(_) => Self::ResourceError(value.to_string()),
            DoipGatewaySetupError::ServerError(_) => Self::ServerError(value.to_string()),
            DoipGatewaySetupError::UnknownECU {
                logical_address,
                protocol_version,
            } => Self::ConfigurationError(format!(
                "Unknown ECU with logical address {logical_address} and protocol version \
                 {protocol_version}"
            )),
        }
    }
}

impl From<TracingSetupError> for AppError {
    fn from(value: TracingSetupError) -> Self {
        match value {
            TracingSetupError::ResourceCreationFailed(_) => Self::ResourceError(value.to_string()),
            TracingSetupError::SubscriberInitializationFailed(_) => {
                Self::InitializationFailed(value.to_string())
            }
        }
    }
}

impl From<ConfigSanityError> for AppError {
    fn from(value: ConfigSanityError) -> Self {
        AppError::ConfigurationError(value.to_string())
    }
}

impl AppArgs {
    #[tracing::instrument(skip(self, config),
        fields(
            dlt_context = dlt_ctx!("MAIN"),
        )
    )]
    pub fn update_config(self, config: &mut Configuration) {
        if let Some(databases_path) = self.databases_path {
            config.database.path = databases_path;
        }
        if let Some(exit_no_database_loaded) = self.exit_no_database_loaded {
            config.database.exit_no_database_loaded = exit_no_database_loaded;
        }
        if let Some(fallback_to_base_variant) = self.fallback_to_base_variant {
            config.database.fallback_to_base_variant = fallback_to_base_variant;
        }
        if let Some(flash_files_path) = self.flash_files_path {
            config.flash_files_path = flash_files_path;
        }
        if let Some(tester_address) = self.tester_address {
            config.doip.tester_address = tester_address;
        }
        if let Some(tester_subnet) = self.tester_subnet {
            config.doip.tester_subnet = tester_subnet;
        }
        if let Some(gateway_port) = self.gateway_port {
            config.doip.gateway_port = gateway_port;
        }
        if let Some(protocol_name) = self.protocol_name {
            config.doip.protocol_name = protocol_name;
        }
        if let Some(listen_address) = self.listen_address {
            config.server.address = listen_address;
        }
        if let Some(listen_port) = self.listen_port {
            config.server.port = listen_port;
        }
        if let Some(file_logging) = self.file_logging {
            config.logging.log_file_config.enabled = file_logging;
        }
        if let Some(log_file_dir) = self.log_file_dir {
            config.logging.log_file_config.path = log_file_dir;
        }
        if let Some(log_file_name) = self.log_file_name {
            config.logging.log_file_config.name = log_file_name;
        }
        if let Some(mdd_decompress) = self.mdd_decompress {
            config.flat_buf.mdd_decompress = mdd_decompress;
        }
    }
}

/// Generate a reference CDA configuration and write it to the requested output.
///
/// # Errors
/// Returns [`AppError`] if generating the reference configuration or writing it fails.
pub fn generate_config_cmd(output: Option<&PathBuf>) -> Result<(), AppError> {
    let content = config::generate::generate_reference_config()
        .map_err(|e| AppError::RuntimeError(format!("Failed to generate config: {e}")))?;

    match output.map(|p| p.as_os_str()) {
        Some(p) if p == "-" => {
            use std::io::Write;
            std::io::stdout()
                .write_all(content.as_bytes())
                .map_err(|e| AppError::RuntimeError(format!("Failed to write stdout: {e}")))?;
        }
        Some(path) => {
            std::fs::write(path, &content)
                .map_err(|e| AppError::RuntimeError(format!("Failed to write config: {e}")))?;
        }
        None => {
            std::fs::write("opensovd-cda.toml", &content)
                .map_err(|e| AppError::RuntimeError(format!("Failed to write config: {e}")))?;
        }
    }
    Ok(())
}

/// Parse CLI arguments and start the CDA with the default startup flow.
///
/// # Errors
/// Returns [`AppError`] if configuration loading, validation, or startup fails.
pub async fn run_from_cli() -> Result<(), AppError> {
    // Box is needed because it's a large future with a size of 16392 bytes
    Box::pin(run(AppArgs::parse())).await
}

#[tracing::instrument(
    skip(args, extra_health_providers, pre_load_hook),
    fields(
        dlt_context = dlt_ctx!("MAIN"),
    )
)]
/// Run the CDA from parsed CLI arguments, with optional extra health providers and a
/// pre-vehicle-load hook. See [`run_with_config_ext`] for parameter documentation.
///
/// # Errors
/// Returns [`AppError`] if configuration loading, validation, or startup fails.
pub async fn run_with_ext<SP, SL, H, Fut>(
    args: AppArgs,
    extra_health_providers: Vec<(&'static str, Arc<dyn cda_health::HealthProvider>)>,
    pre_load_hook: H,
) -> Result<(), AppError>
where
    SP: SecurityPlugin,
    SL: SecurityPluginLoader,
    H: FnOnce(cda_sovd::dynamic_router::DynamicRouter) -> Fut + Send,
    Fut: Future<Output = Result<(), AppError>> + Send,
{
    if let Some(Command::GenerateConfig { output }) = args.command.as_ref() {
        // Exiting after generating config is on purpose.
        return generate_config_cmd(output.as_ref());
    }

    let (mut config, disk_loaded) = config::load_config_with_fallback(args.config.as_deref());

    if disk_loaded && config.runtime_update_config.init_storage_from_config_file {
        let config_file = config::resolve_config_file_path(args.config.as_deref());
        config::seed_storage_from_config_file(
            &config.runtime_update_config.storage_dir,
            &config_file,
        )
        .await;
    }

    if let Some(storage_config) =
        config::load_config_with_storage_override(&config.runtime_update_config.storage_dir).await?
    {
        config = storage_config;
    } else if !disk_loaded {
        config::require_config_source()?;
    }

    // Command line arguments always take precedence over stored configuration
    args.update_config(&mut config);

    config.validate_sanity().map_err(AppError::from)?;

    run_with_config_ext::<SP, SL, _, _>(config, extra_health_providers, pre_load_hook).await
}

/// Run the CDA from parsed CLI arguments.
///
/// # Errors
/// Returns [`AppError`] if configuration loading, validation, or startup fails.
pub async fn run(args: AppArgs) -> Result<(), AppError> {
    Box::pin(run_with_ext::<
        DefaultSecurityPluginData,
        DefaultSecurityPlugin,
        _,
        _,
    >(args, vec![], |_| async { Ok(()) }))
    .await
}

/// Start the CDA runtime from a prepared configuration, with optional extra health providers
/// and a pre-vehicle-load hook.
///
/// - `extra_health_providers`: additional `(key, provider)` pairs registered into the health
///   state alongside the built-in `main` provider. Ignored when the `health` feature is
///   disabled or `config.health.enabled` is `false`.
/// - `pre_load_hook`: called after the webserver, health state, and sd-notify are set up but
///   **before** vehicle data is loaded. Use it to register extra routes or endpoints that
///   should be available during (and benefit from parallelism with) the database load.
///   Must return `Ok(())` to continue startup; an `Err` aborts immediately.
/// - `SP` / `SL`: security plugin data and loader types. Use [`DefaultSecurityPluginData`] and
///   [`DefaultSecurityPlugin`] for the default behaviour.
///
/// # Errors
/// Returns [`AppError`] if tracing setup, webserver startup, hook execution, data loading, or
/// route setup fails.
pub async fn run_with_config_ext<SP, SL, H, Fut>(
    config: Configuration,
    extra_health_providers: Vec<(&'static str, Arc<dyn cda_health::HealthProvider>)>,
    pre_load_hook: H,
) -> Result<(), AppError>
where
    SP: SecurityPlugin,
    SL: SecurityPluginLoader,
    H: FnOnce(cda_sovd::dynamic_router::DynamicRouter) -> Fut + Send,
    Fut: Future<Output = Result<(), AppError>> + Send,
{
    let _tracing_guards = setup_tracing(&config)?;
    tracing::info!("Starting CDA - version {}", cda_version());

    let webserver_config = cda_sovd::WebServerConfig {
        host: config.server.address.clone(),
        port: config.server.port,
    };

    let clonable_shutdown_signal = shutdown_signal().shared();

    let (dynamic_router, webserver_task) =
        cda_sovd::launch_webserver(webserver_config.clone(), clonable_shutdown_signal.clone())
            .await?;

    #[cfg(feature = "health")]
    let (health_state, main_health_provider) = if config.health.enabled {
        let health_state =
            cda_health::add_health_routes(&dynamic_router, cda_version().to_owned()).await;
        let main_health_provider = Arc::new(cda_health::StatusHealthProvider::new(
            cda_health::Status::Starting,
        ));

        health_state
            .register_provider(
                MAIN_HEALTH_COMPONENT_KEY,
                Arc::clone(&main_health_provider) as Arc<dyn cda_health::HealthProvider>,
            )
            .await
            .map_err(|e| AppError::InitializationFailed(e.to_string()))?;
        for (key, provider) in extra_health_providers {
            health_state
                .register_provider(key, provider)
                .await
                .map_err(|e| AppError::InitializationFailed(e.to_string()))?;
        }
        (Some(health_state), Some(main_health_provider))
    } else {
        (None, None)
    };

    #[cfg(not(feature = "health"))]
    let (health_state, main_health_provider): (
        Option<cda_health::HealthState>,
        Option<Arc<cda_health::StatusHealthProvider>>,
    ) = {
        // Prevents compiler warning for unused variable when health feature is disabled
        let _ = extra_health_providers;
        (None, None)
    };

    #[cfg(feature = "systemd-notify")]
    let _sd_notify_task =
        cda_extra::create_sd_notify_task(health_state.clone(), clonable_shutdown_signal.clone());

    register_version_endpoints(&dynamic_router).await;
    pre_load_hook(dynamic_router.clone()).await?;

    setup_vehicle_and_routes::<SP, SL>(
        config,
        &dynamic_router,
        &webserver_config,
        health_state.as_ref(),
        clonable_shutdown_signal.clone(),
    )
    .await?;

    tracing::info!("CDA fully initialized and ready to serve requests");
    if let Some(provider) = main_health_provider {
        provider.update_status(cda_health::Status::Up).await;
    }

    // Wait for shutdown signal
    clonable_shutdown_signal.await;
    tracing::info!("Shutting down...");
    webserver_task
        .await
        .map_err(|e| AppError::RuntimeError(format!("Webserver task join error: {e}")))?;

    Ok(())
}

/// Start the CDA runtime from a prepared configuration.
///
/// # Errors
/// Returns [`AppError`] if tracing setup, webserver startup, data loading, or route setup fails.
pub async fn run_with_config(config: Configuration) -> Result<(), AppError> {
    run_with_config_ext::<DefaultSecurityPluginData, DefaultSecurityPlugin, _, _>(
        config,
        vec![],
        |_| async { Ok(()) },
    )
    .await
}

/// Loads vehicle data, registers all SOVD routes, runtime-update routes, `OpenAPI` routes,
/// and installs the update guard. Extracted from `run_with_config` to keep it under the line limit.
///
/// The type parameters `SP` and `SL` select the security plugin data and loader implementations.
/// Use [`DefaultSecurityPluginData`] and [`DefaultSecurityPlugin`] for the default behaviour.
///
/// # Errors
/// Returns [`AppError`] if vehicle data loading, route registration, or update plugin setup fails.
pub async fn setup_vehicle_and_routes<SP: SecurityPlugin, SL: SecurityPluginLoader>(
    config: Configuration,
    dynamic_router: &cda_sovd::dynamic_router::DynamicRouter,
    webserver_config: &cda_sovd::WebServerConfig,
    health_state: Option<&cda_health::HealthState>,
    clonable_shutdown_signal: futures::future::Shared<
        impl std::future::Future<Output = ()> + Send + 'static,
    >,
) -> Result<(), AppError> {
    tracing::debug!("Webserver is running. Loading sovd routes...");

    let vehicle_data =
        match load_vehicle_data::<_, SP>(&config, clonable_shutdown_signal.clone(), health_state)
            .await
        {
            Ok(data) => data,
            Err(AppError::ShutdownRequested) => {
                tracing::info!("Shutdown requested during database load, exiting cleanly");
                return Ok(());
            }
            Err(e) => return Err(e),
        };

    if vehicle_data.databases.is_empty() && config.database.exit_no_database_loaded {
        return Err(AppError::ResourceError(
            "No database loaded, exiting as configured".to_string(),
        ));
    }

    let flash_files_path = config.flash_files_path.clone();
    let components_config = config.components.clone();
    let runtime_update_config = config.runtime_update_config.clone();

    let (ecu_execution_registry, vehicle_route_handle) = cda_sovd::add_vehicle_routes::<_, _, SL>(
        dynamic_router,
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
    let runtime_update_plugin =
        update::init_default_runtime_update_plugin::<SP, _, SL>(Box::new(RuntimeUpdateContext {
            dynamic_router: dynamic_router.clone(),
            vehicle_route_handle,
            config,
            flash_files_path,
            components_config,
            lock_provider: Arc::clone(&lock_provider),
            update_guard: vehicle_data.update_guard.clone(),
            shutdown_signal: clonable_shutdown_signal,
            runtime_update_config: runtime_update_config.clone(),
            ecu_execution_registry: ecu_execution_registry.clone(),
            uds_manager: vehicle_data.uds_manager,
            doip_gateway: vehicle_data.diagnostic_gateway,
            health: vehicle_data.health_providers,
            variant_detection_handle: Some(vehicle_data.variant_detection_handle),
            security_handler: Arc::new(UpdateSecurityHandler::new(
                Arc::clone(&lock_provider),
                vec![
                    Box::new(flash_transfer_guard),
                    Box::new(ecu_execution_registry),
                ],
            )),
        }))
        .await?;
    update::add_runtime_update_routes::<SL, _>(
        dynamic_router,
        runtime_update_plugin,
        lock_provider,
        &vehicle_data.update_guard,
        runtime_update_config.upload_body_limit_bytes,
        runtime_update_config.retry_after_seconds,
    )
    .await;

    cda_sovd::add_openapi_routes(dynamic_router, &vehicle_data.update_guard, webserver_config)
        .await;

    // SAFETY: Must be applied AFTER all routes are registered (layer only covers existing routes).
    cda_sovd::install_update_guard(dynamic_router, vehicle_data.update_guard.clone()).await;

    Ok(())
}

async fn register_version_endpoints(dynamic_router: &cda_sovd::dynamic_router::DynamicRouter) {
    // [[ dimpl~sovd-api-version-endpoint, Register Version Endpoint ]]
    let serde_json::Value::Object(version_info) = serde_json::json!({
        "id": "version",
        "data": {
            "name": "Eclipse OpenSOVD Classic Diagnostic Adapter",
            "api": {
                "version": "1.1"
            },
            "implementation": {
                "version": cda_version(),
                "commit": env!("GIT_COMMIT_HASH").to_owned(),
                "build_date": env!("BUILD_DATE").to_owned(),
            }
        }
    }) else {
        tracing::error!("Failed to build version information");
        return;
    };
    cda_sovd::add_static_data_endpoint(
        dynamic_router,
        version_info.clone(),
        "/vehicle/v15/apps/sovd2uds/data/version",
    )
    .await;
    cda_sovd::add_static_data_endpoint(dynamic_router, version_info, "/vehicle/v15/data/version")
        .await;
}

/// Loads vehicle data including MDD databases and vehicle components.
///
/// # Errors
/// Returns [`AppError`] if MDD path resolution, database loading, or component creation fails.
pub async fn load_vehicle_data<
    F: Future<Output = ()> + Clone + Send + 'static,
    S: SecurityPlugin,
>(
    config: &Configuration,
    clonable_shutdown_signal: F,
    health: Option<&cda_health::HealthState>,
) -> Result<VehicleData<S>, AppError> {
    let mdd_paths: Vec<PathBuf> = {
        let storage_dir = &config.runtime_update_config.storage_dir;
        let paths = resolve_mdd_paths(storage_dir, &config.database.path).await;
        if paths.is_empty() {
            return Err(AppError::InitializationFailed(
                "No MDD files found".to_string(),
            ));
        }
        paths
    };

    let health_providers = if let Some(health_state) = health {
        let doip = Arc::new(cda_health::StatusHealthProvider::new(
            cda_health::Status::Starting,
        ));
        let database = Arc::new(cda_health::StatusHealthProvider::new(
            cda_health::Status::Starting,
        ));
        health_state
            .register_provider(
                DOIP_HEALTH_COMPONENT_KEY,
                Arc::clone(&doip) as Arc<dyn cda_health::HealthProvider>,
            )
            .await
            .map_err(|e| AppError::InitializationFailed(e.to_string()))?;
        health_state
            .register_provider(
                mdd::DB_HEALTH_COMPONENT_KEY,
                Arc::clone(&database) as Arc<dyn cda_health::HealthProvider>,
            )
            .await
            .map_err(|e| AppError::InitializationFailed(e.to_string()))?;
        Some(HealthProviders { doip, database })
    } else {
        None
    };

    let update_guard = cda_sovd::UpdateGuardState::new();
    let doip_socket =
        cda_comm_doip::create_udp_vir_socket(&config.doip.tester_address, config.doip.gateway_port)
            .map_err(|e| {
                AppError::InitializationFailed(format!("Failed to create DoIP socket: {e}"))
            })?;
    let components = create_vehicle_components::<F, S>(
        config,
        &mdd_paths,
        clonable_shutdown_signal,
        health_providers.as_ref(),
        update_guard.busy_handle(),
        Arc::new(Mutex::new(doip_socket)),
    )
    .await?;

    let ecu_names = components.uds_manager.get_physical_ecus().await;
    Ok(VehicleData {
        uds_manager: components.uds_manager,
        diagnostic_gateway: components.diagnostic_gateway,
        file_managers: components.file_managers,
        locks: Arc::new(Locks::new(ecu_names)),
        update_guard,
        databases: components.databases,
        variant_detection_handle: components.variant_detection_handle,
        health_providers,
    })
}

pub type UdsManagerType<S> = UdsManager<DoipDiagGateway<EcuManager<S>>, EcuManager<S>>;

/// Creates a new UDS manager for the webserver.
/// type alias does not allow specifying hasher, we set the hasher globally.
#[allow(clippy::implicit_hasher)]
#[tracing::instrument(skip_all,
    fields(
        database_count = databases.len(),
        dlt_context = dlt_ctx!("MAIN"),
    )
)]
pub fn create_uds_manager<S: SecurityPlugin>(
    gateway: DoipDiagGateway<EcuManager<S>>,
    databases: Arc<HashMap<String, RwLock<EcuManager<S>>>>,
    variant_detection_receiver: mpsc::Receiver<Vec<String>>,
    functional_description_config: &FunctionalDescriptionConfig,
    fault_config: FaultConfig,
    update_in_progress: Arc<std::sync::atomic::AtomicBool>,
) -> UdsManagerType<S> {
    UdsManager::new(
        gateway,
        databases,
        variant_detection_receiver,
        functional_description_config,
        fault_config,
        update_in_progress,
    )
}

pub struct HealthProviders {
    pub doip: Arc<cda_health::StatusHealthProvider>,
    pub database: Arc<cda_health::StatusHealthProvider>,
}

/// Creates vehicle components (databases, `DoIP` gateway, UDS manager) from configuration.
///
/// # Errors
/// Returns [`AppError`] if database loading or diagnostic gateway creation fails.
pub async fn create_vehicle_components<
    F: Future<Output = ()> + Clone + Send + 'static,
    S: SecurityPlugin,
>(
    config: &Configuration,
    mdd_paths: &[PathBuf],
    shutdown_signal: F,
    health_providers: Option<&HealthProviders>,
    update_in_progress: Arc<std::sync::atomic::AtomicBool>,
    doip_socket: Arc<tokio::sync::Mutex<cda_comm_doip::socket::DoIPUdpSocket>>,
) -> Result<VehicleComponents<S>, AppError> {
    let db_provider = health_providers.map(|h| &h.database);
    let doip_provider = health_providers.map(|h| &h.doip);

    let (databases, file_managers) = load_databases::<S>(config, mdd_paths, db_provider).await?;

    let (variant_detection_tx, variant_detection_rx) = mpsc::channel(50);
    let databases = Arc::new(databases);
    let diagnostic_gateway = create_diagnostic_gateway(
        Arc::clone(&databases),
        &config.doip,
        variant_detection_tx,
        shutdown_signal,
        doip_provider,
        doip_socket,
    )
    .await?;

    let uds_manager = create_uds_manager(
        diagnostic_gateway.clone(),
        Arc::clone(&databases),
        variant_detection_rx,
        &config.functional_description,
        config.faults.clone(),
        update_in_progress,
    );

    let vd = uds_manager.clone();
    let variant_detection_handle = cda_interfaces::spawn_named!("variant-detection", async move {
        vd.start_variant_detection().await;
    });

    Ok(VehicleComponents {
        uds_manager,
        diagnostic_gateway,
        databases,
        file_managers,
        variant_detection_handle,
    })
}

#[tracing::instrument(
    skip(databases, variant_detection, shutdown_signal, doip_health_provider, doip_socket),
    fields(
        database_count = databases.len(),
        dlt_context = dlt_ctx!("MAIN"),
    )
)]
/// # Errors
/// Returns [`DoipGatewaySetupError`] if `DoIP` gateway initialization fails.
pub async fn create_diagnostic_gateway<S: SecurityPlugin>(
    databases: Arc<DatabaseMap<S>>,
    doip_config: &DoipConfig,
    variant_detection: mpsc::Sender<Vec<String>>,
    shutdown_signal: impl Future<Output = ()> + Send + 'static,
    doip_health_provider: Option<&Arc<cda_health::StatusHealthProvider>>,
    doip_socket: Arc<Mutex<cda_comm_doip::socket::DoIPUdpSocket>>,
) -> Result<DoipDiagGateway<EcuManager<S>>, DoipGatewaySetupError> {
    if let Some(provider) = doip_health_provider {
        provider.update_status(cda_health::Status::Starting).await;
    }

    let result = DoipDiagGateway::new(
        doip_config,
        databases,
        variant_detection,
        shutdown_signal,
        doip_socket,
    )
    .await;
    let status = if result.is_ok() {
        cda_health::Status::Up
    } else {
        cda_health::Status::Failed
    };
    if let Some(provider) = doip_health_provider {
        provider.update_status(status).await;
    }
    result
}

/// # Panics
/// Panics if the OS signal handlers cannot be installed.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}

pub struct TracingGuards {
    _file: Option<TracingWorkerGuard>,
    _otel: Option<OtelGuard>,
}

/// # Errors
/// Returns [`TracingSetupError`] if subscriber or exporter initialization fails.
pub fn setup_tracing(config: &Configuration) -> Result<TracingGuards, TracingSetupError> {
    let tracing = cda_tracing::new();
    let mut layers = vec![];
    layers.push(cda_tracing::new_term_subscriber(&config.logging));
    #[cfg(feature = "tokio-tracing")]
    layers.push(cda_tracing::new_tokio_tracing(
        &config.logging.tokio_tracing,
    )?);
    let otel_guard = if config.logging.otel.enabled {
        println!(
            "Starting OpenTelemetry tracing with {}",
            config.logging.otel.endpoint
        );
        let (guard, metrics_layer, otel_layer) =
            cda_tracing::new_otel_subscriber(&config.logging.otel)?;
        layers.push(metrics_layer);
        layers.push(otel_layer);
        Some(guard)
    } else {
        None
    };

    let file_guard = if config.logging.log_file_config.enabled {
        let (guard, file_layer) =
            cda_tracing::new_file_subscriber(&config.logging.log_file_config)?;
        layers.push(file_layer);
        Some(guard)
    } else {
        None
    };

    #[cfg(feature = "dlt-tracing")]
    if config.logging.dlt_tracing.enabled {
        layers.push(cda_tracing::new_dlt_tracing(&config.logging.dlt_tracing)?);
    }

    cda_tracing::init_tracing(tracing.with(layers))?;
    Ok(TracingGuards {
        _file: file_guard,
        _otel: otel_guard,
    })
}

#[must_use]
pub fn cda_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Compute the effective [`ComParams`] for a single ECU.
///
/// Starts from the global `global` config and merges any per-ECU TOML overrides
/// present in `ecu_table`.
///
/// Returns `None` (and emits a `tracing::error!`) if the TOML table cannot be
/// serialised or if figment extraction fails - the caller should `continue` to
/// the next ECU.
pub fn resolve_com_params(
    ecu_name: &str,
    global: &ComParams,
    ecu_overrides: Option<&config::configfile::EcuComParams>,
) -> Option<ComParams> {
    let params: ComParams = match ecu_overrides {
        None => global.clone(),
        Some(overrides) => {
            let toml_str = match toml::to_string(overrides) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(
                        ecu_name = %ecu_name,
                        error = %e,
                        "Failed to serialize per-ECU com_params TOML table; skipping ECU"
                    );
                    return None;
                }
            };
            match Figment::from(Serialized::defaults(global))
                .merge(Toml::string(&toml_str))
                .extract::<ComParams>()
            {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!(
                        ecu_name = %ecu_name,
                        error = %e,
                        "Failed to merge per-ECU com_params overrides; skipping ECU"
                    );
                    return None;
                }
            }
        }
    };

    Some(params)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_com_params_returns_none_on_figment_extraction_failure() {
        let global = ComParams::default();
        // Put a string where figment expects a table (the `uds` key should map
        // to a struct, not a scalar); this reliably triggers an extraction error.
        let mut table = toml::Table::new();
        table.insert(
            "uds".to_owned(),
            toml::Value::String("not_a_struct".to_owned()),
        );
        let ecu_params = crate::config::configfile::EcuComParams(table);
        let result = resolve_com_params("BAD_ECU", &global, Some(&ecu_params));
        assert!(
            result.is_none(),
            "resolve_com_params must return None when figment extraction fails"
        );
    }
}
