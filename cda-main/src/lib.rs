/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

use std::{fs::ReadDir, future::Future, path::PathBuf, sync::Arc};

use cda_comm_doip::{DoipDiagGateway, config::DoipConfig};
use cda_comm_uds::UdsManager;
use cda_core::{DiagServiceResponseStruct, EcuManager};
use cda_database::{FileManager, ProtoLoadConfig, update_mdd_uncompressed};
use cda_health::{HealthState, StatusHealthProvider};
use cda_interfaces::{
    DiagServiceError, DoipGatewaySetupError, EcuAddressProvider, EcuManager as EcuManagerTrait,
    EcuManagerType, FunctionalDescriptionConfig, HashMap, HashMapEntry, HashMapExtensions, HashSet,
    Protocol, UdsEcu,
    datatypes::{ComParams, DatabaseNamingConvention, FaultConfig, FlatbBufConfig},
    dlt_ctx,
    file_manager::{Chunk, ChunkType},
};
use cda_plugin_security::{DefaultSecurityPlugin, DefaultSecurityPluginData, SecurityPlugin};
use cda_sovd::Locks;
use cda_tracing::{OtelGuard, TracingSetupError, TracingWorkerGuard};
use clap::{Parser, Subcommand};
use figment::{
    Figment,
    providers::{Format, Serialized, Toml},
};
use futures::future::FutureExt;
use tokio::{
    signal,
    sync::{RwLock, mpsc},
    task::JoinHandle,
};
use tracing::Instrument;
use tracing_subscriber::layer::SubscriberExt;

use crate::config::configfile::{ConfigSanity, Configuration, EcuConfig};

pub mod config;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const DB_PARALLEL_LOAD_TASKS: usize = 2;

const DB_HEALTH_COMPONENT_KEY: &str = "database";
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

#[derive(Debug)]
struct EcuMetadata {
    mdd_path: String,
    valid: bool,
}

/// Configuration context for loading a single ECU database.
struct EcuLoadContext<'a> {
    mdd_path: String,
    mddfile: &'a PathBuf,
    ecu_name: String,
    flat_buf_settings: &'a FlatbBufConfig,
    database_config: &'a cda_database::DatabaseConfig,
    ecu_config_map: &'a Arc<HashMap<String, EcuConfig>>,
    database_naming_convention: DatabaseNamingConvention,
    func_description_cfg: &'a FunctionalDescriptionConfig,
    protocol: &'a Protocol,
    com_params: &'a Arc<ComParams>,
    fallback_to_base_variant: bool,
}

/// Result of building an ECU manager and associated metadata.
struct EcuLoadResult<S: SecurityPlugin> {
    manager: EcuManager<S>,
    metadata: EcuMetadata,
    files: Vec<Chunk>,
}

type LoadedEcuMap<S> = HashMap<String, (EcuManager<S>, EcuMetadata)>;

pub struct VehicleData<S: SecurityPlugin> {
    pub file_managers: FileManagerMap,
    pub uds_manager: UdsManagerType<S>,
    pub locks: Arc<cda_sovd::Locks>,
    pub databases: Arc<DatabaseMap<S>>,
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

pub const PROTO_LOAD_CONFIG: &[ProtoLoadConfig; 4] = &[
    ProtoLoadConfig {
        type_: ChunkType::DiagnosticDescription,
        load_data: true,
        name: None,
    },
    ProtoLoadConfig {
        type_: ChunkType::CodeFile,
        load_data: false,
        name: None,
    },
    ProtoLoadConfig {
        type_: ChunkType::CodeFilePartial,
        load_data: false,
        name: None,
    },
    ProtoLoadConfig {
        type_: ChunkType::EmbeddedFile,
        load_data: false,
        name: None,
    },
];

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

#[cfg(feature = "config-optional")]
#[allow(clippy::unnecessary_wraps)] // signature must match the `not(feature)` variant
fn load_config_or_default(config_path: Option<&str>) -> Result<Configuration, AppError> {
    Ok(config::load_config(config_path).unwrap_or_else(|e| {
        println!("Failed to load configuration: {e}");
        println!("Using default values");
        config::default_config()
    }))
}

/// Without `config-optional`, a missing or invalid configuration is a hard error.
#[cfg(not(feature = "config-optional"))]
fn load_config_or_default(config_path: Option<&str>) -> Result<Configuration, AppError> {
    config::load_config(config_path).map_err(|e| {
        println!("Failed to load configuration: {e}");
        println!(
            "Provide a configuration file or build with the 'config-optional' feature to allow \
             starting without one."
        );
        AppError::ConfigurationError(e)
    })
}

pub async fn run_from_cli() -> Result<(), AppError> {
    run(AppArgs::parse()).await
}

#[tracing::instrument(
    skip(args),
    fields(
        dlt_context = dlt_ctx!("MAIN"),
    )
)]
pub async fn run(args: AppArgs) -> Result<(), AppError> {
    if let Some(Command::GenerateConfig { output }) = args.command.as_ref() {
        // Exiting after generating config is on purpose.
        return generate_config_cmd(output.as_ref());
    }

    let mut config = load_config_or_default(args.config.as_deref())?;
    config.validate_sanity()?;

    args.update_config(&mut config);

    run_with_config(config).await
}

pub async fn run_with_config(config: Configuration) -> Result<(), AppError> {
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

        if let Err(e) = health_state
            .register_provider(
                MAIN_HEALTH_COMPONENT_KEY,
                Arc::clone(&main_health_provider) as Arc<dyn cda_health::HealthProvider>,
            )
            .await
        {
            tracing::warn!(error = %e, "Failed to register main health provider");
        }
        (Some(health_state), Some(main_health_provider))
    } else {
        (None, None)
    };

    #[cfg(not(feature = "health"))]
    let (health_state, main_health_provider): (
        Option<cda_health::HealthState>,
        Option<Arc<cda_health::StatusHealthProvider>>,
    ) = (None, None);

    #[cfg(feature = "systemd-notify")]
    let _sd_notify_task =
        cda_extra::create_sd_notify_task(health_state.clone(), clonable_shutdown_signal.clone());

    tracing::debug!("Webserver is running. Loading sovd routes...");

    let vehicle_data = match load_vehicle_data::<_, DefaultSecurityPluginData>(
        &config,
        clonable_shutdown_signal.clone(),
        health_state.as_ref(),
    )
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

    cda_sovd::add_vehicle_routes::<DiagServiceResponseStruct, _, _, DefaultSecurityPlugin>(
        &dynamic_router,
        vehicle_data.uds_manager,
        config.flash_files_path.clone(),
        vehicle_data.file_managers,
        vehicle_data.locks,
        config.functional_description,
        config.components,
    )
    .await?;

    // [[ dimpl~sovd-api-version-endpoint, Register Version Endpoint ]]
    if let serde_json::Value::Object(version_info) = serde_json::json!({
        "id": "version",
        "data": {
            "name": "Eclipse OpenSOVD Classic Diagnostic Adapter",
            "api": {
                // 1.1 to match the sovd standard version
                "version": "1.1"
            },
            "implementation": {
                "version": cda_version(),
                "commit": env!("GIT_COMMIT_HASH").to_owned(),
                "build_date": env!("BUILD_DATE").to_owned(),
            }
        }
    }) {
        cda_sovd::add_static_data_endpoint(
            &dynamic_router,
            version_info.clone(),
            "/vehicle/v15/apps/sovd2uds/data/version",
        )
        .await;
        // For now, both version endpoints serve the same data. This might change in the future.
        cda_sovd::add_static_data_endpoint(
            &dynamic_router,
            version_info,
            "/vehicle/v15/data/version",
        )
        .await;
    } else {
        tracing::error!("Failed to build version information");
    }

    cda_sovd::add_openapi_routes(&dynamic_router, &webserver_config).await;

    tracing::info!("CDA fully initialized and ready to serve requests");
    if let Some(provider) = main_health_provider {
        provider.update_status(cda_health::Status::Up).await;
    }

    clonable_shutdown_signal.await;
    tracing::info!("Shutting down...");
    webserver_task
        .await
        .map_err(|e| AppError::RuntimeError(format!("Webserver task join error: {e}")))?;

    Ok(())
}

/// Loads vehicle databases and sets up SOVD routes in the webserver.
/// # Errors
/// Returns `DoipGatewaySetupError` if we failed to create the diagnostic gateway
pub async fn load_vehicle_data<
    F: Future<Output = ()> + Clone + Send + 'static,
    S: SecurityPlugin,
>(
    config: &Configuration,
    clonable_shutdown_signal: F,
    health: Option<&cda_health::HealthState>,
) -> Result<VehicleData<S>, AppError> {
    // Load databases in the background
    let (databases, file_managers) = load_databases::<S>(config, health).await?;

    let (variant_detection_tx, variant_detection_rx) = mpsc::channel(50);
    let databases = Arc::new(databases);
    let diagnostic_gateway = match create_diagnostic_gateway(
        Arc::clone(&databases),
        &config.doip,
        variant_detection_tx,
        clonable_shutdown_signal.clone(),
        health,
    )
    .await
    {
        Ok(gateway) => gateway,
        Err(e) => {
            tracing::error!(error = %e, "Failed to create diagnostic gateway");
            return Err(e.into());
        }
    };

    let uds = create_uds_manager(
        diagnostic_gateway,
        Arc::clone(&databases),
        variant_detection_rx,
        &config.functional_description,
        config.faults.clone(),
    );
    tracing::debug!("Starting variant detection");
    let vdetect = uds.clone();
    cda_interfaces::spawn_named!("startup-variant-detection", async move {
        vdetect.start_variant_detection().await;
    });

    let ecu_names = uds.get_physical_ecus().await;
    Ok(VehicleData {
        uds_manager: uds,
        file_managers,
        locks: Arc::new(Locks::new(ecu_names)),
        databases,
    })
}

/// Loads all MDD databases and file managers from the configured database path.
///
/// # Errors
///
/// Returns [`AppError::ShutdownRequested`] if a shutdown signal is received while
/// databases are still being loaded.
#[tracing::instrument(
    skip(config, health),
    fields(databases_path = %config.database.path)
)]
pub async fn load_databases<S: SecurityPlugin>(
    config: &Configuration,
    health: Option<&cda_health::HealthState>,
) -> Result<(DatabaseMap<S>, FileManagerMap), AppError> {
    // Extract fields from config
    let database_path = &config.database.path;
    let flat_buf_settings = config.flat_buf.clone();
    let database_naming_convention = config.database.naming_convention.clone();
    let func_description_cfg = config.functional_description.clone();
    let fallback_to_base_variant = config.database.fallback_to_base_variant;
    let database_config = config.database.clone();
    let strict_ecu_config = database_config.strict_ecu_config;
    let protocol = cda_interfaces::Protocol::new(config.doip.protocol_name.clone());
    let com_params = config.com_params.clone();

    // Build a normalised (lowercase keys) copy of the per-ECU config map so
    // that lookups are always case-insensitive, consistent with DatabaseMap.
    let ecu_config_map: HashMap<String, EcuConfig> = config
        .ecu
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.clone()))
        .collect();

    let db_health_provider = setup_db_health_provider(health).await;

    let databases: Arc<RwLock<LoadedEcuMap<S>>> = Arc::new(RwLock::new(HashMap::new()));

    let file_managers: Arc<RwLock<HashMap<String, FileManager>>> =
        Arc::new(RwLock::new(HashMap::new()));

    let com_params = Arc::new(com_params);
    let ecu_config_map = Arc::new(ecu_config_map);

    let mut database_load_futures = Vec::new();
    let start = std::time::Instant::now();
    'load_database: {
        let files = match std::fs::read_dir(database_path) {
            Ok(files) => files,
            Err(e) => {
                tracing::error!(error = %e, "Failed to read directory");
                if let Some(provider) = &db_health_provider {
                    provider.update_status(cda_health::Status::Failed).await;
                }
                break 'load_database;
            }
        };

        let files = get_mdd_files_and_size(files);
        let chunk_size = files
            .len()
            .checked_div(DB_PARALLEL_LOAD_TASKS.saturating_add(1))
            .unwrap_or(1)
            .max(1);

        tracing::info!(chunk_size = %chunk_size, "Loading databases");

        for (i, mddfiles) in files.chunks(chunk_size).enumerate() {
            let database = Arc::clone(&databases);
            let file_managers = Arc::clone(&file_managers);
            let paths = mddfiles.to_vec();
            let com_params = Arc::clone(&com_params);
            let ecu_config_map = Arc::clone(&ecu_config_map);
            let database_naming_convention = database_naming_convention.clone();
            let flat_buf_settings = flat_buf_settings.clone();
            let func_description_cfg = func_description_cfg.clone();
            let protocol = protocol.clone();
            let database_config = database_config.clone();

            database_load_futures.push(cda_interfaces::spawn_named!(
                &format!("load-database-{i}"),
                async move {
                    load_database(
                        protocol,
                        database,
                        file_managers,
                        paths,
                        com_params,
                        ecu_config_map,
                        database_naming_convention,
                        flat_buf_settings,
                        func_description_cfg,
                        fallback_to_base_variant,
                        database_config,
                    )
                    .await;
                }
                .instrument(tracing::info_span!("load_database_chunk", chunk_id = i))
            ));
        }
    }

    wait_for_databases_loaded(database_load_futures).await?;
    let databases = databases
        .write()
        .await
        .drain()
        .filter(|(_, (_, meta))| meta.valid)
        .map(|(k, (ecu_manager, _))| (k.to_lowercase(), RwLock::new(ecu_manager)))
        .collect::<HashMap<String, RwLock<EcuManager<S>>>>();
    mark_duplicate_ecus_by_address(&databases).await;

    let file_managers = file_managers
        .write()
        .await
        .drain()
        .map(|(k, v)| (k.to_lowercase(), v))
        .collect::<HashMap<String, FileManager>>();

    // Warn for any per-ECU config keys that did not match a loaded database.
    warn_unmatched_ecu_config_keys(&ecu_config_map, &databases, strict_ecu_config)?;

    let end = std::time::Instant::now();

    tracing::info!(
        database_count = &databases.len(),
        duration = ?end.saturating_duration_since(start),
        "Loaded databases");
    let status = if databases.is_empty() {
        cda_health::Status::Failed
    } else {
        cda_health::Status::Up
    };

    if let Some(provider) = db_health_provider {
        provider.update_status(status).await;
    }
    Ok((databases, file_managers))
}

async fn wait_for_databases_loaded(
    database_load_futures: Vec<JoinHandle<()>>,
) -> Result<(), AppError> {
    for f in database_load_futures {
        tokio::select! {
            () = shutdown_signal() => {
                tracing::info!("Shutdown triggered. Aborting DB load...");
                return Err(AppError::ShutdownRequested);
            },
            res = f =>{
                if let Err(e) = res {
                    tracing::error!(error = ?e, "Failed to load ecu data");
                }
            }
        }
    }
    Ok(())
}

fn get_mdd_files_and_size(files: ReadDir) -> Vec<(PathBuf, u64)> {
    let mut files = files
        .filter_map(|entry| {
            entry.ok().and_then(|entry| {
                let path = entry.path();
                if path.is_file() && path.extension().is_some_and(|ext| ext == "mdd") {
                    let filesize = std::fs::metadata(&path).ok().map_or(0u64, |m| m.len());
                    Some((path, filesize))
                } else {
                    None
                }
            })
        })
        .collect::<Vec<_>>();

    files.sort_by_key(|b| std::cmp::Reverse(b.1));
    files
}

async fn setup_db_health_provider(
    health: Option<&HealthState>,
) -> Option<Arc<StatusHealthProvider>> {
    if let Some(health_state) = health {
        let provider = Arc::new(cda_health::StatusHealthProvider::new(
            cda_health::Status::Starting,
        ));
        if let Err(e) = health_state
            .register_provider(
                DB_HEALTH_COMPONENT_KEY,
                Arc::clone(&provider) as Arc<dyn cda_health::HealthProvider>,
            )
            .await
        {
            tracing::warn!(error = %e, "Failed to register database health provider");
        }
        Some(provider)
    } else {
        None
    }
}

fn warn_unmatched_ecu_config_keys<S: SecurityPlugin>(
    ecu_config_map: &HashMap<String, EcuConfig>,
    databases: &HashMap<String, RwLock<EcuManager<S>>>,
    strict: bool,
) -> Result<(), AppError> {
    let mut unmatched = Vec::new();
    for ecu_key in ecu_config_map.keys() {
        if !databases.contains_key(ecu_key) {
            tracing::warn!(
                ecu_name = %ecu_key,
                "Per-ECU config entry does not match any loaded MDD database - ignored"
            );
            unmatched.push(ecu_key.clone());
        }
    }
    if strict && !unmatched.is_empty() {
        return Err(AppError::ConfigurationError(format!(
            "strict_ecu_config is enabled and the following per-ECU config entries do not match \
             any loaded database: {}",
            unmatched.join(", ")
        )));
    }
    Ok(())
}

async fn mark_duplicate_ecus_by_address<S: SecurityPlugin>(
    databases: &HashMap<String, RwLock<EcuManager<S>>>,
) {
    let mut ecus_by_address: HashMap<u16, HashMap<u16, Vec<String>>> = HashMap::new();
    for (name, db_lock) in databases {
        let db = db_lock.read().await;
        let logical_address = db.logical_address();
        let gateway_address = db.logical_gateway_address();
        ecus_by_address
            .entry(gateway_address)
            .or_default()
            .entry(logical_address)
            .or_default()
            .push(name.clone());
    }

    for logical_map in ecus_by_address.values() {
        for ecu_names in logical_map.values() {
            if ecu_names.len() <= 1 {
                continue;
            }

            for ecu_name in ecu_names {
                let Some(db_lock) = databases.get(ecu_name) else {
                    continue;
                };

                let mut db = db_lock.write().await;
                let duplicates: HashSet<String> = ecu_names
                    .iter()
                    .filter(|&name| name != ecu_name)
                    .cloned()
                    .collect();
                db.set_duplicating_ecu_names(duplicates);
            }
        }
    }
}

/// Compute the effective [`ComParams`] for a single ECU.
///
/// Starts from the global `global` config and merges any per-ECU TOML overrides
/// present in `ecu_table`.
///
/// Returns `None` (and emits a `tracing::error!`) if the TOML table cannot be
/// serialised or if figment extraction fails - the caller should `continue` to
/// the next ECU.
pub(crate) fn resolve_com_params(
    ecu_name: &str,
    global: &ComParams,
    ecu_overrides: Option<&crate::config::configfile::EcuComParams>,
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

/// Extract and build the diagnostic database from proto data.
fn build_diagnostic_database(
    proto_data: &mut HashMap<ChunkType, Vec<Chunk>>,
    ctx: &EcuLoadContext<'_>,
) -> Option<cda_database::datatypes::DiagnosticDatabase> {
    let database_payload = proto_data
        .remove(&ChunkType::DiagnosticDescription)
        .and_then(|mut chunks| chunks.pop())
        .and_then(|c| c.payload);

    let payload = database_payload.or_else(|| {
        tracing::error!(
            mdd_file = %ctx.mddfile.display(),
            ecu_name = %ctx.ecu_name,
            "No payload found in diagnostic description for ECU"
        );
        None
    })?;

    let mut cfg = ctx.database_config.clone();
    if let Some(override_value) = ctx
        .ecu_config_map
        .get(&ctx.ecu_name.to_lowercase())
        .and_then(|c| c.ignore_protocol)
    {
        cfg.ignore_protocol = override_value;
    }

    cda_database::datatypes::DiagnosticDatabase::new_from_bytes(
        ctx.mdd_path.clone(),
        payload,
        ctx.flat_buf_settings.clone(),
        cfg,
    )
    .map_err(|e| {
        tracing::error!(
            mdd_file = %ctx.mddfile.display(),
            ecu_name = %ctx.ecu_name,
            error = %e,
            "Failed to create database from MDD payload"
        );
    })
    .ok()
}

/// Create an ECU manager from diagnostic database and configuration.
fn create_ecu_manager<S: SecurityPlugin>(
    diag_database: cda_database::datatypes::DiagnosticDatabase,
    protocol: Protocol,
    ecu_type: EcuManagerType,
    effective_com_params: &ComParams,
    ctx: &EcuLoadContext<'_>,
) -> Option<EcuManager<S>> {
    EcuManager::new(
        diag_database,
        protocol,
        effective_com_params,
        ctx.database_naming_convention.clone(),
        ecu_type,
        ctx.func_description_cfg,
        ctx.fallback_to_base_variant,
    )
    .map_err(|e| {
        tracing::error!(
            ecu_name = %ctx.ecu_name,
            error = ?e,
            "Failed to create DiagServiceManager"
        );
    })
    .ok()
}

/// Extract file chunks from proto data.
fn extract_file_chunks(mut proto_data: HashMap<ChunkType, Vec<Chunk>>) -> Vec<Chunk> {
    let filtered_chunks: Vec<Chunk> = [
        ChunkType::CodeFile,
        ChunkType::CodeFilePartial,
        ChunkType::EmbeddedFile,
    ]
    .iter()
    .filter_map(|chunk_type| proto_data.remove(chunk_type))
    .flat_map(std::iter::IntoIterator::into_iter)
    .collect();

    filtered_chunks
        .into_iter()
        .chain(proto_data.into_values().flat_map(IntoIterator::into_iter))
        .collect()
}

/// Load and process a single ECU from MDD file.
fn load_ecu_from_file<S: SecurityPlugin>(
    proto_data: HashMap<ChunkType, Vec<Chunk>>,
    ctx: &EcuLoadContext<'_>,
    per_ecu_cfg: Option<&EcuConfig>,
) -> Option<EcuLoadResult<S>> {
    let mut proto_data = proto_data;
    let diag_database = build_diagnostic_database(&mut proto_data, ctx)?;
    let effective_com_params = resolve_com_params(
        &ctx.ecu_name,
        ctx.com_params,
        per_ecu_cfg.and_then(|c| c.com_params.as_ref()),
    )?;
    let protocol = per_ecu_cfg.and_then(|c| c.protocol.as_deref()).map_or_else(
        || ctx.protocol.clone(),
        |name| Protocol::new(name.to_owned()),
    );
    let ecu_type = if ctx.func_description_cfg.description_database == ctx.ecu_name {
        EcuManagerType::FunctionalDescription
    } else {
        EcuManagerType::Ecu
    };
    let manager = create_ecu_manager(
        diag_database,
        protocol,
        ecu_type,
        &effective_com_params,
        ctx,
    )?;
    let files = extract_file_chunks(proto_data);

    Some(EcuLoadResult {
        manager,
        metadata: EcuMetadata {
            mdd_path: ctx.mdd_path.clone(),
            valid: true,
        },
        files,
    })
}

async fn store_ecu_data<S: SecurityPlugin>(
    database: &RwLock<LoadedEcuMap<S>>,
    file_managers: &Arc<RwLock<HashMap<String, FileManager>>>,
    ecu_name: String,
    result: EcuLoadResult<S>,
) {
    let mdd_path = result.metadata.mdd_path.clone();
    let files = result.files;

    check_duplicate_ecu_names(
        database,
        &mdd_path,
        &ecu_name,
        result.manager,
        result.metadata,
    )
    .await;

    file_managers
        .write()
        .await
        .insert(ecu_name, FileManager::new(mdd_path, files));
}

#[allow(clippy::too_many_arguments)]
#[tracing::instrument(
    skip_all,
    fields(
        paths_count = paths.len(),
        dlt_context = dlt_ctx!("MAIN"),
    )
)]
async fn load_database<S: SecurityPlugin>(
    protocol: Protocol,
    database: Arc<RwLock<LoadedEcuMap<S>>>,
    file_managers: Arc<RwLock<HashMap<String, FileManager>>>,
    paths: Vec<(PathBuf, u64)>,
    com_params: Arc<ComParams>,
    ecu_config_map: Arc<HashMap<String, EcuConfig>>,
    database_naming_convention: DatabaseNamingConvention,
    flat_buf_settings: FlatbBufConfig,
    func_description_cfg: FunctionalDescriptionConfig,
    fallback_to_base_variant: bool,
    database_config: cda_database::DatabaseConfig,
) {
    for (mddfile, _) in paths {
        let Some(mdd_path) = mddfile.to_str().map(ToOwned::to_owned) else {
            tracing::error!(
                mdd_file = %mddfile.display(),
                "Failed to convert MDD file path to string");
            continue;
        };

        // Ensure the MDD file contains uncompressed data (rewrite on first
        // use), so that subsequent loads skip LZMA decompression.
        if flat_buf_settings.mdd_decompress
            && let Err(e) = update_mdd_uncompressed(&mdd_path)
        {
            tracing::error!(
                mdd_file = %mddfile.display(),
                error = %e,
                "Failed to update MDD file with uncompressed data");
        }

        match cda_database::load_proto_data(&mdd_path, PROTO_LOAD_CONFIG) {
            Ok((ecu_name, proto_data)) => {
                let per_ecu_cfg = ecu_config_map.get(&ecu_name.to_lowercase());

                let ctx = EcuLoadContext {
                    mdd_path: mdd_path.clone(),
                    mddfile: &mddfile,
                    ecu_name: ecu_name.clone(),
                    flat_buf_settings: &flat_buf_settings,
                    database_config: &database_config,
                    ecu_config_map: &ecu_config_map,
                    database_naming_convention: database_naming_convention.clone(),
                    func_description_cfg: &func_description_cfg,
                    protocol: &protocol,
                    com_params: &com_params,
                    fallback_to_base_variant,
                };

                if let Some(result) = load_ecu_from_file(proto_data, &ctx, per_ecu_cfg) {
                    store_ecu_data(&database, &file_managers, ecu_name, result).await;
                }
            }
            Err(e) => {
                tracing::error!(
                    mdd_file = %mddfile.display(),
                    error = %e,
                    "Failed to load ecu data from file");
            }
        }
    }
}

async fn check_duplicate_ecu_names<S: SecurityPlugin>(
    database: &RwLock<LoadedEcuMap<S>>,
    mdd_path: &String,
    ecu_name: &String,
    diag_service_manager: EcuManager<S>,
    ecu_metadata: EcuMetadata,
) {
    let mut db_write = database.write().await;
    match db_write.entry(ecu_name.clone()) {
        HashMapEntry::Occupied(mut entry) => {
            let (existing_ecu, existing_meta) = entry.get_mut();

            if diag_service_manager.logical_address_eq(existing_ecu) {
                if diag_service_manager.revision() > existing_ecu.revision() {
                    tracing::warn!(
                        ecu_name = %ecu_name,
                        existing_mdd = %existing_meta.mdd_path,
                        existing_revision = %existing_ecu.revision(),
                        new_mdd = %mdd_path,
                        new_revision = %diag_service_manager.revision(),
                        "Replacing ECU with newer revision"
                    );
                    entry.insert((diag_service_manager, ecu_metadata));
                } else {
                    tracing::warn!(
                        ecu_name = %ecu_name,
                        existing_mdd = %existing_meta.mdd_path,
                        existing_revision = %existing_ecu.revision(),
                        new_mdd = %mdd_path,
                        new_revision = %diag_service_manager.revision(),
                        "Keeping existing ECU with newer or equal revision"
                    );
                }
            } else {
                tracing::error!(
                    ecu_name = %ecu_name,
                    "Duplicate ECU with different addresses. Marking as invalid."
                );
                existing_meta.valid = false;
            }
        }
        HashMapEntry::Vacant(entry) => {
            // Mark as invalid and remove later.
            // Not removing now, because there might be multiple duplicates and
            // if we would remove now, next duplicate would be added as new.
            entry.insert((diag_service_manager, ecu_metadata));
        }
    }
}

type UdsManagerType<S> =
    UdsManager<DoipDiagGateway<EcuManager<S>>, DiagServiceResponseStruct, EcuManager<S>>;

/// Creates a new UDS manager for the webserver.
// type alias does not allow specifying hasher, we set the hasher globally.
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
) -> UdsManagerType<S> {
    UdsManager::new(
        gateway,
        databases,
        variant_detection_receiver,
        functional_description_config,
        fault_config,
    )
}

/// Creates a new diagnostic gateway for the webserver.
/// # Errors
/// Returns a string error if the gateway cannot be initialized.
#[tracing::instrument(
    skip(databases, variant_detection, shutdown_signal, health),
    fields(
        database_count = databases.len(),
        dlt_context = dlt_ctx!("MAIN"),
    )
)]
pub async fn create_diagnostic_gateway<S: SecurityPlugin>(
    databases: Arc<DatabaseMap<S>>,
    doip_config: &DoipConfig,
    variant_detection: mpsc::Sender<Vec<String>>,
    shutdown_signal: impl Future<Output = ()> + Send + Clone + 'static,
    health: Option<&cda_health::HealthState>,
) -> Result<DoipDiagGateway<EcuManager<S>>, DoipGatewaySetupError> {
    let doip_health_provider = if let Some(health_state) = health {
        let provider = Arc::new(cda_health::StatusHealthProvider::new(
            cda_health::Status::Starting,
        ));
        if let Err(e) = health_state
            .register_provider(
                DOIP_HEALTH_COMPONENT_KEY,
                Arc::clone(&provider) as Arc<dyn cda_health::HealthProvider>,
            )
            .await
        {
            tracing::warn!(error = %e, "Failed to register DoIP health provider");
        }
        Some(provider)
    } else {
        None
    };

    let result =
        DoipDiagGateway::new(doip_config, databases, variant_detection, shutdown_signal).await;
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

/// Waits for a shutdown signal, such as Ctrl+C or SIGTERM (on unix).
/// # Panics
/// * If subscribing to the signals fails.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
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

/// Setup the tracing to provide logs and analytics.
/// # Errors
/// Returns a `TracingSetupError` if the tracing setup fails.
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

/// Retrieve the version of the opensovd-cda crate.
#[must_use]
pub fn cda_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
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
