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
use cda_comm_uds::{UdsManager, state_coordinator::EcuStateCoordinator};
use cda_core::EcuManager;
use cda_database::FileManager;
use cda_interfaces::{
    DoipGatewaySetupError, EcuConnectivityHandler, FunctionalDescriptionConfig, HashMap,
    HashMapExtensions, UdsQuery, UdsVariant,
    config::ConfigSanity,
    datatypes::{ComParams, FaultConfig},
    dlt_ctx,
    health::HealthProvider,
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
use tokio::sync::{Mutex, RwLock, mpsc};
use tracing_subscriber::layer::SubscriberExt;

use crate::{
    config::{configfile::Configuration, generate::generate_config_cmd},
    mdd::{load_databases, resolve_mdd_paths},
    setup::PreLoadHook,
    update::{UpdatePluginBuilder, create_default_update_plugin, update_plugin_fn},
};

pub mod config;
pub mod error;
pub mod mdd;
pub mod setup;
pub mod update;

pub use error::AppError;
pub use setup::Setup;

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
    pub health_providers: Option<HashMap<String, Arc<dyn HealthProvider>>>,
}

pub struct VehicleComponents<S: SecurityPlugin> {
    pub uds_manager: UdsManagerType<S>,
    pub diagnostic_gateway: DoipDiagGateway<EcuManager<S>>,
    pub databases: Arc<DatabaseMap<S>>,
    pub file_managers: FileManagerMap,
    pub variant_detection_handle: tokio::task::JoinHandle<()>,
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

/// Parse CLI arguments and start the CDA with the default startup flow.
///
/// # Errors
/// Returns [`AppError`] if configuration loading, validation, or startup fails.
pub async fn run_from_cli() -> Result<(), AppError> {
    // Box is needed because it's a large future with a size of 16392 bytes
    Box::pin(run(AppArgs::parse())).await
}

#[tracing::instrument(
    skip(args, setup),
    fields(
        dlt_context = dlt_ctx!("MAIN"),
    )
)]
/// Run the CDA from parsed CLI arguments with a custom [`Setup`].
///
/// This is the primary setup-aware entry point. Pass a [`Setup`] created with
/// [`Setup::new`] and optionally configured with
/// [`Setup::with_preload`] / [`Setup::with_update_plugin`].
///
/// # Errors
/// Returns [`AppError`] if configuration loading, validation, or startup fails.
pub async fn run_with_ext<SP, SL, UPB>(
    args: AppArgs,
    setup: Setup<SP, SL, UPB>,
) -> Result<(), AppError>
where
    SP: SecurityPlugin,
    SL: SecurityPluginLoader,
    UPB: UpdatePluginBuilder<SP>,
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

    run_with_ext_from_config(config, setup).await
}

/// Start the CDA runtime from a prepared configuration with a custom [`Setup`].
///
/// This is the setup-aware version of [`run_with_config`]. Supply a [`Setup`] to
/// configure a custom update plugin and/or a preload hook:
///
/// ```rust,ignore
/// use opensovd_cda_lib::{Setup, run_with_ext_from_config, update::update_plugin_fn};
/// use opensovd_cda_lib::config::configfile::Configuration;
///
/// let config: Configuration = // ... load or construct ...
/// # todo!();
///
/// run_with_ext_from_config::<MySecurityPlugin, MySecurityLoader, _>(
///     config,
///     Setup::new().with_update_plugin(update_plugin_fn(|infra| async move {
///         Ok(MyPlugin::new(infra))
///     })),
/// ).await?;
/// ```
///
/// # Errors
/// Returns [`AppError`] if tracing setup, webserver startup, data loading, or route setup fails.
pub async fn run_with_ext_from_config<SP, SL, UPB>(
    config: Configuration,
    setup: Setup<SP, SL, UPB>,
) -> Result<(), AppError>
where
    SP: SecurityPlugin,
    SL: SecurityPluginLoader,
    UPB: UpdatePluginBuilder<SP>,
{
    let webserver_state = init_webserver(&config, setup.pre_load).await?;

    tracing::debug!("Webserver is running. Loading sovd routes...");
    let vehicle_data = match load_vehicle_data::<SP>(
        &config,
        webserver_state.shutdown_signal.clone(),
        webserver_state.health_state.as_ref(),
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

    setup::setup_runtime_routes::<SP, SL, UPB>(
        config,
        vehicle_data,
        &webserver_state,
        setup.build_update_plugin,
    )
    .await?;

    tracing::info!("CDA fully initialized and ready to serve requests");
    if let Some(provider) = webserver_state.main_health_provider {
        provider.update_status(cda_health::Status::Up).await;
    }

    // Wait for shutdown signal
    webserver_state.shutdown_signal.await;
    tracing::info!("Shutting down...");
    webserver_state
        .webserver_task
        .await
        .map_err(|e| AppError::RuntimeError(format!("Webserver task join error: {e}")))?;

    Ok(())
}

/// Run the CDA from parsed CLI arguments.
///
/// Uses the default security plugin and the default runtime update plugin.
/// To customize startup behavior, use [`run_with_ext`] instead.
///
/// # Errors
/// Returns [`AppError`] if configuration loading, validation, or startup fails.
pub async fn run(args: AppArgs) -> Result<(), AppError> {
    Box::pin(run_with_ext::<
        DefaultSecurityPluginData,
        DefaultSecurityPlugin,
        _,
    >(
        args,
        Setup::new().with_update_plugin(update_plugin_fn(|infra| async move {
            create_default_update_plugin::<DefaultSecurityPluginData, DefaultSecurityPlugin>(infra)
                .await
        })),
    ))
    .await
}

/// Start the CDA runtime from a prepared configuration.
///
/// Uses the default security plugin and the default runtime update plugin.
/// To customize startup behavior, use [`run_with_ext_from_config`] instead.
///
/// # Errors
/// Returns [`AppError`] if tracing setup, webserver startup, data loading, or route setup fails.
pub async fn run_with_config(config: Configuration) -> Result<(), AppError> {
    run_with_ext_from_config::<DefaultSecurityPluginData, DefaultSecurityPlugin, _>(
        config,
        Setup::new().with_update_plugin(update_plugin_fn(
            |infra: setup::CdaRuntime<DefaultSecurityPluginData>| async move {
                create_default_update_plugin::<DefaultSecurityPluginData, DefaultSecurityPlugin>(
                    infra,
                )
                .await
            },
        )),
    )
    .await
}

async fn init_webserver(
    config: &Configuration,
    pre_load: Option<PreLoadHook>,
) -> Result<WebserverState, AppError> {
    let tracing_guards = setup_tracing(config)?;
    tracing::info!("Starting CDA - version {}", cda_version());

    let webserver_config = cda_sovd::WebServerConfig {
        host: config.server.address.clone(),
        port: config.server.port,
    };

    let clonable_shutdown_signal = cda_interfaces::shutdown_signal(shutdown_signal());

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

    register_version_endpoints(&dynamic_router).await;

    if let Some(hook) = pre_load {
        hook(dynamic_router.clone()).await?;
    }

    Ok(WebserverState {
        _tracing_guards: tracing_guards,
        dynamic_router,
        webserver_task,
        shutdown_signal: clonable_shutdown_signal,
        health_state,
        main_health_provider,
    })
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
pub async fn load_vehicle_data<S: SecurityPlugin>(
    config: &Configuration,
    clonable_shutdown_signal: cda_interfaces::ShutdownSignal,
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
        let mut providers: HashMap<String, Arc<dyn HealthProvider>> = HashMap::default();
        providers.insert(
            DOIP_HEALTH_COMPONENT_KEY.to_owned(),
            doip as Arc<dyn HealthProvider>,
        );
        providers.insert(
            mdd::DB_HEALTH_COMPONENT_KEY.to_owned(),
            database as Arc<dyn HealthProvider>,
        );
        Some(providers)
    } else {
        None
    };

    let update_guard = cda_sovd::UpdateGuardState::new();
    let doip_socket =
        cda_comm_doip::create_udp_vir_socket(&config.doip.tester_address, config.doip.gateway_port)
            .map_err(|e| {
                AppError::InitializationFailed(format!("Failed to create DoIP socket: {e}"))
            })?;
    let (components, databases) = create_vehicle_components::<S>(
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
        databases,
        variant_detection_handle: components.variant_detection_handle,
        health_providers,
    })
}

pub type UdsManagerType<S> = UdsManager<DoipDiagGateway<EcuManager<S>>, EcuManager<S>>;

#[allow(
    clippy::implicit_hasher,
    reason = "Type alias does not allow specifying hasher. Hasher is set globally"
)]
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
    state_coordinator: EcuStateCoordinator,
    functional_description_config: &FunctionalDescriptionConfig,
    fault_config: FaultConfig,
    update_in_progress: Arc<std::sync::atomic::AtomicBool>,
) -> UdsManagerType<S> {
    UdsManager::new(
        gateway,
        databases,
        variant_detection_receiver,
        state_coordinator,
        functional_description_config,
        fault_config,
        update_in_progress,
    )
}

/// Collected webserver state produced by [`init_webserver`].
///
/// Passed to [`setup::setup_runtime_routes`] and [`run_with_ext_from_config`] so that
/// the shutdown signal and health provider are accessible after the webserver is started.
pub(crate) struct WebserverState {
    _tracing_guards: TracingGuards,
    pub dynamic_router: cda_sovd::dynamic_router::DynamicRouter,
    webserver_task: tokio::task::JoinHandle<()>,
    pub shutdown_signal: cda_interfaces::ShutdownSignal,
    health_state: Option<cda_health::HealthState>,
    main_health_provider: Option<Arc<cda_health::StatusHealthProvider>>,
}

/// Creates vehicle components (databases, `DoIP` gateway, UDS manager) from configuration.
///
/// # Errors
/// Returns [`AppError`] if database loading or diagnostic gateway creation fails.
#[allow(
    clippy::implicit_hasher,
    reason = "Type alias does not allow specifying hasher. Hasher is set globally"
)]
pub async fn create_vehicle_components<S: SecurityPlugin>(
    config: &Configuration,
    mdd_paths: &[PathBuf],
    shutdown_signal: cda_interfaces::ShutdownSignal,
    health_providers: Option<&HashMap<String, Arc<dyn HealthProvider>>>,
    update_in_progress: Arc<std::sync::atomic::AtomicBool>,
    doip_socket: Arc<Mutex<cda_comm_doip::socket::DoIPUdpSocket>>,
) -> Result<
    (
        cda_interfaces::runtime_update_api::VehicleComponents<
            UdsManagerType<S>,
            DoipDiagGateway<EcuManager<S>>,
            FileManager,
        >,
        Arc<DatabaseMap<S>>,
    ),
    AppError,
> {
    let db_provider = health_providers.and_then(|h| h.get(mdd::DB_HEALTH_COMPONENT_KEY));
    let doip_provider = health_providers.and_then(|h| h.get(DOIP_HEALTH_COMPONENT_KEY));

    let (databases, file_managers) = load_databases::<S>(config, mdd_paths, db_provider).await?;

    let (variant_detection_tx, variant_detection_rx) = mpsc::channel(50);
    let databases = Arc::new(databases);

    // Build runtime states for EcuStateCoordinator from all loaded ECU databases.
    let runtime_states = {
        let mut states = HashMap::new();
        for (ecu_name, ecu_lock) in databases.as_ref() {
            let state = ecu_lock.read().await.runtime_state();
            states.insert(ecu_name.clone(), state);
        }
        states
    };
    let state_coordinator = EcuStateCoordinator::new(runtime_states);
    let connectivity_handler: Arc<dyn EcuConnectivityHandler> = Arc::new(state_coordinator.clone());

    let diagnostic_gateway = create_diagnostic_gateway(
        Arc::clone(&databases),
        &config.doip,
        variant_detection_tx,
        connectivity_handler,
        shutdown_signal,
        doip_provider,
        doip_socket,
    )
    .await?;

    let uds_manager = create_uds_manager(
        diagnostic_gateway.clone(),
        Arc::clone(&databases),
        variant_detection_rx,
        state_coordinator,
        &config.functional_description,
        config.faults.clone(),
        update_in_progress,
    );

    let vd = uds_manager.clone();
    let variant_detection_handle = cda_interfaces::spawn_named!("variant-detection", async move {
        vd.start_variant_detection().await;
    });

    Ok((
        cda_interfaces::runtime_update_api::VehicleComponents {
            uds_manager,
            diagnostic_gateway,
            file_managers,
            variant_detection_handle,
            functional_group_config: config.functional_description.clone(),
        },
        databases,
    ))
}

#[tracing::instrument(
    skip(databases, variant_detection, connectivity_handler, shutdown_signal, doip_health_provider, doip_socket),
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
    connectivity_handler: Arc<dyn EcuConnectivityHandler>,
    shutdown_signal: impl Future<Output = ()> + Send + 'static,
    doip_health_provider: Option<&Arc<dyn HealthProvider>>,
    doip_socket: Arc<Mutex<cda_comm_doip::socket::DoIPUdpSocket>>,
) -> Result<DoipDiagGateway<EcuManager<S>>, DoipGatewaySetupError> {
    if let Some(provider) = doip_health_provider {
        provider.set_status(cda_health::Status::Starting).await;
    }

    let result = DoipDiagGateway::new(
        doip_config,
        databases,
        variant_detection,
        connectivity_handler,
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
        provider.set_status(status).await;
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
