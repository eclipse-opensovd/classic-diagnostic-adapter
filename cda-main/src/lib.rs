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

use cda_comm_doip::{comm_handle::DoipCommHandle, deferred_gateway::DeferredGateway};
use cda_comm_uds::UdsManager;
use cda_core::EcuManager;
use cda_database::FileManager;
use cda_interfaces::{
    CommunicationControl, CommunicationInitMode, FunctionalDescriptionConfig, HashMap,
    ShutdownSignal, UdsQuery, UdsVariant,
    config::ConfigSanity,
    datatypes::{ComParams, FaultConfig},
    dlt_ctx,
    health::HealthStatus,
};
use cda_plugin_runtime_update::UpdateGuard;
use cda_plugin_security::{
    DefaultSecurityPlugin, DefaultSecurityPluginData, SecurityPlugin, SecurityPluginLoader,
};
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
    config::{configfile::Configuration, generate::generate_config_cmd},
    error::AppError,
    mdd::{load_databases, resolve_mdd_paths},
    setup::Setup,
    update::{UpdatePluginBuilder, create_default_update_plugin, update_plugin_fn},
};

pub mod config;
pub mod deferred_init;
pub mod error;
pub mod mdd;
pub mod setup;
pub mod update;

/// Creates a default [`Setup`] with the standard update and init plugins.
///
/// This is used by both [`run`] and [`run_with_config`] to ensure consistent
/// default behavior.
fn default_setup() -> Setup<
    DefaultSecurityPluginData,
    DefaultSecurityPlugin,
    impl UpdatePluginBuilder<DefaultSecurityPluginData>,
    impl crate::deferred_init::AppInitPluginBuilder<DefaultSecurityPluginData>,
> {
    Setup::new()
        .with_update_plugin(update_plugin_fn(|infra| async move {
            create_default_update_plugin(infra).await
        }))
        .with_init_plugin(deferred_init::init_plugin_fn(|| async {
            Ok::<cda_interfaces::OnDemandInitPlugin, AppError>(
                cda_interfaces::OnDemandInitPlugin,
            )
        }))
}

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
/// Run the CDA from parsed CLI arguments with custom setup configuration.
///
/// # Errors
/// Returns [`AppError`] if configuration loading, validation, or startup fails.
pub async fn run_with_ext<SP, SL, UPB, IPB>(
    args: AppArgs,
    setup: Setup<SP, SL, UPB, IPB>,
) -> Result<(), AppError>
where
    SP: SecurityPlugin,
    SL: SecurityPluginLoader,
    UPB: UpdatePluginBuilder<SP> + 'static,
    IPB: deferred_init::AppInitPluginBuilder<SP>,
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

    if disk_loaded && config.runtime_update_config.init_storage_from_database_path {
        mdd::seed_storage_from_database_path(
            &config.runtime_update_config.storage_dir,
            &config.database.path,
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

/// Start the CDA runtime with default arguments.
///
/// # Errors
/// Returns [`AppError`] if tracing setup, webserver startup, data loading, or route setup fails.
pub async fn run(args: AppArgs) -> Result<(), AppError> {
    // Box::pin is required because this is a large future (~16 KB)
    Box::pin(run_with_ext::<
        DefaultSecurityPluginData,
        DefaultSecurityPlugin,
        _,
        _,
    >(
        args,
        default_setup(),
    ))
    .await
}

/// Start the CDA runtime with custom setup configuration.
///
/// # Example
/// ```ignore
/// let setup = Setup::<MySecurityPlugin, MySecurityLoader>::new()
///     .with_pre_load(|router| async move {
///         register_version_endpoints(router).await
///     })
///     .with_update_plugin(update_plugin_fn(|infra| async move {
///         Ok(MyCustomPlugin::new(infra))
///     }));
///
/// run_with_ext_from_config(config, setup).await
/// ```
///
/// # Errors
/// Returns [`AppError`] if tracing setup, webserver startup, data loading, or route setup fails.
pub async fn run_with_ext_from_config<SP, SL, UPB, IPB>(
    config: Configuration,
    setup: Setup<SP, SL, UPB, IPB>,
) -> Result<(), AppError>
where
    SP: SecurityPlugin,
    SL: SecurityPluginLoader,
    UPB: UpdatePluginBuilder<SP> + 'static,
    IPB: deferred_init::AppInitPluginBuilder<SP>,
{
    let _tracing_guards = setup_tracing(&config)?;
    tracing::info!("Starting CDA - version {}", cda_version());

    let webserver_config = cda_sovd::WebServerConfig {
        host: config.server.address.clone(),
        port: config.server.port,
    };

    let shutdown_future: std::pin::Pin<Box<dyn Future<Output = ()> + Send + Sync + 'static>> =
        Box::pin(shutdown_signal());
    let clonable_shutdown_signal = shutdown_future.shared();

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
                Arc::clone(&main_health_provider) as Arc<dyn cda_health::HealthStatus>,
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

    if let Some(pre_load) = setup.pre_load {
        pre_load(dynamic_router.clone()).await?;
    }

    // Build the init plugin so on_ready() is called once communication is active.
    let init_plugin: Arc<dyn cda_interfaces::InitializationPlugin> =
        if let Some(builder) = setup.build_init_plugin {
            Arc::new(builder.build().await?)
        } else {
            Arc::new(cda_interfaces::OnDemandInitPlugin)
        };

    match config.communication.init_mode {
        CommunicationInitMode::Enabled => {
            // Load vehicle data and build infrastructure
            tracing::debug!("Webserver is running. Loading sovd routes...");

            let vehicle_data = match load_vehicle_data::<SP>(
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

            setup::setup_runtime_routes::<SP, SL, _>(
                config,
                vehicle_data,
                &dynamic_router,
                &webserver_config,
                clonable_shutdown_signal.clone(),
                setup.build_update_plugin,
                Some(init_plugin),
            )
            .await?;
        }
        CommunicationInitMode::Deferred => {
            // Link a CancellationToken to the process shutdown signal so the
            // deferred-init actor can cancel its detached init task cleanly
            // on shutdown instead of racing it.
            let shutdown_cancel = tokio_util::sync::CancellationToken::new();
            {
                let token = shutdown_cancel.clone();
                let shutdown_wait = clonable_shutdown_signal.clone();
                cda_interfaces::spawn_named!("deferred-init-shutdown-link", async move {
                    shutdown_wait.await;
                    token.cancel();
                });
            }

            // Box the update plugin builder into a type-erased fn so it can be
            // stored in the actor (which is generic over SP, not UPB).
            let deferred_update_fn: Option<deferred_init::DeferredUpdatePluginFn<SP>> =
                setup.build_update_plugin.map(|builder| {
                    let boxed: deferred_init::DeferredUpdatePluginFn<SP> = Box::new(move |infra| {
                        Box::pin(async move {
                            let plugin = builder.build(infra).await?;
                            Ok(Box::new(plugin)
                                as Box<
                                    dyn cda_interfaces::runtime_update_api::RuntimeFilesUpdatePlugin,
                                >)
                        })
                    });
                    boxed
                });

            deferred_init::setup_deferred_vehicle_routes::<SP, SL>(
                deferred_init::DeferredSetupConfig {
                    config,
                    dynamic_router: &dynamic_router,
                    webserver_config: &webserver_config,
                    health_state: health_state.as_ref(),
                    shutdown_signal: clonable_shutdown_signal.clone(),
                    shutdown_cancel,
                },
                init_plugin,
                deferred_update_fn,
            )
            .await?;
        }
    }

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

/// Start the CDA runtime from a prepared configuration with default settings.
///
/// This is a convenience function that uses the default setup with the standard update plugin.
///
/// # Errors
/// Returns [`AppError`] if tracing setup, webserver startup, data loading, or route setup fails.
pub async fn run_with_config(config: Configuration) -> Result<(), AppError> {
    Box::pin(run_with_ext_from_config::<
        DefaultSecurityPluginData,
        DefaultSecurityPlugin,
        _,
        _,
    >(
        config,
        default_setup(),
    ))
    .await
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

/// Resolves MDD paths from configuration.
///
/// # Errors
/// Returns [`AppError`] if no MDD files are found.
async fn resolve_mdd_paths_from_config(config: &Configuration) -> Result<Vec<PathBuf>, AppError> {
    let storage_dir = &config.runtime_update_config.storage_dir;
    let paths = resolve_mdd_paths(storage_dir, &config.database.path).await;
    if paths.is_empty() {
        return Err(AppError::InitializationFailed(
            "No MDD files found".to_string(),
        ));
    }
    Ok(paths)
}

/// Loads vehicle data including MDD databases and vehicle components.
///
/// Returns a fully built [`VehicleStack`] with communication enabled
/// (`DoIP` gateway activated, ready for diagnostic requests).
///
/// # Errors
/// Returns [`AppError`] if MDD path resolution, database loading, or component creation fails.
///
/// # Panics
/// Panics if `health` is `Some` but the internal database provider holder is `None` (should not
/// occur under normal operation).
pub async fn load_vehicle_data<S: SecurityPlugin>(
    config: &Configuration,
    _clonable_shutdown_signal: ShutdownSignal,
    health: Option<&cda_health::HealthState>,
) -> Result<VehicleStack<S>, AppError> {
    let mdd_paths = resolve_mdd_paths_from_config(config).await?;
    let update_guard = UpdateGuard::new();

    // Build the vehicle stack first so we have a comm_handle to derive the health provider from.
    // The database health provider is passed in so `load_databases` can report status live.
    let db_provider_holder: Option<Arc<cda_health::StatusHealthProvider>> = health.map(|_| {
        Arc::new(cda_health::StatusHealthProvider::new(
            cda_health::Status::Starting,
        ))
    });

    let stack = build_vehicle_stack::<S>(
        config,
        &mdd_paths,
        db_provider_holder.clone(),
        update_guard,
        None,
    )
    .await?;
    // Register health providers now that we have the live comm handle.
    let health_providers = if let Some(health_state) = health {
        let doip_health: Arc<dyn HealthStatus> = Arc::new(stack.comm_handle.health_provider());
        let database = db_provider_holder.expect("db_provider_holder is Some when health is Some");
        health_state
            .register_provider(
                DOIP_HEALTH_COMPONENT_KEY,
                Arc::clone(&doip_health) as Arc<dyn cda_health::HealthStatus>,
            )
            .await
            .map_err(|e| AppError::InitializationFailed(e.to_string()))?;
        health_state
            .register_provider(
                mdd::DB_HEALTH_COMPONENT_KEY,
                Arc::clone(&database) as Arc<dyn cda_health::HealthStatus>,
            )
            .await
            .map_err(|e| AppError::InitializationFailed(e.to_string()))?;
        Some(HealthProviders {
            doip: doip_health,
            database,
        })
    } else {
        None
    };

    // Enable communication immediately for Enabled mode
    stack.comm_handle.enable().await.map_err(|e| {
        AppError::InitializationFailed(format!("Failed to enable DoIP communication: {e}"))
    })?;

    Ok(VehicleStack {
        health_providers,
        ..stack
    })
}

/// Unified UDS manager type using `DeferredGateway` for all communication modes.
///
/// The `DeferredGateway` allows the real `UdsManager` to be constructed at startup
/// in an inactive state. Communication is enabled via the `DoipCommActor` which
/// populates the shared gateway slot.
pub type UdsManagerType<S> = UdsManager<DeferredGateway<EcuManager<S>>, EcuManager<S>>;

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
    gateway: DeferredGateway<EcuManager<S>>,
    databases: Arc<HashMap<String, RwLock<EcuManager<S>>>>,
    variant_detection_receiver: mpsc::Receiver<Vec<String>>,
    state_coordinator: cda_comm_uds::EcuStateCoordinator,
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

/// Named health providers for vehicle components.
#[derive(Clone)]
pub struct HealthProviders {
    pub doip: Arc<dyn HealthStatus>,
    pub database: Arc<cda_health::StatusHealthProvider>,
}

impl HealthProviders {
    /// Converts the health providers to a `HashMap` for use in `CdaRuntime`.
    #[must_use]
    pub fn to_health_map(&self) -> HashMap<String, Arc<dyn HealthStatus>> {
        let mut map: HashMap<String, Arc<dyn HealthStatus>> = HashMap::default();
        map.insert(
            DOIP_HEALTH_COMPONENT_KEY.to_owned(),
            Arc::clone(&self.doip) as Arc<dyn HealthStatus>,
        );
        map.insert(
            mdd::DB_HEALTH_COMPONENT_KEY.to_owned(),
            Arc::clone(&self.database) as Arc<dyn HealthStatus>,
        );
        map
    }
}

/// Result of building the vehicle stack with the new actor-based architecture.
///
/// This structure holds all components needed for vehicle operation in both
/// Enabled and Deferred modes, using the unified `DeferredGateway` approach.
pub struct VehicleStack<S: SecurityPlugin> {
    /// The UDS manager with `DeferredGateway`, ready for operation.
    pub uds_manager: UdsManagerType<S>,
    /// Handle to the `DoIP` communication actor.
    pub comm_handle: DoipCommHandle<EcuManager<S>>,
    /// Databases loaded from MDD files.
    pub databases: Arc<DatabaseMap<S>>,
    /// File managers for flash operations.
    pub file_managers: FileManagerMap,
    /// Lock provider for SOVD operations.
    pub lock_provider: Arc<cda_sovd::SovdLockStateProvider>,
    /// Handle for the variant detection background task.
    pub variant_detection_handle: tokio::task::JoinHandle<()>,
    /// Update guard that blocks requests during an in-progress update.
    pub update_guard: UpdateGuard,
    /// Optional health providers for monitoring `DoIP` and database status.
    pub health_providers: Option<HealthProviders>,
}

/// Builds the vehicle stack, optionally reusing an existing UDP socket.
///
/// Pass `Some(socket)` during runtime reloads to avoid double-binding the `DoIP`
/// UDP port (the original actor's reserved socket is reused).
/// Pass `None` for fresh startup - a new socket is created and the port is reserved.
///
/// # Errors
/// Returns [`AppError`] if database loading or socket creation fails.
#[allow(
    clippy::implicit_hasher,
    reason = "HashMap type alias from cda_interfaces uses custom hasher"
)]
#[tracing::instrument(skip_all,
    fields(
        dlt_context = dlt_ctx!("MAIN"),
    )
)]
pub async fn build_vehicle_stack<S: SecurityPlugin>(
    config: &Configuration,
    mdd_paths: &[PathBuf],
    db_health: Option<Arc<cda_health::StatusHealthProvider>>,
    update_guard: UpdateGuard,
    existing_socket: Option<Arc<Mutex<cda_comm_doip::socket::DoIPUdpSocket>>>,
) -> Result<VehicleStack<S>, AppError> {
    let db_provider = db_health
        .as_ref()
        .map(|h| Arc::clone(h) as Arc<dyn cda_health::HealthProvider>);
    let db_provider = db_provider.as_ref();
    let update_in_progress = update_guard.busy_handle();

    // Load databases
    let (databases, file_managers) = load_databases::<S>(config, mdd_paths, db_provider).await?;

    // Create the state coordinator from the ECU runtime states
    let mut runtime_states: HashMap<String, cda_interfaces::EcuRuntimeState> = HashMap::default();
    for (name, ecu) in &databases {
        let ecu_lock = ecu.read().await;
        runtime_states.insert(name.clone(), ecu_lock.runtime_state());
    }
    let state_coordinator = cda_comm_uds::EcuStateCoordinator::new(runtime_states);

    // Set up variant detection channel
    let (variant_detection_tx, variant_detection_rx) = mpsc::channel(50);
    let databases = Arc::new(databases);

    // Create DoipCommHandle (starts disabled, with socket reserved)
    let comm_handle = if let Some(socket) = existing_socket {
        // Reload path: reuse the existing socket to avoid double-binding the DoIP port.
        cda_comm_doip::comm_handle::new_doip_comm_handle_with_socket(
            config.doip.clone(),
            Arc::clone(&databases),
            variant_detection_tx,
            Arc::new(state_coordinator.clone()),
            socket,
        )
    } else {
        // Fresh startup: bind a new socket and reserve the port.
        cda_comm_doip::comm_handle::new_doip_comm_handle(
            config.doip.clone(),
            Arc::clone(&databases),
            variant_detection_tx,
            Arc::new(state_coordinator.clone()),
        )
        .map_err(|e| {
            AppError::InitializationFailed(format!("Failed to create DoIP comm handle: {e}"))
        })?
    };

    // Create DeferredGateway sharing the actor's slot and socket
    let deferred_gateway = comm_handle.deferred_gateway();

    // Create UDS manager with the deferred gateway
    let uds_manager = create_uds_manager(
        deferred_gateway,
        Arc::clone(&databases),
        variant_detection_rx,
        state_coordinator,
        &config.functional_description,
        config.faults.clone(),
        update_in_progress,
    );

    // Start variant detection task
    let vd = uds_manager.clone();
    let variant_detection_handle = cda_interfaces::spawn_named!("variant-detection", async move {
        vd.start_variant_detection().await;
    });

    // Create locks and lock provider
    let ecu_names = uds_manager.get_physical_ecus().await;
    let locks = Arc::new(cda_sovd::Locks::new(ecu_names));
    let lock_provider = Arc::new(cda_sovd::SovdLockStateProvider::new(locks));

    Ok(VehicleStack {
        uds_manager,
        comm_handle,
        databases,
        file_managers,
        lock_provider,
        variant_detection_handle,
        update_guard,
        health_providers: None,
    })
}

// Note: create_vehicle_components has been replaced by build_vehicle_stack
// The old function is removed as part of the DeferredGateway refactoring

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
