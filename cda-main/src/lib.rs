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

// The `run_with_ext` async state machine grows with every enabled transport;
// with `--all-features` its layout computation overflows rustc's default
// query depth (128) on stable 1.97. Default limit otherwise.
#![recursion_limit = "256"]

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use cda_interfaces::{config::ConfigSanity, dlt_ctx};
use cda_plugin_communication_management::plugin::CommunicationPluginBuilder;
use cda_plugin_security::{
    DefaultSecurityPlugin, DefaultSecurityPluginData, SecurityPlugin, SecurityPluginLoader,
};
use cda_tracing::{OtelGuard, TracingSetupError, TracingWorkerGuard};
use clap::{Parser, Subcommand};
use tracing_subscriber::layer::SubscriberExt;

use crate::{
    config::{configfile::Configuration, generate::generate_config_cmd},
    setup::PreLoadHook,
    update::{UpdatePluginBuilder, create_default_update_plugin, update_plugin_fn},
};

pub mod cda_factory;
pub mod config;
pub mod error;
pub mod mdd;
pub mod mdd_inspector;
pub mod setup;
pub mod update;
pub mod update_security;
pub(crate) mod vehicle;

pub use error::AppError;
pub use setup::Setup;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const DOIP_HEALTH_COMPONENT_KEY: &str = "doip";

#[cfg(feature = "health")]
const MAIN_HEALTH_COMPONENT_KEY: &str = "main";

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
    pub config: Option<PathBuf>,

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
/// Run the CDA from parsed CLI arguments with a custom [`Setup`].
///
/// This is the primary setup-aware entry point. Pass a [`Setup`] created with
/// [`Setup::new`] and optionally configured with
/// [`Setup::with_preload`] / [`Setup::with_update_plugin`].
///
/// # Errors
/// Returns [`AppError`] if configuration loading, validation, or startup fails.
pub async fn run_with_ext<SP, SL, UPB, CPB>(
    args: AppArgs,
    setup: Setup<SP, SL, UPB, CPB>,
) -> Result<(), AppError>
where
    SP: SecurityPlugin,
    SL: SecurityPluginLoader,
    UPB: UpdatePluginBuilder<SP>,
    CPB: CommunicationPluginBuilder,
{
    if let Some(Command::GenerateConfig { output }) = args.command.as_ref() {
        // Exiting after generating config is on purpose.
        return generate_config_cmd(output.as_ref());
    }

    let config_file = match &args.config {
        Some(config_file) => {
            if config_file.exists() {
                config_file
            } else {
                // ignore `config-optional` feature here, because it's specifically for when no config was specified
                return Err(AppError::ConfigurationError {
                    message: format!(
                        "Specified configuration file {} does not exist",
                        config_file.display()
                    ),
                    source: None,
                });
            }
        }
        None => Path::new("opensovd-cda.toml"),
    };

    let (mut config, disk_loaded) = config::load_config_with_fallback(config_file);
    if !disk_loaded {
        config::require_config_source()?;
    }

    // Command line arguments always take precedence over file configuration.
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
/// run_with_ext_from_config::<MySecurityPlugin, MySecurityLoader, _, _>(
///     config,
///     Setup::new().with_update_plugin(update_plugin_fn(|infra| async move {
///         Ok(MyPlugin::new(infra))
///     })),
/// ).await?;
/// ```
///
/// # Errors
/// Returns [`AppError`] if tracing setup, webserver startup, data loading, or route setup fails.
pub async fn run_with_ext_from_config<SP, SL, UPB, CPB>(
    config: Configuration,
    setup: Setup<SP, SL, UPB, CPB>,
) -> Result<(), AppError>
where
    SP: SecurityPlugin,
    SL: SecurityPluginLoader,
    UPB: UpdatePluginBuilder<SP>,
    CPB: CommunicationPluginBuilder,
{
    let webserver_state = init_webserver(
        &config,
        setup.pre_load,
        setup.initialize_tracing,
        setup.shutdown_signal,
    )
    .await?;

    tracing::debug!("Webserver is running. Loading sovd routes...");

    let vehicle_data = match vehicle::load_vehicle_data::<SP>(
        &config,
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

    // Retain the authoritative communication runtime for the full server
    // lifetime, so its event dispatcher keeps running until explicit shutdown.
    let communication_runtime = setup::setup_runtime_routes::<SP, SL, UPB, CPB>(
        config,
        vehicle_data,
        &webserver_state,
        setup.build_update_plugin,
        setup.build_communication_plugin,
    )
    .await?;

    tracing::info!("CDA fully initialized and ready to serve requests");
    if let Some(provider) = &webserver_state.main_health_provider {
        provider.update_status(cda_health::Status::Up).await;
    }

    // Wait for shutdown signal
    webserver_state.shutdown_signal.clone().await;
    tracing::info!("Shutting down...");
    webserver_state.join().await?;
    cda_interfaces::Shutdown::shutdown(&*communication_runtime.plugin).await;

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
    Box::pin(run_with_ext_from_config::<
        DefaultSecurityPluginData,
        DefaultSecurityPlugin,
        _,
        _,
    >(
        config,
        Setup::new().with_update_plugin(update_plugin_fn(
            |infra: setup::CdaRuntime<DefaultSecurityPluginData>| async move {
                create_default_update_plugin::<DefaultSecurityPluginData, DefaultSecurityPlugin>(
                    infra,
                )
                .await
            },
        )),
    ))
    .await
}

async fn init_webserver(
    config: &Configuration,
    pre_load: Option<PreLoadHook>,
    initialize_tracing: bool,
    shutdown_signal: Option<cda_interfaces::ShutdownSignal>,
) -> Result<ApplicationState, AppError> {
    let tracing_guards = if initialize_tracing {
        setup_tracing(config)?
    } else {
        TracingGuards {
            _file: None,
            _otel: None,
        }
    };
    tracing::info!("Starting CDA - version {}", cda_version());

    let webserver_config = cda_sovd::WebServerConfig {
        host: config.server.address.clone(),
        port: config.server.port,
    };

    let clonable_shutdown_signal = shutdown_signal
        .unwrap_or_else(|| cda_interfaces::shutdown_signal(crate::shutdown_signal()));

    let (dynamic_router, webserver_task) =
        cda_sovd::launch_webserver(webserver_config.clone(), clonable_shutdown_signal.clone())
            .await?;

    let mut webserver_state = ApplicationState {
        _tracing_guards: tracing_guards,
        dynamic_router,
        webserver_task: Some(webserver_task),
        shutdown_signal: clonable_shutdown_signal,
        health_state: None,
        main_health_provider: None,
    };

    #[cfg(feature = "health")]
    let (health_state, main_health_provider) = if config.health.enabled {
        let health_state = cda_health::add_health_routes(
            &webserver_state.dynamic_router,
            cda_version().to_owned(),
        )
        .await;
        let main_health_provider = Arc::new(cda_health::StatusHealthProvider::new(
            cda_health::Status::Starting,
        ));
        let registration = health_state
            .register_provider(
                MAIN_HEALTH_COMPONENT_KEY,
                Arc::clone(&main_health_provider) as Arc<dyn cda_health::HealthProvider>,
            )
            .await
            .map_err(|e| AppError::InitializationFailed(e.to_string()));
        registration?;
        (Some(health_state), Some(main_health_provider))
    } else {
        (None, None)
    };

    #[cfg(not(feature = "health"))]
    let (health_state, main_health_provider): (
        Option<cda_health::HealthState>,
        Option<Arc<cda_health::StatusHealthProvider>>,
    ) = (None, None);

    webserver_state.health_state = health_state;
    webserver_state.main_health_provider = main_health_provider;

    #[cfg(feature = "systemd-notify")]
    let _sd_notify_task = cda_extra::create_sd_notify_task(
        webserver_state.health_state.clone(),
        webserver_state.shutdown_signal.clone(),
    );

    register_version_endpoints(&webserver_state.dynamic_router).await;

    if let Some(hook) = pre_load {
        hook(webserver_state.dynamic_router.clone()).await?;
    }

    Ok(webserver_state)
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

/// Collected webserver state produced by [`init_webserver`].
///
/// Passed to [`setup::setup_runtime_routes`] and [`run_with_ext_from_config`] so that
/// the shutdown signal and health provider are accessible after the webserver is started.
///
/// Dropping this value aborts the webserver task, so all error paths are covered
/// automatically without any explicit cleanup calls.
pub(crate) struct ApplicationState {
    _tracing_guards: TracingGuards,
    pub dynamic_router: cda_sovd::dynamic_router::DynamicRouter,
    webserver_task: Option<tokio::task::JoinHandle<()>>,
    pub shutdown_signal: cda_interfaces::ShutdownSignal,
    health_state: Option<cda_health::HealthState>,
    main_health_provider: Option<Arc<cda_health::StatusHealthProvider>>,
}

impl Drop for ApplicationState {
    fn drop(&mut self) {
        if let Some(task) = self.webserver_task.take() {
            task.abort();
        }
    }
}

impl ApplicationState {
    /// Waits for the normally signaled webserver task to finish.
    async fn join(mut self) -> Result<(), AppError> {
        if let Some(task) = self.webserver_task.take() {
            task.await
                .map_err(|e| AppError::RuntimeError(format!("Webserver task join error: {e}")))?;
        }
        Ok(())
    }
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

/// Returns the CDA version string, which is either
/// the value of the `CDA_VERSION` environment variable (if set)
/// or the Cargo package version.
#[must_use]
pub fn cda_version() -> &'static str {
    option_env!("CDA_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
}

#[cfg(test)]
mod webserver_lifecycle_tests {
    use super::*;

    #[tokio::test]
    async fn drop_aborts_webserver_task() {
        let task = tokio::spawn(std::future::pending::<()>());
        let abort_handle = task.abort_handle();

        let state = ApplicationState {
            _tracing_guards: TracingGuards {
                _file: None,
                _otel: None,
            },
            dynamic_router: cda_sovd::dynamic_router::DynamicRouter::new(),
            webserver_task: Some(task),
            shutdown_signal: cda_interfaces::shutdown_signal(std::future::pending()),
            health_state: None,
            main_health_provider: None,
        };

        drop(state);

        // abort() is asynchronous; yield to let the cancellation propagate.
        tokio::task::yield_now().await;
        assert!(abort_handle.is_finished());
    }
}
