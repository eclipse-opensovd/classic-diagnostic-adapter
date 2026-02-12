/*
 * Copyright (c) 2025-2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
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

use std::sync::Arc;

use cda_core::DiagServiceResponseStruct;
use cda_interfaces::dlt_ctx;
use cda_plugin_security::{DefaultSecurityPlugin, DefaultSecurityPluginData};
use clap::Parser;
use futures::future::FutureExt;
use opensovd_cda_lib::{
    AppError, cda_version,
    config::configfile::{ConfigSanity, Configuration},
    setup_tracing, shutdown_signal,
};

#[cfg(feature = "health")]
const MAIN_HEALTH_COMPONENT_KEY: &str = "main";

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct AppArgs {
    #[arg(short, long)]
    databases_path: Option<String>,

    #[arg(short, long)]
    tester_address: Option<String>,

    #[arg(long)]
    tester_subnet: Option<String>,

    #[arg(long)]
    gateway_port: Option<u16>,

    // cannot use Action::SetTrue as it will treat
    // absent arg same as `= false`
    #[arg(short, long)]
    onboard_tester: Option<bool>,

    #[arg(long)]
    listen_address: Option<String>,

    #[arg(long)]
    listen_port: Option<u16>,

    #[arg(short, long)]
    flash_files_path: Option<String>,

    #[arg(long)]
    file_logging: Option<bool>,

    #[arg(long)]
    log_file_dir: Option<String>,

    #[arg(long)]
    log_file_name: Option<String>,

    #[arg(long)]
    exit_no_database_loaded: Option<bool>,
}

#[tokio::main]
#[tracing::instrument(
    fields(
        dlt_context = dlt_ctx!("MAIN"),
    )
)]
async fn main() -> Result<(), AppError> {
    let args = AppArgs::parse();
    let mut config = opensovd_cda_lib::config::load_config().unwrap_or_else(|e| {
        println!("Failed to load configuration: {e}");
        println!("Using default values");
        opensovd_cda_lib::config::default_config()
    });
    config.validate_sanity()?;

    args.update_config(&mut config);

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

    tracing::debug!("Webserver is running. Loading sovd routes...");

    let vehicle_data = opensovd_cda_lib::load_vehicle_data::<_, DefaultSecurityPluginData>(
        &config,
        clonable_shutdown_signal.clone(),
        health_state.as_ref(),
    )
    .await?;

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
    )
    .await?;

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

    // Wait for shutdown signal
    clonable_shutdown_signal.await;
    tracing::info!("Shutting down...");
    webserver_task
        .await
        .map_err(|e| AppError::RuntimeError(format!("Webserver task join error: {e}")))?;

    Ok(())
}

impl AppArgs {
    #[tracing::instrument(skip(self, config),
        fields(
            dlt_context = dlt_ctx!("MAIN"),
        )
    )]
    fn update_config(self, config: &mut Configuration) {
        if let Some(onboard_tester) = self.onboard_tester {
            config.onboard_tester = onboard_tester;
        }
        if let Some(databases_path) = self.databases_path {
            config.database.path = databases_path;
        }
        if let Some(exit_no_database_loaded) = self.exit_no_database_loaded {
            config.database.exit_no_database_loaded = exit_no_database_loaded;
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
    }
}
