/*
 * Copyright (c) 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
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

use cda_core::DiagServiceResponseStruct;
use cda_interfaces::dlt_ctx;
use cda_plugin_security::{DefaultSecurityPlugin, DefaultSecurityPluginData};
use clap::Parser;
use futures::future::FutureExt;
use opensovd_cda_lib::{
    AppError,
    config::configfile::{ConfigSanity, Configuration},
    setup_tracing, shutdown_signal,
};

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
    tracing::info!("Starting CDA...");

    let webserver_config = cda_sovd::WebServerConfig {
        host: config.server.address.clone(),
        port: config.server.port,
    };

    let clonable_shutdown_signal = shutdown_signal().shared();

    let dynamic_router =
        cda_sovd::launch_webserver(webserver_config.clone(), clonable_shutdown_signal.clone())
            .await?;

    tracing::debug!("Webserver is running. Loading sovd routes...");

    let vehicle_data = opensovd_cda_lib::load_vehicle_data::<_, DefaultSecurityPluginData>(
        &config,
        clonable_shutdown_signal.clone(),
    )
    .await?;

    cda_sovd::add_vehicle_routes::<DiagServiceResponseStruct, _, _, DefaultSecurityPlugin>(
        &dynamic_router,
        vehicle_data.uds_manager,
        config.flash_files_path.clone(),
        vehicle_data.file_managers,
        vehicle_data.locks,
    )
    .await?;

    tracing::info!("CDA fully initialized and ready to serve requests");

    // Wait for shutdown signal
    clonable_shutdown_signal.await;
    tracing::info!("Shutting down...");

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
            config.databases_path = databases_path;
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
