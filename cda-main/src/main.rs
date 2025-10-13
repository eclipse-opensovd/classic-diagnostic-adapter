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

use std::sync::Arc;

use cda_plugin_security::DefaultSecurityPluginData;
use clap::Parser;
use futures::future::FutureExt;
use opensovd_cda_lib::{config::configfile::ConfigSanity, shutdown_signal};
use tokio::sync::mpsc;
use tracing_subscriber::layer::SubscriberExt as _;

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
#[tracing::instrument]
async fn main() -> Result<(), String> {
    let args = AppArgs::parse();
    let mut config = opensovd_cda_lib::config::load_config().unwrap_or_else(|e| {
        println!("Failed to load configuration: {e}");
        println!("Using default values");
        opensovd_cda_lib::config::default_config()
    });
    config.validate_sanity()?;

    args.update_config(&mut config);

    let tracing = cda_tracing::new();
    let mut layers = vec![];
    layers.push(cda_tracing::new_term_subscriber(&config.logging));
    #[cfg(feature = "tokio-tracing")]
    layers.push(cda_tracing::new_tokio_tracing(
        &config.logging.tokio_tracing,
    )?);
    let _otel_guard = if config.logging.otel.enabled {
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
    let _guard = if config.logging.log_file_config.enabled {
        let (guard, file_layer) =
            cda_tracing::new_file_subscriber(&config.logging.log_file_config)?;
        layers.push(file_layer);
        Some(guard)
    } else {
        None
    };

    cda_tracing::init_tracing(tracing.with(layers))?;

    tracing::info!("Starting CDA...");

    let database_path = config.databases_path.clone();

    let flash_files_path = config.flash_files_path.clone();

    let protocol = if config.onboard_tester {
        cda_interfaces::Protocol::DoIpDobt
    } else {
        cda_interfaces::Protocol::DoIp
    };

    let (databases, file_managers) = opensovd_cda_lib::load_databases::<DefaultSecurityPluginData>(
        &database_path,
        protocol,
        config.com_params,
        config.database_naming_convention,
        config.flat_buf,
    )
    .await;

    let webserver_config = cda_sovd::WebServerConfig {
        host: config.server.address.clone(),
        port: config.server.port,
    };

    let clonable_shutdown_signal = shutdown_signal().shared();

    let (variant_detection_tx, variant_detection_rx) = mpsc::channel(50);
    let (tester_present_tx, tester_present_rx) = mpsc::channel(10);

    let databases = Arc::new(databases);
    let diagnostic_gateway = match opensovd_cda_lib::create_diagnostic_gateway(
        Arc::clone(&databases),
        &config.doip.tester_address,
        &config.doip.tester_subnet,
        config.doip.gateway_port,
        variant_detection_tx,
        tester_present_tx,
        clonable_shutdown_signal.clone(),
    )
    .await
    {
        Ok(gateway) => gateway,
        Err(e) => {
            tracing::error!(error = %e, "Failed to create diagnostic gateway");
            return Err(e);
        }
    };

    let uds = match opensovd_cda_lib::create_uds_manager(
        diagnostic_gateway,
        databases,
        variant_detection_rx,
        tester_present_rx,
    )
    .await
    {
        Ok(uds) => uds,
        Err(e) => {
            tracing::error!(error = %e, "Failed to create uds manager");
            return Err(e);
        }
    };

    match opensovd_cda_lib::start_webserver(
        flash_files_path,
        file_managers,
        webserver_config,
        uds,
        clonable_shutdown_signal,
    )
    .await
    {
        Ok(Ok(())) => tracing::info!("Shutting down..."),
        Ok(Err(e)) => {
            tracing::error!(error = ?e, "Failed to start webserver");
            std::process::exit(1);
        }
        Err(je) => {
            if je.is_panic() {
                let reason = je.into_panic();
                tracing::error!(panic_reason = ?reason, "Webserver thread panicked");
                std::process::exit(1);
            }
        }
    }

    Ok(())
}

impl AppArgs {
    #[tracing::instrument(skip(self, config))]
    fn update_config(self, config: &mut opensovd_cda_lib::config::configfile::Configuration) {
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
