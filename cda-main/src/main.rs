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
use cda_interfaces::{DiagServiceError, DoipGatewaySetupError, dlt_ctx};
use cda_plugin_security::{DefaultSecurityPlugin, DefaultSecurityPluginData};
use cda_tracing::TracingSetupError;
use clap::Parser;
use futures::future::FutureExt;
use opensovd_cda_lib::{
    config::configfile::{ConfigSanity, Configuration},
    shutdown_signal,
};
use thiserror::Error;
use tracing_subscriber::layer::SubscriberExt as _;

use crate::AppError::{
    ConfigurationError, ConnectionError, DataError, InitializationFailed, NotFound, ResourceError,
    RuntimeError, ServerError,
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

#[derive(Error, Debug)]
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
}

impl From<TracingSetupError> for AppError {
    fn from(value: TracingSetupError) -> Self {
        match value {
            TracingSetupError::ResourceCreationFailed(_) => ResourceError(value.to_string()),
            TracingSetupError::SubscriberInitializationFailed(_) => {
                InitializationFailed(value.to_string())
            }
        }
    }
}

impl From<DoipGatewaySetupError> for AppError {
    fn from(value: DoipGatewaySetupError) -> Self {
        match value {
            DoipGatewaySetupError::InvalidAddress(_) => ConnectionError(value.to_string()),

            DoipGatewaySetupError::SocketCreationFailed(_)
            | DoipGatewaySetupError::PortBindFailed(_) => InitializationFailed(value.to_string()),

            DoipGatewaySetupError::InvalidConfiguration(_) => ConfigurationError(value.to_string()),

            DoipGatewaySetupError::ResourceError(_) => ResourceError(value.to_string()),

            DoipGatewaySetupError::ServerError(_) => ServerError(value.to_string()),
        }
    }
}

impl From<DiagServiceError> for AppError {
    fn from(value: DiagServiceError) -> Self {
        match value {
            DiagServiceError::RequestNotSupported(_)
            | DiagServiceError::BadPayload(_)
            | DiagServiceError::ConnectionClosed
            | DiagServiceError::UnexpectedResponse(_)
            | DiagServiceError::EcuOffline(_)
            | DiagServiceError::NoResponse(_)
            | DiagServiceError::SendFailed(_)
            | DiagServiceError::InvalidAddress(_)
            | DiagServiceError::InvalidRequest(_)
            | DiagServiceError::Timeout => ConnectionError(value.to_string()),

            DiagServiceError::ParameterConversionError(_)
            | DiagServiceError::UnknownOperation
            | DiagServiceError::UdsLookupError(_)
            | DiagServiceError::VariantDetectionError(_)
            | DiagServiceError::AccessDenied(_)
            | DiagServiceError::InvalidSession(_)
            | DiagServiceError::Nack(_) => RuntimeError(value.to_string()),

            DiagServiceError::InvalidSecurityPlugin => ConfigurationError(value.to_string()),

            DiagServiceError::ResourceError(_) => ResourceError(value.to_string()),

            DiagServiceError::NotFound(Some(_)) => NotFound(value.to_string()),

            DiagServiceError::NotFound(None) => NotFound("Resource could not be found.".to_owned()),

            DiagServiceError::DataError(_)
            | DiagServiceError::InvalidDatabase(_)
            | DiagServiceError::DatabaseEntryNotFound(_)
            | DiagServiceError::NotEnoughData { .. } => DataError(value.to_string()),

            DiagServiceError::SetupError(_) | DiagServiceError::ConfigurationError(_) => {
                InitializationFailed(value.to_string())
            }
        }
    }
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
    #[cfg(feature = "dlt-tracing")]
    if config.logging.dlt_tracing.enabled {
        layers.push(cda_tracing::new_dlt_tracing(&config.logging.dlt_tracing)?);
    }

    cda_tracing::init_tracing(tracing.with(layers))?;

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
    .await
    .map_err(|e| {
        let err: AppError = e.into();
        err
    })?;

    cda_sovd::add_vehicle_routes::<DiagServiceResponseStruct, _, _, DefaultSecurityPlugin>(
        &dynamic_router,
        vehicle_data.uds_manager,
        config.flash_files_path.clone(),
        vehicle_data.file_managers,
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
