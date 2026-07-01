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

// Simulator binary; lints relaxed as in lib.
#![allow(
    clippy::uninlined_format_args,
    clippy::arithmetic_side_effects,
    clippy::similar_names
)]

//! MDD-based ECU Simulator for testing CAN/ISO-TP diagnostic operations.

use std::sync::Arc;

use cda_simulator::{
    SimulatorArgs, SimulatorError, api,
    mdd::{self, VariantInfo},
    simulator::{ActiveVariant, SimulatorState, isotp::IsoTpServer},
};
use clap::Parser;
use tokio::signal;
use tracing_subscriber::EnvFilter;

#[tokio::main]
#[allow(clippy::too_many_lines, clippy::collapsible_if)]
async fn main() -> Result<(), SimulatorError> {
    let args = SimulatorArgs::parse();

    // Initialize logging
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .init();

    tracing::info!("CDA Simulator starting");
    tracing::info!(mdd_path = %args.mdd_path, "Loading MDD file");

    // Load MDD and extract data
    let mdd_data = mdd::load_mdd(&args.mdd_path)?;
    tracing::info!(ecu_name = %mdd_data.ecu_name, "Loaded ECU data");

    // List and select variant
    let variants = mdd::extract_variants(&mdd_data.database);
    if variants.is_empty() {
        tracing::error!("No variants found in MDD file");
        return Err(SimulatorError::NoVariants);
    }

    tracing::info!("Available variants:");
    for v in &variants {
        tracing::info!("  - {} {}", v.name, if v.is_base { "(base)" } else { "" });
    }

    let selected_variant = select_variant(&variants, args.variant.as_deref())?;
    tracing::info!(
        variant = %selected_variant.name,
        is_base = selected_variant.is_base,
        "Selected variant"
    );

    // Extract services for the selected variant
    let services = mdd::extract_services(&mdd_data.database, &selected_variant.name)?;
    tracing::info!(service_count = services.len(), "Loaded service definitions");

    // Log some service info
    for ((_sid, sub), service) in services.iter().take(5) {
        tracing::debug!(
            name = %service.name,
            sid = format!("0x{:02X}", service.sid),
            sub_function = sub.map(|s| format!("0x{:02X}", s)),
            params = service.response_params.len(),
            multiframe = service.is_multiframe,
            "Service"
        );
    }
    if services.len() > 5 {
        tracing::debug!("... and {} more services", services.len().saturating_sub(5));
    }

    // Resolve CAN IDs
    let (request_id, response_id) = resolve_can_ids(&args, &mdd_data.database)?;
    tracing::info!(
        request_id = format!("0x{:03X}", request_id),
        response_id = format!("0x{:03X}", response_id),
        "CAN IDs configured"
    );

    // Create simulator state
    let state = Arc::new(SimulatorState::new(
        mdd_data.ecu_name.clone(),
        args.mdd_path.clone(),
        ActiveVariant {
            name: selected_variant.name.clone(),
            is_base: selected_variant.is_base,
        },
        args.interface.clone(),
        request_id,
        response_id,
        services,
    ));

    // Extract and apply variant detection patterns
    // This sets the identification parameters so the CDA detects the correct variant
    let patterns = mdd::extract_variant_patterns(&mdd_data.database, &selected_variant.name);
    if !patterns.is_empty() {
        state.apply_variant_patterns(&patterns).await;
    } else if !selected_variant.is_base {
        tracing::warn!(
            variant = %selected_variant.name,
            "No variant detection patterns found - CDA may not detect this variant correctly"
        );
    }

    // Apply default overrides (after variant-detection patterns; they win on conflict).
    if !args.no_defaults {
        if let Some(path) = resolve_defaults_path(&args) {
            tracing::info!(path = %path.display(), "Loading default overrides");
            match mdd::DefaultOverridesFile::load(&path) {
                Ok(file) => {
                    let (applied, unknown_svc, unknown_param, skipped) =
                        mdd::apply_default_overrides(&state, &file).await;
                    tracing::info!(
                        applied,
                        unknown_service = unknown_svc,
                        unknown_parameter = unknown_param,
                        skipped,
                        "Default overrides applied"
                    );
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "Failed to load defaults");
                }
            }
        }
    }

    // Start REST API (if not disabled)
    if !args.no_api {
        let api_state = Arc::clone(&state);
        let api_address = args.api_address.clone();
        let api_port = args.api_port;

        tracing::info!(
            address = %api_address,
            port = api_port,
            swagger_ui = format!("http://{}:{}/swagger-ui", api_address, api_port),
            "Starting REST API"
        );

        tokio::spawn(async move {
            if let Err(e) = api::launch_api_server(&api_address, api_port, api_state).await {
                tracing::error!(error = %e, "API server error");
            }
        });
    }

    // Start ISO-TP server
    tracing::info!(
        interface = %args.interface,
        request_id = format!("0x{:03X}", request_id),
        response_id = format!("0x{:03X}", response_id),
        "Starting CAN listener"
    );

    let isotp_server = IsoTpServer::new(args.interface.clone(), request_id, response_id);

    // Run until shutdown signal
    tokio::select! {
        result = isotp_server.run(Arc::clone(&state)) => {
            if let Err(e) = result {
                tracing::error!(error = %e, "ISO-TP server error");
            }
        }
        _ = signal::ctrl_c() => {
            tracing::info!("Shutdown signal received");
        }
    }

    // Print final stats
    let stats = state.get_stats().await;
    tracing::info!(
        requests = stats.requests_received,
        responses = stats.responses_sent,
        errors = stats.errors,
        unsupported = stats.unsupported_requests,
        "Final statistics"
    );

    Ok(())
}

/// Select a variant based on CLI argument or default logic
fn select_variant(
    variants: &[VariantInfo],
    requested: Option<&str>,
) -> Result<VariantInfo, SimulatorError> {
    match requested {
        Some(name) => variants
            .iter()
            .find(|v| v.name == name)
            .cloned()
            .ok_or_else(|| SimulatorError::VariantNotFound(name.to_string())),
        None => {
            // Pick base variant or first available
            variants
                .iter()
                .find(|v| v.is_base)
                .or(variants.first())
                .cloned()
                .ok_or(SimulatorError::NoVariants)
        }
    }
}

/// Resolve CAN IDs from CLI arguments or MDD
fn resolve_can_ids(
    args: &SimulatorArgs,
    database: &cda_database::datatypes::DiagnosticDatabase,
) -> Result<(u32, u32), SimulatorError> {
    // Try CLI arguments first
    let cli_request = args.get_request_id()?;
    let cli_response = args.get_response_id()?;

    // Try MDD COM parameters
    let (mdd_request, mdd_response) = mdd::extract_can_ids(database);

    // Resolve with priority: CLI > MDD
    let request_id = cli_request
        .or(mdd_request)
        .ok_or_else(|| SimulatorError::CanIdNotAvailable("request_id".to_string()))?;

    let response_id = cli_response
        .or(mdd_response)
        .ok_or_else(|| SimulatorError::CanIdNotAvailable("response_id".to_string()))?;

    Ok((request_id, response_id))
}

/// Resolve which defaults file to load.
///
/// Order: explicit `--defaults` > sibling `<mdd-stem>.defaults.toml` > None.
/// Returns `None` when no defaults file is configured or discoverable.
fn resolve_defaults_path(args: &SimulatorArgs) -> Option<std::path::PathBuf> {
    if let Some(p) = args.defaults.as_ref() {
        return Some(std::path::PathBuf::from(p));
    }
    let mdd = std::path::Path::new(&args.mdd_path);
    let stem = mdd.file_stem()?.to_str()?;
    let parent = mdd.parent().unwrap_or_else(|| std::path::Path::new("."));
    let candidate = parent.join(format!("{stem}.defaults.toml"));
    candidate.exists().then_some(candidate)
}
