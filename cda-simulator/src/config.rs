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

//! CLI configuration for the ECU simulator.

use clap::Parser;

use crate::error::SimulatorError;

/// MDD-based ECU Simulator for testing CAN/ISO-TP diagnostic operations.
///
/// This simulator parses an MDD file to understand service definitions and
/// responds to diagnostic requests on CAN bus. All behavior is MDD-driven.
#[derive(Parser, Debug, Clone)]
#[command(name = "cda-simulator")]
#[command(about = "MDD-based ECU Simulator for testing CAN/ISO-TP diagnostic operations")]
#[command(version)]
pub struct SimulatorArgs {
    /// Path to the MDD file
    #[arg(short = 'm', long)]
    pub mdd_path: String,

    /// CAN interface to use
    #[arg(short = 'i', long, default_value = "vxcan1")]
    pub interface: String,

    /// CAN ID to listen on (overrides MDD CP_CanPhysicalRequestAddress)
    #[arg(long)]
    pub request_id: Option<String>,

    /// CAN ID to respond on (overrides MDD CP_CanPhysicalResponseAddress)
    #[arg(long)]
    pub response_id: Option<String>,

    /// Variant to simulate (if not specified, lists available and picks default)
    #[arg(short = 'v', long)]
    pub variant: Option<String>,

    /// REST API listen address
    #[arg(long, default_value = "127.0.0.1")]
    pub api_address: String,

    /// REST API listen port
    #[arg(long, default_value = "8080")]
    pub api_port: u16,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    pub log_level: String,

    /// Disable REST API
    #[arg(long)]
    pub no_api: bool,

    /// Path to a defaults TOML file. Loaded at startup, after variant-detection
    /// patterns. If unset, the simulator looks for a sibling file named after
    /// the MDD (e.g. `foo.mdd` -> `foo.defaults.toml` in the same directory).
    #[arg(long)]
    pub defaults: Option<String>,

    /// Disable default-overrides loading entirely (no explicit path, no
    /// sibling auto-discovery).
    #[arg(long)]
    pub no_defaults: bool,
}

impl SimulatorArgs {
    /// Parse a CAN ID string (supports 0x prefix for hex)
    pub fn parse_can_id(s: &str) -> Result<u32, SimulatorError> {
        let s = s.trim().to_lowercase();
        let s = s.strip_prefix("0x").unwrap_or(&s);
        u32::from_str_radix(s, 16)
            .map_err(|_| SimulatorError::Config(format!("Invalid CAN ID: {s}")))
    }

    /// Get the request ID if provided via CLI
    pub fn get_request_id(&self) -> Result<Option<u32>, SimulatorError> {
        self.request_id
            .as_ref()
            .map(|s| Self::parse_can_id(s))
            .transpose()
    }

    /// Get the response ID if provided via CLI
    pub fn get_response_id(&self) -> Result<Option<u32>, SimulatorError> {
        self.response_id
            .as_ref()
            .map(|s| Self::parse_can_id(s))
            .transpose()
    }
}
