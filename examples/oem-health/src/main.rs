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

//! Extension point: **reporting a vendor service in CDA's health endpoint**.
//!
//! An OEM integration usually depends on services CDA knows nothing about - here
//! a fictional `VehicleStatusProvider`. Operators want one readiness answer, not
//! two, so those services report through CDA's own `/health` rather than a
//! second endpoint.
//!
//! ```text
//! cargo run -p example-oem-health -- --config opensovd-cda.toml
//! curl localhost:20002/health
//! ```
//!
//! The providers live in [`health`]; this file is only the wiring.

mod health;

use cda_plugin_security::{DefaultSecurityPlugin, DefaultSecurityPluginData};
use clap::Parser;
use opensovd_cda_lib::{AppArgs, AppError, Setup};

#[tokio::main]
async fn main() -> Result<(), AppError> {
    // Health reporting can be switched off by configuration. Registration is
    // then a silent no-op rather than an error, so an integration does not need
    // to branch on it; `context.health().is_enabled()` tells you if it matters.
    let setup = Setup::<DefaultSecurityPluginData, DefaultSecurityPlugin>::new()
        .with_extension(health::register);

    opensovd_cda_lib::run_with_ext(AppArgs::parse(), setup).await
}
