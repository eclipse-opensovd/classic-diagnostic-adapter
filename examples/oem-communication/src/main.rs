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

//! Extension point: **custom communication plugin**.
//!
//! The communication plugin owns the decision of when the vehicle network may be
//! brought up. CDA's default applies `init_mode` policy (ADR-006) and nothing
//! else; an OEM that has a vehicle-side precondition - ignition on, service
//! mode, a workshop authorisation, a high-voltage interlock - expresses it by
//! replacing the plugin.
//!
//! ```text
//! cargo run -p example-oem-communication -- --config opensovd-cda.toml
//! ```
//!
//! The plugin lives in [`communication`]; this file is only the wiring.

mod communication;

use cda_plugin_security::{DefaultSecurityPlugin, DefaultSecurityPluginData};
use clap::Parser;
use opensovd_cda_lib::{AppArgs, AppError, Setup};

use crate::communication::{ServiceMode, ServiceModeCommunicationPluginBuilder};

#[tokio::main]
async fn main() -> Result<(), AppError> {
    let setup = Setup::<DefaultSecurityPluginData, DefaultSecurityPlugin>::new()
        .with_communication_plugin(ServiceModeCommunicationPluginBuilder {
            service_mode: ServiceMode::new(),
        });

    opensovd_cda_lib::run_with_ext(AppArgs::parse(), setup).await
}
