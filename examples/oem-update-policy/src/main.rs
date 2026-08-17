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

//! Extension point: **custom runtime-update policy and database format**.
//!
//! A CDA that is stock except for who may update the diagnostic databases and
//! what format those databases are in. Storage stays `LocalStorage`; the
//! staging, apply, rollback and cleanup state machine stays CDA's.
//!
//! ```text
//! cargo run -p example-oem-update-policy -- --config opensovd-cda.toml
//! ```
//!
//! The policy and the format reader live in [`policy`]; this file is only the
//! wiring.

mod policy;

use cda_plugin_security::{DefaultSecurityPlugin, DefaultSecurityPluginData};
use clap::Parser;
use opensovd_cda_lib::{AppArgs, AppError, Setup, update::update_plugin_fn};

#[tokio::main]
async fn main() -> Result<(), AppError> {
    let setup = Setup::<DefaultSecurityPluginData, DefaultSecurityPlugin>::new()
        .with_update_plugin(update_plugin_fn(policy::build_update_plugin));

    opensovd_cda_lib::run_with_ext(AppArgs::parse(), setup).await
}
