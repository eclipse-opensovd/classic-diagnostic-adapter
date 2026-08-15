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

//! Extension point: **custom storage backend** for runtime-update files.
//!
//! A CDA that is stock except that the update plugin persists through a vendor
//! backend instead of `LocalStorage`. Real integrations use this to control
//! layout, auditing, or encryption-at-rest.
//!
//! ```text
//! cargo run -p example-oem-storage -- --config opensovd-cda.toml
//! ```
//!
//! The backend lives in [`storage`]; this file is only the wiring.

mod storage;

use cda_plugin_security::{DefaultSecurityPlugin, DefaultSecurityPluginData};
use clap::Parser;
use opensovd_cda_lib::{AppArgs, AppError, Setup, update::update_plugin_fn};

#[tokio::main]
async fn main() -> Result<(), AppError> {
    let setup = Setup::<DefaultSecurityPluginData, DefaultSecurityPlugin>::new()
        .with_update_plugin(update_plugin_fn(storage::build_update_plugin));

    opensovd_cda_lib::run_with_ext(AppArgs::parse(), setup).await
}
