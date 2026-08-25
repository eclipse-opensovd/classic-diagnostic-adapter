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

//! Extension point: **custom SOVD routes**.
//!
//! Standard SOVD covers the services ISO 17978 defines. It does not cover vendor
//! sequences spanning several UDS operations, and it does not cover turning one
//! call into something a tester actually wants. This example mounts three routes
//! that do both, under `/vehicle/v15/x-example-oem`:
//!
//! | Route | What it does |
//! |---|---|
//! | `PUT .../components/{ecu}/routines/{routine}` | Takes the caller\'s lock, raises the session, then runs a routine |
//! | `GET .../components/{ecu}/dtcs` | Reads stored DTCs for one ECU |
//! | `GET .../vehicle-snapshot` | Fans a DTC read across every present ECU and returns one document |
//!
//! ```text
//! cargo run -p example-oem-routes -- --config opensovd-cda.toml
//! curl localhost:20002/vehicle/v15/x-example-oem/vehicle-snapshot
//! ```
//!
//! The routes and handlers live in [`routes`]; this file is only the wiring.

mod routes;

use cda_plugin_security::{DefaultSecurityPlugin, DefaultSecurityPluginData};
use clap::Parser;
use opensovd_cda_lib::{AppArgs, AppError, Setup};

#[tokio::main]
async fn main() -> Result<(), AppError> {
    let setup = Setup::<DefaultSecurityPluginData, DefaultSecurityPlugin>::new()
        .with_extension(routes::register);

    opensovd_cda_lib::run_with_ext(AppArgs::parse(), setup).await
}
