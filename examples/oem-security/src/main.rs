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

//! Extension point: **custom security plugin**.
//!
//! A CDA that is stock except that `DefaultSecurityPlugin` is replaced. This is
//! where an integration puts OAuth2/OIDC, LDAP, or its own token format.
//!
//! ```text
//! cargo run -p example-oem-security -- --config opensovd-cda.toml
//! ```
//!
//! The plugin lives in [`security`]; this file is only the wiring.

mod security;

use clap::Parser;
use opensovd_cda_lib::{AppArgs, AppError, Setup};

use crate::security::{OemSecurityData, OemSecurityLoader};

#[tokio::main]
async fn main() -> Result<(), AppError> {
    // The plugin is chosen by the `Setup` type parameters; nothing else changes.
    let setup = Setup::<OemSecurityData, OemSecurityLoader>::new();

    opensovd_cda_lib::run_with_ext(AppArgs::parse(), setup).await
}
