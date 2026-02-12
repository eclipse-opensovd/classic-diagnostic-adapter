/*
 * Copyright (c) 2025-2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
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

use figment::{
    Figment,
    providers::{Env, Format as _, Serialized, Toml},
};

pub mod configfile;

/// Loads the configuration from a file specified by the `CDA_CONFIG_FILE` environment variable.
/// If the variable is not set, it defaults to `opensovd-cda.toml`.
/// The configuration is merged with default values and environment variables prefixed with `CDA`.
/// # Returns
/// A `Result` containing the loaded configuration or an error message if the loading fails
/// # Errors
/// Returns an error message if the configuration file cannot be read or parsed.
pub fn load_config() -> Result<configfile::Configuration, String> {
    let cda_name = std::option_env!("CDA_NAME").unwrap_or("opensovd-cda");
    let config_file =
        std::env::var("CDA_CONFIG_FILE").unwrap_or_else(|_| format!("{cda_name}.toml"));
    println!("Loading configuration from {config_file}");

    Figment::from(Serialized::defaults(default_config()))
        .merge(Toml::file(&config_file))
        .merge(Env::prefixed("CDA").ignore(&["CDA_CONFIG_FILE"]))
        .extract()
        .map_err(|e| format!("Failed to build configuration: {e}"))
}

#[must_use]
pub fn default_config() -> configfile::Configuration {
    configfile::Configuration::default()
}
