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
use std::path::Path;

use figment::{
    Figment,
    providers::{Env, Format as _, Serialized, Toml},
};

pub mod com_params;
pub mod configfile;
pub mod generate;

/// Loads the configuration, merged with defaults and `CDA`-prefixed env vars.
///
/// Config file resolved in priority order:
/// * `config_file` arg (includes `CDA_CONFIG_FILE` env via clap)
/// * `opensovd-cda.toml`
/// # Errors
/// Returns an error message if the configuration file cannot be read or parsed.
pub fn load_config(config_file: &Path) -> Result<configfile::Configuration, String> {
    println!("Loading configuration from {}", config_file.display());

    Figment::from(Serialized::defaults(default_config()))
        .merge(Toml::file(config_file))
        .merge(Env::prefixed("CDA").ignore(&["CDA_CONFIG_FILE"]))
        .extract()
        .map_err(|e| format!("Failed to build configuration: {e}"))
}

#[must_use]
pub fn default_config() -> configfile::Configuration {
    configfile::Configuration::default()
}

/// Attempt to load config from file; on failure, fall back to defaults.
/// Returns the configuration and whether it was successfully loaded from file.
#[must_use]
pub fn load_config_with_fallback(config_path: &Path) -> (configfile::Configuration, bool) {
    match load_config(config_path) {
        Ok(c) => (c, true),
        Err(e) => {
            println!("Failed to load configuration: {e}");
            (default_config(), false)
        }
    }
}

/// Checks whether a configuration source is available.
///
/// # Errors
/// Returns [`AppError`](crate::AppError) when no configuration source is found
/// (only when the `config-optional` feature is disabled).
pub fn require_config_source() -> Result<(), crate::AppError> {
    if cfg!(feature = "config-optional") {
        println!("No configuration found on disk. Using default values.");
        Ok(())
    } else {
        Err(crate::AppError::ConfigurationError {
            message: "No configuration found. Provide a configuration file or build with the \
                      'config-optional' feature to allow starting without one."
                .to_owned(),
            source: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn load_configuration_fails_on_invalid_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, "this is {{ not valid toml").unwrap();

        let result = load_config(&path);
        let err = result.unwrap_err();
        assert!(
            err.contains("Failed to build configuration"),
            "unexpected error: {err:?}"
        );
    }
}
