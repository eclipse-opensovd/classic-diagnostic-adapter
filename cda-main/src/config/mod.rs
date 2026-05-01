/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

use figment::{
    Figment,
    providers::{Env, Format as _, Serialized, Toml},
};

pub mod configfile;

/// Returns the path of the configuration file to load.
/// Uses the `CDA_CONFIG_FILE` environment variable if set,
/// otherwise defaults to `{CDA_NAME}.toml` (where `CDA_NAME` defaults to `opensovd-cda`).
#[must_use]
pub fn config_file_path() -> String {
    let cda_name = std::option_env!("CDA_NAME").unwrap_or("opensovd-cda");
    std::env::var("CDA_CONFIG_FILE").unwrap_or_else(|_| format!("{cda_name}.toml"))
}

/// Loads the configuration from a file specified by the `CDA_CONFIG_FILE` environment variable.
/// If the variable is not set, it defaults to `opensovd-cda.toml`.
/// The configuration is merged with default values and environment variables prefixed with `CDA`.
/// # Returns
/// A `Result` containing the loaded configuration or an error message if the loading fails
/// # Errors
/// Returns an error message if the configuration file cannot be read or parsed.
pub fn load_config() -> Result<configfile::Configuration, String> {
    let config_file = config_file_path();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_file_path_default() {
        // When CDA_CONFIG_FILE is not set, returns "{CDA_NAME}.toml"
        // CDA_NAME is a compile-time env var defaulting to "opensovd-cda"
        unsafe { std::env::remove_var("CDA_CONFIG_FILE") };
        let path = config_file_path();
        assert!(
            path.ends_with(".toml"),
            "Expected .toml extension, got: {path}"
        );
    }

    #[test]
    fn config_file_path_env_override() {
        unsafe { std::env::set_var("CDA_CONFIG_FILE", "/tmp/my-test-config.toml") };
        let path = config_file_path();
        assert_eq!(path, "/tmp/my-test-config.toml");
        unsafe { std::env::remove_var("CDA_CONFIG_FILE") };
    }

    #[test]
    fn config_file_path_empty_env_is_empty_string() {
        unsafe { std::env::set_var("CDA_CONFIG_FILE", "") };
        let path = config_file_path();
        assert_eq!(path, "");
        unsafe { std::env::remove_var("CDA_CONFIG_FILE") };
    }

    #[test]
    fn default_config_server_address() {
        let config = default_config();
        assert_eq!(config.server.address, "0.0.0.0");
    }

    #[test]
    fn default_config_server_port() {
        let config = default_config();
        assert_eq!(config.server.port, 20002);
    }

    #[test]
    fn default_config_database_path() {
        let config = default_config();
        assert_eq!(config.database.path, ".");
    }

    #[test]
    fn default_config_onboard_tester() {
        let config = default_config();
        assert!(config.onboard_tester);
    }
}
