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
use cda_interfaces::storage_api::{Collection, RandomAccessData, Storage};
use figment::{
    Figment,
    providers::{Env, Format as _, Serialized, Toml},
};

use crate::AppError;

pub mod configfile;
pub mod generate;

/// Loads the configuration, merged with defaults and `CDA`-prefixed env vars.
///
/// Config file resolved in priority order:
/// * `config_file` arg (includes `CDA_CONFIG_FILE` env via clap)
/// * `<CDA_NAME>.toml`
/// # Errors
/// Returns an error message if the configuration file cannot be read or parsed.
pub fn load_config(config_file_path: Option<&str>) -> Result<configfile::Configuration, String> {
    let cda_name = std::option_env!("CDA_NAME").unwrap_or("opensovd-cda");
    let default_path = format!("{cda_name}.toml");
    let config_file = config_file_path.unwrap_or(&default_path);
    println!("Loading configuration from {config_file}");

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
pub fn load_config_with_fallback(config_path: Option<&str>) -> (configfile::Configuration, bool) {
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
#[cfg(feature = "config-optional")]
#[allow(clippy::unnecessary_wraps)]
pub fn require_config_source() -> Result<(), crate::AppError> {
    println!("No configuration found on disk or in storage. Using default values.");
    Ok(())
}

/// Checks whether a configuration source is available.
///
/// # Errors
/// Returns [`AppError::ConfigurationError`](crate::AppError::ConfigurationError) when no
/// configuration file is found on disk or in storage.
#[cfg(not(feature = "config-optional"))]
pub fn require_config_source() -> Result<(), crate::AppError> {
    Err(crate::AppError::ConfigurationError(
        "No configuration found. Provide a configuration file, store one via runtime update, or \
         build with the 'config-optional' feature to allow starting without one."
            .to_owned(),
    ))
}

/// Attempts to load configuration from the storage Configuration collection.
///
/// Scans the collection for configuration files. The filename is not prescribed — any
/// single entry in the collection is accepted.
///
/// # Errors
/// - `Err(AppError::ConfigurationError)` — more than one entry exists (ambiguous) or
///   reading/parsing the stored configuration failed.
///
/// # Returns
/// - `Ok(None)` — storage is unavailable or the collection is empty (no override).
/// - `Ok(Some(config))` — exactly one configuration was found and parsed successfully.
pub async fn load_config_with_storage_override(
    storage_path: &str,
) -> Result<Option<configfile::Configuration>, AppError> {
    let storage = match cda_storage::LocalStorage::new(storage_path) {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(error = %e, "Storage not available, no config override");
            return Ok(None);
        }
    };

    let collection = match storage
        .get_or_create_collection(&cda_interfaces::storage_api::CollectionName::Configuration)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(error = %e, "Cannot access Configuration collection, no config override");
            return Ok(None);
        }
    };

    let keys = collection.list().await.map_err(|e| {
        AppError::ConfigurationError(format!("Failed to list Configuration collection: {e}"))
    })?;

    let key = match keys.as_slice() {
        [] => {
            return Ok(None);
        }
        [single] => single,
        keys => {
            return Err(AppError::ConfigurationError(format!(
                "Expected at most one configuration in storage, found {}: {keys:?}",
                keys.len()
            )));
        }
    };

    let data_handle = collection.read(key).await.map_err(|e| {
        AppError::ConfigurationError(format!("Failed to read stored config '{key}': {e}"))
    })?;

    let size = data_handle.data_size().map_err(|e| {
        AppError::ConfigurationError(format!("Failed to get stored config size for '{key}': {e}"))
    })?;

    let mut buf = vec![0u8; usize::try_from(size).unwrap_or(usize::MAX)];
    data_handle.read_at(0, &mut buf).map_err(|e| {
        AppError::ConfigurationError(format!("Failed to read stored config data '{key}': {e}"))
    })?;

    let config = toml::from_str::<configfile::Configuration>(&String::from_utf8_lossy(&buf))
        .map_err(|e| {
            AppError::ConfigurationError(format!("Failed to parse stored config '{key}': {e}"))
        })?;

    tracing::info!(key, "Using configuration from storage (overrides disk)");
    Ok(Some(config))
}
