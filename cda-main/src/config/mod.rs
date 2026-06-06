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

/// Returns the effective configuration file path.
///
/// Uses `explicit` if provided, otherwise falls back to `<CDA_NAME>.toml`
/// (where `CDA_NAME` is a compile-time env var defaulting to `opensovd-cda`).
#[must_use]
pub fn resolve_config_file_path(explicit: Option<&str>) -> String {
    let cda_name = std::option_env!("CDA_NAME").unwrap_or("opensovd-cda");
    explicit.unwrap_or(&format!("{cda_name}.toml")).to_owned()
}

/// Loads the configuration, merged with defaults and `CDA`-prefixed env vars.
///
/// Config file resolved in priority order:
/// * `config_file` arg (includes `CDA_CONFIG_FILE` env via clap)
/// * `<CDA_NAME>.toml`
/// # Errors
/// Returns an error message if the configuration file cannot be read or parsed.
pub fn load_config(config_file_path: Option<&str>) -> Result<configfile::Configuration, String> {
    let config_file = resolve_config_file_path(config_file_path);
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

/// Seeds the `Configuration` storage collection from `config_file_path` when the collection
/// is empty. This copies the configuration file into storage so that the runtime update plugin
/// has a populated baseline to work with.
pub async fn seed_storage_from_config_file(storage_dir: &str, config_file_path: &str) {
    let data = match std::fs::read(config_file_path) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error = %e, config_file_path, "Cannot read config file for seeding");
            return;
        }
    };

    let key = std::path::Path::new(config_file_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(config_file_path)
        .to_owned();

    if let Some(count) = crate::storage_seed::seed_storage_collection(
        storage_dir,
        &cda_interfaces::storage_api::CollectionName::Configuration,
        std::iter::once((key.clone(), data)),
    )
    .await
        && count > 0
    {
        tracing::info!(
            key,
            config_file_path,
            storage_dir,
            "Seeded Configuration collection from config file"
        );
    }
}

/// Attempts to load configuration from the storage Configuration collection.
///
/// Scans the collection for configuration files. The filename is not prescribed - any
/// single entry in the collection is accepted.
///
/// # Errors
/// - `Err(AppError::ConfigurationError)` - more than one entry exists (ambiguous) or
///   reading/parsing the stored configuration failed.
///
/// # Returns
/// - `Ok(None)` - storage is unavailable or the collection is empty (no override).
/// - `Ok(Some(config))` - exactly one configuration was found and parsed successfully.
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

#[cfg(test)]
mod tests {
    use cda_interfaces::storage_api::{Collection as _, CollectionName, RandomAccessData, Storage};
    use cda_storage::LocalStorage;

    use super::seed_storage_from_config_file;

    #[tokio::test]
    async fn seed_copies_config_file_into_empty_storage() {
        let storage_dir = tempfile::tempdir().expect("storage dir");
        let config_dir = tempfile::tempdir().expect("config dir");
        let config_file = config_dir.path().join("opensovd-cda.toml");
        std::fs::write(&config_file, b"[database]\npath = \".\"").expect("write config");

        seed_storage_from_config_file(
            storage_dir.path().to_str().unwrap(),
            config_file.to_str().unwrap(),
        )
        .await;

        let storage = LocalStorage::new(storage_dir.path()).unwrap();
        let collection = storage
            .get_or_create_collection(&CollectionName::Configuration)
            .await
            .unwrap();
        let keys = collection.list().await.unwrap();
        assert_eq!(keys, vec!["opensovd-cda.toml"]);
    }

    #[tokio::test]
    async fn seed_skips_when_collection_already_populated() {
        let storage_dir = tempfile::tempdir().expect("storage dir");
        let config_dir = tempfile::tempdir().expect("config dir");
        let config_file = config_dir.path().join("new.toml");
        std::fs::write(&config_file, b"[database]\npath = \".\"").expect("write config");

        // Pre-populate storage with an existing entry.
        let storage = LocalStorage::new(storage_dir.path()).unwrap();
        let collection = storage
            .get_or_create_collection(&CollectionName::Configuration)
            .await
            .unwrap();
        let mut tx = storage.begin_transaction().unwrap();
        let mut data: &[u8] = b"EXISTING";
        collection
            .write(&mut tx, "existing.toml", &mut data)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        drop(storage);

        seed_storage_from_config_file(
            storage_dir.path().to_str().unwrap(),
            config_file.to_str().unwrap(),
        )
        .await;

        // Verify collection was NOT modified.
        let storage = LocalStorage::new(storage_dir.path()).unwrap();
        let collection = storage
            .get_or_create_collection(&CollectionName::Configuration)
            .await
            .unwrap();
        let keys = collection.list().await.unwrap();
        assert_eq!(keys, vec!["existing.toml"]);
    }

    #[tokio::test]
    async fn seed_handles_nonexistent_config_file() {
        let storage_dir = tempfile::tempdir().expect("storage dir");

        // Should not panic, just return early.
        seed_storage_from_config_file(
            storage_dir.path().to_str().unwrap(),
            "/tmp/nonexistent_cda_config_test_12345.toml",
        )
        .await;

        let storage = LocalStorage::new(storage_dir.path()).unwrap();
        let collection = storage
            .get_or_create_collection(&CollectionName::Configuration)
            .await
            .unwrap();
        assert!(collection.is_empty().await.unwrap());
    }

    #[tokio::test]
    async fn seed_preserves_config_content_through_storage_roundtrip() {
        let storage_dir = tempfile::tempdir().expect("storage dir");
        let config_dir = tempfile::tempdir().expect("config dir");
        let original_data = b"[database]\npath = \"/app/database\"\n";
        let config_file = config_dir.path().join("opensovd-cda.toml");
        std::fs::write(&config_file, original_data).expect("write config");

        seed_storage_from_config_file(
            storage_dir.path().to_str().unwrap(),
            config_file.to_str().unwrap(),
        )
        .await;

        let storage = LocalStorage::new(storage_dir.path()).unwrap();
        let collection = storage
            .get_or_create_collection(&CollectionName::Configuration)
            .await
            .unwrap();
        let data_handle = collection.read("opensovd-cda.toml").await.unwrap();
        let size = data_handle.data_size().unwrap();
        let mut buf = vec![0u8; usize::try_from(size).expect("size fits in usize")];
        data_handle.read_at(0, &mut buf).unwrap();
        assert_eq!(
            buf, original_data,
            "Storage must preserve config content byte-for-byte"
        );
    }
}
