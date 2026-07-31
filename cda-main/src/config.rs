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

use cda_interfaces::storage_api::{Collection, RandomAccessData, Storage};
use figment::{
    Figment,
    providers::{Env, Format as _, Serialized, Toml},
};

use crate::AppError;

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
        println!("No configuration found on disk or in storage. Using default values.");
        Ok(())
    } else {
        Err(crate::AppError::ConfigurationError {
            message: "No configuration found. Provide a configuration file, store one via runtime \
                      update, or build with the 'config-optional' feature to allow starting \
                      without one."
                .to_owned(),
            source: None,
        })
    }
}

/// Seeds the `Configuration` storage collection from `config_file_path` when the collection
/// is empty. This copies the configuration file into storage so that the runtime update plugin
/// has a populated baseline to work with.
///
/// # Errors
/// Returns [`AppError`](crate::AppError) when no configuration file
/// is accessible.
pub async fn seed_storage_from_config_file(
    storage: &cda_storage::LocalStorage,
    config_file: &Path,
) -> Result<(), crate::AppError> {
    let data = tokio::fs::read(config_file).await.map_err(|source| {
        crate::AppError::ConfigurationError {
            message: format!(
                "Cannot read config file from {} for seeding",
                config_file.display()
            ),
            source: Some(source.into()),
        }
    })?;

    let key = config_file
        .file_name()
        .ok_or_else(|| crate::AppError::ConfigurationError {
            message: format!(
                "Provided configuration file path does not have a file name: {}",
                config_file.display()
            ),
            source: None,
        })?
        .to_string_lossy()
        .to_string();

    let count = cda_storage::storage_seed::seed_storage_collection(
        storage,
        &cda_interfaces::storage_api::CollectionName::Configuration,
        std::iter::once((key.clone(), data)),
    )
    .await;

    if let Some(count) = count
        && count > 0
    {
        let config_file = config_file.display().to_string();
        tracing::info!(
            key,
            config_file,
            "Seeded Configuration collection from config file"
        );
    }
    Ok(())
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
    storage: &cda_storage::LocalStorage,
) -> Result<Option<configfile::Configuration>, AppError> {
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

    let keys = collection
        .list()
        .await
        .map_err(|source| AppError::ConfigurationError {
            message: "Failed to list Configuration collection".to_string(),
            source: Some(source.into()),
        })?;

    let key = match keys.as_slice() {
        [] => {
            return Ok(None);
        }
        [single] => single,
        keys => {
            return Err(AppError::ConfigurationError {
                message: format!(
                    "Expected at most one configuration in storage, found {}: {keys:?}",
                    keys.len()
                ),
                source: None,
            });
        }
    };

    let data_handle =
        collection
            .read(key)
            .await
            .map_err(|source| AppError::ConfigurationError {
                message: format!("Failed to read stored config '{key}'"),
                source: Some(source.into()),
            })?;

    let size = data_handle
        .data_size()
        .map_err(|source| AppError::ConfigurationError {
            message: format!("Failed to get stored config size for '{key}'"),
            source: Some(source.into()),
        })?;

    let mut buf = vec![0u8; usize::try_from(size).unwrap_or(usize::MAX)];
    data_handle
        .read_at(0, &mut buf)
        .map_err(|source| AppError::ConfigurationError {
            message: format!("Failed to read stored config data '{key}'"),
            source: Some(source.into()),
        })?;

    let config = toml::from_str::<configfile::Configuration>(&String::from_utf8_lossy(&buf))
        .map_err(|source| AppError::ConfigurationError {
            message: format!("Failed to parse stored config '{key}'"),
            source: Some(source.into()),
        })?;

    tracing::info!(key, "Using configuration from storage (overrides disk)");
    Ok(Some(config))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use cda_interfaces::storage_api::{CollectionName, RandomAccessData, Storage};
    use cda_storage::LocalStorage;

    use super::*;

    #[tokio::test]
    async fn seed_copies_config_file_into_empty_storage() {
        let fixture = StorageFixture::new();
        let config_dir = tempfile::tempdir().expect("config dir");
        let config_file = config_dir.path().join("opensovd-cda.toml");
        std::fs::write(&config_file, b"[database]\npath = \".\"").expect("write config");

        seed_storage_from_config_file(&fixture.storage, &config_file)
            .await
            .unwrap();

        let collection = fixture
            .storage
            .get_or_create_collection(&CollectionName::Configuration)
            .await
            .unwrap();
        let keys = collection.list().await.unwrap();
        assert_eq!(keys, vec!["opensovd-cda.toml"]);
    }

    #[tokio::test]
    async fn seed_skips_when_collection_already_populated() {
        let fixture = StorageFixture::new();
        let config_dir = tempfile::tempdir().expect("config dir");
        let config_file = config_dir.path().join("new.toml");
        std::fs::write(&config_file, b"[database]\npath = \".\"").expect("write config");

        // Pre-populate storage with an existing entry.
        let collection = fixture
            .storage
            .get_or_create_collection(&CollectionName::Configuration)
            .await
            .unwrap();
        let mut tx = fixture.storage.begin_transaction().unwrap();
        let mut data: &[u8] = b"EXISTING";
        collection
            .write(&mut tx, "existing.toml", &mut data)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        seed_storage_from_config_file(&fixture.storage, &config_file)
            .await
            .unwrap();

        // Verify collection was NOT modified.
        let collection = fixture
            .storage
            .get_or_create_collection(&CollectionName::Configuration)
            .await
            .unwrap();
        let keys = collection.list().await.unwrap();
        assert_eq!(keys, vec!["existing.toml"]);
    }

    #[tokio::test]
    async fn seed_errors_on_nonexistent_config_file() {
        let fixture = StorageFixture::new();

        let result = seed_storage_from_config_file(
            &fixture.storage,
            Path::new("/tmp/nonexistent_cda_config_test_12345.toml"),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn seed_preserves_config_content_through_storage_roundtrip() {
        let fixture = StorageFixture::new();
        let config_dir = tempfile::tempdir().expect("config dir");
        let original_data = b"[database]\npath = \"/app/database\"\n";
        let config_file = config_dir.path().join("opensovd-cda.toml");
        std::fs::write(&config_file, original_data).expect("write config");

        seed_storage_from_config_file(&fixture.storage, &config_file)
            .await
            .unwrap();

        let collection = fixture
            .storage
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

    struct StorageFixture {
        storage: LocalStorage,
        /// Carried along, so that it gets dropped at the end of the test
        _temp_dir: tempfile::TempDir,
    }
    impl StorageFixture {
        fn new() -> Self {
            let temp_dir = tempfile::tempdir().expect("storage dir");
            let storage = LocalStorage::new(temp_dir.path()).unwrap();
            Self {
                storage,
                _temp_dir: temp_dir,
            }
        }
    }
}
