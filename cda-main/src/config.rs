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
use cda_storage::LocalStorage;
use figment::{
    Figment,
    providers::{Env, Format as _, Serialized, Toml},
};

use crate::AppError;

pub mod com_params;
pub mod configfile;
pub mod generate;

pub(super) async fn load_config_from_file_or_storage(
    config_file: Option<&Path>,
) -> Result<configfile::Configuration, AppError> {
    let config_file = match config_file {
        Some(config_file) => {
            if config_file.exists() {
                config_file
            } else {
                // ignore `config-optional` feature here, because it's specifically for when no config was specified
                return Err(AppError::ConfigurationError {
                    message: format!(
                        "Specified configuration file {} does not exist",
                        config_file.display()
                    ),
                    source: None,
                });
            }
        }
        None => Path::new("opensovd-cda.toml"),
    };

    let storage_dir_override = None; //only needed for tests
    load_config_from_file_or_storage_with_storage_dir_override(config_file, storage_dir_override)
        .await
}

async fn load_config_from_file_or_storage_with_storage_dir_override(
    config_file: &Path,
    storage_override: Option<LocalStorage>,
) -> Result<configfile::Configuration, AppError> {
    let (figment_config, loaded_via_figment) = match load_config(config_file) {
        Ok(c) => (c, true),
        Err(e) => {
            println!("Failed to load configuration: {e}");
            (default_config(), false)
        }
    };

    let storage = match storage_override {
        Some(storage) => storage,
        None => match LocalStorage::new(&figment_config.runtime_update_config.storage_dir) {
            Ok(storage) => storage,
            Err(e) => {
                tracing::warn!(error = %e, "Storage not available, not loading config from storage, nor seeding it.");
                return Ok(figment_config);
            }
        },
    };

    let config = if let Some(storage_config) = load_config_with_storage_override(&storage).await? {
        storage_config
    } else {
        if !loaded_via_figment {
            require_config_source()?;
        }

        if figment_config
            .runtime_update_config
            .init_storage_from_config_file
        {
            seed_empty_storage_from_config_file(&storage, config_file).await?;
        }

        figment_config
    };

    Ok(config)
}

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

/// Checks whether a configuration source is available.
///
/// # Errors
/// Returns [`AppError`] when no configuration source is found
/// (only when the `config-optional` feature is disabled).
pub fn require_config_source() -> Result<(), AppError> {
    if cfg!(feature = "config-optional") {
        println!("No configuration found on disk or in storage. Using default values.");
        Ok(())
    } else {
        Err(AppError::ConfigurationError {
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
/// Returns [`AppError`] when no configuration file
/// is accessible.
pub async fn seed_empty_storage_from_config_file(
    storage: &LocalStorage,
    config_file: &Path,
) -> Result<(), AppError> {
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

    let count = cda_storage::storage_seed::seed_empty_storage_collection(
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
    storage: &LocalStorage,
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
    use std::path::PathBuf;

    use cda_interfaces::storage_api::CollectionName;

    use super::*;

    #[tokio::test]
    async fn should_load_config_from_file_when_storage_is_empty() {
        let fixture = StorageFixture::new();

        let mut config = default_config();
        config.database.seed_dir = "configured_dir/".to_string();
        fixture.write_config(&config);

        let result = load_config_from_file_or_storage_with_storage_dir_override(
            &fixture.config_file,
            Some(fixture.storage),
        )
        .await
        .unwrap();

        assert_eq!(result.database.seed_dir, "configured_dir/");
    }

    #[tokio::test]
    async fn should_load_config_from_storage_when_storage_has_been_seeded() {
        let fixture = StorageFixture::new();

        {
            let mut config = default_config();
            config.database.seed_dir = "stored_dir/".to_string();
            fixture.write_config(&config);

            seed_empty_storage_from_config_file(&fixture.storage, &fixture.config_file)
                .await
                .unwrap();
        }

        {
            let mut config = default_config();
            config.database.seed_dir = "configured_dir/".to_string();
            fixture.write_config(&config);
        }

        let result = load_config_from_file_or_storage_with_storage_dir_override(
            &fixture.config_file,
            Some(fixture.storage),
        )
        .await
        .unwrap();

        assert_eq!(result.database.seed_dir, "stored_dir/");
    }

    #[tokio::test]
    async fn seed_copies_config_file_into_empty_storage() {
        let fixture = StorageFixture::new();

        std::fs::write(&fixture.config_file, b"[database]\npath = \".\"").expect("write config");

        seed_empty_storage_from_config_file(&fixture.storage, &fixture.config_file)
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

        std::fs::write(&fixture.config_file, b"[database]\npath = \".\"").expect("write config");

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

        seed_empty_storage_from_config_file(&fixture.storage, &fixture.config_file)
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

        let result = seed_empty_storage_from_config_file(
            &fixture.storage,
            Path::new("/tmp/nonexistent_cda_config_test_12345.toml"),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn seed_preserves_config_content_through_storage_roundtrip() {
        let fixture = StorageFixture::new();

        let original_data = b"[database]\npath = \"/app/database\"\n";
        std::fs::write(&fixture.config_file, original_data).expect("write config");

        seed_empty_storage_from_config_file(&fixture.storage, &fixture.config_file)
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
        config_file: PathBuf,
        /// Carried along, so that it gets dropped at the end of the test
        _temp_dir: tempfile::TempDir,
    }
    impl StorageFixture {
        fn new() -> Self {
            let temp_dir = tempfile::tempdir().expect("temp dir");
            let storage = LocalStorage::new(temp_dir.path()).unwrap();
            let config_file = temp_dir.path().join("opensovd-cda.toml");
            Self {
                storage,
                config_file,
                _temp_dir: temp_dir,
            }
        }
        fn write_config(&self, config: &configfile::Configuration) {
            let config = toml::to_string(&config).unwrap();

            std::fs::write(&self.config_file, config).expect("write config");
        }
    }
}
