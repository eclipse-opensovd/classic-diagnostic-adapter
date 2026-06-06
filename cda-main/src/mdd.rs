/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

use std::{
    fs::ReadDir,
    path::{Path, PathBuf},
    sync::Arc,
};

use cda_core::EcuManager;
use cda_database::{FileManager, ProtoLoadConfig, update_mdd_uncompressed};
use cda_health::StatusHealthProvider;
use cda_interfaces::{
    EcuAddressProvider, EcuManager as EcuManagerTrait, EcuManagerType, FunctionalDescriptionConfig,
    HashMap, HashMapEntry, HashMapExtensions, HashSet, Protocol,
    datatypes::{ComParams, DatabaseNamingConvention, FlatbBufConfig},
    file_manager::{Chunk, ChunkType},
    storage_api::{Collection, CollectionName, DirectFileAccess, Storage},
};
use cda_plugin_security::SecurityPlugin;
use tokio::sync::RwLock;

use crate::{
    AppError, DatabaseMap, FileManagerMap,
    config::configfile::{Configuration, EcuConfig},
    resolve_com_params,
};

pub(crate) const DB_HEALTH_COMPONENT_KEY: &str = "database";

#[derive(Debug, thiserror::Error)]
pub enum MddLoadingError {
    #[error("Failed to load MDD {path}: {reason}")]
    LoadFailed { path: String, reason: String },
    #[error("Failed to decompress MDD {path}: {reason}")]
    DecompressFailed { path: String, reason: String },
}

pub const PROTO_LOAD_CONFIG: &[ProtoLoadConfig; 4] = &[
    ProtoLoadConfig {
        type_: ChunkType::DiagnosticDescription,
        load_data: true,
        name: None,
    },
    ProtoLoadConfig {
        type_: ChunkType::CodeFile,
        load_data: false,
        name: None,
    },
    ProtoLoadConfig {
        type_: ChunkType::CodeFilePartial,
        load_data: false,
        name: None,
    },
    ProtoLoadConfig {
        type_: ChunkType::EmbeddedFile,
        load_data: false,
        name: None,
    },
];

#[derive(Debug)]
pub(crate) struct EcuMetadata {
    pub(crate) mdd_path: String,
    pub(crate) valid: bool,
}

/// Configuration context for loading a single ECU database.
struct EcuLoadContext<'a> {
    mdd_path: String,
    mddfile: &'a PathBuf,
    ecu_name: String,
    flat_buf_settings: &'a FlatbBufConfig,
    database_config: &'a cda_database::DatabaseConfig,
    ecu_config_map: &'a Arc<HashMap<String, EcuConfig>>,
    database_naming_convention: DatabaseNamingConvention,
    func_description_cfg: &'a FunctionalDescriptionConfig,
    protocol: &'a Protocol,
    com_params: &'a Arc<ComParams>,
    fallback_to_base_variant: bool,
}

/// Result of building an ECU manager and associated metadata.
struct EcuLoadResult<S: SecurityPlugin> {
    manager: EcuManager<S>,
    files: Vec<Chunk>,
}

pub(crate) type LoadedEcuMap<S> = HashMap<String, (EcuManager<S>, EcuMetadata)>;

fn get_mdd_files_and_size(files: ReadDir) -> Vec<(PathBuf, u64)> {
    let mut files = files
        .filter_map(|entry| {
            entry.ok().and_then(|entry| {
                let path = entry.path();
                if path.is_file() && path.extension().is_some_and(|ext| ext == "mdd") {
                    let filesize = std::fs::metadata(&path).ok().map_or(0u64, |m| m.len());
                    Some((path, filesize))
                } else {
                    None
                }
            })
        })
        .collect::<Vec<_>>();

    files.sort_by_key(|b| std::cmp::Reverse(b.1));
    files
}

/// Loads MDD database files into memory and returns the database and file-manager maps.
///
/// # Errors
/// Returns [`AppError`] if any database file fails to parse or initialize.
#[tracing::instrument(
    skip(config, mdd_paths, db_health_provider),
    fields(database_count = mdd_paths.len())
)]
pub async fn load_databases<S: SecurityPlugin>(
    config: &Configuration,
    mdd_paths: &[PathBuf],
    db_health_provider: Option<&Arc<StatusHealthProvider>>,
) -> Result<(DatabaseMap<S>, FileManagerMap), AppError> {
    if let Some(provider) = db_health_provider {
        provider.update_status(cda_health::Status::Starting).await;
    }
    let start = std::time::Instant::now();

    let ecu_config_map: HashMap<String, EcuConfig> = config
        .ecu
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.clone()))
        .collect();

    let protocol = cda_interfaces::Protocol::new(config.doip.protocol_name.clone());

    let mut loaded_ecus: LoadedEcuMap<S> = HashMap::new();
    let mut file_managers_map: HashMap<String, FileManager> = HashMap::new();

    for path in mdd_paths {
        let (ecu_name, ecu_manager, file_manager) =
            match load_single_mdd::<S>(path, config, &ecu_config_map, &protocol) {
                Ok(result) => result,
                Err(e) if config.database.ignore_invalid_mdd => {
                    tracing::warn!(path = %path.display(), error = %e, "Skipping invalid MDD file");
                    continue;
                }
                Err(e) => {
                    if let Some(provider) = db_health_provider {
                        provider.update_status(cda_health::Status::Failed).await;
                    }
                    return Err(AppError::DataError(e.to_string()));
                }
            };

        let mdd_path = path.to_str().unwrap_or_default().to_owned();
        insert_or_update_ecu(
            &mut loaded_ecus,
            &ecu_name,
            ecu_manager,
            EcuMetadata {
                mdd_path,
                valid: true,
            },
        );
        file_managers_map.insert(ecu_name, file_manager);
    }

    let databases: DatabaseMap<S> = loaded_ecus
        .into_iter()
        .filter(|(_, (_, meta))| meta.valid)
        .map(
            |(k, (ecu_manager, _)): (String, (EcuManager<S>, EcuMetadata))| {
                (k.to_lowercase(), RwLock::new(ecu_manager))
            },
        )
        .collect();

    mark_duplicate_ecus_by_address(&databases).await;

    let file_managers: FileManagerMap = file_managers_map
        .into_iter()
        .filter(|(k, _): &(String, FileManager)| databases.contains_key(&k.to_lowercase()))
        .map(|(k, v): (String, FileManager)| (k.to_lowercase(), v))
        .collect();

    handle_ecu_config_keys(
        &ecu_config_map,
        &databases,
        config.database.strict_ecu_config,
    )?;

    let end = std::time::Instant::now();
    tracing::info!(
        database_count = databases.len(),
        duration = ?end.saturating_duration_since(start),
        "Loaded databases"
    );

    let status = if databases.is_empty() {
        cda_health::Status::Failed
    } else {
        cda_health::Status::Up
    };
    if let Some(provider) = db_health_provider {
        provider.update_status(status).await;
    }

    Ok((databases, file_managers))
}

/// Returns paths to MDD files, preferring files found in the CDA storage at `storage_dir`.
/// Falls back to the configured `database_path` directory if storage is unavailable or empty.
pub async fn resolve_mdd_paths(storage_dir: &str, database_path: &str) -> Vec<PathBuf> {
    let storage_paths = load_mdd_paths_from_storage(storage_dir).await;
    if let Some(storage_paths) = storage_paths
        && !storage_paths.is_empty()
    {
        tracing::info!(
            count = storage_paths.len(),
            storage_dir,
            "Using MDD files from CDA storage (overrides configured database path)"
        );
        storage_paths
    } else {
        tracing::info!(
            configured_path = %database_path,
            "No MDD files found in storage, falling back to configured database path"
        );
        match std::fs::read_dir(database_path) {
            Ok(files) => get_mdd_files_and_size(files)
                .into_iter()
                .map(|(p, _)| p)
                .collect(),
            Err(e) => {
                tracing::error!(error = %e, "Failed to read directory");
                vec![]
            }
        }
    }
}

/// Returns paths to all MDD files found in the CDA storage at `storage_dir`.
/// Falls back to an empty list if the storage is unavailable or the collection cannot be accessed.
async fn load_mdd_paths_from_storage(storage_dir: &str) -> Option<Vec<PathBuf>> {
    let storage = match cda_storage::LocalStorage::new(storage_dir) {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(error = %e, "Storage not available, skipping storage MDD lookup");
            return None;
        }
    };

    let collection = match storage
        .get_or_create_collection(&CollectionName::DiagnosticDatabase)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(error = %e, "Cannot access DiagnosticDatabase collection");
            return None;
        }
    };

    let keys = match collection.list().await {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to list DiagnosticDatabase collection");
            return None;
        }
    };

    Some(
        keys.iter()
            .filter_map(|k| match collection.file_path(k) {
                Ok(p) => Some(p),
                Err(e) => {
                    tracing::warn!(key = %k, error = %e,
                    "Failed to resolve MDD path in storage, skipping");
                    None
                }
            })
            .collect(),
    )
}

/// Seeds the `DiagnosticDatabase` storage collection from `database_path` when the collection
/// is empty. This copies all `.mdd` files from the filesystem into storage so that the runtime
/// update plugin has a populated baseline to work with.
pub async fn seed_storage_from_database_path(storage_dir: &str, database_path: &str) {
    let mdd_files = match std::fs::read_dir(database_path) {
        Ok(entries) => get_mdd_files_and_size(entries),
        Err(e) => {
            tracing::warn!(error = %e, database_path, "Cannot read database path for seeding");
            return;
        }
    };

    if mdd_files.is_empty() {
        tracing::debug!(database_path, "No MDD files found in database path to seed");
        return;
    }

    let entries = mdd_files.into_iter().filter_map(|(path, _)| {
        let key = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_lowercase)
            .unwrap_or_default();
        if key.is_empty() {
            return None;
        }
        match std::fs::read(&path) {
            Ok(data) => Some((key, data)),
            Err(e) => {
                tracing::warn!(path = %path.display(),
                    error = %e, "Failed to read MDD file for seeding, skipping");
                None
            }
        }
    });

    if let Some(count) = crate::storage_seed::seed_storage_collection(
        storage_dir,
        &CollectionName::DiagnosticDatabase,
        entries,
    )
    .await
    {
        tracing::info!(
            count,
            database_path,
            storage_dir,
            "Seeded DiagnosticDatabase collection from database path"
        );
    }
}

pub(crate) fn handle_ecu_config_keys<S: SecurityPlugin>(
    ecu_config_map: &HashMap<String, EcuConfig>,
    databases: &HashMap<String, RwLock<EcuManager<S>>>,
    strict: bool,
) -> Result<(), AppError> {
    let mut unmatched = Vec::new();
    for ecu_key in ecu_config_map.keys() {
        if !databases.contains_key(ecu_key) {
            tracing::warn!(
                ecu_name = %ecu_key,
                "Per-ECU config entry does not match any loaded MDD database - ignored"
            );
            unmatched.push(ecu_key.clone());
        }
    }
    if strict && !unmatched.is_empty() {
        return Err(AppError::ConfigurationError(format!(
            "strict_ecu_config is enabled and the following per-ECU config entries do not match \
             any loaded database: {}",
            unmatched.join(", ")
        )));
    }
    Ok(())
}

/// Scans `databases` for ECUs sharing the same logical and gateway address and marks them as
/// duplicates of each other by calling `set_duplicating_ecu_names` on each affected manager.
async fn mark_duplicate_ecus_by_address<S: SecurityPlugin>(
    databases: &HashMap<String, RwLock<EcuManager<S>>>,
) {
    let mut ecus_by_address: HashMap<u16, HashMap<u16, Vec<String>>> = HashMap::new();
    for (name, db_lock) in databases {
        let db = db_lock.read().await;
        let logical_address = db.logical_address();
        let gateway_address = db.logical_gateway_address();
        ecus_by_address
            .entry(gateway_address)
            .or_default()
            .entry(logical_address)
            .or_default()
            .push(name.clone());
    }

    for logical_map in ecus_by_address.values() {
        for ecu_names in logical_map.values() {
            if ecu_names.len() <= 1 {
                continue;
            }

            for ecu_name in ecu_names {
                let Some(db_lock) = databases.get(ecu_name) else {
                    continue;
                };

                let mut db = db_lock.write().await;
                let duplicates: HashSet<String> = ecu_names
                    .iter()
                    .filter(|&name| name != ecu_name)
                    .cloned()
                    .collect();
                db.set_duplicating_ecu_names(duplicates);
            }
        }
    }
}

/// Extract and build the diagnostic database from proto data.
fn build_diagnostic_database(
    proto_data: &mut HashMap<ChunkType, Vec<Chunk>>,
    ctx: &EcuLoadContext<'_>,
) -> Option<cda_database::datatypes::DiagnosticDatabase> {
    let database_payload = proto_data
        .remove(&ChunkType::DiagnosticDescription)
        .and_then(|mut chunks| chunks.pop())
        .and_then(|c| c.payload);

    let payload = database_payload.or_else(|| {
        tracing::error!(
            mdd_file = %ctx.mddfile.display(),
            ecu_name = %ctx.ecu_name,
            "No payload found in diagnostic description for ECU"
        );
        None
    })?;

    let mut cfg = ctx.database_config.clone();
    if let Some(override_value) = ctx
        .ecu_config_map
        .get(&ctx.ecu_name.to_lowercase())
        .and_then(|c| c.ignore_protocol)
    {
        cfg.ignore_protocol = override_value;
    }

    cda_database::datatypes::DiagnosticDatabase::new_from_bytes(
        ctx.mdd_path.clone(),
        payload,
        ctx.flat_buf_settings.clone(),
        cfg,
    )
    .map_err(|e| {
        tracing::error!(
            mdd_file = %ctx.mddfile.display(),
            ecu_name = %ctx.ecu_name,
            error = %e,
            "Failed to create database from MDD payload"
        );
    })
    .ok()
}

/// Create an ECU manager from diagnostic database and configuration.
fn create_ecu_manager<S: SecurityPlugin>(
    diag_database: cda_database::datatypes::DiagnosticDatabase,
    protocol: Protocol,
    ecu_type: EcuManagerType,
    effective_com_params: &ComParams,
    ctx: &EcuLoadContext<'_>,
) -> Option<EcuManager<S>> {
    EcuManager::new(
        diag_database,
        protocol,
        effective_com_params,
        ctx.database_naming_convention.clone(),
        ecu_type,
        ctx.func_description_cfg,
        ctx.fallback_to_base_variant,
    )
    .map_err(|e| {
        tracing::error!(
            ecu_name = %ctx.ecu_name,
            error = ?e,
            "Failed to create DiagServiceManager"
        );
    })
    .ok()
}

/// Extract file chunks from proto data.
fn extract_file_chunks(mut proto_data: HashMap<ChunkType, Vec<Chunk>>) -> Vec<Chunk> {
    let filtered_chunks: Vec<Chunk> = [
        ChunkType::CodeFile,
        ChunkType::CodeFilePartial,
        ChunkType::EmbeddedFile,
    ]
    .iter()
    .filter_map(|chunk_type| proto_data.remove(chunk_type))
    .flat_map(IntoIterator::into_iter)
    .collect();

    filtered_chunks
        .into_iter()
        .chain(proto_data.into_values().flat_map(IntoIterator::into_iter))
        .collect()
}

/// Load and process a single ECU from MDD file.
fn load_ecu_from_file<S: SecurityPlugin>(
    proto_data: HashMap<ChunkType, Vec<Chunk>>,
    ctx: &EcuLoadContext<'_>,
    per_ecu_cfg: Option<&EcuConfig>,
) -> Option<EcuLoadResult<S>> {
    let mut proto_data = proto_data;
    let diag_database = build_diagnostic_database(&mut proto_data, ctx)?;
    let effective_com_params = resolve_com_params(
        &ctx.ecu_name,
        ctx.com_params,
        per_ecu_cfg.and_then(|c| c.com_params.as_ref()),
    )?;
    let protocol = per_ecu_cfg.and_then(|c| c.protocol.as_deref()).map_or_else(
        || ctx.protocol.clone(),
        |name| Protocol::new(name.to_owned()),
    );
    let ecu_type = if ctx.func_description_cfg.description_database == ctx.ecu_name {
        EcuManagerType::FunctionalDescription
    } else {
        EcuManagerType::Ecu
    };
    let manager = create_ecu_manager(
        diag_database,
        protocol,
        ecu_type,
        &effective_com_params,
        ctx,
    )?;
    let files = extract_file_chunks(proto_data);

    Some(EcuLoadResult { manager, files })
}

/// Loads a single MDD file and returns the ECU name, manager, and file manager.
///
/// # Errors
///
/// Returns [`MddLoadingError`] if decompression or loading fails.
fn load_single_mdd<S: SecurityPlugin>(
    path: &Path,
    config: &Configuration,
    ecu_config_map: &HashMap<String, EcuConfig>,
    protocol: &Protocol,
) -> Result<(String, EcuManager<S>, FileManager), MddLoadingError> {
    let mdd_path =
        path.to_str()
            .map(ToOwned::to_owned)
            .ok_or_else(|| MddLoadingError::LoadFailed {
                path: path.display().to_string(),
                reason: "Failed to convert path to string".to_string(),
            })?;

    // Ensure the MDD file contains uncompressed data (rewrite on first
    // use), so that subsequent loads skip LZMA decompression.
    if config.flat_buf.mdd_decompress
        && let Err(e) = update_mdd_uncompressed(&mdd_path)
    {
        return Err(MddLoadingError::DecompressFailed {
            path: mdd_path,
            reason: e.to_string(),
        });
    }

    let (ecu_name, proto_data) = cda_database::load_proto_data(&mdd_path, PROTO_LOAD_CONFIG)
        .map_err(|e| MddLoadingError::LoadFailed {
            path: mdd_path.clone(),
            reason: e.to_string(),
        })?;

    let mddfile = PathBuf::from(path);
    let com_params = Arc::new(config.com_params.clone());
    let ecu_config_map = Arc::new(ecu_config_map.clone());

    let ctx = EcuLoadContext {
        mdd_path: mdd_path.clone(),
        mddfile: &mddfile,
        ecu_name: ecu_name.clone(),
        flat_buf_settings: &config.flat_buf,
        database_config: &config.database,
        ecu_config_map: &ecu_config_map,
        database_naming_convention: config.database.naming_convention.clone(),
        func_description_cfg: &config.functional_description,
        protocol,
        com_params: &com_params,
        fallback_to_base_variant: config.database.fallback_to_base_variant,
    };

    let per_ecu_cfg = ecu_config_map.get(&ecu_name.to_lowercase());
    let result = load_ecu_from_file(proto_data, &ctx, per_ecu_cfg).ok_or_else(|| {
        MddLoadingError::LoadFailed {
            path: mdd_path.clone(),
            reason: format!("Failed to load ECU {ecu_name} from MDD"),
        }
    })?;

    let file_manager = FileManager::new(mdd_path, result.files);
    Ok((ecu_name, result.manager, file_manager))
}

/// Inserts or updates an ECU entry in the loaded map, handling duplicate names
/// by comparing logical addresses and revisions.
fn insert_or_update_ecu<S: SecurityPlugin>(
    loaded_ecus: &mut LoadedEcuMap<S>,
    ecu_name: &str,
    ecu_manager: EcuManager<S>,
    ecu_metadata: EcuMetadata,
) {
    let mdd_path = ecu_metadata.mdd_path.clone();
    match loaded_ecus.entry(ecu_name.to_owned()) {
        HashMapEntry::Occupied(mut entry) => {
            let (existing_ecu, existing_meta) = entry.get_mut();
            if !ecu_manager.logical_address_eq(existing_ecu) {
                tracing::error!(
                    ecu_name = %ecu_name,
                    "Duplicate ECU with different addresses. Marking as invalid."
                );
                existing_meta.valid = false;
                return;
            }
            if ecu_manager.revision() > existing_ecu.revision() {
                tracing::warn!(
                    ecu_name = %ecu_name,
                    existing_mdd = %existing_meta.mdd_path,
                    existing_revision = %existing_ecu.revision(),
                    new_mdd = %mdd_path,
                    new_revision = %ecu_manager.revision(),
                    "Replacing ECU with newer revision"
                );
                entry.insert((ecu_manager, ecu_metadata));
            } else {
                tracing::warn!(
                    ecu_name = %ecu_name,
                    existing_mdd = %existing_meta.mdd_path,
                    existing_revision = %existing_ecu.revision(),
                    new_mdd = %mdd_path,
                    new_revision = %ecu_manager.revision(),
                    "Keeping existing ECU with newer or equal revision"
                );
            }
        }
        HashMapEntry::Vacant(entry) => {
            entry.insert((ecu_manager, ecu_metadata));
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::resolve_com_params;

    #[test]
    fn resolve_com_params_returns_none_on_figment_extraction_failure() {
        use cda_interfaces::datatypes::ComParams;
        let global = ComParams::default();
        let mut table = toml::Table::new();
        table.insert(
            "uds".to_owned(),
            toml::Value::String("not_a_struct".to_owned()),
        );
        let ecu_params = crate::config::configfile::EcuComParams(table);
        let result = resolve_com_params("BAD_ECU", &global, Some(&ecu_params));
        assert!(
            result.is_none(),
            "resolve_com_params must return None when figment extraction fails"
        );
    }

    use cda_interfaces::storage_api::{Collection as _, CollectionName, DirectFileAccess, Storage};
    use cda_storage::LocalStorage;

    use super::{resolve_mdd_paths, seed_storage_from_database_path};

    /// Helper: create a temp dir with `.mdd` files containing given data.
    fn create_database_dir(files: &[(&str, &[u8])]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("create temp dir");
        for (name, data) in files {
            std::fs::write(dir.path().join(name), data).expect("write file");
        }
        dir
    }

    #[tokio::test]
    async fn seed_copies_mdd_files_into_empty_storage() {
        let storage_dir = tempfile::tempdir().expect("storage dir");
        let db_dir = create_database_dir(&[
            ("ecu_a.mdd", b"MDD_CONTENT_A"),
            ("ecu_b.mdd", b"MDD_CONTENT_B"),
        ]);

        seed_storage_from_database_path(
            storage_dir.path().to_str().unwrap(),
            db_dir.path().to_str().unwrap(),
        )
        .await;

        let storage = LocalStorage::new(storage_dir.path()).unwrap();
        let collection = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();

        let mut keys = collection.list().await.unwrap();
        keys.sort();
        assert_eq!(keys, vec!["ecu_a.mdd", "ecu_b.mdd"]);
    }

    #[tokio::test]
    async fn seed_skips_when_collection_already_populated() {
        let storage_dir = tempfile::tempdir().expect("storage dir");
        let db_dir = create_database_dir(&[("new.mdd", b"NEW_DATA")]);

        // Pre-populate storage with an existing entry.
        let storage = LocalStorage::new(storage_dir.path()).unwrap();
        let collection = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        let mut tx = storage.begin_transaction().unwrap();
        let mut data: &[u8] = b"EXISTING";
        collection
            .write(&mut tx, "existing.mdd", &mut data)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        drop(storage);

        seed_storage_from_database_path(
            storage_dir.path().to_str().unwrap(),
            db_dir.path().to_str().unwrap(),
        )
        .await;

        // Verify collection was NOT modified.
        let storage = LocalStorage::new(storage_dir.path()).unwrap();
        let collection = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        let keys = collection.list().await.unwrap();
        assert_eq!(keys, vec!["existing.mdd"]);
    }

    #[tokio::test]
    async fn seed_ignores_non_mdd_files() {
        let storage_dir = tempfile::tempdir().expect("storage dir");
        let db_dir = create_database_dir(&[
            ("valid.mdd", b"MDD_DATA"),
            ("readme.txt", b"TEXT"),
            ("data.bin", b"BIN"),
        ]);

        seed_storage_from_database_path(
            storage_dir.path().to_str().unwrap(),
            db_dir.path().to_str().unwrap(),
        )
        .await;

        let storage = LocalStorage::new(storage_dir.path()).unwrap();
        let collection = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        let keys = collection.list().await.unwrap();
        assert_eq!(keys, vec!["valid.mdd"]);
    }

    #[tokio::test]
    async fn seed_handles_empty_database_dir() {
        let storage_dir = tempfile::tempdir().expect("storage dir");
        let db_dir = tempfile::tempdir().expect("empty db dir");

        seed_storage_from_database_path(
            storage_dir.path().to_str().unwrap(),
            db_dir.path().to_str().unwrap(),
        )
        .await;

        let storage = LocalStorage::new(storage_dir.path()).unwrap();
        let collection = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        assert!(collection.is_empty().await.unwrap());
    }

    #[tokio::test]
    async fn seed_handles_nonexistent_database_path() {
        let storage_dir = tempfile::tempdir().expect("storage dir");

        // Should not panic, just return early.
        seed_storage_from_database_path(
            storage_dir.path().to_str().unwrap(),
            "/tmp/nonexistent_cda_test_path_12345",
        )
        .await;

        let storage = LocalStorage::new(storage_dir.path()).unwrap();
        let collection = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        assert!(collection.is_empty().await.unwrap());
    }

    #[tokio::test]
    async fn seed_lowercases_mdd_filenames_as_keys() {
        let storage_dir = tempfile::tempdir().expect("storage dir");
        let db_dir = create_database_dir(&[("ECU_UPPER.mdd", b"UPPER_DATA")]);

        seed_storage_from_database_path(
            storage_dir.path().to_str().unwrap(),
            db_dir.path().to_str().unwrap(),
        )
        .await;

        let storage = LocalStorage::new(storage_dir.path()).unwrap();
        let collection = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        let keys = collection.list().await.unwrap();
        assert_eq!(keys, vec!["ecu_upper.mdd"]);
    }

    #[tokio::test]
    async fn seed_preserves_file_content_through_storage_roundtrip() {
        let storage_dir = tempfile::tempdir().expect("storage dir");
        let original_data = b"MDD_BINARY_PAYLOAD_1234567890";
        let db_dir = create_database_dir(&[("FLXC1000.mdd", original_data)]);

        seed_storage_from_database_path(
            storage_dir.path().to_str().unwrap(),
            db_dir.path().to_str().unwrap(),
        )
        .await;

        let storage = LocalStorage::new(storage_dir.path()).unwrap();
        let collection = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();

        let stored_path = collection.file_path("flxc1000.mdd").unwrap();
        let stored_data = std::fs::read(&stored_path).expect("read stored file");
        assert_eq!(
            stored_data, original_data,
            "Storage must preserve file content byte-for-byte"
        );
    }

    #[tokio::test]
    async fn resolve_mdd_paths_returns_storage_paths_after_seed() {
        let storage_dir = tempfile::tempdir().expect("storage dir");
        let db_dir = create_database_dir(&[("FLXC1000.mdd", b"MDD_A"), ("FSNR2000.mdd", b"MDD_B")]);

        let storage_str = storage_dir.path().to_str().unwrap();
        let db_str = db_dir.path().to_str().unwrap();

        seed_storage_from_database_path(storage_str, db_str).await;
        let paths = resolve_mdd_paths(storage_str, db_str).await;

        assert_eq!(paths.len(), 2, "Expected 2 MDD paths from storage");
        for p in &paths {
            assert!(p.exists(), "Resolved path must exist: {}", p.display());
            // Paths should come from storage, not from the original database dir.
            assert!(
                !p.starts_with(db_dir.path()),
                "Path should come from storage, not the database dir: {}",
                p.display()
            );
        }
    }

    #[tokio::test]
    async fn resolve_mdd_paths_falls_back_when_storage_empty() {
        let storage_dir = tempfile::tempdir().expect("storage dir");
        let db_dir = create_database_dir(&[("ECU.mdd", b"DATA")]);

        // Do NOT seed - storage remains empty.
        let paths = resolve_mdd_paths(
            storage_dir.path().to_str().unwrap(),
            db_dir.path().to_str().unwrap(),
        )
        .await;

        let first = paths.first().expect("first should exist");

        assert_eq!(paths.len(), 1, "Expected 1 MDD path from fallback");
        assert!(
            first.starts_with(db_dir.path()),
            "Path should come from database dir when storage is empty: {}",
            first.display()
        );
    }
}
