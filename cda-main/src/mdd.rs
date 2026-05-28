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
        let (ecu_name, ecu_manager, file_manager) = match load_single_mdd::<S>(
            path,
            config.flat_buf.mdd_decompress,
            &config.flat_buf,
            &config.database,
            &protocol,
            &config.com_params,
            &config.database.naming_convention,
            &config.functional_description,
            config.database.fallback_to_base_variant,
            &ecu_config_map,
        ) {
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

    Some(keys.iter()
        .filter_map(|k| match collection.file_path(k) {
            Ok(p) => Some(p),
            Err(e) => {
                tracing::warn!(key = %k, error = %e, "Failed to resolve MDD path in storage, skipping");
                None
            }
        })
        .collect())
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
// allowed because the only alternative is a struct with the same fields
#[allow(clippy::too_many_arguments)]
fn load_single_mdd<S: SecurityPlugin>(
    path: &Path,
    mdd_decompress: bool,
    flat_buf_settings: &FlatbBufConfig,
    database_config: &cda_database::DatabaseConfig,
    protocol: &Protocol,
    com_params: &ComParams,
    database_naming_convention: &DatabaseNamingConvention,
    func_description_cfg: &FunctionalDescriptionConfig,
    fallback_to_base_variant: bool,
    ecu_config_map: &HashMap<String, EcuConfig>,
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
    if mdd_decompress && let Err(e) = update_mdd_uncompressed(&mdd_path) {
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
    let com_params = Arc::new(com_params.clone());
    let ecu_config_map = Arc::new(ecu_config_map.clone());

    let ctx = EcuLoadContext {
        mdd_path: mdd_path.clone(),
        mddfile: &mddfile,
        ecu_name: ecu_name.clone(),
        flat_buf_settings,
        database_config,
        ecu_config_map: &ecu_config_map,
        database_naming_convention: database_naming_convention.clone(),
        func_description_cfg,
        protocol,
        com_params: &com_params,
        fallback_to_base_variant,
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
}
