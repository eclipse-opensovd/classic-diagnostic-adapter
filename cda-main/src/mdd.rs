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

use std::{
    fs::ReadDir,
    path::{Path, PathBuf},
    sync::Arc,
};

use cda_core::{EcuManager, EcuManagerConfig};
use cda_database::{FileManager, ProtoLoadConfig};
use cda_interfaces::{
    EcuAddresses, EcuManager as EcuManagerTrait, EcuManagerType, FunctionalDescriptionConfig,
    HashMap, HashMapEntry, HashMapExtensions, HashSet, Protocol,
    datatypes::{ComParams, DatabaseNamingConvention, FlatbBufConfig},
    file_manager::{Chunk, ChunkType},
    health::HealthProvider,
    storage_api::{Collection, CollectionName, DirectFileAccess, Storage},
};
use cda_plugin_security::SecurityPlugin;
use tokio::sync::RwLock;

use crate::{
    AppError,
    config::configfile::{Configuration, EcuConfig},
    vehicle::DatabaseMap,
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
    strict_parameter_validation: bool,
}

/// Result of building an ECU manager and associated metadata.
struct EcuLoadResult<S: SecurityPlugin> {
    manager: EcuManager<S>,
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
    db_health_provider: Option<&Arc<dyn HealthProvider>>,
) -> Result<DatabaseMap<S>, AppError> {
    if let Some(provider) = db_health_provider {
        provider.set_status(cda_health::Status::Starting).await;
    }
    let start = std::time::Instant::now();

    let ecu_config_map: HashMap<String, EcuConfig> = config
        .ecu
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.clone()))
        .collect();

    let protocol = cda_interfaces::Protocol::new(config.doip.protocol_name.clone());

    let mut loaded_ecus: LoadedEcuMap<S> = HashMap::new();

    for path in mdd_paths {
        let (ecu_name, ecu_manager) =
            match load_single_mdd::<S>(path, config, &ecu_config_map, &protocol) {
                Ok(result) => result,
                Err(e) if config.database.ignore_invalid_mdd => {
                    tracing::warn!(path = %path.display(), error = %e, "Skipping invalid MDD file");
                    continue;
                }
                Err(e) => {
                    if let Some(provider) = db_health_provider {
                        provider.set_status(cda_health::Status::Failed).await;
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
    }

    let databases: DatabaseMap<S> = loaded_ecus
        .into_iter()
        .filter(|(_, (_, meta))| meta.valid)
        .map(
            |(k, (ecu_manager, _)): (String, (EcuManager<S>, EcuMetadata))| {
                (k.to_lowercase(), Arc::new(RwLock::new(ecu_manager)))
            },
        )
        .collect();

    mark_duplicate_ecus_by_address(&databases).await;

    handle_ecu_config_keys(&ecu_config_map, &databases, config.strict.ecu_config())?;

    let end = std::time::Instant::now();
    tracing::info!(
        database_count = databases.len(),
        duration = ?end.saturating_duration_since(start),
        "Loaded databases"
    );

    // When `exit_no_database_loaded = false` the operator has explicitly opted
    // into running without any ECU databases. Marking health `Failed` in that
    // case would block the readiness probe forever, so treat empty-but-allowed
    // as `Up`.
    let status = if databases.is_empty() && config.database.exit_no_database_loaded {
        cda_health::Status::Failed
    } else {
        cda_health::Status::Up
    };
    if let Some(provider) = db_health_provider {
        provider.set_status(status).await;
    }

    Ok(databases)
}

/// Resolves the MDD paths for `config`.
///
/// Startup and reload use this resolution site with the same configuration pair.
/// An empty result is not an error: a deployment with no MDD files is a legitimate state.
pub async fn resolve_configured_mdd_paths(config: &Configuration) -> Vec<PathBuf> {
    resolve_mdd_paths(
        &config.runtime_update_config.storage_dir,
        &config.database.seed_dir,
    )
    .await
}

/// Returns the authoritative MDD paths for `storage_dir` and `database_seed_dir`.
///
/// An initialized storage collection is authoritative even when empty. The configured database
/// directory is used only while the collection is absent or storage is unavailable.
pub async fn resolve_mdd_paths(storage_dir: &str, database_seed_dir: &str) -> Vec<PathBuf> {
    if let Some(storage_paths) = load_mdd_paths_from_storage(storage_dir).await {
        tracing::info!(
            count = storage_paths.len(),
            storage_dir,
            "Using authoritative MDD collection from CDA storage"
        );
        storage_paths
    } else {
        tracing::info!(
            seed_dir = %database_seed_dir,
            "MDD storage collection is uninitialized; using configured database seed directory"
        );
        match std::fs::read_dir(database_seed_dir) {
            Ok(files) => get_mdd_files_and_size(files)
                .into_iter()
                .map(|(path, _)| path)
                .collect(),
            Err(error) => {
                tracing::error!(%error, "Failed to read database seed directory");
                vec![]
            }
        }
    }
}

/// Returns paths to all MDD files in an initialized CDA storage collection.
///
/// `Some(empty)` means storage was deliberately initialized with no current files; `None` means
/// the collection is absent or storage cannot be accessed.
async fn load_mdd_paths_from_storage(storage_dir: &str) -> Option<Vec<PathBuf>> {
    let storage = match cda_storage::LocalStorage::new(storage_dir) {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(error = %e, "Storage not available, skipping storage MDD lookup");
            return None;
        }
    };

    let collection = match storage
        .get_collection(&CollectionName::DiagnosticDatabase)
        .await
    {
        Ok(c) => c,
        Err(cda_interfaces::storage_api::StorageError::CollectionNotFound(_)) => return None,
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

/// Seeds an absent `DiagnosticDatabase` storage collection from `database_seed_dir`.
///
/// An existing collection, including an intentionally empty one, is never changed. The collection
/// and all `.mdd` entries are committed transactionally so startup and the first rollback share the
/// same baseline.
pub async fn seed_storage_from_database_path(storage_dir: &str, database_seed_dir: &str) {
    let mdd_files = if database_seed_dir.is_empty() {
        // An explicitly empty source means an initialized empty database set, not an
        // unavailable source. Persist that distinction so later resolution cannot
        // resurrect files from a newly configured fallback path.
        Vec::new()
    } else {
        match std::fs::read_dir(database_seed_dir) {
            Ok(entries) => get_mdd_files_and_size(entries),
            Err(error) => {
                tracing::warn!(%error, seed_dir = database_seed_dir, "Cannot read database seed directory");
                return;
            }
        }
    };

    let mut entries = Vec::new();
    for (path, _) in mdd_files {
        let Some(key) = path
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_lowercase)
        else {
            continue;
        };
        match tokio::fs::File::open(&path).await {
            Ok(file) => entries.push((key, file)),
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "Failed to open MDD file for seeding, skipping");
            }
        }
    }

    let storage = match cda_storage::LocalStorage::new(storage_dir) {
        Ok(storage) => storage,
        Err(error) => {
            tracing::warn!(%error, "Storage not available, skipping seed");
            return;
        }
    };

    if let Some(count) = cda_storage::storage_seed::seed_storage_collection_if_nonexistent(
        &storage,
        &CollectionName::DiagnosticDatabase,
        entries,
    )
    .await
    {
        tracing::info!(
            count,
            seed_dir = database_seed_dir,
            storage_dir,
            "Seeded DiagnosticDatabase collection from database seed directory"
        );
    }
}

/// Seeds the `DiagnosticDatabase` storage collection from `mdd_files` when the collection
/// does not exist.
pub async fn seed_storage_if_nonexistent_from_mdd_files(storage_dir: &str, mdd_files: &[PathBuf]) {
    let mut entries = Vec::new();
    for path in mdd_files {
        let Some(key) = path
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_lowercase)
        else {
            continue;
        };
        match tokio::fs::File::open(path).await {
            Ok(file) => entries.push((key, file)),
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "Failed to open MDD file for seeding, skipping");
            }
        }
    }
    let storage = match cda_storage::LocalStorage::new(storage_dir) {
        Ok(storage) => storage,
        Err(error) => {
            tracing::warn!(%error, "Storage not available, skipping seed");
            return;
        }
    };
    let _ = cda_storage::storage_seed::seed_storage_collection_if_nonexistent(
        &storage,
        &CollectionName::DiagnosticDatabase,
        entries,
    )
    .await;
}

pub(crate) fn handle_ecu_config_keys<S: SecurityPlugin>(
    ecu_config_map: &HashMap<String, EcuConfig>,
    databases: &HashMap<String, Arc<RwLock<EcuManager<S>>>>,
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
        return Err(AppError::ConfigurationError {
            message: format!(
                "[strict] ecu_config is enabled and the following per-ECU config entries do not \
                 match any loaded database: {}",
                unmatched.join(", ")
            ),
            source: None,
        });
    }
    Ok(())
}

/// The transport target an ECU description talks to, as far as duplicate
/// detection is concerned: several ECU descriptions sharing one target are
/// candidate models of the same physical node (e.g. the radio variants of a
/// vehicle), and variant detection decides which one is actually installed.
#[derive(Hash, PartialEq, Eq)]
enum DuplicateTargetKey {
    /// Resolved `DoIP` gateway/logical address pair.
    Doip { gateway: u16, logical: u16 },
    /// CAN arbitration ID pair from the MDD com-params, for ECUs without
    /// resolved `DoIP` addressing (e.g. CAN-only databases).
    Can(cda_interfaces::CanIds),
}

/// Scans `databases` for ECUs sharing the same transport target - the
/// resolved `DoIP` gateway/logical address pair, or (for ECUs without `DoIP`
/// addressing) the CAN arbitration ID pair from the MDD com-params - and
/// marks them as duplicates of each other by calling
/// `set_duplicating_ecu_names` on each affected manager.
async fn mark_duplicate_ecus_by_address<S: SecurityPlugin>(
    databases: &HashMap<String, Arc<RwLock<EcuManager<S>>>>,
) {
    use cda_interfaces::CanComParamProvider as _;

    let mut ecus_by_target: HashMap<DuplicateTargetKey, Vec<String>> = HashMap::new();
    for (name, db_lock) in databases {
        let db = db_lock.read().await;
        let key = if db.doip_addresses_resolved() {
            DuplicateTargetKey::Doip {
                gateway: db.logical_gateway_address(),
                logical: db.logical_address(),
            }
        } else if let Some(ids) = db.can_ids() {
            DuplicateTargetKey::Can(ids)
        } else {
            // Without resolved DoIP addressing the addresses are com-param
            // fallback values shared by every such ECU (e.g. a functional
            // description), and without CAN IDs there is no other target
            // identity - no evidence of an actual collision, so grouping
            // would spuriously mark unrelated ECUs as duplicates and
            // suppress base-variant fallback for all of them.
            tracing::debug!(
                ecu_name = %name,
                "Skipping duplicate detection - neither resolved DoIP addressing nor CAN IDs"
            );
            continue;
        };
        ecus_by_target.entry(key).or_default().push(name.clone());
    }

    for ecu_names in ecus_by_target.values() {
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
    embedded_files: FileManager,
) -> Option<EcuManager<S>> {
    EcuManager::new(
        diag_database,
        protocol,
        effective_com_params,
        ctx.database_naming_convention.clone(),
        EcuManagerConfig {
            type_: ecu_type,
            fallback_to_base_variant: ctx.fallback_to_base_variant,
            strict_parameter_validation: ctx.strict_parameter_validation,
        },
        ctx.func_description_cfg,
        embedded_files,
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
    let effective_com_params = crate::config::com_params::resolve_com_params(
        &ctx.ecu_name,
        ctx.com_params,
        per_ecu_cfg.and_then(|c| c.com_params.as_ref()),
    )?;
    let protocol = per_ecu_cfg.and_then(|c| c.protocol.as_deref()).map_or_else(
        || ctx.protocol.clone(),
        |name| Protocol::new(name.to_owned()),
    );
    let ecu_type = if ctx
        .func_description_cfg
        .description_database
        .eq_ignore_ascii_case(&ctx.ecu_name)
    {
        EcuManagerType::FunctionalDescription
    } else {
        EcuManagerType::Ecu
    };
    // Extracted before the manager is built so the embedded-files handle can
    // be stored on the manager itself, rather than kept in a separate map
    // that has no way to stay in sync with it across a reload.
    let embedded_files = FileManager::new(ctx.mdd_path.clone(), extract_file_chunks(proto_data));
    let manager = create_ecu_manager(
        diag_database,
        protocol,
        ecu_type,
        &effective_com_params,
        ctx,
        embedded_files,
    )?;

    Some(EcuLoadResult { manager })
}

/// Loads a single MDD file and returns the ECU name and manager.
///
/// # Errors
///
/// Returns [`MddLoadingError`] if decompression or loading fails.
fn load_single_mdd<S: SecurityPlugin>(
    path: &Path,
    config: &Configuration,
    ecu_config_map: &HashMap<String, EcuConfig>,
    protocol: &Protocol,
) -> Result<(String, EcuManager<S>), MddLoadingError> {
    let mdd_path =
        path.to_str()
            .map(ToOwned::to_owned)
            .ok_or_else(|| MddLoadingError::LoadFailed {
                path: path.display().to_string(),
                reason: "Failed to convert path to string".to_string(),
            })?;

    // Rewrite uncompressed on first use so later loads skip LZMA. Startup and
    // runtime reload take the same path.
    if config.flat_buf.mdd_decompress
        && let Err(e) = cda_database::update_mdd_uncompressed(&mdd_path)
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
        strict_parameter_validation: config.strict.parameter_validation(),
    };

    let per_ecu_cfg = ecu_config_map.get(&ecu_name.to_lowercase());
    let result = load_ecu_from_file(proto_data, &ctx, per_ecu_cfg).ok_or_else(|| {
        MddLoadingError::LoadFailed {
            path: mdd_path.clone(),
            reason: format!("Failed to load ECU {ecu_name} from MDD"),
        }
    })?;

    Ok((ecu_name, result.manager))
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
    use std::{
        path::PathBuf,
    };

    use cda_interfaces::{
        storage_api::{Collection as _, CollectionName, DirectFileAccess, Storage},
    };
    use cda_plugin_security::mock::TestSecurityPlugin;
    use cda_storage::LocalStorage;
    use tempfile::TempDir;

    use super::*;

    /// Helper: create a temp dir with `.mdd` files containing given data.
    fn create_database_dir(files: &[(&str, &[u8])]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("create temp dir");
        for (name, data) in files {
            std::fs::write(dir.path().join(name), data).expect("write file");
        }
        dir
    }

    #[tokio::test]
    async fn seed_copies_mdd_files_into_nonexistent_storage() {
        let fixture = Fixture::new_with_mdd_files(&[
            ("ecu_a.mdd", b"MDD_CONTENT_A"),
            ("ecu_b.mdd", b"MDD_CONTENT_B"),
        ]);

        seed_storage_if_nonexistent_from_mdd_files(
            fixture.storage_dir.path().to_str().unwrap(),
            &fixture.mdd_files,
        )
        .await;

        let storage = LocalStorage::new(fixture.storage_dir.path()).unwrap();
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
        let fixture = Fixture::new_with_mdd_files(&[("new.mdd", b"NEW_DATA")]);

        // Pre-populate storage with an existing entry.
        let storage = LocalStorage::new(fixture.storage_dir.path()).unwrap();
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

        seed_storage_if_nonexistent_from_mdd_files(
            fixture.storage_dir.path().to_str().unwrap(),
            &fixture.mdd_files,
        )
        .await;

        // Verify collection was NOT modified.
        let storage = LocalStorage::new(fixture.storage_dir.path()).unwrap();
        let collection = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        let keys = collection.list().await.unwrap();
        assert_eq!(keys, vec!["existing.mdd"]);
    }

    #[tokio::test]
    async fn seed_handles_no_database_files() {
        let fixture = Fixture::new_with_mdd_files(&[]);

        seed_storage_if_nonexistent_from_mdd_files(
            fixture.storage_dir.path().to_str().unwrap(),
            &fixture.mdd_files,
        )
        .await;

        let storage = LocalStorage::new(fixture.storage_dir.path()).unwrap();
        let collection = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        assert!(collection.is_empty().await.unwrap());
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
            .get_collection(&CollectionName::DiagnosticDatabase)
            .await
            .expect("empty source must create the initialization marker");
        assert!(collection.is_empty().await.unwrap());
    }

    #[tokio::test]
    async fn seed_handles_nonexistent_database_path() {
        let storage_dir = tempfile::tempdir().expect("storage dir");

        seed_storage_from_database_path(
            storage_dir.path().to_str().unwrap(),
            "/tmp/nonexistent_cda_test_path_12345",
        )
        .await;

        let storage = LocalStorage::new(storage_dir.path()).unwrap();
        assert!(
            storage
                .get_collection(&CollectionName::DiagnosticDatabase)
                .await
                .is_err(),
            "an unavailable source must not initialize an authoritative empty collection"
        );
    }

    #[tokio::test]
    async fn seed_lowercases_mdd_filenames_as_keys() {
        let fixture = Fixture::new_with_mdd_files(&[("ECU_UPPER.mdd", b"UPPER_DATA")]);

        seed_storage_if_nonexistent_from_mdd_files(
            fixture.storage_dir.path().to_str().unwrap(),
            &fixture.mdd_files,
        )
        .await;

        let storage = LocalStorage::new(fixture.storage_dir.path()).unwrap();
        let collection = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        let keys = collection.list().await.unwrap();
        assert_eq!(keys, vec!["ecu_upper.mdd"]);
    }

    #[tokio::test]
    async fn seed_preserves_file_content_through_storage_roundtrip() {
        let original_data = b"MDD_BINARY_PAYLOAD_1234567890";
        let fixture = Fixture::new_with_mdd_files(&[("FLXC1000.mdd", original_data)]);

        seed_storage_if_nonexistent_from_mdd_files(
            fixture.storage_dir.path().to_str().unwrap(),
            &fixture.mdd_files,
        )
        .await;

        let storage = LocalStorage::new(fixture.storage_dir.path()).unwrap();
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
    async fn resolve_mdd_paths_ignores_non_mdd_files() {
        let fixture = Fixture::new_with_mdd_files(&[
            ("valid.mdd", b"MDD_DATA"),
            ("readme.txt", b"TEXT"),
            ("data.bin", b"BIN"),
        ]);

        let mdd_files = resolve_mdd_paths(
            fixture.storage_dir.path().to_str().unwrap(),
            fixture.db_dir.path().to_str().unwrap(),
        )
        .await;

        let [valid_file] = mdd_files.as_slice() else {
            panic!("Exactly one file expected.");
        };
        assert_eq!(valid_file.file_name().unwrap(), "valid.mdd");
    }

    #[tokio::test]
    async fn resolve_mdd_paths_returns_storage_paths_after_seed() {
        let fixture =
            Fixture::new_with_mdd_files(&[("FLXC1000.mdd", b"MDD_A"), ("FSNR2000.mdd", b"MDD_B")]);

        let storage_str = fixture.storage_dir.path().to_str().unwrap();
        let db_str = fixture.db_dir.path().to_str().unwrap();

        seed_storage_if_nonexistent_from_mdd_files(storage_str, &fixture.mdd_files).await;
        let paths = resolve_mdd_paths(storage_str, db_str).await;

        assert_eq!(paths.len(), 2, "Expected 2 MDD paths from storage");
        for p in &paths {
            assert!(p.exists(), "Resolved path must exist: {}", p.display());
            // Paths should come from storage, not from the original database dir.
            assert!(
                !p.starts_with(fixture.db_dir.path()),
                "Path should come from storage, not the database dir: {}",
                p.display()
            );
        }
    }

    #[tokio::test]
    async fn resolve_mdd_paths_falls_back_when_storage_is_uninitialized() {
        let fixture = Fixture::new_with_mdd_files(&[("ECU.mdd", b"DATA")]);

        // Do not seed, leaving storage uninitialized.
        let paths = resolve_mdd_paths(
            fixture.storage_dir.path().to_str().unwrap(),
            fixture.db_dir.path().to_str().unwrap(),
        )
        .await;

        let first = paths.first().expect("first should exist");
        assert_eq!(paths.len(), 1, "Expected 1 MDD path from fallback");
        assert!(first.starts_with(fixture.db_dir.path()));
    }

    #[tokio::test]
    async fn initialized_empty_storage_does_not_resurrect_database_seed_dir() {
        let storage_dir = tempfile::tempdir().expect("storage dir");
        let db_dir = create_database_dir(&[("ECU.mdd", b"DATA")]);
        let storage = LocalStorage::new(storage_dir.path()).unwrap();
        storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();

        seed_storage_from_database_path(
            storage_dir.path().to_str().unwrap(),
            db_dir.path().to_str().unwrap(),
        )
        .await;
        let paths = resolve_mdd_paths(
            storage_dir.path().to_str().unwrap(),
            db_dir.path().to_str().unwrap(),
        )
        .await;

        assert!(paths.is_empty());
    }

    #[tokio::test]
    async fn zero_configured_paths_initialize_authoritative_empty_storage() {
        let storage_dir = tempfile::tempdir().expect("storage dir");

        seed_storage_from_database_path(storage_dir.path().to_str().unwrap(), "").await;
        let paths = resolve_mdd_paths(storage_dir.path().to_str().unwrap(), "").await;

        assert!(paths.is_empty());
        let storage = LocalStorage::new(storage_dir.path()).unwrap();
        let collection = storage
            .get_collection(&CollectionName::DiagnosticDatabase)
            .await
            .expect("zero configured paths must persist an intentional empty marker");
        assert!(collection.is_empty().await.unwrap());
    }

    #[tokio::test]
    async fn fresh_seed_is_the_baseline_copied_for_rollback() {
        let storage_dir = tempfile::tempdir().expect("storage dir");
        let db_dir = create_database_dir(&[("ECU.mdd", b"ORIGINAL")]);
        seed_storage_from_database_path(
            storage_dir.path().to_str().unwrap(),
            db_dir.path().to_str().unwrap(),
        )
        .await;

        let storage = LocalStorage::new(storage_dir.path()).unwrap();
        let mut tx = storage.begin_transaction().unwrap();
        storage
            .copy_collection(
                &mut tx,
                &CollectionName::DiagnosticDatabase,
                &CollectionName::DiagnosticDatabaseBackup,
            )
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let backup = storage
            .get_collection(&CollectionName::DiagnosticDatabaseBackup)
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(backup.file_path("ecu.mdd").unwrap()).unwrap(),
            b"ORIGINAL"
        );
    }

    struct Fixture {
        mdd_files: Vec<PathBuf>,
        storage_dir: TempDir,
        db_dir: TempDir,
    }
    impl Fixture {
        fn new_with_mdd_files(mdd_files: &[(&str, &[u8])]) -> Self {
            let storage_dir = tempfile::tempdir().expect("storage dir");
            let db_dir = tempfile::tempdir().expect("DB dir");

            let mdd_files = mdd_files
                .iter()
                .map(|(name, data)| (db_dir.path().join(name), *data))
                .collect::<Vec<_>>();

            for (path, data) in &mdd_files {
                std::fs::write(path, data).expect("write MDD file");
            }

            Self {
                mdd_files: mdd_files.into_iter().map(|(path, _)| path).collect(),
                storage_dir,
                db_dir,
            }
        }
    }

    /// Step 6's decompression is a one-time rewrite: the first load rewrites the
    /// file uncompressed, and every later load — startup or runtime reload —
    /// finds nothing left to decompress.
    #[test]
    fn one_database_load_decompresses_once() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("flxc1000.mdd");
        std::fs::copy(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../testcontainer/odx/FLXC1000.mdd"
            ),
            &path,
        )
        .unwrap();
        let path_str = path.to_str().unwrap().to_owned();
        let mut config = crate::config::default_config();
        config.flat_buf.mdd_decompress = true;
        let ecu_config = std::sync::Arc::new(cda_interfaces::HashMap::default());
        let protocol = cda_interfaces::Protocol::new(config.doip.protocol_name.clone());

        assert!(
            cda_database::update_mdd_uncompressed(&path_str).unwrap(),
            "precondition: the fixture starts out compressed"
        );
        std::fs::copy(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../testcontainer/odx/FLXC1000.mdd"
            ),
            &path,
        )
        .unwrap();

        load_single_mdd::<TestSecurityPlugin>(&path, &config, &ecu_config, &protocol).unwrap();

        assert!(
            !cda_database::update_mdd_uncompressed(&path_str).unwrap(),
            "the load must leave nothing for a later load to decompress"
        );
    }
}
