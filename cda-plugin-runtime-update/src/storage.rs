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
    fmt::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

use cda_database::storage::{DatabaseLocation, current_database_location, database_name};
use cda_interfaces::{
    runtime_update_api::{
        BulkDataCreated, BulkDataCreatedList, BulkDataDescriptor, BulkDataList, HashAlgorithm,
        LockStateProvider, RuntimeFilesQuery, RuntimeUpdateError, RuntimeUpdateSecurityPlugin,
        UploadFile,
    },
    storage_api::{
        Collection, CollectionName, DirectFileAccess, RandomAccessData, Storage, StorageError,
        Transaction,
    },
};
use sha2::{Digest, Sha256};

/// Lazily initializes `destination` from `source` the first time a file targets that collection.
/// No-op if the destination already existed or was already initialized in this transaction.
pub(crate) async fn init_collection_from_copy_if_missing(
    storage: &(impl Storage + 'static),
    tx: &mut Transaction,
    already_exists: bool,
    initialized: &mut bool,
    source: &CollectionName,
    destination: &CollectionName,
) -> Result<(), RuntimeUpdateError> {
    if already_exists || *initialized {
        return Ok(());
    }
    match storage.copy_collection(tx, source, destination).await {
        Ok(()) | Err(StorageError::CollectionNotFound(_)) => {
            // No current collection to init from - skip.
        }
        Err(e) => return Err(e.into()),
    }
    *initialized = true;
    Ok(())
}

pub(crate) fn compute_sha256(data: &impl RandomAccessData) -> Result<String, RuntimeUpdateError> {
    let total = data.data_size().map_err(RuntimeUpdateError::from)?;
    let mut hasher = Sha256::new();
    let mut offset = 0u64;
    let mut buf = vec![0u8; 64 * 1024];

    while offset < total {
        let read = data
            .read_at(offset, &mut buf)
            .map_err(RuntimeUpdateError::from)?;
        if read == 0 {
            break;
        }

        hasher.update(buf.get(..read).unwrap_or(&buf));
        offset = offset.saturating_add(read as u64);
    }

    Ok(to_hex(&hasher.finalize()))
}

fn to_hex(digest: &[u8]) -> String {
    let mut out = String::with_capacity(digest.len().saturating_mul(2));
    for byte in digest {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

/// A descriptor of the database `key`, without the optional metadata.
fn new_descriptor(key: &str) -> BulkDataDescriptor {
    BulkDataDescriptor {
        id: key.to_owned(),
        mimetype: "application/octet-stream".to_owned(),
        name: Some(key.to_owned()),
        size: None,
        hash: None,
        hash_algorithm: None,
        origin_path: None,
        revision: None,
    }
}

/// The revision recorded in the MDD file of `key` at `path`, if it has one.
fn mdd_revision(key: &str, path: &Path) -> Result<Option<String>, RuntimeUpdateError> {
    let path_str = path.to_str().ok_or_else(|| {
        RuntimeUpdateError::StorageError(StorageError::Other(format!(
            "file path for key '{key}' is not valid UTF-8"
        )))
    })?;
    Ok(cda_database::mmap_and_decode_mdd(path_str)
        .ok()
        .and_then(|mdd| mdd.revision))
}

/// Lists all files in a collection, optionally enriching each item with size and hash metadata.
pub(crate) async fn list_collection_files(
    collection: &(impl Collection + DirectFileAccess),
    query: &RuntimeFilesQuery,
) -> Result<BulkDataList, RuntimeUpdateError> {
    let keys = collection.list().await?;
    let mut items = Vec::with_capacity(keys.len());

    for key in &keys {
        let mut item = new_descriptor(key);

        if query.include_file_size {
            match collection.metadata(key).await {
                Ok(meta) => item.size = Some(meta.data_size),
                Err(StorageError::KeyNotFound(_)) => {
                    tracing::warn!(key = %key, "key vanished during iteration, skipping");
                    continue;
                }
                Err(e) => {
                    tracing::warn!(key = %key, error = %e, "failed to read metadata, skipping");
                    continue;
                }
            }
        }

        if let Some(hash) = query.include_hash {
            let data = collection.read(key).await?;
            match hash {
                HashAlgorithm::Sha256 => {
                    let hash = compute_sha256(&*data)?;
                    item.hash = Some(hash);
                    item.hash_algorithm = Some(HashAlgorithm::Sha256);
                }
            }
        }

        if query.include_revision {
            item.revision = mdd_revision(key, &collection.file_path(key)?)?;
        }

        items.push(item);
    }

    Ok(BulkDataList {
        items,
        schema: None,
    })
}

/// Describes the MDD files at `paths` in `database.dir` like [`list_collection_files`]
/// describes a collection, keyed like the seed keys them.
async fn describe_database_dir_files(
    paths: &[PathBuf],
    query: &RuntimeFilesQuery,
) -> Result<Vec<BulkDataDescriptor>, RuntimeUpdateError> {
    let mut items = Vec::with_capacity(paths.len());
    for path in paths {
        let key = database_name(path)?;
        let mut item = new_descriptor(&key);

        if query.include_file_size {
            match tokio::fs::metadata(path).await {
                Ok(meta) => item.size = Some(meta.len()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    tracing::warn!(path = %path.display(), "File vanished during iteration, skipping");
                    continue;
                }
                Err(e) => return Err(StorageError::from(e).into()),
            }
        }

        if let Some(hash) = query.include_hash {
            match hash {
                HashAlgorithm::Sha256 => {
                    let data = match tokio::fs::read(path).await {
                        Ok(data) => data,
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                            tracing::warn!(path = %path.display(), "File vanished during iteration, skipping");
                            continue;
                        }
                        Err(e) => return Err(StorageError::from(e).into()),
                    };
                    item.hash = Some(to_hex(&Sha256::digest(&data)));
                    item.hash_algorithm = Some(HashAlgorithm::Sha256);
                }
            }
        }

        if query.include_revision {
            item.revision = mdd_revision(&key, path)?;
        }

        items.push(item);
    }

    Ok(items)
}

/// Returns the current databases, see [`current_database_location`].
async fn get_current_items(
    storage: &impl Storage,
    database_dir: &Path,
    query: &RuntimeFilesQuery,
) -> Result<Vec<BulkDataDescriptor>, RuntimeUpdateError> {
    match current_database_location(storage, database_dir).await? {
        DatabaseLocation::Storage(collection) => {
            Ok(list_collection_files(&*collection, query).await?.items)
        }
        DatabaseLocation::Dir(paths) => describe_database_dir_files(&paths, query).await,
    }
}

/// Lists the current databases, see [`get_current_items`]. This is a read-only operation.
pub(crate) async fn list_current_files(
    storage: &impl Storage,
    database_dir: &Path,
    query: &RuntimeFilesQuery,
) -> Result<BulkDataList, RuntimeUpdateError> {
    let items = get_current_items(storage, database_dir, query).await?;
    Ok(BulkDataList {
        items,
        schema: None,
    })
}

pub(crate) async fn list_backup_files(
    storage: &impl Storage,
    query: &RuntimeFilesQuery,
) -> Result<BulkDataList, RuntimeUpdateError> {
    let items =
        get_collection_items(storage, &CollectionName::DiagnosticDatabaseBackup, query).await?;
    Ok(BulkDataList {
        items,
        schema: None,
    })
}

/// Remove a file from the next-update snapshot for the relevant collection.
///
/// If the `NextUpdate` collection isn't initialized yet (i.e. no file has been uploaded for that
/// category), it is lazily initialized from the corresponding current collection first, so that
/// files which are only part of `runtimefiles-current` can still be deleted from the pending
/// next-update state.
///
/// On a fresh system, `DiagnosticDatabase` is seeded from `database_dir` first, see
/// [`seed_if_nonexistent`](cda_database::storage::seed_if_nonexistent).
///
/// Returns [`RuntimeUpdateError::FileNotFound`] if the key does not exist in the `NextUpdate`
/// collection (nor, when freshly initialized, in the current collection).
pub(crate) async fn delete_nextupdate_file(
    storage: &(impl Storage + 'static),
    database_dir: &Path,
    file_id: &str,
) -> Result<(), RuntimeUpdateError> {
    let key = file_id.to_lowercase();

    let ext = std::path::Path::new(&key)
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_lowercase);

    let (next_collection_name, current_collection_name) = match ext.as_deref() {
        Some("mdd") => (
            CollectionName::DiagnosticDatabaseNextUpdate,
            CollectionName::DiagnosticDatabase,
        ),
        _ => return Err(RuntimeUpdateError::InvalidFileType(file_id.to_string())),
    };

    cda_database::storage::seed_if_nonexistent(storage, database_dir).await?;

    let next_already_exists = match storage.get_collection(&next_collection_name).await {
        Ok(_) => true,
        Err(StorageError::CollectionNotFound(_)) => false,
        Err(e) => return Err(RuntimeUpdateError::from(e)),
    };

    if !next_already_exists {
        let mut tx = storage.begin_transaction()?;
        let mut initialized = false;
        init_collection_from_copy_if_missing(
            storage,
            &mut tx,
            next_already_exists,
            &mut initialized,
            &current_collection_name,
            &next_collection_name,
        )
        .await?;
        tx.commit().await?;
    }

    let next_col = storage
        .get_or_create_collection(&next_collection_name)
        .await?;

    let next_keys = next_col.list().await?;
    if !next_keys.iter().any(|k| k == &key) {
        return Err(RuntimeUpdateError::FileNotFound(file_id.to_string()));
    }
    let mut tx = storage.begin_transaction()?;
    next_col.delete(&mut tx, &key).await?;
    tx.commit().await?;

    Ok(())
}

pub(crate) async fn delete_all_nextupdate(
    storage: &impl Storage,
) -> Result<Vec<String>, RuntimeUpdateError> {
    let mut deleted_ids = Vec::new();
    for collection_name in [CollectionName::DiagnosticDatabaseNextUpdate] {
        match storage.get_collection(&collection_name).await {
            Ok(collection) => deleted_ids.extend(collection.list().await?),
            Err(StorageError::CollectionNotFound(_)) => {}
            Err(e) => return Err(RuntimeUpdateError::from(e)),
        }
    }
    let mut tx = storage.begin_transaction()?;

    match storage
        .delete_collection(&mut tx, &CollectionName::DiagnosticDatabaseNextUpdate)
        .await
    {
        Ok(()) | Err(StorageError::CollectionNotFound(_)) => {}
        Err(e) => return Err(RuntimeUpdateError::from(e)),
    }

    tx.commit().await?;
    Ok(deleted_ids)
}

/// Returns whether an authoritative backup snapshot exists.
///
/// Used as a pre-condition check before starting a Rollback execution.
pub(crate) async fn backup_snapshot_exists(
    storage: &impl Storage,
) -> Result<bool, RuntimeUpdateError> {
    match storage
        .get_collection(&CollectionName::DiagnosticDatabaseBackup)
        .await
    {
        Ok(_) => Ok(true),
        Err(StorageError::CollectionNotFound(_)) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub(crate) async fn delete_all_backup(
    storage: &impl Storage,
) -> Result<Vec<String>, RuntimeUpdateError> {
    let deleted_ids = match storage
        .get_collection(&CollectionName::DiagnosticDatabaseBackup)
        .await
    {
        Ok(backup) => backup.list().await?,
        Err(StorageError::CollectionNotFound(_)) => Vec::new(),
        Err(error) => return Err(error.into()),
    };
    let mut tx = storage.begin_transaction()?;
    crate::operations::delete_collection_ignore_missing(
        storage,
        &mut tx,
        &CollectionName::DiagnosticDatabaseBackup,
    )
    .await?;
    tx.commit().await?;
    Ok(deleted_ids)
}

/// Computes the MDD "next update" state, falling back to the currently active database when no
/// update is pending yet.
///
/// The logic is:
/// - If the `NextUpdate` collection **exists** (even if empty), its contents represent the target
///   state - an empty `NextUpdate` means "delete all".
/// - If the `NextUpdate` collection **does not exist** (`CollectionNotFound`), the current
///   databases are returned instead: the `DiagnosticDatabase` collection, or the files in
///   `database_dir` while the storage has not been seeded yet.
///
/// This is a **read-only** operation - no writes or transactions are performed.
///
/// # Errors
///
/// Returns [`RuntimeUpdateError`] if storage operations fail when reading collections.
pub async fn compute_nextupdate_state(
    storage: &impl Storage,
    database_dir: &Path,
    query: &RuntimeFilesQuery,
) -> Result<BulkDataList, RuntimeUpdateError> {
    let mut items = match storage
        .get_collection(&CollectionName::DiagnosticDatabaseNextUpdate)
        .await
    {
        Ok(collection) => list_collection_files(&*collection, query).await?.items,
        // No update staged yet: the next update mirrors the current databases.
        Err(StorageError::CollectionNotFound(_)) => {
            get_current_items(storage, database_dir, query).await?
        }
        Err(e) => return Err(RuntimeUpdateError::from(e)),
    };
    items.sort_by(|a, b| a.id.cmp(&b.id));

    Ok(BulkDataList {
        items,
        schema: None,
    })
}

/// Upload MDD files into `DiagnosticDatabaseNextUpdate`.
///
/// The collection is lazily initialized from the current database on first write. On a fresh
/// system, the current database is seeded from `database_dir` first, see
/// [`seed_if_nonexistent`](cda_database::storage::seed_if_nonexistent). All other file types, including TOML
/// configuration files, are rejected.
///
/// Each file is written and committed individually. Immediately after each commit, the file's
/// integrity is verified via `security_handler`. If verification fails, the failing file is
/// deleted (best-effort) and the error is returned; previously accepted files are kept.
pub(crate) async fn upload_files<
    S: Storage + 'static,
    T: RuntimeUpdateSecurityPlugin<L, S::CollectionHandle>,
    L: LockStateProvider,
>(
    storage: &S,
    security_handler: &T,
    database_dir: &Path,
    files: Vec<UploadFile>,
) -> Result<BulkDataCreatedList, RuntimeUpdateError> {
    let mut result = BulkDataCreatedList::default();
    if files.is_empty() {
        return Ok(result);
    }

    if let Some(file) = files.iter().find(|file| {
        std::path::Path::new(&file.filename)
            .extension()
            .and_then(|extension| extension.to_str())
            .is_none_or(|extension| !extension.eq_ignore_ascii_case("mdd"))
    }) {
        return Err(RuntimeUpdateError::InvalidFileType(file.filename.clone()));
    }

    cda_database::storage::seed_if_nonexistent(storage, database_dir).await?;

    // Check existence BEFORE begin_transaction (disk reads).
    let mdd_already_exists = storage
        .get_collection(&CollectionName::DiagnosticDatabaseNextUpdate)
        .await
        .is_ok();
    // Ensure directories exist on disk (must be before begin_transaction).
    let mdd_collection = storage
        .get_or_create_collection(&CollectionName::DiagnosticDatabaseNextUpdate)
        .await?;

    let mut mdd_initialized = false;

    for file in files {
        let ext = std::path::Path::new(&file.filename)
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_lowercase);

        let key = file.filename.to_lowercase();

        match ext.as_deref() {
            Some("mdd") => {
                let mut tx = storage.begin_transaction()?;
                init_collection_from_copy_if_missing(
                    storage,
                    &mut tx,
                    mdd_already_exists,
                    &mut mdd_initialized,
                    &CollectionName::DiagnosticDatabase,
                    &CollectionName::DiagnosticDatabaseNextUpdate,
                )
                .await?;

                let mut stream: &[u8] = &file.data;
                mdd_collection.write(&mut tx, &key, &mut stream).await?;
                tx.commit().await?;

                check_file_integrity_and_roll_back_on_error(
                    storage,
                    security_handler,
                    &mdd_collection,
                    &key,
                )
                .await?;

                result.items.push(BulkDataCreated { id: key });
            }
            _ => return Err(RuntimeUpdateError::InvalidFileType(file.filename.clone())),
        }
    }

    Ok(result)
}

async fn check_file_integrity_and_roll_back_on_error<
    S: Storage + 'static,
    T: RuntimeUpdateSecurityPlugin<L, S::CollectionHandle>,
    L: LockStateProvider,
>(
    storage: &S,
    security_handler: &T,
    collection: &Arc<impl Collection + DirectFileAccess>,
    key: &String,
) -> Result<(), RuntimeUpdateError> {
    if let Err(verification_error) = security_handler
        .check_file_integrity(&collection.file_path(key)?)
        .await
    {
        tracing::warn!(
            key = %key,
            error = %verification_error,
            "File failed integrity check, attempting rollback");

        let rollback_result: Result<(), RuntimeUpdateError> = async {
            let mut tx = storage.begin_transaction()?;
            collection.delete(&mut tx, key).await?;
            tx.commit().await?;
            Ok(())
        }
        .await;

        return match rollback_result {
            Ok(()) => Err(RuntimeUpdateError::ValidationFailed(format!(
                "File failed integrity check and was rolled back: {verification_error}"
            ))),
            Err(rollback_error) => {
                tracing::error!(
                    "Failed to roll back file: {}, running cleanup on the entire transaction",
                    rollback_error
                );

                let cleanup_result = crate::operations::cleanup::execute_cleanup(storage).await;
                Err(match cleanup_result {
                    Err(cleanup_error) => RuntimeUpdateError::FatalError(format!(
                        "Verification failed due to {verification_error}, rollback single file \
                         failed due to {rollback_error}, unable to cleanup update state due to \
                         {cleanup_error}. Application is now in a dangerous update state."
                    )),
                    Ok(()) => RuntimeUpdateError::SevereError(format!(
                        "Verification failed due to {verification_error}, rollback single file \
                         failed due to {rollback_error}, update state was cleaned up, state is \
                         safe but update has to be started from scratch."
                    )),
                })
            }
        };
    }

    Ok(())
}

async fn get_collection_items(
    storage: &impl Storage,
    name: &CollectionName,
    query: &RuntimeFilesQuery,
) -> Result<Vec<BulkDataDescriptor>, RuntimeUpdateError> {
    match storage.get_collection(name).await {
        Ok(collection) => {
            let list = list_collection_files(&*collection, query).await?;
            Ok(list.items)
        }
        Err(StorageError::CollectionNotFound(_)) => Ok(vec![]),
        Err(e) => Err(RuntimeUpdateError::from(e)),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use cda_interfaces::{
        runtime_update_api::{
            BulkDataCreatedList, HashAlgorithm, RuntimeFilesQuery, RuntimeUpdateError, UploadFile,
        },
        storage_api::{
            Collection, CollectionName, DirectFileAccess, RandomAccessData, Storage, StorageError,
        },
    };
    use cda_storage::LocalStorage;
    use sha2::{Digest, Sha256};

    use super::{compute_nextupdate_state, compute_sha256, list_collection_files, upload_files};
    use crate::test_utils::{
        MockLockProvider, MockSecurityHandler, empty_database_dir, make_storage, make_upload_files,
        make_valid_mdd, make_valid_mdd_with_revision, write_file,
    };

    async fn upload<S: cda_interfaces::storage_api::Storage + 'static>(
        storage: &S,
        files: Vec<UploadFile>,
    ) -> Result<BulkDataCreatedList, RuntimeUpdateError> {
        upload_files::<S, MockSecurityHandler, MockLockProvider>(
            storage,
            &MockSecurityHandler::new(),
            empty_database_dir(),
            files,
        )
        .await
    }

    enum RejectKind {
        Mdd,
    }

    struct RejectingSecurityHandler {
        reject_type: RejectKind,
    }

    #[async_trait::async_trait]
    impl<
        L: cda_interfaces::runtime_update_api::LockStateProvider,
        C: cda_interfaces::storage_api::Collection
            + cda_interfaces::storage_api::DirectFileAccess
            + Send
            + Sync
            + 'static,
    > cda_interfaces::runtime_update_api::RuntimeUpdateSecurityPlugin<L, C>
        for RejectingSecurityHandler
    {
        async fn check_execution_allowed(
            &self,
            _lock_state_provider: &L,
            _collections: &cda_interfaces::runtime_update_api::UpdateCollections<C>,
        ) -> Result<(), cda_interfaces::runtime_update_api::RuntimeUpdateError> {
            Ok(())
        }

        async fn check_file_integrity(
            &self,
            _path: &std::path::Path,
        ) -> Result<(), cda_interfaces::runtime_update_api::VerificationError> {
            let rejected = matches!(self.reject_type, RejectKind::Mdd);
            if rejected {
                return Err(cda_interfaces::runtime_update_api::VerificationError(
                    "rejected".to_string(),
                ));
            }
            Ok(())
        }
    }

    async fn upload_rejecting<S: cda_interfaces::storage_api::Storage + 'static>(
        storage: &S,
        files: Vec<cda_interfaces::runtime_update_api::UploadFile>,
        reject_kind: RejectKind,
    ) -> Result<BulkDataCreatedList, RuntimeUpdateError> {
        upload_files::<S, RejectingSecurityHandler, MockLockProvider>(
            storage,
            &RejectingSecurityHandler {
                reject_type: reject_kind,
            },
            empty_database_dir(),
            files,
        )
        .await
    }

    struct RejectingByNameSecurityHandler {
        reject_filename: &'static str,
    }

    #[async_trait::async_trait]
    impl<
        L: cda_interfaces::runtime_update_api::LockStateProvider,
        C: cda_interfaces::storage_api::Collection
            + cda_interfaces::storage_api::DirectFileAccess
            + Send
            + Sync
            + 'static,
    > cda_interfaces::runtime_update_api::RuntimeUpdateSecurityPlugin<L, C>
        for RejectingByNameSecurityHandler
    {
        async fn check_execution_allowed(
            &self,
            _lock_state_provider: &L,
            _collections: &cda_interfaces::runtime_update_api::UpdateCollections<C>,
        ) -> Result<(), cda_interfaces::runtime_update_api::RuntimeUpdateError> {
            Ok(())
        }

        async fn check_file_integrity(
            &self,
            path: &std::path::Path,
        ) -> Result<(), cda_interfaces::runtime_update_api::VerificationError> {
            if path.file_name().and_then(|n| n.to_str()) == Some(self.reject_filename) {
                return Err(cda_interfaces::runtime_update_api::VerificationError(
                    "rejected by name".to_string(),
                ));
            }
            Ok(())
        }
    }

    async fn upload_rejecting_by_name<S: cda_interfaces::storage_api::Storage + 'static>(
        storage: &S,
        files: Vec<cda_interfaces::runtime_update_api::UploadFile>,
        reject_filename: &'static str,
    ) -> Result<BulkDataCreatedList, RuntimeUpdateError> {
        upload_files::<S, RejectingByNameSecurityHandler, MockLockProvider>(
            storage,
            &RejectingByNameSecurityHandler { reject_filename },
            empty_database_dir(),
            files,
        )
        .await
    }

    async fn copy_collection(
        storage: &impl Storage,
        source: &CollectionName,
        dest: &CollectionName,
    ) -> Result<(), RuntimeUpdateError> {
        let mut tx = storage.begin_transaction()?;
        storage.copy_collection(&mut tx, source, dest).await?;
        tx.commit().await?;
        Ok(())
    }

    struct MockData {
        data: Vec<u8>,
        reads: Mutex<Vec<usize>>,
    }

    impl MockData {
        fn new(data: Vec<u8>) -> Self {
            Self {
                data,
                reads: Mutex::new(Vec::new()),
            }
        }

        fn read_sizes(&self) -> Vec<usize> {
            self.reads.lock().unwrap().clone()
        }
    }

    impl RandomAccessData for MockData {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, StorageError> {
            self.reads.lock().unwrap().push(buf.len());

            // test-only: data fits in memory
            let start = usize::try_from(offset).expect("offset fits usize");
            if start >= self.data.len() {
                return Ok(0);
            }

            let end = start.saturating_add(buf.len()).min(self.data.len());
            let n = end.saturating_sub(start);
            let Some(dst) = buf.get_mut(..n) else {
                return Ok(0);
            };
            let Some(src) = self.data.get(start..end) else {
                return Ok(0);
            };
            dst.copy_from_slice(src);
            Ok(n)
        }

        fn data_size(&self) -> Result<u64, StorageError> {
            Ok(self.data.len() as u64)
        }
    }

    #[test]
    fn computes_known_hash() {
        let data = MockData::new(b"hello world".to_vec());

        let hash = compute_sha256(&data).unwrap();

        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn computes_empty_hash() {
        let data = MockData::new(Vec::new());

        let hash = compute_sha256(&data).unwrap();

        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn reads_in_chunks_no_larger_than_64k() {
        let data = MockData::new(vec![0xAB; 70 * 1024]);

        let _ = compute_sha256(&data).unwrap();

        assert!(data.read_sizes().iter().all(|&size| size <= 64 * 1024));
        assert!(data.read_sizes().len() >= 2);
    }

    async fn write_test_file_to_collection(
        storage: &LocalStorage,
        collection: &impl Collection,
        key: &str,
        data: &[u8],
    ) {
        let mut tx = storage.begin_transaction().unwrap();
        let mut cursor: &[u8] = data;
        collection.write(&mut tx, key, &mut cursor).await.unwrap();
        tx.commit().await.unwrap();
    }

    #[tokio::test]
    async fn empty_collection_returns_empty_items() {
        let (storage, _dir) = make_storage();
        let collection = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();

        let query = RuntimeFilesQuery::default();
        let result = list_collection_files(&*collection, &query).await.unwrap();

        assert!(result.items.is_empty());
    }

    #[tokio::test]
    async fn two_files_returns_two_items_with_correct_ids() {
        let (storage, _dir) = make_storage();
        let collection = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();

        write_test_file_to_collection(&storage, &*collection, "alpha.mdd", b"alpha content").await;
        write_test_file_to_collection(&storage, &*collection, "beta.mdd", b"beta content").await;

        let query = RuntimeFilesQuery::default();
        let result = list_collection_files(&*collection, &query).await.unwrap();

        assert_eq!(result.items.len(), 2);
        let mut ids: Vec<&str> = result.items.iter().map(|i| i.id.as_str()).collect();
        ids.sort_unstable();
        assert_eq!(ids, vec!["alpha.mdd", "beta.mdd"]);
    }

    #[tokio::test]
    async fn include_file_size_returns_correct_byte_count() {
        let (storage, _dir) = make_storage();
        let collection = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();

        let data = b"exactly 20 bytes!!!!";
        assert_eq!(data.len(), 20);
        write_test_file_to_collection(&storage, &*collection, "sized.mdd", data).await;

        let query = RuntimeFilesQuery {
            include_file_size: true,
            ..Default::default()
        };
        let result = list_collection_files(&*collection, &query).await.unwrap();

        assert_eq!(result.items.len(), 1);
        let item = result.items.first().unwrap();
        assert_eq!(item.id, "sized.mdd");
        assert_eq!(item.size, Some(20));
    }

    #[tokio::test]
    async fn include_hash_sha256_returns_correct_hash() {
        let (storage, _dir) = make_storage();
        let collection = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();

        write_test_file_to_collection(&storage, &*collection, "hashed.mdd", b"hello world").await;

        let query = RuntimeFilesQuery {
            include_hash: Some(HashAlgorithm::Sha256),
            ..Default::default()
        };
        let result = list_collection_files(&*collection, &query).await.unwrap();

        assert_eq!(result.items.len(), 1);
        let item = result.items.first().unwrap();
        assert_eq!(item.hash_algorithm, Some(HashAlgorithm::Sha256));
        assert_eq!(
            item.hash.as_deref(),
            Some("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
        );
    }

    #[tokio::test]
    async fn no_flags_returns_items_with_only_id() {
        let (storage, _dir) = make_storage();
        let collection = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();

        write_test_file_to_collection(&storage, &*collection, "plain.mdd", b"some data").await;

        let query = RuntimeFilesQuery::default();
        let result = list_collection_files(&*collection, &query).await.unwrap();

        assert_eq!(result.items.len(), 1);
        let item = result.items.first().unwrap();
        assert_eq!(item.id, "plain.mdd");
        assert!(item.hash.is_none());
        assert!(item.hash_algorithm.is_none());
        assert!(item.size.is_none());
        assert!(item.revision.is_none());

        let json = serde_json::to_string(&item).unwrap();
        assert_eq!(
            json,
            r#"{"id":"plain.mdd","mimetype":"application/octet-stream","name":"plain.mdd"}"#
        );
    }

    #[tokio::test]
    async fn all_flags_returns_complete_item() {
        let (storage, _dir) = make_storage();
        let collection = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();

        let mdd = make_valid_mdd_with_revision("FullECU", "v1.2.3");
        write_test_file_to_collection(&storage, &*collection, "full.mdd", &mdd).await;

        let query = RuntimeFilesQuery {
            include_schema: false,
            include_hash: Some(HashAlgorithm::Sha256),
            include_file_size: true,
            include_revision: true,
            created_after: None,
            created_before: None,
        };
        let result = list_collection_files(&*collection, &query).await.unwrap();

        assert_eq!(result.items.len(), 1);
        let item = result.items.first().unwrap();
        assert_eq!(item.id, "full.mdd");
        assert!(item.hash.is_some());
        assert_eq!(item.hash_algorithm, Some(HashAlgorithm::Sha256));
        assert_eq!(item.size, Some(mdd.len() as u64));
        assert_eq!(item.revision, Some("v1.2.3".to_owned()));
    }

    #[tokio::test]
    async fn include_revision_returns_revision_for_mdd() {
        let (storage, _dir) = make_storage();
        let collection = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();

        let mdd = make_valid_mdd_with_revision("RevECU", "rev-42");
        write_test_file_to_collection(&storage, &*collection, "rev.mdd", &mdd).await;

        let query = RuntimeFilesQuery {
            include_revision: true,
            ..RuntimeFilesQuery::default()
        };
        let result = list_collection_files(&*collection, &query).await.unwrap();

        let item = result.items.first().unwrap();
        assert_eq!(item.revision, Some("rev-42".to_owned()));
    }

    #[tokio::test]
    async fn include_revision_is_none_for_mdd_without_revision_field() {
        let (storage, _dir) = make_storage();
        let collection = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();

        let mdd = make_valid_mdd("NoRevECU");
        write_test_file_to_collection(&storage, &*collection, "norev.mdd", &mdd).await;

        let query = RuntimeFilesQuery {
            include_revision: true,
            ..RuntimeFilesQuery::default()
        };
        let result = list_collection_files(&*collection, &query).await.unwrap();

        let item = result.items.first().unwrap();
        assert!(item.revision.is_none());
    }

    #[tokio::test]
    async fn write_file_stores_data_readable_after_commit() {
        let (storage, _dir) = make_storage();
        let name = CollectionName::DiagnosticDatabase;

        storage.get_or_create_collection(&name).await.unwrap();
        let mut data: &[u8] = b"hello storage";
        let mut tx = storage.begin_transaction().unwrap();
        write_file(&storage, &mut tx, &name, "test.mdd", &mut data)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let collection = storage.get_or_create_collection(&name).await.unwrap();
        let handle = collection.read("test.mdd").await.unwrap();
        let mut buf = vec![0u8; 13];
        let n = handle.read_at(0, &mut buf).unwrap();
        assert_eq!(n, 13);
        assert_eq!(&buf, b"hello storage");
    }

    #[tokio::test]
    async fn write_file_normalizes_key_to_lowercase() {
        let (storage, _dir) = make_storage();
        let name = CollectionName::DiagnosticDatabase;

        storage.get_or_create_collection(&name).await.unwrap();
        let mut data: &[u8] = b"ecu data";
        let mut tx = storage.begin_transaction().unwrap();
        write_file(&storage, &mut tx, &name, "ECU1.MDD", &mut data)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let collection = storage.get_or_create_collection(&name).await.unwrap();
        let handle = collection.read("ecu1.mdd").await.unwrap();
        assert_eq!(handle.data_size().unwrap(), 8);
    }

    #[tokio::test]
    async fn copy_collection_copies_all_files() {
        let (storage, _dir) = make_storage();
        let source = CollectionName::DiagnosticDatabase;
        let dest = CollectionName::DiagnosticDatabaseBackup;

        storage.get_or_create_collection(&source).await.unwrap();
        let mut d1: &[u8] = b"file_one";
        let mut tx = storage.begin_transaction().unwrap();
        write_file(&storage, &mut tx, &source, "one", &mut d1)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let mut d2: &[u8] = b"file_two";
        let mut tx = storage.begin_transaction().unwrap();
        write_file(&storage, &mut tx, &source, "two", &mut d2)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        copy_collection(&storage, &source, &dest).await.unwrap();

        let dest_col = storage.get_collection(&dest).await.unwrap();
        let handle = dest_col.read("one").await.unwrap();
        let mut buf = vec![0u8; 8];
        handle.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf, b"file_one");

        let handle = dest_col.read("two").await.unwrap();
        let mut buf = vec![0u8; 8];
        handle.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf, b"file_two");
    }

    async fn write_test_file_by_name(
        storage: &LocalStorage,
        collection: &impl Collection,
        key: &str,
        data: &[u8],
    ) {
        let mut tx = storage.begin_transaction().unwrap();
        let mut cursor: &[u8] = data;
        collection.write(&mut tx, key, &mut cursor).await.unwrap();
        tx.commit().await.unwrap();
    }

    #[tokio::test]
    async fn empty_nextupdate_and_empty_current_returns_empty() {
        let (storage, _dir) = make_storage();
        let query = RuntimeFilesQuery::default();

        let result = compute_nextupdate_state(&storage, empty_database_dir(), &query)
            .await
            .unwrap();

        assert!(result.items.is_empty());
    }

    #[tokio::test]
    async fn two_files_in_current_no_nextupdate_mirrors_current() {
        let (storage, _dir) = make_storage();
        let collection = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();

        write_test_file_by_name(&storage, &*collection, "alpha.mdd", b"alpha content").await;
        write_test_file_by_name(&storage, &*collection, "beta.mdd", b"beta content").await;

        let query = RuntimeFilesQuery::default();
        let result = compute_nextupdate_state(&storage, empty_database_dir(), &query)
            .await
            .unwrap();

        let mut ids: Vec<_> = result.items.iter().map(|i| i.id.clone()).collect();
        ids.sort();
        assert_eq!(
            ids,
            vec!["alpha.mdd".to_string(), "beta.mdd".to_string()],
            "no NextUpdate collection = no pending changes = mirrors current"
        );
    }

    #[tokio::test]
    async fn replacement_in_nextupdate_overwrites_current_item() {
        let (storage, _dir) = make_storage();

        let current = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        write_test_file_by_name(&storage, &*current, "alpha.mdd", b"old alpha").await;
        write_test_file_by_name(&storage, &*current, "beta.mdd", b"beta content").await;

        let pending = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabaseNextUpdate)
            .await
            .unwrap();
        write_test_file_by_name(&storage, &*pending, "alpha.mdd", b"new alpha").await;

        let query = RuntimeFilesQuery {
            include_file_size: true,
            ..Default::default()
        };
        let result = compute_nextupdate_state(&storage, empty_database_dir(), &query)
            .await
            .unwrap();

        // NextUpdate exists -> only NextUpdate content is shown (snapshot model)
        assert_eq!(result.items.len(), 1);
        let alpha = result.items.iter().find(|i| i.id == "alpha.mdd").unwrap();
        assert_eq!(alpha.size, Some(9));
    }

    #[tokio::test]
    async fn new_file_in_nextupdate_adds_to_result() {
        let (storage, _dir) = make_storage();

        let current = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        write_test_file_by_name(&storage, &*current, "existing.mdd", b"existing data").await;

        let pending = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabaseNextUpdate)
            .await
            .unwrap();
        write_test_file_by_name(&storage, &*pending, "new_file.mdd", b"brand new").await;

        let query = RuntimeFilesQuery::default();
        let result = compute_nextupdate_state(&storage, empty_database_dir(), &query)
            .await
            .unwrap();

        // NextUpdate exists -> only NextUpdate content is shown (snapshot model)
        assert_eq!(result.items.len(), 1);
        let Some(item) = result.items.first() else {
            panic!("expected item")
        };
        assert_eq!(item.id, "new_file.mdd");
    }

    #[tokio::test]
    async fn pending_overwrite_verified_by_hash() {
        let (storage, _dir) = make_storage();

        let current = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        write_test_file_by_name(&storage, &*current, "file.mdd", b"original content").await;

        let pending = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabaseNextUpdate)
            .await
            .unwrap();
        write_test_file_by_name(&storage, &*pending, "file.mdd", b"updated content").await;

        let query = RuntimeFilesQuery {
            include_hash: Some(HashAlgorithm::Sha256),
            ..Default::default()
        };
        let result = compute_nextupdate_state(&storage, empty_database_dir(), &query)
            .await
            .unwrap();

        assert_eq!(result.items.len(), 1);
        let Some(item) = result.items.first() else {
            panic!("expected item")
        };
        assert_eq!(item.id, "file.mdd");
        let expected_hash = format!("{:x}", Sha256::digest(b"updated content"));
        assert_eq!(item.hash.as_deref(), Some(expected_hash.as_str()));
    }

    #[tokio::test]
    async fn compute_nextupdate_empty_mdd_nextupdate_shows_empty_mdd() {
        let (storage, _dir) = make_storage();
        let db = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        write_test_file_by_name(&storage, &*db, "ecu1.mdd", b"data").await;
        // Initialize NextUpdate (empty = valid "delete all" target state)
        storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabaseNextUpdate)
            .await
            .unwrap();

        let query = RuntimeFilesQuery::default();
        let result = compute_nextupdate_state(&storage, empty_database_dir(), &query)
            .await
            .unwrap();
        let mdd_ids: Vec<&str> = result
            .items
            .iter()
            .filter(|i| {
                std::path::Path::new(&i.id)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("mdd"))
            })
            .map(|i| i.id.as_str())
            .collect();
        assert!(
            mdd_ids.is_empty(),
            "empty NextUpdate = target state is empty (delete all)"
        );
    }

    #[tokio::test]
    async fn delete_nextupdate_initializes_from_current_when_not_initialized() {
        let (storage, _dir) = make_storage();
        let db = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        write_test_file_by_name(&storage, &*db, "ecu1.mdd", b"data1").await;
        write_test_file_by_name(&storage, &*db, "ecu2.mdd", b"data2").await;

        super::delete_nextupdate_file(&storage, empty_database_dir(), "ecu1.mdd")
            .await
            .expect("delete should succeed by initializing NextUpdate from current first");

        let query = RuntimeFilesQuery::default();
        let result = compute_nextupdate_state(&storage, empty_database_dir(), &query)
            .await
            .unwrap();
        let ids: Vec<&str> = result.items.iter().map(|i| i.id.as_str()).collect();
        assert!(
            !ids.contains(&"ecu1.mdd"),
            "deleted file must not appear in next-update state"
        );
        assert!(
            ids.contains(&"ecu2.mdd"),
            "sibling file from current must still appear in next-update state"
        );
    }

    #[tokio::test]
    async fn delete_nextupdate_returns_file_not_found_for_ghost() {
        let (storage, _dir) = make_storage();
        storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();

        let result =
            super::delete_nextupdate_file(&storage, empty_database_dir(), "ghost.mdd").await;
        assert!(matches!(result, Err(RuntimeUpdateError::FileNotFound(_))));
    }

    #[tokio::test]
    async fn delete_nextupdate_removes_from_already_initialized() {
        let (storage, _dir) = make_storage();
        let next = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabaseNextUpdate)
            .await
            .unwrap();
        write_test_file_by_name(&storage, &*next, "ecu1.mdd", b"data1").await;
        write_test_file_by_name(&storage, &*next, "ecu2.mdd", b"data2").await;

        super::delete_nextupdate_file(&storage, empty_database_dir(), "ecu1.mdd")
            .await
            .unwrap();

        let keys = next.list().await.unwrap();
        assert_eq!(keys, vec!["ecu2.mdd"]);
    }

    #[tokio::test]
    async fn delete_nextupdate_invalid_extension_returns_error() {
        let (storage, _dir) = make_storage();
        let result =
            super::delete_nextupdate_file(&storage, empty_database_dir(), "file.txt").await;
        assert!(matches!(
            result,
            Err(RuntimeUpdateError::InvalidFileType(_))
        ));
    }

    #[tokio::test]
    async fn empty_upload_does_not_create_nextupdate_collection() {
        let (storage, _dir) = make_storage();
        let current = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        write_test_file_by_name(&storage, &*current, "existing.mdd", b"current_data").await;

        let result = upload(&storage, Vec::new()).await.unwrap();

        assert!(result.items.is_empty());
        assert!(matches!(
            storage
                .get_collection(&CollectionName::DiagnosticDatabaseNextUpdate)
                .await,
            Err(StorageError::CollectionNotFound(_))
        ));
        assert_eq!(current.list().await.unwrap(), vec!["existing.mdd"]);
    }

    #[tokio::test]
    async fn upload_stores_mdd() {
        let (storage, _dir) = make_storage();
        let mdd = make_valid_mdd("TestECU");
        let files = make_upload_files(&[("test.mdd", &mdd)]);

        let result = upload(&storage, files).await.unwrap();
        assert_eq!(result.items.len(), 1);
        assert_eq!(result.items.first().unwrap().id, "test.mdd");
    }

    #[tokio::test]
    async fn upload_single_valid_mdd_stored_in_nextupdate() {
        let (storage, _dir) = make_storage();
        let mdd = make_valid_mdd("ECU_Alpha");
        let files = make_upload_files(&[("ECU_Alpha.mdd", &mdd)]);

        let result = upload(&storage, files).await.unwrap();

        assert_eq!(result.items.len(), 1);
        assert_eq!(result.items.first().unwrap().id, "ecu_alpha.mdd");

        let col = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabaseNextUpdate)
            .await
            .unwrap();
        let keys = col.list().await.unwrap();
        assert!(keys.contains(&"ecu_alpha.mdd".to_string()));
    }

    #[tokio::test]
    async fn upload_three_mdd_files_all_stored() {
        let (storage, _dir) = make_storage();
        let mdd1 = make_valid_mdd("Alpha");
        let mdd2 = make_valid_mdd("Beta");
        let mdd3 = make_valid_mdd("Gamma");
        let files = make_upload_files(&[
            ("Alpha.mdd", &mdd1),
            ("Beta.mdd", &mdd2),
            ("Gamma.mdd", &mdd3),
        ]);

        let result = upload(&storage, files).await.unwrap();

        assert_eq!(result.items.len(), 3);
        let ids: Vec<&str> = result.items.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"alpha.mdd"));
        assert!(ids.contains(&"beta.mdd"));
        assert!(ids.contains(&"gamma.mdd"));
    }

    #[tokio::test]
    async fn reject_all_with_invalid_file_returns_err() {
        let (storage, _dir) = make_storage();
        let files = make_upload_files(&[("bad.txt", b"not an mdd or config")]);

        let err = upload(&storage, files).await.unwrap_err();

        assert!(matches!(err, RuntimeUpdateError::InvalidFileType(_)));
    }

    #[tokio::test]
    async fn no_normalize_stores_under_original_lowercase() {
        let (storage, _dir) = make_storage();
        let mdd = make_valid_mdd("AnyECU");
        let files = make_upload_files(&[("MyFile_V2.MDD", &mdd)]);

        let result = upload(&storage, files).await.unwrap();

        assert_eq!(result.items.first().unwrap().id, "myfile_v2.mdd");
    }

    #[tokio::test]
    async fn field_without_filename_is_skipped() {
        let (storage, _dir) = make_storage();
        let mdd = make_valid_mdd("RealECU");
        let files = make_upload_files(&[("", b"ignored data"), ("real.mdd", &mdd)]);

        let result = upload(&storage, files).await.unwrap();

        assert_eq!(result.items.len(), 1);
        assert_eq!(result.items.first().unwrap().id, "real.mdd");
    }

    #[tokio::test]
    async fn upload_mdd_inits_nextupdate_from_current() {
        let (storage, _dir) = make_storage();
        let db = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        write_test_file_by_name(&storage, &*db, "existing.mdd", b"current_data").await;

        let mdd = make_valid_mdd("NewECU");
        let files = make_upload_files(&[("new.mdd", &mdd)]);
        upload(&storage, files).await.unwrap();

        let col = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabaseNextUpdate)
            .await
            .unwrap();
        let keys = col.list().await.unwrap();
        assert!(keys.contains(&"existing.mdd".to_string()));
        assert!(keys.contains(&"new.mdd".to_string()));
    }

    #[tokio::test]
    async fn upload_mdd_no_reinit_when_nextupdate_already_exists() {
        let (storage, _dir) = make_storage();
        let db = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        write_test_file_by_name(&storage, &*db, "current.mdd", b"current").await;
        let next = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabaseNextUpdate)
            .await
            .unwrap();
        write_test_file_by_name(&storage, &*next, "already.mdd", b"already_there").await;

        let mdd = make_valid_mdd("Extra");
        let files = make_upload_files(&[("extra.mdd", &mdd)]);
        upload(&storage, files).await.unwrap();

        let col = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabaseNextUpdate)
            .await
            .unwrap();
        let keys = col.list().await.unwrap();
        assert!(keys.contains(&"already.mdd".to_string()));
        assert!(keys.contains(&"extra.mdd".to_string()));
        assert!(!keys.contains(&"current.mdd".to_string()));
    }

    #[tokio::test]
    async fn upload_mdd_empty_current_graceful() {
        let (storage, _dir) = make_storage();

        let mdd = make_valid_mdd("Fresh");
        let files = make_upload_files(&[("fresh.mdd", &mdd)]);
        let result = upload(&storage, files).await.unwrap();

        assert_eq!(result.items.len(), 1);
        assert_eq!(result.items.first().unwrap().id, "fresh.mdd");
        let col = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabaseNextUpdate)
            .await
            .unwrap();
        let keys = col.list().await.unwrap();
        assert_eq!(keys, vec!["fresh.mdd"]);
    }

    #[tokio::test]
    async fn upload_multiple_mdds_inits_only_once() {
        let (storage, _dir) = make_storage();
        let db = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        write_test_file_by_name(&storage, &*db, "base.mdd", b"base").await;

        let mdd1 = make_valid_mdd("A");
        let mdd2 = make_valid_mdd("B");
        let files = make_upload_files(&[("a.mdd", &mdd1), ("b.mdd", &mdd2)]);
        upload(&storage, files).await.unwrap();

        let col = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabaseNextUpdate)
            .await
            .unwrap();
        let keys = col.list().await.unwrap();
        assert!(keys.contains(&"base.mdd".to_string()));
        assert!(keys.contains(&"a.mdd".to_string()));
        assert!(keys.contains(&"b.mdd".to_string()));
    }

    #[tokio::test]
    async fn upload_integrity_failure_returns_validation_error() {
        let (storage, _dir) = make_storage();
        let mdd = make_valid_mdd("TestECU");
        let files = make_upload_files(&[("test.mdd", &mdd)]);

        let err = upload_rejecting(&storage, files, RejectKind::Mdd)
            .await
            .unwrap_err();

        assert!(
            matches!(err, RuntimeUpdateError::ValidationFailed(_)),
            "{}",
            format!("err={err}")
        );
    }

    #[tokio::test]
    async fn upload_integrity_failure_removes_written_file() {
        let (storage, _dir) = make_storage();
        let mdd = make_valid_mdd("TestECU");
        let files = make_upload_files(&[("test.mdd", &mdd)]);

        let _ = upload_rejecting(&storage, files, RejectKind::Mdd).await;

        let col = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabaseNextUpdate)
            .await
            .unwrap();
        assert!(col.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn upload_integrity_failure_on_second_file_removes_only_second() {
        let (storage, _dir) = make_storage();
        let mdd1 = make_valid_mdd("ECU1");
        let mdd2 = make_valid_mdd("ECU2");

        // Upload the first file successfully, then reject the second.
        upload(&storage, make_upload_files(&[("ecu1.mdd", &mdd1)]))
            .await
            .unwrap();

        let _ = upload_rejecting(
            &storage,
            make_upload_files(&[("ecu2.mdd", &mdd2)]),
            RejectKind::Mdd,
        )
        .await;

        let col = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabaseNextUpdate)
            .await
            .unwrap();
        let keys = col.list().await.unwrap();
        assert_eq!(keys, vec!["ecu1.mdd"]);
    }

    #[tokio::test]
    async fn upload_integrity_failure_does_not_add_to_result() {
        let (storage, _dir) = make_storage();
        let mdd = make_valid_mdd("TestECU");
        let files = make_upload_files(&[("test.mdd", &mdd)]);

        let result = upload_rejecting(&storage, files, RejectKind::Mdd).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn upload_single_call_second_file_fails_integrity_first_is_kept() {
        let (storage, _dir) = make_storage();
        let mdd1 = make_valid_mdd("ECU1");
        let mdd2 = make_valid_mdd("ECU2");
        let files = make_upload_files(&[("ecu1.mdd", &mdd1), ("ecu2.mdd", &mdd2)]);

        let _ = upload_rejecting_by_name(&storage, files, "ecu2.mdd").await;

        let col = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabaseNextUpdate)
            .await
            .unwrap();
        let keys = col.list().await.unwrap();
        assert!(
            keys.contains(&"ecu1.mdd".to_string()),
            "first file must be kept"
        );
        assert!(
            !keys.contains(&"ecu2.mdd".to_string()),
            "failed file must be removed"
        );
    }

    #[tokio::test]
    async fn upload_single_call_second_file_fails_integrity_returns_validation_error() {
        let (storage, _dir) = make_storage();
        let mdd1 = make_valid_mdd("ECU1");
        let mdd2 = make_valid_mdd("ECU2");
        let files = make_upload_files(&[("ecu1.mdd", &mdd1), ("ecu2.mdd", &mdd2)]);

        let err = upload_rejecting_by_name(&storage, files, "ecu2.mdd")
            .await
            .unwrap_err();

        assert!(matches!(err, RuntimeUpdateError::ValidationFailed(_)));
    }

    /// A file in the test `database.dir`.
    struct DirFile {
        name: &'static str,
        content: &'static [u8],
    }

    /// A `database.dir` holding `files`, plus a non-MDD file that must not be seeded.
    fn database_dir_with(files: &[DirFile]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("database dir");
        for file in files {
            std::fs::write(dir.path().join(file.name), file.content).expect("write MDD file");
        }
        std::fs::write(dir.path().join("readme.txt"), b"not a database").expect("write file");
        dir
    }

    async fn sorted_keys(storage: &LocalStorage, name: &CollectionName) -> Vec<String> {
        let mut keys = storage
            .get_collection(name)
            .await
            .expect("collection exists")
            .list()
            .await
            .unwrap();
        keys.sort();
        keys
    }

    #[tokio::test]
    async fn upload_seeds_current_from_database_dir() {
        let (storage, _dir) = make_storage();
        let database_dir = database_dir_with(&[
            DirFile {
                name: "ECU_A.mdd",
                content: b"A",
            },
            DirFile {
                name: "ecu_b.mdd",
                content: b"B",
            },
        ]);

        let mdd = make_valid_mdd("C");
        upload_files::<_, MockSecurityHandler, MockLockProvider>(
            &storage,
            &MockSecurityHandler::new(),
            database_dir.path(),
            make_upload_files(&[("ecu_c.mdd", &mdd)]),
        )
        .await
        .unwrap();

        assert_eq!(
            sorted_keys(&storage, &CollectionName::DiagnosticDatabase).await,
            vec!["ecu_a.mdd", "ecu_b.mdd"],
            "current must hold the databases loaded from database.dir"
        );
        assert_eq!(
            sorted_keys(&storage, &CollectionName::DiagnosticDatabaseNextUpdate).await,
            vec!["ecu_a.mdd", "ecu_b.mdd", "ecu_c.mdd"],
            "the update must start from the databases loaded from database.dir"
        );
        let current = storage
            .get_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(current.file_path("ecu_a.mdd").unwrap()).unwrap(),
            b"A",
            "seeding must preserve the file content"
        );
    }

    #[tokio::test]
    async fn delete_nextupdate_seeds_current_from_database_dir() {
        let (storage, _dir) = make_storage();
        let database_dir = database_dir_with(&[
            DirFile {
                name: "ecu_a.mdd",
                content: b"A",
            },
            DirFile {
                name: "ecu_b.mdd",
                content: b"B",
            },
        ]);

        super::delete_nextupdate_file(&storage, database_dir.path(), "ecu_a.mdd")
            .await
            .expect("a database from database.dir can be deleted from the first update");

        assert_eq!(
            sorted_keys(&storage, &CollectionName::DiagnosticDatabase).await,
            vec!["ecu_a.mdd", "ecu_b.mdd"]
        );
        assert_eq!(
            sorted_keys(&storage, &CollectionName::DiagnosticDatabaseNextUpdate).await,
            vec!["ecu_b.mdd"]
        );
    }

    #[tokio::test]
    async fn rejected_upload_does_not_seed() {
        let (storage, _dir) = make_storage();
        let database_dir = database_dir_with(&[DirFile {
            name: "ecu_a.mdd",
            content: b"A",
        }]);

        let result = upload_files::<_, MockSecurityHandler, MockLockProvider>(
            &storage,
            &MockSecurityHandler::new(),
            database_dir.path(),
            make_upload_files(&[("bad.txt", b"not an mdd")]),
        )
        .await;

        assert!(matches!(
            result,
            Err(RuntimeUpdateError::InvalidFileType(_))
        ));
        assert!(matches!(
            storage
                .get_collection(&CollectionName::DiagnosticDatabase)
                .await,
            Err(StorageError::CollectionNotFound(_))
        ));
    }

    #[tokio::test]
    async fn listings_show_database_dir_until_seeded() {
        let (storage, _dir) = make_storage();
        let database_dir = database_dir_with(&[DirFile {
            name: "ECU_A.mdd",
            content: b"A",
        }]);
        let query = RuntimeFilesQuery {
            include_file_size: true,
            include_hash: Some(HashAlgorithm::Sha256),
            ..Default::default()
        };

        let current = super::list_current_files(&storage, database_dir.path(), &query)
            .await
            .unwrap();
        let [item] = current.items.as_slice() else {
            panic!("current must list the database from database.dir: {current:?}");
        };
        assert_eq!(item.id, "ecu_a.mdd");
        assert_eq!(item.size, Some(1));
        assert_eq!(
            item.hash.as_deref(),
            Some(format!("{:x}", Sha256::digest(b"A")).as_str())
        );
        let next = compute_nextupdate_state(&storage, database_dir.path(), &query)
            .await
            .unwrap();
        let ids = |list: &super::BulkDataList| {
            list.items.iter().map(|i| i.id.clone()).collect::<Vec<_>>()
        };
        assert_eq!(ids(&next), ids(&current), "nextupdate must mirror current");

        // Once seeded, the storage is listed, even when it is empty.
        let mut tx = storage.begin_transaction().unwrap();
        storage
            .create_collection(&mut tx, &CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let current = super::list_current_files(&storage, database_dir.path(), &query)
            .await
            .unwrap();
        assert!(current.items.is_empty(), "{current:?}");
    }

    #[tokio::test]
    async fn dir_listing_skips_vanished_files() {
        let database_dir = database_dir_with(&[DirFile {
            name: "ecu_a.mdd",
            content: b"A",
        }]);
        let vanished = database_dir.path().join("vanished.mdd");
        let query = RuntimeFilesQuery {
            include_file_size: true,
            ..Default::default()
        };

        let items = super::describe_database_dir_files(
            &[database_dir.path().join("ecu_a.mdd"), vanished],
            &query,
        )
        .await
        .unwrap();

        let ids: Vec<&str> = items.iter().map(|i| i.id.as_str()).collect();
        assert_eq!(ids, vec!["ecu_a.mdd"]);
    }

    #[tokio::test]
    async fn upload_with_missing_database_dir_fails_without_seeding() {
        let (storage, _dir) = make_storage();
        let missing = std::path::Path::new("/nonexistent/cda-database-dir");
        let mdd = make_valid_mdd("A");

        let result = upload_files::<_, MockSecurityHandler, MockLockProvider>(
            &storage,
            &MockSecurityHandler::new(),
            missing,
            make_upload_files(&[("ecu_a.mdd", &mdd)]),
        )
        .await;

        assert!(
            matches!(
                result,
                Err(RuntimeUpdateError::StorageError(StorageError::Io(ref e)))
                    if e.kind() == std::io::ErrorKind::NotFound
            ),
            "{result:?}"
        );
        for name in [
            CollectionName::DiagnosticDatabase,
            CollectionName::DiagnosticDatabaseNextUpdate,
        ] {
            assert!(
                matches!(
                    storage.get_collection(&name).await,
                    Err(StorageError::CollectionNotFound(_))
                ),
                "{name} must not exist, so the seed runs once the directory appears"
            );
        }
    }

    #[tokio::test]
    async fn delete_nextupdate_with_missing_database_dir_fails_without_seeding() {
        let (storage, _dir) = make_storage();
        let missing = std::path::Path::new("/nonexistent/cda-database-dir");

        let result = super::delete_nextupdate_file(&storage, missing, "ecu_a.mdd").await;

        assert!(
            matches!(
                result,
                Err(RuntimeUpdateError::StorageError(StorageError::Io(ref e)))
                    if e.kind() == std::io::ErrorKind::NotFound
            ),
            "{result:?}"
        );
        for name in [
            CollectionName::DiagnosticDatabase,
            CollectionName::DiagnosticDatabaseNextUpdate,
        ] {
            assert!(
                matches!(
                    storage.get_collection(&name).await,
                    Err(StorageError::CollectionNotFound(_))
                ),
                "{name} must not exist, so the seed runs once the directory appears"
            );
        }
    }
}
