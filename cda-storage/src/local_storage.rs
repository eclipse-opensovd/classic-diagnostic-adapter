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

//! Local filesystem implementation of the [`Storage`] trait.

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use async_trait::async_trait;
use cda_interfaces::storage_api::{
    Collection, CollectionName, DirectFileAccess, Operation, Storage, StorageError, Transaction,
    TransactionCommitter,
};

use crate::{
    local_collection::LocalCollection,
    paths,
    recovery::{self, BACKUP_EXTENSION},
    wal,
};

/// Local filesystem implementation of the [`Storage`] trait.
///
/// Collections are stored as subdirectories under `{root}/collections/`. The WAL and staging
/// files live under `{root}/journal/`.
pub struct LocalStorage {
    /// Base directory for collection data.
    collections_dir: PathBuf,
    /// Directory containing the WAL file and staging subdirectory.
    journal_dir: PathBuf,
    /// Read-write lock: reads take shared, commit takes exclusive.
    data_lock: Arc<tokio::sync::RwLock<()>>,
    /// Flag to enforce single-transaction-at-a-time.
    tx_active: Arc<AtomicBool>,
}

impl LocalStorage {
    /// Create a new `LocalStorage` rooted at the given directory.
    ///
    /// On construction, performs startup recovery to handle any incomplete transactions from a
    /// previous run.
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`] if directory creation fails or recovery fails.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, StorageError> {
        let root = root.into();
        let collections_dir = root.join("collections");
        let journal_dir = root.join("journal");
        let staging_dir = journal_dir.join(wal::STAGING_DIR_NAME);

        // Ensure directories exist.
        std::fs::create_dir_all(&collections_dir)?;
        std::fs::create_dir_all(&staging_dir)?;

        // Run startup recovery before accepting any operations.
        recovery::recover(&journal_dir, &collections_dir)?;

        tracing::info!(root = %root.display(), "Local storage initialized");

        Ok(Self {
            collections_dir,
            journal_dir,
            data_lock: Arc::new(tokio::sync::RwLock::new(())),
            tx_active: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Return the path to a collection's directory.
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`] if the collection name fails path sanitization (when the
    /// `sanitize-paths` feature is enabled).
    fn collection_dir(&self, name: &CollectionName) -> Result<PathBuf, StorageError> {
        paths::sanitize_path_segment(name.as_str())?;
        Ok(self.collections_dir.join(name.as_str()))
    }
}

impl Storage for LocalStorage {
    type CollectionHandle = LocalCollection;

    async fn get_collection(
        &self,
        name: &CollectionName,
    ) -> Result<Arc<LocalCollection>, StorageError> {
        let _guard = self.data_lock.read().await;
        let dir = self.collection_dir(name)?;
        if !dir.exists() {
            return Err(StorageError::CollectionNotFound(name.to_string()));
        }
        Ok(Arc::new(LocalCollection::new(
            name.clone(),
            dir,
            Arc::clone(&self.data_lock),
        )))
    }

    async fn get_or_create_collection(
        &self,
        name: &CollectionName,
    ) -> Result<Arc<impl Collection + DirectFileAccess + 'static>, StorageError> {
        let dir = self.collection_dir(name)?;

        let read_guard = self.data_lock.read().await;
        if dir.exists() {
            return Ok(Arc::new(LocalCollection::new(
                name.clone(),
                dir,
                Arc::clone(&self.data_lock),
            )));
        }
        drop(read_guard);

        // Collection does not exist -- acquire a write lock to create it.
        // Reject if a transaction is active.
        if self.tx_active.load(Ordering::Acquire) {
            return Err(StorageError::TransactionBusy);
        }
        let write_guard = self.data_lock.write().await;
        // Re-check after acquiring write lock
        if !dir.exists() {
            std::fs::create_dir_all(&dir)?;
            tracing::debug!(collection = %name, "Created collection directory");
        }
        drop(write_guard);

        Ok(Arc::new(LocalCollection::new(
            name.clone(),
            dir,
            Arc::clone(&self.data_lock),
        )))
    }

    fn begin_transaction(&self) -> Result<Transaction, StorageError> {
        // Enforce single-transaction-at-a-time.
        let was_active = self.tx_active.swap(true, Ordering::AcqRel);
        if was_active {
            return Err(StorageError::TransactionBusy);
        }

        let wal_path = self.journal_dir.join(wal::WAL_FILE_NAME);
        let staging_dir = self.journal_dir.join(wal::STAGING_DIR_NAME);

        // Create a fresh WAL file.
        wal::create_wal(&wal_path).inspect_err(|_| {
            // Reset flag if WAL creation fails.
            self.tx_active.store(false, Ordering::Release);
        })?;

        // Ensure staging directory exists.
        std::fs::create_dir_all(&staging_dir).map_err(|e| {
            self.tx_active.store(false, Ordering::Release);
            StorageError::Io(e)
        })?;

        tracing::debug!("Transaction started");

        Ok(Transaction::new(
            wal_path,
            staging_dir,
            Arc::new(LocalStorageCommitter {
                collections_dir: self.collections_dir.clone(),
                data_lock: Arc::clone(&self.data_lock),
                tx_active: Arc::clone(&self.tx_active),
            }),
        ))
    }

    async fn create_collection(
        &self,
        tx: &mut Transaction,
        name: &CollectionName,
    ) -> Result<Arc<impl Collection + DirectFileAccess + 'static>, StorageError> {
        let dir = self.collection_dir(name)?;
        if dir.exists() {
            return Err(StorageError::TransactionConflict(format!(
                "Collection already exists: {name}"
            )));
        }

        let op = Operation::CreateCollection { name: name.clone() };
        wal::append_operation(tx.journal_path(), &op)?;
        tx.record(op);

        // Return a collection handle that points to where the directory *will* be after commit.
        Ok(Arc::new(LocalCollection::new(
            name.clone(),
            dir,
            Arc::clone(&self.data_lock),
        )))
    }

    async fn delete_collection(
        &self,
        tx: &mut Transaction,
        name: &CollectionName,
    ) -> Result<(), StorageError> {
        let dir = self.collection_dir(name)?;
        if !dir.exists() {
            return Err(StorageError::CollectionNotFound(name.to_string()));
        }

        let op = Operation::DeleteCollection { name: name.clone() };
        wal::append_operation(tx.journal_path(), &op)?;
        tx.record(op);

        Ok(())
    }

    async fn copy_collection(
        &self,
        tx: &mut Transaction,
        source: &CollectionName,
        dest: &CollectionName,
    ) -> Result<(), StorageError> {
        let source_dir = self.collection_dir(source)?;
        if !source_dir.exists() {
            return Err(StorageError::CollectionNotFound(source.to_string()));
        }

        let op = Operation::CopyCollection {
            source: source.clone(),
            dest: dest.clone(),
        };
        wal::append_operation(tx.journal_path(), &op)?;
        tx.record(op);

        Ok(())
    }
}

/// Handles commit and rollback callbacks from [`Transaction`].
///
/// This struct is held by the `Transaction` via `Arc<dyn TransactionCommitter>` and provides the
/// bridge back into the storage backend for applying or discarding operations.
struct LocalStorageCommitter {
    collections_dir: PathBuf,
    data_lock: Arc<tokio::sync::RwLock<()>>,
    tx_active: Arc<AtomicBool>,
}

#[async_trait]
impl TransactionCommitter for LocalStorageCommitter {
    async fn apply(
        &self,
        operations: Vec<Operation>,
        journal_path: PathBuf,
    ) -> Result<(), StorageError> {
        async fn apply_inner(
            committer: &LocalStorageCommitter,
            operations: Vec<Operation>,
            journal_path: PathBuf,
        ) -> Result<(), StorageError> {
            let staging_dir = journal_path.parent().map(|p| p.join(wal::STAGING_DIR_NAME));
            let journal_dir = journal_path
                .parent()
                .ok_or_else(|| StorageError::Other("WAL path has no parent directory".to_string()))?
                .to_path_buf();

            // Step 1: Mark the WAL as COMMITTING (in-place pwrite, no fsync yet).
            wal::mark_committing(&journal_path)?;

            // Step 2: Fsync all staging files and the WAL in one batch.
            // This single durability barrier makes both the COMMITTING status and all operation
            // entries durable. If the process crashes after this point, recovery will see
            // COMMITTING and know that operations may have been partially applied.
            if let Some(ref staging) = staging_dir {
                wal::sync_staging_files(staging)?;
            }
            wal::sync_wal(&journal_path)?;

            // Step 3: Acquire exclusive access. Blocks all reads.
            let _write_guard = committer.data_lock.write().await;

            // Step 4: Apply each operation, creating backups for rollback.
            let result = committer.apply_operations(&operations);

            if let Err(e) = &result {
                tracing::warn!(
                    error = %e,
                    "Commit failed, rolling back partially applied operations"
                );
                if let Err(rb_err) =
                    rollback_applied_operations(&committer.collections_dir, &operations)
                {
                    tracing::warn!(error = %rb_err, "Rollback also encountered an error");
                }
            } else {
                // Step 5: Fsync collection directories to make renames durable.
                sync_collection_dirs(&committer.collections_dir, &operations)?;
            }

            // Step 6: Delete the WAL file and fsync the journal directory.
            // This is the point of no return. Once the WAL deletion is durable, recovery will
            // treat any remaining .bak files as orphans from a successfully committed transaction.
            if journal_path.exists() {
                std::fs::remove_file(&journal_path)?;
            }
            wal::sync_journal_dir(&journal_dir)?;

            // Step 7: Clean up .bak files and staging (non-critical, best-effort after point of
            // no return).
            if result.is_ok()
                && let Err(e) = cleanup_backup_files(&committer.collections_dir)
            {
                tracing::warn!(error = %e, "Failed to clean up .bak files after commit");
            }
            if let Some(ref staging) = staging_dir
                && let Err(e) = cleanup_directory_contents(staging)
            {
                tracing::warn!(error = %e, "Failed to clean up staging directory after commit");
            }

            result
        }
        let result = apply_inner(self, operations, journal_path).await;

        // Release the transaction flag.
        self.tx_active.store(false, Ordering::Release);

        if result.is_ok() {
            tracing::info!("Transaction committed successfully");
        }
        result
    }

    fn discard(&self, staging_dir: &Path, journal_path: &Path) {
        // Best-effort cleanup on rollback.
        if let Err(e) = cleanup_directory_contents(staging_dir) {
            tracing::warn!(error = %e, "Failed to clean up staging directory during rollback");
        }
        if journal_path.exists()
            && let Err(e) = std::fs::remove_file(journal_path)
        {
            tracing::warn!(error = %e, "Failed to remove WAL file during rollback");
        }
        self.tx_active.store(false, Ordering::Release);
        tracing::debug!("Transaction rolled back");
    }
}

impl LocalStorageCommitter {
    /// Apply all operations from the journal.
    ///
    /// The Delete* Operations ignore the case that the file or directory was already deleted
    /// on the fs due to external modifications.
    /// In these cases, it's better to continue with the commit instead of failing it,
    /// as the end result is the same (the file/directory is gone).
    fn apply_operations(&self, operations: &[Operation]) -> Result<(), StorageError> {
        for op in operations {
            match op {
                Operation::Write {
                    collection,
                    key,
                    staged_path,
                } => {
                    let target_dir = self.collections_dir.join(collection.as_str());
                    std::fs::create_dir_all(&target_dir)?;
                    let target = target_dir.join(key);

                    // Backup existing file if present.
                    if target.exists() {
                        let backup = append_extension(&target, BACKUP_EXTENSION);
                        std::fs::rename(&target, &backup)?;
                    }

                    // Move staged file into place.
                    std::fs::rename(staged_path, &target)?;
                }
                Operation::Delete { collection, key } => {
                    let target = self.collections_dir.join(collection.as_str()).join(key);
                    if target.exists() {
                        let backup = append_extension(&target, BACKUP_EXTENSION);
                        std::fs::rename(&target, &backup)?;
                    }
                }
                Operation::DeleteAll { collection } => {
                    let dir = self.collections_dir.join(collection.as_str());
                    if dir.exists() {
                        backup_all_files_in_dir(&dir)?;
                    }
                }
                Operation::CreateCollection { name } => {
                    let dir = self.collections_dir.join(name.as_str());
                    std::fs::create_dir_all(&dir)?;
                }
                Operation::DeleteCollection { name } => {
                    let dir = self.collections_dir.join(name.as_str());
                    if dir.exists() {
                        let backup = append_extension(&dir, BACKUP_EXTENSION);
                        std::fs::rename(&dir, &backup)?;
                    }
                }
                Operation::CopyCollection { source, dest } => {
                    let source_dir = self.collections_dir.join(source.as_str());
                    let dest_dir = self.collections_dir.join(dest.as_str());

                    // Back up existing destination for rollback, then create a fresh directory.
                    // This ensures "replace" semantics: the destination ends up with exactly
                    // the source's contents, not a merge of old and new files.
                    if dest_dir.exists() {
                        let backup = append_extension(&dest_dir, BACKUP_EXTENSION);
                        std::fs::rename(&dest_dir, &backup)?;
                    }

                    std::fs::create_dir_all(&dest_dir)?;
                    copy_dir_contents(&source_dir, &dest_dir)?;
                }
            }
        }
        Ok(())
    }
}

/// Append an extension to a path (e.g., `foo.txt` -> `foo.txt.bak`).
fn append_extension(path: &Path, ext: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".");
    s.push(ext);
    PathBuf::from(s)
}

/// Rename every file in a directory to have a `.bak` extension.
fn backup_all_files_in_dir(dir: &Path) -> Result<(), StorageError> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            let backup = append_extension(&path, BACKUP_EXTENSION);
            std::fs::rename(&path, &backup)?;
        }
    }
    Ok(())
}

/// Copy all files from `source` to `dest`.
fn copy_dir_contents(source: &Path, dest: &Path) -> Result<(), StorageError> {
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file()
            && let Some(name) = path.file_name()
        {
            let target = dest.join(name);
            std::fs::copy(&path, &target)?;
        }
    }
    Ok(())
}

/// Remove all `.bak` files and directories under `collections_dir`.
fn cleanup_backup_files(collections_dir: &Path) -> Result<(), StorageError> {
    let bak_ext = std::ffi::OsStr::new(BACKUP_EXTENSION);

    for collection_entry in std::fs::read_dir(collections_dir)? {
        let collection_entry = collection_entry?;
        let path = collection_entry.path();

        // Collection-level backups (directories with .bak extension).
        if path.is_dir() && path.extension() == Some(bak_ext) {
            std::fs::remove_dir_all(&path)?;
            continue;
        }

        if path.is_dir() {
            for entry in std::fs::read_dir(&path)? {
                let entry = entry?;
                let file_path = entry.path();
                if file_path.extension() == Some(bak_ext) {
                    std::fs::remove_file(&file_path)?;
                }
            }
        }
    }

    Ok(())
}

/// Roll back partially applied operations during a failed commit.
///
/// This removes newly created files and directories (for writes to new keys,
/// `CreateCollection`, `CopyCollection`) and then restores `.bak` files (for
/// overwrites/deletes). The order matters: new artifacts must be identified while `.bak` files
/// are still in place (before restoration changes the filesystem state).
fn rollback_applied_operations(
    collections_dir: &Path,
    operations: &[Operation],
) -> Result<(), StorageError> {
    recovery::remove_new_artifacts(collections_dir, operations)?;

    recovery::rollback_partial_commit(collections_dir)?;

    Ok(())
}

/// Fsync the directories that were modified during commit to ensure renames are durable.
///
/// On POSIX systems, `rename()` is atomic but not durable until the *directory* containing the
/// entry is fsynced. This function fsyncs each unique collection directory that was touched by
/// the operations.
///
/// On Windows this is a no-op because NTFS journals metadata changes internally.
// disable the lint on windows to keep signature consistent
#[cfg_attr(windows, allow(clippy::unnecessary_wraps))]
fn sync_collection_dirs(
    collections_dir: &Path,
    operations: &[Operation],
) -> Result<(), StorageError> {
    // On Windows, NTFS journals metadata changes internally so explicit directory fsync is
    // not needed.
    // Additionally, `File::open` on a directory fails due to `FILE_FLAG_BACKUP_SEMANTICS`
    // not being set by the standard library.
    // The early return avoids both the unnecessary work and the platform-specific fsync
    // implementation.
    #[cfg(windows)]
    {
        // Suppress unused variable warnings.
        let _ = &collections_dir;
        let _ = &operations;
    }
    #[cfg(not(windows))]
    {
        let mut synced = std::collections::HashSet::new();

        for op in operations {
            let dir_name = match op {
                Operation::Write { collection, .. }
                | Operation::Delete { collection, .. }
                | Operation::DeleteAll { collection } => Some(collection.as_str()),
                Operation::CreateCollection { name } | Operation::DeleteCollection { name } => {
                    Some(name.as_str())
                }
                Operation::CopyCollection { dest, .. } => Some(dest.as_str()),
            };

            if let Some(name) = dir_name
                && synced.insert(name.to_string())
            {
                let dir = collections_dir.join(name);
                if dir.exists() {
                    let f = std::fs::File::open(&dir)?;
                    f.sync_all()?;
                }
            }
        }

        // Also fsync the collections directory itself (for create/delete collection operations).
        let f = std::fs::File::open(collections_dir)?;
        f.sync_all()?;
    }

    Ok(())
}

/// Remove all files (not directories) in the given directory.
fn cleanup_directory_contents(dir: &Path) -> Result<(), StorageError> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            std::fs::remove_file(&path)?;
        }
    }
    Ok(())
}
