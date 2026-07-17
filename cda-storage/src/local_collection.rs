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

//! Local filesystem implementation of the [`Collection`] trait.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use cda_interfaces::storage_api::{
    Collection, CollectionName, DirectFileAccess, Metadata, Operation, RandomAccessData,
    ReadableStream, StorageError, Transaction,
};
use tokio::io::AsyncWriteExt;

use crate::{io, paths, wal};

/// A collection backed by a directory on the local filesystem.
///
/// Each entry is stored as a file named after its key (normalized to lowercase).
pub struct LocalCollection {
    /// The name of this collection.
    name: CollectionName,
    /// Path to the collection directory: `{root}/collections/{collection_name}/`.
    dir: PathBuf,
    /// Shared read-write lock for coordinating reads vs. commits.
    data_lock: Arc<tokio::sync::RwLock<()>>,
}

impl LocalCollection {
    /// Create a new `LocalCollection` pointing at the given directory.
    pub(crate) fn new(
        name: CollectionName,
        dir: PathBuf,
        data_lock: Arc<tokio::sync::RwLock<()>>,
    ) -> Self {
        Self {
            name,
            dir,
            data_lock,
        }
    }

    /// Return the filesystem path for the given (already normalized) key.
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`] if the key fails path sanitization (when the
    /// `sanitize-paths` feature is enabled).
    fn key_path(&self, key: &str) -> Result<PathBuf, StorageError> {
        paths::sanitize_path_segment(key)?;
        Ok(self.dir.join(key))
    }

    /// Ensures that a file matching `key` (already normalized to lowercase) exists on disk
    /// under exactly that (lowercase) name.
    ///
    /// All keys are normalized to lowercase (see [`normalize_key`]), and [`list`](Collection::list)
    /// returns keys in that same normalized form. However, a file can end up on disk with a
    /// different case than its normalized key - for example when files are placed directly in
    /// the collection directory outside of [`Collection::write`] (such as during initial
    /// provisioning of OEM-supplied files, which often use mixed-case names). If left
    /// unaddressed, such a file would be listed (via its normalized key) but every other
    /// operation (`metadata`, `read`, `delete`, `file_path`) would fail with `KeyNotFound`,
    /// since they resolve the path via the lowercase key directly.
    ///
    /// This self-heals that situation: if no file exists at the exact lowercase path but one
    /// exists under a different case, it is renamed in place to the normalized name (a metadata-
    /// only, same-filesystem operation) so that the on-disk state matches the key-normalization
    /// invariant relied on everywhere else. No-op if the normalized path already exists or no
    /// case-insensitive match is found.
    ///
    /// This is a best-effort, synchronous operation (no lock is taken): the rename is atomic
    /// and idempotent, so a benign race with a concurrent caller doing the same self-heal (or
    /// with a commit) simply results in a harmless `rename` failure that is ignored, since the
    /// target either already exists in the desired state or will shortly.
    fn ensure_normalized_on_disk(&self, key: &str) {
        let target = self.dir.join(key);
        if target.exists() {
            return;
        }

        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            // For valid files which would be listed, check if the name deviates, and normalize
            if is_valid_key(&path) && name != key && name.eq_ignore_ascii_case(key) {
                // Best-effort: ignore errors (e.g. lost the race to another renamer, or the
                // target now exists).
                let _ = std::fs::rename(&path, &target);
                break;
            }
        }
    }
}

/// Normalize a key to lowercase for case-insensitive storage.
fn normalize_key(key: &str) -> String {
    key.to_ascii_lowercase()
}

/// Checks if a key should be listed in a collection
fn is_valid_key(path: &Path) -> bool {
    let bak_ext = std::ffi::OsStr::new(crate::recovery::BACKUP_EXTENSION);
    let tmp_ext = std::ffi::OsStr::new(crate::recovery::STAGING_EXTENSION);

    // Only files are valid, when they are not backup or staging files.
    path.is_file() && path.extension() != Some(bak_ext) && path.extension() != Some(tmp_ext)
}

impl Collection for LocalCollection {
    async fn read(&self, key: &str) -> Result<Arc<impl RandomAccessData + 'static>, StorageError> {
        let key = normalize_key(key);
        let path = self.key_path(&key)?;
        self.ensure_normalized_on_disk(&key);

        let guard = io::acquire_read_lock(&self.data_lock).await;

        let file = std::fs::File::open(&path).map_err(|e| StorageError::map_io_error(e, &key))?;

        let metadata = file.metadata()?;
        let size = metadata.len();

        Ok(Arc::new(io::LocalRandomAccessData::new(file, size, guard)))
    }

    async fn metadata(&self, key: &str) -> Result<Metadata, StorageError> {
        let key = normalize_key(key);
        let path = self.key_path(&key)?;
        self.ensure_normalized_on_disk(&key);

        let _guard = io::acquire_read_lock(&self.data_lock).await;

        let fs_meta = tokio::fs::metadata(&path)
            .await
            .map_err(|e| StorageError::map_io_error(e, &key))?;

        Ok(Metadata {
            name: key,
            data_size: fs_meta.len(),
            custom_props: Vec::new(),
        })
    }

    async fn list(&self) -> Result<Vec<String>, StorageError> {
        let _guard = io::acquire_read_lock(&self.data_lock).await;

        let dir = self.dir.clone();
        let keys = list_keys_in_dir(&dir)?;
        Ok(keys)
    }

    async fn len(&self) -> Result<usize, StorageError> {
        let _guard = io::acquire_read_lock(&self.data_lock).await;

        let dir = self.dir.clone();
        let keys = list_keys_in_dir(&dir)?;
        Ok(keys.len())
    }

    async fn is_empty(&self) -> Result<bool, StorageError> {
        self.len().await.map(|n| n == 0)
    }

    async fn write(
        &self,
        tx: &mut Transaction,
        key: &str,
        data: &mut impl ReadableStream,
    ) -> Result<(), StorageError> {
        let key = normalize_key(key);
        paths::sanitize_path_segment(&key)?;

        // Stream data to a staging file.
        let staging_file_name = format!("{}.tmp", uuid::Uuid::new_v4());
        let staged_path = tx.staging_dir().join(&staging_file_name);
        let staged_path_str = staged_path
            .to_str()
            .ok_or_else(|| StorageError::Other("Invalid staging file path".to_string()))?
            .to_string();

        let mut file = tokio::fs::File::create(&staged_path).await?;
        tokio::io::copy(data, &mut file).await?;
        file.flush().await?;
        // Skip fsync here. staging files are fsynced in a batch at commit time to minimize
        // flash wear. If the process crashes before commit, the staging file is simply
        // discarded during recovery.

        let op = Operation::Write {
            collection: self.name.clone(),
            key,
            staged_path: staged_path_str,
        };

        // Persist to WAL before recording in memory.
        wal::append_operation(tx.journal_path(), &op)?;
        tx.record(op);

        Ok(())
    }

    async fn delete(&self, tx: &mut Transaction, key: &str) -> Result<(), StorageError> {
        let key = normalize_key(key);
        self.ensure_normalized_on_disk(&key);

        // Verify the key exists in committed state.
        let path = self.key_path(&key)?;
        if !path.exists() {
            return Err(StorageError::KeyNotFound(key));
        }

        let op = Operation::Delete {
            collection: self.name.clone(),
            key,
        };

        wal::append_operation(tx.journal_path(), &op)?;
        tx.record(op);

        Ok(())
    }

    async fn delete_all(&self, tx: &mut Transaction) -> Result<(), StorageError> {
        let op = Operation::DeleteAll {
            collection: self.name.clone(),
        };

        wal::append_operation(tx.journal_path(), &op)?;
        tx.record(op);

        Ok(())
    }
}

impl DirectFileAccess for LocalCollection {
    fn dir_path(&self) -> &Path {
        &self.dir
    }

    fn file_path(&self, key: &str) -> Result<PathBuf, StorageError> {
        let key = normalize_key(key);
        self.ensure_normalized_on_disk(&key);
        let path = self.key_path(&key)?;
        if !path.exists() {
            return Err(StorageError::KeyNotFound(key));
        }
        Ok(path)
    }
}

/// List all file names (keys) in a directory, excluding backup and staging files.
///
/// Returned keys are normalized to lowercase to match the invariant used by
/// [`Collection::read`], [`Collection::metadata`], and [`DirectFileAccess::file_path`], all of
/// which normalize the key before resolving it to a path. Without this normalization, a file
/// that ended up on disk with a mixed-case name (e.g. placed there outside of
/// [`Collection::write`], such as during initial provisioning) would be listed under its
/// original case but then fail to resolve via `metadata`/`read`/`file_path`, which look up the
/// lowercased path - causing spurious "key not found" errors on case-sensitive filesystems.
fn list_keys_in_dir(dir: &Path) -> Result<Vec<String>, StorageError> {
    let mut keys = Vec::new();

    if !dir.exists() {
        return Ok(keys);
    }

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        // Skip directories, backup files, and staging files.
        if !is_valid_key(&path) {
            continue;
        }

        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            keys.push(normalize_key(name));
        }
    }

    Ok(keys)
}
