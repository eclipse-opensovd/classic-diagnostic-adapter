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
pub(crate) struct LocalCollection {
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
}

/// Normalize a key to lowercase for case-insensitive storage.
fn normalize_key(key: &str) -> String {
    key.to_lowercase()
}

impl Collection for LocalCollection {
    async fn read(&self, key: &str) -> Result<Arc<impl RandomAccessData + 'static>, StorageError> {
        let key = normalize_key(key);
        let path = self.key_path(&key)?;

        let guard = io::acquire_read_lock(&self.data_lock).await;

        let file = std::fs::File::open(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::KeyNotFound(key.clone())
            } else {
                StorageError::Io(e)
            }
        })?;

        let metadata = file.metadata()?;
        let size = metadata.len();

        Ok(Arc::new(io::LocalRandomAccessData::new(file, size, guard)))
    }

    async fn metadata(&self, key: &str) -> Result<Metadata, StorageError> {
        let key = normalize_key(key);
        let path = self.key_path(&key)?;

        let _guard = io::acquire_read_lock(&self.data_lock).await;

        let fs_meta = tokio::fs::metadata(&path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::KeyNotFound(key.clone())
            } else {
                StorageError::Io(e)
            }
        })?;

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
        let path = self.key_path(&key)?;
        if !path.exists() {
            return Err(StorageError::KeyNotFound(key));
        }
        Ok(path)
    }
}

/// List all file names (keys) in a directory, excluding backup and staging files.
fn list_keys_in_dir(dir: &Path) -> Result<Vec<String>, StorageError> {
    let mut keys = Vec::new();

    if !dir.exists() {
        return Ok(keys);
    }

    let bak_ext = std::ffi::OsStr::new(crate::recovery::BACKUP_EXTENSION);
    let tmp_ext = std::ffi::OsStr::new(crate::recovery::STAGING_EXTENSION);

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        // Skip directories, backup files, and staging files.
        if path.is_dir() || path.extension() == Some(bak_ext) || path.extension() == Some(tmp_ext) {
            continue;
        }

        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            keys.push(name.to_string());
        }
    }

    Ok(keys)
}
