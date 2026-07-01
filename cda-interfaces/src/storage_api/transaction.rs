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
    path::{Path, PathBuf},
    sync::Arc,
};

use async_trait::async_trait;

use super::{collection::CollectionName, error::StorageError};

/// A recorded operation in the transaction journal.
///
/// Operations reference staged files on disk rather than holding data in memory, so even large
/// writes only cost a few hundred bytes of journal metadata.
#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub enum Operation {
    /// Write data from a staging file into a collection entry.
    Write {
        /// The target collection.
        collection: CollectionName,
        /// The key (already normalized to lowercase).
        key: String,
        /// Path to the staged temporary file holding the data.
        staged_path: String,
    },
    /// Delete a single key from a collection.
    Delete {
        /// The target collection.
        collection: CollectionName,
        /// The key to delete (already normalized to lowercase).
        key: String,
    },
    /// Delete all keys from a collection.
    DeleteAll {
        /// The target collection.
        collection: CollectionName,
    },
    /// Create a new, empty collection.
    CreateCollection {
        /// The name of the collection to create.
        name: CollectionName,
    },
    /// Delete an entire collection and all its entries.
    DeleteCollection {
        /// The name of the collection to delete.
        name: CollectionName,
    },
    /// Copy all entries from one collection to another.
    CopyCollection {
        /// The source collection.
        source: CollectionName,
        /// The destination collection.
        dest: CollectionName,
    },
}

/// Callback trait that the storage backend implements to apply or discard a transaction.
///
/// The [`Transaction`] struct holds an `Arc<dyn TransactionCommitter>` so it can call back into
/// the storage backend during commit and drop without the `Transaction` itself needing to know
/// about the concrete storage implementation.
/// Uses `async_trait` to be dyn compatible.
#[async_trait]
pub trait TransactionCommitter: Send + Sync {
    /// Apply all recorded operations atomically.
    ///
    /// Called by [`Transaction::commit`]. The implementation must:
    /// 1. Acquire exclusive access (write lock) to prevent concurrent reads.
    /// 2. Apply each operation, creating `.bak` backups for rollback.
    /// 3. Clean up staging files and the journal on success.
    /// 4. Release the active-transaction flag.
    async fn apply(
        &self,
        operations: Vec<Operation>,
        journal_path: PathBuf,
    ) -> Result<(), StorageError>;

    /// Discard all staged data and the journal file.
    ///
    /// Called on explicit [`Transaction::rollback`] or implicit rollback via [`Drop`].
    /// Must also release the active-transaction flag.
    fn discard(&self, staging_dir: &Path, journal_path: &Path);
}

/// A transaction that records storage mutations and applies them atomically on commit.
///
/// Only one `Transaction` may exist at a time per [`Storage`](super::Storage) instance. Attempting
/// to begin a second transaction while one is active will return
/// [`StorageError::TransactionBusy`].
///
/// ## Lifecycle
///
/// 1. Obtain via [`Storage::begin_transaction`](super::Storage::begin_transaction).
/// 2. Pass `&mut Transaction` to [`Collection`](super::Collection) mutation methods or
///    [`Storage`](super::Storage) collection-management methods.
/// 3. Call [`commit()`](Transaction::commit) to atomically apply all recorded operations.
/// 4. If the `Transaction` is dropped without calling `commit()`, all recorded operations are
///    discarded (implicit rollback).
///
/// ## Crash safety
///
/// The journal is persisted to a WAL file on disk. If the process crashes mid-commit, the storage
/// backend will detect the stale journal on next startup and roll back any partially applied
/// operations.
pub struct Transaction {
    /// In-memory record of all operations recorded so far.
    pub(crate) operations: Vec<Operation>,
    /// Path to the on-disk WAL file for crash recovery.
    pub(crate) journal_path: PathBuf,
    /// Directory where staging files for writes are stored.
    pub(crate) staging_dir: PathBuf,
    /// Whether `commit()` has been called. Prevents double-cleanup on drop.
    pub(crate) committed: bool,
    /// Handle back to the storage backend for applying or discarding operations.
    pub(crate) committer: Arc<dyn TransactionCommitter>,
}

impl Transaction {
    /// Create a new transaction.
    ///
    /// This should only be called by [`Storage`](super::Storage) implementations. End users
    /// should obtain transactions via
    /// [`Storage::begin_transaction`](super::Storage::begin_transaction).
    #[must_use]
    pub fn new(
        journal_path: PathBuf,
        staging_dir: PathBuf,
        committer: Arc<dyn TransactionCommitter>,
    ) -> Self {
        Self {
            operations: Vec::new(),
            journal_path,
            staging_dir,
            committed: false,
            committer,
        }
    }

    /// Apply all recorded operations atomically.
    ///
    /// This acquires exclusive access to the storage backend, applies all operations from the
    /// journal, and cleans up staging files. After this call, all mutations are visible to
    /// subsequent reads.
    ///
    /// Consumes `self` so the transaction cannot be reused after commit.
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`] if any operation fails during application. On failure,
    /// partially applied operations are rolled back automatically.
    pub async fn commit(mut self) -> Result<(), StorageError> {
        self.committed = true;
        let operations = std::mem::take(&mut self.operations);
        let journal_path = self.journal_path.clone();
        self.committer.apply(operations, journal_path).await
    }

    /// Explicitly discard all recorded operations.
    ///
    /// This deletes all staging files and the journal. Equivalent to simply dropping the
    /// `Transaction`, but makes the intent explicit in calling code.
    pub fn rollback(self) {
        // Drop will handle cleanup via the `committed` flag being false.
        drop(self);
    }

    /// Returns the path to the staging directory for this transaction.
    ///
    /// Used by [`Collection`](super::Collection) implementations to write staging files.
    #[must_use]
    pub fn staging_dir(&self) -> &Path {
        &self.staging_dir
    }

    /// Record an operation in the journal.
    ///
    /// The operation is appended to the in-memory list. Callers (i.e., [`Collection`] and
    /// [`Storage`] implementations) are responsible for persisting the operation to the WAL
    /// file as well.
    pub fn record(&mut self, operation: Operation) {
        self.operations.push(operation);
    }

    /// Returns the path to the WAL file for this transaction.
    #[must_use]
    pub fn journal_path(&self) -> &Path {
        &self.journal_path
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        if !self.committed {
            self.committer
                .discard(&self.staging_dir, &self.journal_path);
        }
    }
}
