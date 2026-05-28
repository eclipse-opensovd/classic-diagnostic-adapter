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
    path::{Path, PathBuf},
    sync::Arc,
};

use super::{
    error::StorageError,
    io::{RandomAccessData, ReadableStream},
    transaction::Transaction,
};

/// A named grouping of key-value entries in the storage system.
///
/// Well-known collection names are represented as enum variants. Custom names are supported
/// via [`CollectionName::Custom`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub enum CollectionName {
    /// The primary diagnostic database collection.
    DiagnosticDatabase,
    /// Staging area for a pending database update.
    DiagnosticDatabaseNextUpdate,
    /// Backup of the diagnostic database before an update.
    DiagnosticDatabaseBackup,
    /// Configuration collection for CDA settings.
    Configuration,
    /// Staging area for a pending configuration update.
    ConfigurationNextUpdate,
    /// Backup of the configuration before an update.
    ConfigurationBackup,
    /// A user-defined collection with an arbitrary name.
    Custom(String),
}

impl CollectionName {
    /// Returns a string representation suitable for use as a directory or bucket name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::DiagnosticDatabase => "diagnostic_database",
            Self::DiagnosticDatabaseNextUpdate => "diagnostic_database_next_update",
            Self::DiagnosticDatabaseBackup => "diagnostic_database_backup",
            Self::Configuration => "configuration",
            Self::ConfigurationNextUpdate => "configuration_next_update",
            Self::ConfigurationBackup => "configuration_backup",
            Self::Custom(name) => name.as_str(),
        }
    }
}

impl std::fmt::Display for CollectionName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Metadata about a single entry in a collection.
#[derive(Debug, Clone)]
pub struct Metadata {
    /// The key (name) of the entry.
    pub name: String,
    /// The size of the stored data in bytes.
    pub data_size: u64,
    /// Optional custom properties associated with this entry.
    pub custom_props: Vec<MetadataProperty>,
}

/// A single custom key-value property attached to entry metadata.
#[derive(Debug, Clone)]
pub struct MetadataProperty {
    /// The property key.
    pub key: String,
    /// The property value.
    pub value: String,
}

/// A named collection of key-value entries in the storage system.
///
/// Read operations do not require a transaction and always return committed state.
/// Mutation operations require an exclusive `&mut Transaction` reference.
///
/// All keys are to be treated **case-insensitively**
/// Implementations must normalize keys (e.g., `to_lowercase`) before any storage operation.
pub trait Collection: Send + Sync {
    /// Read the data for the given key, returning a random-access handle.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::KeyNotFound`] if the key does not exist.
    fn read(
        &self,
        key: &str,
    ) -> impl Future<Output = Result<Arc<impl RandomAccessData + 'static>, StorageError>> + Send;

    /// Retrieve metadata for the given key.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::KeyNotFound`] if the key does not exist.
    fn metadata(&self, key: &str) -> impl Future<Output = Result<Metadata, StorageError>> + Send;

    /// List all keys in this collection.
    ///
    /// The returned keys are in their normalized (lowercase) form.
    fn list(&self) -> impl Future<Output = Result<Vec<String>, StorageError>> + Send;

    /// Return the number of entries in this collection.
    fn len(&self) -> impl Future<Output = Result<usize, StorageError>> + Send;

    /// Return whether this collection is empty.
    fn is_empty(&self) -> impl Future<Output = Result<bool, StorageError>> + Send;

    /// Write data from a [`ReadableStream`] to the given key within a transaction.
    ///
    /// The data is streamed to a staging file and only applied on [`Transaction::commit`]. If a
    /// key with the same name already exists, it will be overwritten on commit.
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`] if the staging write fails.
    fn write(
        &self,
        tx: &mut Transaction,
        key: &str,
        data: &mut impl ReadableStream,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Mark a key for deletion within a transaction.
    ///
    /// The deletion is only applied on [`Transaction::commit`].
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::KeyNotFound`] if the key does not exist.
    fn delete(
        &self,
        tx: &mut Transaction,
        key: &str,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Mark all keys in this collection for deletion within a transaction.
    ///
    /// The deletions are only applied on [`Transaction::commit`].
    fn delete_all(
        &self,
        tx: &mut Transaction,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;
}

/// Provides direct filesystem access to collection entries.
///
/// This trait is intended for consumers that need long-lived, unguarded access to the underlying
/// files, typically for memory-mapped I/O. Unlike [`Collection::read`], these methods do **not**
/// acquire a read lock, so the caller is responsible for coordinating with transactions (e.g.,
/// evicting cached memory maps before committing an update that touches the collection).
///
/// Only implemented by storage backends that are backed by a real filesystem.
pub trait DirectFileAccess: Send + Sync {
    /// Returns the base directory path for this collection.
    ///
    /// Useful for callers that need to discover all files in the collection (e.g., enumerating
    /// MDD databases at startup for memory-mapped loading).
    fn dir_path(&self) -> &Path;

    /// Returns the filesystem path for the given key.
    ///
    /// The key is normalized (lowercased) before lookup.
    ///
    /// This does **not** acquire a read lock. The caller must ensure the file is not concurrently
    /// modified (e.g., by evicting cached handles before committing a transaction that touches
    /// this key).
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::KeyNotFound`] if the key does not exist in the collection.
    fn file_path(&self, key: &str) -> Result<PathBuf, StorageError>;
}
