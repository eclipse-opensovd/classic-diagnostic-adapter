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

/// Errors that can occur during storage operations.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// The requested collection does not exist.
    #[error("Collection not found: {0}")]
    CollectionNotFound(String),

    /// The requested key does not exist within a collection.
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    /// The caller does not have permission to perform the requested operation.
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Another transaction is already active (contention).
    #[error("Transaction busy: another transaction is already active")]
    TransactionBusy,

    /// A logical conflict within a transaction (e.g., duplicate collection).
    #[error("Transaction conflict: {0}")]
    TransactionConflict(String),

    /// The storage backend has no space left for the requested operation.
    #[error("No space left: {0}")]
    NoSpaceLeft(String),

    /// An I/O error occurred during a storage operation.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The storage data is corrupted beyond automatic recovery.
    ///
    /// This indicates that the on-disk state cannot be restored to a consistent snapshot.
    /// The caller should treat the affected storage as unusable and reprovision from scratch.
    #[error("Storage corruption: {0}")]
    Corruption(String),

    /// Any other error not covered by the variants above.
    #[error("Unknown error: {0}")]
    Other(String),
}

impl StorageError {
    #[must_use]
    pub fn map_io_error(err: std::io::Error, key: &str) -> Self {
        if err.kind() == std::io::ErrorKind::NotFound {
            StorageError::KeyNotFound(key.to_string())
        } else {
            StorageError::Io(err)
        }
    }
}
