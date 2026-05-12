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

    /// A transaction-related error occurred (e.g., a transaction is already active).
    #[error("Transaction error: {0}")]
    TransactionError(String),

    /// The storage backend has no space left for the requested operation.
    #[error("No space left: {0}")]
    NoSpaceLeft(String),

    /// An I/O error occurred during a storage operation.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Any other error not covered by the variants above.
    #[error("Unknown error: {0}")]
    Other(String),
}
