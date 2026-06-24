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

//! Storage Access API
//!
//! Provides an abstraction layer for storage access, allowing the CDA to interact with different
//! types of storage systems (e.g., local file system, databases) without being tightly coupled to
//! a specific implementation.
//!
//! Key design properties:
//! - **Collection-based key-value model**: Data is organized into named collections, each
//!   containing key-value entries with case-insensitive keys.
//! - **Transactional mutations**: All write operations require an exclusive `&mut Transaction`.
//!   Only one transaction may be active at a time.
//! - **Crash-safe transactions**: The transaction journal is persisted to a Write-Ahead Log (WAL)
//!   on disk. If a crash occurs mid-commit, the transaction is rolled back on next startup.
//! - **No read-your-writes**: Reads always return committed state, even during an open
//!   transaction.
//! - **Streaming I/O**: Writes accept a [`ReadableStream`] to avoid buffering large payloads in
//!   memory. Reads return a [`RandomAccessData`] handle for efficient positional access.

mod collection;
mod error;
mod io;
mod storage;
mod transaction;

pub use collection::{
    Collection,
    CollectionName,
    DirectFileAccess,
    Metadata,
    MetadataProperty,
};
pub use error::StorageError;
pub use io::{
    RandomAccessData,
    ReadableStream,
};
pub use storage::Storage;
pub use transaction::{
    Operation,
    Transaction,
    TransactionCommitter,
};
