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

//! Local filesystem storage backend for the CDA Storage Access API.
//!
//! This crate provides [`LocalStorage`], a crash-safe, transactional storage implementation
//! backed by the local filesystem. It implements the traits defined in
//! [`cda_interfaces::storage_api`].
//!
//! ## Directory layout
//!
//! ```text
//! {root}/
//! \-- collections/
//! \   \-- diagnostic_database/
//! \   \   \-- key_a
//! \   \   \-- key_b
//! \   \-- diagnostic_database_backup/
//! \-- journal/
//!     \-- transaction.wal
//!     \-- staging/
//!         \-- {uuid}.tmp
//! ```
//!
//! ## Usage
//!
//! ```rust,no_run
//! use cda_interfaces::storage_api::{Collection as _, CollectionName, Storage};
//! use cda_storage::LocalStorage;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let storage = LocalStorage::new("/tmp/cda-storage")?;
//!
//! // Read access -> no transaction needed.
//! let collection = storage.get_or_create_collection(&CollectionName::DiagnosticDatabase).await?;
//! let keys = collection.list().await?;
//!
//! // Write access -> requires a transaction.
//! let mut tx = storage.begin_transaction()?;
//! let mut data: &[u8] = b"hello world";
//! collection.write(&mut tx, "my_key", &mut data).await?;
//! tx.commit().await?;
//! # Ok(())
//! # }
//! ```

mod io;
mod local_collection;
mod local_storage;
mod paths;
pub(crate) mod recovery;
pub mod storage_seed;
/// Write-ahead log utilities. Exposed publicly for use in recovery tests.
pub mod wal;

pub use local_collection::LocalCollection;
pub use local_storage::LocalStorage;
