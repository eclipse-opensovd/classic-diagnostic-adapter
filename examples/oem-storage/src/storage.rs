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

//! The storage backend, and the update plugin built over it.
//!
//! Note what is *not* reimplemented: staging, apply, rollback and cleanup all
//! stay CDA's. [`create_update_plugin_with`] takes the standard plugin and swaps
//! only the collaborator being demonstrated.
//!
//! # Backends must be file-backed
//!
//! Whatever the system of record, a backend must expose each file at a
//! filesystem path through `DirectFileAccess::file_path`: CDA memory-maps
//! diagnostic databases (ADR-003), so the reload contract is expressed in
//! `PathBuf` and the loader reads through the page cache rather than through
//! this trait. A database- or object-store-backed implementation must
//! materialise files locally before they can be applied.

use std::sync::Arc;

use cda_interfaces::{
    runtime_update_api::{RuntimeFileInspector, RuntimeFilesUpdatePlugin},
    storage_api::{CollectionName, Storage, StorageError, Transaction},
};
use cda_plugin_security::DefaultSecurityPluginData;
use cda_storage::{LocalCollection, LocalStorage};
use opensovd_cda_lib::{
    AppError,
    mdd_inspector::MddFileInspector,
    setup::{UpdateLockState, UpdatePluginContext},
    update::create_update_plugin_with,
    update_security::DefaultUpdateSecurityHandler,
};

/// Storage backend that records every collection access before delegating.
///
/// Delegating to [`LocalStorage`] keeps the example short while still naming
/// every method of the [`Storage`] contract, so a signature change fails here.
struct AuditedStorage {
    inner: LocalStorage,
}

impl AuditedStorage {
    fn new(path: &str) -> Result<Self, StorageError> {
        Ok(Self {
            inner: LocalStorage::new(path)?,
        })
    }

    /// Stands in for whatever an OEM audit trail would record.
    fn audit(operation: &str, name: &CollectionName) {
        tracing::debug!(operation, collection = ?name, "runtime-update storage access");
    }
}

impl Storage for AuditedStorage {
    type CollectionHandle = LocalCollection;

    async fn get_collection(
        &self,
        name: &CollectionName,
    ) -> Result<Arc<Self::CollectionHandle>, StorageError> {
        Self::audit("get_collection", name);
        self.inner.get_collection(name).await
    }

    async fn get_or_create_collection(
        &self,
        name: &CollectionName,
    ) -> Result<Arc<Self::CollectionHandle>, StorageError> {
        Self::audit("get_or_create_collection", name);
        self.inner.get_or_create_collection(name).await
    }

    fn begin_transaction(&self) -> Result<Transaction, StorageError> {
        self.inner.begin_transaction()
    }

    async fn create_collection(
        &self,
        tx: &mut Transaction,
        name: &CollectionName,
    ) -> Result<Arc<Self::CollectionHandle>, StorageError> {
        Self::audit("create_collection", name);
        self.inner.create_collection(tx, name).await
    }

    async fn delete_collection(
        &self,
        tx: &mut Transaction,
        name: &CollectionName,
    ) -> Result<(), StorageError> {
        Self::audit("delete_collection", name);
        self.inner.delete_collection(tx, name).await
    }

    async fn copy_collection(
        &self,
        tx: &mut Transaction,
        source: &CollectionName,
        dest: &CollectionName,
    ) -> Result<(), StorageError> {
        Self::audit("copy_collection", source);
        self.inner.copy_collection(tx, source, dest).await
    }
}

/// Builds the standard update plugin over the custom backend.
///
/// # Errors
/// Returns [`AppError`] when the backend cannot be opened.
pub async fn build_update_plugin(
    context: UpdatePluginContext,
) -> Result<impl RuntimeFilesUpdatePlugin, AppError> {
    let storage = Arc::new(
        AuditedStorage::new(&context.storage_dir)
            .map_err(|error| AppError::InitializationFailed(error.to_string()))?,
    );

    // Policy and database format stay CDA's; only storage is ours.
    let inspector: Arc<dyn RuntimeFileInspector> = Arc::new(MddFileInspector);
    let security = Arc::new(DefaultUpdateSecurityHandler::<
        UpdateLockState,
        DefaultSecurityPluginData,
    >::new(Arc::clone(&inspector)));

    Ok(create_update_plugin_with(
        context, storage, security, inspector,
    ))
}
