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

//! The process's storage, handed out before it is opened.

use std::sync::{Arc, OnceLock};

use cda_interfaces::storage_api::{CollectionName, Storage, StorageError, Transaction};
use cda_storage::LocalStorage;

/// The one [`LocalStorage`] of the process, available to its users before it
/// is opened.
///
/// Opening waits for the storage to be mounted, and that wait must not keep
/// the webserver from answering health requests. The port opens only once
/// every component is constructed, so the components that use the storage get
/// this handle at construction and the storage is mounted into it later, once
/// the port is open.
///
/// Until then every operation fails with [`StorageError::Unavailable`], never
/// with [`StorageError::CollectionNotFound`]: callers read an absent
/// collection as "nothing stored", which an unmounted storage does not say.
#[derive(Default)]
pub struct MountedStorage {
    storage: OnceLock<Arc<LocalStorage>>,
}

impl MountedStorage {
    /// A handle whose storage is not mounted yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A handle over a storage that is already open.
    #[must_use]
    pub fn mounted(storage: Arc<LocalStorage>) -> Self {
        let mounted = Self::new();
        mounted.mount(storage);
        mounted
    }

    /// Makes `storage` the one every operation goes to.
    ///
    /// The storage is mounted once. A second mount keeps the first storage, so
    /// nothing ever switches the storage underneath a running transaction.
    pub(crate) fn mount(&self, storage: Arc<LocalStorage>) {
        if self.storage.set(storage).is_err() {
            tracing::warn!("Storage is already mounted, keeping the first one");
        }
    }

    /// The opened storage.
    ///
    /// # Errors
    /// Returns [`StorageError::Unavailable`] while the storage is not mounted.
    pub fn local(&self) -> Result<&Arc<LocalStorage>, StorageError> {
        self.storage
            .get()
            .ok_or_else(|| StorageError::Unavailable("storage is not mounted yet".to_owned()))
    }
}

impl Storage for MountedStorage {
    type CollectionHandle = <LocalStorage as Storage>::CollectionHandle;

    async fn get_collection(
        &self,
        name: &CollectionName,
    ) -> Result<Arc<Self::CollectionHandle>, StorageError> {
        self.local()?.get_collection(name).await
    }

    async fn get_or_create_collection(
        &self,
        name: &CollectionName,
    ) -> Result<Arc<Self::CollectionHandle>, StorageError> {
        self.local()?.get_or_create_collection(name).await
    }

    fn begin_transaction(&self) -> Result<Transaction, StorageError> {
        self.local()?.begin_transaction()
    }

    async fn create_collection(
        &self,
        tx: &mut Transaction,
        name: &CollectionName,
    ) -> Result<Arc<Self::CollectionHandle>, StorageError> {
        self.local()?.create_collection(tx, name).await
    }

    async fn delete_collection(
        &self,
        tx: &mut Transaction,
        name: &CollectionName,
    ) -> Result<(), StorageError> {
        self.local()?.delete_collection(tx, name).await
    }

    async fn copy_collection(
        &self,
        tx: &mut Transaction,
        source: &CollectionName,
        dest: &CollectionName,
    ) -> Result<(), StorageError> {
        self.local()?.copy_collection(tx, source, dest).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unmounted_storage_is_unavailable_rather_than_empty() {
        let storage = MountedStorage::new();

        let collection = storage
            .get_collection(&CollectionName::DiagnosticDatabase)
            .await;

        assert!(matches!(collection, Err(StorageError::Unavailable(_))));
        assert!(matches!(
            storage.begin_transaction(),
            Err(StorageError::Unavailable(_))
        ));
    }

    #[tokio::test]
    async fn mounted_storage_reaches_the_local_storage() {
        let dir = tempfile::tempdir().expect("storage dir");
        let storage = MountedStorage::new();
        storage.mount(Arc::new(LocalStorage::new(dir.path()).expect("storage")));

        let collection = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await;

        assert!(collection.is_ok());
    }
}
