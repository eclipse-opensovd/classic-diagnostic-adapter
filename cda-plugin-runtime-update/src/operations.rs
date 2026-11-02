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

use std::sync::Arc;

use cda_interfaces::{
    runtime_update_api::RuntimeUpdateError,
    storage_api::{CollectionName, Storage, StorageError, Transaction},
};

pub mod apply;
pub mod cleanup;
pub mod executions;
pub mod rollback;

pub(crate) async fn try_get_collection<S: Storage>(
    storage: &S,
    name: &CollectionName,
) -> Result<Option<Arc<S::CollectionHandle>>, RuntimeUpdateError> {
    match storage.get_collection(name).await {
        Ok(col) => Ok(Some(col)),
        Err(StorageError::CollectionNotFound(_)) => Ok(None),
        Err(e) => Err(RuntimeUpdateError::from(e)),
    }
}

pub(crate) async fn delete_collection_ignore_missing<S: Storage>(
    storage: &S,
    tx: &mut Transaction,
    name: &CollectionName,
) -> Result<(), RuntimeUpdateError> {
    match storage.delete_collection(tx, name).await {
        Ok(()) | Err(StorageError::CollectionNotFound(_)) => Ok(()),
        Err(e) => Err(RuntimeUpdateError::from(e)),
    }
}

#[cfg(test)]
mod tests {
    use cda_interfaces::storage_api::{CollectionName, Storage as _, StorageError};

    use super::{delete_collection_ignore_missing, try_get_collection};
    use crate::test_utils::{init_collection, make_storage};

    #[tokio::test]
    async fn try_get_collection_returns_some_when_collection_exists() {
        let (storage, _dir) = make_storage();
        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabase,
            &[("a.mdd", b"data")],
        )
        .await;

        let result = try_get_collection(&storage, &CollectionName::DiagnosticDatabase).await;

        assert!(result.unwrap().is_some());
    }

    #[tokio::test]
    async fn try_get_collection_returns_none_when_collection_missing() {
        let (storage, _dir) = make_storage();

        let result = try_get_collection(&storage, &CollectionName::DiagnosticDatabase).await;

        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_collection_ignore_missing_succeeds_when_collection_exists() {
        let (storage, _dir) = make_storage();
        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabase,
            &[("a.mdd", b"data")],
        )
        .await;

        let mut tx = storage.begin_transaction().unwrap();
        let result = delete_collection_ignore_missing(
            &storage,
            &mut tx,
            &CollectionName::DiagnosticDatabase,
        )
        .await;
        tx.commit().await.unwrap();

        assert!(result.is_ok());
        let check = storage
            .get_collection(&CollectionName::DiagnosticDatabase)
            .await;
        assert!(matches!(check, Err(StorageError::CollectionNotFound(_))));
    }

    #[tokio::test]
    async fn delete_collection_ignore_missing_is_ok_when_collection_absent() {
        let (storage, _dir) = make_storage();

        let mut tx = storage.begin_transaction().unwrap();
        let result = delete_collection_ignore_missing(
            &storage,
            &mut tx,
            &CollectionName::DiagnosticDatabase,
        )
        .await;
        tx.commit().await.unwrap();

        assert!(result.is_ok());
    }
}
