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

// SPDX-License-Identifier: Apache-2.0
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

use std::sync::Arc;

use cda_interfaces::{
    runtime_update_api::{
        RuntimeFileReloadHandler,
        RuntimeUpdateError,
    },
    storage_api::{
        Collection,
        CollectionName,
        DirectFileAccess,
        Storage,
        StorageError,
        Transaction,
    },
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

pub(crate) async fn reload_configuration_if_present<S: Storage, R: RuntimeFileReloadHandler>(
    storage: &S,
    reload_handler: &R,
) -> Result<(), RuntimeUpdateError> {
    let config_col = storage
        .get_or_create_collection(&CollectionName::Configuration)
        .await?;
    let config_keys = config_col.list().await?;
    if let Some(first_key) = config_keys.first() {
        let path = config_col.file_path(first_key)?;
        reload_handler
            .reload_configuration(path)
            .await
            .map_err(|e| RuntimeUpdateError::ReloadFailed(e.to_string()))?;
    }
    Ok(())
}

pub(crate) async fn reload_database_if_present<S: Storage, R: RuntimeFileReloadHandler>(
    storage: &S,
    reload_handler: &R,
    decompress: bool,
) -> Result<(), RuntimeUpdateError> {
    let db_col = storage
        .get_or_create_collection(&CollectionName::DiagnosticDatabase)
        .await?;

    let mdd_paths: Vec<_> = db_col
        .list()
        .await
        .map(|files| {
            files
                .iter()
                .filter_map(|key| match db_col.file_path(key) {
                    Ok(p) => Some(p),
                    Err(e) => {
                        tracing::warn!(key = %key, error = %e, "Failed to resolve MDD path, skipping");
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    if decompress {
        for mdd_path in &mdd_paths {
            if let Some(path_str) = mdd_path.to_str() {
                if let Err(e) = cda_database::update_mdd_uncompressed(path_str) {
                    tracing::warn!(
                        mdd_file = %mdd_path.display(),
                        error = %e,
                        "Failed to decompress MDD file after apply, continuing"
                    );
                }
            } else {
                tracing::error!(
                    mdd_file = %mdd_path.display(),
                    "MDD path is not valid UTF-8, skipping decompression",
                );
            }
        }
    }

    reload_handler
        .reload_databases(mdd_paths)
        .await
        .map_err(|e| RuntimeUpdateError::ReloadFailed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use cda_interfaces::storage_api::{
        CollectionName,
        Storage as _,
        StorageError,
    };

    use super::{
        delete_collection_ignore_missing,
        reload_configuration_if_present,
        reload_database_if_present,
        try_get_collection,
    };
    use crate::test_utils::{
        RecordingReloadHandler,
        init_collection,
        make_storage,
        write_test_file,
    };

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

    #[tokio::test]
    async fn reload_configuration_calls_handler_when_config_file_present() {
        let (storage, _dir) = make_storage();
        write_test_file(
            &storage,
            &CollectionName::Configuration,
            "opensovd-cda.toml",
            b"[server]\nport = 8080\n",
        )
        .await;

        let handler = RecordingReloadHandler::new();
        reload_configuration_if_present(&storage, &handler)
            .await
            .unwrap();

        let calls = handler.config_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
    }

    #[tokio::test]
    async fn reload_configuration_does_not_call_handler_when_collection_empty() {
        let (storage, _dir) = make_storage();
        storage
            .get_or_create_collection(&CollectionName::Configuration)
            .await
            .unwrap();

        let handler = RecordingReloadHandler::new();
        reload_configuration_if_present(&storage, &handler)
            .await
            .unwrap();

        let calls = handler.config_calls.lock().unwrap();
        assert!(calls.is_empty());
    }

    #[tokio::test]
    async fn reload_configuration_creates_collection_and_is_ok_when_absent() {
        let (storage, _dir) = make_storage();

        let handler = RecordingReloadHandler::new();
        let result = reload_configuration_if_present(&storage, &handler).await;

        assert!(result.is_ok());
        let calls = handler.config_calls.lock().unwrap();
        assert!(calls.is_empty());
    }

    #[tokio::test]
    async fn reload_database_calls_handler_with_all_mdd_paths() {
        let (storage, _dir) = make_storage();
        write_test_file(
            &storage,
            &CollectionName::DiagnosticDatabase,
            "ecu1.mdd",
            b"mdd_data_1",
        )
        .await;
        write_test_file(
            &storage,
            &CollectionName::DiagnosticDatabase,
            "ecu2.mdd",
            b"mdd_data_2",
        )
        .await;

        let handler = RecordingReloadHandler::new();
        reload_database_if_present(&storage, &handler, false)
            .await
            .unwrap();

        let calls = handler.reload_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls.first().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn reload_database_calls_handler_with_empty_vec_when_collection_empty() {
        let (storage, _dir) = make_storage();
        storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();

        let handler = RecordingReloadHandler::new();
        reload_database_if_present(&storage, &handler, false)
            .await
            .unwrap();

        let calls = handler.reload_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert!(calls.first().unwrap().is_empty());
    }

    #[tokio::test]
    async fn reload_database_creates_collection_and_calls_handler_when_absent() {
        let (storage, _dir) = make_storage();

        let handler = RecordingReloadHandler::new();
        let result = reload_database_if_present(&storage, &handler, false).await;

        assert!(result.is_ok());
        let calls = handler.reload_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert!(calls.first().unwrap().is_empty());
    }
}
