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

use cda_interfaces::{
    runtime_update_api::{RuntimeReloaderPlugin, RuntimeUpdateError},
    storage_api::{CollectionName, Storage, Transaction},
};

use crate::operations::try_get_collection;

async fn swap_collection<S: Storage>(
    storage: &S,
    tx: &mut Transaction,
    current: &CollectionName,
    backup: &CollectionName,
    next_update: &CollectionName,
) -> Result<(), RuntimeUpdateError> {
    storage.copy_collection(tx, current, backup).await?;
    storage.copy_collection(tx, next_update, current).await?;
    Ok(storage.delete_collection(tx, next_update).await?)
}

/// Atomically applies pending MDD files from staging into the live database,
/// backing up current files first.
///
/// The 'apply' performs a **snapshot swap**: the entire `NextUpdate` collection replaces the
/// current collection. Files absent from `NextUpdate` are removed from current.
///
/// # Parameters
/// - `storage`: The storage backend.
/// - `reload_handler`: Notified after commit so the runtime can hot-reload databases.
///
/// # Errors
/// Returns [`RuntimeUpdateError`] if validation, a storage transaction, or the runtime reload
/// fails.
pub async fn execute_apply<S: Storage, R: RuntimeReloaderPlugin + ?Sized>(
    storage: &S,
    reload_handler: &R,
) -> Result<(), RuntimeUpdateError> {
    let mdd_next =
        try_get_collection(storage, &CollectionName::DiagnosticDatabaseNextUpdate).await?;
    if mdd_next.is_none() {
        return Err(RuntimeUpdateError::NoPendingUpdate);
    }

    // get_or_create_collection rejects creation while a transaction is active
    if mdd_next.is_some() {
        storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await?;
        storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabaseBackup)
            .await?;
    }
    let mut tx = storage.begin_transaction()?;

    if mdd_next.is_some() {
        swap_collection(
            storage,
            &mut tx,
            &CollectionName::DiagnosticDatabase,
            &CollectionName::DiagnosticDatabaseBackup,
            &CollectionName::DiagnosticDatabaseNextUpdate,
        )
        .await?;
    }

    tx.commit().await?;

    crate::operations::rollback::reload_after_database_swap(reload_handler).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use cda_interfaces::{
        runtime_update_api::RuntimeUpdateError,
        storage_api::{
            Collection as _, CollectionName, RandomAccessData as _, Storage as _, StorageError,
        },
    };

    use super::execute_apply;
    use crate::test_utils::{
        NoopReloadHandler, RecordingReloadHandler, init_collection, make_storage,
    };

    #[tokio::test]
    async fn apply_updates_current_and_creates_backup() {
        let (storage, _dir) = make_storage();

        // Seed current database
        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabase,
            &[("ecu1.mdd", b"old_data")],
        )
        .await;

        // Seed nextupdate
        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabaseNextUpdate,
            &[("ecu1.mdd", b"new_data")],
        )
        .await;

        execute_apply(&storage, &NoopReloadHandler).await.unwrap();

        // Current should have new data
        let db_col = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        let handle = db_col.read("ecu1.mdd").await.unwrap();
        let size = usize::try_from(handle.data_size().unwrap()).expect("size fits usize");
        let mut buf = vec![0u8; size];
        handle.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf, b"new_data");

        // Backup should have old data
        let backup_col = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabaseBackup)
            .await
            .unwrap();
        let handle = backup_col.read("ecu1.mdd").await.unwrap();
        let size = usize::try_from(handle.data_size().unwrap()).expect("size fits usize");
        let mut buf = vec![0u8; size];
        handle.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf, b"old_data");

        // Nextupdate should be gone (directory removed)
        let result = storage
            .get_collection(&CollectionName::DiagnosticDatabaseNextUpdate)
            .await;
        assert!(matches!(result, Err(StorageError::CollectionNotFound(_))));
    }

    #[tokio::test]
    async fn apply_empty_nextupdate_returns_no_pending_update() {
        let (storage, _dir) = make_storage();

        let result = execute_apply(&storage, &NoopReloadHandler).await;

        assert!(
            matches!(result, Err(RuntimeUpdateError::NoPendingUpdate)),
            "expected NoPendingUpdate, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn apply_atomicity_multiple_files() {
        let (storage, _dir) = make_storage();

        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabase,
            &[("ecu1.mdd", b"old1"), ("ecu2.mdd", b"old2")],
        )
        .await;

        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabaseNextUpdate,
            &[
                ("ecu1.mdd", b"new1"),
                ("ecu2.mdd", b"new2"),
                ("ecu3.mdd", b"new3"),
            ],
        )
        .await;

        execute_apply(&storage, &NoopReloadHandler).await.unwrap();

        // Current should have all new files
        let db_col = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        let keys = db_col.list().await.unwrap();
        assert_eq!(keys.len(), 3);

        let handle = db_col.read("ecu3.mdd").await.unwrap();
        let size = usize::try_from(handle.data_size().unwrap()).expect("size fits usize");
        let mut buf = vec![0u8; size];
        handle.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf, b"new3");

        // Backup should have old files
        let backup_col = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabaseBackup)
            .await
            .unwrap();
        let backup_keys = backup_col.list().await.unwrap();
        assert_eq!(backup_keys.len(), 2);

        // Nextupdate gone
        let result = storage
            .get_collection(&CollectionName::DiagnosticDatabaseNextUpdate)
            .await;
        assert!(matches!(result, Err(StorageError::CollectionNotFound(_))));
    }

    #[tokio::test]
    async fn apply_calls_reload_databases() {
        let (storage, _dir) = make_storage();

        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabaseNextUpdate,
            &[("ecu1.mdd", b"data")],
        )
        .await;

        let handler = RecordingReloadHandler::new();
        execute_apply(&storage, &handler).await.unwrap();

        let calls = handler.reload_calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "reload_databases should be called once");
    }

    #[tokio::test]
    async fn apply_empty_mdd_nextupdate_clears_diagnostic_database() {
        let (storage, _dir) = make_storage();

        // Seed current database with files
        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabase,
            &[("ecu1.mdd", b"data1"), ("ecu2.mdd", b"data2")],
        )
        .await;

        // Create DiagnosticDatabaseNextUpdate as initialized-but-empty (no files)
        storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabaseNextUpdate)
            .await
            .unwrap();

        execute_apply(&storage, &NoopReloadHandler).await.unwrap();

        // DiagnosticDatabase should now be empty (snapshot swap from empty NextUpdate)
        let db_col = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        let keys = db_col.list().await.unwrap();
        assert!(
            keys.is_empty(),
            "DiagnosticDatabase should be empty after applying empty NextUpdate, got: {keys:?}"
        );

        // Backup should have the old files
        let backup_col = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabaseBackup)
            .await
            .unwrap();
        let backup_keys = backup_col.list().await.unwrap();
        assert_eq!(backup_keys.len(), 2);

        // NextUpdate should be gone
        let result = storage
            .get_collection(&CollectionName::DiagnosticDatabaseNextUpdate)
            .await;
        assert!(matches!(result, Err(StorageError::CollectionNotFound(_))));
    }

    #[tokio::test]
    async fn apply_removes_file_absent_from_nextupdate() {
        let (storage, _dir) = make_storage();

        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabase,
            &[("ecu1.mdd", b"data1"), ("ecu2.mdd", b"data2")],
        )
        .await;

        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabaseNextUpdate,
            &[("ecu1.mdd", b"data1_updated")],
        )
        .await;

        execute_apply(&storage, &NoopReloadHandler).await.unwrap();

        let db_col = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        let keys = db_col.list().await.unwrap();
        assert_eq!(keys, vec!["ecu1.mdd"]);

        let handle = db_col.read("ecu1.mdd").await.unwrap();
        let size = usize::try_from(handle.data_size().unwrap()).expect("size fits usize");
        let mut buf = vec![0u8; size];
        handle.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf, b"data1_updated");
    }
}
