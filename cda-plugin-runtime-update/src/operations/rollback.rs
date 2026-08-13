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
    storage_api::{Collection, CollectionName, Storage, Transaction},
};

use crate::operations::{delete_collection_ignore_missing, reload_database_if_present};

async fn restore_from_backup<S: Storage, C: Collection>(
    storage: &S,
    tx: &mut Transaction,
    backup: &CollectionName,
    current: &CollectionName,
    next_update: &CollectionName,
    backup_col: &C,
) -> Result<(), RuntimeUpdateError> {
    storage.copy_collection(tx, backup, current).await?;
    delete_collection_ignore_missing(storage, tx, next_update).await?;
    backup_col.delete_all(tx).await?;
    Ok(())
}

/// Roll back the entire update from the backup.
/// # Errors
/// Returns [`RuntimeUpdateError`] if restore or reload fails.
pub async fn execute_rollback<S: Storage, R: RuntimeReloaderPlugin + ?Sized>(
    storage: &S,
    reload_handler: &R,
) -> Result<(), RuntimeUpdateError> {
    let mdd_backup_col = storage
        .get_or_create_collection(&CollectionName::DiagnosticDatabaseBackup)
        .await?;
    let mdd_backup_empty = mdd_backup_col.is_empty().await?;

    // Guard also checked synchronously in `start_execution` before the task is spawned,
    // so 404 is returned before 202 is sent. Kept here for correctness if called directly.
    if mdd_backup_empty {
        return Err(RuntimeUpdateError::NoBackup);
    }

    let mut tx = storage.begin_transaction()?;

    if !mdd_backup_empty {
        restore_from_backup(
            storage,
            &mut tx,
            &CollectionName::DiagnosticDatabaseBackup,
            &CollectionName::DiagnosticDatabase,
            &CollectionName::DiagnosticDatabaseNextUpdate,
            mdd_backup_col.as_ref(),
        )
        .await?;
    }

    tx.commit().await?;

    if !mdd_backup_empty {
        reload_database_if_present(storage, reload_handler, false).await?;
    }

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

    use super::execute_rollback;
    use crate::test_utils::{
        NoopReloadHandler, RecordingReloadHandler, init_collection, make_storage,
    };

    #[tokio::test]
    async fn rollback_restores_mdd_backup_to_current() {
        let (storage, _dir) = make_storage();

        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabaseBackup,
            &[("ecu1.mdd", b"backup_data")],
        )
        .await;

        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabase,
            &[("ecu1.mdd", b"current_data")],
        )
        .await;

        execute_rollback(&storage, &NoopReloadHandler)
            .await
            .unwrap();

        let db_col = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        let keys = db_col.list().await.unwrap();
        assert!(keys.contains(&"ecu1.mdd".to_string()));

        let handle = db_col.read("ecu1.mdd").await.unwrap();
        let size = usize::try_from(handle.data_size().unwrap()).expect("size fits usize");
        let mut buf = vec![0u8; size];
        handle.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf, b"backup_data");
    }

    #[tokio::test]
    async fn rollback_clears_diagnostic_database_next_update() {
        let (storage, _dir) = make_storage();

        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabaseBackup,
            &[("ecu1.mdd", b"backup")],
        )
        .await;

        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabaseNextUpdate,
            &[("ecu1.mdd", b"pending")],
        )
        .await;

        execute_rollback(&storage, &NoopReloadHandler)
            .await
            .unwrap();

        let result = storage
            .get_collection(&CollectionName::DiagnosticDatabaseNextUpdate)
            .await;
        assert!(
            matches!(result, Err(StorageError::CollectionNotFound(_))),
            "NextUpdate should be gone after rollback"
        );
    }

    #[tokio::test]
    async fn rollback_clears_diagnostic_database_backup() {
        let (storage, _dir) = make_storage();

        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabaseBackup,
            &[("ecu1.mdd", b"backup")],
        )
        .await;

        execute_rollback(&storage, &NoopReloadHandler)
            .await
            .unwrap();

        let backup_col = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabaseBackup)
            .await
            .unwrap();
        assert!(backup_col.is_empty().await.unwrap());
    }

    #[tokio::test]
    async fn rollback_with_empty_backup_returns_no_backup_error() {
        let (storage, _dir) = make_storage();

        let result = execute_rollback(&storage, &NoopReloadHandler).await;
        assert!(
            matches!(result, Err(RuntimeUpdateError::NoBackup)),
            "expected NoBackup, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn rollback_calls_reload_handler() {
        let (storage, _dir) = make_storage();

        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabaseBackup,
            &[("ecu1.mdd", b"backup")],
        )
        .await;

        let handler = RecordingReloadHandler::new();
        execute_rollback(&storage, &handler).await.unwrap();

        let calls = handler.reload_calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "reload_databases should be called once");
    }

    #[tokio::test]
    async fn rollback_no_backup_returns_error() {
        let (storage, _dir) = make_storage();

        let result = execute_rollback(&storage, &NoopReloadHandler).await;
        assert!(
            matches!(result, Err(RuntimeUpdateError::NoBackup)),
            "expected NoBackup when both backup collections are empty, got: {result:?}"
        );
    }
}
