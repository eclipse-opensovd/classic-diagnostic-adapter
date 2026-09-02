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
    runtime_update_api::{ReloadFailure, RuntimeReloaderPlugin, RuntimeUpdateError},
    storage_api::{CollectionName, Storage, StorageError},
};

use crate::operations::delete_collection_ignore_missing;

async fn restore_from_backup<S: Storage>(
    storage: &S,
    backup: &CollectionName,
    current: &CollectionName,
    next_update: &CollectionName,
) -> Result<(), RuntimeUpdateError> {
    // Preserve B first. The storage interface cannot use a destination created
    // earlier in the same transaction as a later copy source, so this durable
    // shuttle commit precedes the atomic A/B replacement. A crash here leaves
    // both original current and backup untouched and an extra recoverable copy.
    let mut preserve = storage.begin_transaction()?;
    storage
        .copy_collection(&mut preserve, current, next_update)
        .await?;
    preserve.commit().await?;

    let mut swap = storage.begin_transaction()?;
    storage.copy_collection(&mut swap, backup, current).await?;
    storage
        .copy_collection(&mut swap, next_update, backup)
        .await?;
    delete_collection_ignore_missing(storage, &mut swap, next_update).await?;
    swap.commit().await?;
    Ok(())
}

/// Swaps backup A into current while preserving displaced current B as the new
/// backup, then clears the temporary next-update shuttle. Storage-only: a caller
/// needing A live prepares it afterwards. If A preparation fails, another swap
/// restores B and retains A as the deterministic rollback candidate.
///
/// # Errors
/// Returns [`RuntimeUpdateError::NoBackup`] if there is nothing to restore.
pub async fn restore_backup<S: Storage>(storage: &S) -> Result<(), RuntimeUpdateError> {
    match storage
        .get_collection(&CollectionName::DiagnosticDatabaseBackup)
        .await
    {
        Ok(_) => {}
        Err(StorageError::CollectionNotFound(_)) => return Err(RuntimeUpdateError::NoBackup),
        Err(error) => return Err(error.into()),
    }
    // The swap needs a source collection even on first recovery.
    storage
        .get_or_create_collection(&CollectionName::DiagnosticDatabase)
        .await?;

    restore_from_backup(
        storage,
        &CollectionName::DiagnosticDatabaseBackup,
        &CollectionName::DiagnosticDatabase,
        &CollectionName::DiagnosticDatabaseNextUpdate,
    )
    .await
}

pub(crate) async fn reload_after_database_swap<R: RuntimeReloaderPlugin + ?Sized>(
    reload_handler: &R,
) -> Result<(), ReloadFailure> {
    reload_handler.reload_databases().await
}

/// Roll back the entire update from the backup, then reload from it.
/// # Errors
/// Returns [`RuntimeUpdateError`] if the persistent restore or runtime reload fails.
pub async fn execute_rollback<S: Storage, R: RuntimeReloaderPlugin + ?Sized>(
    storage: &S,
    reload_handler: &R,
) -> Result<(), RuntimeUpdateError> {
    restore_backup(storage).await?;
    reload_after_database_swap(reload_handler).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use cda_interfaces::{
        runtime_update_api::{ReloadFailure, RuntimeUpdateError},
        storage_api::{
            Collection as _, CollectionName, RandomAccessData as _, Storage as _, StorageError,
        },
    };

    use super::execute_rollback;
    use crate::test_utils::{
        FailingReloadHandler, NoopReloadHandler, RecordingReloadHandler, init_collection,
        make_storage,
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
    async fn rollback_retains_diagnostic_database_backup_until_install_finishes() {
        let (storage, _dir) = make_storage();

        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabaseBackup,
            &[("ecu1.mdd", b"backup")],
        )
        .await;
        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabase,
            &[("current.mdd", b"current")],
        )
        .await;

        execute_rollback(&storage, &NoopReloadHandler)
            .await
            .unwrap();

        let backup_col = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabaseBackup)
            .await
            .unwrap();
        assert!(!backup_col.is_empty().await.unwrap());
    }

    #[tokio::test]
    async fn rollback_restores_present_empty_backup() {
        let (storage, _dir) = make_storage();
        storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabaseBackup)
            .await
            .unwrap();
        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabase,
            &[("current.mdd", b"current")],
        )
        .await;

        execute_rollback(&storage, &NoopReloadHandler)
            .await
            .unwrap();

        let current = storage
            .get_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        assert!(current.list().await.unwrap().is_empty());
        let backup = storage
            .get_collection(&CollectionName::DiagnosticDatabaseBackup)
            .await
            .unwrap();
        assert_eq!(backup.list().await.unwrap(), vec!["current.mdd"]);
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
            "expected NoBackup when the backup collection is absent, got: {result:?}"
        );
        assert!(matches!(
            storage
                .get_collection(&CollectionName::DiagnosticDatabaseBackup)
                .await,
            Err(StorageError::CollectionNotFound(_))
        ));
    }

    #[tokio::test]
    async fn failed_rollback_reload_reports_recovery_required_without_an_unproven_restore() {
        let (storage, _dir) = make_storage();
        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabaseBackup,
            &[("ecu1.mdd", b"backup")],
        )
        .await;
        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabase,
            &[("current.mdd", b"current")],
        )
        .await;

        let result = execute_rollback(&storage, &FailingReloadHandler).await;

        assert!(matches!(
            result,
            Err(RuntimeUpdateError::ReloadFailed(
                ReloadFailure::RecoveryRequired { .. }
            ))
        ));
        let current = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        assert_eq!(current.list().await.unwrap(), vec!["ecu1.mdd"]);
        let backup = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabaseBackup)
            .await
            .unwrap();
        assert_eq!(backup.list().await.unwrap(), vec!["current.mdd"]);
    }
}
