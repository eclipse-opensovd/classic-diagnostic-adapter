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
    runtime_update_api::RuntimeUpdateError,
    storage_api::{CollectionName, Storage, StorageError},
};

use super::delete_collection_ignore_missing;

async fn restore_from_backup<S: Storage>(storage: &S) -> Result<(), RuntimeUpdateError> {
    // The rollback collection holds the displaced current B while the two trade places. The
    // caller materializes it beforehand because `copy_collection` validates its source when
    // the operation is staged rather than when the transaction commits, so a
    // collection that only the preceding copy would create cannot serve as a source.
    let mut swap = storage.begin_transaction()?;
    storage
        .copy_collection(
            &mut swap,
            &CollectionName::DiagnosticDatabase,
            &CollectionName::DiagnosticDatabaseRollback,
        )
        .await?;
    storage
        .copy_collection(
            &mut swap,
            &CollectionName::DiagnosticDatabaseBackup,
            &CollectionName::DiagnosticDatabase,
        )
        .await?;
    storage
        .copy_collection(
            &mut swap,
            &CollectionName::DiagnosticDatabaseRollback,
            &CollectionName::DiagnosticDatabaseBackup,
        )
        .await?;
    storage
        .delete_collection(&mut swap, &CollectionName::DiagnosticDatabaseRollback)
        .await?;
    swap.commit().await?;
    Ok(())
}

/// Swaps backup A into current while preserving displaced current B as the new
/// backup, then clears the rollback collection. One transaction, so a crash leaves
/// the state either fully before or fully after it. It is an involution on
/// (current, backup): running it twice returns to the starting state, which is how a
/// rejected rollback recovers, B being the only copy of the set that still worked.
/// A staged [`CollectionName::DiagnosticDatabaseNextUpdate`] is deliberately
/// untouched here; only a rollback that completes clears it. Storage-only: a caller
/// needing A live prepares it afterwards. A rejected apply recovers differently, see
/// [`restore_backup_and_restage_rejected`].
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
    // Both serve as copy sources in the swap, and `get_or_create_collection` refuses
    // to create while a transaction is active, so they are materialized up front:
    // current can be absent on first recovery, the rollback collection on every run.
    storage
        .get_or_create_collection(&CollectionName::DiagnosticDatabase)
        .await?;
    storage
        .get_or_create_collection(&CollectionName::DiagnosticDatabaseRollback)
        .await?;

    restore_from_backup(storage).await
}

/// Returns the rejected set to staging so the operator can correct and reapply it,
/// and restores the previously live set from the backup. The backup is left alone, so
/// it keeps naming the last known good state. One transaction: current is read before
/// it is overwritten, and the backup is read while still intact. Overwrites
/// [`CollectionName::DiagnosticDatabaseNextUpdate`], which the apply has already
/// consumed; a rejected rollback preserves it instead, see [`restore_backup`].
///
/// # Errors
/// Returns [`RuntimeUpdateError::NoBackup`] if there is nothing to restore.
pub async fn restore_backup_and_restage_rejected<S: Storage>(
    storage: &S,
) -> Result<(), RuntimeUpdateError> {
    match storage
        .get_collection(&CollectionName::DiagnosticDatabaseBackup)
        .await
    {
        Ok(_) => {}
        Err(StorageError::CollectionNotFound(_)) => return Err(RuntimeUpdateError::NoBackup),
        Err(error) => return Err(error.into()),
    }
    // Current is a copy source below, and `get_or_create_collection` refuses to create
    // while a transaction is active, so it is materialized up front: `copy_collection`
    // validates its source when the operation is staged, not when it commits.
    storage
        .get_or_create_collection(&CollectionName::DiagnosticDatabase)
        .await?;

    let mut tx = storage.begin_transaction()?;
    storage
        .copy_collection(
            &mut tx,
            &CollectionName::DiagnosticDatabase,
            &CollectionName::DiagnosticDatabaseNextUpdate,
        )
        .await?;
    storage
        .copy_collection(
            &mut tx,
            &CollectionName::DiagnosticDatabaseBackup,
            &CollectionName::DiagnosticDatabase,
        )
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Discards the staged set once a rollback's databases are live.
///
/// Separate from [`restore_backup`] on purpose: a rollback is only committed
/// once the runtime has accepted the restored database, and discarding the
/// staged update before that would leave a rejected rollback partially applied,
/// because recovering from one swaps current and backup back.
///
/// # Errors
/// Returns [`RuntimeUpdateError`] if the storage transaction fails.
pub async fn discard_staged<S: Storage>(storage: &S) -> Result<(), RuntimeUpdateError> {
    let mut tx = storage.begin_transaction()?;
    delete_collection_ignore_missing(
        storage,
        &mut tx,
        &CollectionName::DiagnosticDatabaseNextUpdate,
    )
    .await?;
    tx.commit().await?;
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

    use super::{discard_staged, restore_backup, restore_backup_and_restage_rejected};
    use crate::test_utils::{init_collection, make_storage};

    async fn read_file(
        storage: &cda_storage::LocalStorage,
        name: &CollectionName,
        key: &str,
    ) -> Vec<u8> {
        let collection = storage.get_collection(name).await.unwrap();
        let handle = collection.read(key).await.unwrap();
        let size = usize::try_from(handle.data_size().unwrap()).expect("size fits usize");
        let mut buf = vec![0u8; size];
        handle.read_at(0, &mut buf).unwrap();
        buf
    }

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

        restore_backup(&storage).await.unwrap();

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

    /// Only a rollback that the runtime accepted clears the staged set, so
    /// restoring the backup on its own must leave it in place.
    #[tokio::test]
    async fn restoring_the_backup_leaves_the_staged_set_alone() {
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

        restore_backup(&storage).await.unwrap();

        assert_eq!(
            read_file(
                &storage,
                &CollectionName::DiagnosticDatabaseNextUpdate,
                "ecu1.mdd"
            )
            .await,
            b"pending"
        );
    }

    #[tokio::test]
    async fn discarding_the_staged_set_clears_diagnostic_database_next_update() {
        let (storage, _dir) = make_storage();
        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabaseNextUpdate,
            &[("ecu1.mdd", b"pending")],
        )
        .await;

        discard_staged(&storage).await.unwrap();

        let result = storage
            .get_collection(&CollectionName::DiagnosticDatabaseNextUpdate)
            .await;
        assert!(
            matches!(result, Err(StorageError::CollectionNotFound(_))),
            "NextUpdate should be gone once the rollback is committed"
        );
    }

    #[tokio::test]
    async fn discarding_an_absent_staged_set_succeeds() {
        let (storage, _dir) = make_storage();

        discard_staged(&storage).await.unwrap();
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

        restore_backup(&storage).await.unwrap();

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

        restore_backup(&storage).await.unwrap();

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
    async fn rollback_no_backup_returns_error() {
        let (storage, _dir) = make_storage();

        let result = restore_backup(&storage).await;
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

    /// The swap is an involution, so running it twice returns to the starting
    /// state. That is what makes it usable as the undo of a rollback whose load
    /// was rejected.
    #[tokio::test]
    async fn restoring_the_backup_twice_returns_to_the_starting_state() {
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

        restore_backup(&storage).await.unwrap();
        restore_backup(&storage).await.unwrap();

        let current = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        assert_eq!(current.list().await.unwrap(), vec!["current.mdd"]);
        let backup = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabaseBackup)
            .await
            .unwrap();
        assert_eq!(backup.list().await.unwrap(), vec!["ecu1.mdd"]);
    }

    /// A swap that failed mid-transaction leaves the internal rollback collection behind.
    /// The next rollback must tolerate it: it is re-created with `get_or_create` and
    /// its stale contents are replaced by the first copy.
    #[tokio::test]
    async fn rollback_tolerates_a_leftover_rollback_collection() {
        let (storage, _dir) = make_storage();
        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabaseRollback,
            &[("stale.mdd", b"stale")],
        )
        .await;
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

        restore_backup(&storage).await.unwrap();

        let current = storage
            .get_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        assert_eq!(current.list().await.unwrap(), vec!["ecu1.mdd"]);
        let backup = storage
            .get_collection(&CollectionName::DiagnosticDatabaseBackup)
            .await
            .unwrap();
        assert_eq!(backup.list().await.unwrap(), vec!["ecu1.mdd"]);
        assert!(
            matches!(
                storage
                    .get_collection(&CollectionName::DiagnosticDatabaseRollback)
                    .await,
                Err(StorageError::CollectionNotFound(_))
            ),
            "the rollback collection must not survive the rollback"
        );
    }

    /// A rejected apply restages the rejected set, restores the previously live
    /// set from the backup, and leaves the backup naming the last known good state.
    #[tokio::test]
    async fn restage_returns_rejected_current_to_next_update_and_keeps_backup() {
        let (storage, _dir) = make_storage();
        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabase,
            &[("ecu1.mdd", b"rejected")],
        )
        .await;
        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabaseBackup,
            &[("ecu1.mdd", b"good")],
        )
        .await;

        restore_backup_and_restage_rejected(&storage).await.unwrap();

        assert_eq!(
            read_file(&storage, &CollectionName::DiagnosticDatabase, "ecu1.mdd").await,
            b"good"
        );
        assert_eq!(
            read_file(
                &storage,
                &CollectionName::DiagnosticDatabaseBackup,
                "ecu1.mdd"
            )
            .await,
            b"good"
        );
        assert_eq!(
            read_file(
                &storage,
                &CollectionName::DiagnosticDatabaseNextUpdate,
                "ecu1.mdd"
            )
            .await,
            b"rejected"
        );
        assert!(
            matches!(
                storage
                    .get_collection(&CollectionName::DiagnosticDatabaseRollback)
                    .await,
                Err(StorageError::CollectionNotFound(_))
            ),
            "restaging needs no temporary collection"
        );
    }

    #[tokio::test]
    async fn restage_without_backup_returns_no_backup() {
        let (storage, _dir) = make_storage();
        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabase,
            &[("ecu1.mdd", b"rejected")],
        )
        .await;

        let result = restore_backup_and_restage_rejected(&storage).await;

        assert!(
            matches!(result, Err(RuntimeUpdateError::NoBackup)),
            "expected NoBackup when the backup collection is absent, got: {result:?}"
        );
        assert_eq!(
            read_file(&storage, &CollectionName::DiagnosticDatabase, "ecu1.mdd").await,
            b"rejected",
            "a refused restage must not touch the live database"
        );
    }
}
