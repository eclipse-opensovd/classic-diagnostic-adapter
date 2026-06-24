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

use cda_interfaces::{
    runtime_update_api::RuntimeUpdateError,
    storage_api::{
        Collection as _,
        CollectionName,
        Storage,
    },
};

use super::delete_collection_ignore_missing;

/// Clear all staging and backup collections atomically.
///
/// Deletes the `NextUpdate` collections entirely and clears all entries from the backup collections
/// in a single transaction:
/// - [`CollectionName::DiagnosticDatabaseNextUpdate`] - deleted (collection removed)
/// - [`CollectionName::DiagnosticDatabaseBackup`] - cleared
/// - [`CollectionName::ConfigurationNextUpdate`] - deleted (collection removed)
/// - [`CollectionName::ConfigurationBackup`] - cleared
///
/// This operation is idempotent - calling it when collections are already absent or empty succeeds.
/// The current database ([`CollectionName::DiagnosticDatabase`]) and active configuration
/// ([`CollectionName::Configuration`]) are never touched.
/// # Errors
///
/// Returns [`RuntimeUpdateError`] if any storage operation fails.
pub async fn execute_cleanup<S: Storage>(storage: &S) -> Result<(), RuntimeUpdateError> {
    let mdd_backup = storage
        .get_or_create_collection(&CollectionName::DiagnosticDatabaseBackup)
        .await?;
    let cfg_backup = storage
        .get_or_create_collection(&CollectionName::ConfigurationBackup)
        .await?;

    let mut tx = storage.begin_transaction()?;

    delete_collection_ignore_missing(
        storage,
        &mut tx,
        &CollectionName::DiagnosticDatabaseNextUpdate,
    )
    .await?;
    mdd_backup.delete_all(&mut tx).await?;
    delete_collection_ignore_missing(storage, &mut tx, &CollectionName::ConfigurationNextUpdate)
        .await?;
    cfg_backup.delete_all(&mut tx).await?;

    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use cda_interfaces::storage_api::{
        Collection as _,
        CollectionName,
        Storage as _,
        StorageError,
    };
    use cda_storage::LocalStorage;

    use super::execute_cleanup;
    use crate::test_utils::{
        make_storage,
        write_file,
    };

    async fn write_dummy(storage: &LocalStorage, collection: &CollectionName, key: &str) {
        storage.get_or_create_collection(collection).await.unwrap();
        let mut data: &[u8] = b"dummy";
        let mut tx = storage.begin_transaction().unwrap();
        write_file(storage, &mut tx, collection, key, &mut data)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    #[tokio::test]
    async fn cleanup_clears_diagnostic_database_next_update() {
        let (storage, _dir) = make_storage();
        write_dummy(
            &storage,
            &CollectionName::DiagnosticDatabaseNextUpdate,
            "a.mdd",
        )
        .await;

        execute_cleanup(&storage).await.unwrap();

        let result = storage
            .get_collection(&CollectionName::DiagnosticDatabaseNextUpdate)
            .await;
        assert!(
            matches!(result, Err(StorageError::CollectionNotFound(_))),
            "NextUpdate should be gone after cleanup"
        );
    }

    #[tokio::test]
    async fn cleanup_clears_diagnostic_database_backup() {
        let (storage, _dir) = make_storage();
        write_dummy(&storage, &CollectionName::DiagnosticDatabaseBackup, "b.mdd").await;

        execute_cleanup(&storage).await.unwrap();

        let col = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabaseBackup)
            .await
            .unwrap();
        assert!(col.is_empty().await.unwrap());
    }

    #[tokio::test]
    async fn cleanup_clears_configuration_next_update() {
        let (storage, _dir) = make_storage();
        write_dummy(
            &storage,
            &CollectionName::ConfigurationNextUpdate,
            "cfg.toml",
        )
        .await;

        execute_cleanup(&storage).await.unwrap();

        let result = storage
            .get_collection(&CollectionName::ConfigurationNextUpdate)
            .await;
        assert!(
            matches!(result, Err(StorageError::CollectionNotFound(_))),
            "NextUpdate should be gone after cleanup"
        );
    }

    #[tokio::test]
    async fn cleanup_clears_configuration_backup() {
        let (storage, _dir) = make_storage();
        write_dummy(&storage, &CollectionName::ConfigurationBackup, "cfg.toml").await;

        execute_cleanup(&storage).await.unwrap();

        let col = storage
            .get_or_create_collection(&CollectionName::ConfigurationBackup)
            .await
            .unwrap();
        assert!(col.is_empty().await.unwrap());
    }

    #[tokio::test]
    async fn cleanup_is_idempotent_when_all_collections_empty() {
        let (storage, _dir) = make_storage();

        let result = execute_cleanup(&storage).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn cleanup_does_not_modify_diagnostic_database() {
        let (storage, _dir) = make_storage();
        write_dummy(&storage, &CollectionName::DiagnosticDatabase, "ecu.mdd").await;

        execute_cleanup(&storage).await.unwrap();

        let col = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        assert!(!col.is_empty().await.unwrap());
        let keys = col.list().await.unwrap();
        assert!(keys.contains(&"ecu.mdd".to_string()));
    }

    #[tokio::test]
    async fn cleanup_does_not_modify_configuration() {
        let (storage, _dir) = make_storage();
        write_dummy(&storage, &CollectionName::Configuration, "config.toml").await;

        execute_cleanup(&storage).await.unwrap();

        let col = storage
            .get_or_create_collection(&CollectionName::Configuration)
            .await
            .unwrap();
        assert!(!col.is_empty().await.unwrap());
        let keys = col.list().await.unwrap();
        assert!(keys.contains(&"config.toml".to_string()));
    }
}
