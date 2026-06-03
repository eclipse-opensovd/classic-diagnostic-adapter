// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

use cda_interfaces::storage_api::{Collection, CollectionName, Storage, Transaction};

use crate::{
    RuntimeFileReloadHandler, RuntimeUpdateError,
    operations::{
        delete_collection_ignore_missing, reload_configuration_if_present,
        reload_database_if_present,
    },
};

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
pub async fn execute_rollback<S: Storage, R: RuntimeFileReloadHandler>(
    storage: &S,
    reload_handler: &R,
) -> Result<(), RuntimeUpdateError> {
    let mdd_backup_col = storage
        .get_or_create_collection(&CollectionName::DiagnosticDatabaseBackup)
        .await?;
    let config_backup_col = storage
        .get_or_create_collection(&CollectionName::ConfigurationBackup)
        .await?;

    let mdd_backup_empty = mdd_backup_col.is_empty().await?;
    let config_backup_empty = config_backup_col.is_empty().await?;

    if mdd_backup_empty && config_backup_empty {
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

    if !config_backup_empty {
        restore_from_backup(
            storage,
            &mut tx,
            &CollectionName::ConfigurationBackup,
            &CollectionName::Configuration,
            &CollectionName::ConfigurationNextUpdate,
            config_backup_col.as_ref(),
        )
        .await?;
    }

    tx.commit().await?;

    if !config_backup_empty {
        reload_configuration_if_present(storage, reload_handler).await?;
    }

    if !mdd_backup_empty {
        reload_database_if_present(storage, reload_handler, false).await?;
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::items_after_statements, clippy::cast_possible_truncation)]
mod tests {
    use std::sync::{Arc, Mutex};

    use cda_interfaces::storage_api::{
        Collection as _, CollectionName, Storage as _, StorageError,
    };

    use super::execute_rollback;
    use crate::{
        RuntimeUpdateError,
        test_utils::{NoopReloadHandler, RecordingReloadHandler, init_collection, make_storage},
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

        use cda_interfaces::storage_api::RandomAccessData as _;
        let handle = db_col.read("ecu1.mdd").await.unwrap();
        let size = handle.data_size().unwrap() as usize;
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
    async fn rollback_with_config_backup_restores_configuration() {
        let (storage, _dir) = make_storage();

        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabaseBackup,
            &[("ecu1.mdd", b"mdd_backup")],
        )
        .await;

        init_collection(
            &storage,
            &CollectionName::ConfigurationBackup,
            &[("config.toml", b"[backup_config]")],
        )
        .await;

        init_collection(
            &storage,
            &CollectionName::Configuration,
            &[("config.toml", b"[current_config]")],
        )
        .await;

        execute_rollback(&storage, &NoopReloadHandler)
            .await
            .unwrap();

        let config_col = storage
            .get_or_create_collection(&CollectionName::Configuration)
            .await
            .unwrap();

        use cda_interfaces::storage_api::RandomAccessData as _;
        let handle = config_col.read("config.toml").await.unwrap();
        let size = handle.data_size().unwrap() as usize;
        let mut buf = vec![0u8; size];
        handle.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf, b"[backup_config]");

        let config_backup_col = storage
            .get_or_create_collection(&CollectionName::ConfigurationBackup)
            .await
            .unwrap();
        assert!(config_backup_col.is_empty().await.unwrap());
    }

    #[tokio::test]
    async fn rollback_mdd_only_leaves_config_collections_untouched() {
        let (storage, _dir) = make_storage();

        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabaseBackup,
            &[("ecu1.mdd", b"mdd_backup")],
        )
        .await;

        init_collection(
            &storage,
            &CollectionName::Configuration,
            &[("config.toml", b"[original_config]")],
        )
        .await;
        init_collection(
            &storage,
            &CollectionName::ConfigurationNextUpdate,
            &[("config.toml", b"[pending_config]")],
        )
        .await;

        execute_rollback(&storage, &NoopReloadHandler)
            .await
            .unwrap();

        let config_col = storage
            .get_or_create_collection(&CollectionName::Configuration)
            .await
            .unwrap();
        use cda_interfaces::storage_api::RandomAccessData as _;
        let handle = config_col.read("config.toml").await.unwrap();
        let size = handle.data_size().unwrap() as usize;
        let mut buf = vec![0u8; size];
        handle.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf, b"[original_config]");

        let config_next_col = storage
            .get_or_create_collection(&CollectionName::ConfigurationNextUpdate)
            .await
            .unwrap();
        assert!(!config_next_col.is_empty().await.unwrap());
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
    async fn rollback_calls_reload_configuration_when_config_restored() {
        let (storage, _dir) = make_storage();

        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabaseBackup,
            &[("ecu1.mdd", b"mdd_backup")],
        )
        .await;

        init_collection(
            &storage,
            &CollectionName::ConfigurationBackup,
            &[("config.toml", b"[backup_config]")],
        )
        .await;

        let handler = RecordingReloadHandler::new();
        execute_rollback(&storage, &handler).await.unwrap();

        let config_calls = handler.config_calls.lock().unwrap();
        assert_eq!(
            config_calls.len(),
            1,
            "reload_configuration should be called once"
        );
        let Some(first_call) = config_calls.first() else {
            panic!("expected call")
        };
        assert!(
            first_call.ends_with("config.toml"),
            "reload_configuration should receive the config file path"
        );
    }

    #[derive(Clone, Default)]
    struct OrderingReloadHandler {
        call_order: Arc<Mutex<Vec<&'static str>>>,
    }

    #[async_trait::async_trait]
    impl crate::RuntimeFileReloadHandler for OrderingReloadHandler {
        async fn reload_databases(
            &self,
            _paths: Vec<std::path::PathBuf>,
        ) -> Result<(), crate::ReloadError> {
            self.call_order.lock().unwrap().push("databases");
            Ok(())
        }

        async fn reload_configuration(
            &self,
            _path: std::path::PathBuf,
        ) -> Result<(), crate::ReloadError> {
            self.call_order.lock().unwrap().push("configuration");
            Ok(())
        }
    }

    #[tokio::test]
    async fn rollback_reloads_configuration_before_databases() {
        let (storage, _dir) = make_storage();

        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabaseBackup,
            &[("ecu1.mdd", b"mdd_backup")],
        )
        .await;

        init_collection(
            &storage,
            &CollectionName::ConfigurationBackup,
            &[("config.toml", b"[backup_config]")],
        )
        .await;

        let handler = OrderingReloadHandler::default();
        execute_rollback(&storage, &handler).await.unwrap();

        let call_order = handler.call_order.lock().unwrap();
        assert_eq!(call_order.as_slice(), ["configuration", "databases"]);
    }

    #[tokio::test]
    async fn rollback_config_only_restores_config() {
        let (storage, _dir) = make_storage();

        init_collection(
            &storage,
            &CollectionName::ConfigurationBackup,
            &[("config.toml", b"[backup_config]")],
        )
        .await;

        init_collection(
            &storage,
            &CollectionName::Configuration,
            &[("config.toml", b"[current_config]")],
        )
        .await;

        let handler = RecordingReloadHandler::new();
        execute_rollback(&storage, &handler).await.unwrap();

        let config_col = storage
            .get_or_create_collection(&CollectionName::Configuration)
            .await
            .unwrap();

        use cda_interfaces::storage_api::RandomAccessData as _;
        let handle = config_col.read("config.toml").await.unwrap();
        let size = handle.data_size().unwrap() as usize;
        let mut buf = vec![0u8; size];
        handle.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf, b"[backup_config]");

        let config_backup_col = storage
            .get_or_create_collection(&CollectionName::ConfigurationBackup)
            .await
            .unwrap();
        assert!(config_backup_col.is_empty().await.unwrap());

        let reload_calls = handler.reload_calls.lock().unwrap();
        assert_eq!(
            reload_calls.len(),
            0,
            "reload_databases should NOT be called for config-only rollback"
        );

        let config_calls = handler.config_calls.lock().unwrap();
        assert_eq!(
            config_calls.len(),
            1,
            "reload_configuration should be called once"
        );
        let Some(first_call) = config_calls.first() else {
            panic!("expected call")
        };
        assert!(
            first_call.ends_with("config.toml"),
            "reload_configuration should receive the config file path"
        );
    }

    #[tokio::test]
    async fn rollback_config_only_does_not_touch_mdd_collections() {
        let (storage, _dir) = make_storage();

        init_collection(
            &storage,
            &CollectionName::ConfigurationBackup,
            &[("config.toml", b"[backup_config]")],
        )
        .await;

        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabase,
            &[("ecu1.mdd", b"current_mdd")],
        )
        .await;

        execute_rollback(&storage, &NoopReloadHandler)
            .await
            .unwrap();

        let db_col = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();

        use cda_interfaces::storage_api::RandomAccessData as _;
        let handle = db_col.read("ecu1.mdd").await.unwrap();
        let size = handle.data_size().unwrap() as usize;
        let mut buf = vec![0u8; size];
        handle.read_at(0, &mut buf).unwrap();
        assert_eq!(
            &buf, b"current_mdd",
            "MDD should be untouched in config-only rollback"
        );
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
