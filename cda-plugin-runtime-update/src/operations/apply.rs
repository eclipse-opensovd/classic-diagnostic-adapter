use cda_interfaces::storage_api::{
    Collection, CollectionName, DirectFileAccess, Storage, Transaction,
};

use crate::{
    LockStateProvider, RuntimeFileReloadHandler, RuntimeFilesUpdateSecurityHandler,
    RuntimeUpdateError, UpdateFileType,
    operations::{reload_configuration_if_present, reload_database_if_present, try_get_collection},
};

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

/// Atomically applies pending MDD files (and optionally config) from the staging
/// `NextUpdate` collections into the live `DiagnosticDatabase` (and `Configuration`)
/// collections, backing up current files first.
///
/// The 'apply' performs a **snapshot swap**: the entire `NextUpdate` collection replaces the
/// current collection. Files absent from `NextUpdate` are removed from current.
///
/// # Parameters
/// - `storage`: The storage backend.
/// - `security_handler`: Validates pending files before committing.
/// - `reload_handler`: Notified after commit so the runtime can hot-reload databases/config.
/// - `mdd_decompress`: If true, decompress MDD files in-place after commit.
///
/// # Errors
/// Returns [`RuntimeUpdateError`] if validation, transaction, or reload fails.
pub async fn execute_apply<
    S: Storage,
    T: RuntimeFilesUpdateSecurityHandler<L>,
    R: RuntimeFileReloadHandler,
    L: LockStateProvider,
>(
    storage: &S,
    security_handler: &T,
    reload_handler: &R,
    mdd_decompress: bool,
) -> Result<(), RuntimeUpdateError> {
    let mdd_next =
        try_get_collection(storage, &CollectionName::DiagnosticDatabaseNextUpdate).await?;
    let cfg_next = try_get_collection(storage, &CollectionName::ConfigurationNextUpdate).await?;

    if mdd_next.is_none() && cfg_next.is_none() {
        return Err(RuntimeUpdateError::NoPendingUpdate);
    }

    if let Some(ref mdd_col) = mdd_next {
        for mdd in mdd_col.list().await? {
            let path = mdd_col.file_path(&mdd)?;
            security_handler
                .check_file_integrity(UpdateFileType::Mdd, &path)
                .await
                .map_err(|e| RuntimeUpdateError::ValidationFailed(e.to_string()))?;
        }
    }

    if let Some(ref cfg_col) = cfg_next {
        let cfg_next_list = cfg_col.list().await?;
        if cfg_next_list.len() > 1 {
            return Err(RuntimeUpdateError::ValidationFailed(format!(
                "Multiple pending config files found: {}",
                cfg_next_list.len()
            )));
        }
        if let Some(cfg) = cfg_next_list.first() {
            let path = cfg_col.file_path(cfg)?;
            security_handler
                .check_file_integrity(UpdateFileType::Config, &path)
                .await
                .map_err(|e| RuntimeUpdateError::ValidationFailed(e.to_string()))?;
        }
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
    if cfg_next.is_some() {
        storage
            .get_or_create_collection(&CollectionName::Configuration)
            .await?;
        storage
            .get_or_create_collection(&CollectionName::ConfigurationBackup)
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

    if cfg_next.is_some() {
        swap_collection(
            storage,
            &mut tx,
            &CollectionName::Configuration,
            &CollectionName::ConfigurationBackup,
            &CollectionName::ConfigurationNextUpdate,
        )
        .await?;
    }

    tx.commit().await?;

    if cfg_next.is_some() {
        reload_configuration_if_present(storage, reload_handler).await?;
    }

    if mdd_next.is_some() {
        reload_database_if_present(storage, reload_handler, mdd_decompress).await?;
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::items_after_statements, clippy::cast_possible_truncation)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use cda_interfaces::storage_api::{
        Collection as _, CollectionName, Storage as _, StorageError,
    };

    use super::execute_apply;
    use crate::{
        RuntimeFilesUpdateSecurityHandler, RuntimeUpdateError, VerificationError,
        test_utils::{
            MockLockProvider, NoopReloadHandler, RecordingReloadHandler, init_collection,
            make_storage,
        },
    };

    struct AcceptAllVerifier;

    #[async_trait]
    impl RuntimeFilesUpdateSecurityHandler<MockLockProvider> for AcceptAllVerifier {
        async fn check_apply_allowed(
            &self,
            _lock_state_provider: &MockLockProvider,
        ) -> Result<(), RuntimeUpdateError> {
            Ok(())
        }

        async fn check_file_integrity(
            &self,
            _type: crate::UpdateFileType,
            _path: &std::path::Path,
        ) -> Result<(), VerificationError> {
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct OrderingReloadHandler {
        call_order: Arc<Mutex<Vec<&'static str>>>,
    }

    #[async_trait]
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

    /// A reload handler that records all calls for assertions
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

        execute_apply(&storage, &AcceptAllVerifier, &NoopReloadHandler, false)
            .await
            .unwrap();

        // Current should have new data
        let db_col = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        use cda_interfaces::storage_api::RandomAccessData as _;
        let handle = db_col.read("ecu1.mdd").await.unwrap();
        let size = handle.data_size().unwrap() as usize;
        let mut buf = vec![0u8; size];
        handle.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf, b"new_data");

        // Backup should have old data
        let backup_col = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabaseBackup)
            .await
            .unwrap();
        let handle = backup_col.read("ecu1.mdd").await.unwrap();
        let size = handle.data_size().unwrap() as usize;
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

        let result = execute_apply(&storage, &AcceptAllVerifier, &NoopReloadHandler, false).await;

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

        execute_apply(&storage, &AcceptAllVerifier, &NoopReloadHandler, false)
            .await
            .unwrap();

        // Current should have all new files
        let db_col = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        let keys = db_col.list().await.unwrap();
        assert_eq!(keys.len(), 3);

        use cda_interfaces::storage_api::RandomAccessData as _;
        let handle = db_col.read("ecu3.mdd").await.unwrap();
        let size = handle.data_size().unwrap() as usize;
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
        execute_apply(&storage, &AcceptAllVerifier, &handler, false)
            .await
            .unwrap();

        let calls = handler.reload_calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "reload_databases should be called once");
    }

    #[tokio::test]
    async fn apply_calls_reload_databases_with_paths() {
        let (storage, dir) = make_storage();

        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabaseNextUpdate,
            &[("ecu1.mdd", b"data")],
        )
        .await;

        let handler = RecordingReloadHandler::new();
        execute_apply(&storage, &AcceptAllVerifier, &handler, false)
            .await
            .unwrap();

        let expected_path = dir
            .path()
            .join("collections")
            .join("diagnostic_database")
            .join("ecu1.mdd");
        let calls = handler.reload_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let Some(first_call) = calls.first() else {
            panic!("expected call")
        };
        assert_eq!(first_call.len(), 1);
        let Some(first_path) = first_call.first() else {
            panic!("expected path")
        };
        assert_eq!(*first_path, expected_path);
    }

    #[tokio::test]
    async fn apply_with_config_updates_configuration() {
        let (storage, _dir) = make_storage();

        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabaseNextUpdate,
            &[("ecu1.mdd", b"mdd_data")],
        )
        .await;

        init_collection(
            &storage,
            &CollectionName::Configuration,
            &[("config.toml", b"[old_config]")],
        )
        .await;

        init_collection(
            &storage,
            &CollectionName::ConfigurationNextUpdate,
            &[("config.toml", b"[new_config]")],
        )
        .await;

        execute_apply(&storage, &AcceptAllVerifier, &NoopReloadHandler, false)
            .await
            .unwrap();

        // Configuration should have new config
        let config_col = storage
            .get_or_create_collection(&CollectionName::Configuration)
            .await
            .unwrap();
        use cda_interfaces::storage_api::RandomAccessData as _;
        let handle = config_col.read("config.toml").await.unwrap();
        let size = handle.data_size().unwrap() as usize;
        let mut buf = vec![0u8; size];
        handle.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf, b"[new_config]");

        // ConfigurationBackup should have old config
        let backup_col = storage
            .get_or_create_collection(&CollectionName::ConfigurationBackup)
            .await
            .unwrap();
        let handle = backup_col.read("config.toml").await.unwrap();
        let size = handle.data_size().unwrap() as usize;
        let mut buf = vec![0u8; size];
        handle.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf, b"[old_config]");

        // ConfigurationNextUpdate should be gone
        let result = storage
            .get_collection(&CollectionName::ConfigurationNextUpdate)
            .await;
        assert!(matches!(result, Err(StorageError::CollectionNotFound(_))));
    }

    #[tokio::test]
    async fn apply_mdd_only_leaves_config_untouched() {
        let (storage, _dir) = make_storage();

        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabaseNextUpdate,
            &[("ecu1.mdd", b"mdd_new")],
        )
        .await;

        init_collection(
            &storage,
            &CollectionName::Configuration,
            &[("config.toml", b"[original]")],
        )
        .await;

        execute_apply(&storage, &AcceptAllVerifier, &NoopReloadHandler, false)
            .await
            .unwrap();

        // Configuration unchanged
        {
            let config_col = storage
                .get_or_create_collection(&CollectionName::Configuration)
                .await
                .unwrap();
            use cda_interfaces::storage_api::RandomAccessData as _;
            let handle = config_col.read("config.toml").await.unwrap();
            let size = handle.data_size().unwrap() as usize;
            let mut buf = vec![0u8; size];
            handle.read_at(0, &mut buf).unwrap();
            assert_eq!(&buf, b"[original]");
        }

        let backup_col = storage
            .get_or_create_collection(&CollectionName::ConfigurationBackup)
            .await
            .unwrap();
        assert!(backup_col.is_empty().await.unwrap());
    }

    #[tokio::test]
    async fn apply_calls_reload_configuration_when_config_updated() {
        let (storage, _dir) = make_storage();

        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabaseNextUpdate,
            &[("ecu1.mdd", b"mdd_data")],
        )
        .await;

        init_collection(
            &storage,
            &CollectionName::ConfigurationNextUpdate,
            &[("config.toml", b"[new_config]")],
        )
        .await;

        let handler = RecordingReloadHandler::new();
        execute_apply(&storage, &AcceptAllVerifier, &handler, false)
            .await
            .unwrap();

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
    async fn apply_reloads_configuration_before_databases() {
        let (storage, _dir) = make_storage();

        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabaseNextUpdate,
            &[("ecu1.mdd", b"mdd_data")],
        )
        .await;

        init_collection(
            &storage,
            &CollectionName::ConfigurationNextUpdate,
            &[("config.toml", b"[new_config]")],
        )
        .await;

        let handler = OrderingReloadHandler::default();
        execute_apply(&storage, &AcceptAllVerifier, &handler, false)
            .await
            .unwrap();

        let call_order = handler.call_order.lock().unwrap();
        assert_eq!(call_order.as_slice(), ["configuration", "databases"]);
    }

    #[tokio::test]
    async fn apply_does_not_call_reload_configuration_without_config() {
        let (storage, _dir) = make_storage();

        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabaseNextUpdate,
            &[("ecu1.mdd", b"data")],
        )
        .await;

        let handler = RecordingReloadHandler::new();
        execute_apply(&storage, &AcceptAllVerifier, &handler, false)
            .await
            .unwrap();

        let config_calls = handler.config_calls.lock().unwrap();
        assert!(
            config_calls.is_empty(),
            "reload_configuration should not be called"
        );
    }

    #[tokio::test]
    async fn apply_with_mdd_decompress_false_succeeds() {
        let (storage, _dir) = make_storage();

        init_collection(
            &storage,
            &CollectionName::DiagnosticDatabaseNextUpdate,
            &[("ecu1.mdd", b"data")],
        )
        .await;

        // mdd_decompress=false, should work fine
        execute_apply(&storage, &AcceptAllVerifier, &NoopReloadHandler, false)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn apply_config_only_without_mdd_succeeds() {
        let (storage, _dir) = make_storage();

        init_collection(
            &storage,
            &CollectionName::Configuration,
            &[("config.toml", b"[old_config]")],
        )
        .await;

        init_collection(
            &storage,
            &CollectionName::ConfigurationNextUpdate,
            &[("config.toml", b"[new_config]")],
        )
        .await;

        execute_apply(&storage, &AcceptAllVerifier, &NoopReloadHandler, false)
            .await
            .expect("config-only apply should succeed");

        // Configuration should have new config
        let config_col = storage
            .get_or_create_collection(&CollectionName::Configuration)
            .await
            .unwrap();
        use cda_interfaces::storage_api::RandomAccessData as _;
        let handle = config_col.read("config.toml").await.unwrap();
        let size = handle.data_size().unwrap() as usize;
        let mut buf = vec![0u8; size];
        handle.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf, b"[new_config]");

        // ConfigurationNextUpdate should be gone
        let result = storage
            .get_collection(&CollectionName::ConfigurationNextUpdate)
            .await;
        use cda_interfaces::storage_api::StorageError;
        assert!(matches!(result, Err(StorageError::CollectionNotFound(_))));

        // DiagnosticDatabase should be untouched (not even created)
        let mdd_result = storage
            .get_collection(&CollectionName::DiagnosticDatabase)
            .await;
        assert!(
            matches!(mdd_result, Err(StorageError::CollectionNotFound(_))),
            "DiagnosticDatabase should not be touched in a config-only apply"
        );
    }

    #[tokio::test]
    async fn apply_config_only_calls_reload_configuration_but_not_reload_databases() {
        let (storage, _dir) = make_storage();

        init_collection(
            &storage,
            &CollectionName::ConfigurationNextUpdate,
            &[("config.toml", b"[new_config]")],
        )
        .await;

        let handler = RecordingReloadHandler::new();
        execute_apply(&storage, &AcceptAllVerifier, &handler, false)
            .await
            .unwrap();

        let config_calls = handler.config_calls.lock().unwrap();
        assert_eq!(
            config_calls.len(),
            1,
            "reload_configuration should be called once"
        );

        let reload_calls = handler.reload_calls.lock().unwrap();
        assert!(
            reload_calls.is_empty(),
            "reload_databases should not be called"
        );
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
        use cda_interfaces::storage_api::Storage as _;
        storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabaseNextUpdate)
            .await
            .unwrap();

        execute_apply(&storage, &AcceptAllVerifier, &NoopReloadHandler, false)
            .await
            .unwrap();

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

        execute_apply(&storage, &AcceptAllVerifier, &NoopReloadHandler, false)
            .await
            .unwrap();

        let db_col = storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        let keys = db_col.list().await.unwrap();
        assert_eq!(keys, vec!["ecu1.mdd"]);

        use cda_interfaces::storage_api::RandomAccessData as _;
        let handle = db_col.read("ecu1.mdd").await.unwrap();
        let size = handle.data_size().unwrap() as usize;
        let mut buf = vec![0u8; size];
        handle.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf, b"data1_updated");
    }
}
