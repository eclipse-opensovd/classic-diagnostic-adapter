// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

use std::sync::{Arc, atomic::AtomicBool};

use async_trait::async_trait;
use cda_interfaces::{
    HashMap,
    runtime_update_api::{
        BulkDataCreatedList, BulkDataList, ExecutionMode, LockStateProvider,
        RuntimeFileReloadHandler, RuntimeFilesQuery, RuntimeFilesUpdatePlugin,
        RuntimeFilesUpdateSecurityHandler, RuntimeUpdateError, UpdateExecution, UploadFile,
    },
    storage_api::Storage,
};
use tokio::sync::RwLock;

/// Default implementation of [`RuntimeFilesUpdatePlugin`] with injectable security and storage.
pub struct DefaultRuntimeFilesUpdatePlugin<
    S: Storage,
    R: RuntimeFileReloadHandler,
    T: RuntimeFilesUpdateSecurityHandler<L, S::CollectionHandle>,
    L: LockStateProvider,
> {
    /// Access to the persistent storage layer (all mutations go through this)
    storage: Arc<S>,
    /// Hot-reload notification handler
    reload_handler: Arc<R>,
    /// Security and file integrity handler
    security_handler: Arc<T>,
    /// Lock state provider passed to security checks
    lock_provider: Arc<L>,
    /// Tracking map for in-progress executions: `exec_id` -> `DbUpdateExecution`
    executions: Arc<RwLock<HashMap<String, UpdateExecution>>>,
    /// If true, call `update_mdd_uncompressed()` after Apply for each MDD file
    mdd_decompress: bool,
    /// Shared flag indicating whether an update is currently in progress.
    /// Other components (e.g. the HTTP update guard, UDS layer) hold clones of this Arc
    /// to observe update state.
    update_in_progress: Arc<AtomicBool>,
}

impl<
    S: Storage,
    R: RuntimeFileReloadHandler,
    T: RuntimeFilesUpdateSecurityHandler<L, S::CollectionHandle>,
    L: LockStateProvider,
> DefaultRuntimeFilesUpdatePlugin<S, R, T, L>
{
    /// Creates a new plugin instance.
    ///
    /// # Arguments
    /// * `storage` - Persistent storage backend for update files
    /// * `reload_handler` - Notified after apply/rollback to hot-reload databases
    /// * `security_handler` - Validates authorization and file integrity
    /// * `lock_provider` - Provides lock state for security validation
    /// * `mdd_decompress` - Whether to decompress MDD files after apply
    /// * `update_in_progress` - Shared flag read by other components to gate operations
    pub fn new(
        storage: Arc<S>,
        reload_handler: Arc<R>,
        security_handler: Arc<T>,
        lock_provider: Arc<L>,
        mdd_decompress: bool,
        update_in_progress: Arc<AtomicBool>,
    ) -> Self {
        Self {
            storage,
            reload_handler,
            security_handler,
            lock_provider,
            executions: Arc::new(RwLock::new(HashMap::default())),
            mdd_decompress,
            update_in_progress,
        }
    }
}

#[async_trait]
impl<
    S: Storage + Send + Sync + 'static,
    R: RuntimeFileReloadHandler,
    T: RuntimeFilesUpdateSecurityHandler<L, S::CollectionHandle>,
    L: LockStateProvider,
> RuntimeFilesUpdatePlugin for DefaultRuntimeFilesUpdatePlugin<S, R, T, L>
{
    async fn list_current(
        &self,
        query: &RuntimeFilesQuery,
    ) -> Result<BulkDataList, RuntimeUpdateError> {
        crate::storage::list_current_files(&*self.storage, query).await
    }

    async fn list_nextupdate(
        &self,
        query: &RuntimeFilesQuery,
    ) -> Result<BulkDataList, RuntimeUpdateError> {
        crate::storage::compute_nextupdate_state(&*self.storage, query).await
    }

    async fn list_backup(
        &self,
        query: &RuntimeFilesQuery,
    ) -> Result<BulkDataList, RuntimeUpdateError> {
        crate::storage::list_backup_files(&*self.storage, query).await
    }

    async fn upload(
        &self,
        files: Vec<UploadFile>,
    ) -> Result<BulkDataCreatedList, RuntimeUpdateError> {
        crate::storage::upload_files(&*self.storage, &*self.security_handler, files).await
    }

    async fn delete_nextupdate(&self) -> Result<(), RuntimeUpdateError> {
        crate::storage::delete_all_nextupdate(&*self.storage).await
    }

    async fn delete_nextupdate_by_id(&self, file_id: &str) -> Result<(), RuntimeUpdateError> {
        crate::storage::delete_nextupdate_file(&*self.storage, file_id).await
    }

    async fn delete_backup(&self) -> Result<(), RuntimeUpdateError> {
        crate::storage::delete_all_backup(&*self.storage).await
    }

    async fn start_execution(&self, mode: ExecutionMode) -> Result<String, RuntimeUpdateError> {
        let params = crate::operations::executions::ExecutionParams {
            storage: &self.storage,
            security_handler: &self.security_handler,
            reload_handler: &self.reload_handler,
            executions: &self.executions,
            update_in_progress: &self.update_in_progress,
            mdd_decompress: self.mdd_decompress,
            lock_state_provider: &*self.lock_provider,
        };
        crate::operations::executions::start_execution(&params, mode).await
    }

    async fn get_execution_status(&self, execution_id: &str) -> Option<UpdateExecution> {
        crate::operations::executions::get_execution_status(&self.executions, execution_id).await
    }

    async fn list_executions(&self) -> Vec<UpdateExecution> {
        self.executions.read().await.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use cda_interfaces::{
        runtime_update_api::{
            ExecutionMode, HashAlgorithm, RuntimeFilesQuery, RuntimeFilesUpdatePlugin,
            RuntimeUpdateError,
        },
        storage_api::CollectionName,
    };
    use cda_storage::LocalStorage;

    use crate::{
        DefaultRuntimeFilesUpdatePlugin,
        test_utils::{
            MockLockProvider, MockSecurityHandler, NoopReloadHandler, make_storage,
            make_upload_files, make_valid_config, make_valid_mdd, write_test_file,
        },
    };

    fn make_plugin(
        storage: LocalStorage,
    ) -> DefaultRuntimeFilesUpdatePlugin<
        LocalStorage,
        NoopReloadHandler,
        MockSecurityHandler,
        MockLockProvider,
    > {
        make_state_with_lock(storage, Some("test-user"), false)
    }

    fn make_state_with_lock(
        storage: LocalStorage,
        owner: Option<&str>,
        has_conflicts: bool,
    ) -> DefaultRuntimeFilesUpdatePlugin<
        LocalStorage,
        NoopReloadHandler,
        MockSecurityHandler,
        MockLockProvider,
    > {
        DefaultRuntimeFilesUpdatePlugin::new(
            Arc::new(storage),
            Arc::new(NoopReloadHandler),
            Arc::new(MockSecurityHandler::new()),
            Arc::new(MockLockProvider {
                owner: owner.map(ToOwned::to_owned),
                has_conflicts,
            }),
            false,
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )
    }

    #[tokio::test]
    async fn get_current_empty_collection_returns_empty_items() {
        let (storage, _dir) = make_storage();
        let plugin = make_plugin(storage);
        let query = RuntimeFilesQuery::default();

        let result = plugin.list_current(&query).await.unwrap();
        assert!(result.items.is_empty());
    }

    #[tokio::test]
    async fn get_current_returns_files_with_metadata() {
        let (storage, _dir) = make_storage();
        write_test_file(
            &storage,
            &CollectionName::DiagnosticDatabase,
            "ecu1.mdd",
            b"data1",
        )
        .await;
        write_test_file(
            &storage,
            &CollectionName::DiagnosticDatabase,
            "ecu2.mdd",
            b"data22",
        )
        .await;
        let plugin = make_plugin(storage);

        let query = RuntimeFilesQuery {
            include_file_size: true,
            include_hash: Some(HashAlgorithm::Sha256),
            ..Default::default()
        };
        let result = plugin.list_current(&query).await.unwrap();

        assert_eq!(result.items.len(), 2);
        for item in &result.items {
            assert!(item.size.is_some());
            assert!(item.hash.is_some());
            assert_eq!(item.hash_algorithm, Some(HashAlgorithm::Sha256));
        }
    }

    #[tokio::test]
    async fn get_nextupdate_shows_merged_view() {
        let (storage, _dir) = make_storage();
        write_test_file(
            &storage,
            &CollectionName::DiagnosticDatabase,
            "existing.mdd",
            b"old",
        )
        .await;
        write_test_file(
            &storage,
            &CollectionName::DiagnosticDatabaseNextUpdate,
            "existing.mdd",
            b"new_version",
        )
        .await;
        write_test_file(
            &storage,
            &CollectionName::DiagnosticDatabaseNextUpdate,
            "added.mdd",
            b"brand_new",
        )
        .await;
        let plugin = make_plugin(storage);

        let query = RuntimeFilesQuery {
            include_file_size: true,
            ..Default::default()
        };
        let result = plugin.list_nextupdate(&query).await.unwrap();

        assert_eq!(result.items.len(), 2, "{:#?}", result.items);
        let existing = result
            .items
            .iter()
            .find(|i| i.id == "existing.mdd")
            .unwrap();
        assert_eq!(existing.size, Some(11));
        let added = result.items.iter().find(|i| i.id == "added.mdd").unwrap();
        assert_eq!(added.size, Some(9));
    }

    #[tokio::test]
    async fn get_backup_empty_returns_empty() {
        let (storage, _dir) = make_storage();
        let plugin = make_plugin(storage);
        let query = RuntimeFilesQuery::default();

        let result = plugin.list_backup(&query).await.unwrap();
        assert!(result.items.is_empty());
    }

    #[tokio::test]
    async fn get_backup_returns_backup_files() {
        let (storage, _dir) = make_storage();
        write_test_file(
            &storage,
            &CollectionName::DiagnosticDatabaseBackup,
            "old_ecu.mdd",
            b"backup_data",
        )
        .await;
        let plugin = make_plugin(storage);

        let query = RuntimeFilesQuery {
            include_file_size: true,
            ..Default::default()
        };
        let result = plugin.list_backup(&query).await.unwrap();

        assert_eq!(result.items.len(), 1);
        let Some(item) = result.items.first() else {
            panic!("expected item")
        };
        assert_eq!(item.id, "old_ecu.mdd");
        assert_eq!(item.size, Some(11));
    }

    #[tokio::test]
    async fn delete_nextupdate_clears_both_collections() {
        let (storage, _dir) = make_storage();
        write_test_file(
            &storage,
            &CollectionName::DiagnosticDatabaseNextUpdate,
            "ecu.mdd",
            b"data",
        )
        .await;
        write_test_file(
            &storage,
            &CollectionName::ConfigurationNextUpdate,
            "cfg.toml",
            b"[cfg]",
        )
        .await;
        let plugin = make_plugin(storage);

        plugin.delete_nextupdate().await.unwrap();

        // After delete_all_nextupdate, list_nextupdate should return no items
        let query = RuntimeFilesQuery::default();
        let result = plugin.list_nextupdate(&query).await.unwrap();
        assert!(result.items.is_empty());
    }

    #[tokio::test]
    async fn delete_by_id_removes_specific_file() {
        let (storage, _dir) = make_storage();
        write_test_file(
            &storage,
            &CollectionName::DiagnosticDatabaseNextUpdate,
            "keep.mdd",
            b"keep",
        )
        .await;
        write_test_file(
            &storage,
            &CollectionName::DiagnosticDatabaseNextUpdate,
            "remove.mdd",
            b"remove",
        )
        .await;
        let plugin = make_plugin(storage);

        plugin.delete_nextupdate_by_id("remove.mdd").await.unwrap();

        let query = RuntimeFilesQuery::default();
        let result = plugin.list_nextupdate(&query).await.unwrap();
        assert_eq!(result.items.len(), 1);
        assert_eq!(result.items.first().unwrap().id, "keep.mdd");
    }

    #[tokio::test]
    async fn delete_by_id_case_insensitive() {
        let (storage, _dir) = make_storage();
        write_test_file(
            &storage,
            &CollectionName::DiagnosticDatabaseNextUpdate,
            "ecu_alpha.mdd",
            b"data",
        )
        .await;
        let state = make_plugin(storage);

        state
            .delete_nextupdate_by_id("ECU_ALPHA.MDD")
            .await
            .unwrap();

        let query = RuntimeFilesQuery::default();
        let result = state.list_nextupdate(&query).await.unwrap();
        assert!(result.items.is_empty());
    }

    #[tokio::test]
    async fn delete_by_id_not_found_returns_file_not_found() {
        let (storage, _dir) = make_storage();
        write_test_file(
            &storage,
            &CollectionName::DiagnosticDatabaseNextUpdate,
            "existing.mdd",
            b"data",
        )
        .await;
        let state = make_plugin(storage);

        let result = state.delete_nextupdate_by_id("nonexistent.mdd").await;
        assert!(matches!(result, Err(RuntimeUpdateError::FileNotFound(_))));
    }

    #[tokio::test]
    async fn delete_backup_clears_both_backup_collections() {
        let (storage, _dir) = make_storage();
        write_test_file(
            &storage,
            &CollectionName::DiagnosticDatabaseBackup,
            "ecu.mdd",
            b"backup",
        )
        .await;
        write_test_file(
            &storage,
            &CollectionName::ConfigurationBackup,
            "cfg.toml",
            b"[bak]",
        )
        .await;
        let state = make_plugin(storage);

        state.delete_backup().await.unwrap();

        let query = RuntimeFilesQuery::default();
        let result = state.list_backup(&query).await.unwrap();
        assert!(result.items.is_empty());
    }

    #[tokio::test]
    async fn upload_mdd_and_config_delegates_to_storage() {
        let (storage, _dir) = make_storage();
        let plugin = make_plugin(storage);
        let mdd = make_valid_mdd("ComboECU");
        let config = make_valid_config();
        let files = make_upload_files(&[("combo.mdd", &mdd), ("opensovd-cda.toml", &config)]);

        let result = plugin.upload(files).await.unwrap();

        assert_eq!(result.items.len(), 2);
        let ids: Vec<&str> = result.items.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"combo.mdd"));
        assert!(ids.contains(&"opensovd-cda.toml"));
    }

    #[tokio::test]
    async fn upload_invalid_file_type_returns_err() {
        let (storage, _dir) = make_storage();
        let files = make_upload_files(&[("bad.txt", b"not an mdd or config")]);
        let plugin = make_plugin(storage);

        let err = plugin.upload(files).await.unwrap_err();

        assert!(matches!(err, RuntimeUpdateError::InvalidFileType(_)));
    }

    #[tokio::test]
    async fn start_execution_apply_returns_execution_id() {
        let (storage, _dir) = make_storage();
        write_test_file(
            &storage,
            &CollectionName::DiagnosticDatabaseNextUpdate,
            "ecu.mdd",
            b"mdd_data",
        )
        .await;

        let plugin = make_plugin(storage);

        let exec_id = plugin.start_execution(ExecutionMode::Apply).await.unwrap();
        assert!(!exec_id.is_empty());

        let status = plugin.get_execution_status(&exec_id).await;
        assert!(status.is_some());
    }

    #[tokio::test]
    async fn start_execution_conflict_when_already_running() {
        let (storage, _dir) = make_storage();
        write_test_file(
            &storage,
            &CollectionName::DiagnosticDatabaseNextUpdate,
            "ecu.mdd",
            b"mdd_data",
        )
        .await;

        let plugin = make_plugin(storage);

        let _exec_id = plugin.start_execution(ExecutionMode::Apply).await.unwrap();

        let result = plugin.start_execution(ExecutionMode::Cleanup).await;
        assert!(matches!(result, Err(RuntimeUpdateError::ExecutionConflict)));
    }
}
