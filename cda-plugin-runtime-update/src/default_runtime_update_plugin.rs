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

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use cda_interfaces::{
    HashMap,
    communication_control::{DisableCommunication, PostUpdateCommunicationMode},
    http_protection::registry::{HttpProtectionRegistry, HttpRouteMatcher},
    runtime_update_api::{
        BulkDataCreatedList, BulkDataList, ExecutionMode, LockStateProvider, RuntimeFileCatalog,
        RuntimeFileStore, RuntimeFilesQuery, RuntimeReloaderPlugin, RuntimeUpdateError,
        RuntimeUpdateExecutor, RuntimeUpdateSecurityPlugin, UpdateExecution, UploadFile,
    },
    storage_api::Storage,
};
use tokio::sync::RwLock;

/// Default implementation of [`RuntimeFilesUpdatePlugin`] with injectable security and storage.
pub struct DefaultRuntimeUpdatePlugin<
    Store: Storage,
    UpdateSecurityPlugin: RuntimeUpdateSecurityPlugin<Lock, Store::CollectionHandle>,
    Lock: LockStateProvider,
> {
    /// Access to the persistent storage layer (all mutations go through this)
    storage: Arc<Store>,
    /// Hot-reload notification handler
    reloader_plugin: Arc<dyn RuntimeReloaderPlugin>,
    /// Security and file integrity handler
    security_handler: Arc<UpdateSecurityPlugin>,
    /// Lock state provider passed to security checks
    lock_provider: Arc<Lock>,
    /// Tracking map for in-progress executions: `exec_id` -> `DbUpdateExecution`
    executions: Arc<RwLock<HashMap<String, UpdateExecution>>>,
    /// Format-specific reads (validate, revision, ECU name), so the plugin
    /// carries no database format of its own.
    communication_disable: Arc<dyn DisableCommunication>,
    http_protections: HttpProtectionRegistry,
    update_exempt_routes: Vec<HttpRouteMatcher>,
    update_retry_after: Duration,
    post_update_mode: PostUpdateCommunicationMode,
}

impl<
    Store: Storage,
    UpdateSecurityPlugin: RuntimeUpdateSecurityPlugin<Lock, Store::CollectionHandle>,
    Lock: LockStateProvider,
> DefaultRuntimeUpdatePlugin<Store, UpdateSecurityPlugin, Lock>
{
    /// Creates a new plugin instance.
    ///
    /// # Arguments
    /// * `storage` - Persistent storage backend for update files
    /// * `reload_handler` - Notified after apply/rollback to hot-reload databases
    /// * `security_handler` - Validates authorization and file integrity
    /// * `lock_provider` - Provides lock state for security validation
    /// * `communication_disable` - Used to acquire exclusive transport disable ownership
    /// * `update_retry_after` - Retry-After duration while an update owns protection
    /// * `post_update_mode` - Communication state to restore after an update
    #[allow(
        clippy::too_many_arguments,
        reason = "Constructor requires many dependencies for plugin initialization, adding a \
                  struct of this is pointless, as it is only used once."
    )]
    pub fn new(
        storage: Arc<Store>,
        reloader_plugin: Arc<dyn RuntimeReloaderPlugin>,
        security_handler: Arc<UpdateSecurityPlugin>,
        lock_provider: Arc<Lock>,
        communication_disable: Arc<dyn DisableCommunication>,
        http_protections: HttpProtectionRegistry,
        update_exempt_routes: Vec<HttpRouteMatcher>,
        update_retry_after: Duration,
        post_update_mode: PostUpdateCommunicationMode,
    ) -> Self {
        Self {
            storage,
            reloader_plugin,
            security_handler,
            lock_provider,
            executions: Arc::new(RwLock::new(HashMap::default())),
            communication_disable,
            http_protections,
            update_exempt_routes,
            update_retry_after,
            post_update_mode,
        }
    }
}

#[async_trait]
impl<
    Store: Storage + Send + Sync + 'static,
    UpdateSecurityPlugin: RuntimeUpdateSecurityPlugin<Lock, Store::CollectionHandle>,
    Lock: LockStateProvider,
> RuntimeFileCatalog for DefaultRuntimeUpdatePlugin<Store, UpdateSecurityPlugin, Lock>
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
}

#[async_trait]
impl<
    Store: Storage + Send + Sync + 'static,
    UpdateSecurityPlugin: RuntimeUpdateSecurityPlugin<Lock, Store::CollectionHandle>,
    Lock: LockStateProvider,
> RuntimeFileStore for DefaultRuntimeUpdatePlugin<Store, UpdateSecurityPlugin, Lock>
{
    async fn upload(
        &self,
        files: Vec<UploadFile>,
    ) -> Result<BulkDataCreatedList, RuntimeUpdateError> {
        crate::storage::upload_files(&*self.storage, &*self.security_handler, files).await
    }

    async fn delete_nextupdate(&self) -> Result<Vec<String>, RuntimeUpdateError> {
        crate::storage::delete_all_nextupdate(&*self.storage).await
    }

    async fn delete_nextupdate_by_id(&self, file_id: &str) -> Result<(), RuntimeUpdateError> {
        crate::storage::delete_nextupdate_file(&*self.storage, file_id).await
    }

    async fn delete_backup(&self) -> Result<Vec<String>, RuntimeUpdateError> {
        crate::storage::delete_all_backup(&*self.storage).await
    }
}

#[async_trait]
impl<
    Store: Storage + Send + Sync + 'static,
    UpdateSecurityPlugin: RuntimeUpdateSecurityPlugin<Lock, Store::CollectionHandle>,
    Lock: LockStateProvider,
> RuntimeUpdateExecutor for DefaultRuntimeUpdatePlugin<Store, UpdateSecurityPlugin, Lock>
{
    async fn start_execution(&self, mode: ExecutionMode) -> Result<String, RuntimeUpdateError> {
        let params = crate::operations::executions::ExecutionParams {
            storage: &self.storage,
            security_handler: &self.security_handler,
            reload_handler: &self.reloader_plugin,
            executions: &self.executions,
            communication_disable: &self.communication_disable,
            http_protections: &self.http_protections,
            update_exempt_routes: &self.update_exempt_routes,
            update_retry_after: self.update_retry_after,
            post_update_mode: self.post_update_mode.clone(),
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
    use std::{sync::Arc, time::Duration};

    use cda_interfaces::{
        communication_control::{CommunicationState, PostUpdateCommunicationMode},
        http_protection::registry::HttpProtectionRegistry,
        runtime_update_api::{
            ExecutionMode, HashAlgorithm, RuntimeFileCatalog, RuntimeFileStore, RuntimeFilesQuery,
            RuntimeUpdateError, RuntimeUpdateExecutor,
        },
        storage_api::CollectionName,
    };
    use cda_plugin_communication_management::lifecycle::{
        communication_disable_for_test,
        disable::{DisableCommunication, DisableReason},
    };
    use cda_storage::LocalStorage;

    use crate::{
        DefaultRuntimeUpdatePlugin,
        test_utils::{
            MockLockProvider, MockSecurityHandler, NoopReloadHandler, StubTransport, make_storage,
            make_upload_files, make_valid_config, write_test_file,
        },
    };

    fn make_plugin(
        storage: LocalStorage,
    ) -> DefaultRuntimeUpdatePlugin<LocalStorage, MockSecurityHandler, MockLockProvider> {
        let (plugin, _disable_comm) = make_state_with_lock(storage, Some("test-user"), false);
        plugin
    }

    fn make_state_with_lock(
        storage: LocalStorage,
        owner: Option<&str>,
        has_conflicts: bool,
    ) -> (
        DefaultRuntimeUpdatePlugin<LocalStorage, MockSecurityHandler, MockLockProvider>,
        Arc<dyn DisableCommunication>,
    ) {
        let transport = StubTransport::new();
        let http_protections = HttpProtectionRegistry::new();
        let communication_disable = communication_disable_for_test(transport, false);

        let plugin = DefaultRuntimeUpdatePlugin::new(
            Arc::new(storage),
            Arc::new(NoopReloadHandler),
            Arc::new(MockSecurityHandler::new()),
            Arc::new(MockLockProvider {
                owner: owner.map(ToOwned::to_owned),
                has_conflicts,
            }),
            Arc::clone(&communication_disable),
            http_protections,
            Vec::new(),
            Duration::from_secs(1),
            PostUpdateCommunicationMode::Enabled,
        );
        (plugin, communication_disable)
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
    async fn delete_nextupdate_clears_mdd_collection() {
        let (storage, _dir) = make_storage();
        write_test_file(
            &storage,
            &CollectionName::DiagnosticDatabaseNextUpdate,
            "ecu.mdd",
            b"data",
        )
        .await;
        let plugin = make_plugin(storage);

        plugin.delete_nextupdate().await.unwrap();

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
    async fn delete_backup_clears_mdd_backup_collection() {
        let (storage, _dir) = make_storage();
        write_test_file(
            &storage,
            &CollectionName::DiagnosticDatabaseBackup,
            "ecu.mdd",
            b"backup",
        )
        .await;
        let state = make_plugin(storage);

        state.delete_backup().await.unwrap();

        let query = RuntimeFilesQuery::default();
        let result = state.list_backup(&query).await.unwrap();
        assert!(result.items.is_empty());
    }

    #[tokio::test]
    async fn upload_rejects_config_files() {
        let (storage, _dir) = make_storage();
        let plugin = make_plugin(storage);
        let config = make_valid_config();
        let files = make_upload_files(&[("opensovd-cda.toml", &config)]);

        let result = plugin.upload(files).await;

        assert!(matches!(
            result,
            Err(RuntimeUpdateError::InvalidFileType(_))
        ));
    }

    #[tokio::test]
    async fn upload_invalid_file_type_returns_err() {
        let (storage, _dir) = make_storage();
        let files = make_upload_files(&[("bad.txt", b"not an mdd or config")]);
        let plugin = make_plugin(storage);

        let err = plugin.upload(files).await.unwrap_err();

        assert!(matches!(err, RuntimeUpdateError::InvalidFileType(_)));
    }

    /// An update needs no transport, so a deferred runtime must not have to
    /// bring the whole network up just to become eligible for one.
    /// The fixture's communication starts `Disabled`.
    #[tokio::test]
    async fn start_execution_allowed_while_communication_is_deferred() {
        let (storage, _dir) = make_storage();
        write_test_file(
            &storage,
            &CollectionName::DiagnosticDatabaseNextUpdate,
            "ecu.mdd",
            b"mdd_data",
        )
        .await;

        let plugin = make_plugin(storage);

        plugin
            .start_execution(ExecutionMode::Apply)
            .await
            .expect("an update must start while communication is deferred");
        assert_eq!(plugin.list_executions().await.len(), 1);
    }

    /// The exclusive disable lease serializes updates, so an execution is
    /// refused while anything else holds it, including an earlier execution.
    #[tokio::test]
    async fn start_execution_conflict_while_disable_lease_held() {
        let (storage, _dir) = make_storage();
        write_test_file(
            &storage,
            &CollectionName::DiagnosticDatabaseNextUpdate,
            "ecu.mdd",
            b"mdd_data",
        )
        .await;

        let (plugin, communication_disable) =
            make_state_with_lock(storage, Some("test-user"), false);
        let lease = communication_disable
            .disable(DisableReason::Custom("test".to_owned()))
            .await
            .expect("lease must be granted from a deferred runtime");

        let result = plugin.start_execution(ExecutionMode::Apply).await;
        assert!(matches!(result, Err(RuntimeUpdateError::ExecutionConflict)));
        assert!(plugin.list_executions().await.is_empty());

        // Releasing a lease taken from `Disabled` leaves communication
        // deferred rather than enabling it.
        assert_eq!(lease.release().await, Ok(CommunicationState::Disabled));
    }
}
