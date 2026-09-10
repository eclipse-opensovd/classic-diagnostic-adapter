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

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use cda_interfaces::{
    HashMap,
    runtime_update_api::{
        BulkDataCreatedList, BulkDataList, ExecutionMode, LockStateProvider, RuntimeFileCatalog,
        RuntimeFileInspector, RuntimeFileStore, RuntimeFileTransaction, RuntimeFilesQuery,
        RuntimeUpdateError, RuntimeUpdateExecutor, RuntimeUpdatePolicy, UpdateDispatcher,
        UpdateExecution, UploadFile,
    },
    storage_api::Storage,
};
use tokio::{sync::RwLock, task::JoinHandle};

/// Upper bound on how long shutdown waits for an in-flight runtime update to
/// reach its own finalization.
///
/// The wait exists because the execution must not be aborted (see the
/// [`Shutdown`](cda_interfaces::Shutdown) implementation). The bound is a hard
/// cap on shutdown, not a budget the slowest healthy update is guaranteed to
/// fit in: a large collection copy on slow storage can exceed it and be cut
/// off. That is accepted, because shutdown must not be held up.
///
/// Being cut off costs the report, not the data. The swap runs in a
/// journalled transaction that startup recovery completes or rolls back, so
/// the database is still left fully before or fully after. What is lost is the
/// in-memory execution record, so no terminal status survives the restart.
const UPDATE_SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// Default implementation of [`RuntimeFileCatalog`], [`RuntimeFileStore`],
/// [`RuntimeFileTransaction`] and [`RuntimeUpdateExecutor`], with injectable
/// policy and storage.
pub struct DefaultRuntimeUpdatePlugin<
    Store: Storage,
    UpdatePolicy: RuntimeUpdatePolicy<Lock, Store::CollectionHandle>,
    Lock: LockStateProvider,
> {
    /// Access to the persistent storage layer (all mutations go through this)
    storage: Arc<Store>,
    /// Runs the runtime transition an execution asks for. Which stages a mode
    /// visits and what the transport looks like afterwards belong to the
    /// application, so the plugin only asks for the transition.
    dispatcher: Arc<dyn UpdateDispatcher>,
    /// Vehicle and lock state policy consulted before an execution proceeds
    policy: Arc<UpdatePolicy>,
    /// Lock state provider passed to the policy
    lock_provider: Arc<Lock>,
    /// Tracking map for in-progress executions: `exec_id` -> `DbUpdateExecution`
    executions: Arc<RwLock<HashMap<String, UpdateExecution>>>,
    /// Format-specific reads (validate, revision, ECU name), so the plugin
    /// carries no database format of its own.
    file_inspector: Arc<dyn RuntimeFileInspector>,
    /// Reporting task of the execution that is in flight, so shutdown can await
    /// it instead of letting it be cut off.
    ///
    /// A single slot is enough because at most one execution is ever live: a
    /// dispatch holds the exclusive execution guards until it finishes, and a
    /// second one inside that window is refused with
    /// [`RuntimeUpdateError::ExecutionConflict`]. Storing a new task therefore
    /// only ever displaces a finished one.
    execution_supervisor: Mutex<Option<JoinHandle<()>>>,
}

impl<
    Store: Storage,
    UpdatePolicy: RuntimeUpdatePolicy<Lock, Store::CollectionHandle>,
    Lock: LockStateProvider,
> DefaultRuntimeUpdatePlugin<Store, UpdatePolicy, Lock>
{
    /// Creates a new plugin instance.
    ///
    /// # Arguments
    /// * `storage` - Persistent storage backend for update files
    /// * `dispatcher` - Runs the runtime transition an execution asks for
    /// * `policy` - Decides whether an execution may proceed given vehicle and lock state
    /// * `lock_provider` - Provides lock state for the policy
    /// * `file_inspector` - Format-specific validation, metadata and revision reads
    pub fn new(
        storage: Arc<Store>,
        dispatcher: Arc<dyn UpdateDispatcher>,
        policy: Arc<UpdatePolicy>,
        lock_provider: Arc<Lock>,
        file_inspector: Arc<dyn RuntimeFileInspector>,
    ) -> Self {
        Self {
            storage,
            dispatcher,
            policy,
            lock_provider,
            executions: Arc::new(RwLock::new(HashMap::default())),
            file_inspector,
            execution_supervisor: Mutex::new(None),
        }
    }
}

#[async_trait]
impl<
    Store: Storage + Send + Sync + 'static,
    UpdatePolicy: RuntimeUpdatePolicy<Lock, Store::CollectionHandle>,
    Lock: LockStateProvider,
> cda_interfaces::Shutdown for DefaultRuntimeUpdatePlugin<Store, UpdatePolicy, Lock>
{
    /// Awaits an in-flight execution; never aborts one.
    ///
    /// The execution holds the communication disable lease and is midway
    /// through swapping the live database, so cutting it leaves exactly the
    /// torn state the update path exists to avoid. The wait is bounded by
    /// `UPDATE_SHUTDOWN_GRACE`; on elapse a warning is logged and shutdown
    /// proceeds. Taking the handle out makes it idempotent.
    ///
    /// # TODO
    ///
    /// This is not hooked up yet, because there is no good place to do so at the
    /// moment. It must be done in the context of #533.
    /// It is implemented here already, to have the general plugin architecture in place.
    async fn shutdown(&self) {
        let Some(supervisor) =
            cda_interfaces::util::std_ext::lock_mutex(&self.execution_supervisor).take()
        else {
            return;
        };

        match tokio::time::timeout(UPDATE_SHUTDOWN_GRACE, supervisor).await {
            Ok(Ok(())) => {}
            Ok(Err(join_error)) => {
                // The supervisor already reported the execution as abnormally
                // terminated; nothing is left to wait for.
                tracing::debug!(
                    error = %join_error,
                    "Runtime update supervisor ended abnormally during shutdown"
                );
            }
            Err(_elapsed) => {
                tracing::warn!(
                    grace_period = ?UPDATE_SHUTDOWN_GRACE,
                    "Runtime update did not finish within the shutdown grace period; shutting \
                     down while it is still running"
                );
            }
        }
    }
}

#[async_trait]
impl<
    Store: Storage + Send + Sync + 'static,
    UpdatePolicy: RuntimeUpdatePolicy<Lock, Store::CollectionHandle>,
    Lock: LockStateProvider,
> RuntimeFileCatalog for DefaultRuntimeUpdatePlugin<Store, UpdatePolicy, Lock>
{
    async fn list_current(
        &self,
        query: &RuntimeFilesQuery,
    ) -> Result<BulkDataList, RuntimeUpdateError> {
        crate::storage::list_current_files(&*self.storage, query, &*self.file_inspector).await
    }

    async fn list_nextupdate(
        &self,
        query: &RuntimeFilesQuery,
    ) -> Result<BulkDataList, RuntimeUpdateError> {
        crate::storage::compute_nextupdate_state(&*self.storage, query, &*self.file_inspector).await
    }

    async fn list_backup(
        &self,
        query: &RuntimeFilesQuery,
    ) -> Result<BulkDataList, RuntimeUpdateError> {
        crate::storage::list_backup_files(&*self.storage, query, &*self.file_inspector).await
    }
}

#[async_trait]
impl<
    Store: Storage + Send + Sync + 'static,
    UpdatePolicy: RuntimeUpdatePolicy<Lock, Store::CollectionHandle>,
    Lock: LockStateProvider,
> RuntimeFileStore for DefaultRuntimeUpdatePlugin<Store, UpdatePolicy, Lock>
{
    async fn upload(
        &self,
        files: Vec<UploadFile>,
    ) -> Result<BulkDataCreatedList, RuntimeUpdateError> {
        crate::storage::upload_files(&*self.storage, &*self.file_inspector, files).await
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
    UpdatePolicy: RuntimeUpdatePolicy<Lock, Store::CollectionHandle>,
    Lock: LockStateProvider,
> RuntimeUpdateExecutor for DefaultRuntimeUpdatePlugin<Store, UpdatePolicy, Lock>
{
    async fn start_execution(&self, mode: ExecutionMode) -> Result<String, RuntimeUpdateError> {
        let params = crate::operations::executions::ExecutionParams {
            storage: &self.storage,
            policy: &self.policy,
            dispatcher: &self.dispatcher,
            executions: &self.executions,
            lock_state_provider: &*self.lock_provider,
            file_inspector: &self.file_inspector,
            execution_supervisor: &self.execution_supervisor,
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

#[async_trait]
impl<
    Store: Storage + Send + Sync + 'static,
    UpdatePolicy: RuntimeUpdatePolicy<Lock, Store::CollectionHandle>,
    Lock: LockStateProvider,
> RuntimeFileTransaction for DefaultRuntimeUpdatePlugin<Store, UpdatePolicy, Lock>
{
    async fn apply_files(&self) -> Result<(), RuntimeUpdateError> {
        crate::operations::apply::execute_apply(&*self.storage).await
    }

    async fn rollback_files(&self) -> Result<(), RuntimeUpdateError> {
        crate::operations::rollback::restore_backup(&*self.storage).await
    }

    async fn discard_staged(&self) -> Result<(), RuntimeUpdateError> {
        crate::operations::rollback::discard_staged(&*self.storage).await
    }

    async fn cleanup_files(&self) -> Result<(), RuntimeUpdateError> {
        crate::operations::cleanup::execute_cleanup(&*self.storage).await
    }

    async fn restore_after_apply(&self) -> Result<(), RuntimeUpdateError> {
        crate::operations::rollback::restore_backup_and_restage_rejected(&*self.storage).await
    }

    async fn restore_after_rollback(&self) -> Result<(), RuntimeUpdateError> {
        crate::operations::rollback::restore_backup(&*self.storage).await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Mutex as StdMutex},
        time::Duration,
    };

    use async_trait::async_trait;
    use cda_interfaces::{
        Shutdown,
        runtime_update_api::{
            AcceptedUpdate, ExecutionFailure, ExecutionMode, ExecutionStatus, HashAlgorithm,
            RuntimeFileCatalog, RuntimeFileStore, RuntimeFilesQuery, RuntimeUpdateError,
            RuntimeUpdateExecutor, UpdateDispatcher,
        },
        storage_api::CollectionName,
    };
    use cda_storage::LocalStorage;
    use tokio::sync::oneshot;

    use crate::{
        DefaultRuntimeUpdatePlugin,
        test_utils::{
            MockLockProvider, MockUpdatePolicy, make_storage, make_upload_files, make_valid_config,
            readable_mdd_bytes, write_test_file,
        },
    };

    /// Stands in for the application's lifecycle, holding the dispatch open
    /// until the test ends it.
    struct HeldDispatcher {
        outcome: StdMutex<Option<oneshot::Sender<Result<(), ExecutionFailure>>>>,
    }

    impl HeldDispatcher {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                outcome: StdMutex::new(None),
            })
        }

        /// Ends the dispatch the way the runtime would, once its guards are down.
        fn finish(&self) {
            if let Some(sender) = self.outcome.lock().expect("poisoned").take() {
                sender.send(Ok(())).ok();
            }
        }
    }

    #[async_trait]
    impl UpdateDispatcher for HeldDispatcher {
        async fn dispatch(
            &self,
            _mode: ExecutionMode,
        ) -> Result<AcceptedUpdate, RuntimeUpdateError> {
            let (sender, receiver) = oneshot::channel();
            *self.outcome.lock().expect("poisoned") = Some(sender);
            Ok(AcceptedUpdate {
                completion: Box::pin(async move {
                    receiver
                        .await
                        .unwrap_or(Err(ExecutionFailure::AbnormalTermination))
                }),
            })
        }
    }

    fn make_plugin(
        storage: LocalStorage,
    ) -> DefaultRuntimeUpdatePlugin<LocalStorage, MockUpdatePolicy, MockLockProvider> {
        make_plugin_with(storage, HeldDispatcher::new() as Arc<dyn UpdateDispatcher>)
    }

    fn make_plugin_with(
        storage: LocalStorage,
        dispatcher: Arc<dyn UpdateDispatcher>,
    ) -> DefaultRuntimeUpdatePlugin<LocalStorage, MockUpdatePolicy, MockLockProvider> {
        DefaultRuntimeUpdatePlugin::new(
            Arc::new(storage),
            dispatcher,
            Arc::new(MockUpdatePolicy::new()),
            Arc::new(MockLockProvider {
                owner: Some("test-user".to_owned()),
                has_conflicts: false,
            }),
            crate::test_utils::test_inspector(),
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

    /// An execution mid storage-swap must not be cut off by shutdown: the
    /// dispatch it started holds the communication disable lease and has already
    /// replaced part of the live database, so shutdown waits for it to finish.
    #[tokio::test]
    async fn shutdown_waits_for_an_execution_that_is_still_running() {
        let (storage, _dir) = make_storage();
        write_test_file(
            &storage,
            &CollectionName::DiagnosticDatabaseNextUpdate,
            "ecu.mdd",
            &readable_mdd_bytes("TestEcu"),
        )
        .await;
        let dispatcher = HeldDispatcher::new();
        let plugin = Arc::new(make_plugin_with(
            storage,
            Arc::clone(&dispatcher) as Arc<dyn UpdateDispatcher>,
        ));

        plugin
            .start_execution(ExecutionMode::Apply)
            .await
            .expect("the apply must start");

        let mut shutting_down = tokio::task::spawn({
            let plugin = Arc::clone(&plugin);
            async move { plugin.shutdown().await }
        });

        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut shutting_down)
                .await
                .is_err(),
            "shutdown must not return while the execution is still swapping the database"
        );

        dispatcher.finish();
        tokio::time::timeout(Duration::from_secs(5), shutting_down)
            .await
            .expect("shutdown must return once the execution has finished")
            .expect("the shutdown task must not panic");

        let executions = plugin.list_executions().await;
        let status = executions.first().map(|execution| &execution.status);
        assert!(
            matches!(status, Some(ExecutionStatus::Completed)),
            "shutdown must have waited for the execution to reach a terminal status, got \
             {status:?}"
        );
    }

    /// Taking the handle out is what makes shutdown idempotent, so a second
    /// call must still return rather than wait on nothing.
    #[tokio::test]
    async fn shutdown_is_idempotent() {
        let (storage, _dir) = make_storage();
        let dispatcher = HeldDispatcher::new();
        let plugin = make_plugin_with(
            storage,
            Arc::clone(&dispatcher) as Arc<dyn UpdateDispatcher>,
        );

        plugin
            .start_execution(ExecutionMode::Cleanup)
            .await
            .expect("the cleanup must start");
        dispatcher.finish();

        for _ in 0..2 {
            tokio::time::timeout(Duration::from_secs(1), plugin.shutdown())
                .await
                .expect("shutdown must not block once the execution has finished");
        }
    }
}
