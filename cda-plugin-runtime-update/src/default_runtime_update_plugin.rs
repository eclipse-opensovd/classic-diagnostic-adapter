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
    communication_control::{DisableCommunication, PostUpdateCommunicationMode},
    http_protection::registry::{HttpProtectionRegistry, HttpRouteMatcher},
    runtime_update_api::{
        BulkDataCreatedList, BulkDataList, DatabaseValidator, ExecutionMode, LockStateProvider,
        RuntimeFileCatalog, RuntimeFileStore, RuntimeFilesQuery, RuntimeReloaderPlugin,
        RuntimeUpdateError, RuntimeUpdateExecutor, RuntimeUpdatePolicy, UpdateExecution,
        UploadFile,
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

/// Default implementation of [`RuntimeFileCatalog`], [`RuntimeFileStore`] and
/// [`RuntimeUpdateExecutor`], with injectable policy and storage.
pub struct DefaultRuntimeUpdatePlugin<
    Store: Storage,
    UpdatePolicy: RuntimeUpdatePolicy<Lock, Store::CollectionHandle>,
    Lock: LockStateProvider,
> {
    /// Access to the persistent storage layer (all mutations go through this)
    storage: Arc<Store>,
    /// Hot-reload notification handler
    reloader_plugin: Arc<dyn RuntimeReloaderPlugin>,
    /// Vehicle and lock state policy consulted before an execution proceeds
    policy: Arc<UpdatePolicy>,
    /// Lock state provider passed to the policy
    lock_provider: Arc<Lock>,
    /// Tracking map for in-progress executions: `exec_id` -> `DbUpdateExecution`
    executions: Arc<RwLock<HashMap<String, UpdateExecution>>>,
    /// Integrator-provided MDD integrity validation.
    database_validator: Arc<dyn DatabaseValidator>,
    communication_disable: Arc<dyn DisableCommunication>,
    http_protections: HttpProtectionRegistry,
    update_exempt_routes: Vec<HttpRouteMatcher>,
    update_retry_after: Duration,
    post_update_mode: PostUpdateCommunicationMode,
    /// Supervisor task of the execution that is in flight, so shutdown can
    /// await it instead of letting it be cut off.
    ///
    /// A single slot is enough because at most one execution is ever live: an
    /// execution takes the exclusive communication disable lease in
    /// `start_execution` and holds it until its own finalization, and a second
    /// `start_execution` inside that window is refused with
    /// `DisableError::Conflict`, surfaced as
    /// [`RuntimeUpdateError::ExecutionConflict`]. Storing a new supervisor
    /// therefore only ever displaces a finished one.
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
    /// * `reload_handler` - Notified after apply/rollback to hot-reload databases
    /// * `policy` - Decides whether an execution may proceed given vehicle and lock state
    /// * `lock_provider` - Provides lock state for the policy
    /// * `database_validator` - Integrator-provided MDD integrity validation
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
        policy: Arc<UpdatePolicy>,
        lock_provider: Arc<Lock>,
        database_validator: Arc<dyn DatabaseValidator>,
        communication_disable: Arc<dyn DisableCommunication>,
        http_protections: HttpProtectionRegistry,
        update_exempt_routes: Vec<HttpRouteMatcher>,
        update_retry_after: Duration,
        post_update_mode: PostUpdateCommunicationMode,
    ) -> Self {
        Self {
            storage,
            reloader_plugin,
            policy,
            lock_provider,
            executions: Arc::new(RwLock::new(HashMap::default())),
            database_validator,
            communication_disable,
            http_protections,
            update_exempt_routes,
            update_retry_after,
            post_update_mode,
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
    UpdatePolicy: RuntimeUpdatePolicy<Lock, Store::CollectionHandle>,
    Lock: LockStateProvider,
> RuntimeFileStore for DefaultRuntimeUpdatePlugin<Store, UpdatePolicy, Lock>
{
    async fn upload(
        &self,
        files: Vec<UploadFile>,
    ) -> Result<BulkDataCreatedList, RuntimeUpdateError> {
        crate::storage::upload_files(&*self.storage, &*self.database_validator, files).await
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
            reload_handler: &self.reloader_plugin,
            executions: &self.executions,
            communication_disable: &self.communication_disable,
            http_protections: &self.http_protections,
            update_exempt_routes: &self.update_exempt_routes,
            update_retry_after: self.update_retry_after,
            post_update_mode: self.post_update_mode.clone(),
            lock_state_provider: &*self.lock_provider,
            database_validator: &self.database_validator,
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

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use async_trait::async_trait;
    use cda_interfaces::{
        Shutdown,
        communication_control::{CommunicationState, PostUpdateCommunicationMode},
        http_protection::registry::HttpProtectionRegistry,
        runtime_update_api::{
            ExecutionMode, ExecutionStatus, HashAlgorithm, RejectedSetDisposition, ReloadFailure,
            RuntimeFileCatalog, RuntimeFileStore, RuntimeFilesQuery, RuntimeReloaderPlugin,
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
            MockLockProvider, MockUpdatePolicy, NoopReloadHandler, StubTransport, make_storage,
            make_upload_files, make_valid_config, readable_mdd_bytes, write_test_file,
        },
    };

    fn make_plugin(
        storage: LocalStorage,
    ) -> DefaultRuntimeUpdatePlugin<LocalStorage, MockUpdatePolicy, MockLockProvider> {
        let (plugin, _disable_comm) = make_state_with_lock(storage, Some("test-user"), false);
        plugin
    }

    fn make_state_with_lock(
        storage: LocalStorage,
        owner: Option<&str>,
        has_conflicts: bool,
    ) -> (
        DefaultRuntimeUpdatePlugin<LocalStorage, MockUpdatePolicy, MockLockProvider>,
        Arc<dyn DisableCommunication>,
    ) {
        make_state_with_reloader(storage, owner, has_conflicts, Arc::new(NoopReloadHandler))
    }

    fn make_state_with_reloader(
        storage: LocalStorage,
        owner: Option<&str>,
        has_conflicts: bool,
        reloader_plugin: Arc<dyn RuntimeReloaderPlugin>,
    ) -> (
        DefaultRuntimeUpdatePlugin<LocalStorage, MockUpdatePolicy, MockLockProvider>,
        Arc<dyn DisableCommunication>,
    ) {
        let transport = StubTransport::new();
        let http_protections = HttpProtectionRegistry::new();
        let communication_disable = communication_disable_for_test(transport, false);

        let plugin = DefaultRuntimeUpdatePlugin::new(
            Arc::new(storage),
            reloader_plugin,
            Arc::new(MockUpdatePolicy::new()),
            Arc::new(MockLockProvider {
                owner: owner.map(ToOwned::to_owned),
                has_conflicts,
            }),
            crate::test_utils::test_database_validator(),
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
            &readable_mdd_bytes("TestEcu"),
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
            &readable_mdd_bytes("TestEcu"),
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

    /// A reloader that parks inside `reload_databases` until the test lets it
    /// through, holding an execution in flight long enough to observe what
    /// shutdown does with it.
    struct GatedReloadHandler {
        entered: tokio::sync::mpsc::UnboundedSender<()>,
        gate: Arc<tokio::sync::Semaphore>,
    }

    /// Test-side handle to [`GatedReloadHandler`]'s reload.
    struct ReloadGate {
        entered: tokio::sync::mpsc::UnboundedReceiver<()>,
        gate: Arc<tokio::sync::Semaphore>,
    }

    impl GatedReloadHandler {
        fn new() -> (Arc<Self>, ReloadGate) {
            let (entered_tx, entered_rx) = tokio::sync::mpsc::unbounded_channel();
            let gate = Arc::new(tokio::sync::Semaphore::new(0));
            let handler = Arc::new(Self {
                entered: entered_tx,
                gate: Arc::clone(&gate),
            });
            let reload = ReloadGate {
                entered: entered_rx,
                gate,
            };
            (handler, reload)
        }
    }

    impl ReloadGate {
        /// Resolves once the reload has started and is parked on the gate.
        async fn entered(&mut self) {
            self.entered
                .recv()
                .await
                .expect("the reload must be reached");
        }

        /// Lets the parked reload run to completion.
        fn release(&self) {
            self.gate.add_permits(1);
        }
    }

    #[async_trait]
    impl RuntimeReloaderPlugin for GatedReloadHandler {
        async fn reload_databases(
            &self,
            _on_reject: RejectedSetDisposition,
        ) -> Result<(), ReloadFailure> {
            let _ = self.entered.send(());
            let _permit = self
                .gate
                .acquire()
                .await
                .expect("gate must not be closed while a reload is parked on it");
            Ok(())
        }
    }

    /// An execution mid storage-swap must not be cut off by shutdown: it holds
    /// the communication disable lease and has already replaced part of the
    /// live database, so shutdown waits for it to finalize itself.
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
        let (reloader, mut reload) = GatedReloadHandler::new();
        let (plugin, _disable_comm) =
            make_state_with_reloader(storage, Some("test-user"), false, reloader);
        let plugin = Arc::new(plugin);

        plugin
            .start_execution(ExecutionMode::Apply)
            .await
            .expect("the apply must start");
        reload.entered().await;

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

        reload.release();
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
        let plugin = make_plugin(storage);

        plugin
            .start_execution(ExecutionMode::Cleanup)
            .await
            .expect("the cleanup must start");

        for _ in 0..2 {
            tokio::time::timeout(Duration::from_secs(1), plugin.shutdown())
                .await
                .expect("shutdown must not block once the execution has finished");
        }
    }
}
