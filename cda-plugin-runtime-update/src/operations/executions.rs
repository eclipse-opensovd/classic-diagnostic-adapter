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

use cda_interfaces::{
    HashMap,
    communication_control::{
        DisableCommunication, DisableError, DisableGuard, DisableReason,
        PostUpdateCommunicationMode,
    },
    http_protection::registry::{
        HttpProtectionConfig, HttpProtectionReason, HttpProtectionRegistry, HttpRouteMatcher,
        HttpStatusCode, OwnedHttpProtection,
    },
    runtime_update_api::{
        ExecutionFailure, ExecutionMode, ExecutionStatus, LockStateProvider, ReloadFailure,
        RuntimeReloaderPlugin, RuntimeUpdateError, RuntimeUpdateSecurityPlugin, UpdateCollections,
        UpdateExecution,
    },
    storage_api::{Collection, CollectionName, DirectFileAccess, Storage},
};
use tokio::sync::RwLock;

pub(crate) struct ExecutionParams<'a, S, R: ?Sized, T, L> {
    pub(crate) storage: &'a Arc<S>,
    pub(crate) security_handler: &'a Arc<T>,
    pub(crate) reload_handler: &'a Arc<R>,
    pub(crate) executions: &'a Arc<RwLock<HashMap<String, UpdateExecution>>>,
    pub(crate) communication_disable: &'a Arc<dyn DisableCommunication>,
    pub(crate) http_protections: &'a HttpProtectionRegistry,
    pub(crate) update_exempt_routes: &'a [HttpRouteMatcher],
    pub(crate) update_retry_after: Duration,
    pub(crate) post_update_mode: PostUpdateCommunicationMode,
    pub(crate) lock_state_provider: &'a L,
}

fn http_protection_config_for_update(
    retry_after: Duration,
    exempt_routes: &[HttpRouteMatcher],
) -> HttpProtectionConfig {
    HttpProtectionConfig::new(
        HttpProtectionReason::UpdateInProgress,
        HttpStatusCode::CONFLICT,
        "Update in progress",
    )
    .with_exempt_routes(exempt_routes.to_vec())
    .with_retry_after(retry_after)
}

pub(crate) async fn start_execution<S, R, T, L>(
    params: &ExecutionParams<'_, S, R, T, L>,
    mode: ExecutionMode,
) -> Result<String, RuntimeUpdateError>
where
    S: Storage + Send + Sync + 'static,
    R: RuntimeReloaderPlugin + ?Sized,
    T: RuntimeUpdateSecurityPlugin<L, S::CollectionHandle>,
    L: LockStateProvider,
{
    let (protection, disable_lease) = acquire_execution_guards(params).await?;
    let collections = match load_update_collections(&**params.storage).await {
        Ok(collections) => collections,
        Err(error) => {
            return Err(reject_execution(error, protection, disable_lease, mode).await);
        }
    };
    let (protection, disable_lease) =
        validate_execution_preconditions(params, mode, &collections, protection, disable_lease)
            .await?;
    let execution_id = register_execution(params.executions, mode).await;

    spawn_execution(
        SpawnExecution {
            mode,
            execution_id: execution_id.clone(),
            storage: Arc::clone(params.storage),
            reload_handler: Arc::clone(params.reload_handler),
            executions: Arc::clone(params.executions),
            post_update_mode: params.post_update_mode.clone(),
        },
        ExecutionGuards::new(protection, disable_lease),
    );

    Ok(execution_id)
}

async fn acquire_execution_guards<S, R: ?Sized, T, L>(
    params: &ExecutionParams<'_, S, R, T, L>,
) -> Result<(OwnedHttpProtection, Box<dyn DisableGuard>), RuntimeUpdateError> {
    let protection = params
        .http_protections
        .protect(http_protection_config_for_update(
            params.update_retry_after,
            params.update_exempt_routes,
        ))
        .map_err(|error| {
            // Built in-process, so this is a programming error. Refuse the
            // execution rather than run it unprotected.
            RuntimeUpdateError::FatalError(format!(
                "Invalid HTTP protection configuration for update: {error}"
            ))
        })?;
    let disable_lease = params
        .communication_disable
        .disable(DisableReason::RuntimeUpdate)
        .await
        .map_err(|error| match error {
            DisableError::Conflict => RuntimeUpdateError::ExecutionConflict,
            DisableError::InUse => RuntimeUpdateError::OperationsInProgress(
                "another operation is running (i.e. flash transfer)".to_string(),
            ),
            DisableError::Failed(failure) => {
                RuntimeUpdateError::CommunicationFailure(failure.to_string())
            }
        })?;

    Ok((protection, disable_lease))
}

/// Rejects an execution whose incoming databases cannot be read.
///
/// A framework precondition rather than a security-plugin concern: readability
/// is not policy, and an application that replaces the plugin must not be able
/// to drop it. Refusing here also keeps the rejection synchronous, before any
/// collection has moved.
async fn validate_incoming_databases<C: Collection + DirectFileAccess>(
    collection: &C,
) -> Result<(), RuntimeUpdateError> {
    for key in collection.list().await? {
        if !key.to_lowercase().ends_with(".mdd") {
            continue;
        }
        crate::mdd::validate(&collection.file_path(&key)?)
            .map_err(|error| RuntimeUpdateError::ValidationFailed(error.to_string()))?;
    }
    Ok(())
}

async fn load_update_collections<S>(
    storage: &S,
) -> Result<UpdateCollections<S::CollectionHandle>, RuntimeUpdateError>
where
    S: Storage + Send + Sync + 'static,
{
    Ok(UpdateCollections {
        pending_mdd: crate::operations::try_get_collection(
            storage,
            &CollectionName::DiagnosticDatabaseNextUpdate,
        )
        .await?,
        current_mdd: crate::operations::try_get_collection(
            storage,
            &CollectionName::DiagnosticDatabase,
        )
        .await?,
        backup_mdd: crate::operations::try_get_collection(
            storage,
            &CollectionName::DiagnosticDatabaseBackup,
        )
        .await?,
    })
}

async fn validate_execution_preconditions<S, R, T, L>(
    params: &ExecutionParams<'_, S, R, T, L>,
    mode: ExecutionMode,
    collections: &UpdateCollections<S::CollectionHandle>,
    protection: OwnedHttpProtection,
    disable_lease: Box<dyn DisableGuard>,
) -> Result<(OwnedHttpProtection, Box<dyn DisableGuard>), RuntimeUpdateError>
where
    S: Storage + Send + Sync + 'static,
    R: RuntimeReloaderPlugin + ?Sized,
    T: RuntimeUpdateSecurityPlugin<L, S::CollectionHandle>,
    L: LockStateProvider,
{
    if let Err(error) = params
        .security_handler
        .check_execution_allowed(params.lock_state_provider, collections)
        .await
    {
        return Err(reject_execution(error, protection, disable_lease, mode).await);
    }

    if mode == ExecutionMode::Rollback {
        match crate::storage::backup_snapshot_exists(&**params.storage).await {
            Ok(false) => {
                return Err(reject_execution(
                    RuntimeUpdateError::NoBackup,
                    protection,
                    disable_lease,
                    mode,
                )
                .await);
            }
            Err(error) => {
                return Err(reject_execution(error, protection, disable_lease, mode).await);
            }
            Ok(true) => {}
        }
    }

    // For Apply: verify there is at least one pending NextUpdate collection before
    // accepting the request. This mirrors the Rollback check above, and must happen
    // before spawning the task so that the 404 is returned synchronously instead of
    // 202 being sent with a later Failed status (execute_apply's own check runs
    // inside the spawned task and is too late to affect the HTTP response).
    if mode == ExecutionMode::Apply && collections.pending_mdd.is_none() {
        return Err(reject_execution(
            RuntimeUpdateError::NoPendingUpdate,
            protection,
            disable_lease,
            mode,
        )
        .await);
    }

    // The databases this mode is about to make live. `Cleanup` makes none live.
    let becoming_live = match mode {
        ExecutionMode::Apply => collections.pending_mdd.as_ref(),
        ExecutionMode::Rollback => collections.backup_mdd.as_ref(),
        ExecutionMode::Cleanup => None,
    };
    if let Some(collection) = becoming_live
        && let Err(error) = validate_incoming_databases(&**collection).await
    {
        return Err(reject_execution(error, protection, disable_lease, mode).await);
    }

    Ok((protection, disable_lease))
}

async fn reject_execution(
    error: RuntimeUpdateError,
    protection: OwnedHttpProtection,
    disable_lease: Box<dyn DisableGuard>,
    mode: ExecutionMode,
) -> RuntimeUpdateError {
    // Restore communication before dropping HTTP protection so ordinary requests cannot enter
    // while the transport is still unavailable.
    match disable_lease.release().await {
        Ok(_) => {
            drop(protection);
            error
        }
        Err(release_failure) => {
            // Nothing was applied, so the runtime is coherent; only communication
            // is left down until a later authorized activation.
            tracing::error!(
                error = %error,
                release_failure = %release_failure,
                ?mode,
                "Failed to resume transport after rejecting runtime update"
            );
            drop(protection);
            RuntimeUpdateError::CommunicationFailure(
                "Communication could not be restored after rejecting the update".to_owned(),
            )
        }
    }
}

async fn register_execution(
    executions: &Arc<RwLock<HashMap<String, UpdateExecution>>>,
    mode: ExecutionMode,
) -> String {
    let execution_id = uuid::Uuid::new_v4().to_string();
    let mut execs = executions.write().await;
    execs.retain(|_, execution| execution.status == ExecutionStatus::Running);
    execs.insert(
        execution_id.clone(),
        UpdateExecution {
            id: execution_id.clone(),
            mode,
            status: ExecutionStatus::Running,
        },
    );
    execution_id
}

struct SpawnExecution<S, R: ?Sized> {
    mode: ExecutionMode,
    execution_id: String,
    storage: Arc<S>,
    reload_handler: Arc<R>,
    executions: Arc<RwLock<HashMap<String, UpdateExecution>>>,
    post_update_mode: PostUpdateCommunicationMode,
}

struct ExecutionGuards {
    protection: Option<OwnedHttpProtection>,
    disable_lease: Option<Box<dyn DisableGuard>>,
}

impl ExecutionGuards {
    fn new(protection: OwnedHttpProtection, disable_lease: Box<dyn DisableGuard>) -> Self {
        Self {
            protection: Some(protection),
            disable_lease: Some(disable_lease),
        }
    }
}

/// How an execution hands the runtime back.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Finalization {
    /// The live database is known good. Settle communication and lift the
    /// update's protection so ordinary traffic resumes.
    Settle {
        /// Leave communication disabled for an explicit activation instead of
        /// restoring what the lease displaced.
        defer: bool,
    },
    /// The previous database could not be restored, so nothing about the live
    /// state is trustworthy. Communication stays disabled and the protection
    /// stays registered until an operator restarts the process.
    Quarantine,
}

/// Finishes the execution: settle communication and drop the HTTP protection.
///
/// A failed settle is logged, not compensated. The reload itself already
/// committed or rolled back inside `reload_databases`, so what is live is
/// coherent either way; only communication is left down for a later activation.
async fn finish_execution<S, R>(
    task: &SpawnExecution<S, R>,
    guards: &mut ExecutionGuards,
    finalization: Finalization,
) where
    S: Storage + Send + Sync + 'static,
    R: RuntimeReloaderPlugin + ?Sized,
{
    let lease = guards
        .disable_lease
        .take()
        .expect("update owns its disable lease until finalization");
    let settled = match finalization {
        Finalization::Settle { defer: false } => lease.release().await.map(|_| ()),
        Finalization::Settle { defer: true } | Finalization::Quarantine => lease.finish().await,
    };
    if let Err(failure) = settled {
        tracing::error!(
            execution_id = %task.execution_id,
            mode = ?task.mode,
            %failure,
            "Update finished but communication could not be settled; it stays disabled until an \
             authorized activation"
        );
    }

    let protection = guards
        .protection
        .take()
        .expect("update owns its HTTP protection until finalization");
    match finalization {
        Finalization::Settle { .. } => drop(protection),
        // Deliberately never lifted: a degraded runtime must keep refusing
        // requests, and only a restart clears this.
        Finalization::Quarantine => protection.retain(),
    }
}

async fn run_execution_frame<S, R>(task: &SpawnExecution<S, R>, guards: &mut ExecutionGuards)
where
    S: Storage + Send + Sync + 'static,
    R: RuntimeReloaderPlugin + ?Sized,
{
    let outcome = execute_operation(task.mode, &*task.storage, &*task.reload_handler).await;
    let (status, finalization) = match &outcome {
        Ok(()) => (
            ExecutionStatus::Completed,
            Finalization::Settle {
                defer: matches!(task.mode, ExecutionMode::Apply | ExecutionMode::Rollback)
                    && matches!(task.post_update_mode, PostUpdateCommunicationMode::Deferred),
            },
        ),
        Err(RuntimeUpdateError::ReloadFailed(ReloadFailure::RecoveryRequired {
            original,
            recovery,
            phase,
        })) => {
            tracing::error!(
                execution_id = %task.execution_id,
                mode = ?task.mode,
                ?phase,
                %original,
                %recovery,
                "Runtime update failed and the previous database could not be restored; the \
                 runtime is degraded and needs a restart"
            );
            (
                ExecutionStatus::Failed(ExecutionFailure::fatal(format!(
                    "Runtime update failed in {phase:?} and the previous database could not be \
                     restored: {original}; recovery failed: {recovery}"
                ))),
                Finalization::Quarantine,
            )
        }
        Err(error) => {
            tracing::error!(
                execution_id = %task.execution_id,
                mode = ?task.mode,
                %error,
                "Runtime update failed; the previous database is still live"
            );
            (
                ExecutionStatus::Failed(ExecutionFailure::ordinary(error.to_string())),
                Finalization::Settle { defer: false },
            )
        }
    };

    finish_execution(task, guards, finalization).await;
    // Publish last: clients treat a terminal status as permission to resume ordinary traffic.
    publish_terminal_status(&task.executions, &task.execution_id, task.mode, status).await;
}

fn spawn_execution<S, R>(task: SpawnExecution<S, R>, mut guards: ExecutionGuards)
where
    S: Storage + Send + Sync + 'static,
    R: RuntimeReloaderPlugin + ?Sized,
{
    let mode = task.mode;
    let supervised_executions = Arc::clone(&task.executions);
    let supervised_execution_id = task.execution_id.clone();

    let handle = cda_interfaces::spawn_named!(&format!("runtime-update-{mode:?}"), async move {
        run_execution_frame(&task, &mut guards).await;
    });

    // A panic in `execute_operation` unwinds past the status write and leaves
    // the execution record `Running` forever. This supervisor awaits the
    // `JoinHandle` and marks the execution `Failed` when the task ended without
    // a terminal status. The class is fatal: unwinding skipped finalization, so
    // whether the swap completed is unknown.
    drop(cda_interfaces::spawn_named!(
        &format!("runtime-update-{mode:?}-supervisor"),
        async move {
            if let Err(join_error) = handle.await {
                tracing::error!(
                    execution_id = %supervised_execution_id,
                    mode = ?mode,
                    error = %join_error,
                    "runtime update task ended without completing normally"
                );
                let mut map = supervised_executions.write().await;
                if let Some(execution) = map.get_mut(&supervised_execution_id)
                    && execution.status == ExecutionStatus::Running
                {
                    execution.status = ExecutionStatus::Failed(ExecutionFailure::fatal(format!(
                        "execution task ended abnormally: {join_error}"
                    )));
                }
            }
        }
    ));
}

async fn publish_terminal_status(
    executions: &Arc<RwLock<HashMap<String, UpdateExecution>>>,
    execution_id: &str,
    mode: ExecutionMode,
    status: ExecutionStatus,
) {
    let mut map = executions.write().await;
    if let Some(execution) = map.get_mut(execution_id) {
        execution.status = status;
    } else {
        tracing::error!(
            execution_id,
            mode = ?mode,
            "Runtime update execution completed without an execution record"
        );
    }
}

pub(crate) async fn get_execution_status(
    executions: &Arc<RwLock<HashMap<String, UpdateExecution>>>,
    execution_id: &str,
) -> Option<UpdateExecution> {
    let execs = executions.read().await;
    execs.get(execution_id).cloned()
}

async fn execute_operation<S, R>(
    mode: ExecutionMode,
    storage: &S,
    reload_handler: &R,
) -> Result<(), RuntimeUpdateError>
where
    S: Storage + Send + Sync + 'static,
    R: RuntimeReloaderPlugin + ?Sized,
{
    match mode {
        ExecutionMode::Apply => {
            crate::operations::apply::execute_apply(storage, reload_handler).await
        }
        ExecutionMode::Rollback => {
            crate::operations::rollback::execute_rollback(storage, reload_handler).await
        }
        ExecutionMode::Cleanup => crate::operations::cleanup::execute_cleanup(storage).await,
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use cda_interfaces::{
        HashMap,
        communication_control::{
            CommunicationOperation, CommunicationOperationFailure, CommunicationState,
            DisableGuard, PostUpdateCommunicationMode, TransportControl, TransportState,
            error::CommControlError,
        },
        http_protection::registry::{HttpProtectionRegistry, HttpRestrictionGuard},
        runtime_update_api::{
            ExecutionFailure, ExecutionFailureClass, ExecutionMode, ExecutionStatus, RecoveryPhase,
            ReloadError, ReloadFailure, RuntimeReloaderPlugin, RuntimeUpdateError, UpdateExecution,
        },
        storage_api::{Collection as _, CollectionName, Storage as _},
    };
    use cda_plugin_communication_management::lifecycle::{
        communication_disable_for_test, disable::DisableCommunication,
    };
    use cda_storage::LocalStorage;
    use tokio::sync::RwLock;

    use crate::test_utils::{
        MockLockProvider, MockSecurityHandler, NoopReloadHandler, StubTransport, make_storage,
        readable_mdd_bytes, write_test_file,
    };

    fn make_transport_and_disable() -> (HttpProtectionRegistry, Arc<dyn DisableCommunication>) {
        let transport = StubTransport::new();
        let restrictions = HttpProtectionRegistry::new();
        let disable = communication_disable_for_test(Arc::<StubTransport>::clone(&transport), true);
        (restrictions, disable)
    }

    /// A transport whose resume (`enable`) parks until the test lets it through,
    /// making the window between "the guards are coming down" and "they are
    /// down" long enough to observe.
    struct GatedTransport {
        entered: tokio::sync::mpsc::UnboundedSender<()>,
        gate: Arc<tokio::sync::Semaphore>,
        state: tokio::sync::Mutex<TransportState>,
    }

    /// Test-side handle to [`GatedTransport`]'s resume.
    struct ResumeGate {
        entered: tokio::sync::mpsc::UnboundedReceiver<()>,
        gate: Arc<tokio::sync::Semaphore>,
    }

    #[derive(Debug)]
    struct FailingFinalizationGuard;

    #[async_trait::async_trait]
    impl DisableGuard for FailingFinalizationGuard {
        async fn release(
            self: Box<Self>,
        ) -> Result<CommunicationState, CommunicationOperationFailure> {
            Err(CommunicationOperationFailure::TransitionFailure {
                operation: CommunicationOperation::Resume,
            })
        }

        async fn finish(self: Box<Self>) -> Result<(), CommunicationOperationFailure> {
            Err(CommunicationOperationFailure::TransitionFailure {
                operation: CommunicationOperation::FinishDisableLease,
            })
        }
    }

    struct RecoveryPreparationFails;

    #[async_trait::async_trait]
    impl RuntimeReloaderPlugin for RecoveryPreparationFails {
        async fn reload_databases(&self) -> Result<(), ReloadFailure> {
            Err(ReloadFailure::RecoveryRequired {
                original: ReloadError::ReplacementFailure("candidate state rejected".to_owned()),
                recovery: ReloadError::ReplacementFailure("restored state rejected".to_owned()),
                phase: RecoveryPhase::RestoredPreparation,
            })
        }
    }

    impl GatedTransport {
        fn new() -> (Arc<Self>, ResumeGate) {
            let (entered_tx, entered_rx) = tokio::sync::mpsc::unbounded_channel();
            let gate = Arc::new(tokio::sync::Semaphore::new(0));
            let transport = Arc::new(Self {
                entered: entered_tx,
                gate: Arc::clone(&gate),
                state: tokio::sync::Mutex::new(TransportState::Enabled),
            });
            let resume = ResumeGate {
                entered: entered_rx,
                gate,
            };
            (transport, resume)
        }
    }

    impl ResumeGate {
        /// Resolves once the resume has started and is parked on the gate.
        async fn entered(&mut self) {
            self.entered
                .recv()
                .await
                .expect("transport resume must be reached");
        }

        /// Lets the parked resume run to completion.
        fn release(&self) {
            self.gate.add_permits(1);
        }
    }

    #[async_trait::async_trait]
    impl TransportControl for GatedTransport {
        async fn enable(&self) -> Result<(), CommControlError> {
            let _ = self.entered.send(());
            let _permit = self
                .gate
                .acquire()
                .await
                .expect("gate must not be closed while a resume is parked on it");
            *self.state.lock().await = TransportState::Enabled;
            Ok(())
        }

        async fn disable(&self) -> Result<(), CommControlError> {
            *self.state.lock().await = TransportState::Disabled;
            Ok(())
        }

        async fn state(&self) -> TransportState {
            *self.state.lock().await
        }
    }

    struct TestFixture {
        storage: Arc<LocalStorage>,
        security_handler: Arc<MockSecurityHandler>,
        reload_handler: Arc<NoopReloadHandler>,
        lock_provider: MockLockProvider,
        executions: Arc<RwLock<HashMap<String, UpdateExecution>>>,
        communication_disable: Arc<dyn DisableCommunication>,
        http_restriction_manager: HttpProtectionRegistry,
        _dir: tempfile::TempDir,
    }

    impl TestFixture {
        fn params(
            &self,
        ) -> super::ExecutionParams<
            '_,
            LocalStorage,
            NoopReloadHandler,
            MockSecurityHandler,
            MockLockProvider,
        > {
            super::ExecutionParams {
                storage: &self.storage,
                security_handler: &self.security_handler,
                reload_handler: &self.reload_handler,
                executions: &self.executions,
                communication_disable: &self.communication_disable,
                http_protections: &self.http_restriction_manager,
                update_exempt_routes: &[],
                update_retry_after: Duration::from_secs(1),
                post_update_mode: PostUpdateCommunicationMode::Enabled,
                lock_state_provider: &self.lock_provider,
            }
        }
    }

    fn make_fixture() -> TestFixture {
        let (storage, dir) = make_storage();
        let (mgr, communication_disable) = make_transport_and_disable();
        TestFixture {
            storage: Arc::new(storage),
            security_handler: Arc::new(MockSecurityHandler::new()),
            reload_handler: Arc::new(NoopReloadHandler),
            lock_provider: MockLockProvider {
                owner: Some("test-user".to_owned()),
                has_conflicts: false,
            },
            executions: Arc::new(RwLock::new(HashMap::default())),
            communication_disable,
            http_restriction_manager: mgr,
            _dir: dir,
        }
    }

    async fn poll_until_terminal(
        executions: &Arc<RwLock<HashMap<String, UpdateExecution>>>,
        exec_id: &str,
    ) -> ExecutionStatus {
        let deadline = tokio::time::Instant::now()
            .checked_add(tokio::time::Duration::from_secs(5))
            .unwrap();
        loop {
            tokio::task::yield_now().await;
            if let Some(exec) = super::get_execution_status(executions, exec_id).await
                && exec.status != ExecutionStatus::Running
            {
                return exec.status;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "Execution did not complete within 5 seconds"
            );
        }
    }

    #[tokio::test]
    async fn start_execution_apply_returns_execution_id() {
        let f = make_fixture();
        write_test_file(
            &f.storage,
            &CollectionName::DiagnosticDatabaseNextUpdate,
            "ecu.mdd",
            &readable_mdd_bytes("TestEcu"),
        )
        .await;

        let exec_id = super::start_execution(&f.params(), ExecutionMode::Apply)
            .await
            .unwrap();
        assert!(!exec_id.is_empty());

        let status = super::get_execution_status(&f.executions, &exec_id).await;
        assert!(status.is_some());
    }

    #[tokio::test]
    async fn start_execution_rollback() {
        let f = make_fixture();
        write_test_file(
            &f.storage,
            &CollectionName::DiagnosticDatabaseBackup,
            "ecu.mdd",
            &readable_mdd_bytes("TestEcu"),
        )
        .await;

        let exec_id = super::start_execution(&f.params(), ExecutionMode::Rollback)
            .await
            .unwrap();
        assert!(!exec_id.is_empty());
        assert_eq!(
            poll_until_terminal(&f.executions, &exec_id).await,
            ExecutionStatus::Completed
        );
        let backup = f
            .storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabaseBackup)
            .await
            .unwrap();
        assert!(backup.is_empty().await.unwrap());
    }

    #[tokio::test]
    async fn start_execution_apply_with_no_pending_update_rejected_synchronously() {
        let f = make_fixture();

        // Nothing seeded into DiagnosticDatabaseNextUpdate:
        // Apply must be rejected synchronously (i.e. `start_execution` itself returns
        // an error) rather than accepted (202-equivalent execution id) only to fail
        // later inside the spawned task.
        let result = super::start_execution(&f.params(), ExecutionMode::Apply).await;

        assert!(
            matches!(result, Err(RuntimeUpdateError::NoPendingUpdate)),
            "expected NoPendingUpdate, got: {result:?}"
        );
        assert!(
            f.executions.read().await.is_empty(),
            "no execution should have been recorded for a synchronously-rejected apply"
        );
        // Transport should be re-enabled (restriction removed) after the error path.
        assert!(
            !f.http_restriction_manager.is_active(),
            "update restriction must be released after a synchronously-rejected apply"
        );
    }

    #[tokio::test]
    async fn start_execution_cleanup_succeeds() {
        let f = make_fixture();
        let exec_id = super::start_execution(&f.params(), ExecutionMode::Cleanup)
            .await
            .unwrap();
        assert!(!exec_id.is_empty());

        let status = poll_until_terminal(&f.executions, &exec_id).await;
        assert_eq!(status, ExecutionStatus::Completed);
    }

    /// A failed settle does not undo the update: the reload already committed,
    /// so the execution completes and only communication is left down.
    async fn assert_finalization_failure_does_not_fail_the_execution(
        post_update_mode: PostUpdateCommunicationMode,
    ) {
        let f = make_fixture();
        write_test_file(
            &f.storage,
            &CollectionName::DiagnosticDatabaseNextUpdate,
            "ecu.mdd",
            &readable_mdd_bytes("TestEcu"),
        )
        .await;
        let execution_id = super::register_execution(&f.executions, ExecutionMode::Apply).await;
        let protection = f
            .http_restriction_manager
            .protect(super::http_protection_config_for_update(
                Duration::from_secs(1),
                &[],
            ))
            .unwrap();
        super::spawn_execution(
            super::SpawnExecution {
                mode: ExecutionMode::Apply,
                execution_id: execution_id.clone(),
                storage: Arc::clone(&f.storage),
                reload_handler: Arc::clone(&f.reload_handler),
                executions: Arc::clone(&f.executions),
                post_update_mode,
            },
            super::ExecutionGuards::new(protection, Box::new(FailingFinalizationGuard)),
        );

        let status = poll_until_terminal(&f.executions, &execution_id).await;
        assert_eq!(status, ExecutionStatus::Completed);
        let current = f
            .storage
            .get_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        assert_eq!(current.list().await.unwrap(), ["ecu.mdd"]);
        // Guards are released even though the settle failed: nothing is left
        // holding the runtime.
        assert!(!f.http_restriction_manager.is_active());
    }

    #[tokio::test]
    async fn failed_release_does_not_fail_the_execution() {
        assert_finalization_failure_does_not_fail_the_execution(
            PostUpdateCommunicationMode::Enabled,
        )
        .await;
    }

    #[tokio::test]
    async fn failed_finish_does_not_fail_the_execution() {
        assert_finalization_failure_does_not_fail_the_execution(
            PostUpdateCommunicationMode::Deferred,
        )
        .await;
    }

    #[tokio::test]
    async fn failed_rejection_finalization_readmits_http_traffic() {
        let f = make_fixture();
        let protection = f
            .http_restriction_manager
            .protect(super::http_protection_config_for_update(
                Duration::from_secs(1),
                &[],
            ))
            .unwrap();

        let error = super::reject_execution(
            RuntimeUpdateError::NoPendingUpdate,
            protection,
            Box::new(FailingFinalizationGuard),
            ExecutionMode::Apply,
        )
        .await;

        // Nothing was applied, so the runtime stays coherent and ordinary HTTP
        // is readmitted; only communication is left down.
        assert!(matches!(error, RuntimeUpdateError::CommunicationFailure(_)));
        assert!(!f.http_restriction_manager.is_active());
    }

    #[tokio::test]
    async fn failed_compensation_retains_protection_and_requires_recovery() {
        let f = make_fixture();
        write_test_file(
            &f.storage,
            &CollectionName::DiagnosticDatabaseNextUpdate,
            "ecu.mdd",
            &readable_mdd_bytes("TestEcu"),
        )
        .await;
        let execution_id = super::register_execution(&f.executions, ExecutionMode::Apply).await;
        let protection = f
            .http_restriction_manager
            .protect(super::http_protection_config_for_update(
                Duration::from_secs(1),
                &[],
            ))
            .unwrap();
        super::spawn_execution(
            super::SpawnExecution {
                mode: ExecutionMode::Apply,
                execution_id: execution_id.clone(),
                storage: Arc::clone(&f.storage),
                reload_handler: Arc::new(RecoveryPreparationFails),
                executions: Arc::clone(&f.executions),
                post_update_mode: PostUpdateCommunicationMode::Enabled,
            },
            super::ExecutionGuards::new(protection, Box::new(FailingFinalizationGuard)),
        );

        // The reload could not restore the previous database, so nothing about
        // the live state is trustworthy. The protection stays registered and
        // only a restart clears it.
        let status = poll_until_terminal(&f.executions, &execution_id).await;
        assert!(
            matches!(
                status,
                ExecutionStatus::Failed(ExecutionFailure {
                    class: ExecutionFailureClass::Fatal,
                    ..
                })
            ),
            "an unrecoverable reload must report a fatal failure, got {status:?}"
        );
        assert!(
            f.http_restriction_manager.is_active(),
            "a runtime that could not be restored must keep refusing requests"
        );
    }

    /// A rollback whose settle fails still rolled back: the backup is live and
    /// the execution completes.
    #[tokio::test]
    async fn failed_rollback_finalization_still_restores_the_backup() {
        let f = make_fixture();
        write_test_file(
            &f.storage,
            &CollectionName::DiagnosticDatabaseBackup,
            "ecu.mdd",
            &readable_mdd_bytes("TestEcu"),
        )
        .await;
        write_test_file(
            &f.storage,
            &CollectionName::DiagnosticDatabase,
            "current.mdd",
            &readable_mdd_bytes("TestEcu"),
        )
        .await;
        let execution_id = super::register_execution(&f.executions, ExecutionMode::Rollback).await;
        let protection = f
            .http_restriction_manager
            .protect(super::http_protection_config_for_update(
                Duration::from_secs(1),
                &[],
            ))
            .unwrap();
        super::spawn_execution(
            super::SpawnExecution {
                mode: ExecutionMode::Rollback,
                execution_id: execution_id.clone(),
                storage: Arc::clone(&f.storage),
                reload_handler: Arc::clone(&f.reload_handler),
                executions: Arc::clone(&f.executions),
                post_update_mode: PostUpdateCommunicationMode::Deferred,
            },
            super::ExecutionGuards::new(protection, Box::new(FailingFinalizationGuard)),
        );

        let status = poll_until_terminal(&f.executions, &execution_id).await;
        assert_eq!(status, ExecutionStatus::Completed);
        let current = f
            .storage
            .get_collection(&CollectionName::DiagnosticDatabase)
            .await
            .unwrap();
        assert_eq!(current.list().await.unwrap(), ["ecu.mdd"]);
        assert!(!f.http_restriction_manager.is_active());
    }

    #[tokio::test]
    async fn terminal_status_is_only_published_after_the_update_guards_are_released() {
        // A client resumes ordinary requests as soon as it reads a terminal
        // status, so that status must not appear while the update's `409`
        // protection is still up. `GatedTransport` holds the resume open to make
        // that window observable. With an instant transport the tail of the
        // execution task runs in a single poll.
        let (transport, mut resume) = GatedTransport::new();
        let mut f = make_fixture();
        f.communication_disable = communication_disable_for_test(transport, true);

        let exec_id = super::start_execution(&f.params(), ExecutionMode::Cleanup)
            .await
            .unwrap();

        resume.entered().await;
        assert_eq!(
            super::get_execution_status(&f.executions, &exec_id)
                .await
                .map(|execution| execution.status),
            Some(ExecutionStatus::Running),
            "the execution must still read as running while its guards are being released"
        );
        assert!(
            f.http_restriction_manager.is_active(),
            "sanity check: the update restriction is still up at this point"
        );

        resume.release();
        let status = poll_until_terminal(&f.executions, &exec_id).await;
        assert_eq!(status, ExecutionStatus::Completed);
        assert!(
            !f.http_restriction_manager.is_active(),
            "update restriction must already be released once the execution reports a terminal \
             status"
        );
    }

    #[tokio::test]
    async fn get_execution_status_unknown_id_returns_none() {
        let f = make_fixture();
        let result = super::get_execution_status(&f.executions, "nonexistent-id").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn start_execution_allowed_when_previous_completed() {
        let f = make_fixture();
        {
            let mut execs = f.executions.write().await;
            execs.insert(
                "prev".to_string(),
                UpdateExecution {
                    id: "prev".to_string(),
                    mode: ExecutionMode::Cleanup,
                    status: ExecutionStatus::Completed,
                },
            );
        }

        let exec_id = super::start_execution(&f.params(), ExecutionMode::Cleanup)
            .await
            .unwrap();
        assert!(!exec_id.is_empty());
    }

    #[tokio::test]
    async fn previous_execution_removed_when_new_one_starts() {
        let f = make_fixture();
        let first_id = super::start_execution(&f.params(), ExecutionMode::Cleanup)
            .await
            .unwrap();

        poll_until_terminal(&f.executions, &first_id).await;

        let _second_id = super::start_execution(&f.params(), ExecutionMode::Cleanup)
            .await
            .unwrap();

        let status = super::get_execution_status(&f.executions, &first_id).await;
        assert!(
            status.is_none(),
            "expected first execution to be removed when second execution started"
        );
    }

    #[tokio::test]
    async fn execution_transitions_to_failed_on_error() {
        let f = make_fixture();
        write_test_file(
            &f.storage,
            &CollectionName::DiagnosticDatabaseNextUpdate,
            "ecu.mdd",
            &readable_mdd_bytes("TestEcu"),
        )
        .await;
        let failing_reload_handler = Arc::new(crate::test_utils::FailingReloadHandler);
        let params = super::ExecutionParams {
            storage: &f.storage,
            security_handler: &f.security_handler,
            reload_handler: &failing_reload_handler,
            executions: &f.executions,
            communication_disable: &f.communication_disable,
            http_protections: &f.http_restriction_manager,
            update_exempt_routes: &[],
            update_retry_after: Duration::from_secs(1),
            post_update_mode: PostUpdateCommunicationMode::Enabled,
            lock_state_provider: &f.lock_provider,
        };

        let exec_id = super::start_execution(&params, ExecutionMode::Apply)
            .await
            .unwrap();

        let status = poll_until_terminal(&f.executions, &exec_id).await;
        assert!(
            matches!(
                status,
                ExecutionStatus::Failed(ExecutionFailure {
                    class: ExecutionFailureClass::Fatal,
                    ..
                })
            ),
            "an unrecoverable reload must report a fatal failure, got {status:?}"
        );
    }
}
