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
    communication_control::{ActivationCause, CommunicationAccess, PostUpdateCommunicationMode},
    runtime_update_api::{
        ExecutionMode, ExecutionStatus, LockStateProvider, RuntimeReloaderPlugin,
        RuntimeUpdateError, RuntimeUpdateSecurityPlugin, UpdateCollections, UpdateExecution,
    },
    storage_api::{CollectionName, Storage},
};
use cda_plugin_communication_management::{
    http_protection::registry::{
        HttpProtectionConfig, HttpProtectionReason, HttpProtectionRegistry, HttpStatusCode,
        OwnedHttpProtection,
    },
    lifecycle::disable::{DisableCommunication, DisableError, DisableLease, DisableReason},
};
use tokio::sync::RwLock;

pub(crate) struct ExecutionParams<'a, S, R: ?Sized, T, L> {
    pub(crate) storage: &'a Arc<S>,
    pub(crate) security_handler: &'a Arc<T>,
    pub(crate) reload_handler: &'a Arc<R>,
    pub(crate) executions: &'a Arc<RwLock<HashMap<String, UpdateExecution>>>,
    pub(crate) communication_disable: &'a Arc<dyn DisableCommunication>,
    pub(crate) communication_access: &'a Arc<dyn CommunicationAccess>,
    pub(crate) http_protections: &'a HttpProtectionRegistry,
    pub(crate) update_retry_after: Duration,
    pub(crate) post_update_mode: PostUpdateCommunicationMode,
    pub(crate) mdd_decompress: bool,
    pub(crate) lock_state_provider: &'a L,
}

fn http_protection_config_for_update(retry_after: Duration) -> HttpProtectionConfig {
    HttpProtectionConfig::new(
        HttpProtectionReason::UpdateInProgress,
        HttpStatusCode::CONFLICT,
        "Update in progress",
    )
    .with_exempt_routes(cda_sovd::routes_accessible_during_update())
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
        Err(error) => return Err(reject_execution(error, protection, disable_lease).await),
    };
    let (protection, disable_lease) =
        validate_execution_preconditions(params, mode, &collections, protection, disable_lease)
            .await?;
    let execution_id = register_execution(params.executions, mode).await;

    spawn_execution(
        mode,
        execution_id.clone(),
        Arc::clone(params.storage),
        Arc::clone(params.reload_handler),
        Arc::clone(params.executions),
        params.mdd_decompress,
        params.post_update_mode.clone(),
        Arc::clone(params.communication_access),
        disable_lease,
        protection,
    );

    Ok(execution_id)
}

async fn acquire_execution_guards<S, R: ?Sized, T, L>(
    params: &ExecutionParams<'_, S, R, T, L>,
) -> Result<(OwnedHttpProtection, DisableLease), RuntimeUpdateError> {
    let protection = params
        .http_protections
        .protect(http_protection_config_for_update(params.update_retry_after))
        .map_err(|error| {
            // The config is built in-process, so this can only be a programming
            // error. Refuse the execution rather than run it unprotected.
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
    })
}

async fn validate_execution_preconditions<S, R, T, L>(
    params: &ExecutionParams<'_, S, R, T, L>,
    mode: ExecutionMode,
    collections: &UpdateCollections<S::CollectionHandle>,
    protection: OwnedHttpProtection,
    disable_lease: DisableLease,
) -> Result<(OwnedHttpProtection, DisableLease), RuntimeUpdateError>
where
    S: Storage + Send + Sync + 'static,
    R: RuntimeReloaderPlugin + ?Sized,
    T: RuntimeUpdateSecurityPlugin<L, S::CollectionHandle>,
    L: LockStateProvider,
{
    if let Err(error) = params
        .security_handler
        .check_apply_allowed(params.lock_state_provider, collections)
        .await
    {
        return Err(reject_execution(error, protection, disable_lease).await);
    }

    if mode == ExecutionMode::Rollback {
        match crate::storage::is_backup_empty(&**params.storage).await {
            Ok(true) => {
                return Err(reject_execution(
                    RuntimeUpdateError::NoBackup,
                    protection,
                    disable_lease,
                )
                .await);
            }
            Err(error) => return Err(reject_execution(error, protection, disable_lease).await),
            Ok(false) => {}
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
        )
        .await);
    }

    Ok((protection, disable_lease))
}

async fn reject_execution(
    error: RuntimeUpdateError,
    protection: OwnedHttpProtection,
    disable_lease: DisableLease,
) -> RuntimeUpdateError {
    // Resume first, drop the update protection second - the same order the
    // completion path in `spawn_execution` uses. Dropping first would open a
    // window where neither this protection nor a restored transport is in
    // place, so requests arriving during the resume would fall through to a
    // handler-level communication error instead of the `409` the caller is
    // still expected to retry against.
    if let Err(release_failure) = disable_lease.release().await {
        tracing::error!(
            error = %error,
            release_failure = %release_failure,
            "Failed to resume transport after rejecting runtime update"
        );
    }
    drop(protection);
    error
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

#[allow(
    clippy::too_many_arguments,
    reason = "Spawned task inputs must be owned"
)]
fn spawn_execution<S, R>(
    mode: ExecutionMode,
    execution_id: String,
    storage: Arc<S>,
    reload_handler: Arc<R>,
    executions: Arc<RwLock<HashMap<String, UpdateExecution>>>,
    mdd_decompress: bool,
    post_update_mode: PostUpdateCommunicationMode,
    communication_access: Arc<dyn CommunicationAccess>,
    disable_lease: DisableLease,
    protection: OwnedHttpProtection,
) where
    S: Storage + Send + Sync + 'static,
    R: RuntimeReloaderPlugin + ?Sized,
{
    let supervised_executions = Arc::clone(&executions);
    let supervised_execution_id = execution_id.clone();

    let handle = cda_interfaces::spawn_named!(&format!("runtime-update-{mode:?}"), async move {
        let result = execute_operation(mode, &*storage, &*reload_handler, mdd_decompress).await;

        if let Err(error) = &result {
            tracing::error!(
                execution_id = %execution_id,
                mode = ?mode,
                error = %error,
                "Runtime update execution failed"
            );
        }

        // Only a successful Apply/Rollback defers: a failed update, or a
        // Cleanup (which changes no runtime component), leaves communication
        // as it found it.
        let should_defer = result.is_ok()
            && matches!(mode, ExecutionMode::Apply | ExecutionMode::Rollback)
            && matches!(post_update_mode, PostUpdateCommunicationMode::Deferred);
        if should_defer {
            drop(disable_lease);
        } else {
            if let Err(failure) = disable_lease.release().await {
                tracing::error!(
                    execution_id = %execution_id,
                    mode = ?mode,
                    error = %failure,
                    "Failed to resume transport after runtime update"
                );
            }
            // Releasing only restores what the lease displaced, so an update
            // that started from a deferred runtime comes back deferred. The
            // configured end state is a separate question, and asking for it
            // is a *request*, not an activation: routing it through
            // `CommunicationAccess` leaves `init_mode` the final word, so
            // `Always`/`OnDemand` come up while `Disabled` stays quiet. A
            // no-op when the release already resumed.
            communication_access.request_activate(ActivationCause::DisableRelease);
        }
        drop(protection);

        // Published last, and deliberately so: the terminal status is what a
        // client polls on before it resumes normal traffic, so it must not
        // become observable while the update guards are still up. Writing it
        // before the release above leaves a window where a caller saw
        // `completed` and then had its next request rejected with the
        // update's `409` - the guards outlived the status that announced they
        // were gone.
        let mut map = executions.write().await;
        if let Some(execution) = map.get_mut(&execution_id) {
            execution.status = match result {
                Ok(()) => ExecutionStatus::Completed,
                Err(ref error) => ExecutionStatus::Failed(error.to_string()),
            };
        } else {
            tracing::error!(
                execution_id = %execution_id,
                mode = ?mode,
                "Runtime update execution completed without an execution record"
            );
        }
        drop(map);
    });

    // `handle` is not awaited above: if `execute_operation` panics, the task
    // unwinds past the status write, and nothing else ever moves the
    // execution record out of `Running`. `DisableLease`'s and
    // `OwnedHttpProtection`'s `Drop` impls still run during that unwind, so
    // the transport is left safe - but the record itself would poll as
    // `Running` forever. This supervisor awaits the `JoinHandle` and marks
    // the execution `Failed` if the task ended without setting a terminal
    // status itself (panic or cancellation).
    cda_interfaces::spawn_named!(&format!("runtime-update-{mode:?}-supervisor"), async move {
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
                execution.status = ExecutionStatus::Failed(format!(
                    "execution task ended abnormally: {join_error}"
                ));
            }
        }
    });
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
    mdd_decompress: bool,
) -> Result<(), RuntimeUpdateError>
where
    S: Storage + Send + Sync + 'static,
    R: RuntimeReloaderPlugin + ?Sized,
{
    match mode {
        ExecutionMode::Apply => {
            crate::operations::apply::execute_apply(storage, reload_handler, mdd_decompress).await
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
            CommunicationAccess, PostUpdateCommunicationMode, TransportControl, TransportState,
            error::CommControlError,
        },
        runtime_update_api::{ExecutionMode, ExecutionStatus, RuntimeUpdateError, UpdateExecution},
        storage_api::CollectionName,
    };
    use cda_plugin_communication_management::{
        http_protection::registry::{HttpProtectionRegistry, HttpRestrictionGuard},
        lifecycle::{
            communication_disable_for_test, disable::DisableCommunication,
            enabled_communication_access_for_test,
        },
    };
    use cda_storage::LocalStorage;
    use tokio::sync::RwLock;

    use crate::test_utils::{
        MockLockProvider, MockSecurityHandler, NoopReloadHandler, StubTransport, make_storage,
        write_test_file,
    };

    fn make_transport_and_disable() -> (HttpProtectionRegistry, Arc<dyn DisableCommunication>) {
        let transport = StubTransport::new();
        let restrictions = HttpProtectionRegistry::new();
        let disable = communication_disable_for_test(Arc::<StubTransport>::clone(&transport), true);
        (restrictions, disable)
    }

    /// A transport whose resume (`enable`) parks until the test lets it
    /// through, so the interval between "the guards are coming down" and
    /// "they are down" is long enough to observe what an execution reports
    /// during it.
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
        communication_access: Arc<dyn CommunicationAccess>,
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
                communication_access: &self.communication_access,
                storage: &self.storage,
                security_handler: &self.security_handler,
                reload_handler: &self.reload_handler,
                executions: &self.executions,
                communication_disable: &self.communication_disable,
                http_protections: &self.http_restriction_manager,
                update_retry_after: Duration::from_secs(1),
                post_update_mode: PostUpdateCommunicationMode::Enabled,
                mdd_decompress: false,
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
            communication_access: enabled_communication_access_for_test(),
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
            b"mdd_data",
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
            b"backup_data",
        )
        .await;

        let exec_id = super::start_execution(&f.params(), ExecutionMode::Rollback)
            .await
            .unwrap();
        assert!(!exec_id.is_empty());
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

    #[tokio::test]
    async fn terminal_status_is_only_published_after_the_update_guards_are_released() {
        // A client polls the execution resource and goes back to issuing
        // ordinary requests as soon as it reads a terminal status, so that
        // status must not become observable while the update's `409`
        // protection is still up.
        //
        // `GatedTransport` holds the resume open until this test lets it
        // finish, which is what makes the window observable at all: with an
        // instant transport the whole tail of the execution task runs inside a
        // single poll, and a status published too early is never seen.
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
            b"mdd_data",
        )
        .await;
        let failing_reload_handler = Arc::new(crate::test_utils::FailingReloadHandler);
        let communication_access = enabled_communication_access_for_test();
        let params = super::ExecutionParams {
            communication_access: &communication_access,
            storage: &f.storage,
            security_handler: &f.security_handler,
            reload_handler: &failing_reload_handler,
            executions: &f.executions,
            communication_disable: &f.communication_disable,
            http_protections: &f.http_restriction_manager,
            update_retry_after: Duration::from_secs(1),
            post_update_mode: PostUpdateCommunicationMode::Enabled,
            mdd_decompress: false,
            lock_state_provider: &f.lock_provider,
        };

        let exec_id = super::start_execution(&params, ExecutionMode::Apply)
            .await
            .unwrap();

        let status = poll_until_terminal(&f.executions, &exec_id).await;
        assert!(matches!(status, ExecutionStatus::Failed(_)));
        // After failure the spawned task re-enables, removing the restriction.
        assert!(!f.http_restriction_manager.is_active());
    }

    #[tokio::test]
    async fn execution_transitions_to_failed_when_task_panics() {
        let f = make_fixture();
        write_test_file(
            &f.storage,
            &CollectionName::DiagnosticDatabaseNextUpdate,
            "ecu.mdd",
            b"mdd_data",
        )
        .await;
        let panicking_reload_handler = Arc::new(crate::test_utils::PanickingReloadHandler);
        let communication_access = enabled_communication_access_for_test();
        let params = super::ExecutionParams {
            communication_access: &communication_access,
            storage: &f.storage,
            security_handler: &f.security_handler,
            reload_handler: &panicking_reload_handler,
            executions: &f.executions,
            communication_disable: &f.communication_disable,
            http_protections: &f.http_restriction_manager,
            update_retry_after: Duration::from_secs(1),
            post_update_mode: PostUpdateCommunicationMode::Enabled,
            mdd_decompress: false,
            lock_state_provider: &f.lock_provider,
        };

        let exec_id = super::start_execution(&params, ExecutionMode::Apply)
            .await
            .unwrap();

        // Without the supervisor task, this would hang until poll_until_terminal's
        // 5s deadline panics the test - the execution task panicked mid-flight and
        // nothing else ever writes a terminal status for it.
        let status = poll_until_terminal(&f.executions, &exec_id).await;
        assert!(
            matches!(status, ExecutionStatus::Failed(_)),
            "expected Failed after the execution task panicked, got: {status:?}"
        );
    }
}
