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

//! Admitting, registering and reporting one runtime-update execution.
//!
//! What the update does to the running runtime is not here: the guards, the
//! stages and the transport target belong to the application's lifecycle and
//! are reached through [`UpdateDispatcher`]. This file owns the catalog side of
//! an execution - the preconditions that make a refusal synchronous, the
//! execution id clients poll, and the terminal status.

use std::sync::{Arc, Mutex};

use cda_interfaces::{
    HashMap,
    runtime_update_api::{
        AcceptedUpdate, ExecutionMode, ExecutionStatus, LockStateProvider, RuntimeFileInspector,
        RuntimeUpdateError, RuntimeUpdatePolicy, UpdateCollections, UpdateDispatcher,
        UpdateExecution,
    },
    storage_api::{Collection, CollectionName, DirectFileAccess, Storage},
    util::std_ext::lock_mutex,
};
use tokio::{sync::RwLock, task::JoinHandle};

/// Everything [`start_execution`] needs to admit, register and report one
/// execution.
pub(crate) struct ExecutionParams<'a, S, T, L> {
    /// Persistent storage; every database mutation goes through it.
    pub(crate) storage: &'a Arc<S>,
    /// Vehicle and lock state policy, asked before anything is disturbed.
    pub(crate) policy: &'a Arc<T>,
    /// Runs the runtime transition the mode asks for, and reports when the
    /// runtime is done with it.
    pub(crate) dispatcher: &'a Arc<dyn UpdateDispatcher>,
    /// The execution registry clients poll. The spawned task publishes its
    /// terminal status here, and `register_execution` prunes finished entries.
    pub(crate) executions: &'a Arc<RwLock<HashMap<String, UpdateExecution>>>,
    /// Consulted by the policy, and directly for the held-lock precondition that
    /// a topology replacement cannot discard live locks.
    pub(crate) lock_state_provider: &'a L,
    /// Format-specific reads, so the framework's readability precondition does
    /// not depend on any one database format.
    pub(crate) file_inspector: &'a Arc<dyn RuntimeFileInspector>,
    /// Takes ownership of the reporting task this call spawns, so shutdown can
    /// await the execution instead of cutting it off.
    pub(crate) execution_supervisor: &'a Mutex<Option<JoinHandle<()>>>,
}

/// Admits one execution and registers it, returning the id clients poll for its
/// status.
///
/// The policy is asked before the dispatch is admitted, and deliberately:
/// admitting one takes the execution guards, which disables communication and
/// refuses other clients, and a caller the policy will refuse must not be able
/// to provoke that. Every other precondition is checked here too, so a client
/// that cannot be served learns synchronously instead of through a later
/// `Failed` status.
///
/// # Errors
/// Returns the policy's own error if it refuses the execution,
/// [`RuntimeUpdateError::ExecutionConflict`] if another dispatch already holds
/// the execution guards, and the mode's precondition failure - `NoBackup` for a
/// rollback without one, `NoPendingUpdate` for an apply with nothing staged.
pub(crate) async fn start_execution<S, T, L>(
    params: &ExecutionParams<'_, S, T, L>,
    mode: ExecutionMode,
) -> Result<String, RuntimeUpdateError>
where
    S: Storage + Send + Sync + 'static,
    T: RuntimeUpdatePolicy<L, S::CollectionHandle>,
    L: LockStateProvider,
{
    let collections = load_update_collections(&**params.storage).await?;

    params
        .policy
        .check_execution_allowed(params.lock_state_provider, &collections)
        .await?;
    validate_execution_preconditions(params, mode, &collections).await?;

    let accepted = params.dispatcher.dispatch(mode).await?;
    let execution_id = register_execution(params.executions, mode).await;
    report_when_finished(
        mode,
        execution_id.clone(),
        Arc::clone(params.executions),
        accepted,
        params.execution_supervisor,
    );

    Ok(execution_id)
}

/// Rejects an execution whose incoming databases cannot be read.
///
/// A framework precondition rather than a security-plugin concern: readability
/// is not policy, and an application that replaces the plugin must not be able
/// to drop it. Refusing here also keeps the rejection synchronous, before any
/// collection has moved.
async fn validate_incoming_databases<C: Collection + DirectFileAccess>(
    collection: &C,
    inspector: &dyn RuntimeFileInspector,
) -> Result<(), RuntimeUpdateError> {
    for key in collection.list().await? {
        if !key.to_lowercase().ends_with(".mdd") {
            continue;
        }
        inspector
            .validate(&collection.file_path(&key)?)
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

async fn validate_execution_preconditions<S, T, L>(
    params: &ExecutionParams<'_, S, T, L>,
    mode: ExecutionMode,
    collections: &UpdateCollections<S::CollectionHandle>,
) -> Result<(), RuntimeUpdateError>
where
    S: Storage + Send + Sync + 'static,
    T: RuntimeUpdatePolicy<L, S::CollectionHandle>,
    L: LockStateProvider,
{
    // Framework-owned, not plugin policy: replacing the lock topology discards every held
    // ECU and functional-group lock, so this is a coherence precondition for the reload and
    // must not be removable by an OEM policy. It runs after the policy so a
    // caller without the vehicle lock still gets `NoLock` rather than `LockConflict`.
    if params.lock_state_provider.has_locks().await {
        return Err(RuntimeUpdateError::LockConflict(
            "Non-vehicle locks are held, cannot apply update".to_owned(),
        ));
    }

    if mode == ExecutionMode::Rollback
        && !crate::storage::backup_snapshot_exists(&**params.storage).await?
    {
        return Err(RuntimeUpdateError::NoBackup);
    }

    // For Apply: verify there is at least one pending NextUpdate collection before
    // accepting the request. This mirrors the Rollback check above, and must happen
    // before the dispatch is admitted so that the 404 is returned synchronously
    // instead of 202 being sent with a later Failed status.
    if mode == ExecutionMode::Apply && collections.pending_mdd.is_none() {
        return Err(RuntimeUpdateError::NoPendingUpdate);
    }

    // The databases this mode is about to make live. `Cleanup` makes none live.
    let becoming_live = match mode {
        ExecutionMode::Apply => collections.pending_mdd.as_ref(),
        ExecutionMode::Rollback => collections.backup_mdd.as_ref(),
        ExecutionMode::Cleanup => None,
    };
    if let Some(collection) = becoming_live {
        validate_incoming_databases(&**collection, &**params.file_inspector).await?;
    }

    Ok(())
}

async fn register_execution(
    executions: &Arc<RwLock<HashMap<String, UpdateExecution>>>,
    mode: ExecutionMode,
) -> String {
    let execution_id = uuid::Uuid::new_v4().to_string();
    let mut execs = executions.write().await;
    execs.retain(|_, execution| matches!(execution.status, ExecutionStatus::Running));
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

/// Waits for the dispatch to finish and publishes the execution's terminal
/// status.
///
/// Its own task, because `start_execution` answers the client with `202` while
/// the stages are still running.
fn report_when_finished(
    mode: ExecutionMode,
    execution_id: String,
    executions: Arc<RwLock<HashMap<String, UpdateExecution>>>,
    accepted: AcceptedUpdate,
    execution_supervisor: &Mutex<Option<JoinHandle<()>>>,
) {
    let task = cda_interfaces::spawn_named!(&format!("runtime-update-{mode:?}"), async move {
        let status = match accepted.completion.await {
            Ok(()) => ExecutionStatus::Completed,
            Err(failure) => {
                tracing::error!(execution_id, ?mode, %failure, "Runtime update failed");
                ExecutionStatus::Failed(failure)
            }
        };
        // Published last: a client treats a terminal status as permission to
        // resume ordinary traffic, and the dispatch resolves only once its
        // guards are down.
        publish_terminal_status(&executions, &execution_id, mode, status).await;
    });

    // Owned so shutdown can await the execution rather than cut it off.
    // Replacing loses no work: at most one execution is ever in flight, because
    // a second dispatch cannot take the execution guards, so a stored task is
    // always a finished one.
    *lock_mutex(execution_supervisor) = Some(task);
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

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use cda_interfaces::{
        HashMap,
        runtime_update_api::{
            AcceptedUpdate, ExecutionFailure, ExecutionFailureClass, ExecutionMode,
            ExecutionStatus, ReloadError, RuntimeUpdateError, UpdateDispatcher, UpdateExecution,
        },
        storage_api::CollectionName,
    };
    use cda_storage::LocalStorage;
    use tokio::sync::{RwLock, oneshot};

    use crate::test_utils::{
        MockLockProvider, MockUpdatePolicy, make_storage, readable_mdd_bytes, write_test_file,
    };

    /// Stands in for the application's lifecycle: records what it was asked to
    /// dispatch and hands the test the sender that ends the dispatch, so the
    /// window between "the guards are coming down" and "they are down" is as
    /// long as the test needs.
    struct TestDispatcher {
        dispatches: AtomicUsize,
        outcome: std::sync::Mutex<Option<oneshot::Sender<Result<(), ExecutionFailure>>>>,
        refuse: Option<fn() -> RuntimeUpdateError>,
    }

    /// What the application reports when its dispatch ended without an outcome.
    fn abnormal_termination() -> ExecutionFailure {
        ExecutionFailure::AbnormalTermination
    }

    impl TestDispatcher {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                dispatches: AtomicUsize::new(0),
                outcome: std::sync::Mutex::new(None),
                refuse: None,
            })
        }

        fn refusing(error: fn() -> RuntimeUpdateError) -> Arc<Self> {
            Arc::new(Self {
                dispatches: AtomicUsize::new(0),
                outcome: std::sync::Mutex::new(None),
                refuse: Some(error),
            })
        }

        fn dispatch_count(&self) -> usize {
            self.dispatches.load(Ordering::SeqCst)
        }

        /// Ends the dispatch the way the runtime would, once its guards are down.
        fn finish(&self, outcome: Result<(), ExecutionFailure>) {
            let sender = self.outcome.lock().expect("poisoned").take();
            sender
                .expect("a dispatch must have been admitted")
                .send(outcome)
                .expect("the reporting task must still be waiting");
        }
    }

    #[async_trait::async_trait]
    impl UpdateDispatcher for TestDispatcher {
        async fn dispatch(
            &self,
            _mode: ExecutionMode,
        ) -> Result<AcceptedUpdate, RuntimeUpdateError> {
            if let Some(error) = self.refuse {
                return Err(error());
            }
            self.dispatches.fetch_add(1, Ordering::SeqCst);
            let (sender, receiver) = oneshot::channel();
            *self.outcome.lock().expect("poisoned") = Some(sender);
            Ok(AcceptedUpdate {
                completion: Box::pin(async move {
                    receiver
                        .await
                        .unwrap_or_else(|_| Err(abnormal_termination()))
                }),
            })
        }
    }

    struct TestFixture {
        storage: Arc<LocalStorage>,
        policy: Arc<MockUpdatePolicy>,
        dispatcher: Arc<dyn UpdateDispatcher>,
        lock_provider: MockLockProvider,
        file_inspector: Arc<dyn cda_interfaces::runtime_update_api::RuntimeFileInspector>,
        executions: Arc<RwLock<HashMap<String, UpdateExecution>>>,
        execution_supervisor: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
        _dir: tempfile::TempDir,
    }

    impl TestFixture {
        fn params(
            &self,
        ) -> super::ExecutionParams<'_, LocalStorage, MockUpdatePolicy, MockLockProvider> {
            super::ExecutionParams {
                storage: &self.storage,
                policy: &self.policy,
                dispatcher: &self.dispatcher,
                executions: &self.executions,
                lock_state_provider: &self.lock_provider,
                file_inspector: &self.file_inspector,
                execution_supervisor: &self.execution_supervisor,
            }
        }
    }

    fn make_fixture_with(dispatcher: Arc<dyn UpdateDispatcher>) -> TestFixture {
        let (storage, dir) = make_storage();
        TestFixture {
            storage: Arc::new(storage),
            policy: Arc::new(MockUpdatePolicy::new()),
            dispatcher,
            lock_provider: MockLockProvider {
                owner: Some("test-user".to_owned()),
                has_conflicts: false,
            },
            file_inspector: crate::test_utils::test_inspector(),
            executions: Arc::new(RwLock::new(HashMap::default())),
            execution_supervisor: std::sync::Mutex::new(None),
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
                && !matches!(exec.status, ExecutionStatus::Running)
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
        let dispatcher = TestDispatcher::new();
        let f = make_fixture_with(Arc::clone(&dispatcher) as Arc<dyn UpdateDispatcher>);
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
        assert!(
            super::get_execution_status(&f.executions, &exec_id)
                .await
                .is_some()
        );

        dispatcher.finish(Ok(()));
        let status = poll_until_terminal(&f.executions, &exec_id).await;
        assert!(
            matches!(status, ExecutionStatus::Completed),
            "expected the apply to complete, got {status:?}"
        );
    }

    #[tokio::test]
    async fn start_execution_rollback() {
        let dispatcher = TestDispatcher::new();
        let f = make_fixture_with(Arc::clone(&dispatcher) as Arc<dyn UpdateDispatcher>);
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
        dispatcher.finish(Ok(()));

        let status = poll_until_terminal(&f.executions, &exec_id).await;
        assert!(
            matches!(status, ExecutionStatus::Completed),
            "expected the rollback to complete, got {status:?}"
        );
    }

    #[tokio::test]
    async fn start_execution_apply_with_no_pending_update_rejected_synchronously() {
        let dispatcher = TestDispatcher::new();
        let f = make_fixture_with(Arc::clone(&dispatcher) as Arc<dyn UpdateDispatcher>);

        // Nothing seeded into DiagnosticDatabaseNextUpdate: Apply must be
        // rejected synchronously rather than accepted only to fail later.
        let result = super::start_execution(&f.params(), ExecutionMode::Apply).await;

        assert!(
            matches!(result, Err(RuntimeUpdateError::NoPendingUpdate)),
            "expected NoPendingUpdate, got: {result:?}"
        );
        assert!(
            f.executions.read().await.is_empty(),
            "no execution should have been recorded for a synchronously-rejected apply"
        );
        assert_eq!(
            dispatcher.dispatch_count(),
            0,
            "a synchronously-rejected apply must not disturb the runtime"
        );
    }

    #[tokio::test]
    async fn start_execution_apply_with_non_vehicle_lock_held_rejected_synchronously() {
        let dispatcher = TestDispatcher::new();
        let mut f = make_fixture_with(Arc::clone(&dispatcher) as Arc<dyn UpdateDispatcher>);
        f.lock_provider.has_conflicts = true;
        write_test_file(
            &f.storage,
            &CollectionName::DiagnosticDatabaseNextUpdate,
            "ecu.mdd",
            b"mdd_data",
        )
        .await;

        // The security plugin permits the apply; the framework check must still refuse it,
        // because the reload would discard the held ECU/functional-group lock.
        let result = super::start_execution(&f.params(), ExecutionMode::Apply).await;

        assert!(
            matches!(result, Err(RuntimeUpdateError::LockConflict(_))),
            "expected LockConflict, got: {result:?}"
        );
        assert!(f.executions.read().await.is_empty());
        assert_eq!(dispatcher.dispatch_count(), 0);
    }

    #[tokio::test]
    async fn start_execution_cleanup_succeeds() {
        let dispatcher = TestDispatcher::new();
        let f = make_fixture_with(Arc::clone(&dispatcher) as Arc<dyn UpdateDispatcher>);

        let exec_id = super::start_execution(&f.params(), ExecutionMode::Cleanup)
            .await
            .unwrap();
        assert!(!exec_id.is_empty());
        dispatcher.finish(Ok(()));

        let status = poll_until_terminal(&f.executions, &exec_id).await;
        assert!(
            matches!(status, ExecutionStatus::Completed),
            "expected the cleanup to complete, got {status:?}"
        );
    }

    /// A conflicting dispatch is what serializes executions, and it is reported
    /// synchronously so the client is not left polling a status that never comes.
    #[tokio::test]
    async fn a_conflicting_dispatch_is_refused_synchronously() {
        let dispatcher = TestDispatcher::refusing(|| RuntimeUpdateError::ExecutionConflict);
        let f = make_fixture_with(dispatcher as Arc<dyn UpdateDispatcher>);

        let result = super::start_execution(&f.params(), ExecutionMode::Cleanup).await;

        assert!(matches!(result, Err(RuntimeUpdateError::ExecutionConflict)));
        assert!(f.executions.read().await.is_empty());
    }

    #[tokio::test]
    async fn terminal_status_is_only_published_after_the_update_guards_are_released() {
        // A client resumes ordinary requests as soon as it reads a terminal
        // status, so that status must not appear while the update's `409`
        // protection is still up. The dispatch resolves only once its guards are
        // down, so holding it open is what makes that window observable.
        let dispatcher = TestDispatcher::new();
        let f = make_fixture_with(Arc::clone(&dispatcher) as Arc<dyn UpdateDispatcher>);

        let exec_id = super::start_execution(&f.params(), ExecutionMode::Cleanup)
            .await
            .unwrap();

        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        let running = super::get_execution_status(&f.executions, &exec_id)
            .await
            .map(|execution| execution.status);
        assert!(
            matches!(running, Some(ExecutionStatus::Running)),
            "the execution must still read as running while its guards are up, got {running:?}"
        );

        dispatcher.finish(Ok(()));
        let status = poll_until_terminal(&f.executions, &exec_id).await;
        assert!(
            matches!(status, ExecutionStatus::Completed),
            "expected the execution to complete, got {status:?}"
        );
    }

    #[tokio::test]
    async fn get_execution_status_unknown_id_returns_none() {
        let f = make_fixture_with(TestDispatcher::new() as Arc<dyn UpdateDispatcher>);
        let result = super::get_execution_status(&f.executions, "nonexistent-id").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn start_execution_allowed_when_previous_completed() {
        let dispatcher = TestDispatcher::new();
        let f = make_fixture_with(Arc::clone(&dispatcher) as Arc<dyn UpdateDispatcher>);
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
        dispatcher.finish(Ok(()));
    }

    #[tokio::test]
    async fn previous_execution_removed_when_new_one_starts() {
        let dispatcher = TestDispatcher::new();
        let f = make_fixture_with(Arc::clone(&dispatcher) as Arc<dyn UpdateDispatcher>);

        let first_id = super::start_execution(&f.params(), ExecutionMode::Cleanup)
            .await
            .unwrap();
        dispatcher.finish(Ok(()));
        poll_until_terminal(&f.executions, &first_id).await;

        let _second_id = super::start_execution(&f.params(), ExecutionMode::Cleanup)
            .await
            .unwrap();
        dispatcher.finish(Ok(()));

        assert!(
            super::get_execution_status(&f.executions, &first_id)
                .await
                .is_none(),
            "expected first execution to be removed when second execution started"
        );
    }

    #[tokio::test]
    async fn execution_transitions_to_failed_on_error() {
        let dispatcher = TestDispatcher::new();
        let f = make_fixture_with(Arc::clone(&dispatcher) as Arc<dyn UpdateDispatcher>);
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
        dispatcher.finish(Err(ExecutionFailure::RecoveryFailed {
            original: ReloadError::General("Simulated reload failure".to_owned()),
            recovery: cda_interfaces::runtime_update_api::RecoveryError::RestoredPreparation(
                ReloadError::General("simulated restored-state rejection".to_owned()),
            ),
        }));

        let status = poll_until_terminal(&f.executions, &exec_id).await;
        assert!(
            matches!(
                &status,
                ExecutionStatus::Failed(failure)
                    if failure.class() == ExecutionFailureClass::Fatal
            ),
            "an unrecoverable reload must report a fatal failure, got {status:?}"
        );
    }

    /// A dispatch that ended without reporting cannot be assumed to have left
    /// the runtime alone, so the execution must not stay `Running` forever.
    #[tokio::test]
    async fn an_unreported_dispatch_fails_the_execution() {
        let dispatcher = TestDispatcher::new();
        let f = make_fixture_with(Arc::clone(&dispatcher) as Arc<dyn UpdateDispatcher>);

        let exec_id = super::start_execution(&f.params(), ExecutionMode::Cleanup)
            .await
            .unwrap();
        drop(dispatcher.outcome.lock().expect("poisoned").take());

        let status = poll_until_terminal(&f.executions, &exec_id).await;
        assert!(
            matches!(
                status,
                ExecutionStatus::Failed(ExecutionFailure::AbnormalTermination)
            ),
            "expected an abnormal termination, got {status:?}"
        );
    }

    /// Policy that refuses every execution and counts how often it was asked.
    struct RefusingPolicy {
        calls: AtomicUsize,
    }

    impl RefusingPolicy {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl<L, C> cda_interfaces::runtime_update_api::RuntimeUpdatePolicy<L, C> for RefusingPolicy
    where
        L: cda_interfaces::runtime_update_api::LockStateProvider,
        C: cda_interfaces::storage_api::Collection
            + cda_interfaces::storage_api::DirectFileAccess
            + Send
            + Sync
            + 'static,
    {
        async fn check_execution_allowed(
            &self,
            _lock_state_provider: &L,
            _collections: &cda_interfaces::runtime_update_api::UpdateCollections<C>,
        ) -> Result<(), RuntimeUpdateError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(RuntimeUpdateError::NoLock(
                "vehicle is not parked".to_owned(),
            ))
        }
    }

    /// An execution the policy refuses must be refused before anything
    /// observable happens.
    ///
    /// The guards a dispatch takes are not bookkeeping: disabling the transport
    /// drops vehicle communication, and the HTTP protection returns 409 on every
    /// non-exempt route. Admitting the dispatch before asking the policy would
    /// let any caller the policy is going to refuse force a real disable/enable
    /// cycle plus a burst of 409s, purely by being refused a moment later. This
    /// pins the ordering, so moving the dispatch ahead of the policy fails here.
    #[tokio::test]
    async fn a_refused_execution_never_disables_the_transport() {
        let dispatcher = TestDispatcher::new();
        let f = make_fixture_with(Arc::clone(&dispatcher) as Arc<dyn UpdateDispatcher>);
        let refusing = Arc::new(RefusingPolicy::new());
        let params = super::ExecutionParams {
            storage: &f.storage,
            policy: &refusing,
            dispatcher: &f.dispatcher,
            executions: &f.executions,
            lock_state_provider: &f.lock_provider,
            file_inspector: &f.file_inspector,
            execution_supervisor: &f.execution_supervisor,
        };

        let result = super::start_execution(&params, ExecutionMode::Apply).await;

        assert!(
            matches!(result, Err(RuntimeUpdateError::NoLock(_))),
            "a refused execution must surface the policy's own error, got: {result:?}"
        );
        assert_eq!(
            refusing.call_count(),
            1,
            "the policy answers once, before anything is disturbed"
        );
        assert_eq!(
            dispatcher.dispatch_count(),
            0,
            "a refused execution must not take the vehicle transport offline"
        );
        assert!(
            f.executions.read().await.is_empty(),
            "a refused execution must not be registered"
        );
    }
}
