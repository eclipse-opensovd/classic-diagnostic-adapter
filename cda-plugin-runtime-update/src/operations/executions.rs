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

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use cda_interfaces::{
    HashMap,
    runtime_update_api::{
        ExecutionMode, ExecutionStatus, LockStateProvider, RuntimeFileReloadHandler,
        RuntimeFilesUpdateSecurityHandler, RuntimeUpdateError, UpdateCollections, UpdateExecution,
    },
    storage_api::{CollectionName, Storage},
};
use tokio::sync::RwLock;

pub(crate) struct ExecutionParams<'a, S, R, T, L> {
    pub(crate) storage: &'a Arc<S>,
    pub(crate) security_handler: &'a Arc<T>,
    pub(crate) reload_handler: &'a Arc<R>,
    pub(crate) executions: &'a Arc<RwLock<HashMap<String, UpdateExecution>>>,
    pub(crate) update_in_progress: &'a Arc<AtomicBool>,
    pub(crate) mdd_decompress: bool,
    pub(crate) lock_state_provider: &'a L,
}

pub(crate) async fn start_execution<S, R, T, L>(
    params: &ExecutionParams<'_, S, R, T, L>,
    mode: ExecutionMode,
) -> Result<String, RuntimeUpdateError>
where
    S: Storage + Send + Sync + 'static,
    R: RuntimeFileReloadHandler,
    T: RuntimeFilesUpdateSecurityHandler<L, S::CollectionHandle>,
    L: LockStateProvider,
{
    params
        .update_in_progress
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| RuntimeUpdateError::ExecutionConflict)?;

    let collections = UpdateCollections {
        pending_mdd: params
            .storage
            .get_collection(&CollectionName::DiagnosticDatabaseNextUpdate)
            .await
            .ok(),
        pending_config: params
            .storage
            .get_collection(&CollectionName::ConfigurationNextUpdate)
            .await
            .ok(),
        current_mdd: params
            .storage
            .get_collection(&CollectionName::DiagnosticDatabase)
            .await
            .ok(),
        current_config: params
            .storage
            .get_collection(&CollectionName::Configuration)
            .await
            .ok(),
    };

    if let Err(e) = params
        .security_handler
        .check_apply_allowed(params.lock_state_provider, &collections)
        .await
    {
        params.update_in_progress.store(false, Ordering::Release);
        return Err(e);
    }
    {
        let execs = params.executions.read().await;
        let has_running = execs.values().any(|e| e.status == ExecutionStatus::Running);
        if has_running {
            params.update_in_progress.store(false, Ordering::Release);
            return Err(RuntimeUpdateError::ExecutionConflict);
        }
    }

    // For Rollback: verify backup is non-empty before accepting the request.
    // This must happen before spawning the task so that the 404 is returned
    // synchronously instead of 202 being sent with a later Failed status.
    if mode == ExecutionMode::Rollback {
        match crate::storage::is_backup_empty(&**params.storage).await {
            Ok(true) => {
                params.update_in_progress.store(false, Ordering::Release);
                return Err(RuntimeUpdateError::NoBackup);
            }
            Err(e) => {
                params.update_in_progress.store(false, Ordering::Release);
                return Err(e);
            }
            Ok(false) => {}
        }
    }

    let execution_id = uuid::Uuid::new_v4().to_string();
    {
        let mut execs = params.executions.write().await;
        // Purge all terminal-state entries before inserting the new one. Entries
        // are not evicted by a TTL; they live until the next execution is started.
        // At this point the has_running guard above guarantees no Running entries
        // exist, so this unconditionally clears the map.
        execs.retain(|_, e| e.status == ExecutionStatus::Running);
        execs.insert(
            execution_id.clone(),
            UpdateExecution {
                id: execution_id.clone(),
                mode,
                status: ExecutionStatus::Running,
            },
        );
    }

    let storage = Arc::clone(params.storage);
    let reload_handler = Arc::clone(params.reload_handler);
    let executions = Arc::clone(params.executions);
    let exec_id_clone = execution_id.clone();
    let mode_clone = mode;
    let update_in_progress = Arc::clone(params.update_in_progress);
    let mdd_decompress = params.mdd_decompress;

    tokio::spawn(async move {
        let result =
            execute_operation(mode_clone, &*storage, &*reload_handler, mdd_decompress).await;

        let mut map = executions.write().await;
        if let Some(exec) = map.get_mut(&exec_id_clone) {
            exec.status = match result {
                Ok(()) => ExecutionStatus::Completed,
                Err(e) => ExecutionStatus::Failed(e.to_string()),
            };
        }

        update_in_progress.store(false, Ordering::Release);
    });

    Ok(execution_id)
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
    R: RuntimeFileReloadHandler,
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
    use std::sync::{Arc, atomic::AtomicBool};

    use cda_interfaces::{
        HashMap,
        runtime_update_api::{ExecutionMode, ExecutionStatus, RuntimeUpdateError, UpdateExecution},
        storage_api::CollectionName,
    };
    use cda_storage::LocalStorage;
    use tokio::sync::RwLock;

    use crate::test_utils::{
        MockLockProvider, MockSecurityHandler, NoopReloadHandler, make_storage, write_test_file,
    };

    struct TestFixture {
        storage: Arc<LocalStorage>,
        security_handler: Arc<MockSecurityHandler>,
        reload_handler: Arc<NoopReloadHandler>,
        lock_provider: MockLockProvider,
        executions: Arc<RwLock<HashMap<String, UpdateExecution>>>,
        update_in_progress: Arc<AtomicBool>,
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
                update_in_progress: &self.update_in_progress,
                mdd_decompress: false,
                lock_state_provider: &self.lock_provider,
            }
        }
    }

    fn make_fixture() -> TestFixture {
        let (storage, dir) = make_storage();
        TestFixture {
            storage: Arc::new(storage),
            security_handler: Arc::new(MockSecurityHandler::new()),
            reload_handler: Arc::new(NoopReloadHandler),
            lock_provider: MockLockProvider {
                owner: Some("test-user".to_owned()),
                has_conflicts: false,
            },
            executions: Arc::new(RwLock::new(HashMap::default())),
            update_in_progress: Arc::new(AtomicBool::new(false)),
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
    async fn get_execution_status_unknown_id_returns_none() {
        let f = make_fixture();
        let result = super::get_execution_status(&f.executions, "nonexistent-id").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn start_execution_conflict_when_already_running() {
        let f = make_fixture();

        {
            let mut execs = f.executions.write().await;
            execs.insert(
                "existing".to_string(),
                UpdateExecution {
                    id: "existing".to_string(),
                    mode: ExecutionMode::Apply,
                    status: ExecutionStatus::Running,
                },
            );
        }

        let result = super::start_execution(&f.params(), ExecutionMode::Cleanup).await;
        assert!(matches!(result, Err(RuntimeUpdateError::ExecutionConflict)));
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

        // Start a first execution (Cleanup always succeeds with an empty storage).
        let first_id = super::start_execution(&f.params(), ExecutionMode::Cleanup)
            .await
            .unwrap();

        // Wait for it to reach a terminal state so it is eligible for removal.
        poll_until_terminal(&f.executions, &first_id).await;

        // Start a second execution - this must purge the first entry.
        let _second_id = super::start_execution(&f.params(), ExecutionMode::Cleanup)
            .await
            .unwrap();

        // The first execution ID must no longer be present.
        let status = super::get_execution_status(&f.executions, &first_id).await;
        assert!(
            status.is_none(),
            "expected first execution to be removed when second execution started"
        );
    }

    #[tokio::test]
    async fn execution_transitions_to_failed_on_error() {
        let f = make_fixture();

        let exec_id = super::start_execution(&f.params(), ExecutionMode::Apply)
            .await
            .unwrap();

        let status = poll_until_terminal(&f.executions, &exec_id).await;
        assert!(matches!(status, ExecutionStatus::Failed(_)));
    }
}
