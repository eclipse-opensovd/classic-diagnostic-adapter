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

use std::sync::Arc;

use cda_interfaces::{
    HashMap,
    communication_control::PostUpdateCommunicationMode,
    runtime_update_api::{
        ExecutionMode, ExecutionStatus, LockStateProvider, RuntimeReloaderPlugin,
        RuntimeUpdateError, RuntimeUpdateSecurityPlugin, UpdateCollections, UpdateExecution,
    },
    storage_api::{CollectionName, Storage},
};
use cda_plugin_communication_management::{
    http_protection::{
        config::{HttpProtectionConfig, HttpProtectionReason, HttpStatusCode},
        registry::HttpProtectionRegistry,
    },
    lifecycle::disable::{DisableCommunication, DisableError, DisableReason},
};
use tokio::sync::RwLock;

pub(crate) struct ExecutionParams<'a, S, R: ?Sized, T, L> {
    pub(crate) storage: &'a Arc<S>,
    pub(crate) security_handler: &'a Arc<T>,
    pub(crate) reload_handler: &'a Arc<R>,
    pub(crate) executions: &'a Arc<RwLock<HashMap<String, UpdateExecution>>>,
    pub(crate) communication_disable: &'a Arc<dyn DisableCommunication>,
    pub(crate) http_protections: &'a HttpProtectionRegistry,
    pub(crate) update_retry_after_seconds: u64,
    pub(crate) post_update_mode: PostUpdateCommunicationMode,
    pub(crate) mdd_decompress: bool,
    pub(crate) lock_state_provider: &'a L,
}

fn http_protection_config_for_update(retry_after_seconds: u64) -> HttpProtectionConfig {
    HttpProtectionConfig::new(
        HttpProtectionReason::UpdateInProgress,
        HttpStatusCode::CONFLICT,
        "Update in progress",
    )
    .with_exempt_routes(crate::routes_exempt_from_update_protection())
    .with_retry_after(retry_after_seconds)
}

#[allow(
    clippy::too_many_lines,
    reason = "Function length acceptable for complex orchestration logic"
)]
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
    // Check for a running execution before attempting to disable transport.
    // This prevents two concurrent callers from both passing the check.
    {
        let execs = params.executions.read().await;
        let has_running = execs.values().any(|e| e.status == ExecutionStatus::Running);
        if has_running {
            return Err(RuntimeUpdateError::ExecutionConflict);
        }
    }

    let protection = params
        .http_protections
        .protect(http_protection_config_for_update(
            params.update_retry_after_seconds,
        ))
        .map_err(|error| RuntimeUpdateError::FatalError(error.to_string()))?;
    let disable_lease = params
        .communication_disable
        .disable(DisableReason::RuntimeUpdate)
        .await
        .map_err(|error| match error {
            DisableError::Conflict | DisableError::InUse => RuntimeUpdateError::ExecutionConflict,
            DisableError::Failed(failure) => {
                RuntimeUpdateError::CommunicationFailure(failure.to_string())
            }
        })?;

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
        let _ = disable_lease.release().await;
        drop(protection);
        return Err(e);
    }

    // For Rollback: verify backup is non-empty before accepting the request.
    if mode == ExecutionMode::Rollback {
        match crate::storage::is_backup_empty(&**params.storage).await {
            Ok(true) => {
                let _ = disable_lease.release().await;
                drop(protection);
                return Err(RuntimeUpdateError::NoBackup);
            }
            Err(e) => {
                let _ = disable_lease.release().await;
                drop(protection);
                return Err(e);
            }
            Ok(false) => {}
        }
    }

    // For Apply: verify there is at least one pending NextUpdate collection.
    if mode == ExecutionMode::Apply
        && collections.pending_mdd.is_none()
        && collections.pending_config.is_none()
    {
        let _ = disable_lease.release().await;
        drop(protection);
        return Err(RuntimeUpdateError::NoPendingUpdate);
    }

    let execution_id = uuid::Uuid::new_v4().to_string();
    {
        let mut execs = params.executions.write().await;
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
    let mdd_decompress = params.mdd_decompress;
    let post_update_mode = params.post_update_mode.clone();
    let disable_lease = disable_lease;
    let protection = protection;

    tokio::spawn(async move {
        let result =
            execute_operation(mode_clone, &*storage, &*reload_handler, mdd_decompress).await;

        let mut map = executions.write().await;
        if let Some(exec) = map.get_mut(&exec_id_clone) {
            exec.status = match result {
                Ok(()) => ExecutionStatus::Completed,
                Err(ref e) => ExecutionStatus::Failed(e.to_string()),
            };
        }
        drop(map);

        let should_defer = result.is_ok()
            && matches!(mode_clone, ExecutionMode::Apply | ExecutionMode::Rollback)
            && matches!(post_update_mode, PostUpdateCommunicationMode::Deferred);
        if should_defer {
            // Release the disable lease, anyone can re-enable communication when needed now.
            // For example done in the 'on demand' plugin upon the next request
            drop(disable_lease);
        } else if let Err(failure) = disable_lease.release().await {
            tracing::error!(%failure, "failed to resume transport after runtime update");
        }
        drop(protection);
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
    use std::sync::Arc;

    use async_trait::async_trait;
    use cda_interfaces::{
        HashMap,
        communication_control::{
            PostUpdateCommunicationMode, TransportControl, TransportState, error::CommControlError,
        },
        runtime_update_api::{ExecutionMode, ExecutionStatus, RuntimeUpdateError, UpdateExecution},
        storage_api::CollectionName,
    };
    use cda_plugin_communication_management::{
        http_protection::{
            config::{HttpProtectionConfig, HttpProtectionReason, HttpStatusCode},
            evaluator::{HttpRestrictionDecision, HttpRestrictionGuard},
            registry::HttpProtectionRegistry,
        },
        lifecycle::{communication_disable_for_test, disable::DisableCommunication},
    };
    use cda_storage::LocalStorage;
    use tokio::sync::RwLock;

    use crate::test_utils::{
        MockLockProvider, MockSecurityHandler, NoopReloadHandler, make_storage, write_test_file,
    };

    /// A simple transport stub that starts disabled (can be enabled/disabled freely).
    struct StubTransport {
        state: tokio::sync::Mutex<TransportState>,
    }

    impl StubTransport {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                state: tokio::sync::Mutex::new(TransportState::Disabled),
            })
        }
    }

    #[async_trait]
    impl TransportControl for StubTransport {
        async fn enable(&self) -> Result<(), CommControlError> {
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

    fn make_transport_and_disable() -> (HttpProtectionRegistry, Arc<dyn DisableCommunication>) {
        let transport = StubTransport::new();
        let restrictions = HttpProtectionRegistry::new();
        let disable = communication_disable_for_test(
            Arc::<StubTransport>::clone(&transport),
            Some((
                restrictions.clone(),
                HttpProtectionConfig::new(
                    HttpProtectionReason::UpdateInProgress,
                    HttpStatusCode::CONFLICT,
                    "Update in progress",
                ),
            )),
            true,
        );
        (restrictions, disable)
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
                update_retry_after_seconds: 1,
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
        // The "already running" check fires before transport disable, so transport
        // stays enabled (restriction remains inactive).
        assert!(matches!(result, Err(RuntimeUpdateError::ExecutionConflict)));
        // Restriction is NOT installed because disable was never called.
        assert!(!f.http_restriction_manager.is_active());
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
        let params = super::ExecutionParams {
            storage: &f.storage,
            security_handler: &f.security_handler,
            reload_handler: &failing_reload_handler,
            executions: &f.executions,
            communication_disable: &f.communication_disable,
            http_protections: &f.http_restriction_manager,
            update_retry_after_seconds: 1,
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

    #[test]
    fn update_protection_blocks_all_routes_except_confirmed_get_routes() {
        let config = super::http_protection_config_for_update(17);

        assert_eq!(config.status, HttpStatusCode::CONFLICT);
        assert_eq!(config.retry_after_seconds, Some(17));
        let factory = HttpProtectionRegistry::new();
        let _protection = factory.protect(config).unwrap();
        for path in [
            "/health",
            "/health/ready",
            "/vehicle/v15/data/version",
            "/vehicle/v15/apps/sovd2uds/operations/runtimefilesupdate/executions",
            "/vehicle/v15/apps/sovd2uds/operations/runtimefilesupdate/executions/abc",
        ] {
            assert!(matches!(
                factory.evaluate(path, &http::Method::GET),
                HttpRestrictionDecision::Pass
            ));
            assert!(matches!(
                factory.evaluate(path, &http::Method::POST),
                HttpRestrictionDecision::Deny(denial)
                if denial.status == HttpStatusCode::CONFLICT
                    && denial.retry_after_seconds == Some(17)
            ));
        }
        assert!(matches!(
            factory.evaluate(
                "/vehicle/v15/apps/sovd2uds/authorization",
                &http::Method::GET,
            ),
            HttpRestrictionDecision::Deny(denial)
            if denial.status == HttpStatusCode::CONFLICT
        ));
    }
}
