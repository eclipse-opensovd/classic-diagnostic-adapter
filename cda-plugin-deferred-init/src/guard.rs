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

//! [`RequestGuard`] implementation for deferred ECU communication initialization.
//!
//! [`DeferredInitGuard`] gates diagnostic endpoints (those requiring `DoIP`
//! communication) behind an initialization check. When the system is not yet
//! initialized and a diagnostic request arrives, the guard:
//!
//! 1. Consults [`InitializationPlugin::can_initialize`] to decide whether
//!    initialization should begin.
//! 2. If approved, spawns an async task to call
//!    [`CommunicationControl::enable`].
//! 3. Calls [`InitializationPlugin::on_initialized`] with the result after
//!    `enable()` completes (success or failure).
//! 4. Returns HTTP 503 with a `Retry-After` header so the client can retry.
//!
//! Non-diagnostic paths (health, version, locks, apps, listing endpoints)
//! always pass through unconditionally.

use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use cda_interfaces::{
    communication_control::CommunicationControl,
    deferred_init_api::{
        DeferredInitError, InitializationContext, InitializationPlugin, TriggerReason,
    },
    guard::{
        GuardDecision, GuardDenial, HttpMethod, RequestGuard, StatusCode,
        requires_doip_communication,
    },
};
use tracing;

// ErrorCode::PreconditionsNotFulfilled = 4280 (from sovd_interfaces)
const ERROR_CODE_PRECONDITIONS_NOT_FULFILLED: u16 = 4280;

/// A [`RequestGuard`] that gates diagnostic endpoints behind deferred ECU
/// communication initialization.
///
/// # Fast-path
///
/// [`is_active`](Self::is_active) checks `comm_active` atomically. Once
/// communication is active the guard short-circuits immediately without
/// allocating the async evaluation future.
///
/// # Evaluation logic
///
/// When active and a diagnostic path is requested:
///
/// 1. If `trigger_in_progress` is already set, skip re-triggering.
/// 2. Otherwise, consult [`InitializationPlugin::can_initialize`].
/// 3. If approved, spawn a task that calls [`CommunicationControl::enable`]
///    and then calls [`InitializationPlugin::on_initialized`] with the result.
/// 4. Return HTTP 503 with `Retry-After`.
#[derive(Clone)]
pub struct DeferredInitGuard {
    /// Shared flag indicating whether communication is active.
    /// When `true`, the guard is inactive (fast-path pass-through).
    comm_active: Arc<AtomicBool>,
    /// Handle to the communication subsystem for triggering enable.
    comm_control: Arc<dyn CommunicationControl>,
    /// Plugin consulted before triggering initialization.
    plugin: Arc<dyn InitializationPlugin>,
    /// Value for the HTTP `Retry-After` header (seconds).
    retry_after_seconds: u64,
    /// Flag to prevent multiple concurrent enable triggers.
    trigger_in_progress: Arc<AtomicBool>,
}

impl DeferredInitGuard {
    /// Creates a new [`DeferredInitGuard`].
    ///
    /// # Arguments
    ///
    /// * `comm_active` - Shared atomic flag from [`CommunicationControl::active`].
    /// * `comm_control` - Handle for triggering communication enable.
    /// * `plugin` - Plugin that decides whether initialization should proceed.
    /// * `retry_after_seconds` - Value for the HTTP `Retry-After` header.
    #[must_use]
    pub fn new(
        comm_active: Arc<AtomicBool>,
        comm_control: Arc<dyn CommunicationControl>,
        plugin: Arc<dyn InitializationPlugin>,
        retry_after_seconds: u64,
    ) -> Self {
        Self {
            comm_active,
            comm_control,
            plugin,
            retry_after_seconds,
            trigger_in_progress: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl RequestGuard for DeferredInitGuard {
    /// Returns `true` when communication is **not** active (i.e. the guard
    /// should evaluate incoming requests).
    fn is_active(&self) -> bool {
        !self.comm_active.load(Ordering::Acquire)
    }

    /// Evaluates whether the request should be allowed or denied.
    ///
    /// Non-diagnostic paths always pass. Diagnostic paths are denied with
    /// HTTP 503 while initialization is pending, and the guard may trigger
    /// initialization if the plugin approves.
    fn evaluate<'a>(
        &'a self,
        path: &'a str,
        _method: HttpMethod,
    ) -> Pin<Box<dyn Future<Output = GuardDecision> + Send + 'a>> {
        Box::pin(async move {
            // Non-diagnostic paths pass unconditionally.
            if !requires_doip_communication(path) {
                return GuardDecision::Pass;
            }

            // If no trigger is currently in progress, consult the plugin.
            if !self.trigger_in_progress.load(Ordering::Acquire) {
                let context = InitializationContext::new(TriggerReason::OnDemand, 1);
                let allowed = self.plugin.can_initialize(&context).await;

                if allowed
                    && self
                        .trigger_in_progress
                        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                {
                    // Spawn the enable task so we don't block the request.
                    let comm_control = Arc::clone(&self.comm_control);
                    let trigger_flag = Arc::clone(&self.trigger_in_progress);
                    let plugin = Arc::clone(&self.plugin);
                    tokio::spawn(async move {
                        let result = match comm_control.enable().await {
                            Ok(()) => {
                                tracing::info!(
                                    "Deferred ECU communication initialization succeeded"
                                );
                                Ok(())
                            }
                            Err(e) => {
                                tracing::error!(
                                    error = %e,
                                    "Deferred ECU communication initialization failed"
                                );
                                Err(DeferredInitError::InitFailed(e.to_string()))
                            }
                        };
                        plugin.on_initialized(&result).await;
                        trigger_flag.store(false, Ordering::Release);
                    });
                }
            }

            // Deny with 503 - initialization is pending or in progress.
            GuardDecision::Deny(GuardDenial {
                status: StatusCode::SERVICE_UNAVAILABLE,
                message: "ECU communication initialization pending".to_owned(),
                error_code: ERROR_CODE_PRECONDITIONS_NOT_FULFILLED,
                retry_after_seconds: Some(self.retry_after_seconds),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[test]
    fn requires_doip_communication_matches_ecu_subpaths() {
        assert!(requires_doip_communication(
            "/vehicle/v15/components/ecu1/data/service"
        ));
        assert!(requires_doip_communication(
            "/vehicle/v15/functions/functionalgroups/AllECUs/operations/op"
        ));
    }

    #[test]
    fn requires_doip_communication_rejects_non_doip_paths() {
        assert!(!requires_doip_communication("/vehicle/v15/components"));
        assert!(!requires_doip_communication(
            "/vehicle/v15/functions/functionalgroups"
        ));
        assert!(!requires_doip_communication("/vehicle/v15/locks"));
        assert!(!requires_doip_communication("/health"));
        assert!(!requires_doip_communication("/vehicle/v15/data/version"));
        assert!(!requires_doip_communication(
            "/vehicle/v15/apps/sovd2uds/bulk-data/flashfiles"
        ));
    }

    // Helpers for on_initialized tests

    use cda_interfaces::{
        communication_control::{CommControlError, CommState, CommunicationControl},
        deferred_init_api::{
            BoxFuture, DeferredInitError, InitializationContext, InitializationPlugin,
        },
        util::tokio_ext,
    };

    /// A mock [`CommunicationControl`] whose `enable()` either succeeds or
    /// returns a fixed error, depending on `should_fail`.
    struct MockCommControl {
        should_fail: bool,
    }

    #[async_trait::async_trait]
    impl CommunicationControl for MockCommControl {
        async fn enable(&self) -> Result<(), CommControlError> {
            if self.should_fail {
                Err(CommControlError::InitFailed("mock failure".to_owned()))
            } else {
                Ok(())
            }
        }

        async fn disable(&self) -> Result<(), CommControlError> {
            Ok(())
        }

        async fn state(&self) -> CommState {
            CommState::Disabled
        }

        fn active(&self) -> Arc<AtomicBool> {
            Arc::new(AtomicBool::new(false))
        }
    }

    /// A mock [`InitializationPlugin`] that records every `on_initialized` call.
    struct RecordingPlugin {
        recorded: Arc<Mutex<Vec<Result<(), DeferredInitError>>>>,
    }

    impl InitializationPlugin for RecordingPlugin {
        fn on_ready(&self, _comm: Arc<dyn CommunicationControl>) -> BoxFuture<'_, ()> {
            Box::pin(async {})
        }

        fn can_initialize(&self, _context: &InitializationContext) -> BoxFuture<'_, bool> {
            Box::pin(async { true })
        }

        fn on_initialized<'a>(
            &'a self,
            result: &'a Result<(), DeferredInitError>,
        ) -> BoxFuture<'a, ()> {
            let result = result.clone();
            let recorded = Arc::clone(&self.recorded);
            Box::pin(async move {
                recorded.lock().unwrap().push(result);
            })
        }
    }

    /// Build a [`DeferredInitGuard`] wired to the given comm-control and plugin.
    fn make_guard(
        comm: Arc<dyn CommunicationControl>,
        plugin: Arc<dyn InitializationPlugin>,
    ) -> DeferredInitGuard {
        let comm_active = comm.active();
        DeferredInitGuard::new(comm_active, comm, plugin, 5)
    }

    #[tokio::test]
    async fn on_initialized_receives_ok_when_enable_succeeds() {
        let recorded: Arc<Mutex<Vec<Result<(), DeferredInitError>>>> =
            Arc::new(Mutex::new(Vec::new()));
        let plugin = Arc::new(RecordingPlugin {
            recorded: Arc::clone(&recorded),
        });
        let comm = Arc::new(MockCommControl { should_fail: false });
        let guard = make_guard(comm, plugin);

        // Trigger evaluation on a diagnostic path - spawns the enable task.
        let decision = guard
            .evaluate("/vehicle/v15/components/ecu1/data/service", HttpMethod::Get)
            .await;

        // Guard must return 503 while init is in progress.
        assert!(matches!(decision, GuardDecision::Deny(_)));

        // Wait for the spawned task to complete.
        tokio_ext::sleep_for(std::time::Duration::from_millis(50)).await;

        let calls = recorded.lock().unwrap().clone();
        assert_eq!(
            calls.len(),
            1,
            "on_initialized should be called exactly once"
        );
        assert_eq!(
            calls.first(),
            Some(&Ok(())),
            "on_initialized should receive Ok(())"
        );
    }

    #[tokio::test]
    async fn on_initialized_receives_failed_when_enable_fails() {
        let recorded: Arc<Mutex<Vec<Result<(), DeferredInitError>>>> =
            Arc::new(Mutex::new(Vec::new()));
        let plugin = Arc::new(RecordingPlugin {
            recorded: Arc::clone(&recorded),
        });
        let comm = Arc::new(MockCommControl { should_fail: true });
        let guard = make_guard(comm, plugin);

        let decision = guard
            .evaluate("/vehicle/v15/components/ecu1/data/service", HttpMethod::Get)
            .await;

        assert!(matches!(decision, GuardDecision::Deny(_)));

        tokio_ext::sleep_for(std::time::Duration::from_millis(50)).await;

        let calls = recorded.lock().unwrap().clone();
        assert_eq!(
            calls.len(),
            1,
            "on_initialized should be called exactly once"
        );
        assert!(
            matches!(calls.first(), Some(Err(DeferredInitError::InitFailed(_)))),
            "on_initialized should receive Err(InitFailed(...))"
        );
    }
}
