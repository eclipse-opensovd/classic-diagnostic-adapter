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
    DiagServiceError, DynamicPlugin, EcuGateway, EcuManager, HashMap, ResetOutcome, UdsSecurity,
    UdsSession,
    diagservices::{DiagServiceResponse, DiagServiceResponseType},
    dlt_ctx,
    util::tokio_ext,
};
use tokio::{sync::RwLock, task::JoinHandle};

use crate::{
    UdsManager,
    types::{EcuIdentifier, ResetTask, ResetType},
};

/// Removes the entry for `ecu_name` from an already locked reset map, aborting
/// and awaiting a scheduled task. Takes the locked map so callers can remove
/// and insert under one lock.
async fn remove_reset(tasks: &mut HashMap<EcuIdentifier, ResetTask>, ecu_name: &str) {
    if let Some(ResetTask::Scheduled(old_task)) = tasks.remove(ecu_name) {
        tokio_ext::abort_and_join(old_task, "ECU access reset").await;
    }
}

impl<S: EcuGateway, T: EcuManager> UdsManager<S, T> {
    fn reset_tasks(
        &self,
        reset_type: ResetType,
    ) -> &Arc<RwLock<HashMap<EcuIdentifier, ResetTask>>> {
        match reset_type {
            ResetType::Session => &self.session_reset_tasks,
            ResetType::SecurityAccess => &self.security_reset_tasks,
        }
    }

    /// Spawns a task that resets the ECU session or security access after
    /// `delay`. The caller stores the handle as a [`ResetTask::Scheduled`]
    /// entry; the task removes that entry before it resets, so the reset
    /// does not abort its own task.
    fn spawn_reset_task(
        &self,
        ecu_name: &str,
        delay: Duration,
        reset_type: ResetType,
    ) -> JoinHandle<()> {
        let ecu_name = ecu_name.to_owned();
        let uds = self.clone();
        cda_interfaces::spawn_named!(&format!("{ecu_name}-reset-{reset_type}"), async move {
            tokio_ext::sleep_for(delay).await;

            uds.reset_tasks(reset_type).write().await.remove(&ecu_name);

            // Use empty security plugin for reset
            let security_plugin: DynamicPlugin = Box::new(());
            tracing::info!(
                ecu_name = %ecu_name,
                access_type = %reset_type,
                "Resetting ECU access"
            );

            let result = match reset_type {
                ResetType::Session => uds.reset_ecu_session(&ecu_name, &security_plugin).await,
                ResetType::SecurityAccess => {
                    uds.reset_ecu_security_access(&ecu_name, &security_plugin)
                        .await
                }
            };

            if let Err(e) = result {
                tracing::error!(
                    ecu_name = %ecu_name,
                    error = %e,
                    access_type = %reset_type,
                    "Failed to reset ECU access"
                );
            }
        })
    }

    /// Replaces the pending reset for `ecu_name` after its session or security
    /// access was set: a scheduled timer is aborted and a deferred reset is
    /// dropped, so neither can reset the new value. With a non-zero
    /// `expiration`, a new task resets the ECU after that duration; otherwise
    /// no reset is pending afterward.
    pub(crate) async fn start_reset_task(
        &self,
        ecu_name: &str,
        expiration: Option<Duration>,
        reset_type: ResetType,
    ) {
        let mut tasks = self.reset_tasks(reset_type).write().await;
        remove_reset(&mut tasks, ecu_name).await;
        if let Some(expiration) = expiration.filter(|expiration| !expiration.is_zero()) {
            let task = self.spawn_reset_task(ecu_name, expiration, reset_type);
            tasks.insert(ecu_name.to_owned(), ResetTask::Scheduled(task));
        }
    }

    /// Removes the reset entry for `ecu_name`, whether `Scheduled` (the task
    /// is aborted) or `Deferred`.
    ///
    /// Called when a reset starts, so it cannot run twice.
    pub(crate) async fn cancel_reset(&self, ecu_name: &str, reset_type: ResetType) {
        remove_reset(&mut *self.reset_tasks(reset_type).write().await, ecu_name).await;
    }

    /// Records a reset that was due while communication was not enabled.
    pub(crate) async fn defer_reset(&self, ecu_name: &str, reset_type: ResetType) {
        tracing::info!(
            ecu_name = %ecu_name,
            access_type = %reset_type,
            "Communication is not enabled; deferring ECU access reset until it is"
        );
        if let Some(ResetTask::Scheduled(old_task)) = self
            .reset_tasks(reset_type)
            .write()
            .await
            .insert(ecu_name.to_owned(), ResetTask::Deferred)
        {
            old_task.abort();
        }
    }

    /// Schedules every deferred session and security-access reset to run
    /// now. Called from `on_enabled`, which must not wait for the UDS
    /// round-trips, so each reset runs in its own task. A reset whose task
    /// finds communication disabled again is deferred again.
    pub(crate) async fn resume_deferred_resets(&self) {
        for reset_type in [ResetType::Session, ResetType::SecurityAccess] {
            let mut tasks = self.reset_tasks(reset_type).write().await;
            let deferred: Vec<EcuIdentifier> = tasks
                .iter()
                .filter(|(_, task)| matches!(task, ResetTask::Deferred))
                .map(|(ecu, _)| ecu.clone())
                .collect();
            for ecu in deferred {
                let task = self.spawn_reset_task(&ecu, Duration::ZERO, reset_type);
                tasks.insert(ecu, ResetTask::Scheduled(task));
            }
        }
    }
}

#[async_trait]
impl<S: EcuGateway, T: EcuManager> UdsSession for UdsManager<S, T> {
    #[tracing::instrument(skip_all,
        fields(dlt_context = dlt_ctx!("UDS"))
    )]
    async fn set_ecu_session(
        &self,
        ecu_name: &str,
        session: &str,
        security_plugin: &DynamicPlugin,
        expiration: Option<Duration>,
    ) -> Result<Self::Response, DiagServiceError> {
        tracing::info!(ecu_name = %ecu_name, session = %session, "Setting session");
        let ecu_diag_service = self.uds_ecu_variant_detection_concluded(ecu_name).await?;
        let dc = ecu_diag_service
            .read()
            .await
            .lookup_session_change(session)
            .await?;
        let result = self
            .send_with_optional_timeout(ecu_name, dc, security_plugin, None, true, None)
            .await?;
        match result.response_type() {
            DiagServiceResponseType::Positive => {
                self.start_reset_task(ecu_name, expiration, ResetType::Session)
                    .await;

                Ok(result)
            }
            DiagServiceResponseType::Negative => Ok(result),
        }
    }

    async fn reset_ecu_session(
        &self,
        ecu_name: &str,
        security_plugin: &DynamicPlugin,
    ) -> Result<ResetOutcome, DiagServiceError> {
        // Cancel any existing session reset task to prevent double resetting
        self.cancel_reset(ecu_name, ResetType::Session).await;

        let ecu_diag_service = self.uds_ecu_db(ecu_name)?;
        let default_session = ecu_diag_service.read().await.default_session()?;
        let current_session = ecu_diag_service.read().await.session().await?;

        if current_session == default_session {
            tracing::info!("Already in default session, nothing to do");
            return Ok(ResetOutcome::Completed);
        }

        // Checked directly rather than through the send path, which would
        // request an activation: a reset must not switch communication on.
        let Ok(_guard) = self.communication_access.acquire() else {
            self.defer_reset(ecu_name, ResetType::Session).await;
            return Ok(ResetOutcome::Deferred);
        };

        let response = self
            .set_ecu_session(ecu_name, &default_session, security_plugin, None)
            .await?;

        match response.response_type() {
            DiagServiceResponseType::Positive => {
                tracing::info!(
                    ecu_name = %ecu_name,
                    session = %default_session,
                    "ECU session reset to default"
                );
                Ok(ResetOutcome::Completed)
            }
            DiagServiceResponseType::Negative => Err(DiagServiceError::UnexpectedResponse(Some(
                "Session reset negative response".to_owned(),
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use cda_interfaces::{
        DynamicPlugin, EcuStateManager, HashMap, ServicePayload, TransportResponse, UdsSession,
        datatypes::FaultConfig,
        diagservices::{DiagServiceResponse, DiagServiceResponseType},
        service_ids,
    };
    use cda_plugin_communication_management::lifecycle::enabled_communication_access_for_test;
    use tokio::sync::RwLock;

    use crate::{
        UdsManager,
        test_helpers::{
            TestEcuDb, TestGateway, negative_session_response, positive_session_response,
        },
    };

    const ECU: &str = "TestECU";

    fn plugin() -> DynamicPlugin {
        Box::new(())
    }

    /// Builds a gateway that answers every request with `response`.
    fn gateway_replying_with(response: Vec<u8>) -> TestGateway {
        TestGateway {
            send_fn: Arc::new(move |response_tx, _| {
                let msg = TransportResponse::UdsResponse(ServicePayload {
                    data: response.clone(),
                    source_address: 0x0001,
                    target_address: 0x0E00,
                    new_session: None,
                    new_security: None,
                });
                response_tx.try_send(Ok(Some(msg))).ok();
                Ok(())
            }),
        }
    }

    /// Builds a manager whose ECU sits in `current_session` and whose gateway
    /// answers every session change with `response`.
    ///
    /// The test ECU encoder supplies `ServicePayload::new_session`, so these
    /// tests exercise the production path that stores it after a positive response.
    async fn manager_in_session(
        current_session: &str,
        response: Vec<u8>,
    ) -> UdsManager<TestGateway, TestEcuDb> {
        let ecus = Arc::new(HashMap::from_iter([(
            ECU.to_owned(),
            RwLock::new(TestEcuDb::new()),
        )]));
        let manager = UdsManager::new_for_raw_payload_tests(
            gateway_replying_with(response),
            ecus,
            FaultConfig::default(),
            enabled_communication_access_for_test(),
        );
        ecu(&manager)
            .await
            .set_service_state(service_ids::SESSION_CONTROL, current_session.to_owned())
            .await;
        manager
    }

    async fn ecu(
        manager: &UdsManager<TestGateway, TestEcuDb>,
    ) -> tokio::sync::RwLockReadGuard<'_, TestEcuDb> {
        manager
            .uds_ecu_db(ECU)
            .expect("test ECU is registered")
            .read()
            .await
    }

    async fn current_session(manager: &UdsManager<TestGateway, TestEcuDb>) -> Option<String> {
        ecu(manager)
            .await
            .get_service_state(service_ids::SESSION_CONTROL)
            .await
    }

    #[tokio::test]
    async fn positive_response_updates_session_state() {
        let manager = manager_in_session("Default", positive_session_response()).await;

        let response = manager
            .set_ecu_session(ECU, "Programming", &plugin(), None)
            .await
            .expect("session change should succeed");

        assert_eq!(response.response_type(), DiagServiceResponseType::Positive);
        assert_eq!(
            current_session(&manager).await.as_deref(),
            Some("Programming")
        );
    }

    #[tokio::test]
    async fn negative_response_leaves_session_state_unchanged() {
        let manager = manager_in_session("Default", negative_session_response()).await;

        let response = manager
            .set_ecu_session(ECU, "Programming", &plugin(), None)
            .await
            .expect("a negative response is still returned as Ok");

        assert_eq!(response.response_type(), DiagServiceResponseType::Negative);
        assert_eq!(current_session(&manager).await.as_deref(), Some("Default"));
    }

    /// A confirmed session change replaces an existing, non-default value.
    #[tokio::test]
    async fn positive_response_replaces_existing_non_default_session_state() {
        let manager = manager_in_session("Programming", positive_session_response()).await;

        manager
            .set_ecu_session(ECU, "Extended", &plugin(), None)
            .await
            .expect("session change should succeed");

        assert_eq!(current_session(&manager).await.as_deref(), Some("Extended"));
    }

    /// A session set without an expiration replaces the timer of an earlier
    /// session change, so that timer cannot reset the newer session.
    #[tokio::test]
    async fn session_set_without_expiration_cancels_earlier_timer() {
        let manager = manager_in_session("Default", positive_session_response()).await;

        manager
            .set_ecu_session(ECU, "Extended", &plugin(), Some(Duration::from_secs(60)))
            .await
            .expect("session change should succeed");
        assert!(manager.session_reset_tasks.read().await.contains_key(ECU));

        manager
            .set_ecu_session(ECU, "Programming", &plugin(), None)
            .await
            .expect("session change should succeed");

        assert!(
            manager.session_reset_tasks.read().await.is_empty(),
            "the earlier timer must not survive a newer session change"
        );
    }
}
