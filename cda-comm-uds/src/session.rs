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
    DiagServiceError, DynamicPlugin, EcuGateway, EcuManager, UdsSecurity, UdsSession,
    diagservices::{DiagServiceResponse, DiagServiceResponseType},
    dlt_ctx,
};

use crate::{UdsManager, types::ResetType};

impl<S: EcuGateway, T: EcuManager> UdsManager<S, T> {
    /// Spawn a background task that resets the ECU session or security access
    /// after the given expiration duration.
    pub(crate) async fn start_reset_task(
        &self,
        ecu_name: &str,
        expiration: Option<Duration>,
        reset_type: ResetType,
    ) {
        let expiration = if let Some(expiration) = expiration
            && expiration > Duration::ZERO
        {
            expiration
        } else {
            return;
        };

        let ecu_name = ecu_name.to_owned();
        let uds_clone = self.clone();

        let reset_task = match reset_type {
            ResetType::Session => Arc::clone(&self.session_reset_tasks),
            ResetType::SecurityAccess => Arc::clone(&self.security_reset_tasks),
        };

        // Cancel any existing reset task for this ECU
        if let Some(old_task) = reset_task.write().await.remove(&ecu_name) {
            old_task.abort();
        }

        let ecu_name_clone = ecu_name.clone();
        let reset_task_clone = Arc::clone(&reset_task);
        let task =
            cda_interfaces::spawn_named!(&format!("{ecu_name}-reset-{reset_type}"), async move {
                cda_interfaces::util::tokio_ext::sleep_for(expiration).await;

                // Remove the task from the map before calling reset to prevent self-abort
                reset_task_clone.write().await.remove(&ecu_name_clone);

                // Use empty security plugin for reset
                let security_plugin: DynamicPlugin = Box::new(());
                tracing::info!(
                    ecu_name = %ecu_name_clone,
                    access_type = %reset_type,
                    "Resetting ECU access, as timeout expired"
                );

                let result = match reset_type {
                    ResetType::Session => {
                        uds_clone
                            .reset_ecu_session(&ecu_name_clone, &security_plugin)
                            .await
                    }
                    ResetType::SecurityAccess => {
                        uds_clone
                            .reset_ecu_security_access(&ecu_name_clone, &security_plugin)
                            .await
                    }
                };

                if let Err(e) = result {
                    tracing::error!(
                        ecu_name = %ecu_name_clone,
                        error = %e,
                        access_type = %reset_type,
                        "Failed to reset ECU access after timeout"
                    );
                }
            });

        reset_task.write().await.insert(ecu_name, task);
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
        let ecu_diag_service = self.uds_ecu_db(ecu_name)?;
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
                ecu_diag_service
                    .read()
                    .await
                    .set_service_state(
                        cda_interfaces::service_ids::SESSION_CONTROL,
                        session.to_owned(),
                    )
                    .await;
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
    ) -> Result<(), DiagServiceError> {
        // Cancel any existing session reset task to prevent double resetting
        if let Some(old_task) = self.session_reset_tasks.write().await.remove(ecu_name) {
            old_task.abort();
        }

        let ecu_diag_service = self.uds_ecu_db(ecu_name)?;
        let default_session = ecu_diag_service.read().await.default_session()?;
        let current_session = ecu_diag_service.read().await.session().await?;

        if current_session == default_session {
            tracing::info!("Already in default session, nothing to do");
            return Ok(());
        }

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
                Ok(())
            }
            DiagServiceResponseType::Negative => Err(DiagServiceError::UnexpectedResponse(Some(
                "Session reset negative response".to_owned(),
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, atomic::AtomicBool};

    use cda_interfaces::{
        DynamicPlugin, EcuStateManager, HashMap, ServicePayload, TransportResponse, UdsSession,
        datatypes::FaultConfig,
        diagservices::{DiagServiceResponse, DiagServiceResponseType},
        service_ids,
    };
    use tokio::sync::RwLock;

    use crate::{
        UdsManager,
        test_helpers::{TestEcuDb, negative_session_response, positive_session_response},
        transport::send_tests::TestGateway,
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
    /// The ECU's encoder deliberately leaves `ServicePayload::new_session`
    /// unset, reproducing the case where the state chart has no transition
    /// starting from the active session. The transport layer's `new_session`
    /// fallback therefore cannot fire, so anything these tests observe in the
    /// `SESSION_CONTROL` state was written by `set_ecu_session` itself.
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
            enable_communication_access_for_test(),
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

    /// Regression test for the ECU appearing stuck in the programming session.
    /// The state chart lookup that populates `ServicePayload::new_session` only
    /// resolves transitions whose source is the active state, so once the ECU
    /// had left the default session that fallback stopped firing and the stored
    /// state was never overwritten again.
    ///
    /// `TestEcuDb` cannot reproduce that lookup (it has no state chart), so what
    /// this pins down is the consequence: a confirmed session change replaces an
    /// existing, non-default value rather than only filling an empty slot.
    #[tokio::test]
    async fn positive_response_replaces_existing_non_default_session_state() {
        let manager = manager_in_session("Programming", positive_session_response()).await;

        manager
            .set_ecu_session(ECU, "Extended", &plugin(), None)
            .await
            .expect("session change should succeed");

        assert_eq!(current_session(&manager).await.as_deref(), Some("Extended"));
    }
}
