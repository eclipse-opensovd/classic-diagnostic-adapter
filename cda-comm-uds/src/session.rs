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
    communication_control::CommunicationGuard,
    diagservices::{DiagServiceResponse, DiagServiceResponseType},
    dlt_ctx,
};

use crate::{UdsManager, VariantReadyEcu, types::ResetType};

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

    async fn set_ecu_session_resolved(
        &self,
        // Not used here beyond forwarding: holding the borrow for the whole
        // call keeps the caller's `CommunicationGuard` alive, so communication
        // cannot be disabled mid-request.
        communication: &CommunicationGuard,
        ecu: &VariantReadyEcu<'_, T>,
        session: &str,
        security_plugin: &DynamicPlugin,
    ) -> Result<<T as cda_interfaces::PayloadDecoder>::Response, DiagServiceError> {
        let dc = ecu.read().await.lookup_session_change(session).await?;
        self.send_service(communication, ecu, dc, security_plugin, None, true)
            .await
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
        let communication_guard = self.acquire_communication_guard()?;
        let data = self.ecu_data.read().await;
        let ecu = self
            .uds_ecu_variant_detection_concluded(&data, ecu_name)
            .await?;
        let result = self
            .set_ecu_session_resolved(&communication_guard, &ecu, session, security_plugin)
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
    ) -> Result<(), DiagServiceError> {
        // Cancel any existing session reset task to prevent double resetting
        if let Some(old_task) = self.session_reset_tasks.write().await.remove(ecu_name) {
            old_task.abort();
        }

        // Communication admission prevents an update writer from being queued while
        // this operation uses one resolved vehicle-data snapshot.
        let communication_guard = self.acquire_communication_guard()?;
        let data = self.ecu_data.read().await;
        let ecu = self
            .uds_ecu_variant_detection_concluded(&data, ecu_name)
            .await?;
        let ecu_read = ecu.read().await;
        let default_session = ecu_read.default_session()?;
        let current_session = ecu_read.session().await?;
        // The send below re-locks this ECU; a queued writer would deadlock it.
        drop(ecu_read);

        if current_session == default_session {
            tracing::info!("Already in default session, nothing to do");
            return Ok(());
        }

        let response = self
            .set_ecu_session_resolved(
                &communication_guard,
                &ecu,
                &default_session,
                security_plugin,
            )
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
