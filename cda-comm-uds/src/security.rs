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

use std::time::Duration;

use async_trait::async_trait;
use cda_interfaces::{
    DiagServiceError, DynamicPlugin, EcuGateway, EcuManager, SecurityAccess, UdsSecurity,
    UdsTransport,
    diagservices::{DiagServiceResponse, DiagServiceResponseType, UdsPayloadData},
};

use crate::{UdsManager, types::ResetType};

#[async_trait]
impl<S: EcuGateway, T: EcuManager> UdsSecurity for UdsManager<S, T> {
    async fn reset_ecu_security_access(
        &self,
        ecu_name: &str,
        security_plugin: &DynamicPlugin,
    ) -> Result<(), DiagServiceError> {
        // Cancel any existing security access reset task to prevent double resetting
        if let Some(old_task) = self.security_reset_tasks.write().await.remove(ecu_name) {
            old_task.abort();
        }

        let ecu_diag_service = self.uds_ecu_db(ecu_name)?;
        let default_security_access = ecu_diag_service.read().await.default_security_access()?;
        let current_security_access = ecu_diag_service.read().await.security_access().await?;

        if current_security_access == default_security_access {
            tracing::debug!("Already at default security access, nothing to do");
            return Ok(());
        }

        let (_, response) = self
            .set_ecu_security_access(
                ecu_name,
                &default_security_access,
                None,
                security_plugin,
                None,
            )
            .await?;

        match response.response_type() {
            DiagServiceResponseType::Positive => {
                tracing::info!(
                    ecu_name = %ecu_name,
                    security_access = %default_security_access,
                    "ECU security access reset to default"
                );
                Ok(())
            }
            DiagServiceResponseType::Negative => Err(DiagServiceError::UnexpectedResponse(Some(
                "Security access reset negative response".to_owned(),
            ))),
        }
    }

    async fn set_ecu_security_access(
        &self,
        ecu_name: &str,
        level: &str,
        authentication_data: Option<UdsPayloadData>,
        security_plugin: &DynamicPlugin,
        expiration: Option<Duration>,
    ) -> Result<(SecurityAccess, Self::Response), DiagServiceError> {
        let ecu_diag_service = self.uds_ecu_db(ecu_name)?;
        let security_access = ecu_diag_service
            .read()
            .await
            .lookup_security_access_change(level, authentication_data.is_some())
            .await?;
        match &security_access {
            SecurityAccess::RequestSeed(dc) => Ok((
                security_access.clone(),
                self.send(ecu_name, dc.clone(), security_plugin, None, false)
                    .await?,
            )),
            SecurityAccess::SendKey(dc) => {
                let result = self
                    .send(
                        ecu_name,
                        dc.clone(),
                        security_plugin,
                        authentication_data,
                        true,
                    )
                    .await?;
                match result.response_type() {
                    DiagServiceResponseType::Positive => {
                        self.start_reset_task(ecu_name, expiration, ResetType::SecurityAccess)
                            .await;

                        Ok((security_access, result))
                    }
                    DiagServiceResponseType::Negative => Ok((security_access, result)),
                }
            }
        }
    }

    async fn get_send_key_param_name(
        &self,
        ecu_name: &str,
        level: &str,
    ) -> Result<String, DiagServiceError> {
        let ecu_diag_service = self.uds_ecu_db(ecu_name)?;
        let security_access = ecu_diag_service
            .read()
            .await
            .lookup_security_access_change(level, true)
            .await?;
        match &security_access {
            SecurityAccess::RequestSeed(_) => {
                unreachable!("Not reached, because has key is set to true above")
            }
            SecurityAccess::SendKey(dc) => {
                let ecu = ecu_diag_service.read().await;
                ecu.get_send_key_param_name(dc).await
            }
        }
    }
}
