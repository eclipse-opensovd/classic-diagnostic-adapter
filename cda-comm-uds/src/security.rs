/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

use std::time::Duration;

use cda_interfaces::{
    DiagServiceError, DynamicPlugin, EcuGateway, EcuManager, SecurityAccess, UdsEcu,
    diagservices::{DiagServiceResponseType, UdsPayloadData},
};

use crate::{
    UdsManager, session::do_start_reset_task, transport::do_send_with_optional_timeout,
    types::ResetType,
};

pub(crate) async fn do_reset_ecu_security_access<
    S: EcuGateway,
    R: cda_interfaces::diagservices::DiagServiceResponse,
    T: EcuManager<Response = R>,
>(
    manager: &UdsManager<S, R, T>,
    ecu_name: &str,
    security_plugin: &DynamicPlugin,
) -> Result<(), DiagServiceError> {
    if let Some(old_task) = manager.security_reset_tasks.write().await.remove(ecu_name) {
        old_task.abort();
    }

    let ecu_diag_service = manager.ecu_manager(ecu_name)?;
    let default_security_access = ecu_diag_service.read().await.default_security_access()?;
    let current_security_access = ecu_diag_service.read().await.security_access().await?;

    if current_security_access == default_security_access {
        tracing::debug!("Already at default security access, nothing to do");
        return Ok(());
    }

    let (_, response) = manager
        .set_ecu_security_access(
            ecu_name,
            &default_security_access,
            None,
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

pub(crate) async fn do_set_ecu_security_access<
    S: EcuGateway,
    R: cda_interfaces::diagservices::DiagServiceResponse,
    T: EcuManager<Response = R>,
>(
    manager: &UdsManager<S, R, T>,
    ecu_name: &str,
    level: &str,
    seed_service: Option<&String>,
    authentication_data: Option<UdsPayloadData>,
    security_plugin: &DynamicPlugin,
    expiration: Option<Duration>,
) -> Result<(SecurityAccess, R), DiagServiceError> {
    let ecu_diag_service = manager.ecu_manager(ecu_name)?;
    let security_access = ecu_diag_service
        .read()
        .await
        .lookup_security_access_change(level, seed_service, authentication_data.is_some())
        .await?;
    match &security_access {
        SecurityAccess::RequestSeed(dc) => Ok((
            security_access.clone(),
            do_send_with_optional_timeout(
                manager,
                ecu_name,
                dc.clone(),
                security_plugin,
                None,
                false,
                None,
            )
            .await?,
        )),
        SecurityAccess::SendKey(dc) => {
            let result = do_send_with_optional_timeout(
                manager,
                ecu_name,
                dc.clone(),
                security_plugin,
                authentication_data,
                true,
                None,
            )
            .await?;
            match result.response_type() {
                DiagServiceResponseType::Positive => {
                    do_start_reset_task(manager, ecu_name, expiration, ResetType::SecurityAccess)
                        .await;

                    Ok((security_access, result))
                }
                DiagServiceResponseType::Negative => Ok((security_access, result)),
            }
        }
    }
}

pub(crate) async fn do_get_send_key_param_name<
    S: EcuGateway,
    R: cda_interfaces::diagservices::DiagServiceResponse,
    T: EcuManager<Response = R>,
>(
    manager: &UdsManager<S, R, T>,
    ecu_name: &str,
    level: &str,
) -> Result<String, DiagServiceError> {
    let ecu_diag_service = manager.ecu_manager(ecu_name)?;
    let security_access = ecu_diag_service
        .read()
        .await
        .lookup_security_access_change(level, None, true)
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
