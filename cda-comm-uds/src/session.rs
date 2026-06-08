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

use std::{sync::Arc, time::Duration};

use cda_interfaces::{
    DiagServiceError, DynamicPlugin, EcuGateway, EcuManager, UdsEcu,
    diagservices::DiagServiceResponseType, dlt_ctx,
};

use crate::{UdsManager, transport::do_send_with_optional_timeout, types::ResetType};

pub(crate) async fn do_start_reset_task<
    S: EcuGateway,
    R: cda_interfaces::diagservices::DiagServiceResponse,
    T: EcuManager<Response = R>,
>(
    manager: &UdsManager<S, R, T>,
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
    let uds_clone = manager.clone();

    let reset_task = match reset_type {
        ResetType::Session => Arc::clone(&manager.session_reset_tasks),
        ResetType::SecurityAccess => Arc::clone(&manager.security_reset_tasks),
    };

    if let Some(old_task) = reset_task.write().await.remove(&ecu_name) {
        old_task.abort();
    }

    let ecu_name_clone = ecu_name.clone();
    let reset_task_clone = Arc::clone(&reset_task);
    let task =
        cda_interfaces::spawn_named!(&format!("{ecu_name}-reset-{reset_type}"), async move {
            cda_interfaces::util::tokio_ext::sleep_for(expiration).await;

            reset_task_clone.write().await.remove(&ecu_name_clone);

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

#[tracing::instrument(skip_all,
    fields(dlt_context = dlt_ctx!("UDS"))
)]
pub(crate) async fn do_set_ecu_session<
    S: EcuGateway,
    R: cda_interfaces::diagservices::DiagServiceResponse,
    T: EcuManager<Response = R>,
>(
    manager: &UdsManager<S, R, T>,
    ecu_name: &str,
    session: &str,
    security_plugin: &DynamicPlugin,
    expiration: Option<Duration>,
) -> Result<R, DiagServiceError> {
    tracing::info!(ecu_name = %ecu_name, session = %session, "Setting session");
    let ecu_diag_service = manager.ecu_manager(ecu_name)?;
    let dc = ecu_diag_service
        .read()
        .await
        .lookup_session_change(session)
        .await?;
    let result =
        do_send_with_optional_timeout(manager, ecu_name, dc, security_plugin, None, true, None)
            .await?;
    match result.response_type() {
        DiagServiceResponseType::Positive => {
            do_start_reset_task(manager, ecu_name, expiration, ResetType::Session).await;

            Ok(result)
        }
        DiagServiceResponseType::Negative => Ok(result),
    }
}

pub(crate) async fn do_reset_ecu_session<
    S: EcuGateway,
    R: cda_interfaces::diagservices::DiagServiceResponse,
    T: EcuManager<Response = R>,
>(
    manager: &UdsManager<S, R, T>,
    ecu_name: &str,
    security_plugin: &DynamicPlugin,
) -> Result<(), DiagServiceError> {
    if let Some(old_task) = manager.session_reset_tasks.write().await.remove(ecu_name) {
        old_task.abort();
    }

    let ecu_diag_service = manager.ecu_manager(ecu_name)?;
    let default_session = ecu_diag_service.read().await.default_session()?;
    let current_session = ecu_diag_service.read().await.session().await?;

    if current_session == default_session {
        tracing::info!("Already in default session, nothing to do");
        return Ok(());
    }

    let response = manager
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
