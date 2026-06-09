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

use cda_interfaces::{
    DiagServiceError, EcuGateway, EcuManager, EcuState, ServicePayload,
    TesterPresentControlMessage, TesterPresentMode, TesterPresentType, UdsEcu, dlt_ctx,
    service_ids,
};
use tokio::time::{MissedTickBehavior, interval as tokio_interval};

use crate::{UdsManager, transport::do_send_with_raw_payload, types::TesterPresentTask};

pub(crate) async fn do_control_tester_present<
    S: EcuGateway,
    R: cda_interfaces::diagservices::DiagServiceResponse,
    T: EcuManager<Response = R>,
>(
    manager: &UdsManager<S, R, T>,
    control_msg: TesterPresentControlMessage,
) -> Result<(), DiagServiceError> {
    match control_msg.mode {
        TesterPresentMode::Start => {
            let mut tester_presents = manager.tester_present_tasks.write().await;
            if tester_presents.get(&control_msg.ecu).is_some() {
                return Err(DiagServiceError::InvalidRequest(format!(
                    "A tester present for {} is already running",
                    control_msg.ecu
                )));
            }

            let interval = if let Some(i) = control_msg.interval {
                i
            } else {
                manager
                    .ecu_manager(&control_msg.ecu)?
                    .read()
                    .await
                    .tester_present_time()
            };
            tracing::debug!(
                "Starting tester present on for {} with interval {:?}",
                control_msg.ecu,
                interval
            );

            let uds = manager.clone();
            let msg_clone = control_msg.clone();
            let task = cda_interfaces::spawn_named!(
                &format!(
                    "tester-present-{}{}",
                    control_msg.ecu,
                    if control_msg.type_.is_functional() {
                        "-functional"
                    } else {
                        ""
                    }
                ),
                async move {
                    let mut schedule = tokio_interval(interval);
                    schedule.set_missed_tick_behavior(MissedTickBehavior::Delay);
                    loop {
                        let _ = schedule.tick().await;
                        if let Ok(ecu) = uds.ecu_manager(&control_msg.ecu) {
                            let ecu_state = ecu.read().await.variant().state;
                            if ecu_state != EcuState::Online {
                                tracing::debug!(
                                    ecu = %control_msg.ecu,
                                    ecu_state = %ecu_state,
                                    "Skipping tester present for ECU that is not online"
                                );
                                continue;
                            }
                        }
                        if let Ok(r) = tokio::time::timeout(
                            interval,
                            do_send_tester_present(&uds, &control_msg),
                        )
                        .await
                        {
                            if let Err(e) = r {
                                tracing::error!(error = %e, "Failed to send tester present");
                            }
                        } else {
                            tracing::error!(
                                "tester present send took longer than scheduled interval of {}",
                                interval.as_millis()
                            );
                        }
                    }
                }
            );

            tester_presents.insert(
                msg_clone.ecu,
                TesterPresentTask {
                    type_: msg_clone.type_,
                    task,
                },
            );

            Ok(())
        }
        TesterPresentMode::Stop => {
            let tester_present = manager
                .tester_present_tasks
                .write()
                .await
                .remove(&control_msg.ecu)
                .ok_or_else(|| {
                    DiagServiceError::InvalidRequest(format!(
                        "ECU {} has no active tester present task",
                        control_msg.ecu
                    ))
                })?;
            tester_present.task.abort();
            Ok(())
        }
    }
}

async fn do_send_tester_present<
    S: EcuGateway,
    R: cda_interfaces::diagservices::DiagServiceResponse,
    T: EcuManager<Response = R>,
>(
    manager: &UdsManager<S, R, T>,
    control_msg: &TesterPresentControlMessage,
) -> Result<(), DiagServiceError> {
    let payload = {
        let ecu = manager.ecu_manager(&control_msg.ecu)?;
        let target_address = match &control_msg.type_ {
            TesterPresentType::Functional(_) => ecu.read().await.logical_functional_address(),
            TesterPresentType::Ecu(_) => ecu.read().await.logical_address(),
        };
        ServicePayload {
            data: vec![service_ids::TESTER_PRESENT, 0x80],
            source_address: ecu.read().await.tester_address(),
            target_address,
            new_session: None,
            new_security: None,
        }
    };

    match do_send_with_raw_payload(manager, &control_msg.ecu, payload, None, false).await {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

#[tracing::instrument(skip_all,
    fields(dlt_context = dlt_ctx!("UDS"))
)]
pub(crate) async fn do_start_tester_present<
    S: EcuGateway,
    R: cda_interfaces::diagservices::DiagServiceResponse,
    T: EcuManager<Response = R>,
>(
    manager: &UdsManager<S, R, T>,
    type_: TesterPresentType,
) -> Result<(), DiagServiceError> {
    match type_ {
        TesterPresentType::Ecu(ref ecu_name) => {
            let ecu = ecu_name.to_owned();
            do_control_tester_present(
                manager,
                TesterPresentControlMessage {
                    mode: TesterPresentMode::Start,
                    type_,
                    ecu,
                    interval: None,
                },
            )
            .await
        }
        TesterPresentType::Functional(ref functional_group) => {
            for name in manager
                .ecus_for_functional_group(functional_group, true)
                .await
            {
                if let Err(e) = do_control_tester_present(
                    manager,
                    TesterPresentControlMessage {
                        mode: TesterPresentMode::Start,
                        type_: type_.clone(),
                        ecu: name.clone(),
                        interval: None,
                    },
                )
                .await
                {
                    tracing::warn!(
                        functional_group = %functional_group,
                        ecu_name = %name,
                        error = %e,
                        "Failed to start tester present for ECU in functional group"
                    );
                }
            }
            Ok(())
        }
    }
}

#[tracing::instrument(skip_all,
    fields(dlt_context = dlt_ctx!("UDS"))
)]
pub(crate) async fn do_stop_tester_present<
    S: EcuGateway,
    R: cda_interfaces::diagservices::DiagServiceResponse,
    T: EcuManager<Response = R>,
>(
    manager: &UdsManager<S, R, T>,
    type_: TesterPresentType,
) -> Result<(), DiagServiceError> {
    match type_ {
        TesterPresentType::Ecu(ref ecu_name) => {
            let ecu = ecu_name.to_owned();
            do_control_tester_present(
                manager,
                TesterPresentControlMessage {
                    mode: TesterPresentMode::Stop,
                    type_,
                    ecu,
                    interval: None,
                },
            )
            .await
        }
        TesterPresentType::Functional(ref functional_group) => {
            for name in manager
                .ecus_for_functional_group(functional_group, true)
                .await
            {
                if let Err(e) = do_control_tester_present(
                    manager,
                    TesterPresentControlMessage {
                        mode: TesterPresentMode::Stop,
                        type_: type_.clone(),
                        ecu: name.clone(),
                        interval: None,
                    },
                )
                .await
                {
                    tracing::warn!(
                        functional_group = %functional_group,
                        ecu_name = %name,
                        error = %e,
                        "Failed to stop tester present for ECU in functional group"
                    );
                }
            }
            Ok(())
        }
    }
}

pub(crate) async fn do_check_tester_present_active<
    S: EcuGateway,
    R: cda_interfaces::diagservices::DiagServiceResponse,
    T: EcuManager<Response = R>,
>(
    manager: &UdsManager<S, R, T>,
    type_: &TesterPresentType,
) -> bool {
    match type_ {
        TesterPresentType::Ecu(ecu_name) => {
            let tester_presents = manager.tester_present_tasks.read().await;
            tester_presents.get(ecu_name).is_some()
        }
        TesterPresentType::Functional(functional_group) => {
            let ecu_names = manager
                .ecus_for_functional_group(functional_group, true)
                .await;
            let tester_presents = manager.tester_present_tasks.read().await;
            ecu_names
                .iter()
                .all(|ecu| tester_presents.get(ecu).is_some())
        }
    }
}
