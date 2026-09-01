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

use async_trait::async_trait;
use cda_interfaces::{
    Connectivity, DiagServiceError, EcuGateway, EcuManager, SUPPRESS_POSITIVE_RESPONSE_BIT,
    ServicePayload, TesterPresentControlMessage, TesterPresentMode, TesterPresentType,
    UdsFunctionalGroup, UdsTesterPresent, dlt_ctx, service_ids,
};
use tokio::time::{MissedTickBehavior, interval as tokio_interval};

use crate::{UdsManager, types::TesterPresentTask};

impl<S: EcuGateway, T: EcuManager> UdsManager<S, T> {
    /// Start or stop a tester present task for a single ECU.
    async fn control_tester_present(
        &self,
        control_msg: TesterPresentControlMessage,
    ) -> Result<(), DiagServiceError> {
        match control_msg.mode {
            TesterPresentMode::Start => {
                let data = self.ecu_data.read().await;
                let mut tester_presents = self.tester_present_tasks.write().await;
                if tester_presents.get(&control_msg.ecu).is_some() {
                    return Err(DiagServiceError::InvalidRequest(format!(
                        "A tester present for {} is already running",
                        control_msg.ecu
                    )));
                }

                let interval = if let Some(i) = control_msg.interval {
                    i
                } else {
                    Self::ecu_in(&data, &control_msg.ecu)?
                        .read()
                        .await
                        .tester_present_time()
                };
                tracing::debug!(
                    "Starting tester present on for {} with interval {:?}",
                    control_msg.ecu,
                    interval
                );

                let uds = self.clone();
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
                        // To ensure accurate timing for tester present messages, use
                        // tokio::time::Interval which internally tracks the elapsed
                        // time since the last tick, thus ensuring that the task is always
                        // executed with the same schedule.
                        let mut schedule = tokio_interval(interval);
                        // change the missed tick behavior from burst to delay, as for
                        // TesterPresent it does not make sense to 'catch up' if a delay
                        // occurred, but rather try to keep the timing consistent again.
                        schedule.set_missed_tick_behavior(MissedTickBehavior::Delay);
                        loop {
                            let _ = schedule.tick().await;
                            // Skip sending if the ECU is not online; the loop will
                            // naturally resume once the ECU is detected online again.
                            let Ok(_communication_guard) = uds.require_communication_ready() else {
                                continue;
                            };
                            let data = uds.ecu_data.read().await;
                            if let Ok(ecu) = Self::ecu_in(&data, &control_msg.ecu) {
                                let ecu_state =
                                    ecu.read().await.runtime_state().status().connectivity;
                                if ecu_state != Connectivity::Online {
                                    tracing::debug!(
                                        ecu = %control_msg.ecu,
                                        ecu_state = %ecu_state,
                                        "Skipping tester present for ECU that is not online"
                                    );
                                    continue;
                                }
                            }

                            // abort sending if it takes longer than `interval` and log an
                            // error, but try to continue sending tester present afterwards.
                            if let Ok(r) = tokio::time::timeout(
                                interval,
                                uds.send_tester_present(&data, &control_msg),
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
                let tester_present = self
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

    /// Send a single tester present message to the ECU.
    async fn send_tester_present(
        &self,
        data: &crate::VehicleEcuData<T>,
        control_msg: &TesterPresentControlMessage,
    ) -> Result<(), DiagServiceError> {
        let ecu = Self::ecu_in(data, &control_msg.ecu)?;
        let payload = {
            let ecu_read = ecu.read().await;
            let target_address = match &control_msg.type_ {
                TesterPresentType::Functional(_) => ecu_read.logical_functional_address(),
                TesterPresentType::Ecu(_) => ecu_read.logical_address(),
            };
            ServicePayload {
                data: vec![service_ids::TESTER_PRESENT, SUPPRESS_POSITIVE_RESPONSE_BIT],
                source_address: ecu_read.tester_address(),
                target_address,
                new_session: None,
                new_security: None,
            }
        };

        match self
            .send_raw_payload_for_ecu(&ecu, &control_msg.ecu, payload, None, false)
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[async_trait]
impl<S: EcuGateway, T: EcuManager> UdsTesterPresent for UdsManager<S, T> {
    #[tracing::instrument(skip_all,
        fields(dlt_context = dlt_ctx!("UDS"))
    )]
    async fn start_tester_present(&self, type_: TesterPresentType) -> Result<(), DiagServiceError> {
        match type_ {
            TesterPresentType::Ecu(ref ecu_name) => {
                let ecu = ecu_name.to_owned();
                self.control_tester_present(TesterPresentControlMessage {
                    mode: TesterPresentMode::Start,
                    type_,
                    ecu,
                    interval: None,
                })
                .await
            }
            TesterPresentType::Functional(ref functional_group) => {
                for name in self.ecus_for_functional_group(functional_group, true).await {
                    if let Err(e) = self
                        .control_tester_present(TesterPresentControlMessage {
                            mode: TesterPresentMode::Start,
                            type_: type_.clone(),
                            ecu: name.clone(),
                            interval: None,
                        })
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
    async fn stop_tester_present(&self, type_: TesterPresentType) -> Result<(), DiagServiceError> {
        match type_ {
            TesterPresentType::Ecu(ref ecu_name) => {
                let ecu = ecu_name.to_owned();
                self.control_tester_present(TesterPresentControlMessage {
                    mode: TesterPresentMode::Stop,
                    type_,
                    ecu,
                    interval: None,
                })
                .await
            }
            TesterPresentType::Functional(ref functional_group) => {
                for name in self.ecus_for_functional_group(functional_group, true).await {
                    if let Err(e) = self
                        .control_tester_present(TesterPresentControlMessage {
                            mode: TesterPresentMode::Stop,
                            type_: type_.clone(),
                            ecu: name.clone(),
                            interval: None,
                        })
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

    async fn check_tester_present_active(&self, type_: &TesterPresentType) -> bool {
        match type_ {
            TesterPresentType::Ecu(ecu_name) => {
                let tester_presents = self.tester_present_tasks.read().await;
                tester_presents.get(ecu_name).is_some()
            }
            TesterPresentType::Functional(functional_group) => {
                let ecu_names = self.ecus_for_functional_group(functional_group, true).await;
                let tester_presents = self.tester_present_tasks.read().await;
                ecu_names
                    .iter()
                    .all(|ecu| tester_presents.get(ecu).is_some())
            }
        }
    }
}

impl<S: EcuGateway, T: EcuManager> UdsManager<S, T> {
    /// Aborts all running tester-present tasks and saves their types so the
    /// lifecycle initialization can restart them after communication is re-enabled.
    pub(crate) async fn snapshot_and_abort_tester_present(&self) {
        let mut tasks = self.tester_present_tasks.write().await;
        let snapshot: Vec<TesterPresentType> = tasks.values().map(|tp| tp.type_.clone()).collect();
        if !snapshot.is_empty() {
            tracing::debug!(
                count = snapshot.len(),
                "Communication disabling; aborting tester-present tasks and saving snapshot"
            );
        }
        let handles: Vec<_> = tasks.drain().map(|(_, tp)| tp.task).collect();
        drop(tasks);
        for handle in handles {
            handle.abort();
            let _ = handle.await;
        }
        *self.tester_present_snapshot.lock().await = snapshot;
    }

    /// Restarts the tester-present tasks captured by
    /// [`UdsManager::snapshot_and_abort_tester_present`].
    ///
    /// The snapshot holds one entry per ECU, so a functional-group tester
    /// present appears once per member. The duplicates are collapsed here,
    /// because [`UdsTesterPresent::start_tester_present`] re-enumerates the
    /// whole group from a single `Functional` entry.
    pub(crate) async fn restart_tester_present_snapshot(&self) {
        let snapshot = std::mem::take(&mut *self.tester_present_snapshot.lock().await);
        let mut started = Vec::with_capacity(snapshot.len());
        for type_ in snapshot {
            if started.contains(&type_) {
                continue;
            }
            started.push(type_.clone());
            if let Err(e) = self.start_tester_present(type_.clone()).await {
                tracing::warn!(
                    ?type_,
                    error = %e,
                    "Failed to restart tester present after communication re-enable"
                );
            }
        }
    }
}
