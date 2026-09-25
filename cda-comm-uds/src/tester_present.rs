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
    Connectivity, DiagServiceError, EcuGateway, EcuManager, SUPPRESS_POSITIVE_RESPONSE_BIT,
    ServicePayload, TesterPresentControlMessage, TesterPresentMode, TesterPresentType,
    UdsFunctionalGroup, UdsTesterPresent, communication_control::CommunicationError, dlt_ctx,
    service_ids,
};
use tokio::time::{MissedTickBehavior, interval as tokio_interval};

use crate::{UdsManager, transport::CommunicationReadiness, types::TesterPresentTask};

/// How often a deferred snapshot restart re-checks whether the activation it
/// belongs to has published `Enabled`.
///
/// [`CommunicationAccess`](cda_interfaces::communication_control::CommunicationAccess)
/// exposes no state-change subscription, so this has to poll. `Enabling` covers
/// whole-vehicle variant detection and can therefore last seconds, which is
/// what this interval is sized against: the added restart latency is far below
/// any tester-present interval.
const SNAPSHOT_RESTART_POLL_INTERVAL: Duration = Duration::from_millis(50);

impl<S: EcuGateway, T: EcuManager> UdsManager<S, T> {
    /// Start or stop a tester present task for a single ECU.
    async fn control_tester_present(
        &self,
        control_msg: TesterPresentControlMessage,
    ) -> Result<(), DiagServiceError> {
        match control_msg.mode {
            TesterPresentMode::Start => {
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
                    self.uds_ecu_db(&control_msg.ecu)?
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
                            if let Ok(ecu) = uds.uds_ecu_db(&control_msg.ecu) {
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
                                uds.send_tester_present(&control_msg),
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

    async fn start_tester_present_tasks(
        &self,
        type_: TesterPresentType,
    ) -> Result<(), DiagServiceError> {
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

    /// Send a single tester present message to the ECU.
    async fn send_tester_present(
        &self,
        control_msg: &TesterPresentControlMessage,
    ) -> Result<(), DiagServiceError> {
        let payload = {
            let ecu = self.uds_ecu_db(&control_msg.ecu)?;
            let target_address = match &control_msg.type_ {
                TesterPresentType::Functional(_) => ecu.read().await.logical_functional_address(),
                TesterPresentType::Ecu(_) => ecu.read().await.logical_address(),
            };
            ServicePayload {
                data: vec![service_ids::TESTER_PRESENT, SUPPRESS_POSITIVE_RESPONSE_BIT],
                source_address: ecu.read().await.tester_address(),
                target_address,
                new_session: None,
                new_security: None,
            }
        };

        match self
            .send_with_raw_payload(
                &control_msg.ecu,
                payload,
                None,
                false,
                CommunicationReadiness::Enforce,
            )
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
        let _guard = self.require_communication_ready()?;
        self.start_tester_present_tasks(type_).await
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
    /// Aborts a deferred snapshot restart that has not run yet.
    ///
    /// The snapshot itself is deliberately left untouched: a restart that was
    /// still waiting has restored nothing, so its types must stay available for
    /// the next activation.
    pub(crate) async fn abort_pending_snapshot_restart(&self) {
        let pending = self.tester_present_restart_task.lock().await.take();
        if let Some(task) = pending {
            task.abort();
            let _ = task.await;
        }
    }

    /// Aborts all running tester-present tasks and saves their types so the
    /// lifecycle initialization can restart them after communication is re-enabled.
    ///
    /// Running tasks are keyed per ECU, so a functional group shows up once per
    /// member. Types are de-duplicated on insert, leaving one `Functional` entry
    /// per group, because [`UdsTesterPresent::start_tester_present`]
    /// re-enumerates the whole group from it.
    ///
    /// The new types are merged into the existing snapshot rather than
    /// replacing it. A restart still waiting for its activation to reach
    /// `Enabled` has started no tasks, so the types it was going to restore
    /// exist only in the snapshot.
    pub(crate) async fn snapshot_and_abort_tester_present(&self) {
        self.abort_pending_snapshot_restart().await;

        let mut tasks = self.tester_present_tasks.write().await;
        let running: Vec<TesterPresentType> = tasks.values().map(|tp| tp.type_.clone()).collect();
        let handles: Vec<_> = tasks.drain().map(|(_, tp)| tp.task).collect();
        drop(tasks);
        for handle in handles {
            handle.abort();
            let _ = handle.await;
        }

        let mut snapshot = self.tester_present_snapshot.lock().await;
        for type_ in running {
            if !snapshot.contains(&type_) {
                snapshot.push(type_);
            }
        }
        if !snapshot.is_empty() {
            tracing::debug!(
                count = snapshot.len(),
                "Communication disabling; aborting tester-present tasks and saving snapshot"
            );
        }
    }

    /// Restarts the tester-present tasks captured by
    /// [`UdsManager::snapshot_and_abort_tester_present`], once the activation
    /// that triggered this initialization has reached `Enabled`.
    ///
    /// The restart waits for the in-flight activation to publish `Enabled`
    /// rather than requesting another activation. It keeps the snapshot when
    /// that activation ends in any other state, so a later activation can retry
    /// the restart. After restoration, the active tasks become the record of
    /// tester-present state and the snapshot is cleared.
    pub(crate) async fn restart_tester_present_snapshot(&self) {
        let snapshot = self.tester_present_snapshot.lock().await.clone();
        if snapshot.is_empty() {
            return;
        }

        self.abort_pending_snapshot_restart().await;

        let uds = self.clone();
        let task = cda_interfaces::spawn_named!("tester-present-snapshot-restart", async move {
            let guard = loop {
                match uds.communication_access.acquire() {
                    Ok(guard) => break guard,
                    Err(CommunicationError::Enabling) => {
                        cda_interfaces::util::tokio_ext::sleep_for(SNAPSHOT_RESTART_POLL_INTERVAL)
                            .await;
                    }
                    Err(e) => {
                        tracing::debug!(
                            error = %e,
                            "Communication did not reach enabled; keeping tester-present snapshot \
                             for the next activation"
                        );
                        return;
                    }
                }
            };

            for type_ in snapshot {
                if let Err(e) = uds.start_tester_present_tasks(type_.clone()).await {
                    tracing::warn!(
                        ?type_,
                        error = %e,
                        "Failed to restart tester present after communication re-enable"
                    );
                }
            }
            drop(guard);

            uds.tester_present_snapshot.lock().await.clear();
        });
        *self.tester_present_restart_task.lock().await = Some(task);
    }
}
