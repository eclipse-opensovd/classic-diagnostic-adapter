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
    Connectivity, DiagServiceError, EcuGateway, EcuManager, HashMap,
    SUPPRESS_POSITIVE_RESPONSE_BIT, ServicePayload, TesterPresentControlMessage, TesterPresentMode,
    TesterPresentType, UdsFunctionalGroup, UdsTesterPresent, dlt_ctx, service_ids,
};
use tokio::{
    task::JoinHandle,
    time::{MissedTickBehavior, interval as tokio_interval},
};

use crate::{UdsManager, transport::CommunicationReadiness, types::TesterPresentTaskId};

fn all_active(
    tester_presents: &HashMap<TesterPresentTaskId, JoinHandle<()>>,
    type_: &TesterPresentType,
    ecu_names: &[String],
) -> bool {
    !ecu_names.is_empty()
        && ecu_names.iter().all(|ecu| {
            tester_presents.contains_key(&TesterPresentTaskId {
                type_: type_.clone(),
                ecu: ecu.clone(),
            })
        })
}

impl<S: EcuGateway, T: EcuManager> UdsManager<S, T> {
    fn spawn_tester_present_task(
        &self,
        control_msg: TesterPresentControlMessage,
        interval: std::time::Duration,
    ) -> JoinHandle<()> {
        tracing::debug!(
            "Starting tester present on for {} with interval {:?}",
            control_msg.ecu,
            interval
        );
        let uds = self.clone();
        cda_interfaces::spawn_named!(
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
                    schedule.tick().await;
                    // Skip sending if the ECU is not online; the loop will
                    // naturally resume once the ECU is detected online again.
                    if let Ok(ecu) = uds.uds_ecu_db(&control_msg.ecu) {
                        let ecu_state = ecu.read().await.runtime_state().status().connectivity;
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
                    if let Ok(result) =
                        tokio::time::timeout(interval, uds.send_tester_present(&control_msg)).await
                    {
                        if let Err(error) = result {
                            tracing::error!(%error, "Failed to send tester present");
                        }
                    } else {
                        tracing::error!(
                            "tester present send took longer than scheduled interval of {}",
                            interval.as_millis()
                        );
                    }
                }
            }
        )
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
        let ecu_names = match &type_ {
            TesterPresentType::Ecu(ecu_name) => vec![ecu_name.clone()],
            TesterPresentType::Functional(functional_group) => {
                self.ecus_for_functional_group(functional_group, true).await
            }
        };

        let mut starts = Vec::with_capacity(ecu_names.len());
        for ecu in ecu_names {
            let interval = self.uds_ecu_db(&ecu)?.read().await.tester_present_time();
            if interval.is_zero() {
                return Err(DiagServiceError::InvalidConfiguration(format!(
                    "Tester present interval for ECU {ecu} must be greater than zero"
                )));
            }
            starts.push((ecu, interval));
        }

        let mut tester_presents = self.tester_present_tasks.write().await;
        for (ecu, interval) in starts {
            let key = TesterPresentTaskId {
                type_: type_.clone(),
                ecu: ecu.clone(),
            };

            tester_presents.entry(key).or_insert_with(|| {
                let control_msg = TesterPresentControlMessage {
                    mode: TesterPresentMode::Start,
                    type_: type_.clone(),
                    ecu,
                    interval: Some(interval),
                };

                self.spawn_tester_present_task(control_msg, interval)
            });
        }

        Ok(())
    }

    #[tracing::instrument(skip_all,
        fields(dlt_context = dlt_ctx!("UDS"))
    )]
    async fn stop_tester_present(&self, type_: TesterPresentType) -> Result<(), DiagServiceError> {
        let ecu_names = match &type_ {
            TesterPresentType::Ecu(ecu_name) => vec![ecu_name.clone()],
            TesterPresentType::Functional(functional_group) => {
                self.ecus_for_functional_group(functional_group, true).await
            }
        };
        let keys = ecu_names
            .iter()
            .map(|ecu| TesterPresentTaskId {
                type_: type_.clone(),
                ecu: ecu.clone(),
            })
            .collect::<Vec<_>>();
        let mut tester_presents = self.tester_present_tasks.write().await;
        for key in keys {
            if let Some(tester_present) = tester_presents.remove(&key) {
                tester_present.abort();
            }
        }
        Ok(())
    }

    async fn check_tester_present_active(&self, type_: &TesterPresentType) -> bool {
        match type_ {
            TesterPresentType::Ecu(ecu_name) => {
                let tester_presents = self.tester_present_tasks.read().await;
                tester_presents.contains_key(&TesterPresentTaskId {
                    type_: type_.clone(),
                    ecu: ecu_name.clone(),
                })
            }
            TesterPresentType::Functional(functional_group) => {
                let ecu_names = self.ecus_for_functional_group(functional_group, true).await;
                let tester_presents = self.tester_present_tasks.read().await;
                all_active(&tester_presents, type_, &ecu_names)
            }
        }
    }
}

impl<S: EcuGateway, T: EcuManager> UdsManager<S, T> {
    /// Aborts all running tester-present tasks and saves their types so the
    /// lifecycle initialization can restart them after communication is re-enabled.
    pub(crate) async fn snapshot_and_abort_tester_present(&self) {
        let mut tasks = self.tester_present_tasks.write().await;
        let snapshot: Vec<TesterPresentType> = tasks.keys().map(|id| id.type_.clone()).collect();
        if !snapshot.is_empty() {
            tracing::debug!(
                count = snapshot.len(),
                "Communication disabling; aborting tester-present tasks and saving snapshot"
            );
        }
        let handles: Vec<_> = tasks.drain().map(|(_, task)| task).collect();
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

#[cfg(test)]
mod tests {
    use cda_interfaces::{HashMap, HashMapExtensions, TesterPresentType};

    use super::all_active;
    use crate::types::TesterPresentTaskId;

    fn task() -> tokio::task::JoinHandle<()> {
        tokio::spawn(std::future::pending())
    }

    #[tokio::test]
    async fn existing_exact_key_is_idempotent() {
        let type_ = TesterPresentType::Ecu("ecu".to_owned());
        let key = TesterPresentTaskId {
            type_: type_.clone(),
            ecu: "ecu".to_owned(),
        };
        let mut tasks: HashMap<TesterPresentTaskId, tokio::task::JoinHandle<()>> = HashMap::new();
        tasks.insert(key.clone(), task());
        let original_id = tasks.get(&key).expect("task exists").id();

        if !tasks.contains_key(&key) {
            tasks.insert(key.clone(), task());
        }

        let existing = tasks.remove(&key).expect("task remains");
        assert_eq!(existing.id(), original_id);
        existing.abort();
    }

    #[tokio::test]
    async fn ecu_and_functional_tasks_coexist() {
        let ecu = "ecu".to_owned();
        let ecu_key = TesterPresentTaskId {
            type_: TesterPresentType::Ecu(ecu.clone()),
            ecu: ecu.clone(),
        };
        let functional_key = TesterPresentTaskId {
            type_: TesterPresentType::Functional("group".to_owned()),
            ecu,
        };
        let mut tasks = HashMap::new();
        tasks.insert(ecu_key.clone(), task());
        tasks.insert(functional_key.clone(), task());

        let ecu_task = tasks.remove(&ecu_key).expect("ECU task exists");
        ecu_task.abort();

        assert!(!tasks.contains_key(&ecu_key));
        assert!(tasks.contains_key(&functional_key));
        tasks
            .remove(&functional_key)
            .expect("functional task exists")
            .abort();
    }

    #[tokio::test]
    async fn functional_support_requires_every_member() {
        let type_ = TesterPresentType::Functional("group".to_owned());
        let ecu_names = vec!["ecu-1".to_owned(), "ecu-2".to_owned()];
        let first_key = TesterPresentTaskId {
            type_: type_.clone(),
            ecu: "ecu-1".to_owned(),
        };
        let second_key = TesterPresentTaskId {
            type_: type_.clone(),
            ecu: "ecu-2".to_owned(),
        };
        let mut tasks = HashMap::new();
        tasks.insert(first_key.clone(), task());

        assert!(!all_active(&tasks, &type_, &ecu_names));

        tasks.insert(second_key.clone(), task());
        assert!(all_active(&tasks, &type_, &ecu_names));

        tasks.remove(&first_key).expect("first task exists").abort();
        tasks
            .remove(&second_key)
            .expect("second task exists")
            .abort();
    }

    #[tokio::test]
    async fn removing_absent_key_is_harmless() {
        let key = TesterPresentTaskId {
            type_: TesterPresentType::Ecu("ecu".to_owned()),
            ecu: "ecu".to_owned(),
        };
        let mut tasks: HashMap<TesterPresentTaskId, tokio::task::JoinHandle<()>> = HashMap::new();

        assert!(tasks.remove(&key).is_none());
        assert!(tasks.is_empty());
    }
}
