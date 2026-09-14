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
    Connectivity, DiagServiceError, EcuGateway, EcuManager, HashMap,
    SUPPRESS_POSITIVE_RESPONSE_BIT, ServicePayload, TesterPresentControlMessage, TesterPresentMode,
    TesterPresentType, UdsEcuDb, UdsFunctionalGroup, UdsTesterPresent, VariantDetection,
    communication_control::CommunicationError, dlt_ctx, service_ids,
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
    fn spawn_tester_present_task(
        &self,
        control_msg: TesterPresentControlMessage,
        interval: std::time::Duration,
    ) -> JoinHandle<()> {
        tracing::debug!(
            "Starting tester present for {} with interval {:?}",
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

    async fn start_tester_present_tasks(
        &self,
        type_: TesterPresentType,
    ) -> Result<(), DiagServiceError> {
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
}

impl<S: EcuGateway, T: UdsEcuDb + VariantDetection> UdsManager<S, T> {
    /// Send a single tester present message to the ECU.
    async fn send_tester_present(
        &self,
        control_msg: &TesterPresentControlMessage,
    ) -> Result<(), DiagServiceError> {
        let (mut data, expect_response, source_address, target_address) = {
            let ecu = self.uds_ecu_db(&control_msg.ecu)?;
            let ecu = ecu.read().await;
            let target_address = match &control_msg.type_ {
                TesterPresentType::Functional(_) => ecu.logical_functional_address(),
                TesterPresentType::Ecu(_) => ecu.logical_address(),
            };
            (
                ecu.tester_present_message(),
                ecu.tester_present_response_expected(),
                ecu.tester_address(),
                target_address,
            )
        };

        // Fall back to the standard tester present request when the ECU does not
        // define a usable message (needs SID + subfunction byte to carry the
        // suppress-positive-response bit).
        if data.len() < 2 {
            tracing::warn!(
                ecu = %control_msg.ecu,
                configured_len = data.len(),
                "Tester present message from com-params is too short; falling back to default"
            );
            data = vec![service_ids::TESTER_PRESENT, 0x00];
        }

        if let Some(subfunction) = data.get_mut(1) {
            if expect_response {
                *subfunction &= !SUPPRESS_POSITIVE_RESPONSE_BIT;
            } else {
                *subfunction |= SUPPRESS_POSITIVE_RESPONSE_BIT;
            }
        }

        let payload = ServicePayload {
            data,
            source_address,
            target_address,
            new_session: None,
            new_security: None,
        };

        match self
            .send_with_raw_payload(
                &control_msg.ecu,
                payload,
                None,
                expect_response,
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
    pub(crate) async fn snapshot_and_abort_tester_present(&self) {
        self.abort_pending_snapshot_restart().await;

        let mut tasks = self.tester_present_tasks.write().await;
        let running: Vec<TesterPresentType> = tasks.keys().map(|id| id.type_.clone()).collect();
        let handles: Vec<_> = tasks.drain().map(|(_, task)| task).collect();
        drop(tasks);
        for handle in handles {
            handle.abort();
            let _ = handle.await;
        }

        // Merge into the snapshot rather than replacing it. A restart that was
        // still waiting for its activation to reach `Enabled` has started no
        // tasks, so the types it was going to restore exist only in the
        // snapshot. Replacing here would drop them for good and tester present
        // would never come back.
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
    /// The restart cannot run inline, because `initialize` runs while the
    /// lifecycle is still `Enabling`. A tester-present task sends on its first
    /// interval tick, which fires immediately; that send would be refused as
    /// not-ready and would request an activation on top of the one already in
    /// flight.
    ///
    /// The snapshot may hold a functional-group entry per member ECU. The
    /// duplicates are collapsed here, because
    /// [`UdsTesterPresent::start_tester_present`] re-enumerates the whole group
    /// from a single `Functional` entry.
    pub(crate) async fn restart_tester_present_snapshot(&self) {
        // Read, do not take. The activation can still end without reaching
        // `Enabled`, and the snapshot has to survive that for the next one.
        let snapshot = self.tester_present_snapshot.lock().await.clone();
        if snapshot.is_empty() {
            return;
        }

        self.abort_pending_snapshot_restart().await;

        let uds = self.clone();
        let task = cda_interfaces::spawn_named!("tester-present-snapshot-restart", async move {
            // Deliberately not `require_communication_ready`: that requests an
            // activation, and this restart belongs to one that is already in
            // flight. Wait for that one to publish `Enabled` instead, then let
            // the normal send path acquire its own guard for every message.
            let guard = loop {
                match uds.communication_access.acquire() {
                    Ok(guard) => break guard,
                    // The activation this restart belongs to is still running.
                    Err(CommunicationError::Enabling) => {
                        cda_interfaces::util::tokio_ext::sleep_for(SNAPSHOT_RESTART_POLL_INTERVAL)
                            .await;
                    }
                    // Any other state means it ended without reaching
                    // `Enabled`. Leave the snapshot in place so the next
                    // `initialize` can restore it.
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

            let mut started = Vec::with_capacity(snapshot.len());
            for type_ in snapshot {
                if started.contains(&type_) {
                    continue;
                }
                started.push(type_.clone());
                if let Err(e) = uds.start_tester_present_tasks(type_.clone()).await {
                    tracing::warn!(
                        ?type_,
                        error = %e,
                        "Failed to restart tester present after communication re-enable"
                    );
                }
            }
            drop(guard);

            // Restored. The running tasks are the record of what is active from
            // here on, and `snapshot_and_abort_tester_present` recaptures them
            // from there.
            uds.tester_present_snapshot.lock().await.clear();
        });
        *self.tester_present_restart_task.lock().await = Some(task);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex as StdMutex};

    use cda_interfaces::{
        DiagServiceError, EcuAddresses, FunctionalTransport, HashMap, HashMapExtensions,
        NetworkTopology, PhysicalTransport, ServicePayload, TesterPresentType,
        TransmissionParameters, TransportResponse, UDS_ID_RESPONSE_BITMASK, datatypes::FaultConfig,
        service_ids,
    };
    use cda_plugin_communication_management::lifecycle::enabled_communication_access_for_test;
    use tokio::sync::{RwLock, mpsc};

    use super::*;
    use crate::{test_helpers::TestEcuDb, types::TesterPresentTaskId};

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

    type CapturedSends = Arc<StdMutex<Vec<(Vec<u8>, bool)>>>;

    #[derive(Clone, Default)]
    struct CaptureGateway {
        sends: CapturedSends,
    }

    impl PhysicalTransport for CaptureGateway {
        fn send(
            &self,
            _transmission_params: TransmissionParameters,
            message: ServicePayload,
            response_sender: mpsc::Sender<Result<Option<TransportResponse>, DiagServiceError>>,
            expect_uds_reply: bool,
        ) -> impl Future<Output = Result<tokio::task::JoinHandle<()>, DiagServiceError>> + Send
        {
            let sends = Arc::clone(&self.sends);
            async move {
                sends
                    .lock()
                    .unwrap()
                    .push((message.data.clone(), expect_uds_reply));

                let response = if expect_uds_reply {
                    let subfunction = message.data.get(1).copied().unwrap_or_default();
                    Some(TransportResponse::UdsResponse(ServicePayload {
                        data: vec![
                            service_ids::TESTER_PRESENT | UDS_ID_RESPONSE_BITMASK,
                            subfunction & !SUPPRESS_POSITIVE_RESPONSE_BIT,
                        ],
                        source_address: message.target_address,
                        target_address: message.source_address,
                        new_session: None,
                        new_security: None,
                    }))
                } else {
                    None
                };
                response_sender.try_send(Ok(response)).unwrap();
                Ok(tokio::task::spawn(std::future::ready(())))
            }
        }

        fn ecu_online<T: EcuAddresses>(
            &self,
            _ecu_name: &str,
            _ecu_db: &RwLock<T>,
        ) -> impl Future<Output = Result<(), DiagServiceError>> + Send {
            std::future::ready(Ok(()))
        }
    }

    impl FunctionalTransport for CaptureGateway {
        fn send_functional(
            &self,
            _transmission_params: TransmissionParameters,
            _message: ServicePayload,
            _expected_ecu_logical_addrs: HashMap<u16, String>,
            _timeout: std::time::Duration,
            _expect_positive_response: bool,
        ) -> impl Future<
            Output = Result<
                HashMap<String, Result<ServicePayload, DiagServiceError>>,
                DiagServiceError,
            >,
        > + Send {
            std::future::ready(Ok(HashMap::new()))
        }
    }

    impl NetworkTopology for CaptureGateway {
        fn get_gateway_network_address(
            &self,
            _logical_address: u16,
        ) -> impl Future<Output = Option<String>> + Send {
            std::future::ready(None)
        }
    }

    #[async_trait::async_trait]
    impl cda_interfaces::Shutdown for CaptureGateway {
        async fn shutdown(&self) {}
    }

    fn make_manager(
        gateway: CaptureGateway,
        ecu: TestEcuDb,
    ) -> UdsManager<CaptureGateway, TestEcuDb> {
        let ecus = Arc::new(HashMap::from_iter([(
            "TestECU".to_string(),
            RwLock::new(ecu),
        )]));
        UdsManager::new_for_raw_payload_tests(
            gateway,
            ecus,
            FaultConfig::default(),
            enabled_communication_access_for_test(),
        )
    }

    fn tester_present_control() -> TesterPresentControlMessage {
        TesterPresentControlMessage {
            mode: TesterPresentMode::Start,
            type_: TesterPresentType::Ecu("TestECU".to_string()),
            ecu: "TestECU".to_string(),
            interval: None,
        }
    }

    #[tokio::test]
    async fn tester_present_uses_configured_message_when_response_is_expected() {
        let gateway = CaptureGateway::default();
        let manager = make_manager(
            gateway.clone(),
            TestEcuDb::with_tester_present_config(vec![0x3E, 0x00], true),
        );

        manager
            .send_tester_present(&tester_present_control())
            .await
            .unwrap();

        assert_eq!(
            *gateway.sends.lock().unwrap(),
            vec![(vec![0x3E, 0x00], true)]
        );
    }

    #[tokio::test]
    async fn tester_present_sets_suppress_bit_when_response_is_not_expected() {
        let gateway = CaptureGateway::default();
        let manager = make_manager(
            gateway.clone(),
            TestEcuDb::with_tester_present_config(vec![0x3E, 0x00], false),
        );

        manager
            .send_tester_present(&tester_present_control())
            .await
            .unwrap();

        assert_eq!(
            *gateway.sends.lock().unwrap(),
            vec![(vec![0x3E, 0x80], false)]
        );
    }
}
