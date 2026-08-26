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
    ServicePayload, TesterPresentControlMessage, TesterPresentMode, TesterPresentType, UdsEcuDb,
    UdsFunctionalGroup, UdsTesterPresent, VariantDetection, dlt_ctx,
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

        let subfunction = data.get_mut(1).ok_or_else(|| {
            DiagServiceError::BadPayload(
                "Configured tester present message must contain a subfunction byte".to_owned(),
            )
        })?;
        if expect_response {
            *subfunction &= !SUPPRESS_POSITIVE_RESPONSE_BIT;
        } else {
            *subfunction |= SUPPRESS_POSITIVE_RESPONSE_BIT;
        }

        let payload = ServicePayload {
            data,
            source_address,
            target_address,
            new_session: None,
            new_security: None,
        };

        match self
            .send_with_raw_payload(&control_msg.ecu, payload, None, expect_response)
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

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex as StdMutex, atomic::AtomicBool};

    use cda_interfaces::{
        DiagServiceError, EcuAddresses, EcuRuntimeState, FunctionalTransport, HashMap,
        HashMapExtensions, NetworkTopology, PhysicalTransport, ServicePayload,
        TransmissionParameters, TransportResponse, UDS_ID_RESPONSE_BITMASK, datatypes::FaultConfig,
        service_ids,
    };
    use tokio::sync::{RwLock, mpsc};

    use super::*;
    use crate::{EcuStateCoordinator, test_helpers::TestEcuDb};

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
        let runtime_states = HashMap::from_iter([("TestECU".to_string(), EcuRuntimeState::new())]);
        let (redetect_tx, _redetect_rx) = mpsc::channel(1);

        UdsManager {
            ecus,
            gateway,
            data_transfers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            ecu_semaphores: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            tester_present_tasks: Arc::new(RwLock::new(HashMap::new())),
            session_reset_tasks: Arc::new(RwLock::new(HashMap::new())),
            security_reset_tasks: Arc::new(RwLock::new(HashMap::new())),
            state_coordinator: EcuStateCoordinator::new(runtime_states, redetect_tx),
            functional_description_database: String::new(),
            fault_config: FaultConfig::default(),
            update_in_progress: Arc::new(AtomicBool::new(false)),
        }
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
