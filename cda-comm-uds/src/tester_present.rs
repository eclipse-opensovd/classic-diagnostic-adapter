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
    DiagServiceError, EcuGateway, EcuManager, HashMap, HashSet, SUPPRESS_POSITIVE_RESPONSE_BIT,
    ServicePayload, TesterPresentControlMessage, TesterPresentMode, TesterPresentType, UdsEcuDb,
    UdsFunctionalGroup, UdsTesterPresent, VariantDetection, dlt_ctx, service_ids, util::tokio_ext,
};
use tokio::{
    task::JoinHandle,
    time::{MissedTickBehavior, interval as tokio_interval},
};

use crate::{UdsManager, transport::CommunicationReadiness, types::TesterPresentTaskId};

/// State of a tester-present map entry (keyed by `(type, ecu)` via
/// [`TesterPresentTaskId`]).
///
/// An entry exists for as long as some lock still wants tester present for that `(type, ecu)`,
/// regardless whether communication is currently enabled. Only
/// [`UdsTesterPresent::stop_tester_present`] removes an entry; suspending and
/// resuming only ever change its state.
pub(crate) enum TesterPresentTask {
    /// The task is actively sending tester present.
    Running(JoinHandle<()>),
    /// Communication is disabled; the task is not running, but the entry is
    /// kept so it can be resumed once communication is enabled again.
    Suspended,
}

impl TesterPresentTask {
    /// Returns the handle if this entry is [`Self::Running`].
    pub(crate) fn into_running(self) -> Option<JoinHandle<()>> {
        match self {
            Self::Running(handle) => Some(handle),
            Self::Suspended => None,
        }
    }
}

fn all_active(
    tester_presents: &HashMap<TesterPresentTaskId, TesterPresentTask>,
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

/// Distinguishes the two ways [`UdsManager::activate_tester_present`] is
/// reached.
enum ActivateMode {
    /// A fresh [`UdsTesterPresent::start_tester_present`] call. ECUs are
    /// resolved from the current functional-group membership; missing or
    /// `Suspended` entries are spawned, `Running` entries are left alone.
    Start,
    /// The resume run from [`CommunicationLifecycle::on_enabled`]
    /// (`cda_interfaces::communication_control::CommunicationLifecycle`), once
    /// communication is enabled again. Only entries that are still `Suspended`
    /// for `type_` are spawned; nothing is inserted that was not already in
    /// the map.
    Resume,
}

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
                        if !ecu_state.is_online() {
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

    /// Resolves the ECUs that a tester-present type currently addresses.
    async fn ecus_for_tester_present_type(&self, type_: &TesterPresentType) -> Vec<String> {
        match type_ {
            TesterPresentType::Ecu(ecu_name) => vec![ecu_name.clone()],
            TesterPresentType::Functional(functional_group) => {
                self.ecus_for_functional_group(functional_group, true).await
            }
        }
    }

    /// Resolves and spawns or resumes tasks for `type_`, used by both
    /// [`UdsTesterPresent::start_tester_present`] and the resume run from
    /// `on_enabled` after communication is re-enabled. The two modes only
    /// differ in which ECUs are considered and in how a zero tester-present
    /// interval is handled; the resolution, spawning and map update are
    /// shared.
    async fn activate_tester_present(
        &self,
        type_: TesterPresentType,
        mode: ActivateMode,
    ) -> Result<(), DiagServiceError> {
        let ecu_names = match mode {
            ActivateMode::Start => self.ecus_for_tester_present_type(&type_).await,
            ActivateMode::Resume => {
                let tester_presents = self.tester_present_tasks.read().await;
                tester_presents
                    .iter()
                    .filter(|(id, task)| {
                        id.type_ == type_ && matches!(task, TesterPresentTask::Suspended)
                    })
                    .map(|(id, _)| id.ecu.clone())
                    .collect()
            }
        };

        let mut resolved = Vec::with_capacity(ecu_names.len());
        for ecu in ecu_names {
            let interval = self.uds_ecu_db(&ecu)?.read().await.tester_present_time();
            if interval.is_zero() {
                // Can only happen in 'start' as a 'resume' should never see the 'zero'
                // interval, as it was rejected in 'start'
                return Err(DiagServiceError::InvalidConfiguration(format!(
                    "Tester present interval for ECU {ecu} must be greater than zero"
                )));
            }
            resolved.push((ecu, interval));
        }

        let mut tester_presents = self.tester_present_tasks.write().await;
        for (ecu, interval) in resolved {
            let key = TesterPresentTaskId {
                type_: type_.clone(),
                ecu: ecu.clone(),
            };
            match (tester_presents.get(&key), interval) {
                // Already sending: a start is idempotent, and a concurrent
                // start already resumed it.
                (Some(TesterPresentTask::Running(_)), _) => {}
                // Removed by `stop_tester_present` since the candidates were
                // read, e.g. a lock released while communication was disabled
                // or enabling: the release wins over the resume.
                (None, _) if matches!(mode, ActivateMode::Resume) => {}
                // A start of a missing or suspended entry, or a resume of a
                // suspended one.
                (_, interval) => {
                    let control_msg = TesterPresentControlMessage {
                        mode: TesterPresentMode::Start,
                        type_: type_.clone(),
                        ecu,
                        interval: Some(interval),
                    };
                    let handle = self.spawn_tester_present_task(control_msg, interval);
                    tester_presents.insert(key, TesterPresentTask::Running(handle));
                }
            }
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
        self.activate_tester_present(type_, ActivateMode::Start)
            .await
    }

    #[tracing::instrument(skip_all,
        fields(dlt_context = dlt_ctx!("UDS"))
    )]
    async fn stop_tester_present(&self, type_: TesterPresentType) -> Result<(), DiagServiceError> {
        let mut tester_presents = self.tester_present_tasks.write().await;
        let keys: Vec<TesterPresentTaskId> = tester_presents
            .keys()
            .filter(|id| id.type_ == type_)
            .cloned()
            .collect();
        for key in keys {
            if let Some(TesterPresentTask::Running(handle)) = tester_presents.remove(&key) {
                tokio_ext::abort_and_join(handle, "tester present").await;
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
    /// Suspends all running tester-present tasks: aborts their handles and
    /// turns their map entries into [`TesterPresentTask::Suspended`].
    ///
    /// Entries are never removed here; only [`UdsTesterPresent::stop_tester_present`]
    /// removes an entry. This is what makes a lock released while
    /// communication is disabled take effect immediately instead of being
    /// silently restored on the next resume.
    pub(crate) async fn suspend_tester_present(&self) {
        let mut tasks = self.tester_present_tasks.write().await;
        let ids: Vec<TesterPresentTaskId> = tasks.keys().cloned().collect();
        let mut handles = Vec::new();
        for id in ids {
            if let Some(TesterPresentTask::Running(handle)) =
                tasks.insert(id, TesterPresentTask::Suspended)
            {
                handles.push(handle);
            }
        }
        drop(tasks);

        if !handles.is_empty() {
            tracing::debug!(
                count = handles.len(),
                "Communication disabling; suspending tester-present tasks"
            );
        }
        for handle in handles {
            tokio_ext::abort_and_join(handle, "tester present").await;
        }
    }

    /// Resumes the tester-present entries suspended by
    /// [`UdsManager::suspend_tester_present`].
    ///
    /// Called from [`CommunicationLifecycle::on_enabled`]
    /// (`cda_interfaces::communication_control::CommunicationLifecycle`), which
    /// the framework guarantees only runs once the lifecycle state has
    /// actually been published as `Enabled`, so [`acquire`] below is expected
    /// to succeed. It can still fail, e.g. if a disable raced in and claimed
    /// the state before this runs; in that case the suspended entries are left
    /// untouched for the next activation to resume.
    ///
    /// [`UdsManager::tester_present_tasks`] is read under lock after the guard
    /// has been acquired, so a [`UdsTesterPresent::stop_tester_present`] call
    /// that happened in between is reflected here.
    ///
    /// [`acquire`]: cda_interfaces::communication_control::CommunicationAccess::acquire
    pub(crate) async fn resume_tester_present(&self) {
        let guard = match self.communication_access.acquire() {
            Ok(guard) => guard,
            Err(e) => {
                tracing::debug!(
                    error = %e,
                    "Communication not acquirable on_enabled; keeping suspended tester-present \
                     entries for the next activation"
                );
                return;
            }
        };

        let pending_types: HashSet<TesterPresentType> = self
            .tester_present_tasks
            .read()
            .await
            .iter()
            .filter(|(_, task)| matches!(task, TesterPresentTask::Suspended))
            .map(|(id, _)| id.type_.clone())
            .collect();

        for type_ in pending_types {
            if let Err(e) = self
                .activate_tester_present(type_.clone(), ActivateMode::Resume)
                .await
            {
                tracing::warn!(
                    ?type_,
                    error = %e,
                    "Failed to resume tester present after communication re-enable"
                );
            }
        }
        drop(guard);
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

    fn running() -> TesterPresentTask {
        TesterPresentTask::Running(tokio::spawn(std::future::pending()))
    }

    #[tokio::test]
    async fn existing_exact_key_is_idempotent() {
        let type_ = TesterPresentType::Ecu("ecu".to_owned());
        let key = TesterPresentTaskId {
            type_: type_.clone(),
            ecu: "ecu".to_owned(),
        };
        let mut tasks: HashMap<TesterPresentTaskId, TesterPresentTask> = HashMap::new();
        tasks.insert(key.clone(), running());
        let original_id = match tasks.get(&key).expect("task exists") {
            TesterPresentTask::Running(handle) => handle.id(),
            TesterPresentTask::Suspended => panic!("expected a running task"),
        };

        if !tasks.contains_key(&key) {
            tasks.insert(key.clone(), running());
        }

        let existing = tasks.remove(&key).expect("task remains");
        match existing {
            TesterPresentTask::Running(handle) => {
                assert_eq!(handle.id(), original_id);
                handle.abort();
            }
            TesterPresentTask::Suspended => panic!("expected a running task"),
        }
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
        tasks.insert(ecu_key.clone(), running());
        tasks.insert(functional_key.clone(), running());

        if let Some(TesterPresentTask::Running(handle)) = tasks.remove(&ecu_key) {
            handle.abort();
        } else {
            panic!("ECU task exists");
        }

        assert!(!tasks.contains_key(&ecu_key));
        assert!(tasks.contains_key(&functional_key));
        if let Some(TesterPresentTask::Running(handle)) = tasks.remove(&functional_key) {
            handle.abort();
        } else {
            panic!("functional task exists");
        }
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
        tasks.insert(first_key.clone(), running());

        assert!(!all_active(&tasks, &type_, &ecu_names));

        tasks.insert(second_key.clone(), running());
        assert!(all_active(&tasks, &type_, &ecu_names));

        if let Some(TesterPresentTask::Running(handle)) = tasks.remove(&first_key) {
            handle.abort();
        } else {
            panic!("first task exists");
        }
        if let Some(TesterPresentTask::Running(handle)) = tasks.remove(&second_key) {
            handle.abort();
        } else {
            panic!("second task exists");
        }
    }

    #[tokio::test]
    async fn suspended_entry_counts_as_active() {
        let type_ = TesterPresentType::Ecu("ecu".to_owned());
        let key = TesterPresentTaskId {
            type_: type_.clone(),
            ecu: "ecu".to_owned(),
        };
        let mut tasks: HashMap<TesterPresentTaskId, TesterPresentTask> = HashMap::new();
        tasks.insert(key.clone(), TesterPresentTask::Suspended);

        assert!(all_active(&tasks, &type_, &["ecu".to_owned()]));
        assert!(tasks.contains_key(&key));
    }

    #[tokio::test]
    async fn removing_absent_key_is_harmless() {
        let key = TesterPresentTaskId {
            type_: TesterPresentType::Ecu("ecu".to_owned()),
            ecu: "ecu".to_owned(),
        };
        let mut tasks: HashMap<TesterPresentTaskId, TesterPresentTask> = HashMap::new();

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
