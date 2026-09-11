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

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use cda_interfaces::{
    DiagComm, DiagServiceError, DynamicPlugin, EcuGateway, EcuManager, HashMap, HashMapExtensions,
    PayloadDecoder, ServicePayload, TransmissionParameters, UdsFunctionalGroup, UdsTransport,
    datatypes::{ComponentDataInfo, ComponentOperationsInfo, RoutineSubfunctions},
    diagservices::{DiagServiceResponse, DiagServiceResponseType, UdsPayloadData},
    dlt_ctx,
};
use tokio::sync::Mutex;

use crate::{
    UdsEcuDb, UdsManager,
    types::{PerGatewayInfo, ResetType},
};

struct PendingEcuInfo {
    ecu_name: String,
    request_lock_key: String,
}

impl<S: EcuGateway, T: UdsEcuDb + PayloadDecoder> UdsManager<S, T> {
    /// Send a functional request to a single gateway and collect responses from all expected ECUs
    #[allow(
        clippy::too_many_arguments,
        reason = "Combining parameters into a struct is not preferred here, to keep call \
                  semantics consistent across all send functions"
    )]
    async fn send_functional_to_gateway(
        &self,
        transmission_params: TransmissionParameters,
        expected_ecus: HashMap<u16, String>,
        service: DiagComm,
        payload: ServicePayload,
        map_to_json: bool,
        timeout: Duration,
        functional_group_name: &str,
        request_lock_keys: Vec<String>,
    ) -> HashMap<String, Result<<T as PayloadDecoder>::Response, DiagServiceError>> {
        // Inspect the subfunction byte for `suppressPosRspMsgIndicationBit` (bit 7).
        // When set, ECUs are not expected to send a positive response.
        let expect_positive_response = !payload.is_suppress_positive_response();

        let _ecu_permits = match self.request_ecu_permits(request_lock_keys).await {
            Ok(permits) => permits,
            Err(error) => {
                tracing::error!(%error, "Failed waiting for functional ECU permits");
                return expected_ecus
                    .into_values()
                    .map(|ecu_name| (ecu_name, Err(error.clone())))
                    .collect();
            }
        };

        // Send functional request via gateway
        match self
            .gateway
            .send_functional(
                transmission_params,
                payload,
                expected_ecus.clone(),
                timeout,
                expect_positive_response,
            )
            .await
        {
            Ok(uds_responses) => {
                let mut result_map = HashMap::new();

                let Some(fgl_ecu) = self.ecus.get(&self.functional_description_database) else {
                    tracing::error!(
                        "Functional description database ECU not found: {}",
                        self.functional_description_database
                    );
                    return HashMap::new();
                };
                for (ecu_name, uds_result) in uds_responses {
                    match uds_result {
                        Ok(msg) => {
                            // Process the response using the ECU's convert_from_uds
                            let ecu_read = fgl_ecu.read().await;
                            let response = ecu_read
                                .convert_from_uds(
                                    &service,
                                    &msg,
                                    map_to_json,
                                    Some(functional_group_name),
                                )
                                .await;
                            result_map.insert(ecu_name, response);
                        }
                        Err(e) => {
                            result_map.insert(ecu_name, Err(e));
                        }
                    }
                }

                result_map
            }
            Err(e) => {
                // Gateway-level error - return error for all ECUs
                let mut result_map = HashMap::new();
                for (_, ecu_name) in expected_ecus {
                    result_map.insert(ecu_name, Err(e.clone()));
                }
                result_map
            }
        }
    }
}

#[async_trait]
impl<S: EcuGateway, T: EcuManager> UdsFunctionalGroup for UdsManager<S, T> {
    async fn get_functional_group_data_info(
        &self,
        security_plugin: &DynamicPlugin,
        functional_group_name: &str,
    ) -> Result<Vec<ComponentDataInfo>, DiagServiceError> {
        self.uds_ecu_db(&self.functional_description_database)?
            .read()
            .await
            .get_functional_group_data_info(security_plugin, functional_group_name)
    }

    async fn get_functional_group_operations_info(
        &self,
        security_plugin: &DynamicPlugin,
        functional_group_name: &str,
    ) -> Result<Vec<ComponentOperationsInfo>, DiagServiceError> {
        self.uds_ecu_db(&self.functional_description_database)?
            .read()
            .await
            .get_functional_group_operations_info(security_plugin, functional_group_name)
    }

    async fn get_functional_group_routine_subfunctions(
        &self,
        security_plugin: &DynamicPlugin,
        functional_group_name: &str,
        service_name: &str,
    ) -> Result<RoutineSubfunctions, DiagServiceError> {
        self.uds_ecu_db(&self.functional_description_database)?
            .read()
            .await
            .get_functional_group_routine_subfunctions(
                security_plugin,
                functional_group_name,
                service_name,
            )
    }

    async fn ecu_functional_groups(&self, ecu_name: &str) -> Result<Vec<String>, DiagServiceError> {
        let groups = self.uds_ecu_db(ecu_name)?.read().await.functional_groups();
        Ok(groups)
    }

    async fn ecus_for_functional_group(
        &self,
        functional_group: &str,
        gateway_only: bool,
    ) -> Vec<String> {
        let mut ecu_names = Vec::new();
        for (name, ecu) in self.ecus.iter() {
            let ecu_guard = ecu.read().await;
            if gateway_only && ecu_guard.logical_address() != ecu_guard.logical_gateway_address() {
                continue; // skip non gateway ECUs
            }
            if !ecu_guard.is_physical_ecu() {
                continue; // skip functional description database
            }
            if !ecu_guard
                .functional_groups()
                .contains(&functional_group.to_owned())
            {
                continue; // skip ECUs not in the functional group
            }
            ecu_names.push(name.clone());
        }
        ecu_names
    }

    #[tracing::instrument(skip(self, security_plugin, payload),
        fields(dlt_context = dlt_ctx!("UDS"))
    )]
    async fn send_functional_group(
        &self,
        functional_group: &str,
        service: DiagComm,
        security_plugin: &DynamicPlugin,
        payload: Option<UdsPayloadData>,
        map_to_json: bool,
    ) -> HashMap<String, Result<Self::Response, DiagServiceError>> {
        let ecu_list = self
            .ecus_for_functional_group(functional_group, false)
            .await;

        if ecu_list.is_empty() {
            tracing::warn!(
                functional_group = %functional_group,
                "No ECUs found in functional group"
            );
            return HashMap::new();
        }

        let _guard = match self.require_communication_ready() {
            Ok(guard) => guard,
            Err(error) => {
                let mut result_map = HashMap::new();
                for ecu_name in ecu_list {
                    result_map.insert(ecu_name, Err(error.clone()));
                }
                return result_map;
            }
        };

        let Some(globals_ecu) = self.ecus.get(&self.functional_description_database) else {
            tracing::warn!(
                functional_group = %functional_group,
                description_database = %self.functional_description_database,
                "Functional description database not found for functional group request"
            );
            return HashMap::new();
        };

        // Create service payload with functional address
        let service_payload = {
            let ecu_read = globals_ecu.read().await;
            match ecu_read
                .create_uds_payload(&service, security_plugin, payload, Some(functional_group))
                .await
            {
                Ok(p) => p,
                Err(e) => {
                    // If payload creation fails, return error for all ECUs
                    let mut result_map = HashMap::new();
                    for ecu_name in ecu_list {
                        result_map.insert(ecu_name, Err(e.clone()));
                    }
                    return result_map;
                }
            }
        };

        let result_map: Arc<
            Mutex<HashMap<String, Result<<T as PayloadDecoder>::Response, DiagServiceError>>>,
        > = Arc::new(Mutex::new(HashMap::new()));

        // Group ECUs by their gateway address
        let mut ecus_by_gateway: HashMap<u16, PerGatewayInfo> = HashMap::new();
        let mut ecu_infos_by_gateway = HashMap::<u16, HashMap<u16, PendingEcuInfo>>::new();

        for ecu_name in &ecu_list {
            if let Some(ecu) = self.ecus.get(ecu_name) {
                let ecu_lock = ecu.read().await;
                if !ecu_lock.is_physical_ecu() {
                    continue;
                }

                let ecu_status = ecu_lock.ecu_status();
                if !ecu_status.is_online_and_detected() {
                    tracing::debug!(
                        ecu = %ecu_name,
                        connectivity = ?ecu_status.connectivity,
                        variant_state = ?ecu_status.variant_state,
                        "Skipping ECU that is not online"
                    );
                    continue;
                }
                let tester_addr = ecu_lock.tester_address();
                let gateway_addr = ecu_lock.logical_gateway_address();
                let logical_addr = ecu_lock.logical_address();
                let func_addr = ecu_lock.logical_functional_address();
                let request_lock_key = ecu_lock.request_lock_key();
                drop(ecu_lock);
                if gateway_addr == logical_addr {
                    let (uds_params, transmission_params) = Self::ecu_send_params(ecu).await;
                    if let Some(_old) = ecus_by_gateway.insert(
                        gateway_addr,
                        PerGatewayInfo {
                            uds_params,
                            transmission_params,
                            source_address: tester_addr,
                            functional_address: func_addr,
                            ecus: HashMap::from_iter([(logical_addr, ecu_name.clone())]),
                            request_lock_keys: vec![request_lock_key],
                        },
                    ) {
                        tracing::error!(
                            ecu_name = %ecu_name,
                            functional_group = %functional_group,
                            gateway_addr = %gateway_addr,
                            "Multiple Online Gateway ecus detected for functional group request. \
                            Only using the first one."
                        );
                        result_map.lock().await.insert(
                            ecu_name.clone(),
                            Err(DiagServiceError::ResourceError(format!(
                                "ECU {ecu_name} is online, but another ECU with the same logical \
                                 address exists and is online."
                            ))),
                        );
                    }
                } else {
                    ecu_infos_by_gateway
                        .entry(gateway_addr)
                        .or_default()
                        .insert(
                            logical_addr,
                            PendingEcuInfo {
                                ecu_name: ecu_name.clone(),
                                request_lock_key,
                            },
                        );
                }
            }
        }

        for (gateway_addr, ecu_info_list) in ecu_infos_by_gateway {
            if let Some(gateway_info) = ecus_by_gateway.get_mut(&gateway_addr) {
                for (logical_addr, ecu_info) in ecu_info_list {
                    gateway_info.ecus.insert(logical_addr, ecu_info.ecu_name);
                    gateway_info
                        .request_lock_keys
                        .push(ecu_info.request_lock_key);
                }
            } else {
                tracing::warn!(
                    functional_group = %functional_group,
                    gateway_addr = %gateway_addr,
                    "No gateway ECU found for functional group request."
                );
            }
        }

        tracing::debug!(
            functional_group = %functional_group,
            gateway_count = ecus_by_gateway.len(),
            total_ecus = ecu_list.len(),
            "Sending functional request to gateways"
        );

        let mut futures = Vec::new();
        for gw_infos in ecus_by_gateway.into_values() {
            let service = service.clone();
            let mut service_payload = service_payload.clone();
            service_payload.source_address = gw_infos.source_address;
            service_payload.target_address = gw_infos.functional_address;
            let result_map = Arc::clone(&result_map);
            let manager = self.clone();
            let fg_name = functional_group.to_owned();
            let fut = async move {
                let gateway_results = manager
                    .send_functional_to_gateway(
                        gw_infos.transmission_params,
                        gw_infos.ecus,
                        service,
                        service_payload,
                        map_to_json,
                        gw_infos.uds_params.timeout_default,
                        &fg_name,
                        gw_infos.request_lock_keys,
                    )
                    .await;

                result_map.lock().await.extend(gateway_results);
            };
            futures.push(fut);
        }

        futures::future::join_all(futures).await;

        let lock = result_map.lock().await;
        let result_map = lock.clone();
        drop(lock);
        result_map
    }

    async fn set_ecu_state(
        &self,
        ecu_name: &str,
        security_plugin: &DynamicPlugin,
        sid: u8,
        service_name: &str,
        params: Option<HashMap<String, serde_json::Value>>,
        map_to_json: bool,
    ) -> Result<Self::Response, DiagServiceError> {
        let ecu = self.uds_ecu_variant_detection_concluded(ecu_name).await?;
        let service = ecu
            .read()
            .await
            .lookup_service_by_sid_and_name(sid, service_name, None)?;

        let response = self
            .send(
                ecu_name,
                service.clone(),
                security_plugin,
                params.map(UdsPayloadData::ParameterMap),
                map_to_json,
            )
            .await;

        if let Ok(response) = response.as_ref()
            && response.response_type() == DiagServiceResponseType::Positive
        {
            ecu.write()
                .await
                .set_service_state(sid, service_name.to_owned())
                .await;
        }

        response
    }

    async fn set_functional_state(
        &self,
        group_name: &str,
        security_plugin: &DynamicPlugin,
        sid: u8,
        service_name: &str,
        params: Option<HashMap<String, serde_json::Value>>,
        mode_expiration: Option<Duration>,
        map_to_json: bool,
    ) -> Result<HashMap<String, Result<Self::Response, DiagServiceError>>, DiagServiceError> {
        let func_group = self.uds_ecu_db(&self.functional_description_database)?;
        let service = func_group.read().await.lookup_service_by_sid_and_name(
            sid,
            service_name,
            Some(group_name),
        )?;

        let response = self
            .send_functional_group(
                group_name,
                service,
                security_plugin,
                params.map(UdsPayloadData::ParameterMap),
                map_to_json,
            )
            .await;

        for (ecu, response) in &response {
            if let Ok(response) = response
                && response.response_type() == DiagServiceResponseType::Positive
                && let Some(ecu_manager) = self.ecus.get(ecu)
            {
                ecu_manager
                    .write()
                    .await
                    .set_service_state(sid, service_name.to_owned())
                    .await;
                if let Some(ref expiration) = mode_expiration {
                    self.start_reset_task(ecu, Some(*expiration), ResetType::Session)
                        .await;
                }
            }
        }

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use cda_interfaces::{
        DiagCommType, DiagServiceError, EcuAddresses, EcuRuntimeState, FunctionalTransport,
        HashMap, HashMapExtensions, NetworkTopology, PhysicalTransport, ServicePayload,
        TransmissionParameters, TransportResponse, VariantDetectionSender,
        communication_control::CommunicationAccess,
        datatypes::{DtcField, DtcRecord, FaultConfig},
        diagservices::{DiagServiceJsonResponse, DiagServiceResponse, DiagServiceResponseType},
    };
    use cda_plugin_communication_management::lifecycle::enabled_communication_access_for_test;
    use tokio::sync::{Mutex, RwLock, Semaphore, mpsc};

    use super::*;
    use crate::{state_coordinator::EcuStateCoordinator, test_helpers::TestEcuDb};

    const GATEWAY_KEY: &str = "a-gateway";
    const CHILD_KEY: &str = "z-child";

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct TestResponse;

    impl DiagServiceResponse for TestResponse {
        fn empty_positive(_service: DiagComm) -> Self {
            Self
        }

        fn is_empty(&self) -> bool {
            true
        }

        fn service_name(&self) -> String {
            String::new()
        }

        fn response_type(&self) -> DiagServiceResponseType {
            DiagServiceResponseType::Positive
        }

        fn get_raw(&self) -> &[u8] {
            &[]
        }

        fn into_json(self) -> Result<DiagServiceJsonResponse, DiagServiceError> {
            unimplemented!()
        }

        fn as_nrc(&self) -> Result<cda_interfaces::diagservices::MappedNRC, DiagServiceError> {
            unimplemented!()
        }

        fn get_dtcs(&self) -> Result<Vec<(DtcField, DtcRecord)>, DiagServiceError> {
            unimplemented!()
        }
    }

    impl PayloadDecoder for TestEcuDb {
        type Response = TestResponse;

        fn convert_from_uds(
            &self,
            _diag_service: &DiagComm,
            _payload: &ServicePayload,
            _map_to_json: bool,
            _functional_group_name: Option<&str>,
        ) -> impl Future<Output = Result<Self::Response, DiagServiceError>> + Send {
            std::future::ready(Ok(TestResponse))
        }

        fn convert_request_from_uds(
            &self,
            _diag_service: &DiagComm,
            _payload: &ServicePayload,
            _map_to_json: bool,
        ) -> impl Future<Output = Result<Self::Response, DiagServiceError>> + Send {
            std::future::ready(Ok(TestResponse))
        }

        fn convert_service_14_response(
            _diag_comm: DiagComm,
            _response: ServicePayload,
        ) -> Result<Self::Response, DiagServiceError> {
            Ok(TestResponse)
        }
    }

    #[derive(Clone)]
    struct RecordingGateway {
        functional_sends: Arc<AtomicUsize>,
    }

    impl PhysicalTransport for RecordingGateway {
        async fn send(
            &self,
            _transmission_params: TransmissionParameters,
            _message: ServicePayload,
            _response_sender: mpsc::Sender<Result<Option<TransportResponse>, DiagServiceError>>,
            _expect_uds_reply: bool,
        ) -> Result<tokio::task::JoinHandle<()>, DiagServiceError> {
            unimplemented!()
        }

        fn ecu_online<T: EcuAddresses>(
            &self,
            _ecu_name: &str,
            _ecu_db: &RwLock<T>,
        ) -> impl Future<Output = Result<(), DiagServiceError>> + Send {
            std::future::ready(Ok(()))
        }
    }

    impl FunctionalTransport for RecordingGateway {
        fn send_functional(
            &self,
            _transmission_params: TransmissionParameters,
            _message: ServicePayload,
            _expected_ecu_logical_addrs: HashMap<u16, String>,
            _timeout: Duration,
            _expect_positive_response: bool,
        ) -> impl Future<
            Output = Result<
                HashMap<String, Result<ServicePayload, DiagServiceError>>,
                DiagServiceError,
            >,
        > + Send {
            self.functional_sends.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(HashMap::new()))
        }
    }

    impl NetworkTopology for RecordingGateway {
        fn get_gateway_network_address(
            &self,
            _logical_address: u16,
        ) -> impl Future<Output = Option<String>> + Send {
            std::future::ready(None)
        }
    }

    #[async_trait]
    impl cda_interfaces::Shutdown for RecordingGateway {
        async fn shutdown(&self) {}
    }

    fn manager() -> UdsManager<RecordingGateway, TestEcuDb> {
        let ecus = Arc::new(HashMap::from_iter([(
            "functional".to_owned(),
            RwLock::new(TestEcuDb::new()),
        )]));
        let (redetect_tx, _redetect_rx) = mpsc::channel(1);
        UdsManager {
            ecus,
            gateway: RecordingGateway {
                functional_sends: Arc::new(AtomicUsize::new(0)),
            },
            data_transfers: Arc::new(Mutex::new(HashMap::new())),
            ecu_semaphores: Arc::new(Mutex::new(HashMap::new())),
            tester_present_tasks: Arc::new(RwLock::new(HashMap::new())),
            session_reset_tasks: Arc::new(RwLock::new(HashMap::new())),
            security_reset_tasks: Arc::new(RwLock::new(HashMap::new())),
            state_coordinator: EcuStateCoordinator::new(
                HashMap::<String, EcuRuntimeState>::new(),
                VariantDetectionSender::new(redetect_tx),
            ),
            functional_description_database: "functional".to_owned(),
            fault_config: FaultConfig::default(),
            communication_access: enabled_communication_access_for_test()
                as Arc<dyn CommunicationAccess>,
            communication_retry_after: Duration::from_secs(1),
            variant_detection_receiver: Arc::new(Mutex::new(None)),
            variant_detection_listener: Arc::new(Mutex::new(None)),
            tester_present_snapshot: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn transmission_params() -> TransmissionParameters {
        TransmissionParameters {
            gateway_address: 1,
            timeout_ack: Duration::from_millis(10),
            ecu_name: "gateway".to_owned(),
            repeat_request_count_transmission: 0,
        }
    }

    fn payload() -> ServicePayload {
        ServicePayload {
            data: vec![0x22],
            source_address: 0x0E00,
            target_address: 0xE400,
            new_session: None,
            new_security: None,
        }
    }

    async fn gate(manager: &UdsManager<RecordingGateway, TestEcuDb>, key: &str) -> Arc<Semaphore> {
        Arc::clone(
            manager
                .ecu_semaphores
                .lock()
                .await
                .entry(key.to_owned())
                .or_insert_with(|| Arc::new(Semaphore::new(1))),
        )
    }

    async fn send(manager: UdsManager<RecordingGateway, TestEcuDb>) {
        manager
            .send_functional_to_gateway(
                transmission_params(),
                HashMap::from_iter([(1, "gateway".to_owned()), (2, "child".to_owned())]),
                DiagComm::new("read", DiagCommType::Data),
                payload(),
                false,
                Duration::from_millis(10),
                "group",
                vec![GATEWAY_KEY.to_owned(), CHILD_KEY.to_owned()],
            )
            .await;
    }

    #[tokio::test]
    async fn functional_send_waits_for_gateway_and_child_permits() {
        for held_key in [GATEWAY_KEY, CHILD_KEY] {
            let manager = manager();
            let sends = Arc::clone(&manager.gateway.functional_sends);
            let held = gate(&manager, held_key)
                .await
                .acquire_owned()
                .await
                .expect("gate must be open");
            let mut task = tokio::spawn(send(manager));

            assert!(
                tokio::time::timeout(Duration::from_millis(20), &mut task)
                    .await
                    .is_err(),
                "functional send should wait for held key: {held_key}"
            );
            assert_eq!(sends.load(Ordering::SeqCst), 0, "held key: {held_key}");

            drop(held);
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .expect("functional send should resume after permit release")
                .expect("functional send task should complete");
            assert_eq!(sends.load(Ordering::SeqCst), 1, "held key: {held_key}");
        }
    }

    #[tokio::test]
    async fn cancelling_functional_send_releases_acquired_permits() {
        let manager = manager();
        let gateway_gate = gate(&manager, GATEWAY_KEY).await;
        let child_gate = gate(&manager, CHILD_KEY).await;
        let held_child = Arc::clone(&child_gate)
            .acquire_owned()
            .await
            .expect("child gate must be open");
        let task = tokio::spawn(send(manager));

        tokio::time::timeout(Duration::from_secs(1), async {
            while gateway_gate.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("functional send should acquire gateway permit before waiting on child");

        task.abort();
        let _ = task.await;
        assert_eq!(gateway_gate.available_permits(), 1);
        drop(held_child);
    }

    #[tokio::test]
    async fn permit_acquisition_failure_is_returned_for_every_expected_ecu() {
        let manager = manager();
        gate(&manager, CHILD_KEY).await.close();

        let results = manager
            .send_functional_to_gateway(
                transmission_params(),
                HashMap::from_iter([(1, "gateway".to_owned()), (2, "child".to_owned())]),
                DiagComm::new("read", DiagCommType::Data),
                payload(),
                false,
                Duration::from_millis(10),
                "group",
                vec![GATEWAY_KEY.to_owned(), CHILD_KEY.to_owned()],
            )
            .await;

        assert_eq!(manager.gateway.functional_sends.load(Ordering::SeqCst), 0);
        assert_eq!(results.len(), 2);
        for ecu_name in ["gateway", "child"] {
            assert_eq!(
                results.get(ecu_name),
                Some(&Err(DiagServiceError::ResourceError(
                    "Request gate was closed".to_owned()
                )))
            );
        }
    }
}
