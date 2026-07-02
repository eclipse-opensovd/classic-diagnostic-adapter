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
    DiagComm, DiagServiceError, DynamicPlugin, EcuGateway, EcuManager, EcuState, HashMap,
    HashMapExtensions, PayloadDecoder, ServicePayload, TransmissionParameters, UdsFunctionalGroup,
    UdsResponse, UdsTransport,
    datatypes::{ComponentDataInfo, ComponentOperationsInfo, RoutineSubfunctions},
    diagservices::{DiagServiceResponse, DiagServiceResponseType, UdsPayloadData},
    dlt_ctx,
};
use tokio::sync::Mutex;

use crate::{
    UdsManager,
    types::{PerGatewayInfo, ResetType},
};

impl<S: EcuGateway, T: EcuManager> UdsManager<S, T> {
    /// Send a functional request to a single gateway and collect responses from all expected ECUs
    #[allow(clippy::too_many_arguments)] // allowing this for now. while combining some arguments
    // based on semantics here would be possible, its preferred to have to call semantics similar
    // in all send functions, as this makes it easier to glance the parameters of the function.
    async fn send_functional_to_gateway(
        &self,
        transmission_params: TransmissionParameters,
        expected_ecus: HashMap<u16, String>,
        service: DiagComm,
        payload: ServicePayload,
        map_to_json: bool,
        timeout: Duration,
        functional_group_name: &str,
    ) -> HashMap<String, Result<<T as PayloadDecoder>::Response, DiagServiceError>> {
        // Inspect the subfunction byte for `suppressPosRspMsgIndicationBit` (bit 7).
        // When set, ECUs are not expected to send a positive response.
        let expect_positive_response = !payload.is_suppress_positive_response();

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
                        Ok(UdsResponse::Message(msg)) => {
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
                        Ok(_) => {
                            // Other UDS response types shouldn't occur in functional communication
                            result_map.insert(
                                ecu_name,
                                Err(DiagServiceError::UnexpectedResponse(Some(
                                    "Unexpected UDS response type in functional communication"
                                        .to_string(),
                                ))),
                            );
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
        let mut ecu_infos_by_gateway = HashMap::<u16, HashMap<u16, String>>::new();

        for ecu_name in &ecu_list {
            if let Some(ecu) = self.ecus.get(ecu_name) {
                let ecu_lock = ecu.read().await;
                if !ecu_lock.is_physical_ecu() {
                    continue;
                }

                let ecu_state = ecu_lock.variant().state;
                if ecu_state != EcuState::Online {
                    tracing::debug!(
                        ecu = %ecu_name,
                        ecu_state = %ecu_state,
                        "Skipping ECU that is not online"
                    );
                    continue;
                }
                let tester_addr = ecu_lock.tester_address();
                let gateway_addr = ecu_lock.logical_gateway_address();
                let logical_addr = ecu_lock.logical_address();
                let func_addr = ecu_lock.logical_functional_address();
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
                        .insert(logical_addr, ecu_name.clone());
                }
            }
        }

        for (gateway_addr, ecu_info_list) in ecu_infos_by_gateway {
            if let Some(gateway_info) = ecus_by_gateway.get_mut(&gateway_addr) {
                gateway_info.ecus.extend(ecu_info_list);
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
        let ecu = self.uds_ecu_db(ecu_name)?;
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
