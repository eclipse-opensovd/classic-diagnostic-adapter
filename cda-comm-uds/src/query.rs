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

use std::fmt::Write as _;

use async_trait::async_trait;
use cda_interfaces::{
    DiagComm, DiagServiceError, DynamicPlugin, EcuGateway, EcuManager, HashMap, HashMapExtensions,
    UdsFunctionalGroup, UdsQuery, UdsTransport,
    datatypes::{
        ComplexComParamValue, ComponentConfigurationsInfo, ComponentDataInfo,
        ComponentOperationsInfo, Ecu, FunctionalGroup, Gateway, NetworkStructure,
        RoutineSubfunctions, SdBoolMappings, SdSdg, single_ecu,
    },
    diagservices::UdsPayloadData,
    dlt_ctx, service_ids,
};

use crate::{UdsManager, util::check_sd_sdg_recursive};

/// Grouping key for the network structure.
///
/// `DoIP` ECUs group under their gateway's logical address. ECUs the
/// transport identifies by name (CAN: the arbitration ID pair is the
/// address, there is no gateway node) each form their own entry - their
/// logical addresses are unresolved com-param defaults shared by every such
/// ECU, so grouping by address would collapse unrelated ECUs into one
/// pseudo-gateway with a single (necessarily wrong) network address.
#[derive(Eq, Hash, PartialEq)]
enum GatewayKey {
    Address(u16),
    Ecu(String),
}

#[async_trait]
impl<S: EcuGateway, T: EcuManager> UdsQuery for UdsManager<S, T> {
    async fn get_ecus(&self) -> Vec<String> {
        self.ecus.keys().cloned().collect()
    }

    async fn get_physical_ecus(&self) -> Vec<String> {
        self.ecus
            .keys()
            .filter(|ecu| **ecu != self.functional_description_database)
            .cloned()
            .collect()
    }

    async fn get_ecus_with_sds(
        &self,
        physical_only: bool,
        expected_sd: &SdBoolMappings,
    ) -> Vec<String> {
        let mut base_list = if physical_only {
            self.get_physical_ecus().await
        } else {
            self.get_ecus().await
        };
        let mut filtered = Vec::new();
        for ecu in base_list.drain(0..) {
            let sdgs = match self.get_sdgs(&ecu, None).await {
                Ok(sdgs) => sdgs,
                Err(e) => {
                    tracing::warn!("Unable to fetch Sdgs for {ecu}: {e}");
                    continue;
                }
            };
            if sdgs
                .iter()
                .any(|sdsdg| check_sd_sdg_recursive(expected_sd, sdsdg))
            {
                filtered.push(ecu);
            }
        }

        filtered
    }

    #[tracing::instrument(skip_all,
        fields(dlt_context = dlt_ctx!("UDS"))
    )]
    async fn get_network_structure(&self) -> NetworkStructure {
        fn ecu_to_network_ecu(ecu: &impl EcuManager) -> Ecu {
            let logical_address_string =
                ecu.logical_address()
                    .to_be_bytes()
                    .iter()
                    .fold("0x".to_owned(), |mut out, b| {
                        let _ = write!(out, "{b:02x}");
                        out
                    });
            let ecu_name = ecu.ecu_name();
            Ecu {
                qualifier: ecu_name.clone(),
                variant: ecu.ecu_status(),
                logical_address: logical_address_string,
                logical_link: format!("{}_on_{}", ecu_name, ecu.protocol()),
            }
        }

        let mut gateways: HashMap<GatewayKey, Gateway> = HashMap::new();

        for ecu in self.ecus.values() {
            let ecu = ecu.read().await;
            if !ecu.is_physical_ecu() {
                continue; // skip functional descriptions
            }
            let ecu_name = ecu.ecu_name();

            let network_ecu = ecu_to_network_ecu(&*ecu);

            if let Some(network_address) = self.gateway.get_ecu_network_address(&ecu_name).await {
                // Name-identified ECU (CAN): its own entry, carrying its own
                // transport address.
                gateways.insert(
                    GatewayKey::Ecu(ecu_name.clone()),
                    Gateway {
                        name: ecu_name,
                        network_address,
                        logical_address: network_ecu.logical_address.clone(),
                        ecus: vec![network_ecu],
                    },
                );
                continue;
            }

            let gateway_addr = ecu.logical_gateway_address();
            let gateway = gateways
                .entry(GatewayKey::Address(gateway_addr))
                .or_insert(Gateway {
                    name: String::new(),
                    network_address: String::new(),
                    logical_address: String::new(),
                    ecus: Vec::new(),
                });

            if gateway_addr == ecu.logical_address() {
                // this is the gateway itself
                gateway.name.clone_from(&ecu_name);
                gateway
                    .logical_address
                    .clone_from(&network_ecu.logical_address);
                if let Some(gateway_network_address) =
                    self.gateway.get_gateway_network_address(gateway_addr).await
                {
                    gateway.network_address = gateway_network_address;
                } else {
                    tracing::warn!(
                        gateway_name = %ecu_name,
                        logical_address = %network_ecu.logical_address,
                        "No network address found for gateway"
                    );
                }
            }

            gateway.ecus.push(network_ecu);
        }

        // Build functional groups from the functional description database
        let group_names = match self.ecus.get(&self.functional_description_database) {
            Some(func_desc_ecu) => func_desc_ecu.read().await.functional_groups(),
            None => Vec::new(),
        };

        let mut functional_groups = Vec::new();
        for group_name in group_names {
            let ecu_names = self.ecus_for_functional_group(&group_name, false).await;
            let mut group_ecus = Vec::new();
            for ecu_name in &ecu_names {
                if let Some(ecu_lock) = self.ecus.get(ecu_name) {
                    let ecu = ecu_lock.read().await;
                    group_ecus.push(ecu_to_network_ecu(&*ecu));
                }
            }
            functional_groups.push(FunctionalGroup {
                qualifier: group_name,
                ecus: group_ecus,
            });
        }

        NetworkStructure {
            functional_groups,
            gateways: gateways.into_values().collect(),
        }
    }

    async fn get_sdgs(
        &self,
        ecu_name: &str,
        service: Option<&DiagComm>,
    ) -> Result<Vec<SdSdg>, DiagServiceError> {
        self.uds_ecu_db(ecu_name)?.read().await.sdgs(service).await
    }

    async fn get_comparams(&self, ecu: &str) -> Result<ComplexComParamValue, DiagServiceError> {
        self.uds_ecu_db(ecu)?.read().await.comparams()
    }

    async fn get_components_data_info(
        &self,
        ecu: &str,
        security_plugin: &DynamicPlugin,
    ) -> Result<Vec<ComponentDataInfo>, DiagServiceError> {
        let items = self
            .uds_ecu_db(ecu)?
            .read()
            .await
            .get_components_data_info(security_plugin);

        Ok(items)
    }

    async fn get_components_configuration_info(
        &self,
        ecu: &str,
        security_plugin: &DynamicPlugin,
    ) -> Result<Vec<ComponentConfigurationsInfo>, DiagServiceError> {
        self.uds_ecu_db(ecu)?
            .read()
            .await
            .get_components_configurations_info(security_plugin)
    }

    async fn get_components_operations_info(
        &self,
        ecu: &str,
        security_plugin: &DynamicPlugin,
    ) -> Result<Vec<ComponentOperationsInfo>, DiagServiceError> {
        let items = self
            .uds_ecu_db(ecu)?
            .read()
            .await
            .get_components_operations_info(security_plugin);
        Ok(items)
    }

    async fn get_routine_subfunctions(
        &self,
        ecu_name: &str,
        service_name: &str,
        security_plugin: &DynamicPlugin,
    ) -> Result<RoutineSubfunctions, DiagServiceError> {
        self.uds_ecu_db(ecu_name)?
            .read()
            .await
            .get_routine_subfunctions(service_name, security_plugin)
    }

    async fn get_components_single_ecu_jobs_info(
        &self,
        ecu: &str,
    ) -> Result<Vec<ComponentDataInfo>, DiagServiceError> {
        let items = self
            .ecus
            .get(ecu)
            .ok_or_else(|| DiagServiceError::NotFound(format!("Unknown ECU: {ecu}")))?
            .read()
            .await
            .get_components_single_ecu_jobs_info();

        Ok(items)
    }

    async fn get_single_ecu_job(
        &self,
        ecu: &str,
        job_name: &str,
    ) -> Result<single_ecu::Job, DiagServiceError> {
        self.uds_ecu_db(ecu)?
            .read()
            .await
            .lookup_single_ecu_job(job_name)
    }

    async fn get_ecu_reset_services(
        &self,
        ecu_name: &str,
    ) -> Result<Vec<String>, DiagServiceError> {
        let diag_manager = self.uds_ecu_db(ecu_name)?.read().await;

        let reset_services = diag_manager
            .lookup_diagcomms_by_request_prefix(&[service_ids::ECU_RESET])?
            .iter()
            .filter_map(|dc| dc.lookup_name.clone())
            .collect();

        drop(diag_manager);
        Ok(reset_services)
    }

    async fn get_ecu_service_state(
        &self,
        ecu_name: &str,
        service: u8,
    ) -> Result<String, DiagServiceError> {
        let diag_manager = self.uds_ecu_db(ecu_name)?.read().await;
        diag_manager
            .get_service_state(service)
            .await
            .ok_or(DiagServiceError::NotFound(format!(
                "Service state for service ID {service:02X} not found in ECU {ecu_name}"
            )))
    }

    async fn ecu_exec_service_from_function_class(
        &self,
        ecu_name: &str,
        func_class_name: &str,
        service_id: u8,
        security_plugin: &DynamicPlugin,
        data: UdsPayloadData,
    ) -> Result<Self::Response, DiagServiceError> {
        let ecu_diag_service = self.uds_ecu_db(ecu_name)?;
        let ecu = ecu_diag_service.read().await;
        let request = ecu.lookup_service_through_func_class(func_class_name, service_id)?;
        self.send(ecu_name, request, security_plugin, Some(data), true)
            .await
    }

    async fn ecu_lookup_service_through_func_class(
        &self,
        ecu_name: &str,
        func_class_name: &str,
        service_id: u8,
    ) -> Result<DiagComm, DiagServiceError> {
        let ecu_diag_service = self.uds_ecu_db(ecu_name)?;
        let ecu = ecu_diag_service.read().await;
        ecu.lookup_service_through_func_class(func_class_name, service_id)
    }
}
