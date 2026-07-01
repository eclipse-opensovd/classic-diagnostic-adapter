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

use std::{
    fmt::Write as _,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use cda_interfaces::{
    DiagComm, DiagServiceError, DynamicPlugin, EcuGateway, EcuManager, EcuState, EcuVariant,
    FlashTransferStartParams, FunctionalDescriptionConfig, HashMap, HashMapExtensions, HashSet,
    HashSetExtensions, PayloadDecoder, SchemaDescription, SchemaProvider, ServicePayload,
    TransmissionParameters, UdsEcu, UdsEcuDb, UdsResponse, UdsTransport,
    datatypes::{
        self, ComponentConfigurationsInfo, ComponentOperationsInfo, DTC_CODE_BIT_LEN,
        DataTransferError, DataTransferMetaData, DataTransferStatus, DtcCode, DtcExtendedInfo,
        DtcMask, DtcReadInformationFunction, DtcRecordAndStatus, DtcSnapshot, Ecu,
        ExtendedDataRecords, ExtendedSnapshots, FaultConfig, FunctionalGroup, Gateway,
        NetworkStructure, RoutineSubfunctions, SdBoolMappings, SdSdg,
    },
    diagservices::{DiagServiceResponse, DiagServiceResponseType, UdsPayloadData},
    dlt_ctx, service_ids, util,
};
use strum::IntoEnumIterator;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt, BufReader},
    sync::{Mutex, RwLock, Semaphore, mpsc, watch},
    task::JoinHandle,
};

mod security;
mod session;
mod tester_present;
mod transport;
mod types;

pub use types::TesterPresentTask;
use types::{EcuDataTransfer, EcuIdentifier, PerGatewayInfo, ResetType};

/// Record number requesting all records/all memory (ISO 14229-1).
const DTC_RECORD_NUMBER_ALL: u8 = 0xFF;

/// DTC group value for "clear all DTCs" (ISO 14229-1, D.1).
/// Sending `0xFFFFFF` as the group-of-DTC clears all groups.
const DTC_GROUP_ALL: [u8; 3] = [0xFF, 0xFF, 0xFF];

pub struct UdsManager<S: EcuGateway, T: UdsEcuDb> {
    ecus: Arc<HashMap<String, RwLock<T>>>,
    gateway: S,
    data_transfers: Arc<Mutex<HashMap<EcuIdentifier, EcuDataTransfer>>>,
    ecu_semaphores: Arc<Mutex<HashMap<String, Arc<Semaphore>>>>,
    tester_present_tasks: Arc<RwLock<HashMap<EcuIdentifier, TesterPresentTask>>>,
    session_reset_tasks: Arc<RwLock<HashMap<EcuIdentifier, JoinHandle<()>>>>,
    security_reset_tasks: Arc<RwLock<HashMap<EcuIdentifier, JoinHandle<()>>>>,
    functional_description_database: String,
    fault_config: FaultConfig,
    update_in_progress: Arc<AtomicBool>,
}

/// Guard that reports whether any ECU flash data transfers are currently active.
///
/// Used by the runtime update plugin to block updates while transfers are in progress.
/// Implements [`cda_interfaces::runtime_update_api::ActivityGuard`] with a conservative
/// locking strategy: if the internal mutex is contended, it reports active transfers
/// to prevent TOCTOU races.
pub struct FlashTransferObserver {
    data_transfers: Arc<Mutex<HashMap<EcuIdentifier, EcuDataTransfer>>>,
}

impl cda_interfaces::runtime_update_api::ActivityGuard for FlashTransferObserver {
    fn is_active(&self) -> bool {
        self.data_transfers
            .try_lock()
            .map_or(true, |guard| !guard.is_empty())
    }
}

impl<S: EcuGateway, T: UdsEcuDb> UdsManager<S, T> {
    fn uds_ecu_db(&self, ecu_name: &str) -> Result<&RwLock<T>, DiagServiceError> {
        self.ecus
            .get(ecu_name)
            .ok_or_else(|| DiagServiceError::NotFound(format!("ECU {ecu_name} not found")))
    }
}

impl<S: EcuGateway, T: EcuManager> UdsManager<S, T> {
    pub fn new(
        gateway: S,
        ecus: Arc<HashMap<String, RwLock<T>>>,
        mut variant_detection_receiver: mpsc::Receiver<Vec<String>>,
        functional_description_config: &FunctionalDescriptionConfig,
        fault_config: FaultConfig,
        update_in_progress: Arc<AtomicBool>,
    ) -> Self {
        let manager = Self {
            ecus,
            gateway,
            data_transfers: Arc::new(Mutex::new(HashMap::new())),
            ecu_semaphores: Arc::new(Mutex::new(HashMap::new())),
            tester_present_tasks: Arc::new(RwLock::new(HashMap::new())),
            session_reset_tasks: Arc::new(RwLock::new(HashMap::new())),
            security_reset_tasks: Arc::new(RwLock::new(HashMap::new())),
            functional_description_database: functional_description_config
                .description_database
                .clone(),
            fault_config,
            update_in_progress,
        };

        let vd_uds_clone = manager.clone();
        cda_interfaces::spawn_named!("variant-detection-receiver", async move {
            while let Some(ecus) = variant_detection_receiver.recv().await {
                let mut processed_duplicates = HashSet::new();
                let mut deduplicated_ecus = Vec::new();

                for ecu_name in ecus {
                    if processed_duplicates.contains(&ecu_name) {
                        continue;
                    }

                    if let Some(ecu) = vd_uds_clone.ecus.get(&ecu_name) {
                        let ecu_read = ecu.read().await;
                        if let Some(duplicates) = ecu_read.duplicating_ecu_names() {
                            processed_duplicates.extend(duplicates.iter().cloned());
                        }
                        deduplicated_ecus.push(ecu_name);
                    }
                }

                vd_uds_clone.start_variant_detection_for_ecus(deduplicated_ecus);
            }
        });

        manager
    }

    pub fn flash_transfer_guard(&self) -> FlashTransferObserver {
        FlashTransferObserver {
            data_transfers: Arc::clone(&self.data_transfers),
        }
    }

    /// Abort all background tasks owned by this instance. Idempotent.
    pub async fn shutdown(&self) {
        let mut tester_present_tasks = self.tester_present_tasks.write().await;
        let mut session_reset_tasks = self.session_reset_tasks.write().await;
        let mut security_reset_tasks = self.security_reset_tasks.write().await;
        let mut data_transfers = self.data_transfers.lock().await;
        tester_present_tasks
            .drain()
            .map(|(_, tp)| tp.task)
            .chain(session_reset_tasks.drain().map(|(_, h)| h))
            .chain(security_reset_tasks.drain().map(|(_, h)| h))
            .chain(data_transfers.drain().map(|(_, t)| t.task))
            .for_each(|h| h.abort());
    }

    #[tracing::instrument(
        skip(self, request, status_sender, reader),
        fields(
            ecu_name,
            transfer_length = length,
            request_name = %request.name,
            dlt_context = dlt_ctx!("UDS"))
    )]
    async fn transfer_ecu_data(
        &self,
        ecu_name: &str,
        length: u64,
        request: DiagComm,
        status_sender: watch::Sender<bool>,
        mut reader: BufReader<File>,
    ) {
        async fn set_transfer_aborted(
            ecu_name: &str,
            transfers: &Arc<Mutex<HashMap<String, EcuDataTransfer>>>,
            reason: String,
            sender: &watch::Sender<bool>,
        ) {
            if let Some(dt) = transfers.lock().await.get_mut(ecu_name) {
                dt.meta_data.status = DataTransferStatus::Aborted;
                dt.meta_data.error = Some(vec![DataTransferError { text: reason }]);
            }
            if let Err(e) = sender.send(true) {
                tracing::error!(error = ?e, "Failed to send data transfer aborted signal");
            }
        }

        let (mut buffer, mut remaining_bytes, block_size, mut next_block_sequence_counter) = {
            let mut lock = self.data_transfers.lock().await;
            let Some(transfer) = lock.get_mut(ecu_name) else {
                tracing::error!("No transfer found, cannot start data transfer");
                return;
            };
            transfer.meta_data.status = DataTransferStatus::Running;
            (
                vec![0; transfer.meta_data.blocksize],
                length,
                transfer.meta_data.blocksize,
                transfer.meta_data.next_block_sequence_counter,
            )
        };

        // we do not want to check the service on every execution, but it is checked before
        // transfer_ecu_data is called
        let skip_security_plugin_check: DynamicPlugin = Box::new(());
        while remaining_bytes > 0 {
            let Some(remaining_as_usize) = remaining_bytes.try_into().ok() else {
                set_transfer_aborted(
                    ecu_name,
                    &self.data_transfers,
                    "Remaining bytes overflowed usize".to_owned(),
                    &status_sender,
                )
                .await;
                break;
            };

            let bytes_to_read = block_size.min(remaining_as_usize);

            let Some(buffer_slice) = buffer.get_mut(..bytes_to_read) else {
                set_transfer_aborted(
                    ecu_name,
                    &self.data_transfers,
                    "Buffer slice out of bounds".to_owned(),
                    &status_sender,
                )
                .await;
                break;
            };

            if let Err(e) = reader.read_exact(buffer_slice).await {
                set_transfer_aborted(
                    ecu_name,
                    &self.data_transfers,
                    format!("Failed to read data: {e:?}"),
                    &status_sender,
                )
                .await;
                break;
            }

            let mut buf = Vec::with_capacity(
                /*block sequence counter*/ 1usize.saturating_add(bytes_to_read),
            );
            buf.push(next_block_sequence_counter);

            let Some(buffer_data) = buffer.get(..bytes_to_read) else {
                set_transfer_aborted(
                    ecu_name,
                    &self.data_transfers,
                    "Buffer slice out of bounds".to_owned(),
                    &status_sender,
                )
                .await;
                break;
            };
            buf.extend_from_slice(buffer_data);

            let uds_payload = UdsPayloadData::Raw(buf);
            let result = self
                .send(
                    ecu_name,
                    request.clone(),
                    &skip_security_plugin_check,
                    Some(uds_payload),
                    true,
                )
                .await;
            if let Err(e) = result {
                set_transfer_aborted(
                    ecu_name,
                    &self.data_transfers,
                    format!("Failed to read data: {e:?}"),
                    &status_sender,
                )
                .await;
                break;
            }

            {
                let mut lock = self.data_transfers.lock().await;
                let Some(transfer) = lock.get_mut(ecu_name) else {
                    tracing::error!("No transfer found, cannot update data transfer");
                    return;
                };

                next_block_sequence_counter = next_block_sequence_counter.wrapping_add(1);
                transfer.meta_data.next_block_sequence_counter = next_block_sequence_counter;
                transfer.meta_data.acknowledged_bytes = transfer
                    .meta_data
                    .acknowledged_bytes
                    .saturating_add(bytes_to_read as u64);

                remaining_bytes = remaining_bytes.saturating_sub(bytes_to_read as u64);
                if remaining_bytes == 0 {
                    transfer.meta_data.status = DataTransferStatus::Finished;
                    if let Err(e) = status_sender.send(true) {
                        tracing::error!(
                            error = ?e,
                            "Failed to send data transfer completion signal"
                        );
                    }
                }
            }
        }
    }

    #[tracing::instrument(skip_all,
        fields(dlt_context = dlt_ctx!("UDS"))
    )]
    fn start_variant_detection_for_ecus(&self, ecus: Vec<String>) {
        for ecu_name in ecus {
            let vd = self.clone();
            cda_interfaces::spawn_named!(&format!("variant-detection-{ecu_name}"), async move {
                match vd.detect_variant(&ecu_name).await {
                    Ok(()) => {
                        tracing::trace!("Variant detection successful");
                    }
                    Err(e) => {
                        tracing::info!(error = %e, "Variant detection failed");
                    }
                }
            });
        }
    }

    async fn request_extended_data(
        &self,
        ecu_name: &str,
        security_plugin: &DynamicPlugin,
        dtc_code: DtcCode,
        service_types: Vec<DtcReadInformationFunction>,
        memory_selection: Option<u8>,
        include_schema: bool,
    ) -> Result<
        (
            <T as PayloadDecoder>::Response,
            DtcReadInformationFunction,
            Option<SchemaDescription>,
        ),
        DiagServiceError,
    > {
        let ecu = self.uds_ecu_db(ecu_name)?;
        let (read_func, extended_data_lookup) = ecu
            .read()
            .await
            .lookup_dtc_services(&service_types)?
            .into_iter()
            .find(|(_, lookup)| lookup.dtcs.iter().any(|dtc| dtc.code == dtc_code))
            .ok_or(DiagServiceError::InvalidRequest(format!(
                "DTC {dtc_code:X} not found in ECU {ecu_name}"
            )))?;

        let mut raw_payload = cda_interfaces::util::extract_bits(
            DTC_CODE_BIT_LEN as usize,
            0,
            &dtc_code.to_be_bytes(),
        )?;
        raw_payload.push(DTC_RECORD_NUMBER_ALL);

        if read_func.is_user_scope() {
            raw_payload.push(memory_selection.unwrap_or(0x00));
        }

        let uds_payload = UdsPayloadData::Raw(raw_payload);

        let schema = if include_schema {
            Some(
                self.schema_for_responses(ecu_name, &extended_data_lookup.service)
                    .await?,
            )
        } else {
            None
        };

        let response = self
            .send(
                ecu_name,
                extended_data_lookup.service,
                security_plugin,
                Some(uds_payload),
                true,
            )
            .await?;

        Ok((response, extended_data_lookup.scope, schema))
    }

    async fn map_extended_data(
        &self,
        ecu_name: &str,
        security_plugin: &DynamicPlugin,
        dtc_code: DtcCode,
        include_schema: bool,
        memory_selection: Option<u8>,
        scope: DtcReadInformationFunction,
    ) -> Result<(Option<ExtendedDataRecords>, Option<serde_json::Value>), DiagServiceError> {
        fn extract_schema_properties(schema_desc: &SchemaDescription) -> Option<serde_json::Value> {
            // todo after solving #54: we are missing the 'Selector' and the case name here
            let schema = schema_desc
                .get_param_properties()?
                .values()
                .filter_map(|p| p.as_object())
                .find(|obj| obj.contains_key("any-of"));

            schema.map(|schema| serde_json::Value::Object(schema.clone()))
        }

        let ext_data_service_type = if scope.is_user_scope() {
            DtcReadInformationFunction::UserMemoryDtcExtDataRecordByDtcNumber
        } else {
            DtcReadInformationFunction::FaultMemoryExtDataRecordByDtcNumber
        };
        let (extended_data_response, _scope, schema_desc) = self
            .request_extended_data(
                ecu_name,
                security_plugin,
                dtc_code,
                vec![ext_data_service_type],
                memory_selection,
                include_schema,
            )
            .await?;

        let schema = if include_schema {
            extract_schema_properties(&schema_desc.ok_or(DiagServiceError::InvalidRequest(
                "Schema requested but not found".to_owned(),
            ))?)
        } else {
            None
        };

        if extended_data_response.response_type() == DiagServiceResponseType::Negative {
            return Ok((None, schema));
        }

        let extended_data_json = extended_data_response.into_json()?;
        let extended_data: Option<HashMap<_, _>> =
            extended_data_json.data.as_object().and_then(|obj| {
                obj.iter()
                    .find_map(|(_, value)| value.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|item| {
                                item.as_object().and_then(|obj| {
                                    let record = obj.iter().find_map(|(_, v)| v.as_object());
                                    let record_number = obj.iter().find_map(|(_, v)| {
                                        if v.is_object() { None } else { Some(v) }
                                    });

                                    if let (Some(record_number), Some(record)) =
                                        (record_number, record)
                                    {
                                        Some((
                                            record_number.to_string().replace('"', ""),
                                            serde_json::Value::Object(record.clone()),
                                        ))
                                    } else {
                                        None
                                    }
                                })
                            })
                            .collect::<HashMap<_, _>>()
                    })
            });

        Ok((
            Some(ExtendedDataRecords {
                data: extended_data,
                errors: if extended_data_json.errors.is_empty() {
                    None
                } else {
                    Some(extended_data_json.errors)
                },
            }),
            schema,
        ))
    }

    async fn map_snapshots(
        &self,
        ecu_name: &str,
        security_plugin: &DynamicPlugin,
        dtc_code: DtcCode,
        include_schema: bool,
        memory_selection: Option<u8>,
        scope: DtcReadInformationFunction,
    ) -> Result<(Option<ExtendedSnapshots>, Option<serde_json::Value>), DiagServiceError> {
        fn extract_schema_properties(schema_desc: &SchemaDescription) -> Option<serde_json::Value> {
            // Todo when solving #54: We are missing the mux case name in the schema.
            let param_properties = schema_desc.get_param_properties()?;
            let mut schema = serde_json::Map::new();

            for (key, value) in param_properties {
                if value.is_array() || value.get("type").is_some_and(|t| t == "integer") {
                    schema.insert(key.clone(), value.clone());
                }
            }

            if schema.is_empty() {
                None
            } else {
                Some(serde_json::Value::Object(schema))
            }
        }
        let snapshot_service_type = if scope.is_user_scope() {
            DtcReadInformationFunction::UserMemoryDtcSnapshotRecordByDtcNumber
        } else {
            DtcReadInformationFunction::FaultMemorySnapshotRecordByDtcNumber
        };
        let (snapshot_data_response, _scope, schema_desc) = self
            .request_extended_data(
                ecu_name,
                security_plugin,
                dtc_code,
                vec![snapshot_service_type],
                memory_selection,
                include_schema,
            )
            .await?;

        let schema = if include_schema {
            extract_schema_properties(&schema_desc.ok_or(DiagServiceError::InvalidRequest(
                "Schema requested but not found".to_owned(),
            ))?)
        } else {
            None
        };

        if snapshot_data_response.response_type() == DiagServiceResponseType::Negative {
            return Ok((None, schema));
        }

        let snapshot_json = snapshot_data_response.into_json()?;
        let snapshot_data: Option<HashMap<_, _>> = snapshot_json
            .data
            .as_object()
            .and_then(|obj| obj.values().find_map(|value| value.as_array()))
            .map(|params| {
                params
                    .iter()
                    .filter_map(|param| param.as_object())
                    .filter_map(|obj| {
                        let records = obj.values().find_map(|v| v.as_array());
                        let number_of_identifiers = obj.values().find_map(|v| v.as_number());
                        let record_number_of_snapshot = obj.values().find(|v| v.is_string());
                        if let (
                            Some(records),
                            Some(number_of_identifiers),
                            Some(record_number_of_snapshot),
                        ) = (records, number_of_identifiers, record_number_of_snapshot)
                        {
                            Some((
                                record_number_of_snapshot.to_string().replace('"', ""),
                                (DtcSnapshot {
                                    number_of_identifiers: number_of_identifiers
                                        .as_u64()
                                        .unwrap_or_default(),
                                    record: records.clone(),
                                }),
                            ))
                        } else {
                            None
                        }
                    })
                    .collect()
            });
        Ok((
            Some(ExtendedSnapshots {
                data: snapshot_data,
                errors: if snapshot_json.errors.is_empty() {
                    None
                } else {
                    Some(snapshot_json.errors)
                },
            }),
            schema,
        ))
    }

    /// Send a functional request to a single gateway and collect responses from all expected ECUs
    #[allow(clippy::too_many_arguments)] // allowing this for now. while combining some arguments
    // based on semantics here would be possible, its preferred to have to call semantics similar
    // in all send functions, as this makes it easiert to glance the parameters of the function.
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
        // Inspect the subfunction byte for suppressPosRspMsgIndicationBit (bit 7).
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

impl<S: Clone + EcuGateway, T: UdsEcuDb> Clone for UdsManager<S, T> {
    fn clone(&self) -> Self {
        Self {
            ecus: Arc::clone(&self.ecus),
            gateway: self.gateway.clone(),
            data_transfers: Arc::clone(&self.data_transfers),
            ecu_semaphores: Arc::clone(&self.ecu_semaphores),
            tester_present_tasks: Arc::clone(&self.tester_present_tasks),
            session_reset_tasks: Arc::clone(&self.session_reset_tasks),
            security_reset_tasks: Arc::clone(&self.security_reset_tasks),
            functional_description_database: self.functional_description_database.clone(),
            fault_config: self.fault_config.clone(),
            update_in_progress: Arc::clone(&self.update_in_progress),
        }
    }
}

#[async_trait]
impl<S: EcuGateway, T: EcuManager> UdsEcu for UdsManager<S, T> {
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
                variant: ecu.variant(),
                logical_address: logical_address_string,
                logical_link: format!("{}_on_{}", ecu_name, ecu.protocol()),
            }
        }

        // it seems that an &u16 doesn't implement into for u16
        // this caused an issue with uds.entry_ref(...).or_insert(...)
        // where rust complained that it cannot convert the key from &u16 to u16
        // as a workaround we use the new type pattern to implement from for &u16
        #[derive(Eq, Hash, PartialEq)]
        struct GatewayAddress(u16);

        impl From<&GatewayAddress> for GatewayAddress {
            fn from(value: &GatewayAddress) -> Self {
                GatewayAddress(value.0)
            }
        }

        let mut gateways: HashMap<GatewayAddress, Gateway> = HashMap::new();

        for ecu in self.ecus.values() {
            let ecu = ecu.read().await;
            if !ecu.is_physical_ecu() {
                continue; // skip functional descriptions
            }
            let ecu_name = ecu.ecu_name();

            let network_ecu = ecu_to_network_ecu(&*ecu);

            let gateway_addr = ecu.logical_gateway_address();
            let gateway = gateways
                .entry(GatewayAddress(gateway_addr))
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
                        "No IP address found for gateway"
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
    ) -> Result<Vec<cda_interfaces::datatypes::SdSdg>, DiagServiceError> {
        self.uds_ecu_db(ecu_name)?.read().await.sdgs(service).await
    }

    async fn get_comparams(
        &self,
        ecu: &str,
    ) -> Result<cda_interfaces::datatypes::ComplexComParamValue, DiagServiceError> {
        self.uds_ecu_db(ecu)?.read().await.comparams()
    }

    async fn get_components_data_info(
        &self,
        ecu: &str,
        security_plugin: &DynamicPlugin,
    ) -> Result<Vec<cda_interfaces::datatypes::ComponentDataInfo>, DiagServiceError> {
        let items = self
            .uds_ecu_db(ecu)?
            .read()
            .await
            .get_components_data_info(security_plugin);

        Ok(items)
    }

    async fn get_functional_group_data_info(
        &self,
        security_plugin: &DynamicPlugin,
        functional_group_name: &str,
    ) -> Result<Vec<cda_interfaces::datatypes::ComponentDataInfo>, DiagServiceError> {
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
    ) -> Result<Vec<cda_interfaces::datatypes::ComponentDataInfo>, DiagServiceError> {
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
    ) -> Result<cda_interfaces::datatypes::single_ecu::Job, DiagServiceError> {
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

    async fn ecu_flash_transfer_start(
        &self,
        ecu_name: &str,
        func_class_name: &str,
        security_plugin: &DynamicPlugin,
        parameters: FlashTransferStartParams<'_>,
    ) -> Result<(), DiagServiceError> {
        let FlashTransferStartParams {
            file_path,
            offset,
            length,
            transfer_meta_data,
        } = parameters;

        if length == 0 {
            return Err(DiagServiceError::InvalidRequest(
                "Transfer length must be greater than 0".to_owned(),
            ));
        }

        // even if the data transfer job is done,
        // data_transfer_exit must be called before starting a new one
        if let Some(transfer) = self.data_transfers.lock().await.get(ecu_name) {
            return Err(DiagServiceError::InvalidRequest(format!(
                "Transfer data already running with id {}",
                transfer.meta_data.id
            )));
        }

        let file = File::open(file_path).await.map_err(|e| {
            DiagServiceError::InvalidRequest(format!("Failed to open file '{file_path}': {e:?}"))
        })?;

        let flash_file_meta_data = file.metadata().await.map_err(|e| {
            DiagServiceError::InvalidRequest(format!("Failed to get metadata: {e:?}"))
        })?;

        let file_size = flash_file_meta_data.len();
        if file_size < offset.saturating_add(length) {
            return Err(DiagServiceError::InvalidRequest(format!(
                "File size {file_size} is too small for the requested offset {offset} and length \
                 {length}",
            )));
        }

        let mut reader = BufReader::new(file);
        reader
            .seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(|e| {
                DiagServiceError::InvalidRequest(format!("Failed to seek to offset in file: {e:?}"))
            })?;

        let ecu = self.uds_ecu_db(ecu_name)?;
        let request = ecu
            .read()
            .await
            .lookup_service_through_func_class(func_class_name, service_ids::TRANSFER_DATA)?;

        ecu.read()
            .await
            .is_service_allowed(&request, security_plugin)
            .await?;

        let ecu_name = ecu_name.to_owned();
        let ecu_name_clone = ecu_name.clone();

        let (sender, receiver) = watch::channel::<bool>(false);

        // lock the transfers, to make sure the task only accesses the transfers once
        // we are fully initialized
        let mut transfer_lock = self.data_transfers.lock().await;
        if self.update_in_progress.load(Ordering::Acquire) {
            return Err(DiagServiceError::InvalidRequest(
                "Runtime update in progress, flash transfer blocked".to_owned(),
            ));
        }
        let uds = self.clone();
        let transfer_task =
            cda_interfaces::spawn_named!(&format!("flashtransfer-{ecu_name}"), async move {
                uds.transfer_ecu_data(&ecu_name, length, request, sender, reader)
                    .await;
            });

        transfer_lock.insert(
            ecu_name_clone,
            EcuDataTransfer {
                meta_data: transfer_meta_data,
                status_receiver: receiver,
                task: transfer_task,
            },
        );
        Ok(())
    }

    async fn ecu_flash_transfer_exit(
        &self,
        ecu_name: &str,
        id: &str,
    ) -> Result<(), DiagServiceError> {
        let mut lock = self.data_transfers.lock().await;
        let transfer = lock.get(ecu_name).ok_or_else(|| {
            DiagServiceError::NotFound(format!("Data transfer for ECU {ecu_name} not found"))
        })?;

        if !matches!(
            transfer.meta_data.status,
            DataTransferStatus::Aborted | DataTransferStatus::Finished
        ) {
            return Err(DiagServiceError::InvalidRequest(format!(
                "Data transfer with id {id} is currently in status {:?}, cannot exit",
                transfer.meta_data.status,
            )));
        }

        // Now it is safe to remove the transfer from the map
        let mut transfer = lock.remove(ecu_name).ok_or_else(|| {
            DiagServiceError::NotFound(format!(
                "Data transfer for ECU {ecu_name} not found during exit"
            ))
        })?;

        if let Err(e) = transfer.status_receiver.changed().await {
            return Err(DiagServiceError::InvalidRequest(format!(
                "Failed to receive data transfer exit signal: {e:?}"
            )));
        }

        transfer.task.await.map_err(|e| {
            DiagServiceError::InvalidRequest(format!("Failed to await data transfer task: {e:?}"))
        })?;

        Ok(())
    }

    async fn ecu_flash_transfer_status(
        &self,
        ecu_name: &str,
    ) -> Result<Vec<DataTransferMetaData>, DiagServiceError> {
        let meta_data = self
            .data_transfers
            .lock()
            .await
            .get(ecu_name)
            .map(|transfer| transfer.meta_data.clone())
            .ok_or_else(|| {
                DiagServiceError::NotFound(format!("No data transfer running for ECU {ecu_name}"))
            })?;

        Ok(vec![meta_data.clone()])
    }

    async fn ecu_flash_transfer_status_id(
        &self,
        ecu_name: &str,
        id: &str,
    ) -> Result<DataTransferMetaData, DiagServiceError> {
        self.ecu_flash_transfer_status(ecu_name)
            .await?
            .into_iter()
            .find(|transfer| transfer.id == id)
            .ok_or_else(|| {
                DiagServiceError::NotFound(format!(
                    "Data transfer with id {id} not found for ECU {ecu_name}"
                ))
            })
    }

    #[tracing::instrument(skip(self), err,
        fields(
            dlt_context = dlt_ctx!("UDS")
        )
    )]
    async fn detect_variant(&self, ecu_name: &str) -> Result<(), DiagServiceError> {
        #[derive(Debug)]
        enum VariantDetectionResult<'a> {
            ExactMatch(&'a str),
            AllFallbacks,
            NoOnlineEcu,
            NoDetection,
        }

        let ecu = self.uds_ecu_db(ecu_name)?;

        let requests = ecu
            .read()
            .await
            .get_variant_detection_requests()
            .iter()
            .map(|(name, service)| Ok((name.to_owned(), service.clone())))
            .collect::<Result<Vec<(String, DiagComm)>, DiagServiceError>>()?;

        if !ecu.read().await.is_loaded() {
            ecu.write().await.load().map_err(|e| {
                DiagServiceError::ResourceError(format!("Failed to load ECU data: {e:?}"))
            })?;
        }

        // Seed the session/security map before sending detection requests so
        // that check_service_preconditions can validate them. This only
        // works for ECUS whose state charts are defined on the base variant level
        if let Err(e) = ecu.read().await.set_default_states().await {
            tracing::debug!(
                error = %e,
                "Could not pre-initialize ECU default states"
            );
        }

        let mut service_responses = HashMap::new();
        'variant_detection_calls: {
            for (name, service) in requests {
                let response = match self
                    .send_with_timeout(
                        ecu_name,
                        service,
                        &(Box::new(()) as DynamicPlugin),
                        None,
                        true,
                        Duration::from_secs(10),
                    )
                    .await
                {
                    Ok(response) => response,
                    Err(e) => {
                        tracing::debug!(
                            request_name = %name,
                            error = %e,
                            "Failed to send variant detection request"
                        );
                        break 'variant_detection_calls; // no need to continue if one fails
                    }
                };
                service_responses.insert(name, response);
            }
        }

        let Some(mut duplicated_ecus) = ecu
            .read()
            .await
            .duplicating_ecu_names()
            .cloned()
            .filter(|d| !d.is_empty())
        else {
            // No duplicated ECUs, proceed with normal variant detection
            return ecu
                .write()
                .await
                .detect_variant(service_responses)
                .await
                .map_err(|e| {
                    DiagServiceError::VariantDetectionError(format!(
                        "Failed to detect variant: {e:?}"
                    ))
                });
        };

        // Detect variants for all duplicated ECUs
        duplicated_ecus.insert(ecu_name.to_owned());

        let detection_result = {
            // First ECU that is online and fell back to base variant (no specific match).
            let mut first_fallback = None;
            let mut any_online = false;

            let mut result = None;
            for ecu_name in &duplicated_ecus {
                let Some(ecu) = self.ecus.get(ecu_name) else {
                    continue;
                };

                if let Err(e) = ecu
                    .write()
                    .await
                    .detect_variant(service_responses.clone())
                    .await
                {
                    tracing::warn!(
                        "Variant detection failed for ECU {ecu_name}: {e:?}, marking as undetected"
                    );
                    continue;
                }

                let variant = ecu.read().await.variant();
                if variant.state != cda_interfaces::EcuState::Online {
                    continue;
                }

                any_online = true;

                if variant.is_fallback {
                    first_fallback.get_or_insert(ecu_name);
                } else {
                    result = Some(VariantDetectionResult::ExactMatch(ecu_name));
                    break;
                }
            }

            let result_fallback_mapper =
                |first_fallback, any_online| match (first_fallback, any_online) {
                    (Some(_), true) => VariantDetectionResult::AllFallbacks,
                    (_, true) => VariantDetectionResult::NoDetection,
                    _ => VariantDetectionResult::NoOnlineEcu,
                };

            result.unwrap_or(result_fallback_mapper(first_fallback, any_online))
        };

        tracing::debug!(?detection_result, "ECU variant detection result");

        match &detection_result {
            VariantDetectionResult::ExactMatch(the_chosen_one) => {
                // Mark all other duplicates, the chosen one keeps its detected variant.
                for ecu_name in &duplicated_ecus {
                    if ecu_name == *the_chosen_one {
                        continue;
                    }
                    if let Some(ecu) = self.ecus.get(ecu_name) {
                        ecu.write().await.mark_as_duplicate();
                    }
                }
            }
            VariantDetectionResult::AllFallbacks => {
                // No specific variant found despite online ECUs - mark all as undetected.
                // Falling back to base variant is only allowed when there are no duplicates.
                for ecu_name in &duplicated_ecus {
                    if let Some(ecu) = self.ecus.get(ecu_name) {
                        ecu.write().await.mark_as_no_variant_detected();
                    }
                }
            }
            VariantDetectionResult::NoOnlineEcu | VariantDetectionResult::NoDetection => {}
        }

        Ok(())
    }

    async fn get_variant(&self, ecu_name: &str) -> Result<EcuVariant, DiagServiceError> {
        let ecu = self.uds_ecu_db(ecu_name)?;
        let variant = ecu.read().await.variant();
        Ok(variant)
    }

    #[tracing::instrument(skip_all,
        fields(dlt_context = dlt_ctx!("UDS"))
    )]
    async fn start_variant_detection(&self) {
        let mut ecus = Vec::new();
        for (ecu_name, db) in self.ecus.iter() {
            if !db.read().await.is_physical_ecu() {
                tracing::debug!(
                    ecu_name = %ecu_name,
                    "Skip variant detection for functional description"
                );
                continue;
            }
            if let Err(DiagServiceError::EcuOffline(_)) =
                self.gateway.ecu_online(ecu_name, db).await
            {
                // empty response means ECU is offline
                if let Err(e) = db
                    .write()
                    .await
                    .detect_variant::<<T as PayloadDecoder>::Response>(HashMap::new())
                    .await
                {
                    tracing::error!(ecu_name = %ecu_name,
                        "Failed to set ECU offline during variant detection: {e:?}");
                }
                continue;
            }

            if db
                .read()
                .await
                .duplicating_ecu_names()
                .is_some_and(|d| ecus.iter().any(|e| d.contains(e)))
            {
                continue; // Only do one variant detection for duplicated ECUs
            }

            ecus.push(ecu_name.to_owned());
        }
        let cloned = self.clone();
        cloned.start_variant_detection_for_ecus(ecus);
    }

    async fn ecu_dtc_by_mask(
        &self,
        ecu_name: &str,
        security_plugin: &DynamicPlugin,
        status: Option<HashMap<String, serde_json::Value>>,
        severity: Option<u32>,
        scope: Option<String>,
        memory_selection: Option<u8>,
    ) -> Result<HashMap<DtcCode, DtcRecordAndStatus>, DiagServiceError> {
        let ecu = self.uds_ecu_db(ecu_name)?;
        let mut all_dtcs = HashMap::new();
        let scoped_services: Vec<_> = ecu
            .read()
            .await
            .lookup_dtc_services(&[
                DtcReadInformationFunction::FaultMemoryByStatusMask,
                DtcReadInformationFunction::UserMemoryDtcByStatusMask,
            ])?
            .into_iter()
            .filter(|(_, lookup)| {
                scope
                    .as_ref()
                    .is_none_or(|scope| scope.eq_ignore_ascii_case(lookup.scope.default_scope()))
            })
            .collect();
        if scoped_services.is_empty() {
            return Err(DiagServiceError::RequestNotSupported(format!(
                "ECU {ecu_name} does not support fault memory {}",
                scope.map(|s| format!("for scope {s}")).unwrap_or_default()
            )));
        }

        let mask = if let Some(status) = status {
            let mut mask = 0x00u8;
            // Status can contain more than the mask bits, thus we need to track
            // if any of the status fields is a mask bit.
            // If not use the default mask.
            let mut any_mask_bit_set = false;

            for mask_bit in DtcMask::iter() {
                let mask_bit_str = mask_bit.to_string().to_lowercase();
                if let Some(val) = status.get(&mask_bit_str)
                    && status_value_to_bool(val)?
                {
                    any_mask_bit_set = true;
                    mask |= mask_bit as u8;
                }
            }

            if any_mask_bit_set { mask } else { u8::MAX }
        } else {
            u8::MAX
        };

        for (read_info, lookup) in scoped_services {
            let mut payload = vec![mask];
            if read_info.is_user_scope() {
                payload.push(memory_selection.unwrap_or(0));
            }
            let payload = UdsPayloadData::Raw(payload);
            let response = self
                .send(
                    ecu_name,
                    lookup.service,
                    security_plugin,
                    Some(payload),
                    true,
                )
                .await?;

            let raw = response.get_raw();
            let active_dtcs = response.get_dtcs()?;

            let mut byte_pos = active_dtcs
                .first()
                .map(|(f, _)| f.byte_pos)
                .unwrap_or_default();
            for (field, record) in active_dtcs {
                // Skip bytes that are reserved for the DTC code.
                // The mask byte comes right after that.
                byte_pos = byte_pos.saturating_add(field.bit_len.div_ceil(8).saturating_add(1));
                let status_byte =
                    raw.get(byte_pos as usize)
                        .copied()
                        .ok_or(DiagServiceError::BadPayload(format!(
                            "Failed to get status byte for DTC {:X}",
                            record.code
                        )))?;

                all_dtcs.insert(
                    record.code,
                    DtcRecordAndStatus {
                        record,
                        scope: lookup.scope,
                        status: get_dtc_status_for_mask(status_byte),
                    },
                );
            }

            if mask == 0xFF || mask == 0x00 {
                for record in lookup.dtcs {
                    all_dtcs.entry(record.code).or_insert(DtcRecordAndStatus {
                        record,
                        scope: lookup.scope,
                        status: get_dtc_status_for_mask(0),
                    });
                }
            }
        }

        Ok(all_dtcs
            .into_iter()
            .filter(|(_code, dtc)| severity.as_ref().is_none_or(|s| dtc.record.severity <= *s))
            .collect())
    }

    async fn ecu_dtc_extended(
        &self,
        ecu_name: &str,
        security_plugin: &DynamicPlugin,
        sae_dtc: &str,
        include_extended_data: bool,
        include_snapshot: bool,
        include_schema: bool,
        memory_selection: Option<u8>,
    ) -> Result<DtcExtendedInfo, DiagServiceError> {
        let dtc_code = decode_dtc_from_str(sae_dtc)?;

        let mut dtc_by_mask: HashMap<DtcCode, DtcRecordAndStatus> = self
            .ecu_dtc_by_mask(
                ecu_name,
                security_plugin,
                None,
                None,
                None,
                memory_selection,
            )
            .await?;

        let record_and_status =
            dtc_by_mask
                .remove(&dtc_code)
                .ok_or(DiagServiceError::InvalidRequest(format!(
                    "DTC {sae_dtc} not found in ECU {ecu_name}"
                )))?;

        let scope = record_and_status.scope;
        let (snapshots, snapshot_schema) = if include_snapshot {
            self.map_snapshots(
                ecu_name,
                security_plugin,
                dtc_code,
                include_schema,
                memory_selection,
                scope,
            )
            .await?
        } else {
            (None, None)
        };

        let (extended_records, extended_schema) = if include_extended_data {
            self.map_extended_data(
                ecu_name,
                security_plugin,
                dtc_code,
                include_schema,
                memory_selection,
                scope,
            )
            .await?
        } else {
            (None, None)
        };

        Ok(DtcExtendedInfo {
            record_and_status,
            extended_data_records: extended_records,
            extended_data_records_schema: extended_schema,
            snapshots,
            snapshots_schema: snapshot_schema,
        })
    }

    async fn delete_dtcs(
        &self,
        ecu_name: &str,
        security_plugin: &DynamicPlugin,
        fault_code: Option<String>,
    ) -> Result<Self::Response, DiagServiceError> {
        let ecu = self.uds_ecu_db(ecu_name)?;
        let delete_dtc_service = ecu.read().await.lookup_service_through_func_class(
            "faultmem",
            service_ids::CLEAR_DIAGNOSTIC_INFORMATION,
        )?;
        ecu.read()
            .await
            .is_service_allowed(&delete_dtc_service, security_plugin)
            .await?;

        // For now only all or single DTC clear is supported.
        // This means we can simply build the payload according to ISO spec here.
        // Once we support clear by group we will need to lookup things from the db.
        let mut payload = vec![service_ids::CLEAR_DIAGNOSTIC_INFORMATION];
        match fault_code {
            Some(ref dtc_code) => {
                let dtc = decode_dtc_from_str(dtc_code)?;
                payload.extend(dtc.to_be_bytes()[1..].to_vec());
            }
            None => {
                payload.extend(DTC_GROUP_ALL);
            }
        }
        let (source_address, target_address) = {
            let read_lock = ecu.read().await;
            (read_lock.tester_address(), read_lock.logical_address())
        };
        let service_payload = ServicePayload {
            data: payload,
            source_address,
            target_address,
            new_security: None,
            new_session: None,
        };

        match self
            .send_with_raw_payload(ecu_name, service_payload, None, true)
            .await?
        {
            None => Err(DiagServiceError::NoResponse(
                "ECU did not respond to DTC clear".to_owned(),
            )),
            Some(resp) => T::convert_service_14_response(delete_dtc_service, resp),
        }
    }

    async fn delete_dtcs_scoped(
        &self,
        ecu_name: &str,
        security_plugin: &DynamicPlugin,
        scope: &str,
    ) -> Result<Self::Response, DiagServiceError> {
        let ecu = self.uds_ecu_db(ecu_name)?;

        // If the requested scope is the default scope, delegate to the standard delete_dtcs path.
        if scope.eq_ignore_ascii_case(&self.fault_config.default_scope) {
            return self.delete_dtcs(ecu_name, security_plugin, None).await;
        }

        // When a user-defined scope is provided, use the configured custom
        // clear service (e.g. RoutineControl 31 01 42 00) via `self.send`
        // which does not require any additional parameters, per definition.
        if !scope.eq_ignore_ascii_case(&self.fault_config.user_memory_scope) {
            return Err(DiagServiceError::InvalidParameter {
                possible_values: HashSet::from_iter([
                    self.fault_config.default_scope.clone(),
                    self.fault_config.user_memory_scope.clone(),
                ]),
            });
        }

        let user_defined_dtc_clear_service = self
            .fault_config
            .user_defined_dtc_clear_service
            .as_ref()
            .ok_or_else(|| {
                DiagServiceError::InvalidConfiguration(
                    "User defined DTC scope name is not set in the configuration, but custom \
                     scope clear is requested"
                        .to_owned(),
                )
            })?;

        let delete_dtc_service = ecu
            .read()
            .await
            .lookup_diagcomms_by_request_prefix(user_defined_dtc_clear_service)?
            .into_iter()
            .next()
            .ok_or_else(|| {
                DiagServiceError::InvalidConfiguration(format!(
                    "Unable to find service matching payload: \
                     {user_defined_dtc_clear_service:02X?}"
                ))
            })?;

        // validate that the service can be called via security plugin
        ecu.read()
            .await
            .is_service_allowed(&delete_dtc_service, security_plugin)
            .await?;

        self.send(ecu_name, delete_dtc_service, security_plugin, None, false)
            .await
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

fn status_value_to_bool(val: &serde_json::Value) -> Result<bool, DiagServiceError> {
    fn int_to_bool(int_val: u64) -> Result<bool, DiagServiceError> {
        if int_val != 0 && int_val != 1 {
            Err(DiagServiceError::InvalidRequest(
                "Invalid status value for mask bit must be 0 or 1 if using integers".to_owned(),
            ))
        } else {
            Ok(int_val == 1)
        }
    }
    match val {
        serde_json::Value::String(str_val) => {
            if let Ok(int_val) = str_val.parse::<u64>() {
                int_to_bool(int_val)
            } else if let Ok(bool_val) = str_val.parse::<bool>() {
                Ok(bool_val)
            } else {
                Err(DiagServiceError::InvalidRequest(
                    "Status value string is neither a valid integer nor boolean".to_owned(),
                ))
            }
        }
        serde_json::Value::Bool(bool_val) => Ok(*bool_val),
        serde_json::Value::Number(num_val) => {
            if let Some(int_val) = num_val.as_u64() {
                int_to_bool(int_val)
            } else {
                Err(DiagServiceError::InvalidRequest(
                    "Status value cannot be parsed as u64".to_owned(),
                ))
            }
        }
        _ => Err(DiagServiceError::InvalidRequest(
            "Status value must be a string, boolean or integer".to_owned(),
        )),
    }
}

macro_rules! check_flag {
    ($status_byte:expr, $flag:ident) => {
        ($status_byte & $flag) == $flag
    };
}

fn get_dtc_status_for_mask(mask: u8) -> datatypes::DtcStatus {
    let test_failed = DtcMask::TestFailed as u8;
    let test_failed_this_operation_cycle = DtcMask::TestFailedThisOperationCycle as u8;
    let pending_dtc = DtcMask::PendingDtc as u8;
    let confirmed_dtc = DtcMask::ConfirmedDtc as u8;
    let test_not_completed_since_last_clear = DtcMask::TestNotCompletedSinceLastClear as u8;
    let test_failed_since_last_clear = DtcMask::TestFailedSinceLastClear as u8;
    let test_not_completed_this_operation_cycle = DtcMask::TestNotCompletedThisOperationCycle as u8;
    let warning_indicator_requested = DtcMask::WarningIndicatorRequested as u8;

    datatypes::DtcStatus {
        test_failed: check_flag!(mask, test_failed),
        test_failed_this_operation_cycle: check_flag!(mask, test_failed_this_operation_cycle),
        pending_dtc: check_flag!(mask, pending_dtc),
        confirmed_dtc: check_flag!(mask, confirmed_dtc),
        test_not_completed_since_last_clear: check_flag!(mask, test_not_completed_since_last_clear),
        test_failed_since_last_clear: check_flag!(mask, test_failed_since_last_clear),
        test_not_completed_this_operation_cycle: check_flag!(
            mask,
            test_not_completed_this_operation_cycle
        ),
        warning_indicator_requested: check_flag!(mask, warning_indicator_requested),
        mask,
    }
}

impl<S: EcuGateway, T: EcuManager> SchemaProvider for UdsManager<S, T> {
    async fn schema_for_request(
        &self,
        ecu: &str,
        service: &DiagComm,
    ) -> Result<cda_interfaces::SchemaDescription, DiagServiceError> {
        self.uds_ecu_db(ecu)?
            .read()
            .await
            .schema_for_request(service)
            .await
    }

    async fn schema_for_responses(
        &self,
        ecu: &str,
        service: &DiagComm,
    ) -> Result<cda_interfaces::SchemaDescription, DiagServiceError> {
        self.uds_ecu_db(ecu)?
            .read()
            .await
            .schema_for_responses(service)
            .await
    }

    async fn schema_for_fg_request(
        &self,
        service: &DiagComm,
        functional_group_name: &str,
    ) -> Result<cda_interfaces::SchemaDescription, DiagServiceError> {
        self.uds_ecu_db(&self.functional_description_database)?
            .read()
            .await
            .schema_for_fg_request(service, functional_group_name)
            .await
    }
}

fn sae_to_dtc_code(sae_dtc: &str) -> Result<DtcCode, DiagServiceError> {
    if sae_dtc.len() != 7 {
        return Err(DiagServiceError::InvalidRequest(format!(
            "Invalid SAE dtc code '{sae_dtc}'"
        )));
    }

    // All urls are converted to lowercase, thus we do the same here,
    // even if SAE dtc codes are usually uppercase.
    let sae_dtc = sae_dtc.to_lowercase();

    // System
    // 00 - Powertrain (P)
    // 01 - Chassis (C)
    // 10 - Body (B)
    // 11 - Network Communications (U)
    let system = match sae_dtc
        .chars()
        .next()
        .ok_or(DiagServiceError::InvalidRequest(format!(
            "Invalid SAE dtc code '{sae_dtc}', missing system"
        )))? {
        'p' => 0,
        'c' => 1,
        'b' => 2,
        'u' => 3,
        _ => {
            return Err(DiagServiceError::InvalidRequest(format!(
                "Unknown system digit in SAE dtc code '{sae_dtc}'"
            )));
        }
    };

    // Group:
    // 00 - SAE/ISO Controlled (0)
    // 01 - Manufacturer Controlled (1)
    // 10 - For (P) SAE/ISO / Rest Manufacturer Controlled (2)
    // 11 - SAE/ISO Controlled (3)
    let group = match sae_dtc
        .chars()
        .nth(1)
        .ok_or(DiagServiceError::InvalidRequest(format!(
            "Invalid SAE dtc code '{sae_dtc}', missing group"
        )))? {
        '0' => 0,
        '1' => 1,
        '2' => 2,
        '3' => 3,
        _ => {
            return Err(DiagServiceError::InvalidRequest(format!(
                "Unknown group digit in SAE dtc code '{sae_dtc}'"
            )));
        }
    };

    let hex_part = sae_dtc.get(2..).ok_or_else(|| {
        DiagServiceError::InvalidRequest(format!(
            "Invalid SAE dtc code '{sae_dtc}', missing hex part"
        ))
    })?;
    let code = DtcCode::from_str_radix(hex_part, 16).map_err(|_| {
        DiagServiceError::InvalidRequest(format!(
            "Invalid hex characters in SAE dtc code '{sae_dtc}'"
        ))
    })?;

    Ok((system << 22) | (group << 20) | code)
}

fn decode_dtc_from_str(dtc_code: &str) -> Result<u32, DiagServiceError> {
    let code = match dtc_code.len() {
        6 | 8 => {
            // read as raw dtc bytes
            let mut dtc_bytes = vec![0u8];
            if dtc_code.len() == 6 {
                dtc_bytes.append(&mut util::decode_hex(dtc_code)?);
            } else {
                dtc_bytes.append(&mut util::decode_hex(dtc_code.trim_start_matches("0x"))?);
            }
            u32::from_be_bytes(dtc_bytes.try_into().map_err(|e| {
                DiagServiceError::InvalidRequest(format!(
                    "Failed to decode DTC code: {dtc_code}. Error: {e:?}"
                ))
            })?)
        }
        7 => sae_to_dtc_code(dtc_code)?,
        _ => {
            return Err(DiagServiceError::InvalidRequest(format!(
                "Invalid DTC format: {dtc_code}. Should be either SAE format or raw DTC code with \
                 optional 0x prefix."
            )));
        }
    };
    Ok(code)
}

fn check_sd_sdg_recursive(expected: &SdBoolMappings, sd_sdg: &SdSdg) -> bool {
    match sd_sdg {
        SdSdg::Sd { value, si, .. } => {
            let Some(sd) = si.as_ref().and_then(|v| expected.get(v)) else {
                return false;
            };
            value.as_ref().is_some_and(|v| sd.contains(v))
        }
        SdSdg::Sdg { sdgs, .. } => sdgs
            .iter()
            .any(|sdsdg| check_sd_sdg_recursive(expected, sdsdg)),
    }
}

#[cfg(test)]
mod tests {
    use cda_interfaces::{
        HashMap,
        datatypes::{DtcMask, SdMappingsTruthyValue, SdSdg},
    };
    use serde_json::json;

    use super::*;

    //Tests for SAE/ISO Diagnostic Trouble Code (DTC) conversion. (https://autodtcs.com/codes/#google_vignette)
    //
    // System
    // 00 - Powertrain (P)
    // 01 - Chassis (C)
    // 10 - Body (B)
    // 11 - Network Communications (U)
    //
    // Group:
    // 00 - SAE/ISO Controlled (0)
    // 01 - Manufacturer Controlled (1)
    // 10 - For (P) SAE/ISO / Rest Manufacturer Controlled (2)
    // 11 - SAE/ISO Controlled (3)
    //
    // You'll see bitfield shifts in some of the expected values below. That's because
    // `sae_to_dtc_code` packs its result as `(system << 22) | (group << 20) | code`,
    // so the system and group bits live at fixed positions in the u32. We rebuild the
    // expected value the same way to make sure each field lands in the right slot.
    // This allows us to compare the expected result with the received response

    #[test]
    fn test_sae_to_dtc_code_powertrain() {
        // P0420 - "Catalyst System Efficiency Below Threshold (Bank 1)"
        // Format: "P000420" -> system=0 (P), group=0, hex=0x00420
        assert_eq!(sae_to_dtc_code("P000420").unwrap(), 0x00420);

        // P0301 - "Cylinder 1 Misfire Detected"
        assert_eq!(sae_to_dtc_code("P000301").unwrap(), 0x00301);
    }

    #[test]
    fn test_sae_to_dtc_code_chassis() {
        // C0035 - "Left Front Wheel Speed Sensor Circuit"
        // Format: "C000035" -> system=1 (C), group=0, hex=0x00035
        assert_eq!(sae_to_dtc_code("C000035").unwrap(), (1u32 << 22) | 0x00035);
    }

    #[test]
    fn test_sae_to_dtc_code_body_generic() {
        // B0001 - "Driver Frontal Stage 1 Deployment Control"
        // Extended format: "B000001" -> system=2 (B), group=0, hex=0x00001
        assert_eq!(sae_to_dtc_code("B000001").unwrap(), (2u32 << 22) | 0x00001);
    }

    #[test]
    fn test_sae_to_dtc_code_body_manufacturer() {
        // B1000 - Manufacturer-specific Body code (e.g., "ECU Defective")
        // Extended format: "B100000" -> system=2 (B), group=1, hex=0x00000
        assert_eq!(
            sae_to_dtc_code("B100000").unwrap(),
            (2u32 << 22) | (1u32 << 20)
        );
    }

    #[test]
    fn test_sae_to_dtc_code_network() {
        // U0001 - "High Speed CAN Communication Bus"
        // Format: "U000001" -> system=3 (U), group=0, hex=0x00001
        assert_eq!(sae_to_dtc_code("U000001").unwrap(), (3u32 << 22) | 0x00001);
    }

    #[test]
    fn test_sae_to_dtc_code_lowercase() {
        // Function should handle lowercase input (calls .to_lowercase() internally)
        // P0420 in lowercase
        assert_eq!(sae_to_dtc_code("p000420").unwrap(), 0x00420);
    }

    #[test]
    fn test_sae_to_dtc_code_case_insensitive() {
        assert_eq!(
            sae_to_dtc_code("p000001").unwrap(),
            sae_to_dtc_code("P000001").unwrap()
        );
        assert_eq!(
            sae_to_dtc_code("u123456").unwrap(),
            sae_to_dtc_code("U123456").unwrap()
        );
    }

    #[test]
    fn test_sae_to_dtc_code_invalid_length() {
        // Standard 5-char SAE format is too short for this function
        assert!(sae_to_dtc_code("P0420").is_err());
        // Too long
        assert!(sae_to_dtc_code("P00042000").is_err());
        // Empty
        assert!(sae_to_dtc_code("P001").is_err());
        assert!(sae_to_dtc_code("P00001").is_err());
        assert!(sae_to_dtc_code("").is_err());
    }

    #[test]
    fn test_sae_to_dtc_code_invalid_system() {
        // 'X' is not a valid system letter (must be P/C/B/U)
        assert!(sae_to_dtc_code("X000420").is_err());
    }

    #[test]
    fn test_sae_to_dtc_code_invalid_group() {
        // '9' is not a valid group digit (must be 0-3)
        assert!(sae_to_dtc_code("P900420").is_err());
    }

    #[test]
    fn test_sae_to_dtc_code_invalid_hex() {
        // 'Z' is not a valid hex character
        assert!(sae_to_dtc_code("P00042Z").is_err());
    }

    #[test]
    fn test_status_value_to_bool_bool_values() {
        assert!(status_value_to_bool(&json!(true)).unwrap());
        assert!(!status_value_to_bool(&json!(false)).unwrap());
    }

    #[test]
    fn test_status_value_to_bool_number_valid() {
        assert!(!status_value_to_bool(&json!(0)).unwrap());
        assert!(status_value_to_bool(&json!(1)).unwrap());
    }

    #[test]
    fn test_status_value_to_bool_number_invalid() {
        assert!(status_value_to_bool(&json!(2)).is_err());
        assert!(status_value_to_bool(&json!(100)).is_err());
    }

    #[test]
    fn test_status_value_to_bool_string_bool() {
        assert!(status_value_to_bool(&json!("true")).unwrap());
        assert!(!status_value_to_bool(&json!("false")).unwrap());
    }

    #[test]
    fn test_status_value_to_bool_string_int_valid() {
        assert!(!status_value_to_bool(&json!("0")).unwrap());
        assert!(status_value_to_bool(&json!("1")).unwrap());
    }

    #[test]
    fn test_status_value_to_bool_string_int_invalid() {
        assert!(status_value_to_bool(&json!("2")).is_err());
    }

    #[test]
    fn test_status_value_to_bool_string_invalid() {
        assert!(status_value_to_bool(&json!("hello")).is_err());
    }

    #[test]
    fn test_status_value_to_bool_invalid_types() {
        assert!(status_value_to_bool(&json!(null)).is_err());
        assert!(status_value_to_bool(&json!([])).is_err());
        assert!(status_value_to_bool(&json!({})).is_err());
    }

    #[test]
    fn test_sae_to_dtc_code_valid_groups() {
        assert_eq!(sae_to_dtc_code("P000001").unwrap(), 0x0000_0001u32);
        assert_eq!(
            sae_to_dtc_code("P100001").unwrap(),
            (1u32 << 20) | 0x0000_0001u32
        );
        assert_eq!(
            sae_to_dtc_code("P200001").unwrap(),
            (2u32 << 20) | 0x0000_0001u32
        );
        assert_eq!(
            sae_to_dtc_code("P300001").unwrap(),
            (3u32 << 20) | 0x0000_0001u32
        );
    }

    #[test]
    fn test_decode_dtc_from_str_6_char() {
        assert_eq!(decode_dtc_from_str("001234").unwrap(), 0x0000_1234u32);
        assert_eq!(decode_dtc_from_str("FFFFFF").unwrap(), 0x00FF_FFFFu32);
    }

    #[test]
    fn test_decode_dtc_from_str_8_char_with_prefix() {
        assert_eq!(decode_dtc_from_str("0x123456").unwrap(), 0x0012_3456u32);
    }

    #[test]
    fn test_decode_dtc_from_str_sae_format() {
        let result = decode_dtc_from_str("P000001").unwrap();
        assert_eq!(result, sae_to_dtc_code("P000001").unwrap());
    }

    #[test]
    fn test_decode_dtc_from_str_invalid() {
        assert!(decode_dtc_from_str("12345").is_err());
        assert!(decode_dtc_from_str("00ZZZZ").is_err());
    }

    #[test]
    fn test_get_dtc_status_for_mask_zero() {
        let status = get_dtc_status_for_mask(0x00);
        assert!(!status.test_failed);
        assert!(!status.test_failed_this_operation_cycle);
        assert!(!status.pending_dtc);
        assert!(!status.confirmed_dtc);
        assert!(!status.test_not_completed_since_last_clear);
        assert!(!status.test_failed_since_last_clear);
        assert!(!status.test_not_completed_this_operation_cycle);
        assert!(!status.warning_indicator_requested);
    }

    #[test]
    fn test_get_dtc_status_for_mask_all() {
        let status = get_dtc_status_for_mask(0xFF);
        assert!(status.test_failed);
        assert!(status.test_failed_this_operation_cycle);
        assert!(status.pending_dtc);
        assert!(status.confirmed_dtc);
        assert!(status.test_not_completed_since_last_clear);
        assert!(status.test_failed_since_last_clear);
        assert!(status.test_not_completed_this_operation_cycle);
        assert!(status.warning_indicator_requested);
    }

    #[test]
    fn test_get_dtc_status_for_mask_individual_bits() {
        let status = get_dtc_status_for_mask(DtcMask::TestFailed as u8);
        assert!(status.test_failed);
        assert!(!status.pending_dtc);

        let status = get_dtc_status_for_mask(DtcMask::PendingDtc as u8);
        assert!(!status.test_failed);
        assert!(status.pending_dtc);

        let status = get_dtc_status_for_mask(DtcMask::ConfirmedDtc as u8);
        assert!(status.confirmed_dtc);

        let status = get_dtc_status_for_mask(DtcMask::WarningIndicatorRequested as u8);
        assert!(status.warning_indicator_requested);
    }

    #[test]
    fn test_get_dtc_status_for_mask_multiple_bits() {
        let status = get_dtc_status_for_mask(0x0F);
        assert!(status.test_failed);
        assert!(status.test_failed_this_operation_cycle);
        assert!(status.pending_dtc);
        assert!(status.confirmed_dtc);
        assert!(!status.test_not_completed_since_last_clear);
    }

    #[test]
    fn test_check_sd_sdg_recursive_sd_no_si() {
        let sd = SdSdg::Sd {
            value: Some("yes".to_string()),
            si: None,
            ti: None,
        };
        let expected: HashMap<String, SdMappingsTruthyValue> = HashMap::new();
        assert!(!check_sd_sdg_recursive(&expected, &sd));
    }

    #[test]
    fn test_check_sd_sdg_recursive_sd_si_not_in_expected() {
        let sd = SdSdg::Sd {
            value: Some("yes".to_string()),
            si: Some("unknown".to_string()),
            ti: None,
        };
        let mut expected: HashMap<String, SdMappingsTruthyValue> = HashMap::new();
        expected.insert(
            "key".to_string(),
            SdMappingsTruthyValue::new(["yes".to_string()].into_iter().collect(), false),
        );
        assert!(!check_sd_sdg_recursive(&expected, &sd));
    }

    #[test]
    fn test_check_sd_sdg_recursive_sd_match() {
        let sd = SdSdg::Sd {
            value: Some("yes".to_string()),
            si: Some("key".to_string()),
            ti: None,
        };
        let mut expected: HashMap<String, SdMappingsTruthyValue> = HashMap::new();
        expected.insert(
            "key".to_string(),
            SdMappingsTruthyValue::new(["yes".to_string()].into_iter().collect(), false),
        );
        assert!(check_sd_sdg_recursive(&expected, &sd));
    }

    #[test]
    fn test_check_sd_sdg_recursive_sd_no_match() {
        let sd = SdSdg::Sd {
            value: Some("no".to_string()),
            si: Some("key".to_string()),
            ti: None,
        };
        let mut expected: HashMap<String, SdMappingsTruthyValue> = HashMap::new();
        expected.insert(
            "key".to_string(),
            SdMappingsTruthyValue::new(["yes".to_string()].into_iter().collect(), false),
        );
        assert!(!check_sd_sdg_recursive(&expected, &sd));
    }

    #[test]
    fn test_check_sd_sdg_recursive_sd_value_none() {
        let sd = SdSdg::Sd {
            value: None,
            si: Some("key".to_string()),
            ti: None,
        };
        let mut expected: HashMap<String, SdMappingsTruthyValue> = HashMap::new();
        expected.insert(
            "key".to_string(),
            SdMappingsTruthyValue::new(["yes".to_string()].into_iter().collect(), false),
        );
        assert!(!check_sd_sdg_recursive(&expected, &sd));
    }

    #[test]
    fn test_check_sd_sdg_recursive_sdg_empty() {
        let sdg = SdSdg::Sdg {
            caption: None,
            si: None,
            sdgs: vec![],
        };
        let expected: HashMap<String, SdMappingsTruthyValue> = HashMap::new();
        assert!(!check_sd_sdg_recursive(&expected, &sdg));
    }

    #[test]
    fn test_check_sd_sdg_recursive_sdg_with_matching_sd() {
        let matching_sd = SdSdg::Sd {
            value: Some("yes".to_string()),
            si: Some("key".to_string()),
            ti: None,
        };
        let sdg = SdSdg::Sdg {
            caption: None,
            si: None,
            sdgs: vec![matching_sd],
        };
        let mut expected: HashMap<String, SdMappingsTruthyValue> = HashMap::new();
        expected.insert(
            "key".to_string(),
            SdMappingsTruthyValue::new(["yes".to_string()].into_iter().collect(), false),
        );
        assert!(check_sd_sdg_recursive(&expected, &sdg));
    }

    #[test]
    fn test_check_sd_sdg_recursive_sdg_nested() {
        let matching_sd = SdSdg::Sd {
            value: Some("yes".to_string()),
            si: Some("key".to_string()),
            ti: None,
        };
        let nested_sdg = SdSdg::Sdg {
            caption: None,
            si: None,
            sdgs: vec![matching_sd],
        };
        let outer_sdg = SdSdg::Sdg {
            caption: None,
            si: None,
            sdgs: vec![nested_sdg],
        };
        let mut expected: HashMap<String, SdMappingsTruthyValue> = HashMap::new();
        expected.insert(
            "key".to_string(),
            SdMappingsTruthyValue::new(["yes".to_string()].into_iter().collect(), false),
        );
        assert!(check_sd_sdg_recursive(&expected, &outer_sdg));
    }
}
