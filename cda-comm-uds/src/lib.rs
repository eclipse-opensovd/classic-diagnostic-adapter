/*
 * Copyright (c) 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
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
    sync::Arc,
    time::{Duration, Instant},
};

use cda_interfaces::{
    DiagComm, DiagCommType, DiagServiceError, DynamicPlugin, EcuGateway, EcuManager,
    FlashTransferStartParams, SchemaDescription, SchemaProvider, SecurityAccess, ServicePayload,
    TesterPresentControlMessage, TesterPresentMode, TesterPresentType, TransmissionParameters,
    UdsEcu, UdsResponse, datatypes,
    datatypes::{
        ComponentConfigurationsInfo, DTC_CODE_BIT_LEN, DataTransferError, DataTransferMetaData,
        DataTransferStatus, DtcCode, DtcExtendedInfo, DtcMask, DtcReadInformationFunction,
        DtcRecordAndStatus, DtcSnapshot, Ecu, ExtendedDataRecords, ExtendedSnapshots, Gateway,
        NetworkStructure, RetryPolicy,
    },
    diagservices::{DiagServiceResponse, DiagServiceResponseType, UdsPayloadData},
    service_ids,
};
use hashbrown::HashMap;
use strum::IntoEnumIterator;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt, BufReader},
    sync::{Mutex, RwLock, mpsc, watch},
    task::JoinHandle,
};

type EcuIdentifier = String;

struct UdsParameters {
    timeout_default: Duration,
    rc_21_retry_policy: RetryPolicy,
    rc_21_completion_timeout: Duration,
    rc_21_repeat_request_time: Duration,
    rc_78_retry_policy: RetryPolicy,
    rc_78_completion_timeout: Duration,
    rc_78_timeout: Duration,
    rc_94_completion_timeout: Duration,
    rc_94_retry_policy: RetryPolicy,
    rc_94_repeat_request_time: Duration,
}

struct EcuDataTransfer {
    meta_data: DataTransferMetaData,
    status_receiver: watch::Receiver<bool>,
    task: JoinHandle<()>,
}

pub struct TesterPresentTask {
    pub type_: TesterPresentType,
    pub task: JoinHandle<()>,
}

pub struct UdsManager<S: EcuGateway, R: DiagServiceResponse, T: EcuManager<Response = R>> {
    ecus: Arc<HashMap<String, RwLock<T>>>,
    gateway: S,
    data_transfers: Arc<Mutex<HashMap<EcuIdentifier, EcuDataTransfer>>>,
    tester_present_tasks: Arc<RwLock<HashMap<EcuIdentifier, TesterPresentTask>>>,
    _phantom: std::marker::PhantomData<R>,
}

impl<S: EcuGateway, R: DiagServiceResponse, T: EcuManager<Response = R>> UdsManager<S, R, T> {
    pub fn new(
        gateway: S,
        ecus: Arc<HashMap<String, RwLock<T>>>,
        mut variant_detection_receiver: mpsc::Receiver<Vec<String>>,
    ) -> Self {
        let manager = Self {
            ecus,
            gateway,
            data_transfers: Arc::new(Mutex::new(HashMap::new())),
            tester_present_tasks: Arc::new(RwLock::new(HashMap::new())),
            _phantom: std::marker::PhantomData,
        };

        let vd_uds_clone = manager.clone();
        cda_interfaces::spawn_named!("variant-detection-receiver", async move {
            while let Some(ecus) = variant_detection_receiver.recv().await {
                vd_uds_clone.start_variant_detection_for_ecus(ecus);
            }
        });

        manager
    }

    fn ecu_diag_service(&self, ecu_name: &str) -> Result<&RwLock<T>, DiagServiceError> {
        self.ecus
            .get(ecu_name)
            .ok_or(DiagServiceError::NotFound(Some(format!(
                "ECU {ecu_name} not found"
            ))))
    }

    #[tracing::instrument(
        skip(self, service, payload),
        fields(ecu_name, service_name = %service.name, has_payload = payload.is_some())
    )]
    async fn send_with_optional_timeout(
        &self,
        ecu_name: &str,
        service: DiagComm,
        security_plugin: &DynamicPlugin,
        payload: Option<UdsPayloadData>,
        map_to_json: bool,
        timeout: Option<Duration>,
    ) -> Result<R, DiagServiceError> {
        let start = Instant::now();
        tracing::debug!(service = ?service, payload = ?payload, "Sending UDS request");
        let ecu = self.ecu_diag_service(ecu_name)?;
        let payload = {
            let ecu = ecu.read().await;
            ecu.create_uds_payload(&service, security_plugin, payload)
                .await?
        };

        let payload_build_after = start.elapsed();

        let response = self
            .send_with_raw_payload(ecu_name, payload, timeout, true)
            .await;
        let response_after = start.elapsed().saturating_sub(payload_build_after);

        let response = match response {
            Ok(msg) => {
                self.ecu_diag_service(ecu_name)
                    .expect("ECU name has been already checked")
                    .read()
                    .await
                    .convert_from_uds(&service, &msg.expect("response expected"), map_to_json)
                    .await
            }
            Err(e) => Err(e),
        };

        let response_mapped = start
            .elapsed()
            .saturating_sub(payload_build_after)
            .saturating_sub(response_after);
        tracing::debug!(
            total_duration = ?start.elapsed(),
            payload_build_duration = ?payload_build_after,
            response_duration = ?response_after,
            mapping_duration = ?response_mapped,
            "UDS request timing breakdown"
        );

        response
    }

    // allowed for clarity, to make it clearer which of the loops is being continued
    #[allow(clippy::needless_continue)]
    #[tracing::instrument(
        skip(self, payload),
        fields(ecu_name, expect_response, payload_size = payload.data.len())
    )]
    async fn send_with_raw_payload(
        &self,
        ecu_name: &str,
        payload: ServicePayload,
        timeout: Option<Duration>,
        expect_response: bool,
    ) -> Result<Option<ServicePayload>, DiagServiceError> {
        let start = std::time::Instant::now();

        let ecu = self.ecu_diag_service(ecu_name)?;
        let (uds_params, transmission_params) = Self::ecu_send_params(ecu).await;

        let rx_timeout = timeout.unwrap_or(uds_params.timeout_default);
        let mut rx_timeout_next = None;

        // outer loop to retry sending frames, resend frames must deal with (N)ACK again
        let (response, sent_after) = 'send: loop {
            let (response_tx, mut response_rx) = mpsc::channel(2);
            self.gateway
                .send(
                    transmission_params.clone(),
                    payload.clone(),
                    response_tx,
                    expect_response,
                )
                .await?;
            let sent_after = start.elapsed();

            // responses might be disabled, i.e. for functional tester presents...
            if !expect_response {
                // ...but wait until the message was (n)ack'd
                response_rx.recv().await;
                return Ok(None);
            }

            // inner loop, deals with UDS frames only, i.e. used to read repeated frames
            // for response pending, without sending a new frame in between.
            let uds_result = 'read_uds_messages: loop {
                match tokio::time::timeout(
                    rx_timeout_next.unwrap_or(rx_timeout),
                    response_rx.recv(),
                )
                .await
                {
                    Ok(Some(result)) => {
                        match result {
                            Ok(Some(UdsResponse::Message(msg))) => {
                                break 'read_uds_messages Ok(msg);
                            }
                            Ok(Some(UdsResponse::BusyRepeatRequest(_))) => {
                                if let Err(e) = validate_timeout_by_policy(
                                    ecu_name,
                                    &uds_params.rc_21_retry_policy,
                                    &start.elapsed(),
                                    &uds_params.rc_21_completion_timeout,
                                ) {
                                    break 'read_uds_messages Err(e);
                                }

                                let sleep_time = uds_params.rc_21_repeat_request_time;
                                tracing::debug!(
                                    sleep_time = ?sleep_time,
                                    "BusyRepeatRequest received, resending after delay"
                                );
                                tokio::time::sleep(sleep_time).await;
                                continue 'send; // continue 'send, will resend the message
                            }
                            Ok(Some(UdsResponse::TemporarilyNotAvailable(_))) => {
                                if let Err(e) = validate_timeout_by_policy(
                                    ecu_name,
                                    &uds_params.rc_94_retry_policy,
                                    &start.elapsed(),
                                    &uds_params.rc_94_completion_timeout,
                                ) {
                                    break 'read_uds_messages Err(e);
                                }

                                let sleep_time = uds_params.rc_94_repeat_request_time;
                                tracing::debug!(
                                    sleep_time = ?sleep_time,
                                    "TemporarilyNotAvailable received, resending after delay"
                                );
                                tokio::time::sleep(sleep_time).await;
                                continue 'send; // continue 'send, will resend the message
                            }
                            Ok(Some(UdsResponse::ResponsePending(_))) => {
                                if let Err(e) = validate_timeout_by_policy(
                                    ecu_name,
                                    &uds_params.rc_78_retry_policy,
                                    &start.elapsed(),
                                    &uds_params.rc_78_completion_timeout,
                                ) {
                                    break 'read_uds_messages Err(e);
                                }
                                tracing::debug!(
                                    "ResponsePending received, continue waiting for final response"
                                );
                                rx_timeout_next = Some(uds_params.rc_78_timeout);
                                continue 'read_uds_messages; // continue reading UDS frames
                            }
                            Ok(response) => {
                                break 'read_uds_messages Err(
                                    DiagServiceError::UnexpectedResponse(Some(format!(
                                        "Unexpected response received: {response:?}"
                                    ))),
                                );
                            }
                            Err(e) => {
                                // i.e. happens when the response is a NACK
                                // or no (n)ack was received before timeout.
                                // The Gateway will handle these cases and only
                                // return this error if there is no recovery path left.
                                // The UdsManager cannot do anything else, so we
                                // just forward the error to the caller.
                                break 'read_uds_messages Err(e);
                            }
                        }
                    }
                    Ok(None) => {
                        tracing::warn!("None response received");
                        break 'read_uds_messages Err(DiagServiceError::UnexpectedResponse(Some(
                            "None response received".to_owned(),
                        )));
                    }
                    Err(_) => {
                        // error means the tokio::time::timeout
                        // elapsed before a response was received
                        break 'read_uds_messages Err(DiagServiceError::Timeout);
                    }
                }
            };
            break 'send (uds_result, sent_after);
        };

        let finish = start.elapsed().saturating_sub(sent_after);
        tracing::debug!(
            total_duration = ?start.elapsed(),
            send_duration = ?sent_after,
            receive_duration = ?finish,
            "Raw UDS request timing breakdown"
        );

        response.map(Option::from)
    }

    async fn ecu_send_params(ecu: &RwLock<T>) -> (UdsParameters, TransmissionParameters) {
        let (uds_params, transmission_params) = {
            let ecu = ecu.read().await;
            (
                UdsParameters {
                    timeout_default: ecu.timeout_default(),
                    rc_21_retry_policy: ecu.rc_21_retry_policy(),
                    rc_21_completion_timeout: ecu.rc_21_completion_timeout(),
                    rc_21_repeat_request_time: ecu.rc_21_repeat_request_time(),
                    rc_78_retry_policy: ecu.rc_78_retry_policy(),
                    rc_78_completion_timeout: ecu.rc_78_completion_timeout(),
                    rc_78_timeout: ecu.rc_78_timeout(),
                    rc_94_retry_policy: ecu.rc_94_retry_policy(),
                    rc_94_completion_timeout: ecu.rc_94_completion_timeout(),
                    rc_94_repeat_request_time: ecu.rc_94_repeat_request_time(),
                },
                TransmissionParameters {
                    gateway_address: ecu.logical_gateway_address(),
                    timeout_ack: ecu.diagnostic_ack_timeout(),
                    ecu_name: ecu.ecu_name(),
                    repeat_request_count_transmission: ecu.repeat_request_count_transmission(),
                },
            )
        };
        (uds_params, transmission_params)
    }

    #[tracing::instrument(
        skip(self, request, status_sender, reader),
        fields(ecu_name, transfer_length = length, request_name = %request.name)
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

        // we do not want to check the service on every execution, but it is be checked before
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

            let mut buf = Vec::with_capacity(/*block sequence counter*/ 1 + bytes_to_read);
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
                transfer.meta_data.acknowledged_bytes += bytes_to_read as u64;

                remaining_bytes -= bytes_to_read as u64;
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
                    self.ecu_diag_service(&control_msg.ecu)?
                        .read()
                        .await
                        .tester_present_time()
                };

                let mut uds = self.clone();
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
                        loop {
                            if let Err(e) = uds.send_tester_present(&control_msg).await {
                                tracing::error!(error = %e, "Failed to send tester present");
                            }
                            tokio::time::sleep(interval).await;
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

    async fn send_tester_present(
        &mut self,
        control_msg: &TesterPresentControlMessage,
    ) -> Result<(), DiagServiceError> {
        let payload = {
            let ecu = self.ecu_diag_service(&control_msg.ecu)?;
            let target_address = match &control_msg.type_ {
                TesterPresentType::Functional(_) => ecu.read().await.logical_functional_address(),
                TesterPresentType::Ecu(_) => ecu.read().await.logical_address(),
            };
            ServicePayload {
                data: vec![service_ids::TESTER_PRESENT, 0x80],
                source_address: ecu.read().await.tester_address(),
                target_address,
                new_session: None,
                new_security: None,
            }
        };

        match self
            .send_with_raw_payload(&control_msg.ecu, payload, None, false)
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    async fn request_extended_data(
        &self,
        ecu_name: &str,
        security_plugin: &DynamicPlugin,
        dtc_code: DtcCode,
        service_types: Vec<DtcReadInformationFunction>,
        include_schema: bool,
    ) -> Result<(R, String, Option<SchemaDescription>), DiagServiceError> {
        let ecu = self.ecu_diag_service(ecu_name)?;
        let (_, extended_data_lookup) = ecu
            .read()
            .await
            .lookup_dtc_services(service_types)?
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
        raw_payload.push(0xFF); // record number, 0xFF means all records or all memory
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

        let (extended_data_response, _scope, schema_desc) = self
            .request_extended_data(
                ecu_name,
                security_plugin,
                dtc_code,
                vec![
                    DtcReadInformationFunction::FaultMemoryExtDataRecordByDtcNumber,
                    DtcReadInformationFunction::UserMemoryDtcExtDataRecordByDtcNumber,
                ],
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
    ) -> Result<(Option<ExtendedSnapshots>, Option<serde_json::Value>), DiagServiceError> {
        fn extract_schema_properties(schema_desc: &SchemaDescription) -> Option<serde_json::Value> {
            let param_properties = schema_desc.get_param_properties()?;
            let mut schema = serde_json::Map::new();

            // Todo when solving #54: We are missing the mux case name in the schema.
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

        let (snapshot_data_response, _scope, schema_desc) = self
            .request_extended_data(
                ecu_name,
                security_plugin,
                dtc_code,
                vec![
                    DtcReadInformationFunction::FaultMemorySnapshotRecordByDtcNumber,
                    DtcReadInformationFunction::UserMemoryDtcSnapshotRecordByDtcNumber,
                ],
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

    async fn ecus_for_functional_group(&self, functional_group: &str) -> Vec<String> {
        let mut ecu_names = Vec::new();
        for (name, ecu) in self.ecus.iter() {
            let ecu_guard = ecu.read().await;
            if ecu_guard.logical_address() != ecu_guard.logical_gateway_address() {
                continue; // skip non gateway ECUs
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
}

impl<S: EcuGateway, R: DiagServiceResponse, T: EcuManager<Response = R>> Clone
    for UdsManager<S, R, T>
{
    fn clone(&self) -> Self {
        Self {
            ecus: Arc::clone(&self.ecus),
            gateway: self.gateway.clone(),
            data_transfers: Arc::clone(&self.data_transfers),
            tester_present_tasks: Arc::clone(&self.tester_present_tasks),
            _phantom: self._phantom,
        }
    }
}

impl<S: EcuGateway, R: DiagServiceResponse, T: EcuManager<Response = R>> UdsEcu
    for UdsManager<S, R, T>
{
    type Response = R;

    async fn get_ecus(&self) -> Vec<String> {
        self.ecus.keys().cloned().collect()
    }

    async fn get_network_structure(&self) -> NetworkStructure {
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
            let ecu_name = ecu.ecu_name();

            let variant = ecu
                .variant_name()
                .unwrap_or_else(|| "BaseVariant".to_owned());

            let logical_address_string =
                ecu.logical_address()
                    .to_be_bytes()
                    .iter()
                    .fold("0x".to_owned(), |mut out, b| {
                        let _ = write!(out, "{b:02x}");
                        out
                    });

            let gateway_addr = ecu.logical_gateway_address();
            let gateway = gateways
                .entry_ref(&GatewayAddress(gateway_addr))
                .or_insert(Gateway {
                    name: String::new(),
                    network_address: String::new(),
                    logical_address: String::new(),
                    ecus: Vec::new(),
                });

            if gateway_addr == ecu.logical_address() {
                // this is the gateway itself
                gateway.name.clone_from(&ecu_name);
                gateway.logical_address.clone_from(&logical_address_string);
                if let Some(gateway_network_address) =
                    self.gateway.get_gateway_network_address(gateway_addr).await
                {
                    gateway.network_address = gateway_network_address;
                } else {
                    tracing::warn!(
                        gateway_name = %ecu_name,
                        logical_address = %logical_address_string,
                        "No IP address found for gateway"
                    );
                }
            }

            gateway.ecus.push(Ecu {
                qualifier: ecu_name.clone(),
                variant: variant.clone(),
                state: ecu.state().to_string(),
                logical_address: logical_address_string,
                logical_link: format!("{}_on_{}", ecu_name, ecu.protocol().value()),
            });
        }

        NetworkStructure {
            functional_groups: vec![],
            gateways: gateways.into_iter().map(|(_, gateway)| gateway).collect(),
        }
    }

    async fn send_genericservice(
        &self,
        ecu_name: &str,
        security_plugin: &DynamicPlugin,
        payload: Vec<u8>,
        timeout: Option<Duration>,
    ) -> Result<Vec<u8>, DiagServiceError> {
        tracing::trace!(ecu_name = %ecu_name, payload = ?payload, "Sending raw UDS packet");

        let payload = self
            .ecu_diag_service(ecu_name)?
            .read()
            .await
            .check_genericservice(security_plugin, payload)?;

        match self
            .send_with_raw_payload(ecu_name, payload, timeout, true)
            .await?
        {
            Some(response) => Ok(response.data),
            None => Ok(Vec::new()),
        }
    }

    async fn get_sdgs(
        &self,
        ecu_name: &str,
        service: Option<&DiagComm>,
    ) -> Result<Vec<cda_interfaces::datatypes::SdSdg>, DiagServiceError> {
        self.ecu_diag_service(ecu_name)?
            .read()
            .await
            .sdgs(service)
            .await
    }

    async fn get_comparams(
        &self,
        ecu: &str,
    ) -> Result<cda_interfaces::datatypes::ComplexComParamValue, DiagServiceError> {
        self.ecu_diag_service(ecu)?.read().await.comparams()
    }

    async fn get_components_data_info(
        &self,
        ecu: &str,
    ) -> Result<Vec<cda_interfaces::datatypes::ComponentDataInfo>, DiagServiceError> {
        let items = self
            .ecu_diag_service(ecu)?
            .read()
            .await
            .get_components_data_info();

        Ok(items)
    }

    async fn get_components_configuration_info(
        &self,
        ecu: &str,
    ) -> Result<Vec<ComponentConfigurationsInfo>, DiagServiceError> {
        self.ecu_diag_service(ecu)?
            .read()
            .await
            .get_components_configurations_info()
    }

    async fn get_components_single_ecu_jobs_info(
        &self,
        ecu: &str,
    ) -> Result<Vec<cda_interfaces::datatypes::ComponentDataInfo>, DiagServiceError> {
        let items = self
            .ecus
            .get(ecu)
            .ok_or_else(|| DiagServiceError::NotFound(Some(format!("Unknown ECU: {ecu}"))))?
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
        self.ecu_diag_service(ecu)?
            .read()
            .await
            .lookup_single_ecu_job(job_name)
    }

    async fn send_with_timeout(
        &self,
        ecu_name: &str,
        service: DiagComm,
        security_plugin: &DynamicPlugin,
        payload: Option<UdsPayloadData>,
        map_to_json: bool,
        timeout: Duration,
    ) -> Result<R, DiagServiceError> {
        self.send_with_optional_timeout(
            ecu_name,
            service,
            security_plugin,
            payload,
            map_to_json,
            Some(timeout),
        )
        .await
    }

    async fn send(
        &self,
        ecu_name: &str,
        service: DiagComm,
        security_plugin: &DynamicPlugin,
        payload: Option<UdsPayloadData>,
        map_to_json: bool,
    ) -> Result<R, DiagServiceError> {
        self.send_with_optional_timeout(
            ecu_name,
            service,
            security_plugin,
            payload,
            map_to_json,
            None,
        )
        .await
    }

    async fn set_ecu_session(
        &self,
        ecu_name: &str,
        session: &str,
        security_plugin: &DynamicPlugin,
        expiration: Duration,
    ) -> Result<Self::Response, DiagServiceError> {
        tracing::info!(ecu_name = %ecu_name, session = %session, "Setting session");
        let ecu_diag_service = self.ecu_diag_service(ecu_name)?;
        let dc = ecu_diag_service
            .read()
            .await
            .lookup_session_change(session)?;
        let result = self.send(ecu_name, dc, security_plugin, None, true).await?;
        match result.response_type() {
            DiagServiceResponseType::Positive => {
                // update ecu DiagServiceManagers internal state.
                let ecu = ecu_diag_service.read().await;
                ecu.set_session(session, expiration)?;
                Ok(result)
            }
            DiagServiceResponseType::Negative => Ok(result),
        }
    }

    async fn set_ecu_security_access(
        &self,
        ecu_name: &str,
        level: &str,
        seed_service: Option<&String>,
        authentication_data: Option<UdsPayloadData>,
        security_plugin: &DynamicPlugin,
        expiration: Duration,
    ) -> Result<(SecurityAccess, R), DiagServiceError> {
        let ecu_diag_service = self.ecu_diag_service(ecu_name)?;
        let security_access = ecu_diag_service
            .read()
            .await
            .lookup_security_access_change(level, seed_service, authentication_data.is_some())?;
        match &security_access {
            SecurityAccess::RequestSeed(dc) => Ok((
                security_access.clone(),
                self.send(ecu_name, dc.clone(), security_plugin, None, false)
                    .await?,
            )),
            SecurityAccess::SendKey(dc) => {
                let result = self
                    .send(
                        ecu_name,
                        dc.clone(),
                        security_plugin,
                        authentication_data,
                        true,
                    )
                    .await?;
                match result.response_type() {
                    DiagServiceResponseType::Positive => {
                        // update ecu DiagServiceManagers internal state.
                        let ecu = ecu_diag_service.read().await;
                        ecu.set_security_access(level, expiration)?;
                        Ok((security_access, result))
                    }
                    DiagServiceResponseType::Negative => Ok((security_access, result)),
                }
            }
        }
    }

    async fn get_send_key_param_name(
        &self,
        ecu_name: &str,
        level: &str,
    ) -> Result<String, DiagServiceError> {
        let ecu_diag_service = self
            .ecus
            .get(ecu_name)
            .ok_or(DiagServiceError::NotFound(None))?;
        let security_access = ecu_diag_service
            .read()
            .await
            .lookup_security_access_change(level, None, true)?;
        match &security_access {
            SecurityAccess::RequestSeed(_) => {
                unreachable!("Not reached, because has key is set to true above")
            }
            SecurityAccess::SendKey(dc) => {
                let ecu = ecu_diag_service.read().await;
                ecu.get_send_key_param_name(dc).await
            }
        }
    }

    async fn get_ecu_reset_services(
        &self,
        ecu_name: &str,
    ) -> Result<Vec<String>, DiagServiceError> {
        let diag_manager = self.ecu_diag_service(ecu_name)?.read().await;

        let reset_services = diag_manager.lookup_service_names_by_sid(service_ids::ECU_RESET)?;
        drop(diag_manager);
        Ok(reset_services)
    }

    async fn ecu_session(&self, ecu_name: &str) -> Result<String, DiagServiceError> {
        let ecu_diag_service = self.ecu_diag_service(ecu_name)?;
        let ecu = ecu_diag_service.read().await;
        ecu.session()
    }

    async fn ecu_security_access(&self, ecu_name: &str) -> Result<String, DiagServiceError> {
        let ecu_diag_service = self.ecu_diag_service(ecu_name)?;
        let ecu = ecu_diag_service.read().await;
        ecu.security_access()
    }

    async fn ecu_exec_service_from_function_class(
        &self,
        ecu_name: &str,
        func_class_name: &str,
        service_id: u8,
        security_plugin: &DynamicPlugin,
        data: UdsPayloadData,
    ) -> Result<R, DiagServiceError> {
        let ecu_diag_service = self.ecu_diag_service(ecu_name)?;
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
        let ecu_diag_service = self.ecu_diag_service(ecu_name)?;
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
        // even if the data transfer job is done,
        // data_transfer_exit must be called before starting a new one
        if let Some(transfer) = self.data_transfers.lock().await.get(ecu_name) {
            return Err(DiagServiceError::InvalidRequest(format!(
                "Transfer data already running with id {}",
                transfer.meta_data.id
            )));
        }

        let file = File::open(file_path).await.map_err(|e| {
            DiagServiceError::InvalidRequest(format!("Failed to open file '{file_path}': {e:?}",))
        })?;

        let flash_file_meta_data = file.metadata().await.map_err(|e| {
            DiagServiceError::InvalidRequest(format!("Failed to get metadata: {e:?}"))
        })?;

        let file_size = flash_file_meta_data.len();
        if file_size < offset + length {
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

        let ecu = self.ecu_diag_service(ecu_name)?;
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
        let transfer = lock.get(ecu_name).ok_or(DiagServiceError::NotFound(None))?;
        if transfer.meta_data.id != id {
            return Err(DiagServiceError::NotFound(None));
        }

        if !matches!(
            transfer.meta_data.status,
            DataTransferStatus::Aborted | DataTransferStatus::Finished
        ) {
            return Err(DiagServiceError::InvalidRequest(format!(
                "Data transfer with id {id} is currently in status {:?}, cannot exit",
                transfer.meta_data.status,
            )));
        }

        let mut transfer = lock
            .remove(ecu_name)
            .ok_or(DiagServiceError::NotFound(None))?;

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
            .ok_or(DiagServiceError::NotFound(None))?;

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
            .ok_or(DiagServiceError::NotFound(None))
    }

    #[tracing::instrument(skip(self), err)]
    async fn detect_variant(&self, ecu_name: &str) -> Result<(), DiagServiceError> {
        let ecu = self.ecu_diag_service(ecu_name)?;

        let requests = ecu
            .read()
            .await
            .get_variant_detection_requests()
            .iter()
            .map(|req| {
                let name = req
                    .split_once('_')
                    .map_or(req.as_str(), |(name, _)| name)
                    .to_owned();

                let service = DiagComm {
                    name: name.clone(),
                    type_: DiagCommType::Data,
                    lookup_name: None,
                };
                Ok((req.to_owned(), service))
            })
            .collect::<Result<Vec<(String, DiagComm)>, DiagServiceError>>()?;

        if !ecu.read().await.is_loaded() {
            ecu.write().await.load().map_err(|e| {
                DiagServiceError::ResourceError(format!("Failed to load ECU data: {e:?}"))
            })?;
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

        ecu.write()
            .await
            .detect_variant(service_responses)
            .await
            .map_err(|e| {
                DiagServiceError::VariantDetectionError(format!("Failed to detect variant: {e:?}"))
            })?;

        Ok(())
    }

    async fn get_variant(&self, ecu_name: &str) -> Result<String, DiagServiceError> {
        let ecu = self.ecu_diag_service(ecu_name)?;

        let variant = ecu
            .read()
            .await
            .variant_name()
            .unwrap_or_else(|| "Unknown".to_owned());
        Ok(variant)
    }

    async fn start_variant_detection(&self) {
        // todo: (SCOPE = after PoC)
        // we should trigger requests for the ECUs
        // based on the logical address and not the name
        let mut ecus = Vec::new();
        for (ecu_name, db) in self.ecus.iter() {
            if let Err(DiagServiceError::EcuOffline(_)) =
                self.gateway.ecu_online(ecu_name, db).await
            {
                tracing::debug!(ecu_name = %ecu_name, "Skip variant detection: ECU offline");
                continue;
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
    ) -> Result<HashMap<DtcCode, DtcRecordAndStatus>, DiagServiceError> {
        let ecu = self.ecu_diag_service(ecu_name)?;
        let mut all_dtcs = HashMap::new();
        let scoped_services: Vec<_> = ecu
            .read()
            .await
            .lookup_dtc_services(vec![
                DtcReadInformationFunction::FaultMemoryByStatusMask,
                DtcReadInformationFunction::UserMemoryDtcByStatusMask,
            ])?
            .into_iter()
            .filter(|(_, lookup)| {
                scope
                    .as_ref()
                    .is_none_or(|scope| scope.to_lowercase() == lookup.scope.to_lowercase())
            })
            .collect();
        if scoped_services.is_empty() {
            return Err(DiagServiceError::RequestNotSupported(format!(
                "ECU {ecu_name} does not support fault memory {}",
                scope.map(|s| format!("for scope {s}")).unwrap_or_default()
            )));
        }

        let mask = if let Some(status) = status {
            let mut mask = 0x00_u8;
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

        for (_, lookup) in scoped_services {
            let payload = UdsPayloadData::Raw(vec![mask]);
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
                byte_pos += field.bit_len.div_ceil(8) + 1;
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
                        scope: lookup.scope.clone(),
                        status: get_dtc_status_for_mask(status_byte),
                    },
                );
            }

            if mask == 0xff || mask == 0x00 {
                for record in lookup.dtcs {
                    all_dtcs.entry(record.code).or_insert(DtcRecordAndStatus {
                        record,
                        scope: lookup.scope.clone(),
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
    ) -> Result<DtcExtendedInfo, DiagServiceError> {
        let dtc_code = sae_to_dtc_code(sae_dtc)?;

        let (snapshots, snapshot_schema) = if include_snapshot {
            self.map_snapshots(ecu_name, security_plugin, dtc_code, include_schema)
                .await?
        } else {
            (None, None)
        };

        let (extended_records, extended_schema) = if include_extended_data {
            self.map_extended_data(ecu_name, security_plugin, dtc_code, include_schema)
                .await?
        } else {
            (None, None)
        };

        let mut dtc_by_mask = self
            .ecu_dtc_by_mask(ecu_name, security_plugin, None, None, None)
            .await?;

        let record_and_status =
            dtc_by_mask
                .remove(&dtc_code)
                .ok_or(DiagServiceError::InvalidRequest(format!(
                    "DTC {sae_dtc} not found in ECU {ecu_name}"
                )))?;

        Ok(DtcExtendedInfo {
            record_and_status,
            extended_data_records: extended_records,
            extended_data_records_schema: extended_schema,
            snapshots,
            snapshots_schema: snapshot_schema,
        })
    }

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
                for name in self.ecus_for_functional_group(functional_group).await {
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
                for name in self.ecus_for_functional_group(functional_group).await {
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
                let ecu_names = self.ecus_for_functional_group(functional_group).await;
                let tester_presents = self.tester_present_tasks.read().await;
                ecu_names
                    .iter()
                    .all(|ecu| tester_presents.get(ecu).is_some())
            }
        }
    }

    async fn ecu_functional_groups(&self, ecu_name: &str) -> Result<Vec<String>, DiagServiceError> {
        let groups = self
            .ecus
            .get(ecu_name)
            .ok_or(DiagServiceError::NotFound(None))?
            .read()
            .await
            .functional_groups();
        Ok(groups)
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

impl<S: EcuGateway, R: DiagServiceResponse, T: EcuManager<Response = R>> SchemaProvider
    for UdsManager<S, R, T>
{
    async fn schema_for_request(
        &self,
        ecu: &str,
        service: &DiagComm,
    ) -> Result<cda_interfaces::SchemaDescription, DiagServiceError> {
        self.ecu_diag_service(ecu)?
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
        self.ecu_diag_service(ecu)?
            .read()
            .await
            .schema_for_responses(service)
            .await
    }
}

fn validate_timeout_by_policy(
    ecu_name: &str,
    policy: &RetryPolicy,
    elapsed: &Duration,
    completion_timeout: &Duration,
) -> Result<(), DiagServiceError> {
    match policy {
        RetryPolicy::Disabled => {
            tracing::debug!(ecu_name = %ecu_name, "Disabled busy repeat policy, aborting");
            Err(DiagServiceError::Timeout)
        }
        RetryPolicy::ContinueUntilTimeout => {
            if elapsed > completion_timeout {
                tracing::warn!(ecu_name = %ecu_name, "Busy repeat took too long, aborting");
                Err(DiagServiceError::Timeout)
            } else {
                tracing::debug!(ecu_name = %ecu_name, "Received busy repeat request, retrying");
                Ok(())
            }
        }
        RetryPolicy::ContinueUnlimited => {
            tracing::debug!(
                ecu_name = %ecu_name,
                "Received busy repeat request, retrying with unlimited retries"
            );
            Ok(())
        }
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

    let hex_part = &sae_dtc[2..];
    let code = DtcCode::from_str_radix(hex_part, 16).map_err(|_| {
        DiagServiceError::InvalidRequest(format!(
            "Invalid hex characters in SAE dtc code '{sae_dtc}'"
        ))
    })?;

    Ok((system << 22) | (group << 20) | code)
}
