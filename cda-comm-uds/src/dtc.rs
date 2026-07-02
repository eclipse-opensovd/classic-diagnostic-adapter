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
    DiagServiceError, DynamicPlugin, EcuGateway, EcuManager, HashMap, HashMapExtensions, HashSet,
    PayloadDecoder, SchemaDescription, SchemaProvider, ServicePayload, UdsDtc, UdsTransport,
    datatypes::{
        self, DTC_CODE_BIT_LEN, DtcCode, DtcExtendedInfo, DtcMask, DtcReadInformationFunction,
        DtcRecordAndStatus, DtcSnapshot, ExtendedDataRecords, ExtendedSnapshots,
    },
    diagservices::{DiagServiceResponse, DiagServiceResponseType, UdsPayloadData},
    service_ids, util,
};
use strum::IntoEnumIterator;

use crate::UdsManager;

/// Record number requesting all records/all memory (ISO 14229-1).
const DTC_RECORD_NUMBER_ALL: u8 = 0xFF;

/// DTC group value for "clear all DTCs" (ISO 14229-1, D.1).
/// Sending `0xFFFFFF` as the group-of-DTC clears all groups.
const DTC_GROUP_ALL: [u8; 3] = [0xFF, 0xFF, 0xFF];

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

impl<S: EcuGateway, T: EcuManager> UdsManager<S, T> {
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

        let mut raw_payload =
            util::extract_bits(DTC_CODE_BIT_LEN as usize, 0, &dtc_code.to_be_bytes())?;
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
}

#[async_trait]
impl<S: EcuGateway, T: EcuManager> UdsDtc for UdsManager<S, T> {
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
}

#[cfg(test)]
mod tests {
    use cda_interfaces::datatypes::DtcMask;
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
}
