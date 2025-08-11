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

use std::{sync::Arc, time::Duration};

use cda_database::datatypes::{
    self, DataOperation, DataType, DiagCodedTypeVariant, DiagnosticDatabase, DiagnosticService,
    LogicalAddressType, MuxDop, StateChart, resolve_comparam,
};
use cda_interfaces::{
    DiagComm, DiagCommAction, DiagCommType, DiagServiceError, EcuAddressProvider, EcuState,
    Protocol, STRINGS, SecurityAccess, ServicePayload,
    datatypes::{
        AddressingMode, ComParams, ComplexComParamValue, ComponentConfigurationsInfo,
        ComponentDataInfo, DatabaseNamingConvention, RetryPolicy, SdSdg, TesterPresentSendType,
        semantics, single_ecu,
    },
    diagservices::{DiagServiceResponse, DiagServiceResponseType, UdsPayloadData},
    get_string, get_string_from_option, get_string_from_option_with_default,
    get_string_with_default, service_ids, spawn_named, util,
};
use hashbrown::{HashMap, HashSet};
use parking_lot::Mutex;
use tokio::task::JoinHandle;

use crate::diag_kernel::{
    Variant,
    diagservices::{
        DiagDataTypeContainer, DiagDataTypeContainerRaw, DiagServiceResponseStruct,
        MappedDiagServiceResponsePayload,
    },
    into_db_protocol,
    operations::{self, json_value_to_uds_data},
    payload::Payload,
    variant_detection,
};

pub struct EcuManager {
    pub(crate) ecu_data: DiagnosticDatabase,
    database_naming_convention: DatabaseNamingConvention,
    tester_address: u16,
    logical_address: u16,
    logical_gateway_address: u16,
    logical_functional_address: u16,

    nack_number_of_retries: HashMap<u8, u32>,
    diagnostic_ack_timeout: Duration,
    retry_period: Duration,
    routing_activation_timeout: Duration,
    repeat_request_count_transmission: u32,
    connection_timeout: Duration,
    connection_retry_delay: Duration,
    connection_retry_attempts: u32,

    variant_detection: variant_detection::VariantDetection,
    variant: Option<Variant>,
    state: EcuState,
    protocol: Protocol,
    access_control: Arc<Mutex<SessionControl>>,

    tester_present_retry_policy: bool,
    tester_present_addr_mode: AddressingMode,
    tester_present_response_expected: bool,
    tester_present_send_type: TesterPresentSendType,
    tester_present_message: Vec<u8>,
    tester_present_exp_pos_resp: Vec<u8>,
    tester_present_exp_neg_resp: Vec<u8>,
    tester_present_time: Duration,
    repeat_req_count_app: u32,
    rc_21_retry_policy: RetryPolicy,
    rc_21_completion_timeout: Duration,
    rc_21_repeat_request_time: Duration,
    rc_78_retry_policy: RetryPolicy,
    rc_78_completion_timeout: Duration,
    rc_78_timeout: Duration,
    rc_94_retry_policy: RetryPolicy,
    rc_94_completion_timeout: Duration,
    rc_94_repeat_request_time: Duration,
    timeout_default: Duration,
}

struct SessionControl {
    session: cda_interfaces::Id,
    security: cda_interfaces::Id,
    /// resets session and or security access back to the default
    /// after a given time
    access_reset_task: Option<JoinHandle<()>>,
}

impl cda_interfaces::EcuAddressProvider for EcuManager {
    fn tester_address(&self) -> u16 {
        self.tester_address
    }

    fn logical_address(&self) -> u16 {
        self.logical_address
    }

    fn logical_gateway_address(&self) -> u16 {
        self.logical_gateway_address
    }

    fn logical_functional_address(&self) -> u16 {
        self.logical_functional_address
    }

    fn ecu_name(&self) -> String {
        self.ecu_data.ecu_name.clone()
    }
}

impl cda_interfaces::EcuManager for EcuManager {
    type Response = DiagServiceResponseStruct;

    fn variant_name(&self) -> Option<String> {
        self.variant.as_ref().map(|v| v.name.clone())
    }

    fn state(&self) -> EcuState {
        self.state
    }

    fn protocol(&self) -> Protocol {
        self.protocol
    }

    fn is_loaded(&self) -> bool {
        self.ecu_data.is_loaded()
    }

    /// This allows to (re)load a database after unloading it during runtime, which could happen
    /// if initially the ECU wasn´t responding but later another request
    /// for reprobing the ECU happens.
    ///
    /// # Errors
    /// Will return `Err` if during runtime the ECU file has been removed or changed
    /// in a way that the error causes mentioned in `Self::new` occur.
    fn load(&mut self) -> Result<(), DiagServiceError> {
        self.ecu_data.load()
    }

    #[tracing::instrument(
        target = "variant detection check",
        skip(self, service_responses),
        fields(ecu_name = self.ecu_data.ecu_name),
    )]
    fn detect_variant<T: DiagServiceResponse + Sized>(
        &mut self,
        service_responses: HashMap<String, T>,
    ) -> Result<(), DiagServiceError> {
        if service_responses.is_empty() {
            self.state = EcuState::Offline;
            return Ok(());
        }
        self.state = EcuState::Online;
        let variant_id = self.variant_detection.evaluate_variant(service_responses)?;
        match self
            .ecu_data
            .variants
            .get(&variant_id)
            .map(|v| Variant {
                name: v.short_name.clone(),
                id: variant_id,
            })
            .ok_or_else(|| {
                DiagServiceError::VariantDetectionError(format!(
                    "Variant ID {variant_id} not found in DB"
                ))
            }) {
            Ok(v) => {
                log::info!(target: &self.ecu_data.ecu_name, "Detected variant: {}", v.name);
                log::debug!(target: &self.ecu_data.ecu_name, "Internal ID: {}", v.id);
                if let Err(e) = self.ecu_data.load_variant_sdgs(v.id) {
                    log::warn!(
                        target: &self.ecu_data.ecu_name,
                        "Error loading variant SDGs: {e:?}"
                    );
                }
                self.variant = Some(v);

                // todo read this from the variant detection instead of assuming default, see #110
                let mut access = self.access_control.lock();
                access.security = self.default_state(semantics::SECURITY)?;
                access.session = self.default_state(semantics::SESSION)?;

                Ok(())
            }
            Err(e) => {
                log::debug!(target: &self.ecu_data.ecu_name, "No Variant detected..Unload DB");
                self.ecu_data.unload();
                Err(e)
            }
        }
    }

    fn get_variant_detection_requests(&self) -> &HashSet<String> {
        &self.variant_detection.diag_service_requests
    }

    fn comparams(&self) -> ComplexComParamValue {
        let mut comparams = HashMap::new();

        // ensure base variant is handled first
        // and maybe be overwritten by variant specific comparams
        let variants = [
            Some(self.ecu_data.base_variant_id),
            self.variant.as_ref().map(|v| v.id),
        ];

        let protocol_id = self
            .ecu_data
            .protocols
            .iter()
            .find_map(|(id, protocol)| {
                if STRINGS
                    .get(protocol.short_name)
                    .is_some_and(|p| p == self.protocol.value())
                {
                    Some(id)
                } else {
                    None
                }
            })
            .expect("Protocol not found in DB");

        variants
            .iter()
            .filter_map(|maybe_id| maybe_id.and_then(|id| self.ecu_data.variants.get(&id)))
            .flat_map(|v| &v.com_params)
            .filter(|cp| cp.protocol_id == Some(*protocol_id))
            .for_each(|cp| match resolve_comparam(&self.ecu_data, cp) {
                Ok((name, value)) => {
                    comparams.insert(name, value);
                }
                Err(e) => {
                    log::warn!(target: &self.ecu_data.ecu_name, "Error resolving ComParam: {e:?}");
                }
            });

        comparams
    }

    fn sdgs(&self, service: Option<&DiagComm>) -> Result<Vec<SdSdg>, DiagServiceError> {
        fn map_sd_sdg(
            ecu_data: &datatypes::DiagnosticDatabase,
            sd_or_sdg_ref: &datatypes::SdOrSdgRef,
        ) -> Option<SdSdg> {
            match sd_or_sdg_ref {
                datatypes::SdOrSdgRef::Sd(id) => ecu_data.sds.get(id).map(|sd| SdSdg::Sd {
                    value: sd.value.and_then(|value| STRINGS.get(value)),
                    si: sd.si.and_then(|si| STRINGS.get(si)),
                    ti: sd.ti.and_then(|ti| STRINGS.get(ti)),
                }),
                datatypes::SdOrSdgRef::Sdg(id) => ecu_data.sdgs.get(id).map(|sdg| SdSdg::Sdg {
                    caption: sdg.caption.and_then(|caption| STRINGS.get(caption)),
                    si: sdg.si.and_then(|si| STRINGS.get(si)),
                    sdgs: sdg
                        .sdgs
                        .iter()
                        .filter_map(|sd_or_sdg| map_sd_sdg(ecu_data, sd_or_sdg))
                        .collect(),
                }),
            }
        }

        let ids = if let Some(service) = service {
            self.lookup_diag_comm(service)
                .map(|service| service.sdgs.clone())
                .unwrap_or_default()
        } else {
            self.variant
                .as_ref()
                .and_then(|v| self.ecu_data.variants.get(&v.id).map(|v| v.sdgs.clone()))
                .or_else(|| {
                    self.ecu_data
                        .variants
                        .get(&self.ecu_data.base_variant_id)
                        .map(|v| v.sdgs.clone())
                })
                .ok_or_else(|| DiagServiceError::InvalidDatabase("No SDG found in DB".to_owned()))?
        };

        let mapped = ids
            .iter()
            .filter_map(|sdg_id| {
                self.ecu_data.sdgs.get(sdg_id).map(|sdg| SdSdg::Sdg {
                    caption: sdg.caption.and_then(|caption| STRINGS.get(caption)),
                    si: sdg.si.and_then(|si| STRINGS.get(si)),
                    sdgs: sdg
                        .sdgs
                        .iter()
                        .filter_map(|sd_or_sdg| map_sd_sdg(&self.ecu_data, sd_or_sdg))
                        .collect(),
                })
            })
            .collect();

        Ok(mapped)
    }

    /// Convert a UDS payload given as `u8` slice into a `DiagServiceResponse`.
    ///
    /// # Errors
    /// Will return `Err` in cases where the payload doesn´t match the expected UDS response, or if
    /// elements of the response cannot be correctly mapped from the raw data.
    #[tracing::instrument(
        target = "convert_from_uds",
        skip(self, diag_service, raw_payload),
        fields(
            ecu_name = self.ecu_data.ecu_name,
            service = diag_service.name,
            input = util::tracing::print_hex(raw_payload, 10),
            output = tracing::field::Empty,
        ),
        err
    )]
    fn convert_from_uds(
        &self,
        diag_service: &DiagComm,
        raw_payload: &[u8],
        map_to_json: bool,
    ) -> Result<DiagServiceResponseStruct, DiagServiceError> {
        let mapped_service = self.lookup_diag_comm(diag_service)?;
        let mut uds_payload = Payload::new(raw_payload);
        let sid = uds_payload
            .first()
            .ok_or_else(|| DiagServiceError::BadPayload("Missing SID".to_owned()))?
            .to_string();

        let responses = self
            .ecu_data
            .responses
            .iter()
            .filter(|(id, _)| {
                mapped_service.pos_responses.iter().any(|pr| pr == *id)
                    || mapped_service.neg_responses.iter().any(|nr| nr == *id)
            })
            .map(|(_, r)| -> Result<_, DiagServiceError> {
                let response_type = r.response_type;
                let mut params: Vec<&datatypes::Parameter> = r
                    .params
                    .iter()
                    .map(|param_ref| self.param_lookup(*param_ref))
                    .collect::<Result<Vec<_>, DiagServiceError>>()?;
                params.sort_by(|a, b| a.byte_pos.cmp(&b.byte_pos).then(a.bit_pos.cmp(&b.bit_pos)));

                Ok((response_type, params))
            })
            .collect::<Result<Vec<_>, DiagServiceError>>()?;

        let mut data = HashMap::new();

        if let Some((t, params)) = responses.iter().find(|(_, params)| {
            params.iter().any(|p| {
                p.byte_pos == 0u32
                    && match p.value {
                        datatypes::ParameterValue::CodedConst(ref c) => {
                            STRINGS.get(c.value) == Some(sid.clone())
                        }
                        _ => false,
                    }
            })
        }) {
            let raw_uds_payload = {
                let base_offset = params
                    .iter()
                    .find(|p| {
                        p.semantic
                            .and_then(|sem| STRINGS.get(sem))
                            .is_some_and(|semantic| semantic == semantics::DATA)
                    })
                    .map_or(0, |p| p.byte_pos);
                &uds_payload.data()[base_offset as usize..]
            }
            .to_vec();
            if *t == datatypes::ResponseType::Positive && !map_to_json {
                return Ok(DiagServiceResponseStruct {
                    service: diag_service.clone(),
                    data: raw_uds_payload,
                    mapped_data: None,
                    response_type: DiagServiceResponseType::Positive,
                });
            }
            for param in params.iter() {
                let semantic = param.semantic.and_then(|sem| STRINGS.get(sem));
                if semantic.is_some_and(|semantic| {
                    semantic != semantics::DATA && semantic != semantics::SERVICEIDRQ
                }) {
                    continue;
                }
                let short_name = STRINGS.get(param.short_name).ok_or_else(|| {
                    DiagServiceError::InvalidDatabase(format!(
                        "Unable to find short name for param: {}",
                        param.short_name
                    ))
                })?;
                self.map_param_from_uds(
                    mapped_service,
                    param,
                    &short_name,
                    &mut uds_payload,
                    &mut data,
                )?;
            }
            let resp = match t {
                datatypes::ResponseType::Negative | datatypes::ResponseType::GlobalNegative => {
                    DiagServiceResponseStruct {
                        service: diag_service.clone(),
                        data: raw_uds_payload,
                        mapped_data: Some(data),
                        response_type: DiagServiceResponseType::Negative,
                    }
                }
                datatypes::ResponseType::Positive => DiagServiceResponseStruct {
                    service: diag_service.clone(),
                    data: raw_uds_payload,
                    mapped_data: Some(data),
                    response_type: DiagServiceResponseType::Positive,
                },
            };
            tracing::Span::current()
                .record("output", format!("Response: {:?}", resp.response_type));

            Ok(resp)
        } else {
            Err(DiagServiceError::UdsLookupError(format!(
                "No matching response found for Service ID {sid}"
            )))
        }
    }

    /// Converts given `UdsPayloadData` into a UDS request payload for the given `DiagService`.
    ///
    /// # Errors
    /// Will return `Err` in cases where the `UdsPayloadData` doesn´t provide required parameters
    /// for the `DiagService` request or if elements of the `UdsPayloadData` cannot be mapped to
    /// the raw UDS bytestream.
    #[tracing::instrument(
        target = "create_uds_payload",
        skip(self, diag_service, data),
        fields(
            ecu_name = self.ecu_data.ecu_name,
            service = diag_service.name,
            action = diag_service.action.to_string(),
            input = data.as_ref().map_or_else(|| "None".to_owned(), ToString::to_string),
            output = tracing::field::Empty
        ),
        err
    )]
    fn create_uds_payload(
        &self,
        diag_service: &DiagComm,
        data: Option<UdsPayloadData>,
    ) -> Result<ServicePayload, DiagServiceError> {
        let mapped_service = self.lookup_diag_comm(diag_service)?;
        let request = self
            .ecu_data
            .requests
            .get(&mapped_service.request_id)
            .ok_or(DiagServiceError::RequestNotSupported)?;

        let mut mapped_params = request
            .params
            .iter()
            .map(|param_ref| {
                self.ecu_data
                    .params
                    .get(param_ref)
                    .ok_or(DiagServiceError::InvalidDatabase(
                        "Unable to find all parameters for request".to_owned(),
                    ))
            })
            .collect::<Result<Vec<_>, DiagServiceError>>()?;

        mapped_params.sort_by(|a, b| a.byte_pos.cmp(&b.byte_pos).then(a.bit_pos.cmp(&b.bit_pos)));

        let mut uds: Vec<u8> = Vec::new();

        let mut num_consts = 0;
        for param in &mapped_params {
            match param.value {
                datatypes::ParameterValue::CodedConst(ref coded_const) => {
                    num_consts += 1;
                    let diag_type = self
                        .ecu_data
                        .diag_coded_types
                        .get(&coded_const.diag_coded_type)
                        .ok_or(DiagServiceError::InvalidDatabase(format!(
                            "Could not lookup DiagCodedType for param: {}",
                            param.short_name
                        )))?;

                    let coded_const_value = STRINGS.get(coded_const.value).ok_or_else(|| {
                        DiagServiceError::InvalidDatabase(format!(
                            "Unable to find coded const value for param: {}",
                            param.short_name
                        ))
                    })?;

                    let uds_val = operations::diag_coded_type_to_uds(
                        diag_type.base_datatype,
                        &coded_const_value,
                    )?;

                    match diag_type.type_ {
                        datatypes::DiagCodedTypeVariant::LeadingLengthInfo(ref val) => {
                            let byte_len = (val / 8).max(1) as usize;
                            uds.extend(&uds_val[uds_val.len() - byte_len..]);
                        }
                        datatypes::DiagCodedTypeVariant::MinMaxLength(_) => {
                            todo!("what type is min/max length?? bits, bytes? sausages?")
                        }
                        datatypes::DiagCodedTypeVariant::StandardLength(ref val) => {
                            let byte_len = (val.bit_length / 8).max(1) as usize;
                            if let Some(mask) = &val.bitmask {
                                for i in uds_val.len() - byte_len..uds_val.len() {
                                    uds.push(uds_val[i] & mask[i]);
                                }
                            } else {
                                uds.extend(&uds_val[uds_val.len() - byte_len..]);
                            }
                        }
                    }
                }
                // skip for now. maybe validate payload according to params and their constraints?
                _ => break,
            }
        }
        if let Some(data) = data {
            match data {
                UdsPayloadData::Raw(bytes) => uds.extend(bytes),
                UdsPayloadData::ParameterMap(json_values) => {
                    // todo: check if json_values is empty...
                    for param in mapped_params.iter().skip(num_consts) {
                        if uds.len() < param.byte_pos as usize {
                            uds.extend(vec![0x0; param.byte_pos as usize - uds.len()]);
                        }
                        let short_name = STRINGS.get(param.short_name).ok_or_else(|| {
                            DiagServiceError::InvalidDatabase(format!(
                                "Unable to find short name for param: {}",
                                param.short_name
                            ))
                        })?;
                        if let Some(value) = json_values.get(&short_name)
                            && let Some(uds_val) = self.map_param_to_uds(param, value)?
                        {
                            operations::extend_with_bit_pos(
                                &mut uds,
                                uds_val,
                                param.bit_pos as usize,
                            );
                        }
                    }
                }
            }
        }
        let sec_ctrl = self.access_control.lock();
        let new_session = mapped_service.transitions.get(&sec_ctrl.session);
        let new_sec = mapped_service.transitions.get(&sec_ctrl.security);
        drop(sec_ctrl);

        tracing::Span::current().record("output", util::tracing::print_hex(&uds, 10));
        Ok(ServicePayload {
            data: uds,
            source_address: self.tester_address,
            target_address: self.logical_address,
            new_session_id: new_session.copied(),
            new_security_access_id: new_sec.copied(),
        })
    }

    /// Looks up a single ECU job by name for the current ECU variant.
    /// # Errors
    /// Will return `Err` if the job cannot be found in the database
    /// Unlikely other case is that neither a lookup in the current nor the base variant succeeded.
    fn lookup_single_ecu_job(&self, job_name: &str) -> Result<single_ecu::Job, DiagServiceError> {
        let log_target = format!("Lookup Single ECU Job [{}].[{job_name}]", self.ecu_name());
        log::debug!(target: &log_target, "Looking job");

        self.variant
            .as_ref()
            .and_then(|variant| {
                self.ecu_data
                    .variants
                    .get(&variant.id)
                    .and_then(|variant| variant.single_ecu_job_lookup.get(job_name))
            })
            .or(self.ecu_data.base_single_ecu_job_lookup.get(job_name))
            .ok_or(DiagServiceError::NotFound)
            .and_then(|id| {
                self.ecu_data
                    .single_ecu_jobs
                    .get(id)
                    .ok_or_else(|| {
                        // this should not happen, there should always be a base variant.
                        log::warn!(
                            target: &log_target,
                            "job reference could not be resolved to a job"
                        );
                        DiagServiceError::NotFound
                    })
                    .map(std::convert::Into::into)
            })
    }

    /// Lookup a service by a given function class name and service id.
    /// # Errors
    /// Will return `Err` if the lookup failed
    fn lookup_service_through_func_class(
        &self,
        func_class_name: &str,
        service_id: u8,
    ) -> Result<DiagComm, DiagServiceError> {
        self.ecu_data
            .functional_classes_lookup
            .get(func_class_name)
            .ok_or(DiagServiceError::NotFound)
            .and_then(|fc| {
                fc.services
                    .get(&u32::from(service_id))
                    .ok_or(DiagServiceError::NotFound)
                    .map(std::convert::Into::into)
            })
    }

    /// Lookup a service by its service id for the current ECU variant.
    /// This will first look up the service in the current variant, then in the base variant
    /// # Errors
    /// Will return `Err` if either the variant or base variant cannot be resolved.
    fn lookup_service_by_sid(&self, service_id: u8) -> Result<Vec<String>, DiagServiceError> {
        let variant = self
            .variant
            .as_ref()
            .and_then(|v| self.ecu_data.variants.get(&v.id))
            .or_else(|| self.ecu_data.variants.get(&self.ecu_data.base_variant_id))
            .ok_or(DiagServiceError::NotFound)?;

        let base_variant = self
            .ecu_data
            .variants
            .get(&self.ecu_data.base_variant_id)
            .ok_or(DiagServiceError::NotFound)?;

        let service_ids = variant.services.iter().chain(base_variant.services.iter());
        let services = service_ids
            .filter_map(|id| {
                self.ecu_data.services.get(id).and_then(|service| {
                    if service.service_id == service_id {
                        STRINGS.get(service.short_name)
                    } else {
                        None
                    }
                })
            })
            .collect::<Vec<_>>();

        Ok(services)
    }

    fn get_components_data_info(&self) -> Vec<ComponentDataInfo> {
        self.ecu_data
            .services
            .iter()
            .filter_map(|(_, service)| {
                if get_string!(service.short_name)
                    .map(|short_name| short_name.ends_with("_Read"))
                    .inspect_err(|e| log::error!("{e}"))
                    != Ok(true)
                {
                    return None;
                }
                Some(ComponentDataInfo {
                    category: get_string_with_default!(service.semantic, |semantic| {
                        semantic.to_lowercase()
                    }),
                    id: get_string_with_default!(service.short_name, |short_name| {
                        short_name.replace("_Read", "").to_lowercase()
                    }),
                    name: get_string_from_option_with_default!(service.long_name, |long_name| {
                        long_name.replace(" Read", "")
                    }),
                })
            })
            .collect()
    }

    fn get_components_single_ecu_jobs_info(&self) -> Vec<ComponentDataInfo> {
        self.ecu_data
            .single_ecu_jobs
            .iter()
            .flat_map(|(_, job)| {
                Some(ComponentDataInfo {
                    category: get_string_with_default!(job.semantic, |semantic| semantic
                        .to_lowercase()),
                    id: get_string_with_default!(job.short_name, |short_name| short_name
                        .replace("_Read", "")
                        .to_lowercase()),
                    name: get_string_from_option_with_default!(job.long_name),
                })
                .into_iter()
            })
            .collect()
    }

    fn set_session(
        &self,
        session: cda_interfaces::Id,
        expiration: Duration,
    ) -> Result<(), DiagServiceError> {
        self.access_control.lock().session = session;
        self.start_reset_task(expiration)
    }

    fn set_security_access(
        &self,
        security_access: cda_interfaces::Id,
        expiration: Duration,
    ) -> Result<(), DiagServiceError> {
        log::debug!(target: &self.ecu_data.ecu_name,
            "Setting security_access to {security_access}");
        self.access_control.lock().security = security_access;
        self.start_reset_task(expiration)
    }

    fn lookup_session_change(
        &self,
        session: &str,
    ) -> Result<(cda_interfaces::Id, DiagComm), DiagServiceError> {
        let session_state_chart = self.state_chart(semantics::SESSION)?;

        let target_session = session_state_chart
            .states
            .iter()
            .find(|(_, state)| {
                STRINGS
                    .get(state.short_name)
                    .is_some_and(|name| name == session)
            })
            .map(|(_, state)| state)
            .ok_or_else(|| {
                log::warn!("Session {session} not found in state chart");
                DiagServiceError::NotFound
            })?;

        let session = self.access_control.lock().session;
        let current_session = session_state_chart.states.get(&session).ok_or_else(|| {
            log::error!("Current session {session} does not exist");
            DiagServiceError::NotFound
        })?;

        let session_service_id = current_session
            .transitions
            .get(&target_session.id)
            .and_then(|transition| transition.session)
            .ok_or_else(|| {
                log::debug!(
                    "No transition from {} to {session} exists, available transitions: {:#?}",
                    get_string_with_default!(current_session.short_name),
                    current_session.transitions,
                );
                DiagServiceError::NotFound
            })?;

        let session_service = self
            .ecu_data
            .services
            .get(&session_service_id)
            .ok_or_else(|| {
                log::warn!("Session service {session_service_id} not found in ECU data");
                DiagServiceError::NotFound
            })?;

        let name = STRINGS.get(session_service.short_name).ok_or_else(|| {
            log::warn!("Session service {session_service_id} has no short name");
            DiagServiceError::NotFound
        })?;

        Ok((
            target_session.id,
            DiagComm {
                name: name.clone(),
                action: DiagCommAction::Start,
                type_: DiagCommType::Modes,
                lookup_name: Some(name),
            },
        ))
    }

    fn lookup_security_access_change(
        &self,
        level: &str,
        seed_service: Option<&String>,
        has_key: bool,
    ) -> Result<SecurityAccess, DiagServiceError> {
        let security_state_chart = self.state_chart(semantics::SECURITY)?;
        let session_control = self.access_control.lock();

        let target_access_level = security_state_chart
            .states
            .iter()
            .find(|(_, state)| {
                STRINGS
                    .get(state.short_name)
                    .is_some_and(|name| name.to_lowercase() == level.to_lowercase())
            })
            .map(|(_, state)| state)
            .ok_or_else(|| {
                log::warn!("Security access '{level}' not found in state chart");
                DiagServiceError::NotFound
            })?;

        let current_access = security_state_chart
            .states
            .get(&session_control.security)
            .ok_or_else(|| {
                log::error!(
                    "Current security access state {} does not exit",
                    session_control.security
                );
                DiagServiceError::NotFound
            })?;

        let security_service_id = current_access
            .transitions
            .get(&target_access_level.id)
            .and_then(|transition| transition.security_access)
            .ok_or_else(|| {
                log::debug!(
                    "No transition from {:?} to {level} exists, available transitions: {:#?}",
                    STRINGS.get(current_access.short_name),
                    current_access.transitions,
                );
                DiagServiceError::NotFound
            })?;

        if has_key {
            // calling this service will change the security access level
            let security_service = self
                .ecu_data
                .services
                .get(&security_service_id)
                .ok_or_else(|| {
                    log::warn!("Session service {security_service_id} not found in ECU data");
                    DiagServiceError::NotFound
                })?;

            let name = STRINGS.get(security_service.short_name).ok_or_else(|| {
                log::warn!("Diagnostic Service {security_service_id} has no short name");
                DiagServiceError::NotFound
            })?;

            Ok(SecurityAccess::SendKey((
                target_access_level.id,
                DiagComm {
                    name: name.clone(),
                    action: DiagCommAction::Start,
                    type_: DiagCommType::Modes,
                    lookup_name: Some(name),
                },
            )))
        } else {
            let security_access_services: Vec<_> = self
                .ecu_data
                .services
                .values()
                .filter(|service| service.service_id == service_ids::SECURITY_ACCESS)
                .collect();

            let seed_service_name = security_access_services
                .iter()
                .find_map(|service| {
                    let name = STRINGS.get(service.short_name)?;
                    seed_service
                        .as_ref()
                        .filter(|v| name.to_lowercase().contains(&v.to_lowercase()))
                        .map(|_| name)
                })
                .or_else(|| {
                    security_access_services.iter().find_map(|service| {
                        STRINGS
                            .get(service.short_name)
                            .filter(|name| name.to_lowercase().contains("seed"))
                    })
                })
                .ok_or_else(|| {
                    log::warn!("Security service not found in ECU data");
                    DiagServiceError::NotFound
                })?;
            Ok(SecurityAccess::RequestSeed(DiagComm {
                name: seed_service_name.clone(),
                action: DiagCommAction::Start,
                type_: DiagCommType::Modes,
                lookup_name: Some(seed_service_name),
            }))
        }
    }

    fn session(&self) -> String {
        let session = self.access_control.lock().session;
        self.state_chart(semantics::SESSION)
            .map_or("Unknown".to_owned(), |chart| {
                chart.states.get(&session).map_or_else(
                    || "Unknown".to_owned(),
                    |state| get_string_with_default!(state.short_name),
                )
            })
    }

    fn security_access(&self) -> String {
        let security_access = self.access_control.lock().security;
        self.state_chart(semantics::SECURITY)
            .map_or("Unknown".to_owned(), |chart| {
                chart.states.get(&security_access).map_or_else(
                    || "Unknown".to_owned(),
                    |state| get_string_with_default!(state.short_name),
                )
            })
    }

    /// Returns all services in /configuration, i.e. 0x22 and 0x2E
    /// that are in the functional group varcoding.
    fn get_components_configurations_info(
        &self,
    ) -> Result<Vec<ComponentConfigurationsInfo>, DiagServiceError> {
        let var_coding_func_class = self
            .ecu_data
            .functional_classes
            .iter()
            .find(|(_, name)| {
                name.to_lowercase() == self.database_naming_convention.functional_class_varcoding
            })
            .map(|(&id, _)| id)
            .ok_or(DiagServiceError::NotFound)?;

        let configuration_sids = [
            service_ids::READ_DATA_BY_IDENTIFIER,
            service_ids::WRITE_DATA_BY_IDENTIFIER,
        ];

        let variant = self
            .variant
            .as_ref()
            .and_then(|v| self.ecu_data.variants.get(&v.id))
            .or_else(|| self.ecu_data.variants.get(&self.ecu_data.base_variant_id))
            .ok_or(DiagServiceError::NotFound)?;

        let base_variant = self
            .ecu_data
            .variants
            .get(&self.ecu_data.base_variant_id)
            .ok_or(DiagServiceError::NotFound)?;

        // Maps a common abbreviated service short name (using the configured affixes) to
        // a vector of bytes of: service_id, ID_parameter_coded_const
        let mut result_map: HashMap<String, HashSet<Vec<u8>>> = HashMap::new();

        // Maps common short name to long name
        let mut long_name_map: HashMap<String, String> = HashMap::new();

        // Iterate over all services of the variant and the base
        variant
            .services
            .iter()
            .chain(base_variant.services.iter())
            .filter_map(|id| {
                self.ecu_data.services.get(id).filter(|service| {
                    service.funct_class == var_coding_func_class
                        && configuration_sids.contains(&service.service_id)
                })
            })
            .for_each(|service| {
                let (bitlength, coded_const_value) =
                    match self.get_service_id_parameter_value(&service) {
                        Some(value) => value,
                        None => return,
                    };

                // trim short names so write and read services are grouped together
                let common_short_name =
                    get_string_with_default!(service.short_name, |short_name| {
                        self.database_naming_convention
                            .trim_short_name_affixes(&short_name)
                    });

                // trim the long name so we can return a descriptive name
                if !long_name_map.contains_key(&common_short_name)
                    && let Some(long_name) =
                        get_string_from_option!(service.long_name, |long_name| {
                            self.database_naming_convention
                                .trim_long_name_affixes(&long_name)
                        })
                {
                    long_name_map.insert(common_short_name.clone(), long_name);
                }

                // collect the coded const bytes of the parameter expressing the ID
                let id_param_bytes =
                    &coded_const_value.to_be_bytes()[(4 - (bitlength / 8)) as usize..];

                // compile the first bytes of the raw uds payload
                let mut service_abstract_entry = Vec::with_capacity(1 + id_param_bytes.len());
                service_abstract_entry.push(service.service_id);
                service_abstract_entry.extend_from_slice(id_param_bytes);

                result_map
                    .entry(common_short_name)
                    .or_default()
                    .insert(service_abstract_entry);
            });

        let mut result: Vec<_> = result_map
            .into_iter()
            .map(
                |(common_short_name, abstracts)| ComponentConfigurationsInfo {
                    name: long_name_map
                        .get(&common_short_name)
                        .cloned()
                        .unwrap_or_default(),
                    id: common_short_name,
                    configurations_type: "parameter".to_owned(),
                    service_abstract: abstracts.into_iter().collect(),
                },
            )
            .collect();
        result.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(result)
    }
}

impl cda_interfaces::UdsComParamProvider for EcuManager {
    fn tester_present_retry_policy(&self) -> bool {
        self.tester_present_retry_policy
    }
    fn tester_present_addr_mode(self) -> AddressingMode {
        self.tester_present_addr_mode.clone()
    }
    fn tester_present_response_expected(self) -> bool {
        self.tester_present_response_expected
    }
    fn tester_present_send_type(self) -> TesterPresentSendType {
        self.tester_present_send_type.clone()
    }
    fn tester_present_message(self) -> Vec<u8> {
        self.tester_present_message.clone()
    }
    fn tester_present_exp_pos_resp(self) -> Vec<u8> {
        self.tester_present_exp_pos_resp.clone()
    }
    fn tester_present_exp_neg_resp(self) -> Vec<u8> {
        self.tester_present_exp_neg_resp.clone()
    }
    fn tester_present_time(&self) -> Duration {
        self.tester_present_time
    }
    fn repeat_req_count_app(&self) -> u32 {
        self.repeat_req_count_app
    }
    fn rc_21_retry_policy(&self) -> RetryPolicy {
        self.rc_21_retry_policy.clone()
    }
    fn rc_21_completion_timeout(&self) -> Duration {
        self.rc_21_completion_timeout
    }
    fn rc_21_repeat_request_time(&self) -> Duration {
        self.rc_21_repeat_request_time
    }
    fn rc_78_retry_policy(&self) -> RetryPolicy {
        self.rc_78_retry_policy.clone()
    }
    fn rc_78_completion_timeout(&self) -> Duration {
        self.rc_78_completion_timeout
    }
    fn rc_78_timeout(&self) -> Duration {
        self.rc_78_timeout
    }
    fn rc_94_retry_policy(&self) -> RetryPolicy {
        self.rc_94_retry_policy.clone()
    }
    fn rc_94_completion_timeout(&self) -> Duration {
        self.rc_94_completion_timeout
    }
    fn rc_94_repeat_request_time(&self) -> Duration {
        self.rc_94_repeat_request_time
    }
    fn timeout_default(&self) -> Duration {
        self.timeout_default
    }
}

impl cda_interfaces::DoipComParamProvider for EcuManager {
    fn nack_number_of_retries(&self) -> &HashMap<u8, u32> {
        &self.nack_number_of_retries
    }
    fn diagnostic_ack_timeout(&self) -> Duration {
        self.diagnostic_ack_timeout
    }
    fn retry_period(&self) -> Duration {
        self.retry_period
    }
    fn routing_activation_timeout(&self) -> Duration {
        self.routing_activation_timeout
    }
    fn repeat_request_count_transmission(&self) -> u32 {
        self.repeat_request_count_transmission
    }
    fn connection_timeout(&self) -> Duration {
        self.connection_timeout
    }
    fn connection_retry_delay(&self) -> Duration {
        self.connection_retry_delay
    }
    fn connection_retry_attempts(&self) -> u32 {
        self.connection_retry_attempts
    }
}

impl EcuManager {
    /// Load diagnostic database for given path
    ///
    /// The created `DiagServiceManager` stores the loaded database as well as some
    /// frequently used values like the tester/logical addresses and required information
    /// for variant detection.
    ///
    /// com_params are used to extract settings from the database.
    /// Each com param is using `ComParamSetting<T>` which has two fields:
    /// * `name`: The name of the com param, used to look up the value in the database.
    /// * `default`: The default value of the com param, used if
    ///     * `name` is not found in the database.
    ///     * the value could not be converted to the expected type.
    ///
    /// # Errors
    ///
    /// Will return `Err` if the ECU database cannot be loaded correctly due to different reasons,
    /// like the format being incompatible or required information missing from the database.
    pub fn new(
        ecu_database_path: String,
        ecu_data_blob: &[u8],
        protocol: Protocol,
        com_params: &ComParams,
        database_naming_convention: DatabaseNamingConvention,
    ) -> Result<Self, DiagServiceError> {
        let database = DiagnosticDatabase::new(ecu_database_path, ecu_data_blob)?;
        let variant_detection = variant_detection::prepare_variant_detection(&database)?;

        let data_protocol: datatypes::Protocol = into_db_protocol(protocol);

        let logical_gateway_address = database
            .find_logical_address(
                LogicalAddressType::Gateway(com_params.doip.logical_gateway_address.name.clone()),
                &data_protocol,
            )
            .unwrap_or(com_params.doip.logical_gateway_address.default);

        let logical_ecu_address = database
            .find_logical_address(
                LogicalAddressType::Ecu(
                    com_params.doip.logical_response_id_table_name.clone(),
                    com_params.doip.logical_ecu_address.name.clone(),
                ),
                &data_protocol,
            )
            .unwrap_or(com_params.doip.logical_ecu_address.default);

        let logical_functional_address = database
            .find_logical_address(
                LogicalAddressType::Functional(
                    com_params.doip.logical_functional_address.name.clone(),
                ),
                &data_protocol,
            )
            .unwrap_or(com_params.doip.logical_functional_address.default);

        let logical_tester_address =
            database.find_com_param(&data_protocol, &com_params.doip.logical_tester_address);

        let nack_number_of_retries = database
            .find_com_param(&data_protocol, &com_params.doip.nack_number_of_retries)
            .iter()
            .map(|(k, v)| {
                let key_result = if let Some(hex_str) = k.strip_prefix("0x") {
                    u8::from_str_radix(hex_str, 16)
                } else {
                    k.parse::<u8>()
                }
                .map_err(|_| {
                    DiagServiceError::ParameterConversionError(format!(
                        "Invalid string for doip.nack_number_of_retries: {k}"
                    ))
                });

                key_result.map(|key| (key, *v))
            })
            .collect::<Result<HashMap<u8, u32>, DiagServiceError>>()?;

        let diagnostic_ack_timeout =
            database.find_com_param(&data_protocol, &com_params.doip.diagnostic_ack_timeout);

        let retry_period = database.find_com_param(&data_protocol, &com_params.doip.retry_period);

        let routing_activation_timeout =
            database.find_com_param(&data_protocol, &com_params.doip.routing_activation_timeout);

        let repeat_request_count_transmission = database.find_com_param(
            &data_protocol,
            &com_params.doip.repeat_request_count_transmission,
        );

        let connection_timeout =
            database.find_com_param(&data_protocol, &com_params.doip.connection_timeout);

        let connection_retry_delay =
            database.find_com_param(&data_protocol, &com_params.doip.connection_retry_delay);

        let connection_retry_attempts =
            database.find_com_param(&data_protocol, &com_params.doip.connection_retry_attempts);

        let tester_present_addr_mode =
            database.find_com_param(&data_protocol, &com_params.uds.tester_present_addr_mode);

        let tester_present_response_expected = database.find_com_param(
            &data_protocol,
            &com_params.uds.tester_present_response_expected,
        );

        let tester_present_send_type =
            database.find_com_param(&data_protocol, &com_params.uds.tester_present_send_type);

        let tester_present_message =
            database.find_com_param(&data_protocol, &com_params.uds.tester_present_message);

        let tester_present_exp_pos_resp =
            database.find_com_param(&data_protocol, &com_params.uds.tester_present_exp_pos_resp);

        let tester_present_exp_neg_resp =
            database.find_com_param(&data_protocol, &com_params.uds.tester_present_exp_neg_resp);

        let tester_present_retry_policy =
            database.find_com_param(&data_protocol, &com_params.uds.tester_present_retry_policy);

        let tester_present_time =
            database.find_com_param(&data_protocol, &com_params.uds.tester_present_time);

        let repeat_req_count_app =
            database.find_com_param(&data_protocol, &com_params.uds.repeat_req_count_app);

        let rc_21_retry_policy =
            database.find_com_param(&data_protocol, &com_params.uds.rc_21_retry_policy);

        let rc_21_completion_timeout =
            database.find_com_param(&data_protocol, &com_params.uds.rc_21_completion_timeout);

        let rc_21_repeat_request_time =
            database.find_com_param(&data_protocol, &com_params.uds.rc_21_repeat_request_time);

        let rc_78_retry_policy =
            database.find_com_param(&data_protocol, &com_params.uds.rc_78_retry_policy);

        let rc_78_completion_timeout =
            database.find_com_param(&data_protocol, &com_params.uds.rc_78_completion_timeout);

        let rc_78_timeout = database.find_com_param(&data_protocol, &com_params.uds.rc_78_timeout);

        let rc_94_retry_policy =
            database.find_com_param(&data_protocol, &com_params.uds.rc_94_retry_policy);

        let rc_94_completion_timeout =
            database.find_com_param(&data_protocol, &com_params.uds.rc_94_completion_timeout);

        let rc_94_repeat_request_time =
            database.find_com_param(&data_protocol, &com_params.uds.rc_94_repeat_request_time);

        let timeout_default =
            database.find_com_param(&data_protocol, &com_params.uds.timeout_default);

        let res = Self {
            ecu_data: database,
            database_naming_convention,
            tester_address: logical_tester_address,
            logical_address: logical_ecu_address,
            logical_gateway_address,
            logical_functional_address,
            nack_number_of_retries,
            diagnostic_ack_timeout,
            retry_period,
            routing_activation_timeout,
            repeat_request_count_transmission,
            connection_timeout,
            connection_retry_delay,
            connection_retry_attempts,
            variant_detection,
            variant: None,
            state: EcuState::NotTested,
            protocol,
            access_control: Arc::new(Mutex::new(SessionControl {
                session: 0,
                security: 0,
                access_reset_task: None,
            })),
            tester_present_retry_policy: tester_present_retry_policy.into(),
            tester_present_addr_mode,
            tester_present_response_expected: tester_present_response_expected.into(),
            tester_present_send_type,
            tester_present_message,
            tester_present_exp_pos_resp,
            tester_present_exp_neg_resp,
            tester_present_time,
            repeat_req_count_app,
            rc_21_retry_policy,
            rc_21_completion_timeout,
            rc_21_repeat_request_time,
            rc_78_retry_policy,
            rc_78_completion_timeout,
            rc_78_timeout,
            rc_94_retry_policy,
            rc_94_completion_timeout,
            rc_94_repeat_request_time,
            timeout_default,
        };

        Ok(res)
    }
    fn param_lookup(&self, param_id: u32) -> Result<&datatypes::Parameter, DiagServiceError> {
        self.ecu_data
            .params
            .get(&param_id)
            .ok_or(DiagServiceError::InvalidDatabase(format!(
                "Param ID {param_id} not present in DB"
            )))
    }

    #[tracing::instrument(
        target = "lookup_diag_comm",
        skip(self, diag_comm),
        fields(
            ecu_name = self.ecu_data.ecu_name,
            diag_comm_name = diag_comm.name,
            action = ?diag_comm.action,
            type_ = ?diag_comm.type_
        ),
        err,
    )]
    fn lookup_diag_comm(
        &self,
        diag_comm: &DiagComm,
    ) -> Result<&DiagnosticService, DiagServiceError> {
        let lookup_name = if let Some(name) = &diag_comm.lookup_name {
            name.to_owned()
        } else {
            match diag_comm.action {
                DiagCommAction::Read => format!("{}_Read", diag_comm.name),
                DiagCommAction::Write => format!("{}_Write", diag_comm.name),
                DiagCommAction::Start => format!("{}_Start", diag_comm.name),
            }
        }
        .to_lowercase();

        let log_target = format!("Lookup Diag Service [{}].[{lookup_name}]", self.ecu_name());
        log::debug!(target: &log_target, "Looking up service");

        let lookup = self
            .variant
            .as_ref()
            .and_then(|variant| {
                self.ecu_data
                    .variants
                    .get(&variant.id)
                    .and_then(|variant| variant.service_lookup.get(&lookup_name))
            })
            .or(self.ecu_data.base_service_lookup.get(&lookup_name))
            .or_else(|| {
                log::warn!(
                    target: &log_target,
                    "Service not found in detected variant or base variant, \
                    trying to find in all variants"
                );
                self.ecu_data
                    .variants
                    .iter()
                    .find_map(|(_, variant)| variant.service_lookup.get(&lookup_name))
            });

        let service = lookup.ok_or(DiagServiceError::NotFound).and_then(|id| {
            self.ecu_data.services.get(id).ok_or_else(|| {
                // this should not happen, there should always be a base variant.
                log::warn!(
                    target: &log_target,
                    "service reference could not be resolved to a service"
                );
                DiagServiceError::NotFound
            })
        })?;

        if !diag_comm
            .type_
            .service_prefix()
            .contains(&service.service_id)
        {
            log::warn!(target: &log_target, "Service ID prefix mismatch. Got {:?}, expected {:?}",
                service.service_id, diag_comm.type_.service_prefix());
            return Err(DiagServiceError::NotFound);
        }

        Ok(service)
    }

    fn map_param_from_uds(
        &self,
        mapped_service: &DiagnosticService,
        param: &datatypes::Parameter,
        param_name: &str,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
    ) -> Result<(), DiagServiceError> {
        match param.value {
            datatypes::ParameterValue::CodedConst(ref c) => {
                let diag_type = self
                    .ecu_data
                    .diag_coded_types
                    .get(&c.diag_coded_type)
                    .ok_or(DiagServiceError::InvalidDatabase(
                        "Unable to lookup DiagCodedType".to_owned(),
                    ))?;

                let value =
                    operations::extract_diag_data_container(param, uds_payload, diag_type, None);

                let value = match value {
                    DiagDataTypeContainer::RawContainer(diag_data_type_container_raw) => {
                        diag_data_type_container_raw
                    }
                    DiagDataTypeContainer::Struct(_hash_map) => {
                        return Err(DiagServiceError::ParameterConversionError(
                            "Struct not supported for UDS payload".to_owned(),
                        ));
                    }
                    DiagDataTypeContainer::RepeatingStruct(_vec) => {
                        return Err(DiagServiceError::ParameterConversionError(
                            "RepeatingStruct not supported for UDS payload".to_owned(),
                        ));
                    }
                };

                let const_value = STRINGS.get(c.value).ok_or_else(|| {
                    DiagServiceError::InvalidDatabase(format!(
                        "Unable to find coded const value for param: {}",
                        param.short_name
                    ))
                })?;
                let expected =
                    operations::diag_coded_type_to_uds(diag_type.base_datatype, &const_value)?
                        .into_iter()
                        // .filter(|v| *v != 0) // remove 0 padding
                        .collect::<Vec<_>>();
                let expected = &expected[expected.len() - value.data.len()..];
                if value.data != expected {
                    return Err(DiagServiceError::BadPayload(format!(
                        "{}: Expected {:?}, got {:?}",
                        param.short_name, expected, value.data
                    )));
                }

                data.insert(
                    param_name.to_owned(),
                    DiagDataTypeContainer::RawContainer(value),
                );
            }
            datatypes::ParameterValue::MatchingRequestParam(ref v) => {
                let request = self
                    .ecu_data
                    .requests
                    .get(&mapped_service.request_id)
                    .ok_or_else(|| {
                        DiagServiceError::UdsLookupError(
                            "Unable to map concrete requests to service".to_owned(),
                        )
                    })?;
                let params = request
                    .params
                    .iter()
                    .map(|p| {
                        self.ecu_data
                            .params
                            .get(p)
                            .ok_or(DiagServiceError::InvalidDatabase(
                                "Param lookup failed".to_owned(),
                            ))
                    })
                    .collect::<Result<Vec<_>, DiagServiceError>>()?;
                let matching_request_param = params
                    .iter()
                    .find(|p| p.byte_pos == v.request_byte_pos as u32)
                    .ok_or_else(|| {
                        DiagServiceError::UdsLookupError(format!(
                            "No matching request parameter found for {}",
                            param.short_name
                        ))
                    })?;
                let param_byte_pos = param.byte_pos;
                let pop = (v.request_byte_pos as u32) < param_byte_pos;
                if pop {
                    uds_payload.push_slice(param.byte_pos as usize, uds_payload.len())?;
                }

                self.map_param_from_uds(
                    mapped_service,
                    matching_request_param,
                    param_name,
                    uds_payload,
                    data,
                )?;

                if pop {
                    uds_payload.pop_slice()?;
                }
            }
            datatypes::ParameterValue::Value(ref v) => {
                if let Some(dop) = self.ecu_data.data_operations.get(&v.dop) {
                    self.map_dop(mapped_service, dop, param, uds_payload, data)?;
                } else {
                    log::error!(target: &self.ecu_data.ecu_name,
                        "{param_name} DoP lookup failed for id {}",
                        v.dop
                    );
                }
            }
            datatypes::ParameterValue::Reserved(_) => {
                // skip for now
            }
        }
        Ok(())
    }
    fn map_nested_struct_to_uds(
        &self,
        structure: &datatypes::StructureDop,
        value: &serde_json::Value,
    ) -> Result<Vec<u8>, DiagServiceError> {
        let mut uds_data: Vec<u8> = Vec::new();
        let Some(value) = value.as_object() else {
            return Err(DiagServiceError::InvalidRequest(format!(
                "Expected value to be object type, but it was: {value:#?}"
            )));
        };
        for param in structure.params.iter() {
            let param =
                self.ecu_data
                    .params
                    .get(param)
                    .ok_or(DiagServiceError::InvalidDatabase(
                        "StaticField Param not found".to_owned(),
                    ))?;
            let short_name = STRINGS.get(param.short_name).ok_or_else(|| {
                DiagServiceError::InvalidDatabase(format!(
                    "Unable to find short name for paramId: {}",
                    param.short_name
                ))
            })?;

            let param_value = value
                .get(&short_name)
                .ok_or(DiagServiceError::InvalidRequest(format!(
                    "Parameter '{short_name}' not part of the request body"
                )))?;

            let mut uds_value = self.map_param_to_uds(param, param_value)?.ok_or(
                DiagServiceError::InvalidDatabase(format!(
                    "Could not map '{param_value}' to uds for parameter '{short_name}'"
                )),
            )?;
            uds_data.append(&mut uds_value);
        }

        Ok(uds_data)
    }

    fn map_param_to_uds(
        &self,
        param: &datatypes::Parameter,
        value: &serde_json::Value,
    ) -> Result<Option<Vec<u8>>, DiagServiceError> {
        match &param.value {
            datatypes::ParameterValue::CodedConst(_coded_const) => Ok(None),
            datatypes::ParameterValue::MatchingRequestParam(_matching_request_param) => {
                // todo can this even be mapped to UDS request?
                Ok(None)
            }
            datatypes::ParameterValue::Value(value_data) => {
                if let Some(dop) = self.ecu_data.data_operations.get(&value_data.dop) {
                    match &dop.variant {
                        datatypes::DataOperationVariant::Normal(normal_dop) => {
                            let Some(diag_type) =
                                self.ecu_data.diag_coded_types.get(&normal_dop.diag_type)
                            else {
                                log::error!(target: &self.ecu_data.ecu_name,
                                    "Unable to lookup DiagCodedType for param: {}",
                                    param.short_name
                                );
                                return Err(DiagServiceError::InvalidDatabase(
                                    "Unable to lookup DiagCodedType".to_owned(),
                                ));
                            };
                            let uds_data = json_value_to_uds_data(
                                diag_type.base_datatype,
                                Some(&normal_dop.compu_method),
                                value,
                            )?;
                            let mapped_data = diag_type.type_.apply(&uds_data);
                            Ok(Some(mapped_data))
                        }
                        datatypes::DataOperationVariant::EndOfPdu(end_of_pdu_dop) => {
                            let Some(value) = value.as_array() else {
                                return Err(DiagServiceError::InvalidRequest(
                                    "Expected array value".to_owned(),
                                ));
                            };
                            // Check length of provided array
                            if value.len() < end_of_pdu_dop.min_items as usize
                                || value.len() > end_of_pdu_dop.max_items as usize
                            {
                                return Err(DiagServiceError::InvalidRequest(
                                    "EndOfPdu expected different amount of items".to_owned(),
                                ));
                            }
                            let structure =
                                self.get_basic_structure(end_of_pdu_dop.field.basic_structure)?;

                            let mut uds_data = Vec::new();
                            for v in value {
                                let mut chunk = self.map_nested_struct_to_uds(structure, v)?;
                                uds_data.append(&mut chunk);
                            }
                            Ok(Some(uds_data))
                        }
                        datatypes::DataOperationVariant::Structure(_structure_dop) => todo!(),
                        datatypes::DataOperationVariant::EnvDataDesc(_env_data_desc_dop) => {
                            todo!()
                        }
                        datatypes::DataOperationVariant::EnvData(_env_data_dop) => todo!(),
                        datatypes::DataOperationVariant::Dtc(_dtc_dop) => todo!(),
                        datatypes::DataOperationVariant::StaticField(_static_field_dop) => {
                            todo!()
                        }
                        datatypes::DataOperationVariant::Mux(_static_field_dop) => {
                            todo!()
                        }
                    }
                } else {
                    log::error!(target: &self.ecu_data.ecu_name,
                        "DoP lookup failed for id {}",
                        value_data.dop
                    );
                    Err(DiagServiceError::InvalidDatabase(
                        "DoP lookup failed".to_owned(),
                    ))
                }
            }
            datatypes::ParameterValue::Reserved(reserved_param) => {
                let mut bits = reserved_param.bit_length as usize;
                let mut mapped = Vec::new();
                // pad full bytes
                while bits > 8 {
                    mapped.push(0x0);
                    bits -= 8;
                }
                Ok(Some(mapped))
            }
        }
    }

    fn map_nested_struct(
        &self,
        structure: &datatypes::StructureDop,
        mapped_service: &DiagnosticService,
        uds_payload: &mut Payload,
        nested_structs: &mut Vec<HashMap<String, DiagDataTypeContainer>>,
    ) -> Result<(), DiagServiceError> {
        let mut nested_data = HashMap::new();
        for param in structure.params.iter() {
            let param =
                self.ecu_data
                    .params
                    .get(param)
                    .ok_or(DiagServiceError::InvalidDatabase(
                        "StaticField Param not found".to_owned(),
                    ))?;
            let short_name = STRINGS.get(param.short_name).ok_or_else(|| {
                DiagServiceError::InvalidDatabase(format!(
                    "Unable to find short name for param: {}",
                    param.short_name
                ))
            })?;
            self.map_param_from_uds(
                mapped_service,
                param,
                &short_name,
                uds_payload,
                &mut nested_data,
            )?;
        }
        nested_structs.push(nested_data);
        Ok(())
    }

    fn map_dop(
        &self,
        mapped_service: &DiagnosticService,
        dop: &DataOperation,
        param: &datatypes::Parameter,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
    ) -> Result<(), DiagServiceError> {
        let short_name = STRINGS.get(param.short_name).ok_or_else(|| {
            DiagServiceError::InvalidDatabase(
                "Unable to find short name for param in Strings".to_string(),
            )
        })?;
        match dop.variant {
            datatypes::DataOperationVariant::Normal(ref normal_dop) => {
                let diag_coded_type = self
                    .ecu_data
                    .diag_coded_types
                    .get(&normal_dop.diag_type)
                    .ok_or(DiagServiceError::InvalidDatabase(
                        "DiagCodedType lookup for NormalDoP failed".to_owned(),
                    ))?;

                let compu_method = &normal_dop.compu_method;
                data.insert(
                    short_name,
                    operations::extract_diag_data_container(
                        param,
                        uds_payload,
                        diag_coded_type,
                        Some(compu_method),
                    ),
                );
            }
            datatypes::DataOperationVariant::EndOfPdu(ref v) => {
                let struct_ = self.get_basic_structure(v.field.basic_structure)?;

                uds_payload.push_slice(param.byte_pos as usize, uds_payload.len())?;
                if struct_.byte_size > 0 {
                    let struct_count = uds_payload.len() / struct_.byte_size as usize;
                    if struct_count > v.max_items as usize {
                        return Err(DiagServiceError::BadPayload(format!(
                            "Too many items in EndOfPduField: {} > {}",
                            struct_count, v.max_items
                        )));
                    }
                }

                let mut nested_structs = Vec::new();
                loop {
                    self.map_nested_struct(
                        struct_,
                        mapped_service,
                        uds_payload,
                        &mut nested_structs,
                    )?;
                    uds_payload.consume();
                    if uds_payload.exhausted() {
                        break;
                    }
                }

                uds_payload.pop_slice()?;

                data.insert(
                    short_name,
                    DiagDataTypeContainer::RepeatingStruct(nested_structs),
                );
            }
            datatypes::DataOperationVariant::Structure(ref structure) => {
                if uds_payload.len() < structure.byte_size as usize {
                    return Err(DiagServiceError::BadPayload(format!(
                        "Not enough data for structure: {} < {}",
                        uds_payload.len(),
                        structure.byte_size
                    )));
                }
                for param in structure.params.iter() {
                    let param = self.ecu_data.params.get(param).ok_or(
                        DiagServiceError::InvalidDatabase("Structure Param not found".to_owned()),
                    )?;
                    self.map_param_from_uds(mapped_service, param, &short_name, uds_payload, data)?;
                }
            }
            datatypes::DataOperationVariant::EnvDataDesc(ref _env_data_desc_dop) => {
                log::warn!(target: "map_dop", "EnvDataDesc not supported");
            }
            datatypes::DataOperationVariant::EnvData(ref _env_data_dop) => {
                log::warn!(target: "map_dop", "EnvData not supported");
            }
            datatypes::DataOperationVariant::Dtc(ref _dtc_dop) => {
                log::warn!(target: "map_dop", "DTC not supported");
            }
            datatypes::DataOperationVariant::StaticField(ref static_field_dop) => {
                let static_field_size = (static_field_dop.item_byte_size
                    * static_field_dop.fixed_number_of_items)
                    as usize;
                if uds_payload.len() < static_field_size {
                    return Err(DiagServiceError::BadPayload(format!(
                        "Not enough data for static field: {} < {static_field_size}",
                        uds_payload.len(),
                    )));
                }
                let basic_structure =
                    self.get_basic_structure(static_field_dop.field.basic_structure)?;
                let mut nested_structs = Vec::new();

                for i in 0..static_field_dop.fixed_number_of_items {
                    let start = (param.byte_pos + i * static_field_dop.item_byte_size) as usize;
                    let end = start + static_field_dop.item_byte_size as usize;
                    uds_payload.push_slice(start, end)?;

                    self.map_nested_struct(
                        basic_structure,
                        mapped_service,
                        uds_payload,
                        &mut nested_structs,
                    )?;

                    uds_payload.pop_slice()?;
                }

                data.insert(
                    short_name,
                    DiagDataTypeContainer::RepeatingStruct(nested_structs),
                );
            }
            datatypes::DataOperationVariant::Mux(ref mux_dop) => {
                self.map_mux(mapped_service, uds_payload, data, short_name, mux_dop)?;
            }
        }

        Ok(())
    }

    fn map_mux(
        &self,
        mapped_service: &DiagnosticService,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        short_name: String,
        mux_dop: &MuxDop,
    ) -> Result<(), DiagServiceError> {
        let byte_pos = mux_dop.byte_position as usize;
        if uds_payload.len() < byte_pos + 1 {
            return Err(DiagServiceError::BadPayload(format!(
                "Not enough data for mux: {} < {byte_pos}",
                uds_payload.len(),
            )));
        }

        uds_payload.set_pos(byte_pos)?;
        let payload = &uds_payload.data()[0];
        let payload_value = f64::from(*payload);
        let case = mux_dop
            .cases
            .iter()
            .find(
                |case| match (case.lower_limit.as_ref(), case.upper_limit.as_ref()) {
                    (Ok(lower_limit), Ok(upper_limit)) => {
                        lower_limit.value <= payload_value && upper_limit.value >= payload_value
                    }
                    _ => false,
                },
            )
            .ok_or_else(|| {
                DiagServiceError::BadPayload(format!(
                    "Mux case not found for value: {payload_value}"
                ))
            })?;

        let structure = self.get_basic_structure(case.structure.unwrap())?;
        let case_name = get_string!(case.short_name).map_err(|_| {
            DiagServiceError::InvalidDatabase("Mux case short name not found".to_owned())
        })?;
        let mut mux_data = HashMap::new();
        mux_data.insert(
            "Selector".to_owned(),
            DiagDataTypeContainer::RawContainer(DiagDataTypeContainerRaw {
                data: vec![*payload],
                data_type: DataType::UInt32,
                compu_method: None,
            }),
        );

        let mut case_data = HashMap::new();
        for param in structure.params.iter() {
            let param =
                self.ecu_data
                    .params
                    .get(param)
                    .ok_or(DiagServiceError::InvalidDatabase(
                        "Structure Param not found".to_owned(),
                    ))?;
            uds_payload.push_slice(byte_pos + 1, uds_payload.len())?;
            self.map_param_from_uds(
                mapped_service,
                param,
                &short_name,
                uds_payload,
                &mut case_data,
            )?;
            uds_payload.pop_slice()?;
        }
        mux_data.insert(case_name, DiagDataTypeContainer::Struct(case_data));
        data.insert(short_name, DiagDataTypeContainer::Struct(mux_data));
        Ok(())
    }

    fn get_basic_structure(
        &self,
        basic_strucure_id: cda_interfaces::Id,
    ) -> Result<&datatypes::StructureDop, DiagServiceError> {
        let basic_structure = self
            .ecu_data
            .data_operations
            .get(&basic_strucure_id)
            .ok_or(DiagServiceError::InvalidDatabase(
                "BasicStructure Dop not found".to_owned(),
            ))?;
        let datatypes::DataOperationVariant::Structure(ref struct_) = basic_structure.variant
        else {
            return Err(DiagServiceError::InvalidDatabase(
                "BasicStructure Dop not a structure".to_owned(),
            ));
        };
        Ok(struct_)
    }

    fn state_chart(&self, semantic: &str) -> Result<&StateChart, DiagServiceError> {
        let state_chart = self
            .variant
            .as_ref()
            .and_then(|variant| {
                self.ecu_data
                    .variants
                    .get(&variant.id)
                    .and_then(|variant| variant.state_charts_lookup.get(semantic))
            })
            .or_else(|| self.ecu_data.base_state_chart_lookup.get(semantic))
            .or_else(|| self.ecu_data.state_chart_lookup.get(semantic))
            .and_then(|state_chart_id| self.ecu_data.state_charts.get(state_chart_id))
            .ok_or(DiagServiceError::NotFound)?;
        Ok(state_chart)
    }
    fn default_state(&self, semantic: &str) -> Result<cda_interfaces::Id, DiagServiceError> {
        self.state_chart(semantic).map(|sec| sec.default_state)
    }
    fn start_reset_task(&self, expiration: Duration) -> Result<(), DiagServiceError> {
        let session_control = Arc::clone(&self.access_control);

        let default_security = self.default_state(semantics::SECURITY)?;
        let default_session = self.default_state(semantics::SESSION)?;

        self.access_control.lock().access_reset_task = Some(spawn_named!(
            &format!("access-reset-{}", self.ecu_name()),
            async move {
                tokio::time::sleep(expiration).await;
                let mut access = session_control.lock();
                access.security = default_security;
                access.session = default_session;
                access.access_reset_task = None;
            }
        ));

        Ok(())
    }

    /// Returns the bit length and value of the service ID parameter for a given
    /// `DiagnosticService`, if available.
    ///
    /// Searches the associated request for a `CodedConst` parameter with the configured
    /// semantic and checks if the type and value are valid.
    ///
    /// Returns a tuple `(bitlength, value)` or `None` if no matching parameter is found.
    fn get_service_id_parameter_value(&self, service: &&DiagnosticService) -> Option<(u32, u32)> {
        let request = match self.ecu_data.requests.get(&service.request_id) {
            Some(request) => request,
            None => {
                log::warn!(
                            target: &self.ecu_data.ecu_name,
                            "No request found for service {service:#?}");
                return None;
            }
        };

        // iterate over the request parameters to find the coded const parameter
        // with the configured semantics
        let coded_const = request.params.iter().find_map(|param_ref| {
            self.ecu_data.params.get(param_ref).and_then(|param| {
                let semantic = param.semantic.and_then(|sem| STRINGS.get(sem));
                match semantic {
                    Some(sem)
                        if sem
                            == self
                                .database_naming_convention
                                .configuration_service_parameter_semantic_id =>
                    {
                        match &param.value {
                            datatypes::ParameterValue::CodedConst(coded_const) => Some(coded_const),
                            _ => None,
                        }
                    }
                    _ => None,
                }
            })
        });
        let coded_const = match coded_const {
            Some(coded_const) => coded_const,
            None => {
                log::warn!(target: &self.ecu_data.ecu_name,
                            "No coded const found for service {service:#?}");
                return None;
            }
        };

        // Ensure the coded const has a compatible type
        let coded_const_type = match self
            .ecu_data
            .diag_coded_types
            .get(&coded_const.diag_coded_type)
        {
            Some(coded_const_type) => coded_const_type,
            None => {
                log::warn!(target: &self.ecu_data.ecu_name, "No diag coded type found \
                             for coded const {coded_const:#?}");
                return None;
            }
        };

        if coded_const_type.base_datatype != DataType::UInt32 {
            log::warn!(target: &self.ecu_data.ecu_name, "Coded const {coded_const:#?} has \
                        unexpected base datatype {:#?}, expected UInt32",
                        coded_const_type.base_datatype);
            return None;
        }

        let bitlength = match &coded_const_type.type_ {
            DiagCodedTypeVariant::LeadingLengthInfo(_) => {
                log::warn!(target: &self.ecu_data.ecu_name, "Coded const {coded_const:#?} \
                        has unexpected type LeadingLengthInfo, expected StandardLength");
                return None;
            }
            DiagCodedTypeVariant::MinMaxLength(_) => {
                log::warn!(target: &self.ecu_data.ecu_name, "Coded const {coded_const:#?} \
                        has unexpected type MinMaxLength, expected StandardLength");
                return None;
            }
            DiagCodedTypeVariant::StandardLength(standard_length_type) => {
                if standard_length_type.bitmask.is_some() {
                    log::warn!(target: &self.ecu_data.ecu_name,
                                "Coded const.type standard_length_type {standard_length_type:#?} \
                                has unexpected bitmask, expected StandardLength without bitmask");
                    return None;
                }
                match standard_length_type.bit_length {
                    16 | 24 | 32 => standard_length_type.bit_length,
                    _ => {
                        log::warn!(target: &self.ecu_data.ecu_name,
                                    "Coded const {coded_const:#?} has unexpected bit length {:#?},\
                                     expected 16, 24 or 32", standard_length_type.bit_length);
                        return None;
                    }
                }
            }
        };

        // lookup the coded const value in the strings
        let coded_const_value = match STRINGS.get(coded_const.value) {
            Some(value) => value,
            None => {
                log::warn!(target: &self.ecu_data.ecu_name,
                            "No coded const value found for {coded_const:#?}");
                return None;
            }
        };

        let coded_const_value = match coded_const_value.parse::<u32>() {
            Ok(value) => value,
            Err(e) => {
                log::warn!(target: &self.ecu_data.ecu_name,
                            "Coded const value '{coded_const_value}' could not be parsed as u32:\
                             {e}");
                return None;
            }
        };
        Some((bitlength, coded_const_value))
    }
}
