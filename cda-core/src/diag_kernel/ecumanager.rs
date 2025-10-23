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

use cda_database::datatypes;
use cda_interfaces::{
    DiagCommAction, DiagCommType, DiagServiceError, DynamicPlugin, EcuState, Protocol, STRINGS,
    SecurityAccess, ServicePayload, StringId,
    datatypes::{
        AddressingMode, ComParams, ComplexComParamValue, ComponentConfigurationsInfo,
        ComponentDataInfo, DTC_CODE_BIT_LEN, DatabaseNamingConvention, DtcLookup,
        DtcReadInformationFunction, RetryPolicy, SdSdg, TesterPresentSendType, semantics,
        single_ecu,
    },
    diagservices::{DiagServiceResponse, DiagServiceResponseType, FieldParseError, UdsPayloadData},
    service_ids,
    service_ids::NEGATIVE_RESPONSE,
    spawn_named, util,
    util::starts_with_ignore_ascii_case,
};
use cda_plugin_security::SecurityPlugin;
use hashbrown::{HashMap, HashSet};
use parking_lot::Mutex;
use tokio::{sync::RwLock, task::JoinHandle};

use crate::{
    DiagDataContainerDtc, MappedResponseData,
    diag_kernel::{
        DiagDataValue,
        diagservices::{
            DiagDataTypeContainer, DiagDataTypeContainerRaw, DiagServiceResponseStruct,
            MappedDiagServiceResponsePayload,
        },
        into_db_protocol,
        operations::{self, json_value_to_uds_data},
        payload::Payload,
        variant_detection,
    },
};

pub struct EcuManager<S: SecurityPlugin> {
    pub(crate) diag_database: datatypes::DiagnosticDatabase,
    db_cache: DbCache,
    ecu_name: String,
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
    variant_index: Option<usize>,
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

    security_plugin_phantom: std::marker::PhantomData<S>,
}

struct SessionControl {
    session: Option<String>,
    security: Option<String>,
    /// resets session and or security access back to the default
    /// after a given time
    access_reset_task: Option<JoinHandle<()>>,
}

#[derive(Default)]
struct DbCache {
    pub(crate) diag_services: RwLock<HashMap<StringId, Option<CacheLocation>>>,
}

impl DbCache {
    pub(crate) async fn reset(&mut self) {
        self.diag_services.write().await.clear();
    }
}

enum CacheLocation {
    Variant(usize),
    BaseVariant(usize),
    EcuShared(usize),
}

impl<S: SecurityPlugin> cda_interfaces::EcuAddressProvider for EcuManager<S> {
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
        self.ecu_name.clone()
    }
}

impl<S: SecurityPlugin> cda_interfaces::EcuManager for EcuManager<S> {
    type Response = DiagServiceResponseStruct;

    fn variant_name(&self) -> Option<String> {
        self.variant()?
            .diag_layer()?
            .short_name()
            .map(ToOwned::to_owned)
    }

    fn state(&self) -> EcuState {
        self.state
    }

    fn protocol(&self) -> Protocol {
        self.protocol
    }

    fn is_loaded(&self) -> bool {
        self.diag_database.is_loaded()
    }

    /// This allows to (re)load a database after unloading it during runtime, which could happen
    /// if initially the ECU wasn´t responding but later another request
    /// for reprobing the ECU happens.
    ///
    /// # Errors
    /// Will return `Err` if during runtime the ECU file has been removed or changed
    /// in a way that the error causes mentioned in `Self::new` occur.
    fn load(&mut self) -> Result<(), DiagServiceError> {
        self.diag_database.load()
    }

    #[tracing::instrument(
        target = "variant detection check",
        skip(self, service_responses),
        fields(ecu_name = self.ecu_name),
    )]
    async fn detect_variant<T: DiagServiceResponse + Sized>(
        &mut self,
        service_responses: HashMap<String, T>,
    ) -> Result<(), DiagServiceError> {
        if service_responses.is_empty() {
            self.state = EcuState::Offline;
            return Ok(());
        }
        self.state = EcuState::Online;
        match variant_detection::evaluate_variant(service_responses, &self.diag_database) {
            Ok(v) => {
                let variant_name = (*v)
                    .diag_layer()
                    .and_then(|d| d.short_name())
                    .unwrap_or_default();

                let variant_index = self.diag_database.ecu_data().ok().and_then(|ecu_data| {
                    ecu_data.variants().and_then(|variants| {
                        variants.iter().position(|variant| {
                            variant
                                .diag_layer()
                                .and_then(|dl| dl.short_name())
                                .is_some_and(|name| name == variant_name)
                        })
                    })
                });

                if self.variant_index != variant_index {
                    self.variant_index = variant_index;
                    // reset cache, because services may have the same lookup names
                    // but differ in parameters etc. between variants
                    self.db_cache.reset().await;
                }

                // todo read this from the variant detection instead of assuming default, see #110
                let mut access = self.access_control.lock();
                access.security = Some(self.default_state(semantics::SECURITY)?);
                access.session = Some(self.default_state(semantics::SESSION)?);

                Ok(())
            }
            Err(e) => {
                tracing::debug!("No variant detected, unloading DB");
                self.diag_database.unload();
                Err(e)
            }
        }
    }

    fn get_variant_detection_requests(&self) -> &HashSet<String> {
        &self.variant_detection.diag_service_requests
    }

    #[tracing::instrument(skip(self), fields(ecu_name = self.ecu_name))]
    fn comparams(&self) -> Result<ComplexComParamValue, DiagServiceError> {
        // ensure base variant is handled first
        // and maybe be overwritten by variant specific comparams
        let variants = [Some(self.diag_database.base_variant()?), self.variant()];

        Ok(variants
            .iter()
            .filter_map(|v| v.as_ref())
            .filter_map(|v| v.diag_layer())
            .filter_map(|dl| dl.com_param_refs())
            .flat_map(|cp_ref_vec| cp_ref_vec.iter())
            .filter(|cp_ref| {
                cp_ref.protocol().is_some_and(|p| {
                    p.diag_layer().is_some_and(|dl| {
                        dl.short_name()
                            .is_some_and(|name| name == self.protocol.value())
                    })
                })
            })
            .filter_map(|cp_ref| datatypes::resolve_comparam(&cp_ref).ok())
            .collect())
    }

    async fn sdgs(
        &self,
        service: Option<&cda_interfaces::DiagComm>,
    ) -> Result<Vec<SdSdg>, DiagServiceError> {
        fn map_sd_sdg(sd_or_sdg: &datatypes::SdOrSdg) -> Option<SdSdg> {
            if let Some(sd) = (*sd_or_sdg).sd_or_sdg_as_sd() {
                Some(SdSdg::Sd {
                    value: sd.value().map(ToOwned::to_owned),
                    si: sd.si().map(ToOwned::to_owned),
                    ti: sd.ti().map(ToOwned::to_owned),
                })
            } else if let Some(sdg) = (*sd_or_sdg).sd_or_sdg_as_sdg() {
                Some(SdSdg::Sdg {
                    caption: sdg.caption_sn().map(ToOwned::to_owned),
                    si: sdg.si().map(ToOwned::to_owned),
                    sdgs: sdg
                        .sds()
                        .map(|sds| {
                            sds.iter()
                                .map(datatypes::SdOrSdg)
                                .filter_map(|sd_or_sdg| map_sd_sdg(&sd_or_sdg))
                                .collect()
                        })
                        .unwrap_or_default(),
                })
            } else {
                tracing::warn!("SDOrSDG has no value");
                None
            }
        }

        let sdgs = if let Some(service) = service {
            self.lookup_diag_service(service)
                .await?
                .diag_comm()
                .and_then(|sdg| sdg.sdgs())
                .map(datatypes::Sdgs)
        } else {
            self.variant()
                .as_ref()
                .and_then(|v| v.diag_layer().and_then(|dl| dl.sdgs()))
                .or_else(|| {
                    self.diag_database
                        .base_variant()
                        .ok()?
                        .diag_layer()
                        .and_then(|dl| dl.sdgs())
                })
                .map(datatypes::Sdgs)
        }
        .ok_or_else(|| DiagServiceError::InvalidDatabase("No SDG found in DB".to_owned()))?;

        let mapped = sdgs
            .sdgs()
            .map(|sdgs| {
                sdgs.iter()
                    .map(|sdg| SdSdg::Sdg {
                        caption: sdg.caption_sn().map(ToOwned::to_owned),
                        si: sdg.si().map(ToOwned::to_owned),
                        sdgs: sdg
                            .sds()
                            .map(|sds| {
                                sds.iter()
                                    .filter_map(|sd_or_sdg| map_sd_sdg(&sd_or_sdg.into()))
                                    .collect()
                            })
                            .unwrap_or_default(),
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Ok(mapped)
    }

    fn check_genericservice(
        &self,
        security_plugin: &DynamicPlugin,
        rawdata: Vec<u8>,
    ) -> Result<ServicePayload, DiagServiceError> {
        if rawdata.is_empty() {
            return Err(DiagServiceError::BadPayload(
                "Expected at least 1 byte".to_owned(),
            ));
        }

        let Some(variant) = self.variant() else {
            return Err(DiagServiceError::InvalidDatabase(
                "No variant selected".to_owned(),
            ));
        };

        let base_variant = self.diag_database.base_variant()?;

        // iterate through the services and for each service, resolve the parameters
        // sort the parameters by byte_pos & bit_pos, and take the first parameter
        // this is the service id. check if the provided rawdata matches the expected
        // bytes for the service id, and if yes, return this service.
        // If no service with a matching SIDRQ can be found, DiagServiceError::NotFound
        // is returned to the caller.
        let mapped_service = variant
            .diag_layer()
            .and_then(|dl| dl.diag_services())
            .into_iter()
            .flatten()
            .chain(
                base_variant
                    .diag_layer()
                    .and_then(|dl| dl.diag_services())
                    .into_iter()
                    .flatten(),
            )
            .map(datatypes::DiagService)
            .find_map(|service| {
                let service_id = service.request_id()?;
                if rawdata.first()? == &service_id {
                    Some(service)
                } else {
                    None
                }
            })
            .ok_or(DiagServiceError::NotFound(None))?;
        let mapped_dc = mapped_service.diag_comm().map(datatypes::DiagComm).ok_or(
            DiagServiceError::InvalidDatabase("Service is missing DiagComm".to_owned()),
        )?;

        Self::check_security_plugin(security_plugin, &mapped_service)?;

        let (new_session, new_security) =
            self.lookup_state_transition_by_diagcomm_for_active(&mapped_dc);

        Ok(ServicePayload {
            data: rawdata,
            new_session,
            new_security,
            source_address: self.tester_address,
            target_address: self.logical_address,
        })
    }

    /// Convert a UDS payload given as `u8` slice into a `DiagServiceResponse`.
    ///
    /// # Errors
    /// Will return `Err` in cases where the payload doesn´t match the expected UDS response, or if
    /// elements of the response cannot be correctly mapped from the raw data.
    #[tracing::instrument(
        target = "convert_from_uds",
        skip(self, diag_service, payload),
        fields(
            ecu_name = self.ecu_name,
            service = diag_service.name,
            input = util::tracing::print_hex(&payload.data, 10),
            output = tracing::field::Empty,
        ),
        err
    )]
    async fn convert_from_uds(
        &self,
        diag_service: &cda_interfaces::DiagComm,
        payload: &ServicePayload,
        map_to_json: bool,
    ) -> Result<DiagServiceResponseStruct, DiagServiceError> {
        let mapped_service = self.lookup_diag_service(diag_service).await?;
        let mapped_diag_comm = mapped_service
            .diag_comm()
            .map(datatypes::DiagComm)
            .ok_or_else(|| DiagServiceError::InvalidDatabase("No DiagComm found".to_owned()))?;

        let mut uds_payload = Payload::new(&payload.data);
        let sid = uds_payload
            .first()
            .ok_or_else(|| DiagServiceError::BadPayload("Missing SID".to_owned()))?;
        let sid_value = sid.to_string();

        let responses: Vec<_> = mapped_service
            .pos_responses()
            .into_iter()
            .flatten()
            .chain(mapped_service.neg_responses().into_iter().flatten())
            .collect();

        let mut data = HashMap::new();
        if let Some((response, params)) = responses.iter().find_map(|r| {
            r.params().and_then(|params| {
                let params: Vec<datatypes::Parameter> =
                    params.iter().map(datatypes::Parameter).collect();
                if params.iter().any(|p| {
                    p.byte_position() == 0
                        && p.specific_data_as_coded_const()
                            .is_some_and(|c| c.coded_value().is_some_and(|v| v == sid_value))
                }) {
                    Some((r, params))
                } else {
                    None
                }
            })
        }) {
            let response_type = response.response_type().try_into()?;
            // in case of a positive response update potential session or security access changes
            if response_type == datatypes::ResponseType::Positive {
                let (new_session, new_security) =
                    self.lookup_state_transition_by_diagcomm_for_active(&mapped_diag_comm);

                if let Some(new_session) = new_session {
                    self.set_session(&new_session, Duration::from_secs(u64::MAX))?;
                }
                if let Some(new_security_access) = new_security {
                    self.set_security_access(&new_security_access, Duration::from_secs(u64::MAX))?;
                }
            }

            let raw_uds_payload = {
                let base_offset = params
                    .iter()
                    .filter(|p| p.semantic().is_some_and(|s| s == semantics::DATA))
                    .map(datatypes::Parameter::byte_position)
                    .min()
                    .unwrap_or(0);
                uds_payload.data()?.get(base_offset as usize..).ok_or(
                    DiagServiceError::BadPayload("Payload offset out of bounds".to_owned()),
                )?
            }
            .to_vec();

            if response_type == datatypes::ResponseType::Positive && !map_to_json {
                return Ok(DiagServiceResponseStruct {
                    service: diag_service.clone(),
                    data: raw_uds_payload,
                    mapped_data: None,
                    response_type: DiagServiceResponseType::Positive,
                });
            }
            let mut mapping_errors = Vec::new();
            for param in params {
                let semantic = param.semantic();
                if semantic.is_some_and(|semantic| {
                    semantic != semantics::DATA && semantic != semantics::SERVICEIDRQ
                }) {
                    continue;
                }
                let short_name = param.short_name().ok_or_else(|| {
                    DiagServiceError::InvalidDatabase(
                        "Unable to find short name for param".to_owned(),
                    )
                })?;

                uds_payload.set_last_read_byte_pos(param.byte_position() as usize);
                match self.map_param_from_uds(
                    &mapped_service,
                    &param,
                    short_name,
                    &mut uds_payload,
                    &mut data,
                ) {
                    Ok(()) => {}
                    Err(DiagServiceError::DataError(error)) => {
                        mapping_errors.push(FieldParseError {
                            path: format!("/{short_name}"),
                            error,
                        });
                    }
                    Err(e) => return Err(e),
                }
            }

            let resp = create_diag_service_response(
                diag_service,
                data,
                response_type,
                raw_uds_payload,
                mapping_errors,
            );
            tracing::Span::current()
                .record("output", format!("Response: {:?}", resp.response_type));

            Ok(resp)
        } else {
            // Returning a response here, because even valid databases may not define a
            // response for a service.
            tracing::debug!("No matching response found for SID: {sid_value}");
            Ok(DiagServiceResponseStruct {
                service: diag_service.clone(),
                data: payload.data.clone(),
                mapped_data: None,
                response_type: if *sid == NEGATIVE_RESPONSE {
                    DiagServiceResponseType::Negative
                } else {
                    DiagServiceResponseType::Positive
                },
            })
        }
    }

    #[tracing::instrument(
        target = "create_uds_payload",
        skip(self, diag_service, security_plugin, data),
        fields(
            ecu_name = self.ecu_name,
            service = diag_service.name,
            action = diag_service.action().to_string(),
            input = data.as_ref().map_or_else(|| "None".to_owned(), ToString::to_string),
            output = tracing::field::Empty
        ),
        err
    )]
    async fn create_uds_payload(
        &self,
        diag_service: &cda_interfaces::DiagComm,
        security_plugin: &DynamicPlugin,
        data: Option<UdsPayloadData>,
    ) -> Result<ServicePayload, DiagServiceError> {
        let mapped_service = self.lookup_diag_service(diag_service).await?;
        let mapped_dc = mapped_service
            .diag_comm()
            .ok_or(DiagServiceError::InvalidDatabase(
                "No DiagComm found".to_owned(),
            ))?;
        let request = mapped_service
            .request()
            .ok_or(DiagServiceError::RequestNotSupported(format!(
                "Service '{}' is not supported",
                diag_service.name
            )))?;

        Self::check_security_plugin(security_plugin, &mapped_service)?;

        let mut mapped_params = request
            .params()
            .map(|params| {
                params
                    .iter()
                    .map(datatypes::Parameter)
                    .collect::<Vec<datatypes::Parameter>>()
            })
            .unwrap_or_default();

        mapped_params.sort_by(|a, b| {
            a.byte_position()
                .cmp(&b.byte_position())
                .then(a.bit_position().cmp(&b.bit_position()))
        });

        let mut uds: Vec<u8> = Vec::new();

        let mut num_consts = 0;
        for param in &mapped_params {
            if let Some(coded_const) = param.specific_data_as_coded_const() {
                num_consts += 1;
                let diag_type: datatypes::DiagCodedType = coded_const
                    .diag_coded_type()
                    .and_then(|t| {
                        let type_: Option<datatypes::DiagCodedType> = t.try_into().ok();
                        type_
                    })
                    .ok_or(DiagServiceError::InvalidDatabase(format!(
                        "Param '{}' is missing DiagCodedType",
                        param.short_name().unwrap_or_default()
                    )))?;
                let coded_const_value =
                    coded_const
                        .coded_value()
                        .ok_or(DiagServiceError::InvalidDatabase(format!(
                            "Param '{}' is missing coded value",
                            param.short_name().unwrap_or_default()
                        )))?;

                let uds_val =
                    operations::string_to_vec_u8(diag_type.base_datatype(), coded_const_value)?;

                diag_type.encode(
                    uds_val,
                    &mut uds,
                    param.byte_position() as usize,
                    param.bit_position() as usize,
                )?;
            }
        }
        if let Some(data) = data {
            match data {
                UdsPayloadData::Raw(bytes) => uds.extend(bytes),
                UdsPayloadData::ParameterMap(json_values) => {
                    // todo: check if json_values is empty...
                    for param in mapped_params.iter().skip(num_consts) {
                        if uds.len() < param.byte_position() as usize {
                            uds.extend(vec![0x0; param.byte_position() as usize - uds.len()]);
                        }
                        let short_name = param.short_name().ok_or_else(|| {
                            DiagServiceError::InvalidDatabase(format!(
                                "Unable to find short name for param: {}",
                                param.short_name().unwrap_or_default()
                            ))
                        })?;

                        if let Some(value) = json_values.get(short_name) {
                            // Setting parent byte position
                            // to 0 because this is the uppermost level.
                            self.map_param_to_uds(param, value, &mut uds, 0)?;
                        } else {
                            return Err(DiagServiceError::BadPayload(format!(
                                "Missing parameter: {short_name}"
                            )));
                        }
                    }
                }
            }
        }

        let (new_session, new_security) =
            self.lookup_state_transition_by_diagcomm_for_active(&(mapped_dc.into()));
        tracing::Span::current().record("output", util::tracing::print_hex(&uds, 10));
        Ok(ServicePayload {
            data: uds,
            source_address: self.tester_address,
            target_address: self.logical_address,
            new_session,
            new_security,
        })
    }

    /// Looks up a single ECU job by name for the current ECU variant.
    /// # Errors
    /// Will return `Err` if the job cannot be found in the database
    /// Unlikely other case is that neither a lookup in the current nor the base variant succeeded.
    #[tracing::instrument(skip(self), fields(ecu_name = self.ecu_name, job_name))]
    fn lookup_single_ecu_job(&self, job_name: &str) -> Result<single_ecu::Job, DiagServiceError> {
        tracing::debug!("Looking up single ECU job");

        self.variant()
            .and_then(|variant| {
                variant.diag_layer().and_then(|diag_layer| {
                    diag_layer.single_ecu_jobs().and_then(|jobs| {
                        jobs.iter().find(|j| {
                            j.diag_comm().is_some_and(|dc| {
                                dc.short_name()
                                    .is_some_and(|n| n.eq_ignore_ascii_case(job_name))
                            })
                        })
                    })
                })
            })
            .or_else(|| {
                self.diag_database
                    .base_variant()
                    .ok()?
                    .diag_layer()
                    .and_then(|diag_layer| {
                        diag_layer.single_ecu_jobs().and_then(|jobs| {
                            jobs.iter().find(|j| {
                                j.diag_comm().is_some_and(|dc| {
                                    dc.short_name()
                                        .is_some_and(|n| n.eq_ignore_ascii_case(job_name))
                                })
                            })
                        })
                    })
            })
            .map(Into::into)
            .ok_or(DiagServiceError::NotFound(None))
    }

    /// Lookup a service by a given function class name and service id.
    /// # Errors
    /// Will return `Err` if the lookup failed
    fn lookup_service_through_func_class(
        &self,
        func_class_name: &str,
        service_id: u8,
    ) -> Result<cda_interfaces::DiagComm, DiagServiceError> {
        self.search_diag_services(|service| {
            service
                .diag_comm()
                .and_then(|dc| {
                    dc.funct_class().and_then(|classes| {
                        classes.iter().find(|fc| {
                            fc.short_name()
                                .is_some_and(|name| name.eq_ignore_ascii_case(func_class_name))
                        })
                    })
                })
                .filter(|_| service.request_id().is_some_and(|id| id == service_id))
                .is_some()
        })
        .and_then(|service| service.try_into().ok())
        .ok_or(DiagServiceError::NotFound(None))
    }

    /// Lookup a service by its service id for the current ECU variant.
    /// This will first look up the service in the current variant, then in the base variant
    /// # Errors
    /// Will return `Err` if either the variant or base variant cannot be resolved.
    fn lookup_service_names_by_sid(&self, service_id: u8) -> Result<Vec<String>, DiagServiceError> {
        let services = self
            .lookup_services_by_sid(service_id)?
            .iter()
            .filter_map(|service| service.diag_comm())
            .filter_map(|dc| dc.short_name())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();

        Ok(services)
    }

    fn get_components_data_info(&self) -> Vec<ComponentDataInfo> {
        self.get_diag_layer_all_variants()
            .iter()
            .filter_map(|dl| dl.diag_services())
            .flat_map(|svcs| svcs.iter())
            .map(datatypes::DiagService)
            .filter_map(|service| {
                let diag_comm = service.diag_comm()?;
                let short_name = diag_comm.short_name()?;
                if !short_name.ends_with("_Read") {
                    return None;
                }
                Some(ComponentDataInfo {
                    category: diag_comm.semantic().unwrap_or_default().to_owned(),
                    id: diag_comm
                        .short_name()
                        .map(|s| s.replace("_Read", "").to_lowercase())
                        .unwrap_or_default(),
                    name: diag_comm
                        .long_name()
                        .and_then(|ln| ln.value().map(|v| v.to_owned().replace(" Read", "")))
                        .unwrap_or_default(),
                })
            })
            .collect()
    }

    fn get_components_single_ecu_jobs_info(&self) -> Vec<ComponentDataInfo> {
        self.get_diag_layer_all_variants()
            .iter()
            .filter_map(|dl| dl.single_ecu_jobs())
            .flat_map(|jobs| jobs.iter())
            .filter_map(|job| {
                let diag_comm = job.diag_comm()?;
                let semantic = diag_comm.semantic()?;
                Some(ComponentDataInfo {
                    category: semantic.to_lowercase(),
                    id: diag_comm
                        .short_name()
                        .map(|n| n.strip_suffix("_Read").unwrap_or(n).to_lowercase())
                        .unwrap_or_default(),
                    name: diag_comm
                        .long_name()
                        .and_then(|ln| ln.value().map(ToOwned::to_owned))
                        .unwrap_or_default(),
                })
            })
            .collect()
    }

    fn set_session(&self, session: &str, expiration: Duration) -> Result<(), DiagServiceError> {
        self.access_control.lock().session = Some(session.to_owned());
        self.start_reset_task(expiration)
    }

    fn set_security_access(
        &self,
        security_access: &str,
        expiration: Duration,
    ) -> Result<(), DiagServiceError> {
        tracing::debug!(
        ecu_name = self.ecu_name,
            security_access = %security_access,
            "Setting security access"
        );
        self.access_control.lock().security = Some(security_access.to_owned());
        self.start_reset_task(expiration)
    }

    fn lookup_session_change(
        &self,
        target_session_name: &str,
    ) -> Result<cda_interfaces::DiagComm, DiagServiceError> {
        let current_session_name =
            self.access_control
                .lock()
                .session
                .clone()
                .ok_or(DiagServiceError::InvalidSession(
                    "ECU session is none".to_string(),
                ))?;

        self.lookup_state_transition_for_active(
            semantics::SESSION,
            &current_session_name,
            target_session_name,
        )
    }

    fn lookup_security_access_change(
        &self,
        level: &str,
        seed_service: Option<&String>,
        has_key: bool,
    ) -> Result<SecurityAccess, DiagServiceError> {
        let current_security_name = self.security_access()?;

        if has_key {
            let security_service = self.lookup_state_transition_for_active(
                semantics::SECURITY,
                &current_security_name,
                level,
            )?;
            Ok(SecurityAccess::SendKey(security_service))
        } else {
            let request_seed_service = self
                .lookup_services_by_sid(service_ids::SECURITY_ACCESS)?
                .into_iter()
                .find(|service| {
                    let service: datatypes::DiagService = (**service).into();

                    let Some(sid) = service.request_id() else {
                        return false;
                    };
                    let Some((sub_func, _)) = service.request_sub_function_id() else {
                        return false;
                    };

                    let name_matches = if let Some(seed_service_name) = seed_service {
                        service.diag_comm().is_some_and(|dc| {
                            dc.short_name().is_some_and(|n| {
                                let n = n.replace('_', "");
                                starts_with_ignore_ascii_case(&n, seed_service_name)
                            })
                        })
                    } else {
                        true
                    };

                    // ISO 14229-1:2020 specifies the given ranges for request seed
                    // 2 parameters: sid_rq and sub_func
                    // needed because the ranges for request seed and send key overlap
                    sid == service_ids::SECURITY_ACCESS
                        && matches!(sub_func, 1 | 3..=5 | 7..=41)
                        && service
                            .request()
                            .is_some_and(|r| r.params().is_some_and(|p| p.len() == 2))
                        && name_matches
                })
                .ok_or(DiagServiceError::NotFound(None))?;

            let request_seed_service = request_seed_service.try_into()?;

            Ok(SecurityAccess::RequestSeed(request_seed_service))
        }
    }

    async fn get_send_key_param_name(
        &self,
        diag_service: &cda_interfaces::DiagComm,
    ) -> Result<String, DiagServiceError> {
        let mapped_service = self.lookup_diag_service(diag_service).await?;
        let request = mapped_service
            .request()
            .ok_or(DiagServiceError::RequestNotSupported(format!(
                "Service '{}' is not supported",
                diag_service.name
            )))?;

        request
            .params()
            .and_then(|params| {
                params.iter().find_map(|p| {
                    if p.semantic().is_some_and(|s| s == semantics::DATA) {
                        p.short_name().map(ToOwned::to_owned)
                    } else {
                        None
                    }
                })
            })
            .ok_or(DiagServiceError::InvalidDatabase(
                "No parameter found for sending key".to_owned(),
            ))
    }

    fn session(&self) -> Result<String, DiagServiceError> {
        self.access_control
            .lock()
            .session
            .clone()
            .ok_or(DiagServiceError::InvalidSession(
                "ECU session is none".to_string(),
            ))
    }

    fn security_access(&self) -> Result<String, DiagServiceError> {
        self.access_control
            .lock()
            .security
            .clone()
            .ok_or(DiagServiceError::InvalidSession(
                "ECU security is none".to_string(),
            ))
    }

    /// Returns all services in /configuration, i.e. 0x22 and 0x2E
    /// that are in the functional group varcoding.
    fn get_components_configurations_info(
        &self,
    ) -> Result<Vec<ComponentConfigurationsInfo>, DiagServiceError> {
        let diag_layers = [
            self.variant().and_then(|v| v.diag_layer()),
            self.diag_database
                .base_variant()
                .ok()
                .and_then(|v| v.diag_layer()),
        ]
        .into_iter()
        .flatten()
        .map(Into::into)
        .collect::<Vec<datatypes::DiagLayer>>();

        let var_coding_func_class_short_name = diag_layers
            .iter()
            .filter_map(|dl| dl.funct_classes())
            .flat_map(|fc_vec| fc_vec.iter())
            .find_map(|fc| {
                fc.short_name().filter(|name| {
                    name.eq_ignore_ascii_case(
                        &self.database_naming_convention.functional_class_varcoding,
                    )
                })
            })
            .ok_or(DiagServiceError::NotFound(None))?;

        let configuration_sids = [
            service_ids::READ_DATA_BY_IDENTIFIER,
            service_ids::WRITE_DATA_BY_IDENTIFIER,
        ];

        // Maps a common abbreviated service short name (using the configured affixes) to
        // a vector of bytes of: service_id, ID_parameter_coded_const
        let mut result_map: HashMap<String, HashSet<Vec<u8>>> = HashMap::new();

        // Maps common short name to long name
        let mut long_name_map: HashMap<String, String> = HashMap::new();

        // Iterate over all services of the variant and the base
        diag_layers
            .iter()
            .filter_map(|dl| dl.diag_services())
            .flat_map(|services| services.iter())
            .map(datatypes::DiagService)
            .filter(|service| {
                service
                    .request_id()
                    .is_some_and(|id| configuration_sids.contains(&id))
            })
            .filter_map(|service| {
                service
                    .diag_comm()
                    .map(|dc| (service, datatypes::DiagComm(dc)))
            })
            .filter(|(_, dc)| {
                dc.funct_class().is_some_and(|fc| {
                    fc.iter().any(|fc| {
                        fc.short_name()
                            .is_some_and(|n| n == var_coding_func_class_short_name)
                    })
                })
            })
            .for_each(|(service, diag_comm)| {
                // trim short names so write and read services are grouped together
                let common_short_name = diag_comm
                    .short_name()
                    .map(|short_name| {
                        self.database_naming_convention
                            .trim_short_name_affixes(short_name)
                    })
                    .unwrap_or_default();

                // trim the long name so we can return a descriptive name
                if !long_name_map.contains_key(&common_short_name)
                    && let Some(long_name) = diag_comm.long_name().and_then(|ln| {
                        ln.value().map(|long_name| {
                            self.database_naming_convention
                                .trim_long_name_affixes(long_name)
                        })
                    })
                {
                    long_name_map.insert(common_short_name.clone(), long_name);
                }

                let Some(service_id) = service.request_id() else {
                    return;
                };
                let Some((sub_function_id, sub_func_id_bit_len)) =
                    service.request_sub_function_id()
                else {
                    return;
                };

                // collect the coded const bytes of the parameter expressing the ID
                let bytes = sub_function_id.to_be_bytes();
                let Some(id_param_bytes) = bytes.get((4 - (sub_func_id_bit_len as usize / 8))..)
                else {
                    return;
                };
                // compile the first bytes of the raw uds payload
                let mut service_abstract_entry = Vec::with_capacity(1 + id_param_bytes.len());
                service_abstract_entry.push(service_id);
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

    fn lookup_dtc_services(
        &self,
        service_types: Vec<DtcReadInformationFunction>,
    ) -> Result<HashMap<DtcReadInformationFunction, DtcLookup>, DiagServiceError> {
        self.lookup_services_by_sid(service_ids::READ_DTC_INFORMATION)?
            .into_iter()
            .filter_map(|service| {
                let (sub_function_id, _) = service.request_sub_function_id()?;
                service_types
                    .iter()
                    .find(|st| (**st as u16) == sub_function_id)
                    .map(|st| (service, st))
            })
            .map(|(service, dtc_service_type)| {
                let scope = service
                    .diag_comm()
                    .and_then(|dc| dc.funct_class())
                    // using first fc for lack of better option
                    .and_then(|fc| fc.iter().next())
                    .and_then(|fc| fc.short_name())
                    .map(|s| s.replace('_', ""))
                    .unwrap_or(dtc_service_type.default_scope().to_owned());

                let service_short_name = service
                    .diag_comm()
                    .and_then(|dc| dc.short_name().map(ToOwned::to_owned))
                    .ok_or_else(|| {
                        DiagServiceError::InvalidDatabase("No DiagComm found".to_owned())
                    })?;

                let params: Vec<datatypes::Parameter> = service
                    .pos_responses()
                    .map(|responses| {
                        responses
                            .iter()
                            .flat_map(|r| r.params().into_iter().flatten())
                            .map(datatypes::Parameter)
                            .collect()
                    })
                    .ok_or_else(|| {
                        DiagServiceError::ParameterConversionError(
                            "No positive response found for DTC service".to_owned(),
                        )
                    })?;

                let dtcs: Vec<cda_interfaces::datatypes::DtcRecord> =
                    Self::find_dtc_dop_in_params(&params)?
                        .and_then(|dtc_dop| {
                            dtc_dop.dtcs().map(|dtcs| {
                                dtcs.iter()
                                    .map(|dtc| {
                                        let record: cda_interfaces::datatypes::DtcRecord =
                                            dtc.into();
                                        record
                                    })
                                    .collect()
                            })
                        })
                        .unwrap_or_default();

                Ok((
                    *dtc_service_type,
                    DtcLookup {
                        scope,
                        service: cda_interfaces::DiagComm {
                            name: service_short_name.clone(),
                            type_: DiagCommType::Faults,
                            lookup_name: Some(service_short_name),
                        },
                        dtcs,
                    },
                ))
            })
            .collect()
    }

    async fn is_service_allowed(
        &self,
        service: &cda_interfaces::DiagComm,
        security_plugin: &DynamicPlugin,
    ) -> Result<(), DiagServiceError> {
        let mapped_service = self.lookup_diag_service(service).await?;
        Self::check_security_plugin(security_plugin, &mapped_service)
    }

    fn functional_groups(&self) -> Vec<String> {
        let Ok(groups) = self.diag_database.functional_groups() else {
            return Vec::new();
        };
        groups
            .into_iter()
            .filter_map(|group| {
                group
                    .diag_layer()
                    .and_then(|dl| dl.short_name().map(str::to_lowercase))
            })
            .collect::<Vec<_>>()
    }
}

impl<S: SecurityPlugin> cda_interfaces::UdsComParamProvider for EcuManager<S> {
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

impl<S: SecurityPlugin> cda_interfaces::DoipComParamProvider for EcuManager<S> {
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

impl<S: SecurityPlugin> EcuManager<S> {
    /// Load diagnostic database for given path
    ///
    /// The created `DiagServiceManager` stores the loaded database as well as some
    /// frequently used values like the tester/logical addresses and required information
    /// for variant detection.
    ///
    /// `com_params` are used to extract settings from the database.
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
    #[allow(clippy::too_many_lines)] // todo split into smaller functions
    pub fn new(
        database: datatypes::DiagnosticDatabase,
        protocol: Protocol,
        com_params: &ComParams,
        database_naming_convention: DatabaseNamingConvention,
    ) -> Result<Self, DiagServiceError> {
        let variant_detection = variant_detection::prepare_variant_detection(&database)?;

        let data_protocol = into_db_protocol(&database, protocol)?;

        let logical_gateway_address = match database.find_logical_address(
            datatypes::LogicalAddressType::Gateway(
                com_params.doip.logical_gateway_address.name.clone(),
            ),
            &database,
            &data_protocol,
        ) {
            Ok(address) => address,
            Err(e) => {
                tracing::error!("Failed to find logical gateway address: {e}");
                com_params.doip.logical_gateway_address.default
            }
        };

        let logical_ecu_address = match database.find_logical_address(
            datatypes::LogicalAddressType::Ecu(
                com_params.doip.logical_response_id_table_name.clone(),
                com_params.doip.logical_ecu_address.name.clone(),
            ),
            &database,
            &data_protocol,
        ) {
            Ok(address) => address,
            Err(e) => {
                tracing::error!("Failed to find logical ECU address: {e}");
                com_params.doip.logical_ecu_address.default
            }
        };

        let logical_functional_address = match database.find_logical_address(
            datatypes::LogicalAddressType::Functional(
                com_params.doip.logical_functional_address.name.clone(),
            ),
            &database,
            &data_protocol,
        ) {
            Ok(address) => address,
            Err(e) => {
                tracing::error!("Failed to find logical functional address: {e}");
                com_params.doip.logical_functional_address.default
            }
        };

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

        let ecu_name = database
            .ecu_data()?
            .ecu_name()
            .map(ToOwned::to_owned)
            .ok_or_else(|| DiagServiceError::InvalidDatabase("ECU name not found".to_owned()))?;

        let res = Self {
            diag_database: database,
            db_cache: DbCache::default(),
            ecu_name,
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
            variant_index: None,
            state: EcuState::NotTested,
            protocol,
            access_control: Arc::new(Mutex::new(SessionControl {
                session: None,
                security: None,
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
            security_plugin_phantom: std::marker::PhantomData::<S>,
        };

        Ok(res)
    }

    fn variant(&self) -> Option<datatypes::Variant<'_>> {
        let idx = self.variant_index?;
        let variants = self.diag_database.ecu_data().ok()?.variants()?;
        Some(variants.get(idx).into())
    }

    fn get_diag_layer_all_variants(&self) -> Vec<datatypes::DiagLayer<'_>> {
        let ecu_data = match self.diag_database.ecu_data() {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(error = ?e, "Failed to get ECU data");
                return Vec::new();
            }
        };

        ecu_data
            .variants()
            .into_iter()
            .flat_map(|vars| vars.iter())
            .filter_map(|variant| variant.diag_layer())
            .map(datatypes::DiagLayer)
            .collect::<Vec<_>>()
    }

    /// Lookup a diagnostic service by its diag comm definition.
    /// This is treated special with a cache because it is used for *every* UDS request.
    pub(in crate::diag_kernel) async fn lookup_diag_service(
        &self,
        diag_comm: &cda_interfaces::DiagComm,
    ) -> Result<datatypes::DiagService<'_>, DiagServiceError> {
        let lookup_name = if let Some(name) = &diag_comm.lookup_name {
            name.to_owned()
        } else {
            match diag_comm.action() {
                DiagCommAction::Read => format!("{}_Read", diag_comm.name),
                DiagCommAction::Write => format!("{}_Write", diag_comm.name),
                DiagCommAction::Start => format!("{}_Start", diag_comm.name),
            }
        }
        .to_lowercase();
        let lookup_id = STRINGS.get_or_insert(&lookup_name);

        if let Some(Some(location)) = self.db_cache.diag_services.read().await.get(&lookup_id) {
            return match self.get_service_by_location(location) {
                Some(service) => Ok(service),
                None => Err(DiagServiceError::NotFound(None)), // cached negative result
            };
        }

        let prefixes = diag_comm.type_.service_prefixes();
        let predicate = |service: &datatypes::DiagService<'_>| {
            service.diag_comm().is_some_and(|dc| {
                dc.short_name()
                    .is_some_and(|name| starts_with_ignore_ascii_case(name, &lookup_name))
            }) && service
                .request_id()
                .is_some_and(|sid| prefixes.contains(&sid))
        };

        // Search and cache the location
        if let Some((service, location)) = self.search_with_location(&predicate) {
            self.db_cache
                .diag_services
                .write()
                .await
                .insert(lookup_id, Some(location));
            return Ok(service);
        }

        self.db_cache
            .diag_services
            .write()
            .await
            .insert(lookup_id, None);
        Err(DiagServiceError::NotFound(None))
    }

    fn search_with_location<F>(
        &self,
        predicate: &F,
    ) -> Option<(datatypes::DiagService<'_>, CacheLocation)>
    where
        F: Fn(&datatypes::DiagService<'_>) -> bool,
    {
        // Search in variant
        if let Some((idx, service)) = self
            .variant()
            .and_then(|v| v.diag_layer())
            .and_then(|dl| dl.diag_services())
            .and_then(|services| {
                services.iter().enumerate().find_map(|(idx, s)| {
                    let service = datatypes::DiagService(s);
                    predicate(&service).then_some((idx, service))
                })
            })
        {
            return Some((service, CacheLocation::Variant(idx)));
        }

        // Search in base variant
        if let Some((idx, service)) = self
            .diag_database
            .base_variant()
            .ok()
            .and_then(|v| v.diag_layer())
            .and_then(|dl| dl.diag_services())
            .and_then(|services| {
                services.iter().enumerate().find_map(|(idx, s)| {
                    let service = datatypes::DiagService(s);
                    predicate(&service).then_some((idx, service))
                })
            })
        {
            return Some((service, CacheLocation::BaseVariant(idx)));
        }

        // Search in ECU shared
        if let Some((idx, service)) = self.find_ecu_shared_services().and_then(|services| {
            services
                .iter()
                .enumerate()
                .find_map(|(idx, s)| predicate(s).then_some((idx, s.clone())))
        }) {
            return Some((service, CacheLocation::EcuShared(idx)));
        }

        None
    }

    fn get_service_by_location(
        &self,
        location: &CacheLocation,
    ) -> Option<datatypes::DiagService<'_>> {
        match location {
            CacheLocation::Variant(idx) => self
                .variant()
                .and_then(|v| v.diag_layer())
                .and_then(|dl| dl.diag_services())
                .map(|s| s.get(*idx))
                .map(datatypes::DiagService),
            CacheLocation::BaseVariant(idx) => self
                .diag_database
                .base_variant()
                .ok()
                .and_then(|v| v.diag_layer())
                .and_then(|dl| dl.diag_services())
                .map(|s| s.get(*idx))
                .map(datatypes::DiagService),
            CacheLocation::EcuShared(idx) => self
                .find_ecu_shared_services()
                .and_then(|services| services.get(*idx).cloned()),
        }
    }

    fn search_diag_services<F>(&self, mut predicate: F) -> Option<datatypes::DiagService<'_>>
    where
        F: for<'a> FnMut(&datatypes::DiagService<'a>) -> bool,
    {
        // Search in current variant
        if let Some(service) = self
            .variant()
            .and_then(|v| v.diag_layer())
            .and_then(|dl| dl.diag_services())
            .and_then(|services| {
                services.into_iter().find_map(|service| {
                    let service = datatypes::DiagService(service);
                    predicate(&service).then_some(service)
                })
            })
        {
            return Some(service);
        }

        // Search in base variant
        if let Some(service) = self
            .diag_database
            .base_variant()
            .ok()
            .and_then(|v| v.diag_layer())
            .and_then(|dl| dl.diag_services())
            .and_then(|services| {
                services.into_iter().find_map(|service| {
                    let service = datatypes::DiagService(service);
                    predicate(&service).then_some(service)
                })
            })
        {
            return Some(service);
        }

        // Search in ECU shared services
        self.find_ecu_shared_services()?
            .into_iter()
            .find(|service| predicate(service))
    }

    fn find_ecu_shared_services(&self) -> Option<Vec<datatypes::DiagService<'_>>> {
        fn find_ecu_shared_services_recursive<'a>(
            parent_refs: impl Iterator<Item = impl Into<datatypes::ParentRef<'a>>>,
        ) -> Option<Vec<datatypes::DiagService<'a>>> {
            parent_refs.into_iter().find_map(|parent_ref| {
                let parent_ref = parent_ref.into();

                match parent_ref.ref_type().try_into() {
                    Ok(datatypes::ParentRefType::EcuSharedData) => Some(
                        parent_ref
                            .ref__as_ecu_shared_data()
                            .and_then(|ecu_shared| ecu_shared.diag_layer())
                            .and_then(|dl| dl.diag_services())
                            .into_iter()
                            .flatten()
                            .map(datatypes::DiagService)
                            .collect(),
                    ),
                    Ok(datatypes::ParentRefType::FunctionalGroup) => parent_ref
                        .ref__as_functional_group()
                        .and_then(|fg| fg.parent_refs())
                        .and_then(|nested_refs| {
                            find_ecu_shared_services_recursive(nested_refs.iter())
                        }),
                    _ => None,
                }
            })
        }

        self.diag_database
            .ecu_data()
            .ok()?
            .functional_groups()?
            .iter()
            .find_map(|fg| {
                fg.parent_refs().and_then(|parent_refs| {
                    find_ecu_shared_services_recursive(parent_refs.iter().map(datatypes::ParentRef))
                })
            })
    }

    fn map_param_from_uds(
        &self,
        mapped_service: &datatypes::DiagService,
        param: &datatypes::Parameter,
        param_name: &str,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
    ) -> Result<(), DiagServiceError> {
        match param.param_type()? {
            datatypes::ParamType::CodedConst => {
                Self::map_param_coded_const_from_uds(param, param_name, uds_payload, data)?;
            }
            datatypes::ParamType::MatchingRequestParam => {
                self.map_param_matching_request_from_uds(
                    mapped_service,
                    param,
                    param_name,
                    uds_payload,
                    data,
                )?;
            }
            datatypes::ParamType::Value => {
                self.map_param_value_from_uds(mapped_service, param, uds_payload, data)?;
            }
            datatypes::ParamType::Reserved => {
                Self::map_param_reserved_from_uds(param, param_name, uds_payload, data)?;
            }
            datatypes::ParamType::TableEntry => {
                tracing::error!("TableStructParam not implemented.");
            }
            datatypes::ParamType::Dynamic => {
                tracing::error!("Dynamic ParamType not implemented.");
            }
            datatypes::ParamType::LengthKey => {
                tracing::error!("LengthKey ParamType not implemented.");
            }
            datatypes::ParamType::NrcConst => {
                tracing::error!("NrcConst ParamType not implemented.");
            }
            datatypes::ParamType::PhysConst => {
                tracing::error!("PhysConst ParamType not implemented.");
            }
            datatypes::ParamType::System => {
                tracing::error!("System ParamType not implemented.");
            }
            datatypes::ParamType::TableKey => {
                tracing::error!("TableKey ParamType not implemented.");
            }
            datatypes::ParamType::TableStruct => {
                tracing::error!("TableStruct ParamType not implemented.");
            }
        }
        Ok(())
    }

    fn map_param_reserved_from_uds(
        param: &datatypes::Parameter,
        param_name: &str,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
    ) -> Result<(), DiagServiceError> {
        let r = param
            .specific_data_as_reserved()
            .ok_or(DiagServiceError::InvalidDatabase(
                "Expected Reserved specific data".to_owned(),
            ))?;

        let coded_type = datatypes::DiagCodedType::new_high_low_byte_order(
            datatypes::DataType::UInt32,
            datatypes::DiagCodedTypeVariant::StandardLength(datatypes::StandardLengthType {
                bit_length: r.bit_length(),
                bit_mask: None,
                condensed: false,
            }),
        )?;

        let (param_data, bit_len) = coded_type.decode(
            uds_payload.data()?,
            param.byte_position() as usize,
            param.bit_position() as usize,
        )?;

        data.insert(
            param_name.to_owned(),
            DiagDataTypeContainer::RawContainer(DiagDataTypeContainerRaw {
                data: param_data,
                bit_len,
                data_type: datatypes::DataType::UInt32,
                compu_method: None,
            }),
        );
        Ok(())
    }

    fn map_param_value_from_uds(
        &self,
        mapped_service: &datatypes::DiagService,
        param: &datatypes::Parameter,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
    ) -> Result<(), DiagServiceError> {
        let v = param
            .specific_data_as_value()
            .ok_or(DiagServiceError::InvalidDatabase(
                "Expected Value specific data".to_owned(),
            ))?;

        let dop =
            v.dop()
                .map(datatypes::DataOperation)
                .ok_or(DiagServiceError::InvalidDatabase(
                    "Value DoP is None".to_owned(),
                ))?;
        self.map_dop_from_uds(mapped_service, &dop, param, uds_payload, data)?;
        Ok(())
    }

    fn map_param_matching_request_from_uds(
        &self,
        mapped_service: &datatypes::DiagService,
        param: &datatypes::Parameter,
        param_name: &str,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
    ) -> Result<(), DiagServiceError> {
        let matching_req_param = param.specific_data_as_matching_request_param().ok_or(
            DiagServiceError::InvalidDatabase(
                "Expected MatchingRequestParam specific data".to_owned(),
            ),
        )?;

        let request = mapped_service
            .request()
            .ok_or(DiagServiceError::InvalidDatabase(
                "Expected request for service".to_owned(),
            ))?;

        let matching_req_param_byte_pos = u32::try_from(matching_req_param.request_byte_pos())
            .map_err(|e| {
                DiagServiceError::InvalidDatabase(format!(
                    "Matching request param byte position conversion error: {e},"
                ))
            })?;

        let matching_request_param = request
            .params()
            .and_then(|params| {
                params
                    .iter()
                    .map(datatypes::Parameter)
                    .find(|p| p.byte_position() == matching_req_param_byte_pos)
            })
            .ok_or_else(|| {
                DiagServiceError::UdsLookupError(format!(
                    "No matching request parameter found for {}",
                    param.short_name().unwrap_or_default()
                ))
            })?;

        let param_byte_pos = param.byte_position();
        let matching_req_param_byte_pos = u32::try_from(matching_req_param.request_byte_pos())
            .map_err(|e| {
                DiagServiceError::InvalidDatabase(format!(
                    "Matching request param byte position conversion error: {e}",
                ))
            })?;

        let pop = matching_req_param_byte_pos < param_byte_pos;
        if pop {
            uds_payload.push_slice(param_byte_pos as usize, uds_payload.len())?;
        }

        self.map_param_from_uds(
            mapped_service,
            &matching_request_param,
            param_name,
            uds_payload,
            data,
        )?;

        if pop {
            uds_payload.pop_slice()?;
        }
        Ok(())
    }

    fn map_param_coded_const_from_uds(
        param: &datatypes::Parameter,
        param_name: &str,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
    ) -> Result<(), DiagServiceError> {
        let c = param
            .specific_data_as_coded_const()
            .ok_or(DiagServiceError::InvalidDatabase(
                "Expected CodedConst specific data".to_owned(),
            ))?;

        let diag_type: datatypes::DiagCodedType = c
            .diag_coded_type()
            .map(TryInto::try_into)
            .transpose()?
            .ok_or(DiagServiceError::InvalidDatabase(
                "Expected DiagCodedType in CodedConst specific data".to_owned(),
            ))?;

        let value = operations::extract_diag_data_container(param, uds_payload, &diag_type, None)?;

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
            DiagDataTypeContainer::DtcStruct(_dtc) => {
                return Err(DiagServiceError::ParameterConversionError(
                    "DtcStruct not supported for UDS payload".to_owned(),
                ));
            }
        };
        let const_value = c.coded_value().ok_or(DiagServiceError::InvalidDatabase(
            "CodedConst has no coded value".to_owned(),
        ))?;
        let expected = operations::string_to_vec_u8(diag_type.base_datatype(), const_value)?
            .into_iter()
            .collect::<Vec<_>>();
        let expected = expected.get(expected.len() - value.data.len()..).ok_or(
            DiagServiceError::BadPayload("Expected value slice out of bounds".to_owned()),
        )?;
        if value.data != expected {
            return Err(DiagServiceError::BadPayload(format!(
                "{}: Expected {:?}, got {:?}",
                param.short_name().unwrap_or_default(),
                expected,
                value.data
            )));
        }

        data.insert(
            param_name.to_owned(),
            DiagDataTypeContainer::RawContainer(value),
        );
        Ok(())
    }

    fn map_mux_to_uds(
        &self,
        mux_dop: &datatypes::MuxDop,
        value: &serde_json::Value,
        uds_payload: &mut Vec<u8>,
    ) -> Result<(), DiagServiceError> {
        let Some(value) = value.as_object() else {
            return Err(DiagServiceError::InvalidRequest(format!(
                "Expected value to be object type, but it was: {value:#?}"
            )));
        };

        let switch_key = &mux_dop
            .switch_key()
            .ok_or(DiagServiceError::InvalidDatabase(
                "Mux switch key is None".to_owned(),
            ))?;
        let switch_key_dop = switch_key.dop().map(datatypes::DataOperation).ok_or(
            DiagServiceError::InvalidDatabase("Mux switch key DoP is None".to_owned()),
        )?;

        match switch_key_dop.variant()? {
            datatypes::DataOperationVariant::Normal(normal_dop) => {
                let switch_key_diag_type = normal_dop.diag_coded_type()?;
                let mut mux_payload = Vec::new();

                // Process selector and encode switch key if present
                let selected_case = value
                    .get("Selector")
                    .or(Some(&serde_json::Value::String("0".to_owned())))
                    .map(|selector| -> Result<_, DiagServiceError> {
                        let switch_key_value = json_value_to_uds_data(
                            switch_key_diag_type.base_datatype(),
                            normal_dop.compu_method().map(Into::into),
                            selector,
                        )?;

                        switch_key_diag_type.encode(
                            switch_key_value.clone(),
                            &mut mux_payload,
                            switch_key.byte_position() as usize,
                            switch_key.bit_position().unwrap_or(0) as usize,
                        )?;

                        let selector = operations::uds_data_to_serializable(
                            switch_key_diag_type.base_datatype(),
                            None,
                            false,
                            &mux_payload,
                        )?;

                        Ok(
                            mux_case_struct_from_selector_value(mux_dop, &selector).and_then(
                                |(case, struct_)| case.short_name().map(|name| (name, struct_)),
                            ),
                        )
                    })
                    .transpose()?
                    .flatten();

                // Get case name and structure from selected case or default
                let (case_name, struct_) = selected_case
                    .or_else(|| {
                        mux_dop.default_case().and_then(|default_case| {
                            default_case.short_name().and_then(|name| {
                                default_case
                                    .structure()
                                    .and_then(|s| {
                                        s.specific_data_as_structure().map(|s| Some(s.into()))
                                    })
                                    .map(|struct_| (name, struct_))
                            })
                        })
                    })
                    .ok_or_else(|| {
                        DiagServiceError::InvalidRequest(
                            "Cannot find selector value or default case".to_owned(),
                        )
                    })?;

                if let Some(struct_) = struct_ {
                    let struct_data = value.get(case_name).ok_or_else(|| {
                        DiagServiceError::BadPayload(format!(
                            "Mux case {case_name} value not found in json"
                        ))
                    })?;

                    let mut struct_payload = Vec::new();
                    self.map_struct_to_uds(&struct_, 0, struct_data, &mut struct_payload)?;

                    mux_payload.extend_from_slice(&struct_payload);
                }

                uds_payload.extend_from_slice(&mux_payload);
                Ok(())
            }
            _ => Err(DiagServiceError::InvalidDatabase(
                "Mux switch key DoP is not a NormalDoP".to_owned(),
            )),
        }
    }

    fn map_struct_to_uds(
        &self,
        structure: &datatypes::StructureDop,
        struct_byte_pos: usize,
        value: &serde_json::Value,
        payload: &mut Vec<u8>,
    ) -> Result<(), DiagServiceError> {
        let Some(value) = value.as_object() else {
            return Err(DiagServiceError::InvalidRequest(format!(
                "Expected value to be object type, but it was: {value:#?}"
            )));
        };

        structure
            .params()
            .into_iter()
            .flatten()
            .map(datatypes::Parameter)
            .try_for_each(|param| {
                let short_name = param.short_name().ok_or_else(|| {
                    DiagServiceError::InvalidDatabase(
                        "Unable to find short name for param".to_owned(),
                    )
                })?;

                let param_value = value
                    .get(short_name)
                    .ok_or(DiagServiceError::InvalidRequest(format!(
                        "Parameter '{short_name}' not part of the request body"
                    )))?;

                self.map_param_to_uds(&param, param_value, payload, struct_byte_pos)
            })
    }

    fn map_param_to_uds(
        &self,
        param: &datatypes::Parameter,
        value: &serde_json::Value,
        payload: &mut Vec<u8>,
        parent_byte_pos: usize,
    ) -> Result<(), DiagServiceError> {
        //  ISO_22901-1:2008-11 7.3.5.4
        //  MATCHING-REQUEST-PARAM, DYNAMIC and NRC-CONST are only allowed in responses
        match param.param_type()? {
            datatypes::ParamType::CodedConst => Ok(()),
            datatypes::ParamType::MatchingRequestParam => Err(DiagServiceError::InvalidRequest(
                "MatchingRequestParam only supported for responses".to_owned(),
            )),
            datatypes::ParamType::Value => {
                self.map_param_value_to_uds(param, value, payload, parent_byte_pos)
            }
            datatypes::ParamType::Reserved => Self::map_reserved_param_to_uds(param, payload),
            datatypes::ParamType::TableStruct => Err(DiagServiceError::ParameterConversionError(
                "Mapping TableStructParam DoP to UDS payload not implemented".to_owned(),
            )),
            datatypes::ParamType::Dynamic => Err(DiagServiceError::ParameterConversionError(
                "Mapping Dynamic DoP to UDS payload not implemented".to_owned(),
            )),
            datatypes::ParamType::LengthKey => Err(DiagServiceError::ParameterConversionError(
                "Mapping LengthKey DoP to UDS payload not implemented".to_owned(),
            )),
            datatypes::ParamType::NrcConst => Err(DiagServiceError::ParameterConversionError(
                "Mapping NrcConst DoP to UDS payload not implemented".to_owned(),
            )),
            datatypes::ParamType::PhysConst => Err(DiagServiceError::ParameterConversionError(
                "Mapping PhysConst DoP to UDS payload not implemented".to_owned(),
            )),
            datatypes::ParamType::System => Err(DiagServiceError::ParameterConversionError(
                "Mapping System DoP to UDS payload not implemented".to_owned(),
            )),
            datatypes::ParamType::TableEntry => Err(DiagServiceError::ParameterConversionError(
                "Mapping TableEntry DoP to UDS payload not implemented".to_owned(),
            )),
            datatypes::ParamType::TableKey => Err(DiagServiceError::ParameterConversionError(
                "Mapping TableKey DoP to UDS payload not implemented".to_owned(),
            )),
        }
    }

    fn map_reserved_param_to_uds(
        param: &datatypes::Parameter,
        payload: &mut Vec<u8>,
    ) -> Result<(), DiagServiceError> {
        let reserved_param =
            param
                .specific_data_as_reserved()
                .ok_or(DiagServiceError::InvalidDatabase(
                    "Expected Reserved specific data".to_owned(),
                ))?;
        let bit_length = reserved_param.bit_length();
        let coded_type = datatypes::DiagCodedType::new_high_low_byte_order(
            datatypes::DataType::UInt32,
            datatypes::DiagCodedTypeVariant::StandardLength(datatypes::StandardLengthType {
                bit_length,
                bit_mask: None,
                condensed: false,
            }),
        )?;
        coded_type.encode(
            vec![0; bit_length as usize],
            payload,
            param.byte_position() as usize,
            param.bit_position() as usize,
        )?;

        Ok(())
    }

    fn map_param_value_to_uds(
        &self,
        param: &datatypes::Parameter,
        value: &serde_json::Value,
        payload: &mut Vec<u8>,
        parent_byte_pos: usize,
    ) -> Result<(), DiagServiceError> {
        let value_data =
            param
                .specific_data_as_value()
                .ok_or(DiagServiceError::InvalidDatabase(
                    "Expected Value specific data".to_owned(),
                ))?;

        let Some(dop) = value_data.dop().map(datatypes::DataOperation) else {
            return Err(DiagServiceError::InvalidDatabase(
                "DoP lookup failed".to_owned(),
            ));
        };
        match dop.variant()? {
            datatypes::DataOperationVariant::Normal(normal_dop) => {
                let diag_type = normal_dop.diag_coded_type()?;
                let uds_data = json_value_to_uds_data(
                    diag_type.base_datatype(),
                    normal_dop.compu_method().map(Into::into),
                    value,
                )?;
                diag_type.encode(
                    uds_data,
                    payload,
                    parent_byte_pos + param.byte_position() as usize,
                    param.bit_position() as usize,
                )?;
                Ok(())
            }
            datatypes::DataOperationVariant::EndOfPdu(end_of_pdu_dop) => {
                let Some(value) = value.as_array() else {
                    return Err(DiagServiceError::InvalidRequest(
                        "Expected array value".to_owned(),
                    ));
                };
                // Check length of provided array
                if value.len() < end_of_pdu_dop.min_number_of_items().unwrap_or(0) as usize
                    || end_of_pdu_dop.max_number_of_items().is_some_and(|max| {
                        // truncation is okay, we check for that below
                        #[allow(clippy::cast_possible_truncation)]
                        let value_len_u32 = value.len() as u32;

                        value.len() > u32::MAX as usize || max > value_len_u32
                    })
                {
                    return Err(DiagServiceError::InvalidRequest(
                        "EndOfPdu expected different amount of items".to_owned(),
                    ));
                }

                let structure = match end_of_pdu_dop.field().and_then(|s| {
                    s.basic_structure()
                        .map(|s| s.specific_data_as_structure().map(datatypes::StructureDop))
                }) {
                    Some(s) => s,
                    None => {
                        return Err(DiagServiceError::InvalidDatabase(
                            "EndOfPdu has no basic structure".to_owned(),
                        ));
                    }
                }
                .ok_or(DiagServiceError::InvalidDatabase(
                    "EndOfPdu basic structure lookup failed".to_owned(),
                ))?;

                for v in value {
                    self.map_struct_to_uds(
                        &structure,
                        param.byte_position() as usize + parent_byte_pos,
                        v,
                        payload,
                    )?;
                }
                Ok(())
            }
            datatypes::DataOperationVariant::Structure(structure_dop) => self.map_struct_to_uds(
                &structure_dop,
                param.byte_position() as usize + parent_byte_pos,
                value,
                payload,
            ),
            datatypes::DataOperationVariant::StaticField(_static_field) => {
                Err(DiagServiceError::ParameterConversionError(
                    "Mapping StaticField DoP to UDS payload not implemented".to_owned(),
                ))
            }
            datatypes::DataOperationVariant::Mux(mux_dop) => {
                self.map_mux_to_uds(&mux_dop, value, payload)
            }
            datatypes::DataOperationVariant::EnvDataDesc(_)
            | datatypes::DataOperationVariant::EnvData(_)
            | datatypes::DataOperationVariant::Dtc(_) => Err(DiagServiceError::InvalidDatabase(
                "EnvData(Desc) and DTC DoPs cannot be mapped via parameters to request, but \
                 handled via a dedicated 'faults' endpoint"
                    .to_owned(),
            )),
            datatypes::DataOperationVariant::DynamicLengthField(_dynamic_length_field) => {
                Err(DiagServiceError::ParameterConversionError(
                    "Mapping DynamicLengthField DoP to UDS payload not implemented".to_owned(),
                ))
            }
        }
    }

    fn map_struct_from_uds(
        &self,
        structure: &datatypes::StructureDop,
        mapped_service: &datatypes::DiagService,
        uds_payload: &mut Payload,
    ) -> Result<HashMap<String, DiagDataTypeContainer>, DiagServiceError> {
        let mut data = HashMap::new();
        let Some(params) = structure.params() else {
            return Ok(data);
        };

        for param in params {
            let short_name = param.short_name().ok_or_else(|| {
                DiagServiceError::InvalidDatabase("Unable to find short name for param".to_owned())
            })?;
            self.map_param_from_uds(
                mapped_service,
                &param.into(),
                short_name,
                uds_payload,
                &mut data,
            )?;
        }
        Ok(data)
    }

    fn map_nested_struct_from_uds(
        &self,
        structure: &datatypes::StructureDop,
        mapped_service: &datatypes::DiagService,
        uds_payload: &mut Payload,
        nested_structs: &mut Vec<HashMap<String, DiagDataTypeContainer>>,
    ) -> Result<(), DiagServiceError> {
        nested_structs.push(self.map_struct_from_uds(structure, mapped_service, uds_payload)?);
        Ok(())
    }

    fn map_dop_from_uds(
        &self,
        mapped_service: &datatypes::DiagService,
        dop: &datatypes::DataOperation,
        param: &datatypes::Parameter,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
    ) -> Result<(), DiagServiceError> {
        let short_name = param
            .short_name()
            .ok_or_else(|| {
                DiagServiceError::InvalidDatabase(
                    "Unable to find short name for param in Strings".to_string(),
                )
            })?
            .to_owned();

        match dop.variant()? {
            datatypes::DataOperationVariant::Normal(normal_dop) => {
                Self::map_normal_dop_from_uds(param, uds_payload, data, short_name, &normal_dop)?;
            }
            datatypes::DataOperationVariant::EndOfPdu(end_of_pdu_dop) => {
                self.map_end_of_pdu_dop_from_uds(
                    mapped_service,
                    uds_payload,
                    data,
                    short_name,
                    &end_of_pdu_dop,
                )?;
            }

            datatypes::DataOperationVariant::Structure(structure_dop) => {
                self.map_strucutre_dop_from_uds(
                    mapped_service,
                    uds_payload,
                    data,
                    &short_name,
                    &structure_dop,
                )?;
            }
            datatypes::DataOperationVariant::Dtc(dtc_dop) => {
                Self::map_dtc_dop_from_uds(param, uds_payload, data, &dtc_dop)?;
            }
            datatypes::DataOperationVariant::StaticField(static_field_dop) => {
                self.map_static_field_dop_from_uds(
                    mapped_service,
                    param,
                    uds_payload,
                    data,
                    short_name,
                    &static_field_dop,
                )?;
            }
            datatypes::DataOperationVariant::Mux(mux_dop) => {
                self.map_mux_dop_from_uds(
                    mapped_service,
                    param,
                    uds_payload,
                    data,
                    short_name,
                    &mux_dop,
                )?;
            }
            datatypes::DataOperationVariant::DynamicLengthField(dynamic_length_field_dop) => {
                self.map_dynamic_length_field_from_uds(
                    mapped_service,
                    param,
                    uds_payload,
                    data,
                    short_name,
                    &dynamic_length_field_dop,
                )?;
            }

            _ => tracing::warn!(
                "DOP variant not supported yet: {:?}",
                dop.specific_data_type().variant_name().unwrap_or("Unknown")
            ),
        }

        Ok(())
    }

    fn map_dynamic_length_field_from_uds(
        &self,
        mapped_service: &datatypes::DiagService,
        param: &datatypes::Parameter,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        short_name: String,
        dynamic_length_field_dop: &datatypes::DynamicLengthDop,
    ) -> Result<(), DiagServiceError> {
        let determine_num_items = dynamic_length_field_dop.determine_number_of_items().ok_or(
            DiagServiceError::InvalidDatabase(
                "DynamicLengthField determine_number_of_items_of_items is None".to_owned(),
            ),
        )?;

        let determine_num_items_dop = determine_num_items
            .dop()
            .map(datatypes::DataOperation)
            .ok_or(DiagServiceError::InvalidDatabase(
                "DynamicLengthField determine_number_of_items DoP is None".to_owned(),
            ))?;

        let num_items_dop = determine_num_items_dop
            .specific_data_as_normal_dop()
            .map(datatypes::NormalDop)
            .ok_or(DiagServiceError::InvalidDatabase(
                "DynamicLengthField num_items DoP is not a NormalDoP".to_owned(),
            ))?;

        let num_items_diag_type: datatypes::DiagCodedType = num_items_dop.diag_coded_type()?;

        let (num_items_data, _bit_len) = num_items_diag_type.decode(
            uds_payload
                .data()?
                .get(param.byte_position() as usize..)
                .ok_or(DiagServiceError::BadPayload(
                    "Not enough bytes to get DynamicLengthField item count".to_owned(),
                ))?,
            determine_num_items.byte_position() as usize,
            determine_num_items.bit_position() as usize,
        )?;

        let num_items_diag_val = operations::uds_data_to_serializable(
            datatypes::DataType::UInt32, // Using hard coded UInt32 as per ISO 22901-1:2008
            None,                        // Also according per spec, no compu method defined.
            false,
            &num_items_data,
        )?;

        let repeated_dop =
            dynamic_length_field_dop
                .field()
                .ok_or(DiagServiceError::InvalidDatabase(
                    "DynamicLengthField field is None".to_owned(),
                ))?;

        let num_items: u32 = num_items_diag_val.try_into()?;
        let num_items_byte_pos = determine_num_items.byte_position() as usize;
        uds_payload.set_last_read_byte_pos(num_items_byte_pos + num_items_data.len());

        let mut repeated_data = Vec::new();

        uds_payload.push_slice(
            dynamic_length_field_dop.offset() as usize,
            uds_payload.len(),
        )?;
        let mut start = uds_payload.last_read_byte_pos() + uds_payload.bytes_to_skip();

        for _ in 0..num_items {
            uds_payload.push_slice(start, uds_payload.len())?;
            if let Some(s) = repeated_dop
                .basic_structure()
                .and_then(|d| d.specific_data_as_structure().map(datatypes::StructureDop))
            {
                let struct_data = self.map_struct_from_uds(&s, mapped_service, uds_payload)?;
                repeated_data.push(struct_data);
            } else if repeated_dop.env_data_desc().is_some() {
                tracing::warn!("DynamicLengthField with EnvDataDesc not implemented");
                uds_payload.pop_slice()?;
                continue;
            } else {
                uds_payload.pop_slice()?;
                return Err(DiagServiceError::InvalidDatabase(
                    "DynamicLengthField repeated_dop is neither Structure nor EnvDataDesc"
                        .to_owned(),
                ));
            }

            uds_payload.pop_slice()?;
            start += uds_payload.last_read_byte_pos() + uds_payload.bytes_to_skip();
        }
        uds_payload.pop_slice()?;
        uds_payload.set_last_read_byte_pos(start - 1);
        data.insert(
            short_name,
            DiagDataTypeContainer::RepeatingStruct(repeated_data),
        );
        Ok(())
    }

    fn map_mux_dop_from_uds(
        &self,
        mapped_service: &datatypes::DiagService,
        param: &datatypes::Parameter,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        short_name: String,
        mux_dop: &datatypes::MuxDop,
    ) -> Result<(), DiagServiceError> {
        let param_byte_pos = param.byte_position();
        uds_payload.push_slice(param_byte_pos as usize, uds_payload.len())?;
        self.map_mux_from_uds(mapped_service, uds_payload, data, short_name, mux_dop)?;
        uds_payload.pop_slice()?;
        Ok(())
    }

    fn map_static_field_dop_from_uds(
        &self,
        mapped_service: &datatypes::DiagService,
        param: &datatypes::Parameter,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        short_name: String,
        static_field_dop: &datatypes::StaticFieldDop,
    ) -> Result<(), DiagServiceError> {
        let static_field_size =
            (static_field_dop.item_byte_size() * static_field_dop.fixed_number_of_items()) as usize;

        if uds_payload.len() < static_field_size {
            return Err(DiagServiceError::BadPayload(format!(
                "Not enough data for static field: {} < {static_field_size}",
                uds_payload.len(),
            )));
        }
        let basic_structure =
            extract_struct_dop_from_field(static_field_dop.field().map(datatypes::DopField))?;
        let mut nested_structs = Vec::new();

        for i in 0..static_field_dop.fixed_number_of_items() {
            let param_byte_pos = param.byte_position();
            let start = (param_byte_pos + i * static_field_dop.item_byte_size()) as usize;
            let end = start + static_field_dop.item_byte_size() as usize;
            uds_payload.push_slice(start, end)?;

            self.map_nested_struct_from_uds(
                &basic_structure,
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
        Ok(())
    }

    fn map_dtc_dop_from_uds(
        param: &datatypes::Parameter,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        dtc_dop: &datatypes::DtcDop,
    ) -> Result<(), DiagServiceError> {
        let coded_type: datatypes::DiagCodedType = dtc_dop.diag_coded_type()?;

        let (dtc_value, _size) = coded_type.decode(
            uds_payload.data()?,
            param.byte_position() as usize,
            param.bit_position() as usize,
        )?;

        let code: u32 = DiagDataValue::new(coded_type.base_datatype(), &dtc_value)?.try_into()?;

        let record = dtc_dop
            .dtcs()
            .and_then(|dtcs| dtcs.iter().find(|dtc| dtc.trouble_code() == code))
            .ok_or(DiagServiceError::BadPayload(format!(
                "No DTC with code {code:X} found in DTC references",
            )))?;

        data.insert(
            "DtcRecord".to_owned(),
            DiagDataTypeContainer::DtcStruct(DiagDataContainerDtc {
                code,
                display_code: record.display_trouble_code().map(ToOwned::to_owned),
                fault_name: record
                    .text()
                    .and_then(|text| text.value().map(ToOwned::to_owned))
                    .unwrap_or_default(),
                severity: record.level().unwrap_or_default(),
                bit_pos: param.byte_position(),
                bit_len: DTC_CODE_BIT_LEN,
                byte_pos: param.byte_position(),
            }),
        );
        Ok(())
    }

    fn map_strucutre_dop_from_uds(
        &self,
        mapped_service: &datatypes::DiagService,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        short_name: &str,
        structure_dop: &datatypes::StructureDop,
    ) -> Result<(), DiagServiceError> {
        let byte_size = structure_dop
            .byte_size()
            .ok_or(DiagServiceError::InvalidDatabase(
                "Structure has no byte size".to_owned(),
            ))? as usize;

        if uds_payload.len() < byte_size {
            return Err(DiagServiceError::NotEnoughData {
                expected: byte_size,
                actual: uds_payload.len(),
            });
        }

        if let Some(params) = structure_dop.params() {
            for param in params.iter().map(datatypes::Parameter) {
                self.map_param_from_uds(mapped_service, &param, short_name, uds_payload, data)?;
            }
        }
        Ok(())
    }

    fn map_end_of_pdu_dop_from_uds(
        &self,
        mapped_service: &datatypes::DiagService,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        short_name: String,
        end_of_pdu_dop: &datatypes::EndOfPdu,
    ) -> Result<(), DiagServiceError> {
        // When a response is read the values of `max-number-of-items`
        // and `min-number-of-items` are deliberately ignored,
        // according to ISO 22901:2008 7.3.6.10.6
        let struct_ =
            extract_struct_dop_from_field(end_of_pdu_dop.field().map(datatypes::DopField))?;
        let mut nested_structs = Vec::new();
        uds_payload.consume();
        loop {
            uds_payload.push_slice_to_abs_end(uds_payload.last_read_byte_pos())?;
            if !uds_payload.exhausted() {
                match self.map_nested_struct_from_uds(
                    &struct_,
                    mapped_service,
                    uds_payload,
                    &mut nested_structs,
                ) {
                    Ok(()) => {}
                    Err(e) => {
                        match e {
                            DiagServiceError::NotEnoughData { .. } => {
                                // Not enough data left to parse another struct, exit loop
                                // and ignore eventual leftover bytes
                                tracing::warn!(
                                    error = %e,
                                    "Not enough data left to parse another struct, \
                                     ignoring leftover bytes"
                                );
                                uds_payload.pop_slice()?;
                                break;
                            }
                            _ => return Err(e),
                        }
                    }
                }
            }
            uds_payload.consume();
            uds_payload.pop_slice()?;
            if uds_payload.exhausted() {
                break;
            }
        }

        data.insert(
            short_name,
            DiagDataTypeContainer::RepeatingStruct(nested_structs),
        );
        Ok(())
    }

    fn map_normal_dop_from_uds(
        param: &datatypes::Parameter,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        short_name: String,
        normal_dop: &datatypes::NormalDop,
    ) -> Result<(), DiagServiceError> {
        let diag_coded_type = normal_dop.diag_coded_type()?;
        let compu_method =
            normal_dop
                .compu_method()
                .map(Into::into)
                .ok_or(DiagServiceError::InvalidDatabase(format!(
                    "param {short_name} has no compu method"
                )))?;

        data.insert(
            short_name,
            operations::extract_diag_data_container(
                param,
                uds_payload,
                &diag_coded_type,
                Some(compu_method),
            )?,
        );
        Ok(())
    }

    fn map_mux_from_uds(
        &self,
        mapped_service: &datatypes::DiagService,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        short_name: String,
        mux_dop: &datatypes::MuxDop,
    ) -> Result<(), DiagServiceError> {
        // Byte pos is the relative position of the data in the uds_payload
        let byte_pos = mux_dop.byte_position() as usize;

        let switch_key = &mux_dop
            .switch_key()
            .ok_or(DiagServiceError::InvalidDatabase(
                "Mux switch key not defined".to_owned(),
            ))?;

        // Byte position of the switch key is relative to the mux byte position
        let mut mux_data = HashMap::new();
        let dop = switch_key.dop().map(datatypes::DataOperation).ok_or(
            DiagServiceError::InvalidDatabase("Mux switch key DoP is None".to_owned()),
        )?;

        match dop.variant()? {
            datatypes::DataOperationVariant::Normal(normal_dop) => {
                let switch_key_diag_type = normal_dop.diag_coded_type()?;

                let (switch_key_data, bit_len) = switch_key_diag_type.decode(
                    uds_payload
                        .data()?
                        .get(switch_key.byte_position() as usize..)
                        .ok_or(DiagServiceError::BadPayload(
                            "Not enough bytes to get switch key".to_owned(),
                        ))?,
                    switch_key.byte_position() as usize,
                    switch_key.bit_position().unwrap_or(0) as usize,
                )?;

                let switch_key_value = operations::uds_data_to_serializable(
                    switch_key_diag_type.base_datatype(),
                    normal_dop.compu_method().map(Into::into).as_ref(),
                    false,
                    &switch_key_data,
                )?;
                uds_payload.set_bytes_to_skip(switch_key_data.len());

                mux_data.insert(
                    "Selector".to_owned(),
                    DiagDataTypeContainer::RawContainer(DiagDataTypeContainerRaw {
                        data: switch_key_data.clone(),
                        data_type: switch_key_diag_type.base_datatype(),
                        bit_len,
                        compu_method: None,
                    }),
                );

                let (case_name, case_structure) =
                    mux_case_struct_from_selector_value(mux_dop, &switch_key_value)
                        .map(|(case, case_struct)| {
                            let name =
                                case.short_name().ok_or(DiagServiceError::InvalidDatabase(
                                    "Mux case short name not found".to_owned(),
                                ))?;
                            Ok::<_, DiagServiceError>((name.to_owned(), case_struct))
                        })
                        .transpose()?
                        .map_or_else(
                            || {
                                mux_dop
                                    .default_case()
                                    .and_then(|default| {
                                        let name = default.short_name()?.to_owned();
                                        let case_struct = default.structure().and_then(|s| {
                                            s.specific_data_as_structure()
                                                .map(datatypes::StructureDop)
                                        });
                                        Some((name, case_struct))
                                    })
                                    .ok_or_else(|| {
                                        DiagServiceError::BadPayload(format!(
                                            "Switch key value not found in mux cases and no \
                                             default case defined for MUX {short_name}"
                                        ))
                                    })
                            },
                            Ok,
                        )?;

                // Omitting the structure from a (default) case is valid and can be used
                // to have a valid switch key that is not connected with further data.
                if let Some(case_structure) = case_structure {
                    uds_payload.push_slice(byte_pos, uds_payload.len())?;
                    let case_data =
                        self.map_struct_from_uds(&case_structure, mapped_service, uds_payload)?;
                    uds_payload.pop_slice()?;
                    mux_data.insert(case_name, DiagDataTypeContainer::Struct(case_data));
                }

                data.insert(short_name, DiagDataTypeContainer::Struct(mux_data));
                Ok(())
            }
            _ => Err(DiagServiceError::InvalidDatabase(
                "Mux switch key DoP is not a NormalDoP".to_owned(),
            )),
        }
    }

    fn lookup_state_transition(
        diag_comm: &datatypes::DiagComm,
        state_chart: &datatypes::StateChart,
        current_state: &str,
    ) -> Option<String> {
        diag_comm
            .state_transition_refs()?
            .iter()
            .find_map(|st_ref| {
                let state_transition = st_ref.state_transition()?;
                state_chart
                    .state_transitions()?
                    .iter()
                    .find(|chart_st| chart_st.source_short_name_ref() == Some(current_state))
                    .and_then(|_| {
                        state_transition
                            .target_short_name_ref()
                            .map(ToOwned::to_owned)
                    })
            })
    }

    fn lookup_state_transition_by_diagcomm_for_active(
        &self,
        diag_comm: &datatypes::DiagComm,
    ) -> (Option<String>, Option<String>) {
        // not using lookup_state_chart, so we spare one lookup of the state charts
        let Ok(base_variant) = self.diag_database.base_variant() else {
            return (None, None);
        };

        let state_charts = base_variant.diag_layer().and_then(|dl| dl.state_charts());
        let state_chart_session = state_charts.as_ref().and_then(|charts| {
            charts.iter().find(|c| {
                c.semantic()
                    .is_some_and(|n| n.eq_ignore_ascii_case(semantics::SESSION))
            })
        });
        let state_chart_security = state_charts.as_ref().and_then(|charts| {
            charts.iter().find(|c| {
                c.semantic()
                    .is_some_and(|n| n.eq_ignore_ascii_case(semantics::SECURITY))
            })
        });

        let access_ctrl = self.access_control.lock();
        let new_session = access_ctrl.session.as_ref().and_then(|session| {
            state_chart_session
                .and_then(|sc| Self::lookup_state_transition(diag_comm, &(sc.into()), session))
        });
        let new_security = access_ctrl.security.as_ref().and_then(|session| {
            state_chart_security
                .and_then(|sc| Self::lookup_state_transition(diag_comm, &(sc.into()), session))
        });

        (new_session, new_security)
    }

    fn lookup_state_transition_for_active(
        &self,
        semantic: &str,
        current_state: &str,
        target_state: &str,
    ) -> Result<cda_interfaces::DiagComm, DiagServiceError> {
        let base_variant = self.diag_database.base_variant()?;
        let semantic_transitions = base_variant
            .diag_layer()
            .and_then(|dl| dl.state_charts())
            .and_then(|charts| {
                charts.iter().find_map(|c| {
                    if c.semantic()
                        .is_some_and(|n| n.eq_ignore_ascii_case(semantic))
                    {
                        c.state_transitions()
                    } else {
                        None
                    }
                })
            })
            .ok_or_else(|| {
                tracing::error!(
                    ecu_name = self.ecu_name,
                    semantic = %semantic,
                    "State chart with given semantic not found in base variant"
                );
                DiagServiceError::NotFound(None)
            })?;

        let service = self
            .search_diag_services(|s| {
                s.diag_comm()
                    .and_then(|dc| dc.state_transition_refs())
                    .is_some_and(|st_refs| {
                        st_refs.iter().any(|st_ref| {
                            st_ref.state_transition().is_some_and(|st| {
                                st.source_short_name_ref()
                                    .is_some_and(|n| n.eq_ignore_ascii_case(current_state))
                                    && st
                                        .target_short_name_ref()
                                        .is_some_and(|n| n.eq_ignore_ascii_case(target_state))
                                    && semantic_transitions.iter().any(|semantic| semantic == st)
                            })
                        })
                    })
            })
            .ok_or_else(|| {
                tracing::error!(
                    current_state,
                    target_state,
                    semantic,
                    "Failed to find service for state transition"
                );
                DiagServiceError::NotFound(None)
            })?;

        service.try_into()
    }

    fn lookup_state_chart(
        &self,
        semantic: &str,
    ) -> Result<datatypes::StateChart<'_>, DiagServiceError> {
        self.diag_database
            .base_variant()?
            .diag_layer()
            .and_then(|dl| dl.state_charts())
            .and_then(|sc| {
                sc.iter()
                    .find(|sc| sc.semantic().is_some_and(|sem| sem == semantic))
            })
            .map(datatypes::StateChart)
            .ok_or(DiagServiceError::NotFound(None))
    }

    fn default_state(&self, semantic: &str) -> Result<String, DiagServiceError> {
        self.lookup_state_chart(semantic)?
            .start_state_short_name_ref()
            .map(ToOwned::to_owned)
            .ok_or(DiagServiceError::InvalidDatabase(
                "No start state defined in state chart".to_owned(),
            ))
    }
    fn start_reset_task(&self, expiration: Duration) -> Result<(), DiagServiceError> {
        let session_control = Arc::clone(&self.access_control);

        let default_security = self.default_state(semantics::SECURITY)?;
        let default_session = self.default_state(semantics::SESSION)?;

        self.access_control.lock().access_reset_task = Some(spawn_named!(
            &format!("access-reset-{}", self.ecu_name),
            async move {
                tokio::time::sleep(expiration).await;
                let mut access = session_control.lock();
                access.security = Some(default_security);
                access.session = Some(default_session);
                access.access_reset_task = None;
            }
        ));

        Ok(())
    }

    fn lookup_services_by_sid(
        &self,
        service_id: u8,
    ) -> Result<Vec<datatypes::DiagService<'_>>, DiagServiceError> {
        let base_variant = self.diag_database.base_variant()?;
        let services = self
            .variant()
            .and_then(|v| v.diag_layer().and_then(|dl| dl.diag_services()))
            .into_iter()
            .flatten()
            .chain(
                base_variant
                    .diag_layer()
                    .and_then(|dl| dl.diag_services())
                    .into_iter()
                    .flatten(),
            )
            .map(datatypes::DiagService)
            .chain(
                // Search in ECU shared services referenced by base variant
                self.find_ecu_shared_services().into_iter().flatten(),
            )
            .filter(|s| s.request_id().is_some_and(|req_id| req_id == service_id))
            .collect::<Vec<_>>();

        if services.is_empty() {
            Err(DiagServiceError::NotFound(None))
        } else {
            Ok(services)
        }
    }

    fn find_dtc_dop_in_params<'a>(
        params: &Vec<datatypes::Parameter<'a>>,
    ) -> Result<Option<datatypes::DtcDop<'a>>, DiagServiceError> {
        for p in params {
            let Some(value) = p.specific_data_as_value() else {
                continue;
            };
            let Some(dop) = value.dop() else { continue };

            if let Some(dtc_dop) = dop.specific_data_as_dtcdop() {
                return Ok(Some(datatypes::DtcDop(dtc_dop)));
            }

            // Recursively search in nested structures
            let nested_params = Self::extract_nested_params(&dop.into())?;
            if let Some(result) = Self::find_dtc_dop_in_params(&nested_params)? {
                return Ok(Some(result));
            }
        }
        Ok(None)
    }

    fn extract_nested_params<'a>(
        dop: &datatypes::DataOperation<'a>,
    ) -> Result<Vec<datatypes::Parameter<'a>>, DiagServiceError> {
        if let Some(end_of_pdu_dop) = dop.specific_data_as_end_of_pdu_field() {
            let struct_ = end_of_pdu_dop
                .field()
                .and_then(|f| f.basic_structure())
                .and_then(|s| s.specific_data_as_structure())
                .ok_or_else(|| {
                    DiagServiceError::InvalidDatabase(
                        "EndOfPdu does not contain a struct".to_owned(),
                    )
                })?;

            return Ok(struct_
                .params()
                .map(|params| params.iter().map(datatypes::Parameter).collect())
                .unwrap_or_default());
        }

        if let Some(structure_dop) = dop.specific_data_as_structure() {
            return Ok(structure_dop
                .params()
                .map(|params| params.iter().map(datatypes::Parameter).collect())
                .unwrap_or_default());
        }

        Ok(Vec::new())
    }

    /// Validate security access via plugin
    /// allows passing a `Box::new(())` to skip security checks
    /// this is used internally, when we don't want to have this run the check again
    fn check_security_plugin(
        security_plugin: &DynamicPlugin,
        service: &datatypes::DiagService,
    ) -> Result<(), DiagServiceError> {
        if let Some(()) = security_plugin.downcast_ref::<()>() {
            tracing::info!("Void security plugin provided, skipping security check");
            return Ok(());
        }
        let security_plugin = security_plugin
            .downcast_ref::<S>()
            .ok_or(DiagServiceError::InvalidSecurityPlugin)
            .map(SecurityPlugin::as_security_plugin)?;

        security_plugin.validate_service(service)
    }
}

fn mux_case_struct_from_selector_value<'a>(
    mux_dop: &'a datatypes::MuxDop,
    switch_key_value: &DiagDataValue,
) -> Option<(datatypes::Case<'a>, Option<datatypes::StructureDop<'a>>)> {
    mux_dop.cases().and_then(|cases| {
        cases
            .iter()
            .find(|case| {
                let lower_limit = case.lower_limit().map(Into::into);
                let upper_limit = case.upper_limit().map(Into::into);
                switch_key_value.within_limits(upper_limit.as_ref(), lower_limit.as_ref())
            })
            .map(|case| {
                let struct_dop = case
                    .structure()
                    .and_then(|s| s.specific_data_as_structure().map(datatypes::StructureDop));
                (case.into(), struct_dop)
            })
    })
}

fn extract_struct_dop_from_field(
    field: Option<datatypes::DopField>,
) -> Result<datatypes::StructureDop, DiagServiceError> {
    field
        .and_then(|f| {
            f.basic_structure()
                .and_then(|s| s.specific_data_as_structure().map(datatypes::StructureDop))
        })
        .ok_or(DiagServiceError::InvalidDatabase(
            "Field none or does not contain a struct".to_owned(),
        ))
}

fn create_diag_service_response(
    diag_service: &cda_interfaces::DiagComm,
    data: HashMap<String, DiagDataTypeContainer>,
    response_type: datatypes::ResponseType,
    raw_uds_payload: Vec<u8>,
    mapping_errors: Vec<FieldParseError>,
) -> DiagServiceResponseStruct {
    match response_type {
        datatypes::ResponseType::Negative | datatypes::ResponseType::GlobalNegative => {
            DiagServiceResponseStruct {
                service: diag_service.clone(),
                data: raw_uds_payload,
                mapped_data: Some(MappedResponseData {
                    data,
                    errors: mapping_errors,
                }),
                response_type: DiagServiceResponseType::Negative,
            }
        }
        datatypes::ResponseType::Positive => DiagServiceResponseStruct {
            service: diag_service.clone(),
            data: raw_uds_payload,
            mapped_data: Some(MappedResponseData {
                data,
                errors: mapping_errors,
            }),
            response_type: DiagServiceResponseType::Positive,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use cda_database::datatypes::{
        DataType, Limit, ResponseType,
        database_builder::{
            Addressing, DiagClassType, DiagCommParams, DiagLayerParams, DiagServiceParams, DopType,
            EcuDataBuilder, EcuDataParams, SpecificDOPData, TransmissionMode,
        },
    };
    use cda_interfaces::{EcuManager, Protocol, datatypes::FlatbBufConfig};
    use cda_plugin_security::DefaultSecurityPluginData;
    use flatbuffers::WIPOffset;
    use serde_json::json;

    use super::*;

    macro_rules! skip_sec_plugin {
        () => {{
            let skip_sec_plugin: DynamicPlugin = Box::new(());
            skip_sec_plugin
        }};
    }

    // allowed because creation of test data should kept together
    #[allow(clippy::too_many_lines)]
    fn create_ecu_manager_with_dynamic_length_field_service() -> (
        super::EcuManager<DefaultSecurityPluginData>,
        cda_interfaces::DiagComm,
        u8,
    ) {
        let mut db_builder = EcuDataBuilder::new();
        let u8_diag_type = db_builder.create_diag_coded_type_standard_length(8, DataType::UInt32);
        let u16_diag_type = db_builder.create_diag_coded_type_standard_length(16, DataType::UInt32);
        let protocol = db_builder.create_protocol(Protocol::DoIp.value(), None, None, None);
        let cp_ref = db_builder.create_com_param_ref(None, None, None, Some(protocol), None);
        let compu_identical =
            db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);

        // Create DOPs for structure parameters
        let num_items_dop = {
            let num_items_dop_specific_data = db_builder
                .create_normal_specific_dop_data(
                    Some(compu_identical),
                    Some(u8_diag_type),
                    None,
                    None,
                    None,
                    None,
                )
                .value_offset();
            db_builder.create_dop(
                *DopType::REGULAR,
                Some("num_items_dop"),
                None,
                *SpecificDOPData::NormalDOP,
                Some(num_items_dop_specific_data),
            )
        };

        // Create the structure for the repeated item
        let repeated_struct = {
            let item_param_dop_specific_data = db_builder
                .create_normal_specific_dop_data(
                    Some(compu_identical),
                    Some(u16_diag_type),
                    None,
                    None,
                    None,
                    None,
                )
                .value_offset();
            let item_param_dop = db_builder.create_dop(
                *DopType::REGULAR,
                Some("item_param_dop"),
                None,
                *SpecificDOPData::NormalDOP,
                Some(item_param_dop_specific_data),
            );

            // Create parameter for the repeated item
            let item_param = db_builder.create_value_param("item_param", item_param_dop, 0, 0);
            db_builder.create_structure(Some(vec![item_param]), Some(2), true)
        };

        let dynamic_length_field_dop = {
            // Create DynamicLengthField DoP
            let dynamic_length_field_dop_specific_data = db_builder
                .create_dynamic_length_specific_dop_data(
                    1,
                    0,
                    0,
                    num_items_dop,
                    Some(repeated_struct),
                )
                .value_offset();

            db_builder.create_dop(
                *DopType::REGULAR,
                Some("dynamic_length_field_dop"),
                None,
                *SpecificDOPData::DynamicLengthField,
                Some(dynamic_length_field_dop_specific_data),
            )
        };

        let sid = 0x2E_u8;
        let dc_name = "TestDynamicLengthFieldService";
        let diag_comm = db_builder.create_diag_comm(DiagCommParams {
            short_name: dc_name,
            long_name: None,
            semantic: None,
            funct_class: None,
            sdgs: None,
            diag_class_type: DiagClassType::START_COMM,
            pre_condition_state_refs: None,
            state_transition_refs: None,
            protocols: Some(vec![protocol]),
            audience: None,
            is_mandatory: false,
            is_executable: true,
            is_final: true,
        });

        let request = {
            let request_num_items_param =
                db_builder.create_value_param("num_items", num_items_dop, 1, 0);
            let sid_param = db_builder.create_coded_const_param(
                "sid",
                &sid.to_string(),
                0,
                0,
                8,
                DataType::UInt32,
            );

            db_builder.create_request(Some(vec![sid_param, request_num_items_param]), None)
        };

        // Build response
        let pos_response = {
            let sid_param = db_builder.create_coded_const_param(
                "test_service_pos_sid",
                &sid.to_string(),
                0,
                0,
                8,
                DataType::UInt32,
            );
            let pos_response_param =
                db_builder.create_value_param("pos_response_param", dynamic_length_field_dop, 1, 0);
            db_builder.create_response(
                ResponseType::Positive,
                Some(vec![sid_param, pos_response_param]),
                None,
            )
        };

        let neg_response = {
            let nack_param = db_builder.create_coded_const_param(
                "test_service_nack",
                &NEGATIVE_RESPONSE.to_string(),
                0,
                0,
                8,
                DataType::UInt32,
            );

            let sid_param = db_builder.create_coded_const_param(
                "test_service_neg_sid",
                &sid.to_string(),
                1,
                0,
                8,
                DataType::UInt32,
            );

            db_builder.create_response(
                ResponseType::Negative,
                Some(vec![nack_param, sid_param]),
                None,
            )
        };

        let diag_service = db_builder.create_diag_service(DiagServiceParams {
            diag_comm: Some(diag_comm),
            request: Some(request),
            pos_responses: vec![pos_response],
            neg_responses: vec![neg_response],
            is_cyclic: false,
            is_multiple: false,
            addressing: *Addressing::FUNCTIONAL_OR_PHYSICAL,
            transmission_mode: *TransmissionMode::SEND_AND_RECEIVE,
            com_param_refs: None,
        });

        let diag_layer = db_builder.create_diag_layer(DiagLayerParams {
            short_name: "TestVariantDiagLayer",
            long_name: None,
            funct_classes: None,
            com_param_refs: Some(vec![cp_ref]),
            diag_services: Some(vec![diag_service]),
            ..Default::default()
        });

        let variant = db_builder.create_variant(diag_layer, true, None, None);
        let ecu_data = db_builder.create_ecu_data_and_finish(EcuDataParams {
            revision: "revision_1",
            version: "1.0.0",
            variants: Some(vec![variant]),
            ..Default::default()
        });

        let db = datatypes::DiagnosticDatabase::new(
            String::default(),
            ecu_data,
            FlatbBufConfig::default(),
        )
        .unwrap();

        let ecu_manager = super::EcuManager::new(
            db,
            Protocol::DoIp,
            &ComParams::default(),
            DatabaseNamingConvention::default(),
        )
        .unwrap();

        let dc = cda_interfaces::DiagComm {
            name: dc_name.to_owned(),
            type_: DiagCommType::Configurations,
            lookup_name: Some(dc_name.to_owned()),
        };

        (ecu_manager, dc, sid)
    }

    // allowed because creation of test data should kept together
    #[allow(clippy::too_many_lines)]
    fn create_ecu_manager_with_struct_service(
        struct_byte_pos: u32,
    ) -> (
        super::EcuManager<DefaultSecurityPluginData>,
        cda_interfaces::DiagComm,
        u8,
        u32,
    ) {
        let mut db_builder = EcuDataBuilder::new();
        let protocol = db_builder.create_protocol(Protocol::DoIp.value(), None, None, None);
        let cp_ref = db_builder.create_com_param_ref(None, None, None, Some(protocol), None);

        // Create the structure with parameters
        let (structure_dop, structure_byte_len) = {
            let compu_identical =
                db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);
            let u16_diag_type =
                db_builder.create_diag_coded_type_standard_length(16, DataType::UInt32);
            let f32_diag_type =
                db_builder.create_diag_coded_type_standard_length(32, DataType::Float32);
            let ascii_diag_type =
                db_builder.create_diag_coded_type_standard_length(32, DataType::AsciiString);

            // Create DOPs for structure parameters
            let param1_dop = {
                let param1_dop_specific_data = db_builder
                    .create_normal_specific_dop_data(
                        Some(compu_identical),
                        Some(u16_diag_type),
                        None,
                        None,
                        None,
                        None,
                    )
                    .value_offset();

                db_builder.create_dop(
                    *DopType::REGULAR,
                    Some("param1_dop"),
                    None,
                    *SpecificDOPData::NormalDOP,
                    Some(param1_dop_specific_data),
                )
            };

            let param2_dop = {
                let param2_dop_specific_data = db_builder
                    .create_normal_specific_dop_data(
                        Some(compu_identical),
                        Some(f32_diag_type),
                        None,
                        None,
                        None,
                        None,
                    )
                    .value_offset();

                db_builder.create_dop(
                    *DopType::REGULAR,
                    Some("param2_dop"),
                    None,
                    *SpecificDOPData::NormalDOP,
                    Some(param2_dop_specific_data),
                )
            };

            let param3_dop = {
                let param3_dop_specific_data = db_builder
                    .create_normal_specific_dop_data(
                        Some(compu_identical),
                        Some(ascii_diag_type),
                        None,
                        None,
                        None,
                        None,
                    )
                    .value_offset();
                db_builder.create_dop(
                    *DopType::REGULAR,
                    Some("param3_dop"),
                    None,
                    *SpecificDOPData::NormalDOP,
                    Some(param3_dop_specific_data),
                )
            };

            // Create parameters for the structure
            let struct_param1 = db_builder.create_value_param("param1", param1_dop, 0, 0);
            let struct_param2 = db_builder.create_value_param("param2", param2_dop, 2, 0);
            let struct_param3 = db_builder.create_value_param("param3", param3_dop, 6, 0);

            let struct_byte_len = 10; // 2 + 4 + 4 bytes
            let structure = db_builder.create_structure(
                Some(vec![struct_param1, struct_param2, struct_param3]),
                Some(struct_byte_len),
                true,
            );

            // Wrap the structure in a DOP
            (
                db_builder.create_structure_dop("test_structure_dop", structure),
                struct_byte_len,
            )
        };

        let sid = 0x2E_u8;
        let dc_name = "TestStructService";
        let diag_comm = db_builder.create_diag_comm(DiagCommParams {
            short_name: dc_name,
            long_name: None,
            semantic: None,
            funct_class: None,
            sdgs: None,
            diag_class_type: DiagClassType::START_COMM,
            pre_condition_state_refs: None,
            state_transition_refs: None,
            protocols: Some(vec![protocol]),
            audience: None,
            is_mandatory: false,
            is_executable: true,
            is_final: true,
        });

        let request = {
            let sid_param = db_builder.create_coded_const_param(
                "sid",
                &sid.to_string(),
                0,
                0,
                8,
                DataType::UInt32,
            );
            let main_param =
                db_builder.create_value_param("main_param", structure_dop, struct_byte_pos, 0);
            db_builder.create_request(Some(vec![sid_param, main_param]), None)
        };

        let diag_service = db_builder.create_diag_service(DiagServiceParams {
            diag_comm: Some(diag_comm),
            request: Some(request),
            pos_responses: vec![],
            neg_responses: vec![],
            is_cyclic: false,
            is_multiple: false,
            addressing: *Addressing::FUNCTIONAL_OR_PHYSICAL,
            transmission_mode: *TransmissionMode::SEND_AND_RECEIVE,
            com_param_refs: None,
        });

        let diag_layer = db_builder.create_diag_layer(DiagLayerParams {
            short_name: "TestVariantDiagLayer",
            long_name: None,
            funct_classes: None,
            com_param_refs: Some(vec![cp_ref]),
            diag_services: Some(vec![diag_service]),
            ..Default::default()
        });

        let variant = db_builder.create_variant(diag_layer, true, None, None);
        let ecu_data = db_builder.create_ecu_data_and_finish(EcuDataParams {
            revision: "revision_1",
            version: "1.0.0",
            variants: Some(vec![variant]),
            ..Default::default()
        });

        let db = datatypes::DiagnosticDatabase::new(
            String::default(),
            ecu_data,
            FlatbBufConfig::default(),
        )
        .unwrap();

        let ecu_manager = super::EcuManager::new(
            db,
            Protocol::DoIp,
            &ComParams::default(),
            DatabaseNamingConvention::default(),
        )
        .unwrap();

        let dc = cda_interfaces::DiagComm {
            name: dc_name.to_owned(),
            type_: DiagCommType::Configurations,
            lookup_name: Some(dc_name.to_owned()),
        };

        (ecu_manager, dc, sid, structure_byte_len)
    }

    fn create_ecu_manager_with_mux_service_and_default_case() -> (
        super::EcuManager<DefaultSecurityPluginData>,
        cda_interfaces::DiagComm,
        u8,
    ) {
        let mut db_builder = EcuDataBuilder::new();
        let u8_diag_type = db_builder.create_diag_coded_type_standard_length(8, DataType::UInt32);
        let compu_identical =
            db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);

        // Create DOP for default structure parameter
        let default_structure_param_1 = {
            let default_structure_param_1_dop_specific_data = db_builder
                .create_normal_specific_dop_data(
                    Some(compu_identical),
                    Some(u8_diag_type),
                    None,
                    None,
                    None,
                    None,
                )
                .value_offset();
            let default_structure_param_1_dop = db_builder.create_dop(
                *DopType::REGULAR,
                Some("default_structure_param_1_dop"),
                None,
                *SpecificDOPData::NormalDOP,
                Some(default_structure_param_1_dop_specific_data),
            );

            // Create parameter for default structure
            db_builder.create_value_param(
                "default_structure_param_1",
                default_structure_param_1_dop,
                0,
                0,
            )
        };

        // Create default structure
        let default_structure =
            db_builder.create_structure(Some(vec![default_structure_param_1]), Some(1), true);
        let default_case = db_builder.create_default_case("default_case", Some(default_structure));

        create_ecu_manager_with_mux_service(Some(db_builder), None, Some(default_case))
    }

    // allowed because creation of test data should kept together
    #[allow(clippy::too_many_lines)]
    fn create_ecu_manager_with_mux_service(
        db_builder: Option<EcuDataBuilder>,
        switch_key: Option<WIPOffset<datatypes::database_builder::SwitchKey>>,
        default_case: Option<WIPOffset<datatypes::database_builder::DefaultCase>>,
    ) -> (
        super::EcuManager<DefaultSecurityPluginData>,
        cda_interfaces::DiagComm,
        u8,
    ) {
        let mut db_builder = db_builder.unwrap_or_default();

        let u8_diag_type = db_builder.create_diag_coded_type_standard_length(8, DataType::UInt32);
        let u16_diag_type = db_builder.create_diag_coded_type_standard_length(16, DataType::UInt32);
        let i16_diag_type = db_builder.create_diag_coded_type_standard_length(16, DataType::Int32);
        let f32_diag_type =
            db_builder.create_diag_coded_type_standard_length(32, DataType::Float32);
        let ascii_diag_type =
            db_builder.create_diag_coded_type_standard_length(32, DataType::AsciiString);
        let protocol = db_builder.create_protocol(Protocol::DoIp.value(), None, None, None);
        let cp_ref = db_builder.create_com_param_ref(None, None, None, Some(protocol), None);
        let compu_identical =
            db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);

        // Create DOPs for case 1 parameters
        let mux_1_case_1_params_dop_1 = {
            let mux_1_case_1_params_dop_1_specific_data = db_builder
                .create_normal_specific_dop_data(
                    Some(compu_identical),
                    Some(f32_diag_type),
                    None,
                    None,
                    None,
                    None,
                )
                .value_offset();
            db_builder.create_dop(
                *DopType::REGULAR,
                Some("mux_1_case_1_params_dop_1"),
                None,
                *SpecificDOPData::NormalDOP,
                Some(mux_1_case_1_params_dop_1_specific_data),
            )
        };

        let mux_1_case_1_params_dop_2 = {
            let mux_1_case_1_params_dop_2_specific_data = db_builder
                .create_normal_specific_dop_data(
                    Some(compu_identical),
                    Some(u8_diag_type),
                    None,
                    None,
                    None,
                    None,
                )
                .value_offset();
            db_builder.create_dop(
                *DopType::REGULAR,
                Some("mux_1_case_1_params_dop_2"),
                None,
                *SpecificDOPData::NormalDOP,
                Some(mux_1_case_1_params_dop_2_specific_data),
            )
        };

        let mux_1_case_2_params_dop_1 = {
            let mux_1_case_2_params_dop_1_specific_data = db_builder
                .create_normal_specific_dop_data(
                    Some(compu_identical),
                    Some(i16_diag_type),
                    None,
                    None,
                    None,
                    None,
                )
                .value_offset();
            db_builder.create_dop(
                *DopType::REGULAR,
                Some("mux_1_case_2_params_dop_1"),
                None,
                *SpecificDOPData::NormalDOP,
                Some(mux_1_case_2_params_dop_1_specific_data),
            )
        };

        let mux_1_case_2_params_dop_2 = {
            let mux_1_case_2_params_dop_2_specific_data = db_builder
                .create_normal_specific_dop_data(
                    Some(compu_identical),
                    Some(ascii_diag_type),
                    None,
                    None,
                    None,
                    None,
                )
                .value_offset();
            db_builder.create_dop(
                *DopType::REGULAR,
                Some("mux_1_case_2_params_dop_2"),
                None,
                *SpecificDOPData::NormalDOP,
                Some(mux_1_case_2_params_dop_2_specific_data),
            )
        };

        // Create parameters for case 1
        let mux_1_case_1_param_1 =
            db_builder.create_value_param("mux_1_case_1_param_1", mux_1_case_1_params_dop_1, 0, 0);
        let mux_1_case_1_param_2 =
            db_builder.create_value_param("mux_1_case_1_param_2", mux_1_case_1_params_dop_2, 4, 0);

        // Create parameters for case 2
        let mux_1_case_2_param_1 =
            db_builder.create_value_param("mux_1_case_2_param_1", mux_1_case_2_params_dop_1, 1, 0);
        let mux_1_case_2_param_2 =
            db_builder.create_value_param("mux_1_case_2_param_2", mux_1_case_2_params_dop_2, 4, 0);

        // Create structures
        let mux_1_case_1_structure = db_builder.create_structure(
            Some(vec![mux_1_case_1_param_1, mux_1_case_1_param_2]),
            Some(7),
            true,
        );

        let mux_1_case_2_structure = db_builder.create_structure(
            Some(vec![mux_1_case_2_param_1, mux_1_case_2_param_2]),
            Some(7),
            true,
        );

        // Create cases using the new helper method
        let mux_1_case_1 = db_builder.create_case(
            "mux_1_case_1",
            Some(Limit {
                value: 1.0.to_string(),
                interval_type: datatypes::IntervalType::Infinite,
            }),
            Some(Limit {
                value: 10.0.to_string(),
                interval_type: datatypes::IntervalType::Infinite,
            }),
            Some(mux_1_case_1_structure),
        );

        let mux_1_case_2 = db_builder.create_case(
            "mux_1_case_2",
            Some(Limit {
                value: 11.0.to_string(),
                interval_type: datatypes::IntervalType::Infinite,
            }),
            Some(Limit {
                value: 600.0.to_string(),
                interval_type: datatypes::IntervalType::Infinite,
            }),
            Some(mux_1_case_2_structure),
        );

        let mux_1_case_3 = db_builder.create_case(
            "mux_1_case_3",
            Some(Limit {
                value: "test".to_owned(),
                interval_type: datatypes::IntervalType::Infinite,
            }),
            None,
            None,
        );

        // Create switch key if not provided
        let mux_1_switch_key = switch_key.unwrap_or_else(|| {
            let switch_key_dop_specific_data = db_builder
                .create_normal_specific_dop_data(
                    Some(compu_identical),
                    Some(u16_diag_type),
                    None,
                    None,
                    None,
                    None,
                )
                .value_offset();
            let switch_key_dop = db_builder.create_dop(
                *DopType::REGULAR,
                Some("switch_key_dop"),
                None,
                *SpecificDOPData::NormalDOP,
                Some(switch_key_dop_specific_data),
            );

            db_builder.create_switch_key(0, Some(0), Some(switch_key_dop))
        });

        let cases = vec![mux_1_case_1, mux_1_case_2, mux_1_case_3];

        // Create mux DOP specific data
        let mux_dop = db_builder.create_mux_dop(
            "mux_dop",
            2,
            Some(mux_1_switch_key),
            default_case,
            Some(cases),
            true,
        );

        let sid = 0x22;
        let dc_name = "TestMuxService";
        let diag_comm = db_builder.create_diag_comm(DiagCommParams {
            short_name: dc_name,
            long_name: None,
            semantic: None,
            funct_class: None,
            sdgs: None,
            diag_class_type: DiagClassType::START_COMM,
            pre_condition_state_refs: None,
            state_transition_refs: None,
            protocols: Some(vec![protocol]),
            audience: None,
            is_mandatory: false,
            is_executable: true,
            is_final: true,
        });

        // Create request with mux parameter
        let request = {
            let sid_param = db_builder.create_coded_const_param(
                "sid",
                &sid.to_string(),
                0,
                0,
                8,
                DataType::UInt32,
            );
            let mux_param = db_builder.create_value_param("mux_1_param", mux_dop, 2, 0);
            db_builder.create_request(Some(vec![sid_param, mux_param]), None)
        };

        // Create response with mux parameter
        let pos_response = {
            let sid_param = db_builder.create_coded_const_param(
                "test_service_pos_sid",
                &sid.to_string(),
                0,
                0,
                8,
                DataType::UInt32,
            );
            let mux_param = db_builder.create_value_param("mux_1_param", mux_dop, 2, 0);
            db_builder.create_response(
                ResponseType::Positive,
                Some(vec![sid_param, mux_param]),
                None,
            )
        };

        let diag_service = db_builder.create_diag_service(DiagServiceParams {
            diag_comm: Some(diag_comm),
            request: Some(request),
            pos_responses: vec![pos_response],
            neg_responses: vec![],
            is_cyclic: false,
            is_multiple: false,
            addressing: *Addressing::FUNCTIONAL_OR_PHYSICAL,
            transmission_mode: *TransmissionMode::SEND_AND_RECEIVE,
            com_param_refs: None,
        });

        let diag_layer = db_builder.create_diag_layer(DiagLayerParams {
            short_name: "TestVariantDiagLayer",
            long_name: None,
            funct_classes: None,
            com_param_refs: Some(vec![cp_ref]),
            diag_services: Some(vec![diag_service]),
            ..Default::default()
        });

        let variant = db_builder.create_variant(diag_layer, true, None, None);
        let ecu_data = db_builder.create_ecu_data_and_finish(EcuDataParams {
            revision: "revision_1",
            version: "1.0.0",
            variants: Some(vec![variant]),
            ..Default::default()
        });

        let db = datatypes::DiagnosticDatabase::new(
            String::default(),
            ecu_data,
            FlatbBufConfig::default(),
        )
        .unwrap();

        let ecu_manager = super::EcuManager::new(
            db,
            Protocol::DoIp,
            &ComParams::default(),
            DatabaseNamingConvention::default(),
        )
        .unwrap();

        let dc = cda_interfaces::DiagComm {
            name: dc_name.to_owned(),
            type_: DiagCommType::Data,
            lookup_name: Some(dc_name.to_owned()),
        };

        (ecu_manager, dc, sid)
    }

    // allowed because creation of test data should kept together
    #[allow(clippy::too_many_lines)]
    fn create_ecu_manager_with_end_pdu_service(
        min_items: u32,
        max_items: Option<u32>,
    ) -> (
        super::EcuManager<DefaultSecurityPluginData>,
        cda_interfaces::DiagComm,
        u8,
    ) {
        let mut db_builder = EcuDataBuilder::new();
        let u8_diag_type = db_builder.create_diag_coded_type_standard_length(8, DataType::UInt32);
        let u16_diag_type = db_builder.create_diag_coded_type_standard_length(16, DataType::UInt32);
        let protocol = db_builder.create_protocol(Protocol::DoIp.value(), None, None, None);
        let cp_ref = db_builder.create_com_param_ref(None, None, None, Some(protocol), None);
        let compu_identical =
            db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);

        // Create DOPs for structure parameters within the EndOfPdu
        let item_param1_dop = {
            let item_param1_dop_specific_data = db_builder
                .create_normal_specific_dop_data(
                    Some(compu_identical),
                    Some(u8_diag_type),
                    None,
                    None,
                    None,
                    None,
                )
                .value_offset();
            db_builder.create_dop(
                *DopType::REGULAR,
                Some("item_param1_dop"),
                None,
                *SpecificDOPData::NormalDOP,
                Some(item_param1_dop_specific_data),
            )
        };

        let item_param2_dop = {
            let item_param2_dop_specific_data = db_builder
                .create_normal_specific_dop_data(
                    Some(compu_identical),
                    Some(u16_diag_type),
                    None,
                    None,
                    None,
                    None,
                )
                .value_offset();
            db_builder.create_dop(
                *DopType::REGULAR,
                Some("item_param2_dop"),
                None,
                *SpecificDOPData::NormalDOP,
                Some(item_param2_dop_specific_data),
            )
        };

        // Create parameters for the repeating structure
        let item_param1 = db_builder.create_value_param("item_param1", item_param1_dop, 0, 0);
        let item_param2 = db_builder.create_value_param("item_param2", item_param2_dop, 1, 0);

        // Create the basic structure that will be repeated
        let item_structure = db_builder.create_structure(
            Some(vec![item_param1, item_param2]),
            Some(3), // byte_size: 1 byte + 2 bytes = 3 bytes per item
            true,
        );

        // Create EndOfPdu DOP using the new helper method
        let end_pdu_dop =
            db_builder.create_end_of_pdu_field_dop(min_items, max_items, Some(item_structure));

        let sid = 0x22_u8;
        let dc_name = "TestEndOfPduService";
        let diag_comm = db_builder.create_diag_comm(DiagCommParams {
            short_name: dc_name,
            long_name: None,
            semantic: None,
            funct_class: None,
            sdgs: None,
            diag_class_type: DiagClassType::START_COMM,
            pre_condition_state_refs: None,
            state_transition_refs: None,
            protocols: Some(vec![protocol]),
            audience: None,
            is_mandatory: false,
            is_executable: true,
            is_final: true,
        });

        // Create request
        let request = {
            let sid_param = db_builder.create_coded_const_param(
                "sid",
                &sid.to_string(),
                0,
                0,
                8,
                DataType::UInt32,
            );
            db_builder.create_request(Some(vec![sid_param]), None)
        };

        // Create response with EndOfPdu parameter
        let pos_response = {
            let sid_param = db_builder.create_coded_const_param(
                "test_service_pos_sid",
                &sid.to_string(),
                0,
                0,
                8,
                DataType::UInt32,
            );
            let end_pdu_param = db_builder.create_value_param("end_pdu_param", end_pdu_dop, 1, 0);
            db_builder.create_response(
                ResponseType::Positive,
                Some(vec![sid_param, end_pdu_param]),
                None,
            )
        };

        let diag_service = db_builder.create_diag_service(DiagServiceParams {
            diag_comm: Some(diag_comm),
            request: Some(request),
            pos_responses: vec![pos_response],
            neg_responses: vec![],
            is_cyclic: false,
            is_multiple: false,
            addressing: *Addressing::FUNCTIONAL_OR_PHYSICAL,
            transmission_mode: *TransmissionMode::SEND_AND_RECEIVE,
            com_param_refs: None,
        });

        let diag_layer = db_builder.create_diag_layer(DiagLayerParams {
            short_name: "TestVariantDiagLayer",
            long_name: None,
            funct_classes: None,
            com_param_refs: Some(vec![cp_ref]),
            diag_services: Some(vec![diag_service]),
            ..Default::default()
        });

        let variant = db_builder.create_variant(diag_layer, true, None, None);
        let ecu_data = db_builder.create_ecu_data_and_finish(EcuDataParams {
            revision: "revision_1",
            version: "1.0.0",
            variants: Some(vec![variant]),
            ..Default::default()
        });

        let db = datatypes::DiagnosticDatabase::new(
            String::default(),
            ecu_data,
            FlatbBufConfig::default(),
        )
        .unwrap();

        let ecu_manager = super::EcuManager::new(
            db,
            Protocol::DoIp,
            &ComParams::default(),
            DatabaseNamingConvention::default(),
        )
        .unwrap();

        let dc = cda_interfaces::DiagComm {
            name: dc_name.to_owned(),
            type_: DiagCommType::Data,
            lookup_name: Some(dc_name.to_owned()),
        };

        (ecu_manager, dc, sid)
    }

    fn create_ecu_manager_with_dtc() -> (
        super::EcuManager<DefaultSecurityPluginData>,
        cda_interfaces::DiagComm,
        u8,
        u32,
    ) {
        let mut db_builder = EcuDataBuilder::new();
        let u32_diag_type = db_builder.create_diag_coded_type_standard_length(32, DataType::UInt32);
        let protocol = db_builder.create_protocol(Protocol::DoIp.value(), None, None, None);
        let cp_ref = db_builder.create_com_param_ref(None, None, None, Some(protocol), None);
        let compu_identical =
            db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);

        let dtc_code = 0xDEAD_BEEF;
        let dtc = db_builder.create_dtc(dtc_code, Some("P1234"), Some("TestFault"), 2);

        let dtc_dop =
            db_builder.create_dtc_dop(u32_diag_type, Some(vec![dtc]), Some(compu_identical));

        let sid = 0x19_u8;
        let dc_name = "TestDtcService";
        let diag_comm = db_builder.create_diag_comm(DiagCommParams {
            short_name: dc_name,
            long_name: None,
            semantic: None,
            funct_class: None,
            sdgs: None,
            diag_class_type: DiagClassType::START_COMM,
            pre_condition_state_refs: None,
            state_transition_refs: None,
            protocols: Some(vec![protocol]),
            audience: None,
            is_mandatory: false,
            is_executable: true,
            is_final: true,
        });

        // Create request
        let request = {
            let sid_param = db_builder.create_coded_const_param(
                "sid",
                &sid.to_string(),
                0,
                0,
                8,
                DataType::UInt32,
            );
            db_builder.create_request(Some(vec![sid_param]), None)
        };

        // Create response with DTC parameter
        let pos_response = {
            let sid_param = db_builder.create_coded_const_param(
                "test_service_pos_sid",
                &sid.to_string(),
                0,
                0,
                8,
                DataType::UInt32,
            );
            let dtc_param = db_builder.create_value_param("dtc_param", dtc_dop, 1, 0);
            db_builder.create_response(
                ResponseType::Positive,
                Some(vec![sid_param, dtc_param]),
                None,
            )
        };

        let diag_service = db_builder.create_diag_service(DiagServiceParams {
            diag_comm: Some(diag_comm),
            request: Some(request),
            pos_responses: vec![pos_response],
            neg_responses: vec![],
            is_cyclic: false,
            is_multiple: false,
            addressing: *Addressing::FUNCTIONAL_OR_PHYSICAL,
            transmission_mode: *TransmissionMode::SEND_AND_RECEIVE,
            com_param_refs: None,
        });

        let diag_layer = db_builder.create_diag_layer(DiagLayerParams {
            short_name: "TestVariantDiagLayer",
            long_name: None,
            funct_classes: None,
            com_param_refs: Some(vec![cp_ref]),
            diag_services: Some(vec![diag_service]),
            ..Default::default()
        });

        let variant = db_builder.create_variant(diag_layer, true, None, None);
        let ecu_data = db_builder.create_ecu_data_and_finish(EcuDataParams {
            revision: "revision_1",
            version: "1.0.0",
            variants: Some(vec![variant]),
            ..Default::default()
        });

        let db = datatypes::DiagnosticDatabase::new(
            String::default(),
            ecu_data,
            FlatbBufConfig::default(),
        )
        .unwrap();

        let ecu_manager = super::EcuManager::new(
            db,
            Protocol::DoIp,
            &ComParams::default(),
            DatabaseNamingConvention::default(),
        )
        .unwrap();

        let dc = cda_interfaces::DiagComm {
            name: dc_name.to_owned(),
            type_: DiagCommType::Faults,
            lookup_name: Some(dc_name.to_owned()),
        };

        (ecu_manager, dc, sid, dtc_code)
    }

    fn create_payload(data: Vec<u8>) -> ServicePayload {
        ServicePayload {
            data,
            source_address: 0u16,
            target_address: 0u16,
            new_security: None,
            new_session: None,
        }
    }

    #[tokio::test]
    async fn test_mux_from_uds_invalid_case_no_default() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_mux_service(None, None, None);
        let response = ecu_manager
            .convert_from_uds(
                &service,
                &create_payload(vec![
                    // Service ID
                    sid,
                    // This does not belong to our mux, it's here to test, if the start byte is used
                    0xff,
                    // Mux param starts here
                    // there is no switch value for 0xffff
                    0xff, 0xff,
                ]),
                true,
            )
            .await;
        assert!(response.is_err());
    }

    #[tokio::test]
    async fn test_mux_from_uds_invalid_case_with_default() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_mux_service_and_default_case();
        let response = ecu_manager
            .convert_from_uds(
                &service,
                &create_payload(vec![
                    // Service ID
                    sid,
                    // This does not belong to our mux, it's here to test, if the start byte is used
                    0xff,
                    // Mux param starts here
                    // there is no switch value for 0xffff, but we have a default case
                    0xff, 0xff, //
                    // value for param 1 of default structure
                    0x42,
                ]),
                true,
            )
            .await
            .unwrap();
        assert_eq!(
            response.serialize_to_json().unwrap().data,
            json!({
                "mux_1_param": {
                        "Selector": 0xffff,
                        "default_case": {
                            "default_structure_param_1": 0x42,
                        }
                },
                "test_service_pos_sid": sid
                }
            )
        );
    }

    #[tokio::test]
    async fn test_mux_from_uds_invalid_payload() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_mux_service(None, None, None);
        let response = ecu_manager
            .convert_from_uds(
                &service,
                &create_payload(vec![
                    // Service ID
                    sid,
                    // This does not belong to our mux, it's here to test, if the start byte is used
                    0xff, // Mux param starts here
                    // + switch key byte 0
                    0x0, 0x0a, // valid switch key but no data, expect error from decode.
                ]),
                true,
            )
            .await;
        assert!(response.is_err());
    }

    #[tokio::test]
    async fn test_mux_from_uds_empty_structure() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_mux_service(None, None, None);
        let response = ecu_manager
            .convert_from_uds(
                &service,
                &create_payload(vec![
                    // Service ID
                    sid,
                    // This does not belong to our mux, it's here to test, if the start byte is used
                    0xff, // Mux param starts here
                    // + switch key byte 0
                    0x00, 0x0a, // valid switch key but no data, expect error from decode.
                ]),
                true,
            )
            .await;

        assert_eq!(
            response.unwrap_err(),
            DiagServiceError::NotEnoughData {
                expected: 4, // the case expects 4 bytes for the float param
                actual: 0
            }
        );
    }

    #[tokio::test]
    async fn test_mux_from_and_to_uds_case_1() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_mux_service(None, None, None);
        // skip formatting, to keep the comments on the bytes they belong to.
        let param_1_value: f32 = 13.37;
        let param_1_bytes = param_1_value.to_be_bytes();
        // skip formatting, to keep the comments on the bytes they belong to.
        #[rustfmt::skip]
        let data = [
            // Service ID
            sid,
            // This does not belong to our mux, it's here to test, if the start byte is used
            0xff,
            // Mux param starts here
            // + switch key byte 0
            0x00,
            // Switch key byte 1
            0x05,
            // value for param 1
            param_1_bytes[0], param_1_bytes[1], param_1_bytes[2], param_1_bytes[3],
            0x07, // value for param 2
        ];

        let mux_1_json = json!({
           "mux_1_param": {
                "Selector": 5,
                "mux_1_case_1": {
                    "mux_1_case_1_param_1": param_1_value,
                    "mux_1_case_1_param_2": 7
                }
            },
        });

        test_mux_from_and_to_uds(ecu_manager, &service, sid, &data.to_vec(), mux_1_json).await;
    }

    #[tokio::test]
    async fn test_mux_from_and_to_uds_case_2() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_mux_service(None, None, None);
        // skip formatting, to keep the comments on the bytes they belong to.
        #[rustfmt::skip]
        let data = [
            // Service ID
            sid,
            // This does not belong to our mux, it's here to test, if the start byte is used
            0xff,
            // Mux param starts here
            // + switch key byte 0
            0x00,
            // switch key byte 1
            0xaa,
            // unused byte, param 1 starts here relative to byte 1 of the switch key
            0xff,
            // byte 0 of param 1
            0x42,
            // byte 1 of param 1
            0x42,
            // unused byte, param 2 starts here relative to byte 4 of the switch key
            0x00,
            // 4 bytes of param 2 (ascii 'test')
            0x74, 0x65, 0x73, 0x74
        ];

        let mux_1_json = json!({
            "mux_1_param": {
                "Selector": 0xaa,
                "mux_1_case_2": {
                    "mux_1_case_2_param_1": 0x4242,
                    "mux_1_case_2_param_2": "test"
                }
            }
        });

        test_mux_from_and_to_uds(ecu_manager, &service, sid, &data.to_vec(), mux_1_json).await;
    }

    #[tokio::test]
    async fn test_mux_from_and_to_uds_case_3() {
        let mut db_builder = EcuDataBuilder::new();
        // Create switch key if not provided
        let switch_key = {
            let ascii_string_diag_type =
                db_builder.create_diag_coded_type_standard_length(32, DataType::AsciiString);
            let compu_identical =
                db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);
            let switch_key_dop_specific_data = db_builder
                .create_normal_specific_dop_data(
                    Some(compu_identical),
                    Some(ascii_string_diag_type),
                    None,
                    None,
                    None,
                    None,
                )
                .value_offset();
            let switch_key_dop = db_builder.create_dop(
                *DopType::REGULAR,
                Some("switch_key_dop"),
                None,
                *SpecificDOPData::NormalDOP,
                Some(switch_key_dop_specific_data),
            );

            db_builder.create_switch_key(0, Some(0), Some(switch_key_dop))
        };

        let (ecu_manager, service, sid) =
            create_ecu_manager_with_mux_service(Some(db_builder), Some(switch_key), None);
        // skip formatting, to keep the comments on the bytes they belong to.
        #[rustfmt::skip]
        let data = [
            // Service ID
            sid,
            // This does not belong to our mux, it's here to test, if the start byte is used
            0xff,
            // Mux param starts here
            // switch selector bytes 'test'
            0x74, 0x65, 0x73, 0x74,
            // Case 3 has no structure, so nothing more follows
        ];

        let mux_1_json = json!({
            "mux_1_param": {
                "Selector": "test",
            }
        });

        test_mux_from_and_to_uds(ecu_manager, &service, sid, &data.to_vec(), mux_1_json).await;
    }

    async fn test_mux_from_and_to_uds(
        ecu_manager: super::EcuManager<DefaultSecurityPluginData>,
        service: &cda_interfaces::DiagComm,
        sid: u8,
        data: &Vec<u8>,
        mux_1_json: serde_json::Value,
    ) {
        let response = ecu_manager
            .convert_from_uds(service, &create_payload(data.clone()), true)
            .await
            .unwrap();

        // JSON for the response assertion
        let expected_response_json = {
            let mut merged = mux_1_json.clone();
            merged
                .as_object_mut()
                .unwrap()
                .insert("test_service_pos_sid".to_string(), json!(sid));
            merged
        };

        // Test from payload to json
        assert_eq!(
            response.serialize_to_json().unwrap().data,
            expected_response_json
        );

        let payload_data =
            UdsPayloadData::ParameterMap(serde_json::from_value(mux_1_json).unwrap());
        let mut service_payload = ecu_manager
            .create_uds_payload(service, &skip_sec_plugin!(), Some(payload_data))
            .await
            .unwrap();
        // The bytes set below are not modified by the create_uds_payload function,
        // because they do not belong to the mux param.
        // Setting them manually here, so we can check the full payload.
        if let Some(byte) = service_payload.data.get_mut(1)
            && let Some(&val) = data.get(1)
        {
            *byte = val;
        }
        if let Some(byte) = service_payload.data.get_mut(4)
            && let Some(&val) = data.get(4)
        {
            *byte = val;
        }

        // Test from json to payload
        assert_eq!(*service_payload.data, *data);
    }

    async fn validate_struct_payload(struct_byte_pos: u32) {
        let (ecu_manager, service, sid, struct_byte_len) =
            create_ecu_manager_with_struct_service(struct_byte_pos);

        // Test data for the structure
        let test_value = json!({
            "param1": 0x1234,
            "param2": 42.42,
            "param3": "test"
        });

        let payload_data =
            UdsPayloadData::ParameterMap(HashMap::from([("main_param".to_string(), test_value)]));

        let result = ecu_manager
            .create_uds_payload(&service, &skip_sec_plugin!(), Some(payload_data))
            .await;

        let service_payload = result.unwrap();

        // sid (1 byte) + gap (4 bytes) + param1 (2 bytes) + param2 (4 bytes) + param3 (4 bytes)
        // sid is missing here because byte pos starts at 0,
        // so we would have to add 1 more byte for sid
        // and subtract one for the gap
        assert_eq!(
            service_payload.data.len(),
            (struct_byte_pos + struct_byte_len) as usize
        );

        // Check sid
        assert_eq!(service_payload.data.first().copied(), Some(sid));

        let payload = service_payload
            .data
            .get(struct_byte_pos as usize..)
            .unwrap();

        // Check param1
        assert_eq!(payload.first().copied(), Some(0x12));
        assert_eq!(payload.get(1).copied(), Some(0x34));

        // Check param2
        let float_bytes = 42.42_f32.to_be_bytes();
        assert_eq!(payload.get(2..6), Some(&float_bytes[..]));

        // Check param3
        assert_eq!(payload.get(6..10), Some(&b"test"[..]));
    }

    #[tokio::test]
    async fn test_map_struct_to_uds() {
        validate_struct_payload(1).await;
    }

    #[tokio::test]
    async fn test_map_struct_to_uds_with_gap_in_payload() {
        validate_struct_payload(5).await;
    }

    #[tokio::test]
    async fn test_map_struct_to_uds_missing_parameter() {
        let (ecu_manager, service, _, _) = create_ecu_manager_with_struct_service(1);

        // Test data missing param2
        let test_value = json!({
            "param1": 0x1234
            // param2 is missing
        });

        let payload_data =
            UdsPayloadData::ParameterMap(HashMap::from([("main_param".to_string(), test_value)]));

        let result = ecu_manager
            .create_uds_payload(&service, &skip_sec_plugin!(), Some(payload_data))
            .await;

        // Should fail because param2 is missing
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(
                e.to_string()
                    .contains("Parameter 'param2' not part of the request body")
            );
        }
    }

    #[tokio::test]
    async fn test_map_struct_to_uds_invalid_json_type() {
        let (ecu_manager, service, _, _) = create_ecu_manager_with_struct_service(1);

        // Test data with wrong type (array instead of object)
        let test_value = json!([1, 2, 3]);

        let payload_data =
            UdsPayloadData::ParameterMap(HashMap::from([("main_param".to_string(), test_value)]));

        let result = ecu_manager
            .create_uds_payload(&service, &skip_sec_plugin!(), Some(payload_data))
            .await;

        // Should fail because we provided an array instead of an object
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("Expected value to be object type"));
        }
    }

    #[tokio::test]
    async fn test_map_mux_to_uds_with_default_case() {
        async fn test_default(
            ecu_manager: &super::EcuManager<DefaultSecurityPluginData>,
            service: &cda_interfaces::DiagComm,
            test_value: serde_json::Value,
            select_value: u16,
            sid: u8,
        ) {
            let payload_data =
                UdsPayloadData::ParameterMap(serde_json::from_value(test_value).unwrap());

            let service_payload = ecu_manager
                .create_uds_payload(service, &skip_sec_plugin!(), Some(payload_data))
                .await
                .unwrap();

            // Non-checked bytes do not belong to the mux param, so they are not set
            assert_eq!(service_payload.data.first().copied(), Some(sid));
            assert_eq!(service_payload.data.get(1).copied(), Some(0));

            // Check switch key
            assert_eq!(
                service_payload.data.get(2).copied(),
                Some(((select_value >> 8) & 0xFF) as u8)
            );
            assert_eq!(
                service_payload.data.get(3).copied(),
                Some((select_value & 0xFF) as u8)
            );

            // Check default_param
            assert_eq!(service_payload.data.get(4).copied(), Some(0x42));
        }

        let (ecu_manager, service, sid) = create_ecu_manager_with_mux_service_and_default_case();
        let with_selector = json!({
            "mux_1_param": {
                "Selector": 0xffff,
                "default_case": {
                    "default_structure_param_1": 0x42,
                }
            },
        });

        let without_selector = json!({
            "mux_1_param": {
                "default_case": {
                    "default_structure_param_1": 0x42,
                }
            },
        });

        test_default(&ecu_manager, &service, with_selector, 0xffff, sid).await;
        // when not selector value is given,
        // the switch key will use the limit value of the default value
        test_default(&ecu_manager, &service, without_selector, 0, sid).await;
    }

    #[tokio::test]
    async fn test_map_mux_to_uds_invalid_json_type() {
        let (ecu_manager, service, _) = create_ecu_manager_with_mux_service(None, None, None);

        // Test data with wrong type (array instead of object)
        let test_value = json!([1, 2, 3]);

        let payload_data =
            UdsPayloadData::ParameterMap(HashMap::from([("mux_1_param".to_string(), test_value)]));

        let result = ecu_manager
            .create_uds_payload(&service, &skip_sec_plugin!(), Some(payload_data))
            .await;

        // Should fail because we provided an array instead of an object
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(
                e.to_string().contains("Expected value to be object type"),
                "Expected error message to contain 'Expected value to be object type', but got: \
                 {e}",
            );
        }
    }

    #[tokio::test]
    async fn test_map_mux_to_uds_missing_case_data() {
        let (ecu_manager, service, _) = create_ecu_manager_with_mux_service(None, None, None);

        // Test data with valid selector but missing case data
        let test_value = json!({
            "mux_1_param": {
                "Selector": 0x0a,
            },
        });

        let payload_data =
            UdsPayloadData::ParameterMap(serde_json::from_value(test_value).unwrap());

        let result = ecu_manager
            .create_uds_payload(&service, &skip_sec_plugin!(), Some(payload_data))
            .await;

        // Should fail because case1 data is missing
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Mux case mux_1_case_1 value not found in json")
        );
    }

    #[tokio::test]
    async fn test_map_struct_from_uds_end_pdu_min_items_not_reached() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_end_pdu_service(3, Some(2));
        // Each item is 3 bytes: 1 byte for param1 + 2 bytes for param2
        let data = vec![
            sid, // Service ID
            // First item
            0x42, // item_param1 = 0x42
            0x12, 0x34, // item_param2 = 0x1234
            // Second item (exactly at the limit)
            0x99, // item_param1 = 0x99
            0x56, 0x78, // item_param2 = 0x5678
        ];

        let response = ecu_manager
            .convert_from_uds(&service, &create_payload(data), true)
            .await
            .unwrap();

        let expected_json = json!({
            "end_pdu_param": [
                {
                    "item_param1": 0x42,
                    "item_param2": 0x1234
                },
                {
                    "item_param1": 0x99,
                    "item_param2": 0x5678
                }
            ],
            "test_service_pos_sid": sid
        });

        assert_eq!(response.serialize_to_json().unwrap().data, expected_json);
    }

    #[tokio::test]
    async fn test_map_struct_from_uds_end_pdu_exact_max_items() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_end_pdu_service(1, Some(2));

        // Create payload with exactly 2 items (the max_items limit)
        // Each item is 3 bytes: 1 byte for param1 + 2 bytes for param2
        let data = vec![
            sid, // Service ID
            // First item
            0x42, // item_param1 = 0x42
            0x12, 0x34, // item_param2 = 0x1234
            // Second item (exactly at the limit)
            0x99, // item_param1 = 0x99
            0x56, 0x78, // item_param2 = 0x5678
        ];

        let response = ecu_manager
            .convert_from_uds(&service, &create_payload(data), true)
            .await
            .unwrap();

        let expected_json = json!({
            "end_pdu_param": [
                {
                    "item_param1": 0x42,
                    "item_param2": 0x1234
                },
                {
                    "item_param1": 0x99,
                    "item_param2": 0x5678
                }
            ],
            "test_service_pos_sid": sid
        });

        assert_eq!(response.serialize_to_json().unwrap().data, expected_json);
    }

    #[tokio::test]
    async fn test_map_struct_from_uds_end_pdu_exceeds_max_items() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_end_pdu_service(1, Some(2));

        // Create payload with 3 items (exceeds max_items = 2)
        let data = vec![
            sid, // Service ID
            0x42, 0x12, 0x34, // First item
            0x99, 0x56, 0x78, // Second item
            // A complete third element would not be ignored as specified in the ODX standard
            0xAA, 0xFF, // Third item, incomplete and exceeding limit, will be ignored
        ];

        let response = ecu_manager
            .convert_from_uds(&service, &create_payload(data), true)
            .await
            .unwrap();
        let expected_json = json!({
            "end_pdu_param": [
                {
                    "item_param1": 0x42,
                    "item_param2": 0x1234
                },
                {
                    "item_param1": 0x99,
                    "item_param2": 0x5678
                }
            ],
            "test_service_pos_sid": sid
        });

        // extra data at the end is ignored.
        assert_eq!(response.serialize_to_json().unwrap().data, expected_json);
    }

    #[tokio::test]
    async fn test_map_struct_from_uds_end_pdu_no_max_no_min_no_data() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_end_pdu_service(0, None);

        // Valid payload, as min_items = 0 and no max_items
        // Only the SID is present, no items follow
        let data = vec![
            sid, // Service ID
        ];

        let response = ecu_manager
            .convert_from_uds(&service, &create_payload(data), true)
            .await
            .unwrap();
        let expected_json = json!({
            "end_pdu_param": [
            ],
            "test_service_pos_sid": sid
        });

        assert_eq!(response.serialize_to_json().unwrap().data, expected_json);
    }

    #[tokio::test]
    async fn test_map_struct_from_uds_end_pdu_no_maximum() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_end_pdu_service(1, None);

        // Create payload with 3 items (exceeds max_items = 2)
        let data = vec![
            sid, // Service ID
            0x42, 0x12, 0x34, // First item
            0x99, 0x56, 0x78, // Second item
            0xAA, 0x9A, 0xBC, // Third item
            0xD0, 0x0F, // extra data at the end, will be ignored
        ];

        let response = ecu_manager
            .convert_from_uds(&service, &create_payload(data), true)
            .await
            .unwrap();
        let expected_json = json!({
            "end_pdu_param": [
                {
                    "item_param1": 0x42,
                    "item_param2": 0x1234
                },
                {
                    "item_param1": 0x99,
                    "item_param2": 0x5678
                },
                 {
                    "item_param1": 0xAA,
                    "item_param2": 0x9ABC
                }
            ],
            "test_service_pos_sid": sid
        });

        assert_eq!(response.serialize_to_json().unwrap().data, expected_json);
    }

    #[tokio::test]
    async fn test_map_dtc_from_uds() {
        let (ecu_manager, service, sid, dtc_code) = create_ecu_manager_with_dtc();

        let mut payload = vec![sid];
        payload.extend_from_slice(&dtc_code.to_be_bytes());

        let response = ecu_manager
            .convert_from_uds(&service, &create_payload(payload), true)
            .await
            .unwrap();

        let expected_json = json!({
            "DtcRecord": {
                "code": dtc_code,
                "display_code": "P1234",
                "fault_name": "TestFault",
                "severity": 2,
            },
            "test_service_pos_sid": sid
        });

        assert_eq!(response.serialize_to_json().unwrap().data, expected_json);
    }

    #[tokio::test]
    async fn test_map_dynamic_length_field_from_uds() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_dynamic_length_field_service();
        let payload = vec![
            sid,  // Service ID
            0x03, // 3 total fields
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        ];

        let response = ecu_manager
            .convert_from_uds(&service, &create_payload(payload), true)
            .await
            .unwrap();

        let expected_json = json!({
            "pos_response_param": [
               { "item_param": 0x1122, },
               { "item_param": 0x3344, },
               { "item_param": 0x5566, },
            ],
             "test_service_pos_sid": sid
        });

        assert_eq!(response.serialize_to_json().unwrap().data, expected_json);
    }

    #[tokio::test]
    async fn test_map_dynamic_length_field_from_uds_not_enough_data() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_dynamic_length_field_service();
        let payload = vec![
            sid,  // Service ID
            0x03, // 3 total fields, but only 2 are provided
            0x11, 0x22, 0x33, 0x44,
        ];

        let response = ecu_manager
            .convert_from_uds(&service, &create_payload(payload), true)
            .await;

        assert_eq!(
            response.err(),
            Some(DiagServiceError::NotEnoughData {
                expected: 2,
                actual: 0
            })
        );
    }

    #[tokio::test]
    async fn test_negative_response() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_dynamic_length_field_service();
        let payload = vec![0x7f, sid];

        let response = ecu_manager
            .convert_from_uds(&service, &create_payload(payload), true)
            .await
            .unwrap();
        assert_eq!(response.response_type, DiagServiceResponseType::Negative);
    }

    #[tokio::test]
    async fn test_negative_response_with_invalid_data_where_no_neg_response_is_defined() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_end_pdu_service(1, None);
        let data = vec![0x7f, sid, 0x33];

        let response = ecu_manager
            .convert_from_uds(&service, &create_payload(data), true)
            .await
            .unwrap();
        assert_eq!(response.response_type, DiagServiceResponseType::Negative);
    }
}
