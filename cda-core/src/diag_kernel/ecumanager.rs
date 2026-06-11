/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

use std::{sync::Arc, time::Duration};

use cda_database::datatypes;
use cda_interfaces::{
    DiagComm, DiagCommType, DiagServiceError, DynamicPlugin, EcuManagerType, EcuState, EcuVariant,
    HashMap, HashMapExtensions, HashSet, HashSetExtensions, Protocol, SecurityAccess,
    ServicePayload,
    datatypes::{
        AddressingMode, CLEAR_FAULT_MEM_POS_RESPONSE_SID, ComParamConfig, ComParamPrecedence,
        ComParams, ComplexComParamValue, ComponentConfigurationsInfo, ComponentDataInfo,
        ComponentOperationsInfo, DTC_CODE_BIT_LEN, DatabaseNamingConvention,
        DiagnosticServiceAffixPosition, DtcLookup, DtcReadInformationFunction, RetryPolicy,
        RoutineSubfunctions, SdSdg, TesterPresentSendType, semantics, single_ecu,
    },
    diagservices::{DiagServiceResponse, DiagServiceResponseType, FieldParseError, UdsPayloadData},
    dlt_ctx, service_ids, subfunction_ids,
    util::{
        self, contains_ignore_ascii_case, ends_with_ignore_ascii_case,
        starts_with_ignore_ascii_case,
    },
};
use cda_plugin_security::SecurityPlugin;
use tokio::sync::RwLock;

use super::service_lookup::DbCache;
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
        variant_detection::{self, VariantDetection},
    },
};

// Helper struct to extract variant data without lifetime dependencies
// Necessary to de-couple set_variant lifetimes and prevent borrow issues,
// we would have when using Variant<'_> from database.
// Not using EcuVariant instead because contains additional fields we're looking up in
// set_variant
struct VariantData {
    name: String,
    is_base_variant: bool,
    is_fallback: bool,
}

#[derive(Clone, Copy)]
struct ParamContext<'a> {
    parameter: &'a datatypes::Parameter<'a>,
    base_offset: usize,
    outer_context: Option<&'a MappedDiagServiceResponsePayload>,
}

impl<'a> ParamContext<'a> {
    fn new(parameter: &'a datatypes::Parameter<'a>, base_offset: usize) -> Self {
        Self {
            parameter,
            base_offset,
            outer_context: None,
        }
    }

    fn with_outer_context(
        self,
        outer_context: Option<&'a MappedDiagServiceResponsePayload>,
    ) -> Self {
        Self {
            outer_context,
            ..self
        }
    }

    fn abs_byte_pos(self) -> usize {
        self.base_offset
            .saturating_add(self.parameter.byte_position() as usize)
    }
}

impl VariantData {
    fn from_variant_and_fallback(v: &datatypes::Variant<'_>, is_fallback: bool) -> Self {
        Self {
            name: (*v)
                .diag_layer()
                .and_then(|d| d.short_name())
                .unwrap_or_default()
                .to_owned(),
            is_base_variant: v.is_base_variant(),
            is_fallback,
        }
    }
}

// Allowed because this holds a bunch of config values.
#[allow(clippy::struct_excessive_bools)]
pub struct EcuManager<S: SecurityPlugin> {
    pub(crate) diag_database: datatypes::DiagnosticDatabase,
    pub(crate) db_cache: DbCache,
    pub(crate) ecu_name: String,
    pub(crate) description_type: EcuManagerType,
    pub(crate) database_naming_convention: DatabaseNamingConvention,
    pub(crate) tester_address: u16,
    pub(crate) logical_address: u16,
    pub(crate) logical_gateway_address: u16,
    pub(crate) logical_functional_address: u16,

    pub(crate) nack_number_of_retries: HashMap<u8, u32>,
    pub(crate) diagnostic_ack_timeout: Duration,
    pub(crate) retry_period: Duration,
    pub(crate) routing_activation_timeout: Duration,
    pub(crate) repeat_request_count_transmission: u32,
    pub(crate) connection_timeout: Duration,
    pub(crate) connection_retry_delay: Duration,
    pub(crate) connection_retry_attempts: u32,

    variant_detection: variant_detection::VariantDetection,
    pub(crate) variant_index: Option<usize>,
    pub(crate) variant: EcuVariant,
    pub(crate) fallback_to_base_variant: bool,
    pub(crate) duplicating_ecu_names: Option<HashSet<String>>,

    pub(crate) protocol: Protocol,
    // functional group: protocol prefixed or postfixed
    pub(crate) fg_protocol_position: DiagnosticServiceAffixPosition,
    pub(crate) ecu_service_states: Arc<RwLock<HashMap<u8, String>>>,

    pub(crate) tester_present_retry_policy: bool,
    pub(crate) tester_present_addr_mode: AddressingMode,
    pub(crate) tester_present_response_expected: bool,
    pub(crate) tester_present_send_type: TesterPresentSendType,
    pub(crate) tester_present_message: Vec<u8>,
    pub(crate) tester_present_exp_pos_resp: Vec<u8>,
    pub(crate) tester_present_exp_neg_resp: Vec<u8>,
    pub(crate) tester_present_time: Duration,
    pub(crate) repeat_req_count_app: u32,
    pub(crate) rc_21_retry_policy: RetryPolicy,
    pub(crate) rc_21_completion_timeout: Duration,
    pub(crate) rc_21_repeat_request_time: Duration,
    pub(crate) rc_78_retry_policy: RetryPolicy,
    pub(crate) rc_78_completion_timeout: Duration,
    pub(crate) rc_78_timeout: Duration,
    pub(crate) rc_94_retry_policy: RetryPolicy,
    pub(crate) rc_94_completion_timeout: Duration,
    pub(crate) rc_94_repeat_request_time: Duration,
    pub(crate) timeout_default: Duration,

    security_plugin_phantom: std::marker::PhantomData<S>,
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

    fn logical_address_eq<T: cda_interfaces::EcuAddressProvider>(&self, other: &T) -> bool {
        self.logical_address == other.logical_address()
            && self.logical_gateway_address() == other.logical_gateway_address()
    }
}

impl<S: SecurityPlugin> cda_interfaces::EcuManager for EcuManager<S> {
    type Response = DiagServiceResponseStruct;

    fn is_physical_ecu(&self) -> bool {
        self.description_type == EcuManagerType::Ecu
    }

    fn variant(&self) -> EcuVariant {
        self.variant.clone()
    }

    fn state(&self) -> EcuState {
        self.variant.state
    }

    fn protocol(&self) -> &Protocol {
        &self.protocol
    }

    fn is_loaded(&self) -> bool {
        self.diag_database.is_loaded()
    }

    /// This allows to (re)load a database after unloading it during runtime, which could happen
    /// if initially the ECU wasn't responding but later another request
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
        fields(
            ecu_name = self.ecu_name,
            dlt_context = dlt_ctx!("CORE"),
        ),
    )]
    async fn detect_variant<T: DiagServiceResponse + Sized>(
        &mut self,
        service_responses: HashMap<String, T>,
    ) -> Result<(), DiagServiceError> {
        if !self.diag_database.is_loaded() {
            tracing::debug!(ecu_name = %self.ecu_name, "Loading database for variant detection");
            self.load()?;
        }

        if service_responses.is_empty() {
            let state = if matches!(
                self.variant.state,
                EcuState::Online
                    | EcuState::Duplicate
                    | EcuState::Disconnected
                    | EcuState::NoVariantDetected
            ) {
                EcuState::Disconnected
            } else {
                EcuState::Offline
            };

            self.variant = EcuVariant {
                name: None,
                is_base_variant: false,
                is_fallback: false,
                state,
                logical_address: self.logical_address,
            };
            return Ok(());
        }
        match variant_detection::evaluate_variant(service_responses, &self.diag_database) {
            Ok(v) => {
                let variant_data = VariantData::from_variant_and_fallback(&v, false);
                self.set_variant(variant_data).await
            }
            Err(e) => {
                if !self.fallback_to_base_variant {
                    self.variant = EcuVariant {
                        name: None,
                        is_base_variant: false,
                        is_fallback: false,
                        state: EcuState::NoVariantDetected,
                        logical_address: self.logical_address,
                    };
                    self.diag_database.unload();
                    tracing::debug!(
                        "No variant detected, fallback to base variant disabled, unloading DB"
                    );
                    return Err(e);
                }

                let base_variant = match self.diag_database.base_variant() {
                    Ok(base_variant) => base_variant,
                    Err(e) => {
                        self.variant = EcuVariant {
                            name: None,
                            is_base_variant: false,
                            is_fallback: false,
                            state: EcuState::NoVariantDetected,
                            logical_address: self.logical_address,
                        };
                        self.diag_database.unload();
                        tracing::debug!(
                            "No variant detected, and no base variant found in DB, unloading DB"
                        );
                        return Err(e);
                    }
                };

                let variant_data = VariantData::from_variant_and_fallback(&base_variant, true);
                self.set_variant(variant_data).await
            }
        }
    }

    fn get_variant_detection_requests(&self) -> &HashMap<String, DiagComm> {
        &self.variant_detection.diag_service_requests
    }

    #[tracing::instrument(skip(self),
        fields(
            ecu_name = self.ecu_name,
            dlt_context = dlt_ctx!("CORE"),
        )
    )]
    fn comparams(&self) -> Result<ComplexComParamValue, DiagServiceError> {
        Ok(self
            .get_diag_layers_from_variant_and_parent_refs()
            .into_iter()
            .filter_map(|dl| dl.com_param_refs())
            .flat_map(|cp_ref_vec| cp_ref_vec.iter())
            .filter(|cp_ref| {
                cp_ref.protocol().is_some_and(|p| {
                    p.diag_layer().is_some_and(|dl| {
                        dl.short_name()
                            .is_some_and(|name| name.eq_ignore_ascii_case(self.protocol.str()))
                    })
                })
            })
            .filter_map(|cp_ref| datatypes::resolve_comparam(&cp_ref).ok())
            .collect())
    }

    #[tracing::instrument(skip_all,
        fields(
            dlt_context = dlt_ctx!("CORE"),
        )
    )]
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
            self.lookup_diag_service(service, None, None)
                .await?
                .diag_comm()
                .and_then(|sdg| sdg.sdgs())
                .map(datatypes::Sdgs)
        } else {
            self.get_diag_layers_from_variant_and_parent_refs()
                .into_iter()
                .find_map(|dl| dl.sdgs())
                .or_else(|| {
                    // Fall back to the base variant's DiagLayer SDGs when no
                    // variant has been detected yet (e.g. ECU is offline).
                    self.diag_database
                        .base_variant()
                        .ok()
                        .and_then(|v| v.diag_layer())
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

    async fn check_genericservice(
        &self,
        security_plugin: &DynamicPlugin,
        rawdata: Vec<u8>,
    ) -> Result<ServicePayload, DiagServiceError> {
        let raw_data_sid = rawdata.first().copied().ok_or_else(|| {
            DiagServiceError::BadPayload("Expected at least 1 byte to read SID".to_owned())
        })?;

        // iterate through the services and for each service, resolve the parameters
        // sort the parameters by byte_pos & bit_pos, and take the first parameter
        // this is the service id. check if the provided rawdata matches the expected
        // bytes for the service id, and if yes, return this service.
        // If no service with a matching SIDRQ can be found, DiagServiceError::NotFound
        // is returned to the caller.
        let matched_services = self.get_services_from_variant_and_parent_refs(|service| {
            service
                .request_id()
                .is_some_and(|service_id| raw_data_sid == service_id)
        });
        let mapped_service = matched_services.first().ok_or_else(|| {
            DiagServiceError::NotFound(format!(
                "No matching generic service found for SID {raw_data_sid:#04X}"
            ))
        })?;
        let mapped_dc = mapped_service.diag_comm().map(datatypes::DiagComm).ok_or(
            DiagServiceError::InvalidDatabase("Service is missing DiagComm".to_owned()),
        )?;

        self.check_service_access(security_plugin, mapped_service)
            .await?;

        let (new_session, new_security) = self
            .lookup_state_transition_by_diagcomm_for_active(&mapped_dc)
            .await;

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
    /// Will return `Err` in cases where the payload doesn't match the expected UDS response, or if
    /// elements of the response cannot be correctly mapped from the raw data.
    #[tracing::instrument(
        target = "convert_from_uds",
        skip(self, diag_service, payload),
        fields(
            ecu_name = self.ecu_name,
            service = diag_service.name,
            input = util::tracing::print_hex(&payload.data, 10),
            output = tracing::field::Empty,
            dlt_context = dlt_ctx!("CORE"),
        ),
        err
    )]
    // allow keeping the function together as it makes sense structurally
    #[allow(clippy::too_many_lines)]
    async fn convert_from_uds(
        &self,
        diag_service: &cda_interfaces::DiagComm,
        payload: &ServicePayload,
        map_to_json: bool,
        functional_group_name: Option<&str>,
    ) -> Result<DiagServiceResponseStruct, DiagServiceError> {
        let mapped_service = self
            .lookup_diag_service(diag_service, functional_group_name, None)
            .await?;
        let mapped_diag_comm = mapped_service
            .diag_comm()
            .map(datatypes::DiagComm)
            .ok_or_else(|| DiagServiceError::InvalidDatabase("No DiagComm found".to_owned()))?;

        let sid = util::try_extract_sid_from_payload(payload.data.as_slice())?;

        let mut uds_payload = Payload::new(&payload.data);
        let response_first_byte = uds_payload.first().ok_or_else(|| {
            DiagServiceError::BadPayload("Payload too short to read first byte".to_owned())
        })?;
        let response_first_byte_value = response_first_byte.to_string();

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
                        && p.specific_data_as_coded_const().is_some_and(|c| {
                            c.coded_value()
                                .is_some_and(|v| v == response_first_byte_value)
                        })
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
                let (new_session, new_security) = self
                    .lookup_state_transition_by_diagcomm_for_active(&mapped_diag_comm)
                    .await;

                if let Some(new_session) = new_session {
                    self.set_service_state(service_ids::SESSION_CONTROL, new_session)
                        .await;
                }
                if let Some(new_security_access) = new_security {
                    self.set_service_state(service_ids::SECURITY_ACCESS, new_security_access)
                        .await;
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
            let mut sorted_params = params;
            sorted_params.sort_by(param_position_order);
            for param in sorted_params {
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

                if param.has_byte_position() {
                    uds_payload.set_last_read_byte_pos(param.byte_position() as usize);
                }
                match self.map_param_from_uds(
                    &mapped_service,
                    short_name,
                    &mut uds_payload,
                    &mut data,
                    ParamContext::new(&param, 0),
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
            tracing::warn!("No matching response found for SID: {sid}");
            Ok(DiagServiceResponseStruct {
                service: diag_service.clone(),
                data: payload.data.clone(),
                mapped_data: None,
                response_type: if *response_first_byte == service_ids::NEGATIVE_RESPONSE {
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
            output = tracing::field::Empty,
            dlt_context = dlt_ctx!("CORE"),
        ),
        err
    )]
    async fn create_uds_payload(
        &self,
        diag_service: &cda_interfaces::DiagComm,
        security_plugin: &DynamicPlugin,
        data: Option<UdsPayloadData>,
        functional_group_name: Option<&str>,
    ) -> Result<ServicePayload, DiagServiceError> {
        let mapped_service = self
            .lookup_diag_service(diag_service, functional_group_name, None)
            .await?;
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

        // Skip the service access check for functional calls
        if functional_group_name.is_none() {
            self.check_service_access(security_plugin, &mapped_service)
                .await?;
        }

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
            match (a.has_byte_position(), b.has_byte_position()) {
                // Both have a position -> normal comparison
                (true, true) => a
                    .byte_position()
                    .cmp(&b.byte_position())
                    .then(a.bit_position().cmp(&b.bit_position())),
                // Only a has no position -> a goes after b
                (false, true) => std::cmp::Ordering::Greater,
                // Only b has no position -> b goes after a
                (true, false) => std::cmp::Ordering::Less,
                // Neither has a position -> preserve order
                (false, false) => std::cmp::Ordering::Equal,
            }
        });

        let mut uds = process_coded_constants(&mapped_params)?;

        // If no input data was provided, fall back to an empty parameter map
        // this allows for a streamlined handling where some values might
        // have defaults that can be used when no data is provided, while returning
        // errors if the request expects input data but it is not provided.
        let data = match data {
            Some(d) => d,
            None => UdsPayloadData::ParameterMap(HashMap::new()),
        };
        match data {
            UdsPayloadData::Raw(bytes) => uds.extend(bytes),
            UdsPayloadData::ParameterMap(json_values) => {
                self.process_parameter_map(&mapped_params, &json_values, &mut uds)?;
            }
        }

        let (new_session, new_security) = self
            .lookup_state_transition_by_diagcomm_for_active(&(mapped_dc.into()))
            .await;
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
    #[tracing::instrument(skip(self),
        fields(
            ecu_name = self.ecu_name,
            dlt_context = dlt_ctx!("CORE"),
            job_name
        )
    )]
    fn lookup_single_ecu_job(&self, job_name: &str) -> Result<single_ecu::Job, DiagServiceError> {
        tracing::debug!("Looking up single ECU job");
        self.get_single_ecu_jobs_from_variant_and_parent_refs(|job| {
            job.diag_comm().is_some_and(|dc| {
                dc.short_name()
                    .is_some_and(|n| n.eq_ignore_ascii_case(job_name))
            })
        })
        .into_iter()
        .next()
        .map(|job| (*job).into())
        .ok_or(DiagServiceError::NotFound(format!(
            "Single ECU job with name '{job_name}' not found"
        )))
    }

    /// Lookup a service by a given function class name and service id.
    /// # Errors
    /// Will return `Err` if the lookup failed
    fn lookup_service_through_func_class(
        &self,
        func_class_name: &str,
        service_id: u8,
    ) -> Result<cda_interfaces::DiagComm, DiagServiceError> {
        self.get_services_from_variant_and_parent_refs(|service| {
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
                .as_ref()
                .is_some_and(|_| service.request_id().is_some_and(|id| id == service_id))
        })
        .into_iter()
        .next()
        .and_then(|service| service.try_into().ok())
        .ok_or_else(|| {
            DiagServiceError::NotFound(format!(
                "Service with functional class '{func_class_name}' and SID {service_id:#04X} not \
                 found"
            ))
        })
    }

    /// Lookup services by matching a service request prefix.
    ///
    /// Finds diagnostic services where the request parameters match a sequence of bytes.
    /// This is useful for finding services based on (partial) service identifier,
    /// including service ID, subfunction, and additional coded constant parameters.
    /// Partial parameters won't match and the prefix must be aligned to parameter boundaries.
    ///
    /// # Parameters
    /// * `service_bytes` - A byte slice containing the service identifier and parameters.
    ///   The first byte is the service ID (SID), followed by any coded constant parameters
    ///   in their sequential byte positions (e.g., `[0x31, 0x01, 0x02, 0x46]`
    ///   Only `uint32_t` coded consts are supported here.
    ///
    /// # Returns
    /// A vector of service short names that match the criteria
    ///
    /// # Errors
    /// Returns `DiagServiceError::NotFound` if no services match the given request prefix,
    /// or `DiagServiceError::InvalidParameter` if the `service_bytes` slice is empty.
    fn lookup_diagcomms_by_request_prefix(
        &self,
        request_bytes: &[u8],
    ) -> Result<Vec<DiagComm>, DiagServiceError> {
        let service_id = *request_bytes.first().ok_or(DiagServiceError::NotFound(
            "cannot lookup service by empty prefix".to_owned(),
        ))?;
        let services: Vec<_> = self
            .lookup_services_by_sid(service_id)?
            .iter()
            .filter(|service| {
                let mut byte_idx = 0usize;
                for param in service.extract_sequential_coded_consts() {
                    let param_byte_count = param.byte_count();
                    if param_byte_count > 4 {
                        return false;
                    }
                    let Some(end_idx) = byte_idx.checked_add(param_byte_count) else {
                        return false;
                    };
                    // Ran out of caller-provided bytes, all provided bytes matched, accept
                    if end_idx > request_bytes.len() {
                        return true;
                    }
                    // extract subslice from `request_bytes`, matching the current parameter
                    let Some(param_slice) = request_bytes.get(byte_idx..end_idx) else {
                        return false;
                    };

                    let mut buf = [0u8; 4];
                    // calculate where in the 4-byte buffer to place the parameter bytes.
                    // i.e. a 2 byte param goes into buf[2..4],
                    // leaving buf[0..2] as zero-padding,
                    // copy this into the buffer and convert into u32 big endian.
                    let start = 4usize.saturating_sub(param_byte_count);
                    let Some(buf_slice) = buf.get_mut(start..) else {
                        return false;
                    };
                    buf_slice.copy_from_slice(param_slice);

                    // check if the parameter from the db matches the input
                    let expected_value = u32::from_be_bytes(buf);
                    if param.value != expected_value {
                        return false;
                    }
                    byte_idx = end_idx;
                }
                true // all consts iterated and all matched
            })
            .filter_map(|service| service.diag_comm())
            .filter_map(|dc| {
                let short_name = dc.short_name()?;
                let type_ = DiagCommType::try_from(service_id).ok()?;

                Some(DiagComm {
                    name: self
                        .database_naming_convention
                        .trim_short_name_affixes(short_name),
                    type_,
                    lookup_name: Some(short_name.to_owned()),
                    subfunction_id: None,
                })
            })
            .collect();

        if services.is_empty() {
            Err(DiagServiceError::NotFound(format!(
                "No service found matching request prefix: {request_bytes:02X?}"
            )))
        } else {
            Ok(services)
        }
    }

    fn lookup_service_by_sid_and_name(
        &self,
        service_id: u8,
        name: &str,
        functional_group_name: Option<&str>,
    ) -> Result<DiagComm, DiagServiceError> {
        let services = if let Some(fg_name) = functional_group_name {
            self.get_services_from_functional_group_and_parent_refs(fg_name, |service| {
                service
                    .request_id()
                    .is_some_and(|req_id| req_id == service_id)
            })?
        } else {
            self.lookup_services_by_sid(service_id)?
        };

        let result = services.iter().find_map(|service| {
            let diag_comm = service.diag_comm()?;
            let short_name = diag_comm.short_name()?;

            let short_name_no_affix = self
                .database_naming_convention
                .trim_service_name_affixes(service_id, short_name.to_owned());
            let matches = match self.database_naming_convention.short_name_affix_position {
                DiagnosticServiceAffixPosition::Suffix => {
                    starts_with_ignore_ascii_case(&short_name_no_affix, name)
                }
                DiagnosticServiceAffixPosition::Prefix => {
                    ends_with_ignore_ascii_case(&short_name_no_affix, name)
                }
            };

            if !matches {
                return None;
            }

            Some(DiagComm {
                name: short_name.to_owned(),
                type_: DiagCommType::try_from(service_id).ok()?,
                lookup_name: Some(short_name.to_owned()),
                subfunction_id: None,
            })
        });

        if let Some(diag_comm) = result {
            Ok(diag_comm)
        } else {
            let alternatives: HashSet<String> = services
                .iter()
                .filter_map(|service| {
                    let diag_comm = service.diag_comm()?;
                    let short_name = diag_comm.short_name()?;
                    let short_name_no_affix =
                        self.database_naming_convention.trim_short_name_affixes(
                            &self
                                .database_naming_convention
                                .trim_service_name_affixes(service_id, short_name.to_owned()),
                        );
                    Some(short_name_no_affix)
                })
                .collect();

            Err(DiagServiceError::InvalidParameter {
                possible_values: alternatives,
            })
        }
    }

    fn get_components_data_info(&self, security_plugin: &DynamicPlugin) -> Vec<ComponentDataInfo> {
        self.get_services_from_variant_and_parent_refs(|service| {
            service
                .request_id()
                .is_some_and(|id| id == service_ids::READ_DATA_BY_IDENTIFIER)
        })
        .into_iter()
        .filter(|service| Self::is_service_visible(security_plugin, service))
        .filter_map(|service| {
            let diag_comm = service.diag_comm()?;
            Some(self.diag_comm_to_component_data_info(&(diag_comm.into())))
        })
        .collect()
    }

    fn get_functional_group_data_info(
        &self,
        security_plugin: &DynamicPlugin,
        functional_group_name: &str,
    ) -> Result<Vec<ComponentDataInfo>, DiagServiceError> {
        Ok(self
            .get_services_from_functional_group_and_parent_refs(functional_group_name, |service| {
                service
                    .request_id()
                    .is_some_and(|id| id == service_ids::READ_DATA_BY_IDENTIFIER)
            })?
            .into_iter()
            .filter(|service| Self::is_service_visible(security_plugin, service))
            .filter_map(|service| {
                let diag_comm = service.diag_comm()?;
                Some(self.diag_comm_to_component_data_info(&(diag_comm.into())))
            })
            .collect())
    }

    /// Returns all `RoutineControl` (SID 0x31) services for the functional group,
    /// with flags indicating whether Stop (0x02) and `RequestResults` (0x03)
    /// subfunctions are also defined.
    fn get_functional_group_operations_info(
        &self,
        security_plugin: &DynamicPlugin,
        functional_group_name: &str,
    ) -> Result<Vec<ComponentOperationsInfo>, DiagServiceError> {
        let routine_ctrl_services = self.get_services_from_functional_group_and_parent_refs(
            functional_group_name,
            |service| {
                service
                    .request_id()
                    .is_some_and(|id| id == service_ids::ROUTINE_CONTROL)
                    && Self::is_service_visible(security_plugin, service)
            },
        )?;

        Ok(self.filter_and_transform_operations(routine_ctrl_services))
    }

    /// Check which additional `RoutineControl` subfunctions are defined for a specific routine
    /// within a functional group.
    ///
    /// Mirrors `get_routine_subfunctions` but scopes the lookup to the given functional group's
    /// diag layer instead of the ECU variant.
    ///
    /// # Errors
    /// Returns `DiagServiceError::NotFound` if the functional group does not exist, or if the
    /// Start (0x01) subfunction for the given service name is not found within it.
    fn get_functional_group_routine_subfunctions(
        &self,
        security_plugin: &DynamicPlugin,
        functional_group_name: &str,
        service_name: &str,
    ) -> Result<RoutineSubfunctions, DiagServiceError> {
        let all_rc_services = self.get_services_from_functional_group_and_parent_refs(
            functional_group_name,
            |service| {
                service
                    .request_id()
                    .is_some_and(|id| id == service_ids::ROUTINE_CONTROL)
                    && Self::is_service_visible(security_plugin, service)
                    && service.diag_comm().is_some_and(|dc| {
                        dc.short_name().is_some_and(|name| {
                            self.trim_routine_name(name)
                                .eq_ignore_ascii_case(service_name)
                        })
                    })
            },
        )?;

        if all_rc_services.is_empty() {
            return Err(DiagServiceError::NotFound(format!(
                "No RoutineControl service with name '{service_name}' found in functional group \
                 '{functional_group_name}'"
            )));
        }

        Ok(Self::subfunction_flags_from_services(&all_rc_services))
    }

    fn get_components_single_ecu_jobs_info(&self) -> Vec<ComponentDataInfo> {
        self.get_single_ecu_jobs_from_variant_and_parent_refs(|_| true)
            .into_iter()
            .filter_map(|job: datatypes::SingleEcuJob<'_>| {
                let diag_comm = job.diag_comm()?;
                let semantic = diag_comm.semantic()?;
                Some(ComponentDataInfo {
                    category: semantic.to_lowercase(),
                    id: diag_comm.short_name().map_or(<_>::default(), |n| {
                        self.database_naming_convention
                            .trim_short_name_affixes(n)
                            .to_lowercase()
                    }),
                    name: diag_comm
                        .long_name()
                        .and_then(|ln| ln.value().map(ToOwned::to_owned))
                        .unwrap_or_default(),
                })
            })
            .collect()
    }

    #[tracing::instrument(skip_all,
        fields(
            dlt_context = dlt_ctx!("CORE"),
        )
    )]
    async fn set_service_state(&self, sid: u8, value: String) {
        tracing::debug!("Setting service state: SID: {sid}, Value: {value}");
        self.ecu_service_states.write().await.insert(sid, value);
    }

    #[tracing::instrument(skip_all,
        fields(
            dlt_context = dlt_ctx!("CORE"),
        )
    )]
    async fn get_service_state(&self, sid: u8) -> Option<String> {
        self.ecu_service_states.read().await.get(&sid).cloned()
    }

    async fn lookup_session_change(
        &self,
        target_session_name: &str,
    ) -> Result<cda_interfaces::DiagComm, DiagServiceError> {
        let current_session_name = self
            .ecu_service_states
            .read()
            .await
            .get(&service_ids::SESSION_CONTROL)
            .cloned()
            .ok_or(DiagServiceError::InvalidState(
                "ECU session is none".to_string(),
            ))?;

        self.lookup_state_transition_for_active(
            semantics::SESSION,
            &current_session_name,
            target_session_name,
        )
    }

    async fn lookup_security_access_change(
        &self,
        level: &str,
        has_key: bool,
    ) -> Result<SecurityAccess, DiagServiceError> {
        let current_security_name = self.security_access().await?;

        if has_key {
            let security_service = self.lookup_state_transition_for_active(
                semantics::SECURITY,
                &current_security_name,
                level,
            )?;
            Ok(SecurityAccess::SendKey(security_service))
        } else {
            // Find the RequestSeed service for the requested level by searching all SID 0x27
            // services in the ISO 14229-1 RequestSeed subfunction range and selecting the one
            // whose short name contains the level name (underscores stripped, case-insensitive).
            // 2 request parameters (SID + subfunction, no key payload) distinguishes RequestSeed
            // from SendKey services whose subfunctions overlap in the ISO range.
            let level_stripped = level.replace('_', "");
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

                    sid == service_ids::SECURITY_ACCESS
                        && matches!(sub_func, 1 | 3..=5 | 7..=41)
                        && service
                            .request()
                            .is_some_and(|r| r.params().is_some_and(|p| p.len() >= 2))
                        && service.diag_comm().is_some_and(|dc| {
                            dc.short_name().is_some_and(|n| {
                                contains_ignore_ascii_case(&n.replace('_', ""), &level_stripped)
                            })
                        })
                })
                .ok_or_else(|| {
                    DiagServiceError::NotFound(format!(
                        "No matching 'request seed' SecurityAccess service found for level \
                         '{level}'"
                    ))
                })?;

            let request_seed_service = request_seed_service.try_into()?;

            Ok(SecurityAccess::RequestSeed(request_seed_service))
        }
    }

    async fn get_send_key_param_name(
        &self,
        diag_service: &cda_interfaces::DiagComm,
    ) -> Result<String, DiagServiceError> {
        let mapped_service = self.lookup_diag_service(diag_service, None, None).await?;
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

    async fn session(&self) -> Result<String, DiagServiceError> {
        self.ecu_service_states
            .read()
            .await
            .get(&service_ids::SESSION_CONTROL)
            .cloned()
            .ok_or(DiagServiceError::InvalidState(
                "ECU session is none".to_string(),
            ))
    }

    fn default_session(&self) -> Result<String, DiagServiceError> {
        self.default_state(semantics::SESSION)
    }

    async fn security_access(&self) -> Result<String, DiagServiceError> {
        self.ecu_service_states
            .read()
            .await
            .get(&service_ids::SECURITY_ACCESS)
            .cloned()
            .ok_or(DiagServiceError::InvalidState(
                "ECU security is none".to_string(),
            ))
    }

    fn default_security_access(&self) -> Result<String, DiagServiceError> {
        self.default_state(semantics::SECURITY)
    }

    /// Returns all services in /configuration,
    /// i.e. 0x22 (`ReadDataByIdentifier`) and 0x2E (`WriteDataByIdentifier`)
    /// that are in the functional group varcoding.
    fn get_components_configurations_info(
        &self,
        security_plugin: &DynamicPlugin,
    ) -> Result<Vec<ComponentConfigurationsInfo>, DiagServiceError> {
        let diag_layers = self.get_diag_layers_from_variant_and_parent_refs();
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
            .ok_or_else(|| {
                DiagServiceError::NotFound(format!(
                    "Functional class '{}' for varcoding not found in any diagnostic layer",
                    self.database_naming_convention.functional_class_varcoding
                ))
            })?;

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
            .filter(|service| Self::is_service_visible(security_plugin, service))
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
                let Some(id_param_bytes) =
                    bytes.get(4usize.saturating_sub(sub_func_id_bit_len as usize / 8)..)
                else {
                    return;
                };
                // compile the first bytes of the raw uds payload
                let mut service_abstract_entry =
                    Vec::with_capacity(1usize.saturating_add(id_param_bytes.len()));
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

    /// Returns all `RoutineControl` (SID 0x31) services for the given ECU,
    /// with flags indicating whether Stop (0x02) and `RequestResults` (0x03)
    /// subfunctions are also defined.
    fn get_components_operations_info(
        &self,
        security_plugin: &DynamicPlugin,
    ) -> Vec<ComponentOperationsInfo> {
        let routine_control_services = self.get_services_from_variant_and_parent_refs(|service| {
            service
                .request_id()
                .is_some_and(|id| id == service_ids::ROUTINE_CONTROL)
                && Self::is_service_visible(security_plugin, service)
        });

        self.filter_and_transform_operations(routine_control_services)
    }

    /// Check which additional `RoutineControl` subfunctions are defined for a specific routine.
    /// Looks for services named `{service_name}_Stop` (0x02) and
    /// `{service_name}_RequestResults` (0x03).
    ///
    /// # Errors
    /// Returns `DiagServiceError::NotFound` if the Start (0x01) subfunction for the given
    /// service name is not found in the ECU description.
    fn get_routine_subfunctions(
        &self,
        service_name: &str,
        security_plugin: &DynamicPlugin,
    ) -> Result<RoutineSubfunctions, DiagServiceError> {
        let all_rc_services = self.get_services_from_variant_and_parent_refs(|service| {
            service
                .request_id()
                .is_some_and(|id| id == service_ids::ROUTINE_CONTROL)
                && Self::is_service_visible(security_plugin, service)
                && service.diag_comm().is_some_and(|dc| {
                    dc.short_name().is_some_and(|name| {
                        self.trim_routine_name(name)
                            .eq_ignore_ascii_case(service_name)
                    })
                })
        });

        if all_rc_services.is_empty() {
            return Err(DiagServiceError::NotFound(format!(
                "No RoutineControl service found for routine '{service_name}'"
            )));
        }

        Ok(Self::subfunction_flags_from_services(&all_rc_services))
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
                    .find(|st| (**st as u32) == sub_function_id)
                    .map(|st| (service, st))
            })
            .map(|(service, dtc_service_type)| {
                let scope = *dtc_service_type;

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
                            subfunction_id: None,
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
        let mapped_service = self.lookup_diag_service(service, None, None).await?;
        self.check_service_access(security_plugin, &mapped_service)
            .await
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
                    .and_then(|dl| dl.short_name())
                    .and_then(|name| {
                        let protocol_value = self.protocol.str();
                        let matches = match self.fg_protocol_position {
                            DiagnosticServiceAffixPosition::Prefix => {
                                util::starts_with_ignore_ascii_case(name, protocol_value)
                            }
                            DiagnosticServiceAffixPosition::Suffix => {
                                util::ends_with_ignore_ascii_case(name, protocol_value)
                            }
                        };
                        if matches {
                            Some(name.to_lowercase())
                        } else {
                            None
                        }
                    })
            })
            .collect::<Vec<_>>()
    }

    fn set_duplicating_ecu_names(&mut self, duplicate_ecus: HashSet<String>) {
        self.duplicating_ecu_names = Some(duplicate_ecus);
    }

    fn duplicating_ecu_names(&self) -> Option<&HashSet<String>> {
        self.duplicating_ecu_names.as_ref()
    }

    fn mark_as_duplicate(&mut self) {
        self.variant.state = EcuState::Duplicate;
        self.diag_database.unload();
    }

    fn mark_as_no_variant_detected(&mut self) {
        self.variant.state = EcuState::NoVariantDetected;
        self.diag_database.unload();
    }

    fn revision(&self) -> String {
        // We cannot remove the closure because there is no direct
        // access to the underlying flatbuf type, as it's not exported from the database
        // crate.
        #[allow(clippy::redundant_closure_for_method_calls)]
        self.diag_database
            .ecu_data()
            .ok()
            .and_then(|s| s.revision())
            .map_or_else(|| "0.0.0".to_owned(), ToOwned::to_owned)
    }

    fn convert_service_14_response(
        &self,
        diag_comm: DiagComm,
        response: ServicePayload,
    ) -> Result<DiagServiceResponseStruct, DiagServiceError> {
        let sid = util::try_extract_sid_from_payload(response.data.as_slice())?;
        let response_type = match sid {
            CLEAR_FAULT_MEM_POS_RESPONSE_SID => DiagServiceResponseType::Positive,
            service_ids::NEGATIVE_RESPONSE => DiagServiceResponseType::Negative,
            unknown => {
                return Err(DiagServiceError::UnexpectedResponse(Some(format!(
                    "received unexpected response with SID {unknown:04x}"
                ))));
            }
        };
        Ok(DiagServiceResponseStruct {
            service: diag_comm,
            data: response.data,
            mapped_data: None,
            response_type,
        })
    }
    fn get_request_parameter_metadata(
        &self,
        service_name: &str,
    ) -> Result<Vec<cda_interfaces::ServiceParameterMetadata>, DiagServiceError> {
        use cda_interfaces::ServiceParameterMetadata;

        use crate::diag_kernel::param_metadata::extract_request_param_type;

        let service = self.get_meta_data_service(service_name)?;
        let Some(request) = service.request() else {
            tracing::warn!("Service '{}' has no request definition", service_name);
            return Ok(Vec::new());
        };

        let Some(params) = request.params() else {
            return Ok(Vec::new());
        };

        tracing::debug!(
            "Service '{}' has {} request parameters",
            service_name,
            params.len()
        );

        let metadata = params
            .into_iter()
            .map(datatypes::Parameter)
            .filter_map(|param| {
                let name = param.short_name().map(ToOwned::to_owned).or_else(|| {
                    tracing::warn!(
                        "Service '{}' has a parameter with no short name, skipping",
                        service_name
                    );
                    None
                })?;

                let semantic = param.semantic().map(ToOwned::to_owned);
                let param_type = extract_request_param_type(&param, service_name, &name).ok()?;

                Some(ServiceParameterMetadata {
                    name,
                    semantic,
                    param_type,
                })
            })
            .collect();

        Ok(metadata)
    }

    /// Get parameter metadata for the POS-RESPONSE of a service.
    ///
    /// Returns one [`ResponseParameterInfo`] per parameter in the first positive
    /// response definition, including byte layout (position, size) and type
    /// information. This is the response-side counterpart of
    /// [`get_request_parameter_metadata`] (which returns request parameters).
    ///
    /// For MUX DOP parameters, the MUX cases are expanded: each case's inner
    /// structure parameters are returned with their names prefixed by the case
    /// short name
    fn get_response_parameter_metadata(
        &self,
        service_name: &str,
    ) -> Result<Vec<cda_interfaces::ResponseParameterInfo>, DiagServiceError> {
        use cda_interfaces::ResponseParameterInfo;

        use crate::diag_kernel::param_metadata::{
            byte_size_from_coded_const, byte_size_from_value_param, expand_mux_cases,
            extract_response_param_type,
        };

        let service = self.get_meta_data_service(service_name)?;
        let pos_responses = match service.pos_responses() {
            Some(r) if !r.is_empty() => r,
            _ => return Ok(Vec::new()),
        };

        let Some(params) = pos_responses.iter().next().and_then(|r| r.params()) else {
            return Ok(Vec::new());
        };

        let mut metadata: Vec<ResponseParameterInfo> = Vec::new();
        for raw_param in params {
            let param = datatypes::Parameter(raw_param);
            let Some(name) = param.short_name().map(ToOwned::to_owned) else {
                continue;
            };
            let semantic = param.semantic().map(ToOwned::to_owned);
            let param_type = extract_response_param_type(&param);

            let byte_size = match &param_type {
                cda_interfaces::ParameterTypeMetadata::Value { .. } => {
                    let (size, is_mux) = byte_size_from_value_param(&param);
                    if is_mux {
                        metadata.extend(expand_mux_cases(&param, param.byte_position()));
                        continue;
                    }
                    size
                }
                cda_interfaces::ParameterTypeMetadata::CodedConst { .. } => {
                    byte_size_from_coded_const(&param)
                }
                cda_interfaces::ParameterTypeMetadata::MatchingRequestParam { byte_length } => {
                    Some(*byte_length)
                }
                cda_interfaces::ParameterTypeMetadata::PhysConst { .. } => None,
            };
            metadata.push(ResponseParameterInfo {
                name,
                semantic,
                param_type,
                byte_position: param.byte_position(),
                bit_position: param.bit_position(),
                byte_size,
            });
        }

        tracing::debug!(
            "Service '{}' has {} positive-response parameters (MUX-expanded)",
            service_name,
            metadata.len()
        );
        Ok(metadata)
    }

    fn get_mux_cases_for_service(
        &self,
        service_name: &str,
    ) -> Result<Vec<cda_interfaces::MuxCaseInfo>, DiagServiceError> {
        use cda_interfaces::MuxCaseInfo;

        let service = self.get_meta_data_service(service_name)?;
        let Some(pos_responses) = service.pos_responses() else {
            return Ok(Vec::new());
        };

        tracing::debug!(
            "Service '{}' has {} positive responses",
            service_name,
            pos_responses.len()
        );

        let mux_cases: Vec<_> = pos_responses
            .into_iter()
            .filter_map(|pr| pr.params())
            .flatten()
            .filter_map(|param| param.specific_data_as_value()?.dop())
            .map(datatypes::DataOperation)
            .flat_map(|dop| -> Vec<MuxCaseInfo> {
                let Ok(datatypes::DataOperationVariant::Mux(mux_dop)) = dop.variant() else {
                    return Vec::new();
                };
                let Some(cases) = mux_dop.cases() else {
                    return Vec::new();
                };
                cases
                    .into_iter()
                    .map(|case| MuxCaseInfo {
                        short_name: case.short_name().unwrap_or_default().to_owned(),
                        long_name: case
                            .long_name()
                            .and_then(|ln| ln.value())
                            .map(ToOwned::to_owned),
                        lower_limit: case
                            .lower_limit()
                            .and_then(|ll| ll.value())
                            .map(ToOwned::to_owned),
                        upper_limit: case
                            .upper_limit()
                            .and_then(|ul| ul.value())
                            .map(ToOwned::to_owned),
                    })
                    .collect()
            })
            .collect();

        tracing::debug!(
            "Service '{}' has {} MUX cases",
            service_name,
            mux_cases.len()
        );
        Ok(mux_cases)
    }

    #[tracing::instrument(
        target = "convert_request_from_uds",
        skip(self, diag_service, payload),
        fields(
            ecu_name = self.ecu_name,
            service = diag_service.name,
            input = util::tracing::print_hex(&payload.data, 10),
            output = tracing::field::Empty,
            dlt_context = dlt_ctx!("CORE"),
        ),
        err
    )]
    async fn convert_request_from_uds(
        &self,
        diag_service: &cda_interfaces::DiagComm,
        payload: &ServicePayload,
        map_to_json: bool,
    ) -> Result<DiagServiceResponseStruct, DiagServiceError> {
        let mapped_service = self.lookup_diag_service(diag_service, None, None).await?;
        let request = mapped_service
            .request()
            .ok_or(DiagServiceError::RequestNotSupported(format!(
                "Service '{}' is not supported",
                diag_service.name
            )))?;

        let mut uds_payload = Payload::new(&payload.data);
        let mut data = HashMap::new();
        let mut mapping_errors = Vec::new();

        let params: Vec<datatypes::Parameter> = request
            .params()
            .map(|params| params.iter().map(datatypes::Parameter).collect())
            .unwrap_or_default();

        for param in params {
            let short_name = param.short_name().ok_or_else(|| {
                DiagServiceError::InvalidDatabase(
                    "Unable to find short name for request param".to_owned(),
                )
            })?;

            uds_payload.set_last_read_byte_pos(if param.has_byte_position() {
                param.byte_position() as usize
            } else {
                uds_payload.last_read_byte_pos()
            });
            match self.map_param_from_uds(
                &mapped_service,
                short_name,
                &mut uds_payload,
                &mut data,
                ParamContext::new(&param, 0),
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

        let raw_uds_payload = payload.data.clone();

        if !map_to_json {
            return Ok(DiagServiceResponseStruct {
                service: diag_service.clone(),
                data: raw_uds_payload,
                mapped_data: None,
                response_type: DiagServiceResponseType::Positive,
            });
        }

        let resp = create_diag_service_response(
            diag_service,
            data,
            datatypes::ResponseType::Positive,
            raw_uds_payload,
            mapping_errors,
        );

        tracing::Span::current().record("output", "RequestMapped");
        Ok(resp)
    }
}

impl<S: SecurityPlugin> EcuManager<S> {
    /// Trims affixes from a routine control service name to derive the base routine name.
    fn trim_routine_name(&self, name: &str) -> String {
        let name_trimmed = self
            .database_naming_convention
            .trim_service_name_affixes(service_ids::ROUTINE_CONTROL, name.to_owned());
        self.database_naming_convention
            .trim_short_name_affixes(&name_trimmed)
    }

    /// Derives `has_stop` / `has_request_results` flags by folding over an
    /// already-fetched slice of `DiagService`s.
    ///
    /// The caller is responsible for pre-filtering the slice to only the
    /// services that belong to the routine of interest. This helper does not
    /// perform any database traversal.
    fn subfunction_flags_from_services(
        services: &[datatypes::DiagService<'_>],
    ) -> RoutineSubfunctions {
        let mask = u32::from(cda_interfaces::DEFAULT_SUBFUNCTION_MASK);
        let mut has_stop = false;
        let mut has_request_results = false;
        for service in services {
            if let Some((sf, _)) = service.request_sub_function_id() {
                let masked = sf & mask;
                if masked == u32::from(subfunction_ids::routine::STOP) {
                    has_stop = true;
                } else if masked == u32::from(subfunction_ids::routine::REQUEST_RESULTS) {
                    has_request_results = true;
                }
            }
        }
        RoutineSubfunctions {
            has_stop,
            has_request_results,
        }
    }

    fn resolve_logical_address(
        database: &datatypes::DiagnosticDatabase,
        data_protocol: Option<&datatypes::Protocol<'_>>,
        config: &ComParamConfig<u16>,
        addr_type: datatypes::LogicalAddressType,
    ) -> u16 {
        if config.precedence == ComParamPrecedence::Config {
            tracing::debug!(
                param_name = %config.name,
                "Using config value (precedence = Config), DB lookup skipped"
            );
            return config.value;
        }

        match database.find_logical_address(addr_type, database, data_protocol.map(|v| &**v)) {
            Ok(address) => address,
            Err(e) => {
                tracing::error!(param_name = %config.name, "Failed to find logical address: {e}");
                config.value
            }
        }
    }

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
    #[tracing::instrument(skip_all,
        fields(
            dlt_context = dlt_ctx!("CORE"),
        )
    )]
    pub fn new(
        database: datatypes::DiagnosticDatabase,
        protocol: Protocol,
        com_params: &ComParams,
        database_naming_convention: DatabaseNamingConvention,
        type_: EcuManagerType,
        func_description_config: &cda_interfaces::FunctionalDescriptionConfig,
        fallback_to_base_variant: bool,
    ) -> Result<Self, DiagServiceError> {
        match type_ {
            EcuManagerType::Ecu => Self::new_ecu_description(
                database,
                protocol,
                com_params,
                database_naming_convention,
                type_,
                func_description_config,
                fallback_to_base_variant,
            ),
            EcuManagerType::FunctionalDescription => Self::new_functional_description(
                database,
                protocol,
                com_params,
                database_naming_convention,
                type_,
                func_description_config,
                fallback_to_base_variant,
            ),
        }
    }

    // allow keeping the function together as it makes sense structurally
    #[allow(clippy::too_many_lines)]
    fn new_ecu_description(
        database: datatypes::DiagnosticDatabase,
        protocol: Protocol,
        com_params: &ComParams,
        database_naming_convention: DatabaseNamingConvention,
        type_: EcuManagerType,
        func_description_config: &cda_interfaces::FunctionalDescriptionConfig,
        fallback_to_base_variant: bool,
    ) -> Result<Self, DiagServiceError> {
        let variant_detection =
            variant_detection::prepare_variant_detection(&database, &database_naming_convention)?;

        // Resolve the database protocol. When ignore_protocol is enabled and
        // the database contains zero protocol definitions, skip protocol-based
        // lookups entirely and fall back to config/default values for all
        // com-params.
        let data_protocol: Option<datatypes::Protocol<'_>> = {
            let protocols = database.protocols()?;
            if protocols.is_empty() && database.config().ignore_protocol {
                tracing::info!(
                    "No protocols in database with ignore_protocol enabled; all com-params will \
                     use config/default values"
                );
                None
            } else {
                Some(into_db_protocol(&database, &protocol)?)
            }
        };
        // Get reference to Protocol wrapper; Deref will convert to inner type where needed
        let data_protocol_ref = data_protocol.as_ref();

        let logical_gateway_address = Self::resolve_logical_address(
            &database,
            data_protocol_ref,
            &com_params.doip.logical_gateway_address,
            datatypes::LogicalAddressType::Gateway(
                com_params.doip.logical_gateway_address.name.clone(),
            ),
        );

        let logical_ecu_address = Self::resolve_logical_address(
            &database,
            data_protocol_ref,
            &com_params.doip.logical_ecu_address,
            datatypes::LogicalAddressType::Ecu(
                com_params.doip.logical_response_id_table_name.clone(),
                com_params.doip.logical_ecu_address.name.clone(),
            ),
        );

        let logical_functional_address = Self::resolve_logical_address(
            &database,
            data_protocol_ref,
            &com_params.doip.logical_functional_address,
            datatypes::LogicalAddressType::Functional(
                com_params.doip.logical_functional_address.name.clone(),
            ),
        );

        let nack_number_of_retries = database
            .find_com_param(data_protocol_ref, &com_params.doip.nack_number_of_retries)?
            .iter()
            .map(datatypes::map_nack_number_of_retries)
            .collect::<Result<HashMap<u8, u32>, DiagServiceError>>()?;

        let ecu_name = database
            .ecu_data()?
            .ecu_name()
            .map(ToOwned::to_owned)
            .ok_or_else(|| DiagServiceError::InvalidDatabase("ECU name not found".to_owned()))?;

        Ok(Self {
            db_cache: DbCache::default(),
            ecu_name,
            description_type: type_,
            database_naming_convention,
            tester_address: database
                .find_com_param(data_protocol_ref, &com_params.doip.logical_tester_address)?,
            logical_address: logical_ecu_address,
            logical_gateway_address,
            logical_functional_address,
            nack_number_of_retries,
            diagnostic_ack_timeout: database
                .find_com_param(data_protocol_ref, &com_params.doip.diagnostic_ack_timeout)?,
            retry_period: database
                .find_com_param(data_protocol_ref, &com_params.doip.retry_period)?,
            routing_activation_timeout: database.find_com_param(
                data_protocol_ref,
                &com_params.doip.routing_activation_timeout,
            )?,
            repeat_request_count_transmission: database.find_com_param(
                data_protocol_ref,
                &com_params.doip.repeat_request_count_transmission,
            )?,
            connection_timeout: database
                .find_com_param(data_protocol_ref, &com_params.doip.connection_timeout)?,
            connection_retry_delay: database
                .find_com_param(data_protocol_ref, &com_params.doip.connection_retry_delay)?,
            connection_retry_attempts: database.find_com_param(
                data_protocol_ref,
                &com_params.doip.connection_retry_attempts,
            )?,
            variant_detection,
            variant_index: None,
            variant: EcuVariant {
                name: None,
                is_base_variant: false,
                is_fallback: false,
                state: EcuState::NotTested,
                logical_address: logical_ecu_address,
            },
            fallback_to_base_variant,
            duplicating_ecu_names: None,
            protocol,
            fg_protocol_position: func_description_config.protocol_position.clone(),
            ecu_service_states: Arc::new(RwLock::default()),
            tester_present_retry_policy: database
                .find_com_param(
                    data_protocol_ref,
                    &com_params.uds.tester_present_retry_policy,
                )?
                .into(),
            tester_present_addr_mode: database
                .find_com_param(data_protocol_ref, &com_params.uds.tester_present_addr_mode)?,
            tester_present_response_expected: database
                .find_com_param(
                    data_protocol_ref,
                    &com_params.uds.tester_present_response_expected,
                )?
                .into(),
            tester_present_send_type: database
                .find_com_param(data_protocol_ref, &com_params.uds.tester_present_send_type)?,
            tester_present_message: database
                .find_com_param(data_protocol_ref, &com_params.uds.tester_present_message)?,
            tester_present_exp_pos_resp: database.find_com_param(
                data_protocol_ref,
                &com_params.uds.tester_present_exp_pos_resp,
            )?,
            tester_present_exp_neg_resp: database.find_com_param(
                data_protocol_ref,
                &com_params.uds.tester_present_exp_neg_resp,
            )?,
            tester_present_time: database
                .find_com_param(data_protocol_ref, &com_params.uds.tester_present_time)?,
            repeat_req_count_app: database
                .find_com_param(data_protocol_ref, &com_params.uds.repeat_req_count_app)?,
            rc_21_retry_policy: database
                .find_com_param(data_protocol_ref, &com_params.uds.rc_21_retry_policy)?,
            rc_21_completion_timeout: database
                .find_com_param(data_protocol_ref, &com_params.uds.rc_21_completion_timeout)?,
            rc_21_repeat_request_time: database
                .find_com_param(data_protocol_ref, &com_params.uds.rc_21_repeat_request_time)?,
            rc_78_retry_policy: database
                .find_com_param(data_protocol_ref, &com_params.uds.rc_78_retry_policy)?,
            rc_78_completion_timeout: database
                .find_com_param(data_protocol_ref, &com_params.uds.rc_78_completion_timeout)?,
            rc_78_timeout: database
                .find_com_param(data_protocol_ref, &com_params.uds.rc_78_timeout)?,
            rc_94_retry_policy: database
                .find_com_param(data_protocol_ref, &com_params.uds.rc_94_retry_policy)?,
            rc_94_completion_timeout: database
                .find_com_param(data_protocol_ref, &com_params.uds.rc_94_completion_timeout)?,
            rc_94_repeat_request_time: database
                .find_com_param(data_protocol_ref, &com_params.uds.rc_94_repeat_request_time)?,
            timeout_default: database
                .find_com_param(data_protocol_ref, &com_params.uds.timeout_default)?,
            security_plugin_phantom: std::marker::PhantomData::<S>,
            diag_database: database, // note: initialize this field last as it moves database
        })
    }

    fn new_functional_description(
        database: datatypes::DiagnosticDatabase,
        protocol: Protocol,
        com_params: &ComParams,
        database_naming_convention: DatabaseNamingConvention,
        type_: EcuManagerType,
        func_description_config: &cda_interfaces::FunctionalDescriptionConfig,
        fallback_to_base_variant: bool,
    ) -> Result<Self, DiagServiceError> {
        // Functional group description: use defaults for all com params
        let logical_ecu_address = com_params.doip.logical_ecu_address.value;
        let nack_number_of_retries = com_params
            .doip
            .nack_number_of_retries
            .value
            .iter()
            .map(datatypes::map_nack_number_of_retries)
            .collect::<Result<HashMap<u8, u32>, DiagServiceError>>()?;

        let ecu_name = database
            .ecu_data()?
            .ecu_name()
            .map(ToOwned::to_owned)
            .ok_or_else(|| DiagServiceError::InvalidDatabase("ECU name not found".to_owned()))?;

        Ok(Self {
            diag_database: database,
            db_cache: DbCache::default(),
            ecu_name,
            description_type: type_,
            database_naming_convention,
            tester_address: com_params.doip.logical_tester_address.value,
            logical_address: logical_ecu_address,
            logical_gateway_address: com_params.doip.logical_gateway_address.value,
            logical_functional_address: com_params.doip.logical_functional_address.value,
            nack_number_of_retries,
            diagnostic_ack_timeout: com_params.doip.diagnostic_ack_timeout.value,
            retry_period: com_params.doip.retry_period.value,
            routing_activation_timeout: com_params.doip.routing_activation_timeout.value,
            repeat_request_count_transmission: com_params
                .doip
                .repeat_request_count_transmission
                .value,
            connection_timeout: com_params.doip.connection_timeout.value,
            connection_retry_delay: com_params.doip.connection_retry_delay.value,
            connection_retry_attempts: com_params.doip.connection_retry_attempts.value,
            variant_detection: VariantDetection {
                diag_service_requests: HashMap::new(),
            },
            variant_index: None,
            variant: EcuVariant {
                name: None,
                is_base_variant: false,
                is_fallback: false,
                state: EcuState::NotTested,
                logical_address: logical_ecu_address,
            },
            fallback_to_base_variant,
            duplicating_ecu_names: None,
            protocol,
            fg_protocol_position: func_description_config.protocol_position.clone(),
            ecu_service_states: Arc::new(RwLock::default()),
            tester_present_retry_policy: com_params
                .uds
                .tester_present_retry_policy
                .value
                .clone()
                .into(),
            tester_present_addr_mode: com_params.uds.tester_present_addr_mode.value.clone(),
            tester_present_response_expected: com_params
                .uds
                .tester_present_response_expected
                .value
                .clone()
                .into(),
            tester_present_send_type: com_params.uds.tester_present_send_type.value.clone(),
            tester_present_message: com_params.uds.tester_present_message.value.clone(),
            tester_present_exp_pos_resp: com_params.uds.tester_present_exp_pos_resp.value.clone(),
            tester_present_exp_neg_resp: com_params.uds.tester_present_exp_neg_resp.value.clone(),
            tester_present_time: com_params.uds.tester_present_time.value,
            repeat_req_count_app: com_params.uds.repeat_req_count_app.value,
            rc_21_retry_policy: com_params.uds.rc_21_retry_policy.value.clone(),
            rc_21_completion_timeout: com_params.uds.rc_21_completion_timeout.value,
            rc_21_repeat_request_time: com_params.uds.rc_21_repeat_request_time.value,
            rc_78_retry_policy: com_params.uds.rc_78_retry_policy.value.clone(),
            rc_78_completion_timeout: com_params.uds.rc_78_completion_timeout.value,
            rc_78_timeout: com_params.uds.rc_78_timeout.value,
            rc_94_retry_policy: com_params.uds.rc_94_retry_policy.value.clone(),
            rc_94_completion_timeout: com_params.uds.rc_94_completion_timeout.value,
            rc_94_repeat_request_time: com_params.uds.rc_94_repeat_request_time.value,
            timeout_default: com_params.uds.timeout_default.value,
            security_plugin_phantom: std::marker::PhantomData::<S>,
        })
    }

    /// Set default states for diagnostic services if not already set.
    /// This prevents overriding the actual session/security state during re-detection.
    async fn set_default_states(&self) -> Result<(), DiagServiceError> {
        // todo read this from the variant detection instead of assuming default, see #110
        // Only set default state if not already set - otherwise we'd override
        // the actual session/security state during re-detection.
        // This prevents an issue if the variant detection is running _after_
        // the session has been changed.
        // For example when switching to 'extended' immediately after the service
        // signals 'ready'

        let mut states = self.ecu_service_states.write().await;
        states
            .entry(service_ids::SESSION_CONTROL)
            .or_insert(self.default_state(semantics::SESSION)?);
        states
            .entry(service_ids::SECURITY_ACCESS)
            .or_insert(self.default_state(semantics::SECURITY)?);
        states
            .entry(service_ids::CONTROL_DTC_SETTING)
            .or_insert_with(|| "on".to_owned());
        states
            .entry(service_ids::COMMUNICATION_CONTROL)
            .or_insert_with(|| "enablerxandenabletx".to_owned());
        Ok(())
    }

    pub(crate) fn variant(&self) -> Option<datatypes::Variant<'_>> {
        let idx = self.variant_index?;
        let variants = self.diag_database.ecu_data().ok()?.variants()?;
        Some(variants.get(idx).into())
    }

    fn diag_comm_to_component_data_info(
        &self,
        diag_comm: &datatypes::DiagComm<'_>,
    ) -> ComponentDataInfo {
        ComponentDataInfo {
            category: diag_comm.semantic().unwrap_or_default().to_owned(),
            id: diag_comm.short_name().map_or(<_>::default(), |s| {
                self.database_naming_convention.trim_short_name_affixes(s)
            }),
            name: diag_comm
                .long_name()
                .and_then(|ln| ln.value())
                .map_or(<_>::default(), |v| {
                    self.database_naming_convention.trim_long_name_affixes(v)
                }),
        }
    }

    #[tracing::instrument(skip_all,
        fields(
            dlt_context = dlt_ctx!("CORE"),
        )
    )]
    fn map_param_from_uds(
        &self,
        mapped_service: &datatypes::DiagService,
        param_name: &str,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        param_ctx: ParamContext<'_>,
    ) -> Result<(), DiagServiceError> {
        match param_ctx.parameter.param_type()? {
            datatypes::ParamType::CodedConst => {
                Self::map_param_coded_const_from_uds(param_name, uds_payload, data, param_ctx)?;
            }
            datatypes::ParamType::MatchingRequestParam => {
                self.map_param_matching_request_from_uds(
                    mapped_service,
                    param_name,
                    uds_payload,
                    data,
                    param_ctx,
                )?;
            }
            datatypes::ParamType::Value => {
                self.map_param_value_from_uds(mapped_service, uds_payload, data, param_ctx)?;
            }
            datatypes::ParamType::Reserved => {
                Self::map_param_reserved_from_uds(param_name, uds_payload, data, param_ctx)?;
            }
            datatypes::ParamType::TableEntry => {
                tracing::error!("TableStructParam not implemented.");
            }
            datatypes::ParamType::Dynamic => {
                tracing::error!("Dynamic ParamType not implemented.");
            }
            datatypes::ParamType::LengthKey => {
                self.map_param_length_key_from_uds(mapped_service, uds_payload, data, param_ctx)?;
            }
            datatypes::ParamType::NrcConst => {
                tracing::error!("NrcConst ParamType not implemented.");
            }
            datatypes::ParamType::PhysConst => {
                self.map_param_phys_const_from_uds(
                    mapped_service,
                    param_name,
                    uds_payload,
                    data,
                    param_ctx,
                )?;
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
        param_name: &str,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        param_ctx: ParamContext<'_>,
    ) -> Result<(), DiagServiceError> {
        let r = param_ctx.parameter.specific_data_as_reserved().ok_or(
            DiagServiceError::InvalidDatabase("Expected Reserved specific data".to_owned()),
        )?;

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
            param_ctx.abs_byte_pos(),
            param_ctx.parameter.bit_position() as usize,
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
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        param_ctx: ParamContext<'_>,
    ) -> Result<(), DiagServiceError> {
        let v = param_ctx.parameter.specific_data_as_value().ok_or(
            DiagServiceError::InvalidDatabase("Expected Value specific data".to_owned()),
        )?;

        let dop =
            v.dop()
                .map(datatypes::DataOperation)
                .ok_or(DiagServiceError::InvalidDatabase(
                    "Value DoP is None".to_owned(),
                ))?;
        self.map_dop_from_uds(mapped_service, &dop, uds_payload, data, param_ctx)?;
        Ok(())
    }

    fn map_param_length_key_from_uds(
        &self,
        mapped_service: &datatypes::DiagService,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        param_ctx: ParamContext<'_>,
    ) -> Result<(), DiagServiceError> {
        let length_key = param_ctx
            .parameter
            .specific_data_as_length_key_ref()
            .ok_or(DiagServiceError::InvalidDatabase(
                "Expected LengthKeyRef specific data".to_owned(),
            ))?;

        let dop = length_key.dop().map(datatypes::DataOperation).ok_or(
            DiagServiceError::InvalidDatabase("LengthKey DoP is None".to_owned()),
        )?;

        self.map_dop_from_uds(mapped_service, &dop, uds_payload, data, param_ctx)
    }

    fn map_param_matching_request_from_uds(
        &self,
        mapped_service: &datatypes::DiagService,
        param_name: &str,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        param_ctx: ParamContext<'_>,
    ) -> Result<(), DiagServiceError> {
        let matching_req_param = param_ctx
            .parameter
            .specific_data_as_matching_request_param()
            .ok_or(DiagServiceError::InvalidDatabase(
                "Expected MatchingRequestParam specific data".to_owned(),
            ))?;

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
                    param_ctx.parameter.short_name().unwrap_or_default()
                ))
            })?;

        let matching_req_param_byte_pos = u32::try_from(matching_req_param.request_byte_pos())
            .map_err(|e| {
                DiagServiceError::InvalidDatabase(format!(
                    "Matching request param byte position conversion error: {e}",
                ))
            })?;

        let pop = matching_req_param_byte_pos < param_ctx.parameter.byte_position();
        if pop {
            uds_payload.push_slice(param_ctx.abs_byte_pos(), uds_payload.len())?;
        }

        self.map_param_from_uds(
            mapped_service,
            param_name,
            uds_payload,
            data,
            ParamContext::new(&matching_request_param, 0),
        )?;

        if pop {
            uds_payload.pop_slice()?;
        }
        Ok(())
    }

    fn map_param_coded_const_from_uds(
        param_name: &str,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        param_ctx: ParamContext<'_>,
    ) -> Result<(), DiagServiceError> {
        let c = param_ctx.parameter.specific_data_as_coded_const().ok_or(
            DiagServiceError::InvalidDatabase("Expected CodedConst specific data".to_owned()),
        )?;

        let diag_type: datatypes::DiagCodedType = c
            .diag_coded_type()
            .map(TryInto::try_into)
            .transpose()?
            .ok_or(DiagServiceError::InvalidDatabase(
                "Expected DiagCodedType in CodedConst specific data".to_owned(),
            ))?;

        let value = operations::extract_diag_data_container(
            param_ctx.parameter.short_name(),
            param_ctx.abs_byte_pos(),
            param_ctx.parameter.bit_position() as usize,
            uds_payload,
            &diag_type,
            None,
        )?;

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
        let const_json_value = str_to_json_value(const_value, diag_type.base_datatype())?;
        let expected =
            operations::json_value_to_uds_data(&diag_type, None, None, &const_json_value)
                .inspect_err(|e| {
                    tracing::error!(
                        error = ?e,
                        "Failed to convert CodedConst coded value to UDS data for parameter '{}'",
                        param_ctx.parameter.short_name().unwrap_or_default()
                    );
                })?
                .into_iter()
                .collect::<Vec<_>>();
        let expected = expected
            .get(expected.len().saturating_sub(value.data.len())..)
            .ok_or(DiagServiceError::BadPayload(
                "Expected value slice out of bounds".to_owned(),
            ))?;
        if value.data != expected {
            return Err(DiagServiceError::BadPayload(format!(
                "{}: Expected {:?}, got {:?}",
                param_ctx.parameter.short_name().unwrap_or_default(),
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

    fn map_param_phys_const_from_uds(
        &self,
        mapped_service: &datatypes::DiagService,
        param_name: &str,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        param_ctx: ParamContext<'_>,
    ) -> Result<(), DiagServiceError> {
        let p = param_ctx.parameter.specific_data_as_phys_const().ok_or(
            DiagServiceError::InvalidDatabase("Expected PhysConst specific data".to_owned()),
        )?;

        let dop =
            p.dop()
                .map(datatypes::DataOperation)
                .ok_or(DiagServiceError::InvalidDatabase(
                    "PhysConst has no DOP".to_owned(),
                ))?;

        // Handle different DOP variants - PhysConst can have Normal or Structure DOPs
        match dop.variant()? {
            datatypes::DataOperationVariant::Normal(normal_dop) => {
                let diag_type = normal_dop.diag_coded_type()?;
                let value = operations::extract_diag_data_container(
                    param_ctx.parameter.short_name(),
                    param_ctx.abs_byte_pos(),
                    param_ctx.parameter.bit_position() as usize,
                    uds_payload,
                    &diag_type,
                    None,
                )?;

                let value = match value {
                    DiagDataTypeContainer::RawContainer(raw) => raw,
                    DiagDataTypeContainer::Struct(_) => {
                        return Err(DiagServiceError::ParameterConversionError(
                            "Struct not supported for Normal DOP PhysConst".to_owned(),
                        ));
                    }
                    DiagDataTypeContainer::RepeatingStruct(_) => {
                        return Err(DiagServiceError::ParameterConversionError(
                            "RepeatingStruct not supported for Normal DOP PhysConst".to_owned(),
                        ));
                    }
                    DiagDataTypeContainer::DtcStruct(_) => {
                        return Err(DiagServiceError::ParameterConversionError(
                            "DtcStruct not supported for Normal DOP PhysConst".to_owned(),
                        ));
                    }
                };

                data.insert(
                    param_name.to_owned(),
                    DiagDataTypeContainer::RawContainer(value),
                );
            }
            // Structure DOP - delegate to the full DOP handler which handles nested params
            datatypes::DataOperationVariant::Structure(_)
            | datatypes::DataOperationVariant::EndOfPdu(_)
            | datatypes::DataOperationVariant::StaticField(_)
            | datatypes::DataOperationVariant::Mux(_)
            | datatypes::DataOperationVariant::DynamicLengthField(_) => {
                self.map_dop_from_uds(mapped_service, &dop, uds_payload, data, param_ctx)?;
            }
            _ => {
                return Err(DiagServiceError::InvalidDatabase(format!(
                    "PhysConst has unsupported DOP variant: {:?}",
                    dop.specific_data_type().variant_name().unwrap_or("Unknown")
                )));
            }
        }

        Ok(())
    }

    fn map_phys_const_param_to_uds(
        &self,
        param: &datatypes::Parameter,
        uds_payload_data: &mut Vec<u8>,
        param_data: Option<&serde_json::Value>,
    ) -> Result<(), DiagServiceError> {
        let p = param
            .specific_data_as_phys_const()
            .ok_or(DiagServiceError::InvalidDatabase(
                "Expected PhysConst specific data".to_owned(),
            ))?;

        let dop =
            p.dop()
                .map(datatypes::DataOperation)
                .ok_or(DiagServiceError::InvalidDatabase(
                    "PhysConst has no DOP".to_owned(),
                ))?;

        let dop_variant = dop.variant()?;

        let value = if let Some(value) = param_data {
            value
        } else if let datatypes::DataOperationVariant::Normal(normal_dop) = dop_variant {
            let diag_type = normal_dop.diag_coded_type()?;
            &p.phys_constant_value()
                .ok_or(DiagServiceError::InvalidRequest(format!(
                    "Required parameter '{}' missing",
                    param.short_name().unwrap_or_default()
                )))
                .and_then(|value| str_to_json_value(value, diag_type.base_datatype()))?
        } else {
            return Err(DiagServiceError::InvalidRequest(format!(
                "Required parameter '{}' missing",
                param.short_name().unwrap_or_default()
            )));
        };

        // Handle different DOP variants - PhysConst can have Normal or Structure DOPs
        match dop.variant()? {
            datatypes::DataOperationVariant::Normal(normal_dop) => {
                let diag_type = normal_dop.diag_coded_type()?;
                let uds_data = json_value_to_uds_data(
                    &diag_type,
                    normal_dop.compu_method().map(Into::into),
                    normal_dop.physical_type().map(Into::into),
                    value,
                )?;
                diag_type.encode(
                    uds_data,
                    uds_payload_data,
                    param.byte_position() as usize,
                    param.bit_position() as usize,
                )?;
            }
            datatypes::DataOperationVariant::Structure(structure_dop) => {
                self.map_struct_to_uds(
                    &structure_dop,
                    param.byte_position() as usize,
                    value,
                    uds_payload_data,
                )?;
            }
            datatypes::DataOperationVariant::Mux(mux_dop) => {
                self.map_mux_to_uds(&mux_dop, value, uds_payload_data)?;
            }
            _ => {
                return Err(DiagServiceError::InvalidDatabase(format!(
                    "PhysConst has unsupported DOP variant: {:?}",
                    dop.specific_data_type().variant_name().unwrap_or("Unknown")
                )));
            }
        }

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
                    .or(Some(&serde_json::Value::from(serde_json::Number::from(0))))
                    .map(|selector| -> Result<_, DiagServiceError> {
                        let switch_key_value = json_value_to_uds_data(
                            &switch_key_diag_type,
                            normal_dop.compu_method().map(Into::into),
                            normal_dop.physical_type().map(Into::into),
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
                            default_case
                                .short_name()
                                .zip(default_case.structure().and_then(|s| {
                                    s.specific_data_as_structure().map(|s| Some(s.into()))
                                }))
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

                self.map_param_to_uds(&param, value.get(short_name), payload, struct_byte_pos)
            })
    }

    fn process_parameter_map(
        &self,
        mapped_params: &[datatypes::Parameter],
        json_values: &HashMap<String, serde_json::Value>,
        uds: &mut Vec<u8>,
    ) -> Result<(), DiagServiceError> {
        for param in mapped_params {
            // When BYTE-POSITION is omitted (ISO 22901-1 §7.4.8) the
            // parameter follows a variable-length PARAM-LENGTH-INFO field
            // and must be appended at the current end of the payload.
            let effective_byte_pos = if param.has_byte_position() {
                param.byte_position() as usize
            } else {
                uds.len()
            };

            if uds.len() < effective_byte_pos {
                uds.extend(vec![0x0; effective_byte_pos.saturating_sub(uds.len())]);
            }
            let short_name = param.short_name().ok_or_else(|| {
                DiagServiceError::InvalidDatabase(format!(
                    "Unable to find short name for param: {}",
                    param.short_name().unwrap_or_default()
                ))
            })?;

            // When BYTE-POSITION is absent, pass effective_byte_pos as
            // parent_byte_pos so that the inner encode writes at the
            // correct absolute position (param.byte_position() returns 0).
            let parent_byte_pos = if param.has_byte_position() {
                0
            } else {
                effective_byte_pos
            };
            self.map_param_to_uds(param, json_values.get(short_name), uds, parent_byte_pos)?;
        }
        Ok(())
    }

    fn map_param_to_uds(
        &self,
        param: &datatypes::Parameter,
        value: Option<&serde_json::Value>,
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
            datatypes::ParamType::LengthKey => {
                Self::map_param_length_key_to_uds(param, value, payload, parent_byte_pos)
            }
            datatypes::ParamType::NrcConst => Err(DiagServiceError::ParameterConversionError(
                "Mapping NrcConst DoP to UDS payload not implemented".to_owned(),
            )),
            datatypes::ParamType::PhysConst => {
                self.map_phys_const_param_to_uds(param, payload, value)
            }
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

    fn map_param_length_key_to_uds(
        param: &datatypes::Parameter,
        value: Option<&serde_json::Value>,
        payload: &mut Vec<u8>,
        parent_byte_pos: usize,
    ) -> Result<(), DiagServiceError> {
        let length_key =
            param
                .specific_data_as_length_key_ref()
                .ok_or(DiagServiceError::InvalidDatabase(
                    "Expected LengthKeyRef specific data".to_owned(),
                ))?;

        let dop = length_key.dop().map(datatypes::DataOperation).ok_or(
            DiagServiceError::InvalidDatabase("LengthKey DoP is None".to_owned()),
        )?;

        let value = value.ok_or_else(|| {
            DiagServiceError::InvalidRequest(format!(
                "Required LengthKey parameter '{}' missing",
                param.short_name().unwrap_or_default()
            ))
        })?;

        match dop.variant()? {
            datatypes::DataOperationVariant::Normal(normal_dop) => {
                let diag_type = normal_dop.diag_coded_type()?;
                let uds_data = json_value_to_uds_data(
                    &diag_type,
                    normal_dop.compu_method().map(Into::into),
                    normal_dop.physical_type().map(Into::into),
                    value,
                )?;
                diag_type.encode(
                    uds_data,
                    payload,
                    parent_byte_pos.saturating_add(param.byte_position() as usize),
                    param.bit_position() as usize,
                )?;
                Ok(())
            }
            _ => Err(DiagServiceError::ParameterConversionError(format!(
                "Unsupported DOP variant for LengthKey parameter '{}'",
                param.short_name().unwrap_or_default()
            ))),
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
        value: Option<&serde_json::Value>,
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

        let dop_variant = dop.variant()?;

        let value = if let Some(value) = value {
            value
        } else if let datatypes::DataOperationVariant::Normal(normal_dop) = dop_variant {
            let diag_type = normal_dop.diag_coded_type()?;
            &value_data
                .physical_default_value()
                .ok_or(DiagServiceError::InvalidRequest(format!(
                    "Required parameter '{}' missing",
                    param.short_name().unwrap_or_default()
                )))
                .and_then(|value| str_to_json_value(value, diag_type.base_datatype()))?
        } else {
            return Err(DiagServiceError::InvalidRequest(format!(
                "Required parameter '{}' missing",
                param.short_name().unwrap_or_default()
            )));
        };

        match dop.variant()? {
            datatypes::DataOperationVariant::Normal(normal_dop) => {
                let diag_type = normal_dop.diag_coded_type()?;
                let uds_data = json_value_to_uds_data(
                    &diag_type,
                    normal_dop.compu_method().map(Into::into),
                    normal_dop.physical_type().map(Into::into),
                    value,
                )?;
                diag_type.encode(
                    uds_data,
                    payload,
                    parent_byte_pos.saturating_add(param.byte_position() as usize),
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
                        (param.byte_position() as usize).saturating_add(parent_byte_pos),
                        v,
                        payload,
                    )?;
                }
                Ok(())
            }
            datatypes::DataOperationVariant::Structure(structure_dop) => self.map_struct_to_uds(
                &structure_dop,
                (param.byte_position() as usize).saturating_add(parent_byte_pos),
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
        outer_context: &MappedDiagServiceResponsePayload,
    ) -> Result<HashMap<String, DiagDataTypeContainer>, DiagServiceError> {
        let mut data = HashMap::new();
        let Some(params) = structure.params() else {
            return Ok(data);
        };

        for param in params {
            let param = datatypes::Parameter(param);
            let short_name = param.short_name().ok_or_else(|| {
                DiagServiceError::InvalidDatabase("Unable to find short name for param".to_owned())
            })?;
            self.map_param_from_uds(
                mapped_service,
                short_name,
                uds_payload,
                &mut data,
                ParamContext::new(&param, 0).with_outer_context(Some(outer_context)),
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
        outer_context: &MappedDiagServiceResponsePayload,
    ) -> Result<(), DiagServiceError> {
        nested_structs.push(self.map_struct_from_uds(
            structure,
            mapped_service,
            uds_payload,
            outer_context,
        )?);
        Ok(())
    }

    #[tracing::instrument(skip_all,
        fields(
            dlt_context = dlt_ctx!("CORE"),
        )
    )]
    fn map_dop_from_uds(
        &self,
        mapped_service: &datatypes::DiagService,
        dop: &datatypes::DataOperation,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        param_ctx: ParamContext<'_>,
    ) -> Result<(), DiagServiceError> {
        let short_name = param_ctx
            .parameter
            .short_name()
            .ok_or_else(|| {
                DiagServiceError::InvalidDatabase(
                    "Unable to find short name for param in Strings".to_string(),
                )
            })?
            .to_owned();

        match dop.variant()? {
            datatypes::DataOperationVariant::Normal(normal_dop) => {
                let diag_coded_type = normal_dop.diag_coded_type()?;
                if let Some(length_key_name) = diag_coded_type.length_key_name() {
                    Self::map_param_length_info_dop_from_uds(
                        uds_payload,
                        data,
                        short_name,
                        &normal_dop,
                        length_key_name,
                        param_ctx,
                    )?;
                } else {
                    Self::map_normal_dop_from_uds(
                        uds_payload,
                        data,
                        short_name,
                        &normal_dop,
                        param_ctx,
                    )?;
                }
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
                self.map_structure_dop_from_uds(
                    mapped_service,
                    uds_payload,
                    data,
                    &short_name,
                    &structure_dop,
                    param_ctx,
                )?;
            }
            datatypes::DataOperationVariant::Dtc(dtc_dop) => {
                Self::map_dtc_dop_from_uds(&short_name, uds_payload, data, &dtc_dop, param_ctx)?;
            }
            datatypes::DataOperationVariant::EnvDataDesc(env_data_desc_dop) => {
                let item = self.map_env_data_desc_item_from_uds(
                    mapped_service,
                    uds_payload,
                    param_ctx.outer_context.unwrap_or(&*data),
                    &env_data_desc_dop,
                    param_ctx.abs_byte_pos(),
                )?;
                data.extend(item);
            }
            datatypes::DataOperationVariant::EnvData(env_data_dop) => {
                if let Some(params) = env_data_dop.params() {
                    for param in params {
                        let param = datatypes::Parameter(param);
                        let name = param.short_name().ok_or_else(|| {
                            DiagServiceError::InvalidDatabase(
                                "EnvData param missing short_name".to_owned(),
                            )
                        })?;
                        self.map_param_from_uds(
                            mapped_service,
                            name,
                            uds_payload,
                            data,
                            ParamContext::new(&param, param_ctx.base_offset)
                                .with_outer_context(param_ctx.outer_context),
                        )?;
                    }
                }
            }
            datatypes::DataOperationVariant::StaticField(static_field_dop) => {
                self.map_static_field_dop_from_uds(
                    mapped_service,
                    uds_payload,
                    data,
                    short_name,
                    &static_field_dop,
                    param_ctx,
                )?;
            }
            datatypes::DataOperationVariant::Mux(mux_dop) => {
                self.map_mux_dop_from_uds(
                    mapped_service,
                    uds_payload,
                    data,
                    short_name,
                    &mux_dop,
                    param_ctx,
                )?;
            }
            datatypes::DataOperationVariant::DynamicLengthField(dynamic_length_field_dop) => {
                self.map_dynamic_length_field_from_uds(
                    mapped_service,
                    uds_payload,
                    data,
                    short_name,
                    &dynamic_length_field_dop,
                    param_ctx,
                )?;
            }
        }

        Ok(())
    }

    fn map_param_length_info_dop_from_uds(
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        short_name: String,
        normal_dop: &datatypes::NormalDop,
        length_key_name: &str,
        param_ctx: ParamContext<'_>,
    ) -> Result<(), DiagServiceError> {
        let byte_count = match data.get(length_key_name) {
            Some(DiagDataTypeContainer::RawContainer(raw)) => {
                let phys_val = operations::uds_data_to_serializable(
                    raw.data_type,
                    raw.compu_method.as_ref(),
                    false,
                    &raw.data,
                )?;
                match phys_val {
                    DiagDataValue::UInt32(n) => n as usize,
                    DiagDataValue::Int32(n) => usize::try_from(n).unwrap_or_else(|_| {
                        tracing::warn!("LENGTH-KEY resolved to negative value {n}, treating as 0");
                        0
                    }),
                    _ => {
                        return Err(DiagServiceError::ParameterConversionError(format!(
                            "LENGTH-KEY '{length_key_name}' resolved to unsupported type: \
                             {phys_val:?}"
                        )));
                    }
                }
            }
            None => {
                return Err(DiagServiceError::InvalidDatabase(format!(
                    "LENGTH-KEY '{length_key_name}' not yet decoded when processing '{short_name}'"
                )));
            }
            _ => {
                return Err(DiagServiceError::InvalidDatabase(format!(
                    "LENGTH-KEY '{length_key_name}' has unexpected container type"
                )));
            }
        };

        let diag_coded_type = normal_dop.diag_coded_type()?;
        let compu_method: Option<datatypes::CompuMethod> =
            normal_dop.compu_method().map(Into::into);
        let data_type = diag_coded_type.base_datatype();

        if byte_count == 0 {
            tracing::debug!(
                "PARAM-LENGTH-INFO-TYPE resolved byte_count=0; inserting empty value (possible \
                 database anomaly)"
            );
            data.insert(
                short_name,
                DiagDataTypeContainer::RawContainer(DiagDataTypeContainerRaw {
                    data: vec![],
                    bit_len: 0,
                    data_type,
                    compu_method,
                }),
            );
            return Ok(());
        }

        let byte_pos = if param_ctx.parameter.has_byte_position() {
            param_ctx.abs_byte_pos()
        } else {
            uds_payload.last_read_byte_pos()
        };
        let uds_bytes = uds_payload.data()?;
        let (decoded_bytes, bit_len) =
            diag_coded_type.decode_with_runtime_byte_length(uds_bytes, byte_pos, byte_count)?;

        uds_payload.set_last_read_byte_pos(byte_pos.saturating_add(byte_count));

        data.insert(
            short_name,
            DiagDataTypeContainer::RawContainer(DiagDataTypeContainerRaw {
                data: decoded_bytes,
                bit_len,
                data_type,
                compu_method,
            }),
        );
        Ok(())
    }

    #[tracing::instrument(skip_all,
        fields(
            dlt_context = dlt_ctx!("CORE"),
        )
    )]
    fn map_dynamic_length_field_from_uds(
        &self,
        mapped_service: &datatypes::DiagService,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        short_name: String,
        dynamic_length_field_dop: &datatypes::DynamicLengthDop,
        param_ctx: ParamContext<'_>,
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

        let param_abs_byte_pos = if param_ctx.parameter.has_byte_position() {
            param_ctx.abs_byte_pos()
        } else {
            param_ctx.base_offset
        };
        let (num_items_data, _count_field_bit_len) = num_items_diag_type.decode(
            uds_payload
                .data()?
                .get(param_abs_byte_pos..)
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

        let repeated_dop = datatypes::DopField(dynamic_length_field_dop.field().ok_or(
            DiagServiceError::InvalidDatabase("DynamicLengthField field is None".to_owned()),
        )?);
        let num_items: u32 = num_items_diag_val.try_into()?;
        let num_items_byte_pos = determine_num_items.byte_position() as usize;
        uds_payload.set_last_read_byte_pos(num_items_byte_pos.saturating_add(num_items_data.len()));

        let mut repeated_data = Vec::new();

        let items_abs_start =
            param_abs_byte_pos.saturating_add(dynamic_length_field_dop.offset() as usize);

        tracing::debug!(
            num_items,
            items_abs_start,
            payload_len = uds_payload.len(),
            count_bytes = ?num_items_data,
            "DynamicLengthField items loop start"
        );

        uds_payload.push_slice(items_abs_start, uds_payload.len())?;

        let mut start = 0usize;

        for _ in 0..num_items {
            let (item_data, item_size) = self.decode_dynamic_length_field_item(
                mapped_service,
                uds_payload,
                data,
                &repeated_dop,
                start,
            )?;
            tracing::debug!(
                item_index = repeated_data.len(),
                item_size,
                next_start = start.saturating_add(item_size),
                keys = ?item_data.keys().collect::<Vec<_>>(),
                "DynamicLengthField item decoded"
            );
            repeated_data.push(item_data);
            start = start.saturating_add(item_size);
        }
        tracing::debug!(
            total_items = repeated_data.len(),
            final_start = start,
            last_read_byte_pos = items_abs_start.saturating_add(start),
            "DynamicLengthField decode complete"
        );
        uds_payload.pop_slice()?;
        uds_payload.set_last_read_byte_pos(items_abs_start.saturating_add(start));
        data.insert(
            short_name,
            DiagDataTypeContainer::RepeatingStruct(repeated_data),
        );
        Ok(())
    }

    fn decode_dynamic_length_field_item(
        &self,
        mapped_service: &datatypes::DiagService,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        repeated_dop: &datatypes::DopField,
        start: usize,
    ) -> Result<(HashMap<String, DiagDataTypeContainer>, usize), DiagServiceError> {
        let bytes_to_skip_before = uds_payload.bytes_to_skip();
        uds_payload.push_slice(start, uds_payload.len())?;
        // Inner item params may omit BYTE-POSITION, falling back to last_read_byte_pos.
        // Reset it to 0 so stale state from count decode doesn't corrupt item decoding.
        uds_payload.set_last_read_byte_pos(0);

        tracing::debug!(
            has_basic_structure = repeated_dop.basic_structure().is_some(),
            has_env_data_desc = repeated_dop.env_data_desc().is_some(),
            basic_struct_specific_data_type = ?repeated_dop
                .basic_structure()
                .map(|d| d.specific_data_type()),
            "DynamicLengthField item decode metadata"
        );

        if let Some(s) = repeated_dop
            .basic_structure()
            .and_then(|d| d.specific_data_as_structure().map(datatypes::StructureDop))
        {
            let struct_data = self.map_struct_from_uds(&s, mapped_service, uds_payload, data)?;
            let item_size = s.byte_size().map_or_else(
                || {
                    let delta_bytes_to_skip = uds_payload
                        .bytes_to_skip()
                        .saturating_sub(bytes_to_skip_before);
                    uds_payload
                        .last_read_byte_pos()
                        .saturating_add(delta_bytes_to_skip)
                },
                |s| s as usize,
            );
            uds_payload.pop_slice()?;
            Ok((struct_data, item_size))
        } else if let Some(env_data_desc_dop) = repeated_dop.env_data_desc() {
            let env_data_desc = env_data_desc_dop.specific_data_as_env_data_desc().ok_or(
                DiagServiceError::InvalidDatabase(
                    "DynamicLengthField env_data_desc DOP is not EnvDataDesc type".to_owned(),
                ),
            )?;
            let env_data_desc = datatypes::EnvDataDescDop(env_data_desc);
            let item_data = self.map_env_data_desc_item_from_uds(
                mapped_service,
                uds_payload,
                data,
                &env_data_desc,
                0,
            )?;
            let delta_bytes_to_skip = uds_payload
                .bytes_to_skip()
                .saturating_sub(bytes_to_skip_before);
            let item_size = uds_payload
                .last_read_byte_pos()
                .saturating_add(delta_bytes_to_skip);
            uds_payload.pop_slice()?;
            Ok((item_data, item_size))
        } else {
            uds_payload.pop_slice()?;
            Err(DiagServiceError::InvalidDatabase(
                "DynamicLengthField repeated_dop is neither Structure nor EnvDataDesc".to_owned(),
            ))
        }
    }

    fn map_mux_dop_from_uds(
        &self,
        mapped_service: &datatypes::DiagService,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        short_name: String,
        mux_dop: &datatypes::MuxDop,
        param_ctx: ParamContext<'_>,
    ) -> Result<(), DiagServiceError> {
        uds_payload.push_slice(param_ctx.abs_byte_pos(), uds_payload.len())?;
        self.map_mux_from_uds(mapped_service, uds_payload, data, short_name, mux_dop)?;
        uds_payload.pop_slice()?;
        Ok(())
    }

    fn map_static_field_dop_from_uds(
        &self,
        mapped_service: &datatypes::DiagService,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        short_name: String,
        static_field_dop: &datatypes::StaticFieldDop,
        param_ctx: ParamContext<'_>,
    ) -> Result<(), DiagServiceError> {
        let static_field_size = static_field_dop
            .item_byte_size()
            .saturating_mul(static_field_dop.fixed_number_of_items())
            as usize;

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
            let start = param_ctx
                .abs_byte_pos()
                .saturating_add(i.saturating_mul(static_field_dop.item_byte_size()) as usize);
            let end = start.saturating_add(static_field_dop.item_byte_size() as usize);
            uds_payload.push_slice(start, end)?;

            self.map_nested_struct_from_uds(
                &basic_structure,
                mapped_service,
                uds_payload,
                &mut nested_structs,
                data,
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
        param_name: &str,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        dtc_dop: &datatypes::DtcDop,
        param_ctx: ParamContext<'_>,
    ) -> Result<(), DiagServiceError> {
        let coded_type: datatypes::DiagCodedType = dtc_dop.diag_coded_type()?;

        let (dtc_value, _size) = coded_type.decode(
            uds_payload.data()?,
            param_ctx.abs_byte_pos(),
            param_ctx.parameter.bit_position() as usize,
        )?;

        let code: u32 = DiagDataValue::new(coded_type.base_datatype(), &dtc_value)?.try_into()?;

        let record = dtc_dop
            .dtcs()
            .and_then(|dtcs| dtcs.iter().find(|dtc| dtc.trouble_code() == code))
            .ok_or(DiagServiceError::BadPayload(format!(
                "No DTC with code {code:X} found in DTC references",
            )))?;

        data.insert(
            param_name.to_owned(),
            DiagDataTypeContainer::DtcStruct(DiagDataContainerDtc {
                code,
                display_code: record.display_trouble_code().map(ToOwned::to_owned),
                fault_name: record
                    .text()
                    .and_then(|text| text.value().map(ToOwned::to_owned))
                    .unwrap_or_default(),
                severity: record.level().unwrap_or_default(),
                bit_pos: param_ctx.parameter.bit_position(),
                bit_len: DTC_CODE_BIT_LEN,
                byte_pos: u32::try_from(param_ctx.abs_byte_pos()).map_err(|_| {
                    DiagServiceError::InvalidDatabase("DTC byte position overflows u32".to_owned())
                })?,
            }),
        );
        Ok(())
    }

    /// Extracts the discriminator value from already-decoded outer data by name.
    /// Handles both `DtcStruct` (returns `.code`) and `RawContainer` (converts bytes to u32).
    fn discriminator_value_from_outer_data(
        outer_data: &MappedDiagServiceResponsePayload,
        param_short_name: &str,
    ) -> Result<u32, DiagServiceError> {
        match outer_data.get(param_short_name) {
            Some(DiagDataTypeContainer::DtcStruct(dtc)) => Ok(dtc.code),
            Some(DiagDataTypeContainer::RawContainer(raw)) => {
                let val = operations::uds_data_to_serializable(
                    raw.data_type,
                    raw.compu_method.as_ref(),
                    false,
                    &raw.data,
                )?;
                match val {
                    DiagDataValue::UInt32(n) => Ok(n),
                    DiagDataValue::Int32(n) => u32::try_from(n).map_err(|_| {
                        DiagServiceError::ParameterConversionError(format!(
                            "EnvDataDesc discriminator '{param_short_name}' is negative: {n}"
                        ))
                    }),
                    _ => Err(DiagServiceError::ParameterConversionError(format!(
                        "EnvDataDesc discriminator '{param_short_name}' resolved to unexpected \
                         type: {val:?}"
                    ))),
                }
            }
            _ => Err(DiagServiceError::InvalidDatabase(format!(
                "EnvDataDesc selector param '{param_short_name}' not found in decoded data"
            ))),
        }
    }

    /// Looks up the discriminator value from `outer_data`, finds the matching `EnvData` in
    /// `env_data_desc`, decodes its params and returns them as a new payload map.
    fn map_env_data_desc_item_from_uds(
        &self,
        mapped_service: &datatypes::DiagService,
        uds_payload: &mut Payload,
        outer_data: &MappedDiagServiceResponsePayload,
        env_data_desc: &datatypes::EnvDataDescDop,
        base_offset: usize,
    ) -> Result<MappedDiagServiceResponsePayload, DiagServiceError> {
        let param_short_name = env_data_desc.param_short_name().ok_or_else(|| {
            DiagServiceError::InvalidDatabase("EnvDataDesc missing param_short_name".to_owned())
        })?;
        let discriminator =
            Self::discriminator_value_from_outer_data(outer_data, param_short_name)?;

        let env_datas = env_data_desc.env_datas().ok_or_else(|| {
            DiagServiceError::InvalidDatabase("EnvDataDesc has no env_datas".to_owned())
        })?;

        // First pass: exact match on dtc_values.
        // Second pass: wildcard (EnvData with empty/absent dtc_values matches any discriminator).
        let matching_env_data = env_datas
            .iter()
            .find_map(|dop| {
                let env_data = dop.specific_data_as_env_data()?;
                let dtc_values = env_data.dtc_values()?;
                if dtc_values.iter().any(|v| v == discriminator) {
                    Some(env_data)
                } else {
                    None
                }
            })
            .or_else(|| {
                env_datas.iter().find_map(|dop| {
                    let env_data = dop.specific_data_as_env_data()?;
                    let is_wildcard = env_data.dtc_values().is_none_or(|v| v.is_empty());
                    if is_wildcard { Some(env_data) } else { None }
                })
            });

        let mut item_data = HashMap::new();
        let Some(env_data) = matching_env_data else {
            tracing::warn!(
                discriminator = format!("{discriminator:#X}"),
                "No EnvData matched discriminator in EnvDataDesc; returning empty map"
            );
            return Ok(item_data);
        };

        if let Some(params) = env_data.params() {
            for param in params {
                let param = datatypes::Parameter(param);
                let name = param.short_name().ok_or_else(|| {
                    DiagServiceError::InvalidDatabase("EnvData param missing short_name".to_owned())
                })?;
                self.map_param_from_uds(
                    mapped_service,
                    name,
                    uds_payload,
                    &mut item_data,
                    ParamContext::new(&param, base_offset).with_outer_context(Some(outer_data)),
                )?;
            }
        }

        Ok(item_data)
    }

    fn map_structure_dop_from_uds(
        &self,
        mapped_service: &datatypes::DiagService,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        short_name: &str,
        structure_dop: &datatypes::StructureDop,
        structure_param_ctx: ParamContext<'_>,
    ) -> Result<(), DiagServiceError> {
        let structure_start = structure_param_ctx.abs_byte_pos();

        if let Some(byte_size) = structure_dop.byte_size() {
            let end = structure_start
                .checked_add(byte_size as usize)
                .ok_or_else(|| {
                    DiagServiceError::BadPayload("Overflow in end calculation".to_owned())
                })?;
            if uds_payload.len() < end {
                return Err(DiagServiceError::NotEnoughData {
                    expected: end,
                    actual: uds_payload.len(),
                });
            }
        }

        if let Some(params) = structure_dop.params() {
            for param in params.iter().map(datatypes::Parameter) {
                self.map_param_from_uds(
                    mapped_service,
                    short_name,
                    uds_payload,
                    data,
                    ParamContext::new(&param, structure_start),
                )?;
            }
        }
        Ok(())
    }

    #[tracing::instrument(skip_all,
        fields(
            dlt_context = dlt_ctx!("CORE"),
        )
    )]
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
        if uds_payload.consume() == 0 {
            return Ok(());
        }
        loop {
            uds_payload.push_slice_to_abs_end(uds_payload.last_read_byte_pos())?;
            if !uds_payload.exhausted() {
                match self.map_nested_struct_from_uds(
                    &struct_,
                    mapped_service,
                    uds_payload,
                    &mut nested_structs,
                    data,
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
            let consumed = uds_payload.consume();
            uds_payload.pop_slice()?;
            if uds_payload.exhausted() {
                break;
            } else if consumed == 0 {
                return Err(DiagServiceError::BadPayload(
                    "EndOfPdu did not consume any bytes, breaking potential infinite loop"
                        .to_owned(),
                ));
            }
        }

        data.insert(
            short_name,
            DiagDataTypeContainer::RepeatingStruct(nested_structs),
        );
        Ok(())
    }

    fn map_normal_dop_from_uds(
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
        short_name: String,
        normal_dop: &datatypes::NormalDop,
        param_ctx: ParamContext<'_>,
    ) -> Result<(), DiagServiceError> {
        let diag_coded_type = normal_dop.diag_coded_type()?;
        let compu_method =
            normal_dop
                .compu_method()
                .map(Into::into)
                .ok_or(DiagServiceError::InvalidDatabase(format!(
                    "param {short_name} has no compu method"
                )))?;

        let byte_pos = if param_ctx.parameter.has_byte_position() {
            param_ctx.abs_byte_pos()
        } else {
            uds_payload.last_read_byte_pos()
        };

        data.insert(
            short_name,
            operations::extract_diag_data_container(
                param_ctx.parameter.short_name(),
                byte_pos,
                param_ctx.parameter.bit_position() as usize,
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
                    // Reset last_read_byte_pos for the case data sub-view.
                    // Inner case params may omit BYTE-POSITION, falling back
                    // to last_read_byte_pos; it must be 0 (start of case data)
                    // rather than stale from a previous context.
                    uds_payload.set_last_read_byte_pos(0);
                    let case_data = self.map_struct_from_uds(
                        &case_structure,
                        mapped_service,
                        uds_payload,
                        data,
                    )?;
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
                // Only return a target if the service's state transition
                // matches one in this state chart.
                // We match by source and target to ensure a SecurityAccess service
                // (which references SECURITY state chart transitions) won't accidentally
                // match transitions in the SESSION state chart.
                let transition_source = state_transition.source_short_name_ref()?;
                let transition_target = state_transition.target_short_name_ref()?;

                // Check if this transition exists in the state chart and starts from current state
                if state_chart.state_transitions()?.iter().any(|chart_st| {
                    chart_st.source_short_name_ref() == Some(transition_source)
                        && chart_st.target_short_name_ref() == Some(transition_target)
                        && transition_source == current_state
                }) {
                    Some(transition_target.to_owned())
                } else {
                    None
                }
            })
    }

    async fn lookup_state_transition_by_diagcomm_for_active(
        &self,
        diag_comm: &datatypes::DiagComm<'_>,
    ) -> (Option<String>, Option<String>) {
        let diag_layers = self.get_diag_layers_from_variant_and_parent_refs();

        let state_chart_session = diag_layers.iter().find_map(|dl| {
            dl.state_charts().and_then(|charts| {
                charts.iter().find(|c| {
                    c.semantic()
                        .is_some_and(|n| n.eq_ignore_ascii_case(semantics::SESSION))
                })
            })
        });
        let state_chart_security = diag_layers.iter().find_map(|dl| {
            dl.state_charts().and_then(|charts| {
                charts.iter().find(|c| {
                    c.semantic()
                        .is_some_and(|n| n.eq_ignore_ascii_case(semantics::SECURITY))
                })
            })
        });

        let states = self.ecu_service_states.write().await;
        let new_session = states
            .get(&service_ids::SESSION_CONTROL)
            .as_ref()
            .and_then(|session| {
                state_chart_session
                    .and_then(|sc| Self::lookup_state_transition(diag_comm, &(sc.into()), session))
            });
        let new_security = states
            .get(&service_ids::SECURITY_ACCESS)
            .as_ref()
            .and_then(|session| {
                state_chart_security
                    .and_then(|sc| Self::lookup_state_transition(diag_comm, &(sc.into()), session))
            });
        drop(states);

        (new_session, new_security)
    }

    #[tracing::instrument(skip_all,
        fields(
            dlt_context = dlt_ctx!("CORE"),
        )
    )]
    fn lookup_state_transition_for_active(
        &self,
        semantic: &str,
        current_state: &str,
        target_state: &str,
    ) -> Result<cda_interfaces::DiagComm, DiagServiceError> {
        let semantic_transitions = self
            .get_diag_layers_from_variant_and_parent_refs()
            .iter()
            .filter_map(|dl| dl.state_charts())
            .flat_map(|charts| charts.iter())
            .find_map(|c| {
                if c.semantic()
                    .is_some_and(|n| n.eq_ignore_ascii_case(semantic))
                {
                    c.state_transitions()
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                tracing::error!(
                    ecu_name = self.ecu_name,
                    semantic = %semantic,
                    "State chart with given semantic not found in base variant"
                );
                DiagServiceError::NotFound(format!(
                    "State chart with semantic '{semantic}' not found in base variant"
                ))
            })?;

        let find_service_for_state = |source_state: &str| {
            self.get_services_from_variant_and_parent_refs(|s| {
                s.diag_comm()
                    .and_then(|dc| dc.state_transition_refs())
                    .is_some_and(|st_refs| {
                        st_refs.iter().any(|st_ref| {
                            st_ref.state_transition().is_some_and(|st| {
                                st.source_short_name_ref()
                                    .is_some_and(|n| n.eq_ignore_ascii_case(source_state))
                                    && st
                                        .target_short_name_ref()
                                        .is_some_and(|n| n.eq_ignore_ascii_case(target_state))
                                    && semantic_transitions.iter().any(|semantic| semantic == st)
                            })
                        })
                    })
            })
            .into_iter()
            .next()
        };

        // Try the current state first. If no matching service is found, fall back
        // to the default state so that services reachable from the default are
        // always available regardless of the actual ECU state.
        let service = find_service_for_state(current_state)
            .or_else(|| {
                let default_state = self.default_state(semantic).ok()?;
                if default_state.eq_ignore_ascii_case(current_state) {
                    return None; // already tried this state
                }
                tracing::debug!(
                    current_state,
                    default_state = %default_state,
                    target_state,
                    semantic,
                    "No service found for current state, falling back to default state"
                );
                find_service_for_state(&default_state)
            })
            .ok_or_else(|| {
                tracing::error!(
                    current_state,
                    target_state,
                    semantic,
                    "Failed to find service for state transition"
                );
                DiagServiceError::NotFound(format!(
                    "No service found for state transition {current_state} -> {target_state} \
                     ({semantic})"
                ))
            })?;

        service.try_into()
    }

    fn lookup_state_chart(
        &self,
        semantic: &str,
    ) -> Result<datatypes::StateChart<'_>, DiagServiceError> {
        self.get_diag_layers_from_variant_and_parent_refs()
            .into_iter()
            .filter_map(|dl| dl.state_charts())
            .flat_map(|sc| sc.iter())
            .find(|sc| sc.semantic().is_some_and(|sem| sem == semantic))
            .map(datatypes::StateChart)
            .ok_or_else(|| {
                DiagServiceError::NotFound(format!(
                    "State chart with semantic '{semantic}' not found in base variant"
                ))
            })
    }

    fn default_state(&self, semantic: &str) -> Result<String, DiagServiceError> {
        self.lookup_state_chart(semantic)?
            .start_state_short_name_ref()
            .map(ToOwned::to_owned)
            .ok_or(DiagServiceError::InvalidDatabase(
                "No start state defined in state chart".to_owned(),
            ))
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
    #[tracing::instrument(
        skip_all,
        fields(
            dlt_context = dlt_ctx!("CORE"),
        )
    )]
    async fn check_service_access(
        &self,
        security_plugin: &DynamicPlugin,
        service: &datatypes::DiagService<'_>,
    ) -> Result<(), DiagServiceError> {
        let diag_comm = service
            .diag_comm()
            .ok_or(DiagServiceError::InvalidDatabase(
                "Service has no DiagComm".to_owned(),
            ))?;
        self.check_service_preconditions(&diag_comm.into()).await?;
        Self::check_security_plugin(security_plugin, service)
    }

    /// Validate security access via plugin
    /// allows passing a `Box::new(())` to skip security checks
    /// this is used internally, when we don't want to have this run the check again
    #[tracing::instrument(
        skip_all,
        fields(
            dlt_context = dlt_ctx!("CORE"),
        )
    )]
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

    /// Returns true if the security plugin allows the user to see this service.
    /// Reuses [`Self::check_security_plugin`] which handles void plugins (always allowed)
    /// and real plugins (delegates to [`SecurityApi::validate_service`]).
    fn is_service_visible(
        security_plugin: &DynamicPlugin,
        service: &datatypes::DiagService<'_>,
    ) -> bool {
        Self::check_security_plugin(security_plugin, service).is_ok()
    }

    fn get_meta_data_service(
        &self,
        service_name: &str,
    ) -> Result<datatypes::DiagService<'_>, DiagServiceError> {
        cda_interfaces::SERVICE_IDS_PARAMETER_META_DATA
            .into_iter()
            .find_map(|sid| {
                self.lookup_services_by_sid(sid)
                    .ok()?
                    .into_iter()
                    .find(|s| {
                        s.diag_comm()
                            .and_then(|dc| dc.short_name())
                            .is_some_and(|n| n == service_name)
                    })
            })
            .ok_or_else(|| {
                DiagServiceError::NotFound(format!("Service '{service_name}' not found"))
            })
    }

    async fn check_service_preconditions(
        &self,
        diag_comm: &datatypes::DiagComm<'_>,
    ) -> Result<(), DiagServiceError> {
        let Some(pre_condition_state_ref) = diag_comm
            .pre_condition_state_refs()
            .filter(|refs| !refs.is_empty())
        else {
            return Ok(());
        };

        // Only take state transitions into account if present.
        let state_transition_refs = diag_comm
            .state_transition_refs()
            .filter(|refs| !refs.is_empty())
            .unwrap_or_default();

        // Get current ECU states
        let (ecu_session, ecu_security_level) = {
            let ecu_states = self.ecu_service_states.read().await;

            let session = ecu_states
                .get(&service_ids::SESSION_CONTROL)
                .cloned()
                .ok_or(DiagServiceError::InvalidState(
                    "ECU session is none".to_string(),
                ))?
                .to_ascii_lowercase();

            let security = ecu_states
                .get(&service_ids::SECURITY_ACCESS)
                .cloned()
                .ok_or(DiagServiceError::InvalidState(
                    "ECU security level is none".to_string(),
                ))?
                .to_ascii_lowercase();

            (session, security)
        };

        let get_state_names = |semantic| {
            Ok(self
                .lookup_state_chart(semantic)?
                .states()
                .into_iter()
                .flatten()
                .filter_map(|s| s.short_name())
                .map(str::to_ascii_lowercase)
                .collect::<HashSet<_>>())
        };

        let session_states = get_state_names(semantics::SESSION)?;
        let security_states = get_state_names(semantics::SECURITY)?;

        let precondition_states: Vec<_> = pre_condition_state_ref
            .iter()
            .filter_map(|state_ref| state_ref.state())
            .filter_map(|state| state.short_name())
            .map(str::to_ascii_lowercase)
            .collect();

        let (mut allowed_security, mut allowed_session): (HashSet<_>, HashSet<_>) =
            precondition_states.into_iter().fold(
                (HashSet::new(), HashSet::new()),
                |(mut security, mut session), state_name| {
                    if security_states.contains(&state_name) {
                        security.insert(state_name);
                    } else if session_states.contains(&state_name) {
                        session.insert(state_name);
                    }
                    (security, session)
                },
            );

        // add state transition sources to allowed security states
        state_transition_refs
            .iter()
            .filter_map(|st_ref| {
                st_ref
                    .state_transition()
                    .and_then(|st| st.source_short_name_ref())
            })
            .map(str::to_ascii_lowercase)
            .for_each(|state| {
                allowed_security.insert(state.clone());
                allowed_session.insert(state);
            });

        // Resolve the default states from the MDD state charts. When checking
        // preconditions we also accept the default state as a valid "current" state,
        // so that services whose preconditions include the default are always reachable
        // regardless of the actual ECU state.
        let default_session = self.default_state(semantics::SESSION)?.to_ascii_lowercase();
        let default_security = self
            .default_state(semantics::SECURITY)?
            .to_ascii_lowercase();

        let validate_state = |required: &HashSet<String>,
                              current: &str,
                              default: &str,
                              state_type: &str|
         -> Result<(), DiagServiceError> {
            if required.is_empty() || required.contains(current) || required.contains(default) {
                Ok(())
            } else {
                Err(DiagServiceError::InvalidState(format!(
                    "{service} - {state_type} mismatch. Required one of: {required:?}, Current: \
                     {current}",
                    service = diag_comm.short_name().unwrap_or("None"),
                )))
            }
        };

        validate_state(
            &allowed_security,
            &ecu_security_level,
            &default_security,
            "Security level",
        )?;
        validate_state(&allowed_session, &ecu_session, &default_session, "Session")
    }

    async fn set_variant(&mut self, variant: VariantData) -> Result<(), DiagServiceError> {
        let variant_name = &variant.name;
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

        let state = if variant_index.is_none() {
            tracing::warn!("Variant '{variant_name}' not found in database variants");
            EcuState::NoVariantDetected
        } else {
            EcuState::Online
        };

        tracing::debug!("Setting variant to '{variant_name}' with state {state:?}");
        self.variant = EcuVariant {
            name: Some(variant.name.clone()),
            is_base_variant: variant.is_base_variant,
            is_fallback: variant.is_fallback,
            state,
            logical_address: self.logical_address,
        };

        self.set_default_states().await
    }

    /// Filter and transform services into `ComponentOperationsInfo`
    /// This is used for operation lookup and metadata.
    fn filter_and_transform_operations(
        &self,
        services: Vec<datatypes::DiagService<'_>>,
    ) -> Vec<ComponentOperationsInfo> {
        services
            .into_iter()
            // filter out services that don't have a DiagComm with a short name
            // and crate a tuple of (id, service) where id is the trimmed short name
            // without any affixes
            .filter_map(|service| {
                let diag_comm = service.diag_comm()?;
                let id = self.trim_routine_name(diag_comm.short_name()?);
                Some((id, service))
            })
            // fold over the id of the previous steps creating a map of
            // ids to a list of services with the same trimmed short name
            .fold(
                HashMap::new(),
                |mut acc: HashMap<String, Vec<datatypes::DiagService>>, (id, service)| {
                    acc.entry(id).or_default().push(service);
                    acc
                },
            )
            .into_iter()
            .filter_map(|(id, services)| {
                // filter out entries that have an empty list of services (shouldn't happen)
                let first_service = services.first()?;
                // map to a struct of `ComponentOperationsInfo`
                let name = first_service
                    .diag_comm()
                    .expect(
                        "DiagComm has to be present as otherwise it would be filtered out before",
                    )
                    .long_name()
                    .and_then(|ln| ln.value())
                    .map(|v| self.database_naming_convention.trim_long_name_affixes(v))
                    .unwrap_or_default();
                let RoutineSubfunctions {
                    has_stop,
                    has_request_results,
                } = Self::subfunction_flags_from_services(&services);
                Some(ComponentOperationsInfo {
                    id,
                    name,
                    has_stop,
                    has_request_results,
                })
            })
            .collect()
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

fn param_position_order(a: &datatypes::Parameter, b: &datatypes::Parameter) -> std::cmp::Ordering {
    match (a.has_byte_position(), b.has_byte_position()) {
        // Both have a position -> normal comparison
        (true, true) => a
            .byte_position()
            .cmp(&b.byte_position())
            .then(a.bit_position().cmp(&b.bit_position())),
        // Only a has no position -> a goes after b
        (false, true) => std::cmp::Ordering::Greater,
        // Only b has no position -> b goes after a
        (true, false) => std::cmp::Ordering::Less,
        // Neither has a position -> preserve order
        (false, false) => std::cmp::Ordering::Equal,
    }
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

fn str_to_json_value(
    value: &str,
    data_type: datatypes::DataType,
) -> Result<serde_json::Value, DiagServiceError> {
    let json_value = match data_type {
        datatypes::DataType::Int32 => {
            let i32val = value.parse::<i32>().map_err(|e| {
                DiagServiceError::InvalidDatabase(format!("CodedConst value conversion error: {e}"))
            })?;
            serde_json::Number::from(i32val).into()
        }
        datatypes::DataType::UInt32 => {
            let u32val = value.parse::<u32>().map_err(|e| {
                DiagServiceError::InvalidDatabase(format!("CodedConst value conversion error: {e}"))
            })?;
            serde_json::Number::from(u32val).into()
        }
        datatypes::DataType::Float32 | datatypes::DataType::Float64 => {
            let f64val = value.parse::<f64>().map_err(|e| {
                DiagServiceError::InvalidDatabase(format!("CodedConst value conversion error: {e}"))
            })?;
            serde_json::Number::from_f64(f64val).into()
        }
        datatypes::DataType::AsciiString
        | datatypes::DataType::Utf8String
        | datatypes::DataType::Unicode2String
        | datatypes::DataType::ByteField => serde_json::Value::from(value),
    };
    Ok(json_value)
}

fn process_coded_constants(
    mapped_params: &[datatypes::Parameter],
) -> Result<Vec<u8>, DiagServiceError> {
    let mut uds: Vec<u8> = Vec::new();

    for param in mapped_params {
        if let Some(coded_const) = param.specific_data_as_coded_const() {
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
            let const_json_value = str_to_json_value(coded_const_value, diag_type.base_datatype())?;

            let uds_val = json_value_to_uds_data(&diag_type, None, None, &const_json_value)
                .inspect_err(|e| {
                    tracing::error!(
                        error = ?e,
                        "Failed to convert CodedConst coded value to UDS data for parameter '{}'",
                        param.short_name().unwrap_or_default()
                    );
                })?;

            diag_type.encode(
                uds_val,
                &mut uds,
                param.byte_position() as usize,
                param.bit_position() as usize,
            )?;
        }
    }

    Ok(uds)
}

#[cfg(test)]
mod tests {
    use std::vec;

    use cda_database::datatypes::{
        DataType,
        database_builder::{DiagClassType, DiagCommParams, DiagLayerParams, EcuDataBuilder},
    };
    use cda_interfaces::{EcuManager, Protocol, UDS_ID_RESPONSE_BITMASK};
    use cda_plugin_security::DefaultSecurityPluginData;
    use serde_json::json;

    use super::*;
    use crate::diag_kernel::test_utils::{
        db_builder::{finish_db, finish_db_with_functional_groups},
        ecu_manager_builder::{
            EndOfPduStructureType, SID_PARM_NAME, ServiceSecurityTransition,
            create_ecu_manager_dlf_sibling_no_byte_pos, create_ecu_manager_env_data_no_wildcard,
            create_ecu_manager_variant_detection, create_ecu_manager_with_dtc,
            create_ecu_manager_with_dynamic_length_field_service,
            create_ecu_manager_with_end_pdu_service, create_ecu_manager_with_env_data_desc,
            create_ecu_manager_with_env_data_desc_wildcard,
            create_ecu_manager_with_length_key_request_service,
            create_ecu_manager_with_mixed_functional_group, create_ecu_manager_with_mux_service,
            create_ecu_manager_with_mux_service_and_default_case,
            create_ecu_manager_with_param_length_info_service,
            create_ecu_manager_with_parameter_metadata,
            create_ecu_manager_with_phys_const_normal_dop_service,
            create_ecu_manager_with_phys_const_structure_dop_service,
            create_ecu_manager_with_preconditions_and_functional_group,
            create_ecu_manager_with_state_transitions,
            create_ecu_manager_with_static_field_service, create_ecu_manager_with_struct_service,
            create_ecu_manager_with_trailing_param_after_param_length_info_service,
            new_ecu_manager,
        },
        mdd_type_builder::{create_sid_only_request, new_diag_comm, new_diag_service},
    };

    macro_rules! skip_sec_plugin {
        () => {{
            let skip_sec_plugin: DynamicPlugin = Box::new(());
            skip_sec_plugin
        }};
    }

    /// Helper: assert that a `convert_from_uds` call succeeds and produces the expected JSON.
    async fn assert_uds_converts_to_json(
        ecu_manager: &super::EcuManager<DefaultSecurityPluginData>,
        service: &cda_interfaces::DiagComm,
        payload_data: Vec<u8>,
        expected_json: serde_json::Value,
    ) {
        let response = ecu_manager
            .convert_from_uds(service, &create_payload(payload_data), true, None)
            .await
            .unwrap();
        assert_eq!(response.serialize_to_json().unwrap().data, expected_json);
    }

    /// Helper: assert that a `convert_from_uds` call returns an error.
    async fn assert_uds_conversion_fails(
        ecu_manager: &super::EcuManager<DefaultSecurityPluginData>,
        service: &cda_interfaces::DiagComm,
        payload_data: Vec<u8>,
    ) -> DiagServiceError {
        ecu_manager
            .convert_from_uds(service, &create_payload(payload_data), true, None)
            .await
            .unwrap_err()
    }

    /// Helper: assert that a `convert_from_uds` call succeeds.
    async fn assert_uds_conversion_succeeds(
        ecu_manager: &super::EcuManager<DefaultSecurityPluginData>,
        service: &cda_interfaces::DiagComm,
        payload_data: Vec<u8>,
    ) {
        let response = ecu_manager
            .convert_from_uds(service, &create_payload(payload_data), true, None)
            .await;
        assert!(response.is_ok(), "Expected convert_from_uds to succeed");
    }

    #[tokio::test]
    async fn test_mux_from_uds_invalid_case_no_default() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_mux_service(None, None, None);
        assert_uds_conversion_fails(
            &ecu_manager,
            &service,
            vec![
                // Service ID
                sid,
                // This does not belong to our mux, it's here to test, if the start byte is used
                0xFF,
                // Mux param starts here
                // there is no switch value for 0xffff
                0xFF, 0xFF,
            ],
        )
        .await;
    }

    #[tokio::test]
    async fn test_mux_from_uds_invalid_case_with_default() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_mux_service_and_default_case();
        assert_uds_converts_to_json(
            &ecu_manager,
            &service,
            vec![
                // Service ID
                sid,
                // This does not belong to our mux, it's here to test, if the start byte is used
                0xFF,
                // Mux param starts here
                // there is no switch value for 0xffff, but we have a default case
                0xFF, 0xFF, //
                // value for param 1 of default structure
                0x42,
            ],
            json!({
                "mux_1_param": {
                        "Selector": 0xffff,
                        "default_case": {
                            "default_structure_param_1": 0x42,
                        }
                },
                "test_service_pos_sid": sid
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn test_mux_from_uds_invalid_payload() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_mux_service(None, None, None);
        // inner params are decoded as empty/absent when the case sub-view
        // is truncated at the payload boundary.
        assert_uds_conversion_succeeds(
            &ecu_manager,
            &service,
            vec![
                // Service ID
                sid,
                // This does not belong to our mux, it's here to test, if the start byte is used
                0xFF, // Mux param starts here
                // + switch key byte 0
                0x0, 0x0A, // valid switch key but no data, trailing params absent.
            ],
        )
        .await;
    }

    #[tokio::test]
    async fn test_mux_from_uds_empty_structure() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_mux_service(None, None, None);
        // inner case params at/beyond the empty sub-view are treated as absent
        // rather than triggering NotEnoughData.
        assert_uds_conversion_succeeds(
            &ecu_manager,
            &service,
            vec![
                // Service ID
                sid,
                // This does not belong to our mux, it's here to test, if the start byte is used
                0xFF, // Mux param starts here
                // + switch key byte 0
                0x00, 0x0A, // valid switch key but no data, trailing params absent.
            ],
        )
        .await;
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
        // Create switch key with ASCII string type
        let switch_key = {
            let ascii_string_diag_type =
                db_builder.create_diag_coded_type_standard_length(32, DataType::AsciiString);
            let compu_identical =
                db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);
            let switch_key_dop = db_builder.create_regular_normal_dop(
                "switch_key_dop",
                ascii_string_diag_type,
                compu_identical,
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
            .convert_from_uds(service, &create_payload(data.clone()), true, None)
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
            .create_uds_payload(service, &skip_sec_plugin!(), Some(payload_data), None)
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

        let payload_data = UdsPayloadData::ParameterMap(
            [("main_param".to_string(), test_value)]
                .into_iter()
                .collect(),
        );

        let result = ecu_manager
            .create_uds_payload(&service, &skip_sec_plugin!(), Some(payload_data), None)
            .await;

        let service_payload = result.unwrap();

        // sid (1 byte) + gap (4 bytes) + param1 (2 bytes) + param2 (4 bytes) + param3 (4 bytes)
        // sid is missing here because byte pos starts at 0,
        // so we would have to add 1 more byte for sid
        // and subtract one for the gap
        assert_eq!(
            service_payload.data.len(),
            struct_byte_pos.saturating_add(struct_byte_len) as usize
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
        let float_bytes = 42.42f32.to_be_bytes();
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

        let payload_data = UdsPayloadData::ParameterMap(
            [("main_param".to_string(), test_value)]
                .into_iter()
                .collect(),
        );

        let result = ecu_manager
            .create_uds_payload(&service, &skip_sec_plugin!(), Some(payload_data), None)
            .await;

        // Should fail because param2 is missing
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(
                e.to_string()
                    .contains("Required parameter 'param2' missing")
            );
        }
    }

    #[tokio::test]
    async fn test_map_struct_to_uds_invalid_json_type() {
        let (ecu_manager, service, _, _) = create_ecu_manager_with_struct_service(1);

        // Test data with wrong type (array instead of object)
        let test_value = json!([1, 2, 3]);

        let payload_data = UdsPayloadData::ParameterMap(
            [("main_param".to_string(), test_value)]
                .into_iter()
                .collect(),
        );

        let result = ecu_manager
            .create_uds_payload(&service, &skip_sec_plugin!(), Some(payload_data), None)
            .await;

        // Should fail because we provided an array instead of an object
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("Expected value to be object type"));
        }
    }

    #[tokio::test]
    async fn test_convert_to_uds_value_exceeds_bit_len() {
        let struct_byte_pos = 1;
        let (ecu_manager, service, _sid, _struct_byte_len) =
            create_ecu_manager_with_struct_service(struct_byte_pos);

        // Test data for the structure
        let test_value = json!({
            "param1": 0x0012_3456,  // exceeds 16 bits
            "param2": 42.42,
            "param3": "test"
        });

        let payload_data = UdsPayloadData::ParameterMap(
            [("main_param".to_string(), test_value)]
                .into_iter()
                .collect(),
        );

        let result = ecu_manager
            .create_uds_payload(&service, &skip_sec_plugin!(), Some(payload_data), None)
            .await;

        let conversion_error = result.unwrap_err();
        assert!(
            conversion_error
                .to_string()
                .contains("1193046 exceeds maximum 65535 for bit length 16")
        );
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
                .create_uds_payload(service, &skip_sec_plugin!(), Some(payload_data), None)
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

        test_default(&ecu_manager, &service, with_selector, 0xFFFF, sid).await;
        // when not selector value is given,
        // the switch key will use the limit value of the default value
        test_default(&ecu_manager, &service, without_selector, 0, sid).await;
    }

    #[tokio::test]
    async fn test_map_mux_to_uds_invalid_json_type() {
        let (ecu_manager, service, _) = create_ecu_manager_with_mux_service(None, None, None);

        // Test data with wrong type (array instead of object)
        let test_value = json!([1, 2, 3]);

        let payload_data = UdsPayloadData::ParameterMap(
            [("mux_1_param".to_string(), test_value)]
                .into_iter()
                .collect(),
        );

        let result = ecu_manager
            .create_uds_payload(&service, &skip_sec_plugin!(), Some(payload_data), None)
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
            .create_uds_payload(&service, &skip_sec_plugin!(), Some(payload_data), None)
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
        let (ecu_manager, service, sid) =
            create_ecu_manager_with_end_pdu_service(3, Some(2), EndOfPduStructureType::FixedSize);
        // Each item is 3 bytes: 1 byte for param1 + 2 bytes for param2
        assert_uds_converts_to_json(
            &ecu_manager,
            &service,
            vec![
                sid, // Service ID
                // First item
                0x42, // item_param1 = 0x42
                0x12, 0x34, // item_param2 = 0x1234
                // Second item (exactly at the limit)
                0x99, // item_param1 = 0x99
                0x56, 0x78, // item_param2 = 0x5678
            ],
            json!({
                "end_pdu_param": [
                    { "item_param1": 0x42, "item_param2": 0x1234 },
                    { "item_param1": 0x99, "item_param2": 0x5678 }
                ],
                "test_service_pos_sid": sid
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn test_map_struct_from_uds_end_pdu_exact_max_items() {
        let (ecu_manager, service, sid) =
            create_ecu_manager_with_end_pdu_service(1, Some(2), EndOfPduStructureType::FixedSize);
        // Create payload with exactly 2 items (the max_items limit)
        // Each item is 3 bytes: 1 byte for param1 + 2 bytes for param2
        assert_uds_converts_to_json(
            &ecu_manager,
            &service,
            vec![
                sid, // Service ID
                // First item
                0x42, // item_param1 = 0x42
                0x12, 0x34, // item_param2 = 0x1234
                // Second item (exactly at the limit)
                0x99, // item_param1 = 0x99
                0x56, 0x78, // item_param2 = 0x5678
            ],
            json!({
                "end_pdu_param": [
                    { "item_param1": 0x42, "item_param2": 0x1234 },
                    { "item_param1": 0x99, "item_param2": 0x5678 }
                ],
                "test_service_pos_sid": sid
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn test_map_struct_from_uds_end_pdu_exceeds_max_items() {
        let (ecu_manager, service, sid) =
            create_ecu_manager_with_end_pdu_service(1, Some(2), EndOfPduStructureType::FixedSize);
        // Create payload with 3 items (exceeds max_items = 2)
        // extra data at the end is ignored.
        assert_uds_converts_to_json(
            &ecu_manager,
            &service,
            vec![
                sid, // Service ID
                0x42, 0x12, 0x34, // First item
                0x99, 0x56, 0x78, // Second item
                // A complete third element would not be ignored as specified in the ODX standard
                0xAA, 0xFF, // Third item, incomplete and exceeding limit, will be ignored
            ],
            json!({
                "end_pdu_param": [
                    { "item_param1": 0x42, "item_param2": 0x1234 },
                    { "item_param1": 0x99, "item_param2": 0x5678 }
                ],
                "test_service_pos_sid": sid
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn test_map_struct_from_uds_end_pdu_no_max_no_min_no_data() {
        let (ecu_manager, service, sid) =
            create_ecu_manager_with_end_pdu_service(0, None, EndOfPduStructureType::FixedSize);
        // Valid payload, as min_items = 0 and no max_items
        // Only the SID is present, no items follow
        assert_uds_converts_to_json(
            &ecu_manager,
            &service,
            vec![sid],
            json!({
                "end_pdu_param": [],
                "test_service_pos_sid": sid
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn test_map_struct_from_uds_end_pdu_no_maximum() {
        let (ecu_manager, service, sid) =
            create_ecu_manager_with_end_pdu_service(1, None, EndOfPduStructureType::FixedSize);
        // Create payload with 3 items, extra data at the end will be ignored
        assert_uds_converts_to_json(
            &ecu_manager,
            &service,
            vec![
                sid, // Service ID
                0x42, 0x12, 0x34, // First item
                0x99, 0x56, 0x78, // Second item
                0xAA, 0x9A, 0xBC, // Third item
                0xD0, 0x0F, // extra data at the end, will be ignored
            ],
            json!({
                "end_pdu_param": [
                    { "item_param1": 0x42, "item_param2": 0x1234 },
                    { "item_param1": 0x99, "item_param2": 0x5678 },
                    { "item_param1": 0xAA, "item_param2": 0x9ABC }
                ],
                "test_service_pos_sid": sid
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn test_map_struct_from_uds_end_pdu_incomplete_second_structure() {
        // First structure is 8 bytes long, then next structure is indicated
        // to be 42 bytes long but there is not enough data
        let (ecu_manager, service, sid) = create_ecu_manager_with_end_pdu_service(
            0,
            None,
            EndOfPduStructureType::LeadingLengthDop,
        );

        let mut data = vec![sid]; // Service ID
        // First complete structure: 1 byte length + 8 bytes data = 9 bytes total
        data.push(8); // Length byte indicating 8 bytes of data
        data.extend(vec![0xAA; 8]); // 8 bytes of data
        // Second incomplete structure: 1 byte length + insufficient data
        data.push(42); // Length byte indicating 42 bytes of data
        data.extend(vec![0xBB; 10]); // Only 10 bytes of data (should be 42)

        assert_uds_converts_to_json(
            &ecu_manager,
            &service,
            data,
            json!({
                "end_pdu_param": [
                    { "data": "0xAA 0xAA 0xAA 0xAA 0xAA 0xAA 0xAA 0xAA" },
                ],
                "test_service_pos_sid": sid
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn test_map_struct_from_uds_end_pdu_zero_length_second_structure() {
        // First structure is 8 bytes long, then next structure is indicated
        // to be 0 bytes long
        let (ecu_manager, service, sid) = create_ecu_manager_with_end_pdu_service(
            0,
            None,
            EndOfPduStructureType::LeadingLengthDop,
        );

        let mut data = vec![sid]; // Service ID
        // First complete structure: 1 byte length + 8 bytes data = 33 bytes total
        data.push(8); // Length byte indicating 32 bytes of data
        data.extend(vec![0xAA; 8]); // 8 bytes of data
        // Second structure with zero length: 1 byte length + 0 bytes data = 1 byte total
        data.push(0); // Length byte indicating 0 bytes of data
        data.push(42); // Garbage byte that should not be read as part of the structure

        assert_uds_converts_to_json(
            &ecu_manager,
            &service,
            data,
            json!({
                "end_pdu_param": [
                    { "data": "0xAA 0xAA 0xAA 0xAA 0xAA 0xAA 0xAA 0xAA" }
                ],
                "test_service_pos_sid": sid
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn test_map_dtc_from_uds() {
        let (ecu_manager, service, sid, dtc_code) = create_ecu_manager_with_dtc();

        let mut payload = vec![sid];
        payload.extend_from_slice(&dtc_code.to_be_bytes());

        assert_uds_converts_to_json(
            &ecu_manager,
            &service,
            payload,
            json!({
                "dtc_param": {
                    "code": dtc_code,
                    "display_code": "P1234",
                    "fault_name": "TestFault",
                    "severity": 2,
                },
                "test_service_pos_sid": sid
            }),
        )
        .await;
    }
    // basic EnvDataDesc decoding: the DTC discriminator is looked up from outer data
    // and correct EnvData block is decoded
    #[tokio::test]
    async fn test_map_env_data_desc_from_uds() {
        let (ecu_manager, service, sid, dtc_code) = create_ecu_manager_with_env_data_desc();

        // Payload: SID(1) + DTC(4 bytes big-endian) + temperature(1 byte)
        let mut payload = vec![sid];
        payload.extend_from_slice(&dtc_code.to_be_bytes());
        payload.push(0x42); // temperature = 66

        assert_uds_converts_to_json(
            &ecu_manager,
            &service,
            payload,
            json!({
                "dtc_param": {
                    "code": dtc_code,
                    "display_code": "P0001",
                    "fault_name": "TestEnvFault",
                    "severity": 1,
                },
                "temperature": 0x42,
                "test_service_pos_sid": sid
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn test_map_dynamic_length_field_from_uds() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_dynamic_length_field_service();
        assert_uds_converts_to_json(
            &ecu_manager,
            &service,
            vec![
                sid,  // Service ID
                0x03, // 3 total fields
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            ],
            json!({
                "pos_response_param": [
                   { "item_param": 0x1122 },
                   { "item_param": 0x3344 },
                   { "item_param": 0x5566 },
                ],
                "test_service_pos_sid": sid
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn test_map_dynamic_length_field_from_uds_not_enough_data() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_dynamic_length_field_service();
        // Claims 3 items but only has data for 2. Item 3 starts at the payload
        // boundary, so decoding treats it as absent and conversion still succeeds.
        assert_uds_conversion_succeeds(
            &ecu_manager,
            &service,
            vec![
                sid,  // Service ID
                0x03, // 3 total fields, but only 2 are provided
                0x11, 0x22, 0x33, 0x44,
            ],
        )
        .await;
    }

    #[tokio::test]
    async fn test_negative_response() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_dynamic_length_field_service();
        let payload = vec![0x7F, sid];

        let response = ecu_manager
            .convert_from_uds(&service, &create_payload(payload), true, None)
            .await
            .unwrap();
        assert_eq!(response.response_type, DiagServiceResponseType::Negative);
    }

    #[tokio::test]
    async fn test_negative_response_with_invalid_data_where_no_neg_response_is_defined() {
        let (ecu_manager, service, sid) =
            create_ecu_manager_with_end_pdu_service(1, None, EndOfPduStructureType::FixedSize);
        let data = vec![0x7F, sid, 0x33];

        let response = ecu_manager
            .convert_from_uds(&service, &create_payload(data), true, None)
            .await
            .unwrap();
        assert_eq!(response.response_type, DiagServiceResponseType::Negative);
    }

    #[tokio::test]
    async fn test_detect_variant_with_empty_responses_to_disconnected() {
        let mut ecu_manager = create_ecu_manager_variant_detection(true);

        for state in [
            EcuState::Online,
            EcuState::NoVariantDetected,
            EcuState::Duplicate,
            EcuState::Disconnected,
        ] {
            ecu_manager.variant.state = state;

            let service_responses: HashMap<String, DiagServiceResponseStruct> = HashMap::new();
            ecu_manager
                .detect_variant::<DiagServiceResponseStruct>(service_responses)
                .await
                .unwrap();

            assert_eq!(ecu_manager.variant.name, None);
            assert!(!ecu_manager.variant.is_base_variant);
            assert_eq!(
                ecu_manager.variant.state,
                EcuState::Disconnected,
                "State should transition to Disconnected from {state:?} with empty responses",
            );
        }
    }

    #[tokio::test]
    async fn test_detect_base_variant() {
        detect_variant(0, true, "BaseVariant".to_owned(), EcuState::Online, None).await;
    }

    #[tokio::test]
    async fn test_detect_specific_variant() {
        detect_variant(
            1,
            false,
            "SpecificVariant".to_owned(),
            EcuState::Online,
            None,
        )
        .await;
    }

    #[tokio::test]
    async fn test_detect_unknown_variant_fallback_disabled() {
        // Must disable base fallback, otherwise we won't get an error in detect_variant but
        // just the base variant instead.
        let mut ecu_manager = create_ecu_manager_variant_detection(false);
        let response = create_variant_response(
            "ReadVariantData",
            [("variant_code".to_owned(), 42)].into_iter().collect(),
        );

        let mut service_responses = HashMap::new();
        service_responses.insert("ReadVariantData".to_owned(), response);

        assert_eq!(
            ecu_manager
                .detect_variant(service_responses)
                .await
                .err()
                .unwrap(),
            DiagServiceError::VariantDetectionError(
                "No variant found for ECU VariantDetectionEcu".to_owned()
            )
        );

        assert!(ecu_manager.variant.name.is_none());
        assert!(!ecu_manager.diag_database.is_loaded());
        assert!(!ecu_manager.variant.is_base_variant);
        assert_eq!(ecu_manager.variant.state, EcuState::NoVariantDetected);
    }

    #[tokio::test]
    async fn test_detect_variant_with_response_from_offline_to_online() {
        let mut ecu_manager = create_ecu_manager_variant_detection(true);
        ecu_manager.variant.state = EcuState::Offline;
        detect_variant(0, true, "BaseVariant".to_owned(), EcuState::Online, None).await;
    }

    #[tokio::test]
    async fn test_detect_unknown_variant_fallback_to_base() {
        let mut ecu_manager = create_ecu_manager_variant_detection(true);
        ecu_manager.fallback_to_base_variant = true;

        let response = create_variant_response(
            "ReadVariantData",
            [("variant_code".to_owned(), 42)].into_iter().collect(),
        );

        let mut service_responses = HashMap::new();
        service_responses.insert("ReadVariantData".to_owned(), response);

        // Should succeed by falling back to base variant
        ecu_manager.detect_variant(service_responses).await.unwrap();

        assert_eq!(ecu_manager.variant.name, Some("BaseVariant".to_owned()));
        assert!(ecu_manager.variant.is_base_variant);
        assert_eq!(ecu_manager.variant.state, EcuState::Online);
        assert!(ecu_manager.diag_database.is_loaded());
        assert!(ecu_manager.variant_index.is_some());
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

    /// Helper to create a variant detection response with specified parameters.
    ///
    /// # Parameters:
    /// - `service_name`: Name of the diagnostic service
    /// - `params`: Map of parameter names to u8 values (e.g., "`variant_code`" -> 0)
    ///
    /// Returns a positive `DiagServiceResponseStruct` with the specified parameters
    /// mapped as `RawContainer` data.
    fn create_variant_response(
        service_name: &str,
        params: HashMap<String, u8>,
    ) -> DiagServiceResponseStruct {
        let service_comm =
            cda_interfaces::DiagComm::new(service_name, DiagCommType::Configurations);

        let data_map: HashMap<String, DiagDataTypeContainer> = params
            .into_iter()
            .map(|(key, value)| {
                (
                    key,
                    DiagDataTypeContainer::RawContainer(DiagDataTypeContainerRaw {
                        data: vec![value],
                        bit_len: 8,
                        data_type: DataType::UInt32,
                        compu_method: None,
                    }),
                )
            })
            .collect();

        DiagServiceResponseStruct {
            service: service_comm,
            data: vec![0x62, 0x01],
            mapped_data: Some(MappedResponseData {
                data: data_map,
                errors: vec![],
            }),
            response_type: DiagServiceResponseType::Positive,
        }
    }

    async fn detect_variant(
        variant_id: u8,
        is_base: bool,
        name: String,
        state: EcuState,
        ecu_manger: Option<super::EcuManager<DefaultSecurityPluginData>>,
    ) {
        let mut ecu_manager = ecu_manger.unwrap_or(create_ecu_manager_variant_detection(true));

        let response = create_variant_response(
            "ReadVariantData",
            [("variant_code".to_owned(), variant_id)]
                .into_iter()
                .collect(),
        );

        let mut service_responses = HashMap::new();
        service_responses.insert("ReadVariantData".to_owned(), response);

        ecu_manager.detect_variant(service_responses).await.unwrap();
        assert_eq!(ecu_manager.variant.name, Some(name));
        assert_eq!(ecu_manager.variant.is_base_variant, is_base);
        assert_eq!(ecu_manager.variant.state, state);
    }

    #[test]
    fn test_get_request_parameter_metadata_success() {
        use cda_interfaces::ParameterTypeMetadata;

        let ecu_manager = create_ecu_manager_with_parameter_metadata();

        // Get parameter metadata for the test service
        let result = ecu_manager.get_request_parameter_metadata("RDBI_TestService");
        assert!(result.is_ok());

        let metadata = result.unwrap();
        assert_eq!(metadata.len(), 3); // sid, RDBI_DID, data

        // Verify sid parameter (CODED-CONST)
        let sid_param = metadata.iter().find(|m| m.name == SID_PARM_NAME).unwrap();
        assert!(matches!(
            sid_param.param_type,
            ParameterTypeMetadata::CodedConst { .. }
        ));
        if let ParameterTypeMetadata::CodedConst { coded_value } = &sid_param.param_type {
            assert_eq!(coded_value, "34");
        }

        // Verify RDBI_DID parameter (CODED-CONST)
        let did_param = metadata.iter().find(|m| m.name == "RDBI_DID").unwrap();
        if let ParameterTypeMetadata::CodedConst { coded_value } = &did_param.param_type {
            assert_eq!(coded_value, "0xF190");
        } else {
            panic!("Expected CODED-CONST parameter type for RDBI_DID");
        }

        // Verify data parameter (VALUE)
        let data_param = metadata.iter().find(|m| m.name == "data").unwrap();
        assert!(matches!(
            data_param.param_type,
            ParameterTypeMetadata::Value { .. }
        ));
    }

    #[test]
    fn test_get_request_parameter_metadata_service_not_found() {
        let ecu_manager = create_ecu_manager_with_parameter_metadata();

        // Try to get metadata for a non-existent service
        let result = ecu_manager.get_request_parameter_metadata("NonExistentService");
        assert!(result.is_err());

        // Should return NotFound error for non-existent service
        assert!(matches!(result, Err(DiagServiceError::NotFound(_))));
    }

    #[test]
    fn test_get_mux_cases_for_service_success() {
        let (ecu_manager, _, _) = create_ecu_manager_with_mux_service(None, None, None);

        // Get MUX cases for the test service
        let result = ecu_manager.get_mux_cases_for_service("TestMuxService");
        assert!(result.is_ok());

        let mux_cases = result.unwrap();
        assert_eq!(mux_cases.len(), 3); // mux_1_case_1, mux_1_case_2, mux_1_case_3

        // Verify case names
        assert!(mux_cases.iter().any(|c| c.short_name == "mux_1_case_1"));
        assert!(mux_cases.iter().any(|c| c.short_name == "mux_1_case_2"));
        assert!(mux_cases.iter().any(|c| c.short_name == "mux_1_case_3"));

        // Verify lower_limit values exist for numeric cases
        let case_1 = mux_cases
            .iter()
            .find(|c| c.short_name == "mux_1_case_1")
            .unwrap();
        assert!(case_1.lower_limit.is_some());

        let case_2 = mux_cases
            .iter()
            .find(|c| c.short_name == "mux_1_case_2")
            .unwrap();
        assert!(case_2.lower_limit.is_some());
    }

    #[test]
    fn test_get_mux_cases_for_service_not_found() {
        let (ecu_manager, _, _) = create_ecu_manager_with_mux_service(None, None, None);

        // Try to get MUX cases for a non-existent service
        let result = ecu_manager.get_mux_cases_for_service("NonExistentService");
        assert!(result.is_err());

        // Should return NotFound error for non-existent service
        assert!(matches!(result, Err(DiagServiceError::NotFound(_))));
    }

    #[test]
    fn test_get_mux_cases_for_service_no_mux_cases() {
        // Use a service without MUX cases
        let ecu_manager = create_ecu_manager_with_parameter_metadata();

        // Get MUX cases for a service that doesn't have MUX responses
        let result = ecu_manager.get_mux_cases_for_service("RDBI_TestService");
        assert!(result.is_ok());

        let mux_cases = result.unwrap();
        // Should return empty vector if no MUX cases found
        assert_eq!(mux_cases.len(), 0);
    }

    #[test]
    fn test_get_request_parameter_metadata_extracts_coded_const_did_value() {
        use cda_interfaces::ParameterTypeMetadata;

        let ecu_manager = create_ecu_manager_with_parameter_metadata();

        // Get parameter metadata
        let result = ecu_manager.get_request_parameter_metadata("RDBI_TestService");
        assert!(result.is_ok());

        let metadata = result.unwrap();

        // Find the DID parameter and extract its value
        let did_param = metadata.iter().find(|m| m.name == "RDBI_DID").unwrap();

        if let ParameterTypeMetadata::CodedConst { coded_value } = &did_param.param_type {
            // Verify the coded value can be parsed as a DID
            // "0xF190" should parse to 61840
            let did_value = if let Some(hex_part) = coded_value
                .strip_prefix("0x")
                .or_else(|| coded_value.strip_prefix("0X"))
            {
                u16::from_str_radix(hex_part, 16).ok()
            } else {
                coded_value.parse::<u16>().ok()
            };

            assert!(
                did_value.is_some(),
                "CODED-CONST value '{coded_value}' should be parseable as DID"
            );
            assert_eq!(did_value.unwrap(), 0xF190);
        } else {
            panic!("Expected CODED-CONST parameter type");
        }
    }

    /// Verifies that `get_request_parameter_metadata` resolves `coded_value` for a
    /// PHYS-CONST parameter backed by a `NormalDOP` with an Identical `CompuMethod`.
    #[test]
    fn test_get_request_parameter_metadata_phys_const_coded_value_resolved() {
        use cda_interfaces::ParameterTypeMetadata;

        let (ecu_manager, _dc, _sid) = create_ecu_manager_with_phys_const_normal_dop_service();

        let result = ecu_manager.get_request_parameter_metadata("TestPhysConstNormalService");
        assert!(result.is_ok());

        let metadata = result.unwrap();

        let did_param = metadata
            .iter()
            .find(|m| m.name == "DID")
            .expect("DID parameter should be present");

        if let ParameterTypeMetadata::PhysConst {
            phys_constant_value,
            coded_value,
        } = &did_param.param_type
        {
            assert_eq!(phys_constant_value, "61840");
            // Identical CompuMethod: phys string parses directly to coded integer
            assert_eq!(
                *coded_value,
                Some(61840u64),
                "PHYS-CONST with Identical CompuMethod must resolve coded_value"
            );
        } else {
            panic!(
                "Expected PhysConst parameter type for DID, got {:?}",
                did_param.param_type
            );
        }
    }

    #[test]
    fn test_get_response_parameter_metadata_service_not_found() {
        let (ecu_manager, _dc, _sid) = create_ecu_manager_with_phys_const_normal_dop_service();

        let result = ecu_manager.get_response_parameter_metadata("NonExistentService");
        assert!(result.is_err());
        assert!(matches!(result, Err(DiagServiceError::NotFound(_))));
    }

    #[test]
    fn test_get_response_parameter_metadata_empty_for_no_pos_response() {
        let (ecu_manager, _dc, _sid, _) = create_ecu_manager_with_struct_service(1);

        // TestStructService has no positive-response definition
        let result = ecu_manager.get_response_parameter_metadata("TestStructService");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    /// Covers `CodedConst` (SID), `PhysConst` (DID), and `Value` (data) response parameters.
    ///
    /// Fixture layout (`pos_response` of `TestPhysConstNormalService`):
    ///   byte 0: `sid`       - CODED-CONST (1 byte)
    ///   byte 1: `DID`       - PHYS-CONST  (u16, `coded_value` = None in response metadata)
    ///   byte 3: `data_param`- VALUE        (u8, 1 byte)
    #[test]
    fn test_get_response_parameter_metadata_phys_const_and_value_params() {
        use cda_interfaces::ParameterTypeMetadata;

        let (ecu_manager, _dc, _sid) = create_ecu_manager_with_phys_const_normal_dop_service();

        let result = ecu_manager.get_response_parameter_metadata("TestPhysConstNormalService");
        assert!(result.is_ok());

        let metadata = result.unwrap();
        assert_eq!(metadata.len(), 3, "Expected sid, DID, data_param");

        // SID: CODED-CONST at byte 0
        let sid_param = metadata
            .iter()
            .find(|m| m.name == "sid")
            .expect("sid param should be present");
        assert!(matches!(
            sid_param.param_type,
            ParameterTypeMetadata::CodedConst { .. }
        ));
        assert_eq!(sid_param.byte_position, 0);
        assert_eq!(sid_param.byte_size, Some(1)); // 8 bits

        // DID: PHYS-CONST at byte 1; response metadata does not resolve coded_value
        let did_param = metadata
            .iter()
            .find(|m| m.name == "DID")
            .expect("DID param should be present");
        if let ParameterTypeMetadata::PhysConst {
            phys_constant_value,
            coded_value,
        } = &did_param.param_type
        {
            assert_eq!(phys_constant_value, "61840");
            assert!(
                coded_value.is_none(),
                "get_response_parameter_metadata does not resolve PhysConst coded_value"
            );
        } else {
            panic!(
                "Expected PhysConst type for DID, got {:?}",
                did_param.param_type
            );
        }
        assert_eq!(did_param.byte_position, 1);
        assert!(did_param.byte_size.is_none());

        // data_param: VALUE at byte 3, u8 = 1 byte
        let data_param = metadata
            .iter()
            .find(|m| m.name == "data_param")
            .expect("data_param should be present");
        assert!(matches!(
            data_param.param_type,
            ParameterTypeMetadata::Value { .. }
        ));
        assert_eq!(data_param.byte_position, 3);
        assert_eq!(data_param.byte_size, Some(1)); // u8 = 8 bits
    }

    /// Verifies MUX expansion: each case's inner parameters appear as
    /// `"case_name/param_name"` entries, and each case produces a
    /// `"__mux_case__/case_name"` marker.
    ///
    /// Fixture layout (`pos_response` of `TestMuxService`):
    ///   byte 0: `test_service_pos_sid` - CODED-CONST (1 byte, SID = 0x22)
    ///   byte 2: `mux_1_param`          - MUX DOP (expanded into case entries)
    ///     switch key: u16 at offset 0 within mux (size = 2 bytes)
    ///     case 1 abs pos = mux(2) + key(2) + `inner_offset`
    ///       `mux_1_case_1_param_1`: f32 -> byte 4, size 4
    ///       `mux_1_case_1_param_2`: u8  -> byte 8, size 1
    ///       marker __`mux_case`__/`mux_1_case_1`: byte 4, size = structure (7)
    ///     case 2 abs pos = 2 + 2 + `inner_offset`
    ///       `mux_1_case_2_param_1`: i16  -> byte 5, size 2
    ///       `mux_1_case_2_param_2`: ascii 32 bits -> byte 8, size 4
    ///       marker __`mux_case`__/`mux_1_case_2`: byte 4, size = structure (7)
    ///     case 3: no structure -> produces no entries
    #[test]
    fn test_get_response_parameter_metadata_mux_expansion() {
        use cda_interfaces::ParameterTypeMetadata;

        let (ecu_manager, _, _) = create_ecu_manager_with_mux_service(None, None, None);

        let result = ecu_manager.get_response_parameter_metadata("TestMuxService");
        assert!(result.is_ok());

        let metadata = result.unwrap();
        // SID (1) + case-1 (2 inner + 1 marker) + case-2 (2 inner + 1 marker) = 7
        assert_eq!(
            metadata.len(),
            7,
            "Expected SID + case-1 entries (2+marker) + case-2 entries (2+marker)"
        );

        // SID coded-const is preserved unchanged
        let sid_param = metadata
            .iter()
            .find(|m| m.name == "test_service_pos_sid")
            .expect("test_service_pos_sid should be present");
        assert!(matches!(
            sid_param.param_type,
            ParameterTypeMetadata::CodedConst { .. }
        ));
        assert_eq!(sid_param.byte_position, 0);

        // Case 1 inner params (mux byte_pos=2, switch_key_size=2)
        let c1p1 = metadata
            .iter()
            .find(|m| m.name == "mux_1_case_1/mux_1_case_1_param_1")
            .expect("mux_1_case_1/mux_1_case_1_param_1 should be present");
        assert!(matches!(
            c1p1.param_type,
            ParameterTypeMetadata::Value { .. }
        ));
        // mux_byte_pos(2) + switch_key_size(2) + inner_byte_pos(0)
        assert_eq!(c1p1.byte_position, 4);
        assert_eq!(c1p1.byte_size, Some(4)); // f32 = 32 bits / 8

        let c1p2 = metadata
            .iter()
            .find(|m| m.name == "mux_1_case_1/mux_1_case_1_param_2")
            .expect("mux_1_case_1/mux_1_case_1_param_2 should be present");
        assert!(matches!(
            c1p2.param_type,
            ParameterTypeMetadata::Value { .. }
        ));
        // mux_byte_pos(2) + switch_key_size(2) + inner_byte_pos(4)
        assert_eq!(c1p2.byte_position, 8);
        assert_eq!(c1p2.byte_size, Some(1)); // u8 = 8 bits / 8

        let marker_1 = metadata
            .iter()
            .find(|m| m.name == "__mux_case__/mux_1_case_1")
            .expect("__mux_case__/mux_1_case_1 marker should be present");
        assert!(matches!(
            marker_1.param_type,
            ParameterTypeMetadata::CodedConst { .. }
        ));
        assert_eq!(marker_1.byte_position, 4); // mux_byte_pos(2) + switch_key_size(2)
        assert_eq!(marker_1.byte_size, Some(7)); // structure byte_size

        // Case 2 inner params
        let c2p1 = metadata
            .iter()
            .find(|m| m.name == "mux_1_case_2/mux_1_case_2_param_1")
            .expect("mux_1_case_2/mux_1_case_2_param_1 should be present");
        assert!(matches!(
            c2p1.param_type,
            ParameterTypeMetadata::Value { .. }
        ));
        // mux_byte_pos(2) + switch_key_size(2) + inner_byte_pos(1)
        assert_eq!(c2p1.byte_position, 5);
        assert_eq!(c2p1.byte_size, Some(2)); // i16 = 16 bits / 8

        let c2p2 = metadata
            .iter()
            .find(|m| m.name == "mux_1_case_2/mux_1_case_2_param_2")
            .expect("mux_1_case_2/mux_1_case_2_param_2 should be present");
        assert!(matches!(
            c2p2.param_type,
            ParameterTypeMetadata::Value { .. }
        ));
        // mux_byte_pos(2) + switch_key_size(2) + inner_byte_pos(4)
        assert_eq!(c2p2.byte_position, 8);
        assert_eq!(c2p2.byte_size, Some(4)); // ascii 32 bits / 8

        let marker_2 = metadata
            .iter()
            .find(|m| m.name == "__mux_case__/mux_1_case_2")
            .expect("__mux_case__/mux_1_case_2 marker should be present");
        assert!(matches!(
            marker_2.param_type,
            ParameterTypeMetadata::CodedConst { .. }
        ));
        assert_eq!(marker_2.byte_position, 4); // mux_byte_pos(2) + switch_key_size(2)
        assert_eq!(marker_2.byte_size, Some(7)); // structure byte_size

        // Case 3 has no structure - must produce no entries at all
        assert!(
            metadata
                .iter()
                .all(|m| !m.name.starts_with("mux_1_case_3/")),
            "mux_1_case_3 has no structure and must not produce entries"
        );
    }

    #[tokio::test]
    async fn test_convert_request_from_uds_success() {
        let (ecu_manager, dc, sid, _struct_byte_len) = create_ecu_manager_with_struct_service(1);

        // Create a valid UDS request payload: SID + struct data
        // SID (1 byte) + param1 (2 bytes) + param2 (4 bytes) + param3 (4 bytes)
        let request_payload = vec![
            sid, // SID
            0x12, 0x34, // param1 (u16)
            0x40, 0x49, 0x0F, 0xDB, // param2 (f32 = 3.14159)
            b'T', b'e', b's', b't', // param3 (ascii string)
        ];

        let payload = create_payload(request_payload.clone());

        // Convert request from UDS
        let result = ecu_manager
            .convert_request_from_uds(&dc, &payload, true)
            .await;

        assert!(result.is_ok());
        let response = result.unwrap();

        // Verify response type is positive (successful parsing)
        assert_eq!(response.response_type, DiagServiceResponseType::Positive);

        // Verify raw data matches input
        assert_eq!(response.data, request_payload);

        // Verify mapped data exists
        assert!(response.mapped_data.is_some());

        let mapped = response.mapped_data.unwrap();

        // Verify no mapping errors
        assert_eq!(mapped.errors.len(), 0);

        // Verify all parameters were parsed (flattened from structure)
        assert!(mapped.data.contains_key(SID_PARM_NAME));
        assert!(mapped.data.contains_key("param1"));
        assert!(mapped.data.contains_key("param2"));
        assert!(mapped.data.contains_key("param3"));
    }

    #[tokio::test]
    async fn test_convert_request_from_uds_with_map_to_json_false() {
        let (ecu_manager, dc, sid, _struct_byte_len) = create_ecu_manager_with_struct_service(1);

        // Create a complete valid UDS request payload
        let request_payload = vec![
            sid, // SID
            0x12, 0x34, // param1 (u16)
            0x40, 0x49, 0x0F, 0xDB, // param2 (f32)
            b'T', b'e', b's', b't', // param3 (ascii string)
        ];

        let payload = create_payload(request_payload.clone());

        // Convert with map_to_json = false
        let result = ecu_manager
            .convert_request_from_uds(&dc, &payload, false)
            .await;

        assert!(result.is_ok());
        let response = result.unwrap();

        // Should have raw data but no mapped data (map_to_json=false)
        assert_eq!(response.data, request_payload);
        assert!(response.mapped_data.is_none());
        assert_eq!(response.response_type, DiagServiceResponseType::Positive);
    }

    #[tokio::test]
    async fn test_phys_const_normal_dop_from_uds() {
        let (ecu_manager, dc, sid) = create_ecu_manager_with_phys_const_normal_dop_service();

        // UDS response: SID(0x62) + DID(0xF190 = 61840) + data(0x42)
        let response_data: Vec<u8> = vec![sid, 0xF1, 0x90, 0x42];

        let payload = create_payload(response_data.clone());

        let result = ecu_manager
            .convert_from_uds(&dc, &payload, true, None)
            .await;

        assert!(result.is_ok());
        let mapped = result.unwrap();
        assert_eq!(mapped.data, response_data);
        assert!(mapped.mapped_data.is_some());

        let mapped_data = mapped.mapped_data.unwrap();

        // Should have entries for DID and data_param (sid is CODED-CONST, not in mapped output)
        assert!(
            mapped_data.data.contains_key("DID"),
            "Expected 'DID' key in mapped data"
        );
        assert!(
            mapped_data.data.contains_key("data_param"),
            "Expected 'data_param' key in mapped data"
        );
    }

    #[tokio::test]
    async fn test_phys_const_structure_dop_from_uds() {
        let (ecu_manager, dc, sid) = create_ecu_manager_with_phys_const_structure_dop_service();

        // UDS response: SID(0x6E) + DID(0xF190) + sub_param1(0x000A, u16) + sub_param2(0xFF, u8)
        let response_data: Vec<u8> = vec![sid, 0xF1, 0x90, 0x00, 0x0A, 0xFF];

        let payload = create_payload(response_data.clone());

        let result = ecu_manager
            .convert_from_uds(&dc, &payload, true, None)
            .await;

        assert!(result.is_ok());
        let mapped = result.unwrap();
        assert_eq!(mapped.data, response_data);
        assert!(mapped.mapped_data.is_some());

        let mapped_data = mapped.mapped_data.unwrap();

        // DID should be present (Normal DOP PhysConst)
        assert!(
            mapped_data.data.contains_key("DID"),
            "Expected 'DID' key in mapped data"
        );

        // Structure sub-params should be FLATTENED into parent map
        assert!(
            mapped_data.data.contains_key("sub_param1"),
            "Expected 'sub_param1' key (flattened from Structure DOP)"
        );
        assert!(
            mapped_data.data.contains_key("sub_param2"),
            "Expected 'sub_param2' key (flattened from Structure DOP)"
        );
    }

    #[tokio::test]
    async fn test_phys_const_normal_dop_to_uds() {
        let (ecu_manager, dc, _sid) = create_ecu_manager_with_phys_const_normal_dop_service();

        // JSON payload: DID = 61840 (0xF190)
        let json_payload = json!({
            "DID": 61840
        });

        let payload_data =
            UdsPayloadData::ParameterMap(serde_json::from_value(json_payload).unwrap());

        let result = ecu_manager
            .create_uds_payload(&dc, &skip_sec_plugin!(), Some(payload_data), None)
            .await;

        assert!(result.is_ok());
        let service_payload = result.unwrap();
        let uds_bytes = &service_payload.data;

        // Expected: SID(0x22) + DID(0xF1, 0x90)
        assert_eq!(
            uds_bytes.first().copied().unwrap(),
            0x22,
            "First byte should be RDBI SID 0x22"
        );
        assert_eq!(
            uds_bytes.get(1).copied().unwrap(),
            0xF1,
            "DID high byte should be 0xF1"
        );
        assert_eq!(
            uds_bytes.get(2).copied().unwrap(),
            0x90,
            "DID low byte should be 0x90"
        );
    }

    #[tokio::test]
    async fn test_phys_const_structure_dop_to_uds() {
        let (ecu_manager, dc, _sid) = create_ecu_manager_with_phys_const_structure_dop_service();

        // JSON payload: DID + DREC with sub-params
        let json_payload = json!({
            "DID": 61840,
            "DREC": {
                "sub_param1": 0x1234,
                "sub_param2": 0xAB
            }
        });

        let payload_data =
            UdsPayloadData::ParameterMap(serde_json::from_value(json_payload).unwrap());

        let result = ecu_manager
            .create_uds_payload(&dc, &skip_sec_plugin!(), Some(payload_data), None)
            .await;

        assert!(result.is_ok());
        let service_payload = result.unwrap();
        let uds_bytes = &service_payload.data;

        // Expected: SID(0x2E) + DID(0xF1, 0x90) + sub_param1(0x12, 0x34) + sub_param2(0xAB)
        assert_eq!(
            uds_bytes.first().copied().unwrap(),
            0x2E,
            "First byte should be WDBI SID 0x2E"
        );
        assert_eq!(uds_bytes.get(1).copied().unwrap(), 0xF1, "DID high byte");
        assert_eq!(uds_bytes.get(2).copied().unwrap(), 0x90, "DID low byte");
        assert_eq!(
            uds_bytes.get(3).copied().unwrap(),
            0x12,
            "sub_param1 high byte"
        );
        assert_eq!(
            uds_bytes.get(4).copied().unwrap(),
            0x34,
            "sub_param1 low byte"
        );
        assert_eq!(uds_bytes.get(5).copied().unwrap(), 0xAB, "sub_param2 byte");
    }

    #[tokio::test]
    async fn test_phys_const_structure_dop_roundtrip() {
        let (ecu_manager, dc, sid) = create_ecu_manager_with_phys_const_structure_dop_service();

        // Step 1: Encode JSON -> UDS
        let json_payload = json!({
            "DID": 61840,
            "DREC": {
                "sub_param1": 10,
                "sub_param2": 255
            }
        });

        let payload_data =
            UdsPayloadData::ParameterMap(serde_json::from_value(json_payload).unwrap());

        let encode_result = ecu_manager
            .create_uds_payload(&dc, &skip_sec_plugin!(), Some(payload_data), None)
            .await;
        assert!(encode_result.is_ok());
        let mut service_payload = encode_result.unwrap();

        // Step 2: Change SID from request (0x2E) to positive response (0x6E)
        if let Some(byte) = service_payload.data.get_mut(0) {
            *byte = sid;
        }

        // Step 3: Decode UDS -> mapped data
        let decode_result = ecu_manager
            .convert_from_uds(&dc, &service_payload, true, None)
            .await;

        assert!(decode_result.is_ok());
        let mapped = decode_result.unwrap();

        assert!(mapped.mapped_data.is_some());
        let mapped_data = mapped.mapped_data.unwrap();

        // Verify roundtrip preserved all params
        assert!(
            mapped_data.data.contains_key("DID"),
            "DID should survive roundtrip"
        );
        assert!(
            mapped_data.data.contains_key("sub_param1"),
            "sub_param1 should survive roundtrip"
        );
        assert!(
            mapped_data.data.contains_key("sub_param2"),
            "sub_param2 should survive roundtrip"
        );
    }

    #[tokio::test]
    async fn test_convert_request_from_uds_and_check_structure() {
        let (ecu_manager, dc, sid, _struct_byte_len) = create_ecu_manager_with_struct_service(3);

        // Create a valid UDS request payload: SID + struct data
        // SID (1 byte) + 2 bytes DID + param1 (2 bytes) + param2 (4 bytes) + param3 (4 bytes)
        let request_payload = vec![
            sid, // SID
            0xF1, 0x00, // DID 0xF100
            0x12, 0x34, // param1 (u16)
            0x40, 0x49, 0x0F, 0xDB, // param2 (u32),
            0x40, 0x49, 0x0F, 0xDB, // param3 (u32)
        ];

        let payload = create_payload(request_payload.clone());

        // Convert request from UDS
        let result = ecu_manager
            .convert_request_from_uds(&dc, &payload, true)
            .await;

        assert!(result.is_ok());
        let response = result.expect("Expected successful conversion from UDS");

        // Verify response type is positive (successful parsing)
        assert_eq!(response.response_type, DiagServiceResponseType::Positive);

        // Verify raw data matches input
        assert_eq!(response.data, request_payload);

        // Verify mapped data exists
        assert!(
            response.mapped_data.is_some(),
            "mapped_data.is_some() was: {}",
            response.mapped_data.is_some()
        );

        let mapped = response.mapped_data.unwrap();

        // Verify no mapping errors
        assert_eq!(
            mapped.errors.len(),
            0,
            "Expected no mapping errors, but got: {:?}",
            mapped.errors
        );

        // Verify all parameters were parsed (flattened from structure)
        assert!(
            mapped.data.contains_key(SID_PARM_NAME),
            "Expected SID parameter to be present"
        );

        // Check exact byte positions for param1 and param2
        // param1: bytes 3 and 4 (after SID and DID)
        let param1_bytes = request_payload.get(3..5).expect("param1 bytes missing");
        let param1_val = match mapped.data.get("param1") {
            Some(crate::diag_kernel::diagservices::DiagDataTypeContainer::RawContainer(raw)) => {
                raw.data.clone()
            }
            _ => panic!("param1 is not RawContainer"),
        };
        assert_eq!(
            param1_bytes,
            &param1_val[..],
            "param1 bytes do not match expected position"
        );

        // param2: bytes 5..9
        let param2_bytes = request_payload.get(5..9).expect("param2 bytes missing");
        let param2_val = match mapped.data.get("param2") {
            Some(crate::diag_kernel::diagservices::DiagDataTypeContainer::RawContainer(raw)) => {
                raw.data.clone()
            }
            _ => panic!("param2 is not RawContainer"),
        };
        assert_eq!(
            param2_bytes,
            &param2_val[..],
            "param2 bytes do not match expected position"
        );

        // param3: bytes 9..13
        let param3_bytes = request_payload.get(9..13).expect("param3 bytes missing");
        let param3_val = match mapped.data.get("param3") {
            Some(crate::diag_kernel::diagservices::DiagDataTypeContainer::RawContainer(raw)) => {
                raw.data.clone()
            }
            _ => panic!("param3 is not RawContainer"),
        };
        assert_eq!(
            param3_bytes,
            &param3_val[..],
            "param3 bytes do not match expected position"
        );
    }

    #[tokio::test]
    async fn test_state_transition_source_allowed_as_valid_security_state() {
        // State transition source states are added to allowed_security states
        let (ecu_manager, dc) =
            create_ecu_manager_with_state_transitions(ServiceSecurityTransition::LockedToExtended);

        // Set ECU to "Locked" state which is the SOURCE of the state transition
        // The service precondition requires "Programming"
        // But the service has a state_transition_ref from "Locked" to "Extended"
        // So "Locked" should be added to allowed security states
        {
            let mut ecu_states = ecu_manager.ecu_service_states.write().await;
            ecu_states.insert(service_ids::SESSION_CONTROL, "DefaultSession".to_string());
            ecu_states.insert(service_ids::SECURITY_ACCESS, "LockedSecurity".to_string());
        }

        let payload_data = UdsPayloadData::Raw(vec![service_ids::WRITE_DATA_BY_IDENTIFIER]);

        let result = ecu_manager
            .create_uds_payload(&dc, &skip_sec_plugin!(), Some(payload_data), None)
            .await;

        assert!(
            result.is_ok(),
            "Service should be allowed from source state of state transition. Error: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_state_precondition() {
        let (ecu_manager, dc) =
            create_ecu_manager_with_state_transitions(ServiceSecurityTransition::LockedToExtended);

        // Set ECU to "Programming" which is in the precondition states
        {
            let mut ecu_states = ecu_manager.ecu_service_states.write().await;
            ecu_states.insert(service_ids::SESSION_CONTROL, "DefaultSession".to_string());
            ecu_states.insert(
                service_ids::SECURITY_ACCESS,
                "ProgrammingSecurity".to_string(),
            );
        }

        let payload_data = UdsPayloadData::Raw(vec![service_ids::WRITE_DATA_BY_IDENTIFIER]);

        // This should succeed because the ECU is in a precondition state
        let result = ecu_manager
            .create_uds_payload(&dc, &skip_sec_plugin!(), Some(payload_data), None)
            .await;

        assert!(
            result.is_ok(),
            "Service should be allowed when in precondition state"
        );
    }

    #[tokio::test]
    async fn test_invalid_security_state_rejected() {
        // Use the shared fixture with ExtendedToProgramming so that the
        // default state (LockedSecurity) is NOT a transition source and
        // therefore not in the allowed set.
        //
        // Allowed security set = {ProgrammingSecurity, ExtendedSecurity}
        //   (precondition + transition source)
        // Default security = LockedSecurity  (NOT in the allowed set)
        let (ecu_manager, dc) = create_ecu_manager_with_state_transitions(
            ServiceSecurityTransition::ExtendedToProgramming,
        );

        // Set ECU security to "LockedSecurity" (the default) - the default is
        // NOT in the allowed set, so neither the actual state nor the default
        // check can pass and the service must be rejected.
        {
            let mut ecu_states = ecu_manager.ecu_service_states.write().await;
            ecu_states.insert(service_ids::SESSION_CONTROL, "DefaultSession".to_string());
            ecu_states.insert(service_ids::SECURITY_ACCESS, "LockedSecurity".to_string());
        }

        let payload_data = UdsPayloadData::Raw(vec![service_ids::WRITE_DATA_BY_IDENTIFIER]);

        let result = ecu_manager
            .create_uds_payload(&dc, &skip_sec_plugin!(), Some(payload_data), None)
            .await;

        assert!(
            result.is_err(),
            "Service should NOT be allowed when neither current nor default security state is in \
             the allowed set"
        );
    }

    #[tokio::test]
    async fn test_functional_group_service_skips_precondition_check() {
        let (ecu_manager, dc, sid) = create_ecu_manager_with_preconditions_and_functional_group();

        // Set ECU to LockedSecurity - does NOT satisfy the ProgrammingSecurity precondition.
        {
            let mut ecu_states = ecu_manager.ecu_service_states.write().await;
            ecu_states.insert(service_ids::SESSION_CONTROL, "DefaultSession".to_string());
            ecu_states.insert(service_ids::SECURITY_ACCESS, "LockedSecurity".to_string());
        }

        // Variant path (functional_group_name = None) must FAIL the precondition.
        let variant_result = ecu_manager
            .create_uds_payload(
                &dc,
                &skip_sec_plugin!(),
                Some(UdsPayloadData::Raw(vec![sid])),
                None,
            )
            .await;
        assert!(
            variant_result.is_err(),
            "Variant service should be rejected when preconditions are not met"
        );

        // Functional group path must SUCCEED - preconditions are not checked.
        let fg_result = ecu_manager
            .create_uds_payload(
                &dc,
                &skip_sec_plugin!(),
                Some(UdsPayloadData::Raw(vec![sid])),
                Some("TestFunctionalGroup"),
            )
            .await;
        assert!(
            fg_result.is_ok(),
            "Functional group service should skip precondition check. Error: {:?}",
            fg_result.err()
        );
    }

    #[tokio::test]
    async fn test_length_key_request_to_uds() {
        let (ecu_manager, dc, sid) = create_ecu_manager_with_length_key_request_service();

        let payload_data = UdsPayloadData::ParameterMap(
            serde_json::from_value(json!({
                "length_indicator": 4,
                "value_param": 500
            }))
            .unwrap(),
        );

        let result = ecu_manager
            .create_uds_payload(&dc, &skip_sec_plugin!(), Some(payload_data), None)
            .await
            .unwrap();

        assert_eq!(result.data, vec![sid, 0x04, 0x01, 0xF4]);
    }

    #[tokio::test]
    async fn test_length_key_request_missing_value_fails() {
        let (ecu_manager, dc, _sid) = create_ecu_manager_with_length_key_request_service();

        let payload_data = UdsPayloadData::ParameterMap(
            serde_json::from_value(json!({"value_param": 500})).unwrap(),
        );

        let result = ecu_manager
            .create_uds_payload(&dc, &skip_sec_plugin!(), Some(payload_data), None)
            .await;

        assert!(result.is_err(), "Missing LENGTH-KEY input must fail");
    }

    #[tokio::test]
    async fn test_length_key_param_encode_zero_length() {
        let (ecu_manager, dc, sid) = create_ecu_manager_with_param_length_info_service();

        let payload_data = UdsPayloadData::ParameterMap(
            serde_json::from_value(json!({"len_key": 0, "var_data": ""})).unwrap(),
        );

        let result = ecu_manager
            .create_uds_payload(&dc, &skip_sec_plugin!(), Some(payload_data), None)
            .await
            .unwrap();

        assert_eq!(result.data, vec![sid, 0x00]);
    }

    #[tokio::test]
    async fn test_length_key_param_encode_nonzero_length() {
        let (ecu_manager, dc, sid) = create_ecu_manager_with_param_length_info_service();

        let payload_data = UdsPayloadData::ParameterMap(
            serde_json::from_value(json!({"len_key": 3, "var_data": "0xAA 0xBB 0xCC"})).unwrap(),
        );

        let result = ecu_manager
            .create_uds_payload(&dc, &skip_sec_plugin!(), Some(payload_data), None)
            .await
            .unwrap();

        assert_eq!(result.data, vec![sid, 0x03, 0xAA, 0xBB, 0xCC]);
    }

    #[tokio::test]
    async fn test_length_key_param_decode_zero_length() {
        let sid = service_ids::WRITE_DATA_BY_IDENTIFIER;
        let pos_sid = sid.saturating_add(UDS_ID_RESPONSE_BITMASK);
        let (ecu_manager, dc, _sid) = create_ecu_manager_with_param_length_info_service();

        assert_uds_converts_to_json(
            &ecu_manager,
            &dc,
            vec![pos_sid, 0x00],
            json!({"pos_sid": u32::from(pos_sid), "len_key": 0, "var_data": ""}),
        )
        .await;
    }

    #[tokio::test]
    async fn test_length_key_param_decode_nonzero_length() {
        let sid = service_ids::WRITE_DATA_BY_IDENTIFIER;
        let pos_sid = sid.saturating_add(UDS_ID_RESPONSE_BITMASK);
        let (ecu_manager, dc, _sid) = create_ecu_manager_with_param_length_info_service();

        assert_uds_converts_to_json(
            &ecu_manager,
            &dc,
            vec![pos_sid, 0x03, 0xAA, 0xBB, 0xCC],
            json!({"pos_sid": u32::from(pos_sid), "len_key": 3, "var_data": "0xAA 0xBB 0xCC"}),
        )
        .await;
    }

    #[tokio::test]
    async fn test_length_key_param_roundtrip() {
        let (ecu_manager, dc, sid) = create_ecu_manager_with_param_length_info_service();
        let pos_sid = sid.saturating_add(UDS_ID_RESPONSE_BITMASK);

        let payload_data = UdsPayloadData::ParameterMap(
            serde_json::from_value(json!({"len_key": 3, "var_data": "0xAA 0xBB 0xCC"})).unwrap(),
        );
        let encoded = ecu_manager
            .create_uds_payload(&dc, &skip_sec_plugin!(), Some(payload_data), None)
            .await
            .unwrap();

        assert_eq!(encoded.data, vec![sid, 0x03, 0xAA, 0xBB, 0xCC]);

        let response_bytes = vec![pos_sid, 0x03, 0xAA, 0xBB, 0xCC];
        let decoded = ecu_manager
            .convert_from_uds(&dc, &create_payload(response_bytes), true, None)
            .await
            .unwrap();

        let json_out = decoded.serialize_to_json().unwrap().data;
        assert_eq!(json_out.get("var_data"), Some(&json!("0xAA 0xBB 0xCC")));
        assert_eq!(json_out.get("len_key"), Some(&json!(3)));
    }

    /// Encodes then decodes a service where a PARAM-LENGTH-INFO field
    /// with non-zero data precedes a trailing fixed-size parameter whose
    /// BYTE-POSITION is omitted (as required by ISO 22901-1 §7.4.8).
    #[tokio::test]
    async fn test_trailing_param_after_param_length_info_roundtrip() {
        let (ecu_manager, dc, sid) =
            create_ecu_manager_with_trailing_param_after_param_length_info_service();
        let pos_sid = sid.saturating_add(UDS_ID_RESPONSE_BITMASK);

        let payload_data = UdsPayloadData::ParameterMap(
            serde_json::from_value(json!({
                "len_key": 3,
                "var_data": "0xAA 0xBB 0xCC",
                "suffix": 500,
            }))
            .unwrap(),
        );

        let encoded = ecu_manager
            .create_uds_payload(&dc, &skip_sec_plugin!(), Some(payload_data), None)
            .await
            .unwrap();

        assert_eq!(
            encoded.data,
            vec![sid, 0x03, 0xAA, 0xBB, 0xCC, 0x01, 0xF4],
            "suffix must be placed after the variable-length data, not at byte 0"
        );

        let response_bytes = vec![pos_sid, 0x03, 0xAA, 0xBB, 0xCC, 0x01, 0xF4];
        let decoded = ecu_manager
            .convert_from_uds(&dc, &create_payload(response_bytes), true, None)
            .await
            .unwrap();

        let json_out = decoded.serialize_to_json().unwrap().data;
        assert_eq!(json_out.get("len_key"), Some(&json!(3)));
        assert_eq!(json_out.get("var_data"), Some(&json!("0xAA 0xBB 0xCC")));
        assert_eq!(
            json_out.get("suffix"),
            Some(&json!(500)),
            "suffix must be decoded from bytes after var_data, not from the (absent) static byte \
             position"
        );
    }

    #[test]
    fn test_get_functional_group_data_info_filters_non_read_services() {
        let ecu_manager = create_ecu_manager_with_mixed_functional_group();

        let result = ecu_manager
            .get_functional_group_data_info(&skip_sec_plugin!(), "MixedGroup")
            .expect("should return Ok");

        assert_eq!(result.len(), 1, "only read services should be returned");
        assert_eq!(
            result.first().expect("Expected element at index 0").id,
            "ReadService"
        );
    }

    #[test]
    fn test_get_functional_group_data_info_no_functional_groups() {
        let mut db_builder = EcuDataBuilder::new();
        let protocol_name = Protocol::default().to_string();
        let protocol = db_builder.create_protocol(&protocol_name, None, None, None);

        // Build a database with no functional groups
        let db = finish_db!(db_builder, protocol, vec![]);
        let ecu_manager = new_ecu_manager(db);

        let result = ecu_manager.get_functional_group_data_info(&skip_sec_plugin!(), "AnyGroup");

        assert!(
            result.is_err(),
            "should fail when database has no functional groups"
        );
        assert!(
            matches!(result, Err(DiagServiceError::InvalidDatabase(_))),
            "expected InvalidDatabase error"
        );
    }
    /// Build an `EcuManager` whose database contains `RoutineControl` services for a
    /// routine named `routine_name`.  `subfunctions` controls which subfunction bytes
    /// (0x01 = Start, 0x02 = Stop, 0x03 = `RequestResults`) are included.
    fn build_ecu_manager_with_routine_subfunctions(
        routine_name: &str,
        subfunctions: &[u8],
    ) -> super::EcuManager<DefaultSecurityPluginData> {
        let mut db_builder = EcuDataBuilder::new();
        let protocol_name = Protocol::default().to_string();
        let protocol = db_builder.create_protocol(&protocol_name, None, None, None);

        let mut services = vec![];
        for &sf in subfunctions {
            let sid_param = db_builder.create_coded_const_param(
                "SID_RQ",
                &service_ids::ROUTINE_CONTROL.to_string(),
                0,
                0,
                8,
                DataType::UInt32,
            );
            let sf_param = db_builder.create_coded_const_param(
                "RoutineControlType",
                &sf.to_string(),
                1,
                0,
                8,
                DataType::UInt32,
            );
            let request = db_builder.create_request(Some(vec![sid_param, sf_param]), None);
            let diag_comm = db_builder.create_diag_comm(DiagCommParams {
                short_name: routine_name,
                diag_class_type: DiagClassType::START_COMM,
                protocols: Some(vec![protocol]),
                ..Default::default()
            });
            services.push(new_diag_service!(
                db_builder,
                diag_comm,
                request,
                vec![],
                vec![]
            ));
        }

        let db = finish_db!(db_builder, protocol, services);
        new_ecu_manager(db)
    }

    /// Build an `EcuManager` with a functional group `fg_name` that contains `RoutineControl`
    /// services for `routine_name` with the given `subfunctions`.
    fn build_ecu_manager_with_fg_routine(
        fg_name: &str,
        routine_name: &str,
        subfunctions: &[u8],
    ) -> super::EcuManager<DefaultSecurityPluginData> {
        let mut db_builder = EcuDataBuilder::new();
        let protocol_name = Protocol::default().to_string();
        let protocol = db_builder.create_protocol(&protocol_name, None, None, None);

        let mut services = vec![];
        for &sf in subfunctions {
            let sid_param = db_builder.create_coded_const_param(
                "SID_RQ",
                &service_ids::ROUTINE_CONTROL.to_string(),
                0,
                0,
                8,
                DataType::UInt32,
            );
            let sf_param = db_builder.create_coded_const_param(
                "RoutineControlType",
                &sf.to_string(),
                1,
                0,
                8,
                DataType::UInt32,
            );
            let request = db_builder.create_request(Some(vec![sid_param, sf_param]), None);
            let diag_comm = db_builder.create_diag_comm(DiagCommParams {
                short_name: routine_name,
                diag_class_type: DiagClassType::START_COMM,
                protocols: Some(vec![protocol]),
                ..Default::default()
            });
            services.push(new_diag_service!(
                db_builder,
                diag_comm,
                request,
                vec![],
                vec![]
            ));
        }

        let fg_diag_layer = db_builder.create_diag_layer(DiagLayerParams {
            short_name: fg_name,
            diag_services: if services.is_empty() {
                None
            } else {
                Some(services)
            },
            ..Default::default()
        });
        let fg = db_builder.create_functional_group(fg_diag_layer, None);
        let db = finish_db_with_functional_groups!(db_builder, protocol, vec![], vec![fg]);
        new_ecu_manager(db)
    }

    /// An ECU DB with only a Start (0x01) service for `"MyRoutine"` should produce
    /// one `ComponentOperationsInfo` with `has_stop = false` and
    /// `has_request_results = false`.
    #[test]
    fn test_get_components_operations_info_start_only() {
        let ecu_manager = build_ecu_manager_with_routine_subfunctions(
            "MyRoutine",
            &[subfunction_ids::routine::START],
        );

        let result = ecu_manager.get_components_operations_info(&skip_sec_plugin!());

        assert_eq!(result.len(), 1, "Expected exactly one operation");
        let op = result.first().expect("Expected at least one operation");
        assert_eq!(op.id, "MyRoutine");
        assert!(!op.has_stop, "Expected has_stop = false");
        assert!(
            !op.has_request_results,
            "Expected has_request_results = false"
        );
    }

    /// An ECU DB with Start (0x01), Stop (0x02), and `RequestResults` (0x03) services
    /// all named `"MyRoutine"` should produce one `ComponentOperationsInfo` with both
    /// `has_stop = true` and `has_request_results = true`.
    #[test]
    fn test_get_components_operations_info_with_stop_and_request_results() {
        let ecu_manager = build_ecu_manager_with_routine_subfunctions(
            "MyRoutine",
            &[
                subfunction_ids::routine::START,
                subfunction_ids::routine::STOP,
                subfunction_ids::routine::REQUEST_RESULTS,
            ],
        );

        let result = ecu_manager.get_components_operations_info(&skip_sec_plugin!());

        assert_eq!(result.len(), 1, "Expected exactly one operation");
        let op = result.first().expect("Expected at least one operation");
        assert_eq!(op.id, "MyRoutine");
        assert!(op.has_stop, "Expected has_stop = true");
        assert!(
            op.has_request_results,
            "Expected has_request_results = true"
        );
    }

    /// An ECU DB with multiple distinct routines; only the ones with a Start
    /// subfunction should appear in the result, each with the correct flags.
    #[test]
    fn test_get_components_operations_info_multiple_routines() {
        let mut db_builder = EcuDataBuilder::new();
        let protocol_name = Protocol::default().to_string();
        let protocol = db_builder.create_protocol(&protocol_name, None, None, None);

        // Build services for RoutineA (Start + Stop) and RoutineB (Start only).
        let mut services = vec![];
        for (name, sfs) in [
            (
                "RoutineA",
                &[
                    subfunction_ids::routine::START,
                    subfunction_ids::routine::STOP,
                ][..],
            ),
            ("RoutineB", &[subfunction_ids::routine::START][..]),
        ] {
            for &sf in sfs {
                let sid_param = db_builder.create_coded_const_param(
                    "SID_RQ",
                    &service_ids::ROUTINE_CONTROL.to_string(),
                    0,
                    0,
                    8,
                    DataType::UInt32,
                );
                let sf_param = db_builder.create_coded_const_param(
                    "RoutineControlType",
                    &sf.to_string(),
                    1,
                    0,
                    8,
                    DataType::UInt32,
                );
                let request = db_builder.create_request(Some(vec![sid_param, sf_param]), None);
                let diag_comm = db_builder.create_diag_comm(DiagCommParams {
                    short_name: name,
                    diag_class_type: DiagClassType::START_COMM,
                    protocols: Some(vec![protocol]),
                    ..Default::default()
                });
                services.push(new_diag_service!(
                    db_builder,
                    diag_comm,
                    request,
                    vec![],
                    vec![]
                ));
            }
        }

        let db = finish_db!(db_builder, protocol, services);
        let ecu_manager = new_ecu_manager(db);

        let mut result = ecu_manager.get_components_operations_info(&skip_sec_plugin!());
        result.sort_by(|a, b| a.id.cmp(&b.id));

        assert_eq!(result.len(), 2);

        let a = result.first().expect("Expected RoutineA");
        assert_eq!(a.id, "RoutineA");
        assert!(a.has_stop);
        assert!(!a.has_request_results);

        let b = result.get(1).expect("Expected RoutineB");
        assert_eq!(b.id, "RoutineB");
        assert!(!b.has_stop);
        assert!(!b.has_request_results);
    }

    /// A DB with no `RoutineControl` services should return an empty list.
    #[test]
    fn test_get_components_operations_info_empty_when_no_routine_control() {
        let mut db_builder = EcuDataBuilder::new();
        let protocol_name = Protocol::default().to_string();
        let protocol = db_builder.create_protocol(&protocol_name, None, None, None);
        let read_request =
            create_sid_only_request!(db_builder, service_ids::READ_DATA_BY_IDENTIFIER);
        let read_diag_comm = new_diag_comm!(db_builder, "SomeData", protocol);
        let service = new_diag_service!(db_builder, read_diag_comm, read_request, vec![], vec![]);
        let db = finish_db!(db_builder, protocol, vec![service]);
        let ecu_manager = new_ecu_manager(db);

        let result = ecu_manager.get_components_operations_info(&skip_sec_plugin!());
        assert!(
            result.is_empty(),
            "Expected no operations for non-routine-control DB"
        );
    }

    /// `get_routine_subfunctions` detects Stop and `RequestResults` when both are present.
    #[test]
    fn test_get_routine_subfunctions_detects_stop_and_request_results() {
        let ecu_manager = build_ecu_manager_with_routine_subfunctions(
            "Routine1",
            &[
                subfunction_ids::routine::START,
                subfunction_ids::routine::STOP,
                subfunction_ids::routine::REQUEST_RESULTS,
            ],
        );

        let subs = ecu_manager
            .get_routine_subfunctions("Routine1", &skip_sec_plugin!())
            .expect("Expected Ok for known routine");
        assert!(subs.has_stop, "Expected has_stop = true");
        assert!(
            subs.has_request_results,
            "Expected has_request_results = true"
        );
    }

    /// `get_routine_subfunctions` returns `false` for both flags when only Start exists.
    #[test]
    fn test_get_routine_subfunctions_no_stop_no_request_results() {
        let ecu_manager = build_ecu_manager_with_routine_subfunctions(
            "Routine1",
            &[subfunction_ids::routine::START],
        );

        let subs = ecu_manager
            .get_routine_subfunctions("Routine1", &skip_sec_plugin!())
            .expect("Expected Ok for known routine");
        assert!(!subs.has_stop, "Expected has_stop = false");
        assert!(
            !subs.has_request_results,
            "Expected has_request_results = false"
        );
    }

    /// `get_routine_subfunctions` uses case-insensitive name matching.
    #[test]
    fn test_get_routine_subfunctions_case_insensitive() {
        let ecu_manager = build_ecu_manager_with_routine_subfunctions(
            "MyRoutine",
            &[
                subfunction_ids::routine::START,
                subfunction_ids::routine::STOP,
            ],
        );

        let subs = ecu_manager
            .get_routine_subfunctions("myroutine", &skip_sec_plugin!())
            .expect("Expected Ok (case-insensitive match)");
        assert!(
            subs.has_stop,
            "Expected has_stop = true (case-insensitive match)"
        );
    }

    /// `get_routine_subfunctions` returns `NotFound` when the Start service is absent.
    #[test]
    fn test_get_routine_subfunctions_returns_not_found_for_unknown_service() {
        let ecu_manager = build_ecu_manager_with_routine_subfunctions(
            "Routine1",
            &[subfunction_ids::routine::START],
        );

        let result =
            ecu_manager.get_routine_subfunctions("NonExistentRoutine", &skip_sec_plugin!());
        assert!(
            matches!(result, Err(DiagServiceError::NotFound(_))),
            "Expected NotFound for unknown service, got: {result:?}"
        );
    }

    /// A functional group containing a `RoutineControl` Start service should be
    /// returned by `get_functional_group_operations_info`.
    #[test]
    fn test_get_functional_group_operations_info_returns_start_service() {
        let ecu_manager = build_ecu_manager_with_fg_routine(
            "TestFG",
            "FgRoutine",
            &[subfunction_ids::routine::START],
        );

        let result = ecu_manager
            .get_functional_group_operations_info(&skip_sec_plugin!(), "TestFG")
            .expect("Expected successful lookup");

        assert_eq!(result.len(), 1, "Expected exactly one FG operation");
        let op = result.first().expect("Expected at least one FG operation");
        assert_eq!(op.id, "FgRoutine");
        assert!(!op.has_stop);
        assert!(!op.has_request_results);
    }

    /// A functional group whose `RoutineControl` Start service also has Stop and
    /// `RequestResults` should reflect that in the flags.
    ///
    /// Note: `get_routine_subfunctions` searches the ECU *variant*, not the FG.
    /// The Stop and `RequestResults` services must therefore be present in the variant
    /// layer (or its parent refs) for the flags to be set.
    #[test]
    fn test_get_functional_group_operations_info_with_stop_and_request_results() {
        let mut db_builder = EcuDataBuilder::new();
        let protocol_name = Protocol::default().to_string();
        let protocol = db_builder.create_protocol(&protocol_name, None, None, None);

        // Build Start, Stop, and RequestResults all in the FG.
        let mut fg_services = vec![];
        for &sf in &[
            subfunction_ids::routine::START,
            subfunction_ids::routine::STOP,
            subfunction_ids::routine::REQUEST_RESULTS,
        ] {
            let sid_p = db_builder.create_coded_const_param(
                "SID_RQ",
                &service_ids::ROUTINE_CONTROL.to_string(),
                0,
                0,
                8,
                DataType::UInt32,
            );
            let sf_p = db_builder.create_coded_const_param(
                "RoutineControlType",
                &sf.to_string(),
                1,
                0,
                8,
                DataType::UInt32,
            );
            let req = db_builder.create_request(Some(vec![sid_p, sf_p]), None);
            let dc = db_builder.create_diag_comm(DiagCommParams {
                short_name: "FgRoutine",
                diag_class_type: DiagClassType::START_COMM,
                protocols: Some(vec![protocol]),
                ..Default::default()
            });
            fg_services.push(new_diag_service!(db_builder, dc, req, vec![], vec![]));
        }

        let fg_diag_layer = db_builder.create_diag_layer(DiagLayerParams {
            short_name: "TestFG",
            diag_services: Some(fg_services),
            ..Default::default()
        });
        let fg = db_builder.create_functional_group(fg_diag_layer, None);
        let db = finish_db_with_functional_groups!(db_builder, protocol, vec![], vec![fg]);
        let ecu_manager = new_ecu_manager(db);

        let result = ecu_manager
            .get_functional_group_operations_info(&skip_sec_plugin!(), "TestFG")
            .expect("Expected successful lookup");

        assert_eq!(result.len(), 1);
        let op = result.first().expect("Expected at least one FG operation");
        assert_eq!(op.id, "FgRoutine");
        assert!(op.has_stop);
        assert!(op.has_request_results);
    }

    /// Querying a functional group that does not exist should return a `NotFound` error.
    #[test]
    fn test_get_functional_group_operations_info_unknown_group() {
        let ecu_manager = build_ecu_manager_with_fg_routine(
            "SomeFG",
            "SomeRoutine",
            &[subfunction_ids::routine::START],
        );

        let result =
            ecu_manager.get_functional_group_operations_info(&skip_sec_plugin!(), "NonExistent");
        assert!(
            matches!(result, Err(DiagServiceError::NotFound(_))),
            "Expected NotFound error for unknown group"
        );
    }

    /// `lookup_diag_service` with `subfunction_id = Some(REQUEST_RESULTS)` locates a DB
    /// service whose `short_name` starts with the base routine name and whose
    /// `request_sub_function_id` equals `0x03`.
    #[tokio::test]
    async fn test_lookup_diag_service_request_results_via_subfunction_id() {
        let ecu_manager = build_ecu_manager_with_routine_subfunctions(
            "MyRoutine_RequestResults",
            &[subfunction_ids::routine::REQUEST_RESULTS],
        );

        // Mirrors how the SOVD handler constructs the DiagComm for RequestResults.
        let diag_comm = DiagComm {
            name: "MyRoutine".to_owned(),
            type_: DiagCommType::Operations,
            lookup_name: None,
            subfunction_id: Some(subfunction_ids::routine::REQUEST_RESULTS),
        };

        let result = ecu_manager
            .lookup_diag_service(&diag_comm, None, None)
            .await;
        assert!(
            result.is_ok(),
            "Expected lookup_diag_service to find RequestResults service, got: {result:?}"
        );
    }

    /// `lookup_diag_service` with `subfunction_id = Some(STOP)` locates a DB service
    /// whose `short_name` starts with the base routine name and whose
    /// `request_sub_function_id` equals `0x02`.
    #[tokio::test]
    async fn test_lookup_diag_service_stop_via_subfunction_id() {
        let ecu_manager = build_ecu_manager_with_routine_subfunctions(
            "MyRoutine_Stop",
            &[subfunction_ids::routine::STOP],
        );

        // Mirrors how the SOVD handler constructs the DiagComm for Stop.
        let diag_comm = DiagComm {
            name: "MyRoutine".to_owned(),
            type_: DiagCommType::Operations,
            lookup_name: None,
            subfunction_id: Some(subfunction_ids::routine::STOP),
        };

        let result = ecu_manager
            .lookup_diag_service(&diag_comm, None, None)
            .await;
        assert!(
            result.is_ok(),
            "Expected lookup_diag_service to find Stop service, got: {result:?}"
        );
    }

    /// `lookup_diag_service` with `subfunction_id = Some(REQUEST_RESULTS)` returns
    /// `NotFound` when no matching service exists in the DB.
    #[tokio::test]
    async fn test_lookup_diag_service_request_results_not_found() {
        // Only a Start service in the DB - no RequestResults.
        let ecu_manager = build_ecu_manager_with_routine_subfunctions(
            "MyRoutine_Start",
            &[subfunction_ids::routine::START],
        );

        let diag_comm = DiagComm {
            name: "MyRoutine".to_owned(),
            type_: DiagCommType::Operations,
            lookup_name: None,
            subfunction_id: Some(subfunction_ids::routine::REQUEST_RESULTS),
        };

        let result = ecu_manager
            .lookup_diag_service(&diag_comm, None, None)
            .await;
        assert!(
            matches!(result, Err(DiagServiceError::NotFound(_))),
            "Expected NotFound error, got: {result:?}"
        );
    }

    /// `lookup_diag_service` with `subfunction_id` that has the SPRMIB bit set
    /// (e.g. `0x83` = `REQUEST_RESULTS | 0x80`) still matches a DB service whose
    /// coded-const subfunction value is `0x03`, because the default mask (`0x7F`)
    /// strips the suppress-positive-response bit before comparing.
    #[tokio::test]
    async fn test_lookup_diag_service_matches_with_sprmib_set() {
        let ecu_manager = build_ecu_manager_with_routine_subfunctions(
            "MyRoutine_RequestResults",
            &[subfunction_ids::routine::REQUEST_RESULTS],
        );

        let diag_comm = DiagComm {
            name: "MyRoutine".to_owned(),
            type_: DiagCommType::Operations,
            lookup_name: None,
            // 0x83 = REQUEST_RESULTS (0x03) | SPRMIB (0x80)
            subfunction_id: Some(subfunction_ids::routine::REQUEST_RESULTS | 0x80),
        };

        let result = ecu_manager
            .lookup_diag_service(&diag_comm, None, None)
            .await;
        assert!(
            result.is_ok(),
            "Expected lookup_diag_service to find RequestResults service even with SPRMIB set, \
             got: {result:?}"
        );
    }

    /// When an explicit `subfunction_mask` of `0xFF` (no masking) is passed,
    /// a subfunction id with the SPRMIB bit set (`0x83`) must NOT match a DB
    /// service with subfunction `0x03`.
    #[tokio::test]
    async fn test_lookup_diag_service_no_match_with_full_mask() {
        let ecu_manager = build_ecu_manager_with_routine_subfunctions(
            "MyRoutine_RequestResults",
            &[subfunction_ids::routine::REQUEST_RESULTS],
        );

        let diag_comm = DiagComm {
            name: "MyRoutine".to_owned(),
            type_: DiagCommType::Operations,
            lookup_name: None,
            subfunction_id: Some(subfunction_ids::routine::REQUEST_RESULTS | 0x80),
        };

        // 0xFF means "compare all 8 bits" - SPRMIB bit will cause a mismatch.
        let result = ecu_manager
            .lookup_diag_service(&diag_comm, None, Some(0xFF))
            .await;
        assert!(
            matches!(result, Err(DiagServiceError::NotFound(_))),
            "Expected NotFound when using mask 0xFF with SPRMIB-set subfunction, got: {result:?}"
        );
    }

    /// With the default mask, `subfunction_id = STOP` (clean, `0x02`) still
    /// matches normally - the mask is a no-op when SPRMIB is not set.
    #[tokio::test]
    async fn test_lookup_diag_service_clean_subfunction_still_matches() {
        let ecu_manager = build_ecu_manager_with_routine_subfunctions(
            "MyRoutine_Stop",
            &[subfunction_ids::routine::STOP],
        );

        let diag_comm = DiagComm {
            name: "MyRoutine".to_owned(),
            type_: DiagCommType::Operations,
            lookup_name: None,
            subfunction_id: Some(subfunction_ids::routine::STOP),
        };

        let result = ecu_manager
            .lookup_diag_service(&diag_comm, None, None)
            .await;
        assert!(
            result.is_ok(),
            "Expected clean subfunction to still match with default mask, got: {result:?}"
        );
    }

    //Static DOP with nested structure decodes inner params at the correct absolute byte positions
    #[tokio::test]
    async fn test_map_static_field_from_uds() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_static_field_service();

        // SID(1) + item0(2) + item1(2) + item2(2) = 7 bytes
        assert_uds_converts_to_json(
            &ecu_manager,
            &service,
            vec![sid, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            json!({
                "test_service_pos_sid": sid,
                "items": [
                    { "item_val": 0x1122u32 },
                    { "item_val": 0x3344u32 },
                    { "item_val": 0x5566u32 },
                ]
            }),
        )
        .await;
    }
    // Static Field returns NotEnoughData when the payload is too short for declared structure size
    #[tokio::test]
    async fn test_map_static_field_from_uds_not_enough_data() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_static_field_service();

        // Only 2 items worth of data (4 bytes) instead of the required 3 items (6 bytes)
        let error =
            assert_uds_conversion_fails(&ecu_manager, &service, vec![sid, 0x11, 0x22, 0x33, 0x44])
                .await;
        assert!(
            matches!(error, DiagServiceError::BadPayload(_)),
            "Expected BadPayload, got: {error:?}"
        );
    }

    // EnvDataDesc selects EnvData whose dtc_values exactly matches the discriminator
    #[tokio::test]
    async fn test_env_data_desc_specific_match() {
        let (ecu_manager, service, sid, specific_dtc, _other_dtc) =
            create_ecu_manager_with_env_data_desc_wildcard();

        let mut payload = vec![sid];
        payload.extend_from_slice(&specific_dtc.to_be_bytes());
        payload.push(0x28); // temperature = 40

        assert_uds_converts_to_json(
            &ecu_manager,
            &service,
            payload,
            json!({
                "test_service_pos_sid": sid,
                "dtc_param": {
                    "code": specific_dtc,
                    "display_code": "P0001",
                    "fault_name": "SpecificFault",
                    "severity": 1,
                },
                "temperature": 0x28u32,
            }),
        )
        .await;
    }
    // EnvDataDesc falls back to wildcard EnvData when no exact match exists
    #[tokio::test]
    async fn test_env_data_desc_wildcard_fallback() {
        let (ecu_manager, service, sid, _specific_dtc, other_dtc) =
            create_ecu_manager_with_env_data_desc_wildcard();

        // other_dtc doesn't match the specific env_data -> wildcard env_data is used
        let mut payload = vec![sid];
        payload.extend_from_slice(&other_dtc.to_be_bytes());
        payload.push(0x55); // humidity = 85

        assert_uds_converts_to_json(
            &ecu_manager,
            &service,
            payload,
            json!({
                "test_service_pos_sid": sid,
                "dtc_param": {
                    "code": other_dtc,
                    "display_code": "P0002",
                    "fault_name": "OtherFault",
                    "severity": 2,
                },
                "humidity": 0x55u32,
            }),
        )
        .await;
    }

    // EnvDataDesc returns an empty map when neither an exact match nor a wildcard match exists
    #[tokio::test]
    async fn test_env_data_desc_no_match_no_wildcard_returns_empty() {
        let (ecu_manager, service, sid, dtc_in_db) = create_ecu_manager_env_data_no_wildcard();

        // dtc_in_db has no matching env_data and there is no wildcard ->
        // env params are absent; DTC itself is decoded normally.
        let mut payload = vec![sid];
        payload.extend_from_slice(&dtc_in_db.to_be_bytes());
        payload.push(0x42);

        assert_uds_converts_to_json(
            &ecu_manager,
            &service,
            payload,
            json!({
                "test_service_pos_sid": sid,
                "dtc_param": {
                    "code": dtc_in_db,
                    "display_code": "P9999",
                    "fault_name": "SomeFault",
                    "severity": 1,
                },
            }),
        )
        .await;
    }

    // a dynamic length fiels param with no byte_position anchors to base_offset,
    // not last_read_byte_pos left over from preceding sibling param
    #[tokio::test]
    async fn test_dlf_no_byte_pos_with_sibling_param() {
        // Regression test: DLF param with has_byte_position=false must anchor to
        // base_offset, not last_read_byte_pos (which a preceding sibling advances).
        //
        // Layout:[SID(0), sibling(1), count(2), item0_hi(3), item0_lo(4), item1_hi(5), item1_lo(6)]
        let (ecu_manager, service, sid) = create_ecu_manager_dlf_sibling_no_byte_pos();

        assert_uds_converts_to_json(
            &ecu_manager,
            &service,
            vec![sid, 0xAB, 0x02, 0x11, 0x22, 0x33, 0x44],
            json!({
                "test_service_pos_sid": sid,
                "sibling_val": 0xABu32,
                "dlf_items": [
                    { "item_val": 0x1122u32 },
                    { "item_val": 0x3344u32 },
                ],
            }),
        )
        .await;
    }
    // verifies that the empty case doesnt misread the item count
    #[tokio::test]
    async fn test_dlf_no_byte_pos_with_sibling_zero_items() {
        let (ecu_manager, service, sid) = create_ecu_manager_dlf_sibling_no_byte_pos();

        // count=0 -> empty array; sibling still decoded correctly
        assert_uds_converts_to_json(
            &ecu_manager,
            &service,
            vec![sid, 0xAB, 0x00],
            json!({
                "test_service_pos_sid": sid,
                "sibling_val": 0xABu32,
                "dlf_items": [],
            }),
        )
        .await;
    }
}
