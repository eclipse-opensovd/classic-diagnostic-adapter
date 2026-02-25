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
    DiagComm, DiagCommAction, DiagCommType, DiagServiceError, DynamicPlugin, EcuManagerType,
    EcuState, EcuVariant, HashMap, HashMapExtensions, HashSet, HashSetExtensions, Protocol,
    STRINGS, SecurityAccess, ServicePayload, StringId,
    datatypes::{
        AddressingMode, CLEAR_FAULT_MEM_POS_RESPONSE_SID, ComParams, ComplexComParamValue,
        ComponentConfigurationsInfo, ComponentDataInfo, DTC_CODE_BIT_LEN, DatabaseNamingConvention,
        DiagnosticServiceAffixPosition, DtcLookup, DtcReadInformationFunction, RetryPolicy, SdSdg,
        TesterPresentSendType, semantics, single_ecu,
    },
    diagservices::{DiagServiceResponse, DiagServiceResponseType, FieldParseError, UdsPayloadData},
    dlt_ctx, service_ids,
    util::{self, ends_with_ignore_ascii_case, starts_with_ignore_ascii_case},
};
use cda_plugin_security::SecurityPlugin;
use tokio::sync::RwLock;

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
    db_cache: DbCache,
    ecu_name: String,
    description_type: EcuManagerType,
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
    variant: EcuVariant,
    fallback_to_base_variant: bool,
    duplicating_ecu_names: Option<HashSet<String>>,

    protocol: Protocol,
    // functional group: protocol prefixed or postfixed
    fg_protocol_position: DiagnosticServiceAffixPosition,
    // functional group: is protocol case sensitive
    fg_protocol_case_sensitive: bool,
    ecu_service_states: Arc<RwLock<HashMap<u8, String>>>,

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

    fn get_variant_detection_requests(&self) -> &HashSet<String> {
        &self.variant_detection.diag_service_requests
    }

    #[tracing::instrument(skip(self),
        fields(
            ecu_name = self.ecu_name,
            dlt_context = dlt_ctx!("CORE"),
        )
    )]
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

    async fn check_genericservice(
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

        self.check_service_access(security_plugin, &mapped_service)
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
            dlt_context = dlt_ctx!("CORE"),
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
            tracing::debug!("No matching response found for SID: {sid}");
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

        self.check_service_access(security_plugin, &mapped_service)
            .await?;

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

        let (mut uds, num_consts) = process_coded_constants(&mapped_params)?;

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
                self.process_parameter_map(&mapped_params, num_consts, &json_values, &mut uds)?;
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
        .ok_or_else(|| {
            DiagServiceError::NotFound(Some(format!(
                "Service with functional class '{func_class_name}' and SID 0x{service_id:02X} not \
                 found"
            )))
        })
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

    fn lookup_service_by_sid_and_name(
        &self,
        service_id: u8,
        name: &str,
    ) -> Result<DiagComm, DiagServiceError> {
        self.lookup_services_by_sid(service_id)?
            .into_iter()
            .find_map(|service| {
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
                })
            })
            .ok_or_else(|| DiagServiceError::NotFound(Some(name.to_owned())))
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
        seed_service: Option<&String>,
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
                        let protocol_value = self.protocol.value();
                        let matches = match self.fg_protocol_position {
                            DiagnosticServiceAffixPosition::Prefix => {
                                if self.fg_protocol_case_sensitive {
                                    name.starts_with(protocol_value)
                                } else {
                                    util::starts_with_ignore_ascii_case(name, protocol_value)
                                }
                            }
                            DiagnosticServiceAffixPosition::Suffix => {
                                if self.fg_protocol_case_sensitive {
                                    name.ends_with(protocol_value)
                                } else {
                                    util::ends_with_ignore_ascii_case(name, protocol_value)
                                }
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
    fn get_service_parameter_metadata(
        &self,
        service_name: &str,
    ) -> Result<Vec<cda_interfaces::ServiceParameterMetadata>, DiagServiceError> {
        use cda_interfaces::ServiceParameterMetadata;
        fn extract_param_type_metadata(
            param: &datatypes::Parameter<'_>,
            service_name: &str,
            name: &str,
        ) -> Result<cda_interfaces::ParameterTypeMetadata, DiagServiceError> {
            use cda_interfaces::ParameterTypeMetadata;

            let param_type = match param.param_type()? {
                datatypes::ParamType::CodedConst => param
                    .specific_data_as_coded_const()
                    .and_then(|cc| cc.coded_value())
                    .map_or(ParameterTypeMetadata::Value, |v| {
                        ParameterTypeMetadata::CodedConst {
                            coded_value: v.to_owned(),
                        }
                    }),
                datatypes::ParamType::PhysConst => param
                    .specific_data_as_phys_const()
                    .and_then(|pc| pc.phys_constant_value())
                    .map_or_else(
                        || {
                            tracing::warn!(
                                "Service '{}' param '{}' PHYS-CONST has no value",
                                service_name,
                                name
                            );
                            ParameterTypeMetadata::Value
                        },
                        |v| ParameterTypeMetadata::PhysConst {
                            phys_constant_value: v.to_owned(),
                        },
                    ),
                _ => ParameterTypeMetadata::Value,
            };

            Ok(param_type)
        }

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
                let param_type = extract_param_type_metadata(&param, service_name, &name).ok()?;

                Some(ServiceParameterMetadata {
                    name,
                    semantic,
                    param_type,
                })
            })
            .collect();

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
        let mapped_service = self.lookup_diag_service(diag_service).await?;
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

        let nack_number_of_retries = database
            .find_com_param(&data_protocol, &com_params.doip.nack_number_of_retries)
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
                .find_com_param(&data_protocol, &com_params.doip.logical_tester_address),
            logical_address: logical_ecu_address,
            logical_gateway_address,
            logical_functional_address,
            nack_number_of_retries,
            diagnostic_ack_timeout: database
                .find_com_param(&data_protocol, &com_params.doip.diagnostic_ack_timeout),
            retry_period: database.find_com_param(&data_protocol, &com_params.doip.retry_period),
            routing_activation_timeout: database
                .find_com_param(&data_protocol, &com_params.doip.routing_activation_timeout),
            repeat_request_count_transmission: database.find_com_param(
                &data_protocol,
                &com_params.doip.repeat_request_count_transmission,
            ),
            connection_timeout: database
                .find_com_param(&data_protocol, &com_params.doip.connection_timeout),
            connection_retry_delay: database
                .find_com_param(&data_protocol, &com_params.doip.connection_retry_delay),
            connection_retry_attempts: database
                .find_com_param(&data_protocol, &com_params.doip.connection_retry_attempts),
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
            fg_protocol_case_sensitive: func_description_config.protocol_case_sensitive,
            ecu_service_states: Arc::new(RwLock::default()),
            tester_present_retry_policy: database
                .find_com_param(&data_protocol, &com_params.uds.tester_present_retry_policy)
                .into(),
            tester_present_addr_mode: database
                .find_com_param(&data_protocol, &com_params.uds.tester_present_addr_mode),
            tester_present_response_expected: database
                .find_com_param(
                    &data_protocol,
                    &com_params.uds.tester_present_response_expected,
                )
                .into(),
            tester_present_send_type: database
                .find_com_param(&data_protocol, &com_params.uds.tester_present_send_type),
            tester_present_message: database
                .find_com_param(&data_protocol, &com_params.uds.tester_present_message),
            tester_present_exp_pos_resp: database
                .find_com_param(&data_protocol, &com_params.uds.tester_present_exp_pos_resp),
            tester_present_exp_neg_resp: database
                .find_com_param(&data_protocol, &com_params.uds.tester_present_exp_neg_resp),
            tester_present_time: database
                .find_com_param(&data_protocol, &com_params.uds.tester_present_time),
            repeat_req_count_app: database
                .find_com_param(&data_protocol, &com_params.uds.repeat_req_count_app),
            rc_21_retry_policy: database
                .find_com_param(&data_protocol, &com_params.uds.rc_21_retry_policy),
            rc_21_completion_timeout: database
                .find_com_param(&data_protocol, &com_params.uds.rc_21_completion_timeout),
            rc_21_repeat_request_time: database
                .find_com_param(&data_protocol, &com_params.uds.rc_21_repeat_request_time),
            rc_78_retry_policy: database
                .find_com_param(&data_protocol, &com_params.uds.rc_78_retry_policy),
            rc_78_completion_timeout: database
                .find_com_param(&data_protocol, &com_params.uds.rc_78_completion_timeout),
            rc_78_timeout: database.find_com_param(&data_protocol, &com_params.uds.rc_78_timeout),
            rc_94_retry_policy: database
                .find_com_param(&data_protocol, &com_params.uds.rc_94_retry_policy),
            rc_94_completion_timeout: database
                .find_com_param(&data_protocol, &com_params.uds.rc_94_completion_timeout),
            rc_94_repeat_request_time: database
                .find_com_param(&data_protocol, &com_params.uds.rc_94_repeat_request_time),
            timeout_default: database
                .find_com_param(&data_protocol, &com_params.uds.timeout_default),
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
        let logical_ecu_address = com_params.doip.logical_ecu_address.default;
        let nack_number_of_retries = com_params
            .doip
            .nack_number_of_retries
            .default
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
            tester_address: com_params.doip.logical_tester_address.default,
            logical_address: logical_ecu_address,
            logical_gateway_address: com_params.doip.logical_gateway_address.default,
            logical_functional_address: com_params.doip.logical_functional_address.default,
            nack_number_of_retries,
            diagnostic_ack_timeout: com_params.doip.diagnostic_ack_timeout.default,
            retry_period: com_params.doip.retry_period.default,
            routing_activation_timeout: com_params.doip.routing_activation_timeout.default,
            repeat_request_count_transmission: com_params
                .doip
                .repeat_request_count_transmission
                .default,
            connection_timeout: com_params.doip.connection_timeout.default,
            connection_retry_delay: com_params.doip.connection_retry_delay.default,
            connection_retry_attempts: com_params.doip.connection_retry_attempts.default,
            variant_detection: VariantDetection {
                diag_service_requests: HashSet::new(),
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
            fg_protocol_case_sensitive: func_description_config.protocol_case_sensitive,
            ecu_service_states: Arc::new(RwLock::default()),
            tester_present_retry_policy: com_params
                .uds
                .tester_present_retry_policy
                .default
                .clone()
                .into(),
            tester_present_addr_mode: com_params.uds.tester_present_addr_mode.default.clone(),
            tester_present_response_expected: com_params
                .uds
                .tester_present_response_expected
                .default
                .clone()
                .into(),
            tester_present_send_type: com_params.uds.tester_present_send_type.default.clone(),
            tester_present_message: com_params.uds.tester_present_message.default.clone(),
            tester_present_exp_pos_resp: com_params.uds.tester_present_exp_pos_resp.default.clone(),
            tester_present_exp_neg_resp: com_params.uds.tester_present_exp_neg_resp.default.clone(),
            tester_present_time: com_params.uds.tester_present_time.default,
            repeat_req_count_app: com_params.uds.repeat_req_count_app.default,
            rc_21_retry_policy: com_params.uds.rc_21_retry_policy.default.clone(),
            rc_21_completion_timeout: com_params.uds.rc_21_completion_timeout.default,
            rc_21_repeat_request_time: com_params.uds.rc_21_repeat_request_time.default,
            rc_78_retry_policy: com_params.uds.rc_78_retry_policy.default.clone(),
            rc_78_completion_timeout: com_params.uds.rc_78_completion_timeout.default,
            rc_78_timeout: com_params.uds.rc_78_timeout.default,
            rc_94_retry_policy: com_params.uds.rc_94_retry_policy.default.clone(),
            rc_94_completion_timeout: com_params.uds.rc_94_completion_timeout.default,
            rc_94_repeat_request_time: com_params.uds.rc_94_repeat_request_time.default,
            timeout_default: com_params.uds.timeout_default.default,
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

    fn variant(&self) -> Option<datatypes::Variant<'_>> {
        let idx = self.variant_index?;
        let variants = self.diag_database.ecu_data().ok()?.variants()?;
        Some(variants.get(idx).into())
    }

    #[tracing::instrument(skip_all,
        fields(
            dlt_context = dlt_ctx!("CORE"),
        )
    )]
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

        Err(DiagServiceError::NotFound(Some(format!(
            "Diagnostic service '{lookup_name}' not found in variant or parent refs"
        ))))
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
            let all_services: Vec<datatypes::DiagService<'a>> = parent_refs
                .into_iter()
                .filter_map(|parent_ref| {
                    let parent_ref = parent_ref.into();

                    match parent_ref.ref_type().try_into() {
                        Ok(datatypes::ParentRefType::EcuSharedData) => Some(
                            parent_ref
                                .ref__as_ecu_shared_data()?
                                .diag_layer()?
                                .diag_services()?
                                .iter()
                                .map(datatypes::DiagService)
                                .collect::<Vec<_>>(),
                        ),
                        Ok(datatypes::ParentRefType::FunctionalGroup) => parent_ref
                            .ref__as_functional_group()
                            .and_then(|fg| fg.parent_refs())
                            .and_then(|nested_refs| {
                                find_ecu_shared_services_recursive(
                                    nested_refs.iter().map(datatypes::ParentRef),
                                )
                            }),
                        Ok(datatypes::ParentRefType::Protocol) => Some(
                            parent_ref
                                .ref__as_protocol()?
                                .diag_layer()?
                                .diag_services()?
                                .iter()
                                .map(datatypes::DiagService)
                                .collect::<Vec<_>>(),
                        ),
                        _ => {
                            tracing::error!(
                                "Unsupported ParentRefType in ECU shared service lookup."
                            );
                            None
                        }
                    }
                })
                .flatten()
                .collect();

            if all_services.is_empty() {
                None
            } else {
                Some(all_services)
            }
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

    #[tracing::instrument(skip_all,
        fields(
            dlt_context = dlt_ctx!("CORE"),
        )
    )]
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
                self.map_param_phys_const_from_uds(
                    mapped_service,
                    param,
                    param_name,
                    uds_payload,
                    data,
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

        let value = operations::extract_diag_data_container(
            param.short_name(),
            param.byte_position() as usize,
            param.bit_position() as usize,
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
                        param.short_name().unwrap_or_default()
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

    fn map_param_phys_const_from_uds(
        &self,
        mapped_service: &datatypes::DiagService,
        param: &datatypes::Parameter,
        param_name: &str,
        uds_payload: &mut Payload,
        data: &mut MappedDiagServiceResponsePayload,
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

        // Handle different DOP variants - PhysConst can have Normal or Structure DOPs
        match dop.variant()? {
            datatypes::DataOperationVariant::Normal(normal_dop) => {
                let diag_type = normal_dop.diag_coded_type()?;
                let value = operations::extract_diag_data_container(
                    param.short_name(),
                    param.byte_position() as usize,
                    param.bit_position() as usize,
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
                self.map_dop_from_uds(mapped_service, &dop, param, uds_payload, data)?;
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

                self.map_param_to_uds(&param, value.get(short_name), payload, struct_byte_pos)
            })
    }

    fn process_parameter_map(
        &self,
        mapped_params: &[datatypes::Parameter],
        num_consts: usize,
        json_values: &HashMap<String, serde_json::Value>,
        uds: &mut Vec<u8>,
    ) -> Result<(), DiagServiceError> {
        for param in mapped_params.iter().skip(num_consts) {
            if uds.len() < param.byte_position() as usize {
                uds.extend(vec![
                    0x0;
                    (param.byte_position() as usize)
                        .saturating_sub(uds.len())
                ]);
            }
            let short_name = param.short_name().ok_or_else(|| {
                DiagServiceError::InvalidDatabase(format!(
                    "Unable to find short name for param: {}",
                    param.short_name().unwrap_or_default()
                ))
            })?;

            // Setting parent byte position
            // to 0 because this is the uppermost level.
            self.map_param_to_uds(param, json_values.get(short_name), uds, 0)?;
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
            datatypes::ParamType::LengthKey => Err(DiagServiceError::ParameterConversionError(
                "Mapping LengthKey DoP to UDS payload not implemented".to_owned(),
            )),
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

    #[tracing::instrument(skip_all,
        fields(
            dlt_context = dlt_ctx!("CORE"),
        )
    )]
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

    #[tracing::instrument(skip_all,
        fields(
            dlt_context = dlt_ctx!("CORE"),
        )
    )]
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
        uds_payload.set_last_read_byte_pos(num_items_byte_pos.saturating_add(num_items_data.len()));

        let mut repeated_data = Vec::new();

        uds_payload.push_slice(
            dynamic_length_field_dop.offset() as usize,
            uds_payload.len(),
        )?;
        let mut start = uds_payload
            .last_read_byte_pos()
            .saturating_add(uds_payload.bytes_to_skip());

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
            start = start.saturating_add(
                uds_payload
                    .last_read_byte_pos()
                    .saturating_add(uds_payload.bytes_to_skip()),
            );
        }
        uds_payload.pop_slice()?;
        uds_payload.set_last_read_byte_pos(start.saturating_sub(1));
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
            let param_byte_pos = param.byte_position();
            let start = param_byte_pos
                .saturating_add(i.saturating_mul(static_field_dop.item_byte_size()))
                as usize;
            let end = start.saturating_add(static_field_dop.item_byte_size() as usize);
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
        if let Some(byte_size) = structure_dop.byte_size() {
            let byte_size = byte_size as usize;
            if uds_payload.len() < byte_size {
                return Err(DiagServiceError::NotEnoughData {
                    expected: byte_size,
                    actual: uds_payload.len(),
                });
            }
        }

        if let Some(params) = structure_dop.params() {
            for param in params.iter().map(datatypes::Parameter) {
                self.map_param_from_uds(mapped_service, &param, short_name, uds_payload, data)?;
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
                param.short_name(),
                param.byte_position() as usize,
                param.bit_position() as usize,
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

    fn lookup_services_by_sid(
        &self,
        service_id: u8,
    ) -> Result<Vec<datatypes::DiagService<'_>>, DiagServiceError> {
        let services = self
            .variant()
            .and_then(|v| v.diag_layer().and_then(|dl| dl.diag_services()))
            .into_iter()
            .flatten()
            .chain(
                self.diag_database
                    .base_variant()
                    .ok()
                    .and_then(|base| base.diag_layer())
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
                DiagServiceError::NotFound(Some(format!("Service '{service_name}' not found")))
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

        let validate_state = |required: &HashSet<String>,
                              current: &str,
                              state_type: &str|
         -> Result<(), DiagServiceError> {
            if required.is_empty() || required.contains(current) {
                Ok(())
            } else {
                Err(DiagServiceError::InvalidState(format!(
                    "{service} - {state_type} mismatch. Required one of: {required:?}, Current: \
                     {current}",
                    service = diag_comm.short_name().unwrap_or("None"),
                )))
            }
        };

        validate_state(&allowed_security, &ecu_security_level, "Security level")?;
        validate_state(&allowed_session, &ecu_session, "Session")
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
) -> Result<(Vec<u8>, usize), DiagServiceError> {
    let mut uds: Vec<u8> = Vec::new();
    let mut num_consts = 0usize;

    for param in mapped_params {
        if let Some(coded_const) = param.specific_data_as_coded_const() {
            num_consts = num_consts.saturating_add(1);
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

    Ok((uds, num_consts))
}

#[cfg(test)]
mod tests {
    use std::vec;

    use cda_database::datatypes::{
        DataType, DiagCodedTypeVariant, Limit, ResponseType,
        database_builder::{
            Addressing, DiagClassType, DiagCommParams, DiagLayerParams, DiagServiceParams, DopType,
            EcuDataBuilder, EcuDataParams, SpecificDOPData, TransmissionMode,
        },
    };
    use cda_interfaces::{EcuManager, Protocol, UDS_ID_RESPONSE_BITMASK};
    use cda_plugin_security::DefaultSecurityPluginData;
    use flatbuffers::WIPOffset;
    use serde_json::json;

    use super::*;

    const SID_PARM_NAME: &str = "sid";

    macro_rules! skip_sec_plugin {
        () => {{
            let skip_sec_plugin: DynamicPlugin = Box::new(());
            skip_sec_plugin
        }};
    }

    /// Helper: finish an `EcuDataBuilder` into a `DiagnosticDatabase` containing
    /// a single variant with one `DiagLayer` that holds the given diag services.
    ///
    /// Delegates to [`EcuDataBuilder::finish_with_single_variant`] with
    /// hardcoded test defaults for layer name, ECU name, revision and version.
    macro_rules! finish_db {
        ($builder:expr, $protocol:expr, $diag_services:expr) => {
            $builder.finish_with_single_variant(
                $protocol,
                $diag_services,
                "TestLayer",
                "TestEcu",
                "1",
                "1.0.0",
            )
        };
    }

    /// Helper: build a `DiagComm` flatbuffer node with test-default fields.
    macro_rules! new_diag_comm {
        ($builder:expr, $name:expr, $protocol:expr) => {
            $builder.create_diag_comm(DiagCommParams {
                short_name: $name,
                diag_class_type: DiagClassType::START_COMM,
                protocols: Some(vec![$protocol]),
                ..Default::default()
            })
        };
    }

    /// Helper: build a `DiagService` flatbuffer node with test-default fields.
    macro_rules! new_diag_service {
        ($builder:expr, $diag_comm:expr, $request:expr, $pos:expr, $neg:expr) => {
            $builder.create_diag_service(DiagServiceParams {
                diag_comm: Some($diag_comm),
                request: Some($request),
                pos_responses: $pos,
                neg_responses: $neg,
                addressing: *Addressing::FUNCTIONAL_OR_PHYSICAL,
                transmission_mode: *TransmissionMode::SEND_AND_RECEIVE,
                ..Default::default()
            })
        };
    }

    /// Helper macro: create a CODED-CONST SID parameter at byte position 0.
    macro_rules! create_sid_param {
        ($builder:expr, $name:expr, $sid:expr) => {
            $builder.create_coded_const_param($name, &$sid.to_string(), 0, 0, 8, DataType::UInt32)
        };
        ($builder:expr, $sid:expr) => {
            create_sid_param!($builder, SID_PARM_NAME, $sid)
        };
    }

    /// Helper macro: create a request containing only a SID parameter.
    macro_rules! create_sid_only_request {
        ($builder:expr, $name:expr, $sid:expr) => {{
            let sid_param = create_sid_param!($builder, $name, $sid);
            $builder.create_request(Some(vec![sid_param]), None)
        }};
        ($builder:expr, $sid:expr) => {
            create_sid_only_request!($builder, SID_PARM_NAME, $sid)
        };
    }

    /// Helper macro: create a positive response with a SID param and one value param.
    macro_rules! create_pos_response_with_param {
        ($builder:expr, $sid:expr, $param_name:expr, $dop:expr, $byte_pos:expr) => {{
            let sid_param = create_sid_param!($builder, "test_service_pos_sid", $sid);
            let value_param = $builder.create_value_param($param_name, $dop, $byte_pos, 0);
            $builder.create_response(
                ResponseType::Positive,
                Some(vec![sid_param, value_param]),
                None,
            )
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
            .convert_from_uds(service, &create_payload(payload_data), true)
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
            .convert_from_uds(service, &create_payload(payload_data), true)
            .await
            .unwrap_err()
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum EndOfPduStructureType {
        FixedSize,
        LeadingLengthDop,
    }

    fn new_ecu_manager(
        db: datatypes::DiagnosticDatabase,
    ) -> super::EcuManager<DefaultSecurityPluginData> {
        super::EcuManager::new(
            db,
            Protocol::DoIp,
            &ComParams::default(),
            DatabaseNamingConvention::default(),
            EcuManagerType::Ecu,
            &cda_interfaces::FunctionalDescriptionConfig {
                description_database: "functional_groups".to_owned(),
                enabled_functional_groups: None,
                protocol_position:
                    cda_interfaces::datatypes::DiagnosticServiceAffixPosition::Suffix,
                protocol_case_sensitive: false,
            },
            true,
        )
        .unwrap()
    }

    fn new_ecu_manager_no_base_fallback(
        db: datatypes::DiagnosticDatabase,
    ) -> super::EcuManager<DefaultSecurityPluginData> {
        super::EcuManager::new(
            db,
            Protocol::DoIp,
            &ComParams::default(),
            DatabaseNamingConvention::default(),
            EcuManagerType::Ecu,
            &cda_interfaces::FunctionalDescriptionConfig {
                description_database: "functional_groups".to_owned(),
                enabled_functional_groups: None,
                protocol_position:
                    cda_interfaces::datatypes::DiagnosticServiceAffixPosition::Suffix,
                protocol_case_sensitive: false,
            },
            false,
        )
        .unwrap()
    }

    /// Creates an ECU manager with a diagnostic service containing a `DynamicLengthField` DOP.
    ///
    /// # Database contents:
    /// - **Service**: `TestDynamicLengthFieldService` (SID: 0x2E - `WriteDataByIdentifier`)
    /// - **Request**: Contains a `num_items` parameter (u8) that specifies the count
    /// - **Response**: Contains a `dynamic_length_field_dop`
    ///   that repeats a structure based on `num_items`
    ///   - Each repeated structure contains `item_param` (u16)
    /// - **DOPs**: `NormalDOP` for `num_items`, `DynamicLengthField` DOP for response
    // allowed because creation of test data should keep together
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
        let compu_identical =
            db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);

        // Create DOPs for structure parameters
        let num_items_dop =
            db_builder.create_regular_normal_dop("num_items_dop", u8_diag_type, compu_identical);

        // Create the structure for the repeated item
        let repeated_struct = {
            let item_param_dop = db_builder.create_regular_normal_dop(
                "item_param_dop",
                u16_diag_type,
                compu_identical,
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

        let sid = service_ids::WRITE_DATA_BY_IDENTIFIER;
        let dc_name = "TestDynamicLengthFieldService";
        let diag_comm = new_diag_comm!(db_builder, dc_name, protocol);

        let request = {
            let sid_param = create_sid_param!(db_builder, sid);
            let request_num_items_param =
                db_builder.create_value_param("num_items", num_items_dop, 1, 0);
            db_builder.create_request(Some(vec![sid_param, request_num_items_param]), None)
        };

        // Build response
        let pos_response = create_pos_response_with_param!(
            db_builder,
            sid,
            "pos_response_param",
            dynamic_length_field_dop,
            1
        );

        let neg_response = {
            let nack_param = db_builder.create_coded_const_param(
                "test_service_nack",
                &service_ids::NEGATIVE_RESPONSE.to_string(),
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

        let diag_service = new_diag_service!(
            db_builder,
            diag_comm,
            request,
            vec![pos_response],
            vec![neg_response]
        );

        let db = finish_db!(db_builder, protocol, vec![diag_service]);
        (
            new_ecu_manager(db),
            cda_interfaces::DiagComm::new(dc_name, DiagCommType::Configurations),
            sid,
        )
    }

    /// Creates an ECU manager with a service
    /// containing different parameter types for metadata testing.
    ///
    /// # Database contents:
    /// - **Service**: `RDBI_TestService` (SID: 0x22 - `ReadDataByIdentifier`)
    /// - **Request**: Contains three parameter types:
    ///   - `sid`: CODED-CONST parameter (value: "34")
    ///   - `RDBI_DID`: CODED-CONST parameter (value: "0xF190" = 61840)
    ///   - `data`: VALUE parameter (u16)
    /// - **Response**: Contains positive response SID
    ///
    /// This helper is used to test parameter metadata extraction, including
    /// distinguishing between CODED-CONST and VALUE parameter types.
    fn create_ecu_manager_with_parameter_metadata() -> super::EcuManager<DefaultSecurityPluginData>
    {
        let mut db_builder = EcuDataBuilder::new();
        let protocol = db_builder.create_protocol(Protocol::DoIp.value(), None, None, None);
        let compu_identical =
            db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);
        let u16_diag_type = db_builder.create_diag_coded_type_standard_length(16, DataType::UInt32);

        // Create a service with CODED-CONST parameters
        let sid = service_ids::READ_DATA_BY_IDENTIFIER;
        let dc_name = "RDBI_TestService";

        // Create DOP for VALUE parameter
        let value_dop =
            db_builder.create_regular_normal_dop("value_dop", u16_diag_type, compu_identical);

        let diag_comm = new_diag_comm!(db_builder, dc_name, protocol);

        // Create request with CODED-CONST and VALUE parameters
        let request = {
            let sid_param = create_sid_param!(db_builder, sid);
            let did_param = db_builder.create_coded_const_param(
                "RDBI_DID",
                "0xF190",
                1,
                0,
                16,
                DataType::UInt32,
            );
            let value_param = db_builder.create_value_param("data", value_dop, 3, 0);
            db_builder.create_request(Some(vec![sid_param, did_param, value_param]), None)
        };

        let pos_response = {
            let sid_param =
                create_sid_param!(db_builder, "pos_sid", (sid + UDS_ID_RESPONSE_BITMASK));
            db_builder.create_response(ResponseType::Positive, Some(vec![sid_param]), None)
        };

        let diag_service =
            new_diag_service!(db_builder, diag_comm, request, vec![pos_response], vec![]);

        let db = finish_db!(db_builder, protocol, vec![diag_service]);
        new_ecu_manager(db)
    }

    /// Creates an ECU manager with a diagnostic service containing a Structure DOP.
    ///
    /// # Database contents:
    /// - **Service**: `TestStructService` (SID: 0x2E - `WriteDataByIdentifier`)
    /// - **Request**: Contains a `main_param` that is a Structure DOP
    ///   - `param1`: u16
    ///   - `param2`: f32
    ///   - `param3`: ASCII string (32 bits)
    /// - **Structure**: 10 bytes total (2 + 4 + 4)
    /// - **DOPs**: `NormalDOPs` for each parameter, wrapped in a Structure DOP
    ///
    /// # Parameters:
    /// - `struct_byte_pos`: The byte position where the structure starts in the payload
    // allowed because creation of test data should kept together
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
        let compu_identical =
            db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);

        // Create the structure with parameters
        let (structure_dop, structure_byte_len) = {
            let u16_diag_type =
                db_builder.create_diag_coded_type_standard_length(16, DataType::UInt32);
            let f32_diag_type =
                db_builder.create_diag_coded_type_standard_length(32, DataType::Float32);
            let ascii_diag_type =
                db_builder.create_diag_coded_type_standard_length(32, DataType::AsciiString);

            // Create DOPs for structure parameters
            let param1_dop =
                db_builder.create_regular_normal_dop("param1_dop", u16_diag_type, compu_identical);
            let param2_dop =
                db_builder.create_regular_normal_dop("param2_dop", f32_diag_type, compu_identical);
            let param3_dop = db_builder.create_regular_normal_dop(
                "param3_dop",
                ascii_diag_type,
                compu_identical,
            );

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

        let sid = service_ids::WRITE_DATA_BY_IDENTIFIER;
        let dc_name = "TestStructService";
        let diag_comm = new_diag_comm!(db_builder, dc_name, protocol);

        let request = {
            let sid_param = create_sid_param!(db_builder, sid);
            let main_param =
                db_builder.create_value_param("main_param", structure_dop, struct_byte_pos, 0);
            db_builder.create_request(Some(vec![sid_param, main_param]), None)
        };

        let diag_service = new_diag_service!(db_builder, diag_comm, request, vec![], vec![]);

        let db = finish_db!(db_builder, protocol, vec![diag_service]);
        (
            new_ecu_manager(db),
            cda_interfaces::DiagComm::new(dc_name, DiagCommType::Configurations),
            sid,
            structure_byte_len,
        )
    }

    /// Creates an ECU manager with a MUX service that includes a default case.
    ///
    /// # Database contents:
    /// - **Service**: `TestMuxService` (SID: `ReadDataByIdentifier` - 0x22)
    /// - **MUX DOP**: Multiplexer with switch key and cases
    ///   - **Switch key**: u16 at byte position 0
    ///   - **Case 1** (range 1-10): Contains f32 and u8 parameters
    ///   - **Case 2** (range 11-600): Contains i16 and ASCII string parameters
    ///   - **Case 3** (string "test"): No structure
    ///   - **Default case**: Contains `default_structure_param_1` (u8)
    /// - **Request and Response**: Both contain the MUX parameter
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
            let default_structure_param_1_dop = db_builder.create_regular_normal_dop(
                "default_structure_param_1_dop",
                u8_diag_type,
                compu_identical,
            );
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

    /// Creates an ECU manager with a MUX (multiplexer) service.
    ///
    /// # Database contents:
    /// - **Service**: `TestMuxService` (SID: `ReadDataByIdentifier` - 0x22)
    /// - **MUX DOP**: Multiplexer with configurable switch key and cases
    ///   - **Switch key**: Configurable via parameter, defaults to u16 at byte position 0
    ///   - **Case 1** (range 1-10):
    ///     - `mux_1_case_1_param_1`: f32 at byte 0
    ///     - `mux_1_case_1_param_2`: u8 at byte 4
    ///   - **Case 2** (range 11-600):
    ///     - `mux_1_case_2_param_1`: i16 at byte 1
    ///     - `mux_1_case_2_param_2`: ASCII string (32 bits) at byte 4
    ///   - **Case 3** (string "test"): No structure
    ///   - **Default case**: Optional, configurable via parameter
    /// - **Request and Response**: Both contain the MUX parameter at byte position 2
    ///
    /// # Parameters:
    /// - `db_builder`: Optional pre-configured builder (creates new if None)
    /// - `switch_key`: Optional custom switch key (creates default u16 if None)
    /// - `default_case`: Optional default case for unmatched switch values
    // allowed because creation of test data should kept together
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
        let compu_identical =
            db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);

        // Create DOPs for case 1 parameters
        let mux_1_case_1_params_dop_1 = db_builder.create_regular_normal_dop(
            "mux_1_case_1_params_dop_1",
            f32_diag_type,
            compu_identical,
        );
        let mux_1_case_1_params_dop_2 = db_builder.create_regular_normal_dop(
            "mux_1_case_1_params_dop_2",
            u8_diag_type,
            compu_identical,
        );

        // Create DOPs for case 2 parameters
        let mux_1_case_2_params_dop_1 = db_builder.create_regular_normal_dop(
            "mux_1_case_2_params_dop_1",
            i16_diag_type,
            compu_identical,
        );
        let mux_1_case_2_params_dop_2 = db_builder.create_regular_normal_dop(
            "mux_1_case_2_params_dop_2",
            ascii_diag_type,
            compu_identical,
        );

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
            let switch_key_dop = db_builder.create_regular_normal_dop(
                "switch_key_dop",
                u16_diag_type,
                compu_identical,
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

        let sid = service_ids::READ_DATA_BY_IDENTIFIER;
        let dc_name = "TestMuxService";
        let diag_comm = new_diag_comm!(db_builder, dc_name, protocol);

        // Create request with mux parameter
        let request = {
            let sid_param = create_sid_param!(db_builder, sid);
            let mux_param = db_builder.create_value_param("mux_1_param", mux_dop, 2, 0);
            db_builder.create_request(Some(vec![sid_param, mux_param]), None)
        };

        // Create response with mux parameter
        let pos_response =
            create_pos_response_with_param!(db_builder, sid, "mux_1_param", mux_dop, 2);

        let diag_service =
            new_diag_service!(db_builder, diag_comm, request, vec![pos_response], vec![]);

        let db = finish_db!(db_builder, protocol, vec![diag_service]);
        (
            new_ecu_manager(db),
            cda_interfaces::DiagComm::new(dc_name, DiagCommType::Data),
            sid,
        )
    }

    /// Creates an ECU manager with an `EndOfPdu` service for variable-length repeated structures.
    ///
    /// # Database contents:
    /// - **Service**: `TestEndOfPduService` (SID: `ReadDataByIdentifier` - 0x22)
    /// - **Request**: Simple request with only SID
    /// - **Response**: Contains an `end_pdu_param` with `EndOfPdu` DOP
    ///   - Repeats a structure until end of payload
    ///   - **Structure type** (configurable):
    ///     - **`FixedSize`**: Each item is 3 bytes
    ///       - `item_param1`: u8 at byte 0
    ///       - `item_param2`: u16 at byte 1
    ///     - **`LeadingLengthDop`**: Variable-size items with 8-bit length prefix
    ///       - `data`: `ByteField` with leading length info
    ///   - **Constraints**:
    ///   - `min_items`: Minimum number of items required
    ///   - `max_items`: Optional maximum number of items allowed
    ///
    /// # Parameters:
    /// - `min_items`: Minimum number of structures required
    /// - `max_items`: Optional maximum number of structures
    /// - `structure_type`: Whether structures are fixed-size or have leading length
    // allowed because creation of test data should kept together
    fn create_ecu_manager_with_end_pdu_service(
        min_items: u32,
        max_items: Option<u32>,
        structure_type: EndOfPduStructureType,
    ) -> (
        super::EcuManager<DefaultSecurityPluginData>,
        cda_interfaces::DiagComm,
        u8,
    ) {
        let mut db_builder = EcuDataBuilder::new();
        let u8_diag_type = db_builder.create_diag_coded_type_standard_length(8, DataType::UInt32);
        let u16_diag_type = db_builder.create_diag_coded_type_standard_length(16, DataType::UInt32);
        let protocol = db_builder.create_protocol(Protocol::DoIp.value(), None, None, None);
        let compu_identical =
            db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);

        // Create the structure that will be repeated in EndOfPdu
        let item_structure = match structure_type {
            EndOfPduStructureType::LeadingLengthDop => {
                // Create structure with leading length DOP
                // The DiagCodedType with LeadingLengthInfo handles the length prefix automatically
                let leading_length_diag_type = db_builder.create_diag_coded_type(
                    None,
                    DataType::ByteField,
                    true,
                    DiagCodedTypeVariant::LeadingLengthInfo(8),
                );

                let data_dop = db_builder.create_regular_normal_dop(
                    "data_dop",
                    leading_length_diag_type,
                    compu_identical,
                );

                let data_param = db_builder.create_value_param("data", data_dop, 0, 0);

                // Create structure with just the data parameter
                db_builder.create_structure(Some(vec![data_param]), None, true)
            }
            EndOfPduStructureType::FixedSize => {
                // Create fixed-size structure
                let item_param1_dop = db_builder.create_regular_normal_dop(
                    "item_param1_dop",
                    u8_diag_type,
                    compu_identical,
                );
                let item_param2_dop = db_builder.create_regular_normal_dop(
                    "item_param2_dop",
                    u16_diag_type,
                    compu_identical,
                );

                // Create parameters for the repeating structure
                let item_param1 =
                    db_builder.create_value_param("item_param1", item_param1_dop, 0, 0);
                let item_param2 =
                    db_builder.create_value_param("item_param2", item_param2_dop, 1, 0);

                // Create the basic structure that will be repeated
                db_builder.create_structure(
                    Some(vec![item_param1, item_param2]),
                    Some(3), // byte_size: 1 byte + 2 bytes = 3 bytes per item
                    true,
                )
            }
        };

        // Create EndOfPdu DOP using the new helper method
        let end_pdu_dop =
            db_builder.create_end_of_pdu_field_dop(min_items, max_items, Some(item_structure));

        let sid = service_ids::READ_DATA_BY_IDENTIFIER;
        let dc_name = "TestEndOfPduService";
        let diag_comm = new_diag_comm!(db_builder, dc_name, protocol);

        // Create request
        let request = create_sid_only_request!(db_builder, sid);

        // Create response with EndOfPdu parameter
        let pos_response =
            create_pos_response_with_param!(db_builder, sid, "end_pdu_param", end_pdu_dop, 1);

        let diag_service =
            new_diag_service!(db_builder, diag_comm, request, vec![pos_response], vec![]);

        let db = finish_db!(db_builder, protocol, vec![diag_service]);
        (
            new_ecu_manager(db),
            cda_interfaces::DiagComm::new(dc_name, DiagCommType::Data),
            sid,
        )
    }

    /// Creates an ECU manager with a DTC (Diagnostic Trouble Code) service.
    ///
    /// # Database contents:
    /// - **Service**: `TestDtcService` (SID: 0x19 - `ReadDTCInformation`)
    /// - **Request**: Simple request with only SID
    /// - **Response**: Contains a `dtc_param` (u32 DTC code)
    /// - **DTC**: Single DTC definition
    ///   - **Code**: 0xDEADBEEF (32-bit)
    ///   - **Display code**: "P1234" (OBD-II format)
    ///   - **Fault name**: "`TestFault`"
    ///   - **Severity**: 2
    /// - **DOP**: DTC DOP with 32-bit coded type
    fn create_ecu_manager_with_dtc() -> (
        super::EcuManager<DefaultSecurityPluginData>,
        cda_interfaces::DiagComm,
        u8,
        u32,
    ) {
        let mut db_builder = EcuDataBuilder::new();
        let u32_diag_type = db_builder.create_diag_coded_type_standard_length(32, DataType::UInt32);
        let protocol = db_builder.create_protocol(Protocol::DoIp.value(), None, None, None);
        let compu_identical =
            db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);

        let dtc_code = 0xDEAD_BEEF;
        let dtc = db_builder.create_dtc(dtc_code, Some("P1234"), Some("TestFault"), 2);

        let dtc_dop =
            db_builder.create_dtc_dop(u32_diag_type, Some(vec![dtc]), Some(compu_identical));

        let sid = service_ids::READ_DTC_INFORMATION;
        let dc_name = "TestDtcService";
        let diag_comm = new_diag_comm!(db_builder, dc_name, protocol);

        // Create request
        let request = create_sid_only_request!(db_builder, sid);

        // Create response with DTC parameter
        let pos_response =
            create_pos_response_with_param!(db_builder, sid, "dtc_param", dtc_dop, 1);

        let diag_service =
            new_diag_service!(db_builder, diag_comm, request, vec![pos_response], vec![]);

        let db = finish_db!(db_builder, protocol, vec![diag_service]);
        (
            new_ecu_manager(db),
            cda_interfaces::DiagComm::new(dc_name, DiagCommType::Faults),
            sid,
            dtc_code,
        )
    }

    /// Creates an ECU manager configured for variant detection testing.
    ///
    /// # Database contents:
    /// - **Service**: `ReadVariantData`
    ///   (SID: `ReadDataByIdentifier` - 0x22, `VARIANT_IDENTIFICATION` class)
    /// - **Request**: Simple request with SID
    /// - **Response**: Contains `variant_code` parameter (u8)
    /// - **Variants**: Two variants with pattern matching
    ///   - **`BaseVariant`** (`is_base=true`):
    ///     - Pattern matches when `variant_code` = 0
    ///     - Contains variant detection service
    ///     - State charts: Session (`DefaultSession`), Security (Locked)
    ///   - **`SpecificVariant`** (`is_base=false`):
    ///     - Pattern matches when `variant_code` = 1
    ///     - Contains variant detection service
    ///     - State charts: Session (`DefaultSession`), Security (Locked)
    /// - **ECU name**: "`VariantDetectionEcu`"
    #[allow(clippy::too_many_lines)] // must be kept together
    fn create_ecu_manager_variant_detection(
        fallback_to_base: bool,
    ) -> super::EcuManager<DefaultSecurityPluginData> {
        let mut db_builder = EcuDataBuilder::new();
        let protocol = db_builder.create_protocol(Protocol::DoIp.value(), None, None, None);
        let cp_ref = db_builder.create_com_param_ref(None, None, None, Some(protocol), None);

        let u8_diag_type = db_builder.create_diag_coded_type_standard_length(8, DataType::UInt32);
        let compu_identical =
            db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);

        // Create a variant detection service
        let vd_service_sid = service_ids::READ_DATA_BY_IDENTIFIER;
        let vd_service_name = "ReadVariantData";

        // Create DOP for variant code response parameter
        let variant_code_dop =
            db_builder.create_regular_normal_dop("variant_code_dop", u8_diag_type, compu_identical);

        // Create the diagnostic communication
        let vd_diag_comm = db_builder.create_diag_comm(DiagCommParams {
            short_name: vd_service_name,
            diag_class_type: DiagClassType::VARIANT_IDENTIFICATION,
            ..Default::default()
        });

        let vd_request = create_sid_only_request!(db_builder, "vd_service_sid", vd_service_sid);

        let vd_pos_response = {
            let sid_param = create_sid_param!(
                db_builder,
                "vd_service_pos_sid",
                (vd_service_sid + UDS_ID_RESPONSE_BITMASK)
            );
            let variant_param =
                db_builder.create_value_param("variant_code", variant_code_dop, 1, 0);
            db_builder.create_response(
                ResponseType::Positive,
                Some(vec![sid_param, variant_param]),
                None,
            )
        };

        let vd_diag_service = new_diag_service!(
            db_builder,
            vd_diag_comm,
            vd_request,
            vec![vd_pos_response],
            vec![]
        );

        // Create state charts for session and security
        let session_state_chart = {
            let default_session_name = "DefaultSession";
            let default_session_state = db_builder.create_state(default_session_name, None);

            db_builder.create_state_chart(
                "Session",
                Some(semantics::SESSION),
                None,
                Some(default_session_name),
                Some(vec![default_session_state]),
            )
        };

        let security_state_chart = {
            let default_security_name = "Locked";
            let default_security_state = db_builder.create_state(default_security_name, None);

            db_builder.create_state_chart(
                "SecurityAccess",
                Some(semantics::SECURITY),
                None,
                Some(default_security_name),
                Some(vec![default_security_state]),
            )
        };

        let sid_param = create_sid_param!(
            db_builder,
            "vd_service_pos_sid_base",
            (vd_service_sid + UDS_ID_RESPONSE_BITMASK)
        );

        let variant_param = db_builder.create_value_param("variant_code", variant_code_dop, 1, 0);

        let pos_response_variant_code = {
            db_builder.create_response(
                ResponseType::Positive,
                Some(vec![sid_param, variant_param]),
                None,
            )
        };
        let diag_service = new_diag_service!(
            db_builder,
            vd_diag_comm,
            vd_request,
            vec![pos_response_variant_code],
            vec![]
        );

        // Create base variant with pattern matching variant_code = 0
        let base_variant = {
            let matching_param_base =
                db_builder.create_matching_parameter("0", diag_service, variant_param);
            let variant_pattern_base =
                db_builder.create_variant_pattern(&vec![matching_param_base]);
            let base_diag_layer = db_builder.create_diag_layer(DiagLayerParams {
                short_name: "BaseVariant",
                com_param_refs: Some(vec![cp_ref]),
                diag_services: Some(vec![vd_diag_service]),
                state_charts: Some(vec![session_state_chart, security_state_chart]),
                ..Default::default()
            });
            db_builder.create_variant(
                base_diag_layer,
                true,
                Some(vec![variant_pattern_base]),
                None,
            )
        };

        // Create second variant with pattern matching variant_code = 1
        let specific_variant = {
            let matching_param_base =
                db_builder.create_matching_parameter("1", diag_service, variant_param);
            let variant_pattern_base =
                db_builder.create_variant_pattern(&vec![matching_param_base]);
            let base_diag_layer = db_builder.create_diag_layer(DiagLayerParams {
                short_name: "SpecificVariant",
                com_param_refs: Some(vec![cp_ref]),
                diag_services: Some(vec![vd_diag_service]),
                state_charts: Some(vec![session_state_chart, security_state_chart]),
                ..Default::default()
            });
            db_builder.create_variant(
                base_diag_layer,
                false,
                Some(vec![variant_pattern_base]),
                None,
            )
        };

        // we need multiple variants, hence cannot use the finish_db! macro,
        // so we finish the db manually here.
        let db = db_builder.finish(EcuDataParams {
            ecu_name: "VariantDetectionEcu",
            revision: "revision_1",
            version: "1.0.0",
            variants: Some(vec![base_variant, specific_variant]),
            ..Default::default()
        });

        if fallback_to_base {
            new_ecu_manager(db)
        } else {
            new_ecu_manager_no_base_fallback(db)
        }
    }

    /// Creates an `EcuManager` with a service that uses a `PhysConst` parameter with a Normal DOP.
    ///
    /// Service layout (response):
    ///   byte 0: SID (CODED-CONST)
    ///   byte 1-2: DID (PHYS-CONST, Normal DOP, u16)
    ///   byte 3: `data_param` (VALUE, u8)
    #[allow(clippy::too_many_lines)]
    fn create_ecu_manager_with_phys_const_normal_dop_service() -> (
        super::EcuManager<DefaultSecurityPluginData>,
        cda_interfaces::DiagComm,
        u8,
    ) {
        let mut db_builder = EcuDataBuilder::new();
        let u8_diag_type = db_builder.create_diag_coded_type_standard_length(8, DataType::UInt32);
        let u16_diag_type = db_builder.create_diag_coded_type_standard_length(16, DataType::UInt32);
        let compu_identical =
            db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);

        // Create Normal DOP for the PhysConst DID parameter
        let did_dop = {
            let did_dop_specific_data = db_builder
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
                Some("did_dop"),
                None,
                *SpecificDOPData::NormalDOP,
                Some(did_dop_specific_data),
            )
        };

        // Create Normal DOP for the VALUE data parameter
        let data_dop = {
            let data_dop_specific_data = db_builder
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
                Some("data_dop"),
                None,
                *SpecificDOPData::NormalDOP,
                Some(data_dop_specific_data),
            )
        };

        let sid = service_ids::READ_DATA_BY_IDENTIFIER + cda_interfaces::UDS_ID_RESPONSE_BITMASK;
        let dc_name = "TestPhysConstNormalService";
        let protocol = db_builder.create_protocol(Protocol::DoIp.value(), None, None, None);
        let diag_comm = new_diag_comm!(db_builder, dc_name, protocol);

        // Request: SID (coded const) + DID (phys const)
        let request = {
            let sid_param =
                create_sid_param!(db_builder, "sid", service_ids::READ_DATA_BY_IDENTIFIER);
            let did_param = db_builder.create_phys_const_param("DID", Some("61840"), did_dop, 1, 0);
            db_builder.create_request(Some(vec![sid_param, did_param]), None)
        };

        // Positive response: SID + DID (phys const) + data (value)
        let pos_response = {
            let sid_param = create_sid_param!(db_builder, "sid", sid);
            let did_param = db_builder.create_phys_const_param("DID", Some("61840"), did_dop, 1, 0);
            let data_param = db_builder.create_value_param("data_param", data_dop, 3, 0);
            db_builder.create_response(
                ResponseType::Positive,
                Some(vec![sid_param, did_param, data_param]),
                None,
            )
        };

        let diag_service =
            new_diag_service!(db_builder, diag_comm, request, vec![pos_response], vec![]);

        let db = finish_db!(db_builder, protocol, vec![diag_service]);

        let ecu_manager = new_ecu_manager(db);

        let dc = cda_interfaces::DiagComm {
            name: dc_name.to_owned(),
            type_: DiagCommType::Data,
            lookup_name: Some(dc_name.to_owned()),
        };

        (ecu_manager, dc, sid)
    }

    /// Creates an `EcuManager` with a service that uses a `PhysConst` parameter
    /// with a Structure DOP.
    ///
    /// Service layout (request):
    ///   byte 0: SID (CODED-CONST)
    ///   byte 1-2: DID (PHYS-CONST, Normal DOP, u16)
    ///   byte 3+: DREC (PHYS-CONST, Structure DOP with sub-params)
    ///     sub-param1: u16 at byte 0
    ///     sub-param2: u8 at byte 2
    #[allow(clippy::too_many_lines)]
    fn create_ecu_manager_with_phys_const_structure_dop_service() -> (
        super::EcuManager<DefaultSecurityPluginData>,
        cda_interfaces::DiagComm,
        u8,
    ) {
        let mut db_builder = EcuDataBuilder::new();
        let u8_diag_type = db_builder.create_diag_coded_type_standard_length(8, DataType::UInt32);
        let u16_diag_type = db_builder.create_diag_coded_type_standard_length(16, DataType::UInt32);
        let compu_identical =
            db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);

        // Create Normal DOP for the PhysConst DID parameter
        let did_dop = {
            let did_dop_specific_data = db_builder
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
                Some("did_dop"),
                None,
                *SpecificDOPData::NormalDOP,
                Some(did_dop_specific_data),
            )
        };

        // Create Structure DOP for the PhysConst DREC parameter
        let structure_dop = {
            // Sub-param DOPs
            let sub_param1_dop = {
                let specific_data = db_builder
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
                    Some("sub_param1_dop"),
                    None,
                    *SpecificDOPData::NormalDOP,
                    Some(specific_data),
                )
            };

            let sub_param2_dop = {
                let specific_data = db_builder
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
                    Some("sub_param2_dop"),
                    None,
                    *SpecificDOPData::NormalDOP,
                    Some(specific_data),
                )
            };

            // Create structure params
            let sub_param1 = db_builder.create_value_param("sub_param1", sub_param1_dop, 0, 0);
            let sub_param2 = db_builder.create_value_param("sub_param2", sub_param2_dop, 2, 0);

            let structure = db_builder.create_structure(
                Some(vec![sub_param1, sub_param2]),
                Some(3), // byte_size: 2 bytes (u16) + 1 byte (u8) = 3 bytes
                true,
            );

            db_builder.create_structure_dop("structure_dop", structure)
        };

        let protocol = db_builder.create_protocol(Protocol::DoIp.value(), None, None, None);
        let sid_request = service_ids::WRITE_DATA_BY_IDENTIFIER;
        let sid_response =
            service_ids::WRITE_DATA_BY_IDENTIFIER + cda_interfaces::UDS_ID_RESPONSE_BITMASK;
        let dc_name = "TestPhysConstStructureService";
        let diag_comm = new_diag_comm!(db_builder, dc_name, protocol);

        // Request: SID (coded const) + DID (phys const, normal) + DREC (phys const, structure)
        let request = {
            let sid_param = create_sid_param!(db_builder, "sid", sid_request);
            let did_param = db_builder.create_phys_const_param("DID", Some("61840"), did_dop, 1, 0);
            let drec_param = db_builder.create_phys_const_param("DREC", None, structure_dop, 3, 0);
            db_builder.create_request(Some(vec![sid_param, did_param, drec_param]), None)
        };

        // Positive response: SID + DID (phys const) + DREC (phys const, structure)
        let pos_response = {
            let sid_param = create_sid_param!(db_builder, "sid", sid_response);
            let did_param = db_builder.create_phys_const_param("DID", Some("61840"), did_dop, 1, 0);
            let drec_param = db_builder.create_phys_const_param("DREC", None, structure_dop, 3, 0);
            db_builder.create_response(
                ResponseType::Positive,
                Some(vec![sid_param, did_param, drec_param]),
                None,
            )
        };

        let diag_service =
            new_diag_service!(db_builder, diag_comm, request, vec![pos_response], vec![]);

        let db = finish_db!(db_builder, protocol, vec![diag_service]);

        let ecu_manager = new_ecu_manager(db);

        let dc = cda_interfaces::DiagComm {
            name: dc_name.to_owned(),
            type_: DiagCommType::Configurations,
            lookup_name: Some(dc_name.to_owned()),
        };

        (ecu_manager, dc, sid_response)
    }

    /// Helper function to create an ECU manager with services that have state transition refs
    fn create_ecu_manager_with_state_transitions() -> (
        super::EcuManager<DefaultSecurityPluginData>,
        cda_interfaces::DiagComm,
    ) {
        let mut db_builder = EcuDataBuilder::new();
        let protocol = db_builder.create_protocol(Protocol::DoIp.value(), None, None, None);
        let cp_ref = db_builder.create_com_param_ref(None, None, None, Some(protocol), None);

        // Create security states
        let locked_state = db_builder.create_state("LockedSecurity", None);
        let extended_state = db_builder.create_state("ExtendedSecurity", None);
        let programming_state = db_builder.create_state("ProgrammingSecurity", None);

        // Create session states
        let default_session_state = db_builder.create_state("DefaultSession", None);
        let extended_session_state = db_builder.create_state("ExtendedSession", None);
        let programming_session_state = db_builder.create_state("ProgrammingSession", None);

        // Create state transitions for session
        let default_to_extended_session = db_builder.create_state_transition(
            "DefaultToExtended",
            Some("DefaultSession"),
            Some("ExtendedSession"),
        );
        let extended_to_programming_session = db_builder.create_state_transition(
            "ExtendedToProgramming",
            Some("ExtendedSession"),
            Some("ProgrammingSession"),
        );

        // Create state transitions for security
        let locked_to_extended_transition = db_builder.create_state_transition(
            "LockedToExtended",
            Some("LockedSecurity"),
            Some("ExtendedSecurity"),
        );

        let extended_to_programming_transition = db_builder.create_state_transition(
            "ExtendedToProgramming",
            Some("ExtendedSecurity"),
            Some("ProgrammingSecurity"),
        );

        // Create state chart for security
        let security_state_chart = db_builder.create_state_chart(
            "SecurityAccess",
            Some(semantics::SECURITY),
            Some(vec![
                locked_to_extended_transition,
                extended_to_programming_transition,
            ]),
            Some("LockedSecurity"),
            Some(vec![locked_state, extended_state, programming_state]),
        );

        // Create state chart for session (simple, no transitions needed for this test)
        let session_state_chart = db_builder.create_state_chart(
            "Session",
            Some(semantics::SESSION),
            Some(vec![
                default_to_extended_session,
                extended_to_programming_session,
            ]),
            Some("DefaultSession"),
            Some(vec![
                default_session_state,
                extended_session_state,
                programming_session_state,
            ]),
        );

        // Create state transition refs for the service
        let state_transition_ref =
            db_builder.create_state_transition_ref(locked_to_extended_transition);
        let session_transition_ref =
            db_builder.create_state_transition_ref(default_to_extended_session);

        // Create precondition state ref - service requires Programming
        let precondition_ref = db_builder.create_pre_condition_state_ref(programming_state);

        // Create a service with state transition refs
        let sid = service_ids::WRITE_DATA_BY_IDENTIFIER;
        let dc_name = "TestServiceWithStateTransitions";

        let diag_comm = db_builder.create_diag_comm(DiagCommParams {
            short_name: dc_name,
            pre_condition_state_refs: Some(vec![precondition_ref]),
            state_transition_refs: Some(vec![session_transition_ref, state_transition_ref]),
            protocols: Some(vec![protocol]),
            ..Default::default()
        });

        let request = create_sid_only_request!(db_builder, sid);
        let diag_service = new_diag_service!(db_builder, diag_comm, request, vec![], vec![]);

        let diag_layer = db_builder.create_diag_layer(DiagLayerParams {
            short_name: "TestVariantDiagLayer",
            com_param_refs: Some(vec![cp_ref]),
            diag_services: Some(vec![diag_service]),
            state_charts: Some(vec![session_state_chart, security_state_chart]),
            ..Default::default()
        });

        let variant = db_builder.create_variant(diag_layer, true, None, None);
        let db = db_builder.finish(EcuDataParams {
            revision: "revision_1",
            version: "1.0.0",
            variants: Some(vec![variant]),
            ..Default::default()
        });

        let dc = cda_interfaces::DiagComm {
            name: dc_name.to_owned(),
            type_: DiagCommType::Configurations,
            lookup_name: Some(dc_name.to_owned()),
        };
        (new_ecu_manager(db), dc)
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
        assert_uds_conversion_fails(
            &ecu_manager,
            &service,
            vec![
                // Service ID
                sid,
                // This does not belong to our mux, it's here to test, if the start byte is used
                0xFF, // Mux param starts here
                // + switch key byte 0
                0x0, 0x0A, // valid switch key but no data, expect error from decode.
            ],
        )
        .await;
    }

    #[tokio::test]
    async fn test_mux_from_uds_empty_structure() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_mux_service(None, None, None);
        let err = assert_uds_conversion_fails(
            &ecu_manager,
            &service,
            vec![
                // Service ID
                sid,
                // This does not belong to our mux, it's here to test, if the start byte is used
                0xFF, // Mux param starts here
                // + switch key byte 0
                0x00, 0x0A, // valid switch key but no data, expect error from decode.
            ],
        )
        .await;

        assert_eq!(
            err,
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

        let payload_data = UdsPayloadData::ParameterMap(
            [("main_param".to_string(), test_value)]
                .into_iter()
                .collect(),
        );

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
            .create_uds_payload(&service, &skip_sec_plugin!(), Some(payload_data))
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
            .create_uds_payload(&service, &skip_sec_plugin!(), Some(payload_data))
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
            .create_uds_payload(&service, &skip_sec_plugin!(), Some(payload_data))
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
                "DtcRecord": {
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
        let err = assert_uds_conversion_fails(
            &ecu_manager,
            &service,
            vec![
                sid,  // Service ID
                0x03, // 3 total fields, but only 2 are provided
                0x11, 0x22, 0x33, 0x44,
            ],
        )
        .await;

        assert_eq!(
            err,
            DiagServiceError::NotEnoughData {
                expected: 2,
                actual: 0
            }
        );
    }

    #[tokio::test]
    async fn test_negative_response() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_dynamic_length_field_service();
        let payload = vec![0x7F, sid];

        let response = ecu_manager
            .convert_from_uds(&service, &create_payload(payload), true)
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
            .convert_from_uds(&service, &create_payload(data), true)
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
    fn test_get_service_parameter_metadata_success() {
        use cda_interfaces::ParameterTypeMetadata;

        let ecu_manager = create_ecu_manager_with_parameter_metadata();

        // Get parameter metadata for the test service
        let result = ecu_manager.get_service_parameter_metadata("RDBI_TestService");
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
            ParameterTypeMetadata::Value
        ));
    }

    #[test]
    fn test_get_service_parameter_metadata_service_not_found() {
        let ecu_manager = create_ecu_manager_with_parameter_metadata();

        // Try to get metadata for a non-existent service
        let result = ecu_manager.get_service_parameter_metadata("NonExistentService");
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
    fn test_get_service_parameter_metadata_extracts_coded_const_did_value() {
        use cda_interfaces::ParameterTypeMetadata;

        let ecu_manager = create_ecu_manager_with_parameter_metadata();

        // Get parameter metadata
        let result = ecu_manager.get_service_parameter_metadata("RDBI_TestService");
        assert!(result.is_ok());

        let metadata = result.unwrap();

        // Find the DID parameter and extract its value
        let did_param = metadata.iter().find(|m| m.name == "RDBI_DID").unwrap();

        if let ParameterTypeMetadata::CodedConst { coded_value } = &did_param.param_type {
            // Verify the coded value can be parsed as a DID
            // "0xF190" should parse to 61840
            let did_value = if coded_value.starts_with("0x") || coded_value.starts_with("0X") {
                u16::from_str_radix(&coded_value[2..], 16).ok()
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

        let result = ecu_manager.convert_from_uds(&dc, &payload, true).await;

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

        let result = ecu_manager.convert_from_uds(&dc, &payload, true).await;

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
            .create_uds_payload(&dc, &skip_sec_plugin!(), Some(payload_data))
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
            .create_uds_payload(&dc, &skip_sec_plugin!(), Some(payload_data))
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

        // Step 1: Encode JSON → UDS
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
            .create_uds_payload(&dc, &skip_sec_plugin!(), Some(payload_data))
            .await;
        assert!(encode_result.is_ok());
        let mut service_payload = encode_result.unwrap();

        // Step 2: Change SID from request (0x2E) to positive response (0x6E)
        if let Some(byte) = service_payload.data.get_mut(0) {
            *byte = sid;
        }

        // Step 3: Decode UDS → mapped data
        let decode_result = ecu_manager
            .convert_from_uds(&dc, &service_payload, true)
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
    async fn test_state_transition_source_allowed_as_valid_security_state() {
        // State transition source states are added to allowed_security states
        let (ecu_manager, dc) = create_ecu_manager_with_state_transitions();

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
            .create_uds_payload(&dc, &skip_sec_plugin!(), Some(payload_data))
            .await;

        assert!(
            result.is_ok(),
            "Service should be allowed from source state of state transition. Error: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_state_precondition() {
        let (ecu_manager, dc) = create_ecu_manager_with_state_transitions();

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
            .create_uds_payload(&dc, &skip_sec_plugin!(), Some(payload_data))
            .await;

        assert!(
            result.is_ok(),
            "Service should be allowed when in precondition state"
        );
    }

    #[tokio::test]
    async fn test_invalid_security_state_rejected() {
        // This test verifies that states that are
        // neither in preconditions nor state transition sources are properly rejected
        let (ecu_manager, dc) = create_ecu_manager_with_state_transitions();

        // Set ECU to "Extended" which is:
        // - NOT in the precondition states (only Programming is)
        // - NOT the source of the state transition (Locked is the source)
        // - It's the TARGET of the transition, but targets are not added to allowed states
        {
            let mut ecu_states = ecu_manager.ecu_service_states.write().await;
            ecu_states.insert(service_ids::SESSION_CONTROL, "DefaultSession".to_string());
            ecu_states.insert(service_ids::SECURITY_ACCESS, "ExtendedSecurity".to_string());
        }

        let payload_data = UdsPayloadData::Raw(vec![service_ids::WRITE_DATA_BY_IDENTIFIER]);

        // This should fail because Extended is neither in preconditions nor a transition source
        let result = ecu_manager
            .create_uds_payload(&dc, &skip_sec_plugin!(), Some(payload_data))
            .await;

        assert!(
            result.is_err(),
            "Service should NOT be allowed from invalid security state"
        );
    }
}
