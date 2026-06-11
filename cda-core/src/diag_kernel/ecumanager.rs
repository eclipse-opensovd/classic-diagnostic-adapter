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
    HashMap, HashMapExtensions, HashSet, Protocol, SecurityAccess,
    ServicePayload,
    datatypes::{
        AddressingMode, ComParamConfig, ComParamPrecedence,
        ComParams, ComplexComParamValue, ComponentConfigurationsInfo, ComponentDataInfo,
        ComponentOperationsInfo, DatabaseNamingConvention,
        DiagnosticServiceAffixPosition, DtcLookup, DtcReadInformationFunction, RetryPolicy,
        RoutineSubfunctions, SdSdg, TesterPresentSendType, single_ecu,
    },
    diagservices::{DiagServiceResponse, UdsPayloadData},
    dlt_ctx,
    util::{ends_with_ignore_ascii_case, starts_with_ignore_ascii_case},
};
use cda_plugin_security::SecurityPlugin;
use tokio::sync::RwLock;

use super::service_lookup::DbCache;
use crate::{
    diag_kernel::{
        diagservices::{
            DiagServiceResponseStruct,
            MappedDiagServiceResponsePayload,
        },
        into_db_protocol,
        variant_detection::{self, VariantDetection},
    },
};

// Helper struct to extract variant data without lifetime dependencies
// Necessary to de-couple set_variant lifetimes and prevent borrow issues,
// we would have when using Variant<'_> from database.
// Not using EcuVariant instead because contains additional fields we're looking up in
// set_variant
pub(crate) struct VariantData {
    pub(crate) name: String,
    pub(crate) is_base_variant: bool,
    pub(crate) is_fallback: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct ParamContext<'a> {
    pub(crate) parameter: &'a datatypes::Parameter<'a>,
    pub(crate) base_offset: usize,
    pub(crate) outer_context: Option<&'a MappedDiagServiceResponsePayload>,
}

impl<'a> ParamContext<'a> {
    pub(crate) fn new(parameter: &'a datatypes::Parameter<'a>, base_offset: usize) -> Self {
        Self {
            parameter,
            base_offset,
            outer_context: None,
        }
    }

    pub(crate) fn with_outer_context(
        self,
        outer_context: Option<&'a MappedDiagServiceResponsePayload>,
    ) -> Self {
        Self {
            outer_context,
            ..self
        }
    }

    pub(crate) fn abs_byte_pos(self) -> usize {
        self.base_offset
            .saturating_add(self.parameter.byte_position() as usize)
    }
}

impl VariantData {
    pub(crate) fn from_variant_and_fallback(v: &datatypes::Variant<'_>, is_fallback: bool) -> Self {
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
        self.check_genericservice(security_plugin, rawdata).await
    }

    /// Convert a UDS payload given as `u8` slice into a `DiagServiceResponse`.
    ///
    /// # Errors
    /// Will return `Err` in cases where the payload doesn't match the expected UDS response, or if
    /// elements of the response cannot be correctly mapped from the raw data.
    // allow keeping the function together as it makes sense structurally
    #[allow(clippy::too_many_lines)]
    async fn convert_from_uds(
        &self,
        diag_service: &cda_interfaces::DiagComm,
        payload: &ServicePayload,
        map_to_json: bool,
        functional_group_name: Option<&str>,
    ) -> Result<DiagServiceResponseStruct, DiagServiceError> {
        self.convert_from_uds(diag_service, payload, map_to_json, functional_group_name)
            .await
    }

    async fn create_uds_payload(
        &self,
        diag_service: &cda_interfaces::DiagComm,
        security_plugin: &DynamicPlugin,
        data: Option<UdsPayloadData>,
        functional_group_name: Option<&str>,
    ) -> Result<ServicePayload, DiagServiceError> {
        self.create_uds_payload(diag_service, security_plugin, data, functional_group_name)
            .await
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
        self.get_components_data_info(security_plugin)
    }

    fn get_functional_group_data_info(
        &self,
        security_plugin: &DynamicPlugin,
        functional_group_name: &str,
    ) -> Result<Vec<ComponentDataInfo>, DiagServiceError> {
        self.get_functional_group_data_info(security_plugin, functional_group_name)
    }

    /// Returns all `RoutineControl` (SID 0x31) services for the functional group,
    /// with flags indicating whether Stop (0x02) and `RequestResults` (0x03)
    /// subfunctions are also defined.
    fn get_functional_group_operations_info(
        &self,
        security_plugin: &DynamicPlugin,
        functional_group_name: &str,
    ) -> Result<Vec<ComponentOperationsInfo>, DiagServiceError> {
        self.get_functional_group_operations_info(security_plugin, functional_group_name)
    }

    /// Check which additional `RoutineControl` subfunctions are defined for a specific routine
    /// within a functional group.
    fn get_functional_group_routine_subfunctions(
        &self,
        security_plugin: &DynamicPlugin,
        functional_group_name: &str,
        service_name: &str,
    ) -> Result<RoutineSubfunctions, DiagServiceError> {
        self.get_functional_group_routine_subfunctions(
            security_plugin,
            functional_group_name,
            service_name,
        )
    }

    fn get_components_single_ecu_jobs_info(&self) -> Vec<ComponentDataInfo> {
        self.get_components_single_ecu_jobs_info()
    }

    async fn set_service_state(&self, sid: u8, value: String) {
        self.set_service_state(sid, value).await;
    }

    async fn get_service_state(&self, sid: u8) -> Option<String> {
        self.get_service_state(sid).await
    }

    async fn lookup_session_change(
        &self,
        target_session_name: &str,
    ) -> Result<cda_interfaces::DiagComm, DiagServiceError> {
        self.lookup_session_change(target_session_name).await
    }

    async fn lookup_security_access_change(
        &self,
        level: &str,
        seed_service: Option<&String>,
        has_key: bool,
    ) -> Result<SecurityAccess, DiagServiceError> {
        self.lookup_security_access_change(level, seed_service, has_key)
            .await
    }

    async fn get_send_key_param_name(
        &self,
        diag_service: &cda_interfaces::DiagComm,
    ) -> Result<String, DiagServiceError> {
        self.get_send_key_param_name(diag_service).await
    }

    async fn session(&self) -> Result<String, DiagServiceError> {
        self.session().await
    }

    fn default_session(&self) -> Result<String, DiagServiceError> {
        self.default_session()
    }

    async fn security_access(&self) -> Result<String, DiagServiceError> {
        self.security_access().await
    }

    fn default_security_access(&self) -> Result<String, DiagServiceError> {
        self.default_security_access()
    }

    /// Returns all services in /configuration,
    /// i.e. 0x22 (`ReadDataByIdentifier`) and 0x2E (`WriteDataByIdentifier`)
    /// that are in the functional group varcoding.
    fn get_components_configurations_info(
        &self,
        security_plugin: &DynamicPlugin,
    ) -> Result<Vec<ComponentConfigurationsInfo>, DiagServiceError> {
        self.get_components_configurations_info(security_plugin)
    }

    /// Returns all `RoutineControl` (SID 0x31) services for the given ECU,
    /// with flags indicating whether Stop (0x02) and `RequestResults` (0x03)
    /// subfunctions are also defined.
    fn get_components_operations_info(
        &self,
        security_plugin: &DynamicPlugin,
    ) -> Vec<ComponentOperationsInfo> {
        self.get_components_operations_info(security_plugin)
    }

    /// Check which additional `RoutineControl` subfunctions are defined for a specific routine.
    fn get_routine_subfunctions(
        &self,
        service_name: &str,
        security_plugin: &DynamicPlugin,
    ) -> Result<RoutineSubfunctions, DiagServiceError> {
        self.get_routine_subfunctions(service_name, security_plugin)
    }

    fn lookup_dtc_services(
        &self,
        service_types: Vec<DtcReadInformationFunction>,
    ) -> Result<HashMap<DtcReadInformationFunction, DtcLookup>, DiagServiceError> {
        self.lookup_dtc_services(service_types)
    }

    async fn is_service_allowed(
        &self,
        service: &cda_interfaces::DiagComm,
        security_plugin: &DynamicPlugin,
    ) -> Result<(), DiagServiceError> {
        self.is_service_allowed(service, security_plugin).await
    }

    fn functional_groups(&self) -> Vec<String> {
        self.functional_groups()
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
        self.convert_service_14_response(diag_comm, response)
    }

    fn get_request_parameter_metadata(
        &self,
        service_name: &str,
    ) -> Result<Vec<cda_interfaces::ServiceParameterMetadata>, DiagServiceError> {
        self.get_request_parameter_metadata(service_name)
    }

    /// Get parameter metadata for the POS-RESPONSE of a service.
    fn get_response_parameter_metadata(
        &self,
        service_name: &str,
    ) -> Result<Vec<cda_interfaces::ResponseParameterInfo>, DiagServiceError> {
        self.get_response_parameter_metadata(service_name)
    }

    fn get_mux_cases_for_service(
        &self,
        service_name: &str,
    ) -> Result<Vec<cda_interfaces::MuxCaseInfo>, DiagServiceError> {
        self.get_mux_cases_for_service(service_name)
    }

    async fn convert_request_from_uds(
        &self,
        diag_service: &cda_interfaces::DiagComm,
        payload: &ServicePayload,
        map_to_json: bool,
    ) -> Result<DiagServiceResponseStruct, DiagServiceError> {
        self.convert_request_from_uds(diag_service, payload, map_to_json)
            .await
    }
}

impl<S: SecurityPlugin> EcuManager<S> {
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

    pub(crate) fn variant(&self) -> Option<datatypes::Variant<'_>> {
        let idx = self.variant_index?;
        let variants = self.diag_database.ecu_data().ok()?.variants()?;
        Some(variants.get(idx).into())
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

#[cfg(test)]
mod tests {
    use cda_database::datatypes::DataType;
    use cda_interfaces::{DiagCommType, EcuManager, HashMapExtensions, diagservices::DiagServiceResponseType};
    use cda_plugin_security::DefaultSecurityPluginData;

    use super::*;
    use crate::{
        MappedResponseData,
        diag_kernel::{
            diagservices::{DiagDataTypeContainer, DiagDataTypeContainerRaw},
        },
    };
    use crate::diag_kernel::test_utils::ecu_manager_builder::create_ecu_manager_variant_detection;

    /// Helper to create a variant detection response with specified parameters.
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

            let service_responses: HashMap<String, DiagServiceResponseStruct> =
                HashMap::default();
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

        ecu_manager.detect_variant(service_responses).await.unwrap();

        assert_eq!(ecu_manager.variant.name, Some("BaseVariant".to_owned()));
        assert!(ecu_manager.variant.is_base_variant);
        assert_eq!(ecu_manager.variant.state, EcuState::Online);
        assert!(ecu_manager.diag_database.is_loaded());
        assert!(ecu_manager.variant_index.is_some());
    }
}
