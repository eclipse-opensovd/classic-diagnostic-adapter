/*
 * SPDX-FileCopyrightText: 2025 Copyright (c) Contributors to the Eclipse Foundation
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

use std::time::Duration;

use cda_database::datatypes;
use cda_interfaces::{
    Connectivity, DiagServiceError, EcuManagerType, EcuRuntimeState, EcuStateManager, HashMap,
    HashMapExtensions, HashSet, PayloadDecoder, Protocol, VariantState,
    datatypes::{
        AddressingMode, ComParamConfig, ComParamPrecedence, ComParams, ComplexComParamValue,
        DatabaseNamingConvention, DiagnosticServiceAffixPosition, RetryPolicy, SdSdg,
        TesterPresentSendType,
    },
    dlt_ctx,
    util::std_ext,
};
use cda_plugin_security::SecurityPlugin;

use super::service_lookup::DbCache;
use crate::diag_kernel::{
    into_db_protocol,
    variant_detection::{self, VariantDetection},
};

// Helper struct to extract variant data without lifetime dependencies
// Necessary to de-couple set_variant lifetimes and prevent borrow issues,
// we would have when using Variant<'_> from database.
// Not using EcuVariant instead because contains additional fields we're looking up in
// set_variant
pub(crate) struct VariantData {
    name: String,
    is_base_variant: bool,
    is_fallback: bool,
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

/// Configuration options passed to [`EcuManager::new`].
///
/// Grouping these together keeps the constructor signature manageable and
/// makes call sites self-documenting.
#[derive(Copy, Clone)]
pub struct EcuManagerConfig {
    /// Whether this ECU represents a physical ECU (`Ecu`) or a functional
    /// group description (`FunctionalDescription`).
    pub type_: EcuManagerType,
    /// When `true`, variant detection failures fall back to the base variant
    /// instead of returning an error.
    pub fallback_to_base_variant: bool,
    /// When `true`, requests containing parameters not defined in the service
    /// are rejected with a `BadPayload` error (400 Bad Request).
    pub strict_parameter_validation: bool,
}

// Allowed because this holds a bunch of config values.
#[allow(clippy::struct_excessive_bools)]
pub struct EcuManager<S: SecurityPlugin> {
    pub(in crate::diag_kernel) diag_database: datatypes::DiagnosticDatabase,
    pub(in crate::diag_kernel) db_cache: DbCache,
    pub(in crate::diag_kernel) ecu_name: String,
    pub(in crate::diag_kernel) description_type: EcuManagerType,
    pub(in crate::diag_kernel) database_naming_convention: DatabaseNamingConvention,
    pub(in crate::diag_kernel) tester_address: u16,
    pub(in crate::diag_kernel) logical_address: u16,
    pub(in crate::diag_kernel) logical_gateway_address: u16,
    pub(in crate::diag_kernel) logical_functional_address: u16,

    pub(in crate::diag_kernel) nack_number_of_retries: HashMap<u8, u32>,
    pub(in crate::diag_kernel) diagnostic_ack_timeout: Duration,
    pub(in crate::diag_kernel) retry_period: Duration,
    pub(in crate::diag_kernel) routing_activation_timeout: Duration,
    pub(in crate::diag_kernel) repeat_request_count_transmission: u32,
    pub(in crate::diag_kernel) connection_timeout: Duration,
    pub(in crate::diag_kernel) connection_retry_delay: Duration,
    pub(in crate::diag_kernel) connection_retry_attempts: u32,

    pub(in crate::diag_kernel) variant_detection: variant_detection::VariantDetection,
    pub(in crate::diag_kernel) fallback_to_base_variant: bool,
    pub(in crate::diag_kernel) strict_parameter_validation: bool,
    pub(in crate::diag_kernel) duplicating_ecu_names: Option<HashSet<String>>,

    pub(in crate::diag_kernel) protocol: Protocol,
    // functional group: protocol prefixed or postfixed
    pub(in crate::diag_kernel) fg_protocol_position: DiagnosticServiceAffixPosition,

    /// Shared runtime state.
    /// Also held by the coordinator actor for external event-driven mutations.
    pub(in crate::diag_kernel) runtime_state: EcuRuntimeState,

    pub(in crate::diag_kernel) tester_present_retry_policy: bool,
    pub(in crate::diag_kernel) tester_present_addr_mode: AddressingMode,
    pub(in crate::diag_kernel) tester_present_response_expected: bool,
    pub(in crate::diag_kernel) tester_present_send_type: TesterPresentSendType,
    pub(in crate::diag_kernel) tester_present_message: Vec<u8>,
    pub(in crate::diag_kernel) tester_present_exp_pos_resp: Vec<u8>,
    pub(in crate::diag_kernel) tester_present_exp_neg_resp: Vec<u8>,
    pub(in crate::diag_kernel) tester_present_time: Duration,
    pub(in crate::diag_kernel) repeat_req_count_app: u32,
    pub(in crate::diag_kernel) rc_21_retry_policy: RetryPolicy,
    pub(in crate::diag_kernel) rc_21_completion_timeout: Duration,
    pub(in crate::diag_kernel) rc_21_repeat_request_time: Duration,
    pub(in crate::diag_kernel) rc_78_retry_policy: RetryPolicy,
    pub(in crate::diag_kernel) rc_78_completion_timeout: Duration,
    pub(in crate::diag_kernel) rc_78_timeout: Duration,
    pub(in crate::diag_kernel) rc_94_retry_policy: RetryPolicy,
    pub(in crate::diag_kernel) rc_94_completion_timeout: Duration,
    pub(in crate::diag_kernel) rc_94_repeat_request_time: Duration,
    pub(in crate::diag_kernel) timeout_default: Duration,

    security_plugin_phantom: std::marker::PhantomData<S>,
}

impl<S: SecurityPlugin> cda_interfaces::EcuAddresses for EcuManager<S> {
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

    fn logical_address_eq<T: cda_interfaces::EcuAddresses>(&self, other: &T) -> bool {
        self.logical_address == other.logical_address()
            && self.logical_gateway_address() == other.logical_gateway_address()
    }
}

impl<S: SecurityPlugin> cda_interfaces::EcuManager for EcuManager<S> {
    type Response = <Self as PayloadDecoder>::Response;
    fn is_physical_ecu(&self) -> bool {
        self.description_type == EcuManagerType::Ecu
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

    fn set_duplicating_ecu_names(&mut self, duplicate_ecus: HashSet<String>) {
        self.duplicating_ecu_names = Some(duplicate_ecus);
    }

    fn duplicating_ecu_names(&self) -> Option<&HashSet<String>> {
        self.duplicating_ecu_names.as_ref()
    }

    fn revision(&self) -> String {
        // We cannot remove the closure because there is no direct
        // access to the underlying flatbuf type, as it's not exported from the database crate.
        #[allow(clippy::redundant_closure_for_method_calls)]
        self.diag_database
            .ecu_data()
            .ok()
            .and_then(|s| s.revision())
            .map_or_else(|| "0.0.0".to_owned(), ToOwned::to_owned)
    }

    fn runtime_state(&self) -> EcuRuntimeState {
        self.runtime_state.clone()
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
        config: EcuManagerConfig,
        func_description_config: &cda_interfaces::FunctionalDescriptionConfig,
    ) -> Result<Self, DiagServiceError> {
        match config.type_ {
            EcuManagerType::Ecu => Self::new_ecu_description(
                database,
                protocol,
                com_params,
                database_naming_convention,
                config,
                func_description_config,
            ),
            EcuManagerType::FunctionalDescription => Self::new_functional_description(
                database,
                protocol,
                com_params,
                database_naming_convention,
                config,
                func_description_config,
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
        config: EcuManagerConfig,
        func_description_config: &cda_interfaces::FunctionalDescriptionConfig,
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
            description_type: config.type_,
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
            fallback_to_base_variant: config.fallback_to_base_variant,
            strict_parameter_validation: config.strict_parameter_validation,
            duplicating_ecu_names: None,
            protocol,
            fg_protocol_position: func_description_config.protocol_position.clone(),
            runtime_state: EcuRuntimeState::new(),
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
        config: EcuManagerConfig,
        func_description_config: &cda_interfaces::FunctionalDescriptionConfig,
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
            description_type: config.type_,
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
            fallback_to_base_variant: config.fallback_to_base_variant,
            strict_parameter_validation: config.strict_parameter_validation,
            duplicating_ecu_names: None,
            protocol,
            fg_protocol_position: func_description_config.protocol_position.clone(),
            runtime_state: EcuRuntimeState::new(),
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
        let idx = std_ext::lock_read(&self.runtime_state.ecu_state).variant_index?;
        let variants = self.diag_database.ecu_data().ok()?.variants()?;
        Some(variants.get(idx).into())
    }

    /// Returns a clone of the shared runtime state.
    ///
    /// Used by the coordinator actor to share access to the same underlying state.
    #[must_use]
    pub fn runtime_state(&self) -> EcuRuntimeState {
        self.runtime_state.clone()
    }

    pub(crate) async fn set_variant(&self, variant: VariantData) -> Result<(), DiagServiceError> {
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

        let current_variant_index = std_ext::lock_read(&self.runtime_state.ecu_state).variant_index;
        if current_variant_index != variant_index {
            // reset cache, because services may have the same lookup names
            // but differ in parameters etc. between variants
            self.db_cache.reset().await;
        }

        tracing::debug!("Setting variant to '{variant_name}'");
        {
            let mut es = std_ext::lock_write(&self.runtime_state.ecu_state);

            if variant_index.is_some() {
                es.connectivity = Connectivity::Online;
                es.variant_state = VariantState::Detected {
                    name: variant.name.clone(),
                    is_base_variant: variant.is_base_variant,
                    is_fallback: variant.is_fallback,
                };
            } else {
                tracing::warn!("Variant '{variant_name}' not found in database variants");
                es.variant_state = VariantState::NotDetected;
            }
            es.variant_index = variant_index;
        }

        self.set_default_states().await
    }
}

#[cfg(test)]
mod tests {
    use cda_database::datatypes::DataType;
    use cda_interfaces::{
        DiagCommType, HashMapExtensions, VariantDetection, diagservices::DiagServiceResponseType,
    };
    use cda_plugin_security::DefaultSecurityPluginData;

    use super::*;
    use crate::{
        MappedResponseData,
        diag_kernel::{
            diagservices::{
                DiagDataTypeContainer, DiagDataTypeContainerRaw, DiagServiceResponseStruct,
            },
            test_utils::ecu_manager_builder::create_ecu_manager_variant_detection,
        },
    };

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
        ecu_manger: Option<super::EcuManager<DefaultSecurityPluginData>>,
        connectivity_state: Connectivity,
        variant_state: VariantState,
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
        let rs = ecu_manager.runtime_state.ecu_state.read().unwrap();
        assert_eq!(rs.variant_state.name(), variant_state.name());
        assert_eq!(
            rs.variant_state.is_base_variant(),
            variant_state.is_base_variant()
        );
        assert_eq!(rs.connectivity, connectivity_state);
        assert_eq!(rs.variant_state, variant_state);
    }

    #[tokio::test]
    async fn test_detect_base_variant() {
        detect_variant(
            0,
            None,
            Connectivity::Online,
            VariantState::Detected {
                name: "BaseVariant".to_owned(),
                is_base_variant: true,
                is_fallback: false,
            },
        )
        .await;
    }

    #[tokio::test]
    async fn test_detect_specific_variant() {
        detect_variant(
            1,
            None,
            Connectivity::Online,
            VariantState::Detected {
                name: "SpecificVariant".to_owned(),
                is_base_variant: false,
                is_fallback: false,
            },
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

        assert!(
            ecu_manager
                .runtime_state
                .ecu_state
                .read()
                .unwrap()
                .variant_state
                .name()
                .is_none()
        );
        assert!(!ecu_manager.diag_database.is_loaded());
        assert!(
            !ecu_manager
                .runtime_state
                .ecu_state
                .read()
                .unwrap()
                .variant_state
                .is_base_variant()
        );
        assert_eq!(
            ecu_manager.runtime_state.status().variant_state,
            VariantState::NotDetected
        );
    }

    #[tokio::test]
    async fn test_detect_variant_with_response_from_offline_to_online() {
        let ecu_manager = create_ecu_manager_variant_detection(true);
        ecu_manager
            .runtime_state
            .ecu_state
            .write()
            .unwrap()
            .connectivity = Connectivity::Offline;
        detect_variant(
            0,
            Some(ecu_manager),
            Connectivity::Online,
            VariantState::Detected {
                name: "BaseVariant".to_owned(),
                is_base_variant: true,
                is_fallback: false,
            },
        )
        .await;
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

        let rs = ecu_manager.runtime_state.ecu_state.read().unwrap();
        assert_eq!(
            rs.variant_state.name().map(ToOwned::to_owned),
            Some("BaseVariant".to_owned())
        );
        assert!(rs.variant_state.is_base_variant());
        assert_eq!(rs.connectivity, Connectivity::Online);
        drop(rs);
        assert!(ecu_manager.diag_database.is_loaded());
        assert!(
            ecu_manager
                .runtime_state
                .ecu_state
                .read()
                .unwrap()
                .variant_index
                .is_some()
        );
    }
}
