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

use std::time::Duration;

use cda_database::datatypes;
use cda_interfaces::{
    DiagServiceError, EcuManagerType, HashMap, Protocol,
    datatypes::{
        AddressingMode, ComParamConfig, ComParamPrecedence, ComParams, RetryPolicy,
        TesterPresentSendType,
    },
};
use cda_plugin_security::SecurityPlugin;

use crate::{EcuManager, diag_kernel::into_db_protocol};

impl<S: SecurityPlugin> cda_interfaces::UdsComParams for EcuManager<S> {
    fn tester_present_retry_policy(&self) -> bool {
        self.com_params.uds.tester_present_retry_policy
    }
    fn tester_present_addr_mode(self) -> AddressingMode {
        self.com_params.uds.tester_present_addr_mode.clone()
    }
    fn tester_present_response_expected(self) -> bool {
        self.com_params.uds.tester_present_response_expected
    }
    fn tester_present_send_type(self) -> TesterPresentSendType {
        self.com_params.uds.tester_present_send_type.clone()
    }
    fn tester_present_message(self) -> Vec<u8> {
        self.com_params.uds.tester_present_message.clone()
    }
    fn tester_present_exp_pos_resp(self) -> Vec<u8> {
        self.com_params.uds.tester_present_exp_pos_resp.clone()
    }
    fn tester_present_exp_neg_resp(self) -> Vec<u8> {
        self.com_params.uds.tester_present_exp_neg_resp.clone()
    }
    fn tester_present_time(&self) -> Duration {
        self.com_params.uds.tester_present_time
    }
    fn repeat_req_count_app(&self) -> u32 {
        self.com_params.uds.repeat_req_count_app
    }
    fn rc_21_retry_policy(&self) -> RetryPolicy {
        self.com_params.uds.rc_21_retry_policy.clone()
    }
    fn rc_21_completion_timeout(&self) -> Duration {
        self.com_params.uds.rc_21_completion_timeout
    }
    fn rc_21_repeat_request_time(&self) -> Duration {
        self.com_params.uds.rc_21_repeat_request_time
    }
    fn rc_78_retry_policy(&self) -> RetryPolicy {
        self.com_params.uds.rc_78_retry_policy.clone()
    }
    fn rc_78_completion_timeout(&self) -> Duration {
        self.com_params.uds.rc_78_completion_timeout
    }
    fn rc_78_timeout(&self) -> Duration {
        self.com_params.uds.rc_78_timeout
    }
    fn rc_94_retry_policy(&self) -> RetryPolicy {
        self.com_params.uds.rc_94_retry_policy.clone()
    }
    fn rc_94_completion_timeout(&self) -> Duration {
        self.com_params.uds.rc_94_completion_timeout
    }
    fn rc_94_repeat_request_time(&self) -> Duration {
        self.com_params.uds.rc_94_repeat_request_time
    }
    fn timeout_default(&self) -> Duration {
        self.com_params.uds.timeout_default
    }
}

impl<S: SecurityPlugin> cda_interfaces::DoipComParams for EcuManager<S> {
    fn nack_number_of_retries(&self) -> &HashMap<u8, u32> {
        &self.com_params.doip.nack_number_of_retries
    }
    fn diagnostic_ack_timeout(&self) -> Duration {
        self.com_params.doip.diagnostic_ack_timeout
    }
    fn retry_period(&self) -> Duration {
        self.com_params.doip.retry_period
    }
    fn routing_activation_timeout(&self) -> Duration {
        self.com_params.doip.routing_activation_timeout
    }
    fn repeat_request_count_transmission(&self) -> u32 {
        self.com_params.doip.repeat_request_count_transmission
    }
    fn connection_timeout(&self) -> Duration {
        self.com_params.doip.connection_timeout
    }
    fn connection_retry_delay(&self) -> Duration {
        self.com_params.doip.connection_retry_delay
    }
    fn connection_retry_attempts(&self) -> u32 {
        self.com_params.doip.connection_retry_attempts
    }
}

/// Communication parameters resolved from the database and/or configuration.
pub struct EffectiveComParams {
    pub doip: EffectiveDoipComParams,
    pub uds: EffectiveUdsComParams,
}

pub struct EffectiveDoipComParams {
    pub tester_address: u16,
    pub logical_address: u16,
    pub logical_gateway_address: u16,
    pub logical_functional_address: u16,
    pub nack_number_of_retries: HashMap<u8, u32>,
    pub diagnostic_ack_timeout: Duration,
    pub retry_period: Duration,
    pub routing_activation_timeout: Duration,
    pub repeat_request_count_transmission: u32,
    pub connection_timeout: Duration,
    pub connection_retry_delay: Duration,
    pub connection_retry_attempts: u32,
}

pub struct EffectiveUdsComParams {
    pub tester_present_retry_policy: bool,
    pub tester_present_addr_mode: AddressingMode,
    pub tester_present_response_expected: bool,
    pub tester_present_send_type: TesterPresentSendType,
    pub tester_present_message: Vec<u8>,
    pub tester_present_exp_pos_resp: Vec<u8>,
    pub tester_present_exp_neg_resp: Vec<u8>,
    pub tester_present_time: Duration,
    pub repeat_req_count_app: u32,
    pub rc_21_retry_policy: RetryPolicy,
    pub rc_21_completion_timeout: Duration,
    pub rc_21_repeat_request_time: Duration,
    pub rc_78_retry_policy: RetryPolicy,
    pub rc_78_completion_timeout: Duration,
    pub rc_78_timeout: Duration,
    pub rc_94_retry_policy: RetryPolicy,
    pub rc_94_completion_timeout: Duration,
    pub rc_94_repeat_request_time: Duration,
    pub timeout_default: Duration,
}

impl EffectiveComParams {
    /// Resolve communication parameters from the database and configuration.
    ///
    /// # Errors
    /// Returns an error when parsing a parameter fails.
    pub fn resolve_from(
        database: &datatypes::DiagnosticDatabase,
        protocol: &Protocol,
        com_params: &ComParams,
        ecu_type: EcuManagerType,
    ) -> Result<Self, DiagServiceError> {
        match ecu_type {
            EcuManagerType::Ecu => Self::resolve_from_database(database, protocol, com_params),
            EcuManagerType::FunctionalDescription => Self::resolve_from_config_defaults(com_params),
        }
    }

    /// Resolve parameters by looking them up in the diagnostic database.
    #[allow(
        clippy::too_many_lines,
        reason = "Keeping all resolution logic together makes structural sense"
    )]
    fn resolve_from_database(
        database: &datatypes::DiagnosticDatabase,
        protocol: &Protocol,
        com_params: &ComParams,
    ) -> Result<Self, DiagServiceError> {
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
                Some(into_db_protocol(database, protocol)?)
            }
        };

        // Get reference to Protocol wrapper; Deref will convert to inner type where needed
        let data_protocol_ref = data_protocol.as_ref();

        let logical_gateway_address = Self::resolve_logical_address(
            database,
            data_protocol_ref,
            &com_params.doip.logical_gateway_address,
            &datatypes::LogicalAddressType::Gateway(
                com_params.doip.logical_gateway_address.name.clone(),
            ),
        );

        let logical_address = Self::resolve_logical_address(
            database,
            data_protocol_ref,
            &com_params.doip.logical_ecu_address,
            &datatypes::LogicalAddressType::Ecu(
                com_params.doip.logical_response_id_table_name.clone(),
                com_params.doip.logical_ecu_address.name.clone(),
            ),
        );

        let logical_functional_address = Self::resolve_logical_address(
            database,
            data_protocol_ref,
            &com_params.doip.logical_functional_address,
            &datatypes::LogicalAddressType::Functional(
                com_params.doip.logical_functional_address.name.clone(),
            ),
        );

        let nack_number_of_retries = database
            .find_com_param(data_protocol_ref, &com_params.doip.nack_number_of_retries)?
            .iter()
            .map(datatypes::map_nack_number_of_retries)
            .collect::<Result<HashMap<u8, u32>, DiagServiceError>>()?;

        Ok(Self {
            doip: EffectiveDoipComParams {
                tester_address: database
                    .find_com_param(data_protocol_ref, &com_params.doip.logical_tester_address)?,
                logical_address,
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
            },
            uds: EffectiveUdsComParams {
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
            },
        })
    }

    /// Use configuration default values directly (for functional group descriptions).
    fn resolve_from_config_defaults(com_params: &ComParams) -> Result<Self, DiagServiceError> {
        let nack_number_of_retries = com_params
            .doip
            .nack_number_of_retries
            .value
            .iter()
            .map(datatypes::map_nack_number_of_retries)
            .collect::<Result<HashMap<u8, u32>, DiagServiceError>>()?;

        Ok(Self {
            doip: EffectiveDoipComParams {
                tester_address: com_params.doip.logical_tester_address.value,
                logical_address: com_params.doip.logical_ecu_address.value,
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
            },
            uds: EffectiveUdsComParams {
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
                tester_present_exp_pos_resp: com_params
                    .uds
                    .tester_present_exp_pos_resp
                    .value
                    .clone(),
                tester_present_exp_neg_resp: com_params
                    .uds
                    .tester_present_exp_neg_resp
                    .value
                    .clone(),
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
            },
        })
    }

    /// Resolve a logical address from the database, with config fallback.
    fn resolve_logical_address(
        database: &datatypes::DiagnosticDatabase,
        data_protocol: Option<&datatypes::Protocol<'_>>,
        config: &ComParamConfig<u16>,
        addr_type: &datatypes::LogicalAddressType,
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
                tracing::error!(
                    config = ?config,
                    protocol = ?data_protocol,
                    addr_type = ?addr_type,
                    error = %e,
                    "Failed to find logical address"
                );
                config.value
            }
        }
    }
}
