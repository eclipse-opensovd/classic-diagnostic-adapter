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

use std::collections::HashSet;

use cda_database::datatypes;
use cda_interfaces::{
    DiagServiceError, DynamicPlugin, HashMap, PayloadEncoder, ServicePayload,
    diagservices::UdsPayloadData, dlt_ctx, util,
};
use cda_plugin_security::SecurityPlugin;

use super::ecumanager::EcuManager;
use crate::diag_kernel::{
    operations::{self, json_value_to_uds_data},
    payload::str_to_json_value,
    payload_decode::mux_case_struct_from_selector_value,
};

impl<S: SecurityPlugin> PayloadEncoder for EcuManager<S> {
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
            None => UdsPayloadData::ParameterMap(HashMap::default()),
        };
        match data {
            UdsPayloadData::Raw(bytes) => uds.extend(bytes),
            UdsPayloadData::ParameterMap(json_values) => {
                self.process_parameter_map(&mapped_params, &json_values, &mut uds)?;
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
}

impl<S: SecurityPlugin> EcuManager<S> {
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
                        #[allow(
                            clippy::cast_possible_truncation,
                            reason = "Truncation is safe; overflow is checked below"
                        )]
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

    fn reject_unexpected_keys<'e, 'k>(
        &self,
        expected: impl Iterator<Item = &'e str>,
        provided: impl Iterator<Item = &'k str>,
    ) -> Result<(), DiagServiceError> {
        if self.strict_parameter_validation {
            let expected_names: HashSet<&str> = expected.collect();
            let unexpected: Vec<&str> = provided.filter(|k| !expected_names.contains(k)).collect();
            if !unexpected.is_empty() {
                return Err(DiagServiceError::BadPayload(format!(
                    "Unexpected parameters in request: {unexpected:?}"
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

                self.reject_unexpected_keys(
                    ["Selector", case_name].into_iter(),
                    value.keys().map(String::as_str),
                )?;

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

        let params: Vec<_> = structure
            .params()
            .into_iter()
            .flatten()
            .map(datatypes::Parameter)
            .collect();

        if self.strict_parameter_validation {
            self.reject_unexpected_keys(
                params.iter().filter_map(|p| p.short_name()),
                value.keys().map(String::as_str),
            )?;
        }

        params.into_iter().try_for_each(|param| {
            let short_name = param.short_name().ok_or_else(|| {
                DiagServiceError::InvalidDatabase("Unable to find short name for param".to_owned())
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
        self.reject_unexpected_keys(
            mapped_params.iter().filter_map(|p| p.short_name()),
            json_values.keys().map(String::as_str),
        )?;

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
    use cda_interfaces::{PayloadDecoder, PayloadEncoder, diagservices::UdsPayloadData};
    use cda_plugin_security::DefaultSecurityPluginData;
    use serde_json::json;

    use super::*;
    use crate::diag_kernel::test_utils::ecu_manager_builder::{
        create_ecu_manager_with_length_key_request_service, create_ecu_manager_with_mux_service,
        create_ecu_manager_with_mux_service_and_default_case,
        create_ecu_manager_with_param_length_info_service,
        create_ecu_manager_with_phys_const_normal_dop_service,
        create_ecu_manager_with_phys_const_structure_dop_service,
        create_ecu_manager_with_struct_service,
        create_ecu_manager_with_trailing_param_after_param_length_info_service,
    };

    macro_rules! skip_sec_plugin {
        () => {{
            let skip_sec_plugin: DynamicPlugin = Box::new(());
            skip_sec_plugin
        }};
    }

    fn create_payload(data: Vec<u8>) -> cda_interfaces::ServicePayload {
        cda_interfaces::ServicePayload {
            data,
            source_address: 0,
            target_address: 0,
            new_session: None,
            new_security: None,
        }
    }

    async fn test_mux_from_and_to_uds(
        ecu_manager: super::super::ecumanager::EcuManager<DefaultSecurityPluginData>,
        service: &cda_interfaces::DiagComm,
        sid: u8,
        data: &Vec<u8>,
        mux_1_json: serde_json::Value,
    ) {
        let response = ecu_manager
            .convert_from_uds(service, &create_payload(data.clone()), true, None)
            .await
            .unwrap();

        let expected_response_json = {
            let mut merged = mux_1_json.clone();
            merged
                .as_object_mut()
                .unwrap()
                .insert("test_service_pos_sid".to_string(), json!(sid));
            merged
        };

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

        assert_eq!(*service_payload.data, *data);
    }

    async fn validate_struct_payload(struct_byte_pos: u32) {
        let (ecu_manager, service, sid, struct_byte_len) =
            create_ecu_manager_with_struct_service(struct_byte_pos);

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

        assert_eq!(
            service_payload.data.len(),
            struct_byte_pos.saturating_add(struct_byte_len) as usize
        );

        assert_eq!(service_payload.data.first().copied(), Some(sid));

        let payload = service_payload
            .data
            .get(struct_byte_pos as usize..)
            .unwrap();

        assert_eq!(payload.first().copied(), Some(0x12));
        assert_eq!(payload.get(1).copied(), Some(0x34));

        let float_bytes = 42.42f32.to_be_bytes();
        assert_eq!(payload.get(2..6), Some(&float_bytes[..]));

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

        let test_value = json!({
            "param1": 0x1234
        });

        let payload_data = UdsPayloadData::ParameterMap(
            [("main_param".to_string(), test_value)]
                .into_iter()
                .collect(),
        );

        let result = ecu_manager
            .create_uds_payload(&service, &skip_sec_plugin!(), Some(payload_data), None)
            .await;

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

        let test_value = json!([1, 2, 3]);

        let payload_data = UdsPayloadData::ParameterMap(
            [("main_param".to_string(), test_value)]
                .into_iter()
                .collect(),
        );

        let result = ecu_manager
            .create_uds_payload(&service, &skip_sec_plugin!(), Some(payload_data), None)
            .await;

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
            ecu_manager: &super::super::ecumanager::EcuManager<DefaultSecurityPluginData>,
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

            assert_eq!(service_payload.data.first().copied(), Some(sid));
            assert_eq!(service_payload.data.get(1).copied(), Some(0));

            assert_eq!(
                service_payload.data.get(2).copied(),
                Some(((select_value >> 8) & 0xFF) as u8)
            );
            assert_eq!(
                service_payload.data.get(3).copied(),
                Some((select_value & 0xFF) as u8)
            );

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
        test_default(&ecu_manager, &service, without_selector, 0, sid).await;
    }

    #[tokio::test]
    async fn test_map_mux_to_uds_invalid_json_type() {
        let (ecu_manager, service, _) = create_ecu_manager_with_mux_service(None, None, None);

        let test_value = json!([1, 2, 3]);

        let payload_data = UdsPayloadData::ParameterMap(
            [("mux_1_param".to_string(), test_value)]
                .into_iter()
                .collect(),
        );

        let result = ecu_manager
            .create_uds_payload(&service, &skip_sec_plugin!(), Some(payload_data), None)
            .await;

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

        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Mux case mux_1_case_1 value not found in json")
        );
    }

    #[tokio::test]
    async fn test_phys_const_normal_dop_to_uds() {
        let (ecu_manager, dc, _sid) = create_ecu_manager_with_phys_const_normal_dop_service();

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

        assert_eq!(uds_bytes.first().copied().unwrap(), 0x2E);
        assert_eq!(uds_bytes.get(1).copied().unwrap(), 0xF1);
        assert_eq!(uds_bytes.get(2).copied().unwrap(), 0x90);
        assert_eq!(uds_bytes.get(3).copied().unwrap(), 0x12);
        assert_eq!(uds_bytes.get(4).copied().unwrap(), 0x34);
        assert_eq!(uds_bytes.get(5).copied().unwrap(), 0xAB);
    }

    #[tokio::test]
    async fn test_phys_const_structure_dop_roundtrip() {
        let (ecu_manager, dc, sid) = create_ecu_manager_with_phys_const_structure_dop_service();

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

        if let Some(byte) = service_payload.data.get_mut(0) {
            *byte = sid;
        }

        let decode_result = ecu_manager
            .convert_from_uds(&dc, &service_payload, true, None)
            .await;

        assert!(decode_result.is_ok());
        let mapped = decode_result.unwrap();

        assert!(mapped.mapped_data.is_some());
        let mapped_data = mapped.mapped_data.unwrap();

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
    async fn test_mux_from_and_to_uds_case_1() {
        let (ecu_manager, service, sid) = create_ecu_manager_with_mux_service(None, None, None);
        let param_1_value: f32 = 13.37;
        let param_1_bytes = param_1_value.to_be_bytes();
        #[rustfmt::skip]
        let data = [
            sid,
            0xff,
            0x00,
            0x05,
            param_1_bytes[0], param_1_bytes[1], param_1_bytes[2], param_1_bytes[3],
            0x07,
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
        #[rustfmt::skip]
        let data = [
            sid,
            0xff,
            0x00,
            0xaa,
            0xff,
            0x42,
            0x42,
            0x00,
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
        use cda_database::datatypes::{DataType, database_builder::EcuDataBuilder};

        let mut db_builder = EcuDataBuilder::new();
        let ascii_string_diag_type =
            db_builder.create_diag_coded_type_standard_length(32, DataType::AsciiString);
        let compu_identical =
            db_builder.create_compu_method(datatypes::CompuCategory::Identical, None, None);
        let switch_key_dop = db_builder.create_regular_normal_dop(
            "switch_key_dop",
            ascii_string_diag_type,
            compu_identical,
        );
        let switch_key = db_builder.create_switch_key(0, Some(0), Some(switch_key_dop));

        let (ecu_manager, service, sid) =
            create_ecu_manager_with_mux_service(Some(db_builder), Some(switch_key), None);
        #[rustfmt::skip]
        let data = [
            sid,
            0xff,
            0x74, 0x65, 0x73, 0x74,
        ];

        let mux_1_json = json!({
            "mux_1_param": {
                "Selector": "test",
            }
        });

        test_mux_from_and_to_uds(ecu_manager, &service, sid, &data.to_vec(), mux_1_json).await;
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
    async fn test_length_key_param_roundtrip() {
        let (ecu_manager, dc, sid) = create_ecu_manager_with_param_length_info_service();
        let pos_sid = sid.saturating_add(cda_interfaces::UDS_ID_RESPONSE_BITMASK);

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

    #[tokio::test]
    async fn test_trailing_param_after_param_length_info_roundtrip() {
        let (ecu_manager, dc, sid) =
            create_ecu_manager_with_trailing_param_after_param_length_info_service();
        let pos_sid = sid.saturating_add(cda_interfaces::UDS_ID_RESPONSE_BITMASK);

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

    #[tokio::test]
    async fn test_process_parameter_map_unexpected_params_strict() {
        let (mut ecu_manager, service, _, _) = create_ecu_manager_with_struct_service(1);
        ecu_manager.strict_parameter_validation = true;

        let struct_value = json!({"param1": 0x1234u32, "param2": 1.0f32, "param3": "hello"});
        // bogus_param is at the top-level service parameter map, not defined in the service
        let payload_data = UdsPayloadData::ParameterMap(
            [
                ("main_param".to_string(), struct_value),
                ("bogus_param".to_string(), json!("should be rejected")),
            ]
            .into_iter()
            .collect(),
        );

        // Strict mode: unexpected params cause a BadPayload error
        let result = ecu_manager
            .create_uds_payload(&service, &skip_sec_plugin!(), Some(payload_data), None)
            .await;

        assert!(result.is_err());
        if let Err(e) = result {
            assert!(
                e.to_string().contains("Unexpected parameters in request"),
                "Expected unexpected parameter error, got: {e}"
            );
        }
    }

    #[tokio::test]
    async fn test_process_parameter_map_nested_unexpected_params_strict() {
        let (mut ecu_manager, service, _, _) = create_ecu_manager_with_struct_service(1);
        ecu_manager.strict_parameter_validation = true;

        // bogus_nested is inside the struct value, not defined in the struct's sub-params
        let struct_value = json!({"param1": 0x1234u32, "param2": 1.0f32, "param3": "hello", "bogus_nested": "reject me"});
        let payload_data = UdsPayloadData::ParameterMap(
            [("main_param".to_string(), struct_value)]
                .into_iter()
                .collect(),
        );

        // Strict mode: unexpected nested params cause a BadPayload error
        let result = ecu_manager
            .create_uds_payload(&service, &skip_sec_plugin!(), Some(payload_data), None)
            .await;

        assert!(result.is_err());
        if let Err(e) = result {
            assert!(
                e.to_string().contains("Unexpected parameters in request"),
                "Expected unexpected parameter error for nested param, got: {e}"
            );
        }
    }

    /// Strict mode must reject unexpected keys inside a Mux parameter object.
    ///
    /// `map_mux_to_uds` only reads `"Selector"` and the matched case name;
    /// any extra keys must be rejected when `strict_parameter_validation` is
    /// enabled, mirroring the behaviour of `map_struct_to_uds` and
    /// `process_parameter_map`.
    #[tokio::test]
    async fn test_map_mux_to_uds_unexpected_params_strict() {
        let (mut ecu_manager, service, _) = create_ecu_manager_with_mux_service(None, None, None);
        ecu_manager.strict_parameter_validation = true;

        // Valid mux payload with an extra key "bogus_mux_key" at the mux
        // object level.  "Selector" and "mux_1_case_1" are the only
        // legitimate keys for this request.
        let test_value = json!({
            "mux_1_param": {
                "Selector": 5,
                "mux_1_case_1": {
                    "mux_1_case_1_param_1": 13.37f32,
                    "mux_1_case_1_param_2": 7
                },
                "bogus_mux_key": "should be rejected"
            }
        });

        let payload_data =
            UdsPayloadData::ParameterMap(serde_json::from_value(test_value).unwrap());

        let result = ecu_manager
            .create_uds_payload(&service, &skip_sec_plugin!(), Some(payload_data), None)
            .await;

        assert!(
            result.is_err(),
            "Expected strict mode to reject unexpected mux-level key 'bogus_mux_key', but the \
             request succeeded"
        );
        if let Err(e) = result {
            assert!(
                e.to_string().contains("Unexpected parameters in request"),
                "Expected 'Unexpected parameters in request' error, got: {e}"
            );
        }
    }
}
