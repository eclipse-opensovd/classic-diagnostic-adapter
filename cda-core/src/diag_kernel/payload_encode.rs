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

        // First narrow down to all services matching the SID (first byte), then
        // further narrow down by comparing the full sequence of coded-constant
        // bytes (SID, sub-function, DID, ...) against the provided raw payload.
        // This is required because multiple services commonly share the same
        // SID (e.g. every WriteDataByIdentifier DID is typically its own
        // service entry, all sharing SID 0x2E), so matching on the SID alone is
        // not sufficient to identify the correct service - doing so would pick
        // an arbitrary service with that SID, causing the wrong service to be
        // used for the access check (and thus reported in any resulting error).
        // If no service with a matching prefix can be found,
        // DiagServiceError::NotFound is returned to the caller.
        let sid_matched_services = self.lookup_services_by_sid(raw_data_sid)?;
        let mapped_service = sid_matched_services
            .iter()
            .find(|service| service.matches_request_prefix(&rawdata))
            .ok_or_else(|| {
                DiagServiceError::NotFound(format!(
                    "No matching generic service found for request prefix: {rawdata:02X?}"
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
        sibling_values: Option<SiblingValues<'_>>,
    ) -> Result<(), DiagServiceError> {
        //  ISO_22901-1:2008-11 7.3.5.4
        //  MATCHING-REQUEST-PARAM, DYNAMIC and NRC-CONST are only allowed in responses
        match param.param_type()? {
            datatypes::ParamType::CodedConst => Ok(()),
            datatypes::ParamType::MatchingRequestParam => Err(DiagServiceError::InvalidRequest(
                "MatchingRequestParam only supported for responses".to_owned(),
            )),
            datatypes::ParamType::Value => {
                self.map_param_value_to_uds(param, value, payload, parent_byte_pos, sibling_values)
            }
            datatypes::ParamType::Reserved => Self::map_reserved_param_to_uds(param, payload),
            datatypes::ParamType::TableStruct => {
                self.map_table_struct_to_uds(param, value, payload, parent_byte_pos, sibling_values)
            }
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
            datatypes::ParamType::TableKey => {
                Self::map_table_key_to_uds(param, value, payload, parent_byte_pos)
            }
        }
    }

    fn map_param_value_to_uds(
        &self,
        param: &datatypes::Parameter,
        value: Option<&serde_json::Value>,
        payload: &mut Vec<u8>,
        parent_byte_pos: usize,
        sibling_values: Option<SiblingValues<'_>>,
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

        // A dynamic length field needs its own handling of missing values
        // (invisible fields may be omitted), so it is dispatched before the
        // generic required-parameter resolution.
        if let datatypes::DataOperationVariant::DynamicLengthField(dynamic_length_field) =
            dop.variant()?
        {
            return self.map_dynamic_length_field_to_uds(
                param,
                &dynamic_length_field,
                value,
                payload,
                parent_byte_pos,
                sibling_values,
            );
        }

        let value = resolve_required_param(
            value,
            &dop,
            || value_data.physical_default_value(),
            param.short_name().unwrap_or_default(),
        )?;

        match dop.variant()? {
            datatypes::DataOperationVariant::Normal(normal_dop) => {
                let diag_type = normal_dop.diag_coded_type()?;
                let uds_data = json_value_to_uds_data(
                    &diag_type,
                    normal_dop.compu_method().map(Into::into),
                    normal_dop.physical_type().map(Into::into),
                    &value,
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

                        value.len() > u32::MAX as usize || value_len_u32 > max
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

                // The EndOfPdu field's own BYTE-POSITION only anchors the *first*
                // repeated structure. Each subsequent item must be appended directly
                // after the previously encoded one, because `DiagCodedType::encode`
                // writes at an absolute byte offset (resizing/overwriting `payload`),
                // rather than appending. Reusing a single fixed offset for every item
                // would make each item overwrite the previous one instead of
                // following it, silently discarding all but the last array element.
                let field_start_pos =
                    (param.byte_position() as usize).saturating_add(parent_byte_pos);
                for v in value {
                    // Use the current end of the payload as the position for this
                    // item, but never go backwards past the field's own start
                    // position (relevant for the very first item, in case earlier
                    // padding/reserved bits have not extended `payload` that far).
                    let item_byte_pos = payload.len().max(field_start_pos);
                    self.map_struct_to_uds(&structure, item_byte_pos, v, payload)?;
                }
                Ok(())
            }
            datatypes::DataOperationVariant::Structure(structure_dop) => self.map_struct_to_uds(
                &structure_dop,
                (param.byte_position() as usize).saturating_add(parent_byte_pos),
                &value,
                payload,
            ),
            datatypes::DataOperationVariant::StaticField(_static_field) => {
                Err(DiagServiceError::ParameterConversionError(
                    "Mapping StaticField DoP to UDS payload not implemented".to_owned(),
                ))
            }
            datatypes::DataOperationVariant::Mux(mux_dop) => {
                self.map_mux_to_uds(&mux_dop, &value, payload)
            }
            datatypes::DataOperationVariant::EnvDataDesc(_)
            | datatypes::DataOperationVariant::EnvData(_)
            | datatypes::DataOperationVariant::Dtc(_) => Err(DiagServiceError::InvalidDatabase(
                "EnvData(Desc) and DTC DoPs cannot be mapped via parameters to request, but \
                 handled via a dedicated 'faults' endpoint"
                    .to_owned(),
            )),
            datatypes::DataOperationVariant::DynamicLengthField(_) => {
                // handled above, before resolving the required value
                Err(DiagServiceError::InvalidDatabase(
                    "Unexpected DynamicLengthField DoP".to_owned(),
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
        let data_type = super::reserved_param_data_type(bit_length);
        let coded_type = datatypes::DiagCodedType::new_high_low_byte_order(
            data_type,
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

        let value = resolve_required_param(
            param_data,
            &dop,
            || p.phys_constant_value(),
            param.short_name().unwrap_or_default(),
        )?;

        // Handle different DOP variants - PhysConst can have Normal or Structure DOPs
        match dop.variant()? {
            datatypes::DataOperationVariant::Normal(normal_dop) => {
                let diag_type = normal_dop.diag_coded_type()?;
                let uds_data = json_value_to_uds_data(
                    &diag_type,
                    normal_dop.compu_method().map(Into::into),
                    normal_dop.physical_type().map(Into::into),
                    &value,
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
                    &value,
                    uds_payload_data,
                )?;
            }
            datatypes::DataOperationVariant::Mux(mux_dop) => {
                self.map_mux_to_uds(&mux_dop, &value, uds_payload_data)?;
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

    /// Encode a TABLE-KEY parameter: resolve the key string to its wire
    /// representation using the table's key DOP and compu method.
    fn map_table_key_to_uds(
        param: &datatypes::Parameter,
        value: Option<&serde_json::Value>,
        payload: &mut Vec<u8>,
        parent_byte_pos: usize,
    ) -> Result<(), DiagServiceError> {
        let value = value.ok_or_else(|| {
            DiagServiceError::InvalidRequest(format!(
                "Required TABLE-KEY parameter '{}' missing",
                param.short_name().unwrap_or_default()
            ))
        })?;

        let key_str = value.as_str().ok_or_else(|| {
            DiagServiceError::InvalidRequest(format!(
                "TABLE-KEY parameter '{}' must be a string, got: {value}",
                param.short_name().unwrap_or_default()
            ))
        })?;

        let table_key_data =
            param
                .specific_data_as_table_key()
                .ok_or(DiagServiceError::InvalidDatabase(
                    "TABLE-KEY param missing TableKey specific data".to_owned(),
                ))?;

        let table_dop = table_key_data.table_key_reference_as_table_dop().ok_or(
            DiagServiceError::InvalidDatabase("TABLE-KEY has no TableDop reference".to_owned()),
        )?;

        let key_dop = table_dop.key_dop().map(datatypes::DataOperation).ok_or(
            DiagServiceError::InvalidDatabase("TableDop missing key_dop".to_owned()),
        )?;

        let rows = table_dop.rows().ok_or(DiagServiceError::InvalidDatabase(
            "TableDop missing rows".to_owned(),
        ))?;

        // Verify the row exists (validates the key value)
        let row_exists = rows.iter().any(|row| {
            row.short_name().is_some_and(|name| name == key_str)
                || row.key().is_some_and(|k| k == key_str)
        });
        if !row_exists {
            let available: Vec<&str> = rows.iter().filter_map(|r| r.short_name()).collect();
            return Err(DiagServiceError::InvalidRequest(format!(
                "TABLE-KEY value '{key_str}' does not match any row. Available: {available:?}"
            )));
        }

        // Encode the key value using the key DOP's compu method
        match key_dop.variant()? {
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
            _ => Err(DiagServiceError::InvalidDatabase(
                "TABLE-KEY key_dop must be a NormalDOP".to_owned(),
            )),
        }
    }

    /// Encode a TABLE-STRUCT parameter: look up which row was selected by the
    /// companion TABLE-KEY, then encode that row's structure (if any).
    fn map_table_struct_to_uds(
        &self,
        param: &datatypes::Parameter,
        value: Option<&serde_json::Value>,
        payload: &mut Vec<u8>,
        parent_byte_pos: usize,
        sibling_values: Option<SiblingValues<'_>>,
    ) -> Result<(), DiagServiceError> {
        let table_struct_data =
            param
                .specific_data_as_table_struct()
                .ok_or(DiagServiceError::InvalidDatabase(
                    "TABLE-STRUCT param missing TableStruct specific data".to_owned(),
                ))?;

        // Follow back-reference to the TABLE-KEY param
        let table_key_param =
            table_struct_data
                .table_key()
                .ok_or(DiagServiceError::InvalidDatabase(
                    "TABLE-STRUCT missing table_key back-reference".to_owned(),
                ))?;
        let table_key_param = datatypes::Parameter(table_key_param);

        // Get the TABLE-KEY's short_name so we can look up the selected key
        // value from the sibling parameters
        let key_param_name =
            table_key_param
                .short_name()
                .ok_or(DiagServiceError::InvalidDatabase(
                    "TABLE-KEY param referenced by TABLE-STRUCT has no short_name".to_owned(),
                ))?;

        // Look up the selected key value from the sibling JSON values
        let sibling_values = sibling_values.ok_or_else(|| {
            DiagServiceError::InvalidRequest(
                "TABLE-STRUCT requires sibling parameter context to resolve the TABLE-KEY value"
                    .to_owned(),
            )
        })?;
        let key_value = sibling_values.get(key_param_name).ok_or_else(|| {
            DiagServiceError::InvalidRequest(format!(
                "TABLE-STRUCT references TABLE-KEY '{key_param_name}' but it is not in the \
                 request parameters"
            ))
        })?;
        let key_str = key_value.as_str().ok_or_else(|| {
            DiagServiceError::InvalidRequest(format!(
                "TABLE-KEY '{key_param_name}' must be a string, got: {key_value}"
            ))
        })?;

        // Resolve the TableDop and find the selected row
        let table_key_data = table_key_param.specific_data_as_table_key().ok_or(
            DiagServiceError::InvalidDatabase(
                "TABLE-KEY param missing TableKey specific data".to_owned(),
            ),
        )?;
        let table_dop = table_key_data.table_key_reference_as_table_dop().ok_or(
            DiagServiceError::InvalidDatabase("TABLE-KEY has no TableDop reference".to_owned()),
        )?;
        let rows = table_dop.rows().ok_or(DiagServiceError::InvalidDatabase(
            "TableDop missing rows".to_owned(),
        ))?;
        let selected_row = rows
            .iter()
            .find(|row| {
                row.short_name().is_some_and(|name| name == key_str)
                    || row.key().is_some_and(|k| k == key_str)
            })
            .ok_or_else(|| {
                DiagServiceError::InvalidRequest(format!(
                    "TABLE-KEY value '{key_str}' does not match any table row"
                ))
            })?;

        // Get the row's structure DOP (may be None for rows with no struct data)
        let structure_dop = selected_row.structure();

        match structure_dop {
            None => {
                // No structure for this row - accept empty input or None
                if let Some(v) = value
                    && !v.as_object().is_some_and(serde_json::Map::is_empty)
                {
                    return Err(DiagServiceError::InvalidRequest(format!(
                        "TABLE-STRUCT for row '{}' has no structure, but non-empty data was \
                         provided: {v}",
                        selected_row.short_name().unwrap_or_default()
                    )));
                }
                Ok(())
            }
            Some(structure_dop_ref) => {
                let structure_dop = datatypes::DataOperation(structure_dop_ref);
                match structure_dop.variant()? {
                    datatypes::DataOperationVariant::Structure(struct_dop) => {
                        // The JSON value should be either:
                        // - {<row_short_name>: {<params>}} (full form)
                        // - {} (acceptable if structure has no required params)
                        let row_name = selected_row.short_name().unwrap_or_default();
                        let struct_value = value.and_then(|v| v.as_object()).and_then(|obj| {
                            if obj.is_empty() {
                                // Empty object - treat as empty struct data
                                None
                            } else {
                                obj.get(row_name)
                            }
                        });

                        let struct_json = match struct_value {
                            Some(v) => v.clone(),
                            None => serde_json::Value::Object(serde_json::Map::new()),
                        };

                        self.map_struct_to_uds(
                            &struct_dop,
                            parent_byte_pos.saturating_add(param.byte_position() as usize),
                            &struct_json,
                            payload,
                        )
                    }
                    _ => Err(DiagServiceError::InvalidDatabase(format!(
                        "TABLE-STRUCT row '{}' structure DOP is not a Structure variant",
                        selected_row.short_name().unwrap_or_default()
                    ))),
                }
            }
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

            self.map_param_to_uds(
                &param,
                value.get(short_name),
                payload,
                struct_byte_pos,
                Some(SiblingValues::Object(value)),
            )
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
            self.map_param_to_uds(
                param,
                json_values.get(short_name),
                uds,
                parent_byte_pos,
                Some(SiblingValues::Map(json_values)),
            )?;
        }
        Ok(())
    }

    /// Encode an ODX DYNAMIC-LENGTH-FIELD (ISO 22901-1 7.3.6.10.4).
    ///
    /// This is the inverse of `map_dynamic_length_field_from_uds`:
    /// * The field is anchored at `parent_byte_pos + BYTE-POSITION` of the parameter.
    /// * The items are encoded one after another, starting at `anchor + OFFSET`.
    /// * The number of items is written at `anchor + DETERMINE-NUMBER-OF-ITEMS/BYTE-POSITION`
    ///   (and its BIT-POSITION) using the DOP of DETERMINE-NUMBER-OF-ITEMS.
    ///
    /// The count is written last and replaces whatever bits are already present at its
    /// position, as the count derived from the provided array is authoritative.
    fn map_dynamic_length_field_to_uds(
        &self,
        param: &datatypes::Parameter,
        dynamic_length_field: &datatypes::DynamicLengthDop,
        value: Option<&serde_json::Value>,
        payload: &mut Vec<u8>,
        parent_byte_pos: usize,
        sibling_values: Option<SiblingValues<'_>>,
    ) -> Result<(), DiagServiceError> {
        let field_name = param.short_name().unwrap_or_default();
        let field = dynamic_length_field
            .field()
            .map(datatypes::DopField)
            .ok_or_else(|| {
                DiagServiceError::InvalidDatabase(format!(
                    "DynamicLengthField '{field_name}' has no FIELD"
                ))
            })?;

        let items: &[serde_json::Value] = match value {
            Some(v) => v.as_array().map(Vec::as_slice).ok_or_else(|| {
                DiagServiceError::InvalidRequest(format!(
                    "Expected array value for DynamicLengthField '{field_name}', got: {v}"
                ))
            })?,
            // An invisible field cannot be provided by the user, encode it as empty.
            None if !field.is_visible() => &[],
            None => {
                return Err(DiagServiceError::InvalidRequest(format!(
                    "Required parameter '{field_name}' missing",
                )));
            }
        };

        let item_kind = DynamicLengthFieldItem::from_field(&field, field_name)?;
        let count_info = DynamicLengthFieldCount::from_dop(dynamic_length_field, field_name)?;

        let param_abs_byte_pos = parent_byte_pos.saturating_add(param.byte_position() as usize);
        let count_byte_pos = param_abs_byte_pos.saturating_add(count_info.byte_position);
        let count_end = count_byte_pos.saturating_add(count_info.byte_len());
        let items_start = param_abs_byte_pos.saturating_add(dynamic_length_field.offset() as usize);

        let coded_count = count_info.coded_count(items.len(), field_name)?;

        if payload.len() < items_start {
            payload.resize(items_start, 0);
        }

        let mut item_pos = items_start;
        for (index, item) in items.iter().enumerate() {
            item_pos = self
                .map_dynamic_length_field_item_to_uds(
                    &item_kind,
                    item,
                    payload,
                    item_pos,
                    sibling_values,
                )
                .map_err(|e| {
                    prefix_error(
                        e,
                        &format!("DynamicLengthField '{field_name}' item {index}"),
                    )
                })?;
        }

        if item_pos > items_start && count_byte_pos < item_pos && items_start < count_end {
            return Err(DiagServiceError::InvalidDatabase(format!(
                "DynamicLengthField '{field_name}': item count at bytes \
                 {count_byte_pos}..{count_end} overlaps the items at bytes \
                 {items_start}..{item_pos}"
            )));
        }

        self.write_dynamic_length_field_count(
            &count_info,
            coded_count,
            payload,
            count_byte_pos,
            field_name,
        )
    }

    /// Encodes one item of a dynamic length field at `item_pos` and returns the position
    /// at which the next item starts.
    fn map_dynamic_length_field_item_to_uds(
        &self,
        item_kind: &DynamicLengthFieldItem<'_>,
        item: &serde_json::Value,
        payload: &mut Vec<u8>,
        item_pos: usize,
        sibling_values: Option<SiblingValues<'_>>,
    ) -> Result<usize, DiagServiceError> {
        // Each item is encoded into its own buffer (anchored at 0), so its extent is
        // exactly the buffer length. Deriving it from `payload.len()` would be wrong
        // whenever the payload already contains data beyond `item_pos`, e.g. a later
        // parameter with an explicit BYTE-POSITION that was encoded before the field.
        let mut item_data = Vec::new();
        let item_len = match item_kind {
            DynamicLengthFieldItem::Structure(structure) => {
                self.map_struct_to_uds(structure, 0, item, &mut item_data)?;
                match structure.byte_size() {
                    Some(byte_size) => {
                        let byte_size = byte_size as usize;
                        if item_data.len() > byte_size {
                            return Err(DiagServiceError::InvalidRequest(format!(
                                "Encoded item needs {} bytes, but the structure has a fixed \
                                 BYTE-SIZE of {byte_size}",
                                item_data.len()
                            )));
                        }
                        byte_size
                    }
                    None => item_data.len(),
                }
            }
            DynamicLengthFieldItem::EnvDataDesc(env_data_desc) => {
                self.map_env_data_desc_item_to_uds(
                    env_data_desc,
                    item,
                    &mut item_data,
                    0,
                    sibling_values,
                )?;
                item_data.len()
            }
        };

        let item_end = item_pos.saturating_add(item_len);
        if payload.len() < item_end {
            payload.resize(item_end, 0);
        }
        // Merge like `DiagCodedType::encode` does: OR into the existing bytes.
        payload
            .get_mut(item_pos..item_pos.saturating_add(item_data.len()))
            .ok_or_else(|| {
                DiagServiceError::BadPayload("DynamicLengthField item out of bounds".to_owned())
            })?
            .iter_mut()
            .zip(&item_data)
            .for_each(|(dst, src)| *dst |= src);
        Ok(item_end)
    }

    /// Inverse of `map_env_data_desc_item_from_uds`: resolves the ENV-DATA selected by the
    /// value of the sibling parameter referenced by the ENV-DATA-DESC and encodes its params.
    fn map_env_data_desc_item_to_uds(
        &self,
        env_data_desc: &datatypes::EnvDataDescDop,
        item: &serde_json::Value,
        payload: &mut Vec<u8>,
        item_pos: usize,
        sibling_values: Option<SiblingValues<'_>>,
    ) -> Result<(), DiagServiceError> {
        let item = item.as_object().ok_or_else(|| {
            DiagServiceError::InvalidRequest(format!(
                "Expected value to be object type, but it was: {item}"
            ))
        })?;
        let selector_name = env_data_desc.param_short_name().ok_or_else(|| {
            DiagServiceError::InvalidDatabase("EnvDataDesc missing param_short_name".to_owned())
        })?;
        let selector_value = sibling_values
            .and_then(|siblings| siblings.get(selector_name))
            .ok_or_else(|| {
                DiagServiceError::InvalidRequest(format!(
                    "EnvDataDesc selector parameter '{selector_name}' not found in request"
                ))
            })?;
        let discriminator = json_value_to_u32(selector_value).ok_or_else(|| {
            DiagServiceError::InvalidRequest(format!(
                "EnvDataDesc selector parameter '{selector_name}' must be an unsigned 32 bit \
                 number, got: {selector_value}"
            ))
        })?;
        let env_datas = env_data_desc.env_datas().ok_or_else(|| {
            DiagServiceError::InvalidDatabase("EnvDataDesc has no env_datas".to_owned())
        })?;

        // Same selection as the decoder: exact match first, wildcard second.
        let matching_env_data = env_datas
            .iter()
            .filter_map(|dop| dop.specific_data_as_env_data())
            .find(|env_data| {
                env_data
                    .dtc_values()
                    .is_some_and(|values| values.iter().any(|v| v == discriminator))
            })
            .or_else(|| {
                env_datas
                    .iter()
                    .filter_map(|dop| dop.specific_data_as_env_data())
                    .find(|env_data| env_data.dtc_values().is_none_or(|v| v.is_empty()))
            });

        let Some(env_data) = matching_env_data else {
            // The decoder yields an empty item in this case, accept exactly that.
            if item.is_empty() {
                return Ok(());
            }
            return Err(DiagServiceError::InvalidRequest(format!(
                "No EnvData matches selector '{selector_name}' value {discriminator:#X}"
            )));
        };

        let params: Vec<_> = env_data
            .params()
            .into_iter()
            .flatten()
            .map(datatypes::Parameter)
            .collect();
        self.reject_unexpected_keys(
            params.iter().filter_map(|p| p.short_name()),
            item.keys().map(String::as_str),
        )?;
        params.iter().try_for_each(|param| {
            let short_name = param.short_name().ok_or_else(|| {
                DiagServiceError::InvalidDatabase("EnvData param missing short_name".to_owned())
            })?;
            self.map_param_to_uds(
                param,
                item.get(short_name),
                payload,
                item_pos,
                Some(SiblingValues::Object(item)),
            )
        })
    }

    /// Writes the item count of a dynamic length field, replacing existing bits.
    ///
    /// Another parameter (e.g. a selector sharing the byte) may already have written a
    /// value at the count position. If it differs from the actual item count this is
    /// rejected in strict mode, otherwise it is logged and overwritten.
    fn write_dynamic_length_field_count(
        &self,
        count_info: &DynamicLengthFieldCount,
        coded_count: Vec<u8>,
        payload: &mut Vec<u8>,
        count_byte_pos: usize,
        field_name: &str,
    ) -> Result<(), DiagServiceError> {
        let byte_len = count_info.byte_len();
        let bit_pos = count_info.bit_position;

        let mut canonical = vec![0u8; byte_len];
        count_info
            .diag_type
            .encode(coded_count.clone(), &mut canonical, 0, bit_pos)?;
        let (new_bits, _) = count_info.diag_type.decode(&canonical, 0, bit_pos)?;

        let mut existing: Vec<u8> = payload
            .iter()
            .skip(count_byte_pos)
            .take(byte_len)
            .copied()
            .collect();
        existing.resize(byte_len, 0);
        let (old_bits, _) = count_info.diag_type.decode(&existing, 0, bit_pos)?;

        if old_bits.iter().any(|&b| b != 0) && old_bits != new_bits {
            if self.strict_parameter_validation {
                return Err(DiagServiceError::InvalidRequest(format!(
                    "DynamicLengthField '{field_name}': the item count position (byte \
                     {count_byte_pos}, bit {bit_pos}) already holds {old_bits:02X?}, which \
                     conflicts with the item count {new_bits:02X?} derived from the provided items"
                )));
            }
            tracing::warn!(
                field = field_name,
                existing = ?old_bits,
                count = ?new_bits,
                "Overwriting conflicting value at DynamicLengthField item count position with \
                 the count derived from the provided items"
            );
        }

        count_info
            .diag_type
            .encode_replace(coded_count, payload, count_byte_pos, bit_pos)
    }
}

/// Parameter values on the same level as the parameter being encoded, used to resolve
/// references to sibling parameters (TABLE-KEY, ENV-DATA-DESC selector).
#[derive(Clone, Copy)]
enum SiblingValues<'a> {
    Map(&'a HashMap<String, serde_json::Value>),
    Object(&'a serde_json::Map<String, serde_json::Value>),
}

impl<'a> SiblingValues<'a> {
    fn get(self, key: &str) -> Option<&'a serde_json::Value> {
        match self {
            SiblingValues::Map(map) => map.get(key),
            SiblingValues::Object(object) => object.get(key),
        }
    }
}

/// The repeated item of a dynamic length field, either a structure or an ENV-DATA-DESC.
enum DynamicLengthFieldItem<'a> {
    Structure(datatypes::StructureDop<'a>),
    EnvDataDesc(datatypes::EnvDataDescDop<'a>),
}

impl<'a> DynamicLengthFieldItem<'a> {
    fn from_field(
        field: &datatypes::DopField<'a>,
        field_name: &str,
    ) -> Result<Self, DiagServiceError> {
        match (field.basic_structure(), field.env_data_desc()) {
            (Some(structure), None) => structure
                .specific_data_as_structure()
                .map(|s| Self::Structure(datatypes::StructureDop(s)))
                .ok_or_else(|| {
                    DiagServiceError::InvalidDatabase(format!(
                        "DynamicLengthField '{field_name}' BASIC-STRUCTURE is not a structure"
                    ))
                }),
            (None, Some(env_data_desc)) => env_data_desc
                .specific_data_as_env_data_desc()
                .map(|e| Self::EnvDataDesc(datatypes::EnvDataDescDop(e)))
                .ok_or_else(|| {
                    DiagServiceError::InvalidDatabase(format!(
                        "DynamicLengthField '{field_name}' ENV-DATA-DESC is not an EnvDataDesc"
                    ))
                }),
            (Some(_), Some(_)) => Err(DiagServiceError::InvalidDatabase(format!(
                "DynamicLengthField '{field_name}' defines both BASIC-STRUCTURE and ENV-DATA-DESC"
            ))),
            (None, None) => Err(DiagServiceError::InvalidDatabase(format!(
                "DynamicLengthField '{field_name}' defines neither BASIC-STRUCTURE nor \
                 ENV-DATA-DESC"
            ))),
        }
    }
}

/// Validated DETERMINE-NUMBER-OF-ITEMS information of a dynamic length field.
struct DynamicLengthFieldCount {
    byte_position: usize,
    bit_position: usize,
    diag_type: datatypes::DiagCodedType,
    compu_method: Option<datatypes::CompuMethod>,
    physical_type: Option<datatypes::PhysicalType>,
    lower_limit: Option<datatypes::Limit>,
    upper_limit: Option<datatypes::Limit>,
    bit_length: u32,
    /// Maximum number of bits that can carry the coded count
    capacity_bits: u32,
    /// Non-condensed bit mask, coded values must not set bits outside of it
    plain_mask: Option<u64>,
}

impl DynamicLengthFieldCount {
    fn from_dop(
        dynamic_length_field: &datatypes::DynamicLengthDop,
        field_name: &str,
    ) -> Result<Self, DiagServiceError> {
        let invalid = |msg: &str| {
            DiagServiceError::InvalidDatabase(format!("DynamicLengthField '{field_name}': {msg}"))
        };

        let determine_num_items = dynamic_length_field
            .determine_number_of_items()
            .ok_or_else(|| invalid("DETERMINE-NUMBER-OF-ITEMS is missing"))?;
        let normal_dop = determine_num_items
            .dop()
            .ok_or_else(|| invalid("DETERMINE-NUMBER-OF-ITEMS has no DOP"))?
            .specific_data_as_normal_dop()
            .map(datatypes::NormalDop)
            .ok_or_else(|| invalid("DETERMINE-NUMBER-OF-ITEMS DOP is not a NormalDOP"))?;
        let diag_type = normal_dop.diag_coded_type()?;
        if diag_type.base_datatype() != datatypes::DataType::UInt32 {
            return Err(invalid(
                "DETERMINE-NUMBER-OF-ITEMS DOP must have base data type A_UINT32",
            ));
        }
        let datatypes::DiagCodedTypeVariant::StandardLength(standard_length) = diag_type.type_()
        else {
            return Err(invalid(
                "DETERMINE-NUMBER-OF-ITEMS DOP must use a STANDARD-LENGTH-TYPE",
            ));
        };
        let bit_length = standard_length.bit_length;
        if bit_length == 0 || bit_length > 32 {
            return Err(invalid(
                "DETERMINE-NUMBER-OF-ITEMS bit length must be 1..=32",
            ));
        }
        let mask = standard_length
            .bit_mask
            .as_ref()
            .filter(|m| !m.is_empty())
            .map(|m| {
                m.iter()
                    .rev()
                    .take(8)
                    .rev()
                    .fold(0u64, |acc, &b| (acc << 8) | u64::from(b))
            });
        let (capacity_bits, plain_mask) = match mask {
            Some(mask) if standard_length.condensed => (mask.count_ones().min(bit_length), None),
            Some(mask) => (bit_length, Some(mask)),
            None => (bit_length, None),
        };

        let bit_position = determine_num_items.bit_position() as usize;
        if bit_position > 7 {
            return Err(invalid(
                "DETERMINE-NUMBER-OF-ITEMS bit position must be 0..=7",
            ));
        }

        let internal_constr = normal_dop.internal_constr();
        Ok(Self {
            byte_position: determine_num_items.byte_position() as usize,
            bit_position,
            compu_method: normal_dop.compu_method().map(Into::into),
            physical_type: normal_dop.physical_type().map(Into::into),
            lower_limit: internal_constr
                .and_then(|c| c.lower_limit())
                .map(Into::into),
            upper_limit: internal_constr
                .and_then(|c| c.upper_limit())
                .map(Into::into),
            diag_type,
            bit_length,
            capacity_bits,
            plain_mask,
        })
    }

    fn byte_len(&self) -> usize {
        self.bit_position
            .saturating_add(self.bit_length as usize)
            .div_ceil(8)
    }

    /// Converts the physical item count into its validated coded representation.
    fn coded_count(&self, count: usize, field_name: &str) -> Result<Vec<u8>, DiagServiceError> {
        let invalid = |msg: String| {
            DiagServiceError::InvalidRequest(format!("DynamicLengthField '{field_name}': {msg}"))
        };
        let count_u32 = u32::try_from(count)
            .map_err(|_| invalid(format!("{count} items exceed the maximum item count")))?;

        let coded = json_value_to_uds_data(
            &self.diag_type,
            self.compu_method.clone(),
            self.physical_type,
            &serde_json::Value::from(count_u32),
        )
        .map_err(|e| invalid(format!("cannot encode item count {count}: {e}")))?;

        if coded.len() > 8 {
            return Err(invalid(format!(
                "coded item count {coded:02X?} exceeds 64 bits"
            )));
        }
        let coded_value = coded.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b));

        if self.capacity_bits < u64::BITS && coded_value >> self.capacity_bits != 0 {
            return Err(invalid(format!(
                "item count {count} (coded {coded_value}) does not fit into the {} bit(s) \
                 available for the item count",
                self.capacity_bits
            )));
        }
        if let Some(mask) = self.plain_mask
            && coded_value & !mask != 0
        {
            return Err(invalid(format!(
                "item count {count} (coded {coded_value}) cannot be represented with bit mask \
                 {mask:#X}"
            )));
        }

        #[allow(
            clippy::cast_precision_loss,
            reason = "Coded value is limited to 32 bits and fits into f64 exactly"
        )]
        let coded_f64 = coded_value as f64;
        check_limit(self.lower_limit.as_ref(), coded_f64, true)
            .and_then(|()| check_limit(self.upper_limit.as_ref(), coded_f64, false))
            .map_err(|msg| {
                invalid(format!(
                    "item count {count} (coded {coded_value}) violates the internal constraint: \
                     {msg}"
                ))
            })?;

        Ok(coded)
    }
}

/// Checks `value` against an optional internal constraint limit.
/// Returns a description of the violation on failure.
fn check_limit(limit: Option<&datatypes::Limit>, value: f64, is_lower: bool) -> Result<(), String> {
    let Some(limit) = limit else {
        return Ok(());
    };
    if limit.interval_type == datatypes::IntervalType::Infinite {
        return Ok(());
    }
    let Ok(bound) = TryInto::<f64>::try_into(limit) else {
        tracing::warn!(limit = ?limit, "Ignoring non-numeric internal constraint limit");
        return Ok(());
    };
    let closed = limit.interval_type == datatypes::IntervalType::Closed;
    let ok = match (is_lower, closed) {
        (true, true) => value >= bound,
        (true, false) => value > bound,
        (false, true) => value <= bound,
        (false, false) => value < bound,
    };
    if ok {
        Ok(())
    } else {
        let (op, kind) = match (is_lower, closed) {
            (true, true) => (">=", "lower"),
            (true, false) => (">", "lower"),
            (false, true) => ("<=", "upper"),
            (false, false) => ("<", "upper"),
        };
        Err(format!("{kind} limit requires value {op} {bound}"))
    }
}

/// Interprets the physical value of an ENV-DATA-DESC selector as `u32`.
///
/// ISO 22901-1 7.3.6.10.3: the switch-key is the *physical* value of the referenced
/// parameter and its PHYSICAL-TYPE shall be `A_UINT32`. Accepted representations, mirroring
/// what the decoder produces:
/// * integer numbers, or floats with an integral value (e.g. from a LINEAR compu method),
/// * decimal or `0x` prefixed hex strings,
/// * DTC objects, using their `code` (as the decoder does for DTC-DOP selectors).
fn json_value_to_u32(value: &serde_json::Value) -> Option<u32> {
    match value {
        serde_json::Value::Number(n) => n.as_u64().or_else(|| {
            n.as_f64()
                .filter(|f| f.fract() == 0.0 && *f >= 0.0 && *f <= f64::from(u32::MAX))
                .map(|f| {
                    #[allow(
                        clippy::cast_possible_truncation,
                        clippy::cast_sign_loss,
                        reason = "Checked above to be an integral value within u32 range"
                    )]
                    let v = f as u64;
                    v
                })
        }),
        serde_json::Value::String(s) => {
            let s = s.trim();
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u64::from_str_radix(hex, 16).ok()
            } else {
                s.parse().ok()
            }
        }
        serde_json::Value::Object(obj) => return obj.get("code").and_then(json_value_to_u32),
        _ => None,
    }
    .and_then(|n| u32::try_from(n).ok())
}

/// Prefixes the message of `error` with `prefix`, keeping the error kind.
fn prefix_error(error: DiagServiceError, prefix: &str) -> DiagServiceError {
    match error {
        DiagServiceError::InvalidRequest(msg) => {
            DiagServiceError::InvalidRequest(format!("{prefix}: {msg}"))
        }
        DiagServiceError::InvalidDatabase(msg) => {
            DiagServiceError::InvalidDatabase(format!("{prefix}: {msg}"))
        }
        DiagServiceError::BadPayload(msg) => {
            DiagServiceError::BadPayload(format!("{prefix}: {msg}"))
        }
        DiagServiceError::ParameterConversionError(msg) => {
            DiagServiceError::ParameterConversionError(format!("{prefix}: {msg}"))
        }
        other => other,
    }
}

/// Convert a *physical* value string (e.g. a `PHYSICAL-DEFAULT-VALUE` or
/// `PHYS-CONSTANT-VALUE`) into a [`serde_json::Value`] for compu-method encoding.
///
/// Unlike [`str_to_json_value`], which parses a value against the *coded*
/// datatype, physical values may be text-table keys (e.g. `"ACTIVE"`).
/// Numeric strings become `Value::Number`; all other strings are kept as
/// `Value::String` so a downstream `TEXTTABLE` compu method can resolve them
/// to the coded value.
fn resolve_required_param<S: AsRef<str>>(
    provided_value: Option<&serde_json::Value>,
    dop: &datatypes::DataOperation,
    default_value: impl FnOnce() -> Option<S>,
    param_name: &str,
) -> Result<serde_json::Value, DiagServiceError> {
    if let Some(value) = provided_value {
        return Ok(value.clone());
    }
    match dop.variant()? {
        datatypes::DataOperationVariant::Normal(_) => {
            let str_val = default_value().ok_or_else(|| {
                DiagServiceError::InvalidRequest(format!(
                    "Required parameter '{param_name}' missing",
                ))
            })?;
            Ok(phys_value_str_to_json(str_val.as_ref()))
        }
        _ => Err(DiagServiceError::InvalidRequest(format!(
            "Required parameter '{param_name}' missing",
        ))),
    }
}

fn phys_value_str_to_json(value: &str) -> serde_json::Value {
    if let Ok(number) = try_parse_str_as_json_number(value) {
        number
    } else {
        serde_json::Value::from(value)
    }
}

fn try_parse_str_as_json_number(value: &str) -> Result<serde_json::Value, DiagServiceError> {
    if let Ok(number) = value.parse::<i64>() {
        Ok(serde_json::Value::Number(number.into()))
    } else if let Ok(number) = value.parse::<u64>() {
        Ok(serde_json::Value::Number(number.into()))
    } else if let Ok(number) = value.parse::<f64>() {
        let float = serde_json::Number::from_f64(number).ok_or_else(|| {
            DiagServiceError::ParameterConversionError(format!(
                "Failed to parse string '{value}' as a number"
            ))
        })?;

        Ok(serde_json::Value::Number(float))
    } else {
        Err(DiagServiceError::ParameterConversionError(format!(
            "Failed to parse string '{value}' as a number"
        )))
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

            let const_json_value =
                if let Ok(number) = try_parse_str_as_json_number(coded_const_value) {
                    number
                } else {
                    str_to_json_value(coded_const_value, diag_type.base_datatype())?
                };

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
    use cda_interfaces::{
        PayloadDecoder, PayloadEncoder, diagservices::UdsPayloadData, service_ids, util::std_ext,
    };
    use cda_plugin_security::DefaultSecurityPluginData;
    use serde_json::json;

    use super::*;
    use crate::diag_kernel::test_utils::ecu_manager_builder::{
        create_ecu_manager_with_end_pdu_request_service,
        create_ecu_manager_with_length_key_request_service,
        create_ecu_manager_with_multiple_routine_control_services,
        create_ecu_manager_with_multiple_write_did_services, create_ecu_manager_with_mux_service,
        create_ecu_manager_with_mux_service_and_default_case,
        create_ecu_manager_with_param_length_info_service,
        create_ecu_manager_with_phys_const_normal_dop_service,
        create_ecu_manager_with_phys_const_structure_dop_service,
        create_ecu_manager_with_phys_const_text_table_service,
        create_ecu_manager_with_struct_service,
        create_ecu_manager_with_trailing_param_after_param_length_info_service,
        create_ecu_manager_with_value_default_text_table_service,
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

    /// Verifies that `map_phys_const_param_to_uds` correctly handles a
    /// `PHYS-CONST` parameter whose `phys_constant_value` is a text-table key
    /// (e.g. "ACTIVE") rather than a numeric literal.
    ///
    /// Regression test: previously, calling `str_to_json_value("ACTIVE", UInt32)`
    /// tried to parse the text-table key as a numeric value and failed with
    /// "cannot parse as u32". The fix wraps non-numeric values as JSON strings,
    /// allowing the `TextTable` compu method to resolve them to the coded value.
    #[tokio::test]
    async fn test_phys_const_text_table_value_encodes_correctly() {
        let (ecu_manager, dc, _sid) = create_ecu_manager_with_phys_const_text_table_service();

        // No user-provided parameters - the PHYS-CONST "MODE" uses its
        // embedded phys_constant_value "ACTIVE" which maps to coded value 1
        // via the TextTable compu method.
        let payload_data = UdsPayloadData::ParameterMap(serde_json::from_value(json!({})).unwrap());

        let result = ecu_manager
            .create_uds_payload(&dc, &skip_sec_plugin!(), Some(payload_data), None)
            .await;

        assert!(
            result.is_ok(),
            "Encoding failed (text-table phys const value not resolved): {:?}",
            result.unwrap_err()
        );

        let service_payload = result.unwrap();
        let uds_bytes = &service_payload.data;

        // byte 0: SID coded const = 0x22 (ReadDataByIdentifier)
        assert_eq!(
            uds_bytes.first().copied().unwrap(),
            service_ids::READ_DATA_BY_IDENTIFIER,
            "SID byte should be 0x22 (ReadDataByIdentifier)"
        );
        // byte 1: MODE phys const "ACTIVE" -> text-table maps to coded value 1
        assert_eq!(
            uds_bytes.get(1).copied().unwrap(),
            0x01,
            "MODE byte should be 0x01 (text-table key 'ACTIVE' resolved to coded value 1)"
        );
    }

    /// Verifies that `map_param_value_to_uds` correctly handles a VALUE
    /// parameter whose `physical_default_value` is a text-table key
    /// (e.g. "ACTIVE") rather than a numeric literal.
    ///
    /// Regression test: currently, calling `str_to_json_value("ACTIVE", UInt32)`
    /// tries to parse the text-table key as a numeric value and fails with
    /// "cannot parse as u32". The fix should wrap non-numeric values as JSON
    /// strings, allowing the `TextTable` compu method to resolve them to the
    /// coded value.
    #[tokio::test]
    async fn test_value_default_text_table_value_encodes_correctly() {
        let (ecu_manager, dc, _sid) = create_ecu_manager_with_value_default_text_table_service();

        // No user-provided parameters - the VALUE param "MODE" uses its
        // embedded physical_default_value "ACTIVE" which should map to coded
        // value 1 via the TextTable compu method.
        let payload_data = UdsPayloadData::ParameterMap(serde_json::from_value(json!({})).unwrap());

        let result = ecu_manager
            .create_uds_payload(&dc, &skip_sec_plugin!(), Some(payload_data), None)
            .await;

        assert!(
            result.is_ok(),
            "Encoding failed (text-table VALUE default value not resolved): {:?}",
            result.unwrap_err()
        );

        let service_payload = result.unwrap();
        let uds_bytes = &service_payload.data;

        // byte 0: SID coded const = 0x22 (ReadDataByIdentifier)
        assert_eq!(
            uds_bytes.first().copied().unwrap(),
            service_ids::READ_DATA_BY_IDENTIFIER,
            "SID byte should be 0x22 (ReadDataByIdentifier)"
        );
        // byte 1: MODE VALUE default "ACTIVE" -> text-table maps to coded value 1
        assert_eq!(
            uds_bytes.get(1).copied().unwrap(),
            0x01,
            "MODE byte should be 0x01 (text-table key 'ACTIVE' resolved to coded value 1)"
        );
    }

    /// Regression test for a fixed-count `EndOfPdu` array parameter (`min_items ==
    /// max_items == 2`), where each item is a struct containing a single
    /// leading-length-prefixed byte field (`RepeatedItem { leading_length_field:
    /// <leading-length ByteField> }`).
    ///
    /// Each `leading_length_field` value is encoded as `[len_byte, ...data]`. With
    /// two distinct 1-byte values (`0xAA` and `0xBB`), the correctly encoded
    /// request must contain BOTH items back-to-back:
    /// `SID, 0x01, 0xAA,  0x01, 0xBB` (6 bytes total).
    ///
    /// Before the fix, `map_param_value_to_uds`'s `EndOfPdu` handling computed the
    /// struct byte position once, outside the loop over array items, and reused it
    /// for every item. Since `DiagCodedType::encode` writes at an *absolute* byte
    /// offset (overwriting, not appending), every item after the first one clobbers
    /// the bytes of the previous item at the same offset. The resulting payload only
    /// contains the last-encoded item, i.e. `SID, 0x01, 0xBB` (3 bytes) - the first
    /// `RepeatedItem` entry (and its leading-length field) is silently lost.
    #[tokio::test]
    async fn test_end_of_pdu_request_encodes_all_items_not_just_last() {
        let (ecu_manager, service, sid) =
            create_ecu_manager_with_end_pdu_request_service(2, Some(2));

        let payload_data = UdsPayloadData::ParameterMap(
            serde_json::from_value(json!({
                "repeated_items": [
                    { "leading_length_field": "AA" },
                    { "leading_length_field": "BB" }
                ]
            }))
            .unwrap(),
        );

        let result = ecu_manager
            .create_uds_payload(&service, &skip_sec_plugin!(), Some(payload_data), None)
            .await;

        let service_payload = result
            .unwrap_or_else(|e| panic!("Encoding the two-item EndOfPdu request failed: {e:?}"));
        let uds_bytes = &service_payload.data;

        assert_eq!(
            uds_bytes.as_slice(),
            &[sid, 0x01, 0xAA, 0x01, 0xBB][..],
            "Expected both RepeatedItem entries to be appended sequentially, but the second item \
             overwrote the first at the same absolute byte offset"
        );
    }

    /// Regression test for the `EndOfPdu` item-count validation bug where the
    /// comparison `max > value_len` was used instead of `value_len > max`.
    ///
    /// With `min_items = 1` and `max_items = Some(20)`, providing a single item is valid
    /// (`1` is within `[1, 20]`), but the buggy comparison (`20 > 1` => `true`) incorrectly
    /// rejected the request with "`EndOfPdu` expected different amount of items".
    #[tokio::test]
    async fn test_end_of_pdu_accepts_item_count_within_min_max_range() {
        let (ecu_manager, service, sid) =
            create_ecu_manager_with_end_pdu_request_service(1, Some(20));

        let payload_data = UdsPayloadData::ParameterMap(
            serde_json::from_value(json!({
                "repeated_items": [
                    { "leading_length_field": "AA" }
                ]
            }))
            .unwrap(),
        );

        let result = ecu_manager
            .create_uds_payload(&service, &skip_sec_plugin!(), Some(payload_data), None)
            .await;

        let service_payload = result.unwrap_or_else(|e| {
            panic!(
                "Encoding a single-item EndOfPdu request (within min/max range) should succeed, \
                 but failed with: {e:?}"
            )
        });

        assert_eq!(service_payload.data.as_slice(), &[sid, 0x01, 0xAA][..]);
    }

    /// Regression test ensuring that providing MORE items than `max_number_of_items`
    /// is still correctly rejected after fixing the comparison direction.
    #[tokio::test]
    async fn test_end_of_pdu_rejects_item_count_above_max() {
        let (ecu_manager, service, _sid) =
            create_ecu_manager_with_end_pdu_request_service(1, Some(1));

        let payload_data = UdsPayloadData::ParameterMap(
            serde_json::from_value(json!({
                "repeated_items": [
                    { "leading_length_field": "AA" },
                    { "leading_length_field": "BB" }
                ]
            }))
            .unwrap(),
        );

        let result = ecu_manager
            .create_uds_payload(&service, &skip_sec_plugin!(), Some(payload_data), None)
            .await;

        assert!(
            result.is_err(),
            "Expected an error when providing more items than max_number_of_items allows"
        );
    }

    /// Regression test for `check_genericservice` incorrectly matching services
    /// by SID alone. When multiple services share the same SID (e.g. several
    /// `WriteDataByIdentifier` services, each for a different DID, all sharing
    /// SID `0x2E`), the raw payload bytes *following* the SID (the DID) must
    /// also be compared, otherwise an arbitrary same-SID service can be
    /// selected - resulting in the wrong service being used for the
    /// precondition/access check (and thus the wrong service name being
    /// reported in any resulting error).
    #[tokio::test]
    async fn test_check_genericservice_matches_correct_did_not_first_same_sid_service() {
        let (
            ecu_manager,
            unrestricted_did,
            unrestricted_name,
            programming_only_did,
            programming_only_name,
        ) = create_ecu_manager_with_multiple_write_did_services();

        // Default state: LockedSecurity / DefaultSession - does NOT satisfy the
        // ProgrammingSecurity precondition of the second service.
        {
            let mut guard = std_ext::lock_write(&ecu_manager.runtime_state.service_states);
            guard.insert(service_ids::SESSION_CONTROL, "DefaultSession".to_string());
            guard.insert(service_ids::SECURITY_ACCESS, "LockedSecurity".to_string());
        }

        let sid = service_ids::WRITE_DATA_BY_IDENTIFIER;
        let did_hi = |did: u16| (did >> 8) as u8;
        let did_lo = |did: u16| (did & 0xFF) as u8;

        // Raw payload for the unrestricted DID must succeed, regardless of
        // which same-SID service happens to be evaluated first.
        let unrestricted_payload = vec![sid, did_hi(unrestricted_did), did_lo(unrestricted_did)];
        let unrestricted_result = ecu_manager
            .check_genericservice(&skip_sec_plugin!(), unrestricted_payload)
            .await;
        assert!(
            unrestricted_result.is_ok(),
            "Expected genericservice call for unrestricted DID {unrestricted_did:#06X} \
             ({unrestricted_name}) to succeed, got: {:?}",
            unrestricted_result.err()
        );

        // Raw payload for the DID that requires ProgrammingSecurity must be
        // rejected, and the error must reference the *actually matched*
        // service, not an arbitrary same-SID service.
        let programming_only_payload = vec![
            sid,
            did_hi(programming_only_did),
            did_lo(programming_only_did),
        ];
        let programming_only_result = ecu_manager
            .check_genericservice(&skip_sec_plugin!(), programming_only_payload)
            .await;
        let err = programming_only_result.expect_err(&format!(
            "Expected genericservice call for restricted DID {programming_only_did:#06X} \
             ({programming_only_name}) to fail due to unmet ProgrammingSecurity precondition"
        ));
        let err_msg = err.to_string();
        assert!(
            err_msg.contains(&programming_only_name),
            "Expected error message to reference the actually matched service \
             '{programming_only_name}', got: {err_msg}"
        );
        assert!(
            !err_msg.contains(&unrestricted_name),
            "Error message should not reference the unrelated service '{unrestricted_name}', got: \
             {err_msg}"
        );
    }

    /// Regression test for `check_genericservice` incorrectly matching services
    /// by SID alone, for a service (`RoutineControl`, SID `0x31`) whose
    /// disambiguating bytes span a sub-function byte *and* a routine
    /// identifier, rather than a single DID immediately following the SID.
    /// Matching by SID alone would arbitrarily pick a same-SID service,
    /// resulting in the wrong service being used for the precondition/access
    /// check (and thus the wrong service name being reported in any resulting
    /// error).
    #[tokio::test]
    async fn test_check_genericservice_matches_correct_routine_not_first_same_sid_service() {
        let (
            ecu_manager,
            unrestricted_routine_id,
            unrestricted_name,
            programming_only_routine_id,
            programming_only_name,
        ) = create_ecu_manager_with_multiple_routine_control_services();

        // Default state: LockedSecurity / DefaultSession - does NOT satisfy the
        // ProgrammingSecurity precondition of the second service.
        {
            let mut guard = std_ext::lock_write(&ecu_manager.runtime_state.service_states);
            guard.insert(service_ids::SESSION_CONTROL, "DefaultSession".to_string());
            guard.insert(service_ids::SECURITY_ACCESS, "LockedSecurity".to_string());
        }

        let sid = service_ids::ROUTINE_CONTROL;
        let subfunction = cda_interfaces::subfunction_ids::routine::REQUEST_RESULTS;
        let id_hi = |id: u16| (id >> 8) as u8;
        let id_lo = |id: u16| (id & 0xFF) as u8;

        // Raw payload for the unrestricted routine ID must succeed, regardless
        // of which same-SID service happens to be evaluated first.
        let unrestricted_payload = vec![
            sid,
            subfunction,
            id_hi(unrestricted_routine_id),
            id_lo(unrestricted_routine_id),
        ];
        let unrestricted_result = ecu_manager
            .check_genericservice(&skip_sec_plugin!(), unrestricted_payload)
            .await;
        assert!(
            unrestricted_result.is_ok(),
            "Expected genericservice call for unrestricted routine ID \
             {unrestricted_routine_id:#06X} ({unrestricted_name}) to succeed, got: {:?}",
            unrestricted_result.err()
        );

        // Raw payload for the routine ID that requires ProgrammingSecurity must
        // be rejected, and the error must reference the *actually matched*
        // service, not an arbitrary same-SID service.
        let programming_only_payload = vec![
            sid,
            subfunction,
            id_hi(programming_only_routine_id),
            id_lo(programming_only_routine_id),
        ];
        let programming_only_result = ecu_manager
            .check_genericservice(&skip_sec_plugin!(), programming_only_payload)
            .await;
        let err = programming_only_result.expect_err(&format!(
            "Expected genericservice call for restricted routine ID \
             {programming_only_routine_id:#06X} ({programming_only_name}) to fail due to unmet \
             ProgrammingSecurity precondition"
        ));
        let err_msg = err.to_string();
        assert!(
            err_msg.contains(&programming_only_name),
            "Expected error message to reference the actually matched service \
             '{programming_only_name}', got: {err_msg}"
        );
        assert!(
            !err_msg.contains(&unrestricted_name),
            "Error message should not reference the unrelated service '{unrestricted_name}', got: \
             {err_msg}"
        );
    }

    mod dynamic_length_field {
        use cda_database::datatypes::{DataType, IntervalType, Limit};
        use cda_interfaces::{
            DiagServiceError, DynamicPlugin, EcuSchemas, PayloadDecoder, PayloadEncoder,
            diagservices::UdsPayloadData,
        };
        use cda_plugin_security::DefaultSecurityPluginData;
        use serde_json::json;

        use super::create_payload;
        use crate::diag_kernel::{
            ecumanager::EcuManager,
            test_utils::ecu_manager_builder::{
                DlfCountCompu, DlfItemConfig, DlfRequestConfig,
                create_ecu_manager_with_dlf_request_service,
            },
        };

        /// SID + DID 0x1234 prefix of every request
        const PREFIX: [u8; 3] = [0x2E, 0x12, 0x34];

        fn manager(
            config: &DlfRequestConfig,
        ) -> (
            EcuManager<DefaultSecurityPluginData>,
            cda_interfaces::DiagComm,
        ) {
            let (ecu_manager, service, _) = create_ecu_manager_with_dlf_request_service(config);
            (ecu_manager, service)
        }

        async fn encode(
            ecu_manager: &EcuManager<DefaultSecurityPluginData>,
            service: &cda_interfaces::DiagComm,
            value: serde_json::Value,
        ) -> Result<Vec<u8>, DiagServiceError> {
            let payload_data = UdsPayloadData::ParameterMap(serde_json::from_value(value).unwrap());
            ecu_manager
                .create_uds_payload(service, &skip_sec_plugin!(), Some(payload_data), None)
                .await
                .map(|p| p.data)
        }

        async fn decode(
            ecu_manager: &EcuManager<DefaultSecurityPluginData>,
            service: &cda_interfaces::DiagComm,
            data: Vec<u8>,
        ) -> serde_json::Value {
            ecu_manager
                .convert_from_uds(service, &create_payload(data), true, None)
                .await
                .unwrap()
                .serialize_to_json()
                .unwrap()
                .data
        }

        fn expected(tail: &[u8]) -> Vec<u8> {
            let mut v = PREFIX.to_vec();
            v.extend_from_slice(tail);
            v
        }

        /// Encodes `value`, checks the bytes and decodes them again, expecting the same
        /// `items` array.
        async fn assert_round_trip(
            config: &DlfRequestConfig,
            value: serde_json::Value,
            tail: &[u8],
        ) {
            let (ecu_manager, service) = manager(config);
            let data = encode(&ecu_manager, &service, value.clone()).await.unwrap();
            assert_eq!(data, expected(tail));
            let decoded = decode(&ecu_manager, &service, data).await;
            assert_eq!(
                decoded.get("items"),
                value.get("items"),
                "decoded: {decoded}"
            );
        }

        async fn encode_err(
            config: &DlfRequestConfig,
            value: serde_json::Value,
        ) -> DiagServiceError {
            let (ecu_manager, service) = manager(config);
            encode(&ecu_manager, &service, value).await.unwrap_err()
        }

        fn closed(value: &str) -> Limit {
            Limit {
                value: value.to_owned(),
                interval_type: IntervalType::Closed,
            }
        }

        #[tokio::test]
        async fn test_zero_items() {
            assert_round_trip(&DlfRequestConfig::default(), json!({"items": []}), &[0x00]).await;
        }

        #[tokio::test]
        async fn test_one_item() {
            assert_round_trip(
                &DlfRequestConfig::default(),
                json!({"items": [{"val": 0x1122}]}),
                &[0x01, 0x11, 0x22],
            )
            .await;
        }

        #[tokio::test]
        async fn test_multiple_items() {
            assert_round_trip(
                &DlfRequestConfig::default(),
                json!({"items": [{"val": 0x1122}, {"val": 0x3344}, {"val": 0x5566}]}),
                &[0x03, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            )
            .await;
        }

        #[tokio::test]
        async fn test_selector_sharing_count_byte() {
            let config = DlfRequestConfig {
                selector_byte_pos: Some(3),
                ..Default::default()
            };
            let (mut ecu_manager, service) = manager(&config);
            let two_items = json!([{"val": 0x1122}, {"val": 0x3344}]);

            // consistent values
            let data = encode(
                &ecu_manager,
                &service,
                json!({"selector": 2, "items": two_items}),
            )
            .await
            .unwrap();
            assert_eq!(data, expected(&[0x02, 0x11, 0x22, 0x33, 0x44]));

            // conflicting selector value is overwritten by the count in lenient mode
            let data = encode(
                &ecu_manager,
                &service,
                json!({"selector": 5, "items": two_items}),
            )
            .await
            .unwrap();
            assert_eq!(data, expected(&[0x02, 0x11, 0x22, 0x33, 0x44]));

            // ... and rejected in strict mode
            ecu_manager.strict_parameter_validation = true;
            let err = encode(
                &ecu_manager,
                &service,
                json!({"selector": 5, "items": two_items}),
            )
            .await
            .unwrap_err();
            assert!(
                matches!(&err, DiagServiceError::InvalidRequest(msg) if msg.contains("conflicts")),
                "{err:?}"
            );
            let data = encode(
                &ecu_manager,
                &service,
                json!({"selector": 2, "items": two_items}),
            )
            .await
            .unwrap();
            assert_eq!(data, expected(&[0x02, 0x11, 0x22, 0x33, 0x44]));
        }

        #[tokio::test]
        async fn test_count_with_byte_and_bit_position() {
            let config = DlfRequestConfig {
                count_byte_pos: 1,
                count_bit_pos: 4,
                count_bit_len: 4,
                offset: 2,
                ..Default::default()
            };
            assert_round_trip(
                &config,
                json!({"items": [{"val": 0x1122}, {"val": 0x3344}]}),
                &[0x00, 0x20, 0x11, 0x22, 0x33, 0x44],
            )
            .await;
        }

        #[tokio::test]
        async fn test_16_bit_count_both_byte_orders() {
            for (high_low, count_bytes) in [(true, [0x00, 0x02]), (false, [0x02, 0x00])] {
                let config = DlfRequestConfig {
                    count_bit_len: 16,
                    count_high_low: high_low,
                    offset: 2,
                    ..Default::default()
                };
                let mut tail = count_bytes.to_vec();
                tail.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
                assert_round_trip(
                    &config,
                    json!({"items": [{"val": 0x1122}, {"val": 0x3344}]}),
                    &tail,
                )
                .await;
            }
        }

        #[tokio::test]
        async fn test_count_overflow() {
            let config = DlfRequestConfig {
                count_bit_len: 2,
                ..Default::default()
            };
            let items: Vec<_> = (0..4).map(|i| json!({"val": i})).collect();
            let err = encode_err(&config, json!({"items": items})).await;
            assert!(
                matches!(err, DiagServiceError::InvalidRequest(_)),
                "{err:?}"
            );

            let items: Vec<_> = (0..3).map(|i| json!({"val": i})).collect();
            let (ecu_manager, service) = manager(&config);
            let data = encode(&ecu_manager, &service, json!({"items": items}))
                .await
                .unwrap();
            assert_eq!(data.get(3), Some(&0x03));
        }

        #[tokio::test]
        async fn test_condensed_mask_capacity() {
            let config = DlfRequestConfig {
                count_mask: Some(vec![0xF0]),
                count_condensed: true,
                ..Default::default()
            };
            // only 4 bits available -> 16 items do not fit
            let items: Vec<_> = (0..16).map(|i| json!({"val": i})).collect();
            let err = encode_err(&config, json!({"items": items})).await;
            assert!(
                matches!(&err, DiagServiceError::InvalidRequest(msg) if msg.contains("4 bit")),
                "{err:?}"
            );

            assert_round_trip(
                &config,
                json!({"items": [{"val": 1}, {"val": 2}, {"val": 3}]}),
                &[0x30, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03],
            )
            .await;
        }

        #[tokio::test]
        async fn test_internal_constraint() {
            let config = DlfRequestConfig {
                count_lower_limit: Some(Limit {
                    value: "0".to_owned(),
                    interval_type: IntervalType::Open,
                }),
                count_upper_limit: Some(closed("2")),
                ..Default::default()
            };
            let err = encode_err(&config, json!({"items": []})).await;
            assert!(
                matches!(&err, DiagServiceError::InvalidRequest(msg) if msg.contains("lower")),
                "{err:?}"
            );
            let items: Vec<_> = (0..3).map(|i| json!({"val": i})).collect();
            let err = encode_err(&config, json!({"items": items})).await;
            assert!(
                matches!(&err, DiagServiceError::InvalidRequest(msg) if msg.contains("upper")),
                "{err:?}"
            );
            assert_round_trip(
                &config,
                json!({"items": [{"val": 1}, {"val": 2}]}),
                &[0x02, 0x00, 0x01, 0x00, 0x02],
            )
            .await;
        }

        #[tokio::test]
        async fn test_linear_compu_count() {
            // phys = coded - 1  =>  coded = items + 1
            let config = DlfRequestConfig {
                count_compu: DlfCountCompu::Linear {
                    offset: -1.0,
                    factor: 1.0,
                },
                ..Default::default()
            };
            assert_round_trip(
                &config,
                json!({"items": [{"val": 1}, {"val": 2}]}),
                &[0x03, 0x00, 0x01, 0x00, 0x02],
            )
            .await;
        }

        #[tokio::test]
        async fn test_offset_zero_overlaps_count() {
            let config = DlfRequestConfig {
                offset: 0,
                ..Default::default()
            };
            let err = encode_err(&config, json!({"items": [{"val": 1}]})).await;
            assert!(
                matches!(err, DiagServiceError::InvalidDatabase(_)),
                "{err:?}"
            );

            // no items -> nothing overlaps
            let (ecu_manager, service) = manager(&config);
            let data = encode(&ecu_manager, &service, json!({"items": []}))
                .await
                .unwrap();
            assert_eq!(data, expected(&[0x00]));
        }

        #[tokio::test]
        async fn test_offset_gap_is_zero_filled() {
            let config = DlfRequestConfig {
                offset: 3,
                ..Default::default()
            };
            assert_round_trip(
                &config,
                json!({"items": [{"val": 0x1122}]}),
                &[0x01, 0x00, 0x00, 0x11, 0x22],
            )
            .await;

            // an empty field still covers the gap up to the item start
            let (ecu_manager, service) = manager(&config);
            let data = encode(&ecu_manager, &service, json!({"items": []}))
                .await
                .unwrap();
            assert_eq!(data, expected(&[0x00, 0x00, 0x00]));
        }

        #[tokio::test]
        async fn test_fixed_byte_size_padding() {
            let config = DlfRequestConfig {
                item: DlfItemConfig::Fixed { byte_size: Some(4) },
                ..Default::default()
            };
            assert_round_trip(
                &config,
                json!({"items": [{"val": 0x1122}, {"val": 0x3344}]}),
                &[0x02, 0x11, 0x22, 0x00, 0x00, 0x33, 0x44, 0x00, 0x00],
            )
            .await;
        }

        #[tokio::test]
        async fn test_fixed_byte_size_overflow() {
            let config = DlfRequestConfig {
                item: DlfItemConfig::Fixed { byte_size: Some(1) },
                ..Default::default()
            };
            let err = encode_err(&config, json!({"items": [{"val": 0x1122}]})).await;
            assert!(
                matches!(&err, DiagServiceError::InvalidRequest(msg)
                    if msg.contains("'items' item 0") && msg.contains("BYTE-SIZE")),
                "{err:?}"
            );
        }

        #[tokio::test]
        async fn test_variable_length_items() {
            let config = DlfRequestConfig {
                item: DlfItemConfig::VariableLength,
                ..Default::default()
            };
            let (ecu_manager, service) = manager(&config);
            let data = encode(
                &ecu_manager,
                &service,
                json!({"items": [{"data": "0x0102"}, {"data": "0x03"}]}),
            )
            .await
            .unwrap();
            assert_eq!(data, expected(&[0x02, 0x02, 0x01, 0x02, 0x01, 0x03]));
            let decoded = decode(&ecu_manager, &service, data).await;
            assert_eq!(
                decoded
                    .get("items")
                    .and_then(|v| v.as_array())
                    .map(Vec::len),
                Some(2),
                "{decoded}"
            );
        }

        #[tokio::test]
        async fn test_nested_dynamic_length_field() {
            assert_round_trip(
                &DlfRequestConfig {
                    item: DlfItemConfig::Nested,
                    ..Default::default()
                },
                json!({"items": [{"inner": [{"v": 1}, {"v": 2}]}, {"inner": []}]}),
                &[0x02, 0x02, 0x01, 0x02, 0x00],
            )
            .await;
        }

        #[tokio::test]
        async fn test_non_array_and_non_object_values() {
            let err = encode_err(&DlfRequestConfig::default(), json!({"items": {"val": 1}})).await;
            assert!(
                matches!(&err, DiagServiceError::InvalidRequest(msg) if msg.contains("array")),
                "{err:?}"
            );
            let err = encode_err(&DlfRequestConfig::default(), json!({"items": [1]})).await;
            assert!(
                matches!(&err, DiagServiceError::InvalidRequest(msg) if msg.contains("item 0")),
                "{err:?}"
            );
        }

        #[tokio::test]
        async fn test_missing_value() {
            let err = encode_err(&DlfRequestConfig::default(), json!({})).await;
            assert!(
                matches!(&err, DiagServiceError::InvalidRequest(msg) if msg.contains("missing")),
                "{err:?}"
            );

            let config = DlfRequestConfig {
                is_visible: false,
                ..Default::default()
            };
            let (ecu_manager, service) = manager(&config);
            let data = encode(&ecu_manager, &service, json!({})).await.unwrap();
            assert_eq!(data, expected(&[0x00]));
        }

        #[tokio::test]
        async fn test_invalid_count_dop() {
            for config in [
                DlfRequestConfig {
                    count_dop_is_structure: true,
                    ..Default::default()
                },
                DlfRequestConfig {
                    count_base_type: DataType::Int32,
                    ..Default::default()
                },
            ] {
                let err = encode_err(&config, json!({"items": []})).await;
                assert!(
                    matches!(err, DiagServiceError::InvalidDatabase(_)),
                    "{err:?}"
                );
            }
        }

        #[tokio::test]
        async fn test_param_without_byte_position_after_sibling() {
            let config = DlfRequestConfig {
                param_byte_pos: None,
                // relative to the field, which starts right after `sibling` (byte 4)
                count_byte_pos: 0,
                offset: 1,
                ..Default::default()
            };
            let value = json!({"sibling": 0xAB, "items": [{"val": 0x1122}]});
            assert_round_trip(&config, value, &[0xAB, 0x01, 0x11, 0x22]).await;
        }

        #[tokio::test]
        async fn test_env_data_desc_items() {
            let config = DlfRequestConfig {
                selector_byte_pos: Some(3),
                param_byte_pos: Some(4),
                item: DlfItemConfig::EnvDataDesc { wildcard: false },
                ..Default::default()
            };
            assert_round_trip(
                &config,
                json!({"selector": 2, "items": [{"b": 0x1122}, {"b": 0x3344}]}),
                &[0x02, 0x02, 0x11, 0x22, 0x33, 0x44],
            )
            .await;
            assert_round_trip(
                &config,
                json!({"selector": 1, "items": [{"a": 0x11}]}),
                &[0x01, 0x01, 0x11],
            )
            .await;

            // no matching ENV-DATA and no wildcard
            let err = encode_err(&config, json!({"selector": 7, "items": [{"a": 1}]})).await;
            assert!(
                matches!(err, DiagServiceError::InvalidRequest(_)),
                "{err:?}"
            );
        }

        #[tokio::test]
        async fn test_env_data_desc_wildcard() {
            let config = DlfRequestConfig {
                selector_byte_pos: Some(3),
                param_byte_pos: Some(4),
                item: DlfItemConfig::EnvDataDesc { wildcard: true },
                ..Default::default()
            };
            assert_round_trip(
                &config,
                json!({"selector": 7, "items": [{"w": 0x55}]}),
                &[0x07, 0x01, 0x55],
            )
            .await;
        }

        #[tokio::test]
        async fn test_env_data_desc_missing_selector() {
            let config = DlfRequestConfig {
                item: DlfItemConfig::EnvDataDesc { wildcard: true },
                ..Default::default()
            };
            let err = encode_err(&config, json!({"items": [{"w": 1}]})).await;
            assert!(
                matches!(&err, DiagServiceError::InvalidRequest(msg) if msg.contains("selector")),
                "{err:?}"
            );
        }

        #[tokio::test]
        async fn test_field_with_both_or_neither_item_kind() {
            for item in [DlfItemConfig::Both, DlfItemConfig::Neither] {
                let config = DlfRequestConfig {
                    item,
                    selector_byte_pos: Some(3),
                    param_byte_pos: Some(4),
                    ..Default::default()
                };
                let err = encode_err(&config, json!({"selector": 1, "items": []})).await;
                assert!(
                    matches!(err, DiagServiceError::InvalidDatabase(_)),
                    "{err:?}"
                );
            }
        }

        #[tokio::test]
        async fn test_variable_length_items_with_later_param_encoded_first() {
            // `trailer` (byte 9) is encoded before `items`, so the payload already
            // extends past the items when they are encoded.
            let config = DlfRequestConfig {
                item: DlfItemConfig::VariableLength,
                trailer_byte_pos: Some(9),
                ..Default::default()
            };
            let (ecu_manager, service) = manager(&config);
            let data = encode(
                &ecu_manager,
                &service,
                json!({"trailer": 0xAB, "items": [{"data": "0x0102"}, {"data": "0x03"}]}),
            )
            .await
            .unwrap();
            assert_eq!(data, expected(&[0x02, 0x02, 0x01, 0x02, 0x01, 0x03, 0xAB]));
        }

        #[tokio::test]
        async fn test_fixed_byte_size_overflow_with_later_param_encoded_first() {
            let config = DlfRequestConfig {
                item: DlfItemConfig::Fixed { byte_size: Some(1) },
                trailer_byte_pos: Some(9),
                ..Default::default()
            };
            let err = encode_err(
                &config,
                json!({"trailer": 0xAB, "items": [{"val": 0x1122}]}),
            )
            .await;
            assert!(
                matches!(&err, DiagServiceError::InvalidRequest(msg) if msg.contains("BYTE-SIZE")),
                "{err:?}"
            );
        }

        #[tokio::test]
        async fn test_env_data_desc_unexpected_keys_only_rejected_in_strict_mode() {
            let config = DlfRequestConfig {
                selector_byte_pos: Some(3),
                param_byte_pos: Some(4),
                item: DlfItemConfig::EnvDataDesc { wildcard: false },
                ..Default::default()
            };
            let value = json!({"selector": 1, "items": [{"a": 0x11, "extra": 1}]});
            let (mut ecu_manager, service) = manager(&config);
            let data = encode(&ecu_manager, &service, value.clone()).await.unwrap();
            assert_eq!(data, expected(&[0x01, 0x01, 0x11]));

            ecu_manager.strict_parameter_validation = true;
            let err = encode(&ecu_manager, &service, value).await.unwrap_err();
            assert!(
                matches!(&err, DiagServiceError::BadPayload(msg) if msg.contains("extra")),
                "{err:?}"
            );
        }

        #[test]
        fn test_selector_value_representations() {
            use super::super::json_value_to_u32;
            assert_eq!(json_value_to_u32(&json!(2)), Some(2));
            assert_eq!(json_value_to_u32(&json!(2.0)), Some(2));
            assert_eq!(json_value_to_u32(&json!(2.5)), None);
            assert_eq!(json_value_to_u32(&json!(-1)), None);
            assert_eq!(json_value_to_u32(&json!(4_294_967_296u64)), None);
            assert_eq!(json_value_to_u32(&json!("0x120")), Some(0x120));
            assert_eq!(json_value_to_u32(&json!("288")), Some(288));
            assert_eq!(
                json_value_to_u32(&json!({"code": 288, "display_code": "P0120"})),
                Some(288)
            );
            assert_eq!(json_value_to_u32(&json!({"display_code": "P0120"})), None);
            assert_eq!(json_value_to_u32(&json!("on")), None);
        }

        #[tokio::test]
        async fn test_request_schema() {
            let (ecu_manager, service) = manager(&DlfRequestConfig::default());
            let schema = ecu_manager.schema_for_request(&service).await.unwrap();
            let schema = serde_json::to_value(schema.into_schema().unwrap()).unwrap();
            let items = schema
                .pointer("/properties/items")
                .unwrap_or_else(|| panic!("no items in {schema}"));
            assert_eq!(items.get("type"), Some(&json!("array")));
            assert_eq!(items.get("minItems"), Some(&json!(0)));
            assert_eq!(items.get("maxItems"), Some(&json!(255)));
            assert!(items.pointer("/items/properties/val").is_some(), "{items}");
        }
    }
}
