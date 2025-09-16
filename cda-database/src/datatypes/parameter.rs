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

use cda_interfaces::{DiagServiceError, STRINGS, StringId};
#[cfg(feature = "deepsize")]
use deepsize::DeepSizeOf;

use crate::{
    datatypes::{Id, ParameterMap, option_str_to_string, ref_optional_none},
    proto::dataformat::{EcuData, param, param::table_key::TableKeyReference},
};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct Parameter {
    pub short_name: StringId,
    pub byte_pos: u32,
    pub bit_pos: u32,
    pub value: ParameterValue,
    pub semantic: Option<StringId>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub enum ParameterValue {
    /// Fixed parameter values, which the user cannot change.
    /// For example the service id.
    CodedConst(CodedConst),
    /// Only used for replies, this is referencing data
    /// in the request that belongs to the response.
    MatchingRequestParam(MatchingRequestParam),
    /// Value references a DOP to convert a concrete value
    /// from the physical representation into the coded value.
    /// The physical default value is used when no value is provided.
    /// This mechanism is also used to re-use `Value` as type for PhysConst.
    Value(ValueData),
    /// Reserved bits in the payload.
    /// Currently used in the CDA for padding when creating UDS payloads and to provide
    /// values for DTCs, to make sure reserved DTC bits are extracted correctly.
    Reserved(ReservedParam),

    TableStructParam(TableStructParam),
}
#[derive(Debug, Clone)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct CodedConst {
    pub value: StringId,
    pub diag_coded_type: Id,
}
#[derive(Debug, Clone)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
/// Repetition of data from request
pub struct MatchingRequestParam {
    pub request_byte_pos: i32,
    pub byte_length: u32,
}
#[derive(Debug, Clone)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct ValueData {
    pub default_value: Option<StringId>,
    pub dop: Id,
}
#[derive(Debug, Clone)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct ReservedParam {
    pub bit_length: u32,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct TableStructParam {
    pub request_byte_pos: u32,
    pub bit_position: u32,
}

#[tracing::instrument(
    skip(ecu_data),
    fields(
        ecu_db_path = %_ecu_db_path,
        param_count = ecu_data.params.len()
    )
)]
pub(super) fn get_parameters(ecu_data: &EcuData, _ecu_db_path: &str) -> ParameterMap {
    ecu_data
        .params
        .iter()
        .map(|p| {
            let value = match &p.specific_data {
                Some(param::SpecificData::CodedConst(c)) => {
                    ParameterValue::CodedConst(CodedConst {
                        value: STRINGS.get_or_insert(&c.coded_value),
                        diag_coded_type: c
                            .diag_coded_type
                            .as_ref()
                            .ok_or_else(|| {
                                DiagServiceError::InvalidDatabase(
                                    "CodedConst has no type.".to_owned(),
                                )
                            })?
                            .r#ref
                            .as_ref()
                            .ok_or_else(|| ref_optional_none("diagCodedType.ref_pb"))?
                            .value,
                    })
                }
                Some(param::SpecificData::MatchingRequestParam(m)) => {
                    ParameterValue::MatchingRequestParam(MatchingRequestParam {
                        request_byte_pos: m.request_byte_pos,
                        byte_length: m.byte_length,
                    })
                }
                Some(param::SpecificData::Value(v)) => ParameterValue::Value(ValueData {
                    default_value: option_str_to_string(v.physical_default_value.as_ref()),
                    dop: v
                        .dop
                        .as_ref()
                        .ok_or_else(|| {
                            DiagServiceError::InvalidDatabase(
                                "Param Value has no DOP set.".to_owned(),
                            )
                        })?
                        .r#ref
                        .as_ref()
                        .ok_or_else(|| ref_optional_none("Value.dop.ref_pb"))?
                        .value,
                }),
                Some(param::SpecificData::Reserved(r)) => ParameterValue::Reserved(ReservedParam {
                    bit_length: r.bit_length,
                }),
                Some(param::SpecificData::PhysConst(c)) => ParameterValue::Value(ValueData {
                    default_value: Some(STRINGS.get_or_insert(&c.phys_constant_value)),
                    dop: c
                        .dop
                        .as_ref()
                        .ok_or_else(|| {
                            DiagServiceError::InvalidDatabase(
                                "Param Value has no DOP set.".to_owned(),
                            )
                        })?
                        .r#ref
                        .as_ref()
                        .ok_or_else(|| ref_optional_none("PhysConst.dop.ref_pb"))?
                        .value,
                }),
                Some(param::SpecificData::TableKey(t)) => t
                    .table_key_reference
                    .as_ref()
                    .ok_or_else(|| {
                        DiagServiceError::InvalidDatabase("TableKey has no reference.".to_owned())
                    })
                    .and_then(|table_key| match table_key {
                        TableKeyReference::Table(table_ref) => table_ref
                            .r#ref
                            .ok_or_else(|| ref_optional_none("Table.ref"))
                            .and_then(|table_ref_val| {
                                ecu_data
                                    .tables
                                    .iter()
                                    .find(|table| {
                                        table
                                            .id
                                            .is_some_and(|t_id| t_id.value == table_ref_val.value)
                                    })
                                    .ok_or_else(|| {
                                        DiagServiceError::InvalidDatabase(
                                            "TableKey reference not found in EcuData.tables"
                                                .to_owned(),
                                        )
                                    })
                            })
                            .and_then(|table| {
                                Ok(ParameterValue::Value(ValueData {
                                    default_value: Some(STRINGS.get_or_insert(&table.short_name)),
                                    dop: table
                                        .key_dop
                                        .as_ref()
                                        .ok_or_else(|| {
                                            DiagServiceError::InvalidDatabase(
                                                "Param Table has no key DOP set.".to_owned(),
                                            )
                                        })?
                                        .r#ref
                                        .as_ref()
                                        .ok_or_else(|| ref_optional_none("Table.key_dop.ref"))?
                                        .value,
                                }))
                            }),
                        TableKeyReference::TableRow(_row) => {
                            Err(DiagServiceError::InvalidDatabase(
                                "TableRow reference not yet implemented".to_owned(),
                            ))
                        }
                    })?,
                Some(param::SpecificData::TableStruct(t)) => t
                    .table_key
                    .iter()
                    .find_map(|key_ref| {
                        key_ref.r#ref.and_then(|param_id| {
                            ecu_data.params.iter().find(|table_key| {
                                table_key.id.is_some_and(|id| id.value == param_id.value)
                            })
                        })
                    })
                    .map(|p| {
                        ParameterValue::TableStructParam(TableStructParam {
                            request_byte_pos: p.byte_position(),
                            bit_position: p.bit_position(),
                        })
                    })
                    .ok_or(DiagServiceError::InvalidDatabase(
                        "TableStruct parameter has no valid TableKey reference.".to_owned(),
                    ))?,
                None => {
                    return Err(DiagServiceError::InvalidDatabase(
                        "Param SpecificData not found".to_owned(),
                    ));
                }
                non_impl => {
                    // Currently not implemented:
                    // TableKey, TableStruct, TableEntry, Dynamic, System, NrcConst
                    return Err(DiagServiceError::InvalidDatabase(format!(
                        "Param SpecificData({:?}) not implemented",
                        std::mem::discriminant(non_impl)
                    )));
                }
            };
            Ok((
                p.id.as_ref()
                    .ok_or_else(|| ref_optional_none("Param.id"))?
                    .value,
                Parameter {
                    short_name: STRINGS.get_or_insert(&p.short_name),
                    byte_pos: p.byte_position(),
                    bit_pos: p.bit_position(),
                    value,
                    semantic: option_str_to_string(p.semantic.as_ref()),
                },
            ))
        })
        .filter_map(|res| match res {
            Ok((id, param)) => Some((id, param)),
            Err(e) => {
                tracing::debug!(error = ?e, "Error processing parameter");
                None
            }
        })
        .collect::<ParameterMap>()
}
