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
    proto::dataformat::{EcuData, param},
};

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct Parameter {
    pub short_name: StringId,
    pub byte_pos: u32,
    pub bit_pos: u32,
    pub value: ParameterValue,
    pub semantic: Option<StringId>,
}

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub enum ParameterValue {
    CodedConst(CodedConst),
    MatchingRequestParam(MatchingRequestParam),
    Value(ValueData),
    Reserved(ReservedParam),
}
#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct CodedConst {
    pub value: StringId,
    pub diag_coded_type: Id,
}
#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct MatchingRequestParam {
    pub request_byte_pos: i32,
    pub byte_length: u32,
}
#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct ValueData {
    pub default_value: Option<StringId>,
    pub dop: Id,
}
#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct ReservedParam {
    pub bit_length: u32,
}

pub(super) fn get_parameters(ecu_data: &EcuData, ecu_db_path: &str) -> ParameterMap {
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
                None => {
                    return Err(DiagServiceError::InvalidDatabase(
                        "Param SpecificData not found".to_owned(),
                    ));
                }
                non_impl => {
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
                log::debug!(target: &ecu_db_path, "Error processing parameter: {e:?}");
                None
            }
        })
        .collect::<ParameterMap>()
}
