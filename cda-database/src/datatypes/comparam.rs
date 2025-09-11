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

use cda_interfaces::{
    DiagServiceError, STRINGS, StringId,
    datatypes::{ComParamSimpleValue, ComParamValue, Unit},
};
#[cfg(feature = "deepsize")]
use deepsize::DeepSizeOf;
use hashbrown::HashMap;

use crate::{
    datatypes::{
        ComParamMap, DataOperation, DataOperationVariant, DiagnosticDatabase, Id, Protocol,
        option_str_to_string, ref_optional_none,
    },
    proto::dataformat::{self, com_param, complex_value::complex_value_entry},
};

#[derive(Debug, Default)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct ComParamRef {
    pub simple_value: Option<StringId>,
    pub complex_value: Option<ComplexValue>,
    pub com_param_id: Id,
    pub protocol_id: Option<Id>,
}

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct ComplexValue {
    pub id: Id,
    pub entries: Vec<ComplexValueEntry>,
}

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub enum ComplexValueEntry {
    SimpleValue(StringId),
    ComplexValue(ComplexValue),
}

#[derive(Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct ComParam {
    pub short_name: StringId,
    pub variant: ComParamVariant,
}
#[derive(Debug, Clone)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub enum ComParamVariant {
    Regular(RegularComParam),
    Complex(ComplexComParam),
}
#[derive(Debug, Clone)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct RegularComParam {
    pub default_value: Option<StringId>,
    pub dop: Id,
}
#[derive(Debug, Clone)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct ComplexComParam {
    pub com_params: Vec<Id>,
}

pub(super) fn get_comparams(ecu_data: &dataformat::EcuData) -> ComParamMap {
    ecu_data
        .com_params
        .iter()
        .map(|cp| -> Result<(u32, ComParam), DiagServiceError> {
            // println!("ComParam: {:?}", cp.shortName);
            let variant = map_comparam_variant(cp)?;
            // println!("ComParam Variant: {:?}", variant);
            let short_name = STRINGS.get_or_insert(&cp.short_name);
            Ok((
                cp.id
                    .as_ref()
                    .ok_or_else(|| ref_optional_none("ComParam.id"))?
                    .value,
                ComParam {
                    short_name,
                    variant,
                },
            ))
        })
        .filter_map(std::result::Result::ok)
        .collect::<ComParamMap>()
}

#[tracing::instrument(skip(r), fields(ctx = %_ctx))]
pub(super) fn map_comparam_ref(
    r: &dataformat::ComParamRef,
    _ctx: &str,
) -> Option<Result<ComParamRef, DiagServiceError>> {
    let Some(com_param_id) = r
        .com_param
        .as_ref()
        .and_then(|cpr| cpr.r#ref.as_ref().map(|obid| obid.value))
    else {
        tracing::debug!("Skipping ComParamRef with no comParam.ref_pb");
        return None;
    };
    let complex_value = match r.complex_value.as_ref().map(map_complex_value).transpose() {
        Ok(complex_value) => complex_value,
        Err(e) => return Some(Err(e)),
    };

    Some(Ok(ComParamRef {
        com_param_id,
        simple_value: option_str_to_string(r.simple_value.as_ref()),
        complex_value,
        protocol_id: r
            .protocol
            .as_ref()
            .and_then(|p| p.r#ref.as_ref().map(|obid| obid.value)),
    }))
}

pub(super) fn map_comparam_variant(
    cp: &dataformat::ComParam,
) -> Result<ComParamVariant, DiagServiceError> {
    match &cp.specific_data {
        Some(com_param::SpecificData::Regular(r)) => {
            Ok(ComParamVariant::Regular(RegularComParam {
                default_value: option_str_to_string(r.physical_default_value.as_ref()),
                dop: r
                    .dop
                    .as_ref()
                    .ok_or_else(|| {
                        DiagServiceError::InvalidDatabase("Comparam DOP ref not set.".to_owned())
                    })?
                    .r#ref
                    .as_ref()
                    .ok_or_else(|| ref_optional_none("Comparam DOP.ref_pb"))?
                    .value,
            }))
        }
        Some(com_param::SpecificData::Complex(c)) => {
            Ok(ComParamVariant::Complex(ComplexComParam {
                com_params: c
                    .com_params
                    .iter()
                    .map(|r| {
                        Ok::<Id, DiagServiceError>(
                            r.r#ref
                                .as_ref()
                                .ok_or_else(|| {
                                    ref_optional_none("ComplexComParam.comParams[].Ref")
                                })?
                                .value,
                        )
                    })
                    .collect::<Result<Vec<_>, DiagServiceError>>()?,
            }))
        }
        None => Err(DiagServiceError::InvalidDatabase(
            "ComParam SpecificData not found".to_owned(),
        )),
    }
}

fn map_complex_value(
    complex_value: &dataformat::ComplexValue,
) -> Result<ComplexValue, DiagServiceError> {
    let entries = complex_value
        .entries
        .iter()
        .map(|e| match &e.value {
            Some(complex_value_entry::Value::SimpleValue(s)) => {
                Ok(ComplexValueEntry::SimpleValue(STRINGS.get_or_insert(s)))
            }
            Some(complex_value_entry::Value::ComplexValue(c)) => {
                Ok(ComplexValueEntry::ComplexValue(map_complex_value(c)?))
            }
            None => Err(DiagServiceError::InvalidDatabase(
                "ComplexValueEntry has no value".to_owned(),
            )),
        })
        .collect::<Result<Vec<_>, DiagServiceError>>()?;
    let id = complex_value
        .id
        .as_ref()
        .ok_or_else(|| ref_optional_none("ComplexValue.id"))?
        .value;
    Ok(ComplexValue { id, entries })
}

pub(super) fn lookup(
    ecu_data: &DiagnosticDatabase,
    protocol: &Protocol,
    param_name: &str,
) -> Result<ComParamValue, DiagServiceError> {
    let lookup = &protocol.short_name;

    let (protocol_id, _protocol) = ecu_data
        .protocols
        .iter()
        .find(|(_id, p)| p.short_name == *lookup)
        .ok_or(DiagServiceError::InvalidDatabase(
            "Failed to find protocol definition".to_owned(),
        ))?;

    let cprefs = ecu_data
        .variants
        .iter()
        .find_map(|(_, v)| {
            if !v.is_base {
                return None;
            }
            Some(
                v.com_params
                    .iter()
                    .filter(|cpref| {
                        { cpref.protocol_id.map(|proto_id| proto_id == *protocol_id) }
                            .unwrap_or(false)
                    })
                    .collect::<Vec<_>>(),
            )
        })
        .ok_or(DiagServiceError::InvalidDatabase(
            "Failed to find base variant".to_owned(),
        ))?;

    let (comparam_ref, comparam_value) = ecu_data
        .com_params
        .iter()
        .find_map(|(id, cp)| {
            if STRINGS
                .get(cp.short_name)
                .is_none_or(|shortname| shortname != param_name)
            {
                return None;
            }
            cprefs
                .iter()
                .find(|cpref| cpref.com_param_id == *id)
                .map(|cpref| (cpref, cp))
        })
        .ok_or(DiagServiceError::DatabaseEntryNotFound(format!(
            "Failed to find {param_name}"
        )))?;

    let (_, cp) = resolve_with_value(ecu_data, comparam_ref, comparam_value)?;

    Ok(cp)
}

pub fn resolve_comparam(
    ecu_data: &DiagnosticDatabase,
    cpref: &ComParamRef,
) -> Result<(String, ComParamValue), DiagServiceError> {
    let comparam = ecu_data
        .com_params
        .get(&cpref.com_param_id)
        .ok_or_else(|| {
            DiagServiceError::InvalidDatabase(format!(
                "ComParam ID {} not present in DB",
                cpref.com_param_id
            ))
        })?;
    resolve_with_value(ecu_data, cpref, comparam)
}

fn resolve_with_value(
    ecu_data: &DiagnosticDatabase,
    cpref: &ComParamRef,
    comparam: &ComParam,
) -> Result<(String, ComParamValue), DiagServiceError> {
    if cpref
        .simple_value
        .as_ref()
        .and(cpref.complex_value.as_ref())
        .is_some()
    {
        return Err(DiagServiceError::InvalidDatabase(format!(
            "ComParamRef for {} has both simple and complex value",
            comparam.short_name
        )));
    }
    let short_name = STRINGS.get(comparam.short_name).ok_or_else(|| {
        DiagServiceError::InvalidDatabase(format!(
            "ComParamRef for {} has no short name",
            comparam.short_name
        ))
    })?;
    if let Some(value) = &cpref.simple_value {
        let value = STRINGS.get(*value).ok_or_else(|| {
            DiagServiceError::InvalidDatabase(format!(
                "ComParamRef for {} has no simple value",
                comparam.short_name
            ))
        })?;

        match &comparam.variant {
            ComParamVariant::Regular(r) => {
                let dop = ecu_data.data_operations.get(&r.dop).ok_or_else(|| {
                    DiagServiceError::InvalidDatabase(format!(
                        "ComParamRef for {} has no data operation",
                        comparam.short_name
                    ))
                })?;
                let unit = extract_dop_unit(dop);

                Ok((
                    short_name,
                    ComParamValue::Simple(ComParamSimpleValue { value, unit }),
                ))
            }
            ComParamVariant::Complex(_) => {
                unreachable!("Will only be called if comparam is simple")
            }
        }
    } else if let Some(complex_value) = &cpref.complex_value {
        resolve_complex_value(ecu_data, comparam, complex_value)
    } else {
        Err(DiagServiceError::InvalidDatabase(format!(
            "ComParamRef for {} has no value",
            comparam.short_name
        )))
    }
}

fn resolve_complex_value(
    ecu_data: &DiagnosticDatabase,
    com_param: &ComParam,
    complex_value: &ComplexValue,
) -> Result<(String, ComParamValue), DiagServiceError> {
    let com_param_shortname = STRINGS.get(com_param.short_name).ok_or_else(|| {
        DiagServiceError::InvalidDatabase(format!(
            "ComParamRef for {} has no short name",
            com_param.short_name
        ))
    })?;
    let variant = match &com_param.variant {
        ComParamVariant::Regular(_) => {
            unreachable!("Will only be called if comparam is complex")
        }
        ComParamVariant::Complex(complex_com_param) => complex_com_param,
    };

    let entries = variant
        .com_params
        .iter()
        .enumerate()
        .map(|(i, id)| {
            let cp = ecu_data.com_params.get(id).ok_or_else(|| {
                DiagServiceError::InvalidDatabase(format!("ComParam ID {id} not present in DB"))
            })?;
            let short_name = STRINGS.get(cp.short_name).ok_or_else(|| {
                DiagServiceError::InvalidDatabase(format!("ComParam ID {id} has no short name"))
            })?;
            match &cp.variant {
                ComParamVariant::Regular(r) => {
                    let c = match &complex_value.entries[i] {
                        ComplexValueEntry::SimpleValue(value) => {
                            let value = STRINGS.get(*value).ok_or_else(|| {
                                DiagServiceError::InvalidDatabase(format!(
                                    "ComParam {} has no simple value",
                                    cp.short_name
                                ))
                            })?;

                            let unit = ecu_data
                                .data_operations
                                .get(&r.dop)
                                .and_then(extract_dop_unit);
                            ComParamValue::Simple(ComParamSimpleValue { value, unit })
                        }
                        ComplexValueEntry::ComplexValue(_) => {
                            return Err(DiagServiceError::InvalidDatabase(format!(
                                "ComParam {} is not a complex ComParam",
                                cp.short_name
                            )));
                        }
                    };
                    Ok((short_name, c))
                }
                ComParamVariant::Complex(_) => {
                    let v = match &complex_value.entries[i] {
                        ComplexValueEntry::SimpleValue(_) => {
                            return Err(DiagServiceError::InvalidDatabase(format!(
                                "ComParam {} is not a simple ComParam",
                                cp.short_name
                            )));
                        }
                        ComplexValueEntry::ComplexValue(complex_value) => {
                            resolve_complex_value(ecu_data, cp, complex_value)?
                        }
                    };
                    Ok(v)
                }
            }
        })
        .collect::<Result<HashMap<String, ComParamValue>, DiagServiceError>>()?;

    Ok((com_param_shortname, ComParamValue::Complex(entries)))
}

fn extract_dop_unit(dop: &DataOperation) -> Option<Unit> {
    if let DataOperationVariant::Normal(dop) = &dop.variant {
        dop.unit.clone()
    } else {
        None
    }
}
