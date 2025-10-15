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
    DiagServiceError,
    datatypes::{ComParamSimpleValue, ComParamValue, Unit},
};
#[cfg(feature = "deepsize")]
use deepsize::DeepSizeOf;
use hashbrown::HashMap;

use crate::{datatypes::DiagnosticDatabase, proto::diagnostic_description::dataformat};
//
// use crate::{datatypes::{
//     ComParamMap, DataOperation, DataOperationVariant, DiagnosticDatabase, Id, Protocol,
//     option_str_to_string, ref_optional_none,
// }, proto, proto::dataformat::{self, com_param, complex_value::complex_value_entry}};
//
// #[derive(Debug, Default)]
// #[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
// pub struct ComParamRef {
//     pub simple_value: Option<StringId>,
//     pub complex_value: Option<ComplexValue>,
//     pub com_param_id: Id,
//     pub protocol_id: Option<Id>,
// }

// #[derive(Debug)]
// #[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
// pub struct ComplexValue {
//     pub id: Id,
//     pub entries: Vec<ComplexValueEntry>,
// }
//
// #[derive(Debug)]
// #[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
// pub enum ComplexValueEntry {
//     SimpleValue(StringId),
//     ComplexValue(ComplexValue),
// }

// #[derive(Debug)]
// #[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
// pub struct ComParam {
//     pub short_name: StringId,
//     pub variant: ComParamVariant,
// }
// #[derive(Debug, Clone)]
// #[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
// pub enum ComParamVariant {
//     Regular(RegularComParam),
//     Complex(ComplexComParam),
// }
// #[derive(Debug, Clone)]
// #[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
// pub struct RegularComParam {
//     pub default_value: Option<StringId>,
//     pub dop: dataformat::DOP,
// }
// #[derive(Debug, Clone)]
// #[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
// pub struct ComplexComParam {
//     pub com_params: Vec<Id>,
// }
//
// #[tracing::instrument(skip(r), fields(ctx = %_ctx))]
// pub(super) fn map_comparam_ref(
//     r: &dataformat::ComParamRef,
//     _ctx: &str,
// ) -> Option<Result<ComParamRef, DiagServiceError>> {
//     let Some(com_param_id) = r
//         .com_param
//         .as_ref()
//         .and_then(|cpr| cpr.r#ref.as_ref().map(|obid| obid.value))
//     else {
//         tracing::debug!("Skipping ComParamRef with no comParam.ref_pb");
//         return None;
//     };
//     let complex_value = match r.complex_value.as_ref().map(map_complex_value).transpose() {
//         Ok(complex_value) => complex_value,
//         Err(e) => return Some(Err(e)),
//     };
//
//     Some(Ok(ComParamRef {
//         com_param_id,
//         simple_value: option_str_to_string(r.simple_value.as_ref()),
//         complex_value,
//         protocol_id: r
//             .protocol
//             .as_ref()
//             .and_then(|p| p.r#ref.as_ref().map(|obid| obid.value)),
//     }))
// }
//
// pub(super) fn map_comparam_variant(
//     cp: &dataformat::ComParam,
// ) -> Result<ComParamVariant, DiagServiceError> {
//     match &cp.specific_data {
//         Some(com_param::SpecificData::Regular(r)) => {
//             Ok(ComParamVariant::Regular(RegularComParam {
//                 default_value: option_str_to_string(r.physical_default_value.as_ref()),
//                 dop: r
//                     .dop
//                     .as_ref()
//                     .ok_or_else(|| {
//                         DiagServiceError::InvalidDatabase("Comparam DOP ref not set.".to_owned())
//                     })?
//                     .r#ref
//                     .as_ref()
//                     .ok_or_else(|| ref_optional_none("Comparam DOP.ref_pb"))?
//                     .value,
//             }))
//         }
//         Some(com_param::SpecificData::Complex(c)) => {
//             Ok(ComParamVariant::Complex(ComplexComParam {
//                 com_params: c
//                     .com_params
//                     .iter()
//                     .map(|r| {
//                         Ok::<Id, DiagServiceError>(
//                             r.r#ref
//                                 .as_ref()
//                                 .ok_or_else(|| {
//                                     ref_optional_none("ComplexComParam.comParams[].Ref")
//                                 })?
//                                 .value,
//                         )
//                     })
//                     .collect::<Result<Vec<_>, DiagServiceError>>()?,
//             }))
//         }
//         None => Err(DiagServiceError::InvalidDatabase(
//             "ComParam SpecificData not found".to_owned(),
//         )),
//     }
// }
//
// fn map_complex_value(
//     complex_value: &dataformat::ComplexValue,
// ) -> Result<ComplexValue, DiagServiceError> {
//     let entries = complex_value
//         .entries
//         .iter()
//         .map(|e| match &e.value {
//             Some(complex_value_entry::Value::SimpleValue(s)) => {
//                 Ok(ComplexValueEntry::SimpleValue(STRINGS.get_or_insert(s)))
//             }
//             Some(complex_value_entry::Value::ComplexValue(c)) => {
//                 Ok(ComplexValueEntry::ComplexValue(map_complex_value(c)?))
//             }
//             None => Err(DiagServiceError::InvalidDatabase(
//                 "ComplexValueEntry has no value".to_owned(),
//             )),
//         })
//         .collect::<Result<Vec<_>, DiagServiceError>>()?;
//     let id = complex_value
//         .id
//         .as_ref()
//         .ok_or_else(|| ref_optional_none("ComplexValue.id"))?
//         .value;
//     Ok(ComplexValue { id, entries })
// }

pub(super) fn lookup(
    ecu_data: &DiagnosticDatabase,
    protocol: &dataformat::Protocol,
    param_name: &str,
) -> Result<ComParamValue, DiagServiceError> {
    let cp_ref = protocol
        .diag_layer()
        .and_then(|dl| dl.com_param_refs())
        .and_then(|params| {
            params.iter().find(|cp_ref| {
                cp_ref
                    .com_param()
                    .is_some_and(|c| c.short_name().is_some_and(|name| name == param_name))
            })
        })
        .ok_or(DiagServiceError::DatabaseEntryNotFound(format!(
            "Failed to find {param_name}"
        )))?;

    let (_, cp) = resolve_com_param_ref(ecu_data, &cp_ref)?;

    Ok(cp)
}

// pub fn resolve_comparam(
//     ecu_data: &DiagnosticDatabase,
//     cpref: &diagnostic_description::dataformat::ComParamRef,
// ) -> Result<(String, ComParamValue), DiagServiceError> {
//     let comparam = ecu_data
//         .com_params
//         .get(&cpref.com_param_id)
//         .ok_or_else(|| {
//             DiagServiceError::InvalidDatabase(format!(
//                 "ComParam ID {} not present in DB",
//                 cpref.com_param_id
//             ))
//         })?;
//     resolve_with_value(ecu_data, cpref, comparam)
// }

pub fn resolve_com_param_ref(
    ecu_data: &DiagnosticDatabase,
    cp_ref: &dataformat::ComParamRef,
) -> Result<(String, ComParamValue), DiagServiceError> {
    let short_name = cp_ref.com_param().and_then(|cp| cp.short_name()).ok_or(
        DiagServiceError::InvalidDatabase("ComParamRef has no com_param short name".to_string()),
    )?;

    if cp_ref.simple_value().is_some() && cp_ref.complex_value().is_some() {
        return Err(DiagServiceError::InvalidDatabase(format!(
            "ComParamRef for {} has both simple and complex value",
            short_name,
        )));
    }

    let com_param = cp_ref.com_param().ok_or(DiagServiceError::InvalidDatabase(
        "ComParamRef has no com_param".to_string(),
    ))?;
    resolve_com_param(ecu_data, &com_param)
}

fn resolve_com_param(
    ecu_data: &DiagnosticDatabase,
    com_param: &dataformat::ComParam,
) -> Result<(String, ComParamValue), DiagServiceError> {
    let param_short_name = com_param
        .short_name()
        .ok_or(DiagServiceError::InvalidDatabase(
            "ComParam in ComplexComParam has no short name".to_string(),
        ))?
        .to_owned();
    if let Some(regular) = com_param.specific_data_as_regular_com_param() {
        let dop = regular.dop().ok_or(DiagServiceError::InvalidDatabase(
            "Regular ComParam has no DOP".to_string(),
        ))?;
        let unit = extract_dop_unit(&dop);
        let default_value = regular.physical_default_value().map(|s| s.to_owned());
        Ok((
            param_short_name,
            ComParamValue::Simple(ComParamSimpleValue {
                value: default_value.unwrap_or_default(),
                unit,
            }),
        ))
    } else if let Some(_complex) = com_param.specific_data_as_complex_com_param() {
        resolve_complex_value(ecu_data, &com_param)
    } else {
        Err(DiagServiceError::InvalidDatabase(
            "ComParam is neither regular nor complex".to_string(),
        ))
    }
}

fn resolve_complex_value(
    ecu_data: &DiagnosticDatabase,
    com_param: &dataformat::ComParam,
) -> Result<(String, ComParamValue), DiagServiceError> {
    let complex_com_param =
        com_param
            .specific_data_as_complex_com_param()
            .ok_or(DiagServiceError::InvalidDatabase(
                "ComParam is not complex".to_string(),
            ))?;
    let short_name = com_param
        .short_name()
        .ok_or(DiagServiceError::InvalidDatabase(
            "ComParamRef has no com_param short name".to_string(),
        ))?
        .to_owned();
    let entries = if let Some(com_params) = complex_com_param.com_params() {
        com_params
            .iter()
            .map(
                |param| -> Result<(String, ComParamValue), DiagServiceError> {
                    resolve_com_param(ecu_data, &param)
                },
            )
            .collect::<Result<HashMap<_, _>, DiagServiceError>>()?
    } else {
        HashMap::new()
    };

    Ok((short_name, ComParamValue::Complex(entries)))
}

fn extract_dop_unit(dop: &dataformat::DOP) -> Option<Unit> {
    if let Some(normal_dop) = dop.specific_data_as_normal_dop() {
        Some(Unit {
            factor_to_si_unit: normal_dop.unit_ref().and_then(|u| u.factorsitounit()),
            offset_to_si_unit: normal_dop.unit_ref().and_then(|u| u.offsetitounit()),
        })
    } else {
        None
    }
}
