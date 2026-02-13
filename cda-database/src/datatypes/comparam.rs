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

use cda_interfaces::{
    DiagServiceError, HashMap,
    datatypes::{ComParamSimpleValue, ComParamValue, Unit},
};

use crate::flatbuf::diagnostic_description::dataformat;

pub(super) fn lookup(
    ecu_data: &crate::datatypes::DiagnosticDatabase,
    protocol: &dataformat::Protocol,
    param_name: &str,
) -> Result<ComParamValue, DiagServiceError> {
    let protocol_name = protocol.diag_layer().and_then(|dl| dl.short_name()).ok_or(
        DiagServiceError::InvalidDatabase("Protocol has no short name".to_owned()),
    )?;

    let cp_ref = ecu_data
        .base_variant()?
        .diag_layer()
        .and_then(|dl| dl.com_param_refs())
        .and_then(|refs| {
            refs.iter().find(|cp_ref| {
                cp_ref
                    .protocol()
                    .and_then(|p| p.diag_layer().and_then(|dl| dl.short_name()))
                    .is_some_and(|sn| sn == protocol_name)
                    && cp_ref
                        .com_param()
                        .and_then(|cp| cp.short_name())
                        .is_some_and(|n| n == param_name)
            })
        })
        .ok_or(DiagServiceError::DatabaseEntryNotFound(format!(
            "No ComParamRef found for {param_name} in protocol {protocol_name}"
        )))?;

    let cp = cp_ref.com_param().ok_or(DiagServiceError::InvalidDatabase(
        "ComParamRef has no ComParam".to_owned(),
    ))?;
    let (_, cp) = resolve_with_value(&cp_ref, &cp)?;
    Ok(cp)
}

fn resolve_with_value(
    cpref: &dataformat::ComParamRef,
    com_param: &dataformat::ComParam,
) -> Result<(String, ComParamValue), DiagServiceError> {
    if cpref
        .simple_value()
        .as_ref()
        .and(cpref.complex_value().as_ref())
        .is_some()
    {
        return Err(DiagServiceError::InvalidDatabase(format!(
            "ComParamRef for {:?} has both simple and complex value",
            com_param.short_name()
        )));
    }
    let short_name = com_param.short_name().ok_or_else(|| {
        DiagServiceError::InvalidDatabase("ComParamRef has no short name".to_owned())
    })?;

    if let Some(value) = &cpref.simple_value() {
        let value = value.value().map(ToOwned::to_owned).ok_or_else(|| {
            DiagServiceError::InvalidDatabase(format!(
                "ComParamRef for {short_name} has no simple value",
            ))
        })?;

        match com_param.com_param_type() {
            dataformat::ComParamType::REGULAR => {
                let regular = com_param
                    .specific_data_as_regular_com_param()
                    .ok_or_else(|| {
                        DiagServiceError::InvalidDatabase(format!(
                            "ComParam {short_name} is not regular, but has regular type",
                        ))
                    })?;

                let dop = regular.dop().ok_or_else(|| {
                    DiagServiceError::InvalidDatabase(format!(
                        "ComParamRef for {short_name} has no data operation",
                    ))
                })?;
                let unit = extract_dop_unit(&dop);

                Ok((
                    short_name.to_owned(),
                    ComParamValue::Simple(ComParamSimpleValue { value, unit }),
                ))
            }
            _ => {
                unreachable!("Will only be called if comparam is simple")
            }
        }
    } else if let Some(complex_value) = &cpref.complex_value() {
        resolve_complex_value(com_param, complex_value)
    } else {
        Err(DiagServiceError::InvalidDatabase(format!(
            "ComParamRef for {short_name} has no value",
        )))
    }
}

/// Resolve a `ComParamRef` into its name and value.
/// # Errors
/// If the `ComParamRef` is invalid or has no value.
pub fn resolve_comparam(
    cpref: &dataformat::ComParamRef,
) -> Result<(String, ComParamValue), DiagServiceError> {
    let com_param = cpref.com_param().ok_or(DiagServiceError::InvalidDatabase(
        "ComParamRef has no ComParam".to_owned(),
    ))?;
    resolve_with_value(cpref, &com_param)
}

fn resolve_complex_value(
    com_param: &dataformat::ComParam,
    complex_value: &dataformat::ComplexValue,
) -> Result<(String, ComParamValue), DiagServiceError> {
    let com_param_shortname = com_param
        .short_name()
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            DiagServiceError::InvalidDatabase("ComParamRef has no short name".to_owned())
        })?;

    let variant = match com_param.com_param_type() {
        dataformat::ComParamType::COMPLEX => com_param
            .specific_data_as_complex_com_param()
            .ok_or_else(|| {
                DiagServiceError::InvalidDatabase(format!(
                    "ComParam {com_param_shortname} is not complex, but has complex type",
                ))
            })?,
        _ => {
            unreachable!("Will only be called if comparam is complex")
        }
    };

    let com_params = variant.com_params().ok_or_else(|| {
        DiagServiceError::InvalidDatabase(format!(
            "Complex ComParam {com_param_shortname} has no comParams",
        ))
    })?;

    let entries = com_params
        .iter()
        .enumerate()
        .map(|(i, cp)| {
            let short_name = cp.short_name().map(ToOwned::to_owned).ok_or_else(|| {
                DiagServiceError::InvalidDatabase("ComParam has no short name".to_string())
            })?;

            match cp.com_param_type() {
                dataformat::ComParamType::REGULAR => {
                    let regular = cp.specific_data_as_regular_com_param().ok_or_else(|| {
                        DiagServiceError::InvalidDatabase(format!(
                            "ComParam {short_name} is not regular, but has regular type",
                        ))
                    })?;

                    let c = if let Some(simple) = complex_value.entries_item_as_simple_value(i) {
                        let value = simple.value().map(ToOwned::to_owned).ok_or_else(|| {
                            DiagServiceError::InvalidDatabase(format!(
                                "ComParam {short_name} has no simple value",
                            ))
                        })?;

                        let unit = regular.dop().as_ref().and_then(extract_dop_unit);
                        ComParamValue::Simple(ComParamSimpleValue { value, unit })
                    } else if let Some(_complex) = complex_value.entries_item_as_complex_value(i) {
                        return Err(DiagServiceError::InvalidDatabase(format!(
                            "ComParam {short_name} is not a complex ComParam",
                        )));
                    } else {
                        return Err(DiagServiceError::InvalidDatabase(format!(
                            "ComplexValue entry for ComParam {short_name} at index {i} has no \
                             value",
                        )));
                    };

                    Ok((short_name, c))
                }
                dataformat::ComParamType::COMPLEX => {
                    let v = if let Some(_simple) = complex_value.entries_item_as_simple_value(i) {
                        return Err(DiagServiceError::InvalidDatabase(format!(
                            "ComParam {short_name} is not a simple ComParam",
                        )));
                    } else if let Some(_complex) = complex_value.entries_item_as_complex_value(i) {
                        resolve_complex_value(&cp, complex_value)?
                    } else {
                        return Err(DiagServiceError::InvalidDatabase(format!(
                            "ComplexValue entry for ComParam {short_name} at index {i} has no \
                             value",
                        )));
                    };
                    Ok(v)
                }
                _ => Err(DiagServiceError::InvalidDatabase(format!(
                    "ComParam {short_name} has unknown type",
                ))),
            }
        })
        .collect::<Result<HashMap<String, ComParamValue>, DiagServiceError>>()?;

    Ok((com_param_shortname, ComParamValue::Complex(entries)))
}

fn extract_dop_unit(dop: &dataformat::DOP) -> Option<Unit> {
    dop.specific_data_as_normal_dop().map(|normal_dop| Unit {
        factor_to_si_unit: normal_dop.unit_ref().and_then(|u| u.factorsitounit()),
        offset_to_si_unit: normal_dop.unit_ref().and_then(|u| u.offsetitounit()),
    })
}

/// Map a DOIP NACK number of retries parameter from (String, u32) to (u8, u32).
/// # Errors
/// If the string cannot be parsed as a u8 (decimal or hex).
pub fn map_nack_number_of_retries<K: AsRef<str>>(
    (name, value): (K, &u32),
) -> Result<(u8, u32), DiagServiceError> {
    let name = name.as_ref();
    let key_result = if let Some(hex_str) = name.strip_prefix("0x") {
        u8::from_str_radix(hex_str, 16)
    } else {
        name.parse::<u8>()
    }
    .map_err(|_| {
        DiagServiceError::ParameterConversionError(format!(
            "Invalid string for doip.nack_number_of_retries: {name}"
        ))
    });

    key_result.map(|key| (key, *value))
}
