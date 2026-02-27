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

use std::fmt::Display;

use cda_database::datatypes::{
    self, BitLength, CompuMethod, CompuScale, DataType, DiagCodedTypeVariant, MinMaxLengthType,
    PhysicalType,
};
use cda_interfaces::{
    DataParseError, DiagServiceError,
    util::{decode_hex, tracing::print_hex},
};

use crate::diag_kernel::{
    DiagDataValue,
    diagservices::{DiagDataTypeContainer, DiagDataTypeContainerRaw},
    iso_14229_nrc, pad_msb_to_len,
    payload::Payload,
};

pub(in crate::diag_kernel) fn uds_data_to_serializable(
    diag_type: datatypes::DataType,
    compu_method: Option<&datatypes::CompuMethod>,
    is_negative_response: bool,
    data: &[u8],
) -> Result<DiagDataValue, DiagServiceError> {
    if data.is_empty() {
        // if data is empty, return empty string
        return Ok(DiagDataValue::String(String::new()));
    }

    'compu: {
        if let Some(compu_method) = compu_method {
            match compu_method.category {
                datatypes::CompuCategory::Identical => break 'compu,
                category => {
                    return compu_lookup(
                        diag_type,
                        compu_method,
                        category,
                        is_negative_response,
                        data,
                    );
                }
            }
        }
    }

    DiagDataValue::new(diag_type, data)
}

enum ConversionDirection<'a> {
    InternalToPhys,
    PhysToInternal(Option<&'a datatypes::CompuValues>),
}

/// Apply rational linear formula bidirectionally per ODX spec (ISO 22901-1)
/// Used by both LINEAR and SCALE-LINEAR COMPU-METHODs.
/// ODX Constraints:
/// - Numerator must have exactly 2 values: [V0=offset, V1=factor]
/// - Denominator must have 0 or 1 value (defaults to 1.0)
/// - When V1=0 (constant function), inverse conversion requires COMPU-INVERSE-VALUE
fn apply_linear_conversion(
    rational_coefficients: &datatypes::CompuRationalCoefficients,
    value: f64,
    direction: &ConversionDirection,
) -> Result<f64, DiagServiceError> {
    if rational_coefficients.numerator.len() != 2 {
        return Err(DiagServiceError::InvalidDatabase(format!(
            "Expected 2 numerators (offset, factor), got {}",
            rational_coefficients.numerator.len()
        )));
    }

    if rational_coefficients.denominator.len() > 1 {
        return Err(DiagServiceError::InvalidDatabase(format!(
            "Expected 0 or 1 denominator, got {}",
            rational_coefficients.denominator.len()
        )));
    }

    let offset = *rational_coefficients.numerator.first().ok_or_else(|| {
        DiagServiceError::InvalidDatabase("Missing numerator[0] (offset)".to_owned())
    })?;
    let factor = *rational_coefficients.numerator.get(1).ok_or_else(|| {
        DiagServiceError::InvalidDatabase("Missing numerator[1] (factor)".to_owned())
    })?;
    let d = rational_coefficients
        .denominator
        .first()
        .copied()
        .unwrap_or(1.0);

    match direction {
        ConversionDirection::PhysToInternal(inverse) => {
            // Per ODX spec: when V1=0 (constant), COMPU-INVERSE-VALUE must be used instead
            if factor == 0.0 {
                return if let Some(inverse) = inverse {
                    Ok(inverse.v)
                } else {
                    Err(DiagServiceError::InvalidDatabase(
                        "Factor (V1) cannot be zero for inverse conversion. Use \
                         COMPU-INVERSE-VALUE for constant functions"
                            .to_owned(),
                    ))
                };
            }
            Ok((d * value - offset) / factor)
        }
        ConversionDirection::InternalToPhys => {
            if d == 0.0 {
                return Err(DiagServiceError::InvalidDatabase(
                    "Denominator cannot be zero".to_owned(),
                ));
            }
            Ok((offset + factor * value) / d)
        }
    }
}

fn compu_lookup(
    diag_type: DataType,
    compu_method: &datatypes::CompuMethod,
    category: datatypes::CompuCategory,
    is_negative_response: bool,
    data: &[u8],
) -> Result<DiagDataValue, DiagServiceError> {
    let lookup = DiagDataValue::new(diag_type, data)?;
    match compu_method.internal_to_phys.scales.iter().find(|scale| {
        let lower = scale.lower_limit.as_ref();
        let upper = scale.upper_limit.as_ref();

        lookup.within_limits(upper, lower)
    }) {
        Some(scale) => match category {
            datatypes::CompuCategory::Identical => unreachable!("Already handled"),
            datatypes::CompuCategory::Linear => {
                compu_lookup_linear(diag_type, compu_method, lookup, scale)
            }
            datatypes::CompuCategory::ScaleLinear => {
                compu_lookup_scale_linear(diag_type, lookup, scale)
            }
            datatypes::CompuCategory::TextTable => compu_lookup_text_table(scale),
            datatypes::CompuCategory::CompuCode => Err(DiagServiceError::RequestNotSupported(
                "compu_lookup for CompuCode is not implemented".to_owned(),
            )),
            datatypes::CompuCategory::TabIntp => Err(DiagServiceError::RequestNotSupported(
                "compu_lookup for TabIntp is not implemented".to_owned(),
            )),
            datatypes::CompuCategory::RatFunc => Err(DiagServiceError::RequestNotSupported(
                "compu_lookup for RatFunc is not implemented".to_owned(),
            )),
            datatypes::CompuCategory::ScaleRatFunc => Err(DiagServiceError::RequestNotSupported(
                "compu_lookup for ScaleRatFunc is not implemented".to_owned(),
            )),
        },
        None => {
            // lookup NRCs from iso for negative responses
            if is_negative_response {
                let lookup: u32 = lookup.try_into()?;
                if lookup <= 0xFF {
                    Ok(DiagDataValue::String(
                        // Okay because the NRC is defined as u8
                        #[allow(clippy::cast_possible_truncation)]
                        iso_14229_nrc::get_nrc_code(lookup as u8).to_owned(),
                    ))
                } else {
                    Ok(DiagDataValue::String(
                        format!("Unknown ({lookup})").to_owned(),
                    ))
                }
            } else {
                Err(DiagServiceError::DataError(DataParseError {
                    value: print_hex(data, 20),
                    details: "Value outside of expected range".to_owned(),
                }))
            }
        }
    }
}

fn compu_lookup_linear(
    diag_type: DataType,
    compu_method: &CompuMethod,
    lookup: DiagDataValue,
    scale: &CompuScale,
) -> Result<DiagDataValue, DiagServiceError> {
    // Per ODX Figure 79: LINEAR category must have exactly one COMPU-SCALE
    if compu_method.internal_to_phys.scales.len() != 1 {
        return Err(DiagServiceError::InvalidDatabase(format!(
            "LINEAR: Expected exactly 1 COMPU-SCALE, got {}",
            compu_method.internal_to_phys.scales.len()
        )));
    }

    let rational_coefficients =
        scale
            .rational_coefficients
            .as_ref()
            .ok_or(DiagServiceError::InvalidDatabase(
                "LINEAR: Missing rational coefficients".to_owned(),
            ))?;

    let lookup_val: f64 = lookup.try_into().map_err(|e| {
        DiagServiceError::ParameterConversionError(format!("Failed to convert lookup value: {e}"))
    })?;
    let val = apply_linear_conversion(
        rational_coefficients,
        lookup_val,
        &ConversionDirection::InternalToPhys,
    )?;
    DiagDataValue::from_number(&val, diag_type)
}

fn compu_lookup_scale_linear(
    diag_type: DataType,
    lookup: DiagDataValue,
    scale: &CompuScale,
) -> Result<DiagDataValue, DiagServiceError> {
    let rational_coefficients =
        scale
            .rational_coefficients
            .as_ref()
            .ok_or(DiagServiceError::InvalidDatabase(
                "SCALE-LINEAR: Missing rational coefficients".to_owned(),
            ))?;

    let lookup_val: f64 = lookup.try_into()?;
    let val = apply_linear_conversion(
        rational_coefficients,
        lookup_val,
        &ConversionDirection::InternalToPhys,
    )?;
    DiagDataValue::from_number(&val, diag_type)
}

fn compu_lookup_text_table(scale: &CompuScale) -> Result<DiagDataValue, DiagServiceError> {
    let consts = scale.consts.as_ref().ok_or_else(|| {
        DiagServiceError::InvalidDatabase("TextTable lookup has no Consts".to_owned())
    })?;
    let mapped_value =
        consts.vt.clone().or(consts.vt_ti.clone()).ok_or_else(|| {
            DiagServiceError::UdsLookupError("failed to read compu value".to_owned())
        })?;
    Ok(DiagDataValue::String(mapped_value))
}

fn decode_numeric_val_from_str(
    value: &str,
    physical_type: PhysicalType,
    diag_type: &datatypes::DiagCodedType,
) -> Result<Vec<u8>, DiagServiceError> {
    match physical_type.base_type {
        DataType::Int32 => value
            .parse::<i32>()
            .map_err(|_| {
                DiagServiceError::ParameterConversionError(format!(
                    "Invalid value for Int32: {value}"
                ))
            })
            .and_then(|v| {
                validate_bit_len_signed(v, diag_type.bit_len().unwrap_or(32))?;
                Ok(v)
            })
            .map(|v| v.to_be_bytes().to_vec()),
        DataType::UInt32 => {
            // according to ISO 22901-1 only UInt32 can have display radix
            match physical_type.display_radix {
                Some(datatypes::Radix::Hex) => {
                    let decoded = decode_hex_with_optional_prefix(value)?;
                    let decoded = if decoded.len() < size_of::<u32>() {
                        pad_msb_to_len(&decoded, size_of::<u32>())
                    } else {
                        decoded
                    };
                    let u32_val =
                        u32::from_be_bytes(decoded.try_into().expect("padded to u32 length"));
                    validate_bit_len_unsigned(u32_val, diag_type.bit_len().unwrap_or(32))?;
                    Ok(u32_val.to_be_bytes().to_vec())
                }
                Some(datatypes::Radix::Octal) => decode_u32_octal_with_optional_prefix(value),
                Some(datatypes::Radix::Binary) => decode_u32_binary_with_optional_prefix(value),
                Some(datatypes::Radix::Decimal) | None => value
                    .parse::<u32>()
                    .map_err(|_| {
                        DiagServiceError::ParameterConversionError(format!(
                            "Invalid value for UInt32: {value}"
                        ))
                    })
                    .and_then(|v| {
                        validate_bit_len_unsigned(v, diag_type.bit_len().unwrap_or(32))?;
                        Ok(v)
                    })
                    .map(|v| v.to_be_bytes().to_vec()),
            }
        }
        // when parsing str -> float we can ignore the precision
        // as that only specifies how many decimal places are displayed
        DataType::Float32 => value
            .parse::<f32>()
            .map_err(|_| {
                DiagServiceError::ParameterConversionError(format!(
                    "Invalid value for Float: {value}"
                ))
            })
            .map(|v| v.to_be_bytes().to_vec()),
        DataType::Float64 => value
            .parse::<f64>()
            .map_err(|_| {
                DiagServiceError::ParameterConversionError(format!(
                    "Invalid value for Float: {value}"
                ))
            })
            .map(|v| v.to_be_bytes().to_vec()),
        DataType::AsciiString
        | DataType::Utf8String
        | DataType::Unicode2String
        | DataType::ByteField => Err(DiagServiceError::ParameterConversionError(format!(
            "Cannot parse string value for non-numeric physical type: {:?}",
            physical_type.base_type
        ))),
    }
}

fn parse_json_to_f64(
    value: &serde_json::Value,
    diag_type: &datatypes::DiagCodedType,
    physical_type: Option<PhysicalType>,
) -> Result<f64, DiagServiceError> {
    // numeric JSON values are used directly
    if let Some(num) = value.as_f64() {
        return Ok(num);
    }

    // we can accept the precision loss here since the value is being converted to f64 anyway
    // when compu methods are applied.
    #[allow(clippy::cast_precision_loss)]
    if let Some(num) = value.as_i64() {
        return Ok(num as f64);
    }

    if let Some(s) = value.as_str()
        && let Some(phys_type) = physical_type
    {
        let base_bytes = decode_numeric_val_from_str(s, phys_type, diag_type)?;
        let val = match diag_type.base_datatype() {
            DataType::Int32 => {
                if base_bytes.len() > size_of::<i32>() {
                    return Err(DiagServiceError::ParameterConversionError(format!(
                        "Input value {base_bytes:?} is too large for Int32"
                    )));
                }
                let padded = pad_msb_to_len(&base_bytes, size_of::<i32>());
                f64::from(i32::from_be_bytes(
                    padded.try_into().expect("input bytes padded to i32 size"),
                ))
            }
            DataType::UInt32 => {
                if base_bytes.len() > size_of::<u32>() {
                    return Err(DiagServiceError::ParameterConversionError(format!(
                        "Input value {s} is too large for UInt32"
                    )));
                }
                let padded = pad_msb_to_len(&base_bytes, size_of::<u32>());
                f64::from(u32::from_be_bytes(
                    padded.try_into().expect("input bytes padded to u32 size"),
                ))
            }
            DataType::Float32 => {
                if base_bytes.len() > size_of::<f32>() {
                    return Err(DiagServiceError::ParameterConversionError(format!(
                        "Input value {s} is too large for Float32"
                    )));
                }
                let padded = pad_msb_to_len(&base_bytes, size_of::<f32>());
                f64::from(f32::from_be_bytes(
                    padded.try_into().expect("input bytes padded to f32 size"),
                ))
            }
            DataType::Float64 => {
                if base_bytes.len() > size_of::<f64>() {
                    return Err(DiagServiceError::ParameterConversionError(format!(
                        "Input value {s} is too large for Float64"
                    )));
                }
                let padded = pad_msb_to_len(&base_bytes, size_of::<f64>());
                f64::from_be_bytes(padded.try_into().expect("input bytes padded to f64 size"))
            }
            DataType::AsciiString
            | DataType::Utf8String
            | DataType::Unicode2String
            | DataType::ByteField => {
                return Err(DiagServiceError::ParameterConversionError(format!(
                    "Cannot parse string value for non-numeric physical type: {:?}",
                    phys_type.base_type
                )));
            }
        } as f64;
        Ok(val)
    } else {
        Err(DiagServiceError::ParameterConversionError(
            "Invalid JSON value for numeric conversion".to_owned(),
        ))
    }
}

/// Helper function to convert an internal value to bytes based on data type
// Casting and truncating is defined in the ISO instead of rounding
#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::cast_sign_loss)]
fn linear_scaled_value_to_bytes(
    value: f64,
    diag_type: datatypes::DataType,
) -> Result<Vec<u8>, DiagServiceError> {
    match diag_type {
        DataType::Int32 => Ok((value as i32).to_be_bytes().to_vec()),
        DataType::UInt32 => Ok((value as u32).to_be_bytes().to_vec()),
        DataType::Float32 => Ok((value as f32).to_be_bytes().to_vec()),
        DataType::Float64 => Ok(value.to_be_bytes().to_vec()),
        _ => Err(DiagServiceError::InvalidDatabase(
            "Database only supports Int32, UInt32, Float32 and Float64 for linear scaling"
                .to_owned(),
        )),
    }
}

// Casting and truncating is defined in the ISO instead of rounding
fn compu_convert(
    diag_type: &datatypes::DiagCodedType,
    compu_method: &datatypes::CompuMethod,
    phys_type: Option<PhysicalType>,
    category: datatypes::CompuCategory,
    value: &serde_json::Value,
) -> Result<Vec<u8>, DiagServiceError> {
    match category {
        datatypes::CompuCategory::Identical => Err(DiagServiceError::RequestNotSupported(
            "compu_convert for Identical is not implemented".to_owned(),
        )),
        datatypes::CompuCategory::Linear => {
            compu_convert_linear(diag_type, compu_method, phys_type, value)
        }
        datatypes::CompuCategory::ScaleLinear => {
            compu_convert_scale_linear(diag_type, compu_method, phys_type, value)
        }
        datatypes::CompuCategory::TextTable => {
            compu_convert_text_table(diag_type.base_datatype(), compu_method, value)
        }
        datatypes::CompuCategory::CompuCode => Err(DiagServiceError::RequestNotSupported(
            "compu_convert for CompuCode is not implemented".to_owned(),
        )),
        datatypes::CompuCategory::TabIntp => Err(DiagServiceError::RequestNotSupported(
            "compu_convert for TabIntp is not implemented".to_owned(),
        )),
        datatypes::CompuCategory::RatFunc => Err(DiagServiceError::RequestNotSupported(
            "compu_convert for RatFunc is not implemented".to_owned(),
        )),
        datatypes::CompuCategory::ScaleRatFunc => Err(DiagServiceError::RequestNotSupported(
            "compu_convert for ScaleRatFunc is not implemented".to_owned(),
        )),
    }
}

fn compu_convert_linear(
    diag_type: &datatypes::DiagCodedType,
    compu_method: &CompuMethod,
    phys_type: Option<PhysicalType>,
    value: &serde_json::Value,
) -> Result<Vec<u8>, DiagServiceError> {
    // Per ODX Figure 79: LINEAR category must have exactly one COMPU-SCALE
    if compu_method.internal_to_phys.scales.len() != 1 {
        return Err(DiagServiceError::InvalidDatabase(format!(
            "LINEAR: Expected exactly 1 COMPU-SCALE, got {}",
            compu_method.internal_to_phys.scales.len()
        )));
    }

    let scale = compu_method
        .internal_to_phys
        .scales
        .first()
        .ok_or_else(|| {
            DiagServiceError::UdsLookupError("Failed to find scales for linear scaling".to_owned())
        })?;

    let physical_value = parse_json_to_f64(value, diag_type, phys_type)?;
    let coeffs = scale.rational_coefficients.as_ref().ok_or_else(|| {
        DiagServiceError::UdsLookupError("LINEAR: Missing rational coefficients".to_owned())
    })?;

    let internal_value = apply_linear_conversion(
        coeffs,
        physical_value,
        &ConversionDirection::PhysToInternal(scale.inverse_values.as_ref()),
    )?;
    linear_scaled_value_to_bytes(internal_value, diag_type.base_datatype())
}

fn compu_convert_scale_linear(
    diag_type: &datatypes::DiagCodedType,
    compu_method: &CompuMethod,
    phys_type: Option<PhysicalType>,
    value: &serde_json::Value,
) -> Result<Vec<u8>, DiagServiceError> {
    // ScaleLinear allows multiple scales with different ranges
    // We need to find the matching scale based on the input values limits
    let physical_value = parse_json_to_f64(value, diag_type, phys_type)?;

    // Find the appropriate scale for the physical value
    // For phys to internal, we need to compute the physical range from internal limits
    let scale = compu_method
        .internal_to_phys
        .scales
        .iter()
        .find(|scale| {
            let Some(coeffs) = scale.rational_coefficients.as_ref() else {
                return false;
            };

            // Compute physical range by transforming internal limits
            let phys_lower = scale.lower_limit.as_ref().and_then(|l| {
                let internal_val: f64 = l.try_into().ok()?;
                apply_linear_conversion(coeffs, internal_val, &ConversionDirection::InternalToPhys)
                    .ok()
            });
            let phys_upper = scale.upper_limit.as_ref().and_then(|u| {
                let internal_val: f64 = u.try_into().ok()?;
                apply_linear_conversion(coeffs, internal_val, &ConversionDirection::InternalToPhys)
                    .ok()
            });

            // Check if physical value falls within computed physical range
            let within_lower = phys_lower.is_none_or(|l| {
                if let Some(limit) = scale.lower_limit.as_ref() {
                    match limit.interval_type {
                        datatypes::IntervalType::Closed => physical_value >= l,
                        datatypes::IntervalType::Open => physical_value > l,
                        datatypes::IntervalType::Infinite => true,
                    }
                } else {
                    physical_value >= l
                }
            });
            let within_upper = phys_upper.is_none_or(|u| {
                if let Some(limit) = scale.upper_limit.as_ref() {
                    match limit.interval_type {
                        datatypes::IntervalType::Closed => physical_value <= u,
                        datatypes::IntervalType::Open => physical_value < u,
                        datatypes::IntervalType::Infinite => true,
                    }
                } else {
                    physical_value <= u
                }
            });

            within_lower && within_upper
        })
        .ok_or_else(|| {
            DiagServiceError::UdsLookupError(
                "Failed to find matching scale for SCALE-LINEAR conversion".to_owned(),
            )
        })?;

    let coeffs = scale.rational_coefficients.as_ref().ok_or_else(|| {
        DiagServiceError::UdsLookupError("SCALE-LINEAR: Missing rational coefficients".to_owned())
    })?;

    let internal_value = apply_linear_conversion(
        coeffs,
        physical_value,
        &ConversionDirection::PhysToInternal(scale.inverse_values.as_ref()),
    )?;
    linear_scaled_value_to_bytes(internal_value, diag_type.base_datatype())
}

fn compu_convert_text_table(
    diag_type: DataType,
    compu_method: &CompuMethod,
    value: &serde_json::Value,
) -> Result<Vec<u8>, DiagServiceError> {
    if !matches!(
        diag_type,
        DataType::Int32 | DataType::UInt32 | DataType::Float32 | DataType::Float64
    ) {
        return Err(DiagServiceError::InvalidDatabase(
            "TextTable conversion only supports numeric data types".to_owned(),
        ));
    }

    let Some(value) = value.as_str().map(|s| s.replace('"', "")) else {
        return Err(DiagServiceError::UdsLookupError(
            "Failed to convert value to string".to_owned(),
        ));
    };

    if let Some(value) = compu_method
        .internal_to_phys
        .scales
        .iter()
        .find_map(|scale| {
            if let Some(text) = scale
                .consts
                .as_ref()
                .and_then(|consts| consts.vt.clone().or(consts.vt_ti.clone()))
                && value == text
            {
                return scale.lower_limit.as_ref();
            }
            None
        })
    {
        return match diag_type {
            DataType::Int32 => {
                let v: i32 = value.try_into()?;
                Ok(v.to_be_bytes().to_vec())
            }
            DataType::UInt32 => {
                let v: u32 = value.try_into()?;
                Ok(v.to_be_bytes().to_vec())
            }
            DataType::Float32 => {
                let v: f32 = value.try_into()?;
                Ok(v.to_be_bytes().to_vec())
            }
            DataType::Float64 => {
                let v: f64 = value.try_into()?;
                Ok(v.to_be_bytes().to_vec())
            }
            // Handled earlier as pre-condition
            _ => unreachable!(),
        };
    }
    Err(DiagServiceError::UdsLookupError(
        "Failed to find matching TextTable value".to_owned(),
    ))
}

pub(in crate::diag_kernel) fn extract_diag_data_container(
    param_short_name: Option<&str>,
    param_byte_pos: usize,
    param_bit_pos: usize,
    payload: &mut Payload,
    diag_type: &datatypes::DiagCodedType,
    compu_method: Option<datatypes::CompuMethod>,
) -> Result<DiagDataTypeContainer, DiagServiceError> {
    let uds_payload = payload.data()?;
    let (data, bit_len) = diag_type.decode(uds_payload, param_byte_pos, param_bit_pos)?;
    let is_optional = match diag_type.type_() {
        DiagCodedTypeVariant::MinMaxLength(MinMaxLengthType { min_length, .. }) => *min_length == 0,
        _ => false,
    };
    if data.is_empty() && !is_optional {
        // at least 1 byte expected, we are using NotEnoughData error here, because
        // this might happen when parsing end of pdu and leftover bytes can be ignored
        tracing::debug!(
            "Not enough Data for parameter {:?} in extract_diag_data_container, expected at least \
             1 byte",
            param_short_name
        );
        return Err(DiagServiceError::NotEnoughData {
            expected: 1,
            actual: 0,
        });
    }

    let data_type = diag_type.base_datatype();
    payload.set_last_read_byte_pos(param_byte_pos.saturating_add(data.len()));

    Ok(DiagDataTypeContainer::RawContainer(
        DiagDataTypeContainerRaw {
            data,
            bit_len,
            data_type,
            compu_method,
        },
    ))
}

pub(in crate::diag_kernel) fn json_value_to_uds_data(
    diag_type: &datatypes::DiagCodedType,
    compu_method: Option<datatypes::CompuMethod>,
    phys_type: Option<PhysicalType>,
    json_value: &serde_json::Value,
) -> Result<Vec<u8>, DiagServiceError> {
    'compu: {
        if let Some(compu_method) = compu_method {
            match compu_method.category {
                datatypes::CompuCategory::Identical => break 'compu,
                category => {
                    return compu_convert(
                        diag_type,
                        &compu_method,
                        phys_type,
                        category,
                        json_value,
                    );
                }
            }
        }
    }

    match diag_type.base_datatype() {
        DataType::Int32 | DataType::UInt32 | DataType::Float32 | DataType::Float64 => {
            numeric_json_value_to_byte_vector(json_value, diag_type, phys_type)
        }
        DataType::ByteField => decode_hex_with_optional_prefix(json_value.as_str().ok_or(
            DiagServiceError::ParameterConversionError("Invalid value for ByteField".to_owned()),
        )?),
        DataType::AsciiString | DataType::Unicode2String | DataType::Utf8String => json_value
            .as_str()
            .ok_or(DiagServiceError::ParameterConversionError(
                "Invalid value for AsciiString".to_owned(),
            ))
            .map(|s| s.as_bytes().to_vec()),
    }
}

fn decode_hex_with_optional_prefix(value: &str) -> Result<Vec<u8>, DiagServiceError> {
    value
        .split([' ', ','])
        .filter(|v: &&str| !v.is_empty())
        .map(|value| {
            if let Some(stripped) = value.to_lowercase().strip_prefix("0x") {
                decode_hex(stripped)
            } else {
                decode_hex(value)
            }
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|vecs| vecs.into_iter().flatten().collect())
}

fn decode_u32_octal_with_optional_prefix(value: &str) -> Result<Vec<u8>, DiagServiceError> {
    let stripped = value.strip_prefix("0o").unwrap_or(value);
    if !stripped.chars().all(|c| ('0'..='7').contains(&c)) {
        return Err(DiagServiceError::ParameterConversionError(
            "Non-octal character found".to_owned(),
        ));
    }
    u32::from_str_radix(stripped, 8)
        .map_err(|_| {
            DiagServiceError::ParameterConversionError(format!("Invalid octal value: {value}"))
        })
        .map(|v| v.to_be_bytes().to_vec())
}

fn decode_u32_binary_with_optional_prefix(value: &str) -> Result<Vec<u8>, DiagServiceError> {
    let stripped = value.strip_prefix("0b").unwrap_or(value);
    if !stripped.chars().all(|c| c == '0' || c == '1') {
        return Err(DiagServiceError::ParameterConversionError(
            "Non-binary character found".to_owned(),
        ));
    }
    u32::from_str_radix(stripped, 2)
        .map_err(|_| {
            DiagServiceError::ParameterConversionError(format!("Invalid binary value: {value}"))
        })
        .map(|v| v.to_be_bytes().to_vec())
}

fn process_numeric_json_value(
    json_value: &serde_json::Value,
    data_type: &datatypes::DiagCodedType,
) -> Result<Vec<u8>, DiagServiceError> {
    let base_type = data_type.base_datatype();
    match base_type {
        DataType::Int32 => {
            let value = json_value
                .as_i64()
                .ok_or(DiagServiceError::ParameterConversionError(format!(
                    "Invalid value for {data_type:?}"
                )))?;
            validate_bit_len_signed(value, data_type.bit_len().unwrap_or(32))?;
            let int_val: i32 = value.try_into().map_err(|_| {
                DiagServiceError::ParameterConversionError(format!(
                    "Failed to convert {value} to Int32"
                ))
            })?;
            Ok(int_val.to_be_bytes().to_vec())
        }
        DataType::UInt32 => {
            let value = json_value
                .as_u64()
                .ok_or(DiagServiceError::ParameterConversionError(format!(
                    "Invalid value for {data_type:?}"
                )))?;
            validate_bit_len_unsigned(value, data_type.bit_len().unwrap_or(32))?;
            let int_val: u32 = value.try_into().map_err(|_| {
                DiagServiceError::ParameterConversionError(format!(
                    "Failed to convert {value} to UInt32"
                ))
            })?;
            Ok(int_val.to_be_bytes().to_vec())
        }
        DataType::Float32 => {
            #[allow(clippy::cast_possible_truncation)] // truncating f64 to f32 is intended here
            json_value
                .as_f64()
                .ok_or(DiagServiceError::ParameterConversionError(
                    "Invalid value for Float32".to_owned(),
                ))
                .map(|v| (v as f32).to_be_bytes().to_vec())
        }
        DataType::Float64 => json_value
            .as_f64()
            .ok_or(DiagServiceError::ParameterConversionError(
                "Invalid value for Float64".to_owned(),
            ))
            .map(|v| v.to_be_bytes().to_vec()),
        _ => Err(DiagServiceError::ParameterConversionError(format!(
            "Not support data type {data_type:?} for value conversion"
        ))),
    }
}

fn process_physical_type_value(
    json_value: &serde_json::Value,
    physical_type: PhysicalType,
    data_type: &datatypes::DiagCodedType,
) -> Result<Vec<u8>, DiagServiceError> {
    let value = json_value
        .as_str()
        .ok_or(DiagServiceError::ParameterConversionError(format!(
            "Non-numeric JSON value {json_value} could not be converted to string"
        )))?;
    let data = decode_numeric_val_from_str(value, physical_type, data_type)?;
    let base_type = data_type.base_datatype();
    if physical_type.base_type == base_type {
        Ok(data)
    } else {
        match physical_type.base_type {
            DataType::Int32 => {
                let val = i32::from_be_bytes(
                    pad_msb_to_len(&data, size_of::<i32>())
                        .try_into()
                        .expect("input bytes padded to i32 size"),
                );
                to_numeric_base_type(val, base_type)
            }
            DataType::UInt32 => {
                let val = u32::from_be_bytes(
                    pad_msb_to_len(&data, size_of::<u32>())
                        .try_into()
                        .expect("input bytes padded to u32 size"),
                );
                to_numeric_base_type(val, base_type)
            }
            DataType::Float32 => {
                let val = f32::from_be_bytes(
                    pad_msb_to_len(&data, size_of::<f32>())
                        .try_into()
                        .expect("input bytes padded to f32 size"),
                );
                to_numeric_base_type(val, base_type)
            }
            DataType::Float64 => {
                let val = f64::from_be_bytes(
                    pad_msb_to_len(&data, size_of::<f64>())
                        .try_into()
                        .expect("input bytes padded to f64 size"),
                );
                to_numeric_base_type(val, base_type)
            }
            DataType::AsciiString
            | DataType::Utf8String
            | DataType::Unicode2String
            | DataType::ByteField => Err(DiagServiceError::ParameterConversionError(format!(
                "Cannot convert from non-numeric physical type {:?} to numeric base type {:?}",
                physical_type.base_type, base_type
            ))),
        }
    }
}

fn validate_data_length(
    data: &[u8],
    base_type: DataType,
    json_value: &serde_json::Value,
) -> Result<(), DiagServiceError> {
    match base_type {
        DataType::Int32 | DataType::UInt32 | DataType::Float32 if data.len() > 4 => {
            return Err(DiagServiceError::ParameterConversionError(format!(
                "Invalid data length {} for {base_type:?} value {json_value}",
                data.len()
            )));
        }
        DataType::Float64 if data.len() > 8 => {
            return Err(DiagServiceError::ParameterConversionError(format!(
                "Invalid data length for {base_type:?}: {}, value {json_value}",
                data.len()
            )));
        }
        _ => {}
    }
    Ok(())
}

fn numeric_json_value_to_byte_vector(
    json_value: &serde_json::Value,
    data_type: &datatypes::DiagCodedType,
    physical_type: Option<PhysicalType>,
) -> Result<Vec<u8>, DiagServiceError> {
    let data = if json_value.is_number() {
        process_numeric_json_value(json_value, data_type)
    } else if let Some(physical_type) = physical_type {
        process_physical_type_value(json_value, physical_type, data_type)
    } else {
        Err(DiagServiceError::ParameterConversionError(format!(
            "Cannot decode non-numeric JSON value {json_value:?} to {:?} without physical type \
             information",
            data_type.base_datatype()
        )))
    };

    if let Ok(ref data) = data {
        validate_data_length(data, data_type.base_datatype(), json_value)?;
    }
    data
}

fn to_numeric_base_type<T: num_traits::ToPrimitive + Display + Copy>(
    val: T,
    base_type: DataType,
) -> Result<Vec<u8>, DiagServiceError> {
    match base_type {
        DataType::Int32 => val
            .to_i32()
            .ok_or(DiagServiceError::ParameterConversionError(format!(
                "Failed to convert {val} to Int32"
            )))
            .map(|v| v.to_be_bytes().to_vec()),
        DataType::UInt32 => val
            .to_u32()
            .ok_or(DiagServiceError::ParameterConversionError(format!(
                "Failed to convert {val} to UInt32"
            )))
            .map(|v| v.to_be_bytes().to_vec()),
        DataType::Float32 => val
            .to_f32()
            .ok_or(DiagServiceError::ParameterConversionError(format!(
                "Failed to convert {val} to Float32"
            )))
            .map(|v| v.to_be_bytes().to_vec()),
        DataType::Float64 => val
            .to_f64()
            .ok_or(DiagServiceError::ParameterConversionError(format!(
                "Failed to convert {val} to Float64"
            )))
            .map(|v| v.to_be_bytes().to_vec()),
        DataType::AsciiString
        | DataType::Utf8String
        | DataType::Unicode2String
        | DataType::ByteField => Err(DiagServiceError::ParameterConversionError(format!(
            "Cannot convert numeric value {val} to non-numeric base type {base_type:?}"
        ))),
    }
}

fn validate_bit_len_signed<T>(value: T, bit_len: BitLength) -> Result<(), DiagServiceError>
where
    T: Copy
        + From<i8>
        + PartialOrd
        + std::fmt::Display
        + num_traits::CheckedShl
        + num_traits::CheckedNeg
        + num_traits::CheckedSub
        + num_traits::Saturating
        + num_traits::bounds::UpperBounded
        + num_traits::bounds::LowerBounded
        + num_traits::Signed,
{
    if bit_len == 0 {
        return Err(DiagServiceError::ParameterConversionError(
            "Bit length 0 is not allowed for validation".to_owned(),
        ));
    }

    let max_value = T::from(1)
        .checked_shl(bit_len.saturating_sub(1))
        .and_then(|v| v.checked_sub(&T::from(1)))
        .unwrap_or_else(T::max_value); // min/max is needed, when bit length == size of T

    let min_value = T::from(1)
        .checked_shl(bit_len.saturating_sub(1))
        .and_then(|v| v.checked_neg())
        .unwrap_or_else(T::min_value);

    if value < min_value {
        return Err(DiagServiceError::ParameterConversionError(format!(
            "Value {value} is below minimum {min_value} for bit length {bit_len}",
        )));
    }

    if value > max_value {
        return Err(DiagServiceError::ParameterConversionError(format!(
            "Value {value} exceeds maximum {max_value} for bit length {bit_len}",
        )));
    }

    Ok(())
}

fn validate_bit_len_unsigned<T>(value: T, bit_len: BitLength) -> Result<(), DiagServiceError>
where
    T: Copy
        + From<u8>
        + PartialOrd
        + std::fmt::Display
        + num_traits::CheckedShl
        + num_traits::Saturating
        + num_traits::bounds::UpperBounded
        + num_traits::Unsigned,
{
    if bit_len == 0 {
        return Err(DiagServiceError::ParameterConversionError(
            "Bit length 0 is not allowed for validation".to_owned(),
        ));
    }

    // range is 0 to 2^bits - 1
    // (T::from(1) << bit_len) - T::from(1);
    let max_value = T::from(1)
        .checked_shl(bit_len)
        // max is needed, when bit length == size of T
        .map_or_else(T::max_value, |v| v.saturating_sub(T::from(1)));

    if value > max_value {
        return Err(DiagServiceError::ParameterConversionError(format!(
            "Value {value} exceeds maximum {max_value} for bit length {bit_len}",
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use cda_database::datatypes::{
        BitLength, CompuCategory, CompuFunction, CompuMethod, CompuRationalCoefficients,
        CompuScale, CompuValues, DataType, DiagCodedType, DiagCodedTypeVariant, IntervalType,
        Limit, MinMaxLengthType, PhysicalType, Radix, StandardLengthType, Termination,
    };

    /// Helper function to create a `DiagCodedType` as `StandardLength` Type for testing
    fn create_diag_coded_type_stl(
        data_type: DataType,
        bit_length_override: Option<BitLength>,
    ) -> DiagCodedType {
        let bit_length = bit_length_override.unwrap_or(match data_type {
            DataType::Int32 | DataType::UInt32 | DataType::Float32 => 32,
            DataType::Float64 => 64,
            DataType::ByteField
            | DataType::AsciiString
            | DataType::Utf8String
            | DataType::Unicode2String => 8, // Default to 8 bits for variable length types
        });
        DiagCodedType::new(
            data_type,
            DiagCodedTypeVariant::StandardLength(StandardLengthType {
                bit_length,
                bit_mask: None,
                condensed: false,
            }),
            true, // high-low byte order
        )
        .unwrap()
    }

    fn create_diag_coded_type_minmax(
        data_type: DataType,
        min_length: u32,
        max_length: Option<u32>,
        termination: Termination,
    ) -> DiagCodedType {
        DiagCodedType::new(
            data_type,
            DiagCodedTypeVariant::MinMaxLength(MinMaxLengthType {
                min_length,
                max_length,
                termination,
            }),
            true,
        )
        .unwrap()
    }

    use crate::diag_kernel::{operations::extract_diag_data_container, payload::Payload};

    #[test]
    fn test_hex_values() {
        let json_value = serde_json::json!("0x11223344");
        let diag_type = create_diag_coded_type_stl(DataType::ByteField, None);
        let result = super::json_value_to_uds_data(&diag_type, None, None, &json_value);
        assert_eq!(result, Ok(vec![0x11, 0x22, 0x33, 0x44]));
    }

    #[test]
    fn test_integer_out_of_range() {
        let json_value = serde_json::json!(i64::MAX);
        let int32_type = create_diag_coded_type_stl(DataType::Int32, None);
        let uint32_type = create_diag_coded_type_stl(DataType::UInt32, None);
        assert!(super::json_value_to_uds_data(&int32_type, None, None, &json_value).is_err());
        assert!(super::json_value_to_uds_data(&uint32_type, None, None, &json_value).is_err());
    }

    #[test]
    fn test_hex_values_odd() {
        let json_value = serde_json::json!("0x1 0x2");

        let bytefield_type = create_diag_coded_type_stl(DataType::ByteField, None);
        let uint32_type = create_diag_coded_type_stl(DataType::UInt32, None);
        let uint32_physical_type = PhysicalType {
            precision: None,
            base_type: DataType::UInt32,
            display_radix: Some(Radix::Hex),
        };

        assert_eq!(
            super::json_value_to_uds_data(&bytefield_type, None, None, &json_value),
            Ok(vec![0x1, 0x2])
        );
        assert_eq!(
            super::json_value_to_uds_data(
                &uint32_type,
                None,
                Some(uint32_physical_type),
                &json_value
            ),
            Ok(vec![0, 0, 1, 2])
        );
    }

    #[test]
    fn test_space_separated_hex_values() {
        let json_value = serde_json::json!("0x00 0x01 0x80 0x00");

        let bytefield_type = create_diag_coded_type_stl(DataType::ByteField, None);
        let uint32_type = create_diag_coded_type_stl(DataType::UInt32, None);
        let uint32_hex_physical_type = PhysicalType {
            precision: None,
            base_type: DataType::UInt32,
            display_radix: Some(Radix::Hex),
        };
        let uint32_dec_physical_type = PhysicalType {
            precision: None,
            base_type: DataType::UInt32,
            display_radix: None, // default is decimal
        };

        let expected = Ok(vec![0x00, 0x01, 0x80, 0x00]);
        assert_eq!(
            super::json_value_to_uds_data(&bytefield_type, None, None, &json_value),
            expected
        );
        // only u32 is supported in hex notation according to ISO 22901-1
        assert_eq!(
            super::json_value_to_uds_data(
                &uint32_type,
                None,
                Some(uint32_hex_physical_type),
                &json_value
            ),
            expected
        );

        assert!(
            super::json_value_to_uds_data(
                &uint32_type,
                None,
                Some(uint32_dec_physical_type),
                &json_value
            )
            .is_err()
        );
    }

    #[test]
    fn test_mixed_values() {
        let json_value = serde_json::json!("ff 0a 12 deadbeef ca7");
        let diag_type = create_diag_coded_type_stl(DataType::ByteField, None);
        let result = super::json_value_to_uds_data(&diag_type, None, None, &json_value);
        assert_eq!(
            result,
            Ok(vec![255, 10, 18, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0x07])
        );
    }

    #[test]
    fn test_hex_long() {
        let json_value = serde_json::json!("c0ffeca7");
        let diag_type = create_diag_coded_type_stl(DataType::ByteField, None);
        let result = super::json_value_to_uds_data(&diag_type, None, None, &json_value);
        assert_eq!(result, Ok(vec![0xC0, 0xFF, 0xEC, 0xA7]));
    }

    #[test]
    fn test_invalid_hex_value() {
        let json_value = serde_json::json!("0xZZ");
        let diag_type = create_diag_coded_type_stl(DataType::ByteField, None);
        let result = super::json_value_to_uds_data(&diag_type, None, None, &json_value);
        assert!(result.is_err());
    }

    #[test]
    fn test_long_byte_value() {
        let json_value = serde_json::json!("0100");
        let diag_type = create_diag_coded_type_stl(DataType::ByteField, Some(9));
        let result = super::json_value_to_uds_data(&diag_type, None, None, &json_value);
        assert_eq!(result, Ok(vec![0x01, 0x00]));
    }

    #[test]
    fn test_float_string() {
        let json_value = serde_json::json!("10.42");

        let int32_type = create_diag_coded_type_stl(DataType::Int32, None);
        let f32_physical_type = PhysicalType {
            precision: None,
            base_type: DataType::Float32,
            display_radix: None,
        };
        let uint32_type = create_diag_coded_type_stl(DataType::UInt32, None);
        let float32_type = create_diag_coded_type_stl(DataType::Float32, None);
        let float64_type = create_diag_coded_type_stl(DataType::Float64, None);

        let int_result = Ok(vec![0x00, 0x00, 0x00, 0x0A]);
        assert_eq!(
            super::json_value_to_uds_data(&int32_type, None, Some(f32_physical_type), &json_value),
            int_result
        );
        assert_eq!(
            super::json_value_to_uds_data(&uint32_type, None, Some(f32_physical_type), &json_value),
            int_result
        );

        assert_eq!(
            super::json_value_to_uds_data(
                &float32_type,
                None,
                Some(f32_physical_type),
                &json_value
            ),
            Ok(vec![65, 38, 184, 82])
        );
        assert_eq!(
            super::json_value_to_uds_data(
                &float64_type,
                None,
                Some(f32_physical_type),
                &json_value
            ),
            Ok(f64::from(10.42f32).to_be_bytes().to_vec())
        );
    }

    #[test]
    fn test_float() {
        let json_value = serde_json::json!(10.42);

        let int32_type = create_diag_coded_type_stl(DataType::Int32, None);
        let uint32_type = create_diag_coded_type_stl(DataType::UInt32, None);
        let bytefield_type = create_diag_coded_type_stl(DataType::ByteField, None);
        let float32_type = create_diag_coded_type_stl(DataType::Float32, None);
        let float64_type = create_diag_coded_type_stl(DataType::Float64, None);

        assert!(super::json_value_to_uds_data(&int32_type, None, None, &json_value).is_err());
        assert!(super::json_value_to_uds_data(&uint32_type, None, None, &json_value).is_err());
        assert!(super::json_value_to_uds_data(&bytefield_type, None, None, &json_value).is_err());

        assert_eq!(
            super::json_value_to_uds_data(&float32_type, None, None, &json_value),
            Ok(vec![65, 38, 184, 82])
        );
        assert_eq!(
            super::json_value_to_uds_data(&float64_type, None, None, &json_value),
            Ok(vec![64, 36, 215, 10, 61, 112, 163, 215])
        );
    }

    #[test]
    fn test_linear_conversion_data_types() {
        let compu_method = CompuMethod {
            category: CompuCategory::Identical,
            internal_to_phys: CompuFunction {
                scales: vec![CompuScale {
                    rational_coefficients: Some(CompuRationalCoefficients {
                        numerator: vec![0.0, 1.0],
                        denominator: vec![1.0],
                    }),
                    consts: None,
                    lower_limit: Some(Limit {
                        value: "0.0".to_owned(),
                        interval_type: IntervalType::Open,
                    }),
                    upper_limit: Some(Limit {
                        value: "100.0".to_owned(),
                        interval_type: IntervalType::Closed,
                    }),
                    inverse_values: None,
                }],
            },
        };

        let value = serde_json::json!("42");
        let int32_type = create_diag_coded_type_stl(DataType::Int32, None);
        let int32_phys_type = Some(PhysicalType {
            precision: None,
            base_type: DataType::Int32,
            display_radix: None,
        });
        let result = super::compu_convert(
            &int32_type,
            &compu_method,
            int32_phys_type,
            CompuCategory::Linear,
            &value,
        );
        assert_eq!(result.unwrap(), 42i32.to_be_bytes().to_vec());

        let value = serde_json::json!("42.42");
        let float32_type = create_diag_coded_type_stl(DataType::Float32, None);
        let float32_phys_type = Some(PhysicalType {
            precision: None,
            base_type: DataType::Float32,
            display_radix: None,
        });
        let result = super::compu_convert(
            &float32_type,
            &compu_method,
            float32_phys_type,
            CompuCategory::Linear,
            &value,
        );
        assert_eq!(result.unwrap(), 42.42f32.to_be_bytes().to_vec());

        let value = serde_json::json!("42.4242");
        let float64_type = create_diag_coded_type_stl(DataType::Float64, None);
        let float64_phys_type = Some(PhysicalType {
            precision: None,
            base_type: DataType::Float64,
            display_radix: None,
        });
        let result = super::compu_convert(
            &float64_type,
            &compu_method,
            float64_phys_type,
            CompuCategory::Linear,
            &value,
        );
        assert_eq!(result.unwrap(), 42.4242f64.to_be_bytes().to_vec());

        let value = serde_json::json!(42);
        let float64_type = create_diag_coded_type_stl(DataType::Float64, None);
        let float64_phys_type = Some(PhysicalType {
            precision: None,
            base_type: DataType::Float64,
            display_radix: None,
        });
        let result = super::compu_convert(
            &float64_type,
            &compu_method,
            float64_phys_type,
            CompuCategory::Linear,
            &value,
        );
        assert_eq!(result.unwrap(), 42f64.to_be_bytes().to_vec());

        let value = serde_json::json!(42);
        let int32_type = create_diag_coded_type_stl(DataType::Int32, None);
        let result = super::compu_convert(
            &int32_type,
            &compu_method,
            int32_phys_type,
            CompuCategory::Linear,
            &value,
        );
        assert_eq!(result.unwrap(), 42i32.to_be_bytes().to_vec());
    }

    #[test]
    fn test_linear_conversion_scaling() {
        let offset = 1.23;
        let factor = 2.0;
        let denominator = 0.5;
        let compu_method = CompuMethod {
            category: CompuCategory::Linear,
            internal_to_phys: CompuFunction {
                scales: vec![CompuScale {
                    rational_coefficients: Some(CompuRationalCoefficients {
                        numerator: vec![offset, factor],
                        denominator: vec![denominator],
                    }),
                    consts: None,
                    lower_limit: Some(Limit {
                        value: "0.0".to_owned(),
                        interval_type: IntervalType::Open,
                    }),
                    upper_limit: Some(Limit {
                        value: "200.0".to_owned(),
                        interval_type: IntervalType::Closed,
                    }),
                    inverse_values: None,
                }],
            },
        };

        // f(x) = (offset + factor * x) / denominator
        // internal->physical: f(42) = (1.23 + 2 * 42)/0.5 = 170.46
        // physical->internal: given physical 170, internal = (0.5*170 - 1.23)/2 = 41.885
        // there is rounding but values are truncated when converting to integer types
        let value = serde_json::json!(170);
        let int32_type = create_diag_coded_type_stl(DataType::Int32, None);
        let int32_phys_type = Some(PhysicalType {
            precision: None,
            base_type: DataType::Int32,
            display_radix: None,
        });
        let result = super::compu_convert(
            &int32_type,
            &compu_method,
            int32_phys_type,
            CompuCategory::Linear,
            &value,
        );
        assert_eq!(result.unwrap(), 41i32.to_be_bytes().to_vec());

        let value = serde_json::json!(170.46);
        let float32_type = create_diag_coded_type_stl(DataType::Float32, None);
        let float32_phys_type = Some(PhysicalType {
            precision: None,
            base_type: DataType::Float32,
            display_radix: None,
        });
        let result = super::compu_convert(
            &float32_type,
            &compu_method,
            float32_phys_type,
            CompuCategory::Linear,
            &value,
        );
        assert_eq!(result.unwrap(), 42.0f32.to_be_bytes().to_vec());
    }

    #[test]
    fn test_compu_convert_text_table() {
        let scale = CompuScale {
            rational_coefficients: None,
            consts: Some(CompuValues {
                v: 0.0,
                vt: Some("TestValue".to_owned()),
                vt_ti: None,
            }),
            lower_limit: Some(Limit {
                value: "42.0".to_owned(),
                interval_type: IntervalType::Closed,
            }),
            upper_limit: Some(Limit {
                value: "100.0".to_owned(),
                interval_type: IntervalType::Closed,
            }),
            inverse_values: None,
        };

        let compu_method = CompuMethod {
            category: CompuCategory::TextTable,
            internal_to_phys: CompuFunction {
                scales: vec![scale],
            },
        };

        let value = serde_json::json!("TestValue");
        let int32_type = create_diag_coded_type_stl(DataType::Int32, None);
        let int32_phys_type = Some(PhysicalType {
            precision: None,
            base_type: DataType::Int32,
            display_radix: None,
        });
        let result = super::compu_convert(
            &int32_type,
            &compu_method,
            int32_phys_type,
            CompuCategory::TextTable,
            &value,
        );
        assert_eq!(result.unwrap(), 42i32.to_be_bytes().to_vec());

        let value = serde_json::json!("NotFound");
        let int32_type = create_diag_coded_type_stl(DataType::Int32, None);
        let result = super::compu_convert(
            &int32_type,
            &compu_method,
            int32_phys_type,
            CompuCategory::TextTable,
            &value,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_numeric_value_from_str() {
        // test decode float
        let base_type = create_diag_coded_type_stl(DataType::Float32, None);
        let phys_type = PhysicalType {
            precision: None,
            base_type: DataType::Float32,
            display_radix: None,
        };
        let value = "10.42";
        let result = super::decode_numeric_val_from_str(value, phys_type, &base_type).unwrap();
        assert_eq!(result, 10.42f32.to_be_bytes().to_vec());

        // test decode int
        let base_type = create_diag_coded_type_stl(DataType::Int32, None);
        let phys_type = PhysicalType {
            precision: None,
            base_type: DataType::Int32,
            display_radix: None,
        };
        let value = "42";
        let result = super::decode_numeric_val_from_str(value, phys_type, &base_type).unwrap();
        assert_eq!(result, 42i32.to_be_bytes().to_vec());

        // test decode int as hex is err
        let value = "0x2A";
        let result = super::decode_numeric_val_from_str(value, phys_type, &base_type);
        assert!(result.is_err());

        // test decode uint as decimal
        let base_type = create_diag_coded_type_stl(DataType::UInt32, None);

        let phys_type = PhysicalType {
            precision: None,
            base_type: DataType::UInt32,
            display_radix: None,
        };
        let value = "42";
        let result = super::decode_numeric_val_from_str(value, phys_type, &base_type).unwrap();
        assert_eq!(result, 42u32.to_be_bytes().to_vec());

        // test decode uint as hex
        let phys_type = PhysicalType {
            precision: None,
            base_type: DataType::UInt32,
            display_radix: Some(Radix::Hex),
        };
        let value = "0x2A";
        let result = super::decode_numeric_val_from_str(value, phys_type, &base_type).unwrap();
        assert_eq!(result, 42u32.to_be_bytes().to_vec());

        // test decode uint as octal
        let phys_type = PhysicalType {
            precision: None,
            base_type: DataType::UInt32,
            display_radix: Some(Radix::Octal),
        };
        let value = "0o52";
        let result = super::decode_numeric_val_from_str(value, phys_type, &base_type).unwrap();
        assert_eq!(result, 42u32.to_be_bytes().to_vec());

        // test decode uint as octal without prefix
        let value = "52";
        let result = super::decode_numeric_val_from_str(value, phys_type, &base_type).unwrap();
        assert_eq!(result, 42u32.to_be_bytes().to_vec());

        // test decode uint as binary
        let phys_type = PhysicalType {
            precision: None,
            base_type: DataType::UInt32,
            display_radix: Some(Radix::Binary),
        };
        let value = "0b101010";
        let result = super::decode_numeric_val_from_str(value, phys_type, &base_type).unwrap();
        assert_eq!(result, 42u32.to_be_bytes().to_vec());

        // test decode uint as binary without prefix
        let value = "101010";
        let result = super::decode_numeric_val_from_str(value, phys_type, &base_type).unwrap();
        assert_eq!(result, 42u32.to_be_bytes().to_vec());
    }

    #[test]
    fn test_validate_bit_len_signed() {
        // Test with bit len = 0 (invalid)
        assert!(super::validate_bit_len_signed(0i16, 0).is_err());

        // Test with bit_len = 8 (range: -128 to 127)
        assert!(super::validate_bit_len_signed(-128i16, 8).is_ok());
        assert!(super::validate_bit_len_signed(127i16, 8).is_ok());
        assert!(super::validate_bit_len_signed(0i16, 8).is_ok());
        assert!(super::validate_bit_len_signed(-129i16, 8).is_err());
        assert!(super::validate_bit_len_signed(128i16, 8).is_err());

        // Test boundary values for bit_len = 7 (range: -64 to 63)
        assert!(super::validate_bit_len_signed(-64i16, 7).is_ok());
        assert!(super::validate_bit_len_signed(63i16, 7).is_ok());
        assert!(super::validate_bit_len_signed(-65i16, 7).is_err());
        assert!(super::validate_bit_len_signed(64i16, 7).is_err());

        // Test edge case: bit_len equal to type size
        assert!(super::validate_bit_len_signed(i8::MIN, 7).is_err());
        assert!(super::validate_bit_len_signed(i8::MIN, 8).is_ok());
        assert!(super::validate_bit_len_signed(i8::MAX, 8).is_ok());
        assert!(super::validate_bit_len_signed(i16::MIN, 16).is_ok());
        assert!(super::validate_bit_len_signed(i16::MAX, 16).is_ok());
    }

    #[test]
    fn test_validate_bit_len_unsigned() {
        // Test with bit_len = 0 (invalid)
        assert!(super::validate_bit_len_unsigned(0u8, 0).is_err());

        // Test with bit_len = 8 (range: 0 to 255)
        assert!(super::validate_bit_len_unsigned(0u16, 8).is_ok());
        assert!(super::validate_bit_len_unsigned(255u16, 8).is_ok());
        assert!(super::validate_bit_len_unsigned(128u16, 8).is_ok());
        assert!(super::validate_bit_len_unsigned(256u16, 8).is_err());

        // Test with bit_len = 16 (range: 0 to 65535)
        assert!(super::validate_bit_len_unsigned(0u32, 16).is_ok());
        assert!(super::validate_bit_len_unsigned(65535u32, 16).is_ok());
        assert!(super::validate_bit_len_unsigned(32768u32, 16).is_ok());
        assert!(super::validate_bit_len_unsigned(65536u32, 16).is_err());

        // Test boundary values for u8 with bit_len = 7 (range: 0 to 127)
        assert!(super::validate_bit_len_unsigned(0u8, 7).is_ok());
        assert!(super::validate_bit_len_unsigned(127u8, 7).is_ok());
        assert!(super::validate_bit_len_unsigned(128u8, 7).is_err());

        // Test edge case: bit_len equal to type size
        assert!(super::validate_bit_len_unsigned(u8::MIN, 8).is_ok());
        assert!(super::validate_bit_len_unsigned(u8::MAX, 8).is_ok());
        assert!(super::validate_bit_len_unsigned(u16::MIN, 16).is_ok());
        assert!(super::validate_bit_len_unsigned(u16::MAX, 16).is_ok());

        // Test middle values
        assert!(super::validate_bit_len_unsigned(5u8, 4).is_ok());
        assert!(super::validate_bit_len_unsigned(15u8, 4).is_ok());
        assert!(super::validate_bit_len_unsigned(16u8, 4).is_err());
    }

    #[test]
    fn test_compu_lookup_linear_multiple_scales_error() {
        // LINEAR must have exactly one COMPU-SCALE
        let compu_method = CompuMethod {
            category: CompuCategory::Linear,
            internal_to_phys: CompuFunction {
                scales: vec![
                    CompuScale {
                        rational_coefficients: Some(CompuRationalCoefficients {
                            numerator: vec![1.0, 2.0],
                            denominator: vec![1.0],
                        }),
                        consts: None,
                        lower_limit: Some(Limit {
                            value: "0.0".to_owned(),
                            interval_type: IntervalType::Closed,
                        }),
                        upper_limit: Some(Limit {
                            value: "5.0".to_owned(),
                            interval_type: IntervalType::Open,
                        }),
                        inverse_values: None,
                    },
                    CompuScale {
                        rational_coefficients: Some(CompuRationalCoefficients {
                            numerator: vec![3.0, 1.0],
                            denominator: vec![1.0],
                        }),
                        consts: None,
                        lower_limit: Some(Limit {
                            value: "5.0".to_owned(),
                            interval_type: IntervalType::Closed,
                        }),
                        upper_limit: Some(Limit {
                            value: "10.0".to_owned(),
                            interval_type: IntervalType::Closed,
                        }),
                        inverse_values: None,
                    },
                ],
            },
        };

        let data = 3u32.to_be_bytes();
        let result =
            super::uds_data_to_serializable(DataType::UInt32, Some(&compu_method), false, &data);
        // Should fail because LINEAR has 2 scales instead of 1
        assert!(result.is_err());
        if let Err(e) = result {
            let error_msg = format!("{e:?}");
            assert!(error_msg.contains("Expected exactly 1 COMPU-SCALE"));
        }
    }

    #[test]
    fn test_compu_lookup_linear_zero_scales_error() {
        // LINEAR must have exactly one COMPU-SCALE, not zero
        let compu_method = CompuMethod {
            category: CompuCategory::Linear,
            internal_to_phys: CompuFunction { scales: vec![] },
        };

        let data = 3u32.to_be_bytes();
        let result =
            super::uds_data_to_serializable(DataType::UInt32, Some(&compu_method), false, &data);
        // Should fail because value doesn't match any scale (no scales exist)
        assert!(result.is_err());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    #[allow(clippy::float_cmp)]
    fn test_compu_lookup_scale_linear_piecewise_function() {
        // ISO 22901-1:2008 Figure 80 example:
        // f(x) = { 1+2x, xE[0,2), 3+x, xE[2,5), 8, xE[5,infinity) }
        let compu_method = CompuMethod {
            category: CompuCategory::ScaleLinear,
            internal_to_phys: CompuFunction {
                scales: vec![
                    // First interval: [0, 2) -> f(x) = 1 + 2x
                    CompuScale {
                        rational_coefficients: Some(CompuRationalCoefficients {
                            numerator: vec![1.0, 2.0], // offset=1, factor=2
                            denominator: vec![1.0],
                        }),
                        consts: None,
                        lower_limit: Some(Limit {
                            value: "0.0".to_owned(),
                            interval_type: IntervalType::Closed, // [0
                        }),
                        upper_limit: Some(Limit {
                            value: "2.0".to_owned(),
                            interval_type: IntervalType::Open, // 2)
                        }),
                        inverse_values: None,
                    },
                    // Second interval: [2, 5) -> f(x) = 3 + x
                    CompuScale {
                        rational_coefficients: Some(CompuRationalCoefficients {
                            numerator: vec![3.0, 1.0], // offset=3, factor=1
                            denominator: vec![1.0],
                        }),
                        consts: None,
                        lower_limit: Some(Limit {
                            value: "2.0".to_owned(),
                            interval_type: IntervalType::Closed, // [2
                        }),
                        upper_limit: Some(Limit {
                            value: "5.0".to_owned(),
                            interval_type: IntervalType::Open, // 5)
                        }),
                        inverse_values: None,
                    },
                    // Third interval: [5, infinity) -> f(x) = 8 (constant)
                    CompuScale {
                        rational_coefficients: Some(CompuRationalCoefficients {
                            numerator: vec![8.0, 0.0], // offset=8, factor=0
                            denominator: vec![1.0],
                        }),
                        consts: None,
                        lower_limit: Some(Limit {
                            value: "5.0".to_owned(),
                            interval_type: IntervalType::Closed, // [5
                        }),
                        upper_limit: Some(Limit {
                            value: "99999.0".to_owned(),
                            interval_type: IntervalType::Infinite, // infinity)
                        }),
                        inverse_values: None,
                    },
                ],
            },
        };

        // First interval: [0, 2) -> f(x) = 1 + 2x
        // Forward: x=0 -> y=1
        let data = 0u32.to_be_bytes();
        let result =
            super::uds_data_to_serializable(DataType::UInt32, Some(&compu_method), false, &data);
        assert!(result.is_ok());
        let value: f64 = result.unwrap().try_into().unwrap();
        assert_eq!(value, 1.0);

        // Inverse: y=1 -> x=0
        let value = serde_json::json!(1.0);
        let float64_type = create_diag_coded_type_stl(DataType::Float64, None);
        let float64_phys_type = Some(PhysicalType {
            precision: None,
            base_type: DataType::Float64,
            display_radix: None,
        });
        let result = super::compu_convert(
            &float64_type,
            &compu_method,
            float64_phys_type,
            CompuCategory::ScaleLinear,
            &value,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0.0f64.to_be_bytes().to_vec());

        // Forward: x=1 -> y=3
        let data = 1u32.to_be_bytes();
        let result =
            super::uds_data_to_serializable(DataType::UInt32, Some(&compu_method), false, &data);
        assert!(result.is_ok());
        let value: f64 = result.unwrap().try_into().unwrap();
        assert_eq!(value, 3.0);

        // Inverse: y=3 -> x=1
        let value = serde_json::json!(3.0);
        let float64_type = create_diag_coded_type_stl(DataType::Float64, None);
        let result = super::compu_convert(
            &float64_type,
            &compu_method,
            float64_phys_type,
            CompuCategory::ScaleLinear,
            &value,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1.0f64.to_be_bytes().to_vec());

        // Forward: x=1.5 -> y=4
        let data = 1.5f32.to_be_bytes();
        let result =
            super::uds_data_to_serializable(DataType::Float32, Some(&compu_method), false, &data);
        assert!(result.is_ok());
        let value: f64 = result.unwrap().try_into().unwrap();
        assert_eq!(value, 4.0);

        // Inverse: y=4 -> x=1.5
        let value = serde_json::json!(4.0);
        let float64_type = create_diag_coded_type_stl(DataType::Float64, None);
        let result = super::compu_convert(
            &float64_type,
            &compu_method,
            float64_phys_type,
            CompuCategory::ScaleLinear,
            &value,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1.5f64.to_be_bytes().to_vec());

        // Second interval: [2, 5) -> f(x) = 3 + x
        // Forward: x=2 -> y=5 (boundary, CLOSED at 2)
        let data = 2u32.to_be_bytes();
        let result =
            super::uds_data_to_serializable(DataType::UInt32, Some(&compu_method), false, &data);
        assert!(result.is_ok());
        let value: f64 = result.unwrap().try_into().unwrap();
        assert_eq!(value, 5.0);

        // Inverse: y=5 -> x=2
        let value = serde_json::json!(5.0);
        let float64_type = create_diag_coded_type_stl(DataType::Float64, None);
        let result = super::compu_convert(
            &float64_type,
            &compu_method,
            float64_phys_type,
            CompuCategory::ScaleLinear,
            &value,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 2.0f64.to_be_bytes().to_vec());

        // Forward: x=3 -> y=6
        let data = 3u32.to_be_bytes();
        let result =
            super::uds_data_to_serializable(DataType::UInt32, Some(&compu_method), false, &data);
        assert!(result.is_ok());
        let value: f64 = result.unwrap().try_into().unwrap();
        assert_eq!(value, 6.0);

        // Inverse: y=6 -> x=3
        let value = serde_json::json!(6.0);
        let float64_type = create_diag_coded_type_stl(DataType::Float64, None);
        let result = super::compu_convert(
            &float64_type,
            &compu_method,
            float64_phys_type,
            CompuCategory::ScaleLinear,
            &value,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 3.0f64.to_be_bytes().to_vec());

        // Forward: x=4 -> y=7
        let data = 4u32.to_be_bytes();
        let result =
            super::uds_data_to_serializable(DataType::UInt32, Some(&compu_method), false, &data);
        assert!(result.is_ok());
        let value: f64 = result.unwrap().try_into().unwrap();
        assert_eq!(value, 7.0);

        // Inverse: y=7 -> x=4
        let value = serde_json::json!(7.0);
        let float64_type = create_diag_coded_type_stl(DataType::Float64, None);
        let result = super::compu_convert(
            &float64_type,
            &compu_method,
            float64_phys_type,
            CompuCategory::ScaleLinear,
            &value,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 4.0f64.to_be_bytes().to_vec());

        // Third interval: [5, infinity) -> f(x) = 8 (constant)
        // Forward: x=5 -> y=8 (boundary)
        let data = 5u32.to_be_bytes();
        let result =
            super::uds_data_to_serializable(DataType::UInt32, Some(&compu_method), false, &data);
        assert!(result.is_ok());
        let value: f64 = result.unwrap().try_into().unwrap();
        assert_eq!(value, 8.0);

        // Forward: x=10 -> y=8 (constant)
        let data = 10u32.to_be_bytes();
        let result =
            super::uds_data_to_serializable(DataType::UInt32, Some(&compu_method), false, &data);
        assert!(result.is_ok());
        let value: f64 = result.unwrap().try_into().unwrap();
        assert_eq!(value, 8.0);

        // Forward: x=100 -> y=8 (constant)
        let data = 100u32.to_be_bytes();
        let result =
            super::uds_data_to_serializable(DataType::UInt32, Some(&compu_method), false, &data);
        assert!(result.is_ok());
        let value: f64 = result.unwrap().try_into().unwrap();
        assert_eq!(value, 8.0);

        // Inverse: y=8 should fail (constant function with V1=0 cannot be inverted)
        let value = serde_json::json!(8.0);
        let float64_type = create_diag_coded_type_stl(DataType::Float64, None);
        let result = super::compu_convert(
            &float64_type,
            &compu_method,
            float64_phys_type,
            CompuCategory::ScaleLinear,
            &value,
        );
        assert!(result.is_err());
        if let Err(e) = result {
            let error_msg = format!("{e:?}");
            assert!(error_msg.contains("Factor (V1) cannot be zero for inverse conversion"));
        }
    }

    #[test]
    // allowed because we expect an exact match on floating point values in this test
    #[allow(clippy::float_cmp)]
    fn test_compu_lookup_scale_linear_with_different_denominators() {
        // SCALE-LINEAR with different denominators per interval
        // f(x) = { (2+4x)/2, xE[0,5), (50+10x)/5, xE[5,10] }
        let compu_method = CompuMethod {
            category: CompuCategory::ScaleLinear,
            internal_to_phys: CompuFunction {
                scales: vec![
                    CompuScale {
                        rational_coefficients: Some(CompuRationalCoefficients {
                            numerator: vec![2.0, 4.0],
                            denominator: vec![2.0],
                        }),
                        consts: None,
                        lower_limit: Some(Limit {
                            value: "0.0".to_owned(),
                            interval_type: IntervalType::Closed,
                        }),
                        upper_limit: Some(Limit {
                            value: "5.0".to_owned(),
                            interval_type: IntervalType::Open,
                        }),
                        inverse_values: None,
                    },
                    CompuScale {
                        rational_coefficients: Some(CompuRationalCoefficients {
                            numerator: vec![50.0, 10.0],
                            denominator: vec![5.0],
                        }),
                        consts: None,
                        lower_limit: Some(Limit {
                            value: "5.0".to_owned(),
                            interval_type: IntervalType::Closed,
                        }),
                        upper_limit: Some(Limit {
                            value: "10.0".to_owned(),
                            interval_type: IntervalType::Closed,
                        }),
                        inverse_values: None,
                    },
                ],
            },
        };

        // First interval: x=2, f(2) = (2 + 4*2) / 2 = 10 / 2 = 5
        let data = 2u32.to_be_bytes();
        let result =
            super::uds_data_to_serializable(DataType::UInt32, Some(&compu_method), false, &data);
        assert!(result.is_ok());
        let value: f64 = result.unwrap().try_into().unwrap();
        assert_eq!(value, 5.0);

        // Second interval: x=6, f(6) = (50 + 10*6) / 5 = 110 / 5 = 22
        let data = 6u32.to_be_bytes();
        let result =
            super::uds_data_to_serializable(DataType::UInt32, Some(&compu_method), false, &data);
        assert!(result.is_ok());
        let value: f64 = result.unwrap().try_into().unwrap();
        assert_eq!(value, 22.0);
    }

    #[test]
    fn test_compu_lookup_scale_linear_value_outside_intervals() {
        // Value outside all intervals should return error
        let compu_method = CompuMethod {
            category: CompuCategory::ScaleLinear,
            internal_to_phys: CompuFunction {
                scales: vec![CompuScale {
                    rational_coefficients: Some(CompuRationalCoefficients {
                        numerator: vec![1.0, 2.0],
                        denominator: vec![1.0],
                    }),
                    consts: None,
                    lower_limit: Some(Limit {
                        value: "10.0".to_owned(),
                        interval_type: IntervalType::Closed,
                    }),
                    upper_limit: Some(Limit {
                        value: "20.0".to_owned(),
                        interval_type: IntervalType::Closed,
                    }),
                    inverse_values: None,
                }],
            },
        };

        // x=5 is outside [10, 20] -> lower limit
        let data = 5u32.to_be_bytes();
        let result =
            super::uds_data_to_serializable(DataType::UInt32, Some(&compu_method), false, &data);
        assert!(result.is_err());

        // x=25 is outside [10, 20] -> upper limit
        let data = 25u32.to_be_bytes();
        let result =
            super::uds_data_to_serializable(DataType::UInt32, Some(&compu_method), false, &data);
        assert!(result.is_err());
    }

    #[test]
    fn test_compu_convert_scale_linear_with_inverse_values() {
        // Test SCALE-LINEAR with a constant function (V1=0) that requires COMPU-INVERSE-VALUE
        // Forward: f(x) = (100.0 + 0.0*x) / 1.0 = 100.0 (always returns 100.0)
        // Inverse: Cannot compute algebraically when V1=0, so must use inverse_values
        let compu_method = CompuMethod {
            category: CompuCategory::ScaleLinear,
            internal_to_phys: CompuFunction {
                scales: vec![CompuScale {
                    rational_coefficients: Some(CompuRationalCoefficients {
                        numerator: vec![100.0, 0.0], // V0=100.0, V1=0.0 (constant function)
                        denominator: vec![1.0],
                    }),
                    consts: None,
                    lower_limit: Some(Limit {
                        value: "0.0".to_owned(),
                        interval_type: IntervalType::Closed,
                    }),
                    upper_limit: Some(Limit {
                        value: "10.0".to_owned(),
                        interval_type: IntervalType::Closed,
                    }),
                    inverse_values: Some(CompuValues {
                        v: 5.0, // When physical value is 100.0, internal value should be 5.0
                        vt: None,
                        vt_ti: None,
                    }),
                }],
            },
        };

        // Test inverse conversion: physical 100.0 -> internal 5.0 (using inverse_values)
        let value = serde_json::json!(100.0);
        let float64_type = create_diag_coded_type_stl(DataType::Float64, None);
        let float64_phys_type = Some(PhysicalType {
            precision: None,
            base_type: DataType::Float64,
            display_radix: None,
        });
        let result = super::compu_convert(
            &float64_type,
            &compu_method,
            float64_phys_type,
            CompuCategory::ScaleLinear,
            &value,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 5.0f64.to_be_bytes().to_vec());
    }

    #[test]
    // the given data in the tests allows and requires exact float comparisons
    #[allow(clippy::float_cmp)]
    fn test_parse_json_to_f64() {
        // test decimal representations
        let str_decimal_int = serde_json::json!("1");
        let u32_phys_type = Some(PhysicalType {
            precision: None,
            base_type: DataType::UInt32,
            display_radix: None,
        });
        let str_decimal_float = serde_json::json!("1.0");
        let f32_phys_type = Some(PhysicalType {
            precision: None,
            base_type: DataType::Float32,
            display_radix: None,
        });
        let decimal_int = serde_json::json!(1);
        let decimal_float = serde_json::json!(1.0);

        for (input, base_type, phys_type) in [
            (&str_decimal_int, DataType::Int32, u32_phys_type),
            (&str_decimal_float, DataType::Float32, f32_phys_type),
            (&decimal_int, DataType::UInt32, u32_phys_type),
            (&decimal_float, DataType::Float32, f32_phys_type),
        ] {
            let diag_coded_type = create_diag_coded_type_stl(base_type, None);

            let result = super::parse_json_to_f64(input, &diag_coded_type, phys_type).unwrap();
            assert_eq!(
                result, 1.0,
                "Failed for data type {base_type:?} with input {input:?}"
            );
        }
        // }
    }

    #[test]
    fn test_min_max_is_optional() {
        let dct =
            create_diag_coded_type_minmax(DataType::ByteField, 0, Some(1), Termination::EndOfPdu);

        let data: [u8; 0] = [];
        let mut payload = Payload::new(&data);
        let res = extract_diag_data_container(Some("test_param"), 0, 0, &mut payload, &dct, None);
        assert!(
            res.is_ok(),
            "MinMaxLengthType with min_length 0 should be no error"
        );

        let dct_min1 =
            create_diag_coded_type_minmax(DataType::ByteField, 1, Some(1), Termination::EndOfPdu);
        let mut payload = Payload::new(&data);
        let res: Result<crate::DiagDataTypeContainer, cda_interfaces::DiagServiceError> =
            extract_diag_data_container(Some("test_param"), 0, 0, &mut payload, &dct_min1, None);
        assert!(
            res.is_err(),
            "MinMaxLengthType with min_length 1 should be error when payload is empty"
        );
    }

    #[test]
    fn test_string_value_exceeds_bit_length_with_matching_physical_type() {
        // 8-bit UInt32: only values 0–255 should be valid
        let uint32_8bit = create_diag_coded_type_stl(DataType::UInt32, Some(8));
        let u32_physical_type = Some(PhysicalType {
            precision: None,
            base_type: DataType::UInt32,
            display_radix: None,
        });

        // Numeric JSON value 99999 is correctly rejected (bit-length check fires)
        let json_numeric = serde_json::json!(99999);
        assert!(
            super::json_value_to_uds_data(&uint32_8bit, None, None, &json_numeric).is_err(),
            "Numeric 99999 should be rejected for 8-bit UInt32"
        );

        // String "99999" with matching physical type should also be rejected,
        // but currently is not because process_physical_type_value returns early
        // without bit-length validation.
        let json_string = serde_json::json!("99999");
        assert!(
            super::json_value_to_uds_data(&uint32_8bit, None, u32_physical_type, &json_string)
                .is_err(),
            "String '99999' should be rejected for 8-bit UInt32, but bit-length validation is \
             skipped"
        );
    }
}
