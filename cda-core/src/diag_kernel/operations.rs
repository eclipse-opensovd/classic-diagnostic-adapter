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

use cda_database::datatypes::{self, DataType};
use cda_interfaces::{
    DataParseError, DiagServiceError,
    util::{decode_hex, tracing::print_hex},
};

use crate::diag_kernel::{
    DiagDataValue,
    diagservices::{DiagDataTypeContainer, DiagDataTypeContainerRaw},
    iso_14229_nrc,
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

enum ConversionDirection {
    PhysToInternal,
    InternalToPhys,
}

/// Apply rational linear formula bidirectionally per ODX spec (ISO 22901-1)
/// Used by both LINEAR (Figure 79) and SCALE-LINEAR (Figure 80) COMPU-METHODs.
///
/// - Forward (internal->physical): f(x) = (V0 + V1*x) / D
/// - Inverse (physical->internal): x = (D*f(x) - V0) / V1
///
/// ODX Constraints:
/// - Numerator must have exactly 2 values: [V0=offset, V1=factor]
/// - Denominator must have 0 or 1 value (defaults to 1.0)
/// - When V1=0 (constant function), inverse conversion requires COMPU-INVERSE-VALUE
fn apply_rational_linear_formula(
    rational_coefficients: &datatypes::CompuRationalCoefficients,
    value: f64,
    direction: ConversionDirection,
) -> Result<f64, DiagServiceError> {
    // Validate numerator: must have exactly 2 values [V0, V1]
    if rational_coefficients.numerator.len() != 2 {
        return Err(DiagServiceError::InvalidDatabase(format!(
            "Expected 2 numerators (offset, factor), got {}",
            rational_coefficients.numerator.len()
        )));
    }

    // Validate denominator: must have 0 or 1 value
    if rational_coefficients.denominator.len() > 1 {
        return Err(DiagServiceError::InvalidDatabase(format!(
            "Expected 0 or 1 denominator, got {}",
            rational_coefficients.denominator.len()
        )));
    }

    // Extract coefficients
    let v0 = rational_coefficients.numerator[0]; // offset
    let v1 = rational_coefficients.numerator[1]; // factor
    let d = rational_coefficients
        .denominator
        .first()
        .copied()
        .unwrap_or(1.0);

    match direction {
        ConversionDirection::PhysToInternal => {
            // Inverse: x = (D*f(x) - V0) / V1
            // Per ODX spec: when V1=0 (constant), COMPU-INVERSE-VALUE must be used instead
            if v1 == 0.0 {
                return Err(DiagServiceError::InvalidDatabase(
                    "Factor (V1) cannot be zero for inverse conversion. Use COMPU-INVERSE-VALUE \
                     for constant functions"
                        .to_owned(),
                ));
            }
            Ok((d * value - v0) / v1)
        }
        ConversionDirection::InternalToPhys => {
            // Forward: f(x) = (V0 + V1*x) / D
            if d == 0.0 {
                return Err(DiagServiceError::InvalidDatabase(
                    "Denominator cannot be zero".to_owned(),
                ));
            }
            Ok((v0 + v1 * value) / d)
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
                // Per ODX Figure 79: LINEAR category must have exactly one COMPU-SCALE
                if compu_method.internal_to_phys.scales.len() != 1 {
                    return Err(DiagServiceError::InvalidDatabase(format!(
                        "LINEAR: Expected exactly 1 COMPU-SCALE, got {}",
                        compu_method.internal_to_phys.scales.len()
                    )));
                }

                let rational_coefficients = scale.rational_coefficients.as_ref().ok_or(
                    DiagServiceError::InvalidDatabase(
                        "LINEAR: Missing rational coefficients".to_owned(),
                    ),
                )?;

                let lookup_val: f64 = lookup.try_into()?;
                let val = apply_rational_linear_formula(
                    rational_coefficients,
                    lookup_val,
                    ConversionDirection::InternalToPhys,
                )?;
                DiagDataValue::from_number(&val, diag_type)
            }
            datatypes::CompuCategory::ScaleLinear => {
                let rational_coefficients = scale.rational_coefficients.as_ref().ok_or(
                    DiagServiceError::InvalidDatabase(
                        "SCALE-LINEAR: Missing rational coefficients".to_owned(),
                    ),
                )?;

                let lookup_val: f64 = lookup.try_into()?;
                let val = apply_rational_linear_formula(
                    rational_coefficients,
                    lookup_val,
                    ConversionDirection::InternalToPhys,
                )?;
                DiagDataValue::from_number(&val, diag_type)
            }
            datatypes::CompuCategory::TextTable => {
                let consts = scale.consts.as_ref().ok_or_else(|| {
                    DiagServiceError::InvalidDatabase("TextTable lookup has no Consts".to_owned())
                })?;
                let mapped_value = consts.vt.clone().or(consts.vt_ti.clone()).ok_or_else(|| {
                    DiagServiceError::UdsLookupError("failed to read compu value".to_owned())
                })?;
                Ok(DiagDataValue::String(mapped_value))
            }
            _ => {
                todo!()
            }
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

/// Helper function to parse a JSON value (number or string) into f64
fn parse_json_to_f64(value: &serde_json::Value) -> Result<f64, DiagServiceError> {
    if value.is_number() {
        value.as_f64().ok_or_else(|| {
            DiagServiceError::ParameterConversionError(
                "Failed to get compu value as f64".to_owned(),
            )
        })
    } else if value.is_string() {
        let trimmed = value
            .as_str()
            .ok_or_else(|| {
                DiagServiceError::ParameterConversionError(
                    "Empty value is not allowed for compu value".to_owned(),
                )
            })?
            .trim_matches('"');
        trimmed.parse::<f64>().map_err(|_| {
            DiagServiceError::ParameterConversionError("Failed to parse string as f64".to_string())
        })
    } else {
        Err(DiagServiceError::ParameterConversionError(
            "Value is not a number or string".to_owned(),
        ))
    }
}

/// Helper function to convert an internal value to bytes based on data type
// #[allow(clippy::cast_possible_truncation)]
// #[allow(clippy::cast_sign_loss)]
fn internal_value_to_bytes(
    internal_value: f64,
    diag_type: datatypes::DataType,
) -> Result<Vec<u8>, DiagServiceError> {
    match diag_type {
        DataType::Int32 => Ok((internal_value as i32).to_be_bytes().to_vec()),
        DataType::UInt32 => Ok((internal_value as u32).to_be_bytes().to_vec()),
        DataType::Float32 => Ok((internal_value as f32).to_be_bytes().to_vec()),
        DataType::Float64 => Ok(internal_value.to_be_bytes().to_vec()),
        _ => Err(DiagServiceError::InvalidDatabase(
            "Database only supports Int32, UInt32, Float32 and Float64 for linear scaling"
                .to_owned(),
        )),
    }
}

// Casting and truncating is defined in the ISO instead of rounding
#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::cast_sign_loss)]
fn compu_convert(
    diag_type: datatypes::DataType,
    compu_method: &datatypes::CompuMethod,
    category: datatypes::CompuCategory,
    value: &serde_json::Value,
) -> Result<Vec<u8>, DiagServiceError> {
    match category {
        datatypes::CompuCategory::Identical => todo!(),
        datatypes::CompuCategory::Linear => {
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
                    DiagServiceError::UdsLookupError(
                        "Failed to find scales for linear scaling".to_owned(),
                    )
                })?;

            let physical_value = parse_json_to_f64(value)?;
            let coeffs = scale.rational_coefficients.as_ref().ok_or_else(|| {
                DiagServiceError::UdsLookupError("LINEAR: Missing rational coefficients".to_owned())
            })?;

            let internal_value = apply_rational_linear_formula(
                coeffs,
                physical_value,
                ConversionDirection::PhysToInternal,
            )?;
            internal_value_to_bytes(internal_value, diag_type)
        }
        datatypes::CompuCategory::ScaleLinear => {
            // ScaleLinear allows multiple scales with different ranges
            // We need to find the matching scale based on the input values limits
            let physical_value = parse_json_to_f64(value)?;

            // Find the appropriate scale for the physical value
            // For phys to internal, we need to compute the physical range from internal limits
            let scale = compu_method
                .internal_to_phys
                .scales
                .iter()
                .find(|scale| {
                    let coeffs = match scale.rational_coefficients.as_ref() {
                        Some(c) => c,
                        None => return false,
                    };

                    // Compute physical range by transforming internal limits
                    let phys_lower = scale.lower_limit.as_ref().and_then(|l| {
                        let internal_val: f64 = l.try_into().ok()?;
                        apply_rational_linear_formula(
                            coeffs,
                            internal_val,
                            ConversionDirection::InternalToPhys,
                        )
                        .ok()
                    });
                    let phys_upper = scale.upper_limit.as_ref().and_then(|u| {
                        let internal_val: f64 = u.try_into().ok()?;
                        apply_rational_linear_formula(
                            coeffs,
                            internal_val,
                            ConversionDirection::InternalToPhys,
                        )
                        .ok()
                    });

                    // Check if physical value falls within computed physical range
                    let within_lower = phys_lower.map_or(true, |l| {
                        // Handle interval type for lower limit
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
                    let within_upper = phys_upper.map_or(true, |u| {
                        // Handle interval type for upper limit
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
                DiagServiceError::UdsLookupError(
                    "SCALE-LINEAR: Missing rational coefficients".to_owned(),
                )
            })?;

            let internal_value = apply_rational_linear_formula(
                coeffs,
                physical_value,
                ConversionDirection::PhysToInternal,
            )?;
            internal_value_to_bytes(internal_value, diag_type)
        }
        datatypes::CompuCategory::TextTable => {
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
                    _ => unreachable!(),
                };
            }
            Err(DiagServiceError::UdsLookupError(
                "Failed to find matching TextTable value".to_owned(),
            ))
        }
        datatypes::CompuCategory::CompuCode => todo!(),
        datatypes::CompuCategory::TabIntp => todo!(),
        datatypes::CompuCategory::RatFunc => todo!(),
        datatypes::CompuCategory::ScaleRatFunc => todo!(),
    }
}

pub(in crate::diag_kernel) fn extract_diag_data_container(
    param: &datatypes::Parameter,
    payload: &mut Payload,
    diag_type: &datatypes::DiagCodedType,
    compu_method: Option<datatypes::CompuMethod>,
) -> Result<DiagDataTypeContainer, DiagServiceError> {
    let byte_pos = param.byte_position() as usize;
    let uds_payload = payload.data()?;
    let (data, bit_len) = diag_type.decode(uds_payload, byte_pos, param.bit_position() as usize)?;

    let data_type = diag_type.base_datatype();
    payload.set_last_read_byte_pos(byte_pos.saturating_add(data.len()));

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
    diag_type: datatypes::DataType,
    compu_method: Option<datatypes::CompuMethod>,
    json_value: &serde_json::Value,
) -> Result<Vec<u8>, DiagServiceError> {
    'compu: {
        if let Some(compu_method) = compu_method {
            match compu_method.category {
                datatypes::CompuCategory::Identical => break 'compu,
                category => {
                    return compu_convert(diag_type, &compu_method, category, json_value);
                }
            }
        }
    }

    match diag_type {
        DataType::Int32
        | DataType::UInt32
        | DataType::Float32
        | DataType::Float64
        | DataType::ByteField => json_value_to_byte_vector(json_value, diag_type),
        DataType::AsciiString | DataType::Unicode2String | DataType::Utf8String => json_value
            .as_str()
            .ok_or(DiagServiceError::ParameterConversionError(
                "Invalid value for AsciiString".to_owned(),
            ))
            .map(|s| s.as_bytes().to_vec()),
    }
}

// truncating values and sign loss is expected when converting float values into a vec<u8>
#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::cast_sign_loss)]
pub(in crate::diag_kernel) fn string_to_vec_u8(
    data_type: DataType,
    value: &str,
) -> Result<Vec<u8>, DiagServiceError> {
    value
        .split_whitespace()
        .map(|value| {
            if value.chars().all(char::is_numeric) {
                match data_type {
                    DataType::ByteField => value
                        .parse::<u64>()
                        .map_err(|_| {
                            DiagServiceError::ParameterConversionError(
                                "Invalid value type for ByteField, failed to parse to u64"
                                    .to_owned(),
                            )
                        })
                        .and_then(|v| {
                            let bytes = v.to_be_bytes();
                            // Find the first non-zero byte, or keep at least one byte
                            let start = bytes
                                .iter()
                                .position(|&b| b != 0)
                                .unwrap_or(bytes.len().saturating_sub(1));
                            bytes
                                .get(start..)
                                .ok_or(DiagServiceError::ParameterConversionError(
                                    "Byte slice out of bounds".to_owned(),
                                ))
                                .map(<[u8]>::to_vec)
                        }),
                    DataType::Int32 => value
                        .parse::<i32>()
                        .map(|v| v.to_be_bytes().to_vec())
                        .map_err(|_| {
                            DiagServiceError::ParameterConversionError(
                                "Invalid value type for i32".to_owned(),
                            )
                        }),
                    DataType::UInt32 => value
                        .parse::<u32>()
                        .map(|v| v.to_be_bytes().to_vec())
                        .map_err(|_| {
                            DiagServiceError::ParameterConversionError(
                                "Invalid value type for u32".to_owned(),
                            )
                        }),
                    DataType::Float32 => value
                        .parse::<f32>()
                        .map(|v| v.to_be_bytes().to_vec())
                        .map_err(|_| {
                            DiagServiceError::ParameterConversionError(
                                "Invalid value type for f32".to_owned(),
                            )
                        }),
                    DataType::Float64 => value
                        .parse::<f64>()
                        .map(|v| v.to_be_bytes().to_vec())
                        .map_err(|_| {
                            DiagServiceError::ParameterConversionError(
                                "Invalid value type for f64".to_owned(),
                            )
                        }),
                    _ => Err(DiagServiceError::ParameterConversionError(
                        "Invalid data type for value extraction".to_owned(),
                    )),
                }
            } else if value.contains('.') {
                let float_value = value.parse::<f64>().map_err(|e| {
                    DiagServiceError::ParameterConversionError(format!(
                        "Invalid value for float, error={e}"
                    ))
                })?;

                match data_type {
                    DataType::ByteField => Ok((float_value as u8).to_be_bytes().to_vec()),
                    DataType::Int32 => Ok((float_value as i32).to_be_bytes().to_vec()),
                    DataType::UInt32 => Ok((float_value as u32).to_be_bytes().to_vec()),
                    DataType::Float32 => Ok((float_value as f32).to_be_bytes().to_vec()),
                    DataType::Float64 => Ok(float_value.to_be_bytes().to_vec()),
                    _ => Err(DiagServiceError::ParameterConversionError(
                        "Invalid data type for float".to_owned(),
                    )),
                }
            } else if let Some(stripped) = value.to_lowercase().strip_prefix("0x") {
                decode_hex(stripped)
            } else {
                decode_hex(value)
            }
        })
        .collect::<Result<Vec<_>, DiagServiceError>>()
        .map(|vecs| vecs.into_iter().flatten().collect())
}

fn json_value_to_byte_vector(
    json_value: &serde_json::Value,
    data_type: DataType,
) -> Result<Vec<u8>, DiagServiceError> {
    fn convert_integer_to_bytes<T>(
        json_value: &serde_json::Value,
        min: T,
        max: T,
        data_type: DataType,
    ) -> Result<Vec<u8>, DiagServiceError>
    where
        T: Into<i64> + Copy,
        i64: From<T>,
    {
        let value = json_value
            .as_i64()
            .ok_or(DiagServiceError::ParameterConversionError(format!(
                "Invalid value for {data_type:?}"
            )))?;

        if value < i64::from(min) || value > i64::from(max) {
            return Err(DiagServiceError::ParameterConversionError(format!(
                "Value out of range for {data_type:?}"
            )));
        }

        Ok(i32::try_from(value)
            .map_err(|e| {
                DiagServiceError::ParameterConversionError(format!("Failed to convert to i32 {e}"))
            })?
            .to_be_bytes()
            .to_vec())
    }

    let data: Result<Vec<u8>, DiagServiceError> = if json_value.is_string() {
        let s = json_value
            .as_str()
            .ok_or(DiagServiceError::ParameterConversionError(
                "Invalid numeric value".to_owned(),
            ))?;

        string_to_vec_u8(data_type, s)
    } else if json_value.is_number() {
        match data_type {
            DataType::Int32 => convert_integer_to_bytes(json_value, i32::MIN, i32::MAX, data_type),
            DataType::UInt32 => convert_integer_to_bytes(
                json_value,
                i64::from(u32::MIN),
                i64::from(u32::MAX),
                data_type,
            ),
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
    } else {
        Err(DiagServiceError::ParameterConversionError(format!(
            "Invalid JSON value {json_value:?} for data type {data_type:?}"
        )))
    };

    if let Ok(data) = data.as_ref() {
        match data_type {
            DataType::Int32 | DataType::UInt32 | DataType::Float32 => {
                if data.len() > 4 {
                    return Err(DiagServiceError::ParameterConversionError(format!(
                        "Invalid data length for {data_type:?}: {}, value {json_value}",
                        data.len()
                    )));
                }
            }
            DataType::Float64 => {
                if data.len() > 8 {
                    return Err(DiagServiceError::ParameterConversionError(format!(
                        "Invalid data length for {data_type:?}: {}, value {json_value}",
                        data.len()
                    )));
                }
            }
            _ => {}
        }
    }
    data
}

#[cfg(test)]
mod tests {
    use cda_database::datatypes::{
        CompuCategory, CompuFunction, CompuMethod, CompuRationalCoefficients, CompuScale,
        CompuValues, DataType, IntervalType, Limit,
    };

    #[test]
    fn test_hex_values() {
        let json_value = serde_json::json!("0x11223344");
        let result = super::json_value_to_uds_data(DataType::ByteField, None, &json_value);
        assert_eq!(result, Ok(vec![0x11, 0x22, 0x33, 0x44]));
    }

    #[test]
    fn test_integer_out_of_range() {
        let json_value = serde_json::json!(i64::MAX);
        assert!(super::json_value_to_uds_data(DataType::Int32, None, &json_value).is_err());
        assert!(super::json_value_to_uds_data(DataType::UInt32, None, &json_value).is_err());
    }

    #[test]
    fn test_hex_values_odd() {
        let json_value = serde_json::json!("0x1 0x2");

        let expected = Ok(vec![0x1, 0x2]);
        assert_eq!(
            super::json_value_to_uds_data(DataType::ByteField, None, &json_value),
            expected
        );
        assert_eq!(
            super::json_value_to_uds_data(DataType::Float64, None, &json_value),
            expected
        );
        assert_eq!(
            super::json_value_to_uds_data(DataType::Float32, None, &json_value),
            expected
        );
        assert_eq!(
            super::json_value_to_uds_data(DataType::Int32, None, &json_value),
            expected
        );
        assert_eq!(
            super::json_value_to_uds_data(DataType::UInt32, None, &json_value),
            expected
        );
    }

    #[test]
    fn test_space_separated_hex_values() {
        let json_value = serde_json::json!("0x00 0x01 0x80 0x00");
        let expected = Ok(vec![0x00, 0x01, 0x80, 0x00]);
        assert_eq!(
            super::json_value_to_uds_data(DataType::ByteField, None, &json_value),
            expected
        );
        assert_eq!(
            super::json_value_to_uds_data(DataType::Float64, None, &json_value),
            expected
        );
        assert_eq!(
            super::json_value_to_uds_data(DataType::Float32, None, &json_value),
            expected
        );
        assert_eq!(
            super::json_value_to_uds_data(DataType::Int32, None, &json_value),
            expected
        );
        assert_eq!(
            super::json_value_to_uds_data(DataType::UInt32, None, &json_value),
            expected
        );
    }

    #[test]
    fn test_mixed_values() {
        let json_value = serde_json::json!("ff 0a 128 deadbeef ca7");
        let result = super::json_value_to_uds_data(DataType::ByteField, None, &json_value);
        assert_eq!(
            result,
            Ok(vec![255, 10, 128, 0xde, 0xad, 0xbe, 0xef, 0xca, 0x07])
        );
    }

    #[test]
    fn test_hex_long() {
        let json_value = serde_json::json!("c0ffeca7");
        let result = super::json_value_to_uds_data(DataType::ByteField, None, &json_value);
        assert_eq!(result, Ok(vec![0xc0, 0xff, 0xec, 0xa7]));
    }

    #[test]
    fn test_invalid_hex_value() {
        let json_value = serde_json::json!("0xZZ");
        let result = super::json_value_to_uds_data(DataType::ByteField, None, &json_value);
        assert!(result.is_err());
    }

    #[test]
    fn test_long_byte_value() {
        let json_value = serde_json::json!("256");
        let result = super::json_value_to_uds_data(DataType::ByteField, None, &json_value);
        assert_eq!(result, Ok(vec![0x01, 0x00]));
    }

    #[test]
    fn test_float_string() {
        let json_value = serde_json::json!("10.42");

        let int_result = Ok(vec![0x00, 0x00, 0x00, 0x0a]);
        assert_eq!(
            super::json_value_to_uds_data(DataType::Int32, None, &json_value),
            int_result
        );
        assert_eq!(
            super::json_value_to_uds_data(DataType::UInt32, None, &json_value),
            int_result
        );
        assert_eq!(
            super::json_value_to_uds_data(DataType::ByteField, None, &json_value),
            Ok(vec![0x0a])
        );

        assert_eq!(
            super::json_value_to_uds_data(DataType::Float32, None, &json_value),
            Ok(vec![65, 38, 184, 82])
        );
        assert_eq!(
            super::json_value_to_uds_data(DataType::Float64, None, &json_value),
            Ok(vec![64, 36, 215, 10, 61, 112, 163, 215])
        );
    }

    #[test]
    fn test_float() {
        let json_value = serde_json::json!(10.42);

        assert!(super::json_value_to_uds_data(DataType::Int32, None, &json_value).is_err());
        assert!(super::json_value_to_uds_data(DataType::UInt32, None, &json_value).is_err());
        assert!(super::json_value_to_uds_data(DataType::ByteField, None, &json_value).is_err());

        assert_eq!(
            super::json_value_to_uds_data(DataType::Float32, None, &json_value),
            Ok(vec![65, 38, 184, 82])
        );
        assert_eq!(
            super::json_value_to_uds_data(DataType::Float64, None, &json_value),
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
                }],
            },
        };

        let value = serde_json::json!("42");
        let result = super::compu_convert(
            DataType::Int32,
            &compu_method,
            CompuCategory::Linear,
            &value,
        );
        assert_eq!(result.unwrap(), 42_i32.to_be_bytes().to_vec());

        let value = serde_json::json!("42.42");
        let result = super::compu_convert(
            DataType::Float32,
            &compu_method,
            CompuCategory::Linear,
            &value,
        );
        assert_eq!(result.unwrap(), 42.42_f32.to_be_bytes().to_vec());

        let value = serde_json::json!("42.4242");
        let result = super::compu_convert(
            DataType::Float64,
            &compu_method,
            CompuCategory::Linear,
            &value,
        );
        assert_eq!(result.unwrap(), 42.4242_f64.to_be_bytes().to_vec());

        let value = serde_json::json!(42);
        let result = super::compu_convert(
            DataType::Float64,
            &compu_method,
            CompuCategory::Linear,
            &value,
        );
        assert_eq!(result.unwrap(), 42_f64.to_be_bytes().to_vec());

        let value = serde_json::json!(42);
        let result = super::compu_convert(
            DataType::Int32,
            &compu_method,
            CompuCategory::Linear,
            &value,
        );
        assert_eq!(result.unwrap(), 42_i32.to_be_bytes().to_vec());
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
                }],
            },
        };

        // f(x) = (offset + factor * x) / denominator
        // Forward (internal->physical): f(42) = (1.23 + 2 * 42)/0.5 = 170.46
        // Inverse (physical->internal): given physical 170, internal = (0.5*170 - 1.23)/2 = 41.885
        let value = serde_json::json!(170);
        let result = super::compu_convert(
            DataType::Int32,
            &compu_method,
            CompuCategory::Linear,
            &value,
        );
        assert_eq!(result.unwrap(), 41_i32.to_be_bytes().to_vec());

        let value = serde_json::json!(170.46);
        let result = super::compu_convert(
            DataType::Float32,
            &compu_method,
            CompuCategory::Linear,
            &value,
        );
        assert_eq!(result.unwrap(), 42.0_f32.to_be_bytes().to_vec());
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
        };

        let compu_method = CompuMethod {
            category: CompuCategory::TextTable,
            internal_to_phys: CompuFunction {
                scales: vec![scale],
            },
        };

        let value = serde_json::json!("TestValue");
        let result = super::compu_convert(
            DataType::Int32,
            &compu_method,
            CompuCategory::TextTable,
            &value,
        );
        assert_eq!(result.unwrap(), 42_i32.to_be_bytes().to_vec());

        let value = serde_json::json!("NotFound");
        let result = super::compu_convert(
            DataType::Int32,
            &compu_method,
            CompuCategory::TextTable,
            &value,
        );
        assert!(result.is_err());
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
                    },
                ],
            },
        };

        let data = 3_u32.to_be_bytes();
        let result =
            super::uds_data_to_serializable(DataType::UInt32, Some(&compu_method), false, &data);
        // Should fail because LINEAR has 2 scales instead of 1
        assert!(result.is_err());
        if let Err(e) = result {
            let error_msg = format!("{:?}", e);
            assert!(error_msg.contains("Expected exactly 1 COMPU-SCALE"));
        }
    }

    #[test]
    fn test_compu_lookup_linear_zero_scales_error() {
        // LINEAR must have exactly one COMPU-SCALE, not zero
        let compu_method = CompuMethod {
            category: CompuCategory::Linear,
            internal_to_phys: CompuFunction {
                scales: vec![], // Empty scales
            },
        };

        let data = 3_u32.to_be_bytes();
        let result =
            super::uds_data_to_serializable(DataType::UInt32, Some(&compu_method), false, &data);
        // Should fail because value doesn't match any scale (no scales exist)
        assert!(result.is_err());
    }

    #[test]
    fn test_compu_lookup_scale_linear_piecewise_function() {
        // ISO 22901-1:2008 Figure 80 example: f(x) = { 1+2x, x∈[0,2), 3+x, x∈[2,5), 8, x∈[5,∞) }
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
                    },
                    // Third interval: [5, ∞) -> f(x) = 8 (constant)
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
                            interval_type: IntervalType::Infinite, // ∞)
                        }),
                    },
                ],
            },
        };

        // First interval: [0, 2) -> f(x) = 1 + 2x
        // Forward: x=0 -> y=1
        let data = 0_u32.to_be_bytes();
        let result =
            super::uds_data_to_serializable(DataType::UInt32, Some(&compu_method), false, &data);
        assert!(result.is_ok());
        let value: f64 = result.unwrap().try_into().unwrap();
        assert_eq!(value, 1.0);

        // Inverse: y=1 -> x=0
        let value = serde_json::json!(1.0);
        let result = super::compu_convert(
            DataType::Float64,
            &compu_method,
            CompuCategory::ScaleLinear,
            &value,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0.0_f64.to_be_bytes().to_vec());

        // Forward: x=1 -> y=3
        let data = 1_u32.to_be_bytes();
        let result =
            super::uds_data_to_serializable(DataType::UInt32, Some(&compu_method), false, &data);
        assert!(result.is_ok());
        let value: f64 = result.unwrap().try_into().unwrap();
        assert_eq!(value, 3.0);

        // Inverse: y=3 -> x=1
        let value = serde_json::json!(3.0);
        let result = super::compu_convert(
            DataType::Float64,
            &compu_method,
            CompuCategory::ScaleLinear,
            &value,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1.0_f64.to_be_bytes().to_vec());

        // Forward: x=1.5 -> y=4
        let data = 1.5_f32.to_be_bytes();
        let result =
            super::uds_data_to_serializable(DataType::Float32, Some(&compu_method), false, &data);
        assert!(result.is_ok());
        let value: f64 = result.unwrap().try_into().unwrap();
        assert_eq!(value, 4.0);

        // Inverse: y=4 -> x=1.5
        let value = serde_json::json!(4.0);
        let result = super::compu_convert(
            DataType::Float64,
            &compu_method,
            CompuCategory::ScaleLinear,
            &value,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1.5_f64.to_be_bytes().to_vec());

        // Second interval: [2, 5) -> f(x) = 3 + x
        // Forward: x=2 -> y=5 (boundary, CLOSED at 2)
        let data = 2_u32.to_be_bytes();
        let result =
            super::uds_data_to_serializable(DataType::UInt32, Some(&compu_method), false, &data);
        assert!(result.is_ok());
        let value: f64 = result.unwrap().try_into().unwrap();
        assert_eq!(value, 5.0);

        // Inverse: y=5 -> x=2
        let value = serde_json::json!(5.0);
        let result = super::compu_convert(
            DataType::Float64,
            &compu_method,
            CompuCategory::ScaleLinear,
            &value,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 2.0_f64.to_be_bytes().to_vec());

        // Forward: x=3 -> y=6
        let data = 3_u32.to_be_bytes();
        let result =
            super::uds_data_to_serializable(DataType::UInt32, Some(&compu_method), false, &data);
        assert!(result.is_ok());
        let value: f64 = result.unwrap().try_into().unwrap();
        assert_eq!(value, 6.0);

        // Inverse: y=6 -> x=3
        let value = serde_json::json!(6.0);
        let result = super::compu_convert(
            DataType::Float64,
            &compu_method,
            CompuCategory::ScaleLinear,
            &value,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 3.0_f64.to_be_bytes().to_vec());

        // Forward: x=4 -> y=7
        let data = 4_u32.to_be_bytes();
        let result =
            super::uds_data_to_serializable(DataType::UInt32, Some(&compu_method), false, &data);
        assert!(result.is_ok());
        let value: f64 = result.unwrap().try_into().unwrap();
        assert_eq!(value, 7.0);

        // Inverse: y=7 -> x=4
        let value = serde_json::json!(7.0);
        let result = super::compu_convert(
            DataType::Float64,
            &compu_method,
            CompuCategory::ScaleLinear,
            &value,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 4.0_f64.to_be_bytes().to_vec());

        // Third interval: [5, ∞) -> f(x) = 8 (constant)
        // Forward: x=5 -> y=8 (boundary)
        let data = 5_u32.to_be_bytes();
        let result =
            super::uds_data_to_serializable(DataType::UInt32, Some(&compu_method), false, &data);
        assert!(result.is_ok());
        let value: f64 = result.unwrap().try_into().unwrap();
        assert_eq!(value, 8.0);

        // Forward: x=10 -> y=8 (constant)
        let data = 10_u32.to_be_bytes();
        let result =
            super::uds_data_to_serializable(DataType::UInt32, Some(&compu_method), false, &data);
        assert!(result.is_ok());
        let value: f64 = result.unwrap().try_into().unwrap();
        assert_eq!(value, 8.0);

        // Forward: x=100 -> y=8 (constant)
        let data = 100_u32.to_be_bytes();
        let result =
            super::uds_data_to_serializable(DataType::UInt32, Some(&compu_method), false, &data);
        assert!(result.is_ok());
        let value: f64 = result.unwrap().try_into().unwrap();
        assert_eq!(value, 8.0);

        // Inverse: y=8 should fail (constant function with V1=0 cannot be inverted)
        let value = serde_json::json!(8.0);
        let result = super::compu_convert(
            DataType::Float64,
            &compu_method,
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
    fn test_compu_lookup_scale_linear_with_different_denominators() {
        // SCALE-LINEAR with different denominators per interval
        // f(x) = { (2+4x)/2, x∈[0,5), (50+10x)/5, x∈[5,10] }
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
                    },
                ],
            },
        };

        // First interval: x=2, f(2) = (2 + 4*2) / 2 = 10 / 2 = 5
        let data = 2_u32.to_be_bytes();
        let result =
            super::uds_data_to_serializable(DataType::UInt32, Some(&compu_method), false, &data);
        assert!(result.is_ok());
        let value: f64 = result.unwrap().try_into().unwrap();
        assert_eq!(value, 5.0);

        // Second interval: x=6, f(6) = (50 + 10*6) / 5 = 110 / 5 = 22
        let data = 6_u32.to_be_bytes();
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
                }],
            },
        };

        // x=5 is outside [10, 20]
        let data = 5_u32.to_be_bytes();
        let result =
            super::uds_data_to_serializable(DataType::UInt32, Some(&compu_method), false, &data);
        assert!(result.is_err());

        // x=25 is outside [10, 20]
        let data = 25_u32.to_be_bytes();
        let result =
            super::uds_data_to_serializable(DataType::UInt32, Some(&compu_method), false, &data);
        assert!(result.is_err());
    }
}
