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
use cda_database::datatypes::{self, BitLength, DataType};
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
                let rational_coefficients = scale.rational_coefficients.as_ref().ok_or(
                    DiagServiceError::InvalidDatabase("Missing rational coefficients".to_owned()),
                )?;

                if rational_coefficients.numerator.len() == 2
                    && rational_coefficients.denominator.is_empty()
                {
                    let lookup_val: f64 = lookup.try_into()?;
                    let num0 = *rational_coefficients.numerator.first().ok_or(
                        DiagServiceError::InvalidDatabase("Missing numerator[0]".to_owned()),
                    )?;
                    let num1 = *rational_coefficients.numerator.get(1).ok_or(
                        DiagServiceError::InvalidDatabase("Missing numerator[1]".to_owned()),
                    )?;
                    let val = num0 + lookup_val * num1;
                    DiagDataValue::from_number(&val, diag_type)
                } else {
                    Err(DiagServiceError::InvalidDatabase(format!(
                        "Invalid linear coefficients expected 2 numerators and 0 denominators, \
                         got {} numerators and {} denominators",
                        rational_coefficients.numerator.len(),
                        rational_coefficients.denominator.len()
                    )))
                }
            }
            datatypes::CompuCategory::ScaleLinear => {
                let rational_coefficients = scale.rational_coefficients.as_ref().ok_or(
                    DiagServiceError::InvalidDatabase("Missing rational coefficients".to_owned()),
                )?;

                if rational_coefficients.numerator.len() != 1
                    || rational_coefficients.denominator.len() != 1
                {
                    return Err(DiagServiceError::UdsLookupError(
                        "Invalid SCALE_LINEAR CoEffs".to_owned(),
                    ));
                }

                let lookup_val: f64 = lookup.try_into()?;
                let num0 = *rational_coefficients.numerator.first().ok_or(
                    DiagServiceError::InvalidDatabase("Missing numerator[0]".to_owned()),
                )?;
                let denom0 = *rational_coefficients.denominator.first().ok_or(
                    DiagServiceError::InvalidDatabase("Missing denominator[0]".to_owned()),
                )?;
                let val = lookup_val * num0 / denom0;
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
            compu_method
                .internal_to_phys
                .scales
                .first()
                .map(|scale| {
                    fn calculate<T>(
                        input: f64,
                        scale: &datatypes::CompuScale,
                    ) -> Result<f64, DiagServiceError>
                    where
                        f64: From<T>,
                        T: std::str::FromStr,
                        T::Err: std::fmt::Debug,
                    {
                        let coeffs = scale.rational_coefficients.as_ref().ok_or_else(|| {
                            DiagServiceError::UdsLookupError(
                                "Rational coefficients not found".to_owned(),
                            )
                        })?;

                        let offset = coeffs.numerator.first().unwrap_or(&0.0);
                        let factor = coeffs.numerator.get(1).unwrap_or(&1.0);
                        let denominator = coeffs.denominator.first().unwrap_or(&1.0);

                        Ok((offset + factor * input) / denominator)
                    }

                    let value = if value.is_number() {
                        value.as_f64().ok_or_else(|| {
                            DiagServiceError::ParameterConversionError(
                                "Failed to get compu value as f64".to_owned(),
                            )
                        })?
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
                            DiagServiceError::ParameterConversionError(
                                "Failed to parse string as f64".to_string(),
                            )
                        })?
                    } else {
                        return Err(DiagServiceError::ParameterConversionError(
                            "Value is not a number or string".to_owned(),
                        ));
                    };

                    match diag_type {
                        DataType::Int32 => calculate::<i32>(value, scale)
                            .map(|r| (r as i32).to_be_bytes().to_vec()),
                        DataType::UInt32 => calculate::<u32>(value, scale)
                            .map(|r| (r as u32).to_be_bytes().to_vec()),
                        DataType::Float32 => calculate::<f32>(value, scale)
                            .map(|r| (r as f32).to_be_bytes().to_vec()),
                        DataType::Float64 => {
                            calculate::<f64>(value, scale).map(|r| r.to_be_bytes().to_vec())
                        }
                        _ => {
                            unreachable!(
                                "Database only support Int32, UInt32, Float32 and Float64 for \
                                 linear scaling"
                            );
                        }
                    }
                })
                .ok_or_else(|| {
                    DiagServiceError::UdsLookupError(
                        "Failed to find scales for linear scaling".to_owned(),
                    )
                })?
        }
        datatypes::CompuCategory::ScaleLinear => todo!(),
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
    if data.is_empty() {
        // at least 1 byte expected, we are using NotEnoughData error here, because
        // this might happen when parsing end of pdu and leftover bytes can be ignored
        return Err(DiagServiceError::NotEnoughData {
            expected: 1,
            actual: 0,
        });
    }

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
    diag_type: &datatypes::DiagCodedType,
    compu_method: Option<datatypes::CompuMethod>,
    json_value: &serde_json::Value,
) -> Result<Vec<u8>, DiagServiceError> {
    let base_type = diag_type.base_datatype();
    'compu: {
        if let Some(compu_method) = compu_method {
            match compu_method.category {
                datatypes::CompuCategory::Identical => break 'compu,
                category => {
                    return compu_convert(base_type, &compu_method, category, json_value);
                }
            }
        }
    }

    match base_type {
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
fn numeric_type_str_to_byte_vec(
    data_type: &datatypes::DiagCodedType,
    value: &str,
) -> Result<Vec<u8>, DiagServiceError> {
    let base_type = data_type.base_datatype();
    let bit_len = data_type.bit_len();
    // static assertation for hard type lengths are already made when DataType
    // `data_type` is constructed. This entails float and ascii length assertions,
    // therefore there is no need to check them again here.
    // Bit length validations are only done for types with actual variable bit lengths
    // (basically all integer types)
    value
        .split_whitespace()
        .map(|value| {
            if value.chars().all(char::is_numeric) {
                match base_type {
                    DataType::ByteField => value
                        .parse::<u64>()
                        .map_err(|_| {
                            DiagServiceError::ParameterConversionError(
                                "Invalid value type for ByteField, failed to parse to u64"
                                    .to_owned(),
                            )
                        })
                        .and_then(|v| {
                            if let Some(bit_len) = bit_len {
                                validate_bit_len_unsigned(v, bit_len)?;
                            }

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
                        .map_err(|_| {
                            DiagServiceError::ParameterConversionError(
                                "Invalid value type for i32".to_owned(),
                            )
                        })
                        .and_then(|v| {
                            if let Some(bit_len) = bit_len {
                                validate_bit_len_signed(v, bit_len)?;
                            }
                            Ok(v.to_be_bytes().to_vec())
                        }),
                    DataType::UInt32 => value
                        .parse::<u32>()
                        .map_err(|_| {
                            DiagServiceError::ParameterConversionError(
                                "Invalid value type for u32".to_owned(),
                            )
                        })
                        .and_then(|v| {
                            if let Some(bit_len) = bit_len {
                                validate_bit_len_unsigned(v, bit_len)?;
                            }
                            Ok(v.to_be_bytes().to_vec())
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

                match base_type {
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
    data_type: &datatypes::DiagCodedType,
) -> Result<Vec<u8>, DiagServiceError> {
    let base_type = data_type.base_datatype();
    let data: Result<Vec<u8>, DiagServiceError> = if json_value.is_string() {
        let s = json_value
            .as_str()
            .ok_or(DiagServiceError::ParameterConversionError(
                "Invalid numeric value".to_owned(),
            ))?;

        numeric_type_str_to_byte_vec(data_type, s)
    } else if json_value.is_number() {
        match base_type {
            DataType::Int32 => {
                let value =
                    json_value
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
                let value =
                    json_value
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
    } else {
        Err(DiagServiceError::ParameterConversionError(format!(
            "Invalid JSON value {json_value:?} for data type {data_type:?}"
        )))
    };

    if let Ok(data) = data.as_ref() {
        match base_type {
            DataType::Int32 | DataType::UInt32 | DataType::Float32 => {
                if data.len() > 4 {
                    return Err(DiagServiceError::ParameterConversionError(format!(
                        "Invalid data length {} for {base_type:?} value {json_value}",
                        data.len()
                    )));
                }
            }
            DataType::Float64 => {
                if data.len() > 8 {
                    return Err(DiagServiceError::ParameterConversionError(format!(
                        "Invalid data length for {base_type:?}: {}, value {json_value}",
                        data.len()
                    )));
                }
            }
            _ => {}
        }
    }
    data
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
        Limit, StandardLengthType,
    };

    /// Helper function to create a `DiagCodedType` for testing
    fn create_diag_coded_type(
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

    #[test]
    fn test_hex_values() {
        let json_value = serde_json::json!("0x11223344");
        let diag_type = create_diag_coded_type(DataType::ByteField, None);
        let result = super::json_value_to_uds_data(&diag_type, None, &json_value);
        assert_eq!(result, Ok(vec![0x11, 0x22, 0x33, 0x44]));
    }

    #[test]
    fn test_integer_out_of_range() {
        let json_value = serde_json::json!(i64::MAX);
        let int32_type = create_diag_coded_type(DataType::Int32, None);
        let uint32_type = create_diag_coded_type(DataType::UInt32, None);
        assert!(super::json_value_to_uds_data(&int32_type, None, &json_value).is_err());
        assert!(super::json_value_to_uds_data(&uint32_type, None, &json_value).is_err());
    }

    #[test]
    fn test_hex_values_odd() {
        let json_value = serde_json::json!("0x1 0x2");

        let bytefield_type = create_diag_coded_type(DataType::ByteField, None);
        let float64_type = create_diag_coded_type(DataType::Float64, None);
        let float32_type = create_diag_coded_type(DataType::Float32, None);
        let int32_type = create_diag_coded_type(DataType::Int32, None);
        let uint32_type = create_diag_coded_type(DataType::UInt32, None);

        let expected = Ok(vec![0x1, 0x2]);
        assert_eq!(
            super::json_value_to_uds_data(&bytefield_type, None, &json_value),
            expected
        );
        assert_eq!(
            super::json_value_to_uds_data(&float64_type, None, &json_value),
            expected
        );
        assert_eq!(
            super::json_value_to_uds_data(&float32_type, None, &json_value),
            expected
        );
        assert_eq!(
            super::json_value_to_uds_data(&int32_type, None, &json_value),
            expected
        );
        assert_eq!(
            super::json_value_to_uds_data(&uint32_type, None, &json_value),
            expected
        );
    }

    #[test]
    fn test_space_separated_hex_values() {
        let json_value = serde_json::json!("0x00 0x01 0x80 0x00");

        let bytefield_type = create_diag_coded_type(DataType::ByteField, None);
        let float64_type = create_diag_coded_type(DataType::Float64, None);
        let float32_type = create_diag_coded_type(DataType::Float32, None);
        let int32_type = create_diag_coded_type(DataType::Int32, None);
        let uint32_type = create_diag_coded_type(DataType::UInt32, None);

        let expected = Ok(vec![0x00, 0x01, 0x80, 0x00]);
        assert_eq!(
            super::json_value_to_uds_data(&bytefield_type, None, &json_value),
            expected
        );
        assert_eq!(
            super::json_value_to_uds_data(&float64_type, None, &json_value),
            expected
        );
        assert_eq!(
            super::json_value_to_uds_data(&float32_type, None, &json_value),
            expected
        );
        assert_eq!(
            super::json_value_to_uds_data(&int32_type, None, &json_value),
            expected
        );
        assert_eq!(
            super::json_value_to_uds_data(&uint32_type, None, &json_value),
            expected
        );
    }

    #[test]
    fn test_mixed_values() {
        let json_value = serde_json::json!("ff 0a 128 deadbeef ca7");
        let diag_type = create_diag_coded_type(DataType::ByteField, None);
        let result = super::json_value_to_uds_data(&diag_type, None, &json_value);
        assert_eq!(
            result,
            Ok(vec![255, 10, 128, 0xde, 0xad, 0xbe, 0xef, 0xca, 0x07])
        );
    }

    #[test]
    fn test_hex_long() {
        let json_value = serde_json::json!("c0ffeca7");
        let diag_type = create_diag_coded_type(DataType::ByteField, None);
        let result = super::json_value_to_uds_data(&diag_type, None, &json_value);
        assert_eq!(result, Ok(vec![0xc0, 0xff, 0xec, 0xa7]));
    }

    #[test]
    fn test_invalid_hex_value() {
        let json_value = serde_json::json!("0xZZ");
        let diag_type = create_diag_coded_type(DataType::ByteField, None);
        let result = super::json_value_to_uds_data(&diag_type, None, &json_value);
        assert!(result.is_err());
    }

    #[test]
    fn test_long_byte_value() {
        let json_value = serde_json::json!("256");
        let diag_type = create_diag_coded_type(DataType::ByteField, Some(9));
        let result = super::json_value_to_uds_data(&diag_type, None, &json_value);
        assert_eq!(result, Ok(vec![0x01, 0x00]));
    }

    #[test]
    fn test_float_string() {
        let json_value = serde_json::json!("10.42");

        let int32_type = create_diag_coded_type(DataType::Int32, None);
        let uint32_type = create_diag_coded_type(DataType::UInt32, None);
        let bytefield_type = create_diag_coded_type(DataType::ByteField, None);
        let float32_type = create_diag_coded_type(DataType::Float32, None);
        let float64_type = create_diag_coded_type(DataType::Float64, None);

        let int_result = Ok(vec![0x00, 0x00, 0x00, 0x0a]);
        assert_eq!(
            super::json_value_to_uds_data(&int32_type, None, &json_value),
            int_result
        );
        assert_eq!(
            super::json_value_to_uds_data(&uint32_type, None, &json_value),
            int_result
        );
        assert_eq!(
            super::json_value_to_uds_data(&bytefield_type, None, &json_value),
            Ok(vec![0x0a])
        );

        assert_eq!(
            super::json_value_to_uds_data(&float32_type, None, &json_value),
            Ok(vec![65, 38, 184, 82])
        );
        assert_eq!(
            super::json_value_to_uds_data(&float64_type, None, &json_value),
            Ok(vec![64, 36, 215, 10, 61, 112, 163, 215])
        );
    }

    #[test]
    fn test_float() {
        let json_value = serde_json::json!(10.42);

        let int32_type = create_diag_coded_type(DataType::Int32, None);
        let uint32_type = create_diag_coded_type(DataType::UInt32, None);
        let bytefield_type = create_diag_coded_type(DataType::ByteField, None);
        let float32_type = create_diag_coded_type(DataType::Float32, None);
        let float64_type = create_diag_coded_type(DataType::Float64, None);

        assert!(super::json_value_to_uds_data(&int32_type, None, &json_value).is_err());
        assert!(super::json_value_to_uds_data(&uint32_type, None, &json_value).is_err());
        assert!(super::json_value_to_uds_data(&bytefield_type, None, &json_value).is_err());

        assert_eq!(
            super::json_value_to_uds_data(&float32_type, None, &json_value),
            Ok(vec![65, 38, 184, 82])
        );
        assert_eq!(
            super::json_value_to_uds_data(&float64_type, None, &json_value),
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
        // so here: f(42) = (1.23 + 2 * 42)/0.5 = 170.46
        let value = serde_json::json!(42);
        let result = super::compu_convert(
            DataType::Int32,
            &compu_method,
            CompuCategory::Linear,
            &value,
        );
        assert_eq!(result.unwrap(), 170_i32.to_be_bytes().to_vec());

        let result = super::compu_convert(
            DataType::Float32,
            &compu_method,
            CompuCategory::Linear,
            &value,
        );
        assert_eq!(result.unwrap(), 170.46_f32.to_be_bytes().to_vec());
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
    fn test_numeric_type_str_to_byte_vec_invalid_bit_values() {
        // Test ByteField with 8-bit length - value 256 exceeds 8 bits
        let bytefield_8bit = DiagCodedType::new(
            DataType::ByteField,
            DiagCodedTypeVariant::StandardLength(StandardLengthType {
                bit_length: 8,
                bit_mask: None,
                condensed: false,
            }),
            true,
        )
        .unwrap();
        super::numeric_type_str_to_byte_vec(&bytefield_8bit, "256").unwrap_err();

        // Test UInt32 with 16-bit length - value 65536 exceeds 16 bits
        let uint32_16bit = DiagCodedType::new(
            DataType::UInt32,
            DiagCodedTypeVariant::StandardLength(StandardLengthType {
                bit_length: 16,
                bit_mask: None,
                condensed: false,
            }),
            true,
        )
        .unwrap();
        super::numeric_type_str_to_byte_vec(&uint32_16bit, "65536").unwrap_err();

        // Test Int32 with 8-bit length - value 128 exceeds signed 8-bit range (-128 to 127)
        let int32_8bit = DiagCodedType::new(
            DataType::Int32,
            DiagCodedTypeVariant::StandardLength(StandardLengthType {
                bit_length: 8,
                bit_mask: None,
                condensed: false,
            }),
            true,
        )
        .unwrap();
        super::numeric_type_str_to_byte_vec(&int32_8bit, "128").unwrap_err();
        super::numeric_type_str_to_byte_vec(&int32_8bit, "-129").unwrap_err();
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
}
