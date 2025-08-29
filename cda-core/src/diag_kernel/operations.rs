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

use cda_database::datatypes::{self, CompuMethod, CompuScale, DataType};
use cda_interfaces::{
    DataParseError, DiagServiceError, STRINGS,
    util::{decode_hex, tracing::print_hex},
};

use crate::diag_kernel::{
    DiagDataValue,
    diagservices::{DiagDataTypeContainer, DiagDataTypeContainerRaw},
    iso_14229_nrc,
    payload::Payload,
};

pub(in crate::diag_kernel) fn uds_data_to_serializable(
    diag_type: DataType,
    compu_method: Option<&CompuMethod>,
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
    compu_method: &CompuMethod,
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
                if scale.rational_coefficients.is_some()
                    && scale
                        .rational_coefficients
                        .as_ref()
                        .unwrap()
                        .numerator
                        .len()
                        == 2
                    && scale
                        .rational_coefficients
                        .as_ref()
                        .unwrap()
                        .denominator
                        .is_empty()
                {
                    let coeffs = scale.rational_coefficients.as_ref().unwrap();
                    let lookup_val: f64 = lookup.try_into()?;
                    let val = coeffs.numerator[0] + lookup_val * coeffs.numerator[1];
                    DiagDataValue::from_number(val, diag_type)
                } else {
                    Ok(lookup)
                }
            }
            datatypes::CompuCategory::ScaleLinear => {
                if scale.rational_coefficients.is_none()
                    || scale
                        .rational_coefficients
                        .as_ref()
                        .unwrap()
                        .numerator
                        .len()
                        != 1
                    || scale
                        .rational_coefficients
                        .as_ref()
                        .unwrap()
                        .denominator
                        .len()
                        != 1
                {
                    return Err(DiagServiceError::UdsLookupError(
                        "Invalid SCALE_LINEAR CoEffs".to_owned(),
                    ));
                }
                let coeffs = scale.rational_coefficients.as_ref().unwrap();
                let lookup_val: f64 = lookup.try_into()?;
                let val = lookup_val * coeffs.numerator[0] / coeffs.denominator[0];
                DiagDataValue::from_number(val, diag_type)
            }
            datatypes::CompuCategory::TextTable => {
                let consts = scale.consts.as_ref().ok_or_else(|| {
                    DiagServiceError::InvalidDatabase("TextTable lookup has no Consts".to_owned())
                })?;
                let mapped_value = consts
                    .vt
                    .or(consts.vt_ti)
                    .and_then(|v| STRINGS.get(v))
                    .ok_or_else(|| {
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

fn compu_convert(
    diag_type: DataType,
    compu_method: &CompuMethod,
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
                    fn calculate<T>(input: f64, scale: &CompuScale) -> Result<f64, DiagServiceError>
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
                        .and_then(|consts| consts.vt.or(consts.vt_ti))
                        .and_then(|text| STRINGS.get(text))
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
    compu_method: Option<&CompuMethod>,
) -> Result<DiagDataTypeContainer, DiagServiceError> {
    let byte_pos = param.byte_pos as usize;
    let uds_payload = payload.data();
    let (data, bit_len) = diag_type.decode(uds_payload, byte_pos, param.bit_pos as usize)?;

    let data_type = diag_type.base_datatype();
    payload.set_last_read_byte_pos(byte_pos + data.len());

    Ok(DiagDataTypeContainer::RawContainer(
        DiagDataTypeContainerRaw {
            data,
            bit_len,
            data_type,
            compu_method: compu_method.cloned(),
        },
    ))
}

pub(in crate::diag_kernel) fn json_value_to_uds_data(
    diag_type: DataType,
    compu_method: Option<&CompuMethod>,
    json_value: &serde_json::Value,
) -> Result<Vec<u8>, DiagServiceError> {
    'compu: {
        if let Some(compu_method) = compu_method {
            match compu_method.category {
                datatypes::CompuCategory::Identical => break 'compu,
                category => {
                    return compu_convert(diag_type, compu_method, category, json_value);
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
                        .parse::<u8>()
                        .map(|v| v.to_be_bytes().to_vec())
                        .map_err(|_| {
                            DiagServiceError::ParameterConversionError(
                                "Invalid value type for ByteField".to_owned(),
                            )
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

        Ok((value as i32).to_be_bytes().to_vec())
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
            DataType::Float32 => json_value
                .as_f64()
                .ok_or(DiagServiceError::ParameterConversionError(
                    "Invalid value for Float32".to_owned(),
                ))
                .map(|v| (v as f32).to_be_bytes().to_vec()),
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
    fn test_invalid_byte_value() {
        let json_value = serde_json::json!("256");
        let result = super::json_value_to_uds_data(DataType::ByteField, None, &json_value);
        assert!(result.is_err());
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
                vt: Some(cda_interfaces::STRINGS.get_or_insert("TestValue")),
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
}
