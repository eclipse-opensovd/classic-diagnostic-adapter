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

use std::fmt::Debug;

use cda_database::datatypes::{DataType, IntervalType, Limit};
use cda_interfaces::{DiagServiceError, Protocol, STRINGS};
use hashbrown::HashMap;
use serde::{Serialize, Serializer};

pub(crate) mod diagservices;
pub(crate) mod ecumanager;
mod iso_14229_nrc;
mod operations;
mod payload;
mod schema;
mod variant_detection;

#[derive(Debug)]
pub enum DiagDataValue {
    Int32(i32),
    UInt32(u32),
    Float32(f32),
    String(String),
    ByteField(Vec<u8>),
    Float64(f64),
    Struct(HashMap<String, DiagDataValue>),
    RepeatingStruct(Vec<HashMap<String, DiagDataValue>>),
}

impl DiagDataValue {
    fn new(diag_type: DataType, data: &[u8]) -> Result<Self, DiagServiceError> {
        match diag_type {
            DataType::Int32 | DataType::UInt32 | DataType::Float32 => {
                let bytes = cda_interfaces::util::u32_padded_bytes(data)?;
                match diag_type {
                    DataType::Int32 => Ok(DiagDataValue::Int32(i32::from_be_bytes(bytes))),
                    DataType::UInt32 => Ok(DiagDataValue::UInt32(u32::from_be_bytes(bytes))),
                    DataType::Float32 => Ok(DiagDataValue::Float32(f32::from_be_bytes(bytes))),
                    _ => unreachable!(),
                }
            }
            DataType::AsciiString | DataType::Utf8String | DataType::Unicode2String => {
                let outval = if diag_type == DataType::AsciiString {
                    data.iter().map(|&b| b as char).collect::<String>()
                } else {
                    String::from_utf8(data.to_vec())
                        .map_err(|e| DiagServiceError::ParameterConversionError(e.to_string()))?
                };
                Ok(DiagDataValue::String(outval))
            }
            DataType::ByteField => Ok(DiagDataValue::ByteField(data.to_vec())),
            DataType::Float64 => {
                let bytes = cda_interfaces::util::f64_padded_bytes(data)?;
                Ok(DiagDataValue::Float64(f64::from_be_bytes(bytes)))
            }
        }
    }

    fn from_number<T: num_traits::ToPrimitive + num_traits::ToBytes + ToString + Debug>(
        value: T,
        diag_type: DataType,
    ) -> Result<Self, DiagServiceError> {
        match diag_type {
            DataType::Int32 => value.to_i32().map(DiagDataValue::Int32),
            DataType::UInt32 => value.to_u32().map(DiagDataValue::UInt32),
            DataType::Float32 => value.to_f32().map(DiagDataValue::Float32),
            DataType::Float64 => value.to_f64().map(DiagDataValue::Float64),
            DataType::ByteField => Some(DiagDataValue::ByteField(
                value.to_be_bytes().as_ref().to_vec(),
            )),
            DataType::AsciiString | DataType::Utf8String | DataType::Unicode2String => {
                Some(DiagDataValue::String(value.to_string()))
            }
        }
        .ok_or_else(|| {
            DiagServiceError::ParameterConversionError(format!(
                "Failed to convert number {value:?} to DiagDataValue"
            ))
        })
    }

    fn within_limits(&self, upper: Option<&Limit>, lower: Option<&Limit>) -> bool {
        fn check_numeric_limits<T>(value: &T, upper: Option<&Limit>, lower: Option<&Limit>) -> bool
        where
            T: PartialOrd,
            for<'a> &'a Limit: TryInto<T>,
        {
            let upper_ok = upper.is_none_or(|u| {
                u.try_into().is_ok_and(|u_val| {
                    if u.interval_type == IntervalType::Open {
                        value < &u_val
                    } else {
                        value <= &u_val
                    }
                })
            });
            let lower_ok = lower.is_none_or(|l| {
                l.try_into().is_ok_and(|l_val| {
                    if l.interval_type == IntervalType::Open {
                        value > &l_val
                    } else {
                        value >= &l_val
                    }
                })
            });
            upper_ok && lower_ok
        }

        fn pad_bytes_to_max_len(bytes: &[u8], target_len: usize) -> Vec<u8> {
            let mut padded = vec![0u8; target_len - bytes.len()];
            padded.extend_from_slice(bytes);
            padded
        }

        match self {
            DiagDataValue::Int32(v) => check_numeric_limits(v, upper, lower),
            DiagDataValue::UInt32(v) => check_numeric_limits(v, upper, lower),
            DiagDataValue::Float32(v) => check_numeric_limits(v, upper, lower),
            DiagDataValue::Float64(v) => check_numeric_limits(v, upper, lower),
            DiagDataValue::ByteField(v) => {
                let upper_bytes =
                    upper.and_then(|u| <&Limit as TryInto<Vec<u8>>>::try_into(u).ok());
                let lower_bytes =
                    lower.and_then(|l| <&Limit as TryInto<Vec<u8>>>::try_into(l).ok());

                // Determine max length for padding
                let max_len = [
                    v.len(),
                    upper_bytes.as_ref().map_or(0, |u| u.len()),
                    lower_bytes.as_ref().map_or(0, |l| l.len()),
                ]
                .into_iter()
                .max()
                .unwrap_or(0);

                let padded_v = pad_bytes_to_max_len(v, max_len);

                // Check upper limit
                let upper_ok = upper_bytes.is_none_or(|u| {
                    let padded_u = pad_bytes_to_max_len(&u, max_len);
                    padded_v <= padded_u
                });

                // Check lower limit
                let lower_ok = lower_bytes.is_none_or(|l| {
                    let padded_l = pad_bytes_to_max_len(&l, max_len);
                    padded_v >= padded_l
                });

                upper_ok && lower_ok
            }
            DiagDataValue::String(v) => {
                // In accordance with the ODX spec, string limits are only checked
                // for equality.
                let upper_ok = upper.is_none_or(|u| &u.value == v);
                let lower_ok = lower.is_none_or(|l| &l.value == v);
                upper_ok && lower_ok
            }
            _ => false,
        }
    }
}

impl TryInto<f64> for DiagDataValue {
    type Error = DiagServiceError;

    fn try_into(self) -> Result<f64, Self::Error> {
        match self {
            DiagDataValue::Int32(i) => Ok(f64::from(i)),
            DiagDataValue::UInt32(i) => Ok(f64::from(i)),
            DiagDataValue::Float32(f) => Ok(f64::from(f)),
            DiagDataValue::Float64(f) => Ok(f),
            _ => Err(DiagServiceError::ParameterConversionError(
                "Cannot convert DiagDataValue to f64".to_owned(),
            )),
        }
    }
}

impl TryInto<u32> for DiagDataValue {
    type Error = DiagServiceError;

    fn try_into(self) -> Result<u32, Self::Error> {
        match self {
            DiagDataValue::Int32(i) => i.try_into().map_err(|_| {
                DiagServiceError::ParameterConversionError(
                    "Int32 value out of u32 range".to_owned(),
                )
            }),
            DiagDataValue::UInt32(i) => Ok(i),
            DiagDataValue::Float32(f) => {
                if f < 0.0 || f > (u32::MAX as f32) {
                    return Err(DiagServiceError::ParameterConversionError(
                        "Float32 value out of u32 range".to_owned(),
                    ));
                }
                Ok(f as u32)
            }
            DiagDataValue::Float64(f) => {
                if f < 0.0 || f > (u32::MAX as f64) {
                    return Err(DiagServiceError::ParameterConversionError(
                        "Float64 value out of u32 range".to_owned(),
                    ));
                }
                Ok(f as u32)
            }
            _ => Err(DiagServiceError::ParameterConversionError(
                "Cannot convert DiagDataValue to u32".to_owned(),
            )),
        }
    }
}

#[derive(Clone)]
pub struct Variant {
    pub name: String,
    pub(crate) id: u32,
}

#[must_use]
pub fn into_db_protocol(val: Protocol) -> cda_database::datatypes::Protocol {
    cda_database::datatypes::Protocol {
        short_name: STRINGS.get_or_insert(val.value()),
    }
}

impl Serialize for DiagDataValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            DiagDataValue::Int32(v) => v.serialize(serializer),
            DiagDataValue::UInt32(v) => v.serialize(serializer),
            DiagDataValue::Float32(v) => v.serialize(serializer),
            DiagDataValue::String(v) => v.serialize(serializer),
            DiagDataValue::ByteField(v) => {
                let byte_string = v
                    .iter()
                    .map(|&b| format!("{b:#04X}"))
                    .collect::<Vec<String>>()
                    .join(" ");
                byte_string.serialize(serializer)
            }
            DiagDataValue::Float64(v) => v.serialize(serializer),
            DiagDataValue::Struct(v) => v.serialize(serializer),
            DiagDataValue::RepeatingStruct(v) => v.serialize(serializer),
        }
    }
}

#[cfg(test)]
mod tests {
    use cda_database::datatypes::IntervalType;

    use super::*;

    #[test]
    fn test_int32_within_limits() {
        let value = DiagDataValue::Int32(50);
        let upper = Limit {
            value: "100".to_string(),
            interval_type: IntervalType::Closed,
        };
        let lower = Limit {
            value: "0".to_string(),
            interval_type: IntervalType::Closed,
        };

        assert!(value.within_limits(Some(&upper), Some(&lower)));

        let value_out_of_range = DiagDataValue::Int32(150);
        assert!(!value_out_of_range.within_limits(Some(&upper), Some(&lower)));

        let value_below_range = DiagDataValue::Int32(-10);
        assert!(!value_below_range.within_limits(Some(&upper), Some(&lower)));
    }

    #[test]
    fn test_optional_limits() {
        let value = DiagDataValue::Int32(50);
        let upper = Limit {
            value: "100".to_string(),
            interval_type: IntervalType::Closed,
        };
        let lower = Limit {
            value: "0".to_string(),
            interval_type: IntervalType::Closed,
        };

        // Test with no upper limit
        assert!(value.within_limits(None, Some(&lower)));

        // Test with no lower limit
        assert!(value.within_limits(Some(&upper), None));

        // Test with no limits at all
        assert!(value.within_limits(None, None));

        // Test value that would be out of range with upper limit
        let high_value = DiagDataValue::Int32(150);
        assert!(high_value.within_limits(None, Some(&lower)));
        assert!(!high_value.within_limits(Some(&upper), None));
    }

    #[test]
    fn test_uint32_within_limits() {
        let value = DiagDataValue::UInt32(50);
        let upper = Limit {
            value: "100".to_string(),
            interval_type: IntervalType::Closed,
        };
        let lower = Limit {
            value: "0".to_string(),
            interval_type: IntervalType::Closed,
        };

        assert!(value.within_limits(Some(&upper), Some(&lower)));

        let value_out_of_range = DiagDataValue::UInt32(150);
        assert!(!value_out_of_range.within_limits(Some(&upper), Some(&lower)));
    }

    #[test]
    fn test_float32_within_limits() {
        let value = DiagDataValue::Float32(50.5);
        let upper = Limit {
            value: "100.0".to_string(),
            interval_type: IntervalType::Closed,
        };
        let lower = Limit {
            value: "0.0".to_string(),
            interval_type: IntervalType::Closed,
        };

        assert!(value.within_limits(Some(&upper), Some(&lower)));

        let value_out_of_range = DiagDataValue::Float32(150.5);
        assert!(!value_out_of_range.within_limits(Some(&upper), Some(&lower)));
    }

    #[test]
    fn test_float64_within_limits() {
        let value = DiagDataValue::Float64(50.5);
        let upper = Limit {
            value: "100.0".to_string(),
            interval_type: IntervalType::Closed,
        };
        let lower = Limit {
            value: "0.0".to_string(),
            interval_type: IntervalType::Closed,
        };

        assert!(value.within_limits(Some(&upper), Some(&lower)));

        let value_out_of_range = DiagDataValue::Float64(150.5);
        assert!(!value_out_of_range.within_limits(Some(&upper), Some(&lower)));
    }

    #[test]
    fn test_bytefield_within_limits() {
        // Test equal length byte arrays
        let value = DiagDataValue::ByteField(vec![0x01, 0x50]);
        let upper = Limit {
            value: "0x02 0x00".to_string(),
            interval_type: IntervalType::Closed,
        };
        let lower = Limit {
            value: "0x01 0x00".to_string(),
            interval_type: IntervalType::Closed,
        };

        assert!(value.within_limits(Some(&upper), Some(&lower)));

        // Test value out of range
        let value = DiagDataValue::ByteField(vec![0x02, 0x00]);
        let upper = Limit {
            value: "0x01 0xFF".to_string(),
            interval_type: IntervalType::Closed,
        };
        let lower = Limit {
            value: "0x01 0x00".to_string(),
            interval_type: IntervalType::Closed,
        };

        assert!(!value.within_limits(Some(&upper), Some(&lower)));
    }

    #[test]
    fn test_bytefield_optional_limits() {
        let value = DiagDataValue::ByteField(vec![0x01, 0x50]);
        let upper = Limit {
            value: "0x02 0x00".to_string(),
            interval_type: IntervalType::Closed,
        };
        let lower = Limit {
            value: "0x01 0x00".to_string(),
            interval_type: IntervalType::Closed,
        };

        // Test with no upper limit
        assert!(value.within_limits(None, Some(&lower)));

        // Test with no lower limit
        assert!(value.within_limits(Some(&upper), None));

        // Test with no limits
        assert!(value.within_limits(None, None));
    }

    #[test]
    fn test_bytefield_padding() {
        // Test that shorter arrays are properly padded with leading zeros
        let value = DiagDataValue::ByteField(vec![0x42]);
        let upper = Limit {
            value: "0xff".to_string(),
            interval_type: IntervalType::Closed,
        };
        let lower = Limit {
            value: "0x00 0x10".to_string(),
            interval_type: IntervalType::Closed,
        };

        assert!(value.within_limits(Some(&upper), Some(&lower)));
    }

    #[test]
    fn test_invalid_limits() {
        let value = DiagDataValue::Int32(50);
        let invalid_upper = Limit {
            value: "invalid".to_string(),
            interval_type: IntervalType::Closed,
        };
        let lower = Limit {
            value: "0".to_string(),
            interval_type: IntervalType::Closed,
        };

        assert!(!value.within_limits(Some(&invalid_upper), Some(&lower)));

        let upper = Limit {
            value: "100".to_string(),
            interval_type: IntervalType::Closed,
        };
        let invalid_lower = Limit {
            value: "invalid".to_string(),
            interval_type: IntervalType::Closed,
        };

        assert!(!value.within_limits(Some(&upper), Some(&invalid_lower)));
    }

    #[test]
    fn test_string_within_limits() {
        let value = DiagDataValue::String("test".to_string());
        let upper = Limit {
            value: "test".to_string(),
            interval_type: IntervalType::Closed,
        };
        let lower = Limit {
            value: "test".to_string(),
            interval_type: IntervalType::Closed,
        };

        assert!(value.within_limits(Some(&upper), Some(&lower)));
        assert!(value.within_limits(None, Some(&lower)));
        assert!(value.within_limits(Some(&upper), None));

        let value = DiagDataValue::String("test_not_within".to_string());
        assert!(!value.within_limits(Some(&upper), Some(&lower)));
        assert!(!value.within_limits(None, Some(&lower)));
        assert!(!value.within_limits(Some(&upper), None));
    }

    #[test]
    fn test_non_supported_types() {
        // repeating structs are not supported
        let upper = Limit {
            value: "100".to_string(),
            interval_type: IntervalType::Closed,
        };
        let lower = Limit {
            value: "0".to_string(),
            interval_type: IntervalType::Closed,
        };
        assert!(
            !DiagDataValue::RepeatingStruct(vec![HashMap::new()])
                .within_limits(Some(&upper), Some(&lower))
        );
        assert!(!DiagDataValue::Struct(HashMap::new()).within_limits(Some(&upper), Some(&lower)));
    }

    #[test]
    fn test_boundary_values() {
        // Test exact boundary values
        let value = DiagDataValue::Int32(100);
        let upper = Limit {
            value: "100".to_string(),
            interval_type: IntervalType::Closed,
        };
        let lower = Limit {
            value: "0".to_string(),
            interval_type: IntervalType::Closed,
        };

        assert!(value.within_limits(Some(&upper), Some(&lower)));

        let value = DiagDataValue::Int32(0);
        assert!(value.within_limits(Some(&upper), Some(&lower)));
    }

    #[test]
    fn test_open_intervals() {
        let value = DiagDataValue::Int32(50);
        let upper_open = Limit {
            value: "100".to_string(),
            interval_type: IntervalType::Open,
        };
        let lower_open = Limit {
            value: "0".to_string(),
            interval_type: IntervalType::Open,
        };

        // Value should be within open interval (0, 100)
        assert!(value.within_limits(Some(&upper_open), Some(&lower_open)));

        // Test boundary values - should be excluded in open intervals
        let boundary_upper = DiagDataValue::Int32(100);
        assert!(!boundary_upper.within_limits(Some(&upper_open), Some(&lower_open)));

        let boundary_lower = DiagDataValue::Int32(0);
        assert!(!boundary_lower.within_limits(Some(&upper_open), Some(&lower_open)));

        // Test mixed open/closed intervals
        let upper_closed = Limit {
            value: "100".to_string(),
            interval_type: IntervalType::Closed,
        };
        let boundary_value = DiagDataValue::Int32(100);
        assert!(boundary_value.within_limits(Some(&upper_closed), Some(&lower_open)));
        assert!(!boundary_value.within_limits(Some(&upper_open), Some(&lower_open)));
    }

    #[test]
    fn test_mixed_interval_types() {
        let value = DiagDataValue::Int32(50);

        // Open upper, closed lower
        let upper_open = Limit {
            value: "100".to_string(),
            interval_type: IntervalType::Open,
        };
        let lower_closed = Limit {
            value: "50".to_string(),
            interval_type: IntervalType::Closed,
        };

        assert!(value.within_limits(Some(&upper_open), Some(&lower_closed)));

        // Closed upper, open lower
        let upper_closed = Limit {
            value: "50".to_string(),
            interval_type: IntervalType::Closed,
        };
        let lower_open = Limit {
            value: "0".to_string(),
            interval_type: IntervalType::Open,
        };

        assert!(value.within_limits(Some(&upper_closed), Some(&lower_open)));

        // Test boundary behavior with mixed types
        let boundary_value = DiagDataValue::Int32(50);
        assert!(boundary_value.within_limits(Some(&upper_closed), Some(&lower_open)));
        assert!(boundary_value.within_limits(Some(&upper_open), Some(&lower_closed)));
    }
}
