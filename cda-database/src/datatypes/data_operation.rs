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

//
use cda_interfaces::{DiagServiceError, util::decode_hex};
#[cfg(feature = "deepsize")]
use deepsize::DeepSizeOf;

use crate::proto::diagnostic_description::dataformat;

#[derive(Copy, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub enum IntervalType {
    Open,
    Closed,
    Infinite,
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct Limit {
    /// A limit can be a numeric type, a string or a byte field.
    /// Numeric types are compared numerically
    /// For strings only the equals operator is supported
    /// For byte fields comparison works like this:
    /// * Values are padded with 0x00 until they are the same length
    /// * Right most byte is least significant (Big endian order)
    /// * Read large unsigned int from the limit and the comparison target
    ///   and compare numerically.
    pub value: String,
    pub interval_type: IntervalType,
}

impl TryInto<u32> for &Limit {
    type Error = DiagServiceError;
    fn try_into(self) -> Result<u32, Self::Error> {
        let f: f64 = self.try_into()?;
        Ok(f as u32)
    }
}

impl TryInto<i32> for &Limit {
    type Error = DiagServiceError;
    fn try_into(self) -> Result<i32, Self::Error> {
        let f: f64 = self.try_into()?;
        Ok(f as i32)
    }
}

impl TryInto<f32> for &Limit {
    type Error = DiagServiceError;
    fn try_into(self) -> Result<f32, Self::Error> {
        if self.value.is_empty() {
            // treat empty string as 0
            return Ok(f32::default());
        }
        self.value.parse().map_err(|e| {
            DiagServiceError::ParameterConversionError(format!(
                "Cannot convert Limit with value {} into f32, {e:?}",
                self.value
            ))
        })
    }
}

impl TryInto<f64> for &Limit {
    type Error = DiagServiceError;
    fn try_into(self) -> Result<f64, Self::Error> {
        if self.value.is_empty() {
            // treat empty string as 0
            return Ok(f64::default());
        }
        self.value.parse().map_err(|e| {
            DiagServiceError::ParameterConversionError(format!(
                "Cannot convert Limit with value {} into f64, {e:?}",
                self.value
            ))
        })
    }
}

impl TryInto<Vec<u8>> for &Limit {
    type Error = DiagServiceError;
    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        self.value
            .split_whitespace()
            .map(|value| {
                if value.chars().all(|c| c.is_ascii_digit()) {
                    value
                        .parse::<u8>()
                        .map(|v| v.to_be_bytes().to_vec())
                        .map_err(|_| {
                            DiagServiceError::ParameterConversionError(
                                "Invalid value type for ByteField".to_owned(),
                            )
                        })
                } else if value.contains('.') {
                    let float_value = value.parse::<f64>().map_err(|e| {
                        DiagServiceError::ParameterConversionError(format!(
                            "Invalid value for float, error={e}"
                        ))
                    })?;
                    Ok((float_value as u8).to_be_bytes().to_vec())
                } else if let Some(stripped) = value.to_lowercase().strip_prefix("0x") {
                    decode_hex(stripped)
                } else {
                    decode_hex(value)
                }
            })
            .collect::<Result<Vec<_>, DiagServiceError>>()
            .map(|vecs| vecs.into_iter().flatten().collect())
    }
}

impl Into<Limit> for dataformat::Limit<'_> {
    fn into(self) -> Limit {
        Limit {
            value: self.value().unwrap_or_default().to_owned(),
            interval_type: self.interval_type().into(),
        }
    }
}

impl Into<IntervalType> for dataformat::IntervalType {
    fn into(self) -> IntervalType {
        match self {
            dataformat::IntervalType::OPEN => IntervalType::Open,
            dataformat::IntervalType::CLOSED => IntervalType::Closed,
            dataformat::IntervalType::INFINITE => IntervalType::Infinite,
            _ => IntervalType::Infinite,
        }
    }
}
