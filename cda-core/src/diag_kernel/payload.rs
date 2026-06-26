/*
 * SPDX-FileCopyrightText: 2025 Copyright (c) Contributors to the Eclipse Foundation
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

use std::collections::VecDeque;

use cda_database::datatypes;
use cda_interfaces::DiagServiceError;

pub(in crate::diag_kernel) struct Payload<'a> {
    data: &'a [u8],
    current_index: usize,
    slices: VecDeque<(usize, usize)>,
    last_read_byte_pos: usize,
    bytes_to_skip: usize,
}

impl<'a> Payload<'a> {
    pub(in crate::diag_kernel) fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            current_index: 0,
            slices: VecDeque::new(),
            last_read_byte_pos: 0,
            bytes_to_skip: 0,
        }
    }
    pub(in crate::diag_kernel) fn set_last_read_byte_pos(&mut self, pos: usize) {
        if pos > self.len() {
            self.last_read_byte_pos = self.len();
        } else {
            self.last_read_byte_pos = pos;
        }
    }

    pub(in crate::diag_kernel) fn set_bytes_to_skip(&mut self, count: usize) {
        self.bytes_to_skip = self.bytes_to_skip.saturating_add(count);
    }

    pub(in crate::diag_kernel) fn bytes_to_skip(&self) -> usize {
        self.bytes_to_skip
    }

    pub(in crate::diag_kernel) fn last_read_byte_pos(&self) -> usize {
        self.last_read_byte_pos
    }

    pub(in crate::diag_kernel) fn data(&self) -> Result<&[u8], DiagServiceError> {
        if let Some(&(start, end)) = self.slices.back() {
            self.data.get(start..end)
        } else {
            self.data.get(self.pos()..)
        }
        .ok_or(DiagServiceError::BadPayload(
            "Slice out of bounds".to_owned(),
        ))
    }

    pub(in crate::diag_kernel) fn pos(&self) -> usize {
        if let Some(&(start, _)) = self.slices.back() {
            start
        } else {
            self.current_index
        }
    }

    pub(in crate::diag_kernel) fn consume(&mut self) -> usize {
        let advance_len = self.last_read_byte_pos.saturating_add(self.bytes_to_skip);
        if self.pos().saturating_add(advance_len) > self.data.len() {
            self.current_index = self.data.len(); // Move to the end if we exceed
        } else {
            self.current_index = self.current_index.saturating_add(advance_len);
        }
        self.last_read_byte_pos = 0;
        self.bytes_to_skip = 0;
        advance_len
    }

    pub(in crate::diag_kernel) fn len(&self) -> usize {
        if let Some(&(start, end)) = self.slices.back() {
            end.saturating_sub(start)
        } else {
            self.data.len()
        }
    }

    pub(in crate::diag_kernel) fn exhausted(&self) -> bool {
        if let Some(&(_, end)) = self.slices.back() {
            self.current_index >= end
        } else {
            self.current_index >= self.data.len()
        }
    }

    pub(in crate::diag_kernel) fn first(&self) -> Option<&u8> {
        self.data.get(self.pos())
    }

    pub(in crate::diag_kernel) fn push_slice_to_abs_end(
        &mut self,
        start: usize,
    ) -> Result<(), DiagServiceError> {
        self.push_slice(start, self.len())
    }

    pub(in crate::diag_kernel) fn push_slice(
        &mut self,
        start: usize,
        end: usize,
    ) -> Result<(), DiagServiceError> {
        // when pushing a new slice, it's _relative_ to the last slice or the whole data if no slice
        let current_start = self.pos();
        let current_len = self.len();

        if start > end || end > current_len {
            return Err(DiagServiceError::BadPayload(
                "Invalid range for restricting view".to_owned(),
            ));
        }

        // Convert relative positions to absolute positions
        let absolute_start = current_start.saturating_add(start);
        let absolute_end = current_start.saturating_add(end).min(self.data.len());

        self.slices.push_back((absolute_start, absolute_end));
        Ok(())
    }

    pub(in crate::diag_kernel) fn pop_slice(&mut self) -> Result<(), DiagServiceError> {
        if self.slices.pop_back().is_none() {
            return Err(DiagServiceError::BadPayload(
                "No restricted view to pop".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Converts a `CODED-CONST` string value from the ODX database into a JSON value.
///
/// The input is the raw string stored in the ODX data, so it follows ODX value
/// coding rules (ISO 22901-1 §7.1.3): numeric values are decimal-coded. Per the
/// value-coding restrictions, `A_INT32`/`A_UINT32` (`Int32`/`UInt32`) "shall be
/// defined decimal", and floats follow XSD `float`/`double` (decimal, optional
/// `e`-notation). Radix prefixes such as `0x`, `0o`, or `0b` are therefore NOT
/// valid here and must not be parsed. Note that ODX `A_UINT32` may carry a
/// `DISPLAY-RADIX` (HEX/DEC/BIN/OCT), but that only governs visualization at the
/// tester, not the coding of the stored value, which stays decimal.
pub(in crate::diag_kernel) fn str_to_json_value(
    value: &str,
    data_type: datatypes::DataType,
) -> Result<serde_json::Value, DiagServiceError> {
    let json_value = match data_type {
        datatypes::DataType::Int32 => {
            let i32val = value.parse::<i32>().map_err(|e| {
                DiagServiceError::InvalidDatabase(format!(
                    "CodedConst value ({value}) conversion error: {e}"
                ))
            })?;
            serde_json::Number::from(i32val).into()
        }
        datatypes::DataType::UInt32 => {
            let u32val = value.parse::<u32>().map_err(|e| {
                DiagServiceError::InvalidDatabase(format!(
                    "CodedConst value ({value}) conversion error: {e}"
                ))
            })?;
            serde_json::Number::from(u32val).into()
        }
        datatypes::DataType::Float32 | datatypes::DataType::Float64 => {
            let f64val = value.parse::<f64>().map_err(|e| {
                DiagServiceError::InvalidDatabase(format!(
                    "CodedConst value ({value}) conversion error: {e}"
                ))
            })?;
            serde_json::Number::from_f64(f64val).into()
        }
        datatypes::DataType::AsciiString
        | datatypes::DataType::Utf8String
        | datatypes::DataType::Unicode2String
        | datatypes::DataType::ByteField => serde_json::Value::from(value),
    };
    Ok(json_value)
}

#[cfg(test)]
mod tests {
    use cda_database::datatypes::DataType;
    use serde_json::json;

    use super::*;

    #[test]
    fn test_payload_type() {
        let raw_payload = vec![
            0xA3, 0x4F, 0x9C, 0xD1, 0x7E, 0x2B, 0x88, 0x5A, 0xB4, 0x3D, 0xE7, 0x0F, 0x61, 0x92,
            0xBC, 0x47, 0x19, 0xFA, 0x33, 0x6D,
        ];
        let mut payload = super::Payload::new(&raw_payload);
        assert_eq!(payload.len(), 20);
        assert_eq!(payload.data().unwrap(), &raw_payload);

        assert!(payload.push_slice(0, 10).is_ok());
        assert_eq!(payload.data().unwrap(), raw_payload.get(0..10).unwrap());
        assert!(payload.push_slice(0, 10).is_ok()); // relative to previous slice (0..10)
        assert_eq!(payload.data().unwrap(), raw_payload.get(0..10).unwrap());
        assert!(payload.push_slice(0, 15).is_err()); // out of bounds of current slice

        assert!(payload.pop_slice().is_ok());
        assert!(payload.pop_slice().is_ok());

        payload.set_last_read_byte_pos(20);
        payload.consume();
        assert!(payload.exhausted()); // should be exhausted now
    }

    #[test]
    fn test_str_to_json_value_int32_success() {
        assert_eq!(str_to_json_value("42", DataType::Int32), Ok(json!(42)));
        assert_eq!(str_to_json_value("-1", DataType::Int32), Ok(json!(-1)));
    }

    #[test]
    fn test_str_to_json_value_int32_invalid() {
        assert!(str_to_json_value("abc", DataType::Int32).is_err());
        assert!(str_to_json_value("12.5", DataType::Int32).is_err());
    }

    #[test]
    fn test_str_to_json_value_uint32_success() {
        assert_eq!(str_to_json_value("42", DataType::UInt32), Ok(json!(42)));
    }

    #[test]
    fn test_str_to_json_value_uint32_invalid() {
        assert!(str_to_json_value("-1", DataType::UInt32).is_err());
        assert!(str_to_json_value("abc", DataType::UInt32).is_err());
    }

    #[test]
    fn test_str_to_json_value_float32() {
        assert_eq!(
            str_to_json_value("3.42", DataType::Float32),
            Ok(json!(3.42))
        );
        assert_eq!(str_to_json_value("42", DataType::Float32), Ok(json!(42.0)));
        assert!(str_to_json_value("abc", DataType::Float32).is_err());
    }

    #[test]
    fn test_str_to_json_value_float64() {
        assert_eq!(
            str_to_json_value("3.42", DataType::Float64),
            Ok(json!(3.42))
        );
    }

    #[test]
    fn test_str_to_json_value_string_types() {
        assert_eq!(
            str_to_json_value("hello", DataType::AsciiString),
            Ok(json!("hello"))
        );
        assert_eq!(
            str_to_json_value("hello", DataType::Utf8String),
            Ok(json!("hello"))
        );
        assert_eq!(
            str_to_json_value("hello", DataType::Unicode2String),
            Ok(json!("hello"))
        );
        assert_eq!(
            str_to_json_value("hello", DataType::ByteField),
            Ok(json!("hello"))
        );
    }
}
