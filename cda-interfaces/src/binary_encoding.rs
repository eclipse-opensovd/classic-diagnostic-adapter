/*
 * SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation
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

//! Textual representation of binary data (e.g. `ByteField` parameters) in
//! SOVD JSON requests and responses.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumString};

use crate::{
    DiagServiceError,
    util::{decode_hex, try_strip_hex_prefix},
};

/// Encoding used to represent binary data as JSON strings.
///
/// [[ dimpl~sovd-api-binary-encoding-type, Base64 and hex encoding of binary data ]]
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
    Display,
    EnumString,
)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase", ascii_case_insensitive)]
pub enum BinaryEncoding {
    /// Standard base64 (RFC 4648, with padding), as required by the SOVD standard.
    #[default]
    Base64,
    /// Space separated, `0x` prefixed upper case hex bytes, e.g. `"0x01 0xAB"`.
    Hex,
}

impl BinaryEncoding {
    /// All supported encodings.
    pub const ALL: [BinaryEncoding; 2] = [BinaryEncoding::Base64, BinaryEncoding::Hex];

    /// JSON schema `format` of string values in this encoding.
    #[must_use]
    pub fn json_schema_format(self) -> &'static str {
        match self {
            BinaryEncoding::Base64 => "byte",
            BinaryEncoding::Hex => "hex",
        }
    }

    /// Encode `data` into its string representation.
    #[must_use]
    pub fn encode(self, data: &[u8]) -> String {
        match self {
            BinaryEncoding::Base64 => base64::engine::general_purpose::STANDARD.encode(data),
            BinaryEncoding::Hex => data
                .iter()
                .map(|b| format!("{b:#04X}"))
                .collect::<Vec<_>>()
                .join(" "),
        }
    }

    /// Decode a string representation into bytes.
    ///
    /// Base64 is decoded leniently: the standard (`+/`) and the URL safe (`-_`)
    /// alphabet are accepted, padding is optional.
    ///
    /// Hex accepts tokens separated by spaces or commas, each with an optional
    /// `0x` prefix (e.g. `"0x01 0x02"`, `"0102"`, `"01,02"`).
    /// # Errors
    /// Returns `DiagServiceError::ParameterConversionError` if `value` is not
    /// valid in the selected encoding.
    pub fn decode(self, value: &str) -> Result<Vec<u8>, DiagServiceError> {
        match self {
            BinaryEncoding::Base64 => decode_base64_lenient(value),
            BinaryEncoding::Hex => decode_hex_with_optional_prefix(value),
        }
    }
}

/// Base64 engine with the standard alphabet that accepts input with or without padding.
const LENIENT_BASE64: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    base64::engine::GeneralPurposeConfig::new()
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
);

/// Decode base64 in the standard or URL safe alphabet, with or without padding.
fn decode_base64_lenient(value: &str) -> Result<Vec<u8>, DiagServiceError> {
    // Map the URL safe alphabet onto the standard one, both are otherwise identical.
    let normalized: String = value
        .trim()
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    LENIENT_BASE64.decode(normalized).map_err(|e| {
        DiagServiceError::ParameterConversionError(format!(
            "Invalid base64 value (standard or URL safe alphabet, padding optional), error={e}"
        ))
    })
}

/// Decode hex tokens separated by spaces or commas, each with an optional `0x` prefix.
/// # Errors
/// Returns `DiagServiceError::ParameterConversionError` on invalid hex input.
pub fn decode_hex_with_optional_prefix(value: &str) -> Result<Vec<u8>, DiagServiceError> {
    value
        .split([' ', ','])
        .filter(|v: &&str| !v.is_empty())
        .map(|value| decode_hex(try_strip_hex_prefix(value).unwrap_or(value)))
        .collect::<Result<Vec<_>, _>>()
        .map(|vecs| vecs.into_iter().flatten().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_is_base64() {
        assert_eq!(BinaryEncoding::default(), BinaryEncoding::Base64);
    }

    #[test]
    fn test_encode() {
        let data = [0x01, 0xAB, 0xFF];
        assert_eq!(BinaryEncoding::Base64.encode(&data), "Aav/");
        assert_eq!(BinaryEncoding::Base64.encode(&[0x01, 0x02]), "AQI=");
        assert_eq!(BinaryEncoding::Hex.encode(&data), "0x01 0xAB 0xFF");
        assert_eq!(BinaryEncoding::Base64.encode(&[]), "");
        assert_eq!(BinaryEncoding::Hex.encode(&[]), "");
    }

    /// [[ test~sovd-api-binary-encoding-codec, Round trip of all byte values in base64 and hex, test ]]
    #[test]
    fn test_round_trip() {
        let data: Vec<u8> = (0..=255).collect();
        for enc in [BinaryEncoding::Base64, BinaryEncoding::Hex] {
            assert_eq!(enc.decode(&enc.encode(&data)).unwrap(), data);
        }
    }

    #[test]
    fn test_decode_invalid() {
        assert!(BinaryEncoding::Base64.decode("not base64!").is_err());
        assert!(BinaryEncoding::Base64.decode("A").is_err());
        assert!(BinaryEncoding::Hex.decode("0xZZ").is_err());
    }

    #[test]
    fn test_decode_base64_lenient() {
        // Padded and unpadded
        for v in ["AQI=", "AQI", " AQI= "] {
            assert_eq!(BinaryEncoding::Base64.decode(v).unwrap(), vec![0x01, 0x02]);
        }
        // Standard and URL safe alphabet
        for v in ["+/8=", "-_8=", "-_8"] {
            assert_eq!(BinaryEncoding::Base64.decode(v).unwrap(), vec![0xFB, 0xFF]);
        }
    }

    #[test]
    fn test_decode_hex_variants() {
        for v in ["0x01 0x02", "0102", "01,02", "0X01, 0X02"] {
            assert_eq!(BinaryEncoding::Hex.decode(v).unwrap(), vec![0x01, 0x02]);
        }
    }

    #[test]
    fn test_from_str_and_serde() {
        assert_eq!("HEX".parse::<BinaryEncoding>(), Ok(BinaryEncoding::Hex));
        assert_eq!(
            "base64".parse::<BinaryEncoding>(),
            Ok(BinaryEncoding::Base64)
        );
        assert!("foo".parse::<BinaryEncoding>().is_err());
        assert_eq!(
            serde_json::from_str::<BinaryEncoding>("\"hex\"").unwrap(),
            BinaryEncoding::Hex
        );
        assert_eq!(
            serde_json::to_string(&BinaryEncoding::Base64).unwrap(),
            "\"base64\""
        );
    }
}
