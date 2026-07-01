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

//! Default parameter overrides loaded from a sibling `.defaults.toml`.
//!
//! The MDD only encodes `CodedConst` values explicitly; all other parameters
//! are zero by default. The defaults file lets an operator pin non-zero
//! initial values for known parameters (e.g. a synthetic VIN marker) without
//! having to push them through the REST API at startup.
//!
//! File format (TOML, top-level key `overrides` mapping `<service>` to
//! `<param>` to a value):
//!
//! ```toml
//! [overrides."VINDataIdentifier_Read".VIN]
//! value = "CDA-SIM-MARKER0000"   # ASCII bytes (padded with 0 to bit_length)
//! bytes = "AABBCC"               # alternative: hex-encoded raw bytes
//! value = 12.0                   # alternative: physical numeric
//! ```
//!
//! Values are applied at startup *after* variant-detection patterns, and only
//! when the (service, param) pair is not already in the override set (so
//! patterns win). Unknown service/param names log a warning and are skipped.

use std::{collections::HashMap, path::Path};

use serde::Deserialize;

use crate::{error::SimulatorError, mdd::ParameterValue, simulator::SimulatorState};

/// Per-parameter payload as written in the defaults file.
///
/// Only one of `value` or `bytes` may be set; if both are present, `bytes`
/// wins (deterministic raw-bit injection takes precedence over the
/// human-friendly physical value).
#[derive(Debug, Clone, Deserialize)]
pub struct DefaultValue {
    /// Physical numeric value, or ASCII string (when no `bytes` is set).
    /// Interpreted via the parameter's conversion if one exists.
    #[serde(default)]
    pub value: Option<toml::Value>,
    /// Hex-encoded raw bytes; takes precedence over `value` when present.
    #[serde(default)]
    pub bytes: Option<String>,
}

/// Top-level defaults-file shape: `overrides.<service>.<param> = DefaultValue`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DefaultOverridesFile {
    #[serde(default)]
    pub overrides: HashMap<String, HashMap<String, DefaultValue>>,
}

impl DefaultOverridesFile {
    /// Load and parse a defaults file from disk.
    ///
    /// # Errors
    /// Returns a `SimulatorError::Config` if the file cannot be read or
    /// parsed.
    pub fn load(path: &Path) -> Result<Self, SimulatorError> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            SimulatorError::Config(format!(
                "failed to read defaults file {}: {e}",
                path.display()
            ))
        })?;
        toml::from_str(&text).map_err(|e| {
            SimulatorError::Config(format!(
                "failed to parse defaults file {}: {e}",
                path.display()
            ))
        })
    }
}

/// Apply defaults to a `SimulatorState` after the variant-detection patterns.
///
/// Counts: (`applied`, `unknown_service`, `unknown_param`, `skipped`).
/// Unknown service/param names log a warning and are skipped - the defaults
/// file stays forward-compatible with new MDD revisions.
pub async fn apply_default_overrides(
    state: &SimulatorState,
    file: &DefaultOverridesFile,
) -> (usize, usize, usize, usize) {
    let mut applied = 0usize;
    let mut unknown_service = 0usize;
    let mut unknown_param = 0usize;
    let mut skipped = 0usize;

    for (service_name, params) in &file.overrides {
        let Some(service) = state.get_service_by_name(service_name) else {
            tracing::warn!(
                service = %service_name,
                "defaults file references unknown service; skipping"
            );
            unknown_service += params.len();
            continue;
        };

        for (param_name, default) in params {
            let Some(param) = service
                .response_params
                .iter()
                .find(|p| p.name == *param_name)
            else {
                tracing::warn!(
                    service = %service_name,
                    parameter = %param_name,
                    "defaults file references unknown parameter; skipping"
                );
                unknown_param += 1;
                continue;
            };

            // Pattern overrides (set during variant detection) win.
            if state.get_override(service_name, param_name).await.is_some() {
                tracing::debug!(
                    service = %service_name,
                    parameter = %param_name,
                    "defaults entry skipped: pattern override already set"
                );
                skipped += 1;
                continue;
            }

            let value = match to_parameter_value(default, param.bit_length) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(
                        service = %service_name,
                        parameter = %param_name,
                        error = %e,
                        "invalid defaults entry; skipping"
                    );
                    skipped += 1;
                    continue;
                }
            };

            tracing::info!(
                service = %service_name,
                parameter = %param_name,
                bit_length = param.bit_length,
                "applied default override"
            );
            state.set_override(service_name, param_name, value).await;
            applied += 1;
        }
    }

    (applied, unknown_service, unknown_param, skipped)
}

/// Convert a `DefaultValue` (as written in the TOML) into a `ParameterValue`
/// that the simulator's existing override pipeline understands.
///
/// Pads/truncates string/bytes payloads to the parameter's byte length, and
/// applies the parameter's conversion (if any) when interpreting numeric
/// values.
fn to_parameter_value(default: &DefaultValue, bit_length: u32) -> Result<ParameterValue, String> {
    let byte_length = ((bit_length.saturating_add(7)) / 8) as usize;

    if let Some(hex) = &default.bytes {
        let bytes = hex::decode(hex.trim_start_matches("0x").trim_start_matches("0X"))
            .map_err(|e| format!("invalid hex in `bytes`: {e}"))?;
        let mut padded = bytes;
        padded.resize(byte_length, 0);
        // Drop trailing bytes if user supplied more than the parameter holds.
        let mut truncated = padded;
        truncated.truncate(byte_length);
        return Ok(ParameterValue::Bytes(truncated));
    }

    let Some(toml_value) = &default.value else {
        return Err("entry has neither `value` nor `bytes`".to_owned());
    };

    match toml_value {
        toml::Value::String(s) => {
            let mut bytes = s.as_bytes().to_vec();
            bytes.resize(byte_length, 0);
            bytes.truncate(byte_length);
            Ok(ParameterValue::Bytes(bytes))
        }
        toml::Value::Integer(i) => Ok(ParameterValue::Int(*i)),
        toml::Value::Float(f) => Ok(ParameterValue::Float(*f)),
        toml::Value::Boolean(b) => Ok(ParameterValue::UInt(u64::from(*b))),
        other => Err(format!("unsupported value type: {other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_file() {
        let text = r#"
[overrides."VINDataIdentifier_Read".VIN]
value = "CDA-SIM-MARKER0000"
"#;
        let file: DefaultOverridesFile = toml::from_str(text).unwrap();
        assert!(file.overrides.contains_key("VINDataIdentifier_Read"));
    }

    #[test]
    fn parse_bytes_entry() {
        let text = r#"
[overrides."Identification_Read".Identification]
bytes = "AABBCC"
"#;
        let file: DefaultOverridesFile = toml::from_str(text).unwrap();
        let p = &file.overrides["Identification_Read"]["Identification"];
        assert_eq!(p.bytes.as_deref(), Some("AABBCC"));
    }

    #[test]
    fn to_value_string_pads_to_bit_length() {
        let d = DefaultValue {
            value: Some(toml::Value::String("AB".to_owned())),
            bytes: None,
        };
        // 136 bits / 8 = 17 bytes; expect "AB" + 15 zero bytes.
        let v = to_parameter_value(&d, 136).unwrap();
        match v {
            ParameterValue::Bytes(b) => {
                assert_eq!(b.len(), 17);
                assert_eq!(&b[..2], b"AB");
                assert!(b[2..].iter().all(|x| *x == 0));
            }
            other => panic!("expected Bytes, got {other:?}"),
        }
    }

    #[test]
    fn to_value_bytes_hex_decodes() {
        let d = DefaultValue {
            value: None,
            bytes: Some("DEAD".to_owned()),
        };
        let v = to_parameter_value(&d, 16).unwrap();
        match v {
            ParameterValue::Bytes(b) => assert_eq!(b, vec![0xDE, 0xAD]),
            other => panic!("expected Bytes, got {other:?}"),
        }
    }

    #[test]
    fn to_value_rejects_unsupported_type() {
        let d = DefaultValue {
            value: Some(toml::Value::Array(vec![])),
            bytes: None,
        };
        assert!(to_parameter_value(&d, 8).is_err());
    }
}
