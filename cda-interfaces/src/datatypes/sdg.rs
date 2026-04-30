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

use serde::{Deserialize, Serialize};

use crate::{HashMap, HashSet};

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum SdSdg {
    /// A single special data group
    Sd {
        #[serde(skip_serializing_if = "Option::is_none")]
        value: Option<String>,
        /// The semantic information (SI) aka the description of the SD
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(default)]
        si: Option<String>,
        /// The text information (TI) of the SD aka the value of the SD
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(default)]
        ti: Option<String>,
    },
    /// A collection of special data groups (SDGs)
    Sdg {
        /// The name of the SDG
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(default)]
        caption: Option<String>,
        /// The semantic information (SI) aka the description of the SD
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(default)]
        si: Option<String>,
        /// The list of SD or SDGs in the SDG
        #[serde(skip_serializing_if = "Vec::is_empty")]
        #[serde(default)]
        sdgs: Vec<SdSdg>,
    },
}

/// A config value to specify which Strings are to be interpreted
/// as truthy and which as falsey
/// `ignore_case` can be set to compare the SD values case-insensitively
#[derive(Serialize, Clone, Debug, schemars::JsonSchema)]
pub struct SdMappingsTruthyValue {
    /// Set of string values considered truthy for this mapping.
    values: HashSet<String>,
    /// Whether to compare values case-insensitively.
    ignore_case: bool,
}

/// Custom `Deserialize` impl that routes through `Self::new()` so that
/// `ignore_case = true` lowercases the stored values at parse time.
/// A derived `Deserialize` would set fields directly, bypassing `new()`,
/// and `contains()` (which lowercases the lookup) would never match the
/// un-lowercased stored values.
impl<'de> Deserialize<'de> for SdMappingsTruthyValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Raw {
            values: HashSet<String>,
            ignore_case: bool,
        }
        let raw = Raw::deserialize(deserializer)?;
        Ok(Self::new(raw.values, raw.ignore_case))
    }
}

impl SdMappingsTruthyValue {
    #[must_use]
    pub fn new(values: HashSet<String>, ignore_case: bool) -> Self {
        // ensure all values are lowercase if we use ignore_case
        let values = if ignore_case {
            values
                .into_iter()
                .map(|v| v.to_ascii_lowercase())
                .collect::<HashSet<_>>()
        } else {
            values
        };
        Self {
            values,
            ignore_case,
        }
    }
    #[must_use]
    pub fn contains(&self, other: &str) -> bool {
        if self.ignore_case {
            self.values.contains(&other.to_ascii_lowercase())
        } else {
            self.values.contains(other)
        }
    }
}

/// A mapping of an SD.si to their truthy values
pub type SdBoolMappings = HashMap<String, SdMappingsTruthyValue>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialized_ignore_case_lowercases_values() {
        let json = r#"{"values": ["Flux Capacitor Mark II", "Enabled"], "ignore_case": true}"#;
        let mapping: SdMappingsTruthyValue = serde_json::from_str(json).unwrap();
        // Values should have been lowercased during deserialization
        assert!(mapping.values.contains("flux capacitor mark ii"));
        assert!(mapping.values.contains("enabled"));
        assert!(!mapping.values.contains("Flux Capacitor Mark II"));
        assert!(!mapping.values.contains("Enabled"));
    }

    #[test]
    fn deserialized_case_sensitive_preserves_values() {
        let json = r#"{"values": ["Flux Capacitor Mark II", "Enabled"], "ignore_case": false}"#;
        let mapping: SdMappingsTruthyValue = serde_json::from_str(json).unwrap();
        assert!(mapping.values.contains("Flux Capacitor Mark II"));
        assert!(mapping.values.contains("Enabled"));
    }

    #[test]
    fn contains_matches_case_insensitive_after_deserialization() {
        let json = r#"{"values": ["Flux Capacitor Mark II", "Plutonium"], "ignore_case": true}"#;
        let mapping: SdMappingsTruthyValue = serde_json::from_str(json).unwrap();
        // Should match regardless of input case
        assert!(mapping.contains("flux capacitor mark ii"));
        assert!(mapping.contains("Flux Capacitor Mark II"));
        assert!(mapping.contains("FLUX CAPACITOR MARK II"));
        assert!(mapping.contains("plutonium"));
        assert!(mapping.contains("Plutonium"));
        assert!(!mapping.contains("Mr. Fusion"));
    }

    #[test]
    fn contains_matches_case_sensitive_after_deserialization() {
        let json = r#"{"values": ["Plutonium", "Mr. Fusion"], "ignore_case": false}"#;
        let mapping: SdMappingsTruthyValue = serde_json::from_str(json).unwrap();
        assert!(mapping.contains("Plutonium"));
        assert!(!mapping.contains("plutonium"));
        assert!(mapping.contains("Mr. Fusion"));
        assert!(!mapping.contains("mr. fusion"));
    }
}
