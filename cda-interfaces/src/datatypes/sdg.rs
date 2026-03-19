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
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct SdMappingsTruthyValue {
    values: HashSet<String>,
    ignore_case: bool,
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
