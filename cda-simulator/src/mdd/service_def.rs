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

//! Service and parameter definitions extracted from MDD.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Source of a service definition
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum ServiceSource {
    /// Service comes from the base variant (inherited)
    BaseVariant,
    /// Service comes from the selected variant (variant-specific or override)
    SelectedVariant,
    /// Service comes from ECU shared data
    EcuShared,
    /// Built-in service (e.g., TesterPresent)
    BuiltIn,
}

impl std::fmt::Display for ServiceSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BaseVariant => write!(f, "base"),
            Self::SelectedVariant => write!(f, "variant"),
            Self::EcuShared => write!(f, "ecu_shared"),
            Self::BuiltIn => write!(f, "builtin"),
        }
    }
}

/// Represents a diagnostic service parsed from the MDD
#[derive(Debug, Clone)]
pub struct ServiceDefinition {
    /// Service short name from MDD
    pub name: String,
    /// Service ID (SID) - e.g., 0x21 for ReadDataByLocalIdentifier
    pub sid: u8,
    /// Sub-function or DID - e.g., 0x25, 0x61, 0x0304
    /// Can be 1 byte (LID) or 2 bytes (DID) depending on service
    pub sub_function: Option<u16>,
    /// Length of sub_function in bytes (1 or 2)
    pub sub_function_len: u8,
    /// Description from MDD SDGS
    pub description: Option<String>,
    /// Response parameters with their default values
    pub response_params: Vec<ResponseParameter>,
    /// Total response payload length (excluding SID and sub-function echo)
    pub response_length: usize,
    /// Whether this requires multi-frame (ISO-TP) - based on response length
    pub is_multiframe: bool,
    /// Source of this service definition (base, variant, or builtin)
    pub source: ServiceSource,
}

impl ServiceDefinition {
    /// Get the key for this service (SID, SubFunction)
    pub fn key(&self) -> (u8, Option<u16>) {
        (self.sid, self.sub_function)
    }
}

/// Represents a single parameter in a response
#[derive(Debug, Clone)]
pub struct ResponseParameter {
    /// Parameter name from MDD
    pub name: String,
    /// Byte position in response (0-indexed, relative to start of data after SID+DID)
    pub byte_position: u32,
    /// Bit position within the byte
    pub bit_position: u32,
    /// Length in bits
    pub bit_length: u32,
    /// Default value
    pub default_value: ParameterValue,
    /// Physical unit (for display)
    pub unit: Option<String>,
    /// Conversion factor (for linear scaling)
    pub conversion: Option<Conversion>,
}

impl ResponseParameter {
    /// Get the byte length of this parameter
    pub fn byte_length(&self) -> u32 {
        (self.bit_length.saturating_add(7)) / 8
    }
}

/// Parameter value types
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum ParameterValue {
    /// Unsigned integer value
    UInt(u64),
    /// Signed integer value
    Int(i64),
    /// Floating point value
    Float(f64),
    /// Raw bytes
    Bytes(Vec<u8>),
    /// String value
    String(String),
}

impl Default for ParameterValue {
    fn default() -> Self {
        Self::UInt(0)
    }
}

impl ParameterValue {
    /// Convert to raw bytes for encoding into response
    pub fn to_raw_bytes(&self, bit_length: u32, conversion: Option<&Conversion>) -> Vec<u8> {
        let byte_length = ((bit_length.saturating_add(7)) / 8) as usize;

        // Get the raw numeric value
        let raw_value: u64 = match self {
            Self::UInt(v) => *v,
            Self::Int(v) => *v as u64,
            Self::Float(v) => {
                // Apply inverse conversion if available to get raw value
                let raw = if let Some(conv) = conversion {
                    conv.physical_to_raw(*v)
                } else {
                    *v
                };
                raw as u64
            }
            Self::Bytes(b) => {
                // Return bytes directly
                let mut result = b.clone();
                result.resize(byte_length, 0);
                return result;
            }
            Self::String(s) => {
                // Return string as bytes
                let mut result = s.as_bytes().to_vec();
                result.resize(byte_length, 0);
                return result;
            }
        };

        // Convert to big-endian bytes (UDS typically uses big-endian)
        let all_bytes = raw_value.to_be_bytes();
        let start = 8usize.saturating_sub(byte_length);
        all_bytes[start..].to_vec()
    }

    /// Get as f64 for API responses
    pub fn as_f64(&self) -> f64 {
        match self {
            Self::UInt(v) => *v as f64,
            Self::Int(v) => *v as f64,
            Self::Float(v) => *v,
            Self::Bytes(_) => 0.0,
            Self::String(_) => 0.0,
        }
    }

    /// Get as u64 for raw value display
    pub fn as_u64(&self) -> u64 {
        match self {
            Self::UInt(v) => *v,
            Self::Int(v) => *v as u64,
            Self::Float(v) => *v as u64,
            Self::Bytes(b) => {
                // Convert bytes to u64 (big-endian)
                let mut result = 0u64;
                for byte in b.iter().take(8) {
                    result = (result << 8) | (*byte as u64);
                }
                result
            }
            Self::String(_) => 0,
        }
    }
}

/// Conversion from MDD CompuMethod - supports various categories
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Conversion {
    /// Conversion category
    pub category: CompuCategory,
    /// For linear: physical = raw * multiplier + offset
    pub multiplier: f64,
    /// Offset for linear conversion
    pub offset: f64,
}

impl Conversion {
    /// Create an identity conversion (no transformation)
    pub fn identity() -> Self {
        Self {
            category: CompuCategory::Identical,
            multiplier: 1.0,
            offset: 0.0,
        }
    }

    /// Create a linear conversion
    pub fn linear(multiplier: f64, offset: f64) -> Self {
        Self {
            category: CompuCategory::Linear,
            multiplier,
            offset,
        }
    }

    /// Convert raw value to physical value
    pub fn raw_to_physical(&self, raw: f64) -> f64 {
        match self.category {
            CompuCategory::Identical => raw,
            CompuCategory::Linear => raw * self.multiplier + self.offset,
            CompuCategory::TextTable => raw, // Text tables don't have numeric conversion
        }
    }

    /// Convert physical value to raw value
    pub fn physical_to_raw(&self, physical: f64) -> f64 {
        match self.category {
            CompuCategory::Identical => physical,
            CompuCategory::Linear => {
                if self.multiplier.abs() < f64::EPSILON {
                    0.0
                } else {
                    (physical - self.offset) / self.multiplier
                }
            }
            CompuCategory::TextTable => physical,
        }
    }
}

/// Computation method category from MDD
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum CompuCategory {
    /// physical = raw (no conversion)
    Identical,
    /// physical = raw * multiplier + offset
    Linear,
    /// Map raw values to strings (not numerically convertible)
    TextTable,
}

impl Default for CompuCategory {
    fn default() -> Self {
        Self::Identical
    }
}

impl std::fmt::Display for CompuCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Identical => write!(f, "Identical"),
            Self::Linear => write!(f, "Linear"),
            Self::TextTable => write!(f, "TextTable"),
        }
    }
}
