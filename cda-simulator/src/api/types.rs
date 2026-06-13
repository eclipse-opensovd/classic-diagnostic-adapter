/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 */

//! API request and response types with OpenAPI schema support.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    mdd::{
        CompuCategory, Conversion, ParameterValue, ResponseParameter, ServiceDefinition,
        ServiceSource,
    },
    simulator::{SimulatorState, SimulatorStats},
};

/// Simulator information response
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SimulatorInfo {
    /// ECU name from MDD
    pub ecu_name: String,
    /// Path to the MDD file
    pub mdd_path: String,
    /// Currently simulated variant
    pub variant: String,
    /// Whether this is the base variant
    pub is_base_variant: bool,
    /// CAN interface name
    pub interface: String,
    /// CAN request ID (hex string)
    pub request_id: String,
    /// CAN response ID (hex string)
    pub response_id: String,
    /// Number of services loaded
    pub service_count: usize,
    /// Number of services inherited from base variant
    pub services_from_base: usize,
    /// Number of services specific to selected variant (including overrides)
    pub services_from_variant: usize,
    /// Number of built-in services (e.g., TesterPresent)
    pub services_builtin: usize,
}

impl SimulatorInfo {
    pub fn from_state(state: &SimulatorState) -> Self {
        let services_from_base = state
            .services
            .values()
            .filter(|s| s.source == ServiceSource::BaseVariant)
            .count();
        let services_from_variant = state
            .services
            .values()
            .filter(|s| s.source == ServiceSource::SelectedVariant)
            .count();
        let services_builtin = state
            .services
            .values()
            .filter(|s| s.source == ServiceSource::BuiltIn)
            .count();

        Self {
            ecu_name: state.ecu_name.clone(),
            mdd_path: state.mdd_path.clone(),
            variant: state.variant.name.clone(),
            is_base_variant: state.variant.is_base,
            interface: state.interface.clone(),
            request_id: format!("0x{:03X}", state.request_id),
            response_id: format!("0x{:03X}", state.response_id),
            service_count: state.services.len(),
            services_from_base,
            services_from_variant,
            services_builtin,
        }
    }
}

/// Variant information
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VariantInfo {
    /// Variant name
    pub name: String,
    /// Whether this is the base variant
    pub is_base: bool,
    /// Whether this variant is currently active
    pub is_active: bool,
}

/// Service information for API responses
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ServiceInfo {
    /// Service name from MDD
    pub name: String,
    /// Service ID (hex string)
    pub sid: String,
    /// Sub-function/DID (hex string, if present)
    pub sub_function: Option<String>,
    /// Service description
    pub description: Option<String>,
    /// Whether this service uses multi-frame ISO-TP
    pub is_multiframe: bool,
    /// Number of response parameters
    pub parameter_count: usize,
    /// Source of this service definition (base, variant, or builtin)
    pub source: String,
}

impl ServiceInfo {
    pub fn from_definition(def: &ServiceDefinition) -> Self {
        Self {
            name: def.name.clone(),
            sid: format!("0x{:02X}", def.sid),
            sub_function: def.sub_function.map(|s| format!("0x{:02X}", s)),
            description: def.description.clone(),
            is_multiframe: def.is_multiframe,
            parameter_count: def.response_params.len(),
            source: def.source.to_string(),
        }
    }
}

/// Detailed service information including parameters
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ServiceDetailInfo {
    /// Basic service info
    #[serde(flatten)]
    pub service: ServiceInfo,
    /// Response parameters
    pub parameters: Vec<ParameterInfo>,
}

/// Parameter information for API responses
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ParameterInfo {
    /// Parameter name from MDD
    pub name: String,
    /// Byte position in response
    pub byte_position: u32,
    /// Bit position within byte
    pub bit_position: u32,
    /// Length in bits
    pub bit_length: u32,
    /// Current physical value (after conversion)
    pub current_value: f64,
    /// Current raw value (before conversion)
    pub raw_value: u64,
    /// Physical unit (from MDD)
    pub unit: Option<String>,
    /// Conversion information
    pub conversion: Option<ConversionInfo>,
    /// Whether this parameter has an override set
    pub has_override: bool,
}

impl ParameterInfo {
    pub fn from_parameter(
        param: &ResponseParameter,
        override_value: Option<&ParameterValue>,
    ) -> Self {
        let (current_value, raw_value, has_override) = if let Some(ov) = override_value {
            match ov {
                // Bytes/String overrides are raw, not physical (as_f64()
                // would yield 0.0): raw from the leading bytes, physical via
                // the raw->physical conversion, like the default-value path.
                ParameterValue::Bytes(_) | ParameterValue::String(_) => {
                    let raw = ov.as_u64();
                    let physical = if let Some(ref conv) = param.conversion {
                        conv.raw_to_physical(raw as f64)
                    } else {
                        raw as f64
                    };
                    (physical, raw, true)
                }
                // Numeric overrides are stored as physical values
                _ => {
                    let physical = ov.as_f64();
                    let raw = if let Some(ref conv) = param.conversion {
                        conv.physical_to_raw(physical) as u64
                    } else {
                        physical as u64
                    };
                    (physical, raw, true)
                }
            }
        } else {
            // Use default value
            let raw = param.default_value.as_u64();
            let physical = if let Some(ref conv) = param.conversion {
                conv.raw_to_physical(raw as f64)
            } else {
                raw as f64
            };
            (physical, raw, false)
        };

        Self {
            name: param.name.clone(),
            byte_position: param.byte_position,
            bit_position: param.bit_position,
            bit_length: param.bit_length,
            current_value,
            raw_value,
            unit: param.unit.clone(),
            conversion: param
                .conversion
                .as_ref()
                .map(ConversionInfo::from_conversion),
            has_override,
        }
    }
}

/// Conversion information for API responses
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ConversionInfo {
    /// Conversion category
    pub category: String,
    /// Multiplier for linear conversion
    pub multiplier: Option<f64>,
    /// Offset for linear conversion
    pub offset: Option<f64>,
}

impl ConversionInfo {
    pub fn from_conversion(conv: &Conversion) -> Self {
        let (multiplier, offset) = match conv.category {
            CompuCategory::Linear => (Some(conv.multiplier), Some(conv.offset)),
            _ => (None, None),
        };

        Self {
            category: conv.category.to_string(),
            multiplier,
            offset,
        }
    }
}

/// Request body for setting a parameter value.
///
/// A tagged union (`{"type": "number", "value": 1.0}`,
/// `{"type": "string", "value": "AB"}`, `{"type": "bytes", "value": "AABB"}`,
/// `{"type": "int", "value": 12}`).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SetParameterValue {
    /// Physical numeric value (conversion applied if the parameter has one).
    Number { value: f64 },
    /// Explicit integer (no float coercion).
    Int { value: i64 },
    /// ASCII bytes (padded with 0 to the parameter's byte length).
    String { value: String },
    /// Hex-encoded raw bytes (padded/truncated to the parameter's byte length).
    Bytes { value: String },
}

/// Override information
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct OverrideInfo {
    /// Service name
    pub service: String,
    /// Parameter name
    pub parameter: String,
    /// Override value: a physical number, integer, string, or raw bytes -
    /// whichever variant the client set on PUT.
    pub value: ParameterValue,
}

/// List of overrides
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct OverrideList {
    /// Number of active overrides
    pub count: usize,
    /// List of overrides
    pub overrides: Vec<OverrideInfo>,
}

/// Statistics response
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StatsResponse {
    /// Number of requests received
    pub requests_received: u64,
    /// Number of responses sent
    pub responses_sent: u64,
    /// Number of errors
    pub errors: u64,
    /// Number of unsupported service requests
    pub unsupported_requests: u64,
}

impl From<SimulatorStats> for StatsResponse {
    fn from(stats: SimulatorStats) -> Self {
        Self {
            requests_received: stats.requests_received,
            responses_sent: stats.responses_sent,
            errors: stats.errors,
            unsupported_requests: stats.unsupported_requests,
        }
    }
}

/// Error response
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ErrorResponse {
    /// Error message
    pub error: String,
}

impl ErrorResponse {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            error: message.into(),
        }
    }
}
