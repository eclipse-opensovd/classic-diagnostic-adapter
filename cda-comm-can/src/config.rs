/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 */

use serde::{Deserialize, Serialize};

use crate::multi_transport::TransportType;

/// Configuration for CAN bus communication.
#[derive(Deserialize, Serialize, Clone, Debug, schemars::JsonSchema)]
pub struct CanConfig {
    /// CAN interface name (e.g., "vxcan0", "can0")
    pub interface: String,

    /// Optional explicit ECU CAN ID mappings.
    /// If not provided, CAN IDs will be read from the MDD COM parameters.
    #[serde(default)]
    pub ecu_mappings: Vec<CanEcuMapping>,

    /// Per-ECU transport override.
    ///
    /// Keys are ECU names (case-insensitive), values are the transport to use.
    /// ECUs not listed here default to `DoIP` when a `DoIP` gateway is available,
    /// falling back to CAN otherwise.
    ///
    /// Example (TOML):
    /// ```toml
    /// [can.transport_overrides]
    /// "MyCanOnlyEcu" = "can"
    /// ```
    #[serde(default)]
    pub transport_overrides: Vec<TransportOverride>,

    /// Timeout for waiting for a response in milliseconds.
    #[serde(default = "default_response_timeout_ms")]
    pub response_timeout_ms: u64,

    /// Timeout for probing ECUs during discovery in milliseconds.
    #[serde(default = "default_probe_timeout_ms")]
    pub probe_timeout_ms: u64,

    /// Optional fallback probe payloads used after the default `TesterPresent` probe.
    ///
    /// This is useful for ECUs that do not answer `TesterPresent` during discovery,
    /// but do respond to another lightweight diagnostic request.
    #[serde(default)]
    pub probe_fallbacks: Vec<CanProbeConfig>,
}

/// Per-ECU transport selection override.
#[derive(Deserialize, Serialize, Clone, Debug, schemars::JsonSchema)]
pub struct TransportOverride {
    /// ECU name as defined in the MDD file (case-insensitive).
    pub ecu_name: String,

    /// Transport to use for this ECU.
    pub transport: TransportType,
}

/// Additional probe payload to try during CAN discovery.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq, schemars::JsonSchema)]
pub struct CanProbeConfig {
    /// Optional friendly label for logs.
    pub name: Option<String>,

    /// UDS request payload encoded as hex, e.g. `22F190` or `22 F1 90`.
    pub payload_hex: String,
}

impl CanProbeConfig {
    /// Parse the configured hex payload into raw bytes.
    ///
    /// # Errors
    /// Returns an error if the payload contains invalid hex or has odd length.
    pub fn payload_bytes(&self) -> Result<Vec<u8>, String> {
        let normalized = self
            .payload_hex
            .replace("0x", "")
            .replace("0X", "")
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '_')
            .collect::<String>();

        if normalized.is_empty() {
            return Err("Probe payload must not be empty".to_owned());
        }

        if normalized.len() % 2 != 0 {
            return Err(format!(
                "Probe payload `{}` must contain an even number of hex digits",
                self.payload_hex
            ));
        }

        hex::decode(&normalized)
            .map_err(|e| format!("Invalid probe payload `{}`: {e}", self.payload_hex))
    }
}

/// Explicit CAN ID mapping for an ECU.
/// Used when MDD COM parameters don't contain CAN addressing info.
#[derive(Deserialize, Serialize, Clone, Debug, schemars::JsonSchema)]
pub struct CanEcuMapping {
    /// ECU name as defined in the MDD file
    pub ecu_name: String,

    /// Physical request CAN ID (e.g., 0x7E0)
    pub request_id: u32,

    /// Physical response CAN ID (e.g., 0x7E8)
    pub response_id: u32,
}

const fn default_response_timeout_ms() -> u64 {
    5000
}

const fn default_probe_timeout_ms() -> u64 {
    100
}

#[cfg(test)]
mod tests {
    use super::CanProbeConfig;

    #[test]
    fn parse_probe_payload_hex_without_spacing() {
        let probe = CanProbeConfig {
            name: Some("read-did".to_owned()),
            payload_hex: "22F190".to_owned(),
        };

        assert_eq!(
            probe.payload_bytes().expect("valid payload"),
            vec![0x22, 0xF1, 0x90]
        );
    }

    #[test]
    fn parse_probe_payload_hex_with_spacing() {
        let probe = CanProbeConfig {
            name: None,
            payload_hex: "22 F1 90".to_owned(),
        };

        assert_eq!(
            probe.payload_bytes().expect("valid payload"),
            vec![0x22, 0xF1, 0x90]
        );
    }

    #[test]
    fn reject_odd_probe_payload_hex() {
        let probe = CanProbeConfig {
            name: None,
            payload_hex: "22F19".to_owned(),
        };

        assert!(probe.payload_bytes().is_err());
    }
}
