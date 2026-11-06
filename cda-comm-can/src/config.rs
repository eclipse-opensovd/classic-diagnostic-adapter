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

use cda_interfaces::TransportType;
use serde::{Deserialize, Serialize};

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
    /// [[can.transport_overrides]]
    /// ecu_name = "MyCanOnlyEcu"
    /// transport = "can"
    /// ```
    #[serde(default)]
    pub transport_overrides: Vec<TransportOverride>,

    /// Timeout for waiting for a response in milliseconds.
    ///
    /// The serde default is needed (unlike for other config types) because
    /// `[can]` is an optional section: the figment defaults tree carries no
    /// values below it, so omitted fields must default at deserialization
    /// time. The canonical values live in the `Default` impl.
    #[serde(default = "default_response_timeout_ms")]
    pub response_timeout_ms: u64,

    /// Timeout for probing ECUs during discovery in milliseconds.
    /// See `response_timeout_ms` for why the serde default is needed.
    #[serde(default = "default_probe_timeout_ms")]
    pub probe_timeout_ms: u64,

    /// Extra rounds through the probe sequence when an ECU did not answer,
    /// self-healing transiently lost exchanges (e.g. bus arbitration during
    /// startup) inside the transport instead of surfacing a spurious offline
    /// to the UDS layer. `0` probes each ECU exactly once per discovery.
    /// See `response_timeout_ms` for why the serde default is needed.
    #[serde(default = "default_probe_retries")]
    pub probe_retries: u32,

    /// Delay between probe retry rounds in milliseconds.
    /// See `response_timeout_ms` for why the serde default is needed.
    #[serde(default = "default_probe_retry_delay_ms")]
    pub probe_retry_delay_ms: u64,

    /// Interval of the functional-broadcast `TesterPresent` keep-alive in
    /// milliseconds; `0` (the default) disables it, keeping a resident
    /// on-board CDA from interfering with network management - sleeping
    /// ECUs are recovered by rediscovery on wake. External testers should
    /// set an interval (e.g. 2000) to hold ECUs awake for the session.
    /// See `response_timeout_ms` for why the serde default is needed.
    #[serde(default = "default_keepalive_interval_ms")]
    pub keepalive_interval_ms: u64,

    /// Whether the built-in `TesterPresent` probe heads the discovery
    /// probe sequence; with `false`, `probe_fallbacks` must be non-empty
    /// and is used verbatim.
    /// See `response_timeout_ms` for why the serde default is needed.
    #[serde(default = "default_default_probes")]
    pub default_probes: bool,

    /// Optional fallback probe payloads used after the default `TesterPresent` probe
    /// (or, with `default_probes = false`, the complete probe sequence).
    ///
    /// This is useful for ECUs that do not answer `TesterPresent` during discovery,
    /// but do respond to another lightweight diagnostic request.
    #[serde(default)]
    pub probe_fallbacks: Vec<CanProbeConfig>,

    /// Byte used to pad transmitted ISO-TP frames (TX padding is always
    /// enabled). Defaults to `0x00`; many ECUs expect `0x55` or `0xCC`.
    /// See `response_timeout_ms` for why the serde default is needed.
    #[serde(default = "default_padding_byte")]
    pub padding_byte: u8,

    /// CAN FD (ISO 15765-2:2016) link layer. If present, ISO-TP frames are
    /// transmitted as CAN FD frames with up to `tx_dl` data bytes; if absent,
    /// classic CAN frames are used. Received CAN FD frames are accepted
    /// either way on the userspace backends (`socketcand:`, `rawcan:`).
    ///
    /// Example (TOML):
    /// ```toml
    /// [can.fd]
    /// tx_dl = 64
    /// brs = true
    /// ```
    ///
    /// The CAN interface itself must be configured for CAN FD: e.g.
    /// `ip link set can0 type can bitrate 500000 dbitrate 2000000 fd on`, or
    /// a CAN FD capable socketcand server such as `cda-can-bridge` (upstream
    /// socketcand is classic CAN only).
    #[serde(default)]
    pub fd: Option<CanFdConfig>,
}

/// CAN FD link layer settings for ISO-TP.
#[derive(Deserialize, Serialize, Clone, Copy, Debug, PartialEq, Eq, schemars::JsonSchema)]
pub struct CanFdConfig {
    /// Max data bytes per transmitted CAN FD frame (`TX_DL`): one of 8, 12,
    /// 16, 20, 24, 32, 48, 64. Defaults to 64.
    #[serde(default = "default_fd_tx_dl")]
    pub tx_dl: u8,

    /// Transmit with bit rate switch (data phase at the data bitrate).
    /// Defaults to `true`.
    #[serde(default = "default_fd_brs")]
    pub brs: bool,
}

impl Default for CanFdConfig {
    fn default() -> Self {
        Self {
            tx_dl: default_fd_tx_dl(),
            brs: default_fd_brs(),
        }
    }
}

impl CanFdConfig {
    /// Valid CAN FD `TX_DL` values.
    pub const VALID_TX_DL: [u8; 8] = [8, 12, 16, 20, 24, 32, 48, 64];

    /// Checks that `tx_dl` is a valid CAN FD data length.
    ///
    /// # Errors
    /// Returns a description of the problem if `tx_dl` is invalid.
    pub fn validate(&self) -> Result<(), String> {
        if Self::VALID_TX_DL.contains(&self.tx_dl) {
            Ok(())
        } else {
            Err(format!(
                "invalid can.fd.tx_dl {}: expected one of {:?}",
                self.tx_dl,
                Self::VALID_TX_DL
            ))
        }
    }
}

fn default_fd_tx_dl() -> u8 {
    64
}

fn default_fd_brs() -> bool {
    true
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

        if !normalized.len().is_multiple_of(2) {
            // Reject instead of deferring to decode_hex's zero-padding: for a
            // UDS probe payload a missing nibble is a config mistake, and
            // silently padding it would put a different request on the bus.
            return Err(format!(
                "Probe payload `{}` must contain an even number of hex digits",
                self.payload_hex
            ));
        }

        cda_interfaces::util::decode_hex(&normalized)
            .map_err(|e| format!("Invalid probe payload `{}`: {e}", self.payload_hex))
    }
}

/// Explicit CAN ID mapping for an ECU.
/// Used when MDD COM parameters don't contain CAN addressing info.
#[derive(Deserialize, Serialize, Clone, Debug, schemars::JsonSchema)]
pub struct CanEcuMapping {
    /// ECU name as defined in the MDD file.
    pub ecu_name: String,

    /// Physical request CAN identifier.
    ///
    /// Supports both:
    /// - 11-bit standard CAN IDs (e.g. `0x7E0`)
    /// - 29-bit extended CAN IDs (e.g. `0x18DA10F1`, ISO 15765-4 normal
    ///   fixed addressing)
    pub request_id: u32,

    /// Physical response CAN identifier.
    ///
    /// Supports both:
    /// - 11-bit standard CAN IDs (e.g. `0x7E8`)
    /// - 29-bit extended CAN IDs (e.g. `0x18DAF110`)
    pub response_id: u32,

    /// ISO-TP addressing mode. Extended addressing prefixes the given byte to every
    /// ISO-TP payload; Standard uses only the CAN ID for addressing.
    #[serde(default)]
    pub addressing_mode: CanAddressingMode,
}

#[derive(
    Deserialize, Serialize, Clone, Copy, Default, PartialEq, Eq, Debug, schemars::JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum CanAddressingMode {
    /// No address-extension byte; ISO-TP addressing comes entirely from the
    /// CAN ID.
    #[default]
    Standard,
    /// Mixed/extended addressing: the given address-extension byte is
    /// prefixed to every ISO-TP payload.
    Extended(u8),
}

impl Default for CanConfig {
    fn default() -> Self {
        Self {
            interface: "can0".to_owned(),
            ecu_mappings: Vec::new(),
            transport_overrides: Vec::new(),
            response_timeout_ms: 5000,
            probe_timeout_ms: 100,
            probe_retries: 0,
            probe_retry_delay_ms: 100,
            keepalive_interval_ms: 0,
            default_probes: true,
            probe_fallbacks: Vec::new(),
            padding_byte: 0x00,
            fd: None,
        }
    }
}

fn default_padding_byte() -> u8 {
    CanConfig::default().padding_byte
}

fn default_response_timeout_ms() -> u64 {
    CanConfig::default().response_timeout_ms
}

fn default_probe_timeout_ms() -> u64 {
    CanConfig::default().probe_timeout_ms
}

fn default_probe_retries() -> u32 {
    CanConfig::default().probe_retries
}

fn default_probe_retry_delay_ms() -> u64 {
    CanConfig::default().probe_retry_delay_ms
}

fn default_default_probes() -> bool {
    CanConfig::default().default_probes
}

fn default_keepalive_interval_ms() -> u64 {
    CanConfig::default().keepalive_interval_ms
}

#[cfg(test)]
mod tests {
    use super::{CanConfig, CanFdConfig, CanProbeConfig};

    /// `[can]` is an optional config section, so it is deserialized directly
    /// from the user's TOML without the figment defaults tree behind it. A
    /// minimal section must still work; this pins the serde-default fields.
    #[test]
    fn minimal_can_section_deserializes_with_defaults() {
        let config: CanConfig = toml::from_str(r#"interface = "vcan0""#).expect("minimal config");

        assert_eq!(config.interface, "vcan0");
        assert_eq!(
            config.response_timeout_ms,
            CanConfig::default().response_timeout_ms
        );
        assert_eq!(
            config.probe_timeout_ms,
            CanConfig::default().probe_timeout_ms
        );
        assert!(config.default_probes);
        assert_eq!(
            config.keepalive_interval_ms,
            CanConfig::default().keepalive_interval_ms
        );
        assert!(config.ecu_mappings.is_empty());
        assert!(config.transport_overrides.is_empty());
        assert!(config.probe_fallbacks.is_empty());
        assert_eq!(config.padding_byte, 0x00);
        assert!(config.fd.is_none());
    }

    #[test]
    fn can_fd_section_deserializes_with_defaults() {
        let config: CanConfig = toml::from_str(
            r#"
            interface = "socketcand:bridge:29536:can0"
            padding_byte = 0x55
            [fd]
            "#,
        )
        .expect("fd config");
        assert_eq!(config.padding_byte, 0x55);
        let fd = config.fd.expect("fd section");
        assert_eq!(fd, CanFdConfig::default());
        assert_eq!(fd.tx_dl, 64);
        assert!(fd.brs);
        assert!(fd.validate().is_ok());
    }

    #[test]
    fn can_fd_tx_dl_is_validated() {
        let config: CanConfig = toml::from_str(
            r#"
            interface = "can0"
            [fd]
            tx_dl = 10
            brs = false
            "#,
        )
        .expect("fd config");
        let fd = config.fd.expect("fd section");
        assert!(!fd.brs);
        assert!(fd.validate().is_err());
        for tx_dl in CanFdConfig::VALID_TX_DL {
            assert!(CanFdConfig { tx_dl, brs: true }.validate().is_ok());
        }
    }

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
