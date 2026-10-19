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

use cda_interfaces::{
    Protocol,
    config::{ConfigSanity, ConfigSanityError},
};
use serde::{Deserialize, Serialize};

/// How gateways are discovered on the network.
#[derive(
    Deserialize, Serialize, Clone, Copy, Debug, Default, PartialEq, Eq, schemars::JsonSchema,
)]
pub enum DiscoveryMode {
    /// No discovery of any kind: no VIR is broadcast and VAMs are ignored.
    /// ECUs are only connected through an explicit direct-connect request.
    Disabled,
    /// Only react to spontaneous VAMs. No VIR is broadcast.
    VamOnly,
    /// Broadcast a VIR on startup and react to the resulting and later VAMs.
    #[default]
    Full,
}

impl DiscoveryMode {
    /// Whether a VIR is broadcast when the transport starts.
    #[must_use]
    pub fn sends_vir(self) -> bool {
        matches!(self, Self::Full)
    }

    /// Whether VAMs are listened for (and the discovery socket is bound).
    #[must_use]
    pub fn listens_for_vams(self) -> bool {
        matches!(self, Self::Full | Self::VamOnly)
    }
}

/// `DoIP` (Diagnostics over IP) transport layer configuration.
#[derive(Deserialize, Serialize, Clone, Debug, schemars::JsonSchema)]
pub struct DoipConfig {
    /// Whether the `DoIP` transport is enabled.
    /// When `false`, CDA skips `DoIP` initialization entirely (useful for
    /// CAN-only or DoIP-less test setups).
    /// Defaults to `true` to preserve the historical DoIP-first behavior.
    pub enabled: bool,
    /// IP address of the diagnostic tester interface.
    pub tester_address: String,
    /// Subnet mask for the tester network.
    pub tester_subnet: String,
    /// UDP/TCP port for `DoIP` gateway discovery and communication.
    pub gateway_port: u16,
    /// TLS port for secure `DoIP` communication.
    pub tls_port: u16,
    /// Timeout in milliseconds for sending `DoIP` messages.
    pub send_timeout_ms: u64,
    /// Whether to request a diagnostic message positive acknowledgement.
    pub send_diagnostic_message_ack: bool,
    /// Interval in seconds between `DoIP` alive check requests sent on idle connections.
    /// The alive check is only sent when no diagnostic communication has occurred
    /// for this duration. Set to 0 to disable the alive check.
    pub alive_check_interval_secs: u64,
    /// Whether the SOVD operation `/apps/sovd2uds/operations/doip-connect-ecu` is offered,
    /// which connects an ECU directly to a given IP address instead of discovering it
    /// via VIR/VAM. Intended for ECU development, disabled by default.
    pub direct_connect_enabled: bool,
    /// How gateways are discovered on the network:
    /// - `Disabled`: no discovery of any kind, ECUs are only connected through an
    ///   explicit direct-connect request.
    /// - `VamOnly`: only react to spontaneous VAMs, no VIR is broadcast.
    /// - `Full`: broadcast a VIR on startup and react to the resulting and later VAMs.
    pub discovery: DiscoveryMode,
    /// The name of the protocol to use.
    /// Matched case-insensitive against the database.
    /// The special value `"auto-can"` defers the choice to the MDD-driven
    /// CAN protocol auto-detection (see `into_db_protocol`; the markers are
    /// configurable via `database.naming_convention.can_protocol_markers`).
    pub protocol_name: String,
}

impl DoipConfig {
    /// Checks that `tester_address` is assigned to a local network interface.
    ///
    /// The tester address is used as the source address of every `DoIP`
    /// connection. A stale address only shows up as an obscure bind error once
    /// the first connection is attempted, so this is meant to be checked at startup.
    ///
    /// # Errors
    /// Returns [`ConfigSanityError::InvalidValue`] if the address cannot be
    /// parsed or no local interface has it.
    pub fn check_tester_address_available(&self) -> Result<(), ConfigSanityError> {
        let ip = self
            .tester_address
            .parse::<std::net::IpAddr>()
            .map_err(|e| ConfigSanityError::InvalidValue {
                field: "tester_address".to_owned(),
                reason: format!("{} is not a valid IP address: {e}", self.tester_address),
            })?;
        // Binding only succeeds for addresses that belong to a local interface.
        std::net::UdpSocket::bind((ip, 0)).map(|_| ()).map_err(|e| {
            ConfigSanityError::InvalidValue {
                field: "tester_address".to_owned(),
                reason: format!(
                    "{ip} is not available on this host ({e}). Set doip.tester_address to the \
                     address of the network interface connected to the vehicle."
                ),
            }
        })
    }
}

impl Default for DoipConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            tester_address: "127.0.0.1".to_owned(),
            tester_subnet: "255.255.0.0".to_owned(),
            gateway_port: 13400,
            tls_port: 3496,
            send_timeout_ms: 1000,
            send_diagnostic_message_ack: true,
            alive_check_interval_secs: 1800, // 30 minutes
            direct_connect_enabled: false,
            discovery: DiscoveryMode::default(),
            protocol_name: Protocol::default().to_string(),
        }
    }
}

impl ConfigSanity for DoipConfig {
    fn validate_sanity(&self) -> Result<(), ConfigSanityError> {
        fn validate_ip(ip: &str, field: &str) -> Result<(), ConfigSanityError> {
            ip.parse::<std::net::IpAddr>().map(|_| ()).map_err(|_| {
                ConfigSanityError::InvalidValue {
                    field: field.to_owned(),
                    reason: format!("{ip} is neither a valid IPv4 nor IPv6 address"),
                }
            })
        }

        fn validate_port(port: u16, field: &str) -> Result<(), ConfigSanityError> {
            if port == 0 {
                return Err(ConfigSanityError::InvalidValue {
                    field: field.to_owned(),
                    reason: "Port must be greater than 0".to_string(),
                });
            }
            Ok(())
        }

        fn validate_timeout(timeout: u64, field: &str) -> Result<(), ConfigSanityError> {
            if timeout == 0 {
                return Err(ConfigSanityError::InvalidValue {
                    field: field.to_owned(),
                    reason: "Timeout must be greater than 0".to_string(),
                });
            }
            Ok(())
        }

        // A disabled DoIP transport binds no endpoint (CAN-only operation), so
        // its address/port/timeout fields are unused and may be left at their
        // zero/placeholder defaults; validating them would reject a valid
        // CAN-only configuration.
        if !self.enabled {
            return Ok(());
        }

        validate_ip(&self.tester_address, "tester_address")?;
        validate_ip(&self.tester_subnet, "tester_address")?;
        validate_port(self.gateway_port, "gateway_port")?;
        validate_port(self.tls_port, "tls_port")?;
        validate_timeout(self.send_timeout_ms, "send_timeout_ms")?;
        if self.alive_check_interval_secs > u64::from(u32::MAX) {
            return Err(ConfigSanityError::InvalidValue {
                field: "alive_check_interval_secs".to_owned(),
                reason: "Interval is too large, use 0 to disable it".to_string(),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use cda_interfaces::config::ConfigSanity;
    use doip_definitions::header::ProtocolVersion;

    use super::{DiscoveryMode, DoipConfig};

    #[test]
    fn disabled_doip_skips_field_validation() {
        // CAN-only operation: DoIP is disabled and its endpoint fields are left
        // at zero/placeholder defaults. Sanity must accept this instead of
        // rejecting the unused gateway_port == 0.
        let config = DoipConfig {
            enabled: false,
            gateway_port: 0,
            tls_port: 0,
            tester_address: String::new(),
            tester_subnet: String::new(),
            send_timeout_ms: 0,
            ..Default::default()
        };
        assert!(config.validate_sanity().is_ok());
    }

    #[test]
    fn enabled_doip_still_rejects_zero_port() {
        let config = DoipConfig {
            enabled: true,
            gateway_port: 0,
            ..Default::default()
        };
        assert!(config.validate_sanity().is_err());
    }

    #[test]
    fn tester_address_check_accepts_a_local_address() {
        let config = DoipConfig {
            tester_address: "127.0.0.1".to_owned(),
            ..Default::default()
        };
        assert!(config.check_tester_address_available().is_ok());
    }

    #[test]
    fn tester_address_check_rejects_an_address_no_interface_has() {
        // TEST-NET-1 (RFC 5737) is never assigned to a host interface.
        let config = DoipConfig {
            tester_address: "192.0.2.1".to_owned(),
            ..Default::default()
        };
        let error = config.check_tester_address_available().unwrap_err();
        assert!(
            error.to_string().contains("192.0.2.1"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn tester_address_check_rejects_an_invalid_address() {
        let config = DoipConfig {
            tester_address: "not-an-ip".to_owned(),
            ..Default::default()
        };
        assert!(config.check_tester_address_available().is_err());
    }

    #[test]
    fn direct_connect_is_disabled_by_default() {
        assert!(!DoipConfig::default().direct_connect_enabled);
    }

    #[test]
    fn discovery_defaults_to_full() {
        assert_eq!(DoipConfig::default().discovery, DiscoveryMode::Full);
    }

    #[test]
    fn discovery_mode_behaviour() {
        assert!(DiscoveryMode::Full.sends_vir());
        assert!(DiscoveryMode::Full.listens_for_vams());
        assert!(!DiscoveryMode::VamOnly.sends_vir());
        assert!(DiscoveryMode::VamOnly.listens_for_vams());
        assert!(!DiscoveryMode::Disabled.sends_vir());
        assert!(!DiscoveryMode::Disabled.listens_for_vams());
    }

    #[test]
    fn non_default_discovery_passes_sanity() {
        for discovery in [DiscoveryMode::Disabled, DiscoveryMode::VamOnly] {
            let config = DoipConfig {
                discovery,
                ..Default::default()
            };
            assert!(config.validate_sanity().is_ok());
        }
    }

    #[test]
    fn protocol_version_from_u8() {
        let v2: u8 = 0x02;
        let v3: u8 = 0x03;

        assert_eq!(
            ProtocolVersion::try_from(&v2).unwrap(),
            ProtocolVersion::Iso13400_2012
        );
        assert_eq!(
            ProtocolVersion::try_from(&v3).unwrap(),
            ProtocolVersion::Iso13400_2019
        );
    }
}
