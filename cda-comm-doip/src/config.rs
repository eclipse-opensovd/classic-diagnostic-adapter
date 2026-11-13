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

/// How gateways are discovered on the network, once communication has been
/// initialized. Independent of `communication.init_mode`, which controls when
/// communication starts and whether a persisted topology is reused.
#[derive(
    Deserialize, Serialize, Clone, Copy, Debug, Default, PartialEq, Eq, schemars::JsonSchema,
)]
pub enum DiscoveryMode {
    /// No discovery of any kind: no VIR is broadcast, VAMs are ignored and
    /// persisted gateways are not reconnected. ECUs are only connected through an
    /// explicit direct-connect request.
    Disabled,
    /// No VIR is ever broadcast, neither at startup nor as a fallback. VAMs are
    /// handled as `communication.vam_handling_mode` allows. Persisted gateways
    /// are reconnected by unicast to their persisted address; one that cannot be
    /// connected this way is reported unreachable.
    VamOnly,
    /// Broadcast a VIR on startup and handle VAMs as
    /// `communication.vam_handling_mode` allows. A persisted gateway that cannot
    /// be reached at its persisted address is searched by VIR.
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

/// Lower bound of the dynamic port range (ISO 13400-2 REQ 4.DoIP-135).
pub const DYNAMIC_PORT_RANGE_START: u16 = 49152;
/// Upper bound of the dynamic port range (ISO 13400-2 REQ 4.DoIP-135).
pub const DYNAMIC_PORT_RANGE_END: u16 = 65535;

/// Local UDP port the vehicle identification request (VIR) is sent from.
///
/// ISO 13400-2 (REQ 4.DoIP-135) requires the client to send UDP messages from
/// `UDP_TEST_EQUIPMENT_REQUEST`, a port dynamically assigned within 49152..=65535.
/// Gateways answer the VIR to this port (REQ 4.DoIP-137).
///
/// In the configuration file this is either an integer or a `"start-end"` string:
/// - `0`: the operating system picks an ephemeral port.
/// - `13400`: a fixed port. Using the gateway port keeps the legacy behavior of
///   sending from and receiving on the discovery port.
/// - `"49152-65535"`: a free port from the inclusive range is picked.
#[derive(Deserialize, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(try_from = "VirSourcePortRepr", into = "VirSourcePortRepr")]
pub enum VirSourcePort {
    /// A fixed port, `0` lets the operating system choose.
    Port(u16),
    /// A free port from the inclusive range `start..=end`.
    Range { start: u16, end: u16 },
}

impl VirSourcePort {
    /// Whether every port that can be selected lies within the dynamic port
    /// range required by ISO 13400-2. `0` is considered conformant, although the
    /// operating system's ephemeral range may differ.
    #[must_use]
    pub fn is_in_dynamic_range(self) -> bool {
        match self {
            Self::Port(0) => true,
            Self::Port(port) => port >= DYNAMIC_PORT_RANGE_START,
            Self::Range { start, .. } => start >= DYNAMIC_PORT_RANGE_START,
        }
    }
}

impl Default for VirSourcePort {
    fn default() -> Self {
        Self::Range {
            start: DYNAMIC_PORT_RANGE_START,
            end: DYNAMIC_PORT_RANGE_END,
        }
    }
}

impl std::fmt::Display for VirSourcePort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Port(port) => write!(f, "{port}"),
            Self::Range { start, end } => write!(f, "{start}-{end}"),
        }
    }
}

impl std::str::FromStr for VirSourcePort {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parse_port = |port: &str| {
            port.trim()
                .parse::<u16>()
                .map_err(|e| format!("Invalid port `{}`: {e}", port.trim()))
        };
        match value.split_once('-') {
            None => parse_port(value).map(Self::Port),
            Some((start, end)) => {
                let (start, end) = (parse_port(start)?, parse_port(end)?);
                match (start, end) {
                    (0, _) => Err(format!(
                        "Invalid port range `{value}`: ports must be greater than 0"
                    )),
                    (start, end) if start > end => Err(format!(
                        "Invalid port range `{value}`: start is greater than end"
                    )),
                    (start, end) => Ok(Self::Range { start, end }),
                }
            }
        }
    }
}

/// Serialized form of [`VirSourcePort`]: an integer port or a `"start-end"` string.
#[derive(Deserialize, Serialize, schemars::JsonSchema)]
#[serde(untagged)]
enum VirSourcePortRepr {
    Port(u16),
    Text(String),
}

impl TryFrom<VirSourcePortRepr> for VirSourcePort {
    type Error = String;

    fn try_from(repr: VirSourcePortRepr) -> Result<Self, Self::Error> {
        match repr {
            VirSourcePortRepr::Port(port) => Ok(Self::Port(port)),
            VirSourcePortRepr::Text(text) => text.parse(),
        }
    }
}

impl From<VirSourcePort> for VirSourcePortRepr {
    fn from(port: VirSourcePort) -> Self {
        match port {
            VirSourcePort::Port(port) => Self::Port(port),
            range @ VirSourcePort::Range { .. } => Self::Text(range.to_string()),
        }
    }
}

impl schemars::JsonSchema for VirSourcePort {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "VirSourcePort".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        VirSourcePortRepr::json_schema(generator)
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
    /// Local UDP port the vehicle identification request (VIR) is sent from and
    /// the responses are received on. Either a port (`0` lets the operating
    /// system choose) or an inclusive range `"start-end"` from which a free port
    /// is picked. ISO 13400-2 requires a port within `"49152-65535"` (default).
    /// Setting it to `gateway_port` restores the legacy behavior of sending the
    /// VIR from the discovery port. Spontaneous VAMs are always received on
    /// `gateway_port`. A single port is retried 3 times, 200 ms apart, a range
    /// tries each of its ports once. If no port can be bound, an error is logged
    /// and no VIR is sent; `DoIP` communication is still enabled and gateways are
    /// connected by VAMs or directly. The VIR search of the persisted reconnect
    /// uses this setting as well.
    pub vir_source_port: VirSourcePort,
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
    /// Only available in builds with the `doip-direct-connect` feature. If set
    /// without that feature, an error is logged and the operation remains unavailable.
    pub direct_connect_enabled: bool,
    /// How gateways are discovered on the network, once communication has been
    /// initialized (independent of `communication.init_mode`):
    /// - `Disabled`: no VIR, VAMs are ignored and persisted gateways are not
    ///   reconnected. ECUs are only connected through an explicit direct-connect
    ///   request.
    /// - `VamOnly`: no VIR, neither at startup nor as a fallback. VAMs are handled
    ///   as `communication.vam_handling_mode` allows. Persisted gateways are
    ///   reconnected by unicast; one that cannot be connected is reported
    ///   unreachable.
    /// - `Full`: broadcast a VIR on startup and handle VAMs as
    ///   `communication.vam_handling_mode` allows. A persisted gateway that cannot
    ///   be reached at its persisted address is searched by VIR.
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
    /// the first connection is attempted, so this is checked when the transport is
    /// enabled (not at process start, the interface may only come up later).
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
            vir_source_port: VirSourcePort::default(),
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

        fn validate_vir_source_port(
            port: VirSourcePort,
            field: &str,
        ) -> Result<(), ConfigSanityError> {
            if let VirSourcePort::Range { start, end } = port
                && (start == 0 || start > end)
            {
                return Err(ConfigSanityError::InvalidValue {
                    field: field.to_owned(),
                    reason: format!(
                        "Invalid port range {start}-{end}, start must be greater than 0 and not \
                         greater than end"
                    ),
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
        validate_ip(&self.tester_subnet, "tester_subnet")?;
        validate_port(self.gateway_port, "gateway_port")?;
        validate_port(self.tls_port, "tls_port")?;
        validate_vir_source_port(self.vir_source_port, "vir_source_port")?;
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

    use super::{DiscoveryMode, DoipConfig, VirSourcePort};

    #[derive(serde::Deserialize)]
    struct PortHolder {
        port: VirSourcePort,
    }

    fn parse_toml_like(value: &str) -> Result<VirSourcePort, serde_json::Error> {
        serde_json::from_str::<PortHolder>(&format!("{{\"port\": {value}}}")).map(|h| h.port)
    }

    #[test]
    fn vir_source_port_defaults_to_dynamic_range() {
        assert_eq!(
            DoipConfig::default().vir_source_port,
            VirSourcePort::Range {
                start: 49152,
                end: 65535
            }
        );
    }

    #[test]
    fn vir_source_port_deserializes_port_zero_and_range() {
        assert_eq!(parse_toml_like("0").unwrap(), VirSourcePort::Port(0));
        assert_eq!(
            parse_toml_like("13400").unwrap(),
            VirSourcePort::Port(13400)
        );
        assert_eq!(
            parse_toml_like("\"50000\"").unwrap(),
            VirSourcePort::Port(50000)
        );
        assert_eq!(
            parse_toml_like("\"50000 - 50010\"").unwrap(),
            VirSourcePort::Range {
                start: 50000,
                end: 50010
            }
        );
    }

    #[test]
    fn vir_source_port_rejects_invalid_values() {
        for value in [
            "\"50010-50000\"",
            "\"0-10\"",
            "\"abc\"",
            "\"1-70000\"",
            "70000",
        ] {
            assert!(parse_toml_like(value).is_err(), "{value} must be rejected");
        }
    }

    #[test]
    fn vir_source_port_round_trips() {
        for port in [
            VirSourcePort::Port(0),
            VirSourcePort::Port(13400),
            VirSourcePort::default(),
        ] {
            let json = serde_json::to_string(&port).unwrap();
            assert_eq!(parse_toml_like(&json).unwrap(), port);
        }
    }

    #[test]
    fn vir_source_port_dynamic_range_check() {
        assert!(VirSourcePort::Port(0).is_in_dynamic_range());
        assert!(VirSourcePort::Port(49152).is_in_dynamic_range());
        assert!(!VirSourcePort::Port(13400).is_in_dynamic_range());
        assert!(VirSourcePort::default().is_in_dynamic_range());
        assert!(
            !VirSourcePort::Range {
                start: 40000,
                end: 50000
            }
            .is_in_dynamic_range()
        );
    }

    #[test]
    fn sanity_rejects_inverted_vir_source_port_range() {
        let config = DoipConfig {
            vir_source_port: VirSourcePort::Range {
                start: 50010,
                end: 50000,
            },
            ..Default::default()
        };
        assert!(config.validate_sanity().is_err());
    }

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
