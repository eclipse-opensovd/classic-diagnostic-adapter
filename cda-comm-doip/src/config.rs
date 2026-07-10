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

use cda_config::validate::{ConfigSanity, ConfigSanityError};
use cda_interfaces::Protocol;
use serde::{Deserialize, Serialize};

/// `DoIP` (Diagnostics over IP) transport layer configuration.
#[derive(Deserialize, Serialize, Clone, Debug, schemars::JsonSchema)]
pub struct DoipConfig {
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
    /// The name of the protocol to use.
    /// Matched case-insensitive against the database.
    pub protocol_name: String,
}

impl Default for DoipConfig {
    fn default() -> Self {
        Self {
            tester_address: "127.0.0.1".to_owned(),
            tester_subnet: "255.255.0.0".to_owned(),
            gateway_port: 13400,
            tls_port: 3496,
            send_timeout_ms: 1000,
            send_diagnostic_message_ack: true,
            alive_check_interval_secs: 1800, // 30 minutes
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
    use doip_definitions::header::ProtocolVersion;

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
