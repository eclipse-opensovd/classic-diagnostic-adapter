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

use cda_interfaces::Protocol;
use serde::{Deserialize, Serialize};

/// `DoIP` (Diagnostics over IP) transport layer configuration.
#[derive(Deserialize, Serialize, Clone, Debug, schemars::JsonSchema)]
pub struct DoipConfig {
    /// Whether the `DoIP` transport is enabled.
    /// When `false`, CDA skips `DoIP` initialization entirely (useful for
    /// CAN-only or DoIP-less test setups).
    /// Defaults to `true` to preserve the historical DoIP-first behavior.
    #[serde(default = "default_doip_enabled")]
    pub enabled: bool,
    /// `DoIP` protocol version byte (e.g. 0x02 for ISO 13400-2:2012).
    pub protocol_version: u8,
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
    /// The special value `"auto"` defers the choice to the MDD-driven
    /// auto-detect (see `into_db_protocol`).
    pub protocol_name: String,
}

fn default_doip_enabled() -> bool {
    true
}

impl Default for DoipConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            protocol_version: 0x02,
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
