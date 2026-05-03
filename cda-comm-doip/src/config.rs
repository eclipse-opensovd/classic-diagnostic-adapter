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

use cda_interfaces::Protocol;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct DoipConfig {
    pub protocol_version: u8,
    pub tester_address: String,
    pub tester_subnet: String,
    pub gateway_port: u16,
    pub tls_port: u16,
    pub send_timeout_ms: u64,
    pub send_diagnostic_message_ack: bool,
    pub protocol_name: String,
}

impl Default for DoipConfig {
    fn default() -> Self {
        Self {
            protocol_version: 0x02,
            tester_address: "127.0.0.1".to_owned(),
            tester_subnet: "255.255.0.0".to_owned(),
            gateway_port: 13400,
            tls_port: 3496,
            send_timeout_ms: 1000,
            send_diagnostic_message_ack: true,
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
