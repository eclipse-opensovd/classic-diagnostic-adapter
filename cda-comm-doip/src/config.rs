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

/// `DoIP` (Diagnostics over IP) transport layer configuration.
#[derive(Deserialize, Serialize, Clone, Debug, schemars::JsonSchema)]
pub struct DoipConfig {
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
        }
    }
}
