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

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct DoipConfig {
    pub protocol_version: u8,
    pub tester_address: String,
    pub tester_subnet: String,
    pub gateway_port: u16,
    pub send_timeout_ms: u64,
    pub send_diagnostic_message_ack: bool,
}

impl Default for DoipConfig {
    fn default() -> Self {
        Self {
            protocol_version: 0x02,
            tester_address: "127.0.0.1".to_owned(),
            tester_subnet: "255.255.0.0".to_owned(),
            gateway_port: 13400,
            send_timeout_ms: 1000,
            send_diagnostic_message_ack: true,
        }
    }
}
