/*
 * Copyright (c) 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
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

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealthConfig {
    pub address: String,
    pub port: u16,
    pub enabled: bool,
    pub exit_process_on_error: bool,
}

impl Default for HealthConfig {
    fn default() -> Self {
        HealthConfig {
            address: "127.0.0.1".to_owned(),
            port: 20020,
            enabled: true,
            exit_process_on_error: false,
        }
    }
}
