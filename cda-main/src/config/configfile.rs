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

use cda_interfaces::datatypes::ComParams;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Configuration {
    pub server: ServerConfig,
    pub doip: DoipConfig,
    pub logging: cda_tracing::LoggingConfig,
    pub onboard_tester: bool,
    pub databases_path: String,
    pub flash_files_path: String,
    pub com_params: ComParams,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct ServerConfig {
    pub address: String,
    pub port: u16,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct DoipConfig {
    pub tester_address: String,
    pub gateway_port: u16,
}

impl Default for Configuration {
    fn default() -> Self {
        Configuration {
            onboard_tester: true,
            databases_path: ".".to_owned(),
            flash_files_path: ".".to_owned(),
            server: ServerConfig {
                address: "0.0.0.0".to_owned(),
                port: 20002,
            },
            doip: DoipConfig {
                tester_address: "10.2.1.240".to_owned(),
                gateway_port: 13400,
            },
            logging: cda_tracing::LoggingConfig::default(),
            com_params: ComParams::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use figment::{
        Figment,
        providers::{Format, Serialized, Toml},
    };

    use super::*;

    #[tokio::test]
    async fn load_config_toml() {
        let config_str = r#"
databases_path = "/app/database"
flash_files_path = "/app/flash"
onboard_tester = true

[logging.tokio_tracing]
server = "0.0.0.0:6669"

[logging.otel]
enabled = true
endpoint = "http://jaeger:4317"

[com_params.doip]
nack_number_of_retries.default = {"0x03" = 42, "0x04" = 43}
nack_number_of_retries.name = "CP_TEST"

"#;

        let figment = Figment::from(Serialized::defaults(Configuration::default()))
            .merge(Toml::string(config_str));
        let config: Configuration = figment.extract().unwrap();
        assert_eq!(
            config
                .com_params
                .doip
                .nack_number_of_retries
                .default
                .get("0x03"),
            Some(&42)
        );
        assert_eq!(
            config
                .com_params
                .doip
                .nack_number_of_retries
                .default
                .get("0x04"),
            Some(&43)
        );
        assert_eq!(
            config.com_params.doip.nack_number_of_retries.name,
            "CP_TEST"
        );
    }
}
