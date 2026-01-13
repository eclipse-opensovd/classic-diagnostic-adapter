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

pub use cda_comm_doip::config::DoipConfig;
use cda_interfaces::{
    FunctionalDescriptionConfig,
    datatypes::{
        ComParams, DatabaseNamingConvention, DiagnosticServiceAffixPosition, FlatbBufConfig,
    },
};
use serde::{Deserialize, Serialize};

use crate::AppError;

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Configuration {
    pub server: ServerConfig,
    pub doip: DoipConfig,
    pub database: DatabaseConfig,
    pub logging: cda_tracing::LoggingConfig,
    pub onboard_tester: bool,
    pub flash_files_path: String,
    pub com_params: ComParams,
    pub flat_buf: FlatbBufConfig,
    pub functional_description: FunctionalDescriptionConfig,
    #[cfg(feature = "health")]
    pub health: cda_health::config::HealthConfig,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct ServerConfig {
    pub address: String,
    pub port: u16,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct DatabaseConfig {
    pub path: String,
    pub naming_convention: DatabaseNamingConvention,
    /// If true, the application will exit if no database could be loaded.
    pub exit_no_database_loaded: bool,
}

pub trait ConfigSanity {
    /// Checks the configuration for common mistakes and returns an error message if found.
    /// # Errors
    /// Returns `Err(String)` if a sanity check fails, with a descriptive error message.
    fn validate_sanity(&self) -> Result<(), AppError>;
}

impl Default for Configuration {
    fn default() -> Self {
        Configuration {
            onboard_tester: true,
            database: DatabaseConfig {
                path: ".".to_owned(),
                naming_convention: DatabaseNamingConvention::default(),
                exit_no_database_loaded: false,
            },
            flash_files_path: ".".to_owned(),
            server: ServerConfig {
                address: "0.0.0.0".to_owned(),
                port: 20002,
            },
            #[cfg(feature = "health")]
            health: cda_health::config::HealthConfig::default(),
            doip: DoipConfig {
                tester_address: "10.2.1.240".to_owned(),
                tester_subnet: "255.255.0.0".to_owned(),
                gateway_port: 13400,
                send_timeout_ms: 1000,
            },
            logging: cda_tracing::LoggingConfig::default(),
            com_params: ComParams::default(),
            flat_buf: FlatbBufConfig::default(),
            functional_description: FunctionalDescriptionConfig {
                description_database: "functional_groups".to_owned(),
                enabled_functional_groups: None,
                protocol_position:
                    cda_interfaces::datatypes::DiagnosticServiceAffixPosition::Suffix,
                protocol_case_sensitive: false,
            },
        }
    }
}

impl ConfigSanity for Configuration {
    fn validate_sanity(&self) -> Result<(), AppError> {
        self.database.naming_convention.validate_sanity()?;
        // Add more checks for Configuration fields here if needed
        Ok(())
    }
}

impl ConfigSanity for DatabaseNamingConvention {
    fn validate_sanity(&self) -> Result<(), AppError> {
        const SHORT_NAME_AFFIX_KEY: &str = "database_naming_convention.short_name_affixes";
        const LONG_NAME_AFFIX_KEY: &str = "database_naming_convention.long_name_affixes";

        // Check short name affixes
        for affix in &self.short_name_affixes {
            match self.short_name_affix_position {
                DiagnosticServiceAffixPosition::Prefix => {
                    if affix.starts_with(' ') {
                        return Err(AppError::ConfigurationError(format!(
                            "{SHORT_NAME_AFFIX_KEY}: '{affix}' has leading whitespace"
                        )));
                    }
                }
                DiagnosticServiceAffixPosition::Suffix => {
                    if affix.ends_with(' ') {
                        return Err(AppError::ConfigurationError(format!(
                            "{SHORT_NAME_AFFIX_KEY}: '{affix}' has trailing whitespace"
                        )));
                    }
                }
            }
        }

        // Check long name affixes
        for affix in &self.long_name_affixes {
            match self.long_name_affix_position {
                DiagnosticServiceAffixPosition::Prefix => {
                    if affix.starts_with(' ') {
                        return Err(AppError::ConfigurationError(format!(
                            "{LONG_NAME_AFFIX_KEY}: '{affix}' has leading whitespace"
                        )));
                    }
                }
                DiagnosticServiceAffixPosition::Suffix => {
                    if affix.ends_with(' ') {
                        return Err(AppError::ConfigurationError(format!(
                            "{LONG_NAME_AFFIX_KEY}: '{affix}' has trailing whitespace"
                        )));
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use cda_interfaces::datatypes::DiagnosticServiceAffixPosition;
    use figment::{
        Figment,
        providers::{Format, Serialized, Toml},
    };

    use super::*;

    #[tokio::test]
    async fn load_config_toml() -> Result<(), Box<dyn std::error::Error>> {
        let config_str = r#"
flash_files_path = "/app/flash"
onboard_tester = true

[database]
path = "/app/database"

[database.naming_convention]
short_name_affix_position = "Prefix"
long_name_affix_position = "Prefix"
configuration_service_parameter_semantic_id = "ID"
short_name_affixes = [ "Read_", "Write_" ]
long_name_affixes = [ "Read ", "Write " ]

[logging.tokio_tracing]
server = "0.0.0.0:6669"

[logging.otel]
enabled = true
endpoint = "http://jaeger:4317"

[com_params.doip]
nack_number_of_retries.default = {"0x03" = 42, "0x04" = 43}
nack_number_of_retries.name = "CP_TEST"

[functional_description]
description_database = "teapot"

"#;

        let figment = Figment::from(Serialized::defaults(Configuration::default()))
            .merge(Toml::string(config_str));
        let config: Configuration = figment.extract()?;
        config.validate_sanity().map_err(|err| err.to_string())?;
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

        assert_eq!(
            config.database.naming_convention.short_name_affix_position,
            DiagnosticServiceAffixPosition::Prefix,
        );

        assert_eq!(
            config.database.naming_convention.long_name_affix_position,
            DiagnosticServiceAffixPosition::Prefix,
        );

        assert_eq!(
            config
                .database
                .naming_convention
                .configuration_service_parameter_semantic_id,
            "ID".to_owned(),
        );
        assert_eq!(
            config.functional_description.description_database,
            "teapot".to_owned()
        );
        Ok(())
    }

    #[tokio::test]
    async fn load_config_toml_sanityfail_short_name() -> Result<(), Box<dyn std::error::Error>> {
        let config_str = r#"
[database.naming_convention]
short_name_affix_position = "Prefix"
short_name_affixes = [ " Read", " Write_" ]
"#;
        let figment = Figment::from(Serialized::defaults(Configuration::default()))
            .merge(Toml::string(config_str));
        let config: Configuration = figment.extract()?;
        assert!(config.validate_sanity().is_err());
        Ok(())
    }

    #[tokio::test]
    async fn load_config_toml_sanityfail_long_name() -> Result<(), Box<dyn std::error::Error>> {
        let config_str = r#"
[database.naming_convention]
long_name_affix_position = "Suffix"
long_name_affixes = [ "Read ", "Write_ " ]
"#;
        let figment = Figment::from(Serialized::defaults(Configuration::default()))
            .merge(Toml::string(config_str));
        let config: Configuration = figment.extract()?;
        assert!(config.validate_sanity().is_err());
        Ok(())
    }
}
