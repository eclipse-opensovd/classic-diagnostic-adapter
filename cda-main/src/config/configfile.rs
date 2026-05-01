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

pub use cda_comm_doip::config::DoipConfig;
pub use cda_database::DatabaseConfig;
use cda_interfaces::{
    FunctionalDescriptionConfig, HashMap,
    datatypes::{
        ComParams, ComponentsConfig, DatabaseNamingConvention, DiagnosticServiceAffixPosition,
        FaultConfig, FlatbBufConfig, SdBoolMappings, SdMappingsTruthyValue,
    },
};
use serde::{Deserialize, Serialize};
use toml::Table;

use crate::AppError;

/// Per-ECU protocol short-name overrides.
///
/// When an ECU's MDD uses non-standard protocol short names (e.g. `"DMC_DoIP"`
/// instead of `"UDS_Ethernet_DoIP"`), set them here so that the CDA resolves
/// com-params and services from the correct protocol layer.
#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct EcuProtocolConfig {
    /// Protocol short name used for UDS / `DoIP` lookups.
    /// Defaults to `"UDS_Ethernet_DoIP"` when absent.
    pub uds: Option<String>,
    /// Protocol short name used for UDS / `DoIP` DOBT lookups.
    /// Defaults to `"UDS_Ethernet_DoIP_DOBT"` when absent.
    pub uds_dobt: Option<String>,
}

/// Per-ECU configuration block.  Keeps room for future per-ECU settings
/// beyond `com_params`.
#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct EcuConfig {
    /// Raw partial TOML for per-ECU `com_params` overrides.  Only fields the user
    /// explicitly writes are present.  Merged over the global `ComParams` at
    /// `load_database` time using the same key hierarchy as `[com_params]`.
    #[serde(default)]
    pub com_params: Option<Table>,
    /// Optional per-ECU protocol short-name overrides.
    #[serde(default)]
    pub protocol: Option<EcuProtocolConfig>,
}

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
    pub components: ComponentsConfig,
    #[cfg(feature = "health")]
    pub health: cda_health::config::HealthConfig,
    pub faults: FaultConfig,
    /// Per-ECU configuration blocks keyed by ECU short name (case-insensitive
    /// match against the MDD short name returned by `load_proto_data`).
    #[serde(default)]
    pub ecu: HashMap<String, EcuConfig>,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct ServerConfig {
    pub address: String,
    pub port: u16,
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
                fallback_to_base_variant: true,
                ignore_protocol: false,
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
                ..Default::default()
            },
            logging: cda_tracing::LoggingConfig::default(),
            com_params: ComParams::default(),
            flat_buf: FlatbBufConfig::default(),
            functional_description: FunctionalDescriptionConfig {
                description_database: "functional_groups".to_owned(),
                enabled_functional_groups: None,
                protocol_position:
                    cda_interfaces::datatypes::DiagnosticServiceAffixPosition::Suffix,
            },
            components: ComponentsConfig {
                additional_fields: HashMap::from_iter([
                    (
                        "x-sovd2uds-can-ecus".into(),
                        SdBoolMappings::from_iter([(
                            "CAN".to_owned(),
                            SdMappingsTruthyValue::new(
                                ["yes"].into_iter().map(ToOwned::to_owned).collect::<_>(),
                                true,
                            ),
                        )]),
                    ),
                    (
                        "x-sovd2uds-lin-ecus".into(),
                        SdBoolMappings::from_iter([(
                            "LIN".to_owned(),
                            SdMappingsTruthyValue::new(
                                ["yes"].into_iter().map(ToOwned::to_owned).collect::<_>(),
                                true,
                            ),
                        )]),
                    ),
                ]),
            },
            faults: FaultConfig::default(),
            ecu: HashMap::default(),
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
        const SERVICE_NAME_AFFIX_KEY: &str = "database_naming_convention.service_name_affixes";

        fn validate_affix(
            affix: &str,
            pos: &DiagnosticServiceAffixPosition,
            key: &str,
        ) -> Result<(), AppError> {
            match pos {
                DiagnosticServiceAffixPosition::Prefix => {
                    if affix.starts_with(' ') {
                        return Err(AppError::ConfigurationError(format!(
                            "{key}: '{affix}' has leading whitespace"
                        )));
                    }
                }
                DiagnosticServiceAffixPosition::Suffix => {
                    if affix.ends_with(' ') {
                        return Err(AppError::ConfigurationError(format!(
                            "{key}: '{affix}' has trailing whitespace"
                        )));
                    }
                }
            }
            Ok(())
        }

        // Check short name affixes
        for affix in &self.short_name_affixes {
            validate_affix(affix, &self.short_name_affix_position, SHORT_NAME_AFFIX_KEY)?;
        }

        // Check long name affixes
        for affix in &self.long_name_affixes {
            validate_affix(affix, &self.long_name_affix_position, LONG_NAME_AFFIX_KEY)?;
        }

        // Validate services affixes
        for (pos, affixes) in self.service_affixes.values() {
            for affix in affixes {
                validate_affix(affix, pos, SERVICE_NAME_AFFIX_KEY)?;
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

[database.naming_convention.service_affixes]
0x10 = ["Prefix", ["Control_"]]

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
        assert_eq!(
            config
                .database
                .naming_convention
                .service_affixes
                .get(&0x10.to_string()),
            Some(&(
                DiagnosticServiceAffixPosition::Prefix,
                vec!["Control_".to_string()]
            ))
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

    #[tokio::test]
    async fn load_config_toml_additional_fields_ignore_case_lowercases_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let config_str = r#"
[components.additional_fields.x-sovd2uds-time-travel-ecus.FluxCapacitor]
values = ["Flux Capacitor Mark II", "Flux Capacitor Mark III", "yes"]
ignore_case = true

[components.additional_fields.x-sovd2uds-power-source-ecus.PowerSource]
values = ["Plutonium", "Mr. Fusion"]
ignore_case = true
"#;
        let figment = Figment::from(Serialized::defaults(Configuration::default()))
            .merge(Toml::string(config_str));
        let config: Configuration = figment.extract()?;

        // Verify the FluxCapacitor additional field was loaded and values match case-insensitively
        let flux_field = config
            .components
            .additional_fields
            .get("x-sovd2uds-time-travel-ecus")
            .expect("x-sovd2uds-time-travel-ecus should exist");
        let flux_mapping = flux_field
            .get("FluxCapacitor")
            .expect("FluxCapacitor mapping should exist");
        assert!(
            flux_mapping.contains("flux capacitor mark ii"),
            "Should match lowercase"
        );
        assert!(
            flux_mapping.contains("Flux Capacitor Mark II"),
            "Should match original case"
        );
        assert!(
            flux_mapping.contains("FLUX CAPACITOR MARK II"),
            "Should match uppercase"
        );
        assert!(flux_mapping.contains("yes"), "Should match lowercase 'yes'");
        assert!(flux_mapping.contains("YES"), "Should match uppercase 'YES'");

        // Verify the PowerSource additional field
        let power_field = config
            .components
            .additional_fields
            .get("x-sovd2uds-power-source-ecus")
            .expect("x-sovd2uds-power-source-ecus should exist");
        let power_mapping = power_field
            .get("PowerSource")
            .expect("PowerSource mapping should exist");
        assert!(power_mapping.contains("Plutonium"));
        assert!(power_mapping.contains("plutonium"));
        assert!(power_mapping.contains("Mr. Fusion"));
        assert!(power_mapping.contains("mr. fusion"));

        Ok(())
    }

    #[tokio::test]
    async fn load_config_toml_per_ecu_com_params() -> Result<(), Box<dyn std::error::Error>> {
        let config_str = r"
[ecu.TMCC3000.com_params.doip.logical_gateway_address]
default = 12288

[ecu.TMCC3000.com_params.doip.logical_functional_address]
default = 65535
";
        let figment = Figment::from(Serialized::defaults(Configuration::default()))
            .merge(Toml::string(config_str));
        let config: Configuration = figment.extract()?;

        let tmcc = config
            .ecu
            .get("TMCC3000")
            .expect("TMCC3000 ecu config should be present");
        let table = tmcc.com_params.as_ref().expect("com_params should be Some");
        assert!(
            table
                .get("doip")
                .and_then(|d| d.as_table())
                .and_then(|d| d.get("logical_gateway_address"))
                .and_then(|g| g.as_table())
                .and_then(|g| g.get("default"))
                .and_then(toml::Value::as_integer)
                == Some(12288),
            "logical_gateway_address.default should be 12288"
        );
        assert!(
            table
                .get("doip")
                .and_then(|d| d.as_table())
                .and_then(|d| d.get("logical_functional_address"))
                .and_then(|g| g.as_table())
                .and_then(|g| g.get("default"))
                .and_then(toml::Value::as_integer)
                == Some(65535),
            "logical_functional_address.default should be 65535"
        );
        Ok(())
    }

    /// A per-ECU field that IS set in the TOML overrides the global value.
    #[tokio::test]
    async fn ecu_com_params_override_replaces_global_field()
    -> Result<(), Box<dyn std::error::Error>> {
        // Global has logical_gateway_address.default = 0 (Rust default).
        // Per-ECU table sets it to 12288.
        let ecu_toml = r"
[doip.logical_gateway_address]
default = 12288
";
        let ecu_table: toml::Table = toml::from_str(ecu_toml)?;
        let global = ComParams::default();
        let effective: ComParams =
            figment::Figment::from(figment::providers::Serialized::defaults(&global))
                .merge(figment::providers::Toml::string(&toml::to_string(
                    &ecu_table,
                )?))
                .extract()?;

        assert_eq!(
            effective.doip.logical_gateway_address.default, 12288u16,
            "per-ECU override should replace global logical_gateway_address.default"
        );
        Ok(())
    }

    /// A per-ECU field that is NOT set in the TOML retains the global value.
    #[tokio::test]
    async fn ecu_com_params_unset_field_retains_global_value()
    -> Result<(), Box<dyn std::error::Error>> {
        // Global has logical_gateway_address.default = 0x1234.
        // Per-ECU table only sets logical_functional_address.
        let ecu_toml = r"
[doip.logical_functional_address]
default = 9999
";
        let ecu_table: toml::Table = toml::from_str(ecu_toml)?;
        let mut global = ComParams::default();
        global.doip.logical_gateway_address.default = 0x1234u16;

        let effective: ComParams =
            figment::Figment::from(figment::providers::Serialized::defaults(&global))
                .merge(figment::providers::Toml::string(&toml::to_string(
                    &ecu_table,
                )?))
                .extract()?;

        assert_eq!(
            effective.doip.logical_gateway_address.default, 0x1234u16,
            "unset per-ECU field should retain global value"
        );
        assert_eq!(
            effective.doip.logical_functional_address.default, 9999u16,
            "set per-ECU field should override global"
        );
        Ok(())
    }
}
