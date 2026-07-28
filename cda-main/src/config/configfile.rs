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

// `CanConfig` is always available: the `config` module of cda-comm-can is not
// gated on the `can` feature, only the SocketCAN transport code is. This keeps
// the configuration schema (and all public function signatures that mention
// `CanConfig`) identical across feature combinations, which matters because
// cargo feature unification can otherwise produce mismatched signatures
// between crates (e.g. integration-tests vs. opensovd_cda_lib under
// `--all-features`). A `[can]` section in a non-`can` build is rejected with
// an actionable error in `Configuration::validate_sanity` instead.
pub use cda_comm_can::{
    TransportType,
    config::{CanConfig, CanEcuMapping, TransportOverride},
};
pub use cda_comm_doip::config::DoipConfig;
pub use cda_database::DatabaseConfig;
use cda_interfaces::{
    FunctionalDescriptionConfig, HashMap,
    config::{ConfigSanity, ConfigSanityError},
    datatypes::{
        ComParams, ComponentsConfig, FaultConfig, FlatbBufConfig, SdBoolMappings,
        SdMappingsTruthyValue,
    },
};
pub use cda_plugin_runtime_update::config::RuntimeUpdateConfig;
use serde::{Deserialize, Serialize};

pub use super::com_params::EcuComParams;

/// Strict-mode flags that opt in to stricter runtime validation.
///
/// When `enabled` is `true`, every individual check is activated regardless
/// of its own value.  Individual flags can also be turned on independently
/// for more granular control.
#[derive(Deserialize, Serialize, Clone, Debug, Default, schemars::JsonSchema)]
pub struct StrictConfig {
    /// Master switch - when `true`, all individual strict checks are enabled.
    pub enabled: bool,
    /// Reject requests containing parameters not defined in the diagnostic
    /// service with a `BadPayload` error (HTTP 400).
    pub parameter_validation: bool,
    /// Exit with an error if any key under `[ecu.<name>]` does not match a
    /// loaded MDD database.
    pub ecu_config: bool,
}

impl StrictConfig {
    #[must_use]
    pub fn parameter_validation(&self) -> bool {
        self.enabled || self.parameter_validation
    }

    #[must_use]
    pub fn ecu_config(&self) -> bool {
        self.enabled || self.ecu_config
    }
}

/// Top-level application configuration.
#[derive(Deserialize, Serialize, Clone, Debug, schemars::JsonSchema)]
pub struct Configuration {
    /// SOVD HTTP server bind settings.
    pub server: ServerConfig,
    /// `DoIP` (Diagnostics over IP) transport layer settings.
    pub doip: DoipConfig,
    /// Optional CAN bus transport configuration.
    /// When enabled, the adapter can communicate with ECUs over CAN bus.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub can: Option<CanConfig>,
    /// Diagnostic database loading and naming settings.
    pub database: DatabaseConfig,
    /// Logging, file output, and tracing backend settings.
    pub logging: cda_tracing::LoggingConfig,
    /// Path to the directory containing flash files.
    pub flash_files_path: String,
    /// Default communication parameters for UDS and `DoIP` protocols.
    pub com_params: ComParams,
    /// `FlatBuffers` verification settings for MDD database parsing.
    pub flat_buf: FlatbBufConfig,
    /// Functional group description and lookup settings.
    pub functional_description: FunctionalDescriptionConfig,
    /// Component response customization.
    pub components: ComponentsConfig,
    /// Health check endpoint settings.
    #[cfg(feature = "health")]
    pub health: cda_health::config::HealthConfig,
    /// DTC (Diagnostic Trouble Code) fault memory settings.
    pub faults: FaultConfig,
    /// Per-ECU configuration blocks keyed by ECU short name (case-insensitive
    /// match against the MDD short name returned by `load_proto_data`).
    pub ecu: HashMap<String, EcuConfig>,
    /// Configuration for update plugin, i.e. storage paths
    pub runtime_update_config: RuntimeUpdateConfig,
    /// Strict-mode validation flags.
    pub strict: StrictConfig,
}

/// Per-ECU configuration block.
#[derive(Deserialize, Serialize, Clone, Debug, Default, schemars::JsonSchema)]
pub struct EcuConfig {
    /// Per-ECU communication parameter overrides, merged over the global
    /// `com_params` at database load time.  Only explicitly specified fields
    /// override the global values.
    #[serde(default)]
    pub com_params: Option<EcuComParams>,
    /// When `true`, overrides `database.ignore_protocol` for this ECU only.
    #[serde(default)]
    pub ignore_protocol: Option<bool>,
    /// Override the protocol short-name used to look up the protocol layer in
    /// the MDD for this ECU.  Replaces the global `doip.protocol_name`.
    #[serde(default)]
    pub protocol: Option<String>,
}

/// SOVD HTTP server bind configuration.
#[derive(Deserialize, Serialize, Clone, Debug, schemars::JsonSchema)]
pub struct ServerConfig {
    /// IP address the server listens on.
    pub address: String,
    /// TCP port the server listens on.
    pub port: u16,
}
impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            address: "0.0.0.0".to_owned(),
            port: 20002,
        }
    }
}

impl Default for Configuration {
    fn default() -> Self {
        Configuration {
            database: DatabaseConfig::default(),
            flash_files_path: ".".to_owned(),
            server: ServerConfig::default(),
            #[cfg(feature = "health")]
            health: cda_health::config::HealthConfig::default(),
            doip: DoipConfig {
                tester_address: "10.2.1.240".to_owned(),
                ..Default::default()
            },
            can: None,
            logging: cda_tracing::LoggingConfig::default(),
            com_params: ComParams::default(),
            flat_buf: FlatbBufConfig::default(),
            functional_description: FunctionalDescriptionConfig::default(),
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
            runtime_update_config: RuntimeUpdateConfig::default(),
            strict: StrictConfig::default(),
        }
    }
}

impl Configuration {
    /// A CDA without any transport cannot talk to a single ECU; refuse to
    /// start instead of serving a healthy-looking API that can do nothing.
    fn validate_transport_presence(&self) -> Result<(), ConfigSanityError> {
        // CAN support is compile-time optional. The config type itself parses
        // in every build (see the `CanConfig` re-export above), so reject a
        // configured [can] section here with an actionable message instead of
        // failing later during gateway setup.
        #[cfg(not(feature = "can"))]
        if self.can.is_some() {
            return Err(ConfigSanityError::InvalidValue {
                field: "can".to_owned(),
                reason: "[can] is configured, but this binary was built without CAN support. \
                         Rebuild with `--features can` or remove the [can] section."
                    .to_owned(),
            });
        }

        if !self.doip.enabled && self.can.is_none() {
            return Err(ConfigSanityError::InvalidValue {
                field: "doip.enabled".to_owned(),
                reason: "No transport configured: doip.enabled = false and no [can] section. \
                         Enable DoIP or configure CAN."
                    .to_owned(),
            });
        }
        Ok(())
    }

    /// CAN ECU mappings must be unambiguous: a duplicate ECU name silently
    /// loses one mapping, two ECUs sharing an arbitration-ID pair open two
    /// ISO-TP sockets on identical IDs (cross-talk with undefined delivery),
    /// and `request_id == response_id` makes an ECU answer itself. All three
    /// are config footguns that are expensive to debug from the bus side.
    fn validate_can_mappings(&self) -> Result<(), ConfigSanityError> {
        let Some(ref can) = self.can else {
            return Ok(());
        };

        let mut names = cda_interfaces::HashSet::default();
        let mut id_pairs = cda_interfaces::HashSet::default();
        for mapping in &can.ecu_mappings {
            if mapping.request_id == mapping.response_id {
                return Err(ConfigSanityError::InvalidValue {
                    field: "can.ecu_mappings".to_owned(),
                    reason: format!(
                        "ECU '{}' uses the same CAN ID {:#X} as request_id and response_id",
                        mapping.ecu_name, mapping.request_id
                    ),
                });
            }
            if !names.insert(mapping.ecu_name.to_lowercase()) {
                return Err(ConfigSanityError::InvalidValue {
                    field: "can.ecu_mappings".to_owned(),
                    reason: format!(
                        "Duplicate mapping for ECU '{}' (names are matched case-insensitively)",
                        mapping.ecu_name
                    ),
                });
            }
            if !id_pairs.insert((mapping.request_id, mapping.response_id)) {
                return Err(ConfigSanityError::InvalidValue {
                    field: "can.ecu_mappings".to_owned(),
                    reason: format!(
                        "ECU '{}' reuses the CAN ID pair {:#X}/{:#X} of another mapping",
                        mapping.ecu_name, mapping.request_id, mapping.response_id
                    ),
                });
            }
        }
        Ok(())
    }

    /// Transport pins must be satisfiable: a pin to a transport that cannot
    /// serve the ECU would only surface as `EcuOffline` at runtime.
    fn validate_transport_overrides(&self) -> Result<(), ConfigSanityError> {
        let Some(ref can) = self.can else {
            return Ok(());
        };
        for transport_override in &can.transport_overrides {
            match transport_override.transport {
                // A pin to CAN is validated at gateway setup, not here: the
                // ECU may get its CAN addressing from the MDD com-params,
                // which the config layer cannot see.
                cda_comm_can::TransportType::Can => {}
                cda_comm_can::TransportType::DoIP => {
                    if !self.doip.enabled {
                        return Err(ConfigSanityError::InvalidValue {
                            field: "can.transport_overrides".to_owned(),
                            reason: format!(
                                "Pins ECU '{}' to DoIP, but doip.enabled = false",
                                transport_override.ecu_name
                            ),
                        });
                    }
                }
            }
        }
        Ok(())
    }
}

impl ConfigSanity for Configuration {
    fn validate_sanity(&self) -> Result<(), ConfigSanityError> {
        self.database.naming_convention.validate_sanity()?;
        self.doip.validate_sanity()?;
        self.validate_transport_presence()?;
        self.validate_can_mappings()?;
        self.validate_transport_overrides()?;

        // Add more checks for Configuration fields here if needed
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
nack_number_of_retries.value = {"0x03" = 42, "0x04" = 43}
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
                .value
                .get("0x03"),
            Some(&42)
        );
        assert_eq!(
            config
                .com_params
                .doip
                .nack_number_of_retries
                .value
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

    /// A `[can]` section must parse in every build (the config type is not
    /// feature-gated), but `validate_sanity` must reject it when the binary
    /// was built without CAN support.
    #[tokio::test]
    async fn can_section_parses_and_sanity_depends_on_feature()
    -> Result<(), Box<dyn std::error::Error>> {
        let config_str = r#"
[can]
interface = "vcan0"
"#;
        let figment = Figment::from(Serialized::defaults(Configuration::default()))
            .merge(Toml::string(config_str));
        let config: Configuration = figment.extract()?;
        let can = config.can.as_ref().expect("can section should be parsed");
        assert_eq!(can.interface, "vcan0");

        #[cfg(feature = "can")]
        config
            .validate_sanity()
            .expect("can section should pass sanity with can feature");
        #[cfg(not(feature = "can"))]
        {
            let err = config
                .validate_sanity()
                .expect_err("can section should fail sanity without can feature");
            assert!(
                err.to_string().contains("--features can"),
                "error should tell the user how to enable CAN support, got: {err}"
            );
        }
        Ok(())
    }

    /// Ambiguous `[[can.ecu_mappings]]` configurations must be rejected:
    /// duplicate ECU names, reused arbitration-ID pairs, and
    /// `request_id == response_id` all lead to silent misbehavior on the bus.
    #[cfg(feature = "can")]
    #[tokio::test]
    async fn can_ecu_mappings_sanity_rejects_ambiguity() -> Result<(), Box<dyn std::error::Error>> {
        async fn config_with_mappings(
            mappings: &str,
        ) -> Result<Configuration, Box<dyn std::error::Error>> {
            let config_str = format!(
                r#"
[can]
interface = "vcan0"
{mappings}"#
            );
            let figment = Figment::from(Serialized::defaults(Configuration::default()))
                .merge(Toml::string(&config_str));
            Ok(figment.extract()?)
        }

        let valid = config_with_mappings(
            r#"
[[can.ecu_mappings]]
ecu_name = "ECU1"
request_id = 0x7E0
response_id = 0x7E8

[[can.ecu_mappings]]
ecu_name = "ECU2"
request_id = 0x7E1
response_id = 0x7E9
"#,
        )
        .await?;
        valid
            .validate_sanity()
            .expect("distinct mappings should pass sanity");

        let duplicate_name = config_with_mappings(
            r#"
[[can.ecu_mappings]]
ecu_name = "ECU1"
request_id = 0x7E0
response_id = 0x7E8

[[can.ecu_mappings]]
ecu_name = "ecu1"
request_id = 0x7E1
response_id = 0x7E9
"#,
        )
        .await?;
        let err = duplicate_name
            .validate_sanity()
            .expect_err("case-insensitive duplicate ECU name should fail sanity");
        assert!(err.to_string().contains("Duplicate mapping"), "got: {err}");

        let duplicate_pair = config_with_mappings(
            r#"
[[can.ecu_mappings]]
ecu_name = "ECU1"
request_id = 0x7E0
response_id = 0x7E8

[[can.ecu_mappings]]
ecu_name = "ECU2"
request_id = 0x7E0
response_id = 0x7E8
"#,
        )
        .await?;
        let err = duplicate_pair
            .validate_sanity()
            .expect_err("reused CAN ID pair should fail sanity");
        assert!(err.to_string().contains("CAN ID pair"), "got: {err}");

        let self_answering = config_with_mappings(
            r#"
[[can.ecu_mappings]]
ecu_name = "ECU1"
request_id = 0x7E0
response_id = 0x7E0
"#,
        )
        .await?;
        let err = self_answering
            .validate_sanity()
            .expect_err("request_id == response_id should fail sanity");
        assert!(
            err.to_string().contains("request_id and response_id"),
            "got: {err}"
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
    async fn load_config_toml_service_affixes_hex_keys() -> Result<(), Box<dyn std::error::Error>> {
        let config_str = r#"
[database.naming_convention]
short_name_affix_position = "Suffix"
long_name_affix_position = "Suffix"

[database.naming_convention.service_affixes]
0x31 = ["Suffix", ["_start", "_stop", "_requestresults", "_start_func", "_stop_func", "_requestresults_func"]]
0x85 = ["Prefix", ["DTC_Setting_Mode_"]]
"#;

        let figment = Figment::from(Serialized::defaults(Configuration::default()))
            .merge(Toml::string(config_str));
        let config: Configuration = figment.extract()?;

        assert_eq!(
            config
                .database
                .naming_convention
                .service_affixes
                .get(&0x31u8.to_string()),
            Some(&(
                DiagnosticServiceAffixPosition::Suffix,
                vec![
                    "_start".to_owned(),
                    "_stop".to_owned(),
                    "_requestresults".to_owned(),
                    "_start_func".to_owned(),
                    "_stop_func".to_owned(),
                    "_requestresults_func".to_owned(),
                ]
            ))
        );
        assert_eq!(
            config
                .database
                .naming_convention
                .service_affixes
                .get(&0x85u8.to_string()),
            Some(&(
                DiagnosticServiceAffixPosition::Prefix,
                vec!["DTC_Setting_Mode_".to_owned()]
            ))
        );
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

    #[test]
    fn schemars_captures_doc_comments() {
        let schema = schemars::schema_for!(DatabaseConfig);
        let schema_json = serde_json::to_value(&schema).unwrap();
        let desc = schema_json
            .get("properties")
            .and_then(|v| v.get("exit_no_database_loaded"))
            .and_then(|v| v.get("description"))
            .and_then(|v| v.as_str())
            .expect("description should be present");
        assert!(
            desc.contains("the application will exit if no database could be loaded"),
            "Expected doc comment in description, got: {desc}"
        );
    }

    #[test]
    fn strict_config_master_switch_enables_all() {
        let cfg = StrictConfig {
            enabled: true,
            parameter_validation: false,
            ecu_config: false,
        };
        assert!(cfg.parameter_validation());
        assert!(cfg.ecu_config());
    }

    #[test]
    fn strict_config_individual_flags_work_independently() {
        let cfg = StrictConfig {
            enabled: false,
            parameter_validation: true,
            ecu_config: false,
        };
        assert!(cfg.parameter_validation());
        assert!(!cfg.ecu_config());
    }

    #[test]
    fn strict_config_defaults_to_all_disabled() {
        let cfg = StrictConfig::default();
        assert!(!cfg.parameter_validation());
        assert!(!cfg.ecu_config());
    }

    #[tokio::test]
    async fn strict_config_parsed_from_toml() {
        let config_str = r"
[strict]
enabled = false
parameter_validation = true
";
        let figment = Figment::from(Serialized::defaults(Configuration::default()))
            .merge(Toml::string(config_str));
        let config: Configuration = figment.extract().unwrap();
        assert!(config.strict.parameter_validation());
        assert!(!config.strict.ecu_config());
    }
}
