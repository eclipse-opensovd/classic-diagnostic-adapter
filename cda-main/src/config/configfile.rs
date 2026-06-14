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

// `CanConfig` is always available: the `config` module of cda-comm-can is not
// gated on the `can` feature, only the SocketCAN transport code is. This keeps
// the configuration schema (and all public function signatures that mention
// `CanConfig`) identical across feature combinations, which matters because
// cargo feature unification can otherwise produce mismatched signatures
// between crates (e.g. integration-tests vs. opensovd_cda_lib under
// `--all-features`). A `[can]` section in a non-`can` build is rejected with
// an actionable error in `Configuration::validate_sanity` instead.
pub use cda_comm_can::config::{CanConfig, CanEcuMapping};
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

use crate::AppError;

/// Type-safe per-ECU communication parameter overrides.
///
/// Internally stores a partial TOML table (only the keys the user explicitly
/// wrote) so that Figment merge semantics can layer them on top of the global
/// [`ComParams`].  The public API exposes typed construction and the JSON schema
/// reflects the full [`ComParams`] structure for documentation/validation.
#[derive(Clone, Debug)]
pub struct EcuComParams(pub(crate) toml::Table);

/// Construct per-ECU overrides from a fully-typed [`ComParams`].
///
/// All fields in the provided `ComParams` will be serialized and will
/// override the corresponding global values at resolve time.
///
/// # Errors
/// Returns an error if `params` cannot be serialized to a TOML table.
impl TryFrom<ComParams> for EcuComParams {
    type Error = toml::ser::Error;
    fn try_from(com_params: ComParams) -> Result<Self, Self::Error> {
        let value = toml::Value::try_from(com_params)?;
        let table = value
            .as_table()
            .cloned()
            .expect("ComParams must serialize to a TOML table");
        Ok(Self(table))
    }
}

impl Serialize for EcuComParams {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EcuComParams {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use figment::providers::Format as _;

        let table = toml::Table::deserialize(deserializer)?;

        // Validate: the partial table must be merge-compatible with ComParams.
        let toml_str = toml::to_string(&table).map_err(serde::de::Error::custom)?;
        let validated: ComParams = figment::Figment::from(
            figment::providers::Serialized::defaults(ComParams::default()),
        )
        .merge(figment::providers::Toml::string(&toml_str))
        .extract()
        .map_err(serde::de::Error::custom)?;

        // Detect silently-ignored keys by round-tripping through the typed ComParams.
        // Any input key that doesn't appear in the re-serialized output was unknown to
        // the schema and would be silently dropped at resolve time.
        let reference = toml::Value::try_from(&validated).map_err(serde::de::Error::custom)?;
        let reference_table = reference
            .as_table()
            .ok_or_else(|| serde::de::Error::custom("Serialized ComParams is not a table"))?;
        let unknown = find_unknown_keys(&table, reference_table, "");
        if !unknown.is_empty() {
            return Err(serde::de::Error::custom(format!(
                "unknown com_param field(s) (possible typo): {unknown}",
                unknown = unknown.join(", ")
            )));
        }

        Ok(Self(table))
    }
}

fn find_unknown_keys(input: &toml::Table, reference: &toml::Table, prefix: &str) -> Vec<String> {
    let mut unknown = Vec::new();
    for (key, value) in input {
        let full_path = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        match reference.get(key) {
            None => unknown.push(full_path),
            Some(ref_value) => {
                if let (toml::Value::Table(input_sub), toml::Value::Table(ref_sub)) =
                    (value, ref_value)
                {
                    unknown.extend(find_unknown_keys(input_sub, ref_sub, &full_path));
                }
            }
        }
    }
    unknown
}

impl Default for EcuComParams {
    fn default() -> Self {
        Self(toml::Table::new())
    }
}

impl schemars::JsonSchema for EcuComParams {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        <ComParams as schemars::JsonSchema>::schema_name()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        <ComParams as schemars::JsonSchema>::json_schema(generator)
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
    #[serde(default)]
    pub ecu: HashMap<String, EcuConfig>,
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

pub trait ConfigSanity {
    /// Checks the configuration for common mistakes and returns an error message if found.
    /// # Errors
    /// Returns `Err(String)` if a sanity check fails, with a descriptive error message.
    fn validate_sanity(&self) -> Result<(), AppError>;
}

impl Default for Configuration {
    fn default() -> Self {
        Configuration {
            database: DatabaseConfig {
                path: ".".to_owned(),
                naming_convention: DatabaseNamingConvention::default(),
                exit_no_database_loaded: false,
                fallback_to_base_variant: true,
                ignore_protocol: false,
                strict_ecu_config: false,
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
            can: None,
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
        // CAN support is compile-time optional. The config type itself parses
        // in every build (see the `CanConfig` re-export above), so reject a
        // configured [can] section here with an actionable message instead of
        // failing later during gateway setup.
        #[cfg(not(feature = "can"))]
        if self.can.is_some() {
            return Err(AppError::ConfigurationError(
                "[can] is configured, but this binary was built without CAN support. Rebuild with \
                 `--features can` or remove the [can] section."
                    .to_owned(),
            ));
        }
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

    fn parse_ecu_com_params(toml_str: &str) -> Result<EcuComParams, toml::de::Error> {
        toml::from_str(toml_str)
    }

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

    #[tokio::test]
    async fn load_config_toml_per_ecu_com_params() {
        let config_str = r"
[ecu.TMCC3000.com_params.doip.logical_gateway_address]
value = 12288

[ecu.TMCC3000.com_params.doip.logical_functional_address]
value = 65535
";
        let figment = Figment::from(Serialized::defaults(Configuration::default()))
            .merge(Toml::string(config_str));
        let config: Configuration = figment.extract().expect("Failed to parse config file");

        let tmcc = config
            .ecu
            .get("TMCC3000")
            .expect("TMCC3000 ecu config should be present");
        let ecu_com_params = tmcc.com_params.as_ref().expect("com_params should be Some");
        let resolved =
            crate::resolve_com_params("TMCC3000", &config.com_params, Some(ecu_com_params))
                .expect("resolve should succeed");

        assert_eq!(
            resolved.doip.logical_gateway_address.value, 12288u16,
            "logical_gateway_address.default should be 12288"
        );
        assert_eq!(
            resolved.doip.logical_functional_address.value, 65535u16,
            "logical_functional_address.default should be 65535"
        );
    }

    /// A per-ECU field that IS set in the TOML overrides the global value.
    #[tokio::test]
    async fn ecu_com_params_override_replaces_global_field() {
        // Global has logical_gateway_address.value = 0 (Rust default).
        // Per-ECU table sets it to 12288.
        let ecu_toml = r"
[doip.logical_gateway_address]
value = 12288
";
        let ecu_overrides = parse_ecu_com_params(ecu_toml).expect("Failed to parse ECU com params");
        let global = ComParams::default();
        let effective = crate::resolve_com_params("test", &global, Some(&ecu_overrides))
            .expect("Resolve should succeed");

        assert_eq!(
            effective.doip.logical_gateway_address.value, 12288u16,
            "Per-ECU override should replace global logical_gateway_address.default"
        );
    }

    /// A per-ECU field that is NOT set in the TOML retains the global value.
    #[tokio::test]
    async fn ecu_com_params_unset_field_retains_global_value() {
        // Global has logical_gateway_address.value = 0x1234.
        // Per-ECU table only sets logical_functional_address.
        let ecu_toml = r"
[doip.logical_functional_address]
value = 9999
";
        let ecu_overrides = parse_ecu_com_params(ecu_toml).expect("Failed to parse ECU com params");
        let mut global = ComParams::default();
        global.doip.logical_gateway_address.value = 0x1234u16;

        let effective = crate::resolve_com_params("test", &global, Some(&ecu_overrides))
            .expect("resolve should succeed");

        assert_eq!(
            effective.doip.logical_gateway_address.value, 0x1234u16,
            "unset per-ECU field should retain global value"
        );
        assert_eq!(
            effective.doip.logical_functional_address.value, 9999u16,
            "set per-ECU field should override global"
        );
    }

    #[tokio::test]
    async fn ecu_com_params_precedence_config_survives_figment_merge() {
        let ecu_toml = r#"
[doip.logical_gateway_address]
value = 12288
precedence = "Config"
"#;
        let ecu_overrides = parse_ecu_com_params(ecu_toml).expect("Failed to parse ECU com params");
        let global = ComParams::default();
        let effective = crate::resolve_com_params("test", &global, Some(&ecu_overrides))
            .expect("resolve should succeed");

        assert_eq!(
            effective.doip.logical_gateway_address.precedence,
            cda_interfaces::datatypes::ComParamPrecedence::Config,
            "precedence = Config should survive figment merge"
        );
    }

    #[tokio::test]
    async fn ecu_com_params_precedence_defaults_to_database_when_unset() {
        let ecu_toml = r"
[doip.logical_gateway_address]
value = 12288
";
        let ecu_overrides = parse_ecu_com_params(ecu_toml).expect("Failed to parse ECU com params");
        let global = ComParams::default();
        let effective = crate::resolve_com_params("test", &global, Some(&ecu_overrides))
            .expect("resolve should succeed");

        assert_eq!(
            effective.doip.logical_gateway_address.precedence,
            cda_interfaces::datatypes::ComParamPrecedence::Database,
            "precedence should default to Database when not set in TOML"
        );
    }

    #[test]
    fn ecu_com_params_rejects_unknown_field() {
        // timeout_daefault is spelled wrong, should be timeout_default
        let typo_toml = r#"
[uds.timeout_daefault]
name = "CP_P6Max"
precedence = "Config"

[uds.timeout_daefault.default]
secs = 5
nanos = 0
"#;
        let result = parse_ecu_com_params(typo_toml);
        assert!(
            result.is_err(),
            "should reject unknown field 'timeout_daefault'"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("timeout_daefault"),
            "error should name the offending field, got: {err}"
        );
    }

    #[test]
    fn ecu_com_params_rejects_leaf_typo() {
        let typo_toml = r"
[uds.timeout_default.value]
secnds = 5
nanos = 0
";
        let result = parse_ecu_com_params(typo_toml);
        assert!(result.is_err(), "should reject unknown leaf key 'secss'");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("secnds"),
            "error should name the offending key, got: {err}"
        );
    }

    /// Validates that the figment extraction error path is reachable: when the
    /// per-ECU TOML contains a scalar where a struct is expected, `extract` fails.
    /// This anchors the `Err(e) => { ...; return None }` branch in
    /// `resolve_com_params` to a real, reproducible input without requiring
    /// access to the private function itself.
    #[test]
    fn figment_extraction_fails_on_incompatible_type_in_ecu_table() {
        let global = ComParams::default();

        // A plain scalar where figment expects the ComParamConfig struct.
        let bad_toml = r"
[doip]
logical_gateway_address = 9999
";
        let result = Figment::from(Serialized::defaults(&global))
            .merge(Toml::string(bad_toml))
            .extract::<ComParams>();

        assert!(
            result.is_err(),
            "figment extraction must fail when the TOML contains an incompatible type; confirms \
             the resolve_com_params Err branch is reachable"
        );
    }
}
