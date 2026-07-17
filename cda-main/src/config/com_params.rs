/*
 * SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation
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

use cda_interfaces::datatypes::{ComParams, ComParamsPatch};
use serde::{Deserialize, Serialize};
use struct_patch::Patch;

/// Compute the effective [`ComParams`] for a single ECU.
///
/// Starts from the global `global` config and merges any per-ECU TOML overrides
/// present in `ecu_table`.
///
/// Returns `None` (and emits a `tracing::error!`) if the TOML table cannot be //TODO update
/// serialised or if figment extraction fails - the caller should `continue` to
/// the next ECU.
pub fn resolve_com_params(
    ecu_name: &str, //TODO remove
    global: &ComParams,
    ecu_overrides: Option<&EcuComParams>,
) -> Option<ComParams> { //TODO always return ComParams
    let params: ComParams = match ecu_overrides {
        None => global.clone(),
        Some(overrides) => {
            let mut global = global.clone();
            Patch::apply(&mut global, overrides.0.clone());
            global
        }
    };

    Some(params)
}

/// Type-safe per-ECU communication parameter overrides.
///
/// Internally stores a partial TOML table (only the keys the user explicitly //TODO update
/// wrote) so that Figment merge semantics can layer them on top of the global
/// [`ComParams`].  The public API exposes typed construction and the JSON schema
/// reflects the full [`ComParams`] structure for documentation/validation.
#[derive(Clone, Debug)]
pub struct EcuComParams(pub(crate) ComParamsPatch);

/// Construct per-ECU overrides from a fully-typed [`ComParams`].
///
/// All fields in the provided `ComParams` will be serialized and will
/// override the corresponding global values at resolve time.
///
/// # Errors
/// Returns an error if `params` cannot be serialized to a TOML table.
impl TryFrom<ComParams> for EcuComParams {
    type Error = toml::ser::Error;
    fn try_from(com_params: ComParams) -> Result<Self, Self::Error> { //TODO try_from → from
        Ok(Self(Patch::into_patch(com_params)))
    }
}

impl Serialize for EcuComParams {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EcuComParams {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        ComParamsPatch::deserialize(deserializer)
            .map(Self)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::configfile::Configuration;

//     #[tokio::test]
//     async fn load_config_toml_per_ecu_com_params() { //TODO
//         let config_str = r"
// [ecu.TMCC3000.com_params.doip.logical_gateway_address]
// value = 12288
//
// [ecu.TMCC3000.com_params.doip.logical_functional_address]
// value = 65535
// ";
//         let figment = Figment::from(Serialized::defaults(Configuration::default()))
//             .merge(Toml::string(config_str));
//         let config: Configuration = figment.extract().expect("Failed to parse config file");
//
//         let tmcc = config
//             .ecu
//             .get("TMCC3000")
//             .expect("TMCC3000 ecu config should be present");
//         let ecu_com_params = tmcc.com_params.as_ref().expect("com_params should be Some");
//         let resolved = resolve_com_params("TMCC3000", &config.com_params, Some(ecu_com_params))
//             .expect("resolve should succeed");
//
//         assert_eq!(
//             resolved.doip.logical_gateway_address.value, 12288u16,
//             "logical_gateway_address.default should be 12288"
//         );
//         assert_eq!(
//             resolved.doip.logical_functional_address.value, 65535u16,
//             "logical_functional_address.default should be 65535"
//         );
//     }

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
        let effective = resolve_com_params("test", &global, Some(&ecu_overrides))
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

        let effective = resolve_com_params("test", &global, Some(&ecu_overrides))
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
        let effective = resolve_com_params("test", &global, Some(&ecu_overrides))
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
        let effective = resolve_com_params("test", &global, Some(&ecu_overrides))
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
[doip]

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

    fn parse_ecu_com_params(toml_str: &str) -> Result<EcuComParams, toml::de::Error> {
        toml::from_str(toml_str)
    }
}
