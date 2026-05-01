/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

use std::{collections::BTreeMap, fmt::Write};

use cda_interfaces::{FunctionalDescriptionConfig, datatypes::FaultConfig};

use crate::config::configfile::Configuration;

/// Create a Configuration instance with example values for fields that default to `None`.
/// This ensures they appear in the generated reference config output.
fn reference_config_instance() -> Configuration {
    let mut config = Configuration::default();

    config.faults = FaultConfig {
        user_defined_dtc_clear_service: Some(vec![0x31, 0x01, 0x02, 0x46]),
        ..config.faults
    };

    config.functional_description = FunctionalDescriptionConfig {
        enabled_functional_groups: Some(cda_interfaces::HashSet::from_iter([
            "example_group".to_owned()
        ])),
        ..config.functional_description
    };

    #[cfg(feature = "tokio-tracing")]
    {
        config.logging.tokio_tracing.recording_path = Some("/tmp/tokio-recording".to_owned());
    }

    config
}

#[rustfmt::skip]
const SPDX_HEADER: &str = "\
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0

";

/// Errors that can occur during reference config generation.
#[derive(thiserror::Error, Debug)]
pub enum GenerateConfigError {
    #[error("Failed to serialize configuration schema to JSON: {0}")]
    SchemaJson(#[source] serde_json::Error),
    #[error("Failed to serialize reference config to TOML: {0}")]
    TomlValue(#[source] toml::ser::Error),
    #[error("Failed to format TOML as pretty string: {0}")]
    TomlFormat(#[source] toml::ser::Error),
}

/// Generate a fully-commented reference TOML configuration string.
/// All value lines are commented out with `# `. Section headers remain uncommented.
/// Fields with doc comments have their description prepended as a TOML comment.
///
/// # Errors
///
/// Returns an error if the configuration schema cannot be serialized to JSON or TOML.
pub fn generate_reference_config() -> Result<String, GenerateConfigError> {
    let schema = schemars::schema_for!(Configuration);
    let schema_json = serde_json::to_value(&schema).map_err(GenerateConfigError::SchemaJson)?;

    let toml_value = toml::Value::try_from(reference_config_instance())
        .map_err(GenerateConfigError::TomlValue)?;
    let sorted_value = sort_toml_value(toml_value);
    let default_toml =
        toml::to_string_pretty(&sorted_value).map_err(GenerateConfigError::TomlFormat)?;

    let desc_map = build_description_map(&schema_json);

    Ok(format!(
        "{SPDX_HEADER}{}",
        process_toml(&default_toml, &desc_map)
    ))
}

/// Recursively sort all tables in a TOML value by key to ensure deterministic output.
fn sort_toml_value(value: toml::Value) -> toml::Value {
    match value {
        toml::Value::Table(table) => {
            let sorted: toml::map::Map<String, toml::Value> = table
                .into_iter()
                .map(|(k, v)| (k, sort_toml_value(v)))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect();
            toml::Value::Table(sorted)
        }
        toml::Value::Array(arr) => {
            toml::Value::Array(arr.into_iter().map(sort_toml_value).collect())
        }
        other => other,
    }
}

/// Build a map from TOML dotted path (e.g. "server.address") to description string.
fn build_description_map(schema_json: &serde_json::Value) -> BTreeMap<String, String> {
    let defs = schema_json
        .get("$defs")
        .or_else(|| schema_json.get("definitions"))
        .cloned()
        .unwrap_or(serde_json::Value::Object(serde_json::Map::default()));
    walk_schema(schema_json, &defs, "")
}

fn resolve_ref<'a>(
    schema_node: &'a serde_json::Value,
    defs: &'a serde_json::Value,
) -> &'a serde_json::Value {
    schema_node
        .get("$ref")
        .and_then(|v| v.as_str())
        .and_then(|r| {
            r.strip_prefix("#/$defs/")
                .or_else(|| r.strip_prefix("#/definitions/"))
        })
        .and_then(|name| defs.get(name))
        .unwrap_or(schema_node)
}

fn walk_schema(
    node: &serde_json::Value,
    defs: &serde_json::Value,
    prefix: &str,
) -> BTreeMap<String, String> {
    let resolved = resolve_ref(node, defs);

    resolved
        .get("properties")
        .and_then(|p| p.as_object())
        .into_iter()
        .flatten()
        .flat_map(|(key, value)| {
            let path = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{prefix}.{key}")
            };

            let resolved_value = resolve_ref(value, defs);

            let desc_entry = value
                .get("description")
                .or_else(|| resolved_value.get("description"))
                .and_then(|d| d.as_str())
                .map(|desc| (path.clone(), desc.to_string()));

            let children = walk_schema(resolved_value, defs, &path);

            desc_entry.into_iter().chain(children)
        })
        .collect()
}

/// Check if a trimmed line is a TOML section header (e.g. `[section]` or `[[array]]`).
/// Array value lines like `["value"],` also start with `[` but are NOT section headers.
fn is_toml_section_header(trimmed: &str) -> bool {
    if trimmed.starts_with("[[") {
        trimmed.ends_with("]]") && !trimmed.contains('"') && !trimmed.contains(',')
    } else if trimmed.starts_with('[') {
        trimmed.ends_with(']') && !trimmed.contains('"') && !trimmed.contains(',')
    } else {
        false
    }
}

/// Post-process the raw TOML string: comment out value lines, inject descriptions.
fn process_toml(raw_toml: &str, desc_map: &BTreeMap<String, String>) -> String {
    raw_toml
        .lines()
        .scan(Vec::<String>::new(), |section_stack, line| {
            Some(format_toml_line(line, section_stack, desc_map))
        })
        .collect()
}

fn format_toml_line(
    line: &str,
    section_stack: &mut Vec<String>,
    desc_map: &BTreeMap<String, String>,
) -> String {
    let trimmed = line.trim();

    if trimmed.is_empty() {
        return String::from("\n");
    }

    if is_toml_section_header(trimmed) {
        let section_name = trimmed.trim_start_matches('[').trim_end_matches(']');
        *section_stack = section_name.split('.').map(String::from).collect();

        return desc_map
            .get(section_name)
            .into_iter()
            .flat_map(|desc| desc.lines())
            .map(|l| {
                if l.is_empty() {
                    "#".to_owned()
                } else {
                    format!("# {l}")
                }
            })
            .chain(std::iter::once(line.to_owned()))
            .fold(String::new(), |mut acc, l| {
                let _ = writeln!(acc, "{l}");
                acc
            });
    }

    let description = trimmed.find('=').and_then(|eq_pos| {
        let key = trimmed[..eq_pos].trim();
        let full_path = if section_stack.is_empty() {
            key.to_string()
        } else {
            format!("{}.{key}", section_stack.join("."))
        };
        desc_map.get(&full_path)
    });

    description
        .into_iter()
        .flat_map(|desc| desc.lines())
        .map(|l| {
            if l.is_empty() {
                "#".to_owned()
            } else {
                format!("# {l}")
            }
        })
        .chain(std::iter::once(format!("# {line}")))
        .fold(String::new(), |mut acc, l| {
            let _ = writeln!(acc, "{l}");
            acc
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_reference_config_is_non_empty() {
        let result = generate_reference_config().unwrap();
        assert!(!result.is_empty(), "output should not be empty");
        assert!(result.contains("[server]"), "should have [server] section");
        assert!(result.contains("[doip]"), "should have [doip] section");
    }

    #[test]
    fn generate_reference_config_all_values_commented() {
        let result = generate_reference_config().unwrap();
        for line in result.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.starts_with('[') && !trimmed.contains('"') && !trimmed.contains(',') {
                continue;
            }
            assert!(
                trimmed.starts_with('#'),
                "Non-section line should start with '#': {line}"
            );
        }
    }

    #[test]
    fn generate_reference_config_has_doc_comments() {
        let result = generate_reference_config().unwrap();
        assert!(
            result.contains("the application will exit if no database could be loaded"),
            "Should contain doc comment for exit_no_database_loaded"
        );
    }

    #[test]
    fn generate_reference_config_is_deterministic() {
        let result1 = generate_reference_config().unwrap();
        let result2 = generate_reference_config().unwrap();
        assert_eq!(result1, result2, "output should be deterministic");
    }

    #[test]
    fn generate_reference_config_has_option_fields() {
        let result = generate_reference_config().unwrap();
        assert!(
            result.contains("user_defined_dtc_clear_service"),
            "Should contain user_defined_dtc_clear_service"
        );
        assert!(
            result.contains("enabled_functional_groups"),
            "Should contain enabled_functional_groups"
        );
    }

    #[test]
    fn generate_reference_config_has_no_feature_notes() {
        let result = generate_reference_config().unwrap();
        assert!(
            !result.contains("# NOTE: Requires feature"),
            "Should not contain feature requirement notes"
        );
    }
}
