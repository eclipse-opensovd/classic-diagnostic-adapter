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
        let key = trimmed.get(..eq_pos).map(str::trim)?;
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

    #[test]
    fn generate_reference_config_parses_as_valid_config() {
        use figment::{
            Figment,
            providers::{Format, Serialized, Toml},
        };

        use crate::config::configfile::ConfigSanity;

        let reference = generate_reference_config().unwrap();
        let config: crate::config::configfile::Configuration =
            Figment::from(Serialized::defaults(crate::config::default_config()))
                .merge(Toml::string(&reference))
                .extract()
                .expect("generated reference config should be parseable as a valid Configuration");
        config
            .validate_sanity()
            .expect("parsed reference config should pass sanity validation");
    }

    /// Collect all leaf property paths from the JSON Schema.
    /// A "leaf" is a property that, after resolving `$ref`, has no nested `properties`.
    fn collect_schema_leaf_paths(
        node: &serde_json::Value,
        defs: &serde_json::Value,
        prefix: &str,
    ) -> Vec<String> {
        let resolved = resolve_ref(node, defs);

        let Some(properties) = resolved.get("properties").and_then(|p| p.as_object()) else {
            return Vec::new();
        };

        properties
            .iter()
            .flat_map(|(key, value)| {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };

                let resolved_value = resolve_ref(value, defs);
                let children = collect_schema_leaf_paths(resolved_value, defs, &path);

                if children.is_empty() {
                    vec![path]
                } else {
                    children
                }
            })
            .collect()
    }

    fn collect_toml_paths(value: &toml::Value, prefix: &str) -> Vec<String> {
        match value {
            toml::Value::Table(table) => table
                .iter()
                .flat_map(|(key, val)| {
                    let path = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{prefix}.{key}")
                    };

                    let mut paths = vec![path.clone()];
                    paths.extend(collect_toml_paths(val, &path));
                    paths
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Verify that every config property has a doc-comment description.
    /// If this test fails, a struct field is missing a `///` doc comment.
    /// schemars uses doc comments to populate the `description` field in the JSON Schema,
    /// which is then used to generate the reference configuration documentation.
    #[test]
    fn all_config_properties_have_descriptions() {
        let schema = schemars::schema_for!(Configuration);
        let schema_json =
            serde_json::to_value(&schema).expect("schema serialization should succeed");

        let defs = schema_json
            .get("$defs")
            .or_else(|| schema_json.get("definitions"))
            .cloned()
            .unwrap_or(serde_json::Value::Object(serde_json::Map::default()));

        let schema_paths = collect_schema_leaf_paths(&schema_json, &defs, "");
        let desc_map = build_description_map(&schema_json);

        // Filter out secs and nanos, because otherwise the test will complain
        // that the description for these fields is missing
        // i.e.
        // Add doc comments to the corresponding struct fields:
        //   - com_params.doip.connection_retry_delay.default.nanos
        let missing: Vec<&str> = schema_paths
            .iter()
            .filter(|path| !desc_map.contains_key(*path))
            .filter(|path| {
                !std::path::Path::new(path)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("secs"))
                    && !std::path::Path::new(path)
                        .extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("nanos"))
            })
            .map(String::as_str)
            .collect();

        assert!(
            missing.is_empty(),
            "The following config properties are missing doc-comment descriptions.\nAdd /// doc \
             comments to the corresponding struct fields:\n  - {}",
            missing.join("\n  - ")
        );
    }

    /// Verify generated config matches committed `opensovd-cda.toml` for the enabled
    /// feature subset. Compares structurally so feature-gated sections that are
    /// absent from the build are simply skipped.
    ///
    /// Fix with: `cargo run --all-features -- generate-config --output opensovd-cda.toml`
    #[test]
    fn generate_reference_config_matches_committed_file() {
        let generated = generate_reference_config().unwrap();

        let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .find(|p| p.join("Cargo.lock").exists())
            .expect("could not find workspace root (Cargo.lock)");
        let committed = std::fs::read_to_string(workspace_root.join("opensovd-cda.toml")).unwrap();

        if generated == committed {
            return;
        }

        let gen_sections = extract_value_lines_by_section(&generated);
        let com_sections = extract_value_lines_by_section(&committed);

        for (section, gen_lines) in &gen_sections {
            let com_lines = com_sections.get(section).unwrap_or_else(|| {
                panic!(
                    "Section {section} not found in committed opensovd-cda.toml. Regenerate with: \
                     cargo run --all-features -- generate-config --output opensovd-cda.toml"
                )
            });
            assert_eq!(
                gen_lines, com_lines,
                "Value lines in section {section} differ. Regenerate with: cargo run \
                 --all-features -- generate-config --output opensovd-cda.toml"
            );
        }
    }

    /// Extract commented-out key=value lines grouped by section header.
    /// Ignores doc-comment lines (lines without `=` that aren't inside a multiline array).
    fn extract_value_lines_by_section(text: &str) -> BTreeMap<String, Vec<String>> {
        let mut sections: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut current_section = String::new();
        let mut bracket_depth: usize = 0;

        for line in text.lines() {
            let trimmed = line.trim();

            if bracket_depth == 0 && is_toml_section_header(trimmed) {
                current_section = trimmed.to_owned();
                sections.entry(current_section.clone()).or_default();
                continue;
            }

            let Some(uncommented) = trimmed.strip_prefix("# ") else {
                continue;
            };

            if bracket_depth > 0 {
                sections
                    .entry(current_section.clone())
                    .or_default()
                    .push(uncommented.to_owned());
                bracket_depth =
                    bracket_depth.saturating_add(uncommented.chars().filter(|&c| c == '[').count());
                bracket_depth =
                    bracket_depth.saturating_sub(uncommented.chars().filter(|&c| c == ']').count());
            } else if uncommented.contains(" = ") {
                sections
                    .entry(current_section.clone())
                    .or_default()
                    .push(uncommented.to_owned());
                bracket_depth =
                    bracket_depth.saturating_add(uncommented.chars().filter(|&c| c == '[').count());
                bracket_depth =
                    bracket_depth.saturating_sub(uncommented.chars().filter(|&c| c == ']').count());
            }
        }
        sections
    }

    /// Verify that `reference_config_instance()` populates all optional fields defined
    /// in the schema. If this test fails, a new `Option<T>` field was added to a config
    /// struct but not given an example value in `reference_config_instance()`.
    #[test]
    fn reference_config_covers_all_schema_fields() {
        let schema = schemars::schema_for!(Configuration);
        let schema_json =
            serde_json::to_value(&schema).expect("schema serialization should succeed");

        let defs = schema_json
            .get("$defs")
            .or_else(|| schema_json.get("definitions"))
            .cloned()
            .unwrap_or(serde_json::Value::Object(serde_json::Map::default()));

        let schema_paths = collect_schema_leaf_paths(&schema_json, &defs, "");

        let toml_value = toml::Value::try_from(reference_config_instance())
            .expect("reference config serialization should succeed");
        let toml_paths: std::collections::HashSet<String> =
            collect_toml_paths(&toml_value, "").into_iter().collect();

        let missing: Vec<&str> = schema_paths
            .iter()
            .filter(|path| !toml_paths.contains(*path))
            .map(String::as_str)
            .collect();

        assert!(
            missing.is_empty(),
            "The following schema fields are missing from reference_config_instance().\nAdd \
             example values for these fields so they appear in the generated reference config:\n  \
             - {}",
            missing.join("\n  - ")
        );
    }
}
