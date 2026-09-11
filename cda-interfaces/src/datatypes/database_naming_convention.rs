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
use serde::{Deserialize, Serialize};

use crate::{
    DiagCommAction, HashMap,
    config::{ConfigSanity, ConfigSanityError},
    service_ids,
    util::serde_ext,
};

/// Holds configuration for diagnostic service naming conventions.
///
/// # Fields
/// - `short_name_affix_position`: Position of affixes in short names (prefix or suffix).
/// - `long_name_affix_position`: Position of affixes in long names (prefix or suffix).
/// - `configuration_service_parameter_semantic_id`: Parameter semantic used to distinguish
///   between different services in configurations
/// - `configuration_functional_classes`: Functional class names for filtering services that
///   are routed to `/configurations` instead of `/data`.
/// - `category_mapping`: Maps a functional class name to a `/data` category for 0x22/0x2E
///   services that are *not* routed to `/configurations`. A functional class must not appear
///   both here and in `configuration_functional_classes`.
/// - `default_category`: Fallback category used for 0x22/0x2E services whose functional class
///   is not present in `category_mapping` (and not in `configuration_functional_classes`).
/// - `short_name_affixes`: List of lowercase affixes for short names.
///   **Each affix must match the specified `short_name_affix_position`
///   (i.e., be a prefix if `Prefix`, or a suffix if `Suffix`).**
///   Order matters: compound affixes (e.g. `_read_dump`) must come before general ones
///   (e.g. `_dump`).
/// - `long_name_affixes`: List of lowercase affixes for long names.
///   **Each affix must match the specified `long_name_affix_position`
///   (i.e., be a prefix if `Prefix`, or a suffix if `Suffix`).**
///   Order matters: compound affixes (e.g. ` read dump`) must come before general ones
///   (e.g. `dump`).
///  - `service_affixes`: List of affixes that apply only to the given service.
///    This can be used to remove additional things from a service name during lookup.
///    All affixes share the same position (prefix or suffix).
///    Keys support both decimal (`"133"`) and hexadecimal (`"0x85"` / `"0X85"`) service IDs.
///    Example: The service is named `DTC_Settings_Mode_Off`, but "off" is passed via SOVD.
///    To match the service configure, `[0x85, (Prefix, ["Dtc_Settings_Mode_"])]`
///
/// Common affixes (e.g. `read`, `write`) should be placed first for performance, but compound
/// affixes must precede their base forms for correct matching.
///
#[derive(Deserialize, Serialize, Clone, Debug, schemars::JsonSchema)]
pub struct DatabaseNamingConvention {
    /// Position of affixes in diagnostic service short names.
    pub short_name_affix_position: DiagnosticServiceAffixPosition,
    /// Position of affixes in diagnostic service long names.
    pub long_name_affix_position: DiagnosticServiceAffixPosition,
    /// Semantic ID used to identify the distinguishing parameter of a service.
    pub configuration_service_parameter_semantic_id: String,
    /// Functional class names used to route 0x22/0x2E services to `/configurations`.
    pub configuration_functional_classes: Vec<String>,
    /// Maps a functional class name to a `/data` category for 0x22/0x2E services that are not
    /// routed to `/configurations`. A functional class must not appear both here and in
    /// `configuration_functional_classes`.
    #[serde(default)]
    pub category_mapping: Vec<FunctionalClassCategoryMapping>,
    /// Fallback category for 0x22/0x2E services whose functional class has no entry in
    /// `category_mapping`.
    #[serde(default = "default_category")]
    pub default_category: String,
    /// Ordered list of lowercase affixes to strip from short names during service lookup.
    ///
    /// Compound affixes (e.g. `_read_dump`) must come before general ones (e.g. `_dump`).
    pub short_name_affixes: Vec<String>,
    /// Ordered list of lowercase affixes to strip from long names during service lookup.
    ///
    /// Compound affixes (e.g. ` read dump`) must come before general ones (e.g. `dump`).
    pub long_name_affixes: Vec<String>,
    /// Per-service-ID affixes for additional name stripping during lookup.
    ///
    /// The key is the UDS service ID as a string and can be decimal (`"133"`) or hex
    /// (`"0x85"` / `"0X85"`); keys are normalized internally to decimal strings.
    /// Each entry specifies the affix position and a list of affixes.
    // technically key should be u8, but it's not supported for toml parse / figment.
    // it will be validated in the validate sanity function
    #[serde(deserialize_with = "serde_ext::normalized_u8_key_map::deserialize")]
    pub service_affixes: HashMap<String, (DiagnosticServiceAffixPosition, Vec<String>)>,
    /// Protocol short-names that identify diagnostics-over-CAN in the MDD,
    /// matched case-insensitively. When the configured protocol name is one
    /// of these but the database has no layer of exactly that name, protocol
    /// resolution tries the other entries in order. OEM databases with
    /// different protocol names configure their own list.
    #[serde(default = "default_can_protocol_aliases")]
    pub can_protocol_aliases: Vec<String>,
    /// Case-insensitive substrings that mark a protocol short-name as
    /// diagnostics-over-CAN during `"auto-can"` protocol detection.
    #[serde(default = "default_can_protocol_markers")]
    pub can_protocol_markers: Vec<String>,
    /// Affixes used to derive a service lookup name from a [`DiagCommAction`].
    ///
    /// These are applied when a [`crate::DiagComm`] has no explicit `lookup_name`
    /// and the lookup name must be derived from the diagnostic communication's
    /// action (read, write, start, request results, stop).
    #[serde(default)]
    pub action_affixes: DiagCommActionAffixes,
    /// Database semantics to identify the type of service
    pub semantics: Semantics,
}

/// Maps a single ODX functional class name to a `/data` category.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, schemars::JsonSchema)]
pub struct FunctionalClassCategoryMapping {
    /// The ODX functional class short name (case-insensitive match).
    pub functional_class: String,
    /// The category to assign to 0x22/0x2E services belonging to this functional class.
    pub category: String,
}

fn default_category() -> String {
    "x-sovd2uds-unmapped".to_owned()
}

/// Defines the name for the database semantics. Although they should follow the labels
/// defined in the standards, in practice some OEM deviate from this.
#[derive(Deserialize, Serialize, Clone, Debug, schemars::JsonSchema)]
pub struct Semantics {
    /// Semantic to identify `data` parameter within a UDS response, by matching the
    ///  parameter semantic against this value.
    pub data: String,
    /// Semantic to identify the `request id` parameter within a UDS response,
    /// by matching the parameter semantic against this value.
    pub service_id_rq: String,
    /// Semantic for `session` services. Used to lookup services and state charts that
    /// control the `session` of an ECU.
    pub session: String,
    /// Semantic for `security` services. Used to lookup services and state charts that
    /// control the `security` (level) of an ECU.
    pub security: String,
}

impl Default for Semantics {
    fn default() -> Self {
        Self {
            data: "DATA".to_owned(),
            service_id_rq: "SERVICEIDRQ".to_owned(),
            session: "SESSION".to_owned(),
            security: "SECURITY".to_owned(),
        }
    }
}

impl ConfigSanity for DatabaseNamingConvention {
    fn validate_sanity(&self) -> Result<(), ConfigSanityError> {
        const SHORT_NAME_AFFIX_KEY: &str = "database_naming_convention.short_name_affixes";
        const LONG_NAME_AFFIX_KEY: &str = "database_naming_convention.long_name_affixes";
        const SERVICE_NAME_AFFIX_KEY: &str = "database_naming_convention.service_name_affixes";

        fn validate_affix(
            affix: &str,
            pos: &DiagnosticServiceAffixPosition,
            key: &str,
        ) -> Result<(), ConfigSanityError> {
            match pos {
                DiagnosticServiceAffixPosition::Prefix => {
                    if affix.starts_with(' ') {
                        return Err(ConfigSanityError::InvalidValue {
                            field: key.to_owned(),
                            reason: format!("'{affix}' has leading whitespace"),
                        });
                    }
                }
                DiagnosticServiceAffixPosition::Suffix => {
                    if affix.ends_with(' ') {
                        return Err(ConfigSanityError::InvalidValue {
                            field: key.to_owned(),
                            reason: format!("'{affix}' has trailing whitespace"),
                        });
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

        // A functional class must not be routed to /configurations and also have a category
        // mapping to /data at the same time.
        for mapping in &self.category_mapping {
            if self
                .configuration_functional_classes
                .iter()
                .any(|fc| fc.eq_ignore_ascii_case(&mapping.functional_class))
            {
                return Err(ConfigSanityError::InvalidValue {
                    field: "database_naming_convention.category_mapping".to_owned(),
                    reason: format!(
                        "functional class '{}' is present in both \
                         'configuration_functional_classes' and 'category_mapping'",
                        mapping.functional_class
                    ),
                });
            }
        }

        Ok(())
    }
}

impl DatabaseNamingConvention {
    /// Returns `true` if the given functional class name is configured to route 0x22/0x2E
    /// services to `/configurations` instead of `/data`.
    #[must_use]
    pub fn is_configuration_functional_class(&self, functional_class_name: &str) -> bool {
        self.configuration_functional_classes
            .iter()
            .any(|fc| fc.eq_ignore_ascii_case(functional_class_name))
    }

    /// Resolves the `/data` category for a 0x22/0x2E service belonging to the given functional
    /// class, using the configured `category_mapping`, falling back to `default_category` if no
    /// entry matches.
    #[must_use]
    pub fn category_for_functional_class(&self, functional_class_name: &str) -> &str {
        self.category_mapping
            .iter()
            .find(|mapping| {
                mapping
                    .functional_class
                    .eq_ignore_ascii_case(functional_class_name)
            })
            .map_or(self.default_category.as_str(), |mapping| {
                mapping.category.as_str()
            })
    }

    /// Trims a diagnostic service long name using the configured affixes and naming position.
    /// The first matching affix is removed and the result is returned.
    /// Affixes must be lowercase for correct matching.
    /// Returns the trimmed name or the original if no affix matches.
    #[must_use]
    pub fn trim_long_name_affixes(&self, long_name: &str) -> String {
        let long_name_lowercase = long_name.to_lowercase();
        for affix in &self.long_name_affixes {
            if self.long_name_affix_position == DiagnosticServiceAffixPosition::Prefix
                && long_name_lowercase.starts_with(affix)
            {
                return long_name
                    .get(affix.len()..)
                    .unwrap_or(long_name)
                    .to_string();
            }
            if self.long_name_affix_position == DiagnosticServiceAffixPosition::Suffix
                && long_name_lowercase.ends_with(affix)
            {
                return long_name
                    .get(..long_name.len().saturating_sub(affix.len()))
                    .unwrap_or(long_name)
                    .to_string();
            }
        }
        long_name.to_string()
    }

    /// Trims a diagnostic service short name using the configured affixes and naming position.
    /// The first matching affix is removed and the result is returned.
    /// Affixes must be lowercase for correct matching.
    /// Returns the trimmed name or the original if no affix matches.
    #[must_use]
    pub fn trim_short_name_affixes(&self, short_name: &str) -> String {
        let short_name_lowercase = short_name.to_lowercase();
        for affix in &self.short_name_affixes {
            if self.short_name_affix_position == DiagnosticServiceAffixPosition::Prefix
                && short_name_lowercase.starts_with(affix)
            {
                return short_name
                    .get(affix.len()..)
                    .unwrap_or(short_name)
                    .to_string();
            }
            if self.short_name_affix_position == DiagnosticServiceAffixPosition::Suffix
                && short_name_lowercase.ends_with(affix)
            {
                return short_name
                    .get(..short_name.len().saturating_sub(affix.len()))
                    .unwrap_or(short_name)
                    .to_string();
            }
        }
        short_name.to_string()
    }

    #[must_use]
    pub fn trim_service_name_affixes(&self, service_id: u8, short_name: String) -> String {
        let Some((position, affixes)) = self.service_affixes.get(&service_id.to_string()) else {
            return short_name;
        };
        let short_name_lowercase = short_name.to_lowercase();
        for affix in affixes {
            let affix_lowercase = affix.to_lowercase();
            if *position == DiagnosticServiceAffixPosition::Prefix
                && short_name_lowercase.starts_with(affix_lowercase.as_str())
            {
                return short_name
                    .get(affix.len()..)
                    .unwrap_or(&short_name)
                    .to_string();
            }
            if *position == DiagnosticServiceAffixPosition::Suffix
                && short_name_lowercase.ends_with(affix_lowercase.as_str())
            {
                return short_name
                    .get(..short_name.len().saturating_sub(affix.len()))
                    .unwrap_or(&short_name)
                    .to_string();
            }
        }
        short_name
    }

    /// Trims affixes from a routine control service name to derive the base routine name.
    #[must_use]
    pub fn trim_routine_name(&self, name: &str) -> String {
        let name_trimmed =
            self.trim_service_name_affixes(service_ids::ROUTINE_CONTROL, name.to_owned());
        self.trim_short_name_affixes(&name_trimmed)
    }

    /// Derives a service lookup name from a base name and a [`DiagCommAction`].
    ///
    /// The action-specific affix configured in [`Self::action_affixes`] is applied
    /// at the configured position (prefix or suffix). Used when a `DiagComm` has no
    /// explicit `lookup_name`.
    #[must_use]
    pub fn apply_action_affix(&self, name: &str, action: &DiagCommAction) -> String {
        let affix = match action {
            DiagCommAction::Read => &self.action_affixes.read,
            DiagCommAction::Write => &self.action_affixes.write,
            DiagCommAction::Start => &self.action_affixes.start,
            DiagCommAction::RequestResults => &self.action_affixes.request_results,
            DiagCommAction::Stop => &self.action_affixes.stop,
        };
        match self.action_affixes.position {
            DiagnosticServiceAffixPosition::Prefix => format!("{affix}{name}"),
            DiagnosticServiceAffixPosition::Suffix => format!("{name}{affix}"),
        }
    }
}

impl Default for DatabaseNamingConvention {
    /// Creates a default configuration that assumes data is suffixed, with '_dump' as
    /// the last suffix for short names, followed by '_write' or '_read'.
    /// '`configuration_service_parameter_semantic_id`'
    /// is used to identify the parameter of a service
    /// that distinguishes services from each other.
    /// The long name is the description; the same trimming rules apply.
    fn default() -> Self {
        Self {
            short_name_affix_position: DiagnosticServiceAffixPosition::Suffix,
            long_name_affix_position: DiagnosticServiceAffixPosition::Suffix,
            configuration_service_parameter_semantic_id: "ID".to_owned(),
            configuration_functional_classes: vec!["varcoding".to_owned()],
            category_mapping: Vec::new(),
            default_category: default_category(),
            short_name_affixes: vec![
                "_read".to_owned(),
                "_write".to_owned(),
                "_read_dump".to_owned(),
                "_write_dump".to_owned(),
                "_dump".to_owned(),
                "_read_func".to_owned(),
                "_write_func".to_owned(),
                "_read_dump_func".to_owned(),
                "_write_dump_func".to_owned(),
                "_dump_func".to_owned(),
                "_control_func".to_owned(),
                "_control".to_owned(),
            ],
            long_name_affixes: vec![
                " read".to_owned(),
                " write".to_owned(),
                " read dump".to_owned(),
                " write dump".to_owned(),
                " dump".to_owned(),
                " read func".to_owned(),
                " write func".to_owned(),
                " read dump func".to_owned(),
                " write dump func".to_owned(),
                " dump func".to_owned(),
                " control func".to_owned(),
                " control".to_owned(),
            ],
            service_affixes: HashMap::from_iter([
                (
                    service_ids::CONTROL_DTC_SETTING.to_string(),
                    (
                        DiagnosticServiceAffixPosition::Prefix,
                        vec!["DTC_Setting_Mode_".to_owned()],
                    ),
                ),
                (
                    service_ids::ROUTINE_CONTROL.to_string(),
                    (
                        DiagnosticServiceAffixPosition::Suffix,
                        vec![
                            "_start".to_owned(),
                            "_stop".to_owned(),
                            "_requestresults".to_owned(),
                            "_start_func".to_owned(),
                            "_stop_func".to_owned(),
                            "_requestresults_func".to_owned(),
                        ],
                    ),
                ),
            ]),
            can_protocol_aliases: [
                "UDS_CAN",
                "ISO_11898_2_DWCAN",
                "ISO_11898_3_DWFTCAN",
                "CAN",
                "ISO_15765_2",
                "ISO_15765_3",
            ]
            .map(str::to_owned)
            .to_vec(),
            can_protocol_markers: ["CAN", "ISO_11898"].map(str::to_owned).to_vec(),
            semantics: Semantics::default(),
            action_affixes: DiagCommActionAffixes::default(),
        }
    }
}

fn default_can_protocol_aliases() -> Vec<String> {
    DatabaseNamingConvention::default().can_protocol_aliases
}

fn default_can_protocol_markers() -> Vec<String> {
    DatabaseNamingConvention::default().can_protocol_markers
}

/// Position of a naming affix relative to the diagnostic service name.
#[derive(Deserialize, Serialize, PartialEq, Clone, Debug, schemars::JsonSchema)]
pub enum DiagnosticServiceAffixPosition {
    /// Affix appears before the service name.
    Prefix,
    /// Affix appears after the service name.
    Suffix,
}

/// Per-action affixes used to derive a service lookup name from a base name and a
/// [`DiagCommAction`].
///
/// All affixes share the same [`Self::position`] (prefix or suffix). They are
/// applied when a [`crate::DiagComm`] has no explicit `lookup_name` and the lookup
/// name must be derived from the diagnostic communication's action.
#[derive(Deserialize, Serialize, Clone, Debug, schemars::JsonSchema)]
pub struct DiagCommActionAffixes {
    /// Position of the action affixes relative to the service name.
    pub position: DiagnosticServiceAffixPosition,
    /// Affix applied for [`DiagCommAction::Read`].
    pub read: String,
    /// Affix applied for [`DiagCommAction::Write`].
    pub write: String,
    /// Affix applied for [`DiagCommAction::Start`].
    pub start: String,
    /// Affix applied for [`DiagCommAction::RequestResults`].
    pub request_results: String,
    /// Affix applied for [`DiagCommAction::Stop`].
    pub stop: String,
}

impl Default for DiagCommActionAffixes {
    /// Creates a default configuration that suffixes the base name with the action,
    /// e.g. `_Read`, `_Write`, `_Start`, `_RequestResults`, `_Stop`.
    fn default() -> Self {
        Self {
            position: DiagnosticServiceAffixPosition::Suffix,
            read: "_Read".to_owned(),
            write: "_Write".to_owned(),
            start: "_Start".to_owned(),
            request_results: "_RequestResults".to_owned(),
            stop: "_Stop".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_convention(prefix: bool) -> DatabaseNamingConvention {
        DatabaseNamingConvention {
            short_name_affix_position: if prefix {
                DiagnosticServiceAffixPosition::Prefix
            } else {
                DiagnosticServiceAffixPosition::Suffix
            },
            long_name_affix_position: if prefix {
                DiagnosticServiceAffixPosition::Prefix
            } else {
                DiagnosticServiceAffixPosition::Suffix
            },
            configuration_service_parameter_semantic_id: "ID".to_owned(),
            configuration_functional_classes: vec!["varcoding".to_owned()],
            category_mapping: Vec::new(),
            default_category: default_category(),
            short_name_affixes: if prefix {
                vec!["pre_".to_owned(), "s_".to_owned()]
            } else {
                vec!["_post".to_owned(), "_s".to_owned()]
            },
            long_name_affixes: if prefix {
                vec!["pre ".to_owned(), "l ".to_owned()]
            } else {
                vec![" post".to_owned(), " l".to_owned()]
            },
            service_affixes: HashMap::default(),
            semantics: Semantics::default(),
            action_affixes: DiagCommActionAffixes::default(),
            ..Default::default()
        }
    }

    #[test]
    fn test_trim_long_name_affixes_suffix() {
        let conv = make_convention(false);
        // Suffix match
        assert_eq!(conv.trim_long_name_affixes("Data post"), "Data");
        assert_eq!(conv.trim_long_name_affixes("Data l"), "Data");
        // Compound suffixes
        let conv = DatabaseNamingConvention {
            long_name_affix_position: DiagnosticServiceAffixPosition::Suffix,
            long_name_affixes: vec![" post l".to_owned(), " post".to_owned(), " l".to_owned()],
            ..make_convention(false)
        };
        assert_eq!(conv.trim_long_name_affixes("Data post l"), "Data");
        assert_eq!(conv.trim_long_name_affixes("Data post"), "Data");
        // No match
        assert_eq!(
            conv.trim_long_name_affixes("Data something"),
            "Data something"
        );
    }

    #[test]
    fn test_trim_long_name_affixes_prefix() {
        let conv = make_convention(true);
        // Prefix match
        assert_eq!(conv.trim_long_name_affixes("pre Data"), "Data");
        assert_eq!(conv.trim_long_name_affixes("l Data"), "Data");
        // Compound prefixes
        let conv = DatabaseNamingConvention {
            long_name_affix_position: DiagnosticServiceAffixPosition::Prefix,
            long_name_affixes: vec!["pre l ".to_owned(), "pre ".to_owned(), "l ".to_owned()],
            ..make_convention(true)
        };
        assert_eq!(conv.trim_long_name_affixes("pre l Data"), "Data");
        assert_eq!(conv.trim_long_name_affixes("pre Data"), "Data");
        // No match
        assert_eq!(
            conv.trim_long_name_affixes("something Data"),
            "something Data"
        );
    }

    #[test]
    fn test_trim_short_name_affixes_suffix() {
        let conv = make_convention(false);
        // Suffix match
        assert_eq!(conv.trim_short_name_affixes("data_post"), "data");
        assert_eq!(conv.trim_short_name_affixes("data_s"), "data");
        // Compound suffixes
        let conv = DatabaseNamingConvention {
            short_name_affix_position: DiagnosticServiceAffixPosition::Suffix,
            short_name_affixes: vec!["_post_s".to_owned(), "_post".to_owned(), "_s".to_owned()],
            ..make_convention(false)
        };
        assert_eq!(conv.trim_short_name_affixes("data_post_s"), "data");
        assert_eq!(conv.trim_short_name_affixes("data_post"), "data");
        // No match
        assert_eq!(conv.trim_short_name_affixes("data_x"), "data_x");
    }

    #[test]
    fn test_trim_short_name_affixes_prefix() {
        let conv = make_convention(true);
        // Prefix match
        assert_eq!(conv.trim_short_name_affixes("pre_data"), "data");
        assert_eq!(conv.trim_short_name_affixes("s_data"), "data");
        // Compound prefixes
        let conv = DatabaseNamingConvention {
            short_name_affix_position: DiagnosticServiceAffixPosition::Prefix,
            short_name_affixes: vec!["pre_s_".to_owned(), "pre_".to_owned(), "s_".to_owned()],
            ..make_convention(true)
        };
        assert_eq!(conv.trim_short_name_affixes("pre_s_data"), "data");
        assert_eq!(conv.trim_short_name_affixes("pre_data"), "data");
        // No match
        assert_eq!(conv.trim_short_name_affixes("x_data"), "x_data");
    }

    #[test]
    fn test_trim_affixes_case_insensitive() {
        let conv = DatabaseNamingConvention {
            short_name_affix_position: DiagnosticServiceAffixPosition::Prefix,
            long_name_affix_position: DiagnosticServiceAffixPosition::Suffix,
            short_name_affixes: vec!["pre_".to_owned()],
            long_name_affixes: vec![" post".to_owned()],
            configuration_service_parameter_semantic_id: "ID".to_owned(),
            configuration_functional_classes: vec!["varcoding".to_owned()],
            category_mapping: Vec::new(),
            default_category: default_category(),
            service_affixes: HashMap::default(),
            action_affixes: DiagCommActionAffixes::default(),
            semantics: Semantics::default(),
            ..Default::default()
        };
        assert_eq!(conv.trim_short_name_affixes("PRE_data"), "data");
        assert_eq!(conv.trim_long_name_affixes("Data POST"), "Data");
    }

    #[test]
    fn test_trim_edge_cases_empty_string() {
        let conv = make_convention(false);
        // Should return empty string for empty input
        assert_eq!(conv.trim_short_name_affixes(""), "");
        assert_eq!(conv.trim_long_name_affixes(""), "");
    }

    #[test]
    fn test_trim_edge_cases_empty_affix_list() {
        let mut conv = make_convention(false);
        conv.short_name_affixes.clear();
        conv.long_name_affixes.clear();
        // Should return original string if no affixes
        assert_eq!(conv.trim_short_name_affixes("data_post"), "data_post");
        assert_eq!(conv.trim_long_name_affixes("Data post"), "Data post");
    }

    #[test]
    fn test_trim_edge_cases_affix_equals_whole_string() {
        let mut conv = make_convention(false);
        conv.short_name_affixes = vec!["data_post".to_owned()];
        conv.long_name_affixes = vec!["data post".to_owned()];
        // Should trim to empty string if affix matches whole string
        assert_eq!(conv.trim_short_name_affixes("data_post"), "");
        assert_eq!(conv.trim_long_name_affixes("data post"), "");
    }

    #[test]
    fn test_trim_edge_cases_affix_longer_than_string() {
        let mut conv = make_convention(false);
        conv.short_name_affixes = vec!["verylongaffix".to_owned()];
        conv.long_name_affixes = vec!["much longer affix".to_owned()];
        // Should return original string if affix is longer than input
        assert_eq!(conv.trim_short_name_affixes("short"), "short");
        assert_eq!(conv.trim_long_name_affixes("tiny"), "tiny");
    }

    #[test]
    fn test_service_affixes_accepts_hex_key() {
        let json = r#"
        {
            "short_name_affix_position": "Suffix",
            "long_name_affix_position": "Suffix",
            "configuration_service_parameter_semantic_id": "ID",
            "configuration_functional_classes": ["varcoding"],
            "short_name_affixes": [],
            "long_name_affixes": [],
            "service_affixes": {
                "0x85": ["Prefix", ["DTC_Setting_Mode_"]]
            },
            "semantics": {
                "data": "DATA",
                "service_id_rq": "SERVICEIDRQ",
                "session": "SESSION",
                "security": "SECURITY"
            }
        }
        "#;

        let conv: DatabaseNamingConvention =
            serde_json::from_str(json).expect("hex key should deserialize");

        assert_eq!(
            conv.service_affixes.get("133"),
            Some(&(
                DiagnosticServiceAffixPosition::Prefix,
                vec!["DTC_Setting_Mode_".to_owned()]
            ))
        );
    }

    #[test]
    fn test_apply_action_affix_default_suffix() {
        let conv = make_convention(false);
        // Default action affixes suffix the base name with the action.
        assert_eq!(
            conv.apply_action_affix("Data", &DiagCommAction::Read),
            "Data_Read"
        );
        assert_eq!(
            conv.apply_action_affix("Data", &DiagCommAction::Write),
            "Data_Write"
        );
        assert_eq!(
            conv.apply_action_affix("Routine", &DiagCommAction::Start),
            "Routine_Start"
        );
        assert_eq!(
            conv.apply_action_affix("Routine", &DiagCommAction::RequestResults),
            "Routine_RequestResults"
        );
        assert_eq!(
            conv.apply_action_affix("Routine", &DiagCommAction::Stop),
            "Routine_Stop"
        );
    }

    #[test]
    fn test_apply_action_affix_prefix() {
        let conv = DatabaseNamingConvention {
            action_affixes: DiagCommActionAffixes {
                position: DiagnosticServiceAffixPosition::Prefix,
                read: "Read_".to_owned(),
                write: "Write_".to_owned(),
                start: "Start_".to_owned(),
                request_results: "RequestResults_".to_owned(),
                stop: "Stop_".to_owned(),
            },
            ..make_convention(false)
        };
        assert_eq!(
            conv.apply_action_affix("Data", &DiagCommAction::Read),
            "Read_Data"
        );
        assert_eq!(
            conv.apply_action_affix("Data", &DiagCommAction::Write),
            "Write_Data"
        );
        assert_eq!(
            conv.apply_action_affix("Routine", &DiagCommAction::Start),
            "Start_Routine"
        );
        assert_eq!(
            conv.apply_action_affix("Routine", &DiagCommAction::RequestResults),
            "RequestResults_Routine"
        );
        assert_eq!(
            conv.apply_action_affix("Routine", &DiagCommAction::Stop),
            "Stop_Routine"
        );
    }

    #[test]
    fn test_apply_action_affix_empty() {
        let conv = DatabaseNamingConvention {
            action_affixes: DiagCommActionAffixes {
                position: DiagnosticServiceAffixPosition::Suffix,
                read: String::new(),
                write: String::new(),
                start: String::new(),
                request_results: String::new(),
                stop: String::new(),
            },
            ..make_convention(false)
        };
        // Empty affixes leave the base name unchanged.
        assert_eq!(
            conv.apply_action_affix("Data", &DiagCommAction::Read),
            "Data"
        );
    }

    #[test]
    fn test_is_configuration_functional_class_case_insensitive() {
        let conv = DatabaseNamingConvention {
            configuration_functional_classes: vec![
                "VarCoding".to_owned(),
                "calibration".to_owned(),
            ],
            ..make_convention(false)
        };
        assert!(conv.is_configuration_functional_class("varcoding"));
        assert!(conv.is_configuration_functional_class("CALIBRATION"));
        assert!(!conv.is_configuration_functional_class("sensors"));
    }

    #[test]
    fn test_category_for_functional_class_uses_mapping() {
        let conv = DatabaseNamingConvention {
            category_mapping: vec![
                FunctionalClassCategoryMapping {
                    functional_class: "Sensors".to_owned(),
                    category: "identData".to_owned(),
                },
                FunctionalClassCategoryMapping {
                    functional_class: "measurements".to_owned(),
                    category: "currentData".to_owned(),
                },
            ],
            default_category: "x-sovd2uds-unmapped".to_owned(),
            ..make_convention(false)
        };
        assert_eq!(conv.category_for_functional_class("sensors"), "identData");
        assert_eq!(
            conv.category_for_functional_class("MEASUREMENTS"),
            "currentData"
        );
    }

    #[test]
    fn test_category_for_functional_class_falls_back_to_default() {
        let conv = DatabaseNamingConvention {
            category_mapping: vec![FunctionalClassCategoryMapping {
                functional_class: "sensors".to_owned(),
                category: "identData".to_owned(),
            }],
            default_category: "x-sovd2uds-unmapped".to_owned(),
            ..make_convention(false)
        };
        assert_eq!(
            conv.category_for_functional_class("unknown_class"),
            "x-sovd2uds-unmapped"
        );
    }

    #[test]
    fn test_validate_sanity_rejects_functional_class_in_both_lists() {
        let conv = DatabaseNamingConvention {
            configuration_functional_classes: vec!["varcoding".to_owned()],
            category_mapping: vec![FunctionalClassCategoryMapping {
                functional_class: "VarCoding".to_owned(),
                category: "identData".to_owned(),
            }],
            ..make_convention(false)
        };
        let result = conv.validate_sanity();
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ConfigSanityError::InvalidValue { .. })
        ));
    }

    #[test]
    fn test_validate_sanity_accepts_disjoint_lists() {
        let conv = DatabaseNamingConvention {
            configuration_functional_classes: vec!["varcoding".to_owned()],
            category_mapping: vec![FunctionalClassCategoryMapping {
                functional_class: "sensors".to_owned(),
                category: "identData".to_owned(),
            }],
            ..make_convention(false)
        };
        assert!(conv.validate_sanity().is_ok());
    }

    #[test]
    fn test_default_category_is_unmapped_marker() {
        assert_eq!(
            DatabaseNamingConvention::default().default_category,
            "x-sovd2uds-unmapped"
        );
    }
}
