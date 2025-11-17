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

/// Holds configuration for diagnostic service naming conventions.
///
/// # Fields
/// - `short_name_affix_position`: Position of affixes in short names (prefix or suffix).
/// - `long_name_affix_position`: Position of affixes in long names (prefix or suffix).
/// - `configuration_service_parameter_semantic_id`: Parameter semantic used to distinguish
///   between different services in configurations
/// - `functional_class_varcoding`: Functional class name for filtering varcoding services.
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
///
/// Common affixes (e.g. `read`, `write`) should be placed first for performance, but compound
/// affixes must precede their base forms for correct matching.
///

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct DatabaseNamingConvention {
    pub short_name_affix_position: DiagnosticServiceAffixPosition,
    pub long_name_affix_position: DiagnosticServiceAffixPosition,
    pub configuration_service_parameter_semantic_id: String,
    pub functional_class_varcoding: String,
    pub short_name_affixes: Vec<String>,
    pub long_name_affixes: Vec<String>,
}

impl DatabaseNamingConvention {
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
                return long_name[affix.len()..].to_string();
            }
            if self.long_name_affix_position == DiagnosticServiceAffixPosition::Suffix
                && long_name_lowercase.ends_with(affix)
            {
                return long_name[..long_name.len().saturating_sub(affix.len())].to_string();
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
                return short_name[affix.len()..].to_string();
            }
            if self.short_name_affix_position == DiagnosticServiceAffixPosition::Suffix
                && short_name_lowercase.ends_with(affix)
            {
                return short_name[..short_name.len().saturating_sub(affix.len())].to_string();
            }
        }
        short_name.to_string()
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
            functional_class_varcoding: "varcoding".to_owned(),
            short_name_affixes: vec![
                "_read".to_owned(),
                "_write".to_owned(),
                "_read_dump".to_owned(),
                "_write_dump".to_owned(),
                "_dump".to_owned(),
            ],
            long_name_affixes: vec![
                " read".to_owned(),
                " write".to_owned(),
                " read dump".to_owned(),
                " write dump".to_owned(),
                " dump".to_owned(),
            ],
        }
    }
}

#[derive(Deserialize, Serialize, PartialEq, Clone, Debug)]
pub enum DiagnosticServiceAffixPosition {
    Prefix,
    Suffix,
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
            functional_class_varcoding: "varcoding".to_owned(),
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
            functional_class_varcoding: "varcoding".to_owned(),
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
}
