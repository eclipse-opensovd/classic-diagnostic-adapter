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

//! Configuration of the SOVD API surface (version segment, ISO 17978-3 §5.6).

use cda_interfaces::config::{ConfigSanity, ConfigSanityError};
use serde::{Deserialize, Serialize};

/// Path prefix in front of the version segment, e.g. `/vehicle/v15/components`.
pub const API_PATH_PREFIX: &str = "/vehicle";
/// Version segment all SOVD routes are mounted under. It is always served, so
/// existing clients keep working when further segments are configured.
pub const CANONICAL_VERSION_SEGMENT: &str = "v15";
/// Version of ISO 17978-3 implemented by the server, reported in `version-info`.
pub const SOVD_STANDARD_VERSION: &str = "1.1.0";

/// SOVD API surface settings.
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema, PartialEq, Eq)]
pub struct SovdApiConfig {
    /// Version segments served in addition to `v15`, e.g. `["v1"]` makes
    /// `/vehicle/v1/components` an alias of `/vehicle/v15/components`.
    /// Each segment must have the form `v<number>`.
    #[serde(default = "default_version_aliases")]
    pub version_aliases: Vec<String>,
}

fn default_version_aliases() -> Vec<String> {
    vec!["v1".to_owned()]
}

impl Default for SovdApiConfig {
    fn default() -> Self {
        Self {
            version_aliases: default_version_aliases(),
        }
    }
}

impl SovdApiConfig {
    /// All version segments the server answers on, the canonical one first.
    #[must_use]
    pub fn version_segments(&self) -> Vec<String> {
        let mut segments = vec![CANONICAL_VERSION_SEGMENT.to_owned()];
        for alias in &self.version_aliases {
            let alias = alias.to_lowercase();
            if !segments.contains(&alias) {
                segments.push(alias);
            }
        }
        segments
    }
}

impl ConfigSanity for SovdApiConfig {
    fn validate_sanity(&self) -> Result<(), ConfigSanityError> {
        for alias in &self.version_aliases {
            let valid = alias
                .strip_prefix('v')
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
            if !valid {
                return Err(ConfigSanityError::InvalidValue {
                    field: "sovd_api.version_aliases".to_owned(),
                    reason: format!("'{alias}' is not a version segment of the form v<number>"),
                });
            }
        }
        Ok(())
    }
}

/// Maps a request path on a version alias to the canonical segment, so the
/// routes only need to be mounted once. `path` must already be lowercase.
pub(crate) fn rewrite_version_alias(path: &str, aliases: &[String]) -> Option<String> {
    let rest = path.strip_prefix(API_PATH_PREFIX)?.strip_prefix('/')?;
    let (segment, tail) = rest.find('/').map_or((rest, ""), |i| rest.split_at(i));
    if segment == CANONICAL_VERSION_SEGMENT || !aliases.iter().any(|a| a == segment) {
        return None;
    }
    Some(format!(
        "{API_PATH_PREFIX}/{CANONICAL_VERSION_SEGMENT}{tail}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aliases() -> Vec<String> {
        vec!["v1".to_owned()]
    }

    #[test]
    fn alias_is_rewritten_to_canonical_segment() {
        assert_eq!(
            rewrite_version_alias("/vehicle/v1/components/ecu", &aliases()).as_deref(),
            Some("/vehicle/v15/components/ecu")
        );
        assert_eq!(
            rewrite_version_alias("/vehicle/v1", &aliases()).as_deref(),
            Some("/vehicle/v15")
        );
    }

    #[test]
    fn other_paths_are_left_alone() {
        for path in [
            "/vehicle/v15/components",
            "/vehicle/v10/components",
            "/vehicle/version-info",
            "/v1/components",
            "/health",
        ] {
            assert_eq!(rewrite_version_alias(path, &aliases()), None, "{path}");
        }
    }

    #[test]
    fn version_segments_lists_canonical_first_without_duplicates() {
        let config = SovdApiConfig {
            version_aliases: vec!["V1".to_owned(), "v15".to_owned(), "v1".to_owned()],
        };
        assert_eq!(config.version_segments(), vec!["v15", "v1"]);
    }

    #[test]
    fn sanity_rejects_malformed_segments() {
        assert!(SovdApiConfig::default().validate_sanity().is_ok());
        for bad in ["", "v", "1", "vx", "v1/x"] {
            let config = SovdApiConfig {
                version_aliases: vec![bad.to_owned()],
            };
            assert!(config.validate_sanity().is_err(), "{bad}");
        }
    }
}
