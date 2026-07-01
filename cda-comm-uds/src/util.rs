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

use cda_interfaces::datatypes::{SdBoolMappings, SdSdg};

/// Recursively checks whether an [`SdSdg`] tree contains a matching SD entry
/// according to the provided `expected` mappings.
pub(crate) fn check_sd_sdg_recursive(expected: &SdBoolMappings, sd_sdg: &SdSdg) -> bool {
    match sd_sdg {
        SdSdg::Sd { value, si, .. } => {
            let Some(sd) = si.as_ref().and_then(|v| expected.get(v)) else {
                return false;
            };
            value.as_ref().is_some_and(|v| sd.contains(v))
        }
        SdSdg::Sdg { sdgs, .. } => sdgs
            .iter()
            .any(|sdsdg| check_sd_sdg_recursive(expected, sdsdg)),
    }
}

#[cfg(test)]
mod tests {
    use cda_interfaces::{
        HashMap, HashMapExtensions,
        datatypes::{SdMappingsTruthyValue, SdSdg},
    };

    use super::*;

    #[test]
    fn test_check_sd_sdg_recursive_sd_no_si() {
        let sd = SdSdg::Sd {
            value: Some("yes".to_string()),
            si: None,
            ti: None,
        };
        let expected: HashMap<String, SdMappingsTruthyValue> = HashMap::new();
        assert!(!check_sd_sdg_recursive(&expected, &sd));
    }

    #[test]
    fn test_check_sd_sdg_recursive_sd_si_not_in_expected() {
        let sd = SdSdg::Sd {
            value: Some("yes".to_string()),
            si: Some("unknown".to_string()),
            ti: None,
        };
        let mut expected: HashMap<String, SdMappingsTruthyValue> = HashMap::new();
        expected.insert(
            "key".to_string(),
            SdMappingsTruthyValue::new(["yes".to_string()].into_iter().collect(), false),
        );
        assert!(!check_sd_sdg_recursive(&expected, &sd));
    }

    #[test]
    fn test_check_sd_sdg_recursive_sd_match() {
        let sd = SdSdg::Sd {
            value: Some("yes".to_string()),
            si: Some("key".to_string()),
            ti: None,
        };
        let mut expected: HashMap<String, SdMappingsTruthyValue> = HashMap::new();
        expected.insert(
            "key".to_string(),
            SdMappingsTruthyValue::new(["yes".to_string()].into_iter().collect(), false),
        );
        assert!(check_sd_sdg_recursive(&expected, &sd));
    }

    #[test]
    fn test_check_sd_sdg_recursive_sd_no_match() {
        let sd = SdSdg::Sd {
            value: Some("no".to_string()),
            si: Some("key".to_string()),
            ti: None,
        };
        let mut expected: HashMap<String, SdMappingsTruthyValue> = HashMap::new();
        expected.insert(
            "key".to_string(),
            SdMappingsTruthyValue::new(["yes".to_string()].into_iter().collect(), false),
        );
        assert!(!check_sd_sdg_recursive(&expected, &sd));
    }

    #[test]
    fn test_check_sd_sdg_recursive_sd_value_none() {
        let sd = SdSdg::Sd {
            value: None,
            si: Some("key".to_string()),
            ti: None,
        };
        let mut expected: HashMap<String, SdMappingsTruthyValue> = HashMap::new();
        expected.insert(
            "key".to_string(),
            SdMappingsTruthyValue::new(["yes".to_string()].into_iter().collect(), false),
        );
        assert!(!check_sd_sdg_recursive(&expected, &sd));
    }

    #[test]
    fn test_check_sd_sdg_recursive_sdg_empty() {
        let sdg = SdSdg::Sdg {
            caption: None,
            si: None,
            sdgs: vec![],
        };
        let expected: HashMap<String, SdMappingsTruthyValue> = HashMap::new();
        assert!(!check_sd_sdg_recursive(&expected, &sdg));
    }

    #[test]
    fn test_check_sd_sdg_recursive_sdg_with_matching_sd() {
        let matching_sd = SdSdg::Sd {
            value: Some("yes".to_string()),
            si: Some("key".to_string()),
            ti: None,
        };
        let sdg = SdSdg::Sdg {
            caption: None,
            si: None,
            sdgs: vec![matching_sd],
        };
        let mut expected: HashMap<String, SdMappingsTruthyValue> = HashMap::new();
        expected.insert(
            "key".to_string(),
            SdMappingsTruthyValue::new(["yes".to_string()].into_iter().collect(), false),
        );
        assert!(check_sd_sdg_recursive(&expected, &sdg));
    }

    #[test]
    fn test_check_sd_sdg_recursive_sdg_nested() {
        let matching_sd = SdSdg::Sd {
            value: Some("yes".to_string()),
            si: Some("key".to_string()),
            ti: None,
        };
        let nested_sdg = SdSdg::Sdg {
            caption: None,
            si: None,
            sdgs: vec![matching_sd],
        };
        let outer_sdg = SdSdg::Sdg {
            caption: None,
            si: None,
            sdgs: vec![nested_sdg],
        };
        let mut expected: HashMap<String, SdMappingsTruthyValue> = HashMap::new();
        expected.insert(
            "key".to_string(),
            SdMappingsTruthyValue::new(["yes".to_string()].into_iter().collect(), false),
        );
        assert!(check_sd_sdg_recursive(&expected, &outer_sdg));
    }
}
