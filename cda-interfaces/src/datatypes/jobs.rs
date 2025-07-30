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

pub mod single_ecu {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    pub struct LongName {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(default)]
        pub value: Option<String>,

        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(default)]
        pub ti: Option<String>,
    }

    #[derive(Serialize, Deserialize)]
    pub struct Param {
        pub short_name: String,

        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(default)]
        pub physical_default_value: Option<String>,

        // todo dop is out of for POC
        // pub dop: u32,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(default)]
        pub semantic: Option<String>,

        #[serde(skip_serializing_if = "skip_long_name_if_none_or_empty")]
        #[serde(default)]
        pub long_name: Option<LongName>,
    }

    #[derive(Serialize, Deserialize)]
    pub struct ProgCode {
        pub code_file: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(default)]
        pub encryption: Option<String>,

        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(default)]
        pub syntax: Option<String>,

        pub revision: String,

        pub entrypoint: String,
    }

    #[derive(Serialize, Deserialize)]
    pub struct Job {
        #[serde(rename = "x-input-params")]
        pub input_params: Vec<Param>,

        #[serde(rename = "x-output-params")]
        pub output_params: Vec<Param>,

        #[serde(rename = "x-neg-output-params")]
        pub neg_output_params: Vec<Param>,

        #[serde(rename = "x-prog-code")]
        pub prog_codes: Vec<ProgCode>,
    }

    // Clippy would prefer if we would pass Option<&LongName> instead.
    // But this is not compatible with the Serialization derive from serde.
    #[allow(clippy::ref_option)]
    fn skip_long_name_if_none_or_empty(long_name: &Option<LongName>) -> bool {
        long_name
            .as_ref()
            .and_then(|ln| ln.value.as_ref().or(ln.ti.as_ref()))
            .is_none()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_param_serialization() {
            let param_with_empty_long_name = Param {
                short_name: "TestShortName".to_string(),
                physical_default_value: None,
                semantic: None,
                long_name: Some(LongName {
                    value: None,
                    ti: None,
                }),
            };

            let param_with_long_name_has_value = Param {
                short_name: "TestShortName".to_string(),
                physical_default_value: None,
                semantic: None,
                long_name: Some(LongName {
                    value: Some("Value".to_string()),
                    ti: None,
                }),
            };

            let param_with_long_name_ti_has_value = Param {
                short_name: "TestShortName".to_string(),
                physical_default_value: None,
                semantic: None,
                long_name: Some(LongName {
                    value: None,
                    ti: Some("Value".to_string()),
                }),
            };

            let param_without_long_name = Param {
                short_name: "TestShortName".to_string(),
                physical_default_value: None,
                semantic: None,
                long_name: None,
            };

            let serialized_empty_long_name =
                serde_json::to_string(&param_with_empty_long_name).unwrap();
            let serialized_with_long_name_value =
                serde_json::to_string(&param_with_long_name_has_value).unwrap();
            let serialized_with_long_name_ti =
                serde_json::to_string(&param_with_long_name_ti_has_value).unwrap();
            let serialized_without_long_name =
                serde_json::to_string(&param_without_long_name).unwrap();

            assert_eq!(
                serialized_empty_long_name,
                r#"{"short_name":"TestShortName"}"#
            );

            assert_eq!(
                serialized_with_long_name_value,
                r#"{"short_name":"TestShortName","long_name":{"value":"Value"}}"#
            );

            assert_eq!(
                serialized_with_long_name_ti,
                r#"{"short_name":"TestShortName","long_name":{"ti":"Value"}}"#
            );

            assert_eq!(
                serialized_without_long_name,
                r#"{"short_name":"TestShortName"}"#
            );
        }
    }
}
