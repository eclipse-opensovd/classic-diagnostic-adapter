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

use hashbrown::HashMap;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Unit {
    pub factor_to_si_unit: Option<f64>,
    pub offset_to_si_unit: Option<f64>,
}

#[derive(Serialize, Clone)]
pub struct ComParamSimpleValue {
    pub value: String,
    pub unit: Option<Unit>,
}

/// Custom deserialization for `ComParamSimpleValue` to handle both string and struct formats.
/// The string format is a simple value, leaving unit None,
/// while the struct format includes a value and an optional unit.
/// Mostly necessary to handle incoming data from the webserver, as setting the unit
/// there is superfluous. Also to retain compatibility with existing clients that
/// might send just a string value.
impl<'de> Deserialize<'de> for ComParamSimpleValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum ComParamSimpleValueHelper {
            String(String),
            Struct { value: String, unit: Option<Unit> },
        }

        let helper = ComParamSimpleValueHelper::deserialize(deserializer)?;

        match helper {
            ComParamSimpleValueHelper::String(value) => {
                Ok(ComParamSimpleValue { value, unit: None })
            }
            ComParamSimpleValueHelper::Struct { value, unit } => {
                Ok(ComParamSimpleValue { value, unit })
            }
        }
    }
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(untagged)]
pub enum ComParamValue {
    Simple(ComParamSimpleValue),
    Complex(ComplexComParamValue),
}

pub type ComplexComParamValue = HashMap<String, ComParamValue>;

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum ExecutionStatus {
    Running,
    Completed,
    Failed,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum Capability {
    Execute,
    Stop,
    Freeze,
    Reset,
    Status,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DataTransferStatus {
    Running,
    Aborted,
    Finished,
    Queued,
}

#[derive(Serialize, Clone)]
pub struct DataTransferError {
    pub text: String,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct DataTransferMetaData {
    pub acknowledged_bytes: u64,
    pub blocksize: usize,
    pub next_block_sequence_counter: u8,
    pub id: String,
    pub file_id: String,
    pub status: DataTransferStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Vec<DataTransferError>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn com_param_simple_deserialization() {
        let json_data_string = "\"example_value\"";
        let deserialized_string: ComParamSimpleValue =
            serde_json::from_str(json_data_string).unwrap();
        assert_eq!(deserialized_string.value, "example_value");
        assert!(deserialized_string.unit.is_none());

        let json_data_struct = r#"{
        "value": "test",
        "unit": {
            "factor_to_si_unit": 1.0,
            "offset_to_si_unit": 0.0
        }
        }"#;
        let deserialized_struct: ComParamSimpleValue =
            serde_json::from_str(json_data_struct).unwrap();
        assert_eq!(deserialized_struct.value, "test");
        let unit = deserialized_struct.unit.unwrap();
        assert_eq!(unit.factor_to_si_unit.unwrap(), 1.0);
        assert_eq!(unit.offset_to_si_unit.unwrap(), 0.0);

        let json_data_struct = r#"{
        "value": "test",
        "unit": {
            "factor_to_si_unit": 1.0
        }
        }"#;
        let deserialized_struct: ComParamSimpleValue =
            serde_json::from_str(json_data_struct).unwrap();
        assert_eq!(deserialized_struct.value, "test");
        let unit = deserialized_struct.unit.unwrap();
        assert_eq!(unit.factor_to_si_unit.unwrap(), 1.0);
        assert!(unit.offset_to_si_unit.is_none());

        let json_data_struct = r#"{"value": "test"}"#;
        let deserialized_struct: ComParamSimpleValue =
            serde_json::from_str(json_data_struct).unwrap();
        assert_eq!(deserialized_struct.value, "test");
        assert!(deserialized_struct.unit.is_none());

        let json_data_struct = r#"{"unit": {"factor_to_si_unit": 1.0}}"#;
        assert!(serde_json::from_str::<ComParamSimpleValue>(json_data_struct).is_err());
    }
}
