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

pub(crate) mod executions;

#[cfg(test)]
mod tests {
    use sovd_interfaces::components::ecu::operations::comparams::ComParamSimpleValue;

    #[test]
    #[allow(clippy::float_cmp, reason = "Test verifies exact deserialized values")]
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
