/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

use super::{DataError, Deserialize, HashMap, Serialize};

pub mod service {
    use super::{DataError, Deserialize, HashMap, Serialize};

    /// Query parameters for `POST /operations/{operation}`.
    #[derive(Debug, Default, Deserialize, schemars::JsonSchema)]
    pub struct Query {
        #[serde(rename = "include-schema", default)]
        pub include_schema: bool,
        /// When `true`, skip sending the UDS Start (0x01) request to all ECUs.
        #[serde(rename = "x-sovd2uds-suppressService", default)]
        pub suppress_service: bool,
    }

    /// Request payload for functional group operations
    #[derive(Deserialize, schemars::JsonSchema)]
    pub struct Request {
        pub parameters: HashMap<String, serde_json::Value>,
    }

    impl crate::Payload for Request {
        fn get_data_map(&self) -> HashMap<String, serde_json::Value> {
            self.parameters.clone()
        }
    }

    /// Response for functional group operation POST operations
    /// Returns parameters keyed by ECU name at the top level
    #[derive(Serialize, schemars::JsonSchema)]
    pub struct Response<T> {
        /// Parameter results per ECU - key is ECU name, value is the parameters result
        pub parameters: HashMap<String, serde_json::Map<String, serde_json::Value>>,
        /// Errors that occurred during the operation
        /// JSON pointers reference /parameters/{ecu-name} or /parameters/{ecu-name}/{field}
        #[serde(skip_serializing_if = "Vec::is_empty")]
        pub errors: Vec<DataError<T>>,
        #[schemars(skip)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub schema: Option<schemars::Schema>,
    }
}

pub mod get {
    pub type Query = crate::IncludeSchemaQuery;
}

/// A single item in the `GET /functions/functionalgroups/{group}/operations` collection.
/// Spec Table 169 (`OperationDescription`).
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
pub struct FgOperationCollectionItem {
    /// Trimmed short-name used as the service identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// If `true`, the execution of the operation requires proof of co-location.
    /// Always `false` for classic UDS routines.
    pub proximity_proof_required: bool,
    /// If `true`, the execution of the operation is asynchronous (has Stop or `RequestResults`).
    pub asynchronous_execution: bool,
}
