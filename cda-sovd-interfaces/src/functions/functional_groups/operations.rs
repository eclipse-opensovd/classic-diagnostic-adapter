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

use super::{DataError, HashMap, Serialize};

pub mod service {
    use serde::Deserialize;

    use super::{DataError, HashMap, Serialize};
    pub use crate::common::operations::OperationQuery as Query;

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

/// Response body for `GET /operations/{operation}/executions/{id}` on a functional group.
///
/// Mirrors `AsyncGetByIdResponse` from the component ECU operations, but uses ECU-keyed
/// parameters (one entry per ECU in the group)
#[derive(Serialize, schemars::JsonSchema)]
pub struct FgAsyncGetByIdResponse<T> {
    /// Status of the executed operation.
    pub status: crate::components::ecu::operations::ExecutionStatus,
    /// Capability executed at the moment (always `execute` for CDA routines).
    pub capability: crate::components::ecu::operations::GetByIdCapability,
    /// Response parameters per ECU - key is ECU name, value is the parameters map.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub parameters: HashMap<String, serde_json::Map<String, serde_json::Value>>,
    /// Errors that occurred during execution, with JSON pointers to per-ECU entries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<DataError<T>>,
    #[schemars(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<schemars::Schema>,
}

pub use crate::common::operations::OperationCollectionItem;
