/*
 * Copyright (c) 2025-2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
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

use super::{DataError, Deserialize, HashMap, Serialize};

pub mod service {
    use super::{DataError, Deserialize, HashMap, Serialize};

    /// Query parameters for POST operation service requests
    pub type Query = crate::IncludeSchemaQuery;

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
