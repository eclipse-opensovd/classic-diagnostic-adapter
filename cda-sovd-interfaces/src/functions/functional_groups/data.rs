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

use cda_interfaces::HashMap;
use serde::Deserialize;

/// Request for a functional group write request
/// The field `data` is a JSON object expected to contain
/// the necessary parameters for the given request.
#[derive(Deserialize, schemars::JsonSchema)]
pub struct DataRequestPayload {
    data: HashMap<String, serde_json::Value>,
}

impl crate::Payload for DataRequestPayload {
    fn get_data_map(&self) -> HashMap<String, serde_json::Value> {
        self.data.clone()
    }
}

pub mod service {
    use cda_interfaces::HashMap;
    use serde::{Deserialize, Serialize};

    use crate::error::DataError;

    /// Query parameters for GET/PUT data service requests
    pub type Query = crate::IncludeSchemaQuery;

    /// Response for functional group data GET/PUT operations
    /// Returns data keyed by ECU name at the top level
    #[derive(Serialize, Deserialize, schemars::JsonSchema)]
    pub struct Response<T> {
        /// Data results per ECU - key is ECU name, value is the data result
        pub data: HashMap<String, serde_json::Map<String, serde_json::Value>>,
        /// Errors that occurred during the operation
        /// JSON pointers reference /data/{ecu-name} or /data/{ecu-name}/{field}
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
