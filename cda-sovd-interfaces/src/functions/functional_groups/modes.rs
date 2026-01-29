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

pub type Query = crate::IncludeSchemaQuery;
pub mod get {
    pub type Response = crate::common::modes::get::Response;
    pub type ResponseItem = crate::common::modes::get::ModeCollectionItem;
}

pub mod commctrl {
    pub mod put {
        use cda_interfaces::HashMap;
        use serde::{Deserialize, Serialize};

        use crate::error::ApiErrorResponse;

        pub type Request = crate::common::modes::commctrl::put::Request;
        pub type ResponseElement = crate::common::modes::put::Response<String>;

        /// Returns data keyed by ECU name at the top level
        #[derive(Serialize, Deserialize, schemars::JsonSchema)]
        pub struct Response<T> {
            /// Data results per ECU - key is ECU name, value is the data result
            pub modes: HashMap<String, ResponseElement>,
            /// Errors that occurred during the operation
            #[serde(skip_serializing_if = "Vec::is_empty")]
            pub errors: Vec<ApiErrorResponse<T>>,
            #[schemars(skip)]
            #[serde(skip_serializing_if = "Option::is_none")]
            pub schema: Option<schemars::Schema>,
        }
    }
}

pub mod dtcsetting {
    pub mod put {
        use cda_interfaces::HashMap;
        use serde::{Deserialize, Serialize};

        use crate::error::ApiErrorResponse;

        pub type Request = crate::common::modes::dtcsetting::put::Request;
        pub type ResponseElement = crate::common::modes::put::Response<String>;

        /// Returns data keyed by ECU name at the top level
        #[derive(Serialize, Deserialize, schemars::JsonSchema)]
        pub struct Response<T> {
            /// Data results per ECU - key is ECU name, value is the data result
            pub modes: HashMap<String, ResponseElement>,
            /// Errors that occurred during the operation
            #[serde(skip_serializing_if = "Vec::is_empty")]
            pub errors: Vec<ApiErrorResponse<T>>,
            #[schemars(skip)]
            #[serde(skip_serializing_if = "Option::is_none")]
            pub schema: Option<schemars::Schema>,
        }
    }
}
