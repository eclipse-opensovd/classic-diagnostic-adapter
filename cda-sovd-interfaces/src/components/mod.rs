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

use serde::{Deserialize, Serialize};

pub mod ecu;

pub mod get {
    pub type Response = crate::ResourceResponse;
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct ComponentQuery {
    #[serde(rename = "x-include-sdgs", default)]
    pub include_sdgs: bool,
    #[serde(rename = "include-schema", default)]
    pub include_schema: bool,
}

pub mod common {
    pub mod modes {

        pub type Query = crate::IncludeSchemaQuery;
        pub mod get {
            use serde::{Deserialize, Serialize};

            use crate::Items;

            /// Used in the GET `/components/ecu/{ecu_id|functional_group}/modes/{mode_id}` endpoint
            #[derive(Serialize, Deserialize, schemars::JsonSchema)]
            pub struct Mode<T> {
                /// The name of the mode, optional in accordance with sovd standard
                pub name: Option<String>,
                /// The translation ID for the name
                #[serde(skip_serializing_if = "Option::is_none")]
                pub translation_id: Option<String>,
                /// The value of the mode.
                #[serde(skip_serializing_if = "Option::is_none")]
                pub value: Option<T>,
                /// The schema of the mode resource.
                #[schemars(skip)]
                #[serde(skip_serializing_if = "Option::is_none")]
                pub schema: Option<schemars::Schema>,
            }

            #[derive(Serialize, Deserialize, schemars::JsonSchema)]
            pub struct ModeCollectionItem {
                /// The resource identifier of the mode on an entity
                pub id: String,
                /// The name of the mode
                #[serde(skip_serializing_if = "Option::is_none")]
                pub name: Option<String>,
                /// The translation ID for the name
                #[serde(skip_serializing_if = "Option::is_none")]
                pub translation_id: Option<String>,
            }

            pub type Response = Items<ModeCollectionItem>;
        }

        pub mod put {
            use serde::{Deserialize, Serialize};

            #[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
            #[schemars(rename = "UpdateAccessModesResponse")]
            pub struct Response<T> {
                pub id: String,
                pub value: T,
                #[schemars(skip)]
                #[serde(skip_serializing_if = "Option::is_none")]
                pub schema: Option<schemars::Schema>,
            }
        }

        pub mod commctrl {
            pub mod put {
                use cda_interfaces::HashMap;
                use serde::{Deserialize, Serialize};

                #[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
                #[schemars(rename = "UpdateCommCtrlModesRequest")]
                pub struct Request {
                    /// Sub-function to enable/disable Rx/Tx communication
                    pub value: String,
                    /// Additional parameters, which will be passed directly to the ECU
                    pub parameters: Option<HashMap<String, serde_json::Value>>,
                }
            }
        }
    }
}
