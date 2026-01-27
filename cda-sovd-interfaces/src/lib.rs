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

use cda_interfaces::HashMap;
use serde::{Deserialize, Serialize};

use crate::error::DataError;

pub mod apps;
pub mod components;
pub mod error;
pub mod functions;
pub mod locking;

fn default_true() -> bool {
    true
}

pub trait Payload {
    fn get_data_map(&self) -> HashMap<String, serde_json::Value>;
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct Resource {
    pub href: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub name: String,
}

#[derive(Deserialize, Serialize, Debug, schemars::JsonSchema)]
pub struct Items<T> {
    pub items: Vec<T>,
    #[schemars(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<schemars::Schema>,
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct ResourceResponse {
    pub items: Vec<Resource>,
    #[schemars(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<schemars::Schema>,
}

#[derive(Serialize, Debug, schemars::JsonSchema)]
pub struct ObjectDataItem<T> {
    pub id: String,
    pub data: serde_json::Map<String, serde_json::Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<DataError<T>>,
    #[schemars(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<schemars::Schema>,
}

#[derive(Deserialize, Serialize, Debug, schemars::JsonSchema)]
pub struct ArrayDataItem {
    pub id: String,
    pub data: Vec<serde_json::Value>,
}

#[derive(Deserialize, Debug, schemars::JsonSchema)]
pub struct IncludeSchemaQuery {
    #[serde(rename = "include-schema", default)]
    pub include_schema: bool,
}

pub mod sovd2uds {
    use std::path::PathBuf;

    use serde::Serialize;

    #[derive(Serialize, schemars::JsonSchema)]
    pub struct FileList {
        #[serde(rename = "items")]
        pub files: Vec<File>,
        #[serde(skip_serializing)]
        pub path: Option<PathBuf>,
        #[schemars(skip)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub schema: Option<schemars::Schema>,
    }

    #[derive(Serialize, Debug, Clone, schemars::JsonSchema)]
    pub struct File {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub hash: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub hash_algorithm: Option<HashAlgorithm>,
        pub id: String,
        pub mimetype: String,
        pub size: u64,
        #[serde(rename = "x-sovd2uds-OrigPath")]
        pub origin_path: String,
    }
    #[derive(Serialize, Debug, Clone, schemars::JsonSchema)]
    pub enum HashAlgorithm {
        None,
        // todo: support hashing algorithms
    }
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
