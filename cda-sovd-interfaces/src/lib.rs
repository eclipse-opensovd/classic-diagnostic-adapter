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
