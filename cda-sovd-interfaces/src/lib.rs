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
use serde::{Deserialize, Serialize};
#[cfg(feature = "swagger-ui")]
use utoipa::ToSchema;

pub mod apps;
pub mod components;
pub mod error;
pub mod locking;

pub trait Payload {
    fn get_data_map(&self) -> HashMap<String, serde_json::Value>;
}

#[derive(Serialize)]
#[cfg_attr(feature = "swagger-ui", derive(ToSchema))]
pub struct Resource {
    pub href: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub name: String,
}

#[derive(Deserialize, Serialize, Debug)]
#[cfg_attr(feature = "swagger-ui", derive(ToSchema))]
pub struct Items<T> {
    pub items: Vec<T>,
}

#[cfg_attr(feature = "swagger-ui", derive(ToSchema))]
#[derive(Serialize)]
pub struct ResourceResponse {
    pub items: Vec<Resource>,
}

#[derive(Deserialize, Serialize, Debug)]
#[cfg_attr(feature = "swagger-ui", derive(ToSchema))]
pub struct DataItem {
    pub id: String,
    pub data: serde_json::Value,
}

pub mod sovd2uds {
    use std::path::PathBuf;

    use serde::Serialize;

    #[derive(Serialize)]
    pub struct FileList {
        #[serde(rename = "items")]
        pub files: Vec<File>,
        #[serde(skip_serializing)]
        pub path: Option<PathBuf>,
    }

    #[derive(Serialize, Debug, Clone)]
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
    #[derive(Serialize, Debug, Clone)]
    pub enum HashAlgorithm {
        None,
        // todo: support hashing algorithms
    }
}
