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

#[derive(Serialize, schemars::JsonSchema)]
pub struct ComponentsResponse<T> {
    pub items: Vec<T>,
    #[serde(rename = "x-sovd2uds-rootlocked-ecus")]
    pub rootlocked_ecus: Vec<T>,
    #[serde(rename = "x-sovd2uds-lin-ecus")]
    pub lin_ecus: Vec<T>,
    #[schemars(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<schemars::Schema>,
}
