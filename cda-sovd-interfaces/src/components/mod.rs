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

use serde::Deserialize;

pub mod ecu;
pub mod functional_groups;

pub mod get {
    pub type Response = crate::ResourceResponse;
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct ComponentQuery {
    #[serde(rename = "x-include-sdgs", default)]
    pub include_sdgs: bool,
    #[serde(rename = "include-schema", default)]
    pub include_schema: bool,
}
