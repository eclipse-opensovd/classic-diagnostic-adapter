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

/// Response Structure for /components
///
/// It contains a list of all components that are loaded by the CDA.<br>
/// `additional_fields` allows to extend the component response with adidtional fields.<br>
/// See [`ComponentsConfig`](cda_interfaces::datatypes::ComponentsConfig) for
/// additional details.
#[derive(Serialize, schemars::JsonSchema)]
pub struct ComponentsResponse<T> {
    pub items: Vec<T>,
    #[serde(flatten)]
    #[schemars(skip)]
    pub additional_fields: HashMap<String, Vec<T>>,
    #[schemars(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<schemars::Schema>,
}
