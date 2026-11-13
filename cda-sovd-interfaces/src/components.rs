/*
 * SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation
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

pub mod ecu;

pub mod get {
    pub type Response = crate::ResourceResponse;
}

/// Query parameters for fetching the list of components.
#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct ComponentQuery {
    /// Whether to include the Service Data Groups (SDGs) in the response.
    #[serde(rename = "x-sovd2uds-includesdgs", alias = "x-include-sdgs", default)]
    pub include_sdgs: bool,

    /// Whether to include the JSON schema in the response.
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
    /// All physical ECUs loaded by the CDA, each as a resource reference
    /// (`href`, `id`, `name`) to its component.
    ///
    /// This list is unfiltered. Filtered subsets, if configured, are returned as
    /// additional top-level fields next to `items`. No ordering is guaranteed.
    pub items: Vec<T>,

    /// Additional fields extending the component response, keyed by field name.
    #[serde(flatten)]
    #[schemars(skip)]
    pub additional_fields: HashMap<String, Vec<T>>,

    /// Optional JSON schema for the response.
    #[schemars(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<schemars::Schema>,
}
