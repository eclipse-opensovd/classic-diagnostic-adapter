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

pub mod modes;

/// Response structure for functional group operations
/// Returns parameters for multiple ECUs with ECU names as top-level keys
pub mod operations;

/// Response structure for functional group data operations
/// Returns data for multiple ECUs with ECU names as top-level keys
pub mod data;

use cda_interfaces::HashMap;
use serde::{Deserialize, Serialize};

use crate::error::DataError;

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FunctionalGroup {
    pub id: String,
    pub locks: String,
    pub operations: String,
    pub data: String,
    #[schemars(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<schemars::Schema>,
}

pub mod get {
    pub type Response = super::FunctionalGroup;
}
