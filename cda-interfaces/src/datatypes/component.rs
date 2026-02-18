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

use serde::{Deserialize, Serialize};

use crate::{HashMap, datatypes::SdBoolMappings};

pub struct ComponentDataInfo {
    pub category: String,
    pub id: String,
    pub name: String,
}

pub struct ComponentConfigurationsInfo {
    pub id: String,
    pub name: String,
    pub configurations_type: String,
    pub service_abstract: Vec<Vec<u8>>,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct ComponentsConfig {
    /// Allows to specify additional fields to be added to the component response.
    /// The key corresponds to the name of the field in the response.
    /// `SdBoolMappings` defines the conditions that a component must satisfy to be
    /// included in the additional field.
    pub additional_fields: HashMap<String, SdBoolMappings>,
}
