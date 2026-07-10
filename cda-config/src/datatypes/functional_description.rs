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

use cda_interfaces::HashSet;
use serde::{Deserialize, Serialize};

/// Functional group description and lookup configuration.
#[derive(Deserialize, Serialize, Clone, Debug, schemars::JsonSchema)]
pub struct FunctionalDescriptionConfig {
    /// Name of the database containing functional group definitions.
    pub description_database: String,
    /// Optional set of functional group names to enable.
    /// When absent, all functional groups are enabled.
    pub enabled_functional_groups: Option<HashSet<String>>,
    /// Position of the protocol identifier in service names.
    pub protocol_position: super::DiagnosticServiceAffixPosition,
}
impl Default for FunctionalDescriptionConfig {
    fn default() -> Self {
        Self {
            description_database: "functional_groups".to_owned(),
            enabled_functional_groups: None,
            protocol_position: super::DiagnosticServiceAffixPosition::Suffix,
        }
    }
}
