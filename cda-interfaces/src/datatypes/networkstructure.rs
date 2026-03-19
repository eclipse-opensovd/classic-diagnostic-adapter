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

use serde::Serialize;

use crate::EcuVariant;

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Ecu {
    pub qualifier: String,   // name
    pub variant: EcuVariant, // variant
    pub logical_address: String,
    pub logical_link: String, // ${qualifier}_on_${protocol}
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Gateway {
    pub name: String,
    pub network_address: String,
    pub logical_address: String,
    pub ecus: Vec<Ecu>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct FunctionalGroup {
    pub qualifier: String,
    pub ecus: Vec<Ecu>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct NetworkStructure {
    pub functional_groups: Vec<FunctionalGroup>,
    pub gateways: Vec<Gateway>,
}
