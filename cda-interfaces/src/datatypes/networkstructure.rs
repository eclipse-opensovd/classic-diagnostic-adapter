/*
 * SPDX-FileCopyrightText: 2025 Copyright (c) Contributors to the Eclipse Foundation
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

use crate::EcuState;

/// Internal ECU record produced by the UDS layer.
///
/// Converted to the SOVD JSON representation via [`IntoSovd`] in `cda-sovd`
pub struct Ecu {
    /// ECU qualifier (name).
    pub qualifier: String,
    /// Current variant/connectivity status. Mapped to `Variant` and `EcuState` strings by the
    /// SOVD layer.
    pub variant: EcuState,
    /// Logical address formatted as a hex string (e.g. `"0x2000"`).
    pub logical_address: String,
    /// Logical link name (e.g. `"ECU_on_UDS_Ethernet_DoIP"`).
    pub logical_link: String,
}

/// Gateway record, converted to SOVD JSON via [`IntoSovd`]
pub struct Gateway {
    /// Gateway name.
    pub name: String,
    /// Network address of the gateway.
    pub network_address: String,
    /// Logical address formatted as a hex string.
    pub logical_address: String,
    /// ECUs reachable through this gateway.
    pub ecus: Vec<Ecu>,
}

/// Functional group record, converted to SOVD JSON via [`IntoSovd`]
pub struct FunctionalGroup {
    /// Functional group qualifier.
    pub qualifier: String,
    /// ECUs belonging to this functional group.
    pub ecus: Vec<Ecu>,
}

/// Top-level network structure, converted to SOVD JSON via [`IntoSovd`]
pub struct NetworkStructure {
    /// All functional groups in the network.
    pub functional_groups: Vec<FunctionalGroup>,
    /// All gateways in the network.
    pub gateways: Vec<Gateway>,
}
