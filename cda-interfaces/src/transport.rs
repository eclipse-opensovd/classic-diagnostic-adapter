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

//! Transport type selection for multi-transport routing.

use serde::{Deserialize, Serialize};

/// Identifies which physical transport is used to reach an ECU.
///
/// Used in per-ECU transport overrides (see `cda-comm-can`'s `TransportOverride`)
/// and in [`DiagnosticTransportRouter`](cda_transport_orchestrator::DiagnosticTransportRouter)
/// for the ECU-binding map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum TransportType {
    /// Diagnostics over IP (Ethernet)
    #[serde(alias = "DoIP", alias = "DOIP")]
    DoIP,
    /// CAN bus with ISO-TP
    #[serde(alias = "CAN", alias = "Can")]
    Can,
}
