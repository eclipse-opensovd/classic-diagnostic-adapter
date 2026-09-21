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

//! Paths of the SOVD resources of the CDA, relative to `/vehicle/v15/`, see
//! [`vehicle_url`](crate::util::http::vehicle_url).

use const_format::formatcp;

/// The `sovd2uds` app of the CDA.
const APPS_SOVD2UDS: &str = "apps/sovd2uds";
/// The network structure: gateways, and the ECUs behind them.
pub(crate) const APPS_SOVD2UDS_DATA_NETWORKSTRUCTURE: &str =
    formatcp!("{}/data/networkstructure", APPS_SOVD2UDS);
/// The version of the app.
pub(crate) const APPS_SOVD2UDS_DATA_VERSION: &str = formatcp!("{}/data/version", APPS_SOVD2UDS);
/// The bulk data categories of the app.
pub(crate) const APPS_SOVD2UDS_BULK_DATA: &str = formatcp!("{}/bulk-data", APPS_SOVD2UDS);
/// The flash files.
pub(crate) const APPS_SOVD2UDS_BULK_DATA_FLASHFILES: &str =
    formatcp!("{}/flashfiles", APPS_SOVD2UDS_BULK_DATA);
/// The operations of the app.
pub(crate) const APPS_SOVD2UDS_OPERATIONS: &str = formatcp!("{}/operations", APPS_SOVD2UDS);

// The ECUs of ecu-sim, by the name ecu-sim and the SOVD components use.
pub(crate) const ECU_FLXC1000: &str = "flxc1000";
const ECU_FLXCNG1000: &str = "flxcng1000";
pub(crate) const ECU_FSNR2000: &str = "fsnr2000";
pub(crate) const ECU_TMCC3000: &str = "tmcc3000";
pub(crate) const ECU_HOVR4000: &str = "hovr4000";
pub(crate) const ECU_JGWT5000: &str = "jgwt5000";
/// An ECU ecu-sim serves without a database, only reachable over CAN.
pub(crate) const ECU_TMC1001: &str = "tmc1001";

/// The components of the vehicle.
const COMPONENTS: &str = "components";

pub(crate) const COMPONENTS_FLXC1000_BASE: &str = formatcp!("{}/{}", COMPONENTS, ECU_FLXC1000);
pub(crate) const COMPONENTS_FLXCNG1000_BASE: &str = formatcp!("{}/{}", COMPONENTS, ECU_FLXCNG1000);
pub(crate) const COMPONENTS_FSNR2000_BASE: &str = formatcp!("{}/{}", COMPONENTS, ECU_FSNR2000);
pub(crate) const COMPONENTS_TMCC3000_BASE: &str = formatcp!("{}/{}", COMPONENTS, ECU_TMCC3000);
pub(crate) const COMPONENTS_HOVR4000_BASE: &str = formatcp!("{}/{}", COMPONENTS, ECU_HOVR4000);
pub(crate) const COMPONENTS_JGWT5000_BASE: &str = formatcp!("{}/{}", COMPONENTS, ECU_JGWT5000);

/// The data resources of FLXC1000.
pub(crate) const COMPONENTS_FLXC1000_DATA: &str = formatcp!("{}/data", COMPONENTS_FLXC1000_BASE);
/// The VIN of FLXC1000.
pub(crate) const COMPONENTS_FLXC1000_DATA_VINDATAIDENTIFIER: &str =
    formatcp!("{}/vindataidentifier", COMPONENTS_FLXC1000_DATA);
/// The data resources of FSNR2000.
pub(crate) const COMPONENTS_FSNR2000_DATA: &str = formatcp!("{}/data", COMPONENTS_FSNR2000_BASE);

/// The functional group of the `DoIP` ECUs.
pub(crate) const FUNCTIONS_FUNCTIONALGROUPS_DOIP_BASE: &str =
    "functions/functionalgroups/fgl_uds_ethernet_doip_dobt";
