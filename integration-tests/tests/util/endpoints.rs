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
pub(crate) const SOVD2UDS: &str = "apps/sovd2uds";
/// The network structure: gateways, and the ECUs behind them.
pub(crate) const SOVD2UDS_NETWORK_STRUCTURE: &str = formatcp!("{}/data/networkstructure", SOVD2UDS);
/// The version of the app.
pub(crate) const SOVD2UDS_VERSION: &str = formatcp!("{}/data/version", SOVD2UDS);
/// The bulk data categories of the app.
pub(crate) const SOVD2UDS_BULK_DATA: &str = formatcp!("{}/bulk-data", SOVD2UDS);
/// The flash files.
pub(crate) const SOVD2UDS_FLASH_FILES: &str = formatcp!("{}/flashfiles", SOVD2UDS_BULK_DATA);
/// The operations of the app.
pub(crate) const SOVD2UDS_OPERATIONS: &str = formatcp!("{}/operations", SOVD2UDS);

// The ECUs of ecu-sim, by the name ecu-sim and the SOVD components use.
pub(crate) const ECU_FLXC1000: &str = "flxc1000";
pub(crate) const ECU_FLXCNG1000: &str = "flxcng1000";
pub(crate) const ECU_FSNR2000: &str = "fsnr2000";
pub(crate) const ECU_TMCC3000: &str = "tmcc3000";
pub(crate) const ECU_HOVR4000: &str = "hovr4000";
pub(crate) const ECU_JGWT5000: &str = "jgwt5000";

pub(crate) const ECU_FLXC1000_ENDPOINT: &str = formatcp!("components/{}", ECU_FLXC1000);
pub(crate) const ECU_FLXCNG1000_ENDPOINT: &str = formatcp!("components/{}", ECU_FLXCNG1000);
pub(crate) const ECU_FSNR2000_ENDPOINT: &str = formatcp!("components/{}", ECU_FSNR2000);
pub(crate) const ECU_TMCC3000_ENDPOINT: &str = formatcp!("components/{}", ECU_TMCC3000);
pub(crate) const ECU_HOVR4000_ENDPOINT: &str = formatcp!("components/{}", ECU_HOVR4000);
pub(crate) const ECU_JGWT5000_ENDPOINT: &str = formatcp!("components/{}", ECU_JGWT5000);

/// The data resources of FLXC1000.
pub(crate) const ECU_FLXC1000_DATA_ENDPOINT: &str = formatcp!("{}/data", ECU_FLXC1000_ENDPOINT);
/// The VIN of FLXC1000.
pub(crate) const ECU_FLXC1000_VIN_ENDPOINT: &str =
    formatcp!("{}/vindataidentifier", ECU_FLXC1000_DATA_ENDPOINT);

/// The functional group of the `DoIP` ECUs.
pub(crate) const FUNCTIONAL_GROUP_ENDPOINT: &str =
    "functions/functionalgroups/fgl_uds_ethernet_doip_dobt";
