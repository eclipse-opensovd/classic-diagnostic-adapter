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

//! Types of the version endpoints: the `version-info` resource (ISO 17978-3 §7.4.2,
//! Tables 36-38) and the vendor-specific `data/version` resources.

use serde::{Deserialize, Serialize};

/// Response of `GET {host}[/{manufacturer}]/version-info` (Table 36).
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, schemars::JsonSchema)]
pub struct VersionInfo {
    /// One entry per SOVD API version offered by the server.
    pub sovd_info: Vec<SovdInfo>,
    #[schemars(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<schemars::Schema>,
}

/// A single SOVD API version (Table 37).
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, schemars::JsonSchema)]
pub struct SovdInfo {
    /// Version of the SOVD standard implemented by this API version, e.g. `1.1.0`.
    pub version: String,
    /// Base URI of this API version, a URI reference such as `/vehicle/v1`.
    pub base_uri: String,
    /// Information about the server implementation.
    pub vendor_info: VendorInfo,
}

/// Information about the server implementation (Table 38: `name` and `version`, plus the
/// build details the standard allows as additional vendor specific information).
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, schemars::JsonSchema)]
pub struct VendorInfo {
    /// Name of the server implementation.
    pub name: String,
    /// Version of the server implementation.
    pub version: String,
    /// Git commit hash of the build.
    pub commit: String,
    /// Date the binary was built.
    pub build_date: String,
}

/// Response of the vendor-specific `GET .../data/version` resources.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, schemars::JsonSchema)]
pub struct DataVersion {
    /// Identifier of the data resource, `version`.
    pub id: String,
    /// The version data.
    pub data: VersionData,
    #[schemars(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<schemars::Schema>,
}

/// Version data of the server implementation.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, schemars::JsonSchema)]
pub struct VersionData {
    /// Name of the server implementation.
    pub name: String,
    /// The implemented SOVD API.
    pub api: ApiVersion,
    /// The server implementation.
    pub implementation: ImplementationVersion,
}

/// Version of the implemented SOVD API.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, schemars::JsonSchema)]
pub struct ApiVersion {
    /// Version of the SOVD standard, e.g. `1.1.0`.
    pub version: String,
}

/// Version and build of the server implementation.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, schemars::JsonSchema)]
pub struct ImplementationVersion {
    /// Version of the server implementation.
    pub version: String,
    /// Git commit hash of the build.
    pub commit: String,
    /// Date the binary was built.
    pub build_date: String,
}
