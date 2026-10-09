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

//! Types of the `version-info` resource (ISO 17978-3 §5.6, Tables 36-38).
//!
//! The shape matches `opensovd_models::version` of opensovd-core, so the types can be
//! moved into the shared models crate without a wire change.

use serde::{Deserialize, Serialize};

/// A URI reference as used for `base_uri`.
pub type UriReference = String;

/// Response of `GET {host}[/{manufacturer}]/version-info` (Table 36).
#[derive(Debug, Serialize, Deserialize, Clone, schemars::JsonSchema)]
pub struct VersionInfo<V> {
    /// One entry per SOVD API instance offered by the server.
    pub sovd_info: Vec<SovdInfo<V>>,
    #[schemars(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<schemars::Schema>,
}

/// A single SOVD API instance (Table 37).
#[derive(Debug, Serialize, Deserialize, Clone, schemars::JsonSchema)]
pub struct SovdInfo<V> {
    /// Version of the SOVD standard implemented by this instance, e.g. `1.1.0`.
    pub version: String,
    /// Base URI of the instance, e.g. `/vehicle/v1`.
    pub base_uri: UriReference,
    /// Manufacturer specific information about the instance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor_info: Option<V>,
}

/// Default vendor info (Table 38 leaves the content to the manufacturer).
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, schemars::JsonSchema)]
pub struct VendorInfo {
    /// Version of the server implementation.
    pub version: String,
    /// Name of the server implementation.
    pub name: String,
}

/// Vendor info reported by the CDA: the default fields plus build details.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, schemars::JsonSchema)]
pub struct BuildVendorInfo {
    /// Name of the server implementation.
    pub name: String,
    /// Version of the server implementation.
    pub version: String,
    /// Git commit hash of the build.
    pub commit: String,
    /// Date the binary was built.
    pub build_date: String,
}

pub mod get {
    pub type Response<V> = super::VersionInfo<V>;
    pub type Query = crate::IncludeSchemaQuery;
}
