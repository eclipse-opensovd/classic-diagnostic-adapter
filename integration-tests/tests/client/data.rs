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

//! `/vehicle/v15/data`: data of the vehicle.

use serde::Deserialize;

/// The version of an SOVD API, e.g. [`SovdTestClient::version`].
/// `sovd_interfaces` has no type for it.
#[derive(Debug, Deserialize)]
pub(crate) struct Version {
    pub(crate) id: String,
    pub(crate) data: VersionData,
}

#[derive(Debug, Deserialize)]
pub(crate) struct VersionData {
    pub(crate) name: String,
    pub(crate) api: ApiVersion,
    pub(crate) implementation: ImplementationVersion,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ApiVersion {
    pub(crate) version: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ImplementationVersion {
    pub(crate) version: String,
    pub(crate) commit: String,
    pub(crate) build_date: String,
}
