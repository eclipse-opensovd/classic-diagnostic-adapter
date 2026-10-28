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

//! `components/{ecu}/data`: the data resources of a component.

use cda_sovd::VendorErrorCode;
use http::Method;
use serde::Serialize;
use sovd_interfaces::{ObjectDataItem, components::ecu::ServicesSdgs};

use crate::client::{Request, Response, Result, SovdTestClient};

/// A data resource, e.g. `components/{ecu}/data/{id}`.
#[derive(Clone)]
pub(crate) struct DataHandle<'a> {
    client: &'a SovdTestClient,
    path: String,
}

impl<'a> DataHandle<'a> {
    pub(crate) fn new(client: &'a SovdTestClient, path: String) -> Self {
        Self { client, path }
    }

    /// Reads the data.
    ///
    /// # Errors
    /// See [`Request::send_json`].
    pub(crate) async fn get(&self) -> Result<Response<DataItem>> {
        self.request(Method::GET).send_json().await
    }

    /// Writes `data`. Returns the answer of the ECU, or `None` if it answered
    /// without data.
    ///
    /// # Errors
    /// See [`Request::send_json`].
    pub(crate) async fn put(&self, data: &impl Serialize) -> Result<Response<Option<DataItem>>> {
        self.request(Method::PUT).json(data).send_json_opt().await
    }

    /// Reads the special data groups of the data resource
    /// (`x-sovd2uds-includesdgs`).
    ///
    /// # Errors
    /// See [`Request::send_json`].
    pub(crate) async fn sdgs(&self) -> Result<Response<ServicesSdgs>> {
        self.request(Method::GET)
            .query("x-sovd2uds-includesdgs", "true")
            .send_json()
            .await
    }

    /// A request with `method` to the resource, for requests without a typed
    /// method, e.g. with query parameters.
    pub(crate) fn request(&self, method: Method) -> Request<'a> {
        self.client.request(method, self.path.clone())
    }
}

/// The value of a data resource.
pub(crate) type DataItem = ObjectDataItem<VendorErrorCode>;
