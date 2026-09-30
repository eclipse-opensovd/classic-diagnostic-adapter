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

//! `components/{ecu}/modes/{id}`: a mode of a component. Functional groups
//! have modes of the same shape (`functions/functionalgroups/{fg}/modes`).

use http::Method;
use serde::{Serialize, de::DeserializeOwned};

use crate::client::{Request, Response, Result, SovdTestClient};

/// A mode of an entity, e.g. `session`, `security`, `commctrl` or
/// `dtcsetting`. Requests and responses differ per mode, so the typed methods
/// take the `sovd_interfaces` types of the mode, e.g.
/// `modes::security_and_session::put::SessionRequest`.
#[derive(Clone)]
pub(crate) struct ModeHandle<'a> {
    client: &'a SovdTestClient,
    path: String,
}

impl<'a> ModeHandle<'a> {
    pub(crate) fn new(client: &'a SovdTestClient, path: String) -> Self {
        Self { client, path }
    }

    /// Reads the mode, e.g. as a
    /// `sovd_interfaces::common::modes::get::Mode<String>`.
    ///
    /// # Errors
    /// See [`Request::send_json`].
    pub(crate) async fn get<T: DeserializeOwned>(&self) -> Result<Response<T>> {
        self.request(Method::GET).send_json().await
    }

    /// Sets the mode with `request`, and returns the response, e.g. a
    /// `sovd_interfaces::common::modes::put::Response<String>`.
    ///
    /// # Errors
    /// See [`Request::send_json`].
    pub(crate) async fn put<T: DeserializeOwned>(
        &self,
        request: &impl Serialize,
    ) -> Result<Response<T>> {
        self.request(Method::PUT).json(request).send_json().await
    }

    /// A request with `method` to the mode, for requests without a typed
    /// method.
    pub(crate) fn request(&self, method: Method) -> Request<'a> {
        self.client.request(method, self.path.clone())
    }
}
