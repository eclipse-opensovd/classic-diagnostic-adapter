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

//! `components/{ecu}/faults`: the fault memory of a component.

use cda_sovd::VendorErrorCode;
use http::Method;
use sovd_interfaces::components::ecu::faults::{self, id::get::ExtendedFault};

use crate::client::{Request, Response, Result, SovdTestClient, child};

/// The fault memory of a component.
#[derive(Clone)]
pub(crate) struct Faults<'a> {
    client: &'a SovdTestClient,
    path: String,
}

impl<'a> Faults<'a> {
    pub(crate) fn new(client: &'a SovdTestClient, path: String) -> Self {
        Self { client, path }
    }

    /// Lists the faults.
    ///
    /// # Errors
    /// See [`Request::send_json`].
    pub(crate) async fn list(&self) -> Result<Response<faults::get::Response>> {
        self.request(Method::GET).send_json().await
    }

    /// Deletes all faults, in the user-defined `scope` if given.
    ///
    /// # Errors
    /// See [`Request::send`].
    pub(crate) async fn delete_all(&self, scope: Option<&str>) -> Result<Response<()>> {
        with_scope(self.request(Method::DELETE), scope)
            .send_empty()
            .await
    }

    /// The fault `code`, e.g. `01E240`.
    pub(crate) fn fault(&self, code: &str) -> FaultHandle<'a> {
        FaultHandle {
            client: self.client,
            path: child(&self.path, code),
        }
    }

    /// A request with `method` to the fault memory, for requests without a
    /// typed method.
    pub(crate) fn request(&self, method: Method) -> Request<'a> {
        self.client.request(method, self.path.clone())
    }
}

/// A fault of a component.
#[derive(Clone)]
pub(crate) struct FaultHandle<'a> {
    client: &'a SovdTestClient,
    path: String,
}

impl<'a> FaultHandle<'a> {
    /// Reads the fault, with its extended and snapshot data.
    ///
    /// # Errors
    /// See [`Request::send_json`].
    pub(crate) async fn get(&self) -> Result<Response<ExtendedFault<VendorErrorCode>>> {
        self.request(Method::GET).send_json().await
    }

    /// Deletes the fault, in the user-defined `scope` if given.
    ///
    /// # Errors
    /// See [`Request::send`].
    pub(crate) async fn delete(&self, scope: Option<&str>) -> Result<Response<()>> {
        with_scope(self.request(Method::DELETE), scope)
            .send_empty()
            .await
    }

    /// A request with `method` to the fault, for requests without a typed
    /// method.
    pub(crate) fn request(&self, method: Method) -> Request<'a> {
        self.client.request(method, self.path.clone())
    }
}

fn with_scope<'a>(request: Request<'a>, scope: Option<&str>) -> Request<'a> {
    match scope {
        Some(scope) => request.query("scope", scope),
        None => request,
    }
}
