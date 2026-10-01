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

//! `apps/sovd2uds/operations/runtimefilesupdate`: the operation that applies,
//! rolls back or cleans up a runtime update.

use http::Method;
use sovd_interfaces::{
    Items,
    apps::sovd2uds::operations::runtimefilesupdate::{
        ExecutionMode, ExecutionParameters, ExecutionRequest, ExecutionResponse,
    },
    common::operations::OperationIdItem,
};

use crate::client::{Request, Response, Result, SovdTestClient, child};

/// The executions of the runtime update operation.
#[derive(Clone)]
pub(crate) struct RuntimeFilesUpdate<'a> {
    client: &'a SovdTestClient,
    path: String,
}

impl<'a> RuntimeFilesUpdate<'a> {
    pub(crate) fn new(client: &'a SovdTestClient, path: String) -> Self {
        Self { client, path }
    }

    /// Starts an execution in `mode`.
    ///
    /// # Errors
    /// See [`Request::send_json`].
    pub(crate) async fn start(&self, mode: ExecutionMode) -> Result<Response<OperationIdItem>> {
        self.request(Method::POST, "")
            .json(&ExecutionRequest {
                parameters: ExecutionParameters { mode },
            })
            .send_json()
            .await
    }

    /// Lists the executions.
    ///
    /// # Errors
    /// See [`Request::send_json`].
    pub(crate) async fn executions(&self) -> Result<Response<Items<OperationIdItem>>> {
        self.request(Method::GET, "").send_json().await
    }

    /// Reads the execution `id`.
    ///
    /// # Errors
    /// See [`Request::send_json`].
    pub(crate) async fn execution(&self, id: &str) -> Result<Response<ExecutionResponse>> {
        self.request(Method::GET, id).send_json().await
    }

    /// A request with `method` to the executions, or to the execution `path`
    /// if not empty, for requests without a typed method.
    pub(crate) fn request(&self, method: Method, path: &str) -> Request<'a> {
        if path.is_empty() {
            self.client.request(method, self.path.clone())
        } else {
            self.client.request(method, child(&self.path, path))
        }
    }
}
