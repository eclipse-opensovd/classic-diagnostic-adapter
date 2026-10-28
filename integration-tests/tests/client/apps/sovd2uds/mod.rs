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

//! `apps/sovd2uds`: the `sovd2uds` app, and its data.

use http::Method;
use sovd_interfaces::{
    ResourceResponse,
    apps::sovd2uds::{bulk_data::flash_files, data::network_structure},
};

use self::{bulk_data::RuntimeFiles, operations::RuntimeFilesUpdate};
use crate::client::{Request, Response, Result, SovdTestClient, child, data::Version};

pub(crate) mod bulk_data;
pub(crate) mod operations;

const PATH: &str = "apps/sovd2uds";

/// The `sovd2uds` app.
#[derive(Clone)]
pub(crate) struct Sovd2Uds<'a> {
    client: &'a SovdTestClient,
}

impl<'a> Sovd2Uds<'a> {
    pub(crate) fn new(client: &'a SovdTestClient) -> Self {
        Self { client }
    }

    /// The version of the app (`data/version`).
    ///
    /// # Errors
    /// See [`Request::send_json`].
    pub(crate) async fn version(&self) -> Result<Response<Version>> {
        self.request(Method::GET, "data/version").send_json().await
    }

    /// The network structure: the gateways and the ECUs behind them.
    ///
    /// # Errors
    /// See [`Request::send_json`].
    pub(crate) async fn network_structure(
        &self,
    ) -> Result<Response<network_structure::get::Response>> {
        self.request(Method::GET, "data/networkstructure")
            .send_json()
            .await
    }

    /// Lists the bulk data categories.
    ///
    /// # Errors
    /// See [`Request::send_json`].
    pub(crate) async fn bulk_data(&self) -> Result<Response<ResourceResponse>> {
        self.request(Method::GET, "bulk-data").send_json().await
    }

    /// Lists the flash files.
    ///
    /// # Errors
    /// See [`Request::send_json`].
    pub(crate) async fn flash_files(&self) -> Result<Response<flash_files::get::Response>> {
        self.request(Method::GET, "bulk-data/flashfiles")
            .send_json()
            .await
    }

    /// The databases in use (`runtimefiles-current`).
    pub(crate) fn runtime_files_current(&self) -> RuntimeFiles<'a> {
        self.runtime_files("runtimefiles-current")
    }

    /// The databases of the next update (`runtimefiles-nextupdate`).
    pub(crate) fn runtime_files_next_update(&self) -> RuntimeFiles<'a> {
        self.runtime_files("runtimefiles-nextupdate")
    }

    /// The databases before the last update (`runtimefiles-backup`).
    pub(crate) fn runtime_files_backup(&self) -> RuntimeFiles<'a> {
        self.runtime_files("runtimefiles-backup")
    }

    /// The operation that applies, rolls back or cleans up a runtime update.
    pub(crate) fn runtime_files_update(&self) -> RuntimeFilesUpdate<'a> {
        RuntimeFilesUpdate::new(
            self.client,
            format!("{PATH}/operations/runtimefilesupdate/executions"),
        )
    }

    /// A request with `method` to the sub-resource `path` of the app, for
    /// requests without a typed method.
    pub(crate) fn request(&self, method: Method, path: &str) -> Request<'a> {
        self.client.request(method, child(PATH, path))
    }

    fn runtime_files(&self, category: &str) -> RuntimeFiles<'a> {
        RuntimeFiles::new(self.client, format!("{PATH}/bulk-data/{category}"))
    }
}
