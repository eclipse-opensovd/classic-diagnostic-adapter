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

//! `components/{ecu}/x-sovd2uds-download`: the flash download of a component.

use cda_sovd::VendorErrorCode;
use http::Method;
use sovd_interfaces::{
    Items,
    components::ecu::x::sovd2uds::download::{
        flash_transfer::{self, get::DataTransferMetaData},
        request_download,
    },
};

use crate::client::{Request, Response, Result, SovdTestClient, child};

/// The flash download of a component (`x-sovd2uds-download`).
#[derive(Clone)]
pub(crate) struct Download<'a> {
    client: &'a SovdTestClient,
    path: String,
}

impl<'a> Download<'a> {
    pub(crate) fn new(client: &'a SovdTestClient, path: String) -> Self {
        Self { client, path }
    }

    /// Requests a download with the `RequestDownload` parameters
    /// `parameters`. Returns the answer of the ECU, or `None` if it answered
    /// without data.
    ///
    /// # Errors
    /// See [`Request::send`].
    pub(crate) async fn request_download(
        &self,
        parameters: &serde_json::Value,
    ) -> Result<Response<Option<request_download::put::Response<VendorErrorCode>>>> {
        self.request(Method::PUT, "requestdownload")
            .json(&serde_json::json!({ "requestdownload": parameters }))
            .send_json_opt()
            .await
    }

    /// Starts transferring a flash file.
    ///
    /// # Errors
    /// See [`Request::send_json`].
    pub(crate) async fn start_transfer(
        &self,
        request: &flash_transfer::post::Request,
    ) -> Result<Response<flash_transfer::post::Response>> {
        self.request(Method::POST, "flashtransfer")
            .json(request)
            .send_json()
            .await
    }

    /// Lists the transfers.
    ///
    /// # Errors
    /// See [`Request::send_json`].
    pub(crate) async fn transfers(&self) -> Result<Response<Items<DataTransferMetaData>>> {
        self.request(Method::GET, "flashtransfer").send_json().await
    }

    /// Reads the state of the transfer `id`.
    ///
    /// # Errors
    /// See [`Request::send_json`].
    pub(crate) async fn transfer(&self, id: &str) -> Result<Response<DataTransferMetaData>> {
        self.request(Method::GET, &format!("flashtransfer/{id}"))
            .send_json()
            .await
    }

    /// Deletes the transfer `id`.
    ///
    /// # Errors
    /// See [`Request::send`].
    pub(crate) async fn delete_transfer(&self, id: &str) -> Result<Response<()>> {
        self.request(Method::DELETE, &format!("flashtransfer/{id}"))
            .send_empty()
            .await
    }

    /// Ends the transfer (`RequestTransferExit`).
    ///
    /// # Errors
    /// See [`Request::send`].
    pub(crate) async fn transfer_exit(&self) -> Result<Response<()>> {
        self.request(Method::PUT, "transferexit").send_empty().await
    }

    /// A request with `method` to the sub-resource `path` of the download,
    /// for requests without a typed method, e.g. with invalid bodies.
    pub(crate) fn request(&self, method: Method, path: &str) -> Request<'a> {
        self.client.request(method, child(&self.path, path))
    }
}
