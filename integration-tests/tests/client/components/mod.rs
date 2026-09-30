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

//! `components/{ecu}`: a component, and its configurations.

use std::time::Duration;

use http::{Method, StatusCode};
use serde::Serialize;
use sovd_interfaces::{
    Items,
    common::operations::OperationCollectionItem,
    components::ecu::{self, configurations, data as ecu_data, modes as ecu_modes},
};

use self::{
    data::DataHandle, faults::Faults, modes::ModeHandle, operations::Operation,
    x_sovd2uds_download::Download,
};
use crate::client::{
    Request, Response, Result, SovdTestClient, child,
    locks::{LockHandle, Locks},
};

pub(crate) mod data;
pub(crate) mod faults;
pub(crate) mod modes;
pub(crate) mod operations;
pub(crate) mod x_sovd2uds_download;

/// A component, e.g. an ECU.
#[derive(Clone)]
pub(crate) struct Component<'a> {
    client: &'a SovdTestClient,
    path: String,
}

impl<'a> Component<'a> {
    pub(crate) fn new(client: &'a SovdTestClient, path: String) -> Self {
        Self { client, path }
    }

    /// Reads the component.
    ///
    /// # Errors
    /// See [`Request::send_json`].
    pub(crate) async fn get(&self) -> Result<Response<ecu::get::Response>> {
        self.request(Method::GET, "").send_json().await
    }

    /// Reads the component with the query parameters `query`, e.g. a
    /// [`sovd_interfaces::components::ComponentQuery`] to include its special
    /// data groups.
    ///
    /// # Errors
    /// See [`Request::send_json`].
    pub(crate) async fn get_with(
        &self,
        query: &impl Serialize,
    ) -> Result<Response<ecu::get::Response>> {
        self.request(Method::GET, "")
            .query_params(query)
            .send_json()
            .await
    }

    /// Sends the raw UDS request `payload` to the component
    /// (`genericservice`), and returns the raw UDS response.
    ///
    /// # Errors
    /// See [`Request::send`].
    pub(crate) async fn generic_service(&self, payload: &[u8]) -> Result<Response<Vec<u8>>> {
        let octet_stream = mime::APPLICATION_OCTET_STREAM.essence_str();
        Ok(self
            .request(Method::PUT, "genericservice")
            .header(http::header::ACCEPT, octet_stream)
            .bytes(octet_stream, payload.to_vec())
            .send()
            .await?
            .map(Option::unwrap_or_default))
    }

    /// Triggers the variant detection of the component.
    ///
    /// # Errors
    /// See [`Request::send`].
    pub(crate) async fn detect_variant(&self) -> Result<Response<()>> {
        self.request(Method::PUT, "").send_empty().await
    }

    /// Lists the data resources.
    ///
    /// # Errors
    /// See [`Request::send_json`].
    pub(crate) async fn data_list(&self) -> Result<Response<ecu_data::get::Response>> {
        self.request(Method::GET, "data").send_json().await
    }

    /// Lists the data resources, repeating the request as long as the CDA
    /// answers `pending`, e.g. `503 Service Unavailable` while its
    /// communication is deferred.
    ///
    /// # Errors
    /// See [`Request::poll_while`], or
    /// [`Error::InvalidResponse`](crate::client::Error::InvalidResponse) if the
    /// body is not a data list.
    pub(crate) async fn poll_data_list_while(
        &self,
        pending: StatusCode,
        timeout: Duration,
    ) -> Result<Response<ecu_data::get::Response>> {
        self.request(Method::GET, "data")
            .poll_while(pending, timeout)
            .await?
            .json()
    }

    /// The data resource `id`.
    pub(crate) fn data(&self, id: &str) -> DataHandle<'a> {
        DataHandle::new(self.client, child(&self.path, &format!("data/{id}")))
    }

    /// Lists the configurations.
    ///
    /// # Errors
    /// See [`Request::send_json`].
    pub(crate) async fn configurations(&self) -> Result<Response<configurations::get::Response>> {
        self.request(Method::GET, "configurations")
            .send_json()
            .await
    }

    /// Reads the configuration `id`.
    ///
    /// # Errors
    /// See [`Request::send_json`].
    pub(crate) async fn configuration(
        &self,
        id: &str,
    ) -> Result<Response<configurations::get_service::Response>> {
        self.request(Method::GET, &format!("configurations/{id}"))
            .send_json()
            .await
    }

    /// The fault memory.
    pub(crate) fn faults(&self) -> Faults<'a> {
        Faults::new(self.client, child(&self.path, "faults"))
    }

    /// Lists the modes.
    ///
    /// # Errors
    /// See [`Request::send_json`].
    pub(crate) async fn modes(&self) -> Result<Response<ecu_modes::get::Response>> {
        self.request(Method::GET, "modes").send_json().await
    }

    /// The mode `id`, e.g. [`sovd_interfaces::common::modes::SESSION_ID`].
    pub(crate) fn mode(&self, id: &str) -> ModeHandle<'a> {
        ModeHandle::new(self.client, child(&self.path, &format!("modes/{id}")))
    }

    /// Lists the operations.
    ///
    /// # Errors
    /// See [`Request::send_json`].
    pub(crate) async fn operations(&self) -> Result<Response<Items<OperationCollectionItem>>> {
        self.request(Method::GET, "operations").send_json().await
    }

    /// The operation `id`.
    pub(crate) fn operation(&self, id: &str) -> Operation<'a> {
        Operation::new(self.client, child(&self.path, &format!("operations/{id}")))
    }

    /// The locks of the component.
    pub(crate) fn locks(&self) -> Locks<'a> {
        Locks::new(self.client, child(&self.path, "locks"))
    }

    /// The lock `id` of the component.
    pub(crate) fn lock(&self, id: &str) -> LockHandle<'a> {
        self.locks().lock(id)
    }

    /// The flash download (`x-sovd2uds-download`).
    pub(crate) fn download(&self) -> Download<'a> {
        Download::new(self.client, child(&self.path, "x-sovd2uds-download"))
    }

    /// A request with `method` to the sub-resource `path` of the component,
    /// or to the component itself if `path` is empty, for requests without a
    /// typed method.
    pub(crate) fn request(&self, method: Method, path: &str) -> Request<'a> {
        if path.is_empty() {
            self.client.request(method, self.path.clone())
        } else {
            self.client.request(method, child(&self.path, path))
        }
    }
}
