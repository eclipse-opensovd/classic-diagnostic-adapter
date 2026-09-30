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

//! `apps/sovd2uds/bulk-data`: the bulk data categories of the app, e.g. the
//! runtime files.

use http::Method;
use sovd_interfaces::apps::sovd2uds::bulk_data::{
    BulkDataCreatedList, BulkDataDeleted, BulkDataList,
};

use crate::client::{Request, Response, Result, SovdTestClient, child};

/// A category of runtime files, e.g. [`Sovd2Uds::runtime_files_next_update`].
#[derive(Clone)]
pub(crate) struct RuntimeFiles<'a> {
    client: &'a SovdTestClient,
    path: String,
}

impl<'a> RuntimeFiles<'a> {
    pub(crate) fn new(client: &'a SovdTestClient, path: String) -> Self {
        Self { client, path }
    }

    /// The path of the category, relative to `/vehicle/v15/`.
    pub(crate) fn path(&self) -> &str {
        &self.path
    }

    /// Lists the files.
    ///
    /// # Errors
    /// See [`Request::send_json`].
    pub(crate) async fn list(&self) -> Result<Response<BulkDataList>> {
        self.request(Method::GET).send_json().await
    }

    /// Uploads the files of `form`.
    ///
    /// # Errors
    /// See [`Request::send`].
    pub(crate) async fn upload(
        &self,
        form: reqwest::multipart::Form,
    ) -> Result<Response<BulkDataCreatedList>> {
        self.request(Method::POST).multipart(form).send_json().await
    }

    /// Uploads `bytes` as a single file with the given content type, and the
    /// `Content-Disposition` header `content_disposition` if given, which
    /// carries the file name.
    ///
    /// # Errors
    /// See [`Request::send_json`].
    pub(crate) async fn upload_bytes(
        &self,
        content_type: &str,
        bytes: Vec<u8>,
        content_disposition: Option<&str>,
    ) -> Result<Response<BulkDataCreatedList>> {
        let request = self.request(Method::POST).bytes(content_type, bytes);
        match content_disposition {
            Some(value) => request.header(reqwest::header::CONTENT_DISPOSITION, value),
            None => request,
        }
        .send_json()
        .await
    }

    /// Lists the files matching `query`, e.g.
    /// `[("created-after", "2025-01-01T00:00:00Z")]`.
    ///
    /// # Errors
    /// See [`Request::send_json`].
    pub(crate) async fn list_with(&self, query: &[(&str, &str)]) -> Result<Response<BulkDataList>> {
        query
            .iter()
            .fold(self.request(Method::GET), |request, (key, value)| {
                request.query(key, value)
            })
            .send_json()
            .await
    }

    /// Deletes all files.
    ///
    /// # Errors
    /// See [`Request::send_json`].
    pub(crate) async fn delete_all(&self) -> Result<Response<BulkDataDeleted>> {
        self.request(Method::DELETE).send_json().await
    }

    /// The file `id`.
    pub(crate) fn file(&self, id: &str) -> RuntimeFile<'a> {
        RuntimeFile {
            client: self.client,
            path: child(&self.path, id),
        }
    }

    /// A request with `method` to the category, for requests without a typed
    /// method, e.g. uploads with other content types, or queries.
    pub(crate) fn request(&self, method: Method) -> Request<'a> {
        self.client.request(method, self.path.clone())
    }
}

/// A runtime file.
#[derive(Clone)]
pub(crate) struct RuntimeFile<'a> {
    client: &'a SovdTestClient,
    path: String,
}

impl<'a> RuntimeFile<'a> {
    /// Reads the file, as the CDA sends it.
    ///
    /// # Errors
    /// See [`Request::send`].
    pub(crate) async fn get(&self) -> Result<Response> {
        self.request(Method::GET).send().await
    }

    /// Deletes the file.
    ///
    /// # Errors
    /// See [`Request::send`].
    pub(crate) async fn delete(&self) -> Result<Response<()>> {
        self.request(Method::DELETE).send_empty().await
    }

    /// A request with `method` to the file, for requests without a typed
    /// method.
    pub(crate) fn request(&self, method: Method) -> Request<'a> {
        self.client.request(method, self.path.clone())
    }
}
