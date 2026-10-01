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

//! [`SovdTestClient`], the client the tests reach the SOVD API of the CDA
//! with.
//!
//! Shaped like `opensovd_client::Client`: entity handles such as
//! [`SovdTestClient::component`] with typed methods returning the
//! `sovd_interfaces` types, and a non-success status as [`Error::Api`], so
//! that the tests can move to that client once it covers what they use.
//! A success comes as a [`Response`], which carries the status and headers
//! for the tests to check, e.g. with [`Response::expect_status`], and
//! dereferences to the typed body.
//!
//! The modules mirror the SOVD resource tree below `/vehicle/v15`.
//! [`SovdTestClient::request`] reaches resources without a typed method, and
//! requests the typed methods do not send, e.g. malformed ones.

#![allow(
    dead_code,
    reason = "The client covers the SOVD resources of the CDA, a superset of what the tests use \
              today, as a base for opensovd-client"
)]

pub(crate) mod apps;
pub(crate) mod components;
pub(crate) mod data;
mod error;
pub(crate) mod functions;
pub(crate) mod locks;
mod request;

use http::Method;
use opensovd_cda_lib::config::configfile::Configuration;
use serde::{Deserialize, Serialize};

use self::{
    apps::sovd2uds::Sovd2Uds, components::Component, data::Version,
    functions::functional_groups::FunctionalGroup, locks::Locks,
};
pub(crate) use self::{
    error::{Error, Result},
    request::{Request, Response},
};

/// The client id [`SovdTestClient::authorize`] uses by default.
pub(crate) const DEFAULT_CLIENT_ID: &str = "test_client";
const CLIENT_SECRET: &str = "test_secret";

/// A client of the SOVD API (`/vehicle/v15`) of one CDA, optionally
/// authorized with a bearer token. Cheap to clone.
#[derive(Clone, Debug)]
pub(crate) struct SovdTestClient {
    /// `http://host:port/vehicle/v15`, without a trailing slash.
    base_url: String,
    token: Option<String>,
}

/// The body of `POST authorize`. `sovd_interfaces` has no type for it.
#[derive(Serialize)]
struct AuthorizeRequest<'a> {
    client_id: &'a str,
    client_secret: &'a str,
}

/// The response of `POST authorize`. `sovd_interfaces` has no type for it.
#[derive(Deserialize)]
struct AuthorizeResponse {
    access_token: String,
}

impl SovdTestClient {
    /// An unauthorized client of the CDA configured by `config`.
    pub(crate) fn new(config: &Configuration) -> Self {
        Self {
            base_url: format!(
                "http://{}:{}/vehicle/v15",
                config.server.address(),
                config.server.port()
            ),
            token: None,
        }
    }

    /// A client of the CDA configured by `config`, authorized as the test
    /// client `client_id`, e.g. [`DEFAULT_CLIENT_ID`].
    ///
    /// # Errors
    /// Returns an error if the CDA does not authorize the client.
    pub(crate) async fn authorize(config: &Configuration, client_id: &str) -> Result<Self> {
        let client = Self::new(config);
        let response = client
            .request(Method::POST, "authorize")
            .json(&AuthorizeRequest {
                client_id,
                client_secret: CLIENT_SECRET,
            })
            .send_json::<AuthorizeResponse>()
            .await?
            .into_body();
        Ok(client.with_token(response.access_token))
    }

    /// This client, sending `token` as its bearer token.
    pub(crate) fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    /// The URL of `path`, relative to `/vehicle/v15/`.
    pub(crate) fn url(&self, path: &str) -> String {
        format!("{}/{path}", self.base_url)
    }

    /// A component, e.g. an ECU.
    pub(crate) fn component(&self, id: &str) -> Component<'_> {
        Component::new(self, format!("components/{id}"))
    }

    /// A functional group.
    pub(crate) fn functional_group(&self, id: &str) -> FunctionalGroup<'_> {
        FunctionalGroup::new(self, format!("functions/functionalgroups/{id}"))
    }

    /// The `sovd2uds` app.
    pub(crate) fn sovd2uds(&self) -> Sovd2Uds<'_> {
        Sovd2Uds::new(self)
    }

    /// The locks of the vehicle.
    pub(crate) fn locks(&self) -> Locks<'_> {
        Locks::new(self, "locks".to_owned())
    }

    /// The locks at `path`, relative to `/vehicle/v15/`, for tests that
    /// iterate over lock collections.
    pub(crate) fn locks_at(&self, path: &str) -> Locks<'_> {
        Locks::new(self, path.to_owned())
    }

    /// The version of the SOVD API of the vehicle (`data/version`).
    ///
    /// # Errors
    /// See [`Request::send_json`].
    pub(crate) async fn version(&self) -> Result<Response<Version>> {
        self.request(Method::GET, "data/version").send_json().await
    }

    /// A request with `method` to `path`, relative to `/vehicle/v15/`, for
    /// resources without a typed method.
    pub(crate) fn request(&self, method: Method, path: impl Into<String>) -> Request<'_> {
        Request::new(self, method, path.into())
    }

    /// The headers every request of this client carries: the bearer token.
    pub(crate) fn headers(&self) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        if let Some(token) = &self.token {
            headers.insert(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {token}")
                    .parse()
                    .expect("invalid bearer token"),
            );
        }
        headers
    }
}

/// `path/child`.
fn child(path: &str, child: &str) -> String {
    format!("{path}/{child}")
}
