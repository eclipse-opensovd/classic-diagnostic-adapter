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

use std::time::{Duration, Instant};

use http::{HeaderMap, Method, StatusCode};
use serde::{Serialize, de::DeserializeOwned};

use crate::client::{Error, Result, SovdTestClient};

/// How long a single request may take.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Delay between the requests of [`Request::poll_while`].
const POLL_INTERVAL: Duration = Duration::from_millis(100);

enum Body {
    None,
    Bytes {
        content_type: String,
        bytes: Vec<u8>,
    },
    Multipart(reqwest::multipart::Form),
}

/// A request to the CDA, sent by [`Self::send`], [`Self::send_json`] or
/// [`Self::poll_while`]. The typed methods of the client build on it, and it
/// reaches resources without a typed method.
#[must_use = "a request is only sent by `send`, `send_json` or `poll_while`"]
pub(crate) struct Request<'a> {
    client: &'a SovdTestClient,
    method: Method,
    path: String,
    query: Vec<(String, String)>,
    headers: HeaderMap,
    body: Body,
}

impl<'a> Request<'a> {
    pub(crate) fn new(client: &'a SovdTestClient, method: Method, path: String) -> Self {
        Self {
            client,
            method,
            path,
            query: Vec::new(),
            headers: HeaderMap::new(),
            body: Body::None,
        }
    }

    /// Adds the header `name: value`.
    pub(crate) fn header(mut self, name: http::header::HeaderName, value: &str) -> Self {
        self.headers
            .insert(name, value.parse().expect("invalid header value"));
        self
    }

    /// Sends `body` as JSON.
    pub(crate) fn json(self, body: &impl Serialize) -> Self {
        let bytes = serde_json::to_vec(body).expect("request body serializes to JSON");
        self.bytes(mime::APPLICATION_JSON.essence_str(), bytes)
    }

    /// Sends `body` as JSON as it is, e.g. to test malformed requests.
    pub(crate) fn raw_json(self, body: impl Into<String>) -> Self {
        self.bytes(
            mime::APPLICATION_JSON.essence_str(),
            body.into().into_bytes(),
        )
    }

    /// Sends `bytes` with the given content type.
    pub(crate) fn bytes(mut self, content_type: &str, bytes: Vec<u8>) -> Self {
        self.body = Body::Bytes {
            content_type: content_type.to_owned(),
            bytes,
        };
        self
    }

    /// Sends `form` as `multipart/form-data`.
    pub(crate) fn multipart(mut self, form: reqwest::multipart::Form) -> Self {
        self.body = Body::Multipart(form);
        self
    }

    /// Adds the query parameter `key=value`.
    pub(crate) fn query(mut self, key: &str, value: &str) -> Self {
        self.query.push((key.to_owned(), value.to_owned()));
        self
    }

    /// Adds the query parameters of `query`, e.g. a query type of
    /// `sovd_interfaces`, serialized as a flat map of its fields. Fields that
    /// serialize to `null` are left out.
    pub(crate) fn query_params(mut self, query: &impl Serialize) -> Self {
        let serde_json::Value::Object(fields) =
            serde_json::to_value(query).expect("query parameters serialize to JSON")
        else {
            panic!("query parameters must serialize to a JSON object");
        };
        for (key, value) in fields {
            let value = match value {
                serde_json::Value::Null => continue,
                serde_json::Value::String(value) => value,
                other => other.to_string(),
            };
            self.query.push((key, value));
        }
        self
    }

    /// The URL the request goes to.
    pub(crate) fn url(&self) -> String {
        let url = self.client.url(&self.path);
        if self.query.is_empty() {
            return url;
        }
        let query = self
            .query
            .iter()
            .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        format!("{url}?{query}")
    }

    /// Sends the request.
    ///
    /// # Errors
    /// Returns [`Error::Api`] if the CDA answers with a status other than a
    /// success, or [`Error::Transport`] if the request fails.
    pub(crate) async fn send(self) -> Result<Response> {
        let url = self.url();
        let mut builder = reqwest::Client::new()
            .request(self.method, &url)
            .headers(self.client.headers())
            .headers(self.headers)
            .timeout(REQUEST_TIMEOUT);
        builder = match self.body {
            Body::None => builder,
            Body::Bytes {
                content_type,
                bytes,
            } => builder
                .header(reqwest::header::CONTENT_TYPE, content_type)
                .body(bytes),
            Body::Multipart(form) => builder.multipart(form),
        };
        let response = builder.send().await.map_err(|e| Error::Transport {
            url: url.clone(),
            message: e.to_string(),
        })?;
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.bytes().await.map_err(|e| Error::Transport {
            url: url.clone(),
            message: format!("failed to read the body: {e}"),
        })?;
        let body = (!body.is_empty()).then(|| body.to_vec());
        if !status.is_success() {
            return Err(Error::Api {
                status,
                url,
                headers: Box::new(headers),
                body: body.map(|body| String::from_utf8_lossy(&body).into_owned()),
            });
        }
        Ok(Response {
            status,
            url,
            headers,
            body,
        })
    }

    /// Sends the request and deserializes the body of the response.
    ///
    /// # Errors
    /// See [`Self::send`], or [`Error::InvalidResponse`] if the body is not a
    /// `T`.
    pub(crate) async fn send_json<T: DeserializeOwned>(self) -> Result<Response<T>> {
        self.send().await?.json()
    }

    /// Sends the request and deserializes the body of the response, if the
    /// CDA sent one.
    ///
    /// # Errors
    /// See [`Self::send`], or [`Error::InvalidResponse`] if the body is not a
    /// `T`.
    pub(crate) async fn send_json_opt<T: DeserializeOwned>(self) -> Result<Response<Option<T>>> {
        self.send().await?.json_opt()
    }

    /// Sends the request and drops the body of the response.
    ///
    /// # Errors
    /// See [`Self::send`].
    pub(crate) async fn send_empty(self) -> Result<Response<()>> {
        Ok(self.send().await?.ignore_body())
    }

    /// Sends the request as long as the CDA answers `pending`, and returns
    /// the outcome of the first request answered otherwise. Only for requests
    /// without a body.
    ///
    /// # Errors
    /// Returns [`Error::Timeout`] if the CDA still answers `pending` after
    /// `timeout`, or the error of the first request not answered `pending`.
    pub(crate) async fn poll_while(
        self,
        pending: StatusCode,
        timeout: Duration,
    ) -> Result<Response> {
        assert!(
            matches!(self.body, Body::None),
            "only requests without a body can be repeated"
        );
        let deadline = Instant::now()
            .checked_add(timeout)
            .expect("Timeout is too large");
        loop {
            let request = Request {
                client: self.client,
                method: self.method.clone(),
                path: self.path.clone(),
                query: self.query.clone(),
                headers: self.headers.clone(),
                body: Body::None,
            };
            match request.send().await {
                Err(error) if error.status() == Some(pending) => {
                    if Instant::now() >= deadline {
                        return Err(Error::Timeout(format!(
                            "{} still answers {pending} after {timeout:?}",
                            self.path
                        )));
                    }
                    cda_interfaces::util::tokio_ext::sleep_for(POLL_INTERVAL).await;
                }
                Ok(response) if response.status() == pending => {
                    if Instant::now() >= deadline {
                        return Err(Error::Timeout(format!(
                            "{} still answers {pending} after {timeout:?}",
                            self.path
                        )));
                    }
                    cda_interfaces::util::tokio_ext::sleep_for(POLL_INTERVAL).await;
                }
                outcome => return outcome,
            }
        }
    }
}

/// A successful response of the CDA: its status and headers, and its body
/// as a `T`, which it dereferences to. Unread, the body is the bytes the CDA
/// sent, if any, see [`Self::json`].
///
/// Tests check the status with [`Self::expect_status`].
#[derive(Debug)]
pub(crate) struct Response<T = Option<Vec<u8>>> {
    status: StatusCode,
    url: String,
    headers: HeaderMap,
    body: T,
}

impl<T> Response<T> {
    pub(crate) fn status(&self) -> StatusCode {
        self.status
    }

    /// The URL the request went to.
    pub(crate) fn url(&self) -> &str {
        &self.url
    }

    pub(crate) fn header(&self, name: http::header::HeaderName) -> Option<&http::HeaderValue> {
        self.headers.get(name)
    }

    /// The `Location` header, e.g. of a created resource.
    pub(crate) fn location(&self) -> Option<&str> {
        self.header(http::header::LOCATION)
            .and_then(|value| value.to_str().ok())
    }

    /// Checks that the CDA answered `expected`.
    ///
    /// # Panics
    /// If the CDA answered another status.
    #[track_caller]
    pub(crate) fn expect_status(self, expected: StatusCode) -> Self {
        assert_eq!(self.status, expected, "unexpected status from {}", self.url);
        self
    }

    /// The body.
    pub(crate) fn into_body(self) -> T {
        self.body
    }

    /// The response with the body `f` makes of this body.
    pub(crate) fn map<U>(self, f: impl FnOnce(T) -> U) -> Response<U> {
        Response {
            status: self.status,
            url: self.url,
            headers: self.headers,
            body: f(self.body),
        }
    }

    /// The response with the body `f` makes of this response, e.g. from its
    /// headers.
    ///
    /// # Errors
    /// The error of `f`.
    pub(crate) fn try_map<U>(self, f: impl FnOnce(&Self) -> Result<U>) -> Result<Response<U>> {
        let body = f(&self)?;
        Ok(Response {
            status: self.status,
            url: self.url,
            headers: self.headers,
            body,
        })
    }
}

impl<T> std::ops::Deref for Response<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.body
    }
}

impl<T> std::ops::DerefMut for Response<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.body
    }
}

impl Response {
    /// The body as text, `None` if the CDA sent none or no UTF-8.
    pub(crate) fn text(&self) -> Option<&str> {
        self.body
            .as_deref()
            .and_then(|body| std::str::from_utf8(body).ok())
    }

    /// Deserializes the body.
    ///
    /// # Errors
    /// Returns [`Error::InvalidResponse`] if there is no body or it is not a
    /// `T`.
    pub(crate) fn json<T: DeserializeOwned>(self) -> Result<Response<T>> {
        let body = self.parse()?;
        Ok(self.map(|_| body))
    }

    /// Deserializes the body, or `None` if the CDA sent none, e.g. with
    /// `204 No Content`.
    ///
    /// # Errors
    /// Returns [`Error::InvalidResponse`] if the body is not a `T`.
    pub(crate) fn json_opt<T: DeserializeOwned>(self) -> Result<Response<Option<T>>> {
        let body = match self.body {
            None => None,
            Some(_) => Some(self.parse()?),
        };
        Ok(self.map(|_| body))
    }

    /// Drops the body, for responses whose body does not matter.
    pub(crate) fn ignore_body(self) -> Response<()> {
        self.map(drop)
    }

    fn parse<T: DeserializeOwned>(&self) -> Result<T> {
        let body = self.body.as_deref().ok_or_else(|| Error::InvalidResponse {
            url: self.url.clone(),
            message: format!("{} has no body", self.status),
            body: None,
        })?;
        serde_json::from_slice(body).map_err(|e| Error::InvalidResponse {
            url: self.url.clone(),
            message: format!("not a {}: {e}", std::any::type_name::<T>()),
            body: Some(String::from_utf8_lossy(body).into_owned()),
        })
    }
}
