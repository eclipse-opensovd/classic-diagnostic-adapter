/*
 * SPDX-FileCopyrightText: 2025 Copyright (c) Contributors to the Eclipse Foundation
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
use std::{
    future::Future,
    time::{Duration, Instant},
};

use cda_interfaces::HashMap;
use http::HeaderMap;
use opensovd_cda_lib::config::configfile::Configuration;
use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;

use crate::util::{
    TestingError,
    test_env::{Lease, TestEnv},
};

#[derive(Debug)]
pub(crate) struct Response {
    status: StatusCode,
    body: Option<String>,
    #[allow(
        dead_code,
        reason = "Headers captured for debugging. Not all tests assert on them"
    )]
    header_map: HeaderMap,
}

#[derive(Default)]
pub(crate) struct QueryParams(pub HashMap<String, String>);

pub(crate) async fn auth_header(
    config: &Configuration,
    client_id: Option<&str>,
) -> Result<HeaderMap, TestingError> {
    Ok(bearer_token_header(&authorize(config, client_id).await?))
}

/// An `Authorization` header with the bearer `token`.
pub(crate) fn bearer_token_header(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        format!("Bearer {token}")
            .parse()
            .expect("invalid header value"),
    );
    headers
}

async fn authorize(
    config: &Configuration,
    client_id: Option<&str>,
) -> Result<String, TestingError> {
    let body = &serde_json::json!(
    {
        "client_id": client_id.unwrap_or("test_client"),
        "client_secret": "test_secret",
    });
    let response = send_cda_request(
        config,
        "authorize",
        StatusCode::OK,
        Method::POST,
        Some(&body.to_string()),
        None,
        None,
    )
    .await?;
    extract_field_from_json::<String>(&response_to_json(&response)?, "access_token")
}

pub(crate) fn response_to_json_to_field<T: DeserializeOwned + std::fmt::Debug>(
    response: &Response,
    field: &str,
) -> Result<T, TestingError> {
    extract_field_from_json(&response_to_json(response)?, field)
}

pub(crate) fn extract_field_from_json<T: DeserializeOwned + std::fmt::Debug>(
    json: &serde_json::Value,
    field: &str,
) -> Result<T, TestingError> {
    json.get(field).map_or(
        Err(TestingError::InvalidData(format!(
            "Field '{field}' not found in JSON: {json:#?}"
        ))),
        |v| {
            serde_json::from_value(v.clone())
                .ok()
                .ok_or_else(|| {
                    format!(
                        "Failed to deserialize '{field}' into: {}",
                        std::any::type_name::<T>()
                    )
                })
                .map_err(TestingError::InvalidData)
        },
    )
}

pub(crate) fn response_to_json(response: &Response) -> Result<serde_json::Value, TestingError> {
    if let Some(body) = &response.body {
        serde_json::from_str(body).map_err(|e| TestingError::InvalidData(e.to_string()))
    } else {
        Err(TestingError::InvalidData("No body was provided".to_owned()))
    }
}

pub(crate) fn response_to_t<T>(response: &Response) -> Result<T, TestingError>
where
    T: DeserializeOwned,
{
    if let Some(body) = &response.body {
        serde_json::from_str(body).map_err(|e| {
            TestingError::InvalidData(format!(
                "Failed to deserialize into {}: {}. JSON: {}",
                std::any::type_name::<T>(),
                e,
                body
            ))
        })
    } else {
        Err(TestingError::InvalidData("No body was provided".to_owned()))
    }
}

/// The URL of `endpoint` below `/vehicle/v15/` of the CDA configured by
/// `config`, e.g. `components/flxc1000/data`.
pub(crate) fn vehicle_url(config: &Configuration, endpoint: &str) -> String {
    format!(
        "http://{}:{}/vehicle/v15/{endpoint}",
        config.server.address(),
        config.server.port()
    )
}

/// A CDA and the headers authorizing requests to it: a test environment as
/// its default test client, or [`Authorized`] with explicit headers, e.g. of
/// another user or of a CDA outside a test environment.
pub(crate) trait CdaClient {
    fn config(&self) -> &Configuration;
    async fn auth(&self) -> Result<HeaderMap, TestingError>;
}

impl CdaClient for TestEnv {
    fn config(&self) -> &Configuration {
        &self.config
    }

    async fn auth(&self) -> Result<HeaderMap, TestingError> {
        self.auth_header().await
    }
}

impl CdaClient for Lease {
    fn config(&self) -> &Configuration {
        &self.config
    }

    async fn auth(&self) -> Result<HeaderMap, TestingError> {
        self.auth_header().await
    }
}

impl TestEnv {
    /// This environment as a [`CdaClient`] with `headers`, e.g. of another
    /// user than the default test client.
    pub(crate) fn with_headers<'a>(&'a self, headers: &'a HeaderMap) -> Authorized<'a> {
        Authorized {
            config: &self.config,
            headers,
        }
    }
}

/// A [`CdaClient`] with explicit headers.
pub(crate) struct Authorized<'a> {
    pub(crate) config: &'a Configuration,
    pub(crate) headers: &'a HeaderMap,
}

impl CdaClient for Authorized<'_> {
    fn config(&self) -> &Configuration {
        self.config
    }

    fn auth(&self) -> impl Future<Output = Result<HeaderMap, TestingError>> {
        std::future::ready(Ok(self.headers.clone()))
    }
}

/// [`send_cda_request`] to the CDA of `cda`, authorized by it.
///
/// # Errors
/// See [`send_cda_request`], or the client is not authorized.
pub(crate) async fn send_authenticated_cda_request(
    cda: &impl CdaClient,
    endpoint: &str,
    expected_status: StatusCode,
    method: Method,
    data: Option<&str>,
    query_params: Option<&QueryParams>,
) -> Result<Response, TestingError> {
    let auth = cda.auth().await?;
    send_cda_request(
        cda.config(),
        endpoint,
        expected_status,
        method,
        data,
        Some(&auth),
        query_params,
    )
    .await
}

pub(crate) async fn send_cda_request(
    config: &Configuration,
    endpoint: &str,
    expected_status: StatusCode,
    method: Method,
    data: Option<&str>,
    headers: Option<&HeaderMap>,
    query_params: Option<&QueryParams>,
) -> Result<Response, TestingError> {
    let url_params = query_params
        .unwrap_or(&QueryParams::default())
        .to_query_string();
    let url = reqwest::Url::parse(&vehicle_url(config, &format!("{endpoint}{url_params}")))
        .expect("Invalid endpoint URL");

    send_request(expected_status, method, data, headers, url).await
}

pub(crate) async fn send_request(
    expected_status: StatusCode,
    method: Method,
    data: Option<&str>,
    headers: Option<&HeaderMap>,
    url: reqwest::Url,
) -> Result<Response, TestingError> {
    let response = send_request_any_status(method, data, headers, url.clone()).await?;
    if response.status != expected_status {
        return Err(TestingError::UnexpectedResponse {
            expected: expected_status,
            actual: response.status,
            body: response.body,
            message: "Expected status does not match".to_owned(),
            url: url.to_string(),
        });
    }
    Ok(response)
}

/// Sends a request and returns the response whatever its status.
async fn send_request_any_status(
    method: Method,
    data: Option<&str>,
    headers: Option<&HeaderMap>,
    url: reqwest::Url,
) -> Result<Response, TestingError> {
    let client = reqwest::Client::new();
    let mut request_builder = client.request(method, url.clone()).header(
        reqwest::header::CONTENT_TYPE,
        mime::APPLICATION_JSON.essence_str(),
    );

    if let Some(json_data) = data {
        request_builder = request_builder.body(json_data.to_string());
    }

    if let Some(header_map) = headers {
        // Replaces the default `Content-Type`, unlike `header`, which appends.
        request_builder = request_builder.headers(header_map.clone());
    }

    let req_response = request_builder
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| {
            if e.is_timeout() {
                TestingError::Timeout(format!("Fetching {url} timed out"))
            } else {
                TestingError::ProcessFailed(format!("Fetching {url} failed: {}", error_chain(&e)))
            }
        })?;
    let header_map = req_response.headers().clone();
    let status = req_response.status();
    let body = if status == StatusCode::NO_CONTENT {
        None
    } else {
        Some(
            req_response
                .text()
                .await
                .map_err(|_| TestingError::UnexpectedResponse {
                    expected: status,
                    actual: status,
                    body: None,
                    message: "Failed to get text from response".to_owned(),
                    url: url.to_string(),
                })?,
        )
    };

    Ok(Response {
        status,
        body,
        header_map,
    })
}

/// Sends `GET`s to `endpoint` of `cda` for as long as it answers `pending`,
/// and returns the first other response, whatever its status.
///
/// # Errors
/// Returns [`TestingError::Timeout`] if the CDA still answers `pending` after
/// `timeout`, or an error if a request fails.
pub(crate) async fn poll_while(
    cda: &impl CdaClient,
    endpoint: &str,
    pending: StatusCode,
    timeout: Duration,
) -> Result<Response, TestingError> {
    let url =
        reqwest::Url::parse(&vehicle_url(cda.config(), endpoint)).expect("Invalid endpoint URL");
    let headers = cda.auth().await?;
    poll_until(timeout, Duration::from_millis(100), || async {
        let response =
            send_request_any_status(Method::GET, None, Some(&headers), url.clone()).await?;
        Ok(if response.status == pending {
            Err(format!("{endpoint} still answers {pending}"))
        } else {
            Ok(response)
        })
    })
    .await
}

/// Calls `poll` every `interval` for at most `timeout`, until it is done or
/// fails. `poll` returns one of:
///
/// - `Ok(Ok(value))`: done; `value` is returned.
/// - `Ok(Err(reason))`: not done yet, e.g. `"ECUs not online: flxc1000=Offline"`;
///   polled again after `interval`. The last `reason` goes into the timeout
///   error, to tell what never happened.
/// - `Err(error)`: failed in a way waiting does not fix, e.g. a runtime update
///   that reported `Failed`; returned right away.
///
/// # Errors
/// Returns [`TestingError::Timeout`] with the last `reason` if `poll` is not
/// done within `timeout`, or the `error` it failed with.
pub(crate) async fn poll_until<T, F, Fut>(
    timeout: Duration,
    interval: Duration,
    mut poll: F,
) -> Result<T, TestingError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Result<T, String>, TestingError>>,
{
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| TestingError::SetupError(format!("timeout {timeout:?} too large")))?;
    loop {
        let pending = match poll().await? {
            Ok(done) => return Ok(done),
            Err(pending) => pending,
        };
        if Instant::now() >= deadline {
            return Err(TestingError::Timeout(format!(
                "{pending} after {timeout:?}"
            )));
        }
        cda_interfaces::util::tokio_ext::sleep_for(interval).await;
    }
}

impl QueryParams {
    pub fn to_query_string(&self) -> String {
        if self.0.is_empty() {
            String::new()
        } else {
            let params = self
                .0
                .iter()
                .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
                .collect::<Vec<_>>()
                .join("&");
            format!("?{params}")
        }
    }
}

impl Response {
    pub(crate) fn status(&self) -> StatusCode {
        self.status
    }

    pub(crate) fn header(&self, name: http::header::HeaderName) -> Option<&http::HeaderValue> {
        self.header_map.get(name)
    }
}

/// Sends a request over a Unix domain socket connection using `reqwest`
/// (the same HTTP client used throughout these integration tests), so the
/// tests exercise a spec-compliant client the same way a real consumer of
/// the Unix socket transport (e.g. `opensovd-gateway`) would.
///
/// # Errors
/// Returns [`TestingError`] if the socket can't be reached, the response
/// can't be read, or the status doesn't match `expected_status`.
#[cfg(unix)]
pub(crate) async fn send_unix_socket_request(
    socket_path: &str,
    endpoint: &str,
    expected_status: StatusCode,
    method: Method,
    data: Option<&str>,
) -> Result<Response, TestingError> {
    let client = reqwest::Client::builder()
        .unix_socket(socket_path)
        .build()
        .map_err(|e| {
            TestingError::ProcessFailed(format!("Failed to build unix socket client: {e}"))
        })?;

    let body = data.unwrap_or_default().to_owned();
    let mut request_builder = client.request(method, format!("http://localhost{endpoint}"));
    if !body.is_empty() {
        request_builder = request_builder
            .header(
                reqwest::header::CONTENT_TYPE,
                mime::APPLICATION_JSON.essence_str(),
            )
            .body(body);
    }

    let response = request_builder.send().await.map_err(|e| {
        TestingError::ProcessFailed(format!(
            "Failed to send request over unix socket {socket_path}: {e}"
        ))
    })?;

    let status = response.status();
    let header_map = response.headers().clone();
    let body_bytes = response
        .bytes()
        .await
        .map_err(|e| TestingError::ProcessFailed(format!("Failed to read response body: {e}")))?;
    let body = if body_bytes.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&body_bytes).into_owned())
    };

    if status != expected_status {
        return Err(TestingError::UnexpectedResponse {
            expected: expected_status,
            actual: status,
            body,
            message: "Expected status does not match".to_owned(),
            url: format!("unix://{socket_path}{endpoint}"),
        });
    }

    Ok(Response {
        status,
        body,
        header_map,
    })
}

/// `error` with its sources, e.g. `error sending request: client error
/// (Connect): Connection refused (os error 61)`. Display of a reqwest error
/// leaves out what the request failed on.
fn error_chain(error: &dyn std::error::Error) -> String {
    let mut chain = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        chain.push_str(": ");
        chain.push_str(&cause.to_string());
        source = cause.source();
    }
    chain
}
