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
use std::time::Duration;

use http::HeaderMap;
use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;

use crate::util::TestingError;

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
        request_builder = header_map
            .iter()
            .fold(request_builder, |builder, (key, value)| {
                builder.header(key, value)
            });
    }

    let req_response = request_builder
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|_| TestingError::Timeout(format!("Fetching {url} timed out")))?;
    Response::read(req_response, url.as_str()).await
}

impl Response {
    /// Reads the status, headers and body of the response to `url`.
    ///
    /// # Errors
    /// Returns an error if the body cannot be read.
    pub(crate) async fn read(response: reqwest::Response, url: &str) -> Result<Self, TestingError> {
        let header_map = response.headers().clone();
        let status = response.status();
        let body = if status == StatusCode::NO_CONTENT {
            None
        } else {
            Some(
                response
                    .text()
                    .await
                    .map_err(|_| TestingError::UnexpectedResponse {
                        expected: status,
                        actual: status,
                        body: None,
                        message: "Failed to get text from response".to_owned(),
                        url: url.to_owned(),
                    })?,
            )
        };
        Ok(Self {
            status,
            body,
            header_map,
        })
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
