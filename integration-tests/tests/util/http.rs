/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */
use std::time::Duration;

use http::HeaderMap;
use opensovd_cda_lib::config::configfile::Configuration;
use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;

use crate::util::TestingError;

pub(crate) struct Response {
    #[allow(dead_code)]
    status: StatusCode,
    body: Option<String>,
    #[allow(dead_code)]
    header_map: HeaderMap,
}

pub(crate) async fn auth_header(
    config: &Configuration,
    client_id: Option<&str>,
) -> Result<HeaderMap, TestingError> {
    let token = authorize(config, client_id).await?;
    let mut headers = HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        format!("Bearer {token}")
            .parse()
            .expect("invalid header value"),
    );
    Ok(headers)
}

async fn authorize(
    config: &Configuration,
    client_id: Option<&str>,
) -> Result<String, TestingError> {
    let response = send_cda_json_request(
        config,
        "authorize",
        StatusCode::OK,
        Method::POST,
        &serde_json::json!({"client_id": client_id.unwrap_or("test_client"), "client_secret": "test_secret"}),
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

pub(crate) async fn send_cda_json_request(
    config: &Configuration,
    endpoint: &str,
    expected_status: StatusCode,
    method: Method,
    data: &serde_json::Value,
    headers: Option<&HeaderMap>,
) -> Result<Response, TestingError> {
    let headers = if headers
        .as_ref()
        .and_then(|h| h.get(reqwest::header::CONTENT_TYPE))
        .is_none()
    {
        let mut headers = headers.map_or_else(HeaderMap::new, Clone::clone);
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static(mime::APPLICATION_JSON.essence_str()),
        );
        headers
    } else {
        headers.map_or_else(HeaderMap::new, Clone::clone)
    };

    send_cda_request(
        config,
        endpoint,
        expected_status,
        method,
        Some(&data.to_string()),
        Some(&headers),
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
) -> Result<Response, TestingError> {
    let base_url = format!("http://{}:{}", &config.server.address, config.server.port);
    let endpoint_path = format!("/vehicle/v15/{endpoint}");

    let url = reqwest::Url::parse(&base_url)
        .expect("Invalid base URL")
        .join(&endpoint_path)
        .expect("Invalid endpoint path");

    send_request(expected_status, method, data, headers, url).await
}

pub(crate) async fn send_request(
    expected_status: StatusCode,
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
                    expected: expected_status,
                    actual: status,
                    body: None,
                    message: "Failed to get text from response".to_owned(),
                    url: url.to_string(),
                })?,
        )
    };

    if status != expected_status {
        return Err(TestingError::UnexpectedResponse {
            expected: expected_status,
            actual: status,
            body,
            message: "Expected status does not match".to_owned(),
            url: url.to_string(),
        });
    }

    Ok(Response {
        status,
        body: body.clone(),
        header_map,
    })
}
