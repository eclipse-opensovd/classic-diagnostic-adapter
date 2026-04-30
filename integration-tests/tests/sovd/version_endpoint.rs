/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

use axum::http::StatusCode;
use opensovd_cda_lib::cda_version;
use reqwest::Method;

use crate::util::{
    http::{extract_field_from_json, response_to_json},
    runtime::setup_integration_test,
};

fn assert_version_response(json: &serde_json::Value) {
    let id = extract_field_from_json::<String>(json, "id").expect("Missing 'id' field");
    assert_eq!(id, "version");

    let data =
        extract_field_from_json::<serde_json::Value>(json, "data").expect("Missing 'data' field");
    let name = extract_field_from_json::<String>(&data, "name").expect("Missing 'data.name' field");
    assert_eq!(name, "Eclipse OpenSOVD Classic Diagnostic Adapter");

    let api =
        extract_field_from_json::<serde_json::Value>(&data, "api").expect("Missing 'data.api'");
    let api_version =
        extract_field_from_json::<String>(&api, "version").expect("Missing 'data.api.version'");
    assert_eq!(api_version, "1.1");

    let implementation = extract_field_from_json::<serde_json::Value>(&data, "implementation")
        .expect("Missing 'data.implementation'");
    let impl_version = extract_field_from_json::<String>(&implementation, "version")
        .expect("Missing 'data.implementation.version'");
    assert_eq!(impl_version, cda_version());
}

/// [[ itest~sovd-api-version-endpoint, Version Endpoint Integration Test ]]
#[tokio::test]
async fn test_version_endpoint() {
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();
    let host = &runtime.config.server.address;
    let port = runtime.config.server.port;

    // Test app-scoped version endpoint
    let app_url = reqwest::Url::parse(&format!(
        "http://{host}:{port}/vehicle/v15/apps/sovd2uds/data/version"
    ))
    .expect("Invalid URL");

    let response =
        crate::util::http::send_request(StatusCode::OK, Method::GET, None, None, app_url)
            .await
            .expect("GET app version endpoint failed");

    let json = response_to_json(&response).expect("Failed to parse version response");
    assert_version_response(&json);

    // Test global version endpoint
    let global_url = reqwest::Url::parse(&format!("http://{host}:{port}/vehicle/v15/data/version"))
        .expect("Invalid URL");

    let response =
        crate::util::http::send_request(StatusCode::OK, Method::GET, None, None, global_url)
            .await
            .expect("GET global version endpoint failed");

    let json = response_to_json(&response).expect("Failed to parse version response");
    assert_version_response(&json);
}
