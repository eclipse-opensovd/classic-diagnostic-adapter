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

//! `/genericservice` in JSON (default) and `application/octet-stream` form.
//!
//! The integration test CDA is configured with `server.binary_encoding = "hex"`.

use std::time::Duration;

use const_format::formatcp;
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};

use crate::{
    sovd,
    util::{
        http::{
            QueryParams, Response, extract_field_from_json, response_to_json, send_cda_request,
        },
        locks::{COMPONENTS_FLXC1000_LOCKS, Lock},
        test_env::TestEnv,
    },
};

const GENERICSERVICE: &str = formatcp!("{}/genericservice", sovd::COMPONENTS_FLXC1000_BASE);

async fn put_generic(
    test_env: &TestEnv,
    body: &str,
    extra_headers: &[(header::HeaderName, &'static str)],
    query: Option<&QueryParams>,
    expected_status: StatusCode,
) -> Response {
    let mut headers: HeaderMap = test_env.auth_header().await.expect("Auth failed");
    for (name, value) in extra_headers {
        headers.insert(name.clone(), HeaderValue::from_static(value));
    }
    send_cda_request(
        &test_env.config,
        GENERICSERVICE,
        expected_status,
        Method::PUT,
        Some(body),
        Some(&headers),
        query,
    )
    .await
    .expect("Generic service request failed")
}

fn response_field(response: &Response) -> String {
    let json = response_to_json(response).expect("Response is not JSON");
    assert_eq!(
        extract_field_from_json::<String>(&json, "id").expect("Response has no id field"),
        "genericservice"
    );
    extract_field_from_json(&json, "data").expect("Response has no data field")
}

/// `22 F1 90` (VIN) and `10 01` (default session) in all combinations of JSON,
/// octet-stream and binary encodings. The raw requests use `10 01` because
/// the test HTTP helper only sends UTF-8 bodies.
/// [[ itest~sovd-api-generic-service, Generic service in JSON and octet-stream form, itest ]]
#[tokio::test]
async fn test_genericservice_json_and_octet_stream() {
    let test_env = TestEnv::builder().await.unwrap();
    let _lock = Lock::acquire(
        &test_env,
        COMPONENTS_FLXC1000_LOCKS,
        Duration::from_secs(60),
    )
    .await;

    // JSON with the configured default encoding (hex)
    let response = put_generic(
        &test_env,
        r#"{"data": "0x22 0xF1 0x90"}"#,
        &[],
        None,
        StatusCode::OK,
    )
    .await;
    assert!(response_field(&response).starts_with("0x62 0xF1 0x90 "));

    // The hex notation of the request is mirrored in the response
    for (request, prefix) in [
        (r#"{"data": "22 F1 90"}"#, "62F190"),
        (r#"{"request": "0x22F190"}"#, "0x62F190"),
        (r#"{"send": "0x22F190"}"#, "0x62F190"),
    ] {
        let response = put_generic(&test_env, request, &[], None, StatusCode::OK).await;
        let value = response_field(&response);
        assert!(value.starts_with(prefix), "{request}: {value}");
        assert!(!value.contains(' '), "{request}: {value}");
    }

    // JSON with base64 selected per request
    let base64 = QueryParams(
        [("x-sovd2uds-binary-encoding".to_owned(), "base64".to_owned())]
            .into_iter()
            .collect(),
    );
    let response = put_generic(
        &test_env,
        r#"{"data": "IvGQ"}"#,
        &[],
        Some(&base64),
        StatusCode::OK,
    )
    .await;
    assert!(response_field(&response).starts_with("YvGQ"));

    // JSON request, raw response
    let response = put_generic(
        &test_env,
        r#"{"data": "1001"}"#,
        &[(header::ACCEPT, "application/octet-stream")],
        None,
        StatusCode::OK,
    )
    .await;
    assert_octet_session_response(&response);

    // Raw request without Accept answers raw
    let response = put_generic(
        &test_env,
        "\x10\x01",
        &[(header::CONTENT_TYPE, "application/octet-stream")],
        None,
        StatusCode::OK,
    )
    .await;
    assert_octet_session_response(&response);

    // Raw request, JSON response
    let response = put_generic(
        &test_env,
        "\x10\x01",
        &[
            (header::CONTENT_TYPE, "application/octet-stream"),
            (header::ACCEPT, "application/json"),
        ],
        None,
        StatusCode::OK,
    )
    .await;
    assert!(response_field(&response).starts_with("0x50 0x01"));
}

fn assert_octet_session_response(response: &Response) {
    assert_eq!(
        response.header(header::CONTENT_TYPE),
        Some(&HeaderValue::from_static("application/octet-stream"))
    );
    assert!(
        response.body().is_some_and(|b| b.starts_with("\x50\x01")),
        "Unexpected body: {:?}",
        response.body()
    );
}

/// A negative response of the ECU is passed through with HTTP 200 in the body
/// format selected by the client, like a positive response.
/// [[ itest~sovd-api-generic-service-nrc, Generic service passes NRCs through, itest ]]
#[tokio::test]
async fn test_genericservice_nrc() {
    let test_env = TestEnv::builder().await.unwrap();
    let _lock = Lock::acquire(
        &test_env,
        COMPONENTS_FLXC1000_LOCKS,
        Duration::from_secs(60),
    )
    .await;

    // RequestTransferExit outside of the boot variant: NRC 0x31 (requestOutOfRange)
    let response = put_generic(&test_env, r#"{"data": "37"}"#, &[], None, StatusCode::OK).await;
    assert_eq!(response_field(&response), "7F3731");

    let response = put_generic(
        &test_env,
        r#"{"data": "37"}"#,
        &[(header::ACCEPT, "application/octet-stream")],
        None,
        StatusCode::OK,
    )
    .await;
    assert_eq!(response.body(), Some("\x7f\x37\x31"));
}

/// Invalid JSON requests are rejected before anything is sent to the ECU.
#[tokio::test]
async fn test_genericservice_invalid_json_request() {
    let test_env = TestEnv::builder().await.unwrap();
    let _lock = Lock::acquire(
        &test_env,
        COMPONENTS_FLXC1000_LOCKS,
        Duration::from_secs(60),
    )
    .await;

    for body in [r#"{"data": "zz"}"#, r#"{"data": ""}"#, "{}"] {
        put_generic(&test_env, body, &[], None, StatusCode::BAD_REQUEST).await;
    }
    put_generic(
        &test_env,
        r#"{"data": "1001"}"#,
        &[(header::ACCEPT, "text/plain")],
        None,
        StatusCode::BAD_REQUEST,
    )
    .await;
}
