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

//! The integration test CDA is configured with `server.binary_encoding = "hex"`.
//! These tests select base64 per request via the `x-sovd2uds-binary-encoding`
//! query parameter.

use std::time::Duration;

use http::{Method, StatusCode};
use sovd_interfaces::components::ecu::modes::security_and_session::put::{
    ModeKey, Request, RequestSeedResponse, Response,
};

use crate::{
    sovd::{self, ECU_FLXC1000, ecu::switch_session},
    util::{
        ecusim,
        http::{
            QueryParams, Response as HttpResponse, extract_field_from_json, response_to_json,
            response_to_t, send_authenticated_cda_request,
        },
        locks::{self, create_lock, lock_operation},
        test_env::{TestEnv, Transport, skip_unless},
    },
};

const BINARY_ENCODING_QUERY_PARAM: &str = "x-sovd2uds-binary-encoding";

fn encoding_query(encoding: &str) -> QueryParams {
    QueryParams(
        [(BINARY_ENCODING_QUERY_PARAM.to_owned(), encoding.to_owned())]
            .into_iter()
            .collect(),
    )
}

async fn put_security(
    test_env: &TestEnv,
    request: &Request,
    query: &QueryParams,
    expected_status: StatusCode,
) -> HttpResponse {
    send_authenticated_cda_request(
        test_env,
        &format!("{}/modes/security", sovd::COMPONENTS_FLXC1000_BASE),
        expected_status,
        Method::PUT,
        Some(&serde_json::to_string(request).expect("Request must serialize")),
        Some(query),
    )
    .await
    .expect("Security request failed")
}

/// Runs `SecurityAccess` Level 7 with base64 coded seed and key.
#[tokio::test]
async fn test_security_access_with_base64_encoding() {
    if skip_unless(
        Transport::uses_doip,
        "SecurityAccess sequencing not yet supported over CAN",
    ) {
        return;
    }
    let test_env = TestEnv::builder().await.unwrap();
    let ecu_endpoint = sovd::COMPONENTS_FLXC1000_BASE;

    let ecu_lock = create_lock(
        Duration::from_secs(60),
        locks::COMPONENTS_FLXC1000_LOCKS,
        StatusCode::CREATED,
        &test_env,
    )
    .await;
    let lock_id =
        extract_field_from_json::<String>(&response_to_json(&ecu_lock).unwrap(), "id").unwrap();
    lock_operation(
        locks::COMPONENTS_FLXC1000_LOCKS,
        Some(&lock_id),
        &test_env,
        StatusCode::OK,
        Method::GET,
    )
    .await;

    ecusim::switch_variant(&test_env.ecu_sim, "FLXC1000", "BOOT")
        .await
        .unwrap();
    send_authenticated_cda_request(
        &test_env,
        ecu_endpoint,
        StatusCode::OK,
        Method::PUT,
        None,
        None,
    )
    .await
    .unwrap();
    switch_session("programming", &test_env, ecu_endpoint, StatusCode::OK)
        .await
        .unwrap()
        .unwrap();

    let base64 = encoding_query("base64");

    // The ECU sim returns the deterministic seed 0x00..0x07.
    let seed_request = Request {
        value: "Level_7_RequestSeed".to_owned(),
        mode_expiration: None,
        key: None,
        parameters: None,
    };
    let seed_response: RequestSeedResponse =
        response_to_t(&put_security(&test_env, &seed_request, &base64, StatusCode::OK).await)
            .unwrap();
    assert_eq!(seed_response.seed.request_seed, "AAECAwQFBgc=");

    // The same request with explicit hex encoding returns the hex representation.
    let seed_response: RequestSeedResponse = response_to_t(
        &put_security(
            &test_env,
            &seed_request,
            &encoding_query("hex"),
            StatusCode::OK,
        )
        .await,
    )
    .unwrap();
    assert_eq!(
        seed_response.seed.request_seed,
        "0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07"
    );

    // Key is each seed byte + 13, i.e. 0x0D..0x14.
    let recorder = test_env
        .record(ECU_FLXC1000)
        .await
        .expect("Failed to start ECU sim recording");
    let key_response: Response<String> = response_to_t(
        &put_security(
            &test_env,
            &Request {
                value: "Level_7".to_owned(),
                mode_expiration: None,
                key: Some(ModeKey {
                    send_key: "DQ4PEBESExQ=".to_owned(),
                }),
                parameters: None,
            },
            &base64,
            StatusCode::OK,
        )
        .await,
    )
    .unwrap();
    assert_eq!(key_response.value, "Level_7");

    let recorded_frames = recorder
        .stop()
        .await
        .expect("Failed to stop ECU sim recording");
    assert!(
        recorded_frames
            .iter()
            .any(|f| f.eq_ignore_ascii_case("27080d0e0f1011121314")),
        "Expected SendKey frame (27080d0e0f1011121314), got: {recorded_frames:?}"
    );

    lock_operation(
        locks::COMPONENTS_FLXC1000_LOCKS,
        Some(&lock_id),
        &test_env,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;
}

/// An unknown encoding in the query parameter is rejected.
#[tokio::test]
async fn test_invalid_binary_encoding_is_rejected() {
    let test_env = TestEnv::builder().await.unwrap();

    send_authenticated_cda_request(
        &test_env,
        &format!("{}/data/identification", sovd::COMPONENTS_FLXC1000_BASE),
        StatusCode::BAD_REQUEST,
        Method::GET,
        None,
        Some(&encoding_query("base32")),
    )
    .await
    .unwrap();
}
