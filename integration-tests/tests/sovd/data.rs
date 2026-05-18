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

use http::{Method, StatusCode};

use crate::{
    sovd::hook_cleanup,
    util::{
        ecusim,
        http::{auth_header, send_cda_request},
        runtime::{EcuSim, setup_integration_test},
    },
};

/// Tests that CDA correctly rejects ECU responses where the DID (Data Identifier)
/// in the positive response does not match the DID that was requested.
///
/// According to ISO 14229-1, a `ReadDataByIdentifier` positive response must echo
/// the same DID bytes as the request. If the ECU responds with a different DID,
/// the response is invalid and CDA should treat it as if no valid response was
/// received (timeout -> HTTP 504 Gateway Timeout).
///
/// This test verifies that the CDA correctly ignores an invalid DID and returns
/// HTTP 504 if no further correct message is received within the timeout period.
#[tokio::test]
async fn test_wrong_did_in_response_returns_504() {
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();

    let cleanup_sim = runtime.ecu_sim.clone();
    hook_cleanup(move || {
        let sim = cleanup_sim.clone();
        async move { cleanup(&sim).await }
    });

    let auth = auth_header(&runtime.config, None).await.unwrap();

    // Install a raw response override on FLXC1000:
    // When the ECU receives ReadDataByIdentifier for DID 0xF190 (VIN),
    // respond with correct SID (0x62) but WRONG DID (0xF200) + fake data.
    //
    // Normal request:  22 F1 90  (ReadDataByIdentifier, DID=0xF190)
    // Normal response: 62 F1 90 <VIN data>
    // Override response: 62 F2 00 41 42 43 (correct SID, wrong DID 0xF200, fake data "ABC")
    ecusim::set_interceptor(
        &runtime.ecu_sim,
        "FLXC1000",
        "did_mismatch",
        "22f190",
        "62f20041424344",
    )
    .await
    .expect("Failed to install interceptor");

    // Attempt to read the VIN data from FLXC1000.
    // CDA should detect the DID mismatch and return 504 Gateway Timeout.
    let result = send_cda_request(
        &runtime.config,
        "components/flxc1000/data/vindataidentifier",
        StatusCode::GATEWAY_TIMEOUT,
        Method::GET,
        None,
        Some(&auth),
        None,
    )
    .await;

    assert!(
        result.is_ok(),
        "Expected 504 Gateway Timeout when ECU responds with wrong DID, got: {result:?}"
    );

    cleanup(&runtime.ecu_sim).await;
}

async fn cleanup(ecu_sim: &EcuSim) {
    // Clean up: remove the interceptor so other tests are not affected.
    ecusim::clear_interceptor(ecu_sim, "FLXC1000", "did_mismatch")
        .await
        .expect("Failed to clear interceptor");
}
