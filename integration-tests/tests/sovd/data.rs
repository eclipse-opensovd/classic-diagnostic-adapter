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

use std::time::Duration;

use http::{HeaderMap, Method, StatusCode};
use opensovd_cda_lib::config::configfile::Configuration;
use serde_json::json;

use crate::{
    sovd::{
        hook_cleanup,
        locks::{ECU_ENDPOINT as ECU_LOCK_ENDPOINT, create_lock, lock_operation},
    },
    util::{
        ecusim,
        http::{
            auth_header, extract_field_from_json, response_to_json, send_cda_json_request,
            send_cda_request,
        },
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

/// Tests that CDA returns an error response when an ECU replies with a positive
/// `ReadDataByIdentifier` response that is too short to contain the expected data.
///
/// According to ISO 14229-1, a `ReadDataByIdentifier` positive response (`0x62`) must
/// include the DID echo bytes followed by the actual data record. If the ECU sends only
/// the SID and DID bytes (3 bytes total) without any data payload, CDA must return an
/// error indicating the payload was too short.
///
/// This test verifies that CDA correctly detects the truncated response and returns
/// HTTP 400 Bad Request.
#[tokio::test]
async fn test_short_ecu_response_returns_error() {
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();

    let cleanup_sim = runtime.ecu_sim.clone();
    hook_cleanup(move || {
        let sim = cleanup_sim.clone();
        async move { cleanup_truncated(&sim).await }
    });

    let auth = auth_header(&runtime.config, None).await.unwrap();

    // Install a raw response override on FLXC1000:
    // When the ECU receives ReadDataByIdentifier for DID 0xF200 (FluxCapacitorPowerConsumption),
    // respond with correct SID+DID bytes only, no data payload.
    //
    // Normal request:  22 F2 00  (ReadDataByIdentifier, DID=0xF200)
    // Normal response: 62 F2 00 <4 data bytes>  (INT32 power consumption value)
    // Override response: 62 F2 00  (correct SID+DID, but missing the 4 data bytes)
    ecusim::set_interceptor(
        &runtime.ecu_sim,
        "FLXC1000",
        "truncated_response",
        "22f200",
        "62f200",
    )
    .await
    .expect("Failed to install interceptor");

    // Attempt to read the FluxCapacitorPowerConsumption data from FLXC1000.
    // CDA should detect the truncated payload and return an error, not 204 No Content.
    let result = send_cda_request(
        &runtime.config,
        "components/flxc1000/data/fluxcapacitorpowerconsumption",
        StatusCode::BAD_REQUEST,
        Method::GET,
        None,
        Some(&auth),
        None,
    )
    .await;

    assert!(
        result.is_ok(),
        "Expected 400 Bad Request when ECU responds with truncated payload, got: {result:?}"
    );

    cleanup_truncated(&runtime.ecu_sim).await;
}

async fn cleanup(ecu_sim: &EcuSim) {
    // Clean up: remove the interceptor so other tests are not affected.
    // Cannot use panic, in a panic handler, hence have to resort to eprintln
    if let Err(e) = ecusim::clear_interceptor(ecu_sim, "FLXC1000", "did_mismatch").await {
        eprintln!("Failed to clear raw response override: {e}");
    }
}

async fn cleanup_truncated(ecu_sim: &EcuSim) {
    // Clean up: remove the interceptor so other tests are not affected.
    // Cannot use panic, in a panic handler, hence have to resort to eprintln
    if let Err(e) = ecusim::clear_interceptor(ecu_sim, "FLXC1000", "truncated_response").await {
        eprintln!("Failed to clear truncated response interceptor: {e}");
    }
}

const TIMELINE_ENDPOINT: &str = "components/flxc1000/data/fluxcapacitortimeline";

async fn write_timeline(config: &Configuration, auth: &HeaderMap, data: &serde_json::Value) {
    send_cda_json_request(
        config,
        TIMELINE_ENDPOINT,
        StatusCode::NO_CONTENT,
        Method::PUT,
        &json!({ "data": data }),
        Some(auth),
    )
    .await
    .expect("Failed to write FluxCapacitorTimeline");
}

async fn read_timeline(config: &Configuration, auth: &HeaderMap) -> serde_json::Value {
    let response = send_cda_request(
        config,
        TIMELINE_ENDPOINT,
        StatusCode::OK,
        Method::GET,
        None,
        Some(auth),
        None,
    )
    .await
    .expect("Failed to read FluxCapacitorTimeline");
    extract_field_from_json(
        &response_to_json(&response).expect("response should be JSON"),
        "data",
    )
    .expect("response should contain data")
}

/// Writes and reads DID 0xF300 (`FluxCapacitorTimeline`), whose data record consists of
/// three chained DYNAMIC-LENGTH-FIELDs (see `testcontainer/odx/dynamic_length_fields.py`):
///
/// * `Destinations` with an explicit BYTE-POSITION, 8 bit count,
/// * `Waypoints` without BYTE-POSITION, whose items contain a nested
///   DYNAMIC-LENGTH-FIELD `Readings`,
/// * `Passengers` without BYTE-POSITION, 16 bit count and OFFSET 2.
///
/// The ECU simulator parses written data strictly and rejects any layout mismatch,
/// so a successful round trip verifies both the encoder (0x2E) and the decoder (0x22).
/// The exact request bytes are additionally checked via the simulator recorder.
#[tokio::test]
async fn test_chained_dynamic_length_fields_write_and_read() {
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();
    let auth = auth_header(&runtime.config, None).await.unwrap();

    let ecu_lock = create_lock(
        Duration::from_secs(60),
        ECU_LOCK_ENDPOINT,
        StatusCode::CREATED,
        &runtime.config,
        &auth,
    )
    .await;
    let lock_id = extract_field_from_json::<String>(
        &response_to_json(&ecu_lock).expect("lock response should be JSON"),
        "id",
    )
    .expect("lock response should contain an id");

    let timeline = json!({
        "Destinations": [
            { "Year": 1885, "Month": 9 },
            { "Year": 2015, "Month": 10 },
            { "Year": 1955, "Month": 11 },
        ],
        "Waypoints": [
            { "WaypointId": 7, "Readings": [{ "Reading": 1210 }, { "Reading": 88 }] },
            { "WaypointId": 8, "Readings": [] },
        ],
        "Passengers": [{ "PassengerId": 1 }, { "PassengerId": 3 }],
    });
    let empty_timeline = json!({ "Destinations": [], "Waypoints": [], "Passengers": [] });

    ecusim::start_recording(&runtime.ecu_sim, "flxc1000")
        .await
        .expect("failed to start ECU sim recording");
    write_timeline(&runtime.config, &auth, &timeline).await;
    let read_back = read_timeline(&runtime.config, &auth).await;
    write_timeline(&runtime.config, &auth, &empty_timeline).await;
    let read_back_empty = read_timeline(&runtime.config, &auth).await;
    let frames = ecusim::stop_and_clear_recording(&runtime.ecu_sim, "flxc1000")
        .await
        .expect("failed to stop ECU sim recording");

    lock_operation(
        ECU_LOCK_ENDPOINT,
        Some(&lock_id),
        &runtime.config,
        &auth,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;

    let writes: Vec<String> = frames
        .iter()
        .map(|f| f.to_ascii_lowercase())
        .filter(|f| f.starts_with("2ef300"))
        .collect();
    assert_eq!(
        writes,
        [
            concat!(
                "2ef300", "03", "075d09", "07df0a", "07a30b", // Destinations
                "02", "07", "02", "04ba", "0058", "08", "00", // Waypoints (nested Readings)
                "0002", "01", "03", // Passengers (16 bit count)
            ),
            concat!("2ef300", "00", "00", "0000"),
        ],
        "unexpected WriteDataByIdentifier requests, all frames: {frames:?}"
    );

    assert_eq!(read_back, timeline);
    assert_eq!(read_back_empty, empty_timeline);
}
