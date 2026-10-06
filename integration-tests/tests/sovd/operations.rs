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

use cda_interfaces::HashMap;
use const_format::formatcp;
use http::{Method, StatusCode};
use serde::Deserialize;
use sovd_interfaces::{
    Items,
    components::ecu::operations::{AsyncGetByIdResponse, ExecutionStatus, OperationCollectionItem},
};

/// Local deserializable mirror of `AsyncPostResponse` (the interface type is serialize-only).
#[derive(Debug, Deserialize)]
struct AsyncPostBody {
    pub id: String,
    pub status: ExecutionStatus,
}

use crate::{
    sovd::{COMPONENTS_FLXC1000_BASE, ECU_FLXC1000, FUNCTIONS_FUNCTIONALGROUPS_DOIP_BASE},
    util::{
        http::{
            QueryParams, extract_field_from_json, response_to_json, response_to_t,
            send_authenticated_cda_request,
        },
        locks::{self, Lock},
        test_env::TestEnv,
    },
};

/// The operations of FLXC1000.
const COMPONENTS_FLXC1000_OPERATIONS: &str = formatcp!("{}/operations", COMPONENTS_FLXC1000_BASE);
/// The self test of FLXC1000.
const COMPONENTS_FLXC1000_OPERATIONS_SELFTEST: &str =
    formatcp!("{}/selftest", COMPONENTS_FLXC1000_OPERATIONS);
/// Executions of [`COMPONENTS_FLXC1000_OPERATIONS_SELFTEST`].
const COMPONENTS_FLXC1000_OPERATIONS_SELFTEST_EXECUTIONS: &str =
    formatcp!("{}/executions", COMPONENTS_FLXC1000_OPERATIONS_SELFTEST);
/// Executions of the sensor calibration of FLXC1000.
const COMPONENTS_FLXC1000_OPERATIONS_CALIBRATESENSORS_EXECUTIONS: &str = formatcp!(
    "{}/calibratesensors/executions",
    COMPONENTS_FLXC1000_OPERATIONS
);
/// Executions of the time circuits of FLXC1000.
const COMPONENTS_FLXC1000_OPERATIONS_TIMECIRCUITS_EXECUTIONS: &str =
    formatcp!("{}/timecircuits/executions", COMPONENTS_FLXC1000_OPERATIONS);
/// The operations of the functional group.
const FUNCTIONS_FUNCTIONALGROUPS_DOIP_OPERATIONS: &str =
    formatcp!("{}/operations", FUNCTIONS_FUNCTIONALGROUPS_DOIP_BASE);
/// Executions of the safety squints of the functional group.
const FUNCTIONS_FUNCTIONALGROUPS_DOIP_OPERATIONS_ENGAGE_SAFETY_SQUINTS_EXECUTIONS: &str = formatcp!(
    "{}/engage_safety_squints/executions",
    FUNCTIONS_FUNCTIONALGROUPS_DOIP_OPERATIONS
);

/// Expiration of the locks the tests acquire.
const LOCK_EXPIRATION: Duration = Duration::from_secs(60);

#[tokio::test]
async fn test_list_operations() {
    let test_env = TestEnv::builder().await.unwrap();

    let response = send_authenticated_cda_request(
        &test_env,
        COMPONENTS_FLXC1000_OPERATIONS,
        StatusCode::OK,
        Method::GET,
        None,
        None,
    )
    .await
    .unwrap();

    let list: Items<OperationCollectionItem> = response_to_t(&response).unwrap();

    let selftest = list
        .items
        .iter()
        .find(|op| op.id.eq_ignore_ascii_case("selftest"))
        .expect("selftest operation not found in list");
    assert!(
        !selftest.asynchronous_execution,
        "selftest should not be asynchronous"
    );
    assert!(
        !selftest.proximity_proof_required,
        "selftest should not require proximity proof"
    );

    let calibrate = list
        .items
        .iter()
        .find(|op| op.id.eq_ignore_ascii_case("calibratesensors"))
        .expect("calibratesensors operation not found in list");
    assert!(
        calibrate.asynchronous_execution,
        "calibratesensors should be asynchronous"
    );
    assert!(
        !calibrate.proximity_proof_required,
        "calibratesensors should not require proximity proof"
    );
}

#[tokio::test]
async fn test_sync_operation_requires_lock() {
    let test_env = TestEnv::builder().await.unwrap();

    send_authenticated_cda_request(
        &test_env,
        COMPONENTS_FLXC1000_OPERATIONS_SELFTEST_EXECUTIONS,
        StatusCode::CONFLICT,
        Method::POST,
        Some("{}"),
        None,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn test_async_operation_delete_after_lock_release() {
    let test_env = TestEnv::builder().await.unwrap();

    let lock = Lock::acquire(&test_env, locks::COMPONENTS_FLXC1000_LOCKS, LOCK_EXPIRATION).await;

    // Start async operation while holding the lock
    let post_response = send_authenticated_cda_request(
        &test_env,
        COMPONENTS_FLXC1000_OPERATIONS_CALIBRATESENSORS_EXECUTIONS,
        StatusCode::ACCEPTED,
        Method::POST,
        Some("{}"),
        None,
    )
    .await
    .unwrap();
    let post_body: AsyncPostBody = response_to_t(&post_response).unwrap();
    let execution_id = post_body.id.clone();

    // Release the lock before attempting DELETE
    lock.release(&test_env).await;

    // DELETE is a write operation and requires a currently active lock.
    send_authenticated_cda_request(
        &test_env,
        &format!("{COMPONENTS_FLXC1000_OPERATIONS_CALIBRATESENSORS_EXECUTIONS}/{execution_id}"),
        StatusCode::CONFLICT,
        Method::DELETE,
        None,
        None,
    )
    .await
    .unwrap();

    let _cleanup_lock =
        Lock::acquire(&test_env, locks::COMPONENTS_FLXC1000_LOCKS, LOCK_EXPIRATION).await;
    send_authenticated_cda_request(
        &test_env,
        &format!("{COMPONENTS_FLXC1000_OPERATIONS_CALIBRATESENSORS_EXECUTIONS}/{execution_id}"),
        StatusCode::OK,
        Method::DELETE,
        None,
        None,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn test_sync_operation() {
    let test_env = TestEnv::builder().await.unwrap();

    let _lock = Lock::acquire(&test_env, locks::COMPONENTS_FLXC1000_LOCKS, LOCK_EXPIRATION).await;

    send_authenticated_cda_request(
        &test_env,
        COMPONENTS_FLXC1000_OPERATIONS_SELFTEST_EXECUTIONS,
        StatusCode::OK,
        Method::POST,
        Some("{}"),
        None,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn test_async_operation_lifecycle() {
    let test_env = TestEnv::builder().await.unwrap();

    let _lock = Lock::acquire(&test_env, locks::COMPONENTS_FLXC1000_LOCKS, LOCK_EXPIRATION).await;

    // Start the async calibration - expect 202 Accepted
    let post_response = send_authenticated_cda_request(
        &test_env,
        COMPONENTS_FLXC1000_OPERATIONS_CALIBRATESENSORS_EXECUTIONS,
        StatusCode::ACCEPTED,
        Method::POST,
        Some("{}"),
        None,
    )
    .await
    .unwrap();

    let post_body: AsyncPostBody = response_to_t(&post_response).unwrap();
    assert_eq!(post_body.status, ExecutionStatus::Running);
    let execution_id = post_body.id.clone();

    // GET the list of executions - should contain our id
    let list_response = send_authenticated_cda_request(
        &test_env,
        COMPONENTS_FLXC1000_OPERATIONS_CALIBRATESENSORS_EXECUTIONS,
        StatusCode::OK,
        Method::GET,
        None,
        None,
    )
    .await
    .unwrap();
    let list_json = response_to_json(&list_response).unwrap();
    let items = extract_field_from_json::<Vec<serde_json::Value>>(&list_json, "items").unwrap();
    assert!(
        items.iter().any(|item| item
            .get("id")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|id| id == execution_id)),
        "execution id {execution_id} not found in list"
    );

    // GET by id - triggers RequestResults, handler marks Completed on positive response
    let get_response = send_authenticated_cda_request(
        &test_env,
        &format!("{COMPONENTS_FLXC1000_OPERATIONS_CALIBRATESENSORS_EXECUTIONS}/{execution_id}"),
        StatusCode::OK,
        Method::GET,
        None,
        None,
    )
    .await
    .unwrap();
    let get_body: AsyncGetByIdResponse<serde_json::Value> = response_to_t(&get_response).unwrap();
    assert_eq!(
        get_body.status,
        ExecutionStatus::Completed,
        "status should be completed after RequestResults positive response"
    );

    let query_params = QueryParams(HashMap::from_iter([(
        "x-sovd2uds-force".to_string(),
        "true".to_string(),
    )]));
    // Clean up - stop the operation
    send_authenticated_cda_request(
        &test_env,
        &format!("{COMPONENTS_FLXC1000_OPERATIONS_CALIBRATESENSORS_EXECUTIONS}/{execution_id}"),
        StatusCode::OK,
        Method::DELETE,
        None,
        Some(&query_params),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn test_async_operation_get_results_after_stop() {
    let test_env = TestEnv::builder().await.unwrap();

    let _lock = Lock::acquire(&test_env, locks::COMPONENTS_FLXC1000_LOCKS, LOCK_EXPIRATION).await;

    // Start async operation
    let post_response = send_authenticated_cda_request(
        &test_env,
        COMPONENTS_FLXC1000_OPERATIONS_CALIBRATESENSORS_EXECUTIONS,
        StatusCode::ACCEPTED,
        Method::POST,
        Some("{}"),
        None,
    )
    .await
    .unwrap();
    let post_body: AsyncPostBody = response_to_t(&post_response).unwrap();
    let execution_id = post_body.id.clone();

    // Stop it - CalibrateSensors Stop echoes RoutineId (semantic="DATA") -> 200 with stopped body
    send_authenticated_cda_request(
        &test_env,
        &format!("{COMPONENTS_FLXC1000_OPERATIONS_CALIBRATESENSORS_EXECUTIONS}/{execution_id}"),
        StatusCode::OK,
        Method::DELETE,
        None,
        None,
    )
    .await
    .unwrap();

    // After Stop, the execution is removed - a GET by id should return 404
    send_authenticated_cda_request(
        &test_env,
        &format!("{COMPONENTS_FLXC1000_OPERATIONS_CALIBRATESENSORS_EXECUTIONS}/{execution_id}"),
        StatusCode::NOT_FOUND,
        Method::GET,
        None,
        None,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn test_async_operation_not_found() {
    let test_env = TestEnv::builder().await.unwrap();

    let _lock = Lock::acquire(&test_env, locks::COMPONENTS_FLXC1000_LOCKS, LOCK_EXPIRATION).await;

    send_authenticated_cda_request(
        &test_env,
        &format!("{COMPONENTS_FLXC1000_OPERATIONS}/nonexistentoperation/executions"),
        StatusCode::NOT_FOUND,
        Method::POST,
        Some("{}"),
        None,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn test_async_operation_in_flight_conflict() {
    let test_env = TestEnv::builder().await.unwrap();

    let _lock = Lock::acquire(&test_env, locks::COMPONENTS_FLXC1000_LOCKS, LOCK_EXPIRATION).await;

    // First POST - should succeed with 202
    let post_response = send_authenticated_cda_request(
        &test_env,
        COMPONENTS_FLXC1000_OPERATIONS_CALIBRATESENSORS_EXECUTIONS,
        StatusCode::ACCEPTED,
        Method::POST,
        Some("{}"),
        None,
    )
    .await
    .unwrap();
    let post_body: AsyncPostBody = response_to_t(&post_response).unwrap();
    let execution_id = post_body.id.clone();

    // Second POST while first is still running - rejected with 409 Conflict
    send_authenticated_cda_request(
        &test_env,
        COMPONENTS_FLXC1000_OPERATIONS_CALIBRATESENSORS_EXECUTIONS,
        StatusCode::CONFLICT,
        Method::POST,
        Some("{}"),
        None,
    )
    .await
    .unwrap();

    let query_params = QueryParams(HashMap::from_iter([(
        "x-sovd2uds-force".to_string(),
        "true".to_string(),
    )]));

    // Clean up the first execution using force=true
    send_authenticated_cda_request(
        &test_env,
        &format!("{COMPONENTS_FLXC1000_OPERATIONS_CALIBRATESENSORS_EXECUTIONS}/{execution_id}"),
        StatusCode::OK,
        Method::DELETE,
        None,
        Some(&query_params),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn test_sync_operation_sends_correct_uds_frame() {
    let test_env = TestEnv::builder().await.unwrap();

    let _lock = Lock::acquire(&test_env, locks::COMPONENTS_FLXC1000_LOCKS, LOCK_EXPIRATION).await;

    let recorder = test_env
        .record(ECU_FLXC1000)
        .await
        .expect("failed to start recording");

    send_authenticated_cda_request(
        &test_env,
        COMPONENTS_FLXC1000_OPERATIONS_SELFTEST_EXECUTIONS,
        StatusCode::OK,
        Method::POST,
        Some("{}"),
        None,
    )
    .await
    .unwrap();

    let recordings = recorder.stop().await.expect("failed to stop recording");

    // SelfTest Start: SID=0x31, subfunction=0x01, routine_id=0x1001
    assert!(
        recordings.contains(&"31011001".to_owned()),
        "expected SelfTest Start frame 31011001, got: {recordings:?}"
    );
}

#[tokio::test]
async fn test_async_operation_sends_correct_uds_frames() {
    let test_env = TestEnv::builder().await.unwrap();

    let _lock = Lock::acquire(&test_env, locks::COMPONENTS_FLXC1000_LOCKS, LOCK_EXPIRATION).await;

    let recorder = test_env
        .record(ECU_FLXC1000)
        .await
        .expect("failed to start recording");

    // Start - triggers CalibrateSensors Start (31 01 10 02)
    let post_response = send_authenticated_cda_request(
        &test_env,
        COMPONENTS_FLXC1000_OPERATIONS_CALIBRATESENSORS_EXECUTIONS,
        StatusCode::ACCEPTED,
        Method::POST,
        Some("{}"),
        None,
    )
    .await
    .unwrap();
    let post_body: AsyncPostBody = response_to_t(&post_response).unwrap();
    let execution_id = post_body.id.clone();

    // GET by id - triggers CalibrateSensors RequestResults (31 03 10 02)
    send_authenticated_cda_request(
        &test_env,
        &format!("{COMPONENTS_FLXC1000_OPERATIONS_CALIBRATESENSORS_EXECUTIONS}/{execution_id}"),
        StatusCode::OK,
        Method::GET,
        None,
        None,
    )
    .await
    .unwrap();

    let query_params = QueryParams(HashMap::from_iter([(
        "x-sovd2uds-force".to_string(),
        "true".to_string(),
    )]));
    // DELETE - triggers CalibrateSensors Stop (31 02 10 02)
    send_authenticated_cda_request(
        &test_env,
        &format!("{COMPONENTS_FLXC1000_OPERATIONS_CALIBRATESENSORS_EXECUTIONS}/{execution_id}"),
        StatusCode::OK,
        Method::DELETE,
        None,
        Some(&query_params),
    )
    .await
    .unwrap();

    let recordings = recorder.stop().await.expect("failed to stop recording");

    // CalibrateSensors Start: SID=0x31, subfunction=0x01, routine_id=0x1002
    assert!(
        recordings.contains(&"31011002".to_owned()),
        "expected CalibrateSensors Start frame 31011002, got: {recordings:?}"
    );
    // CalibrateSensors RequestResults: SID=0x31, subfunction=0x03, routine_id=0x1002
    assert!(
        recordings.contains(&"31031002".to_owned()),
        "expected CalibrateSensors RequestResults frame 31031002, got: {recordings:?}"
    );
    // CalibrateSensors Stop: SID=0x31, subfunction=0x02, routine_id=0x1002
    assert!(
        recordings.contains(&"31021002".to_owned()),
        "expected CalibrateSensors Stop frame 31021002, got: {recordings:?}"
    );
}

/// Verify that the `TimeCircuits` routine is listed as an asynchronous operation
/// (it has Start/Stop/RequestResults).
#[tokio::test]
async fn test_time_circuits_operation_listed() {
    let test_env = TestEnv::builder().await.unwrap();

    let response = send_authenticated_cda_request(
        &test_env,
        COMPONENTS_FLXC1000_OPERATIONS,
        StatusCode::OK,
        Method::GET,
        None,
        None,
    )
    .await
    .unwrap();

    let list: Items<OperationCollectionItem> = response_to_t(&response).unwrap();

    let time_circuits = list
        .items
        .iter()
        .find(|op| op.id.eq_ignore_ascii_case("timecircuits"))
        .expect("timecircuits operation not found in list");
    assert!(
        time_circuits.asynchronous_execution,
        "timecircuits should be asynchronous"
    );
    assert!(
        !time_circuits.proximity_proof_required,
        "timecircuits should not require proximity proof"
    );
}

/// Full lifecycle of the `TimeCircuits` routine using the default (`PresentDay`)
/// travel method: Start with no parameters, poll `RequestResults` until the
/// routine reports the "Arrived" step (`percentComplete` reaches 100 and a
/// non-empty `message` is returned), then Stop.
#[tokio::test]
async fn test_time_circuits_lifecycle() {
    let test_env = TestEnv::builder().await.unwrap();

    let _lock = Lock::acquire(&test_env, locks::COMPONENTS_FLXC1000_LOCKS, LOCK_EXPIRATION).await;

    // Start with the default ("PresentDay") travel method - travelMethod (the
    // TABLE-KEY row selector) and travelMethodData (the TABLE-STRUCT
    // dependent data, empty for this row) must both be present.
    let post_response = send_authenticated_cda_request(
        &test_env,
        COMPONENTS_FLXC1000_OPERATIONS_TIMECIRCUITS_EXECUTIONS,
        StatusCode::ACCEPTED,
        Method::POST,
        Some(r#"{"parameters":{"travelMethod":"PresentDay","travelMethodData":{}}}"#),
        None,
    )
    .await
    .unwrap();
    let post_body: AsyncPostBody = response_to_t(&post_response).unwrap();
    assert_eq!(post_body.status, ExecutionStatus::Running);
    let execution_id = post_body.id.clone();

    // Poll RequestResults - each GET advances the simulated progress by 25%.
    // percentComplete goes 25 -> 50 -> 75 -> 100 (step Arrived on the 4th call).
    let expected_percentages = [25u64, 50, 75, 100];
    let expected_steps = ["Accelerating", "TemporalDisplacement", "Arrived", "Arrived"];
    for (i, (&expected_percent, &expected_step)) in expected_percentages
        .iter()
        .zip(expected_steps.iter())
        .enumerate()
    {
        let get_response = send_authenticated_cda_request(
            &test_env,
            &format!("{COMPONENTS_FLXC1000_OPERATIONS_TIMECIRCUITS_EXECUTIONS}/{execution_id}"),
            StatusCode::OK,
            Method::GET,
            None,
            None,
        )
        .await
        .unwrap();
        let get_json = response_to_json(&get_response).unwrap();
        let parameters = get_json
            .get("parameters")
            .unwrap_or_else(|| panic!("call {i}: response must contain 'parameters'"));
        let percent_complete = parameters
            .get("percentComplete")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_else(|| panic!("call {i}: missing 'percentComplete'"));
        assert_eq!(
            percent_complete, expected_percent,
            "call {i}: unexpected percentComplete"
        );
        let step = parameters
            .get("step")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("call {i}: missing 'step'"));
        assert_eq!(step, expected_step, "call {i}: unexpected step");

        let message = parameters
            .get("message")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if step == "Arrived" {
            assert!(
                !message.is_empty(),
                "call {i}: expected non-empty message once Arrived"
            );
        } else {
            assert!(
                message.is_empty(),
                "call {i}: expected empty message before Arrived, got: {message}"
            );
        }
    }

    // Clean up - stop the operation
    let query_params = QueryParams(HashMap::from_iter([(
        "x-sovd2uds-force".to_string(),
        "true".to_string(),
    )]));
    send_authenticated_cda_request(
        &test_env,
        &format!("{COMPONENTS_FLXC1000_OPERATIONS_TIMECIRCUITS_EXECUTIONS}/{execution_id}"),
        StatusCode::OK,
        Method::DELETE,
        None,
        Some(&query_params),
    )
    .await
    .unwrap();
}

/// Verify the exact UDS frames sent for the `TimeCircuits` Start/RequestResults/Stop
/// sequence (routine id `0x1003`).
#[tokio::test]
async fn test_time_circuits_sends_correct_uds_frames() {
    let test_env = TestEnv::builder().await.unwrap();

    let _lock = Lock::acquire(&test_env, locks::COMPONENTS_FLXC1000_LOCKS, LOCK_EXPIRATION).await;

    let recorder = test_env
        .record(ECU_FLXC1000)
        .await
        .expect("failed to start recording");

    // Start - triggers TimeCircuits Start (31 01 10 03), default/PresentDay travel method
    let post_response = send_authenticated_cda_request(
        &test_env,
        COMPONENTS_FLXC1000_OPERATIONS_TIMECIRCUITS_EXECUTIONS,
        StatusCode::ACCEPTED,
        Method::POST,
        Some(r#"{"parameters":{"travelMethod":"PresentDay","travelMethodData":{}}}"#),
        None,
    )
    .await
    .unwrap();
    let post_body: AsyncPostBody = response_to_t(&post_response).unwrap();
    let execution_id = post_body.id.clone();

    // GET by id - triggers TimeCircuits RequestResults (31 03 10 03)
    send_authenticated_cda_request(
        &test_env,
        &format!("{COMPONENTS_FLXC1000_OPERATIONS_TIMECIRCUITS_EXECUTIONS}/{execution_id}"),
        StatusCode::OK,
        Method::GET,
        None,
        None,
    )
    .await
    .unwrap();

    let query_params = QueryParams(HashMap::from_iter([(
        "x-sovd2uds-force".to_string(),
        "true".to_string(),
    )]));
    // DELETE - triggers TimeCircuits Stop (31 02 10 03)
    send_authenticated_cda_request(
        &test_env,
        &format!("{COMPONENTS_FLXC1000_OPERATIONS_TIMECIRCUITS_EXECUTIONS}/{execution_id}"),
        StatusCode::OK,
        Method::DELETE,
        None,
        Some(&query_params),
    )
    .await
    .unwrap();

    let recordings = recorder.stop().await.expect("failed to stop recording");

    // TimeCircuits Start: SID=0x31, subfunction=0x01, routine_id=0x1003
    assert!(
        recordings.iter().any(|frame| frame.starts_with("31011003")),
        "expected TimeCircuits Start frame starting with 31011003, got: {recordings:?}"
    );
    // TimeCircuits RequestResults: SID=0x31, subfunction=0x03, routine_id=0x1003
    assert!(
        recordings.contains(&"31031003".to_owned()),
        "expected TimeCircuits RequestResults frame 31031003, got: {recordings:?}"
    );
    // TimeCircuits Stop: SID=0x31, subfunction=0x02, routine_id=0x1003
    assert!(
        recordings.contains(&"31021003".to_owned()),
        "expected TimeCircuits Stop frame 31021003, got: {recordings:?}"
    );
}

/// Verify the correct UDS frame for `TimeCircuits` Start with `ManualEntry` travel method.
/// The `ManualEntry` row encodes: travelMethod key=0x01 followed by
/// destinationYear (uint16), destinationMonth (uint8), destinationDay (uint8).
#[tokio::test]
async fn test_time_circuits_manual_entry_uds_frame() {
    let test_env = TestEnv::builder().await.unwrap();

    let _lock = Lock::acquire(&test_env, locks::COMPONENTS_FLXC1000_LOCKS, LOCK_EXPIRATION).await;

    let recorder = test_env
        .record(ECU_FLXC1000)
        .await
        .expect("failed to start recording");

    // Start with ManualEntry: year=1985, month=10, day=26
    let post_response = send_authenticated_cda_request(
        &test_env,
        COMPONENTS_FLXC1000_OPERATIONS_TIMECIRCUITS_EXECUTIONS,
        StatusCode::ACCEPTED,
        Method::POST,
        Some(
            r#"{"parameters":{"travelMethod":"ManualEntry","travelMethodData":{"ManualEntry":{"destinationYear":1985,"destinationMonth":10,"destinationDay":26}}}}"#,
        ),
        None,
    )
    .await
    .unwrap();
    let post_body: AsyncPostBody = response_to_t(&post_response).unwrap();
    let execution_id = post_body.id.clone();

    // Stop the operation
    let query_params = QueryParams(HashMap::from_iter([(
        "x-sovd2uds-force".to_string(),
        "true".to_string(),
    )]));
    send_authenticated_cda_request(
        &test_env,
        &format!("{COMPONENTS_FLXC1000_OPERATIONS_TIMECIRCUITS_EXECUTIONS}/{execution_id}"),
        StatusCode::OK,
        Method::DELETE,
        None,
        Some(&query_params),
    )
    .await
    .unwrap();

    let recordings = recorder.stop().await.expect("failed to stop recording");

    // TimeCircuits Start with ManualEntry:
    // SID=0x31, sub=0x01, routine_id=0x1003, travelMethod=0x01 (ManualEntry),
    // destinationYear=0x07C1 (1985), destinationMonth=0x0A (10), destinationDay=0x1A (26)
    let expected_start = "3101100301" // SID + sub + routine_id + key
        .to_owned()
        + "07c1" // year 1985
        + "0a" // month 10
        + "1a"; // day 26
    assert!(
        recordings
            .iter()
            .any(|frame| frame.to_lowercase() == expected_start),
        "expected TimeCircuits ManualEntry Start frame '{expected_start}', got: {recordings:?}"
    );
}

/// Verify the correct UDS frame for `TimeCircuits` Start with `PresetDestination` travel method.
/// The `PresetDestination` row encodes: travelMethod key=0x02 followed by presetId (uint8 texttable).
#[tokio::test]
async fn test_time_circuits_preset_destination_uds_frame() {
    let test_env = TestEnv::builder().await.unwrap();

    let _lock = Lock::acquire(&test_env, locks::COMPONENTS_FLXC1000_LOCKS, LOCK_EXPIRATION).await;

    let recorder = test_env
        .record(ECU_FLXC1000)
        .await
        .expect("failed to start recording");

    // Start with PresetDestination: presetId="2015-10-21_HillValley" (coded value 3)
    let post_response = send_authenticated_cda_request(
        &test_env,
        COMPONENTS_FLXC1000_OPERATIONS_TIMECIRCUITS_EXECUTIONS,
        StatusCode::ACCEPTED,
        Method::POST,
        Some(
            r#"{"parameters":{"travelMethod":"PresetDestination","travelMethodData":{"PresetDestination":{"presetId":"2015-10-21_HillValley"}}}}"#,
        ),
        None,
    )
    .await
    .unwrap();
    let post_body: AsyncPostBody = response_to_t(&post_response).unwrap();
    let execution_id = post_body.id.clone();

    // Stop the operation
    let query_params = QueryParams(HashMap::from_iter([(
        "x-sovd2uds-force".to_string(),
        "true".to_string(),
    )]));
    send_authenticated_cda_request(
        &test_env,
        &format!("{COMPONENTS_FLXC1000_OPERATIONS_TIMECIRCUITS_EXECUTIONS}/{execution_id}"),
        StatusCode::OK,
        Method::DELETE,
        None,
        Some(&query_params),
    )
    .await
    .unwrap();

    let recordings = recorder.stop().await.expect("failed to stop recording");

    // TimeCircuits Start with PresetDestination:
    // SID=0x31, sub=0x01, routine_id=0x1003, travelMethod=0x02 (PresetDestination),
    // presetId=0x03 (2015-10-21_HillValley)
    let expected_start = "31011003" // SID + sub + routine_id
        .to_owned()
        + "02" // key: PresetDestination
        + "03"; // presetId: 2015-10-21_HillValley
    assert!(
        recordings
            .iter()
            .any(|frame| frame.to_lowercase() == expected_start),
        "expected TimeCircuits PresetDestination Start frame '{expected_start}', got: \
         {recordings:?}"
    );
}

/// Verify that listing operations on a functional group includes
/// `engage_safety_squints` and that it is marked as asynchronous (it has Stop).
#[tokio::test]
async fn test_functional_operation_list() {
    let test_env = TestEnv::builder().await.unwrap();

    let response = send_authenticated_cda_request(
        &test_env,
        FUNCTIONS_FUNCTIONALGROUPS_DOIP_OPERATIONS,
        StatusCode::OK,
        Method::GET,
        None,
        None,
    )
    .await
    .unwrap();

    let list: Items<OperationCollectionItem> = response_to_t(&response).unwrap();

    let squints = list
        .items
        .iter()
        .find(|op| op.id.eq_ignore_ascii_case("engage_safety_squints"))
        .expect("engage_safety_squints operation not found in functional group operations list");
    assert!(
        squints.asynchronous_execution,
        "engage_safety_squints should be asynchronous (has Stop)"
    );
    assert!(
        !squints.proximity_proof_required,
        "engage_safety_squints should not require proximity proof"
    );
}

/// Verify that `POST`ing a functional-group operation without holding the FG lock
/// is rejected with 409 Conflict.
#[tokio::test]
async fn test_functional_operation_post_no_lock() {
    let test_env = TestEnv::builder().await.unwrap();

    send_authenticated_cda_request(
        &test_env,
        FUNCTIONS_FUNCTIONALGROUPS_DOIP_OPERATIONS_ENGAGE_SAFETY_SQUINTS_EXECUTIONS,
        StatusCode::CONFLICT,
        Method::POST,
        Some(r#"{"parameters":{"SquintSlitWidth":2.5}}"#),
        None,
    )
    .await
    .unwrap();
}

/// Full lifecycle for a functional-group operation without `RequestResults`:
///
/// 1. **POST** (Start) -> 202 Accepted, execution id returned
/// 2. **GET by id** -> Execution with an errors object indicating no `RequestResults` subfunction
/// 3. **DELETE** (Stop) -> 204 No Content (execution removed)
#[tokio::test]
async fn test_functional_operation_lifecycle_no_request_results() {
    let test_env = TestEnv::builder().await.unwrap();

    let _lock = Lock::acquire(
        &test_env,
        locks::FUNCTIONS_FUNCTIONALGROUPS_DOIP_LOCKS,
        LOCK_EXPIRATION,
    )
    .await;

    // 1. POST (Start) -> 202 Accepted
    let post_response = send_authenticated_cda_request(
        &test_env,
        FUNCTIONS_FUNCTIONALGROUPS_DOIP_OPERATIONS_ENGAGE_SAFETY_SQUINTS_EXECUTIONS,
        StatusCode::ACCEPTED,
        Method::POST,
        Some(r#"{"parameters":{"SquintSlitWidth":2.5}}"#),
        None,
    )
    .await
    .unwrap();

    let post_body: AsyncPostBody = response_to_t(&post_response).unwrap();
    assert_eq!(post_body.status, ExecutionStatus::Running);
    let execution_id = post_body.id.clone();

    // 2. GET by execution id -> 200 with execution status + errors array
    //    (operation has no RequestResults, so the response carries a DataError
    //    at path "/")
    let get_response = send_authenticated_cda_request(
        &test_env,
        &format!(
            "{FUNCTIONS_FUNCTIONALGROUPS_DOIP_OPERATIONS_ENGAGE_SAFETY_SQUINTS_EXECUTIONS}/\
             {execution_id}"
        ),
        StatusCode::OK,
        Method::GET,
        None,
        None,
    )
    .await
    .unwrap();

    let get_json = response_to_json(&get_response).unwrap();
    let status = extract_field_from_json::<String>(&get_json, "status")
        .expect("response must contain 'status'");
    assert_eq!(
        status, "running",
        "execution should still be running (Stop not called yet)"
    );
    let errors = extract_field_from_json::<Vec<serde_json::Value>>(&get_json, "errors")
        .expect("response must contain 'errors' when RequestResults is not supported");
    assert_eq!(errors.len(), 1, "expected exactly one error entry");
    let data_error = errors.first().expect("errors array must not be empty");
    assert_eq!(
        data_error.get("path"),
        Some(&serde_json::json!("/")),
        "error path must be '/'"
    );
    let message = data_error
        .get("error")
        .and_then(|e| e.get("message"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    assert!(
        message.contains("RequestResults"),
        "error message should mention RequestResults, got: {message}"
    );

    // 3. DELETE (Stop) -> 204 No Content
    send_authenticated_cda_request(
        &test_env,
        &format!(
            "{FUNCTIONS_FUNCTIONALGROUPS_DOIP_OPERATIONS_ENGAGE_SAFETY_SQUINTS_EXECUTIONS}/\
             {execution_id}"
        ),
        StatusCode::NO_CONTENT,
        Method::DELETE,
        None,
        None,
    )
    .await
    .unwrap();
}

/// Verify that GET `{ecu}/operations/{op}` returns 200 OK with the correct operation info even
/// when the ECU has never been contacted (variant is in the initial `NotTested` state).
#[tokio::test]
async fn test_get_operation_info_before_variant_detection() {
    let test_env = TestEnv::builder().await.unwrap();

    // Use ecusim recording to prove no UDS frame is sent for a pure info GET.
    let recorder = test_env.record(ECU_FLXC1000).await.unwrap();

    let response = send_authenticated_cda_request(
        &test_env,
        COMPONENTS_FLXC1000_OPERATIONS_SELFTEST,
        StatusCode::OK,
        Method::GET,
        None,
        None,
    )
    .await
    .unwrap();

    let frames = recorder.stop().await.unwrap();
    assert!(
        frames.is_empty(),
        "Expected no UDS frames for a pure info GET, but got: {frames:?}"
    );

    let list: Items<OperationCollectionItem> = response_to_t(&response).unwrap();
    assert_eq!(list.items.len(), 1, "Expected exactly one item in response");
    let op = list.items.first().expect("Expected one operation item");
    assert!(
        op.id.eq_ignore_ascii_case("selftest"),
        "Expected id 'selftest', got: {}",
        op.id
    );
    assert!(
        !op.asynchronous_execution,
        "selftest should not be asynchronous (no Stop or RequestResults)"
    );
    assert!(
        !op.proximity_proof_required,
        "selftest should not require proximity proof"
    );
}
