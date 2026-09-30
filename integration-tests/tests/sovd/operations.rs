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

use http::StatusCode;
use serde::de::DeserializeOwned;
use sovd_interfaces::components::ecu::operations::{
    ExecutionStatus, OperationDeleteQuery, service::executions,
};

use crate::{
    client::{
        self,
        components::operations::ExecutionHandle,
        locks::{Lock, Locks},
    },
    sovd::{ECU_FLXC1000, FUNCTIONAL_GROUP},
    util::test_env::TestEnv,
};

/// The self test of FLXC1000, a synchronous operation.
const SELF_TEST: &str = "selftest";
/// The sensor calibration of FLXC1000, an asynchronous operation.
const CALIBRATE_SENSORS: &str = "calibratesensors";
/// The time circuits of FLXC1000, an asynchronous operation.
const TIME_CIRCUITS: &str = "timecircuits";
/// The safety squints of the functional group, an asynchronous operation.
const ENGAGE_SAFETY_SQUINTS: &str = "engage_safety_squints";

/// Expiration of the locks the tests acquire.
const LOCK_EXPIRATION: Duration = Duration::from_secs(60);

/// A start request without parameters, the empty JSON object `{}`.
/// [`executions::Request`] would send `{"parameters":null}` instead.
fn no_parameters() -> serde_json::Value {
    serde_json::json!({})
}

/// A start request with `parameters`, a JSON object.
fn with_parameters(parameters: serde_json::Value) -> executions::Request {
    let serde_json::Value::Object(parameters) = parameters else {
        panic!("parameters must be a JSON object, got {parameters}");
    };
    executions::Request {
        timeout: None,
        parameters: Some(parameters.into_iter().collect()),
    }
}

/// Stops `execution`, with `x-sovd2uds-force=true` if `force`, and without
/// query parameters otherwise.
async fn stop<E: DeserializeOwned>(
    execution: &ExecutionHandle<'_, E>,
    force: bool,
) -> client::Result<client::Response<Option<E>>> {
    if force {
        execution
            .delete_with(&OperationDeleteQuery {
                force: true,
                ..Default::default()
            })
            .await
    } else {
        execution.delete().await
    }
}

/// Acquires a lock in `locks` expiring after [`LOCK_EXPIRATION`], and checks
/// that it can be read back.
///
/// # Panics
/// If the lock is not created (`201 Created`) or cannot be read back.
async fn acquire_lock(locks: Locks<'_>) -> Lock {
    let lock = locks
        .create(LOCK_EXPIRATION)
        .await
        .expect("failed to create lock")
        .expect_status(StatusCode::CREATED)
        .into_body();
    lock.handle()
        .get()
        .await
        .expect("failed to read back lock")
        .expect_status(StatusCode::OK);
    lock
}

#[tokio::test]
async fn test_list_operations() {
    let test_env = TestEnv::builder().await.unwrap();

    let list = test_env
        .client()
        .component(ECU_FLXC1000)
        .operations()
        .await
        .unwrap()
        .expect_status(StatusCode::OK);

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

    let err = test_env
        .client()
        .component(ECU_FLXC1000)
        .operation(SELF_TEST)
        .start(&no_parameters())
        .await
        .expect_err("starting an operation without a lock must fail");
    assert_eq!(err.status(), Some(StatusCode::CONFLICT));
}

#[tokio::test]
async fn test_async_operation_delete_after_lock_release() {
    let test_env = TestEnv::builder().await.unwrap();
    let ecu = test_env.client().component(ECU_FLXC1000);
    let operation = ecu.operation(CALIBRATE_SENSORS);

    let lock = acquire_lock(ecu.locks()).await;

    // Start async operation while holding the lock
    let started = operation
        .start(&no_parameters())
        .await
        .unwrap()
        .expect_status(StatusCode::ACCEPTED)
        .into_body()
        .started();
    let execution = operation.execution(&started.id);

    // Release the lock before attempting DELETE
    lock.release()
        .await
        .unwrap()
        .expect_status(StatusCode::NO_CONTENT);

    // DELETE is a write operation and requires a currently active lock.
    let Err(err) = stop(&execution, false).await else {
        panic!("stopping an execution without a lock must fail");
    };
    assert_eq!(err.status(), Some(StatusCode::CONFLICT));

    let _cleanup_lock = acquire_lock(ecu.locks()).await;
    stop(&execution, false)
        .await
        .unwrap()
        .expect_status(StatusCode::OK);
}

#[tokio::test]
async fn test_sync_operation() {
    let test_env = TestEnv::builder().await.unwrap();
    let ecu = test_env.client().component(ECU_FLXC1000);

    let _lock = acquire_lock(ecu.locks()).await;

    ecu.operation(SELF_TEST)
        .start(&no_parameters())
        .await
        .unwrap()
        .expect_status(StatusCode::OK)
        .into_body()
        .completed();
}

#[tokio::test]
async fn test_async_operation_lifecycle() {
    let test_env = TestEnv::builder().await.unwrap();
    let ecu = test_env.client().component(ECU_FLXC1000);
    let operation = ecu.operation(CALIBRATE_SENSORS);

    let _lock = acquire_lock(ecu.locks()).await;

    // Start the async calibration - expect 202 Accepted
    let started = operation
        .start(&no_parameters())
        .await
        .unwrap()
        .expect_status(StatusCode::ACCEPTED)
        .into_body()
        .started();
    assert_eq!(started.status, Some(ExecutionStatus::Running));
    let execution_id = started.id;

    // GET the list of executions - should contain our id
    let executions = operation
        .executions()
        .await
        .unwrap()
        .expect_status(StatusCode::OK);
    assert!(
        executions.items.iter().any(|item| item.id == execution_id),
        "execution id {execution_id} not found in list"
    );

    // GET by id - triggers RequestResults, handler marks Completed on positive response
    let execution = operation.execution(&execution_id);
    let state = execution.get().await.unwrap().expect_status(StatusCode::OK);
    assert_eq!(
        state.status,
        ExecutionStatus::Completed,
        "status should be completed after RequestResults positive response"
    );

    // Clean up - stop the operation
    stop(&execution, true)
        .await
        .unwrap()
        .expect_status(StatusCode::OK);
}

#[tokio::test]
async fn test_async_operation_get_results_after_stop() {
    let test_env = TestEnv::builder().await.unwrap();
    let ecu = test_env.client().component(ECU_FLXC1000);
    let operation = ecu.operation(CALIBRATE_SENSORS);

    let _lock = acquire_lock(ecu.locks()).await;

    // Start async operation
    let started = operation
        .start(&no_parameters())
        .await
        .unwrap()
        .expect_status(StatusCode::ACCEPTED)
        .into_body()
        .started();
    let execution = operation.execution(&started.id);

    // Stop it - CalibrateSensors Stop echoes RoutineId (semantic="DATA") -> 200 with stopped body
    stop(&execution, false)
        .await
        .unwrap()
        .expect_status(StatusCode::OK);

    // After Stop, the execution is removed - a GET by id should return 404
    let Err(err) = execution.get().await else {
        panic!("a stopped execution must be gone");
    };
    assert_eq!(err.status(), Some(StatusCode::NOT_FOUND));
}

#[tokio::test]
async fn test_async_operation_not_found() {
    let test_env = TestEnv::builder().await.unwrap();
    let ecu = test_env.client().component(ECU_FLXC1000);

    let _lock = acquire_lock(ecu.locks()).await;

    let err = ecu
        .operation("nonexistentoperation")
        .start(&no_parameters())
        .await
        .expect_err("starting an unknown operation must fail");
    assert_eq!(err.status(), Some(StatusCode::NOT_FOUND));
}

#[tokio::test]
async fn test_async_operation_in_flight_conflict() {
    let test_env = TestEnv::builder().await.unwrap();
    let ecu = test_env.client().component(ECU_FLXC1000);
    let operation = ecu.operation(CALIBRATE_SENSORS);

    let _lock = acquire_lock(ecu.locks()).await;

    // First POST - should succeed with 202
    let started = operation
        .start(&no_parameters())
        .await
        .unwrap()
        .expect_status(StatusCode::ACCEPTED)
        .into_body()
        .started();

    // Second POST while first is still running - rejected with 409 Conflict
    let err = operation
        .start(&no_parameters())
        .await
        .expect_err("a second execution must be rejected while the first runs");
    assert_eq!(err.status(), Some(StatusCode::CONFLICT));

    // Clean up the first execution using force=true
    stop(&operation.execution(&started.id), true)
        .await
        .unwrap()
        .expect_status(StatusCode::OK);
}

#[tokio::test]
async fn test_sync_operation_sends_correct_uds_frame() {
    let test_env = TestEnv::builder().await.unwrap();
    let ecu = test_env.client().component(ECU_FLXC1000);

    let _lock = acquire_lock(ecu.locks()).await;

    let recorder = test_env
        .record(ECU_FLXC1000)
        .await
        .expect("failed to start recording");

    ecu.operation(SELF_TEST)
        .start(&no_parameters())
        .await
        .unwrap()
        .expect_status(StatusCode::OK)
        .into_body()
        .completed();

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
    let ecu = test_env.client().component(ECU_FLXC1000);
    let operation = ecu.operation(CALIBRATE_SENSORS);

    let _lock = acquire_lock(ecu.locks()).await;

    let recorder = test_env
        .record(ECU_FLXC1000)
        .await
        .expect("failed to start recording");

    // Start - triggers CalibrateSensors Start (31 01 10 02)
    let started = operation
        .start(&no_parameters())
        .await
        .unwrap()
        .expect_status(StatusCode::ACCEPTED)
        .into_body()
        .started();
    let execution = operation.execution(&started.id);

    // GET by id - triggers CalibrateSensors RequestResults (31 03 10 02)
    execution.get().await.unwrap().expect_status(StatusCode::OK);

    // DELETE - triggers CalibrateSensors Stop (31 02 10 02)
    stop(&execution, true)
        .await
        .unwrap()
        .expect_status(StatusCode::OK);

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

    let list = test_env
        .client()
        .component(ECU_FLXC1000)
        .operations()
        .await
        .unwrap()
        .expect_status(StatusCode::OK);

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
    let ecu = test_env.client().component(ECU_FLXC1000);
    let operation = ecu.operation(TIME_CIRCUITS);

    let _lock = acquire_lock(ecu.locks()).await;

    // Start with the default ("PresentDay") travel method - travelMethod (the
    // TABLE-KEY row selector) and travelMethodData (the TABLE-STRUCT
    // dependent data, empty for this row) must both be present.
    let started = operation
        .start(&with_parameters(serde_json::json!({
            "travelMethod": "PresentDay",
            "travelMethodData": {}
        })))
        .await
        .unwrap()
        .expect_status(StatusCode::ACCEPTED)
        .into_body()
        .started();
    assert_eq!(started.status, Some(ExecutionStatus::Running));
    let execution = operation.execution(&started.id);

    // Poll RequestResults - each GET advances the simulated progress by 25%.
    // percentComplete goes 25 -> 50 -> 75 -> 100 (step Arrived on the 4th call).
    let expected_percentages = [25u64, 50, 75, 100];
    let expected_steps = ["Accelerating", "TemporalDisplacement", "Arrived", "Arrived"];
    for (i, (&expected_percent, &expected_step)) in expected_percentages
        .iter()
        .zip(expected_steps.iter())
        .enumerate()
    {
        let state = execution
            .get()
            .await
            .unwrap()
            .expect_status(StatusCode::OK)
            .into_body();
        let parameters = state
            .parameters
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
    stop(&execution, true)
        .await
        .unwrap()
        .expect_status(StatusCode::OK);
}

/// Verify the exact UDS frames sent for the `TimeCircuits` Start/RequestResults/Stop
/// sequence (routine id `0x1003`).
#[tokio::test]
async fn test_time_circuits_sends_correct_uds_frames() {
    let test_env = TestEnv::builder().await.unwrap();
    let ecu = test_env.client().component(ECU_FLXC1000);
    let operation = ecu.operation(TIME_CIRCUITS);

    let _lock = acquire_lock(ecu.locks()).await;

    let recorder = test_env
        .record(ECU_FLXC1000)
        .await
        .expect("failed to start recording");

    // Start - triggers TimeCircuits Start (31 01 10 03), default/PresentDay travel method
    let started = operation
        .start(&with_parameters(serde_json::json!({
            "travelMethod": "PresentDay",
            "travelMethodData": {}
        })))
        .await
        .unwrap()
        .expect_status(StatusCode::ACCEPTED)
        .into_body()
        .started();
    let execution = operation.execution(&started.id);

    // GET by id - triggers TimeCircuits RequestResults (31 03 10 03)
    execution.get().await.unwrap().expect_status(StatusCode::OK);

    // DELETE - triggers TimeCircuits Stop (31 02 10 03)
    stop(&execution, true)
        .await
        .unwrap()
        .expect_status(StatusCode::OK);

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
    let ecu = test_env.client().component(ECU_FLXC1000);
    let operation = ecu.operation(TIME_CIRCUITS);

    let _lock = acquire_lock(ecu.locks()).await;

    let recorder = test_env
        .record(ECU_FLXC1000)
        .await
        .expect("failed to start recording");

    // Start with ManualEntry: year=1985, month=10, day=26
    let started = operation
        .start(&with_parameters(serde_json::json!({
            "travelMethod": "ManualEntry",
            "travelMethodData": {
                "ManualEntry": {
                    "destinationYear": 1985,
                    "destinationMonth": 10,
                    "destinationDay": 26
                }
            }
        })))
        .await
        .unwrap()
        .expect_status(StatusCode::ACCEPTED)
        .into_body()
        .started();

    // Stop the operation
    stop(&operation.execution(&started.id), true)
        .await
        .unwrap()
        .expect_status(StatusCode::OK);

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
    let ecu = test_env.client().component(ECU_FLXC1000);
    let operation = ecu.operation(TIME_CIRCUITS);

    let _lock = acquire_lock(ecu.locks()).await;

    let recorder = test_env
        .record(ECU_FLXC1000)
        .await
        .expect("failed to start recording");

    // Start with PresetDestination: presetId="2015-10-21_HillValley" (coded value 3)
    let started = operation
        .start(&with_parameters(serde_json::json!({
            "travelMethod": "PresetDestination",
            "travelMethodData": {
                "PresetDestination": { "presetId": "2015-10-21_HillValley" }
            }
        })))
        .await
        .unwrap()
        .expect_status(StatusCode::ACCEPTED)
        .into_body()
        .started();

    // Stop the operation
    stop(&operation.execution(&started.id), true)
        .await
        .unwrap()
        .expect_status(StatusCode::OK);

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

    let list = test_env
        .client()
        .functional_group(FUNCTIONAL_GROUP)
        .operations()
        .await
        .unwrap()
        .expect_status(StatusCode::OK);

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

    let err = test_env
        .client()
        .functional_group(FUNCTIONAL_GROUP)
        .operation(ENGAGE_SAFETY_SQUINTS)
        .start(&with_parameters(
            serde_json::json!({ "SquintSlitWidth": 2.5 }),
        ))
        .await
        .expect_err("starting a functional operation without a lock must fail");
    assert_eq!(err.status(), Some(StatusCode::CONFLICT));
}

/// Full lifecycle for a functional-group operation without `RequestResults`:
///
/// 1. **POST** (Start) -> 202 Accepted, execution id returned
/// 2. **GET by id** -> Execution with an errors object indicating no `RequestResults` subfunction
/// 3. **DELETE** (Stop) -> 204 No Content (execution removed)
#[tokio::test]
async fn test_functional_operation_lifecycle_no_request_results() {
    let test_env = TestEnv::builder().await.unwrap();
    let group = test_env.client().functional_group(FUNCTIONAL_GROUP);
    let operation = group.operation(ENGAGE_SAFETY_SQUINTS);

    let _lock = acquire_lock(group.locks()).await;

    // 1. POST (Start) -> 202 Accepted
    let started = operation
        .start(&with_parameters(
            serde_json::json!({ "SquintSlitWidth": 2.5 }),
        ))
        .await
        .unwrap()
        .expect_status(StatusCode::ACCEPTED)
        .into_body()
        .started();
    assert_eq!(started.status, Some(ExecutionStatus::Running));
    let execution = operation.execution(&started.id);

    // 2. GET by execution id -> 200 with execution status + errors array
    //    (operation has no RequestResults, so the response carries a DataError
    //    at path "/")
    let state = execution.get().await.unwrap().expect_status(StatusCode::OK);
    assert_eq!(
        state.status,
        ExecutionStatus::Running,
        "execution should still be running (Stop not called yet)"
    );
    assert_eq!(state.errors.len(), 1, "expected exactly one error entry");
    let data_error = state
        .errors
        .first()
        .expect("errors array must not be empty");
    assert_eq!(data_error.path, "/", "error path must be '/'");
    let message = &data_error.error.message;
    assert!(
        message.contains("RequestResults"),
        "error message should mention RequestResults, got: {message}"
    );

    // 3. DELETE (Stop) -> 204 No Content
    stop(&execution, false)
        .await
        .unwrap()
        .expect_status(StatusCode::NO_CONTENT);
}

/// Verify that GET `{ecu}/operations/{op}` returns 200 OK with the correct operation info even
/// when the ECU has never been contacted (variant is in the initial `NotTested` state).
#[tokio::test]
async fn test_get_operation_info_before_variant_detection() {
    let test_env = TestEnv::builder().await.unwrap();

    // Use ecusim recording to prove no UDS frame is sent for a pure info GET.
    let recorder = test_env.record(ECU_FLXC1000).await.unwrap();

    let description = test_env
        .client()
        .component(ECU_FLXC1000)
        .operation(SELF_TEST)
        .get()
        .await
        .unwrap()
        .expect_status(StatusCode::OK);

    let frames = recorder.stop().await.unwrap();
    assert!(
        frames.is_empty(),
        "Expected no UDS frames for a pure info GET, but got: {frames:?}"
    );

    let list = description.into_body();
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
