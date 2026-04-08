use cda_interfaces::HashMap;
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
    sovd,
    util::{
        ecusim,
        http::{
            QueryParams, auth_header, extract_field_from_json, response_to_json, response_to_t,
            send_cda_request,
        },
        runtime::setup_integration_test,
    },
};

#[tokio::test]
async fn test_list_operations() {
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();
    let auth = auth_header(&runtime.config, None).await.unwrap();
    let ecu_endpoint = sovd::ECU_FLXC1000_ENDPOINT;

    let response = send_cda_request(
        &runtime.config,
        &format!("{ecu_endpoint}/operations"),
        StatusCode::OK,
        Method::GET,
        None,
        Some(&auth),
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
async fn test_sync_operation_no_lock() {
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();
    let auth = auth_header(&runtime.config, None).await.unwrap();
    let ecu_endpoint = sovd::ECU_FLXC1000_ENDPOINT;

    send_cda_request(
        &runtime.config,
        &format!("{ecu_endpoint}/operations/selftest/executions"),
        StatusCode::FORBIDDEN,
        Method::POST,
        Some("{}"),
        Some(&auth),
        None,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn test_async_operation_delete_no_lock() {
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();
    let auth = auth_header(&runtime.config, None).await.unwrap();
    let ecu_endpoint = sovd::ECU_FLXC1000_ENDPOINT;

    let lock_id = acquire_ecu_lock(runtime, &auth).await;

    // Start async operation while holding the lock
    let post_response = send_cda_request(
        &runtime.config,
        &format!("{ecu_endpoint}/operations/calibratesensors/executions"),
        StatusCode::ACCEPTED,
        Method::POST,
        Some("{}"),
        Some(&auth),
        None,
    )
    .await
    .unwrap();
    let post_body: AsyncPostBody = response_to_t(&post_response).unwrap();
    let execution_id = post_body.id.clone();

    // Release the lock before attempting DELETE
    release_ecu_lock(runtime, &auth, &lock_id).await;

    // DELETE without a lock - should be 403
    send_cda_request(
        &runtime.config,
        &format!("{ecu_endpoint}/operations/calibratesensors/executions/{execution_id}"),
        StatusCode::FORBIDDEN,
        Method::DELETE,
        None,
        Some(&auth),
        None,
    )
    .await
    .unwrap();

    // Re-acquire lock for cleanup
    let lock_id2 = acquire_ecu_lock(runtime, &auth).await;
    let query_params = QueryParams(HashMap::from_iter([(
        "x-sovd2uds-force".to_string(),
        "true".to_string(),
    )]));
    // CalibrateSensors Stop echoes RoutineId (semantic="DATA") -> 200 with stopped body
    send_cda_request(
        &runtime.config,
        &format!("{ecu_endpoint}/operations/calibratesensors/executions/{execution_id}"),
        StatusCode::OK,
        Method::DELETE,
        None,
        Some(&auth),
        Some(&query_params),
    )
    .await
    .unwrap();
    release_ecu_lock(runtime, &auth, &lock_id2).await;
}

#[tokio::test]
async fn test_sync_operation() {
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();
    let auth = auth_header(&runtime.config, None).await.unwrap();
    let ecu_endpoint = sovd::ECU_FLXC1000_ENDPOINT;

    let lock_id = acquire_ecu_lock(runtime, &auth).await;

    send_cda_request(
        &runtime.config,
        &format!("{ecu_endpoint}/operations/selftest/executions"),
        StatusCode::OK,
        Method::POST,
        Some("{}"),
        Some(&auth),
        None,
    )
    .await
    .unwrap();

    release_ecu_lock(runtime, &auth, &lock_id).await;
}

#[tokio::test]
async fn test_async_operation_lifecycle() {
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();
    let auth = auth_header(&runtime.config, None).await.unwrap();
    let ecu_endpoint = sovd::ECU_FLXC1000_ENDPOINT;

    let lock_id = acquire_ecu_lock(runtime, &auth).await;

    // Start the async calibration - expect 202 Accepted
    let post_response = send_cda_request(
        &runtime.config,
        &format!("{ecu_endpoint}/operations/calibratesensors/executions"),
        StatusCode::ACCEPTED,
        Method::POST,
        Some("{}"),
        Some(&auth),
        None,
    )
    .await
    .unwrap();

    let post_body: AsyncPostBody = response_to_t(&post_response).unwrap();
    assert_eq!(post_body.status, ExecutionStatus::Running);
    let execution_id = post_body.id.clone();

    // GET the list of executions - should contain our id
    let list_response = send_cda_request(
        &runtime.config,
        &format!("{ecu_endpoint}/operations/calibratesensors/executions"),
        StatusCode::OK,
        Method::GET,
        None,
        Some(&auth),
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
    let get_response = send_cda_request(
        &runtime.config,
        &format!("{ecu_endpoint}/operations/calibratesensors/executions/{execution_id}"),
        StatusCode::OK,
        Method::GET,
        None,
        Some(&auth),
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

    // Verify ECU sim runningCalibration is still true (Start was called but not Stop)
    let ecu_state = ecusim::get_ecu_state(&runtime.ecu_sim, "flxc1000")
        .await
        .expect("Failed to get ECU sim state");
    assert!(
        ecu_state.running_calibration,
        "ECU sim should have runningCalibration=true (Stop was not called)"
    );

    let query_params = QueryParams(HashMap::from_iter([(
        "x-sovd2uds-force".to_string(),
        "true".to_string(),
    )]));
    // Clean up - stop the operation
    send_cda_request(
        &runtime.config,
        &format!("{ecu_endpoint}/operations/calibratesensors/executions/{execution_id}"),
        StatusCode::OK,
        Method::DELETE,
        None,
        Some(&auth),
        Some(&query_params),
    )
    .await
    .unwrap();

    release_ecu_lock(runtime, &auth, &lock_id).await;
}

#[tokio::test]
async fn test_async_operation_get_results_after_stop() {
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();
    let auth = auth_header(&runtime.config, None).await.unwrap();
    let ecu_endpoint = sovd::ECU_FLXC1000_ENDPOINT;

    let lock_id = acquire_ecu_lock(runtime, &auth).await;

    // Start async operation
    let post_response = send_cda_request(
        &runtime.config,
        &format!("{ecu_endpoint}/operations/calibratesensors/executions"),
        StatusCode::ACCEPTED,
        Method::POST,
        Some("{}"),
        Some(&auth),
        None,
    )
    .await
    .unwrap();
    let post_body: AsyncPostBody = response_to_t(&post_response).unwrap();
    let execution_id = post_body.id.clone();

    // Stop it - CalibrateSensors Stop echoes RoutineId (semantic="DATA") -> 200 with stopped body
    send_cda_request(
        &runtime.config,
        &format!("{ecu_endpoint}/operations/calibratesensors/executions/{execution_id}"),
        StatusCode::OK,
        Method::DELETE,
        None,
        Some(&auth),
        None,
    )
    .await
    .unwrap();

    // After Stop, the execution is removed - a GET by id should return 404
    send_cda_request(
        &runtime.config,
        &format!("{ecu_endpoint}/operations/calibratesensors/executions/{execution_id}"),
        StatusCode::NOT_FOUND,
        Method::GET,
        None,
        Some(&auth),
        None,
    )
    .await
    .unwrap();

    release_ecu_lock(runtime, &auth, &lock_id).await;
}

#[tokio::test]
async fn test_async_operation_not_found() {
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();
    let auth = auth_header(&runtime.config, None).await.unwrap();
    let ecu_endpoint = sovd::ECU_FLXC1000_ENDPOINT;

    let lock_id = acquire_ecu_lock(runtime, &auth).await;

    send_cda_request(
        &runtime.config,
        &format!("{ecu_endpoint}/operations/nonexistentoperation/executions"),
        StatusCode::NOT_FOUND,
        Method::POST,
        Some("{}"),
        Some(&auth),
        None,
    )
    .await
    .unwrap();

    release_ecu_lock(runtime, &auth, &lock_id).await;
}

#[tokio::test]
async fn test_async_operation_in_flight_conflict() {
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();
    let auth = auth_header(&runtime.config, None).await.unwrap();
    let ecu_endpoint = sovd::ECU_FLXC1000_ENDPOINT;

    let lock_id = acquire_ecu_lock(runtime, &auth).await;

    // First POST - should succeed with 202
    let post_response = send_cda_request(
        &runtime.config,
        &format!("{ecu_endpoint}/operations/calibratesensors/executions"),
        StatusCode::ACCEPTED,
        Method::POST,
        Some("{}"),
        Some(&auth),
        None,
    )
    .await
    .unwrap();
    let post_body: AsyncPostBody = response_to_t(&post_response).unwrap();
    let execution_id = post_body.id.clone();

    // Second POST while first is still running - rejected with 409 Conflict
    send_cda_request(
        &runtime.config,
        &format!("{ecu_endpoint}/operations/calibratesensors/executions"),
        StatusCode::CONFLICT,
        Method::POST,
        Some("{}"),
        Some(&auth),
        None,
    )
    .await
    .unwrap();

    let query_params = QueryParams(HashMap::from_iter([(
        "x-sovd2uds-force".to_string(),
        "true".to_string(),
    )]));

    // Clean up the first execution using force=true
    send_cda_request(
        &runtime.config,
        &format!("{ecu_endpoint}/operations/calibratesensors/executions/{execution_id}"),
        StatusCode::OK,
        Method::DELETE,
        None,
        Some(&auth),
        Some(&query_params),
    )
    .await
    .unwrap();

    release_ecu_lock(runtime, &auth, &lock_id).await;
}

#[tokio::test]
async fn test_sync_operation_sends_correct_uds_frame() {
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();
    let auth = auth_header(&runtime.config, None).await.unwrap();
    let ecu_endpoint = sovd::ECU_FLXC1000_ENDPOINT;

    let lock_id = acquire_ecu_lock(runtime, &auth).await;

    ecusim::start_recording(&runtime.ecu_sim, "flxc1000")
        .await
        .expect("failed to start recording");

    send_cda_request(
        &runtime.config,
        &format!("{ecu_endpoint}/operations/selftest/executions"),
        StatusCode::OK,
        Method::POST,
        Some("{}"),
        Some(&auth),
        None,
    )
    .await
    .unwrap();

    let recordings = ecusim::stop_and_clear_recording(&runtime.ecu_sim, "flxc1000")
        .await
        .expect("failed to stop recording");

    // SelfTest Start: SID=0x31, subfunction=0x01, routine_id=0x1001
    assert!(
        recordings.contains(&"31011001".to_owned()),
        "expected SelfTest Start frame 31011001, got: {recordings:?}"
    );

    release_ecu_lock(runtime, &auth, &lock_id).await;
}

#[tokio::test]
async fn test_async_operation_sends_correct_uds_frames() {
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();
    let auth = auth_header(&runtime.config, None).await.unwrap();
    let ecu_endpoint = sovd::ECU_FLXC1000_ENDPOINT;

    let lock_id = acquire_ecu_lock(runtime, &auth).await;

    ecusim::start_recording(&runtime.ecu_sim, "flxc1000")
        .await
        .expect("failed to start recording");

    // Start - triggers CalibrateSensors Start (31 01 10 02)
    let post_response = send_cda_request(
        &runtime.config,
        &format!("{ecu_endpoint}/operations/calibratesensors/executions"),
        StatusCode::ACCEPTED,
        Method::POST,
        Some("{}"),
        Some(&auth),
        None,
    )
    .await
    .unwrap();
    let post_body: AsyncPostBody = response_to_t(&post_response).unwrap();
    let execution_id = post_body.id.clone();

    // GET by id - triggers CalibrateSensors RequestResults (31 03 10 02)
    send_cda_request(
        &runtime.config,
        &format!("{ecu_endpoint}/operations/calibratesensors/executions/{execution_id}"),
        StatusCode::OK,
        Method::GET,
        None,
        Some(&auth),
        None,
    )
    .await
    .unwrap();

    let query_params = QueryParams(HashMap::from_iter([(
        "x-sovd2uds-force".to_string(),
        "true".to_string(),
    )]));
    // DELETE - triggers CalibrateSensors Stop (31 02 10 02)
    send_cda_request(
        &runtime.config,
        &format!("{ecu_endpoint}/operations/calibratesensors/executions/{execution_id}"),
        StatusCode::OK,
        Method::DELETE,
        None,
        Some(&auth),
        Some(&query_params),
    )
    .await
    .unwrap();

    let recordings = ecusim::stop_and_clear_recording(&runtime.ecu_sim, "flxc1000")
        .await
        .expect("failed to stop recording");

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

    release_ecu_lock(runtime, &auth, &lock_id).await;
}

async fn acquire_ecu_lock(
    runtime: &crate::util::runtime::TestRuntime,
    auth: &http::HeaderMap,
) -> String {
    use std::time::Duration;

    use crate::sovd::locks::{self, create_lock, lock_operation};

    #[cfg_attr(nightly, allow(unknown_lints, clippy::duration_suboptimal_units))]
    let expiration_timeout = Duration::from_secs(60);
    let ecu_lock = create_lock(
        expiration_timeout,
        locks::ECU_ENDPOINT,
        StatusCode::CREATED,
        &runtime.config,
        auth,
    )
    .await;
    let lock_id = extract_field_from_json::<String>(
        &response_to_json(&ecu_lock).expect("failed to parse ecu_lock response as JSON"),
        "id",
    )
    .expect("missing 'id' field in ecu_lock response");

    lock_operation(
        locks::ECU_ENDPOINT,
        Some(&lock_id),
        &runtime.config,
        auth,
        StatusCode::OK,
        Method::GET,
    )
    .await;

    lock_id
}

async fn release_ecu_lock(
    runtime: &crate::util::runtime::TestRuntime,
    auth: &http::HeaderMap,
    lock_id: &str,
) {
    use crate::sovd::locks::{self, lock_operation};

    lock_operation(
        locks::ECU_ENDPOINT,
        Some(lock_id),
        &runtime.config,
        auth,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;
}

const FG_ENDPOINT: &str = "functions/functionalgroups/fgl_uds_ethernet_doip_dobt";

async fn acquire_fg_lock(
    runtime: &crate::util::runtime::TestRuntime,
    auth: &http::HeaderMap,
) -> String {
    use std::time::Duration;

    use crate::sovd::locks::{self, create_lock, lock_operation};

    #[cfg_attr(nightly, allow(unknown_lints, clippy::duration_suboptimal_units))]
    let expiration_timeout = Duration::from_secs(60);
    let fg_lock = create_lock(
        expiration_timeout,
        locks::FUNCTIONAL_GROUP_ENDPOINT,
        StatusCode::CREATED,
        &runtime.config,
        auth,
    )
    .await;
    let lock_id = extract_field_from_json::<String>(
        &response_to_json(&fg_lock).expect("failed to parse fg_lock response as JSON"),
        "id",
    )
    .expect("missing 'id' field in fg_lock response");

    lock_operation(
        locks::FUNCTIONAL_GROUP_ENDPOINT,
        Some(&lock_id),
        &runtime.config,
        auth,
        StatusCode::OK,
        Method::GET,
    )
    .await;

    lock_id
}

async fn release_fg_lock(
    runtime: &crate::util::runtime::TestRuntime,
    auth: &http::HeaderMap,
    lock_id: &str,
) {
    use crate::sovd::locks::{self, lock_operation};

    lock_operation(
        locks::FUNCTIONAL_GROUP_ENDPOINT,
        Some(lock_id),
        &runtime.config,
        auth,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;
}

/// Verify that listing operations on a functional group includes
/// `engage_safety_squints` and that it is marked as asynchronous (it has Stop).
#[tokio::test]
async fn test_functional_operation_list() {
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();
    let auth = auth_header(&runtime.config, None).await.unwrap();

    let response = send_cda_request(
        &runtime.config,
        &format!("{FG_ENDPOINT}/operations"),
        StatusCode::OK,
        Method::GET,
        None,
        Some(&auth),
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
/// is rejected with 403 Forbidden.
#[tokio::test]
async fn test_functional_operation_post_no_lock() {
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();
    let auth = auth_header(&runtime.config, None).await.unwrap();

    send_cda_request(
        &runtime.config,
        &format!("{FG_ENDPOINT}/operations/engage_safety_squints/executions"),
        StatusCode::FORBIDDEN,
        Method::POST,
        Some(r#"{"parameters":{"SquintSlitWidth":2.5}}"#),
        Some(&auth),
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
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();
    let auth = auth_header(&runtime.config, None).await.unwrap();

    let lock_id = acquire_fg_lock(runtime, &auth).await;

    // 1. POST (Start) -> 202 Accepted
    let post_response = send_cda_request(
        &runtime.config,
        &format!("{FG_ENDPOINT}/operations/engage_safety_squints/executions"),
        StatusCode::ACCEPTED,
        Method::POST,
        Some(r#"{"parameters":{"SquintSlitWidth":2.5}}"#),
        Some(&auth),
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
    let get_response = send_cda_request(
        &runtime.config,
        &format!("{FG_ENDPOINT}/operations/engage_safety_squints/executions/{execution_id}"),
        StatusCode::OK,
        Method::GET,
        None,
        Some(&auth),
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
    send_cda_request(
        &runtime.config,
        &format!("{FG_ENDPOINT}/operations/engage_safety_squints/executions/{execution_id}"),
        StatusCode::NO_CONTENT,
        Method::DELETE,
        None,
        Some(&auth),
        None,
    )
    .await
    .unwrap();

    release_fg_lock(runtime, &auth, &lock_id).await;
}
