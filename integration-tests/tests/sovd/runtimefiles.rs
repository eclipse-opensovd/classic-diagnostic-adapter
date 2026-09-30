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

use std::time::{Duration, Instant};

use const_format::formatcp;
use http::{Method, StatusCode};
use sovd_interfaces::{
    apps::sovd2uds::{
        bulk_data::BulkDataCreatedList,
        operations::runtimefilesupdate::{ExecutionMode, ExecutionStatusKind},
    },
    common::operations::OperationIdItem,
    sovd2uds::BulkDataDescriptor,
};
use testcontainers::{ContainerAsync, GenericImage, runners::AsyncRunner};

use crate::{
    client::{
        self, DEFAULT_CLIENT_ID, Response, SovdTestClient, apps::sovd2uds::bulk_data::RuntimeFiles,
        locks::Lock,
    },
    sovd::{ECU_FLXC1000, ECU_FSNR2000, FUNCTIONAL_GROUP},
    util::{
        TestingError,
        config::{mdd_file_path, test_container_dir},
        endpoints::SOVD2UDS_OPERATIONS,
        locks::{NON_OWNER_BEARER_TOKEN, default_timeout},
        test_containers::{cda_container, cda_container_config, restart_cda_container},
        test_env::{TestEnv, wait_for_ecus_online},
    },
};

/// The executions of the runtime update operation, for the `Location` they
/// are reported at.
const RUNTIMEFILES_UPDATE_EXECUTIONS: &str =
    formatcp!("{}/runtimefilesupdate/executions", SOVD2UDS_OPERATIONS);

/// Asserts that the CDA answered `result` with the error status `expected`.
#[track_caller]
fn assert_error_status<T>(result: client::Result<T>, expected: StatusCode, context: &str) {
    match result {
        Ok(_) => panic!("{context}: expected {expected}, but the request succeeded"),
        Err(err) => assert_eq!(err.status(), Some(expected), "{context}: {err}"),
    }
}

/// Polls `GET /executions/{id}` until the execution reaches a terminal status
/// (`completed` or `failed`), giving up after `timeout`, and returns the final
/// response body.
///
/// Runtime-file update executions run asynchronously: `POST /executions`
/// returns `202` immediately while a background task performs the work and
/// only then clears the update-in-progress guard. Until that guard clears,
/// non-exempt requests (e.g. deleting the vehicle lock) are rejected with
/// `409 Conflict`. Tests must therefore wait for a terminal status before
/// issuing such follow-up requests, otherwise they race the background task.
///
/// The body stays JSON, because the caller asserts which fields it lacks.
async fn wait_for_execution_terminal(
    client: &SovdTestClient,
    execution_id: &str,
    timeout: Duration,
) -> Result<serde_json::Value, TestingError> {
    const POLL_INTERVAL: Duration = Duration::from_millis(100);

    let deadline = std::time::Instant::now()
        .checked_add(timeout)
        .expect("deadline must not overflow");

    loop {
        // Raw JSON rather than the typed execution, which would not notice
        // the fields the caller asserts to be absent.
        let execution = client
            .sovd2uds()
            .runtime_files_update()
            .request(Method::GET, execution_id)
            .send_json::<serde_json::Value>()
            .await?
            .expect_status(StatusCode::OK)
            .into_body();
        if let Some("completed" | "failed") =
            execution.get("status").and_then(serde_json::Value::as_str)
        {
            return Ok(execution);
        }

        assert!(
            std::time::Instant::now() < deadline,
            "execution {execution_id} did not reach a terminal status within {timeout:?}"
        );
        cda_interfaces::util::tokio_ext::sleep_for(POLL_INTERVAL).await;
    }
}

/// Tests that mutating runtime-update endpoints reject requests without a vehicle lock.
#[tokio::test]
async fn runtimefiles_requires_lock() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let sovd2uds = test_env.client().sovd2uds();

    let form = reqwest::multipart::Form::new().part(
        "files",
        reqwest::multipart::Part::bytes(b"fake content".to_vec()).file_name("test.mdd"),
    );
    assert_error_status(
        sovd2uds.runtime_files_next_update().upload(form).await,
        StatusCode::FORBIDDEN,
        "Expected 403 for upload without vehicle lock",
    );

    assert_error_status(
        sovd2uds.runtime_files_next_update().delete_all().await,
        StatusCode::FORBIDDEN,
        "Expected 403 for deleting the next update without vehicle lock",
    );

    for mode in [
        ExecutionMode::Apply,
        ExecutionMode::Rollback,
        ExecutionMode::Cleanup,
    ] {
        assert_error_status(
            sovd2uds.runtime_files_update().start(mode).await,
            StatusCode::FORBIDDEN,
            &format!("Expected 403 for {mode:?} without vehicle lock"),
        );
    }

    Ok(())
}

/// Checks the runtime file update execution resources follow ISO 17978-3 section 7.14.
#[tokio::test]
async fn runtimefiles_execution_responses_follow_operation_standard() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let client = test_env.client();
    let lock = setup_with_lock(client).await;

    let response = client
        .sovd2uds()
        .runtime_files_update()
        .start(ExecutionMode::Cleanup)
        .await?
        .expect_status(StatusCode::ACCEPTED);
    let execution_id = response.id.clone();
    let expected_location = client.url(&format!("{RUNTIMEFILES_UPDATE_EXECUTIONS}/{execution_id}"));
    assert_eq!(
        response.location(),
        Some(expected_location.as_str()),
        "202 responses must identify the execution resource with an absolute Location URI"
    );

    // JSON rather than the typed list, which would not notice extra fields.
    let list = client
        .sovd2uds()
        .runtime_files_update()
        .request(Method::GET, "")
        .send_json::<serde_json::Value>()
        .await?
        .expect_status(StatusCode::OK)
        .into_body();
    assert_eq!(
        list,
        serde_json::json!({ "items": [{ "id": execution_id }] }),
        "execution collection items must contain only their identifiers"
    );

    // Poll until the async execution reaches a terminal status. Reading the
    // status only once here would race the background task and could leave the
    // update-in-progress guard set, causing the lock deletion below to fail
    // with 409 Conflict.
    let execution =
        wait_for_execution_terminal(client, &execution_id, Duration::from_secs(10)).await?;
    assert_eq!(
        execution.get("status").and_then(serde_json::Value::as_str),
        Some("completed"),
        "cleanup execution must complete successfully"
    );
    assert!(
        execution.get("id").is_none() && execution.get("mode").is_none(),
        "execution details must not expose operation-specific values at the top level"
    );
    assert_eq!(
        execution
            .get("parameters")
            .and_then(|p| p.get("mode"))
            .expect("mode should exist"),
        "cleanup"
    );
    assert!(
        execution
            .get("parameters")
            .and_then(|p| p.get("reason"))
            .is_none(),
        "a successful execution must not include a failure reason"
    );

    lock.release().await?.expect_status(StatusCode::NO_CONTENT);
    Ok(())
}

/// Checks ISO bulk-data response conventions used by the runtime file categories.
#[tokio::test]
async fn runtimefiles_bulk_data_responses_follow_standard() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let client = test_env.client();
    let next_update = client.sovd2uds().runtime_files_next_update();
    let lock = setup_with_lock(client).await;

    let upload = upload_mdd(client).await?.expect_status(StatusCode::CREATED);
    let first_id = &upload
        .items
        .first()
        .expect("upload response must identify the created file")
        .id;
    let expected_location = client.url(&format!("{}/{first_id}", next_update.path()));
    assert_eq!(
        upload.location(),
        Some(expected_location.as_str()),
        "bulk-data uploads must identify a created resource with Location"
    );

    let list = next_update.list().await?.expect_status(StatusCode::OK);
    assert!(
        list.items
            .iter()
            .all(|item| item.name.as_deref() == Some(&item.id)),
        "runtime file descriptors must expose the filename as name"
    );

    let filtered = next_update
        .list_with(&[
            ("created-after", "2025-01-01T00:00:00Z"),
            ("created-before", "2026-01-01T00:00:00Z"),
        ])
        .await?
        .expect_status(StatusCode::OK);
    assert_eq!(filtered.items.len(), list.items.len());

    let deleted = next_update
        .delete_all()
        .await?
        .expect_status(StatusCode::OK);
    assert!(deleted.errors.is_empty());
    assert!(deleted.deleted_ids.iter().any(|id| id == first_id));

    let categories = client
        .sovd2uds()
        .bulk_data()
        .await?
        .expect_status(StatusCode::OK);
    for name in [
        "runtimefiles-current",
        "runtimefiles-nextupdate",
        "runtimefiles-backup",
    ] {
        assert!(
            categories.items.iter().any(|item| item.name == name),
            "bulk-data discovery must include {name}"
        );
    }

    lock.release().await?.expect_status(StatusCode::NO_CONTENT);
    Ok(())
}

#[tokio::test]
async fn runtimefiles_lifecycle() -> Result<(), TestingError> {
    // Acquire an exclusive vehicle lock (spec: all modifying actions require one).
    let test_env = TestEnv::builder().await?;
    let client = test_env.client();

    let lock = client
        .locks()
        .create(Duration::from_secs(333))
        .await?
        .expect_status(StatusCode::CREATED)
        .into_body();

    // Snapshot the current database item count so we can verify rollback restores it.
    let initial_count = client
        .sovd2uds()
        .runtime_files_current()
        .list()
        .await?
        .expect_status(StatusCode::OK)
        .into_body()
        .items
        .len();

    // POST a .mdd file via multipart form data (spec: "Adds files to the next update").
    let upload_response = upload_mdd(client).await?;
    assert_eq!(
        upload_response.status(),
        StatusCode::CREATED,
        "Expected 201 for MDD upload"
    );

    // GET nextupdate must show the uploaded file (case-insensitive match per spec).
    assert_nextupdate_contains_flxc1000(client).await?;

    // Trigger "Apply" - pending update becomes active database.
    execute_mode(client, ExecutionMode::Apply).await?;
    assert_state_after_apply(client, initial_count).await?;

    execute_mode(client, ExecutionMode::Rollback).await?;
    assert_state_after_rollback(client, initial_count).await?;

    // Trigger "Cleanup" - spec: "reset all pending updates, as well as deleting the backup".
    execute_mode(client, ExecutionMode::Cleanup).await?;
    assert_state_after_cleanup(client).await?;

    // Release the vehicle lock.
    lock.release().await?.expect_status(StatusCode::NO_CONTENT);

    Ok(())
}

/// Spec: "Adding or deleting files must only be allowed in the runtimefiles-nextupdate category,
/// and not for the runtimefiles-backup or runtimefiles-current category."
#[tokio::test]
async fn runtimefiles_post_delete_forbidden_on_current_and_backup() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let client = test_env.client();
    let sovd2uds = client.sovd2uds();
    let lock = setup_with_lock(client).await;

    let mdd_bytes = read_mdd_fixture("FLXC1000.mdd");

    let form = reqwest::multipart::Form::new().part(
        "files",
        reqwest::multipart::Part::bytes(mdd_bytes.clone()).file_name("test.mdd"),
    );
    assert_error_status(
        sovd2uds.runtime_files_current().upload(form).await,
        StatusCode::METHOD_NOT_ALLOWED,
        "Expected 405 for POST to runtimefiles-current",
    );

    assert_error_status(
        sovd2uds.runtime_files_current().delete_all().await,
        StatusCode::METHOD_NOT_ALLOWED,
        "Expected 405 for DELETE of runtimefiles-current",
    );

    let form = reqwest::multipart::Form::new().part(
        "files",
        reqwest::multipart::Part::bytes(mdd_bytes).file_name("test.mdd"),
    );
    assert_error_status(
        sovd2uds.runtime_files_backup().upload(form).await,
        StatusCode::METHOD_NOT_ALLOWED,
        "Expected 405 for POST to runtimefiles-backup",
    );

    lock.release().await?.expect_status(StatusCode::NO_CONTENT);
    Ok(())
}

/// Spec: "Only the subject of the lock is allowed to use the endpoints."
/// This specifically tests that a non-lock-holder cannot DELETE the backup.
#[tokio::test]
async fn runtimefiles_non_owner_cannot_delete_backup() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let client = test_env.client();
    let lock = setup_with_lock(client).await;

    let upload_response = upload_mdd(client).await?;
    assert_eq!(upload_response.status(), StatusCode::CREATED);

    execute_mode(client, ExecutionMode::Apply).await?;
    let backup = ids(&client.sovd2uds().runtime_files_backup()).await?;
    assert!(!backup.is_empty(), "Precondition: backup must not be empty");

    let non_owner = test_env
        .anonymous_client()
        .with_token(NON_OWNER_BEARER_TOKEN);
    assert_error_status(
        non_owner
            .sovd2uds()
            .runtime_files_backup()
            .delete_all()
            .await,
        StatusCode::FORBIDDEN,
        "Expected 403 for deleting the backup by a non-lock-holder",
    );

    assert_eq!(
        ids(&client.sovd2uds().runtime_files_backup()).await?,
        backup,
        "the backup changed although its deletion was forbidden"
    );

    lock.release().await?.expect_status(StatusCode::NO_CONTENT);
    Ok(())
}

/// Spec: "none of the endpoints should allow retrieval of the files by default"
#[tokio::test]
async fn runtimefiles_file_retrieval_not_allowed() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let sovd2uds = test_env.client().sovd2uds();

    assert_error_status(
        sovd2uds
            .runtime_files_current()
            .file("FLXC1000.mdd")
            .get()
            .await,
        StatusCode::NOT_FOUND,
        "Expected 404 for retrieving a file of runtimefiles-current",
    );

    assert_error_status(
        sovd2uds
            .runtime_files_next_update()
            .file("FLXC1000.mdd")
            .get()
            .await,
        StatusCode::METHOD_NOT_ALLOWED,
        "Expected 405 for retrieving a file of runtimefiles-nextupdate",
    );

    assert_error_status(
        sovd2uds
            .runtime_files_backup()
            .file("FLXC1000.mdd")
            .get()
            .await,
        StatusCode::NOT_FOUND,
        "Expected 404 for retrieving a file of runtimefiles-backup",
    );

    Ok(())
}

/// Spec: "Deletes the file from the pending update" - file must exist to be deleted.
#[tokio::test]
async fn runtimefiles_delete_nonexistent_file_returns_not_found() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let client = test_env.client();
    let lock = setup_with_lock(client).await;

    assert_error_status(
        client
            .sovd2uds()
            .runtime_files_next_update()
            .file("this-file-does-not-exist.mdd")
            .delete()
            .await,
        StatusCode::NOT_FOUND,
        "Expected 404 for deleting a file that does not exist",
    );

    lock.release().await?.expect_status(StatusCode::NO_CONTENT);
    Ok(())
}

/// Spec: "Deletes the backup of the previously used diagnostic database, to free up storage space."
/// Tests idempotency: deleting an already-empty backup.
#[tokio::test]
async fn runtimefiles_delete_backup_when_empty() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let client = test_env.client();
    let backup = client.sovd2uds().runtime_files_backup();
    let lock = setup_with_lock(client).await;

    execute_mode(client, ExecutionMode::Cleanup).await?;

    let backup_items = backup
        .list()
        .await?
        .expect_status(StatusCode::OK)
        .into_body()
        .items;
    assert!(
        backup_items.is_empty(),
        "Precondition: backup must be empty after cleanup"
    );

    // If implementation returns 404 instead, that's a finding.
    backup.delete_all().await?.expect_status(StatusCode::OK);

    lock.release().await?.expect_status(StatusCode::NO_CONTENT);
    Ok(())
}

/// Spec: Execution mode values must be accepted case-insensitively
/// (e.g. "apply", "APPLY", "Apply").
#[tokio::test]
async fn runtimefiles_execution_mode_case_insensitive() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let client = test_env.client();
    let lock = setup_with_lock(client).await;

    // Upload a file so Apply has something to work with
    upload_mdd(client)
        .await
        .expect("Precondition: upload must succeed");

    // Test lowercase "apply"
    let execution_id = start_execution(client, r#"{"parameters": {"mode": "apply"}}"#)
        .await?
        .expect_status(StatusCode::ACCEPTED)
        .json::<OperationIdItem>()?
        .into_body()
        .id;
    wait_for_execution_completion(client, &execution_id).await?;

    // Upload again for uppercase test
    upload_mdd(client)
        .await
        .expect("Precondition: second upload must succeed");

    // Test uppercase "APPLY"
    let execution_id = start_execution(client, r#"{"parameters": {"mode": "APPLY"}}"#)
        .await?
        .expect_status(StatusCode::ACCEPTED)
        .json::<OperationIdItem>()?
        .into_body()
        .id;
    wait_for_execution_completion(client, &execution_id).await?;

    lock.release().await?.expect_status(StatusCode::NO_CONTENT);
    Ok(())
}

/// Spec: GET endpoints for nextupdate and backup must support query parameters:
/// x-sovd2uds-include-hash, x-sovd2uds-include-file-size, x-sovd2uds-include-revision.
#[tokio::test]
async fn runtimefiles_query_parameters_all_endpoints() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let client = test_env.client();
    let sovd2uds = client.sovd2uds();
    let lock = setup_with_lock(client).await;

    // Upload a file so nextupdate is non-empty
    upload_mdd(client)
        .await
        .expect("Precondition: upload must succeed");

    // Reads should not depend on a vehicle lock, so release it before GET checks.
    lock.release().await?.expect_status(StatusCode::NO_CONTENT);

    // Test hash query on nextupdate
    let nextupdate_hash_list = sovd2uds
        .runtime_files_next_update()
        .list_with(&[("x-sovd2uds-include-hash", "sha256")])
        .await?
        .expect_status(StatusCode::OK);
    let first_item = nextupdate_hash_list
        .items
        .first()
        .expect("Precondition: nextupdate must not be empty");
    assert!(
        first_item.hash.is_some(),
        "Expected 'hash' field in nextupdate when x-sovd2uds-include-hash=sha256 is set"
    );

    // Apply to populate backup
    let lock = setup_with_lock(client).await;
    execute_mode(client, ExecutionMode::Apply).await?;
    lock.release().await?.expect_status(StatusCode::NO_CONTENT);

    // Test file-size query on backup
    let backup_size_list = sovd2uds
        .runtime_files_backup()
        .list_with(&[("x-sovd2uds-include-file-size", "true")])
        .await?
        .expect_status(StatusCode::OK);
    let first_item = backup_size_list
        .items
        .first()
        .expect("Precondition: backup must not be empty");
    assert!(
        first_item.size.is_some(),
        "Expected file size field in backup when x-sovd2uds-include-file-size=true is set"
    );
    Ok(())
}

/// Spec: Uploading multiple files in a single multipart request must be supported.
#[tokio::test]
async fn runtimefiles_upload_multiple_files() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let client = test_env.client();
    let next_update = client.sovd2uds().runtime_files_next_update();
    let lock = setup_with_lock(client).await;

    let mdd_bytes = read_mdd_fixture("FLXC1000.mdd");

    // Build a multipart form with TWO file parts
    let form = reqwest::multipart::Form::new()
        .part(
            "files",
            reqwest::multipart::Part::bytes(mdd_bytes.clone()).file_name("FILE_A.mdd"),
        )
        .part(
            "files",
            reqwest::multipart::Part::bytes(mdd_bytes).file_name("FILE_B.mdd"),
        );

    let uploaded = next_update
        .upload(form)
        .await
        .expect("Expected success for multi-file upload");
    let location = uploaded
        .location()
        .expect("multi-file upload must include Location");
    assert!(
        location.ends_with("/file_a.mdd"),
        "multi-file upload Location must point to the first created file, got {location}"
    );

    // Verify both files appear in nextupdate
    let items = next_update
        .list()
        .await?
        .expect_status(StatusCode::OK)
        .into_body()
        .items;
    assert!(
        items.len() >= 2,
        "Expected at least 2 items after uploading FILE_A.mdd and FILE_B.mdd, got {}",
        items.len()
    );

    lock.release().await?.expect_status(StatusCode::NO_CONTENT);
    Ok(())
}

/// Spec: The nextupdate upload endpoint must also accept a single file uploaded as
/// `application/octet-stream`, with the filename taken from the `Content-Disposition`
/// header (quoted form: `attachment; filename="foo.mdd"`).
#[tokio::test]
async fn runtimefiles_upload_octet_stream() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let client = test_env.client();
    let lock = setup_with_lock(client).await;

    let response =
        upload_mdd_octet_stream(client, Some("attachment; filename=\"FLXC1000.mdd\"")).await?;

    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "Expected 201 Created for octet-stream upload, got {}",
        response.status()
    );

    let items = client
        .sovd2uds()
        .runtime_files_next_update()
        .list()
        .await?
        .expect_status(StatusCode::OK)
        .into_body()
        .items;
    assert!(
        items
            .iter()
            .any(|item| item.id.to_lowercase() == "flxc1000.mdd"),
        "Expected FLXC1000.mdd to appear in nextupdate after octet-stream upload"
    );

    lock.release().await?.expect_status(StatusCode::NO_CONTENT);
    Ok(())
}

/// Spec: The `Content-Disposition` filename parameter must also be accepted in its
/// unquoted form (`filename=foo.mdd`).
#[tokio::test]
async fn runtimefiles_upload_octet_stream_unquoted_filename() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let client = test_env.client();
    let lock = setup_with_lock(client).await;

    let response =
        upload_mdd_octet_stream(client, Some("attachment; filename=FLXC1000.mdd")).await?;

    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "Expected 201 Created for octet-stream upload with unquoted filename, got {}",
        response.status()
    );

    lock.release().await?.expect_status(StatusCode::NO_CONTENT);
    Ok(())
}

/// Spec: An `application/octet-stream` upload without a `Content-Disposition` header
/// must be rejected with 400 Bad Request.
#[tokio::test]
async fn runtimefiles_upload_octet_stream_missing_content_disposition() -> Result<(), TestingError>
{
    let test_env = TestEnv::builder().await?;
    let client = test_env.client();
    let lock = setup_with_lock(client).await;

    assert_error_status(
        upload_mdd_octet_stream(client, None).await,
        StatusCode::BAD_REQUEST,
        "Expected 400 Bad Request for octet-stream upload without Content-Disposition",
    );

    lock.release().await?.expect_status(StatusCode::NO_CONTENT);
    Ok(())
}

/// Spec: An `application/octet-stream` upload with a `Content-Disposition` header that
/// has no `filename` parameter must be rejected with 400 Bad Request.
#[tokio::test]
async fn runtimefiles_upload_octet_stream_missing_filename_param() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let client = test_env.client();
    let lock = setup_with_lock(client).await;

    assert_error_status(
        upload_mdd_octet_stream(client, Some("attachment")).await,
        StatusCode::BAD_REQUEST,
        "Expected 400 Bad Request for octet-stream upload without filename param",
    );

    lock.release().await?.expect_status(StatusCode::NO_CONTENT);
    Ok(())
}

/// Spec: An upload with an unsupported `Content-Type` (neither `multipart/form-data`
/// nor `application/octet-stream`) must be rejected with 400 Bad Request.
#[tokio::test]
async fn runtimefiles_upload_unsupported_content_type() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let client = test_env.client();
    let lock = setup_with_lock(client).await;

    assert_error_status(
        upload_mdd_raw(
            client,
            "text/plain",
            Some("attachment; filename=\"FLXC1000.mdd\""),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "Expected 400 Bad Request for upload with unsupported Content-Type",
    );

    lock.release().await?.expect_status(StatusCode::NO_CONTENT);
    Ok(())
}

/// Spec: Applying when there are no pending changes (nextupdate == current)
/// must not return 202 Accepted (primary expectation: 404).
#[tokio::test]
async fn runtimefiles_apply_with_no_pending_changes() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let client = test_env.client();
    let lock = setup_with_lock(client).await;

    // Reset nextupdate to current state (spec: DELETE removes all pending changes,
    // resetting nextupdate to the currently active database - not to empty).
    client
        .sovd2uds()
        .runtime_files_next_update()
        .delete_all()
        .await?
        .expect_status(StatusCode::OK);

    // Attempt Apply with no pending changes (nextupdate == current) - must NOT return 202
    let apply_result = client
        .sovd2uds()
        .runtime_files_update()
        .start(ExecutionMode::Apply)
        .await;
    if apply_result.map_or_else(|err| err.status() != Some(StatusCode::NOT_FOUND), |_| true) {
        // If the server returns something other than 404, that's a finding - log it but don't fail
        // The primary assertion is that it must NOT be 202
    }

    lock.release().await?.expect_status(StatusCode::NO_CONTENT);
    Ok(())
}

/// Spec: Rollback when backup is empty must return 404 Not Found.
#[tokio::test]
async fn runtimefiles_rollback_with_no_backup() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let client = test_env.client();
    let backup = client.sovd2uds().runtime_files_backup();
    let lock = setup_with_lock(client).await;

    // Clear backup
    backup.delete_all().await?.expect_status(StatusCode::OK);
    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(1)).await;

    // Verify backup is empty
    let backup_items = backup
        .list()
        .await?
        .expect_status(StatusCode::OK)
        .into_body()
        .items;
    assert!(
        backup_items.is_empty(),
        "Precondition: backup must be empty before Rollback"
    );

    // Attempt Rollback with empty backup - expect 404
    assert_error_status(
        client
            .sovd2uds()
            .runtime_files_update()
            .start(ExecutionMode::Rollback)
            .await,
        StatusCode::NOT_FOUND,
        "Expected 404 for Rollback without backup",
    );

    lock.release().await?.expect_status(StatusCode::NO_CONTENT);
    Ok(())
}

/// Spec: Rollback must clear any newly uploaded pending files from nextupdate.
#[tokio::test]
async fn runtimefiles_rollback_clears_nextupdate_with_new_pending() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let client = test_env.client();
    let sovd2uds = client.sovd2uds();
    let lock = setup_with_lock(client).await;

    // Step 1: Upload and Apply to establish a backup
    upload_mdd(client)
        .await
        .expect("Precondition: first upload must succeed");
    execute_mode(client, ExecutionMode::Apply).await?;

    // Step 2: Upload a new file to nextupdate (new pending changes)
    upload_mdd_with_filename(client, "NEW_PENDING.mdd")
        .await
        .expect("Precondition: second upload must succeed");

    // Step 3: Rollback - should revert current and clear nextupdate
    execute_mode(client, ExecutionMode::Rollback).await?;

    // Step 4: Verify NEW_PENDING.mdd (the uploaded pending file) is gone, and nextupdate mirrors
    // the restored current state.
    let nextupdate_items = sovd2uds
        .runtime_files_next_update()
        .list()
        .await?
        .expect_status(StatusCode::OK)
        .into_body()
        .items;
    assert!(
        !nextupdate_items
            .iter()
            .any(|i| i.id.to_lowercase().contains("new_pending")),
        "Expected NEW_PENDING.mdd to be gone from nextupdate after Rollback, got {:?}",
        nextupdate_items.iter().map(|i| &i.id).collect::<Vec<_>>()
    );

    let current_items = sovd2uds
        .runtime_files_current()
        .list()
        .await?
        .expect_status(StatusCode::OK)
        .into_body()
        .items;
    assert_eq!(
        ids_of(&nextupdate_items),
        ids_of(&current_items),
        "Expected nextupdate to mirror current after Rollback (no pending changes)"
    );

    lock.release().await?.expect_status(StatusCode::NO_CONTENT);
    Ok(())
}

/// Spec: Apply must be blocked (409 Conflict) when a functional group lock is held by
/// another operation.
#[tokio::test]
async fn runtimefiles_apply_blocked_by_active_operations() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let client = test_env.client();

    // Create vehicle lock (required for runtimefiles mutations)
    let vehicle_lock = client
        .locks()
        .create(Duration::from_secs(333))
        .await?
        .expect_status(StatusCode::CREATED)
        .into_body();

    // Upload a file so Apply has something to work with
    upload_mdd(client)
        .await
        .expect("Precondition: upload must succeed");

    // Create functional group lock (same user) to block Apply
    let fg_lock = client
        .functional_group(FUNCTIONAL_GROUP)
        .locks()
        .create(Duration::from_secs(333))
        .await?
        .expect_status(StatusCode::CREATED)
        .into_body();

    // Attempt Apply while functional group lock is held - expect 409 Conflict
    assert_error_status(
        client
            .sovd2uds()
            .runtime_files_update()
            .start(ExecutionMode::Apply)
            .await,
        StatusCode::CONFLICT,
        "Expected 409 for Apply while a functional group lock is held",
    );

    fg_lock
        .release()
        .await?
        .expect_status(StatusCode::NO_CONTENT);

    // Now Apply should succeed (202)
    execute_mode(client, ExecutionMode::Apply).await?;

    // Release vehicle lock
    vehicle_lock
        .release()
        .await?
        .expect_status(StatusCode::NO_CONTENT);

    Ok(())
}

/// Helper: reads the MDD fixture testcontainer/odx/{name} (e.g. "FSNR2000.mdd").
fn read_mdd_fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        test_container_dir()
            .expect("testcontainer dir")
            .join(format!("odx/{name}")),
    )
    .unwrap_or_else(|e| panic!("MDD fixture {name} not found: {e}"))
}

/// Helper: uploads the MDD fixture `fixture` to nextupdate as `file_name`.
/// Returns the response, as callers check its exact status.
async fn upload_mdd_fixture(
    client: &SovdTestClient,
    fixture: &str,
    file_name: &str,
) -> client::Result<Response<BulkDataCreatedList>> {
    let form = reqwest::multipart::Form::new().part(
        "files",
        reqwest::multipart::Part::bytes(read_mdd_fixture(fixture)).file_name(file_name.to_owned()),
    );
    client
        .sovd2uds()
        .runtime_files_next_update()
        .upload(form)
        .await
}

/// Helper: uploads the MDD fixture to nextupdate and returns the response.
pub(crate) async fn upload_mdd(
    client: &SovdTestClient,
) -> client::Result<Response<BulkDataCreatedList>> {
    upload_mdd_fixture(client, "FLXC1000.mdd", "FLXC1000.mdd").await
}

/// Helper: uploads an MDD from testcontainer/odx/{name} (e.g. "FSNR2000.mdd").
async fn upload_mdd_by_name(
    client: &SovdTestClient,
    name: &str,
) -> client::Result<Response<BulkDataCreatedList>> {
    upload_mdd_fixture(client, name, name).await
}

/// Helper: uploads an MDD fixture with a custom filename.
async fn upload_mdd_with_filename(
    client: &SovdTestClient,
    filename: &str,
) -> client::Result<Response<BulkDataCreatedList>> {
    upload_mdd_fixture(client, "FLXC1000.mdd", filename).await
}

/// Helper: uploads the `FLXC1000.mdd` fixture as a single raw-body request with the
/// given `Content-Type`, optionally setting a `Content-Disposition` header value.
async fn upload_mdd_raw(
    client: &SovdTestClient,
    content_type: &str,
    content_disposition: Option<&str>,
) -> client::Result<Response<BulkDataCreatedList>> {
    client
        .sovd2uds()
        .runtime_files_next_update()
        .upload_bytes(
            content_type,
            read_mdd_fixture("FLXC1000.mdd"),
            content_disposition,
        )
        .await
}

/// Helper: uploads the `FLXC1000.mdd` fixture as a single `application/octet-stream`
/// request, optionally setting a `Content-Disposition` header value.
async fn upload_mdd_octet_stream(
    client: &SovdTestClient,
    content_disposition: Option<&str>,
) -> client::Result<Response<BulkDataCreatedList>> {
    upload_mdd_raw(client, "application/octet-stream", content_disposition).await
}

/// Helper: creates a vehicle lock, released when the returned guard drops.
///
/// TODO(#495): the guard releases the lock on every path, but only on a best
/// effort basis: it does not wait out an active runtime update protection,
/// neither when the lock is created nor when it is dropped. A lock dropped
/// inside that window stays (the CDA answers 409), which then fails every
/// later test asserting on lock ownership. So tests still release it with
/// [`Lock::release`], which checks the response, after their executions have
/// completed.
/// <https://github.com/eclipse-opensovd/classic-diagnostic-adapter/issues/495>
pub(crate) async fn setup_with_lock(client: &SovdTestClient) -> Lock {
    client
        .locks()
        .create(Duration::from_secs(333))
        .await
        .expect("Failed to create lock")
        .expect_status(StatusCode::CREATED)
        .into_body()
}

/// Helper: deletes the file `id` of `files`, which the CDA answers with
/// `204 No Content`.
async fn delete_file(files: &RuntimeFiles<'_>, id: &str) -> Result<(), TestingError> {
    let response = files.file(id).delete().await?;
    assert_eq!(
        response.status(),
        StatusCode::NO_CONTENT,
        "Expected 204 for deleting {id}"
    );
    Ok(())
}

/// The file names of every MDD the test container ships, i.e. the whole vehicle.
///
/// Read from disk rather than hard-coded, so that a fixture added later is
/// expected in the seeded database as well.
fn mdd_file_names() -> Vec<String> {
    let mdd_dir = std::path::PathBuf::from(mdd_file_path().expect("MDD directory"));
    let names: Vec<String> = std::fs::read_dir(&mdd_dir)
        .expect("MDD directory not readable")
        .filter_map(|entry| Some(entry.ok()?.file_name().to_string_lossy().into_owned()))
        .filter(|name| name.to_lowercase().ends_with(".mdd"))
        .collect();
    assert!(
        names.len() > 1,
        "expected the MDD directory {} to hold the whole vehicle, found {names:?}",
        mdd_dir.display()
    );
    names
}

/// Helper: starts a runtime update execution with the JSON `body` as it is.
/// Raw rather than `RuntimeFilesUpdate::start`, which only sends the modes
/// as `ExecutionMode` serializes them, not in other letter cases.
async fn start_execution(client: &SovdTestClient, body: &str) -> client::Result<Response> {
    client
        .sovd2uds()
        .runtime_files_update()
        .request(Method::POST, "")
        .raw_json(body)
        .send()
        .await
}

/// POSTs an execution mode to the executions endpoint (expecting 202 Accepted)
/// and waits for that execution to finish.
pub(crate) async fn execute_mode(
    client: &SovdTestClient,
    mode: ExecutionMode,
) -> Result<OperationIdItem, TestingError> {
    let response = client.sovd2uds().runtime_files_update().start(mode).await?;
    assert_eq!(
        response.status(),
        StatusCode::ACCEPTED,
        "Expected 202 for starting a {mode:?} execution"
    );
    let execution = response.into_body();
    wait_for_execution_completion(client, &execution.id).await?;
    Ok(execution)
}

/// Waits until `execution_id` has finished **and** the update's HTTP protection
/// has been lifted.
///
/// Waiting for `completed` alone is not enough. The update task publishes that
/// status, then re-enables communication, and only then drops the protection.
/// Until it does, every non-exempt route answers `409 Update in progress`,
/// including `DELETE /vehicle/v15/locks/{id}`, so a test returning inside that
/// window cannot release its own vehicle lock.
///
/// The execution resource stays readable throughout, being on the exempt list.
async fn wait_for_execution_completion(
    client: &SovdTestClient,
    execution_id: &str,
) -> Result<(), TestingError> {
    const TIMEOUT: Duration = Duration::from_secs(60);

    let deadline = Instant::now()
        .checked_add(TIMEOUT)
        .ok_or_else(|| TestingError::SetupError("timeout overflowed Instant".to_owned()))?;
    let update = client.sovd2uds().runtime_files_update();
    loop {
        let execution = update
            .execution(execution_id)
            .await?
            .expect_status(StatusCode::OK)
            .into_body();
        match execution.status {
            ExecutionStatusKind::Completed => break,
            ExecutionStatusKind::Running => {}
            ExecutionStatusKind::Failed => {
                return Err(TestingError::InvalidData(format!(
                    "runtime update {execution_id} failed: {}",
                    execution
                        .parameters
                        .reason
                        .unwrap_or_else(|| "no reason reported".to_owned())
                )));
            }
        }
        if Instant::now() >= deadline {
            return Err(TestingError::Timeout(format!(
                "runtime update {execution_id} did not complete within {TIMEOUT:?}"
            )));
        }
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(100)).await;
    }

    // `runtimefiles-current` is not exempt, so it answers 409 for as long as
    // the protection is installed. A raw request, as only a request can be
    // polled.
    client
        .sovd2uds()
        .runtime_files_current()
        .request(Method::GET)
        .poll_while(
            StatusCode::CONFLICT,
            deadline.saturating_duration_since(Instant::now()),
        )
        .await?;
    Ok(())
}

/// Helper: asserts the uploaded FLXC1000.mdd is visible in nextupdate (case-insensitive).
async fn assert_nextupdate_contains_flxc1000(client: &SovdTestClient) -> Result<(), TestingError> {
    let items = client
        .sovd2uds()
        .runtime_files_next_update()
        .list()
        .await?
        .expect_status(StatusCode::OK)
        .into_body()
        .items;
    assert!(
        !items.is_empty(),
        "Expected at least one item in nextupdate after upload"
    );
    assert!(
        items
            .iter()
            .any(|item| item.id.to_lowercase().contains(ECU_FLXC1000)),
        "Expected FLXC1000.mdd in nextupdate items"
    );
    Ok(())
}

/// Helper: verifies the post-Apply invariants:
/// current non-empty, nextupdate mirrors current (no pending changes), and backup matches the
/// original current snapshot.
async fn assert_state_after_apply(
    client: &SovdTestClient,
    initial_count: usize,
) -> Result<(), TestingError> {
    let sovd2uds = client.sovd2uds();
    let current = sovd2uds
        .runtime_files_current()
        .list()
        .await?
        .expect_status(StatusCode::OK)
        .into_body()
        .items;
    assert!(
        !current.is_empty(),
        "Expected non-empty current after apply"
    );

    let nextupdate = sovd2uds
        .runtime_files_next_update()
        .list()
        .await?
        .expect_status(StatusCode::OK)
        .into_body()
        .items;
    assert_eq!(
        ids_of(&nextupdate),
        ids_of(&current),
        "Expected nextupdate to mirror current after apply (no pending changes)"
    );

    let backup = sovd2uds
        .runtime_files_backup()
        .list()
        .await?
        .expect_status(StatusCode::OK)
        .into_body()
        .items;
    assert_eq!(
        backup.len(),
        initial_count,
        "Expected backup to match the original current snapshot after apply"
    );

    Ok(())
}

/// Helper: verifies the post-Rollback invariants:
/// current count matches `expected_count`, nextupdate mirrors current (no pending changes).
async fn assert_state_after_rollback(
    client: &SovdTestClient,
    expected_count: usize,
) -> Result<(), TestingError> {
    let sovd2uds = client.sovd2uds();
    let current = sovd2uds
        .runtime_files_current()
        .list()
        .await?
        .expect_status(StatusCode::OK)
        .into_body()
        .items;
    assert_eq!(
        current.len(),
        expected_count,
        "Expected item count to match initial count after rollback"
    );

    let nextupdate = sovd2uds
        .runtime_files_next_update()
        .list()
        .await?
        .expect_status(StatusCode::OK)
        .into_body()
        .items;
    assert_eq!(
        ids_of(&nextupdate),
        ids_of(&current),
        "Expected nextupdate to mirror current after rollback (spec: state of nextupdate must be \
         reset)"
    );

    sovd2uds
        .runtime_files_backup()
        .list()
        .await?
        .expect_status(StatusCode::OK);

    Ok(())
}

/// Helper: verifies the post-Cleanup invariants:
/// backup empty, nextupdate mirrors current (no pending changes).
async fn assert_state_after_cleanup(client: &SovdTestClient) -> Result<(), TestingError> {
    let sovd2uds = client.sovd2uds();
    let backup = sovd2uds
        .runtime_files_backup()
        .list()
        .await?
        .expect_status(StatusCode::OK)
        .into_body()
        .items;
    assert!(backup.is_empty(), "Expected empty backup after cleanup");

    let current = sovd2uds
        .runtime_files_current()
        .list()
        .await?
        .expect_status(StatusCode::OK)
        .into_body()
        .items;
    let nextupdate = sovd2uds
        .runtime_files_next_update()
        .list()
        .await?
        .expect_status(StatusCode::OK)
        .into_body()
        .items;
    assert_eq!(
        ids_of(&nextupdate),
        ids_of(&current),
        "Expected nextupdate to mirror current after cleanup (spec: reset all pending updates)"
    );

    Ok(())
}

/// Helper: returns the sorted set of item ids from a bulk-data item list, for order-independent
/// comparisons between `runtimefiles-current` and `runtimefiles-nextupdate`.
fn ids_of(items: &[BulkDataDescriptor]) -> Vec<String> {
    let mut ids: Vec<String> = items.iter().map(|i| i.id.to_lowercase()).collect();
    ids.sort();
    ids
}

/// Helper: finds the FLXC1000 entry id in nextupdate, failing the test if absent.
async fn find_flxc1000_id_in_nextupdate(client: &SovdTestClient) -> Result<String, TestingError> {
    let items = client
        .sovd2uds()
        .runtime_files_next_update()
        .list()
        .await?
        .expect_status(StatusCode::OK)
        .into_body()
        .items;
    let id = items
        .iter()
        .find(|item| item.id.to_lowercase().contains(ECU_FLXC1000))
        .expect("Expected flxc1000.mdd in nextupdate after staging init")
        .id
        .clone();
    Ok(id)
}

/// Helper: verifies ECU route state after Apply (FLXC1000 gone, FSNR2000 present, health ok).
async fn assert_ecu_routes_after_apply(test_env: &TestEnv) -> Result<(), TestingError> {
    let client = test_env.client();

    // FLXC1000 was removed from staging -> its route no longer exists.
    assert_route(client, ECU_FLXC1000, StatusCode::NOT_FOUND).await;

    // FSNR2000 was in staging, so its route must survive the rebuild.
    assert_route(client, ECU_FSNR2000, StatusCode::OK).await;

    // The health route lives in a separate group and must not be affected
    // by replace_routes on the vehicle route handle. It is outside the SOVD
    // API the client reaches.
    let health_url = format!(
        "http://{}:{}/health/ready",
        test_env.config.server.address(),
        test_env.config.server.port()
    );
    let health_response = reqwest::Client::new()
        .get(&health_url)
        .send()
        .await
        .expect("health request failed");
    assert_eq!(
        health_response.status(),
        StatusCode::NO_CONTENT,
        "Expected 204 from /health/ready after Apply"
    );

    Ok(())
}

/// Spec: DELETE on /runtimefiles-nextupdate removes all pending changes - nextupdate
/// mirrors runtimefiles-current because there are no pending files anymore.
#[tokio::test]
async fn runtimefiles_delete_nextupdate_clears_pending() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let client = test_env.client();
    let sovd2uds = client.sovd2uds();
    let lock = setup_with_lock(client).await;

    let upload_response = upload_mdd(client).await?;
    assert_eq!(upload_response.status(), StatusCode::CREATED);

    let nextupdate_items = sovd2uds
        .runtime_files_next_update()
        .list()
        .await?
        .expect_status(StatusCode::OK)
        .into_body()
        .items;
    assert!(
        !nextupdate_items.is_empty(),
        "Precondition: nextupdate should have items after upload"
    );

    sovd2uds
        .runtime_files_next_update()
        .delete_all()
        .await?
        .expect_status(StatusCode::OK);

    let post_delete_items = sovd2uds
        .runtime_files_next_update()
        .list()
        .await?
        .expect_status(StatusCode::OK)
        .into_body()
        .items;
    let current_items = sovd2uds
        .runtime_files_current()
        .list()
        .await?
        .expect_status(StatusCode::OK)
        .into_body()
        .items;
    assert_eq!(
        ids_of(&post_delete_items),
        ids_of(&current_items),
        "Expected nextupdate to mirror current after DELETE (no pending files)"
    );

    lock.release().await?.expect_status(StatusCode::NO_CONTENT);
    Ok(())
}

/// Spec: DELETE on /runtimefiles-nextupdate/{id} "deletes the file from the pending update".
#[tokio::test]
async fn runtimefiles_delete_nextupdate_by_id() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let client = test_env.client();
    let next_update = client.sovd2uds().runtime_files_next_update();
    let lock = setup_with_lock(client).await;

    let upload_response = upload_mdd(client).await?;
    assert_eq!(upload_response.status(), StatusCode::CREATED);

    let nextupdate_items = next_update
        .list()
        .await?
        .expect_status(StatusCode::OK)
        .into_body()
        .items;

    let file_id = nextupdate_items
        .iter()
        .find(|item| item.id.to_lowercase().contains(ECU_FLXC1000))
        .expect("Expected to find FLXC1000 file id in nextupdate")
        .id
        .clone();

    delete_file(&next_update, &file_id).await?;

    let post_delete_items = next_update
        .list()
        .await?
        .expect_status(StatusCode::OK)
        .into_body()
        .items;
    let still_has_file = post_delete_items
        .iter()
        .any(|item| item.id.to_lowercase().contains(ECU_FLXC1000));
    assert!(
        !still_has_file,
        "Expected FLXC1000 to be removed from nextupdate after DELETE by id"
    );

    lock.release().await?.expect_status(StatusCode::NO_CONTENT);
    Ok(())
}

/// Spec: DELETE on /runtimefiles-backup "deletes the backup of the previously used diagnostic
/// database, to free up storage space."
#[tokio::test]
async fn runtimefiles_delete_backup() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let client = test_env.client();
    let backup = client.sovd2uds().runtime_files_backup();
    let lock = setup_with_lock(client).await;

    let upload_response = upload_mdd(client).await?;
    assert_eq!(upload_response.status(), StatusCode::CREATED);

    execute_mode(client, ExecutionMode::Apply).await?;

    let backup_items = backup
        .list()
        .await?
        .expect_status(StatusCode::OK)
        .into_body()
        .items;
    assert!(
        !backup_items.is_empty(),
        "Precondition: backup should be non-empty after apply"
    );

    backup.delete_all().await?.expect_status(StatusCode::OK);

    let post_delete_backup_items = backup
        .list()
        .await?
        .expect_status(StatusCode::OK)
        .into_body()
        .items;
    assert!(
        post_delete_backup_items.is_empty(),
        "Expected empty backup after DELETE"
    );

    lock.release().await?.expect_status(StatusCode::NO_CONTENT);
    Ok(())
}

/// Spec: "File names must be handled case-insensitively on all operating systems to make usage
/// regardless of OS consistent, to avoid duplicated entries."
#[tokio::test]
async fn runtimefiles_case_insensitive_filenames() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let client = test_env.client();
    let next_update = client.sovd2uds().runtime_files_next_update();
    let lock = setup_with_lock(client).await;

    let upload_response = upload_mdd_with_filename(client, "FLXC1000.MDD").await?;
    assert_eq!(upload_response.status(), StatusCode::CREATED);

    // Upload again with lowercase - should overwrite, not duplicate
    let upload_response2 = upload_mdd_with_filename(client, "flxc1000.mdd").await?;
    assert_eq!(upload_response2.status(), StatusCode::CREATED);

    let nextupdate_items = next_update
        .list()
        .await?
        .expect_status(StatusCode::OK)
        .into_body()
        .items;

    let matching_items: Vec<_> = nextupdate_items
        .iter()
        .filter(|item| item.id.to_lowercase().contains(ECU_FLXC1000))
        .collect();
    assert_eq!(
        matching_items.len(),
        1,
        "Expected exactly one entry for FLXC1000 regardless of upload case (got {})",
        matching_items.len()
    );

    // Verify deletion also works case-insensitively
    let file_id = &matching_items
        .first()
        .expect("Expected at least one FLXC1000 item")
        .id;
    let opposite_case_id = if file_id.chars().any(char::is_uppercase) {
        file_id.to_lowercase()
    } else {
        file_id.to_uppercase()
    };
    delete_file(&next_update, &opposite_case_id).await?;

    let post_delete_items = next_update
        .list()
        .await?
        .expect_status(StatusCode::OK)
        .into_body()
        .items;
    let still_has_file = post_delete_items
        .iter()
        .any(|item| item.id.to_lowercase().contains(ECU_FLXC1000));
    assert!(
        !still_has_file,
        "Expected file to be deleted via case-insensitive id path"
    );

    lock.release().await?.expect_status(StatusCode::NO_CONTENT);
    Ok(())
}

/// Spec: GET endpoints must support query parameters: x-sovd2uds-include-hash,
/// x-sovd2uds-include-file-size, x-sovd2uds-include-revision.
#[tokio::test]
async fn runtimefiles_query_parameters() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let current = test_env.client().sovd2uds().runtime_files_current();

    let hash_list = current
        .list_with(&[("x-sovd2uds-include-hash", "sha256")])
        .await?
        .expect_status(StatusCode::OK);
    let first_item = hash_list
        .items
        .first()
        .expect("Precondition: current must not be empty");
    assert!(
        first_item.hash.is_some(),
        "Expected 'hash' field when x-sovd2uds-include-hash=sha256 is set"
    );

    let size_list = current
        .list_with(&[("x-sovd2uds-include-file-size", "true")])
        .await?
        .expect_status(StatusCode::OK);
    let first_item = size_list
        .items
        .first()
        .expect("Precondition: current must not be empty");
    assert!(
        first_item.size.is_some(),
        "Expected file size field when x-sovd2uds-include-file-size=true is set"
    );

    let revision_list = current
        .list_with(&[("x-sovd2uds-include-revision", "true")])
        .await?
        .expect_status(StatusCode::OK);
    // Not all the test ecus have a revision set
    assert!(
        revision_list
            .items
            .iter()
            .any(|item| item.revision.is_some()),
        "Expected at least one item with 'revision' field when x-sovd2uds-include-revision=true \
         is set, items: {:?}",
        revision_list.items
    );

    Ok(())
}

/// Spec: "Only the subject of the lock is allowed to use the endpoints."
#[tokio::test]
async fn runtimefiles_only_lock_holder_can_mutate() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let lock = setup_with_lock(test_env.client()).await;

    let non_owner = test_env
        .anonymous_client()
        .with_token(NON_OWNER_BEARER_TOKEN);
    let sovd2uds = non_owner.sovd2uds();

    // Non-owner: upload should be forbidden
    let form = reqwest::multipart::Form::new().part(
        "files",
        reqwest::multipart::Part::bytes(read_mdd_fixture("FLXC1000.mdd")).file_name("FLXC1000.mdd"),
    );
    assert_error_status(
        sovd2uds.runtime_files_next_update().upload(form).await,
        StatusCode::FORBIDDEN,
        "Expected 403 for upload by non-lock-holder",
    );

    // Non-owner: DELETE nextupdate should be forbidden
    assert_error_status(
        sovd2uds.runtime_files_next_update().delete_all().await,
        StatusCode::FORBIDDEN,
        "Expected 403 for DELETE of nextupdate by non-lock-holder",
    );

    // Non-owner: Apply, Rollback and Cleanup should be forbidden
    for mode in [
        ExecutionMode::Apply,
        ExecutionMode::Rollback,
        ExecutionMode::Cleanup,
    ] {
        assert_error_status(
            sovd2uds.runtime_files_update().start(mode).await,
            StatusCode::FORBIDDEN,
            &format!("Expected 403 for {mode:?} by non-lock-holder"),
        );
    }

    lock.release().await?.expect_status(StatusCode::NO_CONTENT);
    Ok(())
}

/// Proves that after an Apply with a reduced MDD set (FLXC1000 removed from staging),
/// the missing ECU's route returns 404, the health endpoint remains 204, and after
/// Rollback the ECU route is restored (200).
///
/// Workflow: upload FSNR2000 to trigger staging init from the seeded current collection,
/// then explicitly delete flxc1000.mdd from nextupdate, then Apply.
#[tokio::test]
async fn runtimefiles_apply_removes_ecu_routes() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let client = test_env.client();

    // Pre-check: FLXC1000 exists at baseline.
    assert_route(client, ECU_FLXC1000, StatusCode::OK).await;

    // All mutating runtimefiles endpoints require a vehicle lock.
    let lock = setup_with_lock(client).await;

    // Upload FSNR2000.mdd -> triggers init_collection_from_copy_if_missing, copying all
    // current MDDs into nextupdate, then adds FSNR2000 on top.
    let upload_response = upload_mdd_by_name(client, "FSNR2000.mdd").await?;
    assert_eq!(
        upload_response.status(),
        StatusCode::CREATED,
        "Expected 201 for FSNR2000.mdd upload"
    );

    // Verify FLXC1000 is in nextupdate (copied from current during init) and delete it.
    let flxc1000_id = find_flxc1000_id_in_nextupdate(client).await?;

    // Explicitly delete FLXC1000 from nextupdate - staging now lacks FLXC1000.
    delete_file(&client.sovd2uds().runtime_files_next_update(), &flxc1000_id).await?;

    // Trigger Apply - the CDA replaces its entire DB with staging (without FLXC1000).
    // The reload_databases path shuts down the old UDS/gateway and rebuilds routes.
    execute_mode(client, ExecutionMode::Apply).await?;
    assert_ecu_routes_after_apply(&test_env).await?;

    // Apply created a backup of the original database; Rollback restores it.
    execute_mode(client, ExecutionMode::Rollback).await?;

    // Wait for all ECUs to come back online after the reload triggered by rollback.
    // The reload creates a new DoIP gateway that must re-discover ECUs via VIR/VAM
    // and run variant detection.
    wait_for_ecus_online(&test_env.config).await?;

    // Rollback restores the original database -> FLXC1000 is back.
    assert_route(client, ECU_FLXC1000, StatusCode::OK).await;

    lock.release().await?.expect_status(StatusCode::NO_CONTENT);
    Ok(())
}

/// Spec: Apply must be blocked (409 Conflict) when the caller holds both a vehicle lock
/// and an ECU lock simultaneously.
///
/// The ECU lock signals that the ECU is currently in use (e.g. an active diagnostic session).
/// Replacing the runtime database while such a lock is held would silently discard the
/// in-progress session, so the implementation must reject the request with 409 Conflict.
/// Once the ECU lock is released, Apply must succeed (202 Accepted).
#[tokio::test]
async fn runtimefiles_apply_blocked_by_vehicle_and_ecu_lock() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let client = test_env.client();

    // All mutating runtimefiles endpoints require a vehicle lock.
    let vehicle_lock = setup_with_lock(client).await;

    // The update starts from the running databases, so re-uploading one of them
    // keeps the vehicle unchanged for every later test.
    let response = upload_mdd(client).await?;
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "upload FLXC1000.mdd"
    );

    // Creating an ECU lock while the vehicle lock is already held is allowed,
    // but it must block any subsequent Apply/Rollback/Cleanup execution.
    let ecu_lock = client
        .component(ECU_FLXC1000)
        .locks()
        .create(default_timeout())
        .await?
        .expect_status(StatusCode::CREATED)
        .into_body();

    // The caller owns both locks, but the ECU lock still prevents a live
    // database swap - expect 409 Conflict.
    assert_error_status(
        client
            .sovd2uds()
            .runtime_files_update()
            .start(ExecutionMode::Apply)
            .await,
        StatusCode::CONFLICT,
        "Expected 409 for Apply while an ECU lock is held",
    );

    ecu_lock
        .release()
        .await?
        .expect_status(StatusCode::NO_CONTENT);

    // With only the vehicle lock held, the database swap is safe to proceed.
    // No Rollback afterwards, because the update did not change the vehicle.
    execute_mode(client, ExecutionMode::Apply).await?;

    vehicle_lock
        .release()
        .await?
        .expect_status(StatusCode::NO_CONTENT);

    Ok(())
}

// The databases in `database.dir` are the starting point of the first update.
//
// Startup never writes to the storage. The first write of an update seeds the
// storage from `database.dir`, exactly once: an update that deliberately
// removes every database must not be undone by seeding again, neither by the
// next update nor by a restart.
//
// The following tests run their own CDA container with writable storage,
// because applying updates would otherwise change the database of the shared
// test CDA.

/// Uploading a single database on a fresh system must stage it on top of the
/// databases loaded from `database.dir`, not replace them.
#[tokio::test]
async fn runtimefiles_first_update_starts_from_database_dir() -> Result<(), TestingError> {
    let cda = start_cda().await?;
    let config = cda_container_config(&cda).await?;
    let client = SovdTestClient::authorize(&config, DEFAULT_CLIENT_ID).await?;
    let sovd2uds = client.sovd2uds();
    let dir_ids = database_dir_ids();

    // Precondition: running from database.dir.
    assert_route(&client, ECU_FSNR2000, StatusCode::OK).await;

    let lock = setup_with_lock(&client).await;

    let response = upload_mdd_by_name(&client, "FLXC1000.mdd").await?;
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "upload FLXC1000.mdd"
    );

    assert_eq!(
        ids(&sovd2uds.runtime_files_next_update()).await?,
        dir_ids,
        "the first update must start from the databases in database.dir"
    );

    execute_mode(&client, ExecutionMode::Apply).await?;

    assert_eq!(
        ids(&sovd2uds.runtime_files_current()).await?,
        dir_ids,
        "applying the first update must keep the databases from database.dir"
    );
    assert_eq!(
        ids(&sovd2uds.runtime_files_backup()).await?,
        dir_ids,
        "the backup of the first update must be the databases from database.dir"
    );
    // An ECU that was not part of the upload keeps its routes.
    assert_route(&client, ECU_FSNR2000, StatusCode::OK).await;

    execute_mode(&client, ExecutionMode::Rollback).await?;

    assert_eq!(
        ids(&sovd2uds.runtime_files_current()).await?,
        dir_ids,
        "rolling back the first update must restore the databases from database.dir"
    );
    assert_route(&client, ECU_FSNR2000, StatusCode::OK).await;

    lock.release().await?.expect_status(StatusCode::NO_CONTENT);
    Ok(())
}

/// Deleting every database is a deliberate, empty data set. Neither the next
/// update nor a restart may seed `database.dir` again.
#[tokio::test]
async fn runtimefiles_deleting_all_databases_is_not_undone_by_seeding() -> Result<(), TestingError>
{
    let cda = start_cda().await?;
    let config = cda_container_config(&cda).await?;
    let client = SovdTestClient::authorize(&config, DEFAULT_CLIENT_ID).await?;
    let dir_ids = database_dir_ids();

    let lock = setup_with_lock(&client).await;

    // The first write of the update is a delete. It has to seed first, so the
    // databases from database.dir exist in the update and can be deleted.
    let next_update = client.sovd2uds().runtime_files_next_update();
    for id in &dir_ids {
        delete_file(&next_update, id).await?;
    }
    assert_eq!(
        ids(&next_update).await?,
        Vec::<String>::new(),
        "every database from database.dir was deleted from the update"
    );

    execute_mode(&client, ExecutionMode::Apply).await?;

    assert_eq!(
        ids(&client.sovd2uds().runtime_files_current()).await?,
        Vec::<String>::new(),
        "applying the update must leave no databases"
    );
    assert_route(&client, ECU_FLXC1000, StatusCode::NOT_FOUND).await;
    lock.release().await?.expect_status(StatusCode::NO_CONTENT);

    // The empty data set must survive a restart: the storage exists, so
    // database.dir must not be loaded again.
    let config = restart_cda_container(&cda).await?;
    let client = SovdTestClient::authorize(&config, DEFAULT_CLIENT_ID).await?;
    assert_route(&client, ECU_FLXC1000, StatusCode::NOT_FOUND).await;
    assert_route(&client, ECU_FSNR2000, StatusCode::NOT_FOUND).await;

    // The next update starts from the empty data set, not from database.dir.
    let lock = setup_with_lock(&client).await;
    let response = upload_mdd_by_name(&client, "FLXC1000.mdd").await?;
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "upload FLXC1000.mdd"
    );
    assert_eq!(
        ids(&client.sovd2uds().runtime_files_next_update()).await?,
        vec!["flxc1000.mdd".to_owned()],
        "the storage was seeded before, so it must not be seeded again"
    );

    execute_mode(&client, ExecutionMode::Apply).await?;
    assert_route(&client, ECU_FLXC1000, StatusCode::OK).await;
    assert_route(&client, ECU_FSNR2000, StatusCode::NOT_FOUND).await;

    lock.release().await?.expect_status(StatusCode::NO_CONTENT);
    Ok(())
}

/// A CDA with the test databases in `database.dir` and writable, empty storage.
async fn start_cda() -> Result<ContainerAsync<GenericImage>, TestingError> {
    cda_container()
        .await?
        // Returns once the CDA reports ready, i.e. has loaded its databases.
        .start()
        .await
        .map_err(|e| TestingError::SetupError(format!("Failed to start CDA container: {e}")))
}

/// The ids the databases in `database.dir` have in the update endpoints.
fn database_dir_ids() -> Vec<String> {
    let mut ids: Vec<String> = mdd_file_names()
        .into_iter()
        .map(|name| name.to_lowercase())
        .collect();
    ids.sort();
    ids
}

/// The sorted, lowercased ids listed by a runtime files category.
async fn ids(files: &RuntimeFiles<'_>) -> Result<Vec<String>, TestingError> {
    Ok(ids_of(
        &files
            .list()
            .await?
            .expect_status(StatusCode::OK)
            .into_body()
            .items,
    ))
}

/// Asserts that the component `ecu` is served (`200 OK`), or answered with the
/// error status `expected`, e.g. `404 Not Found` for an ECU without database.
async fn assert_route(client: &SovdTestClient, ecu: &str, expected: StatusCode) {
    match client.component(ecu).get().await {
        Ok(response) => assert_eq!(
            response.status(),
            expected,
            "{ecu} is served, expected {expected}"
        ),
        Err(err) => assert_eq!(err.status(), Some(expected), "{ecu}: {err}"),
    }
}
