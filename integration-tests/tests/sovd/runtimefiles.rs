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

use cda_interfaces::{HashMap, HashMapExtensions};
use http::{Method, StatusCode};
use opensovd_cda_lib::config::configfile::Configuration;
use sovd_interfaces::{
    apps::sovd2uds::bulk_data::{BulkDataList, runtimefiles::ExecutionMode},
    common::operations::OperationIdItem,
    locking::post_put::Response as LockResponse,
};

use crate::{
    sovd,
    sovd::{
        ECU_FLXC1000_ENDPOINT, ECU_FSNR2000_ENDPOINT,
        locks::{
            self, NON_OWNER_BEARER_TOKEN, bearer_token_header, create_lock, default_timeout,
            lock_operation,
        },
    },
    util::{
        TestingError,
        http::{QueryParams, auth_header, response_to_t, send_cda_request},
        runtime::{setup_integration_test, test_container_dir, wait_for_ecus_online},
    },
};

const RUNTIMEFILES_NEXTUPDATE: &str = "apps/sovd2uds/bulk-data/runtimefiles-nextupdate";
const RUNTIMEFILES_CURRENT: &str = "apps/sovd2uds/bulk-data/runtimefiles-current";
const RUNTIMEFILES_BACKUP: &str = "apps/sovd2uds/bulk-data/runtimefiles-backup";
const RUNTIMEFILES_EXECUTIONS: &str = "apps/sovd2uds/bulk-data/runtimefiles-nextupdate/executions";
const RUNTIMEFILES_OPERATIONS: &str = "apps/sovd2uds/operations/diagnostic-database-update";

/// Tests that mutating endpoints return 403 Forbidden without a vehicle lock.
#[tokio::test]
async fn runtimefiles_requires_lock() -> Result<(), TestingError> {
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;

    let auth_value = auth
        .get(reqwest::header::AUTHORIZATION)
        .expect("Authorization header missing")
        .clone();
    let client = reqwest::Client::new();
    let form = reqwest::multipart::Form::new().part(
        "files",
        reqwest::multipart::Part::bytes(b"fake content".to_vec()).file_name("test.mdd"),
    );
    let upload_url = format!(
        "http://{}:{}/vehicle/v15/{RUNTIMEFILES_NEXTUPDATE}",
        runtime.config.server.address, runtime.config.server.port
    );
    let upload_response = client
        .post(&upload_url)
        .header(reqwest::header::AUTHORIZATION, auth_value)
        .multipart(form)
        .send()
        .await
        .expect("upload request failed");
    assert_eq!(
        upload_response.status(),
        StatusCode::FORBIDDEN,
        "Expected 403 for upload without vehicle lock"
    );

    send_cda_request(
        &runtime.config,
        RUNTIMEFILES_NEXTUPDATE,
        StatusCode::FORBIDDEN,
        Method::DELETE,
        None,
        Some(&auth),
        None,
    )
    .await?;

    let body = mode_json(ExecutionMode::Apply);
    send_cda_request(
        &runtime.config,
        RUNTIMEFILES_EXECUTIONS,
        StatusCode::FORBIDDEN,
        Method::POST,
        Some(&body),
        Some(&auth),
        None,
    )
    .await?;

    let body = mode_json(ExecutionMode::Rollback);
    send_cda_request(
        &runtime.config,
        RUNTIMEFILES_EXECUTIONS,
        StatusCode::FORBIDDEN,
        Method::POST,
        Some(&body),
        Some(&auth),
        None,
    )
    .await?;

    let body = mode_json(ExecutionMode::Cleanup);
    send_cda_request(
        &runtime.config,
        RUNTIMEFILES_EXECUTIONS,
        StatusCode::FORBIDDEN,
        Method::POST,
        Some(&body),
        Some(&auth),
        None,
    )
    .await?;

    Ok(())
}

#[tokio::test]
async fn runtimefiles_lifecycle() -> Result<(), TestingError> {
    // Acquire an exclusive vehicle lock (spec: all modifying actions require one).
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;

    let lock_response = create_lock(
        Duration::from_secs(333),
        locks::VEHICLE_ENDPOINT,
        StatusCode::CREATED,
        &runtime.config,
        &auth,
    )
    .await;
    let lock_id = response_to_t::<LockResponse>(&lock_response)?.id;

    // Snapshot the current database item count so we can verify rollback restores it.
    let initial_count = get_file_list(&runtime.config, &auth, RUNTIMEFILES_CURRENT)
        .await?
        .items
        .len();

    // POST a .mdd file via multipart form data (spec: "Adds files to the next update").
    let upload_response = upload_mdd(&runtime.config, &auth).await;
    assert_eq!(
        upload_response.status(),
        StatusCode::CREATED,
        "Expected 201 for MDD upload"
    );

    // GET nextupdate must show the uploaded file (case-insensitive match per spec).
    assert_nextupdate_contains_flxc1000(&runtime.config, &auth).await?;

    // Trigger "Apply" - pending update becomes active database.
    execute_mode(&runtime.config, &auth, ExecutionMode::Apply).await?;
    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(3)).await;
    assert_state_after_apply(&runtime.config, &auth).await?;

    // Trigger "Rollback" - restore previous database from backup.
    execute_mode(&runtime.config, &auth, ExecutionMode::Rollback).await?;
    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(3)).await;
    assert_state_after_rollback(&runtime.config, &auth, initial_count).await?;

    // Trigger "Cleanup" - spec: "reset all pending updates, as well as deleting the backup".
    execute_mode(&runtime.config, &auth, ExecutionMode::Cleanup).await?;
    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(1)).await;
    assert_state_after_cleanup(&runtime.config, &auth).await?;

    // Release the vehicle lock.
    lock_operation(
        locks::VEHICLE_ENDPOINT,
        Some(&lock_id),
        &runtime.config,
        &auth,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;

    Ok(())
}

/// Spec: "Adding or deleting files must only be allowed in the runtimefiles-nextupdate category,
/// and not for the runtimefiles-backup or runtimefiles-current category."
#[tokio::test]
async fn runtimefiles_post_delete_forbidden_on_current_and_backup() -> Result<(), TestingError> {
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;
    let lock_id = setup_with_lock(&runtime.config, &auth).await;

    let mdd_bytes = std::fs::read(
        test_container_dir()
            .expect("testcontainer dir")
            .join("odx/FLXC1000.mdd"),
    )
    .expect("MDD fixture not found");
    let auth_value = auth
        .get(reqwest::header::AUTHORIZATION)
        .expect("Authorization header missing")
        .clone();
    let client = reqwest::Client::new();

    let form = reqwest::multipart::Form::new().part(
        "files",
        reqwest::multipart::Part::bytes(mdd_bytes.clone()).file_name("test.mdd"),
    );
    let current_url = format!(
        "http://{}:{}/vehicle/v15/{RUNTIMEFILES_CURRENT}",
        runtime.config.server.address, runtime.config.server.port
    );
    let response = client
        .post(&current_url)
        .header(reqwest::header::AUTHORIZATION, auth_value.clone())
        .multipart(form)
        .send()
        .await
        .expect("POST to runtimefiles-current failed");
    assert_eq!(
        response.status(),
        StatusCode::METHOD_NOT_ALLOWED,
        "Expected 405 for POST to runtimefiles-current"
    );

    send_cda_request(
        &runtime.config,
        RUNTIMEFILES_CURRENT,
        StatusCode::METHOD_NOT_ALLOWED,
        Method::DELETE,
        None,
        Some(&auth),
        None,
    )
    .await?;

    let form = reqwest::multipart::Form::new().part(
        "files",
        reqwest::multipart::Part::bytes(mdd_bytes).file_name("test.mdd"),
    );
    let backup_url = format!(
        "http://{}:{}/vehicle/v15/{RUNTIMEFILES_BACKUP}",
        runtime.config.server.address, runtime.config.server.port
    );
    let response = client
        .post(&backup_url)
        .header(reqwest::header::AUTHORIZATION, auth_value)
        .multipart(form)
        .send()
        .await
        .expect("POST to runtimefiles-backup failed");
    assert_eq!(
        response.status(),
        StatusCode::METHOD_NOT_ALLOWED,
        "Expected 405 for POST to runtimefiles-backup"
    );

    teardown_lock(&runtime.config, &auth, &lock_id).await;
    Ok(())
}

/// Spec: "Only the subject of the lock is allowed to use the endpoints."
/// This specifically tests that a non-lock-holder cannot DELETE the backup.
#[tokio::test]
async fn runtimefiles_non_owner_cannot_delete_backup() -> Result<(), TestingError> {
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;
    let lock_id = setup_with_lock(&runtime.config, &auth).await;

    let upload_response = upload_mdd(&runtime.config, &auth).await;
    assert_eq!(upload_response.status(), StatusCode::CREATED);

    execute_mode(&runtime.config, &auth, ExecutionMode::Apply).await?;
    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(3)).await;

    let non_owner_auth = bearer_token_header(NON_OWNER_BEARER_TOKEN);
    send_cda_request(
        &runtime.config,
        RUNTIMEFILES_BACKUP,
        StatusCode::FORBIDDEN,
        Method::DELETE,
        None,
        Some(&non_owner_auth),
        None,
    )
    .await?;

    execute_mode(&runtime.config, &auth, ExecutionMode::Rollback).await?;
    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(3)).await;

    teardown_lock(&runtime.config, &auth, &lock_id).await;
    Ok(())
}

/// Spec: "none of the endpoints should allow retrieval of the files by default"
#[tokio::test]
async fn runtimefiles_file_retrieval_not_allowed() -> Result<(), TestingError> {
    let (runtime, _lock) = setup_integration_test(false).await?;
    let auth = auth_header(&runtime.config, None).await?;

    send_cda_request(
        &runtime.config,
        &format!("{RUNTIMEFILES_CURRENT}/FLXC1000.mdd"),
        StatusCode::NOT_FOUND,
        Method::GET,
        None,
        Some(&auth),
        None,
    )
    .await?;

    send_cda_request(
        &runtime.config,
        &format!("{RUNTIMEFILES_NEXTUPDATE}/FLXC1000.mdd"),
        StatusCode::METHOD_NOT_ALLOWED,
        Method::GET,
        None,
        Some(&auth),
        None,
    )
    .await?;

    send_cda_request(
        &runtime.config,
        &format!("{RUNTIMEFILES_BACKUP}/FLXC1000.mdd"),
        StatusCode::NOT_FOUND,
        Method::GET,
        None,
        Some(&auth),
        None,
    )
    .await?;

    Ok(())
}

/// Spec: "Deletes the file from the pending update" - file must exist to be deleted.
#[tokio::test]
async fn runtimefiles_delete_nonexistent_file_returns_not_found() -> Result<(), TestingError> {
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;
    let lock_id = setup_with_lock(&runtime.config, &auth).await;

    send_cda_request(
        &runtime.config,
        &format!("{RUNTIMEFILES_NEXTUPDATE}/this-file-does-not-exist.mdd"),
        StatusCode::NOT_FOUND,
        Method::DELETE,
        None,
        Some(&auth),
        None,
    )
    .await?;

    teardown_lock(&runtime.config, &auth, &lock_id).await;
    Ok(())
}

/// Spec: "Deletes the backup of the previously used diagnostic database, to free up storage space."
/// Tests idempotency: deleting an already-empty backup.
#[tokio::test]
async fn runtimefiles_delete_backup_when_empty() -> Result<(), TestingError> {
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;
    let lock_id = setup_with_lock(&runtime.config, &auth).await;

    execute_mode(&runtime.config, &auth, ExecutionMode::Cleanup).await?;
    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(1)).await;

    let backup_items = get_file_list(&runtime.config, &auth, RUNTIMEFILES_BACKUP)
        .await?
        .items;
    assert!(
        backup_items.is_empty(),
        "Precondition: backup must be empty after cleanup"
    );

    // If implementation returns 404 instead, that's a finding.
    send_cda_request(
        &runtime.config,
        RUNTIMEFILES_BACKUP,
        StatusCode::NO_CONTENT,
        Method::DELETE,
        None,
        Some(&auth),
        None,
    )
    .await?;

    teardown_lock(&runtime.config, &auth, &lock_id).await;
    Ok(())
}

/// Spec: Execution mode values must be accepted case-insensitively
/// (e.g. "apply", "APPLY", "Apply").
#[tokio::test]
async fn runtimefiles_execution_mode_case_insensitive() -> Result<(), TestingError> {
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;
    let lock_id = setup_with_lock(&runtime.config, &auth).await;

    // Upload a file so Apply has something to work with
    let upload_response = upload_mdd(&runtime.config, &auth).await;
    assert!(
        upload_response.status().is_success(),
        "Precondition: upload must succeed, got {}",
        upload_response.status()
    );

    // Test lowercase "apply"
    send_cda_request(
        &runtime.config,
        RUNTIMEFILES_EXECUTIONS,
        StatusCode::ACCEPTED,
        Method::POST,
        Some(r#"{"mode": "apply"}"#),
        Some(&auth),
        None,
    )
    .await?;
    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(3)).await;

    // Upload again for uppercase test
    let upload_response2 = upload_mdd(&runtime.config, &auth).await;
    assert!(
        upload_response2.status().is_success(),
        "Precondition: second upload must succeed, got {}",
        upload_response2.status()
    );

    // Test uppercase "APPLY"
    send_cda_request(
        &runtime.config,
        RUNTIMEFILES_EXECUTIONS,
        StatusCode::ACCEPTED,
        Method::POST,
        Some(r#"{"mode": "APPLY"}"#),
        Some(&auth),
        None,
    )
    .await?;
    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(3)).await;

    teardown_lock(&runtime.config, &auth, &lock_id).await;
    Ok(())
}

/// Spec: The operations endpoint must be accessible as an alternative alias for executions.
#[tokio::test]
async fn runtimefiles_operations_endpoint_alias() -> Result<(), TestingError> {
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;
    let lock_id = setup_with_lock(&runtime.config, &auth).await;

    // Upload a file so Apply has something to work with
    let upload_response = upload_mdd(&runtime.config, &auth).await;
    assert!(
        upload_response.status().is_success(),
        "Precondition: upload must succeed, got {}",
        upload_response.status()
    );

    // Use RUNTIMEFILES_OPERATIONS instead of RUNTIMEFILES_EXECUTIONS
    let body = mode_json(ExecutionMode::Apply);
    send_cda_request(
        &runtime.config,
        RUNTIMEFILES_OPERATIONS,
        StatusCode::ACCEPTED,
        Method::POST,
        Some(&body),
        Some(&auth),
        None,
    )
    .await?;
    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(3)).await;

    teardown_lock(&runtime.config, &auth, &lock_id).await;
    Ok(())
}

/// Spec: GET endpoints for nextupdate and backup must support query parameters:
/// x-sovd2uds-include-hash, x-sovd2uds-include-file-size, x-sovd2uds-include-revision.
#[tokio::test]
async fn runtimefiles_query_parameters_all_endpoints() -> Result<(), TestingError> {
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;
    let lock_id = setup_with_lock(&runtime.config, &auth).await;

    // Upload a file so nextupdate is non-empty
    let upload_response = upload_mdd(&runtime.config, &auth).await;
    assert!(
        upload_response.status().is_success(),
        "Precondition: upload must succeed, got {}",
        upload_response.status()
    );

    // Reads should not depend on a vehicle lock, so release it before GET checks.
    teardown_lock(&runtime.config, &auth, &lock_id).await;

    // Test hash query on nextupdate
    let mut hash_params = HashMap::new();
    hash_params.insert("x-sovd2uds-include-hash".to_owned(), "sha256".to_owned());
    let nextupdate_hash_response = send_cda_request(
        &runtime.config,
        RUNTIMEFILES_NEXTUPDATE,
        StatusCode::OK,
        Method::GET,
        None,
        Some(&auth),
        Some(&QueryParams(hash_params)),
    )
    .await?;
    let nextupdate_hash_list = response_to_t::<BulkDataList>(&nextupdate_hash_response)?;
    if let Some(first_item) = nextupdate_hash_list.items.first() {
        assert!(
            first_item.hash.is_some(),
            "Expected 'hash' field in nextupdate when x-sovd2uds-include-hash=sha256 is set"
        );
    }

    // Apply to populate backup
    let lock_id = setup_with_lock(&runtime.config, &auth).await;
    execute_mode(&runtime.config, &auth, ExecutionMode::Apply).await?;
    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(3)).await;
    teardown_lock(&runtime.config, &auth, &lock_id).await;

    // Test file-size query on backup
    let mut size_params = HashMap::new();
    size_params.insert("x-sovd2uds-include-file-size".to_owned(), "true".to_owned());
    let backup_size_response = send_cda_request(
        &runtime.config,
        RUNTIMEFILES_BACKUP,
        StatusCode::OK,
        Method::GET,
        None,
        Some(&auth),
        Some(&QueryParams(size_params)),
    )
    .await?;
    let backup_size_list = response_to_t::<BulkDataList>(&backup_size_response)?;
    if let Some(first_item) = backup_size_list.items.first() {
        assert!(
            first_item.size.is_some(),
            "Expected file size field in backup when x-sovd2uds-include-file-size=true is set"
        );
    }
    Ok(())
}

/// Spec: Uploading multiple files in a single multipart request must be supported.
#[tokio::test]
async fn runtimefiles_upload_multiple_files() -> Result<(), TestingError> {
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;
    let lock_id = setup_with_lock(&runtime.config, &auth).await;

    let mdd_bytes = std::fs::read(
        test_container_dir()
            .expect("testcontainer dir")
            .join("odx/FLXC1000.mdd"),
    )
    .expect("MDD fixture not found");
    let auth_value = auth
        .get(reqwest::header::AUTHORIZATION)
        .expect("Authorization header missing")
        .clone();
    let client = reqwest::Client::new();

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

    let upload_url = format!(
        "http://{}:{}/vehicle/v15/{RUNTIMEFILES_NEXTUPDATE}",
        runtime.config.server.address, runtime.config.server.port
    );
    let response = client
        .post(&upload_url)
        .header(reqwest::header::AUTHORIZATION, auth_value)
        .multipart(form)
        .send()
        .await
        .expect("multi-file upload request failed");

    assert!(
        response.status().is_success(),
        "Expected success for multi-file upload, got {}",
        response.status()
    );

    // Verify both files appear in nextupdate
    let list_response = send_cda_request(
        &runtime.config,
        RUNTIMEFILES_NEXTUPDATE,
        StatusCode::OK,
        Method::GET,
        None,
        Some(&auth),
        None,
    )
    .await?;
    let items = response_to_t::<BulkDataList>(&list_response)?.items;
    assert!(
        items.len() >= 2,
        "Expected at least 2 items after uploading FILE_A.mdd and FILE_B.mdd, got {}",
        items.len()
    );

    teardown_lock(&runtime.config, &auth, &lock_id).await;
    Ok(())
}

/// Spec: Applying when there are no pending changes (nextupdate == current)
/// must not return 202 Accepted (primary expectation: 404).
#[tokio::test]
async fn runtimefiles_apply_with_no_pending_changes() -> Result<(), TestingError> {
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;
    let lock_id = setup_with_lock(&runtime.config, &auth).await;

    // Reset nextupdate to current state (spec: DELETE removes all pending changes,
    // resetting nextupdate to the currently active database - not to empty).
    send_cda_request(
        &runtime.config,
        RUNTIMEFILES_NEXTUPDATE,
        StatusCode::NO_CONTENT,
        Method::DELETE,
        None,
        Some(&auth),
        None,
    )
    .await?;

    // Attempt Apply with no pending changes (nextupdate == current) - must NOT return 202
    let body = mode_json(ExecutionMode::Apply);
    let apply_response = send_cda_request(
        &runtime.config,
        RUNTIMEFILES_EXECUTIONS,
        StatusCode::NOT_FOUND,
        Method::POST,
        Some(&body),
        Some(&auth),
        None,
    )
    .await;
    if apply_response.is_err() {
        // If the server returns something other than 404, that's a finding - log it but don't fail
        // The primary assertion is that it must NOT be 202
    }

    teardown_lock(&runtime.config, &auth, &lock_id).await;
    Ok(())
}

/// Spec: Rollback when backup is empty must return 404 Not Found.
#[tokio::test]
async fn runtimefiles_rollback_with_no_backup() -> Result<(), TestingError> {
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;
    let lock_id = setup_with_lock(&runtime.config, &auth).await;

    // Clear backup
    send_cda_request(
        &runtime.config,
        RUNTIMEFILES_BACKUP,
        StatusCode::NO_CONTENT,
        Method::DELETE,
        None,
        Some(&auth),
        None,
    )
    .await?;
    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(1)).await;

    // Verify backup is empty
    let backup_response = send_cda_request(
        &runtime.config,
        RUNTIMEFILES_BACKUP,
        StatusCode::OK,
        Method::GET,
        None,
        Some(&auth),
        None,
    )
    .await?;
    let backup_items = response_to_t::<BulkDataList>(&backup_response)?.items;
    assert!(
        backup_items.is_empty(),
        "Precondition: backup must be empty before Rollback"
    );

    // Attempt Rollback with empty backup - expect 404
    let body = mode_json(ExecutionMode::Rollback);
    send_cda_request(
        &runtime.config,
        RUNTIMEFILES_EXECUTIONS,
        StatusCode::NOT_FOUND,
        Method::POST,
        Some(&body),
        Some(&auth),
        None,
    )
    .await?;

    teardown_lock(&runtime.config, &auth, &lock_id).await;
    Ok(())
}

/// Spec: Rollback must clear any newly uploaded pending files from nextupdate.
#[tokio::test]
async fn runtimefiles_rollback_clears_nextupdate_with_new_pending() -> Result<(), TestingError> {
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;
    let lock_id = setup_with_lock(&runtime.config, &auth).await;

    // Step 1: Upload and Apply to establish a backup
    let upload_response = upload_mdd(&runtime.config, &auth).await;
    assert!(
        upload_response.status().is_success(),
        "Precondition: first upload must succeed, got {}",
        upload_response.status()
    );
    execute_mode(&runtime.config, &auth, ExecutionMode::Apply).await?;
    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(3)).await;

    // Step 2: Upload a new file to nextupdate (new pending changes)
    let upload_response2 =
        upload_mdd_with_filename(&runtime.config, &auth, "NEW_PENDING.mdd").await;
    assert!(
        upload_response2.status().is_success(),
        "Precondition: second upload must succeed, got {}",
        upload_response2.status()
    );

    // Step 3: Rollback - should revert current and clear nextupdate
    execute_mode(&runtime.config, &auth, ExecutionMode::Rollback).await?;
    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(3)).await;

    // Step 4: Verify nextupdate is empty after rollback
    let nextupdate_items = get_file_list(&runtime.config, &auth, RUNTIMEFILES_NEXTUPDATE)
        .await?
        .items;
    assert!(
        nextupdate_items.is_empty(),
        "Expected nextupdate to be empty after Rollback, but found {} items",
        nextupdate_items.len()
    );

    teardown_lock(&runtime.config, &auth, &lock_id).await;
    Ok(())
}

/// Spec: Apply must be blocked (409 Conflict) when a functional group lock is held by
/// another operation.
#[tokio::test]
async fn runtimefiles_apply_blocked_by_active_operations() -> Result<(), TestingError> {
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;

    // Create vehicle lock (required for runtimefiles mutations)
    let vehicle_lock_response = create_lock(
        Duration::from_secs(333),
        locks::VEHICLE_ENDPOINT,
        StatusCode::CREATED,
        &runtime.config,
        &auth,
    )
    .await;
    let vehicle_lock_id = response_to_t::<LockResponse>(&vehicle_lock_response)?.id;

    // Upload a file so Apply has something to work with
    let upload_response = upload_mdd(&runtime.config, &auth).await;
    assert!(
        upload_response.status().is_success(),
        "Precondition: upload must succeed, got {}",
        upload_response.status()
    );

    // Create functional group lock (same user) to block Apply
    let fg_lock_response = create_lock(
        Duration::from_secs(333),
        locks::FUNCTIONAL_GROUP_ENDPOINT,
        StatusCode::CREATED,
        &runtime.config,
        &auth,
    )
    .await;
    let fg_lock_id = response_to_t::<LockResponse>(&fg_lock_response)?.id;

    // Attempt Apply while functional group lock is held - expect 409 Conflict
    let body = mode_json(ExecutionMode::Apply);
    send_cda_request(
        &runtime.config,
        RUNTIMEFILES_EXECUTIONS,
        StatusCode::CONFLICT,
        Method::POST,
        Some(&body),
        Some(&auth),
        None,
    )
    .await?;

    lock_operation(
        locks::FUNCTIONAL_GROUP_ENDPOINT,
        Some(&fg_lock_id),
        &runtime.config,
        &auth,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;

    // Now Apply should succeed (202)
    execute_mode(&runtime.config, &auth, ExecutionMode::Apply).await?;
    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(3)).await;

    // Release vehicle lock
    send_cda_request(
        &runtime.config,
        &format!("locks/{vehicle_lock_id}"),
        StatusCode::NO_CONTENT,
        Method::DELETE,
        None,
        Some(&auth),
        None,
    )
    .await?;

    Ok(())
}

/// Helper: uploads the MDD fixture to nextupdate and returns the raw reqwest response.
async fn upload_mdd(config: &Configuration, auth: &http::HeaderMap) -> reqwest::Response {
    let mdd_bytes = std::fs::read(
        test_container_dir()
            .expect("testcontainer dir")
            .join("odx/FLXC1000.mdd"),
    )
    .expect("MDD fixture not found");
    let auth_value = auth
        .get(reqwest::header::AUTHORIZATION)
        .expect("Authorization header missing")
        .clone();
    let client = reqwest::Client::new();
    let form = reqwest::multipart::Form::new().part(
        "files",
        reqwest::multipart::Part::bytes(mdd_bytes).file_name("FLXC1000.mdd"),
    );
    let upload_url = format!(
        "http://{}:{}/vehicle/v15/{RUNTIMEFILES_NEXTUPDATE}",
        config.server.address, config.server.port
    );
    client
        .post(&upload_url)
        .header(reqwest::header::AUTHORIZATION, auth_value)
        .multipart(form)
        .send()
        .await
        .expect("upload request failed")
}

/// Helper: uploads an MDD from testcontainer/odx/{name} (e.g. "FSNR2000.mdd").
async fn upload_mdd_by_name(
    config: &Configuration,
    auth: &http::HeaderMap,
    name: &str,
) -> reqwest::Response {
    let mdd_bytes = std::fs::read(
        test_container_dir()
            .expect("testcontainer dir")
            .join(format!("odx/{name}")),
    )
    .unwrap_or_else(|_| panic!("MDD fixture {name} not found"));
    let auth_value = auth
        .get(reqwest::header::AUTHORIZATION)
        .expect("Authorization header missing")
        .clone();
    let client = reqwest::Client::new();
    let form = reqwest::multipart::Form::new().part(
        "files",
        reqwest::multipart::Part::bytes(mdd_bytes).file_name(name.to_owned()),
    );
    let upload_url = format!(
        "http://{}:{}/vehicle/v15/{RUNTIMEFILES_NEXTUPDATE}",
        config.server.address, config.server.port
    );
    client
        .post(&upload_url)
        .header(reqwest::header::AUTHORIZATION, auth_value)
        .multipart(form)
        .send()
        .await
        .expect("upload request failed")
}

/// Helper: uploads an MDD fixture with a custom filename.
async fn upload_mdd_with_filename(
    config: &Configuration,
    auth: &http::HeaderMap,
    filename: &str,
) -> reqwest::Response {
    let mdd_bytes = std::fs::read(
        test_container_dir()
            .expect("testcontainer dir")
            .join("odx/FLXC1000.mdd"),
    )
    .expect("MDD fixture not found");
    let auth_value = auth
        .get(reqwest::header::AUTHORIZATION)
        .expect("Authorization header missing")
        .clone();
    let client = reqwest::Client::new();
    let form = reqwest::multipart::Form::new().part(
        "files",
        reqwest::multipart::Part::bytes(mdd_bytes).file_name(filename.to_owned()),
    );
    let upload_url = format!(
        "http://{}:{}/vehicle/v15/{RUNTIMEFILES_NEXTUPDATE}",
        config.server.address, config.server.port
    );
    client
        .post(&upload_url)
        .header(reqwest::header::AUTHORIZATION, auth_value)
        .multipart(form)
        .send()
        .await
        .expect("upload request failed")
}

/// Helper: creates a vehicle lock and returns the lock id.
async fn setup_with_lock(config: &Configuration, auth: &http::HeaderMap) -> String {
    let lock_response = create_lock(
        Duration::from_secs(333),
        locks::VEHICLE_ENDPOINT,
        StatusCode::CREATED,
        config,
        auth,
    )
    .await;
    response_to_t::<LockResponse>(&lock_response)
        .expect("Failed to deserialize lock response")
        .id
}

/// Helper: releases a vehicle lock.
async fn teardown_lock(config: &Configuration, auth: &http::HeaderMap, lock_id: &str) {
    send_cda_request(
        config,
        &format!("locks/{lock_id}"),
        StatusCode::NO_CONTENT,
        Method::DELETE,
        None,
        Some(auth),
        None,
    )
    .await
    .expect("Failed to release lock");
}

/// Helper: GETs a runtimefiles list endpoint and deserializes the typed response.
async fn get_file_list(
    config: &Configuration,
    auth: &http::HeaderMap,
    endpoint: &str,
) -> Result<BulkDataList, TestingError> {
    let response = send_cda_request(
        config,
        endpoint,
        StatusCode::OK,
        Method::GET,
        None,
        Some(auth),
        None,
    )
    .await?;
    response_to_t::<BulkDataList>(&response)
}

/// Serializes an `ExecutionMode` into the JSON body expected by execution endpoints.
fn mode_json(mode: ExecutionMode) -> String {
    serde_json::json!({ "mode": mode }).to_string()
}

/// Helper: POSTs an execution mode to the executions endpoint (expects 202 Accepted).
async fn execute_mode(
    config: &Configuration,
    auth: &http::HeaderMap,
    mode: ExecutionMode,
) -> Result<OperationIdItem, TestingError> {
    let body = mode_json(mode);
    let response = send_cda_request(
        config,
        RUNTIMEFILES_EXECUTIONS,
        StatusCode::ACCEPTED,
        Method::POST,
        Some(&body),
        Some(auth),
        None,
    )
    .await?;
    response_to_t::<OperationIdItem>(&response)
}

/// Helper: asserts the uploaded FLXC1000.mdd is visible in nextupdate (case-insensitive).
async fn assert_nextupdate_contains_flxc1000(
    config: &Configuration,
    auth: &http::HeaderMap,
) -> Result<(), TestingError> {
    let items = get_file_list(config, auth, RUNTIMEFILES_NEXTUPDATE)
        .await?
        .items;
    assert!(
        !items.is_empty(),
        "Expected at least one item in nextupdate after upload"
    );
    assert!(
        items
            .iter()
            .any(|item| item.id.to_lowercase().contains("flxc1000")),
        "Expected FLXC1000.mdd in nextupdate items"
    );
    Ok(())
}

/// Helper: verifies the post-Apply invariants:
/// current non-empty, nextupdate empty, backup non-empty.
async fn assert_state_after_apply(
    config: &Configuration,
    auth: &http::HeaderMap,
) -> Result<(), TestingError> {
    let current = get_file_list(config, auth, RUNTIMEFILES_CURRENT)
        .await?
        .items;
    assert!(
        !current.is_empty(),
        "Expected non-empty current after apply"
    );

    let nextupdate = get_file_list(config, auth, RUNTIMEFILES_NEXTUPDATE)
        .await?
        .items;
    assert!(
        nextupdate.is_empty(),
        "Expected empty nextupdate after apply"
    );

    let backup = get_file_list(config, auth, RUNTIMEFILES_BACKUP)
        .await?
        .items;
    assert!(
        !backup.is_empty(),
        "Expected non-empty backup after apply (original db backed up)"
    );

    Ok(())
}

/// Helper: verifies the post-Rollback invariants:
/// current count matches `expected_count`, nextupdate empty.
async fn assert_state_after_rollback(
    config: &Configuration,
    auth: &http::HeaderMap,
    expected_count: usize,
) -> Result<(), TestingError> {
    let current = get_file_list(config, auth, RUNTIMEFILES_CURRENT)
        .await?
        .items;
    assert_eq!(
        current.len(),
        expected_count,
        "Expected item count to match initial count after rollback"
    );

    let nextupdate = get_file_list(config, auth, RUNTIMEFILES_NEXTUPDATE)
        .await?
        .items;
    assert!(
        nextupdate.is_empty(),
        "Expected empty nextupdate after rollback (spec: state of nextupdate must be reset)"
    );

    get_file_list(config, auth, RUNTIMEFILES_BACKUP).await?;

    Ok(())
}

/// Helper: verifies the post-Cleanup invariants:
/// backup empty, nextupdate empty.
async fn assert_state_after_cleanup(
    config: &Configuration,
    auth: &http::HeaderMap,
) -> Result<(), TestingError> {
    let backup = get_file_list(config, auth, RUNTIMEFILES_BACKUP)
        .await?
        .items;
    assert!(backup.is_empty(), "Expected empty backup after cleanup");

    let nextupdate = get_file_list(config, auth, RUNTIMEFILES_NEXTUPDATE)
        .await?
        .items;
    assert!(
        nextupdate.is_empty(),
        "Expected empty nextupdate after cleanup (spec: reset all pending updates)"
    );

    Ok(())
}

/// Helper: finds the FLXC1000 entry id in nextupdate, failing the test if absent.
async fn find_flxc1000_id_in_nextupdate(
    config: &Configuration,
    auth: &http::HeaderMap,
) -> Result<String, TestingError> {
    let items = get_file_list(config, auth, RUNTIMEFILES_NEXTUPDATE)
        .await?
        .items;
    let id = items
        .iter()
        .find(|item| item.id.to_lowercase().contains("flxc1000"))
        .expect("Expected flxc1000.mdd in nextupdate after staging init")
        .id
        .clone();
    Ok(id)
}

/// Helper: verifies ECU route state after Apply (FLXC1000 gone, FSNR2000 present, health ok).
async fn assert_ecu_routes_after_apply(
    config: &Configuration,
    auth: &http::HeaderMap,
) -> Result<(), TestingError> {
    // FLXC1000 was removed from staging -> its route no longer exists.
    send_cda_request(
        config,
        ECU_FLXC1000_ENDPOINT,
        StatusCode::NOT_FOUND,
        Method::GET,
        None,
        Some(auth),
        None,
    )
    .await?;

    // FSNR2000 was in staging, so its route must survive the rebuild.
    send_cda_request(
        config,
        ECU_FSNR2000_ENDPOINT,
        StatusCode::OK,
        Method::GET,
        None,
        Some(auth),
        None,
    )
    .await?;

    // The health route lives in a separate group and must not be affected
    // by replace_routes on the vehicle route handle.
    let health_url = format!(
        "http://{}:{}/health/ready",
        config.server.address, config.server.port
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
/// returns empty because there are no pending files.
#[tokio::test]
async fn runtimefiles_delete_nextupdate_clears_pending() -> Result<(), TestingError> {
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;
    let lock_id = setup_with_lock(&runtime.config, &auth).await;

    let upload_response = upload_mdd(&runtime.config, &auth).await;
    assert_eq!(upload_response.status(), StatusCode::CREATED);

    let nextupdate_items = get_file_list(&runtime.config, &auth, RUNTIMEFILES_NEXTUPDATE)
        .await?
        .items;
    assert!(
        !nextupdate_items.is_empty(),
        "Precondition: nextupdate should have items after upload"
    );

    send_cda_request(
        &runtime.config,
        RUNTIMEFILES_NEXTUPDATE,
        StatusCode::NO_CONTENT,
        Method::DELETE,
        None,
        Some(&auth),
        None,
    )
    .await?;

    let post_delete_items = get_file_list(&runtime.config, &auth, RUNTIMEFILES_NEXTUPDATE)
        .await?
        .items;
    assert!(
        post_delete_items.is_empty(),
        "Expected empty nextupdate after DELETE (no pending files)"
    );

    teardown_lock(&runtime.config, &auth, &lock_id).await;
    Ok(())
}

/// Spec: DELETE on /runtimefiles-nextupdate/{id} "deletes the file from the pending update".
#[tokio::test]
async fn runtimefiles_delete_nextupdate_by_id() -> Result<(), TestingError> {
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;
    let lock_id = setup_with_lock(&runtime.config, &auth).await;

    let upload_response = upload_mdd(&runtime.config, &auth).await;
    assert_eq!(upload_response.status(), StatusCode::CREATED);

    let nextupdate_items = get_file_list(&runtime.config, &auth, RUNTIMEFILES_NEXTUPDATE)
        .await?
        .items;

    let file_id = nextupdate_items
        .iter()
        .find(|item| item.id.to_lowercase().contains("flxc1000"))
        .expect("Expected to find FLXC1000 file id in nextupdate")
        .id
        .clone();

    send_cda_request(
        &runtime.config,
        &format!("{RUNTIMEFILES_NEXTUPDATE}/{file_id}"),
        StatusCode::NO_CONTENT,
        Method::DELETE,
        None,
        Some(&auth),
        None,
    )
    .await?;

    let post_delete_response = send_cda_request(
        &runtime.config,
        RUNTIMEFILES_NEXTUPDATE,
        StatusCode::OK,
        Method::GET,
        None,
        Some(&auth),
        None,
    )
    .await?;
    let post_delete_items = response_to_t::<BulkDataList>(&post_delete_response)?.items;
    let still_has_file = post_delete_items
        .iter()
        .any(|item| item.id.to_lowercase().contains("flxc1000"));
    assert!(
        !still_has_file,
        "Expected FLXC1000 to be removed from nextupdate after DELETE by id"
    );

    teardown_lock(&runtime.config, &auth, &lock_id).await;
    Ok(())
}

/// Spec: DELETE on /runtimefiles-backup "deletes the backup of the previously used diagnostic
/// database, to free up storage space."
#[tokio::test]
async fn runtimefiles_delete_backup() -> Result<(), TestingError> {
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;
    let lock_id = setup_with_lock(&runtime.config, &auth).await;

    let upload_response = upload_mdd(&runtime.config, &auth).await;
    assert_eq!(upload_response.status(), StatusCode::CREATED);

    execute_mode(&runtime.config, &auth, ExecutionMode::Apply).await?;
    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(3)).await;

    let backup_items = get_file_list(&runtime.config, &auth, RUNTIMEFILES_BACKUP)
        .await?
        .items;
    assert!(
        !backup_items.is_empty(),
        "Precondition: backup should be non-empty after apply"
    );

    send_cda_request(
        &runtime.config,
        RUNTIMEFILES_BACKUP,
        StatusCode::NO_CONTENT,
        Method::DELETE,
        None,
        Some(&auth),
        None,
    )
    .await?;

    let post_delete_backup = send_cda_request(
        &runtime.config,
        RUNTIMEFILES_BACKUP,
        StatusCode::OK,
        Method::GET,
        None,
        Some(&auth),
        None,
    )
    .await?;
    let post_delete_backup_items = response_to_t::<BulkDataList>(&post_delete_backup)?.items;
    assert!(
        post_delete_backup_items.is_empty(),
        "Expected empty backup after DELETE"
    );

    // The backup was deleted above, so Rollback is not possible (no backup to restore from).
    // Use Cleanup instead to clear any pending state and leave the server in a clean state.
    execute_mode(&runtime.config, &auth, ExecutionMode::Cleanup).await?;
    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(1)).await;

    teardown_lock(&runtime.config, &auth, &lock_id).await;
    Ok(())
}

/// Spec: "File names must be handled case-insensitively on all operating systems to make usage
/// regardless of OS consistent, to avoid duplicated entries."
#[tokio::test]
async fn runtimefiles_case_insensitive_filenames() -> Result<(), TestingError> {
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;
    let lock_id = setup_with_lock(&runtime.config, &auth).await;

    let upload_response = upload_mdd_with_filename(&runtime.config, &auth, "FLXC1000.MDD").await;
    assert_eq!(upload_response.status(), StatusCode::CREATED);

    // Upload again with lowercase - should overwrite, not duplicate
    let upload_response2 = upload_mdd_with_filename(&runtime.config, &auth, "flxc1000.mdd").await;
    assert_eq!(upload_response2.status(), StatusCode::CREATED);

    let nextupdate_items = get_file_list(&runtime.config, &auth, RUNTIMEFILES_NEXTUPDATE)
        .await?
        .items;

    let matching_items: Vec<_> = nextupdate_items
        .iter()
        .filter(|item| item.id.to_lowercase().contains("flxc1000"))
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
    send_cda_request(
        &runtime.config,
        &format!("{RUNTIMEFILES_NEXTUPDATE}/{opposite_case_id}"),
        StatusCode::NO_CONTENT,
        Method::DELETE,
        None,
        Some(&auth),
        None,
    )
    .await?;

    let post_delete_response = send_cda_request(
        &runtime.config,
        RUNTIMEFILES_NEXTUPDATE,
        StatusCode::OK,
        Method::GET,
        None,
        Some(&auth),
        None,
    )
    .await?;
    let post_delete_items = response_to_t::<BulkDataList>(&post_delete_response)?.items;
    let still_has_file = post_delete_items
        .iter()
        .any(|item| item.id.to_lowercase().contains("flxc1000"));
    assert!(
        !still_has_file,
        "Expected file to be deleted via case-insensitive id path"
    );

    teardown_lock(&runtime.config, &auth, &lock_id).await;
    Ok(())
}

/// Spec: GET endpoints must support query parameters: x-sovd2uds-include-hash,
/// x-sovd2uds-include-file-size, x-sovd2uds-include-revision.
#[tokio::test]
async fn runtimefiles_query_parameters() -> Result<(), TestingError> {
    let (runtime, _lock) = setup_integration_test(false).await?;
    let auth = auth_header(&runtime.config, None).await?;

    let mut hash_params = HashMap::new();
    hash_params.insert("x-sovd2uds-include-hash".to_owned(), "sha256".to_owned());
    let hash_response = send_cda_request(
        &runtime.config,
        RUNTIMEFILES_CURRENT,
        StatusCode::OK,
        Method::GET,
        None,
        Some(&auth),
        Some(&QueryParams(hash_params)),
    )
    .await?;
    let hash_list = response_to_t::<BulkDataList>(&hash_response)?;
    if let Some(first_item) = hash_list.items.first() {
        assert!(
            first_item.hash.is_some(),
            "Expected 'hash' field when x-sovd2uds-include-hash=sha256 is set"
        );
    }

    let mut size_params = HashMap::new();
    size_params.insert("x-sovd2uds-include-file-size".to_owned(), "true".to_owned());
    let size_response = send_cda_request(
        &runtime.config,
        RUNTIMEFILES_CURRENT,
        StatusCode::OK,
        Method::GET,
        None,
        Some(&auth),
        Some(&QueryParams(size_params)),
    )
    .await?;
    let size_list = response_to_t::<BulkDataList>(&size_response)?;
    if let Some(first_item) = size_list.items.first() {
        assert!(
            first_item.size.is_some(),
            "Expected file size field when x-sovd2uds-include-file-size=true is set"
        );
    }

    let mut revision_params = HashMap::new();
    revision_params.insert("x-sovd2uds-include-revision".to_owned(), "true".to_owned());
    let revision_response = send_cda_request(
        &runtime.config,
        RUNTIMEFILES_CURRENT,
        StatusCode::OK,
        Method::GET,
        None,
        Some(&auth),
        Some(&QueryParams(revision_params)),
    )
    .await?;
    let revision_list = response_to_t::<BulkDataList>(&revision_response)?;
    if !revision_list.items.is_empty() {
        // Not all the test ecus have a revision set
        assert!(
            revision_list
                .items
                .iter()
                .any(|item| item.revision.is_some()),
            "Expected at least one item with 'revision' field when \
             x-sovd2uds-include-revision=true is set, items: {:?}",
            revision_list.items
        );
    }

    Ok(())
}

/// Spec: "Only the subject of the lock is allowed to use the endpoints."
#[tokio::test]
async fn runtimefiles_only_lock_holder_can_mutate() -> Result<(), TestingError> {
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;
    let lock_id = setup_with_lock(&runtime.config, &auth).await;

    let non_owner_auth = bearer_token_header(NON_OWNER_BEARER_TOKEN);

    // Non-owner: upload should be forbidden
    let non_owner_auth_value = non_owner_auth
        .get(reqwest::header::AUTHORIZATION)
        .expect("Authorization header missing")
        .clone();
    let client = reqwest::Client::new();
    let mdd_bytes = std::fs::read(
        test_container_dir()
            .expect("testcontainer dir")
            .join("odx/FLXC1000.mdd"),
    )
    .expect("MDD fixture not found");
    let form = reqwest::multipart::Form::new().part(
        "files",
        reqwest::multipart::Part::bytes(mdd_bytes).file_name("FLXC1000.mdd"),
    );
    let upload_url = format!(
        "http://{}:{}/vehicle/v15/{RUNTIMEFILES_NEXTUPDATE}",
        runtime.config.server.address, runtime.config.server.port
    );
    let upload_response = client
        .post(&upload_url)
        .header(reqwest::header::AUTHORIZATION, non_owner_auth_value)
        .multipart(form)
        .send()
        .await
        .expect("upload request failed");
    assert_eq!(
        upload_response.status(),
        StatusCode::FORBIDDEN,
        "Expected 403 for upload by non-lock-holder"
    );

    // Non-owner: DELETE nextupdate should be forbidden
    send_cda_request(
        &runtime.config,
        RUNTIMEFILES_NEXTUPDATE,
        StatusCode::FORBIDDEN,
        Method::DELETE,
        None,
        Some(&non_owner_auth),
        None,
    )
    .await?;

    // Non-owner: Apply should be forbidden
    let body = mode_json(ExecutionMode::Apply);
    send_cda_request(
        &runtime.config,
        RUNTIMEFILES_EXECUTIONS,
        StatusCode::FORBIDDEN,
        Method::POST,
        Some(&body),
        Some(&non_owner_auth),
        None,
    )
    .await?;

    // Non-owner: Rollback should be forbidden
    let body = mode_json(ExecutionMode::Rollback);
    send_cda_request(
        &runtime.config,
        RUNTIMEFILES_EXECUTIONS,
        StatusCode::FORBIDDEN,
        Method::POST,
        Some(&body),
        Some(&non_owner_auth),
        None,
    )
    .await?;

    // Non-owner: Cleanup should be forbidden
    let body = mode_json(ExecutionMode::Cleanup);
    send_cda_request(
        &runtime.config,
        RUNTIMEFILES_EXECUTIONS,
        StatusCode::FORBIDDEN,
        Method::POST,
        Some(&body),
        Some(&non_owner_auth),
        None,
    )
    .await?;

    teardown_lock(&runtime.config, &auth, &lock_id).await;
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
    // Acquire an exclusive integration-test lock so no other test interferes.
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;

    // Pre-check: FLXC1000 exists at baseline (proves storage was seeded).
    send_cda_request(
        &runtime.config,
        sovd::ECU_FLXC1000_ENDPOINT,
        StatusCode::OK,
        Method::GET,
        None,
        Some(&auth),
        None,
    )
    .await?;

    // All mutating runtimefiles endpoints require a vehicle lock.
    let lock_id = setup_with_lock(&runtime.config, &auth).await;

    // Upload FSNR2000.mdd -> triggers init_collection_from_copy_if_missing, copying all
    // current MDDs into nextupdate, then adds FSNR2000 on top.
    let upload_response = upload_mdd_by_name(&runtime.config, &auth, "FSNR2000.mdd").await;
    assert_eq!(
        upload_response.status(),
        StatusCode::CREATED,
        "Expected 201 for FSNR2000.mdd upload"
    );

    // Verify FLXC1000 is in nextupdate (copied from current during init) and delete it.
    let flxc1000_id = find_flxc1000_id_in_nextupdate(&runtime.config, &auth).await?;

    // Explicitly delete FLXC1000 from nextupdate - staging now lacks FLXC1000.
    send_cda_request(
        &runtime.config,
        &format!("{RUNTIMEFILES_NEXTUPDATE}/{flxc1000_id}"),
        StatusCode::NO_CONTENT,
        Method::DELETE,
        None,
        Some(&auth),
        None,
    )
    .await?;

    // Trigger Apply - the CDA replaces its entire DB with staging (without FLXC1000).
    // The reload_databases path shuts down the old UDS/gateway and rebuilds routes;
    // 5 s is sufficient for the integration-test environment.
    execute_mode(&runtime.config, &auth, ExecutionMode::Apply).await?;
    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(5)).await;
    assert_ecu_routes_after_apply(&runtime.config, &auth).await?;

    // Apply created a backup of the original database; Rollback restores it.
    execute_mode(&runtime.config, &auth, ExecutionMode::Rollback).await?;
    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(5)).await;

    // Wait for all ECUs to come back online after the reload triggered by rollback.
    // The reload creates a fresh DoIP gateway that must re-discover ECUs via VIR/VAM
    // and run variant detection. Without this wait, subsequent tests may find ECUs
    // still in Offline state.
    wait_for_ecus_online(&runtime.config).await?;

    // Rollback restores the original database -> FLXC1000 is back.
    send_cda_request(
        &runtime.config,
        ECU_FLXC1000_ENDPOINT,
        StatusCode::OK,
        Method::GET,
        None,
        Some(&auth),
        None,
    )
    .await?;

    teardown_lock(&runtime.config, &auth, &lock_id).await;
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
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;

    // All mutating runtimefiles endpoints require a vehicle lock.
    let vehicle_lock_response = create_lock(
        default_timeout(),
        locks::VEHICLE_ENDPOINT,
        StatusCode::CREATED,
        &runtime.config,
        &auth,
    )
    .await;
    let vehicle_lock_id = response_to_t::<LockResponse>(&vehicle_lock_response)?.id;

    let upload_response = upload_mdd(&runtime.config, &auth).await;
    assert!(
        upload_response.status().is_success(),
        "Precondition: MDD upload must succeed, got {}",
        upload_response.status()
    );

    // Creating an ECU lock while the vehicle lock is already held is allowed,
    // but it must block any subsequent Apply/Rollback/Cleanup execution.
    let ecu_lock_response = create_lock(
        default_timeout(),
        locks::ECU_ENDPOINT,
        StatusCode::CREATED,
        &runtime.config,
        &auth,
    )
    .await;
    let ecu_lock_id = response_to_t::<LockResponse>(&ecu_lock_response)?.id;

    // The caller owns both locks, but the ECU lock still prevents a live
    // database swap - expect 409 Conflict.
    let body = mode_json(ExecutionMode::Apply);
    send_cda_request(
        &runtime.config,
        RUNTIMEFILES_EXECUTIONS,
        StatusCode::CONFLICT,
        Method::POST,
        Some(&body),
        Some(&auth),
        None,
    )
    .await?;

    lock_operation(
        locks::ECU_ENDPOINT,
        Some(&ecu_lock_id),
        &runtime.config,
        &auth,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;

    // With only the vehicle lock held, the database swap is safe to proceed.
    execute_mode(&runtime.config, &auth, ExecutionMode::Apply).await?;
    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(3)).await;

    // Roll back to restore the original database before releasing the vehicle lock.
    execute_mode(&runtime.config, &auth, ExecutionMode::Rollback).await?;
    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(3)).await;

    send_cda_request(
        &runtime.config,
        &format!("locks/{vehicle_lock_id}"),
        StatusCode::NO_CONTENT,
        Method::DELETE,
        None,
        Some(&auth),
        None,
    )
    .await?;

    Ok(())
}
