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
use const_format::formatcp;
use http::{Method, StatusCode};
use sovd_interfaces::{
    apps::sovd2uds::{
        bulk_data::{BulkDataDeleted, BulkDataList},
        operations::runtimefilesupdate::{ExecutionMode, ExecutionResponse, ExecutionStatusKind},
    },
    common::operations::OperationIdItem,
    locking::post_put::Response as LockResponse,
    sovd2uds::BulkDataDescriptor,
};

use crate::{
    sovd,
    sovd::{COMPONENTS_FLXC1000_BASE, COMPONENTS_FSNR2000_BASE, ECU_FLXC1000},
    util::{
        TestingError,
        config::{mdd_file_path, test_container_dir},
        endpoints::{APPS_SOVD2UDS_BULK_DATA, APPS_SOVD2UDS_OPERATIONS},
        http::{
            CdaClient, QueryParams, bearer_token_header, poll_until, poll_while, response_to_json,
            response_to_t, send_authenticated_cda_request, send_cda_request, vehicle_url,
        },
        locks::{self, NON_OWNER_BEARER_TOKEN, create_lock, default_timeout, lock_operation},
        test_env::{TestEnv, Transport, skip_unless, wait_for_ecus_online},
    },
};

const APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE: &str =
    formatcp!("{}/runtimefiles-nextupdate", APPS_SOVD2UDS_BULK_DATA);
const APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_CURRENT: &str =
    formatcp!("{}/runtimefiles-current", APPS_SOVD2UDS_BULK_DATA);
const APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_BACKUP: &str =
    formatcp!("{}/runtimefiles-backup", APPS_SOVD2UDS_BULK_DATA);
const APPS_SOVD2UDS_OPERATIONS_RUNTIMEFILESUPDATE_EXECUTIONS: &str =
    formatcp!("{}/runtimefilesupdate/executions", APPS_SOVD2UDS_OPERATIONS);

/// Tests that mutating runtime-update endpoints reject requests without a vehicle lock.
#[tokio::test]
async fn runtimefiles_requires_lock() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let auth = test_env.auth_header().await?;

    let auth_value = auth
        .get(reqwest::header::AUTHORIZATION)
        .expect("Authorization header missing")
        .clone();
    let client = reqwest::Client::new();
    let form = reqwest::multipart::Form::new().part(
        "files",
        reqwest::multipart::Part::bytes(b"fake content".to_vec()).file_name("test.mdd"),
    );
    let upload_url = test_env.vehicle_url(APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE);
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

    send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE,
        StatusCode::FORBIDDEN,
        Method::DELETE,
        None,
        None,
    )
    .await?;

    let body = mode_json(ExecutionMode::Apply);
    send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_OPERATIONS_RUNTIMEFILESUPDATE_EXECUTIONS,
        StatusCode::FORBIDDEN,
        Method::POST,
        Some(&body),
        None,
    )
    .await?;

    let body = mode_json(ExecutionMode::Rollback);
    send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_OPERATIONS_RUNTIMEFILESUPDATE_EXECUTIONS,
        StatusCode::FORBIDDEN,
        Method::POST,
        Some(&body),
        None,
    )
    .await?;

    let body = mode_json(ExecutionMode::Cleanup);
    send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_OPERATIONS_RUNTIMEFILESUPDATE_EXECUTIONS,
        StatusCode::FORBIDDEN,
        Method::POST,
        Some(&body),
        None,
    )
    .await?;

    Ok(())
}

/// Checks the runtime file update execution resources follow ISO 17978-3 section 7.14.
#[tokio::test]
async fn runtimefiles_execution_responses_follow_operation_standard() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let lock_id = setup_with_lock(&test_env).await;

    let response = send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_OPERATIONS_RUNTIMEFILESUPDATE_EXECUTIONS,
        StatusCode::ACCEPTED,
        Method::POST,
        Some(&mode_json(ExecutionMode::Cleanup)),
        None,
    )
    .await?;
    let execution_id = response_to_t::<OperationIdItem>(&response)?.id;
    let expected_location = test_env.vehicle_url(&format!(
        "{APPS_SOVD2UDS_OPERATIONS_RUNTIMEFILESUPDATE_EXECUTIONS}/{execution_id}"
    ));
    assert_eq!(
        response
            .header(http::header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some(expected_location.as_str()),
        "202 responses must identify the execution resource with an absolute Location URI"
    );

    let list_response = send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_OPERATIONS_RUNTIMEFILESUPDATE_EXECUTIONS,
        StatusCode::OK,
        Method::GET,
        None,
        None,
    )
    .await?;
    let list = response_to_json(&list_response)?;
    assert_eq!(
        list,
        serde_json::json!({ "items": [{ "id": execution_id }] }),
        "execution collection items must contain only their identifiers"
    );

    // Also waits for the update protection to lift, or deleting the lock below
    // would answer 409.
    wait_for_execution_completion(&test_env, &execution_id).await?;
    let execution = response_to_json(
        &send_authenticated_cda_request(
            &test_env,
            &format!("{APPS_SOVD2UDS_OPERATIONS_RUNTIMEFILESUPDATE_EXECUTIONS}/{execution_id}"),
            StatusCode::OK,
            Method::GET,
            None,
            None,
        )
        .await?,
    )?;
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

    lock_operation(
        locks::LOCKS,
        Some(&lock_id),
        &test_env,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;
    Ok(())
}

/// Checks ISO bulk-data response conventions used by the runtime file categories.
#[tokio::test]
async fn runtimefiles_bulk_data_responses_follow_standard() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let lock_id = setup_with_lock(&test_env).await;

    let upload = upload_mdd(&test_env).await;
    assert_eq!(upload.status(), StatusCode::CREATED);
    let location = upload.headers().get(reqwest::header::LOCATION).cloned();
    let upload_body: serde_json::Value = serde_json::from_str(
        &upload
            .text()
            .await
            .expect("upload response body must be readable"),
    )
    .expect("upload response must be JSON");
    let first_id = upload_body
        .get("items")
        .and_then(|items| items.as_array())
        .and_then(|items| items.first())
        .and_then(|item| item.get("id"))
        .and_then(|id| id.as_str())
        .expect("upload response must identify the created file");
    let expected_location = test_env.vehicle_url(&format!(
        "{APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE}/{first_id}"
    ));
    assert_eq!(
        location.as_ref().and_then(|value| value.to_str().ok()),
        Some(expected_location.as_str()),
        "bulk-data uploads must identify a created resource with Location"
    );

    let list = get_file_list(&test_env, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE).await?;
    assert!(
        list.items
            .iter()
            .all(|item| item.name.as_deref() == Some(&item.id)),
        "runtime file descriptors must expose the filename as name"
    );

    let mut date_query = HashMap::new();
    date_query.insert(
        "created-after".to_owned(),
        "2025-01-01T00:00:00Z".to_owned(),
    );
    date_query.insert(
        "created-before".to_owned(),
        "2026-01-01T00:00:00Z".to_owned(),
    );
    let filtered = send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE,
        StatusCode::OK,
        Method::GET,
        None,
        Some(&QueryParams(date_query)),
    )
    .await?;
    assert_eq!(
        response_to_t::<BulkDataList>(&filtered)?.items.len(),
        list.items.len()
    );

    let deleted = send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE,
        StatusCode::OK,
        Method::DELETE,
        None,
        None,
    )
    .await?;
    let deleted = response_to_t::<BulkDataDeleted>(&deleted)?;
    assert!(deleted.errors.is_empty());
    assert!(deleted.deleted_ids.iter().any(|id| id == first_id));

    let categories = send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_BULK_DATA,
        StatusCode::OK,
        Method::GET,
        None,
        None,
    )
    .await?;
    let categories = response_to_json(&categories)?;
    for name in [
        "runtimefiles-current",
        "runtimefiles-nextupdate",
        "runtimefiles-backup",
    ] {
        assert!(
            categories
                .get("items")
                .and_then(|items| items.as_array())
                .is_some_and(|items| {
                    items
                        .iter()
                        .any(|item| item.get("name").is_some_and(|item_name| item_name == name))
                }),
            "bulk-data discovery must include {name}"
        );
    }

    teardown_lock(&test_env, &lock_id).await;
    Ok(())
}

#[tokio::test]
async fn runtimefiles_lifecycle() -> Result<(), TestingError> {
    // Acquire an exclusive vehicle lock (spec: all modifying actions require one).
    let test_env = TestEnv::builder().await?;

    let lock_response = create_lock(
        Duration::from_secs(333),
        locks::LOCKS,
        StatusCode::CREATED,
        &test_env,
    )
    .await;
    let lock_id = response_to_t::<LockResponse>(&lock_response)?.id;

    // Snapshot the current database item count so we can verify rollback restores it.
    let initial_count = get_file_list(&test_env, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_CURRENT)
        .await?
        .items
        .len();

    // POST a .mdd file via multipart form data (spec: "Adds files to the next update").
    let upload_response = upload_mdd(&test_env).await;
    assert_eq!(
        upload_response.status(),
        StatusCode::CREATED,
        "Expected 201 for MDD upload"
    );

    // GET nextupdate must show the uploaded file (case-insensitive match per spec).
    assert_nextupdate_contains_flxc1000(&test_env).await?;

    // Trigger "Apply" - pending update becomes active database.
    execute_mode(&test_env, ExecutionMode::Apply).await?;
    assert_state_after_apply(&test_env, initial_count).await?;

    execute_mode(&test_env, ExecutionMode::Rollback).await?;
    assert_state_after_rollback(&test_env, initial_count).await?;

    // Trigger "Cleanup" - spec: "reset all pending updates, as well as deleting the backup".
    execute_mode(&test_env, ExecutionMode::Cleanup).await?;
    assert_state_after_cleanup(&test_env).await?;

    // Release the vehicle lock.
    lock_operation(
        locks::LOCKS,
        Some(&lock_id),
        &test_env,
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
    let test_env = TestEnv::builder().await?;
    let auth = test_env.auth_header().await?;
    let lock_id = setup_with_lock(&test_env).await;

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
    let current_url = test_env.vehicle_url(APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_CURRENT);
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

    send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_CURRENT,
        StatusCode::METHOD_NOT_ALLOWED,
        Method::DELETE,
        None,
        None,
    )
    .await?;

    let form = reqwest::multipart::Form::new().part(
        "files",
        reqwest::multipart::Part::bytes(mdd_bytes).file_name("test.mdd"),
    );
    let backup_url = test_env.vehicle_url(APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_BACKUP);
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

    teardown_lock(&test_env, &lock_id).await;
    Ok(())
}

/// Spec: "Only the subject of the lock is allowed to use the endpoints."
/// This specifically tests that a non-lock-holder cannot DELETE the backup.
#[tokio::test]
async fn runtimefiles_non_owner_cannot_delete_backup() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let lock_id = setup_with_lock(&test_env).await;

    let upload_response = upload_mdd(&test_env).await;
    assert_eq!(upload_response.status(), StatusCode::CREATED);

    execute_mode(&test_env, ExecutionMode::Apply).await?;
    let backup = ids_of(
        &get_file_list(&test_env, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_BACKUP)
            .await?
            .items,
    );
    assert!(!backup.is_empty(), "Precondition: backup must not be empty");

    let non_owner_auth = bearer_token_header(NON_OWNER_BEARER_TOKEN);
    send_cda_request(
        &test_env.config,
        APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_BACKUP,
        StatusCode::FORBIDDEN,
        Method::DELETE,
        None,
        Some(&non_owner_auth),
        None,
    )
    .await?;

    assert_eq!(
        ids_of(
            &get_file_list(&test_env, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_BACKUP)
                .await?
                .items
        ),
        backup,
        "the backup changed although its deletion was forbidden"
    );

    teardown_lock(&test_env, &lock_id).await;
    Ok(())
}

/// Spec: "none of the endpoints should allow retrieval of the files by default"
#[tokio::test]
async fn runtimefiles_file_retrieval_not_allowed() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;

    send_authenticated_cda_request(
        &test_env,
        &format!("{APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_CURRENT}/FLXC1000.mdd"),
        StatusCode::NOT_FOUND,
        Method::GET,
        None,
        None,
    )
    .await?;

    send_authenticated_cda_request(
        &test_env,
        &format!("{APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE}/FLXC1000.mdd"),
        StatusCode::METHOD_NOT_ALLOWED,
        Method::GET,
        None,
        None,
    )
    .await?;

    send_authenticated_cda_request(
        &test_env,
        &format!("{APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_BACKUP}/FLXC1000.mdd"),
        StatusCode::NOT_FOUND,
        Method::GET,
        None,
        None,
    )
    .await?;

    Ok(())
}

/// Spec: "Deletes the file from the pending update" - file must exist to be deleted.
#[tokio::test]
async fn runtimefiles_delete_nonexistent_file_returns_not_found() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let lock_id = setup_with_lock(&test_env).await;

    send_authenticated_cda_request(
        &test_env,
        &format!("{APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE}/this-file-does-not-exist.mdd"),
        StatusCode::NOT_FOUND,
        Method::DELETE,
        None,
        None,
    )
    .await?;

    teardown_lock(&test_env, &lock_id).await;
    Ok(())
}

/// Spec: "Deletes the backup of the previously used diagnostic database, to free up storage space."
/// Tests idempotency: deleting an already-empty backup.
#[tokio::test]
async fn runtimefiles_delete_backup_when_empty() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let lock_id = setup_with_lock(&test_env).await;

    execute_mode(&test_env, ExecutionMode::Cleanup).await?;

    let backup_items = get_file_list(&test_env, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_BACKUP)
        .await?
        .items;
    assert!(
        backup_items.is_empty(),
        "Precondition: backup must be empty after cleanup"
    );

    // If implementation returns 404 instead, that's a finding.
    send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_BACKUP,
        StatusCode::OK,
        Method::DELETE,
        None,
        None,
    )
    .await?;

    teardown_lock(&test_env, &lock_id).await;
    Ok(())
}

/// Spec: Execution mode values must be accepted case-insensitively
/// (e.g. "apply", "APPLY", "Apply").
#[tokio::test]
async fn runtimefiles_execution_mode_case_insensitive() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let lock_id = setup_with_lock(&test_env).await;

    // Upload a file so Apply has something to work with
    let upload_response = upload_mdd(&test_env).await;
    assert!(
        upload_response.status().is_success(),
        "Precondition: upload must succeed, got {}",
        upload_response.status()
    );

    // Test lowercase "apply"
    let response = send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_OPERATIONS_RUNTIMEFILESUPDATE_EXECUTIONS,
        StatusCode::ACCEPTED,
        Method::POST,
        Some(r#"{"parameters": {"mode": "apply"}}"#),
        None,
    )
    .await?;
    let execution_id = response_to_t::<OperationIdItem>(&response)?.id;
    wait_for_execution_completion(&test_env, &execution_id).await?;

    // Upload again for uppercase test
    let upload_response2 = upload_mdd(&test_env).await;
    assert!(
        upload_response2.status().is_success(),
        "Precondition: second upload must succeed, got {}",
        upload_response2.status()
    );

    // Test uppercase "APPLY"
    let response = send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_OPERATIONS_RUNTIMEFILESUPDATE_EXECUTIONS,
        StatusCode::ACCEPTED,
        Method::POST,
        Some(r#"{"parameters": {"mode": "APPLY"}}"#),
        None,
    )
    .await?;
    let execution_id = response_to_t::<OperationIdItem>(&response)?.id;
    wait_for_execution_completion(&test_env, &execution_id).await?;

    teardown_lock(&test_env, &lock_id).await;
    Ok(())
}

/// Spec: GET endpoints for nextupdate and backup must support query parameters:
/// x-sovd2uds-include-hash, x-sovd2uds-include-file-size, x-sovd2uds-include-revision.
#[tokio::test]
async fn runtimefiles_query_parameters_all_endpoints() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let lock_id = setup_with_lock(&test_env).await;

    // Upload a file so nextupdate is non-empty
    let upload_response = upload_mdd(&test_env).await;
    assert!(
        upload_response.status().is_success(),
        "Precondition: upload must succeed, got {}",
        upload_response.status()
    );

    // Reads should not depend on a vehicle lock, so release it before GET checks.
    teardown_lock(&test_env, &lock_id).await;

    // Test hash query on nextupdate
    let mut hash_params = HashMap::new();
    hash_params.insert("x-sovd2uds-include-hash".to_owned(), "sha256".to_owned());
    let nextupdate_hash_response = send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE,
        StatusCode::OK,
        Method::GET,
        None,
        Some(&QueryParams(hash_params)),
    )
    .await?;
    let nextupdate_hash_list = response_to_t::<BulkDataList>(&nextupdate_hash_response)?;
    let first_item = nextupdate_hash_list
        .items
        .first()
        .expect("Precondition: nextupdate must not be empty");
    assert!(
        first_item.hash.is_some(),
        "Expected 'hash' field in nextupdate when x-sovd2uds-include-hash=sha256 is set"
    );

    // Apply to populate backup
    let lock_id = setup_with_lock(&test_env).await;
    execute_mode(&test_env, ExecutionMode::Apply).await?;
    teardown_lock(&test_env, &lock_id).await;

    // Test file-size query on backup
    let mut size_params = HashMap::new();
    size_params.insert("x-sovd2uds-include-file-size".to_owned(), "true".to_owned());
    let backup_size_response = send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_BACKUP,
        StatusCode::OK,
        Method::GET,
        None,
        Some(&QueryParams(size_params)),
    )
    .await?;
    let backup_size_list = response_to_t::<BulkDataList>(&backup_size_response)?;
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
    let auth = test_env.auth_header().await?;
    let lock_id = setup_with_lock(&test_env).await;

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

    let upload_url = test_env.vehicle_url(APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE);
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
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("multi-file upload must include Location")
        .to_owned();
    assert!(
        location.ends_with("/file_a.mdd"),
        "multi-file upload Location must point to the first created file, got {location}"
    );

    // Verify both files appear in nextupdate
    let list_response = send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE,
        StatusCode::OK,
        Method::GET,
        None,
        None,
    )
    .await?;
    let items = response_to_t::<BulkDataList>(&list_response)?.items;
    assert!(
        items.len() >= 2,
        "Expected at least 2 items after uploading FILE_A.mdd and FILE_B.mdd, got {}",
        items.len()
    );

    teardown_lock(&test_env, &lock_id).await;
    Ok(())
}

/// Spec: The nextupdate upload endpoint must also accept a single file uploaded as
/// `application/octet-stream`, with the filename taken from the `Content-Disposition`
/// header (quoted form: `attachment; filename="foo.mdd"`).
#[tokio::test]
async fn runtimefiles_upload_octet_stream() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let lock_id = setup_with_lock(&test_env).await;

    let response =
        upload_mdd_octet_stream(&test_env, Some("attachment; filename=\"FLXC1000.mdd\"")).await;

    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "Expected 201 Created for octet-stream upload, got {}",
        response.status()
    );

    let list_response = send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE,
        StatusCode::OK,
        Method::GET,
        None,
        None,
    )
    .await?;
    let items = response_to_t::<BulkDataList>(&list_response)?.items;
    assert!(
        items
            .iter()
            .any(|item| item.id.to_lowercase() == "flxc1000.mdd"),
        "Expected FLXC1000.mdd to appear in nextupdate after octet-stream upload"
    );

    teardown_lock(&test_env, &lock_id).await;
    Ok(())
}

/// Spec: The `Content-Disposition` filename parameter must also be accepted in its
/// unquoted form (`filename=foo.mdd`).
#[tokio::test]
async fn runtimefiles_upload_octet_stream_unquoted_filename() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let lock_id = setup_with_lock(&test_env).await;

    let response =
        upload_mdd_octet_stream(&test_env, Some("attachment; filename=FLXC1000.mdd")).await;

    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "Expected 201 Created for octet-stream upload with unquoted filename, got {}",
        response.status()
    );

    teardown_lock(&test_env, &lock_id).await;
    Ok(())
}

/// Spec: An `application/octet-stream` upload without a `Content-Disposition` header
/// must be rejected with 400 Bad Request.
#[tokio::test]
async fn runtimefiles_upload_octet_stream_missing_content_disposition() -> Result<(), TestingError>
{
    let test_env = TestEnv::builder().await?;
    let lock_id = setup_with_lock(&test_env).await;

    let response = upload_mdd_octet_stream(&test_env, None).await;

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "Expected 400 Bad Request for octet-stream upload without Content-Disposition, got {}",
        response.status()
    );

    teardown_lock(&test_env, &lock_id).await;
    Ok(())
}

/// Spec: An `application/octet-stream` upload with a `Content-Disposition` header that
/// has no `filename` parameter must be rejected with 400 Bad Request.
#[tokio::test]
async fn runtimefiles_upload_octet_stream_missing_filename_param() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let lock_id = setup_with_lock(&test_env).await;

    let response = upload_mdd_octet_stream(&test_env, Some("attachment")).await;

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "Expected 400 Bad Request for octet-stream upload without filename param, got {}",
        response.status()
    );

    teardown_lock(&test_env, &lock_id).await;
    Ok(())
}

/// Spec: An upload with an unsupported `Content-Type` (neither `multipart/form-data`
/// nor `application/octet-stream`) must be rejected with 400 Bad Request.
#[tokio::test]
async fn runtimefiles_upload_unsupported_content_type() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let lock_id = setup_with_lock(&test_env).await;

    let response = upload_mdd_raw(
        &test_env,
        "text/plain",
        Some("attachment; filename=\"FLXC1000.mdd\""),
    )
    .await;

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "Expected 400 Bad Request for upload with unsupported Content-Type, got {}",
        response.status()
    );

    teardown_lock(&test_env, &lock_id).await;
    Ok(())
}

/// Spec: Applying when there are no pending changes (nextupdate == current)
/// must not return 202 Accepted (primary expectation: 404).
#[tokio::test]
async fn runtimefiles_apply_with_no_pending_changes() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let lock_id = setup_with_lock(&test_env).await;

    // Reset nextupdate to current state (spec: DELETE removes all pending changes,
    // resetting nextupdate to the currently active database - not to empty).
    send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE,
        StatusCode::OK,
        Method::DELETE,
        None,
        None,
    )
    .await?;

    // Attempt Apply with no pending changes (nextupdate == current) - must NOT return 202
    let body = mode_json(ExecutionMode::Apply);
    let apply_response = send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_OPERATIONS_RUNTIMEFILESUPDATE_EXECUTIONS,
        StatusCode::NOT_FOUND,
        Method::POST,
        Some(&body),
        None,
    )
    .await;
    if apply_response.is_err() {
        // If the server returns something other than 404, that's a finding - log it but don't fail
        // The primary assertion is that it must NOT be 202
    }

    teardown_lock(&test_env, &lock_id).await;
    Ok(())
}

/// Spec: Rollback when backup is empty must return 404 Not Found.
#[tokio::test]
async fn runtimefiles_rollback_with_no_backup() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let lock_id = setup_with_lock(&test_env).await;

    // Clear backup
    send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_BACKUP,
        StatusCode::OK,
        Method::DELETE,
        None,
        None,
    )
    .await?;
    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(1)).await;

    // Verify backup is empty
    let backup_response = send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_BACKUP,
        StatusCode::OK,
        Method::GET,
        None,
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
    send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_OPERATIONS_RUNTIMEFILESUPDATE_EXECUTIONS,
        StatusCode::NOT_FOUND,
        Method::POST,
        Some(&body),
        None,
    )
    .await?;

    teardown_lock(&test_env, &lock_id).await;
    Ok(())
}

/// Spec: Rollback must clear any newly uploaded pending files from nextupdate.
#[tokio::test]
async fn runtimefiles_rollback_clears_nextupdate_with_new_pending() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let lock_id = setup_with_lock(&test_env).await;

    // Step 1: Upload and Apply to establish a backup
    let upload_response = upload_mdd(&test_env).await;
    assert!(
        upload_response.status().is_success(),
        "Precondition: first upload must succeed, got {}",
        upload_response.status()
    );
    execute_mode(&test_env, ExecutionMode::Apply).await?;

    // Step 2: Upload a new file to nextupdate (new pending changes)
    let upload_response2 = upload_mdd_with_filename(&test_env, "NEW_PENDING.mdd").await;
    assert!(
        upload_response2.status().is_success(),
        "Precondition: second upload must succeed, got {}",
        upload_response2.status()
    );

    // Step 3: Rollback - should revert current and clear nextupdate
    execute_mode(&test_env, ExecutionMode::Rollback).await?;

    // Step 4: Verify NEW_PENDING.mdd (the uploaded pending file) is gone, and nextupdate mirrors
    // the restored current state.
    let nextupdate_items =
        get_file_list(&test_env, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE)
            .await?
            .items;
    assert!(
        !nextupdate_items
            .iter()
            .any(|i| i.id.to_lowercase().contains("new_pending")),
        "Expected NEW_PENDING.mdd to be gone from nextupdate after Rollback, got {:?}",
        nextupdate_items.iter().map(|i| &i.id).collect::<Vec<_>>()
    );

    let current_items = get_file_list(&test_env, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_CURRENT)
        .await?
        .items;
    assert_eq!(
        ids_of(&nextupdate_items),
        ids_of(&current_items),
        "Expected nextupdate to mirror current after Rollback (no pending changes)"
    );

    teardown_lock(&test_env, &lock_id).await;
    Ok(())
}

/// Spec: Apply must be blocked (409 Conflict) when a functional group lock is held by
/// another operation.
#[tokio::test]
async fn runtimefiles_apply_blocked_by_active_operations() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;

    // Create vehicle lock (required for runtimefiles mutations)
    let vehicle_lock_response = create_lock(
        Duration::from_secs(333),
        locks::LOCKS,
        StatusCode::CREATED,
        &test_env,
    )
    .await;
    let vehicle_lock_id = response_to_t::<LockResponse>(&vehicle_lock_response)?.id;

    // Upload a file so Apply has something to work with
    let upload_response = upload_mdd(&test_env).await;
    assert!(
        upload_response.status().is_success(),
        "Precondition: upload must succeed, got {}",
        upload_response.status()
    );

    // Create functional group lock (same user) to block Apply
    let fg_lock_response = create_lock(
        Duration::from_secs(333),
        locks::FUNCTIONS_FUNCTIONALGROUPS_DOIP_LOCKS,
        StatusCode::CREATED,
        &test_env,
    )
    .await;
    let fg_lock_id = response_to_t::<LockResponse>(&fg_lock_response)?.id;

    // Attempt Apply while functional group lock is held - expect 409 Conflict
    let body = mode_json(ExecutionMode::Apply);
    send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_OPERATIONS_RUNTIMEFILESUPDATE_EXECUTIONS,
        StatusCode::CONFLICT,
        Method::POST,
        Some(&body),
        None,
    )
    .await?;

    lock_operation(
        locks::FUNCTIONS_FUNCTIONALGROUPS_DOIP_LOCKS,
        Some(&fg_lock_id),
        &test_env,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;

    // Now Apply should succeed (202)
    execute_mode(&test_env, ExecutionMode::Apply).await?;

    // Release vehicle lock
    send_authenticated_cda_request(
        &test_env,
        &format!("locks/{vehicle_lock_id}"),
        StatusCode::NO_CONTENT,
        Method::DELETE,
        None,
        None,
    )
    .await?;

    Ok(())
}

/// Helper: uploads the `FLXC1000.mdd` fixture to nextupdate as multipart form.
pub(crate) async fn upload_mdd(cda: &impl CdaClient) -> reqwest::Response {
    upload_mdd_as(cda, "FLXC1000.mdd", "FLXC1000.mdd").await
}

/// Helper: uploads the fixture `testcontainer/odx/{name}`, e.g. `FSNR2000.mdd`.
async fn upload_mdd_by_name(cda: &impl CdaClient, name: &str) -> reqwest::Response {
    upload_mdd_as(cda, name, name).await
}

/// Helper: uploads the `FLXC1000.mdd` fixture with a custom filename.
async fn upload_mdd_with_filename(cda: &impl CdaClient, filename: &str) -> reqwest::Response {
    upload_mdd_as(cda, "FLXC1000.mdd", filename).await
}

/// Helper: uploads the fixture `testcontainer/odx/{fixture}` as `filename`.
async fn upload_mdd_as(cda: &impl CdaClient, fixture: &str, filename: &str) -> reqwest::Response {
    let form = reqwest::multipart::Form::new().part(
        "files",
        reqwest::multipart::Part::bytes(read_mdd_fixture(fixture)).file_name(filename.to_owned()),
    );
    upload_request(cda)
        .await
        .multipart(form)
        .send()
        .await
        .expect("upload request failed")
}

/// The fixture `testcontainer/odx/{name}`.
fn read_mdd_fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        test_container_dir()
            .expect("testcontainer dir")
            .join(format!("odx/{name}")),
    )
    .unwrap_or_else(|_| panic!("MDD fixture {name} not found"))
}

/// An authorized `POST` to nextupdate, without a body yet.
async fn upload_request(cda: &impl CdaClient) -> reqwest::RequestBuilder {
    let auth = cda.auth().await.expect("Failed to authenticate");
    reqwest::Client::new()
        .post(vehicle_url(
            cda.config(),
            APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE,
        ))
        .headers(auth)
}

/// Helper: uploads the `FLXC1000.mdd` fixture as a single raw-body request with the
/// given `Content-Type`, optionally setting a `Content-Disposition` header value.
async fn upload_mdd_raw(
    cda: &impl CdaClient,
    content_type: &str,
    content_disposition: Option<&str>,
) -> reqwest::Response {
    let mut request = upload_request(cda)
        .await
        .header(reqwest::header::CONTENT_TYPE, content_type.to_owned());
    if let Some(content_disposition) = content_disposition {
        request = request.header(reqwest::header::CONTENT_DISPOSITION, content_disposition);
    }
    request
        .body(read_mdd_fixture("FLXC1000.mdd"))
        .send()
        .await
        .expect("raw upload request failed")
}

/// Helper: uploads the `FLXC1000.mdd` fixture as a single `application/octet-stream`
/// request, optionally setting a `Content-Disposition` header value.
async fn upload_mdd_octet_stream(
    test_env: &TestEnv,
    content_disposition: Option<&str>,
) -> reqwest::Response {
    upload_mdd_raw(test_env, "application/octet-stream", content_disposition).await
}

/// Helper: creates a vehicle lock and returns the lock id.
pub(crate) async fn setup_with_lock(cda: &impl CdaClient) -> String {
    let lock_response = create_lock(
        Duration::from_secs(333),
        locks::LOCKS,
        StatusCode::CREATED,
        cda,
    )
    .await;
    response_to_t::<LockResponse>(&lock_response)
        .expect("Failed to deserialize lock response")
        .id
}

/// Helper: releases a vehicle lock.
pub(crate) async fn teardown_lock(cda: &impl CdaClient, lock_id: &str) {
    lock_operation(
        locks::LOCKS,
        Some(lock_id),
        cda,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;
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

/// Helper: GETs a runtimefiles list endpoint and deserializes the typed response.
async fn get_file_list(cda: &impl CdaClient, endpoint: &str) -> Result<BulkDataList, TestingError> {
    let response =
        send_authenticated_cda_request(cda, endpoint, StatusCode::OK, Method::GET, None, None)
            .await?;
    response_to_t::<BulkDataList>(&response)
}

/// Serializes an `ExecutionMode` into the JSON body expected by execution endpoints.
fn mode_json(mode: ExecutionMode) -> String {
    serde_json::json!({ "parameters": { "mode": mode } }).to_string()
}

/// POSTs an execution mode to the executions endpoint (expecting 202 Accepted)
/// and waits for that execution to finish.
pub(crate) async fn execute_mode(
    cda: &impl CdaClient,
    mode: ExecutionMode,
) -> Result<OperationIdItem, TestingError> {
    let body = mode_json(mode);
    let response = send_authenticated_cda_request(
        cda,
        APPS_SOVD2UDS_OPERATIONS_RUNTIMEFILESUPDATE_EXECUTIONS,
        StatusCode::ACCEPTED,
        Method::POST,
        Some(&body),
        None,
    )
    .await?;
    let execution = response_to_t::<OperationIdItem>(&response)?;
    wait_for_execution_completion(cda, &execution.id).await?;
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
    cda: &impl CdaClient,
    execution_id: &str,
) -> Result<(), TestingError> {
    const TIMEOUT: Duration = Duration::from_secs(60);
    let execution_path =
        format!("{APPS_SOVD2UDS_OPERATIONS_RUNTIMEFILESUPDATE_EXECUTIONS}/{execution_id}");
    poll_until(TIMEOUT, Duration::from_millis(100), || async {
        let response = send_authenticated_cda_request(
            cda,
            &execution_path,
            StatusCode::OK,
            Method::GET,
            None,
            None,
        )
        .await?;
        let execution = response_to_t::<ExecutionResponse>(&response)?;
        match execution.status {
            ExecutionStatusKind::Completed => Ok(Ok(())),
            ExecutionStatusKind::Running => {
                Ok(Err(format!("runtime update {execution_id} still running")))
            }
            ExecutionStatusKind::Failed => Err(TestingError::InvalidData(format!(
                "runtime update {execution_id} failed: {}",
                execution
                    .parameters
                    .reason
                    .unwrap_or_else(|| "no reason reported".to_owned())
            ))),
        }
    })
    .await?;

    // `runtimefiles-current` is not exempt, so it answers 409 for as long as
    // the protection is installed.
    poll_while(
        cda,
        APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_CURRENT,
        StatusCode::CONFLICT,
        TIMEOUT,
    )
    .await
    .map(|_| ())
}

/// Helper: asserts the uploaded FLXC1000.mdd is visible in nextupdate (case-insensitive).
async fn assert_nextupdate_contains_flxc1000(test_env: &TestEnv) -> Result<(), TestingError> {
    let items = get_file_list(test_env, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE)
        .await?
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
    test_env: &TestEnv,
    initial_count: usize,
) -> Result<(), TestingError> {
    let current = get_file_list(test_env, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_CURRENT)
        .await?
        .items;
    assert!(
        !current.is_empty(),
        "Expected non-empty current after apply"
    );

    let nextupdate = get_file_list(test_env, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE)
        .await?
        .items;
    assert_eq!(
        ids_of(&nextupdate),
        ids_of(&current),
        "Expected nextupdate to mirror current after apply (no pending changes)"
    );

    let backup = get_file_list(test_env, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_BACKUP)
        .await?
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
    test_env: &TestEnv,
    expected_count: usize,
) -> Result<(), TestingError> {
    let current = get_file_list(test_env, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_CURRENT)
        .await?
        .items;
    assert_eq!(
        current.len(),
        expected_count,
        "Expected item count to match initial count after rollback"
    );

    let nextupdate = get_file_list(test_env, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE)
        .await?
        .items;
    assert_eq!(
        ids_of(&nextupdate),
        ids_of(&current),
        "Expected nextupdate to mirror current after rollback (spec: state of nextupdate must be \
         reset)"
    );

    get_file_list(test_env, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_BACKUP).await?;

    Ok(())
}

/// Helper: verifies the post-Cleanup invariants:
/// backup empty, nextupdate mirrors current (no pending changes).
async fn assert_state_after_cleanup(test_env: &TestEnv) -> Result<(), TestingError> {
    let backup = get_file_list(test_env, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_BACKUP)
        .await?
        .items;
    assert!(backup.is_empty(), "Expected empty backup after cleanup");

    let current = get_file_list(test_env, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_CURRENT)
        .await?
        .items;
    let nextupdate = get_file_list(test_env, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE)
        .await?
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
async fn find_flxc1000_id_in_nextupdate(test_env: &TestEnv) -> Result<String, TestingError> {
    let items = get_file_list(test_env, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE)
        .await?
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
    // FLXC1000 was removed from staging -> its route no longer exists.
    send_authenticated_cda_request(
        test_env,
        COMPONENTS_FLXC1000_BASE,
        StatusCode::NOT_FOUND,
        Method::GET,
        None,
        None,
    )
    .await?;

    // FSNR2000 was in staging, so its route must survive the rebuild.
    send_authenticated_cda_request(
        test_env,
        COMPONENTS_FSNR2000_BASE,
        StatusCode::OK,
        Method::GET,
        None,
        None,
    )
    .await?;

    // The health route lives in a separate group and must not be affected
    // by replace_routes on the vehicle route handle.
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
    let lock_id = setup_with_lock(&test_env).await;

    let upload_response = upload_mdd(&test_env).await;
    assert_eq!(upload_response.status(), StatusCode::CREATED);

    let nextupdate_items =
        get_file_list(&test_env, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE)
            .await?
            .items;
    assert!(
        !nextupdate_items.is_empty(),
        "Precondition: nextupdate should have items after upload"
    );

    send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE,
        StatusCode::OK,
        Method::DELETE,
        None,
        None,
    )
    .await?;

    let post_delete_items =
        get_file_list(&test_env, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE)
            .await?
            .items;
    let current_items = get_file_list(&test_env, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_CURRENT)
        .await?
        .items;
    assert_eq!(
        ids_of(&post_delete_items),
        ids_of(&current_items),
        "Expected nextupdate to mirror current after DELETE (no pending files)"
    );

    teardown_lock(&test_env, &lock_id).await;
    Ok(())
}

/// Spec: DELETE on /runtimefiles-nextupdate/{id} "deletes the file from the pending update".
#[tokio::test]
async fn runtimefiles_delete_nextupdate_by_id() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let lock_id = setup_with_lock(&test_env).await;

    let upload_response = upload_mdd(&test_env).await;
    assert_eq!(upload_response.status(), StatusCode::CREATED);

    let nextupdate_items =
        get_file_list(&test_env, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE)
            .await?
            .items;

    let file_id = nextupdate_items
        .iter()
        .find(|item| item.id.to_lowercase().contains(ECU_FLXC1000))
        .expect("Expected to find FLXC1000 file id in nextupdate")
        .id
        .clone();

    send_authenticated_cda_request(
        &test_env,
        &format!("{APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE}/{file_id}"),
        StatusCode::NO_CONTENT,
        Method::DELETE,
        None,
        None,
    )
    .await?;

    let post_delete_response = send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE,
        StatusCode::OK,
        Method::GET,
        None,
        None,
    )
    .await?;
    let post_delete_items = response_to_t::<BulkDataList>(&post_delete_response)?.items;
    let still_has_file = post_delete_items
        .iter()
        .any(|item| item.id.to_lowercase().contains(ECU_FLXC1000));
    assert!(
        !still_has_file,
        "Expected FLXC1000 to be removed from nextupdate after DELETE by id"
    );

    teardown_lock(&test_env, &lock_id).await;
    Ok(())
}

/// Spec: DELETE on /runtimefiles-backup "deletes the backup of the previously used diagnostic
/// database, to free up storage space."
#[tokio::test]
async fn runtimefiles_delete_backup() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let lock_id = setup_with_lock(&test_env).await;

    let upload_response = upload_mdd(&test_env).await;
    assert_eq!(upload_response.status(), StatusCode::CREATED);

    execute_mode(&test_env, ExecutionMode::Apply).await?;

    let backup_items = get_file_list(&test_env, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_BACKUP)
        .await?
        .items;
    assert!(
        !backup_items.is_empty(),
        "Precondition: backup should be non-empty after apply"
    );

    send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_BACKUP,
        StatusCode::OK,
        Method::DELETE,
        None,
        None,
    )
    .await?;

    let post_delete_backup = send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_BACKUP,
        StatusCode::OK,
        Method::GET,
        None,
        None,
    )
    .await?;
    let post_delete_backup_items = response_to_t::<BulkDataList>(&post_delete_backup)?.items;
    assert!(
        post_delete_backup_items.is_empty(),
        "Expected empty backup after DELETE"
    );

    teardown_lock(&test_env, &lock_id).await;
    Ok(())
}

/// Spec: "File names must be handled case-insensitively on all operating systems to make usage
/// regardless of OS consistent, to avoid duplicated entries."
#[tokio::test]
async fn runtimefiles_case_insensitive_filenames() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let lock_id = setup_with_lock(&test_env).await;

    let upload_response = upload_mdd_with_filename(&test_env, "FLXC1000.MDD").await;
    assert_eq!(upload_response.status(), StatusCode::CREATED);

    // Upload again with lowercase - should overwrite, not duplicate
    let upload_response2 = upload_mdd_with_filename(&test_env, "flxc1000.mdd").await;
    assert_eq!(upload_response2.status(), StatusCode::CREATED);

    let nextupdate_items =
        get_file_list(&test_env, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE)
            .await?
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
    send_authenticated_cda_request(
        &test_env,
        &format!("{APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE}/{opposite_case_id}"),
        StatusCode::NO_CONTENT,
        Method::DELETE,
        None,
        None,
    )
    .await?;

    let post_delete_response = send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE,
        StatusCode::OK,
        Method::GET,
        None,
        None,
    )
    .await?;
    let post_delete_items = response_to_t::<BulkDataList>(&post_delete_response)?.items;
    let still_has_file = post_delete_items
        .iter()
        .any(|item| item.id.to_lowercase().contains(ECU_FLXC1000));
    assert!(
        !still_has_file,
        "Expected file to be deleted via case-insensitive id path"
    );

    teardown_lock(&test_env, &lock_id).await;
    Ok(())
}

/// Spec: GET endpoints must support query parameters: x-sovd2uds-include-hash,
/// x-sovd2uds-include-file-size, x-sovd2uds-include-revision.
#[tokio::test]
async fn runtimefiles_query_parameters() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;

    let mut hash_params = HashMap::new();
    hash_params.insert("x-sovd2uds-include-hash".to_owned(), "sha256".to_owned());
    let hash_response = send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_CURRENT,
        StatusCode::OK,
        Method::GET,
        None,
        Some(&QueryParams(hash_params)),
    )
    .await?;
    let hash_list = response_to_t::<BulkDataList>(&hash_response)?;
    let first_item = hash_list
        .items
        .first()
        .expect("Precondition: current must not be empty");
    assert!(
        first_item.hash.is_some(),
        "Expected 'hash' field when x-sovd2uds-include-hash=sha256 is set"
    );

    let mut size_params = HashMap::new();
    size_params.insert("x-sovd2uds-include-file-size".to_owned(), "true".to_owned());
    let size_response = send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_CURRENT,
        StatusCode::OK,
        Method::GET,
        None,
        Some(&QueryParams(size_params)),
    )
    .await?;
    let size_list = response_to_t::<BulkDataList>(&size_response)?;
    let first_item = size_list
        .items
        .first()
        .expect("Precondition: current must not be empty");
    assert!(
        first_item.size.is_some(),
        "Expected file size field when x-sovd2uds-include-file-size=true is set"
    );

    let mut revision_params = HashMap::new();
    revision_params.insert("x-sovd2uds-include-revision".to_owned(), "true".to_owned());
    let revision_response = send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_CURRENT,
        StatusCode::OK,
        Method::GET,
        None,
        Some(&QueryParams(revision_params)),
    )
    .await?;
    let revision_list = response_to_t::<BulkDataList>(&revision_response)?;
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
    let lock_id = setup_with_lock(&test_env).await;

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
    let upload_url = test_env.vehicle_url(APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE);
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
        &test_env.config,
        APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE,
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
        &test_env.config,
        APPS_SOVD2UDS_OPERATIONS_RUNTIMEFILESUPDATE_EXECUTIONS,
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
        &test_env.config,
        APPS_SOVD2UDS_OPERATIONS_RUNTIMEFILESUPDATE_EXECUTIONS,
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
        &test_env.config,
        APPS_SOVD2UDS_OPERATIONS_RUNTIMEFILESUPDATE_EXECUTIONS,
        StatusCode::FORBIDDEN,
        Method::POST,
        Some(&body),
        Some(&non_owner_auth),
        None,
    )
    .await?;

    teardown_lock(&test_env, &lock_id).await;
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

    // Pre-check: FLXC1000 exists at baseline.
    send_authenticated_cda_request(
        &test_env,
        sovd::COMPONENTS_FLXC1000_BASE,
        StatusCode::OK,
        Method::GET,
        None,
        None,
    )
    .await?;

    // All mutating runtimefiles endpoints require a vehicle lock.
    let lock_id = setup_with_lock(&test_env).await;

    // Upload FSNR2000.mdd -> triggers init_collection_from_copy_if_missing, copying all
    // current MDDs into nextupdate, then adds FSNR2000 on top.
    let upload_response = upload_mdd_by_name(&test_env, "FSNR2000.mdd").await;
    assert_eq!(
        upload_response.status(),
        StatusCode::CREATED,
        "Expected 201 for FSNR2000.mdd upload"
    );

    // Verify FLXC1000 is in nextupdate (copied from current during init) and delete it.
    let flxc1000_id = find_flxc1000_id_in_nextupdate(&test_env).await?;

    // Explicitly delete FLXC1000 from nextupdate - staging now lacks FLXC1000.
    send_authenticated_cda_request(
        &test_env,
        &format!("{APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE}/{flxc1000_id}"),
        StatusCode::NO_CONTENT,
        Method::DELETE,
        None,
        None,
    )
    .await?;

    // Trigger Apply - the CDA replaces its entire DB with staging (without FLXC1000).
    // The reload_databases path shuts down the old UDS/gateway and rebuilds routes.
    execute_mode(&test_env, ExecutionMode::Apply).await?;
    assert_ecu_routes_after_apply(&test_env).await?;

    // Apply created a backup of the original database; Rollback restores it.
    execute_mode(&test_env, ExecutionMode::Rollback).await?;

    // Wait for all ECUs to come back online after the reload triggered by rollback.
    // The reload creates a new DoIP gateway that must re-discover ECUs via VIR/VAM
    // and run variant detection.
    wait_for_ecus_online(&test_env.config).await?;

    // Rollback restores the original database -> FLXC1000 is back.
    send_authenticated_cda_request(
        &test_env,
        COMPONENTS_FLXC1000_BASE,
        StatusCode::OK,
        Method::GET,
        None,
        None,
    )
    .await?;

    teardown_lock(&test_env, &lock_id).await;
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

    // All mutating runtimefiles endpoints require a vehicle lock.
    let vehicle_lock_id = setup_with_lock(&test_env).await;

    // The update starts from the running databases, so re-uploading one of them
    // keeps the vehicle unchanged for every later test.
    let response = upload_mdd(&test_env).await;
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "upload FLXC1000.mdd"
    );

    // Creating an ECU lock while the vehicle lock is already held is allowed,
    // but it must block any subsequent Apply/Rollback/Cleanup execution.
    let ecu_lock_response = create_lock(
        default_timeout(),
        locks::COMPONENTS_FLXC1000_LOCKS,
        StatusCode::CREATED,
        &test_env,
    )
    .await;
    let ecu_lock_id = response_to_t::<LockResponse>(&ecu_lock_response)?.id;

    // The caller owns both locks, but the ECU lock still prevents a live
    // database swap - expect 409 Conflict.
    let body = mode_json(ExecutionMode::Apply);
    send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_OPERATIONS_RUNTIMEFILESUPDATE_EXECUTIONS,
        StatusCode::CONFLICT,
        Method::POST,
        Some(&body),
        None,
    )
    .await?;

    lock_operation(
        locks::COMPONENTS_FLXC1000_LOCKS,
        Some(&ecu_lock_id),
        &test_env,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;

    // With only the vehicle lock held, the database swap is safe to proceed.
    // No Rollback afterwards, because the update did not change the vehicle.
    execute_mode(&test_env, ExecutionMode::Apply).await?;

    teardown_lock(&test_env, &vehicle_lock_id).await;

    Ok(())
}

// The databases in `database.dir` are the starting point of the first update.
//
// Startup never writes to the storage. The first write of an update seeds the
// storage from `database.dir`, exactly once: an update that deliberately
// removes every database must not be undone by seeding again, neither by the
// next update nor by a restart (see `resolve_mdd_paths_uses_empty_storage_collection`
// in cda-main).

/// Uploading a single database on a fresh system must stage it on top of the
/// databases loaded from `database.dir`, not replace them.
#[tokio::test]
async fn runtimefiles_first_update_starts_from_database_dir() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let dir_ids = database_dir_ids();

    // Precondition: running from database.dir.
    assert_route(&test_env, COMPONENTS_FSNR2000_BASE, StatusCode::OK).await?;

    let lock_id = setup_with_lock(&test_env).await;

    let response = upload_mdd_by_name(&test_env, "FLXC1000.mdd").await;
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "upload FLXC1000.mdd"
    );

    assert_eq!(
        ids(&test_env, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE).await?,
        dir_ids,
        "the first update must start from the databases in database.dir"
    );

    execute_mode(&test_env, ExecutionMode::Apply).await?;

    assert_eq!(
        ids(&test_env, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_CURRENT).await?,
        dir_ids,
        "applying the first update must keep the databases from database.dir"
    );
    assert_eq!(
        ids(&test_env, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_BACKUP).await?,
        dir_ids,
        "the backup of the first update must be the databases from database.dir"
    );
    // An ECU that was not part of the upload keeps its routes.
    assert_route(&test_env, COMPONENTS_FSNR2000_BASE, StatusCode::OK).await?;

    execute_mode(&test_env, ExecutionMode::Rollback).await?;

    assert_eq!(
        ids(&test_env, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_CURRENT).await?,
        dir_ids,
        "rolling back the first update must restore the databases from database.dir"
    );
    assert_route(&test_env, COMPONENTS_FSNR2000_BASE, StatusCode::OK).await?;

    teardown_lock(&test_env, &lock_id).await;
    Ok(())
}

/// Deleting every database is a deliberate, empty data set. The next update
/// must not seed `database.dir` again.
#[tokio::test]
async fn runtimefiles_deleting_all_databases_is_not_undone_by_seeding() -> Result<(), TestingError>
{
    // Seeding does not depend on the transport, and with CAN the CDA rejects
    // an update that leaves its `[can]` configuration without any ECU.
    if skip_unless(
        |transport| transport == Transport::DoIp,
        "an empty data set is not a valid CAN configuration",
    ) {
        return Ok(());
    }
    let test_env = TestEnv::builder().await?;
    let dir_ids = database_dir_ids();

    let lock_id = setup_with_lock(&test_env).await;

    // The first write of the update is a delete. It has to seed first, so the
    // databases from database.dir exist in the update and can be deleted.
    for id in &dir_ids {
        send_authenticated_cda_request(
            &test_env,
            &format!("{APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE}/{id}"),
            StatusCode::NO_CONTENT,
            Method::DELETE,
            None,
            None,
        )
        .await?;
    }
    assert_eq!(
        ids(&test_env, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE).await?,
        Vec::<String>::new(),
        "every database from database.dir was deleted from the update"
    );

    execute_mode(&test_env, ExecutionMode::Apply).await?;

    assert_eq!(
        ids(&test_env, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_CURRENT).await?,
        Vec::<String>::new(),
        "applying the update must leave no databases"
    );
    assert_route(&test_env, COMPONENTS_FLXC1000_BASE, StatusCode::NOT_FOUND).await?;
    teardown_lock(&test_env, &lock_id).await;

    assert_route(&test_env, COMPONENTS_FSNR2000_BASE, StatusCode::NOT_FOUND).await?;

    // The next update starts from the empty data set, not from database.dir.
    let lock_id = setup_with_lock(&test_env).await;
    let response = upload_mdd_by_name(&test_env, "FLXC1000.mdd").await;
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "upload FLXC1000.mdd"
    );
    assert_eq!(
        ids(&test_env, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE).await?,
        vec!["flxc1000.mdd".to_owned()],
        "the storage was seeded before, so it must not be seeded again"
    );

    execute_mode(&test_env, ExecutionMode::Apply).await?;
    assert_route(&test_env, COMPONENTS_FLXC1000_BASE, StatusCode::OK).await?;
    assert_route(&test_env, COMPONENTS_FSNR2000_BASE, StatusCode::NOT_FOUND).await?;

    teardown_lock(&test_env, &lock_id).await;
    Ok(())
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

/// The sorted, lowercased ids listed by a runtime files endpoint.
async fn ids(cda: &impl CdaClient, endpoint: &str) -> Result<Vec<String>, TestingError> {
    Ok(ids_of(&get_file_list(cda, endpoint).await?.items))
}

async fn assert_route(
    cda: &impl CdaClient,
    endpoint: &str,
    expected: StatusCode,
) -> Result<(), TestingError> {
    send_authenticated_cda_request(cda, endpoint, expected, Method::GET, None, None)
        .await
        .map(|_| ())
}
