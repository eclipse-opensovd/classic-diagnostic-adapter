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
use opensovd_cda_lib::config::configfile::Configuration;
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
    sovd::{
        COMPONENTS_FLXC1000_BASE, COMPONENTS_FSNR2000_BASE, COMPONENTS_TMCC3000_BASE, ECU_FLXC1000,
        ECU_FSNR2000, FUNCTIONS_FUNCTIONALGROUPS_DOIP_BASE,
    },
    util::{
        TestingError,
        config::{mdd_file_path, test_container_dir},
        endpoints::{APPS_SOVD2UDS_BULK_DATA, APPS_SOVD2UDS_OPERATIONS},
        http::{
            CdaClient, QueryParams, bearer_token_header, extract_field_from_json, poll_until,
            poll_while, response_to_json, response_to_t, send_authenticated_cda_request,
            send_cda_request, send_request, vehicle_url,
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

/// Tests that mutating endpoints return 403 Forbidden unless the caller is the
/// subject of the vehicle lock.
///
/// Spec: "Only the subject of the lock is allowed to use the endpoints."
///
/// The same five mutating operations must be refused in both situations: when
/// no vehicle lock exists at all, and when the lock is held by someone else.
#[tokio::test]
async fn runtimefiles_mutations_require_the_lock_holder() -> Result<(), TestingError> {
    /// Asserts that every mutating runtimefiles operation is refused with 403
    /// for the caller `cda`. `situation` names the setup, so a failure
    /// localizes.
    async fn assert_mutations_forbidden(
        cda: &impl CdaClient,
        situation: &str,
    ) -> Result<(), TestingError> {
        // Multipart upload to nextupdate.
        let form = reqwest::multipart::Form::new().part(
            "files",
            reqwest::multipart::Part::bytes(b"fake content".to_vec()).file_name("test.mdd"),
        );
        let upload_response = upload_request(cda)
            .await
            .multipart(form)
            .send()
            .await
            .expect("upload request failed");
        assert_eq!(
            upload_response.status(),
            StatusCode::FORBIDDEN,
            "Expected 403 for upload ({situation})"
        );

        // DELETE of the whole pending update.
        send_authenticated_cda_request(
            cda,
            APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE,
            StatusCode::FORBIDDEN,
            Method::DELETE,
            None,
            None,
        )
        .await?;

        // Apply, Rollback and Cleanup executions.
        for mode in [
            ExecutionMode::Apply,
            ExecutionMode::Rollback,
            ExecutionMode::Cleanup,
        ] {
            send_authenticated_cda_request(
                cda,
                APPS_SOVD2UDS_OPERATIONS_RUNTIMEFILESUPDATE_EXECUTIONS,
                StatusCode::FORBIDDEN,
                Method::POST,
                Some(&mode_json(mode)),
                None,
            )
            .await?;
        }

        Ok(())
    }

    let test_env = TestEnv::builder().await?;

    // No vehicle lock exists, so even the owner is refused.
    assert_mutations_forbidden(&test_env, "no vehicle lock held").await?;

    // The owner holds the vehicle lock, so a non-owner is refused.
    let lock_id = setup_with_lock(&test_env).await;
    let non_owner_auth = bearer_token_header(NON_OWNER_BEARER_TOKEN);
    assert_mutations_forbidden(
        &test_env.with_headers(&non_owner_auth),
        "vehicle lock held by another subject",
    )
    .await?;

    teardown_lock(&test_env, &lock_id).await;
    Ok(())
}

/// A caller without the vehicle lock is refused for *lacking authorization*, not
/// for the ECU lock that happens to be held.
#[tokio::test]
async fn missing_vehicle_lock_outranks_a_held_ecu_lock() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;

    // Taken without ever holding the vehicle lock: releasing a vehicle lock
    // cascades to the ECU locks under it, so acquiring one directly is the only
    // way to reach "ECU lock held, vehicle lock absent".
    let ecu_lock = create_lock(
        default_timeout(),
        locks::COMPONENTS_FLXC1000_LOCKS,
        StatusCode::CREATED,
        &test_env,
    )
    .await;
    let ecu_lock_id = response_to_t::<LockResponse>(&ecu_lock)?.id;

    send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_OPERATIONS_RUNTIMEFILESUPDATE_EXECUTIONS,
        StatusCode::FORBIDDEN,
        Method::POST,
        Some(&mode_json(ExecutionMode::Apply)),
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
///
/// Spec: "none of the endpoints should allow retrieval of the files by default"
///
/// Spec: "Deletes the file from the pending update" - file must exist to be deleted.
#[tokio::test]
async fn runtimefiles_unsupported_operations_are_rejected() -> Result<(), TestingError> {
    // The retrieval checks below used to run without a vehicle lock. They are
    // read-only, so folding them into the lock-holding setup of the other
    // checks is a deliberate tightening rather than a change of what is
    // asserted.
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

    // Retrieving a single file is not offered by any of the three categories.
    for (endpoint, expected_status, label) in [
        (
            APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_CURRENT,
            StatusCode::NOT_FOUND,
            "current",
        ),
        (
            APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE,
            StatusCode::METHOD_NOT_ALLOWED,
            "nextupdate",
        ),
        (
            APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_BACKUP,
            StatusCode::NOT_FOUND,
            "backup",
        ),
    ] {
        send_authenticated_cda_request(
            &test_env,
            &format!("{endpoint}/FLXC1000.mdd"),
            expected_status,
            Method::GET,
            None,
            None,
        )
        .await
        .map_err(|error| {
            TestingError::InvalidData(format!(
                "Expected {expected_status} for GET of a file in {label}: {error}"
            ))
        })?;
    }

    // Deleting a file that is not part of the pending update is a miss.
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
///
/// Spec: The `Content-Disposition` filename parameter must also be accepted in its
/// unquoted form (`filename=foo.mdd`).
///
/// Spec: An `application/octet-stream` upload without a `Content-Disposition` header
/// must be rejected with 400 Bad Request.
///
/// Spec: An `application/octet-stream` upload with a `Content-Disposition` header that
/// has no `filename` parameter must be rejected with 400 Bad Request.
///
/// Spec: An upload with an unsupported `Content-Type` (neither `multipart/form-data`
/// nor `application/octet-stream`) must be rejected with 400 Bad Request.
#[tokio::test]
async fn runtimefiles_raw_upload_content_type_and_disposition() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let lock_id = setup_with_lock(&test_env).await;

    // (Content-Type, Content-Disposition, expected status, label)
    let cases: &[(&str, Option<&str>, StatusCode, &str)] = &[
        (
            "application/octet-stream",
            Some("attachment; filename=\"FLXC1000.mdd\""),
            StatusCode::CREATED,
            "octet-stream upload with quoted filename",
        ),
        (
            "application/octet-stream",
            Some("attachment; filename=FLXC1000.mdd"),
            StatusCode::CREATED,
            "octet-stream upload with unquoted filename",
        ),
        (
            "application/octet-stream",
            None,
            StatusCode::BAD_REQUEST,
            "octet-stream upload without Content-Disposition",
        ),
        (
            "application/octet-stream",
            Some("attachment"),
            StatusCode::BAD_REQUEST,
            "octet-stream upload without filename param",
        ),
        (
            "text/plain",
            Some("attachment; filename=\"FLXC1000.mdd\""),
            StatusCode::BAD_REQUEST,
            "upload with unsupported Content-Type",
        ),
    ];

    for &(content_type, content_disposition, expected_status, label) in cases {
        let response = upload_mdd_raw(&test_env, content_type, content_disposition).await;
        assert_eq!(
            response.status(),
            expected_status,
            "Expected {expected_status} for {label}, got {}",
            response.status()
        );

        if expected_status == StatusCode::CREATED {
            // An accepted raw upload must show up in the pending update.
            let items = get_file_list(&test_env, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE)
                .await?
                .items;
            assert!(
                items
                    .iter()
                    .any(|item| item.id.to_lowercase() == "flxc1000.mdd"),
                "Expected FLXC1000.mdd to appear in nextupdate after {label}"
            );
        }
    }

    // Hand nextupdate back mirroring current, the successful uploads above staged a file.
    send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE,
        StatusCode::OK,
        Method::DELETE,
        None,
        None,
    )
    .await?;

    teardown_lock(&test_env, &lock_id).await;
    Ok(())
}

/// Spec: Applying when there are no pending changes (nextupdate == current)
/// must not return 202 Accepted (primary expectation: 404).
///
/// Spec: Rollback when backup is empty must return 404 Not Found.
#[tokio::test]
async fn runtimefiles_execution_refused_without_precondition() -> Result<(), TestingError> {
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
    send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_OPERATIONS_RUNTIMEFILESUPDATE_EXECUTIONS,
        StatusCode::NOT_FOUND,
        Method::POST,
        Some(&mode_json(ExecutionMode::Apply)),
        None,
    )
    .await?;

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
    wait_for_empty_backup(&test_env, default_timeout()).await?;

    // Attempt Rollback with empty backup - expect 404
    send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_OPERATIONS_RUNTIMEFILESUPDATE_EXECUTIONS,
        StatusCode::NOT_FOUND,
        Method::POST,
        Some(&mode_json(ExecutionMode::Rollback)),
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

/// Waits until `execution_id` has completed **and** the update's HTTP
/// protection has been lifted, see [`wait_for_execution_terminal`].
///
/// # Errors
/// Returns [`TestingError::InvalidData`] if the execution failed.
async fn wait_for_execution_completion(
    cda: &impl CdaClient,
    execution_id: &str,
) -> Result<(), TestingError> {
    let execution = wait_for_execution_terminal(cda, execution_id).await?;
    match execution.status {
        ExecutionStatusKind::Completed => Ok(()),
        ExecutionStatusKind::Running | ExecutionStatusKind::Failed => {
            Err(TestingError::InvalidData(format!(
                "runtime update {execution_id} did not complete: {}",
                execution
                    .parameters
                    .reason
                    .unwrap_or_else(|| "no reason reported".to_owned())
            )))
        }
    }
}

/// Waits until `execution_id` has finished, completed or failed, **and** the
/// update's HTTP protection has been lifted, and returns the execution.
///
/// Waiting for the status alone is not enough. The update task publishes it,
/// then re-enables communication, and only then drops the protection. Until it
/// does, every non-exempt route answers `409 Update in progress`, including
/// `DELETE /vehicle/v15/locks/{id}`, so a test returning inside that window
/// cannot release its own vehicle lock.
///
/// The execution resource stays readable throughout, being on the exempt list.
async fn wait_for_execution_terminal(
    cda: &impl CdaClient,
    execution_id: &str,
) -> Result<ExecutionResponse, TestingError> {
    const TIMEOUT: Duration = Duration::from_secs(60);
    let execution_path =
        format!("{APPS_SOVD2UDS_OPERATIONS_RUNTIMEFILESUPDATE_EXECUTIONS}/{execution_id}");
    let execution = poll_until(TIMEOUT, Duration::from_millis(100), || async {
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
        Ok(match execution.status {
            ExecutionStatusKind::Running => {
                Err(format!("runtime update {execution_id} still running"))
            }
            ExecutionStatusKind::Completed | ExecutionStatusKind::Failed => Ok(execution),
        })
    })
    .await?;

    // `runtimefiles-current` is not exempt, so it answers 409 for as long as
    // the protection is installed.
    let response = poll_while(
        cda,
        APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_CURRENT,
        StatusCode::CONFLICT,
        TIMEOUT,
    )
    .await?;
    if response.status() != StatusCode::OK {
        return Err(TestingError::InvalidData(format!(
            "unexpected status while waiting for the update protection to lift: {response:?}"
        )));
    }
    Ok(execution)
}

/// POSTs an execution mode to the executions endpoint (expecting 202 Accepted)
/// and waits for it to complete or fail, see [`wait_for_execution_terminal`].
async fn execute_mode_to_terminal(
    cda: &impl CdaClient,
    mode: ExecutionMode,
) -> Result<ExecutionResponse, TestingError> {
    let response = send_authenticated_cda_request(
        cda,
        APPS_SOVD2UDS_OPERATIONS_RUNTIMEFILESUPDATE_EXECUTIONS,
        StatusCode::ACCEPTED,
        Method::POST,
        Some(&mode_json(mode)),
        None,
    )
    .await?;
    let execution = response_to_t::<OperationIdItem>(&response)?;
    wait_for_execution_terminal(cda, &execution.id).await
}

/// Polls an ECU operation execution until it leaves `running`.
///
/// An in-flight operation holds a communication guard, and a runtime update
/// admitted against one is refused with `409 Conflict`. A test that starts an
/// operation and then applies an update has to wait the operation out first,
/// otherwise it races the ECU simulator for that refusal.
async fn wait_for_ecu_operation_terminal(
    cda: &impl CdaClient,
    execution_path: &str,
) -> Result<(), TestingError> {
    poll_until(
        Duration::from_secs(30),
        Duration::from_millis(100),
        || async {
            let response = send_authenticated_cda_request(
                cda,
                execution_path,
                StatusCode::OK,
                Method::GET,
                None,
                None,
            )
            .await?;
            match response_to_json(&response)?
                .get("status")
                .and_then(serde_json::Value::as_str)
            {
                Some("running") => Ok(Err(format!(
                    "operation execution {execution_path} still running"
                ))),
                Some(_) => Ok(Ok(())),
                None => Err(TestingError::InvalidData(format!(
                    "operation execution {execution_path} reported no status"
                ))),
            }
        },
    )
    .await
}

/// Polls the backup collection until it is empty.
///
/// `DELETE` on the backup answers `200` before the removal is necessarily
/// visible to a following read, so asserting emptiness straight after it races
/// the deletion.
async fn wait_for_empty_backup(
    cda: &impl CdaClient,
    timeout: Duration,
) -> Result<(), TestingError> {
    poll_until(timeout, Duration::from_millis(100), || async {
        let items = get_file_list(cda, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_BACKUP)
            .await?
            .items;
        Ok(if items.is_empty() {
            Ok(())
        } else {
            Err(format!("backup still lists {:?}", ids_of(&items)))
        })
    })
    .await
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

/// Helper: verifies live ECU data after Apply (FLXC1000 gone, FSNR2000 present, health ok).
async fn assert_ecu_routes_after_apply(test_env: &TestEnv) -> Result<(), TestingError> {
    // The templated route resolves FLXC1000 against the live ECU set and returns a miss.
    send_authenticated_cda_request(
        test_env,
        COMPONENTS_FLXC1000_BASE,
        StatusCode::NOT_FOUND,
        Method::GET,
        None,
        None,
    )
    .await?;

    // FSNR2000 was in staging, so its live lookup must still succeed.
    send_authenticated_cda_request(
        test_env,
        COMPONENTS_FSNR2000_BASE,
        StatusCode::OK,
        Method::GET,
        None,
        None,
    )
    .await?;

    // Reloading vehicle data must not affect the independently registered health group.
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

    assert_openapi_lists_live_ecus(test_env).await?;

    Ok(())
}

/// Helper: verifies the generated `OpenAPI` document describes exactly the ECU
/// set the router serves after an Apply.
///
/// The document is expanded per request from `uds.get_physical_ecus()`, while
/// `{component_id}` routes resolve through the `EcuContext` extractor. Both read
/// the same live state independently, so asserting only on the routes above
/// would let the published contract drift away from them across a reload.
async fn assert_openapi_lists_live_ecus(cda: &impl CdaClient) -> Result<(), TestingError> {
    let url = reqwest::Url::parse(&format!(
        "http://{}:{}{}",
        cda.config().server.address(),
        cda.config().server.port(),
        cda_sovd::OPENAPI_JSON_ROUTE
    ))
    .expect("invalid openapi.json URL");
    let auth = cda.auth().await?;
    let response = send_request(StatusCode::OK, Method::GET, None, Some(&auth), url).await?;
    let paths = response_to_json(&response)?
        .get("paths")
        .and_then(serde_json::Value::as_object)
        .cloned()
        .ok_or_else(|| TestingError::InvalidData("openapi.json has no paths object".to_owned()))?;

    let surviving = format!("/vehicle/v15/{COMPONENTS_FSNR2000_BASE}");
    for path in [
        surviving.clone(),
        format!("{surviving}/data"),
        format!("{surviving}/faults"),
        format!("{surviving}/locks"),
    ] {
        assert!(
            paths.contains_key(&path),
            "openapi.json must document {path} for the surviving ECU {ECU_FSNR2000}, got {:?}",
            paths.keys().collect::<Vec<_>>()
        );
    }

    let removed = format!("/vehicle/v15/{COMPONENTS_FLXC1000_BASE}");
    let stale: Vec<&String> = paths
        .keys()
        .filter(|path| **path == removed || path.starts_with(&format!("{removed}/")))
        .collect();
    assert!(
        stale.is_empty(),
        "openapi.json must not document the removed ECU {removed}, found {stale:?}"
    );

    let templated: Vec<&String> = paths
        .keys()
        .filter(|path| {
            path.contains("{component_id}")
                || path.contains("{functional_group_id}")
                || path.contains("{*")
        })
        .collect();
    assert!(
        templated.is_empty(),
        "openapi.json must expand every component and functional-group template, found \
         {templated:?}"
    );

    Ok(())
}

/// Spec: DELETE on /runtimefiles-nextupdate/{id} "deletes the file from the pending update".
///
/// Spec: "File names must be handled case-insensitively on all operating systems to make usage
/// regardless of OS consistent, to avoid duplicated entries."
///
/// Spec: DELETE on /runtimefiles-nextupdate removes all pending changes - nextupdate
/// mirrors runtimefiles-current because there are no pending files anymore.
#[tokio::test]
async fn runtimefiles_delete_from_nextupdate() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let lock_id = setup_with_lock(&test_env).await;

    // Deleting by the id exactly as the collection lists it.
    let upload_response = upload_mdd(&test_env).await;
    assert_eq!(upload_response.status(), StatusCode::CREATED);

    let file_id = find_flxc1000_id_in_nextupdate(&test_env).await?;
    send_authenticated_cda_request(
        &test_env,
        &format!("{APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE}/{file_id}"),
        StatusCode::NO_CONTENT,
        Method::DELETE,
        None,
        None,
    )
    .await?;

    let post_delete_items =
        get_file_list(&test_env, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE)
            .await?
            .items;
    assert!(
        !post_delete_items
            .iter()
            .any(|item| item.id.to_lowercase().contains(ECU_FLXC1000)),
        "Expected FLXC1000 to be removed from nextupdate after DELETE by id"
    );

    // Uploading the same name in two cases must not duplicate the entry, and
    // deleting it must work through the opposite-case id.
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

    let post_delete_items =
        get_file_list(&test_env, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE)
            .await?
            .items;
    assert!(
        !post_delete_items
            .iter()
            .any(|item| item.id.to_lowercase().contains(ECU_FLXC1000)),
        "Expected file to be deleted via case-insensitive id path"
    );

    // Deleting the whole collection resets it to the currently active database.
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

/// A staged set that every file of parses but that does not satisfy the
/// configuration fails to build. Recovery must restore the live data and the
/// stored MDD bytes, keep the backup, and return the rejected set to staging.
#[tokio::test]
async fn failed_real_ecu_data_build_restores_live_data_and_mdd_bytes() -> Result<(), TestingError> {
    let mut test_env = TestEnv::builder().await?;

    // The whole vehicle satisfies the configuration, so this start succeeds;
    // the set staged below does not, so its build fails. Recovery restores the
    // still-satisfying live set and returns the rejected set to staging,
    // making this an ordinary failure.
    let mut config = test_env.config.clone();
    require_flxc1000_in_config(&mut config);
    test_env.replace_cda(&config).await?;
    wait_for_ecus_online(&test_env.config).await?;
    let vehicle_lock_id = setup_with_lock(&test_env).await;

    // Puts the live set into the storage, to compare its bytes below.
    stage_full_database(&test_env).await?;
    execute_mode(&test_env, ExecutionMode::Apply).await?;
    wait_for_ecus_online(&test_env.config).await?;
    let original_bytes = storage_file_bytes(&test_env, "diagnostic_database").await?;

    stage_database_without(&test_env, "FLXC1000.mdd").await?;
    let execution = execute_mode_to_terminal(&test_env, ExecutionMode::Apply).await?;
    assert!(
        matches!(execution.status, ExecutionStatusKind::Failed),
        "an update that does not satisfy the configuration must fail, got {execution:?}"
    );

    assert_eq!(
        storage_file_bytes(&test_env, "diagnostic_database").await?,
        original_bytes,
        "a failed build must restore the MDD bytes of the live set"
    );
    send_authenticated_cda_request(
        &test_env,
        COMPONENTS_FLXC1000_BASE,
        StatusCode::OK,
        Method::GET,
        None,
        None,
    )
    .await?;
    let backup = get_file_list(&test_env, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_BACKUP)
        .await?
        .items;
    assert!(
        backup
            .iter()
            .any(|item| item.id.eq_ignore_ascii_case("flxc1000.mdd")),
        "the backup must keep naming the last known good set, got {backup:?}"
    );
    let staged = get_file_list(&test_env, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE)
        .await?
        .items;
    assert!(
        !staged
            .iter()
            .any(|item| item.id.eq_ignore_ascii_case("flxc1000.mdd")),
        "the rejected set must be back in staging, got {staged:?}"
    );

    // The locks of the restored ECU work as before.
    let ecu_lock = create_lock(
        default_timeout(),
        locks::COMPONENTS_FLXC1000_LOCKS,
        StatusCode::CREATED,
        &test_env,
    )
    .await;
    let ecu_lock_id = response_to_t::<LockResponse>(&ecu_lock)?.id;
    lock_operation(
        locks::COMPONENTS_FLXC1000_LOCKS,
        Some(&ecu_lock_id),
        &test_env,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;
    teardown_lock(&test_env, &vehicle_lock_id).await;
    Ok(())
}

/// Like [`failed_real_ecu_data_build_restores_live_data_and_mdd_bytes`], for a
/// rollback to a backup that does not satisfy the configuration.
#[tokio::test]
async fn failed_real_rollback_build_restores_live_data_and_mdd_bytes() -> Result<(), TestingError> {
    let mut test_env = TestEnv::builder().await?;
    let vehicle_lock_id = setup_with_lock(&test_env).await;

    // Leave the reduced set as the rollback candidate and the full set live.
    stage_database_without(&test_env, "FLXC1000.mdd").await?;
    execute_mode(&test_env, ExecutionMode::Apply).await?;
    stage_full_database(&test_env).await?;
    execute_mode(&test_env, ExecutionMode::Apply).await?;
    let live_bytes = storage_file_bytes(&test_env, "diagnostic_database").await?;
    teardown_lock(&test_env, &vehicle_lock_id).await;

    // The live set satisfies the configuration, so this start succeeds; the
    // rollback candidate does not, so the build over it fails. A restore swaps
    // rather than copies, so recovery swaps the live set back. The new CDA
    // starts from the storage of the old one, which holds both sets.
    let mut config = test_env.config.clone();
    require_flxc1000_in_config(&mut config);
    test_env.replace_cda_keeping_storage(&config).await?;
    wait_for_ecus_online(&test_env.config).await?;
    let vehicle_lock_id = setup_with_lock(&test_env).await;

    let execution = execute_mode_to_terminal(&test_env, ExecutionMode::Rollback).await?;
    assert!(
        matches!(execution.status, ExecutionStatusKind::Failed),
        "a rollback that does not satisfy the configuration must fail, got {execution:?}"
    );

    send_authenticated_cda_request(
        &test_env,
        COMPONENTS_FLXC1000_BASE,
        StatusCode::OK,
        Method::GET,
        None,
        None,
    )
    .await?;
    assert_eq!(
        storage_file_bytes(&test_env, "diagnostic_database").await?,
        live_bytes,
        "a failed rollback must restore the MDD bytes of the live set"
    );

    teardown_lock(&test_env, &vehicle_lock_id).await;
    Ok(())
}

/// Proves that after an Apply with a reduced MDD set (FLXC1000 removed from staging),
/// the missing ECU returns 404, the health endpoint remains 204, the `OpenAPI`
/// document follows the live ECU set, and after Rollback the ECU is restored (200).
///
/// Workflow: upload FSNR2000 to trigger staging init from the seeded current collection,
/// then explicitly delete flxc1000.mdd from nextupdate, then Apply.
#[tokio::test]
async fn runtimefiles_apply_updates_live_ecu_set() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;

    // Pre-check: FLXC1000 exists at baseline (proves the baseline database is live).
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

    // Apply installs the staged database without rebuilding the manager, gateway, or routes.
    execute_mode(&test_env, ExecutionMode::Apply).await?;
    assert_ecu_routes_after_apply(&test_env).await?;

    // Apply created a backup of the original database; Rollback restores it.
    execute_mode(&test_env, ExecutionMode::Rollback).await?;

    // The disable and enable cycle makes the persistent gateway rediscover ECUs and
    // run variant detection. Wait so later steps do not observe an offline transition.
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

/// The functional groups follow the live database: removing their MDD empties
/// the listing, and a rollback brings them back.
#[tokio::test]
async fn functional_group_listing_tracks_the_live_database() -> Result<(), TestingError> {
    const FUNCTIONS_FUNCTIONALGROUPS: &str = "functions/functionalgroups";

    let test_env = TestEnv::builder().await?;
    let lock_id = setup_with_lock(&test_env).await;

    stage_full_database(&test_env).await?;
    execute_mode(&test_env, ExecutionMode::Apply).await?;
    assert_route(
        &test_env,
        FUNCTIONS_FUNCTIONALGROUPS_DOIP_BASE,
        StatusCode::OK,
    )
    .await?;

    stage_database_without(&test_env, "functional_groups.mdd").await?;
    execute_mode(&test_env, ExecutionMode::Apply).await?;
    let response = send_authenticated_cda_request(
        &test_env,
        FUNCTIONS_FUNCTIONALGROUPS,
        StatusCode::OK,
        Method::GET,
        None,
        None,
    )
    .await?;
    assert_eq!(
        response_to_json(&response)?.get("items"),
        Some(&serde_json::json!([])),
        "removing the functional groups database must empty the listing"
    );
    assert_route(
        &test_env,
        FUNCTIONS_FUNCTIONALGROUPS_DOIP_BASE,
        StatusCode::NOT_FOUND,
    )
    .await?;

    execute_mode(&test_env, ExecutionMode::Rollback).await?;
    let response = send_authenticated_cda_request(
        &test_env,
        FUNCTIONS_FUNCTIONALGROUPS,
        StatusCode::OK,
        Method::GET,
        None,
        None,
    )
    .await?;
    assert!(
        response_to_json(&response)?
            .get("items")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|items| !items.is_empty()),
        "a rollback must bring the functional groups back"
    );
    assert_route(
        &test_env,
        FUNCTIONS_FUNCTIONALGROUPS_DOIP_BASE,
        StatusCode::OK,
    )
    .await?;

    teardown_lock(&test_env, &lock_id).await;
    Ok(())
}

/// A finished operation execution does not survive a runtime update, not even
/// one whose new database still lists the ECU it ran on.
///
/// Nothing runs across the update: an in-flight operation holds a communication
/// guard, and an update is refused with 409 while one is held. Only the stored
/// `ServiceExecution` record could cross it. That record lives in the
/// `EcuRegistryEntry` a registry lookup returns, which is SOVD bookkeeping, not
/// vehicle data - no ECU survives an update, every `EcuManager` is rebuilt. An
/// update therefore builds a fresh entry for every identity it names, and the
/// still-listed ECU is the case that would be kept if any were, which is why it
/// is the one exercised here.
#[tokio::test]
async fn async_operation_execution_does_not_survive_a_runtime_update() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let executions = format!("{COMPONENTS_FLXC1000_BASE}/operations/calibratesensors/executions");

    let ecu_lock = create_lock(
        default_timeout(),
        locks::COMPONENTS_FLXC1000_LOCKS,
        StatusCode::CREATED,
        &test_env,
    )
    .await;
    let ecu_lock_id = response_to_t::<LockResponse>(&ecu_lock)?.id;

    let execution = send_authenticated_cda_request(
        &test_env,
        &executions,
        StatusCode::ACCEPTED,
        Method::POST,
        Some("{}"),
        None,
    )
    .await?;
    let execution_id: String = extract_field_from_json(&response_to_json(&execution)?, "id")?;
    let execution = format!("{executions}/{execution_id}");

    // The record must be readable before the update, and the operation must be
    // done before the Apply below: an update is refused while its communication
    // guard is held.
    wait_for_ecu_operation_terminal(&test_env, &execution).await?;
    lock_operation(
        locks::COMPONENTS_FLXC1000_LOCKS,
        Some(&ecu_lock_id),
        &test_env,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;

    let vehicle_lock_id = setup_with_lock(&test_env).await;
    stage_full_database(&test_env).await?;
    execute_mode(&test_env, ExecutionMode::Apply).await?;

    // The ECU is still listed, but its entry was replaced along with the
    // databases behind it.
    assert_route(&test_env, &execution, StatusCode::NOT_FOUND).await?;

    stage_database_without(&test_env, "FLXC1000.mdd").await?;
    execute_mode(&test_env, ExecutionMode::Apply).await?;
    assert_route(&test_env, COMPONENTS_FLXC1000_BASE, StatusCode::NOT_FOUND).await?;

    execute_mode(&test_env, ExecutionMode::Rollback).await?;
    wait_for_ecus_online(&test_env.config).await?;
    assert_route(&test_env, &execution, StatusCode::NOT_FOUND).await?;

    // The re-added ECU can be locked again.
    let readded_ecu_lock = create_lock(
        default_timeout(),
        locks::COMPONENTS_FLXC1000_LOCKS,
        StatusCode::CREATED,
        &test_env,
    )
    .await;
    let readded_ecu_lock_id = response_to_t::<LockResponse>(&readded_ecu_lock)?.id;
    lock_operation(
        locks::COMPONENTS_FLXC1000_LOCKS,
        Some(&readded_ecu_lock_id),
        &test_env,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;

    teardown_lock(&test_env, &vehicle_lock_id).await;
    Ok(())
}

/// Apply must be blocked while an ECU lock proves diagnostic work is in progress.
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

/// A held communication guard must refuse a runtime update outright: the update
/// cannot take the exclusive disable lease, so admission fails with
/// `OperationsInProgress` (409) instead of pulling the transport out from under
/// a running operation.
#[tokio::test]
async fn runtimefiles_apply_refused_while_communication_guard_held() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;

    // The vehicle lock authorizes the ECU operation below as well as the update.
    let vehicle_lock_id = setup_with_lock(&test_env).await;
    stage_full_database(&test_env).await?;

    // An async operation execution holds a communication guard until it is deleted.
    let executions = format!("{COMPONENTS_TMCC3000_BASE}/operations/calibratesensors/executions");
    let start_response = send_authenticated_cda_request(
        &test_env,
        &executions,
        StatusCode::ACCEPTED,
        Method::POST,
        Some("{}"),
        None,
    )
    .await?;
    let execution_id: String = extract_field_from_json(&response_to_json(&start_response)?, "id")?;

    let refusal = send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_OPERATIONS_RUNTIMEFILESUPDATE_EXECUTIONS,
        StatusCode::CONFLICT,
        Method::POST,
        Some(&mode_json(ExecutionMode::Apply)),
        None,
    )
    .await?;
    let message: String = extract_field_from_json(&response_to_json(&refusal)?, "message")?;
    assert!(
        message.to_lowercase().contains("operation"),
        "Expected the refusal to name the running operation, got {message:?}"
    );

    // Releasing the guard must be the only thing standing between the same
    // request and a 202, so that the 409 above cannot pass for an unrelated
    // precondition failure.
    let force = QueryParams(HashMap::from_iter([(
        "x-sovd2uds-force".to_string(),
        "true".to_string(),
    )]));
    send_authenticated_cda_request(
        &test_env,
        &format!("{executions}/{execution_id}"),
        StatusCode::OK,
        Method::DELETE,
        None,
        Some(&force),
    )
    .await?;

    execute_mode(&test_env, ExecutionMode::Apply).await?;
    execute_mode(&test_env, ExecutionMode::Cleanup).await?;
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

/// Stages exactly the whole vehicle, every MDD in `database.dir`, discarding
/// whatever is pending, so that applying it brings back the vehicle the CDA
/// started with.
///
/// Requires the caller to hold the vehicle lock.
pub(crate) async fn stage_full_database(cda: &impl CdaClient) -> Result<(), TestingError> {
    stage_database_except(cda, None).await
}

/// Stages every MDD in `database.dir` except `exclude`, so that applying it
/// removes exactly that one database from the vehicle.
///
/// Requires the caller to hold the vehicle lock.
pub(crate) async fn stage_database_without(
    cda: &impl CdaClient,
    exclude: &str,
) -> Result<(), TestingError> {
    stage_database_except(cda, Some(exclude)).await
}

/// Stages every MDD in `database.dir` except `exclude`, and nothing else.
async fn stage_database_except(
    cda: &impl CdaClient,
    exclude: Option<&str>,
) -> Result<(), TestingError> {
    // Start over from the current collection, without the pending changes of
    // a previous step.
    send_authenticated_cda_request(
        cda,
        APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE,
        StatusCode::OK,
        Method::DELETE,
        None,
        None,
    )
    .await?;

    let all = mdd_file_names();
    let staged: Vec<String> = all
        .iter()
        .filter(|name| exclude.is_none_or(|exclude| !name.eq_ignore_ascii_case(exclude)))
        .cloned()
        .collect();
    if let Some(exclude) = exclude {
        assert!(
            !staged.is_empty() && staged.len() != all.len(),
            "Precondition: {exclude} must be one of several fixtures, found {all:?}"
        );
    }

    for name in &staged {
        let response = upload_mdd_by_name(cda, name).await;
        assert_eq!(
            response.status(),
            StatusCode::CREATED,
            "Precondition: staging {name} must succeed"
        );
    }

    // The first write of an update starts from the current collection, so
    // the excluded database, or one from an earlier update, can still be
    // there. Remove everything not staged above.
    let staged_ids: Vec<String> = staged.iter().map(|name| name.to_lowercase()).collect();
    for id in ids(cda, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE).await? {
        if !staged_ids.contains(&id) {
            send_authenticated_cda_request(
                cda,
                &format!("{APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE}/{id}"),
                StatusCode::NO_CONTENT,
                Method::DELETE,
                None,
                None,
            )
            .await?;
        }
    }

    let mut expected = staged_ids;
    expected.sort();
    assert_eq!(
        ids(cda, APPS_SOVD2UDS_BULK_DATA_RUNTIMEFILES_NEXTUPDATE).await?,
        expected,
        "Precondition: staging must hold exactly the requested databases"
    );
    Ok(())
}

/// Configures FLXC1000, which a reduced staged set will not contain, and makes
/// an unmatched per-ECU entry fatal.
///
/// Building a database without that ECU then fails the way it does for an
/// operator whose configuration and pushed database have drifted apart. Unlike
/// an unreadable file, this is not caught by the execution's up-front
/// validation: every staged file parses, they just do not satisfy the
/// configuration.
fn require_flxc1000_in_config(config: &mut Configuration) {
    config.ecu.entry(ECU_FLXC1000.to_owned()).or_default();
    config.strict.ecu_config = true;
}

/// The stored bytes of `flxc1000.mdd` in the storage `collection` of the CDA.
async fn storage_file_bytes(test_env: &TestEnv, collection: &str) -> Result<Vec<u8>, TestingError> {
    test_env
        .read_cda_storage_file(&format!("collections/{collection}/flxc1000.mdd"))
        .await
}
