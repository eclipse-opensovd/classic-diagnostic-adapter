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

use cda_interfaces::{HashMap, HashMapExtensions};
use http::{Method, StatusCode};
use opensovd_cda_lib::config::configfile::{Configuration, EcuConfig};
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
        ECU_FLXC1000_ENDPOINT, ECU_FSNR2000_ENDPOINT, ECU_TMCC3000_ENDPOINT,
        locks::{
            self, NON_OWNER_BEARER_TOKEN, bearer_token_header, create_lock, default_timeout,
            lock_operation,
        },
    },
    util::{
        TestingError,
        http::{
            QueryParams, auth_header, extract_field_from_json, response_to_json, response_to_t,
            send_cda_request, send_request,
        },
        runtime::{
            restart_cda, restart_cda_with_config, setup_integration_test, test_container_dir,
            wait_for_ecus_online, with_temporary_cda,
        },
    },
};

const RUNTIMEFILES_NEXTUPDATE: &str = "apps/sovd2uds/bulk-data/runtimefiles-nextupdate";
const RUNTIMEFILES_CURRENT: &str = "apps/sovd2uds/bulk-data/runtimefiles-current";
const RUNTIMEFILES_BACKUP: &str = "apps/sovd2uds/bulk-data/runtimefiles-backup";
const RUNTIMEFILES_UPDATE_EXECUTIONS: &str =
    "apps/sovd2uds/operations/runtimefilesupdate/executions";

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
async fn wait_for_execution_terminal(
    config: &Configuration,
    auth: &http::HeaderMap,
    execution_id: &str,
    timeout: Duration,
) -> Result<serde_json::Value, TestingError> {
    const POLL_INTERVAL: Duration = Duration::from_millis(100);

    let deadline = std::time::Instant::now()
        .checked_add(timeout)
        .expect("deadline must not overflow");

    loop {
        let response = send_cda_request(
            config,
            &format!("{RUNTIMEFILES_UPDATE_EXECUTIONS}/{execution_id}"),
            StatusCode::OK,
            Method::GET,
            None,
            Some(auth),
            None,
        )
        .await?;
        let execution = response_to_json(&response)?;
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

/// Polls the backup collection until it is empty, and returns once it is.
///
/// `DELETE` on the backup answers `200` before the removal is necessarily
/// visible to a following read, so asserting emptiness straight after it races
/// the deletion.
async fn wait_for_empty_backup(
    config: &Configuration,
    auth: &http::HeaderMap,
    timeout: Duration,
) -> Result<(), TestingError> {
    const POLL_INTERVAL: Duration = Duration::from_millis(100);

    let deadline = std::time::Instant::now()
        .checked_add(timeout)
        .expect("deadline must not overflow");

    loop {
        let response = send_cda_request(
            config,
            RUNTIMEFILES_BACKUP,
            StatusCode::OK,
            Method::GET,
            None,
            Some(auth),
            None,
        )
        .await?;
        if response_to_t::<BulkDataList>(&response)?.items.is_empty() {
            return Ok(());
        }

        assert!(
            std::time::Instant::now() < deadline,
            "backup was not empty within {timeout:?}"
        );
        cda_interfaces::util::tokio_ext::sleep_for(POLL_INTERVAL).await;
    }
}

/// Polls an ECU operation execution until it leaves `running`, and returns once
/// it has.
///
/// An in-flight operation holds a communication guard, and a runtime update
/// admitted against one is refused with `409 Conflict`. A test that starts an
/// operation and then applies an update has to wait the operation out first,
/// otherwise it races the ECU simulator for that refusal.
async fn wait_for_ecu_operation_terminal(
    config: &Configuration,
    auth: &http::HeaderMap,
    execution_path: &str,
) -> Result<(), TestingError> {
    const TIMEOUT: Duration = Duration::from_secs(30);
    const POLL_INTERVAL: Duration = Duration::from_millis(100);

    let deadline = Instant::now()
        .checked_add(TIMEOUT)
        .expect("deadline must not overflow");
    loop {
        let response = send_cda_request(
            config,
            execution_path,
            StatusCode::OK,
            Method::GET,
            None,
            Some(auth),
            None,
        )
        .await?;
        match response_to_json(&response)?
            .get("status")
            .and_then(serde_json::Value::as_str)
        {
            Some("running") => {}
            Some(_) => return Ok(()),
            None => {
                return Err(TestingError::InvalidData(format!(
                    "operation execution {execution_path} reported no status"
                )));
            }
        }

        assert!(
            Instant::now() < deadline,
            "operation execution {execution_path} still running after {TIMEOUT:?}"
        );
        cda_interfaces::util::tokio_ext::sleep_for(POLL_INTERVAL).await;
    }
}

async fn wait_for_update_protection_release(
    config: &Configuration,
    auth: &http::HeaderMap,
) -> Result<(), TestingError> {
    let authorization = auth
        .get(reqwest::header::AUTHORIZATION)
        .ok_or_else(|| TestingError::SetupError("Authorization header missing".to_owned()))?;
    let url = format!(
        "http://{}:{}/vehicle/v15/{RUNTIMEFILES_CURRENT}",
        config.server.address, config.server.port
    );
    #[cfg_attr(
        nightly,
        allow(
            unknown_lints,
            clippy::duration_suboptimal_units,
            reason = "from_mins is not available in Rust 1.88, our MSRV"
        )
    )]
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(60))
        .expect("deadline must not overflow");
    loop {
        let status = reqwest::Client::new()
            .get(&url)
            .header(reqwest::header::AUTHORIZATION, authorization)
            .send()
            .await
            .map_err(|error| TestingError::ProcessFailed(error.to_string()))?
            .status();
        if status == StatusCode::OK {
            return Ok(());
        }
        if status != StatusCode::CONFLICT {
            return Err(TestingError::InvalidData(format!(
                "unexpected status while waiting for update protection release: {status}"
            )));
        }
        assert!(
            Instant::now() < deadline,
            "update protection remained active"
        );
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(100)).await;
    }
}

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
    /// for the caller identified by `auth`. `situation` names the setup, so a
    /// failure localizes.
    async fn assert_mutations_forbidden(
        config: &Configuration,
        auth: &http::HeaderMap,
        situation: &str,
    ) -> Result<(), TestingError> {
        // Multipart upload to nextupdate.
        let auth_value = auth
            .get(reqwest::header::AUTHORIZATION)
            .expect("Authorization header missing")
            .clone();
        let form = reqwest::multipart::Form::new().part(
            "files",
            reqwest::multipart::Part::bytes(b"fake content".to_vec()).file_name("test.mdd"),
        );
        let upload_url = format!(
            "http://{}:{}/vehicle/v15/{RUNTIMEFILES_NEXTUPDATE}",
            config.server.address, config.server.port
        );
        let upload_response = reqwest::Client::new()
            .post(&upload_url)
            .header(reqwest::header::AUTHORIZATION, auth_value)
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
        send_cda_request(
            config,
            RUNTIMEFILES_NEXTUPDATE,
            StatusCode::FORBIDDEN,
            Method::DELETE,
            None,
            Some(auth),
            None,
        )
        .await?;

        // Apply, Rollback and Cleanup executions.
        for mode in [
            ExecutionMode::Apply,
            ExecutionMode::Rollback,
            ExecutionMode::Cleanup,
        ] {
            let body = mode_json(mode);
            send_cda_request(
                config,
                RUNTIMEFILES_UPDATE_EXECUTIONS,
                StatusCode::FORBIDDEN,
                Method::POST,
                Some(&body),
                Some(auth),
                None,
            )
            .await?;
        }

        Ok(())
    }

    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;

    // No vehicle lock exists, so even the owner is refused.
    assert_mutations_forbidden(&runtime.config, &auth, "no vehicle lock held").await?;

    // The owner holds the vehicle lock, so a non-owner is refused.
    let lock_id = setup_with_lock(&runtime.config, &auth).await;
    let non_owner_auth = bearer_token_header(NON_OWNER_BEARER_TOKEN);
    assert_mutations_forbidden(
        &runtime.config,
        &non_owner_auth,
        "vehicle lock held by another subject",
    )
    .await?;

    teardown_lock(&runtime.config, &auth, &lock_id).await;
    Ok(())
}

/// A caller without the vehicle lock is refused for *lacking authorization*, not
/// for the ECU lock that happens to be held.
#[tokio::test]
async fn missing_vehicle_lock_outranks_a_held_ecu_lock() -> Result<(), TestingError> {
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;

    // Taken without ever holding the vehicle lock: releasing a vehicle lock
    // cascades to the ECU locks under it, so acquiring one directly is the only
    // way to reach "ECU lock held, vehicle lock absent".
    let ecu_lock = create_lock(
        default_timeout(),
        locks::ECU_ENDPOINT,
        StatusCode::CREATED,
        &runtime.config,
        &auth,
    )
    .await;
    let ecu_lock_id = response_to_t::<LockResponse>(&ecu_lock)?.id;

    send_cda_request(
        &runtime.config,
        RUNTIMEFILES_UPDATE_EXECUTIONS,
        StatusCode::FORBIDDEN,
        Method::POST,
        Some(&mode_json(ExecutionMode::Apply)),
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
    Ok(())
}

/// Checks the runtime file update execution resources follow ISO 17978-3 section 7.14.
#[tokio::test]
async fn runtimefiles_execution_responses_follow_operation_standard() -> Result<(), TestingError> {
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;
    let lock_id = setup_with_lock(&runtime.config, &auth).await;

    let response = send_cda_request(
        &runtime.config,
        RUNTIMEFILES_UPDATE_EXECUTIONS,
        StatusCode::ACCEPTED,
        Method::POST,
        Some(&mode_json(ExecutionMode::Cleanup)),
        Some(&auth),
        None,
    )
    .await?;
    let execution_id = response_to_t::<OperationIdItem>(&response)?.id;
    let expected_location = format!(
        "http://{}:{}/vehicle/v15/{RUNTIMEFILES_UPDATE_EXECUTIONS}/{execution_id}",
        runtime.config.server.address, runtime.config.server.port
    );
    assert_eq!(
        response
            .header(http::header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some(expected_location.as_str()),
        "202 responses must identify the execution resource with an absolute Location URI"
    );

    let list_response = send_cda_request(
        &runtime.config,
        RUNTIMEFILES_UPDATE_EXECUTIONS,
        StatusCode::OK,
        Method::GET,
        None,
        Some(&auth),
        None,
    )
    .await?;
    let list = response_to_json(&list_response)?;
    assert_eq!(
        list,
        serde_json::json!({ "items": [{ "id": execution_id }] }),
        "execution collection items must contain only their identifiers"
    );

    // Poll until the async execution reaches a terminal status. Reading the
    // status only once here would race the background task and could leave the
    // update-in-progress guard set, causing the lock deletion below to fail
    // with 409 Conflict.
    let execution = wait_for_execution_terminal(
        &runtime.config,
        &auth,
        &execution_id,
        Duration::from_secs(10),
    )
    .await?;
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

/// Checks ISO bulk-data response conventions used by the runtime file categories.
#[tokio::test]
async fn runtimefiles_bulk_data_responses_follow_standard() -> Result<(), TestingError> {
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;
    let lock_id = setup_with_lock(&runtime.config, &auth).await;

    let upload = upload_mdd(&runtime.config, &auth).await;
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
    let expected_location = format!(
        "http://{}:{}/vehicle/v15/{RUNTIMEFILES_NEXTUPDATE}/{first_id}",
        runtime.config.server.address, runtime.config.server.port
    );
    assert_eq!(
        location.as_ref().and_then(|value| value.to_str().ok()),
        Some(expected_location.as_str()),
        "bulk-data uploads must identify a created resource with Location"
    );

    let list = get_file_list(&runtime.config, &auth, RUNTIMEFILES_NEXTUPDATE).await?;
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
    let filtered = send_cda_request(
        &runtime.config,
        RUNTIMEFILES_NEXTUPDATE,
        StatusCode::OK,
        Method::GET,
        None,
        Some(&auth),
        Some(&QueryParams(date_query)),
    )
    .await?;
    assert_eq!(
        response_to_t::<BulkDataList>(&filtered)?.items.len(),
        list.items.len()
    );

    let deleted = send_cda_request(
        &runtime.config,
        RUNTIMEFILES_NEXTUPDATE,
        StatusCode::OK,
        Method::DELETE,
        None,
        Some(&auth),
        None,
    )
    .await?;
    let deleted = response_to_t::<BulkDataDeleted>(&deleted)?;
    assert!(deleted.errors.is_empty());
    assert!(deleted.deleted_ids.iter().any(|id| id == first_id));

    let categories = send_cda_request(
        &runtime.config,
        "apps/sovd2uds/bulk-data",
        StatusCode::OK,
        Method::GET,
        None,
        Some(&auth),
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

    teardown_lock(&runtime.config, &auth, &lock_id).await;
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
    assert_state_after_apply(&runtime.config, &auth, initial_count).await?;

    execute_mode(&runtime.config, &auth, ExecutionMode::Rollback).await?;
    assert_state_after_rollback(&runtime.config, &auth, initial_count).await?;

    // Trigger "Cleanup" - spec: "reset all pending updates, as well as deleting the backup".
    execute_mode(&runtime.config, &auth, ExecutionMode::Cleanup).await?;
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
///
/// Spec: "none of the endpoints should allow retrieval of the files by default"
///
/// Spec: "Deletes the file from the pending update" - file must exist to be deleted.
#[tokio::test]
async fn runtimefiles_unsupported_operations_are_rejected() -> Result<(), TestingError> {
    // The retrieval checks below used to run non-exclusively and without a
    // vehicle lock. They are read-only, so folding them into the exclusive,
    // lock-holding setup of the other two checks is a deliberate tightening
    // rather than a change of what is asserted.
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

    // Retrieving a single file is not offered by any of the three categories.
    for (endpoint, expected_status, label) in [
        (RUNTIMEFILES_CURRENT, StatusCode::NOT_FOUND, "current"),
        (
            RUNTIMEFILES_NEXTUPDATE,
            StatusCode::METHOD_NOT_ALLOWED,
            "nextupdate",
        ),
        (RUNTIMEFILES_BACKUP, StatusCode::NOT_FOUND, "backup"),
    ] {
        send_cda_request(
            &runtime.config,
            &format!("{endpoint}/FLXC1000.mdd"),
            expected_status,
            Method::GET,
            None,
            Some(&auth),
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
        StatusCode::OK,
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
    let response = send_cda_request(
        &runtime.config,
        RUNTIMEFILES_UPDATE_EXECUTIONS,
        StatusCode::ACCEPTED,
        Method::POST,
        Some(r#"{"parameters": {"mode": "apply"}}"#),
        Some(&auth),
        None,
    )
    .await?;
    let execution_id = response_to_t::<OperationIdItem>(&response)?.id;
    wait_for_execution_completion(&runtime.config, &auth, &execution_id).await?;

    // Upload again for uppercase test
    let upload_response2 = upload_mdd(&runtime.config, &auth).await;
    assert!(
        upload_response2.status().is_success(),
        "Precondition: second upload must succeed, got {}",
        upload_response2.status()
    );

    // Test uppercase "APPLY"
    let response = send_cda_request(
        &runtime.config,
        RUNTIMEFILES_UPDATE_EXECUTIONS,
        StatusCode::ACCEPTED,
        Method::POST,
        Some(r#"{"parameters": {"mode": "APPLY"}}"#),
        Some(&auth),
        None,
    )
    .await?;
    let execution_id = response_to_t::<OperationIdItem>(&response)?.id;
    wait_for_execution_completion(&runtime.config, &auth, &execution_id).await?;

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
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;
    let lock_id = setup_with_lock(&runtime.config, &auth).await;

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
        let response =
            upload_mdd_raw(&runtime.config, &auth, content_type, content_disposition).await;
        assert_eq!(
            response.status(),
            expected_status,
            "Expected {expected_status} for {label}, got {}",
            response.status()
        );

        if expected_status == StatusCode::CREATED {
            // An accepted raw upload must show up in the pending update.
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
                items
                    .iter()
                    .any(|item| item.id.to_lowercase() == "flxc1000.mdd"),
                "Expected FLXC1000.mdd to appear in nextupdate after {label}"
            );
        }
    }

    // Hand nextupdate back mirroring current, the successful uploads above staged a file.
    send_cda_request(
        &runtime.config,
        RUNTIMEFILES_NEXTUPDATE,
        StatusCode::OK,
        Method::DELETE,
        None,
        Some(&auth),
        None,
    )
    .await?;

    teardown_lock(&runtime.config, &auth, &lock_id).await;
    Ok(())
}

/// Spec: Applying when there are no pending changes (nextupdate == current)
/// must not return 202 Accepted (primary expectation: 404).
///
/// Spec: Rollback when backup is empty must return 404 Not Found.
#[tokio::test]
async fn runtimefiles_execution_refused_without_precondition() -> Result<(), TestingError> {
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;
    let lock_id = setup_with_lock(&runtime.config, &auth).await;

    // Reset nextupdate to current state (spec: DELETE removes all pending changes,
    // resetting nextupdate to the currently active database - not to empty).
    send_cda_request(
        &runtime.config,
        RUNTIMEFILES_NEXTUPDATE,
        StatusCode::OK,
        Method::DELETE,
        None,
        Some(&auth),
        None,
    )
    .await?;

    // Attempt Apply with no pending changes (nextupdate == current) - must NOT return 202
    let body = mode_json(ExecutionMode::Apply);
    send_cda_request(
        &runtime.config,
        RUNTIMEFILES_UPDATE_EXECUTIONS,
        StatusCode::NOT_FOUND,
        Method::POST,
        Some(&body),
        Some(&auth),
        None,
    )
    .await?;

    // Clear backup
    send_cda_request(
        &runtime.config,
        RUNTIMEFILES_BACKUP,
        StatusCode::OK,
        Method::DELETE,
        None,
        Some(&auth),
        None,
    )
    .await?;
    wait_for_empty_backup(&runtime.config, &auth, default_timeout()).await?;

    // Attempt Rollback with empty backup - expect 404
    let body = mode_json(ExecutionMode::Rollback);
    send_cda_request(
        &runtime.config,
        RUNTIMEFILES_UPDATE_EXECUTIONS,
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

    // Step 4: Verify NEW_PENDING.mdd (the uploaded pending file) is gone, and nextupdate mirrors
    // the restored current state.
    let nextupdate_items = get_file_list(&runtime.config, &auth, RUNTIMEFILES_NEXTUPDATE)
        .await?
        .items;
    assert!(
        !nextupdate_items
            .iter()
            .any(|i| i.id.to_lowercase().contains("new_pending")),
        "Expected NEW_PENDING.mdd to be gone from nextupdate after Rollback, got {:?}",
        nextupdate_items.iter().map(|i| &i.id).collect::<Vec<_>>()
    );

    let current_items = get_file_list(&runtime.config, &auth, RUNTIMEFILES_CURRENT)
        .await?
        .items;
    assert_eq!(
        ids_of(&nextupdate_items),
        ids_of(&current_items),
        "Expected nextupdate to mirror current after Rollback (no pending changes)"
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
        RUNTIMEFILES_UPDATE_EXECUTIONS,
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

/// Helper: uploads the `FLXC1000.mdd` fixture as a single raw-body request with the
/// given `Content-Type`, optionally setting a `Content-Disposition` header value.
async fn upload_mdd_raw(
    config: &Configuration,
    auth: &http::HeaderMap,
    content_type: &str,
    content_disposition: Option<&str>,
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
    let upload_url = format!(
        "http://{}:{}/vehicle/v15/{RUNTIMEFILES_NEXTUPDATE}",
        config.server.address, config.server.port
    );
    let mut request = reqwest::Client::new()
        .post(&upload_url)
        .header(reqwest::header::AUTHORIZATION, auth_value)
        .header(reqwest::header::CONTENT_TYPE, content_type.to_owned());
    if let Some(content_disposition) = content_disposition {
        request = request.header(reqwest::header::CONTENT_DISPOSITION, content_disposition);
    }
    request
        .body(mdd_bytes)
        .send()
        .await
        .expect("raw upload request failed")
}

/// Helper: creates a vehicle lock and returns the lock id.
///
/// TODO(#495): pair this with the matching `teardown_lock` in a guard that
/// releases the lock on every path and waits out an active runtime update
/// protection at both ends. Today an early return leaks the lock, which then
/// fails every later test asserting on lock ownership.
/// <https://github.com/eclipse-opensovd/classic-diagnostic-adapter/issues/495>
pub(crate) async fn setup_with_lock(config: &Configuration, auth: &http::HeaderMap) -> String {
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
pub(crate) async fn teardown_lock(config: &Configuration, auth: &http::HeaderMap, lock_id: &str) {
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

/// Stages the complete MDD fixture set in `runtimefiles-nextupdate`, so that
/// applying that snapshot reproduces the database the CDA is already running.
///
/// Apply is a snapshot swap. The staged collection replaces the active one and
/// anything missing from it is dropped. Uploading a single MDD and letting
/// `init_collection_from_copy_if_missing` seed the rest needs a populated
/// `runtimefiles-current`, which a fresh test container does not have, so it
/// would apply a one-ECU snapshot to the whole shared suite.
///
/// Requires the caller to hold the vehicle lock.
pub(crate) async fn stage_full_database(
    config: &Configuration,
    auth: &http::HeaderMap,
) -> Result<(), TestingError> {
    // Start from an empty staging collection so the applied snapshot is exactly
    // the fixture set, not whatever a previous test left pending.
    send_cda_request(
        config,
        RUNTIMEFILES_NEXTUPDATE,
        StatusCode::OK,
        Method::DELETE,
        None,
        Some(auth),
        None,
    )
    .await?;

    for name in mdd_file_names() {
        let response = upload_mdd_by_name(config, auth, &name).await;
        assert_eq!(
            response.status(),
            StatusCode::CREATED,
            "Precondition: staging {name} must succeed"
        );
    }
    Ok(())
}

/// The file names of every MDD the test container ships, i.e. the whole vehicle.
///
/// Read from disk rather than hard-coded, so that a fixture added later ends up
/// in the staged snapshot instead of silently disappearing from the vehicle.
fn mdd_file_names() -> Vec<String> {
    let odx_dir = test_container_dir().expect("testcontainer dir").join("odx");
    let names: Vec<String> = std::fs::read_dir(&odx_dir)
        .expect("MDD directory not readable")
        .filter_map(|entry| Some(entry.ok()?.file_name().to_string_lossy().into_owned()))
        .filter(|name| name.to_lowercase().ends_with(".mdd"))
        .collect();
    assert!(
        names.len() > 1,
        "expected the MDD directory {} to hold the whole vehicle, found {names:?}",
        odx_dir.display()
    );
    names
}

/// Configures an ECU that a reduced staged set will not contain, and makes an
/// unmatched per-ECU entry fatal.
///
/// Building a database without that ECU then fails the way it does for an
/// operator whose configuration and pushed database have drifted apart. Unlike
/// an unreadable file, this is not caught by the execution's up-front
/// validation: every staged file parses, they just do not satisfy the
/// configuration.
fn require_flxc1000_in_config(config: &mut Configuration) {
    config
        .ecu
        .insert("FLXC1000".to_owned(), EcuConfig::default());
    config.strict.ecu_config = true;
}

fn storage_file_bytes(config: &Configuration, collection: &str) -> Result<Vec<u8>, TestingError> {
    let use_docker = std::env::var("CDA_INTEGRATION_TEST_USE_DOCKER").map_or(true, |v| v == "true");
    if use_docker {
        let output = std::process::Command::new("docker")
            .args([
                "compose",
                "exec",
                "-T",
                "cda",
                "cat",
                &format!("/app/collections/{collection}/flxc1000.mdd"),
            ])
            .current_dir(test_container_dir()?)
            .output()
            .map_err(|error| TestingError::ProcessFailed(error.to_string()))?;
        if !output.status.success() {
            return Err(TestingError::ProcessFailed(
                String::from_utf8_lossy(&output.stderr).into_owned(),
            ));
        }
        return Ok(output.stdout);
    }
    std::fs::read(
        std::path::Path::new(&config.runtime_update_config.storage_dir)
            .join("collections")
            .join(collection)
            .join("flxc1000.mdd"),
    )
    .map_err(|error| TestingError::ProcessFailed(error.to_string()))
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
    serde_json::json!({ "parameters": { "mode": mode } }).to_string()
}

/// POSTs an execution mode and returns either completed or failed terminal state.
#[cfg_attr(
    nightly,
    allow(
        unknown_lints,
        clippy::duration_suboptimal_units,
        reason = "from_mins is not available in Rust 1.88, our MSRV"
    )
)]
async fn execute_mode_to_terminal(
    config: &Configuration,
    auth: &http::HeaderMap,
    mode: ExecutionMode,
) -> Result<serde_json::Value, TestingError> {
    let response = send_cda_request(
        config,
        RUNTIMEFILES_UPDATE_EXECUTIONS,
        StatusCode::ACCEPTED,
        Method::POST,
        Some(&mode_json(mode)),
        Some(auth),
        None,
    )
    .await?;
    let execution = response_to_t::<OperationIdItem>(&response)?;
    wait_for_execution_terminal(config, auth, &execution.id, Duration::from_secs(60)).await
}

/// POSTs an execution mode to the executions endpoint (expecting 202 Accepted)
/// and waits for that execution to finish.
pub(crate) async fn execute_mode(
    config: &Configuration,
    auth: &http::HeaderMap,
    mode: ExecutionMode,
) -> Result<OperationIdItem, TestingError> {
    let body = mode_json(mode);
    let response = send_cda_request(
        config,
        RUNTIMEFILES_UPDATE_EXECUTIONS,
        StatusCode::ACCEPTED,
        Method::POST,
        Some(&body),
        Some(auth),
        None,
    )
    .await?;
    let execution = response_to_t::<OperationIdItem>(&response)?;
    wait_for_execution_completion(config, auth, &execution.id).await?;
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
    config: &Configuration,
    auth: &http::HeaderMap,
    execution_id: &str,
) -> Result<(), TestingError> {
    #[cfg_attr(
        nightly,
        allow(
            unknown_lints,
            clippy::duration_suboptimal_units,
            reason = "from_mins is not available in Rust 1.88, our MSRV"
        )
    )]
    const TIMEOUT: Duration = Duration::from_secs(60);

    let deadline = Instant::now()
        .checked_add(TIMEOUT)
        .ok_or_else(|| TestingError::SetupError("timeout overflowed Instant".to_owned()))?;
    let execution_path = format!("{RUNTIMEFILES_UPDATE_EXECUTIONS}/{execution_id}");
    loop {
        let response = send_cda_request(
            config,
            &execution_path,
            StatusCode::OK,
            Method::GET,
            None,
            Some(auth),
            None,
        )
        .await?;
        let execution = response_to_t::<ExecutionResponse>(&response)?;
        match execution.status {
            ExecutionStatusKind::Completed => break,
            ExecutionStatusKind::Running => {}
            ExecutionStatusKind::Failed => {
                return Err(TestingError::InvalidData(format!(
                    "runtime update {execution_id} did not complete: {}",
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
    // the protection is installed.
    let authorization = auth
        .get(reqwest::header::AUTHORIZATION)
        .ok_or_else(|| TestingError::SetupError("Authorization header missing".to_owned()))?;
    let url = format!(
        "http://{}:{}/vehicle/v15/{RUNTIMEFILES_CURRENT}",
        config.server.address, config.server.port
    );
    let client = reqwest::Client::new();
    loop {
        let status = client
            .get(&url)
            .header(reqwest::header::AUTHORIZATION, authorization)
            .send()
            .await
            .map_err(|error| TestingError::ProcessFailed(error.to_string()))?
            .status();
        if status != StatusCode::CONFLICT {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(TestingError::Timeout(format!(
                "update protection still active {TIMEOUT:?} after {execution_id} completed"
            )));
        }
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(100)).await;
    }
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
/// current non-empty, nextupdate mirrors current (no pending changes), and backup matches the
/// original current snapshot.
async fn assert_state_after_apply(
    config: &Configuration,
    auth: &http::HeaderMap,
    initial_count: usize,
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
    assert_eq!(
        ids_of(&nextupdate),
        ids_of(&current),
        "Expected nextupdate to mirror current after apply (no pending changes)"
    );

    let backup = get_file_list(config, auth, RUNTIMEFILES_BACKUP)
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
    assert_eq!(
        ids_of(&nextupdate),
        ids_of(&current),
        "Expected nextupdate to mirror current after rollback (spec: state of nextupdate must be \
         reset)"
    );

    get_file_list(config, auth, RUNTIMEFILES_BACKUP).await?;

    Ok(())
}

/// Helper: verifies the post-Cleanup invariants:
/// backup empty, nextupdate mirrors current (no pending changes).
async fn assert_state_after_cleanup(
    config: &Configuration,
    auth: &http::HeaderMap,
) -> Result<(), TestingError> {
    let backup = get_file_list(config, auth, RUNTIMEFILES_BACKUP)
        .await?
        .items;
    assert!(backup.is_empty(), "Expected empty backup after cleanup");

    let current = get_file_list(config, auth, RUNTIMEFILES_CURRENT)
        .await?
        .items;
    let nextupdate = get_file_list(config, auth, RUNTIMEFILES_NEXTUPDATE)
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

/// Helper: verifies live ECU data after Apply (FLXC1000 gone, FSNR2000 present, health ok).
async fn assert_ecu_routes_after_apply(
    config: &Configuration,
    auth: &http::HeaderMap,
) -> Result<(), TestingError> {
    // The templated route resolves FLXC1000 against the live ECU set and returns a miss.
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

    // FSNR2000 was in staging, so its live lookup must still succeed.
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

    // Reloading vehicle data must not affect the independently registered health group.
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

    assert_openapi_lists_live_ecus(config, auth).await?;

    Ok(())
}

/// Helper: verifies the generated `OpenAPI` document describes exactly the ECU
/// set the router serves after an Apply.
///
/// The document is expanded per request from `uds.get_physical_ecus()`, while
/// `{component_id}` routes resolve through the `EcuContext` extractor. Both read
/// the same live state independently, so asserting only on the routes above
/// would let the published contract drift away from them across a reload.
async fn assert_openapi_lists_live_ecus(
    config: &Configuration,
    auth: &http::HeaderMap,
) -> Result<(), TestingError> {
    let url = reqwest::Url::parse(&format!(
        "http://{}:{}{}",
        config.server.address,
        config.server.port,
        cda_sovd::OPENAPI_JSON_ROUTE
    ))
    .expect("invalid openapi.json URL");
    let response = send_request(StatusCode::OK, Method::GET, None, Some(auth), url).await?;
    let paths = response_to_json(&response)?
        .get("paths")
        .and_then(serde_json::Value::as_object)
        .cloned()
        .ok_or_else(|| TestingError::InvalidData("openapi.json has no paths object".to_owned()))?;

    let surviving = format!("/vehicle/v15/{ECU_FSNR2000_ENDPOINT}");
    for path in [
        surviving.clone(),
        format!("{surviving}/data"),
        format!("{surviving}/faults"),
        format!("{surviving}/locks"),
    ] {
        assert!(
            paths.contains_key(&path),
            "openapi.json must document {path} for the surviving ECU, got {:?}",
            paths.keys().collect::<Vec<_>>()
        );
    }

    let removed = format!("/vehicle/v15/{ECU_FLXC1000_ENDPOINT}");
    let stale: Vec<&String> = paths
        .keys()
        .filter(|path| path.starts_with(&removed))
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
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;
    let lock_id = setup_with_lock(&runtime.config, &auth).await;

    // Deleting by the id exactly as the collection lists it.
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

    let post_delete_items = get_file_list(&runtime.config, &auth, RUNTIMEFILES_NEXTUPDATE)
        .await?
        .items;
    assert!(
        !post_delete_items
            .iter()
            .any(|item| item.id.to_lowercase().contains("flxc1000")),
        "Expected FLXC1000 to be removed from nextupdate after DELETE by id"
    );

    // Uploading the same name in two cases must not duplicate the entry, and
    // deleting it must work through the opposite-case id.
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

    let post_delete_items = get_file_list(&runtime.config, &auth, RUNTIMEFILES_NEXTUPDATE)
        .await?
        .items;
    assert!(
        !post_delete_items
            .iter()
            .any(|item| item.id.to_lowercase().contains("flxc1000")),
        "Expected file to be deleted via case-insensitive id path"
    );

    // Deleting the whole collection resets it to the currently active database.
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
        StatusCode::OK,
        Method::DELETE,
        None,
        Some(&auth),
        None,
    )
    .await?;

    let post_delete_items = get_file_list(&runtime.config, &auth, RUNTIMEFILES_NEXTUPDATE)
        .await?
        .items;
    let current_items = get_file_list(&runtime.config, &auth, RUNTIMEFILES_CURRENT)
        .await?
        .items;
    assert_eq!(
        ids_of(&post_delete_items),
        ids_of(&current_items),
        "Expected nextupdate to mirror current after DELETE (no pending files)"
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
        StatusCode::OK,
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

#[tokio::test]
async fn failed_real_ecu_data_build_restores_live_data_and_mdd_bytes() -> Result<(), TestingError> {
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;
    let vehicle_lock_id = setup_with_lock(&runtime.config, &auth).await;

    stage_full_database(&runtime.config, &auth).await?;
    execute_mode(&runtime.config, &auth, ExecutionMode::Apply).await?;
    wait_for_ecus_online(&runtime.config).await?;
    let original_bytes = storage_file_bytes(&runtime.config, "diagnostic_database")?;
    teardown_lock(&runtime.config, &auth, &vehicle_lock_id).await;

    // The live set still satisfies the configuration, so this start succeeds;
    // the set staged below does not, so its build fails. Recovery restores the
    // still-satisfying backup and returns the rejected set to staging, making
    // this an ordinary failure.
    restart_cda_with_config(&runtime.config, require_flxc1000_in_config).await?;
    wait_for_ecus_online(&runtime.config).await?;
    let vehicle_lock_id = setup_with_lock(&runtime.config, &auth).await;

    stage_database_without(&runtime.config, &auth, "FLXC1000.mdd").await?;
    let execution = execute_mode_to_terminal(&runtime.config, &auth, ExecutionMode::Apply).await?;
    assert_eq!(execution.get("status"), Some(&serde_json::json!("failed")));
    wait_for_update_protection_release(&runtime.config, &auth).await?;

    assert_eq!(
        storage_file_bytes(&runtime.config, "diagnostic_database")?,
        original_bytes
    );
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
    let backup = get_file_list(&runtime.config, &auth, RUNTIMEFILES_BACKUP)
        .await?
        .items;
    assert!(
        backup
            .iter()
            .any(|item| item.id.eq_ignore_ascii_case("flxc1000.mdd")),
        "the backup must keep naming the last known good set, got {backup:?}"
    );
    let staged = get_file_list(&runtime.config, &auth, RUNTIMEFILES_NEXTUPDATE)
        .await?
        .items;
    assert!(
        !staged
            .iter()
            .any(|item| item.id.eq_ignore_ascii_case("flxc1000.mdd")),
        "the rejected set must be back in staging, got {staged:?}"
    );

    let ecu_lock = create_lock(
        default_timeout(),
        locks::ECU_ENDPOINT,
        StatusCode::CREATED,
        &runtime.config,
        &auth,
    )
    .await;
    let ecu_lock_id = response_to_t::<LockResponse>(&ecu_lock)?.id;
    lock_operation(
        locks::ECU_ENDPOINT,
        Some(&ecu_lock_id),
        &runtime.config,
        &auth,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;
    teardown_lock(&runtime.config, &auth, &vehicle_lock_id).await;
    // Hand the shared configuration back to the next test.
    restart_cda(&runtime.config).await?;
    wait_for_ecus_online(&runtime.config).await?;
    Ok(())
}

#[tokio::test]
async fn failed_real_rollback_build_restores_live_data_and_mdd_bytes() -> Result<(), TestingError> {
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;
    let vehicle_lock_id = setup_with_lock(&runtime.config, &auth).await;

    // Leave the reduced set as the rollback candidate and the full set live.
    stage_database_without(&runtime.config, &auth, "FLXC1000.mdd").await?;
    execute_mode(&runtime.config, &auth, ExecutionMode::Apply).await?;
    stage_full_database(&runtime.config, &auth).await?;
    execute_mode(&runtime.config, &auth, ExecutionMode::Apply).await?;
    let live_bytes = storage_file_bytes(&runtime.config, "diagnostic_database")?;
    teardown_lock(&runtime.config, &auth, &vehicle_lock_id).await;

    // The live set satisfies the configuration, so this start succeeds; the
    // rollback candidate does not, so the build over it fails. A restore swaps
    // rather than copies, so recovery swaps the live set back.
    restart_cda_with_config(&runtime.config, require_flxc1000_in_config).await?;
    wait_for_ecus_online(&runtime.config).await?;
    let vehicle_lock_id = setup_with_lock(&runtime.config, &auth).await;

    let execution =
        execute_mode_to_terminal(&runtime.config, &auth, ExecutionMode::Rollback).await?;
    assert_eq!(execution.get("status"), Some(&serde_json::json!("failed")));
    wait_for_update_protection_release(&runtime.config, &auth).await?;

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
    assert_eq!(
        storage_file_bytes(&runtime.config, "diagnostic_database")?,
        live_bytes
    );

    teardown_lock(&runtime.config, &auth, &vehicle_lock_id).await;
    restart_cda(&runtime.config).await?;
    wait_for_ecus_online(&runtime.config).await?;
    Ok(())
}

/// An applied empty database set is durable: the storage collection stays
/// authoritative across a restart, so nothing reseeds the deleted databases
/// from the configured database directory.
#[tokio::test]
async fn applied_empty_snapshot_survives_restart() -> Result<(), TestingError> {
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;
    let vehicle_lock_id = setup_with_lock(&runtime.config, &auth).await;

    stage_empty_database(&runtime.config, &auth).await?;
    execute_mode(&runtime.config, &auth, ExecutionMode::Apply).await?;
    assert!(
        get_file_list(&runtime.config, &auth, RUNTIMEFILES_CURRENT)
            .await?
            .items
            .is_empty()
    );
    send_cda_request(
        &runtime.config,
        ECU_FLXC1000_ENDPOINT,
        StatusCode::NOT_FOUND,
        Method::GET,
        None,
        Some(&auth),
        None,
    )
    .await?;

    teardown_lock(&runtime.config, &auth, &vehicle_lock_id).await;

    // The restart finds no database in storage and must not reseed one, so it
    // needs a configuration that tolerates an empty vehicle.
    let mut empty_vehicle_config = runtime.config.clone();
    empty_vehicle_config.database.exit_no_database_loaded = false;

    with_temporary_cda(
        &runtime.config,
        empty_vehicle_config,
        || async {},
        || async {
            assert!(
                get_file_list(&runtime.config, &auth, RUNTIMEFILES_CURRENT)
                    .await
                    .expect("Failed to list the current runtime files")
                    .items
                    .is_empty(),
                "the restart must not reseed the emptied collection"
            );
            send_cda_request(
                &runtime.config,
                ECU_FLXC1000_ENDPOINT,
                StatusCode::NOT_FOUND,
                Method::GET,
                None,
                Some(&auth),
                None,
            )
            .await
            .expect("The vehicle must still be empty after the restart");

            // Restore the full vehicle so the shared CDA, which exits without a
            // database, comes back up for the following tests.
            let lock_id = setup_with_lock(&runtime.config, &auth).await;
            stage_full_database(&runtime.config, &auth)
                .await
                .expect("Failed to stage the full database");
            execute_mode(&runtime.config, &auth, ExecutionMode::Apply)
                .await
                .expect("Failed to apply the full database");
            teardown_lock(&runtime.config, &auth, &lock_id).await;
        },
    )
    .await;

    wait_for_ecus_online(&runtime.config).await?;
    Ok(())
}

#[tokio::test]
async fn runtimefiles_apply_updates_live_ecu_set() -> Result<(), TestingError> {
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

    // Apply installs the staged database without rebuilding the manager, gateway, or routes.
    execute_mode(&runtime.config, &auth, ExecutionMode::Apply).await?;
    assert_ecu_routes_after_apply(&runtime.config, &auth).await?;

    // Apply created a backup of the original database; Rollback restores it.
    execute_mode(&runtime.config, &auth, ExecutionMode::Rollback).await?;

    // The disable and enable cycle makes the persistent gateway rediscover ECUs and
    // run variant detection. Wait so later tests do not observe an offline transition.
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

#[tokio::test]
async fn functional_group_listing_tracks_the_live_database() -> Result<(), TestingError> {
    const GROUPS_ENDPOINT: &str = "functions/functionalgroups";
    const GROUP_ENDPOINT: &str = "functions/functionalgroups/fgl_uds_ethernet_doip_dobt";

    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;
    let lock_id = setup_with_lock(&runtime.config, &auth).await;

    stage_full_database(&runtime.config, &auth).await?;
    execute_mode(&runtime.config, &auth, ExecutionMode::Apply).await?;
    send_cda_request(
        &runtime.config,
        GROUP_ENDPOINT,
        StatusCode::OK,
        Method::GET,
        None,
        Some(&auth),
        None,
    )
    .await?;

    stage_database_without(&runtime.config, &auth, "functional_groups.mdd").await?;
    execute_mode(&runtime.config, &auth, ExecutionMode::Apply).await?;
    let response = send_cda_request(
        &runtime.config,
        GROUPS_ENDPOINT,
        StatusCode::OK,
        Method::GET,
        None,
        Some(&auth),
        None,
    )
    .await?;
    assert_eq!(
        response_to_json(&response)?.get("items"),
        Some(&serde_json::json!([]))
    );
    send_cda_request(
        &runtime.config,
        GROUP_ENDPOINT,
        StatusCode::NOT_FOUND,
        Method::GET,
        None,
        Some(&auth),
        None,
    )
    .await?;

    execute_mode(&runtime.config, &auth, ExecutionMode::Rollback).await?;
    let response = send_cda_request(
        &runtime.config,
        GROUPS_ENDPOINT,
        StatusCode::OK,
        Method::GET,
        None,
        Some(&auth),
        None,
    )
    .await?;
    assert!(
        response_to_json(&response)?
            .get("items")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|items| !items.is_empty())
    );
    send_cda_request(
        &runtime.config,
        GROUP_ENDPOINT,
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
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;

    let ecu_lock = create_lock(
        default_timeout(),
        locks::ECU_ENDPOINT,
        StatusCode::CREATED,
        &runtime.config,
        &auth,
    )
    .await;
    let ecu_lock_body = response_to_json(&ecu_lock)?;
    let ecu_lock_id = ecu_lock_body
        .get("id")
        .and_then(serde_json::Value::as_str)
        .expect("ECU lock response must contain an id")
        .to_owned();

    let execution = send_cda_request(
        &runtime.config,
        &format!("{ECU_FLXC1000_ENDPOINT}/operations/calibratesensors/executions"),
        StatusCode::ACCEPTED,
        Method::POST,
        Some("{}"),
        Some(&auth),
        None,
    )
    .await?;
    let execution_body = response_to_json(&execution)?;
    let execution_id = execution_body
        .get("id")
        .and_then(serde_json::Value::as_str)
        .expect("operation response must contain an id")
        .to_owned();

    // The record must be readable before the update, and the operation must be
    // done before the Apply below: an update is refused while its communication
    // guard is held.
    wait_for_ecu_operation_terminal(
        &runtime.config,
        &auth,
        &format!("{ECU_FLXC1000_ENDPOINT}/operations/calibratesensors/executions/{execution_id}"),
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

    let vehicle_lock_id = setup_with_lock(&runtime.config, &auth).await;
    stage_full_database(&runtime.config, &auth).await?;
    execute_mode(&runtime.config, &auth, ExecutionMode::Apply).await?;

    // The ECU is still listed, but its entry was replaced along with the
    // databases behind it.
    send_cda_request(
        &runtime.config,
        &format!("{ECU_FLXC1000_ENDPOINT}/operations/calibratesensors/executions/{execution_id}"),
        StatusCode::NOT_FOUND,
        Method::GET,
        None,
        Some(&auth),
        None,
    )
    .await?;

    stage_database_without(&runtime.config, &auth, "FLXC1000.mdd").await?;
    execute_mode(&runtime.config, &auth, ExecutionMode::Apply).await?;
    send_cda_request(
        &runtime.config,
        ECU_FLXC1000_ENDPOINT,
        StatusCode::NOT_FOUND,
        Method::GET,
        None,
        Some(&auth),
        None,
    )
    .await?;

    execute_mode(&runtime.config, &auth, ExecutionMode::Rollback).await?;
    wait_for_ecus_online(&runtime.config).await?;
    send_cda_request(
        &runtime.config,
        &format!("{ECU_FLXC1000_ENDPOINT}/operations/calibratesensors/executions/{execution_id}"),
        StatusCode::NOT_FOUND,
        Method::GET,
        None,
        Some(&auth),
        None,
    )
    .await?;
    let readded_ecu_lock = create_lock(
        default_timeout(),
        locks::ECU_ENDPOINT,
        StatusCode::CREATED,
        &runtime.config,
        &auth,
    )
    .await;
    let readded_ecu_lock_id = response_to_t::<LockResponse>(&readded_ecu_lock)?.id;
    lock_operation(
        locks::ECU_ENDPOINT,
        Some(&readded_ecu_lock_id),
        &runtime.config,
        &auth,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;

    teardown_lock(&runtime.config, &auth, &vehicle_lock_id).await;
    Ok(())
}

/// Apply must be blocked while an ECU lock proves diagnostic work is in progress.
#[tokio::test]
async fn runtimefiles_apply_blocked_by_vehicle_and_ecu_lock() -> Result<(), TestingError> {
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;

    // All mutating runtimefiles endpoints require a vehicle lock.
    let vehicle_lock_id = setup_with_lock(&runtime.config, &auth).await;

    // Apply is a snapshot swap, so a one-file upload would leave the shared CDA
    // serving a one-ECU vehicle to every later test.
    stage_full_database(&runtime.config, &auth).await?;

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
        RUNTIMEFILES_UPDATE_EXECUTIONS,
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
    // No Rollback afterwards, because the staged snapshot was the active
    // database. On a pristine container the backup Apply takes is empty, so
    // Rollback would answer 404 and abort before the vehicle lock is released.
    execute_mode(&runtime.config, &auth, ExecutionMode::Apply).await?;

    teardown_lock(&runtime.config, &auth, &vehicle_lock_id).await;

    Ok(())
}

/// A held communication guard must refuse a runtime update outright: the update
/// cannot take the exclusive disable lease, so admission fails with
/// `OperationsInProgress` (409) instead of pulling the transport out from under
/// a running operation.
#[tokio::test]
async fn runtimefiles_apply_refused_while_communication_guard_held() -> Result<(), TestingError> {
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;
    wait_for_ecus_online(&runtime.config).await?;

    // The vehicle lock authorizes the ECU operation below as well as the update.
    let vehicle_lock_id = setup_with_lock(&runtime.config, &auth).await;
    stage_full_database(&runtime.config, &auth).await?;

    // An async operation execution holds a communication guard until it is deleted.
    // On its own ECU, so a completed execution another test leaves behind on
    // FLXC1000 cannot collide with this one.
    let start_response = send_cda_request(
        &runtime.config,
        &format!("{ECU_TMCC3000_ENDPOINT}/operations/calibratesensors/executions"),
        StatusCode::ACCEPTED,
        Method::POST,
        Some("{}"),
        Some(&auth),
        None,
    )
    .await?;
    let execution_id: String = extract_field_from_json(&response_to_json(&start_response)?, "id")?;

    let refusal = send_cda_request(
        &runtime.config,
        RUNTIMEFILES_UPDATE_EXECUTIONS,
        StatusCode::CONFLICT,
        Method::POST,
        Some(&mode_json(ExecutionMode::Apply)),
        Some(&auth),
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
    send_cda_request(
        &runtime.config,
        &format!("{ECU_TMCC3000_ENDPOINT}/operations/calibratesensors/executions/{execution_id}"),
        StatusCode::OK,
        Method::DELETE,
        None,
        Some(&auth),
        Some(&force),
    )
    .await?;

    execute_mode(&runtime.config, &auth, ExecutionMode::Apply).await?;
    execute_mode(&runtime.config, &auth, ExecutionMode::Cleanup).await?;
    teardown_lock(&runtime.config, &auth, &vehicle_lock_id).await;

    Ok(())
}

/// Stages an authoritative empty database snapshot.
async fn stage_empty_database(
    config: &Configuration,
    auth: &http::HeaderMap,
) -> Result<(), TestingError> {
    stage_full_database(config, auth).await?;
    let items = get_file_list(config, auth, RUNTIMEFILES_NEXTUPDATE)
        .await?
        .items;
    for item in items {
        send_cda_request(
            config,
            &format!("{RUNTIMEFILES_NEXTUPDATE}/{}", item.id),
            StatusCode::NO_CONTENT,
            Method::DELETE,
            None,
            Some(auth),
            None,
        )
        .await?;
    }
    assert!(
        get_file_list(config, auth, RUNTIMEFILES_NEXTUPDATE)
            .await?
            .items
            .is_empty()
    );
    Ok(())
}

/// Stages every MDD fixture except `exclude`, so that applying the snapshot
/// removes exactly that one ECU from the vehicle.
///
/// Requires the caller to hold the vehicle lock.
pub(crate) async fn stage_database_without(
    config: &Configuration,
    auth: &http::HeaderMap,
    exclude: &str,
) -> Result<(), TestingError> {
    send_cda_request(
        config,
        RUNTIMEFILES_NEXTUPDATE,
        StatusCode::OK,
        Method::DELETE,
        None,
        Some(auth),
        None,
    )
    .await?;

    let all = mdd_file_names();
    let staged: Vec<String> = all
        .iter()
        .filter(|name| !name.eq_ignore_ascii_case(exclude))
        .cloned()
        .collect();
    assert!(
        !staged.is_empty() && staged.len() != all.len(),
        "Precondition: {exclude} must be one of several fixtures, found {all:?}"
    );

    for name in staged {
        let response = upload_mdd_by_name(config, auth, &name).await;
        assert_eq!(
            response.status(),
            StatusCode::CREATED,
            "Precondition: staging {name} must succeed"
        );
    }

    // The first upload into an empty staging area seeds it from the current
    // collection, so the excluded file can reappear. Remove it after uploading.
    let excluded_key = exclude.to_lowercase();
    let items = get_file_list(config, auth, RUNTIMEFILES_NEXTUPDATE)
        .await?
        .items;
    for item in items.iter().filter(|item| {
        item.id
            .to_lowercase()
            .contains(excluded_key.trim_end_matches(".mdd"))
    }) {
        send_cda_request(
            config,
            &format!("{RUNTIMEFILES_NEXTUPDATE}/{}", item.id),
            StatusCode::NO_CONTENT,
            Method::DELETE,
            None,
            Some(auth),
            None,
        )
        .await?;
    }

    let remaining = get_file_list(config, auth, RUNTIMEFILES_NEXTUPDATE)
        .await?
        .items;
    assert!(
        !remaining.iter().any(|item| item
            .id
            .to_lowercase()
            .contains(excluded_key.trim_end_matches(".mdd"))),
        "Precondition: {exclude} must be absent from staging, got {:?}",
        remaining.iter().map(|item| &item.id).collect::<Vec<_>>()
    );
    Ok(())
}
