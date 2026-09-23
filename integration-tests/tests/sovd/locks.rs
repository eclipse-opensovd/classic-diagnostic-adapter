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

use http::{HeaderMap, Method, StatusCode};
use serde::{self, Deserialize};

use crate::{
    sovd,
    sovd::{ECU_FLXC1000, set_dtc_setting_with_headers},
    util::{
        TestingError,
        http::{
            extract_field_from_json, response_to_json, response_to_json_to_field, send_cda_request,
        },
        locks::{
            ECU_ENDPOINT, ENDPOINTS, FUNCTIONAL_GROUP_ENDPOINT, NON_OWNER_BEARER_TOKEN,
            VEHICLE_ENDPOINT, bearer_token_header, create_lock, create_lock_with_headers,
            create_lock_with_payload, default_timeout, lock_expiration, lock_operation,
            lock_operation_with_headers,
        },
        test_env::TestEnv,
    },
};

#[tokio::test]
async fn lock_unlock() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;

    for endpoint in ENDPOINTS {
        // Check if the lock is created successfully and deleted after the timeout
        {
            let expiration_timeout = Duration::from_secs(2);
            let timing_out_lock =
                create_lock(expiration_timeout, endpoint, StatusCode::CREATED, &test_env).await;
            let lock_id =
                extract_field_from_json::<String>(&response_to_json(&timing_out_lock)?, "id")?;

            lock_operation(
                endpoint,
                Some(&lock_id),
                &test_env,
                StatusCode::OK,
                Method::GET,
            )
            .await;
            cda_interfaces::util::tokio_ext::sleep_for(expiration_timeout).await;
            lock_operation(
                endpoint,
                Some(&lock_id),
                &test_env,
                StatusCode::NOT_FOUND,
                Method::GET,
            )
            .await;

            // lock expired, expect 404
            lock_operation(
                endpoint,
                Some(&lock_id),
                &test_env,
                StatusCode::NOT_FOUND,
                Method::DELETE,
            )
            .await;
        }

        // Test if creating a lock twice extends the expiration time on the same lock
        // instead of creating a new lock or returning an error.
        {
            let create_first =
                create_lock(default_timeout(), endpoint, StatusCode::CREATED, &test_env).await;
            let create_first_json = response_to_json(&create_first)?;
            let lock_id = extract_field_from_json::<String>(&create_first_json, "id")?;
            let expected_location = format!("/vehicle/v15/{endpoint}/{lock_id}");
            assert_eq!(
                create_first
                    .header(http::header::LOCATION)
                    .and_then(|value| value.to_str().ok()),
                Some(expected_location.as_str())
            );

            let expiration_first = lock_expiration(&test_env, endpoint, &lock_id).await?;

            cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(2)).await;

            let create_second =
                create_lock(default_timeout(), endpoint, StatusCode::OK, &test_env).await;

            let create_second_json = response_to_json(&create_second)?;
            assert_eq!(
                create_second
                    .header(http::header::LOCATION)
                    .and_then(|value| value.to_str().ok()),
                None
            );
            let expiration_second = lock_expiration(&test_env, endpoint, &lock_id).await?;

            assert!(expiration_first < expiration_second);

            // second call extended the lock but ids stayed the same.
            assert_eq!(create_first_json, create_second_json);
            lock_operation(
                endpoint,
                Some(&lock_id),
                &test_env,
                StatusCode::NO_CONTENT,
                Method::DELETE,
            )
            .await;
        }
    }

    Ok(())
}

#[tokio::test]
async fn unrelated_functional_group_and_ecu_locks_can_coexist() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;

    let func_lock_response = create_lock(
        default_timeout(),
        FUNCTIONAL_GROUP_ENDPOINT,
        StatusCode::CREATED,
        &test_env,
    )
    .await;
    let lock_id: String = response_to_json_to_field(&func_lock_response, "id")?;

    let ecu_lock_response = create_lock(
        default_timeout(),
        ECU_ENDPOINT,
        StatusCode::CREATED,
        &test_env,
    )
    .await;
    let ecu_lock_id: String = response_to_json_to_field(&ecu_lock_response, "id")?;

    lock_operation(
        ECU_ENDPOINT,
        Some(&ecu_lock_id),
        &test_env,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;

    lock_operation(
        FUNCTIONAL_GROUP_ENDPOINT,
        Some(&lock_id),
        &test_env,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;

    Ok(())
}

#[tokio::test]
async fn ownership() -> Result<(), TestingError> {
    #[derive(Deserialize)]
    struct LockElement {
        id: String,
        owned: bool,
    }

    #[derive(Deserialize)]
    struct LockList {
        items: Vec<LockElement>,
    }

    let test_env = TestEnv::builder().await?;
    let auth_owner = test_env.auth_header().await?;
    let auth_other = test_env.auth_header_for("ownership-test").await?;

    for endpoint in ENDPOINTS {
        let lock_id: String = response_to_json_to_field(
            &create_lock(default_timeout(), endpoint, StatusCode::CREATED, &test_env).await,
            "id",
        )?;

        let get_lock_list = async |auth: &HeaderMap| {
            serde_json::from_value(response_to_json(
                &lock_operation_with_headers(
                    endpoint,
                    None,
                    &test_env.config,
                    auth,
                    StatusCode::OK,
                    Method::GET,
                )
                .await,
            )?)
            .map_err(|e| TestingError::InvalidData(format!("Failed to parse lock list, err={e}")))
        };

        let lock_list_user_1: LockList = get_lock_list(&auth_owner).await?;
        let lock_list_user_2: LockList = get_lock_list(&auth_other).await?;

        assert_eq!(lock_list_user_1.items.len(), 1);
        assert_eq!(lock_list_user_2.items.len(), 1);

        let item_user_1 = lock_list_user_1
            .items
            .iter()
            .find(|e| e.id == lock_id)
            .unwrap_or_else(|| panic!("Owner lock id {lock_id} not found"));
        let item_user_2 = lock_list_user_2
            .items
            .iter()
            .find(|e| e.id == lock_id)
            .unwrap_or_else(|| panic!("Other user lock id {lock_id} not found"));

        assert!(item_user_1.owned);
        assert!(!item_user_2.owned);

        lock_operation(
            endpoint,
            Some(&lock_id),
            &test_env,
            StatusCode::NO_CONTENT,
            Method::DELETE,
        )
        .await;

        let lock_id: String = response_to_json_to_field(
            &create_lock_with_headers(
                default_timeout(),
                endpoint,
                StatusCode::CREATED,
                &test_env.config,
                &auth_other,
            )
            .await,
            "id",
        )?;
        let lock_list_user_2: LockList = get_lock_list(&auth_other).await?;
        let item_user_2 = lock_list_user_2
            .items
            .iter()
            .find(|e| e.id == lock_id)
            .unwrap_or_else(|| panic!("After delete, user 2 lock id {lock_id} not found"));
        assert!(item_user_2.owned);

        lock_operation_with_headers(
            endpoint,
            Some(&lock_id),
            &test_env.config,
            &auth_other,
            StatusCode::NO_CONTENT,
            Method::DELETE,
        )
        .await;
    }

    Ok(())
}

#[tokio::test]
async fn test_vehicle_locking_blocked_by_other() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let auth_user2 = test_env.auth_header_for("user2").await?;

    // User1 creates a functional lock
    let func_lock_id: String = response_to_json_to_field(
        &create_lock(
            default_timeout(),
            FUNCTIONAL_GROUP_ENDPOINT,
            StatusCode::CREATED,
            &test_env,
        )
        .await,
        "id",
    )?;

    // User2 cannot create a vehicle lock because user1 holds a lock
    create_lock_with_headers(
        default_timeout(),
        VEHICLE_ENDPOINT,
        StatusCode::LOCKED,
        &test_env.config,
        &auth_user2,
    )
    .await;

    // Cleanup
    lock_operation(
        FUNCTIONAL_GROUP_ENDPOINT,
        Some(&func_lock_id),
        &test_env,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;

    Ok(())
}

#[tokio::test]
async fn test_vehicle_lock_delete_hierarchy() -> Result<(), TestingError> {
    async fn create_ecu_and_func_lock(
        user: &HeaderMap,
        test_env: &TestEnv,
    ) -> Result<(String, String), TestingError> {
        // Create locks in correct hierarchy: ECU (lowest) -> Functional -> Vehicle (highest)
        let ecu_lock_id: String = response_to_json_to_field(
            &create_lock_with_headers(
                default_timeout(),
                ECU_ENDPOINT,
                StatusCode::CREATED,
                &test_env.config,
                user,
            )
            .await,
            "id",
        )?;

        let func_lock_id: String = response_to_json_to_field(
            &create_lock_with_headers(
                default_timeout(),
                FUNCTIONAL_GROUP_ENDPOINT,
                StatusCode::CREATED,
                &test_env.config,
                user,
            )
            .await,
            "id",
        )?;

        Ok((ecu_lock_id, func_lock_id))
    }

    async fn assert_ecu_and_func_locks_deleted(
        ecu_lock_id: &str,
        func_lock_id: &str,
        user: &HeaderMap,
        test_env: &TestEnv,
    ) {
        lock_operation_with_headers(
            ECU_ENDPOINT,
            Some(ecu_lock_id),
            &test_env.config,
            user,
            StatusCode::NOT_FOUND,
            Method::GET,
        )
        .await;

        lock_operation_with_headers(
            FUNCTIONAL_GROUP_ENDPOINT,
            Some(func_lock_id),
            &test_env.config,
            user,
            StatusCode::NOT_FOUND,
            Method::GET,
        )
        .await;
    }

    async fn create_vehicle_lock(
        test_env: &TestEnv,
        user: &HeaderMap,
    ) -> Result<String, TestingError> {
        response_to_json_to_field(
            &create_lock_with_headers(
                default_timeout(),
                VEHICLE_ENDPOINT,
                StatusCode::CREATED,
                &test_env.config,
                user,
            )
            .await,
            "id",
        )
    }

    async fn delete_lock(test_env: &TestEnv, user: &HeaderMap, lock_id: &str) {
        lock_operation_with_headers(
            VEHICLE_ENDPOINT,
            Some(lock_id),
            &test_env.config,
            user,
            StatusCode::NO_CONTENT,
            Method::DELETE,
        )
        .await;
    }

    let test_env = TestEnv::builder().await?;
    let auth_user1 = test_env.auth_header().await?;
    let auth_user2 = test_env.auth_header_for("user2").await?;

    // tests are done with two users to ensure locks are properly deleted
    // test with locks created before vehicle lock
    {
        for user in [&auth_user1, &auth_user2] {
            let (ecu_lock_id, func_lock_id) = create_ecu_and_func_lock(user, &test_env).await?;
            let vehicle_lock = create_vehicle_lock(&test_env, user).await?;
            delete_lock(&test_env, user, &vehicle_lock).await;
            assert_ecu_and_func_locks_deleted(&ecu_lock_id, &func_lock_id, user, &test_env).await;
        }
    }

    // test with locks created after vehicle lock
    {
        for user in [&auth_user1, &auth_user2] {
            let vehicle_lock = create_vehicle_lock(&test_env, user).await?;
            let (ecu_lock_id, func_lock_id) = create_ecu_and_func_lock(user, &test_env).await?;
            delete_lock(&test_env, user, &vehicle_lock).await;
            assert_ecu_and_func_locks_deleted(&ecu_lock_id, &func_lock_id, user, &test_env).await;
        }
    }
    Ok(())
}

#[tokio::test]
async fn test_vehicle_lock_cannot_be_deleted_by_non_owner() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let auth_other = test_env.auth_header_for("other-user").await?;

    // Owner creates vehicle lock
    let vehicle_lock_id: String = response_to_json_to_field(
        &create_lock(
            default_timeout(),
            VEHICLE_ENDPOINT,
            StatusCode::CREATED,
            &test_env,
        )
        .await,
        "id",
    )?;

    // Other user cannot delete the vehicle lock
    lock_operation_with_headers(
        VEHICLE_ENDPOINT,
        Some(&vehicle_lock_id),
        &test_env.config,
        &auth_other,
        StatusCode::FORBIDDEN,
        Method::DELETE,
    )
    .await;

    // Verify lock still exists
    lock_operation(
        VEHICLE_ENDPOINT,
        Some(&vehicle_lock_id),
        &test_env,
        StatusCode::OK,
        Method::GET,
    )
    .await;

    // Owner can delete their own lock
    lock_operation(
        VEHICLE_ENDPOINT,
        Some(&vehicle_lock_id),
        &test_env,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;

    Ok(())
}

#[tokio::test]
async fn test_component_ownership_protection_with_vehicle_lock_only() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;

    // Lock the vehicle as 'owner'
    let expiration_timeout = Duration::from_secs(30);
    let ecu_lock = create_lock(
        expiration_timeout,
        VEHICLE_ENDPOINT,
        StatusCode::CREATED,
        &test_env,
    )
    .await;
    let lock_id = extract_field_from_json::<String>(&response_to_json(&ecu_lock)?, "id")?;

    // Create headers for non_owner using the specific bearer token
    let auth_non_owner = bearer_token_header(NON_OWNER_BEARER_TOKEN);

    // Non-owner tries to set dtcsetting - should fail because lock owners differ
    // Without lock, the CDA should reject the request
    set_dtc_setting_with_headers(
        "On",
        &test_env.config,
        &auth_non_owner,
        sovd::ECU_FLXC1000_ENDPOINT,
        StatusCode::LOCKED,
    )
    .await?;

    // Cleanup: delete the lock as owner
    lock_operation(
        VEHICLE_ENDPOINT,
        Some(&lock_id),
        &test_env,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;

    Ok(())
}

#[tokio::test]
async fn vehicle_lock_exclusivity_controls_foreign_communication() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let other = bearer_token_header(NON_OWNER_BEARER_TOKEN);

    let non_exclusive_id: String = response_to_json_to_field(
        &create_lock_with_payload(
            VEHICLE_ENDPOINT,
            StatusCode::CREATED,
            &test_env,
            &serde_json::json!({
                "lock_expiration": default_timeout().as_secs(),
                "x-sovd2uds-isexclusive": false,
            }),
        )
        .await,
        "id",
    )?;
    send_cda_request(
        &test_env.config,
        sovd::ECU_FLXC1000_VIN_ENDPOINT,
        StatusCode::OK,
        Method::GET,
        None,
        Some(&other),
        None,
    )
    .await?;
    set_dtc_setting_with_headers(
        "On",
        &test_env.config,
        &other,
        sovd::ECU_FLXC1000_ENDPOINT,
        StatusCode::LOCKED,
    )
    .await?;
    lock_operation(
        VEHICLE_ENDPOINT,
        Some(&non_exclusive_id),
        &test_env,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;

    let exclusive_id: String = response_to_json_to_field(
        &create_lock_with_payload(
            VEHICLE_ENDPOINT,
            StatusCode::CREATED,
            &test_env,
            &serde_json::json!({
                "lock_expiration": default_timeout().as_secs(),
                "x-sovd2uds-isexclusive": true,
            }),
        )
        .await,
        "id",
    )?;
    let recorder = test_env.record(ECU_FLXC1000).await?;
    send_cda_request(
        &test_env.config,
        sovd::ECU_FLXC1000_VIN_ENDPOINT,
        StatusCode::LOCKED,
        Method::GET,
        None,
        Some(&other),
        None,
    )
    .await?;
    let frames = recorder.stop().await?;
    assert!(frames.is_empty(), "Rejected read reached ECU: {frames:?}");
    lock_operation(
        VEHICLE_ENDPOINT,
        Some(&exclusive_id),
        &test_env,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;

    Ok(())
}
