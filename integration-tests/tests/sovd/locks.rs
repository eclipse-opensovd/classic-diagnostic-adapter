/*
 * Copyright (c) 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
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

use chrono::{DateTime, Utc};
use http::{HeaderMap, Method, StatusCode};
use opensovd_cda_lib::config::configfile::Configuration;
use serde::{self, Deserialize};

use crate::{
    sovd,
    util::{
        TestingError,
        http::{
            Response, auth_header, extract_field_from_json, response_to_json,
            response_to_json_to_field, send_cda_json_request, send_cda_request,
        },
        runtime::{TestRuntime, setup_integration_test},
    },
};

#[tokio::test]
async fn lock_unlock() -> Result<(), TestingError> {
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;

    for endpoint in ENDPOINTS {
        // Check if the lock is created successfully and deleted after the timeout
        {
            let expiration_timeout = Duration::from_secs(2);
            let timing_out_lock = create_lock(
                expiration_timeout,
                endpoint,
                StatusCode::CREATED,
                &runtime.config,
                &auth,
            )
            .await;
            let lock_id =
                extract_field_from_json::<String>(&response_to_json(&timing_out_lock)?, "id")?;

            lock_operation(
                endpoint,
                Some(&lock_id),
                &runtime.config,
                &auth,
                StatusCode::OK,
                Method::GET,
            )
            .await;
            tokio::time::sleep(expiration_timeout).await;
            lock_operation(
                endpoint,
                Some(&lock_id),
                &runtime.config,
                &auth,
                StatusCode::NOT_FOUND,
                Method::GET,
            )
            .await;

            // lock expired, expect 404
            lock_operation(
                endpoint,
                Some(&lock_id),
                &runtime.config,
                &auth,
                StatusCode::NOT_FOUND,
                Method::DELETE,
            )
            .await;
        }

        // Test if creating a lock twice extends the expiration time on the same lock
        // instead of creating a new lock or returning an error.
        {
            let create_first = create_lock(
                default_timeout(),
                endpoint,
                StatusCode::CREATED,
                &runtime.config,
                &auth,
            )
            .await;
            let create_first_json = response_to_json(&create_first)?;
            let lock_id = extract_field_from_json::<String>(&create_first_json, "id")?;

            let expiration_first =
                lock_expiration(&runtime.config, &auth, endpoint, &lock_id).await?;

            tokio::time::sleep(Duration::from_secs(2)).await;

            let create_second = create_lock(
                default_timeout(),
                endpoint,
                StatusCode::CREATED,
                &runtime.config,
                &auth,
            )
            .await;

            let create_second_json = response_to_json(&create_second)?;
            let expiration_second =
                lock_expiration(&runtime.config, &auth, endpoint, &lock_id).await?;

            assert!(expiration_first < expiration_second);

            // second call extended the lock but ids stayed the same.
            assert_eq!(create_first_json, create_second_json);
            lock_operation(
                endpoint,
                Some(&lock_id),
                &runtime.config,
                &auth,
                StatusCode::NO_CONTENT,
                Method::DELETE,
            )
            .await;
        }
    }

    Ok(())
}

#[cfg(feature = "functional-locks-tests")]
#[tokio::test]
async fn cannot_lock_ecu_with_existing_functional_log() -> Result<(), TestingError> {
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth = auth_header(&runtime.config, None).await?;

    let func_lock_response = create_lock(
        default_timeout(),
        FUNCTIONAL_GROUP_ENDPOINT,
        StatusCode::CREATED,
        &runtime.config,
        &auth,
    )
    .await;
    let lock_id: String = response_to_json_to_field(&func_lock_response, "id")?;

    create_lock(
        default_timeout(),
        ECU_ENDPOINT,
        StatusCode::CONFLICT,
        &runtime.config,
        &auth,
    )
    .await;

    lock_operation(
        FUNCTIONAL_GROUP_ENDPOINT,
        Some(&lock_id),
        &runtime.config,
        &auth,
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

    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth_owner = auth_header(&runtime.config, None).await?;
    let auth_other = auth_header(&runtime.config, Some("ownership-test")).await?;

    for endpoint in ENDPOINTS {
        let lock_id: String = response_to_json_to_field(
            &create_lock(
                default_timeout(),
                endpoint,
                StatusCode::CREATED,
                &runtime.config,
                &auth_owner,
            )
            .await,
            "id",
        )?;

        let get_lock_list = async |auth: &HeaderMap| {
            serde_json::from_value(response_to_json(
                &lock_operation(
                    endpoint,
                    None,
                    &runtime.config,
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
            &runtime.config,
            &auth_owner,
            StatusCode::NO_CONTENT,
            Method::DELETE,
        )
        .await;

        let lock_id: String = response_to_json_to_field(
            &create_lock(
                default_timeout(),
                endpoint,
                StatusCode::CREATED,
                &runtime.config,
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

        lock_operation(
            endpoint,
            Some(&lock_id),
            &runtime.config,
            &auth_other,
            StatusCode::NO_CONTENT,
            Method::DELETE,
        )
        .await;
    }

    Ok(())
}

#[cfg(feature = "functional-locks-tests")]
#[tokio::test]
async fn test_vehicle_locking_blocked_by_other() -> Result<(), TestingError> {
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth_user1 = auth_header(&runtime.config, None).await?;
    let auth_user2 = auth_header(&runtime.config, Some("user2")).await?;

    // User1 creates a functional lock
    let func_lock_id: String = response_to_json_to_field(
        &create_lock(
            default_timeout(),
            FUNCTIONAL_GROUP_ENDPOINT,
            StatusCode::CREATED,
            &runtime.config,
            &auth_user1,
        )
        .await,
        "id",
    )?;

    // User2 cannot create a vehicle lock because user1 holds a lock
    create_lock(
        default_timeout(),
        VEHICLE_ENDPOINT,
        StatusCode::FORBIDDEN,
        &runtime.config,
        &auth_user2,
    )
    .await;

    // Cleanup
    lock_operation(
        FUNCTIONAL_GROUP_ENDPOINT,
        Some(&func_lock_id),
        &runtime.config,
        &auth_user1,
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
        runtime: &TestRuntime,
    ) -> Result<(String, String), TestingError> {
        // Create locks in correct hierarchy: ECU (lowest) -> Functional -> Vehicle (highest)
        let ecu_lock_id: String = response_to_json_to_field(
            &create_lock(
                default_timeout(),
                ECU_ENDPOINT,
                StatusCode::CREATED,
                &runtime.config,
                user,
            )
            .await,
            "id",
        )?;

        let func_lock_id: String = if cfg!(feature = "functional-locks-tests") {
            response_to_json_to_field(
                &create_lock(
                    default_timeout(),
                    FUNCTIONAL_GROUP_ENDPOINT,
                    StatusCode::CREATED,
                    &runtime.config,
                    user,
                )
                .await,
                "id",
            )?
        } else {
            "empty".to_owned()
        };

        Ok((ecu_lock_id, func_lock_id))
    }

    #[allow(unused_variables)] // with functional group tests disabled func_lock_id is unused
    async fn assert_ecu_and_func_locks_deleted(
        ecu_lock_id: &str,
        func_lock_id: &str,
        user: &HeaderMap,
        runtime: &TestRuntime,
    ) {
        lock_operation(
            ECU_ENDPOINT,
            Some(ecu_lock_id),
            &runtime.config,
            user,
            StatusCode::NOT_FOUND,
            Method::GET,
        )
        .await;

        #[cfg(feature = "functional-locks-tests")]
        lock_operation(
            FUNCTIONAL_GROUP_ENDPOINT,
            Some(func_lock_id),
            &runtime.config,
            user,
            StatusCode::NOT_FOUND,
            Method::GET,
        )
        .await;
    }

    async fn create_vehicle_lock(
        runtime: &TestRuntime,
        user: &HeaderMap,
    ) -> Result<String, TestingError> {
        response_to_json_to_field(
            &create_lock(
                default_timeout(),
                VEHICLE_ENDPOINT,
                StatusCode::CREATED,
                &runtime.config,
                user,
            )
            .await,
            "id",
        )
    }

    async fn delete_lock(runtime: &TestRuntime, user: &HeaderMap, lock_id: &str) {
        lock_operation(
            VEHICLE_ENDPOINT,
            Some(lock_id),
            &runtime.config,
            user,
            StatusCode::NO_CONTENT,
            Method::DELETE,
        )
        .await;
    }

    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth_user1 = auth_header(&runtime.config, None).await?;
    let auth_user2 = auth_header(&runtime.config, Some("user2")).await?;

    // tests are done with two users to ensure locks are properly deleted
    // test with locks created before vehicle lock
    {
        for user in [&auth_user1, &auth_user2] {
            let (ecu_lock_id, func_lock_id) = create_ecu_and_func_lock(user, runtime).await?;
            let vehicle_lock = create_vehicle_lock(runtime, user).await?;
            delete_lock(runtime, user, &vehicle_lock).await;
            assert_ecu_and_func_locks_deleted(&ecu_lock_id, &func_lock_id, user, runtime).await;
        }
    }

    // test with locks created after vehicle lock
    {
        for user in [&auth_user1, &auth_user2] {
            let vehicle_lock = create_vehicle_lock(runtime, user).await?;
            let (ecu_lock_id, func_lock_id) = create_ecu_and_func_lock(user, runtime).await?;
            delete_lock(runtime, user, &vehicle_lock).await;
            assert_ecu_and_func_locks_deleted(&ecu_lock_id, &func_lock_id, user, runtime).await;
        }
    }
    Ok(())
}

#[tokio::test]
async fn test_vehicle_lock_cannot_be_deleted_by_non_owner() -> Result<(), TestingError> {
    let (runtime, _lock) = setup_integration_test(true).await?;
    let auth_owner = auth_header(&runtime.config, None).await?;
    let auth_other = auth_header(&runtime.config, Some("other-user")).await?;

    // Owner creates vehicle lock
    let vehicle_lock_id: String = response_to_json_to_field(
        &create_lock(
            default_timeout(),
            VEHICLE_ENDPOINT,
            StatusCode::CREATED,
            &runtime.config,
            &auth_owner,
        )
        .await,
        "id",
    )?;

    // Other user cannot delete the vehicle lock
    lock_operation(
        VEHICLE_ENDPOINT,
        Some(&vehicle_lock_id),
        &runtime.config,
        &auth_other,
        StatusCode::FORBIDDEN,
        Method::DELETE,
    )
    .await;

    // Verify lock still exists
    lock_operation(
        VEHICLE_ENDPOINT,
        Some(&vehicle_lock_id),
        &runtime.config,
        &auth_owner,
        StatusCode::OK,
        Method::GET,
    )
    .await;

    // Owner can delete their own lock
    lock_operation(
        VEHICLE_ENDPOINT,
        Some(&vehicle_lock_id),
        &runtime.config,
        &auth_owner,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;

    Ok(())
}

pub(crate) const FUNCTIONAL_GROUP_ENDPOINT: &str =
    "functions/functionalgroups/fgl_uds_ethernet_doip_dobt/locks";

pub(crate) const ECU_ENDPOINT: &str =
    const_format::formatcp!("{}/locks", sovd::ECU_FLXC1000_ENDPOINT);

pub(crate) const VEHICLE_ENDPOINT: &str = "locks";

#[cfg(feature = "functional-locks-tests")]
pub(crate) const ENDPOINTS: [&str; 3] = [FUNCTIONAL_GROUP_ENDPOINT, VEHICLE_ENDPOINT, ECU_ENDPOINT];

#[cfg(not(feature = "functional-locks-tests"))]
pub(crate) const ENDPOINTS: [&str; 2] = [VEHICLE_ENDPOINT, ECU_ENDPOINT];

pub(crate) async fn lock_operation(
    endpoint: &str,
    lock_id: Option<&str>,
    config: &Configuration,
    headers: &HeaderMap,
    status: StatusCode,
    method: Method,
) -> Response {
    let lock_endpoint = format!(
        "{endpoint}{}",
        lock_id.map_or(String::new(), |id| format!("/{id}"))
    );
    send_cda_request(config, &lock_endpoint, status, method, None, Some(headers))
        .await
        .expect("lock operation failed")
}

pub(crate) async fn create_lock(
    expiration: Duration,
    endpoint: &str,
    status: StatusCode,
    webserver: &Configuration,
    auth: &HeaderMap,
) -> Response {
    let payload = serde_json::json!({
        "exclusive": false,
        "lock_expiration": expiration.as_secs(),
    });
    send_cda_json_request(
        webserver,
        endpoint,
        status,
        Method::POST,
        &payload,
        Some(auth),
    )
    .await
    .expect("Failed to create lock")
}

fn default_timeout() -> Duration {
    Duration::from_secs(3600)
}

async fn lock_expiration(
    cfg: &Configuration,
    auth_header: &HeaderMap,
    endpoint: &str,
    lock_id: &str,
) -> Result<DateTime<Utc>, TestingError> {
    let response = lock_operation(
        endpoint,
        Some(lock_id),
        cfg,
        auth_header,
        StatusCode::OK,
        Method::GET,
    )
    .await;

    let expiration: String = response_to_json_to_field(&response, "lock_expiration")?;

    match expiration.parse::<DateTime<Utc>>() {
        Ok(date_time) => Ok(date_time),
        Err(_) => Err(TestingError::InvalidData(
            "Failed to parse lock expiration datetime".to_string(),
        )),
    }
}
