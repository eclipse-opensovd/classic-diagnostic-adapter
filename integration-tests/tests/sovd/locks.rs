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

use chrono::{DateTime, Utc};
use http::{Method, StatusCode};
use serde_json::Map;
use sovd_interfaces::locking;

use crate::{
    client::{
        SovdTestClient,
        locks::{Lock, Locks},
    },
    sovd::{self, ECU_FLXC1000, FUNCTIONAL_GROUP, set_dtc_setting},
    util::{
        TestingError,
        endpoints::{COMPONENTS_FLXC1000_BASE, FUNCTIONS_FUNCTIONALGROUPS_DOIP_BASE},
        locks::{NON_OWNER_BEARER_TOKEN, default_timeout},
        test_env::TestEnv,
    },
};

/// The lock collections of the functional group, the vehicle and FLXC1000.
const ENDPOINTS: [&str; 3] = [
    const_format::formatcp!("{}/locks", FUNCTIONS_FUNCTIONALGROUPS_DOIP_BASE),
    "locks",
    const_format::formatcp!("{}/locks", COMPONENTS_FLXC1000_BASE),
];

/// The expiration of the lock `id` of `locks`.
async fn lock_expiration(locks: &Locks<'_>, id: &str) -> Result<DateTime<Utc>, TestingError> {
    let expiration = locks
        .lock(id)
        .get()
        .await?
        .expect_status(StatusCode::OK)
        .into_body()
        .lock_expiration;
    expiration.parse::<DateTime<Utc>>().map_err(|_| {
        TestingError::InvalidData("Failed to parse lock expiration datetime".to_string())
    })
}

#[tokio::test]
async fn lock_unlock() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let client = test_env.client();

    for endpoint in ENDPOINTS {
        let locks = client.locks_at(endpoint);

        // Check if the lock is created successfully and deleted after the timeout
        {
            let expiration_timeout = Duration::from_secs(2);
            let timing_out_lock = locks
                .create(expiration_timeout)
                .await?
                .expect_status(StatusCode::CREATED)
                .into_body();
            let lock = timing_out_lock.handle();

            lock.get().await?.expect_status(StatusCode::OK);
            // The CDA removes the lock once it expired, which may take a
            // moment longer than the expiration under load.
            let err = lock
                .request(Method::GET)
                .poll_while(
                    StatusCode::OK,
                    expiration_timeout.saturating_add(Duration::from_secs(5)),
                )
                .await
                .map(drop)
                .expect_err("expired lock still exists");
            assert_eq!(err.status(), Some(StatusCode::NOT_FOUND), "{err}");

            // lock expired, expect 404
            let err = lock
                .delete()
                .await
                .expect_err("expired lock could be deleted");
            assert_eq!(err.status(), Some(StatusCode::NOT_FOUND));
        }

        // Test if creating a lock twice extends the expiration time on the same lock
        // instead of creating a new lock or returning an error.
        {
            let create_first = locks
                .create(default_timeout())
                .await?
                .expect_status(StatusCode::CREATED);
            let lock_id = create_first.id().to_owned();
            let expected_location = locks.lock(&lock_id).absolute_path();
            assert_eq!(create_first.location(), Some(expected_location.as_str()));
            let create_first = create_first.into_body();

            let expiration_first = lock_expiration(&locks, &lock_id).await?;

            cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(2)).await;

            // Extending the lock answers 200 without a `Location`.
            let create_second = locks
                .create(default_timeout())
                .await?
                .expect_status(StatusCode::OK);
            assert_eq!(create_second.location(), None);
            let second = create_second.into_body();

            let expiration_second = lock_expiration(&locks, &lock_id).await?;

            assert!(expiration_first < expiration_second);

            // second call extended the lock but ids stayed the same.
            let to_json = |lock: &locking::Lock| {
                serde_json::to_value(lock).map_err(|e| {
                    TestingError::InvalidData(format!("Failed to serialize lock: {e}"))
                })
            };
            assert_eq!(to_json(create_first.info())?, to_json(second.info())?);
            create_first
                .release()
                .await?
                .expect_status(StatusCode::NO_CONTENT);
        }
    }

    Ok(())
}

#[tokio::test]
async fn unrelated_functional_group_and_ecu_locks_can_coexist() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let client = test_env.client();

    let func_lock = client
        .functional_group(FUNCTIONAL_GROUP)
        .locks()
        .create(default_timeout())
        .await?
        .expect_status(StatusCode::CREATED)
        .into_body();

    let ecu_lock = client
        .component(ECU_FLXC1000)
        .locks()
        .create(default_timeout())
        .await?
        .expect_status(StatusCode::CREATED)
        .into_body();

    ecu_lock
        .release()
        .await?
        .expect_status(StatusCode::NO_CONTENT);
    func_lock
        .release()
        .await?
        .expect_status(StatusCode::NO_CONTENT);

    Ok(())
}

#[tokio::test]
async fn ownership() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let owner = test_env.client();
    let other = test_env.client_as("ownership-test").await?;

    for endpoint in ENDPOINTS {
        let lock = owner
            .locks_at(endpoint)
            .create(default_timeout())
            .await?
            .expect_status(StatusCode::CREATED)
            .into_body();
        let lock_id = lock.id().to_owned();

        let lock_list_user_1 = owner
            .locks_at(endpoint)
            .list()
            .await?
            .expect_status(StatusCode::OK);
        let lock_list_user_2 = other
            .locks_at(endpoint)
            .list()
            .await?
            .expect_status(StatusCode::OK);

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

        lock.release().await?.expect_status(StatusCode::NO_CONTENT);

        let lock = other
            .locks_at(endpoint)
            .create(default_timeout())
            .await?
            .expect_status(StatusCode::CREATED)
            .into_body();
        let lock_id = lock.id().to_owned();
        let lock_list_user_2 = other
            .locks_at(endpoint)
            .list()
            .await?
            .expect_status(StatusCode::OK);
        let item_user_2 = lock_list_user_2
            .items
            .iter()
            .find(|e| e.id == lock_id)
            .unwrap_or_else(|| panic!("After delete, user 2 lock id {lock_id} not found"));
        assert!(item_user_2.owned);

        lock.release().await?.expect_status(StatusCode::NO_CONTENT);
    }

    Ok(())
}

#[tokio::test]
async fn test_vehicle_locking_blocked_by_other() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let user2 = test_env.client_as("user2").await?;

    // User1 creates a functional lock
    let func_lock = test_env
        .client()
        .functional_group(FUNCTIONAL_GROUP)
        .locks()
        .create(default_timeout())
        .await?
        .expect_status(StatusCode::CREATED)
        .into_body();

    // User2 cannot create a vehicle lock because user1 holds a lock
    let err = user2
        .locks()
        .create(default_timeout())
        .await
        .map(drop)
        .expect_err("user2 locked the vehicle while user1 holds a lock");
    assert_eq!(err.status(), Some(StatusCode::LOCKED));

    // Cleanup
    func_lock
        .release()
        .await?
        .expect_status(StatusCode::NO_CONTENT);

    Ok(())
}

#[tokio::test]
async fn test_vehicle_lock_delete_hierarchy() -> Result<(), TestingError> {
    /// Creates the ECU and the functional group lock.
    async fn create_ecu_and_func_lock(user: &SovdTestClient) -> Result<(Lock, Lock), TestingError> {
        // Create locks in correct hierarchy: ECU (lowest) -> Functional -> Vehicle (highest)
        let ecu_lock = user
            .component(ECU_FLXC1000)
            .locks()
            .create(default_timeout())
            .await?
            .expect_status(StatusCode::CREATED)
            .into_body();

        let func_lock = user
            .functional_group(FUNCTIONAL_GROUP)
            .locks()
            .create(default_timeout())
            .await?
            .expect_status(StatusCode::CREATED)
            .into_body();

        Ok((ecu_lock, func_lock))
    }

    async fn assert_ecu_and_func_locks_deleted(
        ecu_lock: &Lock,
        func_lock: &Lock,
        user: &SovdTestClient,
    ) {
        let err = user
            .component(ECU_FLXC1000)
            .lock(ecu_lock.id())
            .get()
            .await
            .map(drop)
            .expect_err("ECU lock still exists");
        assert_eq!(err.status(), Some(StatusCode::NOT_FOUND));

        let err = user
            .functional_group(FUNCTIONAL_GROUP)
            .lock(func_lock.id())
            .get()
            .await
            .map(drop)
            .expect_err("functional group lock still exists");
        assert_eq!(err.status(), Some(StatusCode::NOT_FOUND));
    }

    let test_env = TestEnv::builder().await?;
    let user1 = test_env.client();
    let user2 = test_env.client_as("user2").await?;

    // tests are done with two users to ensure locks are properly deleted
    // test with locks created before vehicle lock
    {
        for user in [user1, &user2] {
            let (ecu_lock, func_lock) = create_ecu_and_func_lock(user).await?;
            let vehicle_lock = user
                .locks()
                .create(default_timeout())
                .await?
                .expect_status(StatusCode::CREATED)
                .into_body();
            vehicle_lock
                .release()
                .await?
                .expect_status(StatusCode::NO_CONTENT);
            assert_ecu_and_func_locks_deleted(&ecu_lock, &func_lock, user).await;
        }
    }

    // test with locks created after vehicle lock
    {
        for user in [user1, &user2] {
            let vehicle_lock = user
                .locks()
                .create(default_timeout())
                .await?
                .expect_status(StatusCode::CREATED)
                .into_body();
            let (ecu_lock, func_lock) = create_ecu_and_func_lock(user).await?;
            vehicle_lock
                .release()
                .await?
                .expect_status(StatusCode::NO_CONTENT);
            assert_ecu_and_func_locks_deleted(&ecu_lock, &func_lock, user).await;
        }
    }
    Ok(())
}

#[tokio::test]
async fn test_vehicle_lock_cannot_be_deleted_by_non_owner() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let other = test_env.client_as("other-user").await?;

    // Owner creates vehicle lock
    let vehicle_lock = test_env
        .client()
        .locks()
        .create(default_timeout())
        .await?
        .expect_status(StatusCode::CREATED)
        .into_body();

    // Other user cannot delete the vehicle lock
    let err = other
        .locks()
        .lock(vehicle_lock.id())
        .delete()
        .await
        .expect_err("other user deleted the vehicle lock");
    assert_eq!(err.status(), Some(StatusCode::FORBIDDEN));

    // Verify lock still exists
    vehicle_lock
        .handle()
        .get()
        .await?
        .expect_status(StatusCode::OK);

    // Owner can delete their own lock
    vehicle_lock
        .release()
        .await?
        .expect_status(StatusCode::NO_CONTENT);

    Ok(())
}

#[tokio::test]
async fn test_component_ownership_protection_with_vehicle_lock_only() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;

    // Lock the vehicle as 'owner'
    let expiration_timeout = Duration::from_secs(30);
    let vehicle_lock = test_env
        .client()
        .locks()
        .create(expiration_timeout)
        .await?
        .expect_status(StatusCode::CREATED)
        .into_body();

    // Client for the non_owner using the specific bearer token
    let non_owner = test_env
        .anonymous_client()
        .with_token(NON_OWNER_BEARER_TOKEN);

    // Non-owner tries to set dtcsetting - should fail because lock owners differ
    // Without lock, the CDA should reject the request
    let err = set_dtc_setting(&non_owner.component(ECU_FLXC1000), "On")
        .await
        .expect_err("non-owner set the DTC setting");
    assert_eq!(err.status(), Some(StatusCode::LOCKED));

    // Cleanup: delete the lock as owner
    vehicle_lock
        .release()
        .await?
        .expect_status(StatusCode::NO_CONTENT);

    Ok(())
}

#[tokio::test]
async fn vehicle_lock_exclusivity_controls_foreign_communication() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().await?;
    let locks = test_env.client().locks();
    let other = test_env
        .anonymous_client()
        .with_token(NON_OWNER_BEARER_TOKEN);
    let other_ecu = other.component(ECU_FLXC1000);
    let vin = other_ecu.data("vindataidentifier");

    let non_exclusive = locks
        .create_with(&locking::Request {
            lock_expiration: default_timeout().as_secs(),
            break_lock: false,
            x_sovd2uds_isexclusive: Some(false),
            metadata: Map::new(),
        })
        .await?
        .expect_status(StatusCode::CREATED)
        .into_body();
    vin.get().await?.expect_status(StatusCode::OK);
    let err = set_dtc_setting(&other_ecu, "On")
        .await
        .expect_err("non-owner set the DTC setting");
    assert_eq!(err.status(), Some(StatusCode::LOCKED));
    non_exclusive
        .release()
        .await?
        .expect_status(StatusCode::NO_CONTENT);

    let exclusive = locks
        .create_with(&locking::Request {
            lock_expiration: default_timeout().as_secs(),
            break_lock: false,
            x_sovd2uds_isexclusive: Some(true),
            metadata: Map::new(),
        })
        .await?
        .expect_status(StatusCode::CREATED)
        .into_body();
    let recorder = test_env.record(sovd::ECU_FLXC1000).await?;
    let err = vin
        .get()
        .await
        .expect_err("non-owner read through an exclusive lock");
    assert_eq!(err.status(), Some(StatusCode::LOCKED));
    let frames = recorder.stop().await?;
    assert!(frames.is_empty(), "Rejected read reached ECU: {frames:?}");
    exclusive
        .release()
        .await?
        .expect_status(StatusCode::NO_CONTENT);

    Ok(())
}
