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

use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use http::{HeaderMap, Method, StatusCode};
use opensovd_cda_lib::config::configfile::Configuration;
use serde::{self, Deserialize};

use crate::{
    sovd,
    sovd::set_dtc_setting,
    util::{
        TestingError,
        http::{
            Response, auth_header, extract_field_from_json, response_to_json,
            response_to_json_to_field, send_cda_json_request, send_cda_request,
        },
        test_env::{TestEnv, block_on_shared_runtime, setup_integration_test},
    },
};

// must be skipped due to conflicting formatter rules between nightly and stable
#[rustfmt::skip]
pub(crate) const NON_OWNER_BEARER_TOKEN: &str =
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvd25lcnNoaXAtdGVzdCIsImV4cCI6MjAwMDAwMDAwMH0.\
     _qb-vSkPnV_Lff2wNH4VXugc-DcvGdzJxwTmb4J48Xs";

pub(crate) fn bearer_token_header(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        format!("Bearer {token}")
            .parse()
            .expect("invalid header value"),
    );
    headers
}

#[tokio::test]
async fn lock_unlock() -> Result<(), TestingError> {
    let runtime = setup_integration_test().await?;
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
            cda_interfaces::util::tokio_ext::sleep_for(expiration_timeout).await;
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
            let lock = Lock::create(endpoint, &runtime.config, &auth).await?;

            let expiration_first =
                lock_expiration(&runtime.config, &auth, endpoint, lock.id()).await?;

            cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(2)).await;

            let create_second = create_lock(
                default_timeout(),
                endpoint,
                StatusCode::CREATED,
                &runtime.config,
                &auth,
            )
            .await;

            let expiration_second =
                lock_expiration(&runtime.config, &auth, endpoint, lock.id()).await?;

            assert!(expiration_first < expiration_second);

            // second call extended the lock but ids stayed the same.
            let second_id: String = response_to_json_to_field(&create_second, "id")?;
            assert_eq!(lock.id(), second_id);
            lock.delete().await;
        }
    }

    Ok(())
}

#[tokio::test]
async fn cannot_lock_ecu_with_existing_functional_log() -> Result<(), TestingError> {
    let runtime = setup_integration_test().await?;
    let auth = auth_header(&runtime.config, None).await?;

    let _func_lock = Lock::create(FUNCTIONAL_GROUP_ENDPOINT, &runtime.config, &auth).await?;

    create_lock(
        default_timeout(),
        ECU_ENDPOINT,
        StatusCode::CONFLICT,
        &runtime.config,
        &auth,
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

    let runtime = setup_integration_test().await?;
    let auth_owner = auth_header(&runtime.config, None).await?;
    let auth_other = auth_header(&runtime.config, Some("ownership-test")).await?;

    for endpoint in ENDPOINTS {
        let lock = Lock::create(endpoint, &runtime.config, &auth_owner).await?;
        let lock_id = lock.id().to_owned();

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

        lock.delete().await;

        let lock = Lock::create(endpoint, &runtime.config, &auth_other).await?;
        let lock_list_user_2: LockList = get_lock_list(&auth_other).await?;
        let item_user_2 = lock_list_user_2
            .items
            .iter()
            .find(|e| e.id == lock.id())
            .unwrap_or_else(|| panic!("After delete, user 2 lock id {} not found", lock.id()));
        assert!(item_user_2.owned);

        lock.delete().await;
    }

    Ok(())
}

#[tokio::test]
async fn test_vehicle_locking_blocked_by_other() -> Result<(), TestingError> {
    let runtime = setup_integration_test().await?;
    let auth_user1 = auth_header(&runtime.config, None).await?;
    let auth_user2 = auth_header(&runtime.config, Some("user2")).await?;

    // User1 creates a functional lock
    let _func_lock = Lock::create(FUNCTIONAL_GROUP_ENDPOINT, &runtime.config, &auth_user1).await?;

    // User2 cannot create a vehicle lock because user1 holds a lock
    create_lock(
        default_timeout(),
        VEHICLE_ENDPOINT,
        StatusCode::FORBIDDEN,
        &runtime.config,
        &auth_user2,
    )
    .await;

    Ok(())
}

#[tokio::test]
async fn test_vehicle_lock_delete_hierarchy() -> Result<(), TestingError> {
    /// Asserts that deleting the vehicle lock deleted `locks` too.
    async fn assert_deleted(runtime: &TestEnv, user: &HeaderMap, locks: [&Lock; 2]) {
        for lock in locks {
            lock_operation(
                &lock.endpoint,
                Some(lock.id()),
                &runtime.config,
                user,
                StatusCode::NOT_FOUND,
                Method::GET,
            )
            .await;
        }
    }

    let runtime = setup_integration_test().await?;
    let auth_user1 = auth_header(&runtime.config, None).await?;
    let auth_user2 = auth_header(&runtime.config, Some("user2")).await?;

    // Locks in hierarchy: ECU (lowest) -> Functional -> Vehicle (highest).
    // Tests are done with two users to ensure locks are properly deleted.

    // test with locks created before vehicle lock
    for user in [&auth_user1, &auth_user2] {
        let ecu_lock = Lock::create(ECU_ENDPOINT, &runtime.config, user).await?;
        let func_lock = Lock::create(FUNCTIONAL_GROUP_ENDPOINT, &runtime.config, user).await?;
        let vehicle_lock = Lock::create(VEHICLE_ENDPOINT, &runtime.config, user).await?;
        vehicle_lock.delete().await;
        assert_deleted(&runtime, user, [&ecu_lock, &func_lock]).await;
    }

    // test with locks created after vehicle lock
    for user in [&auth_user1, &auth_user2] {
        let vehicle_lock = Lock::create(VEHICLE_ENDPOINT, &runtime.config, user).await?;
        let ecu_lock = Lock::create(ECU_ENDPOINT, &runtime.config, user).await?;
        let func_lock = Lock::create(FUNCTIONAL_GROUP_ENDPOINT, &runtime.config, user).await?;
        vehicle_lock.delete().await;
        assert_deleted(&runtime, user, [&ecu_lock, &func_lock]).await;
    }
    Ok(())
}

#[tokio::test]
async fn test_vehicle_lock_cannot_be_deleted_by_non_owner() -> Result<(), TestingError> {
    let runtime = setup_integration_test().await?;
    let auth_owner = auth_header(&runtime.config, None).await?;
    let auth_other = auth_header(&runtime.config, Some("other-user")).await?;

    // Owner creates vehicle lock
    let vehicle_lock = Lock::create(VEHICLE_ENDPOINT, &runtime.config, &auth_owner).await?;

    // Other user cannot delete the vehicle lock
    lock_operation(
        VEHICLE_ENDPOINT,
        Some(vehicle_lock.id()),
        &runtime.config,
        &auth_other,
        StatusCode::FORBIDDEN,
        Method::DELETE,
    )
    .await;

    // Verify lock still exists
    lock_operation(
        VEHICLE_ENDPOINT,
        Some(vehicle_lock.id()),
        &runtime.config,
        &auth_owner,
        StatusCode::OK,
        Method::GET,
    )
    .await;

    // Owner can delete their own lock
    vehicle_lock.delete().await;

    Ok(())
}

#[tokio::test]
async fn test_component_ownership_protection_with_vehicle_lock_only() -> Result<(), TestingError> {
    let runtime = setup_integration_test().await?;
    let auth_owner = auth_header(&runtime.config, None).await?;

    // Lock the vehicle as 'owner'
    let _vehicle_lock = Lock::create(VEHICLE_ENDPOINT, &runtime.config, &auth_owner).await?;

    // Create headers for non_owner using the specific bearer token
    let auth_non_owner = bearer_token_header(NON_OWNER_BEARER_TOKEN);

    // Non-owner tries to set dtcsetting - should fail because lock owners differ
    // Without lock, the CDA should reject the request
    set_dtc_setting(
        "On",
        &runtime.config,
        &auth_non_owner,
        sovd::ECU_FLXC1000_ENDPOINT,
        StatusCode::FORBIDDEN,
    )
    .await?;

    Ok(())
}

pub(crate) const FUNCTIONAL_GROUP_ENDPOINT: &str =
    const_format::formatcp!("{}/locks", sovd::FUNCTIONAL_GROUP_DOIP_ENDPOINT);

pub(crate) const ECU_ENDPOINT: &str =
    const_format::formatcp!("{}/locks", sovd::ECU_FLXC1000_ENDPOINT);

pub(crate) const ECU_FSNR2000_ENDPOINT: &str =
    const_format::formatcp!("{}/locks", sovd::ECU_FSNR2000_ENDPOINT);

pub(crate) const VEHICLE_ENDPOINT: &str = "locks";

pub(crate) const ENDPOINTS: [&str; 3] = [FUNCTIONAL_GROUP_ENDPOINT, VEHICLE_ENDPOINT, ECU_ENDPOINT];

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
    send_cda_request(
        config,
        &lock_endpoint,
        status,
        method,
        None,
        Some(headers),
        None,
    )
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

/// The expiration of the locks tests create. Tests that check lock expiry
/// pass a shorter one to [`create_lock`].
pub(crate) fn default_timeout() -> Duration {
    Duration::from_secs(100)
}

/// A lock created by a test. It is deleted when dropped, also when the test
/// fails, so tests do not have to clean up.
///
/// Use [`Lock::delete`] to delete it at a specific point and check that this
/// succeeds. Dropping a lock the CDA has removed by itself, e.g. because it
/// expired or its vehicle lock was deleted, is fine.
#[must_use = "the lock is deleted as soon as it is dropped"]
pub(crate) struct Lock {
    endpoint: String,
    /// `None` once deleted.
    id: Option<String>,
    config: Configuration,
    auth: HeaderMap,
}

impl Lock {
    /// Creates a lock on `endpoint` that expires after [`default_timeout`].
    ///
    /// # Errors
    /// Returns an error if the lock is not created.
    pub(crate) async fn create(
        endpoint: &str,
        config: &Configuration,
        auth: &HeaderMap,
    ) -> Result<Self, TestingError> {
        let response = create_lock(
            default_timeout(),
            endpoint,
            StatusCode::CREATED,
            config,
            auth,
        )
        .await;
        let id: String = response_to_json_to_field(&response, "id")?;
        Ok(Self {
            endpoint: endpoint.to_owned(),
            id: Some(id),
            config: config.clone(),
            auth: auth.clone(),
        })
    }

    pub(crate) fn id(&self) -> &str {
        self.id.as_deref().expect("a lock has its id until deleted")
    }

    /// Deletes the lock and asserts that the CDA answers `204 No Content`.
    ///
    /// Waits out an installed runtime update protection first, see
    /// [`delete_lock`].
    pub(crate) async fn delete(mut self) {
        let id = self.id.take().expect("a lock has its id until deleted");
        if let Err(e) = delete_lock(&self.endpoint, &id, &self.config, &self.auth).await {
            panic!("Failed to delete lock {id}: {e}");
        }
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        let Some(id) = self.id.take() else {
            return;
        };
        let endpoint = self.endpoint.clone();
        let lock_id = id.clone();
        let config = self.config.clone();
        let auth = self.auth.clone();
        let result = block_on_shared_runtime(async move {
            delete_lock(&endpoint, &lock_id, &config, &auth).await
        });
        // A lock that expired or was removed with a higher lock is gone
        // already, which is fine here.
        match result {
            Some(
                Ok(())
                | Err(TestingError::UnexpectedResponse {
                    actual: StatusCode::NOT_FOUND,
                    ..
                }),
            ) => {}
            Some(Err(e)) => eprintln!("Failed to delete lock {id} on drop: {e}"),
            None => eprintln!("Failed to delete lock {id} on drop: the request panicked"),
        }
    }
}

/// Deletes the lock `id` on `endpoint`, expecting `204 No Content`.
///
/// A runtime update installs an HTTP protection that answers every request
/// not on its exempt list with `409 Update in progress`, and it outlives the
/// update execution for a moment. Deleting a lock is not exempt, so while the
/// protection is installed, the request is repeated until it is lifted, for
/// at most [`UPDATE_PROTECTION_TIMEOUT`].
async fn delete_lock(
    endpoint: &str,
    id: &str,
    config: &Configuration,
    auth: &HeaderMap,
) -> Result<(), TestingError> {
    let deadline = Instant::now()
        .checked_add(UPDATE_PROTECTION_TIMEOUT)
        .expect("deadline must not overflow");
    let lock_endpoint = format!("{endpoint}/{id}");
    loop {
        match send_cda_request(
            config,
            &lock_endpoint,
            StatusCode::NO_CONTENT,
            Method::DELETE,
            None,
            Some(auth),
            None,
        )
        .await
        {
            Err(TestingError::UnexpectedResponse {
                actual: StatusCode::CONFLICT,
                body: Some(body),
                ..
            }) if body.contains(UPDATE_IN_PROGRESS) && Instant::now() < deadline => {
                cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(100)).await;
            }
            result => return result.map(|_| ()),
        }
    }
}

/// The message of the `409 Conflict` answered while a runtime update
/// protection is installed.
const UPDATE_IN_PROGRESS: &str = "Update in progress";

/// How long [`delete_lock`] waits for a runtime update protection to be
/// lifted. Generous, as it is lifted only after the database is reloaded.
const UPDATE_PROTECTION_TIMEOUT: Duration = Duration::from_secs(60);

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
