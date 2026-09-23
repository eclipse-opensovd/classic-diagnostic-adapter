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

//! Locks of the CDA: creating and deleting them as the default test client or
//! another one, and [`Lock`], a lock that is released when dropped.

use std::time::Duration;

use chrono::{DateTime, Utc};
use const_format::formatcp;
use http::{HeaderMap, Method, StatusCode};
use opensovd_cda_lib::config::configfile::Configuration;
use serde_json::Value;

use crate::util::{
    TestingError,
    endpoints::{
        ECU_FLXC1000_ENDPOINT, FUNCTIONAL_GROUP_ENDPOINT as FUNCTIONAL_GROUP_ENDPOINT_BASE,
    },
    http::{
        Response, extract_field_from_json, response_to_json, response_to_json_to_field,
        send_cda_json_request, send_cda_request,
    },
    test_env::{TestEnv, block_on_shared_runtime},
};

/// A token of another client than the default test client, which does not
/// own the locks of the test.
// must be skipped due to conflicting formatter rules between nightly and stable
#[rustfmt::skip]
pub(crate) const NON_OWNER_BEARER_TOKEN: &str =
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvd25lcnNoaXAtdGVzdCIsImV4cCI6MjAwMDAwMDAwMH0.\
     _qb-vSkPnV_Lff2wNH4VXugc-DcvGdzJxwTmb4J48Xs";

/// An `Authorization` header with the bearer `token`.
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

/// The locks of the functional group.
pub(crate) const FUNCTIONAL_GROUP_ENDPOINT: &str =
    formatcp!("{}/locks", FUNCTIONAL_GROUP_ENDPOINT_BASE);

/// The locks of FLXC1000.
pub(crate) const ECU_ENDPOINT: &str = formatcp!("{}/locks", ECU_FLXC1000_ENDPOINT);

/// The locks of the vehicle.
pub(crate) const VEHICLE_ENDPOINT: &str = "locks";

/// All lock endpoints.
pub(crate) const ENDPOINTS: [&str; 3] = [FUNCTIONAL_GROUP_ENDPOINT, VEHICLE_ENDPOINT, ECU_ENDPOINT];

/// [`lock_operation_with_headers`] as the default test client of `test_env`.
pub(crate) async fn lock_operation(
    endpoint: &str,
    lock_id: Option<&str>,
    test_env: &TestEnv,
    status: StatusCode,
    method: Method,
) -> Response {
    let auth = test_env
        .auth_header()
        .await
        .expect("Failed to authenticate");
    lock_operation_with_headers(endpoint, lock_id, &test_env.config, &auth, status, method).await
}

/// [`create_lock_with_headers`] as the default test client of `test_env`.
pub(crate) async fn create_lock(
    expiration: Duration,
    endpoint: &str,
    status: StatusCode,
    test_env: &TestEnv,
) -> Response {
    let auth = test_env
        .auth_header()
        .await
        .expect("Failed to authenticate");
    create_lock_with_headers(expiration, endpoint, status, &test_env.config, &auth).await
}

/// [`create_lock_with_payload_with_headers`] as the default test client of
/// `test_env`.
pub(crate) async fn create_lock_with_payload(
    endpoint: &str,
    status: StatusCode,
    test_env: &TestEnv,
    payload: &Value,
) -> Response {
    let auth = test_env
        .auth_header()
        .await
        .expect("Failed to authenticate");
    create_lock_with_payload_with_headers(endpoint, status, &test_env.config, &auth, payload).await
}

pub(crate) async fn lock_operation_with_headers(
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

pub(crate) async fn create_lock_with_headers(
    expiration: Duration,
    endpoint: &str,
    status: StatusCode,
    webserver: &Configuration,
    auth: &HeaderMap,
) -> Response {
    let payload = serde_json::json!({
        "lock_expiration": expiration.as_secs(),
    });
    create_lock_with_payload_with_headers(endpoint, status, webserver, auth, &payload).await
}

pub(crate) async fn create_lock_with_payload_with_headers(
    endpoint: &str,
    status: StatusCode,
    webserver: &Configuration,
    auth: &HeaderMap,
    payload: &Value,
) -> Response {
    send_cda_json_request(
        webserver,
        endpoint,
        status,
        Method::POST,
        payload,
        Some(auth),
    )
    .await
    .expect("Failed to create lock")
}

/// A lock expiration long enough for any test.
pub(crate) fn default_timeout() -> Duration {
    Duration::from_secs(3600)
}

/// The expiration of the lock `lock_id` at `endpoint`.
///
/// # Errors
/// Returns an error if the expiration is missing or cannot be parsed.
pub(crate) async fn lock_expiration(
    test_env: &TestEnv,
    endpoint: &str,
    lock_id: &str,
) -> Result<DateTime<Utc>, TestingError> {
    let response = lock_operation(
        endpoint,
        Some(lock_id),
        test_env,
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

/// A lock of the default test client, from [`Lock::acquire`].
///
/// Released when dropped, so a test does not have to release it on every
/// path. [`Lock::release`] releases it explicitly and checks the response,
/// for tests that go on without it.
#[must_use = "the lock is released when dropped"]
pub(crate) struct Lock {
    endpoint: String,
    id: String,
    config: Configuration,
    auth: HeaderMap,
    held: bool,
}

impl Lock {
    /// Acquires a lock at `endpoint`, e.g. [`ECU_ENDPOINT`], as the default
    /// test client, expiring after `expiration`, and checks that it can be
    /// read back.
    ///
    /// # Panics
    /// If the lock is not created or cannot be read back.
    pub(crate) async fn acquire(test_env: &TestEnv, endpoint: &str, expiration: Duration) -> Self {
        let response = create_lock(expiration, endpoint, StatusCode::CREATED, test_env).await;
        let id = extract_field_from_json::<String>(
            &response_to_json(&response).expect("lock response is not JSON"),
            "id",
        )
        .expect("lock response has no id");
        lock_operation(endpoint, Some(&id), test_env, StatusCode::OK, Method::GET).await;
        Self {
            endpoint: endpoint.to_owned(),
            id,
            config: test_env.config.clone(),
            auth: test_env
                .auth_header()
                .await
                .expect("Failed to authenticate"),
            held: true,
        }
    }

    /// Releases the lock.
    ///
    /// # Panics
    /// If the CDA does not answer `204 No Content`.
    pub(crate) async fn release(mut self) {
        self.held = false;
        lock_operation_with_headers(
            &self.endpoint,
            Some(&self.id),
            &self.config,
            &self.auth,
            StatusCode::NO_CONTENT,
            Method::DELETE,
        )
        .await;
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        if !self.held {
            return;
        }
        let path = format!("{}/{}", self.endpoint, self.id);
        let config = self.config.clone();
        let auth = self.auth.clone();
        block_on_shared_runtime(async move {
            // Best effort: the lock may be gone already, e.g. expired, or
            // removed with a restarted CDA.
            let _ = send_cda_request(
                &config,
                &path,
                StatusCode::NO_CONTENT,
                Method::DELETE,
                None,
                Some(&auth),
                None,
            )
            .await;
        });
    }
}
