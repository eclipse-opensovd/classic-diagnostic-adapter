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

//! Locks of the CDA: creating, reading and deleting them, and [`Lock`].

use std::time::Duration;

use chrono::{DateTime, Utc};
use const_format::formatcp;
use http::{Method, StatusCode};
use serde_json::Value;

use crate::util::{
    TestingError,
    endpoints::{COMPONENTS_FLXC1000_BASE, FUNCTIONS_FUNCTIONALGROUPS_DOIP_BASE},
    http::{
        CdaClient, Response, extract_field_from_json, response_to_json, response_to_json_to_field,
        send_authenticated_cda_request,
    },
};

/// A token of another client than the default test client, which does not
/// own the locks of the test.
// must be skipped due to conflicting formatter rules between nightly and stable
#[rustfmt::skip]
pub(crate) const NON_OWNER_BEARER_TOKEN: &str =
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvd25lcnNoaXAtdGVzdCIsImV4cCI6MjAwMDAwMDAwMH0.\
     _qb-vSkPnV_Lff2wNH4VXugc-DcvGdzJxwTmb4J48Xs";

/// The locks of the functional group.
pub(crate) const FUNCTIONS_FUNCTIONALGROUPS_DOIP_LOCKS: &str =
    formatcp!("{}/locks", FUNCTIONS_FUNCTIONALGROUPS_DOIP_BASE);

/// The locks of FLXC1000.
pub(crate) const COMPONENTS_FLXC1000_LOCKS: &str = formatcp!("{}/locks", COMPONENTS_FLXC1000_BASE);

/// The locks of the vehicle.
pub(crate) const LOCKS: &str = "locks";

/// All lock endpoints.
pub(crate) const ENDPOINTS: [&str; 3] = [
    FUNCTIONS_FUNCTIONALGROUPS_DOIP_LOCKS,
    LOCKS,
    COMPONENTS_FLXC1000_LOCKS,
];

/// Sends `method` to the lock `lock_id` at `endpoint`, or to `endpoint` itself.
///
/// # Panics
/// If the request fails or the status is not `status`.
pub(crate) async fn lock_operation(
    endpoint: &str,
    lock_id: Option<&str>,
    cda: &impl CdaClient,
    status: StatusCode,
    method: Method,
) -> Response {
    let lock_endpoint = format!(
        "{endpoint}{}",
        lock_id.map_or(String::new(), |id| format!("/{id}"))
    );
    send_authenticated_cda_request(cda, &lock_endpoint, status, method, None, None)
        .await
        .expect("lock operation failed")
}

/// Creates a lock at `endpoint` expiring after `expiration`.
///
/// # Panics
/// If the request fails or the status is not `status`.
pub(crate) async fn create_lock(
    expiration: Duration,
    endpoint: &str,
    status: StatusCode,
    cda: &impl CdaClient,
) -> Response {
    let payload = serde_json::json!({
        "lock_expiration": expiration.as_secs(),
    });
    create_lock_with_payload(endpoint, status, cda, &payload).await
}

/// Creates a lock at `endpoint` with the request body `payload`.
///
/// # Panics
/// If the request fails or the status is not `status`.
pub(crate) async fn create_lock_with_payload(
    endpoint: &str,
    status: StatusCode,
    cda: &impl CdaClient,
    payload: &Value,
) -> Response {
    send_authenticated_cda_request(
        cda,
        endpoint,
        status,
        Method::POST,
        Some(&payload.to_string()),
        None,
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
    cda: &impl CdaClient,
    endpoint: &str,
    lock_id: &str,
) -> Result<DateTime<Utc>, TestingError> {
    let response = lock_operation(endpoint, Some(lock_id), cda, StatusCode::OK, Method::GET).await;

    let expiration: String = response_to_json_to_field(&response, "lock_expiration")?;

    match expiration.parse::<DateTime<Utc>>() {
        Ok(date_time) => Ok(date_time),
        Err(_) => Err(TestingError::InvalidData(
            "Failed to parse lock expiration datetime".to_string(),
        )),
    }
}

/// A lock from [`Lock::acquire`]. A lock that is not released does not
/// outlive the test: every lease starts a new CDA.
pub(crate) struct Lock {
    endpoint: String,
    id: String,
}

impl Lock {
    /// Acquires a lock at `endpoint`, e.g. [`COMPONENTS_FLXC1000_LOCKS`],
    /// expiring after `expiration`, and checks that it can be read back.
    ///
    /// # Panics
    /// If the lock is not created or cannot be read back.
    pub(crate) async fn acquire(
        cda: &impl CdaClient,
        endpoint: &str,
        expiration: Duration,
    ) -> Self {
        let response = create_lock(expiration, endpoint, StatusCode::CREATED, cda).await;
        let id = extract_field_from_json::<String>(
            &response_to_json(&response).expect("lock response is not JSON"),
            "id",
        )
        .expect("lock response has no id");
        lock_operation(endpoint, Some(&id), cda, StatusCode::OK, Method::GET).await;
        Self {
            endpoint: endpoint.to_owned(),
            id,
        }
    }

    /// Releases the lock.
    ///
    /// # Panics
    /// If the CDA does not answer `204 No Content`.
    pub(crate) async fn release(self, cda: &impl CdaClient) {
        lock_operation(
            &self.endpoint,
            Some(&self.id),
            cda,
            StatusCode::NO_CONTENT,
            Method::DELETE,
        )
        .await;
    }
}
