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
use http::StatusCode;
use testcontainers::{ImageExt, runners::AsyncRunner};

use crate::{
    sovd::{
        ECU_FLXC1000_ENDPOINT, get_ecu_component,
        runtimefiles::{setup_with_lock_with_headers, upload_mdd_with_headers},
    },
    util::{
        TestingError,
        http::auth_header,
        test_containers::{cda_container, cda_container_config},
    },
};

/// Everything the CDA reads at startup is read-only: the root filesystem,
/// which holds the default storage directory, and the databases directory.
#[tokio::test]
async fn cda_should_work_on_a_read_only_partition() -> Result<(), TestingError> {
    let cda = cda_container()
        .await?
        .with_readonly_rootfs(true)
        // Returns once the CDA reports ready, i.e. has loaded its databases.
        .start()
        .await
        .map_err(|e| TestingError::SetupError(format!("Failed to start CDA container: {e}")))?;

    let config = cda_container_config(&cda).await?;

    // Served from the databases loaded out of the read-only directory.
    get_ecu_component(&config, ECU_FLXC1000_ENDPOINT, StatusCode::OK, None).await?;

    Ok(())
}

#[tokio::test]
async fn database_update_on_read_only_partition_returns_read_only_error() -> Result<(), TestingError>
{
    let cda = cda_container()
        .await?
        .with_readonly_rootfs(true)
        .start()
        .await
        .map_err(|e| TestingError::SetupError(format!("Failed to start CDA container: {e}")))?;

    let config = cda_container_config(&cda).await?;
    let auth = auth_header(&config, None).await?;
    let _lock_id = setup_with_lock_with_headers(&config, &auth).await;

    let response = upload_mdd_with_headers(&config, &auth).await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = response
        .text()
        .await
        .map_err(|e| TestingError::InvalidData(format!("Could not read storage error: {e}")))?;
    let error: serde_json::Value = serde_json::from_str(&body).map_err(|e| {
        TestingError::InvalidData(format!("Expected a JSON storage error response: {e}"))
    })?;
    assert!(
        error
            .get("message")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|message| message.starts_with("Storage error: Storage is read-only:")),
        "Expected a read-only storage error, got {error}"
    );

    // The failed write must not bring down the CDA or prevent further reads.
    get_ecu_component(&config, ECU_FLXC1000_ENDPOINT, StatusCode::OK, None).await?;

    Ok(())
}
