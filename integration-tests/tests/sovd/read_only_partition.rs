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

use crate::{
    sovd::{
        COMPONENTS_FLXC1000_BASE, get_ecu_component,
        runtimefiles::{setup_with_lock, upload_mdd},
    },
    util::{TestingError, test_env::TestEnv},
};

/// Everything the CDA reads at startup is read-only: the root filesystem,
/// which holds the default storage directory, and the databases directory.
#[tokio::test]
async fn cda_should_work_on_a_read_only_partition() -> Result<(), TestingError> {
    let test_env = TestEnv::builder().with_read_only_rootfs().await?;

    // Served from the databases loaded out of the read-only directory.
    get_ecu_component(
        &test_env.config,
        COMPONENTS_FLXC1000_BASE,
        StatusCode::OK,
        None,
    )
    .await?;

    Ok(())
}

#[tokio::test]
async fn database_update_on_read_only_partition_returns_read_only_error() -> Result<(), TestingError>
{
    let test_env = TestEnv::builder().with_read_only_rootfs().await?;
    setup_with_lock(&test_env).await;

    let response = upload_mdd(&test_env).await;
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
    get_ecu_component(
        &test_env.config,
        COMPONENTS_FLXC1000_BASE,
        StatusCode::OK,
        None,
    )
    .await?;

    Ok(())
}
