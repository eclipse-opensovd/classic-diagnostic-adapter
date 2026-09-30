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
use cda_sovd::VendorErrorCode;
use http::StatusCode;
use testcontainers::{ImageExt, runners::AsyncRunner};

use crate::{
    client::{DEFAULT_CLIENT_ID, SovdTestClient},
    sovd::{
        ECU_FLXC1000,
        runtimefiles::{setup_with_lock, upload_mdd},
    },
    util::{
        TestingError,
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
    SovdTestClient::new(&config)
        .component(ECU_FLXC1000)
        .get()
        .await?
        .expect_status(StatusCode::OK);

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
    let client = SovdTestClient::authorize(&config, DEFAULT_CLIENT_ID).await?;
    let _lock = setup_with_lock(&client).await;

    let err = upload_mdd(&client)
        .await
        .expect_err("uploading to a read-only storage must fail");
    assert_eq!(err.status(), Some(StatusCode::INTERNAL_SERVER_ERROR));
    let error = err.api_error::<VendorErrorCode>().ok_or_else(|| {
        TestingError::InvalidData(format!("Expected a JSON storage error response: {err}"))
    })?;
    assert!(
        error
            .message
            .starts_with("Storage error: Storage is read-only:"),
        "Expected a read-only storage error, got {error:?}"
    );

    // The failed write must not bring down the CDA or prevent further reads.
    SovdTestClient::new(&config)
        .component(ECU_FLXC1000)
        .get()
        .await?
        .expect_status(StatusCode::OK);

    Ok(())
}
