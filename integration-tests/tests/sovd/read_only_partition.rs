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
use opensovd_cda_lib::config::configfile::Configuration;
use testcontainers::{ImageExt, runners::AsyncRunner};

use crate::{
    sovd::{ECU_FLXC1000_ENDPOINT, get_ecu_component},
    util::{
        TestingError,
        test_containers::{CDA_HTTP_PORT, cda_container},
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

    let mut config = Configuration::default();
    config.server.address = cda
        .get_host()
        .await
        .map_err(|e| TestingError::SetupError(format!("Failed to get CDA host: {e}")))?
        .to_string();
    config.server.port = cda
        .get_host_port_ipv4(CDA_HTTP_PORT)
        .await
        .map_err(|e| TestingError::SetupError(format!("Failed to get CDA port: {e}")))?;

    // Served from the databases loaded out of the read-only directory.
    get_ecu_component(&config, ECU_FLXC1000_ENDPOINT, StatusCode::OK, None).await?;

    Ok(())
}
