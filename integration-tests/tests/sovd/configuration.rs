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

use opensovd_cda_lib::config::configfile::{Configuration, DatabaseConfig};

use crate::util::runtime::{find_available_tcp_port, start_cda, stop_cda, wait_for_cda_online};

/// The CDA must keep running when its database path contains no MDD files.
#[tokio::test]
async fn cda_stays_running_when_no_database_loaded() {
    let empty_db_dir = tempfile::tempdir().expect("create empty temp db dir");

    let host = "127.0.0.1".to_owned();
    let port = find_available_tcp_port(&host).expect("find free port");

    let mut config = Configuration {
        database: DatabaseConfig {
            seed_dir: empty_db_dir.path().to_string_lossy().into_owned(),
            ..Default::default()
        },
        ..Configuration::default()
    };
    config.server.address.clone_from(&host);
    config.server.port = port;
    // Disable DoIP so no transport socket is bound, avoids binding failures on
    // interfaces that only exist inside the compose network.
    config.doip.enabled = false;

    start_cda(config.clone());

    wait_for_cda_online(&config.server)
        .await
        .expect("CDA must stay running without any database");

    stop_cda().await.expect("Failed to stop CDA");
}
