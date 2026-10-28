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
use opensovd_cda_lib::cda_version;

use crate::{client::data::Version, util::test_env::TestEnv};

fn assert_version_response(version: &Version) {
    assert_eq!(version.id, "version");
    assert_eq!(
        version.data.name,
        "Eclipse OpenSOVD Classic Diagnostic Adapter"
    );
    assert_eq!(version.data.api.version, "1.1");
    assert_eq!(version.data.implementation.version, cda_version());
}

/// [[ itest~sovd-api-version-endpoint, Version Endpoint Integration Test, itest ]]
#[tokio::test]
async fn test_version_endpoint() {
    let test_env = TestEnv::builder().await.unwrap();
    let client = test_env.anonymous_client();

    // Test app-scoped version endpoint
    let version = client
        .sovd2uds()
        .version()
        .await
        .expect("GET app version endpoint failed")
        .expect_status(StatusCode::OK);
    assert_version_response(&version);

    // Test global version endpoint
    let version = client
        .version()
        .await
        .expect("GET global version endpoint failed")
        .expect_status(StatusCode::OK);
    assert_version_response(&version);
}
