/*
 * Copyright (c) 2025-2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
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

use std::{env, process::Command};

const DATE_FORMAT: &str = "%Y-%m-%dT%H:%M:%SZ";

fn main() {
    // Re-run on local changes or new commits
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");

    let build_date = if let Ok(source_date_epoch) = env::var("SOURCE_DATE_EPOCH") {
        // During integration tests, allow invalid or missing SOURCE_DATE_EPOCH.
        // Especially when running the tests in gitlab CI, the variable
        // maybe defined through the integration tests but is empty.
        // As it doesn't matter for the tests, we assume a default.
        // For non-test build, we want to ensure that the variable is valid.
        #[cfg(feature = "integration-tests")]
        let epoch = source_date_epoch.parse::<i64>().unwrap_or({
            println!("cargo:warning=SOURCE_DATE_EPOCH not specified, using empty");
            0i64
        });
        #[cfg(not(feature = "integration-tests"))]
        let epoch = source_date_epoch.parse::<i64>().expect(&format!(
            "SOURCE_DATE_EPOCH is not a valid integer: {source_date_epoch}"
        ));
        chrono::DateTime::from_timestamp(epoch, 0)
            .expect("SOURCE_DATE_EPOCH not in range for timestamp")
            .format(DATE_FORMAT)
            .to_string()
    } else {
        get_git_date()
    };

    let commit_hash_str = if let Ok(sha) = env::var("SOURCE_GIT_SHA") {
        sha
    } else {
        match Command::new("git")
            .args(["rev-parse", "--short", "HEAD"])
            .output()
        {
            Ok(output) if output.status.success() => {
                String::from_utf8_lossy(&output.stdout).trim().to_owned()
            }
            _ => {
                panic!("Failed to get commit hash");
            }
        }
    };

    // Make env variables available to the crate
    println!("cargo:rustc-env=BUILD_DATE={build_date}");
    println!("cargo:rustc-env=GIT_COMMIT_HASH={commit_hash_str}");
}

fn get_git_date() -> String {
    let git_output = Command::new("git")
        .args(["log", "-1", "--format=%aI"])
        .output()
        .expect("Failed to get build date via git");

    assert!(
        git_output.status.success(),
        "Git command failed: {}",
        String::from_utf8_lossy(&git_output.stderr)
    );

    let git_date = String::from_utf8_lossy(&git_output.stdout)
        .trim()
        .to_owned();

    match chrono::DateTime::parse_from_rfc3339(&git_date) {
        Ok(parsed) => parsed.format(DATE_FORMAT).to_string(),
        Err(e) => panic!("Failed to parse RFC3339 date: {e:?}"),
    }
}
