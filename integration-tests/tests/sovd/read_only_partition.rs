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
use std::{path::PathBuf, thread, time::Duration};

use testcontainers::{
    ContainerRequest, GenericImage, ImageExt,
    core::{Mount, WaitFor, logs::LogFrame},
    runners::{AsyncBuilder, AsyncRunner},
};

#[tokio::test]
async fn cda_should_work_on_a_read_only_partition() {
    let cda = prepare_cda_container().await
        .with_readonly_rootfs(true);

    let cda = {
        let databases_dir_on_host = PathBuf::from("../testcontainer/odx")
            .canonicalize()
            .unwrap(); //need absolute path
        let databases_dir_in_container = "/odx";

        cda.with_cmd(["--databases-dir", databases_dir_in_container])
            .with_mount(Mount::bind_mount(
                databases_dir_on_host.to_string_lossy(),
                databases_dir_in_container,
            ))
    };

    let container = cda.start().await.unwrap();

    eprintln!("CDA container started!");

    tokio::time::sleep(Duration::from_secs(5)).await; //TODO trigger some requests on CDA to ensure nothing writes to disk (except the Update plugin)

    eprintln!("Terminating and removing CDA container!");
}

pub type CdaContainer = ContainerRequest<GenericImage>;

//TODO move into util module
pub async fn prepare_cda_container() -> CdaContainer {
    eprintln!("Building CDA container image. This may take a few minutes...");

    let metadata = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .expect("Failed to read workspace metadata");

    let workspace_root = metadata.workspace_root;

    let mut image = testcontainers::GenericBuildableImage::new("cda-integration-test", "0.0.0")
        .with_dockerfile(workspace_root.join("testcontainer/cda/Dockerfile"))
        .with_file(
            workspace_root.join("testcontainer/cda/entrypoint.sh"),
            "/testcontainer/cda/entrypoint.sh",
        )
        .with_file(workspace_root.join("Cargo.toml"), "/Cargo.toml")
        .with_file(workspace_root.join("Cargo.lock"), "/Cargo.lock");

    for package in &metadata.packages {
        if metadata.workspace_members.contains(&package.id) {
            let manifest_dir = package
                .manifest_path
                .parent()
                .expect("Missing manifest dir");
            let relative_path = manifest_dir
                .strip_prefix(&workspace_root)
                .expect("Not in workspace");
            let target_path = format!("/{}", relative_path.as_str());
            image = image.with_file(manifest_dir, target_path);
        }
    }

    let image = image
        // use default BUILD_PROFILE=release here; setting BUILD_PROFILE=dev made the build significantly slower
        .build_image()
        .await
        .expect("Failed to build CDA container image");

    eprintln!("Completed building CDA container image. Preparing run...");

    let mut image = image
        .with_wait_for(WaitFor::message_on_either_std("CDA fully initialized")) //substring match
        .with_log_consumer(|record: &LogFrame| match record {
            LogFrame::StdOut(message) => {
                print!("CDA: {}", String::from_utf8_lossy(message));
            }
            LogFrame::StdErr(message) => {
                eprint!("CDA: {}", String::from_utf8_lossy(message));
            }
        });

    let thread_name = thread::current().name()
        .expect("Cannot determine name of test thread for naming CDA container")
        .replace("::", ".");
    image = image.with_container_name(format!("cda-integration-test-{thread_name}"));

    // passthrough envs into container
    if let Some(env) = option_env!("RUST_LOG") {
        image = image.with_env_var("RUST_LOG", env)
    }
    if let Some(env) = option_env!("RUST_BACKTRACE") {
        image = image.with_env_var("RUST_BACKTRACE", env)
    }

    image
}
