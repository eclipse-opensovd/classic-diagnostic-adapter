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

//! Containers for integration tests, run with `testcontainers`.
//!
//! Images are built once per test process and shared; every test starts its
//! own containers from them, so tests do not depend on each other and can run
//! in parallel.
//!
//! Instead of building, a prebuilt CDA image can be given through
//! [`CDA_TEST_IMAGE_NAME`] and [`CDA_TEST_IMAGE_TAG`], e.g. the image CI has
//! already built.

use testcontainers::{
    ContainerRequest, GenericBuildableImage, GenericImage, Image, ImageExt,
    core::{AccessMode, IntoContainerPort, Mount, WaitFor, logs::LogFrame},
    runners::AsyncBuilder,
};
use tokio::sync::OnceCell;

use crate::util::{TestingError, runtime::mdd_file_path};

/// Port the CDA serves HTTP on inside its container.
pub(crate) const CDA_HTTP_PORT: u16 = 20002;

/// Where the test databases are mounted inside the CDA container, read-only.
pub(crate) const CDA_DATABASES_DIR: &str = "/app/odx";

/// Name of a prebuilt CDA image to use instead of building one, e.g.
/// `ghcr.io/org/opensovd-cda`. Set together with [`CDA_TEST_IMAGE_TAG`].
pub(crate) const CDA_TEST_IMAGE_NAME: &str = "CDA_TEST_IMAGE_NAME";
/// Tag of the prebuilt CDA image named by [`CDA_TEST_IMAGE_NAME`].
pub(crate) const CDA_TEST_IMAGE_TAG: &str = "CDA_TEST_IMAGE_TAG";

const CDA_IMAGE_NAME: &str = "cda-integration-test";
const CDA_IMAGE_TAG: &str = "0.0.0";

/// Environment variables passed through from the test process to containers.
const PASSTHROUGH_ENV: [&str; 2] = ["RUST_LOG", "RUST_BACKTRACE"];

pub(crate) type CdaContainer = ContainerRequest<GenericImage>;

static CDA_IMAGE: OnceCell<GenericImage> = OnceCell::const_new();

/// A CDA container request for the calling test, ready to be customized and
/// started.
///
/// The test databases are mounted read-only at [`CDA_DATABASES_DIR`] and passed
/// as `--databases-dir`; replacing the arguments with `with_cmd` has to repeat
/// that. Starting it waits until the CDA reports ready on `/health/ready`, i.e.
/// has loaded its databases. [`CDA_HTTP_PORT`] is published on a random host
/// port, see `get_host_port_ipv4`.
///
/// Must be called from the test itself, not a spawned task, see
/// [`current_test_name`].
///
/// # Errors
/// Returns [`TestingError::SetupError`] if the image cannot be built, or
/// [`TestingError::PathNotFound`] if the test databases are missing.
pub(crate) async fn cda_container() -> Result<CdaContainer, TestingError> {
    let test_name = current_test_name();
    let databases_dir = mdd_file_path()?;
    let image = cda_image().await?.clone();

    let prefix = format!("[{test_name}] CDA: ");
    let mut container = image
        .with_mount(
            Mount::bind_mount(databases_dir, CDA_DATABASES_DIR)
                .with_access_mode(AccessMode::ReadOnly),
        )
        .with_cmd(["--databases-dir", CDA_DATABASES_DIR])
        .with_label("org.eclipse.opensovd.cda.test", &test_name)
        .with_log_consumer(move |record: &LogFrame| match record {
            LogFrame::StdOut(message) => {
                print!("{prefix}{}", String::from_utf8_lossy(message));
            }
            LogFrame::StdErr(message) => {
                eprint!("{prefix}{}", String::from_utf8_lossy(message));
            }
        });

    for name in PASSTHROUGH_ENV {
        if let Ok(value) = std::env::var(name) {
            container = container.with_env_var(name, value);
        }
    }

    Ok(container)
}

/// The name of the running test, for labels and log prefixes.
///
/// libtest runs every test on a thread named after the test. Code running in a
/// spawned task sees the name of a runtime worker thread instead.
fn current_test_name() -> String {
    std::thread::current()
        .name()
        .unwrap_or("unnamed-test")
        .to_owned()
}

/// The CDA image: the prebuilt one named by [`CDA_TEST_IMAGE_NAME`] and
/// [`CDA_TEST_IMAGE_TAG`] if set, otherwise built on first use.
async fn cda_image() -> Result<&'static GenericImage, TestingError> {
    CDA_IMAGE
        .get_or_try_init(|| async {
            if let Some(image) = prebuilt_image(CDA_TEST_IMAGE_NAME, CDA_TEST_IMAGE_TAG)? {
                eprintln!(
                    "Using prebuilt CDA container image {}:{}.",
                    image.name(),
                    image.tag()
                );
                return Ok(image
                    .with_exposed_port(CDA_HTTP_PORT.tcp())
                    .with_wait_for(WaitFor::healthcheck()));
            }
            eprintln!("Building CDA container image. This may take a few minutes...");
            let image = cda_buildable_image()?
                // The default BUILD_PROFILE=release; dev builds were significantly slower.
                .build_image()
                .await
                .map_err(|e| {
                    TestingError::SetupError(format!("Failed to build CDA container image: {e}"))
                })?;
            eprintln!("Completed building CDA container image.");

            Ok(image
                .with_exposed_port(CDA_HTTP_PORT.tcp())
                .with_wait_for(WaitFor::healthcheck()))
        })
        .await
}

/// The prebuilt image named by the environment variables `name_var` and
/// `tag_var`, or `None` if neither is set.
///
/// Name and tag are passed to Docker as they are; Docker rejects a malformed
/// reference when the first container is created.
///
/// # Errors
/// Returns [`TestingError::SetupError`] if only one of the two is set.
fn prebuilt_image(name_var: &str, tag_var: &str) -> Result<Option<GenericImage>, TestingError> {
    let var = |name: &str| {
        std::env::var(name)
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    };
    match (var(name_var), var(tag_var)) {
        (None, None) => Ok(None),
        (Some(name), Some(tag)) => Ok(Some(GenericImage::new(name, tag))),
        _ => Err(TestingError::SetupError(format!(
            "{name_var} and {tag_var} must be set together"
        ))),
    }
}

/// The CDA image definition: `testcontainer/cda/Dockerfile` with the
/// workspace as build context.
fn cda_buildable_image() -> Result<GenericBuildableImage, TestingError> {
    let metadata = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .map_err(|e| TestingError::SetupError(format!("Failed to read workspace metadata: {e}")))?;
    let workspace_root = metadata.workspace_root;

    let mut image = GenericBuildableImage::new(CDA_IMAGE_NAME, CDA_IMAGE_TAG)
        .with_dockerfile(workspace_root.join("testcontainer/cda/Dockerfile"))
        .with_file(
            workspace_root.join("testcontainer/cda/entrypoint.sh"),
            "/testcontainer/cda/entrypoint.sh",
        )
        .with_file(workspace_root.join("Cargo.toml"), "/Cargo.toml")
        .with_file(workspace_root.join("Cargo.lock"), "/Cargo.lock");

    for package in metadata
        .packages
        .iter()
        .filter(|package| metadata.workspace_members.contains(&package.id))
    {
        let manifest_dir = package.manifest_path.parent().ok_or_else(|| {
            TestingError::SetupError(format!("No manifest dir for {}", package.name))
        })?;
        let relative_path = manifest_dir.strip_prefix(&workspace_root).map_err(|_| {
            TestingError::SetupError(format!("{} is not in the workspace", package.name))
        })?;
        image = image.with_file(manifest_dir, format!("/{relative_path}"));
    }

    Ok(image)
}
