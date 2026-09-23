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
//! Instead of building, a prebuilt image can be given by name and tag through
//! the variables of [`CDA_TEST_IMAGE`], [`ECU_SIM_TEST_IMAGE`] or
//! [`SOCKETCAND_TEST_IMAGE`].
//! This avoids building in every test process, e.g. under `cargo nextest`,
//! which runs every test in its own process.

use std::{
    future::Future,
    path::PathBuf,
    sync::{
        Arc, LazyLock, Mutex, Once, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use futures::StreamExt;
use testcontainers::{
    ContainerRequest, GenericBuildableImage, GenericImage, Healthcheck, Image, ImageExt,
    bollard::{container::LogOutput, query_parameters::LogsOptionsBuilder},
    core::{
        AccessMode, BuildImageOptions, IntoContainerPort, Mount, WaitFor,
        client::docker_client_instance, logs::LogFrame,
    },
    runners::AsyncBuilder,
};
use tokio::sync::OnceCell;

use crate::util::{
    TestingError,
    config::{CAN_BUS_NAME, SOCKETCAND_PORT, mdd_file_path, test_container_dir},
    test_env::{can_infra, coverage_mode},
};

/// Port the CDA serves HTTP on inside its container.
pub(crate) const CDA_HTTP_PORT: u16 = 20002;

/// Where the test databases are mounted inside the CDA container, read-only.
pub(crate) const CDA_DATABASES_DIR: &str = "/app/odx";

/// Port of the ecu-sim control API inside its container.
pub(crate) const ECU_SIM_CONTROL_PORT: u16 = 8181;

/// Environment variables naming a prebuilt image to use instead of building
/// one. Name and tag are set together, e.g. `ghcr.io/org/opensovd-cda` and
/// `coverage`, and passed to Docker as they are.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PrebuiltImageVars {
    pub(crate) name: &'static str,
    pub(crate) tag: &'static str,
}

/// Prebuilt CDA image. It is used for every [`CdaVariant`], so it has to match
/// the variant the tests need.
pub(crate) const CDA_TEST_IMAGE: PrebuiltImageVars = PrebuiltImageVars {
    name: "CDA_TEST_IMAGE_NAME",
    tag: "CDA_TEST_IMAGE_TAG",
};
/// Prebuilt ecu-sim image.
pub(crate) const ECU_SIM_TEST_IMAGE: PrebuiltImageVars = PrebuiltImageVars {
    name: "ECU_SIM_TEST_IMAGE_NAME",
    tag: "ECU_SIM_TEST_IMAGE_TAG",
};
/// Prebuilt socketcand image.
pub(crate) const SOCKETCAND_TEST_IMAGE: PrebuiltImageVars = PrebuiltImageVars {
    name: "SOCKETCAND_TEST_IMAGE_NAME",
    tag: "SOCKETCAND_TEST_IMAGE_TAG",
};

const CDA_IMAGE_NAME: &str = "cda-integration-test";
const ECU_SIM_IMAGE_NAME: &str = "ecu-sim-integration-test";
const SOCKETCAND_IMAGE_NAME: &str = "socketcand-integration-test";
const LOCAL_IMAGE_TAG: &str = "0.0.0";

/// Label holding the name of the test that started a container.
const TEST_LABEL: &str = "org.eclipse.opensovd.cda.test";
/// Label holding the service a container runs, e.g. `ecu-sim`.
pub(crate) const SERVICE_LABEL: &str = "org.eclipse.opensovd.cda.test.service";
/// Label holding the [`session_id`] of the test process that started a
/// container. The containers of a process are removed at its exit, see
/// [`register_session_cleanup`].
pub(crate) const SESSION_LABEL: &str = "org.eclipse.opensovd.cda.test.session";

/// A file of zeros added to every build context.
///
/// `testcontainers` uploads the build context as the body of the build request
/// and `BuildKit` loads it as a remote context. With Docker Desktop 29.8, loading
/// it hung indefinitely at `[internal] load remote build context` for contexts
/// of roughly 100 KB to 1 MB, like the ecu-sim one, while smaller and larger
/// ones (from about 2 MB) loaded in well under a second. The padding keeps
/// every context in the working range.
const BUILD_CONTEXT_PADDING: &str = "/.build-context-padding";
const BUILD_CONTEXT_PADDING_SIZE: usize = 4 * 1024 * 1024;

/// Where a coverage-instrumented CDA writes its profile. Every container runs
/// the CDA once, so one fixed file per container suffices, and it can be copied
/// out as a single file.
const CDA_COVERAGE_PROFILE_FILE: &str = "/app/coverage/cda.profraw";
/// The CDA binary in its image, needed to decode the coverage profiles.
const CDA_BINARY: &str = "/app/opensovd-cda";

/// How often the healthchecks of the containers run during their start period.
///
/// Docker probes every 5 s during the start period unless a start interval is
/// set, so a container that is up after about 1 s was only reported healthy,
/// and `testcontainers` only returned from `start`, after about 5 s.
const HEALTHCHECK_START_INTERVAL: Duration = Duration::from_millis(100);

/// ecu-sim is a JVM service; on a loaded machine it takes a while to come up.
pub(crate) const ECU_SIM_STARTUP_TIMEOUT: Duration = Duration::from_secs(3 * 60);
const SOCKETCAND_STARTUP_TIMEOUT: Duration = Duration::from_secs(60);

/// Environment variables passed through from the test process to containers.
const PASSTHROUGH_ENV: [&str; 2] = ["RUST_LOG", "RUST_BACKTRACE"];

pub(crate) type CdaContainer = ContainerRequest<GenericImage>;
pub(crate) type EcuSimContainer = ContainerRequest<GenericImage>;
pub(crate) type SocketcandContainer = ContainerRequest<GenericImage>;

static CDA_IMAGE_RELEASE: OnceCell<GenericImage> = OnceCell::const_new();
static CDA_IMAGE_RELEASE_CAN: OnceCell<GenericImage> = OnceCell::const_new();
static CDA_IMAGE_COVERAGE: OnceCell<GenericImage> = OnceCell::const_new();
static CDA_IMAGE_COVERAGE_CAN: OnceCell<GenericImage> = OnceCell::const_new();
static ECU_SIM_IMAGE: OnceCell<GenericImage> = OnceCell::const_new();
static SOCKETCAND_IMAGE: OnceCell<GenericImage> = OnceCell::const_new();

/// Build variant of the CDA image. Every variant is a separate image, built at
/// most once per test process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CdaVariant {
    /// Compile in the socketcand-backed CAN transport (`can-socketcand`).
    pub(crate) can: bool,
    /// Build with coverage instrumentation. Like every variant, it is an
    /// optimized build with debug assertions and overflow checks, see
    /// `CHECK_RUSTFLAGS` in `testcontainer/cda/Dockerfile`.
    pub(crate) coverage: bool,
}

impl CdaVariant {
    /// The variant selected by the environment: CAN when the CAN
    /// infrastructure is in use (pure CAN or mixed), coverage when
    /// `CDA_INTEGRATION_TEST_COVERAGE` is set.
    pub(crate) fn from_env() -> Self {
        Self {
            can: can_infra(),
            coverage: coverage_mode(),
        }
    }

    fn tag(self) -> &'static str {
        match (self.coverage, self.can) {
            (false, false) => "release",
            (false, true) => "release-can",
            (true, false) => "coverage",
            (true, true) => "coverage-can",
        }
    }

    fn image_cell(self) -> &'static OnceCell<GenericImage> {
        match (self.coverage, self.can) {
            (false, false) => &CDA_IMAGE_RELEASE,
            (false, true) => &CDA_IMAGE_RELEASE_CAN,
            (true, false) => &CDA_IMAGE_COVERAGE,
            (true, true) => &CDA_IMAGE_COVERAGE_CAN,
        }
    }

    /// Build arguments of `testcontainer/cda/Dockerfile` for this variant.
    fn build_options(self) -> BuildImageOptions {
        let mut options = BuildImageOptions::new()
            .with_build_arg("SOURCE_DATE_EPOCH", "0")
            .with_build_arg("SOURCE_GIT_SHA", "unknown");
        if self.can {
            options = options.with_build_arg("CDA_FEATURES", "can-socketcand");
        }
        if self.coverage {
            options = options.with_build_arg("RUSTFLAGS", "-C instrument-coverage");
        }
        options
    }
}

/// Where the ecu-sim reaches socketcand to serve its ECUs over CAN.
#[derive(Clone, Debug)]
pub(crate) struct SocketcandEndpoint {
    /// Host name or IP of socketcand, as seen from the ecu-sim container.
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) bus: String,
}

impl SocketcandEndpoint {
    /// socketcand on `host` with the default port and bus.
    pub(crate) fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port: SOCKETCAND_PORT,
            bus: CAN_BUS_NAME.to_owned(),
        }
    }
}

/// Who the containers of a test belong to: the test named in their
/// [`TEST_LABEL`], and the name their output is prefixed with.
///
/// The log name is shared by all containers of an owner and can be changed
/// while they run, so the output of a pooled environment names the test that
/// currently leases it.
#[derive(Clone, Debug)]
pub(crate) struct ContainerOwner {
    test_name: String,
    log_name: Arc<Mutex<String>>,
    log_frames: Arc<AtomicU64>,
}

impl ContainerOwner {
    /// The calling test, see [`current_test_name`].
    pub(crate) fn current_test() -> Self {
        Self::new(current_test_name())
    }

    pub(crate) fn new(test_name: impl Into<String>) -> Self {
        let test_name = test_name.into();
        Self {
            log_name: Arc::new(Mutex::new(test_name.clone())),
            test_name,
            log_frames: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Prefixes the output of the owned containers with `log_name` from now on.
    pub(crate) fn set_log_name(&self, log_name: impl Into<String>) {
        *self.log_name.lock().unwrap_or_else(PoisonError::into_inner) = log_name.into();
    }

    /// How many log frames of the owned containers have been printed so far.
    pub(crate) fn log_frames(&self) -> u64 {
        self.log_frames.load(Ordering::Relaxed)
    }

    fn print(&self, service: &str, stderr: bool, message: &[u8]) {
        let prefix = format!(
            "[{}] {service}: ",
            self.log_name.lock().unwrap_or_else(PoisonError::into_inner)
        );
        let message = String::from_utf8_lossy(message);
        if stderr {
            eprint!("{prefix}{message}");
        } else {
            print!("{prefix}{message}");
        }
        self.log_frames.fetch_add(1, Ordering::Relaxed);
    }
}

/// A CDA container request for the calling test, built as the variant selected
/// by the environment, see [`CdaVariant::from_env`] and
/// [`cda_container_variant`].
///
/// # Errors
/// See [`cda_container_variant`].
pub(crate) async fn cda_container() -> Result<CdaContainer, TestingError> {
    cda_container_variant(CdaVariant::from_env()).await
}

/// A CDA container request of the given variant for the calling test, ready to
/// be customized and started.
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
pub(crate) async fn cda_container_variant(
    variant: CdaVariant,
) -> Result<CdaContainer, TestingError> {
    cda_container_for(variant, &ContainerOwner::current_test()).await
}

/// Like [`cda_container_variant`], for the containers of `owner`. Can be
/// called from any task.
///
/// # Errors
/// See [`cda_container_variant`].
pub(crate) async fn cda_container_for(
    variant: CdaVariant,
    owner: &ContainerOwner,
) -> Result<CdaContainer, TestingError> {
    let databases_dir = mdd_file_path()?;
    let image = cda_image(variant).await?;

    let mut container = with_test_defaults(
        image
            .with_mount(
                Mount::bind_mount(databases_dir, CDA_DATABASES_DIR)
                    .with_access_mode(AccessMode::ReadOnly),
            )
            .with_cmd(["--databases-dir", CDA_DATABASES_DIR])
            // The healthcheck of the image, probed every 100 ms while the CDA
            // starts, see HEALTHCHECK_START_INTERVAL.
            .with_health_check(
                Healthcheck::cmd_shell(format!(
                    "curl -fsS http://localhost:{CDA_HTTP_PORT}/health/ready || exit 1"
                ))
                .with_interval(Duration::from_secs(1))
                .with_timeout(Duration::from_secs(5))
                .with_retries(30)
                .with_start_period(Duration::from_secs(30))
                .with_start_interval(HEALTHCHECK_START_INTERVAL),
            ),
        "cda",
        owner,
    );
    if variant.coverage {
        container = container.with_env_var("LLVM_PROFILE_FILE", CDA_COVERAGE_PROFILE_FILE);
    }

    Ok(container)
}

/// An ecu-sim container request for the calling test, ready to be customized
/// and started.
///
/// The container is privileged with `NET_ADMIN`, so the sim can
/// add its extra IPs (`USE_MULTIPLE_IPS`) to `eth0`. With `can`, the sim also
/// serves its ECUs over CAN through that socketcand; without, it is
/// `DoIP`-only. Starting it waits until the control API on
/// [`ECU_SIM_CONTROL_PORT`] answers, which is published on a random host port.
///
/// Must be called from the test itself, not a spawned task, see
/// [`current_test_name`].
///
/// # Errors
/// Returns [`TestingError::SetupError`] if the image cannot be built, or
/// [`TestingError::PathNotFound`] if the `testcontainer` directory is missing.
pub(crate) async fn ecu_sim_container(
    can: Option<&SocketcandEndpoint>,
) -> Result<EcuSimContainer, TestingError> {
    ecu_sim_container_for(can, &ContainerOwner::current_test()).await
}

/// Like [`ecu_sim_container`], for the containers of `owner`. Can be called
/// from any task.
///
/// # Errors
/// See [`ecu_sim_container`].
pub(crate) async fn ecu_sim_container_for(
    can: Option<&SocketcandEndpoint>,
    owner: &ContainerOwner,
) -> Result<EcuSimContainer, TestingError> {
    let image = ecu_sim_image().await?;

    let mut container = with_test_defaults(
        image
            .with_privileged(true)
            .with_cap_add("NET_ADMIN")
            .with_env_var("USE_MULTIPLE_IPS", "true")
            .with_env_var("SIM_NETWORK_INTERFACE", "eth0")
            .with_health_check(
                Healthcheck::cmd_shell(format!(
                    "curl -f http://localhost:{ECU_SIM_CONTROL_PORT}/ || exit 1"
                ))
                .with_interval(Duration::from_secs(1))
                .with_timeout(Duration::from_secs(5))
                .with_retries(10)
                .with_start_period(Duration::from_secs(30))
                .with_start_interval(HEALTHCHECK_START_INTERVAL),
            )
            .with_startup_timeout(ECU_SIM_STARTUP_TIMEOUT),
        "ecu-sim",
        owner,
    );
    if let Some(can) = can {
        container = container
            .with_env_var("SIM_CAN_SOCKETCAND_HOST", &can.host)
            .with_env_var("SIM_CAN_SOCKETCAND_PORT", can.port.to_string())
            .with_env_var("SIM_CAN_SOCKETCAND_BUS", &can.bus);
    }

    Ok(container)
}

/// A socketcand container request for the calling test, ready to be customized
/// and started.
///
/// It creates the `vcan0` bus at start, which needs the `vcan` kernel module on
/// the Docker host, and serves it on [`SOCKETCAND_PORT`] of the container's
/// `eth0`. Starting it waits until that port is listening; it is also
/// published on a random host port.
///
/// The bus is created in the network namespace of the container, so every
/// socketcand container has a `vcan0` of its own, and the CDA and ecu-sim
/// connected to it over TCP share a bus with nobody else.
///
/// Must be called from the test itself, not a spawned task, see
/// [`current_test_name`].
///
/// # Errors
/// Returns [`TestingError::SetupError`] if the image cannot be built, or
/// [`TestingError::PathNotFound`] if the `testcontainer` directory is missing.
pub(crate) async fn socketcand_container() -> Result<SocketcandContainer, TestingError> {
    socketcand_container_for(&ContainerOwner::current_test()).await
}

/// Like [`socketcand_container`], for the containers of `owner`. Can be called
/// from any task.
///
/// # Errors
/// See [`socketcand_container`].
pub(crate) async fn socketcand_container_for(
    owner: &ContainerOwner,
) -> Result<SocketcandContainer, TestingError> {
    let image = socketcand_image().await?;

    Ok(with_test_defaults(
        image
            .with_privileged(true)
            .with_cap_add("NET_ADMIN")
            .with_health_check(
                Healthcheck::cmd_shell(format!("ss -ltn | grep -q {SOCKETCAND_PORT} || exit 1"))
                    .with_interval(Duration::from_secs(1))
                    .with_timeout(Duration::from_secs(5))
                    .with_retries(15)
                    .with_start_period(Duration::from_secs(10))
                    .with_start_interval(HEALTHCHECK_START_INTERVAL),
            )
            .with_startup_timeout(SOCKETCAND_STARTUP_TIMEOUT),
        "socketcand",
        owner,
    ))
}

/// Settings every test container gets: labels with the test name, the service
/// and the [`session_id`], a log consumer printing the container output
/// prefixed with the owner's log name and the service, and the
/// [`PASSTHROUGH_ENV`] variables of the test process.
fn with_test_defaults(
    container: ContainerRequest<GenericImage>,
    service: &'static str,
    owner: &ContainerOwner,
) -> ContainerRequest<GenericImage> {
    register_session_cleanup();

    let log_owner = owner.clone();
    let mut container = container
        .with_label(TEST_LABEL, &owner.test_name)
        .with_label(SERVICE_LABEL, service)
        .with_label(SESSION_LABEL, session_id())
        .with_log_consumer(move |record: &LogFrame| match record {
            LogFrame::StdOut(message) => log_owner.print(service, false, message),
            LogFrame::StdErr(message) => log_owner.print(service, true, message),
        });

    for name in PASSTHROUGH_ENV {
        if let Ok(value) = std::env::var(name) {
            container = container.with_env_var(name, value);
        }
    }

    container
}

/// Prints the output of the container `container_id` from `since` (seconds
/// since the Unix epoch) on, like the log consumer of [`with_test_defaults`],
/// until the container stops.
///
/// The log consumer of a container ends when the container stops, so a
/// container that is started again needs this to keep its output visible.
/// Spawns onto the current runtime.
pub(crate) fn follow_logs_since(
    container_id: String,
    service: &'static str,
    owner: ContainerOwner,
    since: i32,
) {
    tokio::spawn(async move {
        let docker = match docker_client_instance().await {
            Ok(docker) => docker,
            Err(e) => {
                eprintln!("Failed to follow the logs of {service} {container_id}: {e}");
                return;
            }
        };
        let options = LogsOptionsBuilder::new()
            .follow(true)
            .stdout(true)
            .stderr(true)
            .since(since)
            .build();
        let mut logs = docker.logs(&container_id, Some(options));
        while let Some(Ok(output)) = logs.next().await {
            match output {
                LogOutput::StdErr { message } => owner.print(service, true, &message),
                LogOutput::StdOut { message } | LogOutput::Console { message } => {
                    owner.print(service, false, &message);
                }
                LogOutput::StdIn { .. } => {}
            }
        }
    });
}

/// Seconds since the Unix epoch, as taken by [`follow_logs_since`].
pub(crate) fn unix_time_secs() -> i32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i32::try_from(elapsed.as_secs()).ok())
        .unwrap_or(0)
}

/// Identifies this test process in the [`SESSION_LABEL`] of its containers:
/// its PID and start time, so it stays unique when PIDs are reused.
pub(crate) fn session_id() -> &'static str {
    static SESSION_ID: LazyLock<String> =
        LazyLock::new(|| format!("{}-{}", std::process::id(), unix_time_secs()));
    &SESSION_ID
}

/// Removes the containers of this [`session_id`] at process exit, and the
/// networks named after it (see [`session_network_prefix`]).
///
/// Dropped containers remove themselves, but pooled test environments live in
/// statics, which are never dropped. With coverage, the CDA containers are
/// first stopped gracefully and their profiles copied out, like when a CDA
/// container is removed during the run.
fn register_session_cleanup() {
    static REGISTERED: Once = Once::new();

    extern "C" fn cleanup() {
        let session = format!("label={SESSION_LABEL}={}", session_id());
        let containers = docker_cli_lines(&["ps", "-aq", "--filter", &session]);
        if coverage_mode() {
            let cda = format!("label={SERVICE_LABEL}=cda");
            let cdas = docker_cli_lines(&["ps", "-aq", "--filter", &session, "--filter", &cda]);
            if !cdas.is_empty() {
                let mut stop = vec!["stop", "-t", "10"];
                stop.extend(cdas.iter().map(String::as_str));
                docker_cli_lines(&stop);
            }
            for id in &cdas {
                save_coverage_with_cli(id);
            }
        }
        if !containers.is_empty() {
            let mut rm = vec!["rm", "-f", "-v"];
            rm.extend(containers.iter().map(String::as_str));
            docker_cli_lines(&rm);
        }
        let networks = docker_cli_lines(&[
            "network",
            "ls",
            "-q",
            "--filter",
            &format!("name={}", session_network_prefix()),
        ]);
        if !networks.is_empty() {
            let mut rm = vec!["network", "rm"];
            rm.extend(networks.iter().map(String::as_str));
            docker_cli_lines(&rm);
        }
    }

    REGISTERED.call_once(|| {
        // SAFETY: `cleanup` is a plain `extern "C"` function without arguments,
        // as `atexit` requires.
        unsafe {
            libc::atexit(cleanup);
        }
    });
}

/// Every network of this [`session_id`] is named with this prefix, so the
/// session cleanup can find them; `testcontainers` creates networks without
/// labels.
pub(crate) fn session_network_prefix() -> String {
    format!("cda-itest-{}-", session_id())
}

/// Runs the docker CLI and returns the lines of its output, or none if it
/// fails, which is reported on stderr.
fn docker_cli_lines(args: &[&str]) -> Vec<String> {
    match std::process::Command::new("docker").args(args).output() {
        Ok(output) if output.status.success() => String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
        Ok(output) => {
            eprintln!(
                "docker {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            );
            Vec::new()
        }
        Err(e) => {
            eprintln!("Failed to run docker {}: {e}", args.join(" "));
            Vec::new()
        }
    }
}

/// Copies the coverage profile of the stopped CDA container `container_id` and,
/// once per process, the CDA binary to [`coverage_output_dir`], with the docker
/// CLI. Blocks.
///
/// `testcontainers` can copy files out of a container too, but its futures for
/// that are not `Send`, so they cannot run on the shared runtime.
pub(crate) fn save_coverage_with_cli(container_id: &str) {
    let Some(dir) = coverage_output_dir() else {
        return;
    };
    let profile = dir.join(coverage_profile_name(container_id));
    docker_cli_lines(&[
        "cp",
        &format!("{container_id}:{CDA_COVERAGE_PROFILE_FILE}"),
        &profile.to_string_lossy(),
    ]);
    if claim_coverage_binary_copy() {
        let status = std::process::Command::new("docker")
            .arg("cp")
            .arg(format!("{container_id}:{CDA_BINARY}"))
            .arg(dir.join("opensovd-cda"))
            .status();
        if !status.is_ok_and(|status| status.success()) {
            eprintln!("Failed to copy the CDA binary out of {container_id}");
            release_coverage_binary_copy();
        }
    }
}

/// `<workspace>/target/coverage`, created if missing, where the coverage
/// profiles of the CDA containers and the CDA binary are collected for
/// `.github/actions/process-docker-coverage`.
fn coverage_output_dir() -> Option<PathBuf> {
    let dir = test_container_dir()
        .ok()?
        .parent()?
        .join("target")
        .join("coverage");
    match std::fs::create_dir_all(&dir) {
        Ok(()) => Some(dir),
        Err(e) => {
            eprintln!("Failed to create coverage directory {}: {e}", dir.display());
            None
        }
    }
}

/// File name of the coverage profile of the CDA container `container_id`,
/// unique across containers and test processes.
fn coverage_profile_name(container_id: &str) -> String {
    let id: String = container_id.chars().take(12).collect();
    format!("cda-{}-{id}.profraw", session_id())
}

static COVERAGE_BINARY_CLAIMED: AtomicBool = AtomicBool::new(false);

/// Whether the caller is the first to copy out the CDA binary in this process.
/// A caller whose copy failed hands the job on with
/// [`release_coverage_binary_copy`].
fn claim_coverage_binary_copy() -> bool {
    !COVERAGE_BINARY_CLAIMED.swap(true, Ordering::SeqCst)
}

fn release_coverage_binary_copy() {
    COVERAGE_BINARY_CLAIMED.store(false, Ordering::SeqCst);
}

/// The name of the running test, for labels and log prefixes.
///
/// libtest runs every test on a thread named after the test. Code running in a
/// spawned task sees the name of a runtime worker thread instead.
pub(crate) fn current_test_name() -> String {
    std::thread::current()
        .name()
        .unwrap_or("unnamed-test")
        .to_owned()
}

/// The CDA image of the given variant, built on first use.
async fn cda_image(variant: CdaVariant) -> Result<GenericImage, TestingError> {
    let service = format!("CDA ({})", variant.tag());
    let image = cached_image(variant.image_cell(), &service, CDA_TEST_IMAGE, || async {
        build_image(
            cda_buildable_image(variant)?,
            variant.build_options(),
            &service,
        )
        .await
    })
    .await?;

    Ok(image
        .with_exposed_port(CDA_HTTP_PORT.tcp())
        .with_wait_for(WaitFor::healthcheck()))
}

/// The ecu-sim image, built on first use.
async fn ecu_sim_image() -> Result<GenericImage, TestingError> {
    let image = cached_image(&ECU_SIM_IMAGE, "ecu-sim", ECU_SIM_TEST_IMAGE, || async {
        build_image(
            ecu_sim_buildable_image()?,
            BuildImageOptions::new(),
            "ecu-sim",
        )
        .await
    })
    .await?;

    Ok(image
        .with_exposed_port(ECU_SIM_CONTROL_PORT.tcp())
        .with_wait_for(WaitFor::healthcheck()))
}

/// The socketcand image, built on first use.
async fn socketcand_image() -> Result<GenericImage, TestingError> {
    let image = cached_image(
        &SOCKETCAND_IMAGE,
        "socketcand",
        SOCKETCAND_TEST_IMAGE,
        || async {
            build_image(
                socketcand_buildable_image()?,
                BuildImageOptions::new(),
                "socketcand",
            )
            .await
        },
    )
    .await?;

    Ok(image
        .with_exposed_port(SOCKETCAND_PORT.tcp())
        .with_wait_for(WaitFor::healthcheck()))
}

/// The image in `cell`, initialized on first use: the prebuilt image named by
/// `prebuilt` if set, otherwise built by `build`.
async fn cached_image<F, Fut>(
    cell: &'static OnceCell<GenericImage>,
    service: &str,
    prebuilt: PrebuiltImageVars,
    build: F,
) -> Result<GenericImage, TestingError>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<GenericImage, TestingError>>,
{
    cell.get_or_try_init(|| async {
        if let Some(image) = prebuilt_image(prebuilt)? {
            eprintln!(
                "Using prebuilt {service} container image {}:{}.",
                image.name(),
                image.tag()
            );
            return Ok(image);
        }
        eprintln!("Building {service} container image. This may take a few minutes...");
        let image = build().await?;
        eprintln!("Completed building {service} container image.");
        Ok(image)
    })
    .await
    .cloned()
}

/// The prebuilt image named by `vars`, or `None` if neither variable is set.
///
/// Name and tag are passed to Docker as they are; Docker rejects a malformed
/// reference when the first container is created.
///
/// # Errors
/// Returns [`TestingError::SetupError`] if only one of the two is set.
fn prebuilt_image(vars: PrebuiltImageVars) -> Result<Option<GenericImage>, TestingError> {
    let var = |name: &str| {
        std::env::var(name)
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    };
    match (var(vars.name), var(vars.tag)) {
        (None, None) => Ok(None),
        (Some(name), Some(tag)) => Ok(Some(GenericImage::new(name, tag))),
        _ => Err(TestingError::SetupError(format!(
            "{} and {} must be set together",
            vars.name, vars.tag
        ))),
    }
}

/// Builds `image`, with [`BUILD_CONTEXT_PADDING`] added to its build context.
async fn build_image(
    image: GenericBuildableImage,
    options: BuildImageOptions,
    service: &str,
) -> Result<GenericImage, TestingError> {
    image
        .with_data(vec![0u8; BUILD_CONTEXT_PADDING_SIZE], BUILD_CONTEXT_PADDING)
        .build_image_with(options)
        .await
        .map_err(|e| {
            TestingError::SetupError(format!("Failed to build {service} container image: {e}"))
        })
}

/// The CDA image definition: `testcontainer/cda/Dockerfile` with the
/// workspace as build context, tagged per variant.
fn cda_buildable_image(variant: CdaVariant) -> Result<GenericBuildableImage, TestingError> {
    let metadata = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .map_err(|e| TestingError::SetupError(format!("Failed to read workspace metadata: {e}")))?;
    let workspace_root = metadata.workspace_root;

    let mut image = GenericBuildableImage::new(CDA_IMAGE_NAME, variant.tag())
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

/// The ecu-sim image definition: `testcontainer/ecu-sim/docker/Dockerfile`.
///
/// The build context holds only the sources the Gradle build needs. The build
/// context is not filtered by a `.dockerignore`, and the directory usually
/// also holds large local Gradle and IDE outputs (`build/`, `.gradle/`, ...).
fn ecu_sim_buildable_image() -> Result<GenericBuildableImage, TestingError> {
    let ecu_sim_dir = test_container_dir()?.join("ecu-sim");

    let mut image = GenericBuildableImage::new(ECU_SIM_IMAGE_NAME, LOCAL_IMAGE_TAG)
        .with_dockerfile(ecu_sim_dir.join("docker/Dockerfile"));
    for path in [
        // Read by ktlint, which runs as part of `gradle build`.
        ".editorconfig",
        "build.gradle.kts",
        "settings.gradle.kts",
        "gradle.properties",
        "gradle",
        "src",
        "docker",
    ] {
        image = image.with_file(ecu_sim_dir.join(path), format!("/{path}"));
    }

    Ok(image)
}

/// The socketcand image definition: `testcontainer/socketcand/Dockerfile`,
/// which needs no other files.
fn socketcand_buildable_image() -> Result<GenericBuildableImage, TestingError> {
    Ok(
        GenericBuildableImage::new(SOCKETCAND_IMAGE_NAME, LOCAL_IMAGE_TAG)
            .with_dockerfile(test_container_dir()?.join("socketcand/Dockerfile")),
    )
}
