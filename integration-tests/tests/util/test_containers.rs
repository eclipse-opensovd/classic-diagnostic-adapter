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
//! environment variables, see [`Service`].
//! This avoids building in every test process, e.g. under `cargo nextest`,
//! which runs every test in its own process.

use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Write},
    net::{Ipv4Addr, TcpStream},
    path::PathBuf,
    sync::{
        Arc, LazyLock, Mutex, MutexGuard, PoisonError, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use futures::StreamExt;
use testcontainers::{
    ContainerAsync, ContainerRequest, GenericBuildableImage, GenericImage, Healthcheck, Image,
    ImageExt, TestcontainersError,
    bollard::{
        container::LogOutput,
        models::{HostConfig, PortBinding},
        query_parameters::LogsOptionsBuilder,
    },
    core::{
        AccessMode, BuildImageOptions, IntoContainerPort, Mount, WaitFor,
        client::docker_client_instance, logs::LogFrame,
    },
    runners::{AsyncBuilder, AsyncRunner},
};
use tokio::{runtime::Handle, sync::OnceCell};

use crate::util::{
    TestingError,
    config::{
        CAN_BUS_NAME, CDA_DATABASES_DIR, CDA_HTTP_PORT, ECU_SIM_CONTROL_PORT, SOCKETCAND_PORT,
        mdd_file_path, test_container_dir,
    },
    test_env::{TOKIO_RUNTIME, coverage_mode, env_flag},
};

const LOCAL_IMAGE_TAG: &str = "0.0.0";

/// How often a container whose host port is taken is started, see
/// [`is_port_conflict`].
pub(crate) const PORT_CONFLICT_ATTEMPTS: usize = 5;

/// The host address the containers publish their ports on, see
/// [`publish_on_loopback`].
pub(crate) const PUBLISH_HOST: Ipv4Addr = Ipv4Addr::LOCALHOST;

/// Label holding the [`session_id`] of the test process that started a
/// container. The containers of a process are removed at its exit, see
/// [`RYUK_IMAGE`].
pub(crate) const SESSION_LABEL: &str = "org.eclipse.opensovd.cda.test.session";

/// A file of zeros added to every build context, so that Docker Desktop does
/// not truncate it.
///
/// `testcontainers` uploads the build context as the body of `POST /build`.
/// dockerd starts streaming the build progress while it still reads the body,
/// as `BuildKit` loads the context. Docker Desktop (4.93) relays the API through
/// a proxy that is a Go HTTP server without full duplex: once the response
/// headers are written, Go reads and discards an unread rest of the request
/// body of up to 256 KiB (`maxPostHandlerReadBytes`) and closes it. dockerd
/// then gets a truncated context, and the build hangs at `[internal] load
/// remote build context`; the proxy logs `http: invalid Read on closed Body`.
/// Contexts of roughly 100 KB to 1 MB, like the ecu-sim one, are affected
/// depending on timing. With the padding, more than 256 KiB of every context
/// is still unread when the response starts, which Go does not discard.
const BUILD_CONTEXT_PADDING: &str = "/.build-context-padding";
const BUILD_CONTEXT_PADDING_SIZE: usize = 4 * 1024 * 1024;

/// The directory of [`CDA_COVERAGE_PROFILE_FILE`].
const CDA_COVERAGE_DIR: &str = "/app/coverage";
/// Where a coverage-instrumented CDA writes its profile. Every container runs
/// the CDA once, so one fixed file per container suffices, and it can be copied
/// out as a single file.
const CDA_COVERAGE_PROFILE_FILE: &str = "/app/coverage/cda.profraw";
/// The CDA binary in its image, needed to decode the coverage profiles.
const CDA_BINARY: &str = "/app/opensovd-cda";

/// How often the healthchecks of the containers run during their start period.
///
/// Without a start interval, Docker probes every 5 s during the start period,
/// so a container that is up after about 1 s is only reported healthy, and
/// `testcontainers` only returns from `start`, after about 5 s.
const HEALTHCHECK_START_INTERVAL: Duration = Duration::from_millis(100);

/// ecu-sim is a JVM service; on a loaded machine it takes a while to come up.
pub(crate) const ECU_SIM_STARTUP_TIMEOUT: Duration = Duration::from_secs(3 * 60);
const SOCKETCAND_STARTUP_TIMEOUT: Duration = Duration::from_secs(60);

/// Environment variables passed through from the test process to containers.
const PASSTHROUGH_ENV: [&str; 2] = ["RUST_LOG", "RUST_BACKTRACE"];

/// The images of the test containers. Each is built once per test process,
/// unless a prebuilt one is named by the variables `<prefix>_NAME` and
/// `<prefix>_TAG`, see [`Self::prebuilt_prefix`]. Name and tag are passed to
/// Docker as they are, e.g. `ghcr.io/org/opensovd-cda` and `coverage`.
///
/// Displayed, and as [`AsRef<str>`], as the prefix of their output: `cda`,
/// `ecu-sim`, `socketcand`.
#[derive(Clone, Copy, Debug, strum::Display, strum::AsRefStr)]
#[strum(serialize_all = "kebab-case")]
pub(crate) enum Service {
    Cda,
    EcuSim,
    Socketcand,
}

impl Service {
    /// Prefix of the variables naming a prebuilt image, see [`Service`]. A
    /// prebuilt CDA image is used for every test, so it has to be built like
    /// [`cda_build_options`]: with `can-socketcand`, and instrumented when
    /// `CDA_INTEGRATION_TEST_COVERAGE` is set.
    fn prebuilt_prefix(self) -> &'static str {
        match self {
            Self::Cda => "CDA_TEST_IMAGE",
            Self::EcuSim => "ECU_SIM_TEST_IMAGE",
            Self::Socketcand => "SOCKETCAND_TEST_IMAGE",
        }
    }

    /// The port the healthcheck probes, published on a random host port.
    fn port(self) -> u16 {
        match self {
            Self::Cda => CDA_HTTP_PORT,
            Self::EcuSim => ECU_SIM_CONTROL_PORT,
            Self::Socketcand => SOCKETCAND_PORT,
        }
    }

    /// The image of this service, once [`image`] has built or named it.
    fn image(self) -> &'static OnceCell<GenericImage> {
        static CDA: OnceCell<GenericImage> = OnceCell::const_new();
        static ECU_SIM: OnceCell<GenericImage> = OnceCell::const_new();
        static SOCKETCAND: OnceCell<GenericImage> = OnceCell::const_new();
        match self {
            Self::Cda => &CDA,
            Self::EcuSim => &ECU_SIM,
            Self::Socketcand => &SOCKETCAND,
        }
    }

    fn buildable(self) -> Result<(GenericBuildableImage, BuildImageOptions), TestingError> {
        Ok(match self {
            Self::Cda => (cda_buildable_image()?, cda_build_options()),
            Self::EcuSim => (ecu_sim_buildable_image()?, BuildImageOptions::new()),
            Self::Socketcand => (
                GenericBuildableImage::new("socketcand-integration-test", LOCAL_IMAGE_TAG)
                    .with_dockerfile(test_container_dir()?.join("socketcand/Dockerfile")),
                BuildImageOptions::new(),
            ),
        })
    }
}

/// Tag of the locally built CDA image: `coverage` when
/// `CDA_INTEGRATION_TEST_COVERAGE` is set, `release` otherwise, so that both
/// variants can be built side by side.
fn cda_image_tag() -> &'static str {
    if coverage_mode() {
        "coverage"
    } else {
        "release"
    }
}

/// Build arguments of `testcontainer/cda/Dockerfile`.
///
/// The CAN transport (`can-socketcand`) is always compiled in: the features
/// only add code, so one image serves the `DoIP`, CAN and mixed tests alike.
/// Coverage instrumentation is added when `CDA_INTEGRATION_TEST_COVERAGE` is
/// set. Either way it is an optimized build with debug assertions and overflow
/// checks, see `CHECK_RUSTFLAGS` in `testcontainer/cda/Dockerfile`.
fn cda_build_options() -> BuildImageOptions {
    let options = BuildImageOptions::new()
        .with_build_arg("SOURCE_DATE_EPOCH", "0")
        .with_build_arg("SOURCE_GIT_SHA", "unknown")
        .with_build_arg("CDA_FEATURES", "can-socketcand");
    if coverage_mode() {
        options.with_build_arg("RUSTFLAGS", "-C instrument-coverage")
    } else {
        options
    }
}

/// Where the ecu-sim reaches socketcand to serve its ECUs over CAN.
#[derive(Clone, Debug)]
pub(crate) struct SocketCanEndpoint {
    /// Host name or IP of socketcand, as seen from the ecu-sim container.
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) bus: String,
}

impl SocketCanEndpoint {
    /// socketcand on `host` with the default port and bus.
    pub(crate) fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port: SOCKETCAND_PORT,
            bus: CAN_BUS_NAME.to_owned(),
        }
    }
}

/// The buffer collecting the output of the containers of a test.
///
/// Container output is not printed while the containers run, but buffered,
/// prefixed with the service, until [`Self::print_output`] prints it for the
/// test that uses the containers, or Ctrl+C prints all of it, see
/// [`exit_on_ctrl_c`]. Clones share the buffer.
#[derive(Clone, Debug)]
pub(crate) struct ContainerOwner {
    output: Arc<Mutex<Output>>,
}

#[derive(Debug, Default)]
struct Output {
    /// The test using the containers now, for the header of the output.
    test_name: String,
    bytes: Vec<u8>,
}

/// The output buffers of all owners, for printing them on Ctrl+C.
static OUTPUTS: Mutex<Vec<Weak<Mutex<Output>>>> = Mutex::new(Vec::new());

impl ContainerOwner {
    pub(crate) fn new(test_name: impl Into<String>) -> Self {
        let output = Arc::new(Mutex::new(Output {
            test_name: test_name.into(),
            bytes: Vec::new(),
        }));
        let mut outputs = OUTPUTS.lock().unwrap_or_else(PoisonError::into_inner);
        outputs.retain(|output| output.strong_count() > 0);
        outputs.push(Arc::downgrade(&output));
        Self { output }
    }

    /// Names the test using the containers from now on, e.g. the test
    /// leasing a pooled environment.
    pub(crate) fn set_test_name(&self, test_name: impl Into<String>) {
        self.lock_output().test_name = test_name.into();
    }

    /// Prints the output the owned containers wrote since the last call, and
    /// clears it.
    ///
    /// It is printed with `eprint!`, which libtest captures per test: called
    /// on the thread of a test, it is shown only if that test fails, or with
    /// `--nocapture`.
    pub(crate) fn print_output(&self) {
        let (test_name, bytes) = {
            let mut output = self.lock_output();
            (output.test_name.clone(), std::mem::take(&mut output.bytes))
        };
        if !bytes.is_empty() {
            eprint!("{}", output_report(&test_name, &bytes));
        }
    }

    /// Drops the output buffered so far, e.g. that of the previous test using
    /// a pooled environment.
    pub(crate) fn clear_output(&self) {
        self.lock_output().bytes.clear();
    }

    fn record(&self, service: Service, message: &[u8]) {
        let bytes = &mut self.lock_output().bytes;
        bytes.extend_from_slice(service.as_ref().as_bytes());
        bytes.extend_from_slice(b": ");
        bytes.extend_from_slice(message);
        if !message.ends_with(b"\n") {
            bytes.push(b'\n');
        }
    }

    fn lock_output(&self) -> MutexGuard<'_, Output> {
        self.output.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn output_report(test_name: &str, bytes: &[u8]) -> String {
    format!(
        "---- container output of {test_name} ----\n{}---- end of container output of {test_name} \
         ----\n",
        String::from_utf8_lossy(bytes)
    )
}

/// Writes the output buffered by all owners straight to the stderr of the
/// process, bypassing the capture of libtest, which is lost when the process
/// exits on Ctrl+C. Shows where hanging tests got stuck.
fn print_all_output() {
    let outputs: Vec<_> = OUTPUTS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .filter_map(Weak::upgrade)
        .collect();
    let mut stderr = std::io::stderr().lock();
    for output in outputs {
        let output = output.lock().unwrap_or_else(PoisonError::into_inner);
        if !output.bytes.is_empty() {
            // There is nothing to report a failed write to.
            let _ = stderr.write_all(output_report(&output.test_name, &output.bytes).as_bytes());
        }
    }
}

/// A CDA container request for the containers of `owner`, ready to be
/// customized and started. Can be called from any task.
///
/// The test databases are mounted read-only at [`CDA_DATABASES_DIR`] and passed
/// as `--databases-dir`; replacing the arguments with `with_cmd` has to repeat
/// that. Starting it waits until the CDA reports ready on `/health/ready`, i.e.
/// has loaded its databases. [`CDA_HTTP_PORT`] is published on a
/// host port of [`PUBLISH_HOST`], see [`publish_on_loopback`].
///
/// Its output is buffered for `owner`, see [`ContainerOwner::print_output`].
///
/// # Errors
/// Returns [`TestingError::SetupError`] if the image cannot be built, or
/// [`TestingError::PathNotFound`] if the test databases are missing.
pub(crate) async fn cda_container_for(
    owner: &ContainerOwner,
) -> Result<ContainerRequest<GenericImage>, TestingError> {
    let databases_dir = mdd_file_path()?;
    let image = image(Service::Cda).await?;

    let mut container = with_test_defaults(
        image
            .with_mount(read_only_bind(databases_dir, CDA_DATABASES_DIR))
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
        Service::Cda,
        owner,
    );
    if coverage_mode() {
        // A volume, which, unlike a tmpfs, keeps the profile after the CDA
        // stopped, to be copied out, and is writable even when the root
        // filesystem is not.
        container = container
            .with_env_var("LLVM_PROFILE_FILE", CDA_COVERAGE_PROFILE_FILE)
            .with_mount(Mount::volume_mount("", CDA_COVERAGE_DIR));
    }

    Ok(container)
}

/// A read-only bind mount of `host_path` at `container_path`.
pub(crate) fn read_only_bind(
    host_path: impl Into<String>,
    container_path: impl Into<String>,
) -> Mount {
    Mount::bind_mount(host_path, container_path).with_access_mode(AccessMode::ReadOnly)
}

/// An ecu-sim container request for the containers of `owner`, ready to be customized
/// and started.
///
/// The container is privileged with `NET_ADMIN`, so the sim can
/// add its extra IPs (`USE_MULTIPLE_IPS`) to `eth0`. With `can`, the sim also
/// serves its ECUs over CAN through that socketcand; without, it is
/// `DoIP`-only. Starting it waits until the control API on
/// [`ECU_SIM_CONTROL_PORT`] answers, which is published on a
/// host port of [`PUBLISH_HOST`].
///
/// # Errors
/// Returns [`TestingError::SetupError`] if the image cannot be built, or
/// [`TestingError::PathNotFound`] if the `testcontainer` directory is missing.
pub(crate) async fn ecu_sim_container_for(
    can: Option<&SocketCanEndpoint>,
    owner: &ContainerOwner,
) -> Result<ContainerRequest<GenericImage>, TestingError> {
    let image = image(Service::EcuSim).await?;

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
        Service::EcuSim,
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

/// A socketcand container request for the containers of `owner`, ready to be customized
/// and started.
///
/// It creates the `vcan0` bus at start, which needs the `vcan` kernel module on
/// the Docker host, and serves it on [`SOCKETCAND_PORT`] of the container's
/// `eth0`. Starting it waits until that port is listening; it is also
/// published on a host port of [`PUBLISH_HOST`].
///
/// The bus is created in the network namespace of the container, so every
/// socketcand container has a `vcan0` of its own, and the CDA and ecu-sim
/// connected to it over TCP share a bus with nobody else.
///
/// # Errors
/// Returns [`TestingError::SetupError`] if the image cannot be built, or
/// [`TestingError::PathNotFound`] if the `testcontainer` directory is missing.
pub(crate) async fn socketcand_container_for(
    owner: &ContainerOwner,
) -> Result<ContainerRequest<GenericImage>, TestingError> {
    let image = image(Service::Socketcand).await?;

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
        Service::Socketcand,
        owner,
    ))
}

/// Settings every test container gets: the port of `service` published on
/// [`PUBLISH_HOST`], see [`publish_on_loopback`], the [`SESSION_LABEL`] the
/// reaper removes it by, a log consumer buffering its output for the owner,
/// see [`ContainerOwner::print_output`], and the [`PASSTHROUGH_ENV`]
/// variables of the test process.
fn with_test_defaults(
    container: ContainerRequest<GenericImage>,
    service: Service,
    owner: &ContainerOwner,
) -> ContainerRequest<GenericImage> {
    let log_owner = owner.clone();
    let port = service.port();
    let mut container = container
        .with_host_config_modifier(move |config| publish_on_loopback(config, port))
        .with_label(SESSION_LABEL, session_id())
        .with_log_consumer(move |record: &LogFrame| match record {
            LogFrame::StdOut(message) | LogFrame::StdErr(message) => {
                log_owner.record(service, message);
            }
        });

    for name in PASSTHROUGH_ENV {
        if let Ok(value) = std::env::var(name) {
            container = container.with_env_var(name, value);
        }
    }

    container
}

/// Publishes `port` of a container on [`PUBLISH_HOST`] only, on a host port
/// Docker picks.
///
/// Docker Desktop picks that port inside its VM, without knowing the ports of
/// host processes. Published on all addresses, as by default, a host process
/// listening on `127.0.0.1` on the same port,
/// gets the requests meant for the container. Published
/// on `127.0.0.1`, such a port fails the start instead, see
/// [`is_port_conflict`], and no host process can take it while the container
/// runs.
fn publish_on_loopback(config: &mut HostConfig, port: u16) {
    config.publish_all_ports = Some(false);
    config.port_bindings = Some(HashMap::from([(
        format!("{port}/tcp"),
        Some(vec![PortBinding {
            host_ip: Some(PUBLISH_HOST.to_string()),
            host_port: None,
        }]),
    )]));
}

/// Whether starting a container failed because the host port Docker picked,
/// see [`publish_on_loopback`], is taken by a host process.
pub(crate) fn is_port_conflict(error: &TestcontainersError) -> bool {
    let error = error.to_string();
    error.contains("address already in use") || error.contains("port is already allocated")
}

/// Starts the stopped `container` and keeps buffering its output, like the
/// log consumer of [`with_test_defaults`] did before it stopped. Does not wait
/// for the container to be ready.
///
/// Docker picks a new host port at every start; while a host process has taken
/// it, see [`is_port_conflict`], the start is tried again.
///
/// # Errors
/// Returns the error of Docker if the container cannot be started.
pub(crate) async fn start_stopped(
    container: &ContainerAsync<GenericImage>,
    service: Service,
    owner: ContainerOwner,
) -> Result<(), TestcontainersError> {
    // Taken before starting, so no output of the new run is missed.
    let since = unix_time_secs();
    let mut started = container.start().await;
    for _ in 1..PORT_CONFLICT_ATTEMPTS {
        match &started {
            Err(e) if is_port_conflict(e) => started = container.start().await,
            _ => break,
        }
    }
    started?;
    follow_logs_since(container.id().to_owned(), service, owner, since);
    Ok(())
}

/// Buffers the output of the container `container_id` from `since` (seconds
/// since the Unix epoch) on for `owner`, like the log consumer of
/// [`with_test_defaults`], until the container stops. Docker resolves `since`
/// to the second, so output the previous run wrote in the second of the
/// restart may appear twice.
///
/// The log consumer of a container ends when the container stops, so a
/// container that is started again needs this to keep its output.
/// Spawns onto the current runtime.
fn follow_logs_since(container_id: String, service: Service, owner: ContainerOwner, since: i32) {
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
                LogOutput::StdErr { message }
                | LogOutput::StdOut { message }
                | LogOutput::Console { message } => owner.record(service, &message),
                LogOutput::StdIn { .. } => {}
            }
        }
    });
}

/// Seconds since the Unix epoch, as taken by [`follow_logs_since`].
fn unix_time_secs() -> i32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i32::try_from(elapsed.as_secs()).ok())
        .unwrap_or(0)
}

/// Identifies this test process in the [`SESSION_LABEL`] of its containers:
/// its PID and start time, so it stays unique when PIDs are reused.
fn session_id() -> &'static str {
    static SESSION_ID: LazyLock<String> =
        LazyLock::new(|| format!("{}-{}", std::process::id(), unix_time_secs()));
    &SESSION_ID
}

/// Ryuk, the resource reaper of Testcontainers. Connected to this process, it
/// removes the containers and networks of this [`session_id`] once the
/// connection drops, however the process ends: dropped containers remove
/// themselves, but pooled environments live in statics, which are never
/// dropped, and Ctrl+C or a crash ends the process without dropping anything.
const RYUK_IMAGE: (&str, &str) = ("testcontainers/ryuk", "0.12.0");
const RYUK_PORT: u16 = 8080;
/// The Docker socket Ryuk talks to, as seen from the Docker host. Overridden
/// like in the other Testcontainers implementations, e.g. for rootless Docker.
const DOCKER_SOCKET_OVERRIDE: &str = "TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE";
/// `true` runs Ryuk privileged, as on hosts with `SELinux`; like in the other
/// Testcontainers implementations.
const RYUK_PRIVILEGED: &str = "TESTCONTAINERS_RYUK_CONTAINER_PRIVILEGED";
/// `true` skips Ryuk, where it cannot run, like in the other Testcontainers
/// implementations. Containers then outlive a test process that does not end
/// normally, and pooled environments are not removed at all.
const RYUK_DISABLED: &str = "TESTCONTAINERS_RYUK_DISABLED";

/// Exit status after Ctrl+C: 128 + `SIGINT`.
const INTERRUPTED_EXIT_STATUS: i32 = 130;

/// Starts the reaper on first use, see [`RYUK_IMAGE`], and registers the
/// Ctrl+C handler, see [`exit_on_ctrl_c`].
async fn start_session() -> Result<(), TestingError> {
    static REAPER: OnceCell<Option<(ContainerAsync<GenericImage>, TcpStream)>> =
        OnceCell::const_new();
    REAPER
        .get_or_try_init(|| async {
            exit_on_ctrl_c();
            if env_flag(RYUK_DISABLED) {
                return Ok(None);
            }
            let reaper = start_reaper().await.map_err(|e| {
                TestingError::SetupError(format!("Failed to start the resource reaper: {e}"))
            })?;
            Ok::<_, TestingError>(Some(reaper))
        })
        .await
        .map(|_| ())
}

/// Starts Ryuk and tells it what to remove: the containers labeled with this
/// [`session_id`], and the networks named after it, which `testcontainers`
/// creates without labels. The returned connection has to stay open for as
/// long as the process runs.
async fn start_reaper()
-> Result<(ContainerAsync<GenericImage>, TcpStream), Box<dyn std::error::Error>> {
    let socket =
        std::env::var(DOCKER_SOCKET_OVERRIDE).unwrap_or_else(|_| "/var/run/docker.sock".to_owned());
    let reaper = GenericImage::new(RYUK_IMAGE.0, RYUK_IMAGE.1)
        .with_exposed_port(RYUK_PORT.tcp())
        .with_wait_for(WaitFor::message_on_either_std("msg=Started"))
        .with_mount(Mount::bind_mount(socket, "/var/run/docker.sock"))
        // Removes within a second after this process is gone.
        .with_env_var("RYUK_RECONNECTION_TIMEOUT", "1s")
        // Never dropped either; Ryuk removes itself when it is done.
        .with_host_config_modifier(|config| {
            config.auto_remove = Some(true);
            publish_on_loopback(config, RYUK_PORT);
        })
        .with_privileged(env_flag(RYUK_PRIVILEGED))
        .start()
        .await?;
    let port = reaper.get_host_port_ipv4(RYUK_PORT).await?;

    let mut connection = TcpStream::connect((PUBLISH_HOST, port))?;
    // Ryuk answers right away; do not hang the tests if it does not.
    connection.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut acks = BufReader::new(connection.try_clone()?);
    for filter in [
        format!("label={SESSION_LABEL}={}", session_id()),
        format!("name={}", session_network_prefix()),
    ] {
        writeln!(connection, "{filter}")?;
        let mut ack = String::new();
        acks.read_line(&mut ack)?;
        if ack.trim() != "ACK" {
            return Err(format!("Ryuk did not acknowledge {filter}: {ack}").into());
        }
    }
    Ok((reaper, connection))
}

/// On Ctrl+C, prints the buffered output of the running tests and exits right
/// away, without waiting for them: the reaper removes their containers.
///
/// A task on the shared runtime, which lives as long as the process; the
/// runtime of a test ends with the test.
fn exit_on_ctrl_c() {
    TOKIO_RUNTIME.spawn(async {
        if tokio::signal::ctrl_c().await.is_err() {
            return;
        }
        print_all_output();
        // Not `eprintln!`: the task may run on a thread that inherited the
        // output capture of a test.
        let _ = std::io::stderr()
            .lock()
            .write_all(b"Interrupted, the test containers are removed in the background.\n");
        // `_exit`, not `exit`: the tests still running must not run
        // destructors or `atexit` handlers.
        // SAFETY: `_exit` only ends the process.
        unsafe { libc::_exit(INTERRUPTED_EXIT_STATUS) }
    });
}

/// Every network of this [`session_id`] is named with this prefix, so the
/// reaper can find them; `testcontainers` creates networks without labels.
pub(crate) fn session_network_prefix() -> String {
    format!("cda-itest-{}-", session_id())
}

/// Copies the coverage profile of the stopped CDA container `cda` and, once
/// per process, the CDA binary to [`coverage_output_dir`].
pub(crate) async fn save_coverage(cda: Arc<ContainerAsync<GenericImage>>) {
    let Some(dir) = coverage_output_dir() else {
        return;
    };
    let profile = dir.join(coverage_profile_name(cda.id()));
    let copy_binary = claim_coverage_binary_copy();
    // The copy futures of `testcontainers` are not `Send`, so they cannot run
    // as tasks of the shared runtime; a blocking thread drives them instead.
    let copied = tokio::task::spawn_blocking(move || {
        Handle::current().block_on(async {
            if let Err(e) = cda.copy_file_from(CDA_COVERAGE_PROFILE_FILE, profile).await {
                eprintln!(
                    "Failed to copy the coverage profile out of {}: {e}",
                    cda.id()
                );
            }
            if copy_binary {
                let binary = cda
                    .copy_file_from(CDA_BINARY, dir.join("opensovd-cda"))
                    .await;
                if let Err(e) = &binary {
                    eprintln!("Failed to copy the CDA binary out of {}: {e}", cda.id());
                }
                return binary.is_ok();
            }
            true
        })
    })
    .await;
    if copy_binary && !copied.unwrap_or(false) {
        release_coverage_binary_copy();
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

/// The name of the running test, for its container labels.
///
/// libtest runs every test on a thread named after the test. Code running in a
/// spawned task sees the name of a runtime worker thread instead.
pub(crate) fn current_test_name() -> String {
    std::thread::current()
        .name()
        .unwrap_or("unnamed-test")
        .to_owned()
}

/// The image of `service`, built or named on first use, see [`Service`].
async fn image(service: Service) -> Result<GenericImage, TestingError> {
    start_session().await?;
    let image = service
        .image()
        .get_or_try_init(|| async {
            if let Some(image) = prebuilt_image(service.prebuilt_prefix())? {
                eprintln!(
                    "Using prebuilt {service} image {}:{}.",
                    image.name(),
                    image.tag()
                );
                return Ok(image);
            }
            eprintln!("Building {service} image. This may take a few minutes...");
            let (image, options) = service.buildable()?;
            let image = image
                .with_data(vec![0u8; BUILD_CONTEXT_PADDING_SIZE], BUILD_CONTEXT_PADDING)
                .build_image_with(options)
                .await
                .map_err(|e| {
                    TestingError::SetupError(format!("Failed to build {service} image: {e}"))
                })?;
            eprintln!("Completed building {service} image.");
            Ok::<_, TestingError>(image)
        })
        .await?
        .clone();

    Ok(image
        .with_exposed_port(service.port().tcp())
        .with_wait_for(WaitFor::healthcheck()))
}

/// The prebuilt image named by `<prefix>_NAME` and `<prefix>_TAG`, or `None`
/// if neither is set.
///
/// # Errors
/// Returns [`TestingError::SetupError`] if only one of the two is set.
fn prebuilt_image(prefix: &str) -> Result<Option<GenericImage>, TestingError> {
    let var = |suffix: &str| {
        std::env::var(format!("{prefix}_{suffix}"))
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    };
    match (var("NAME"), var("TAG")) {
        (None, None) => Ok(None),
        (Some(name), Some(tag)) => Ok(Some(GenericImage::new(name, tag))),
        _ => Err(TestingError::SetupError(format!(
            "{prefix}_NAME and {prefix}_TAG must be set together"
        ))),
    }
}

/// The CDA image definition: `testcontainer/cda/Dockerfile` with the
/// workspace as build context, tagged by [`cda_image_tag`].
fn cda_buildable_image() -> Result<GenericBuildableImage, TestingError> {
    let metadata = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .map_err(|e| TestingError::SetupError(format!("Failed to read workspace metadata: {e}")))?;
    let workspace_root = metadata.workspace_root;

    let mut image = GenericBuildableImage::new("cda-integration-test", cda_image_tag())
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

    let mut image = GenericBuildableImage::new("ecu-sim-integration-test", LOCAL_IMAGE_TAG)
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
