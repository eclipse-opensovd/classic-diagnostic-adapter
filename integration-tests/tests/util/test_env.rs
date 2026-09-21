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

//! Isolated test environments on `testcontainers`, and a pool of them.
//!
//! A [`TestEnv`] is a Docker network of its own with ecu-sim, the CDA and, for
//! CAN, socketcand (whose `vcan0` is per container), so environments run in
//! parallel. Tests lease one with [`TestEnv::builder`]. The pool reuses the
//! network, socketcand and ecu-sim, which saves starting and removing them for
//! every test; every lease resets ecu-sim and gets a new CDA. A test that
//! changes the reused parts, or panics, leaves a dirty environment, which is
//! discarded instead.
//!
//! Pooled environments outlive the test that created them, so their container
//! operations run on the shared [`TOKIO_RUNTIME`]. Their container output is
//! printed when a lease ends, and shown only if the test fails.

use std::{
    future::{Future, IntoFuture},
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc, LazyLock, Mutex, Once, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use cda_interfaces::{
    communication_control::{
        CommunicationInitMode, CommunicationSettings, PostUpdateCommunicationMode,
        VariantDetectionMode,
    },
    config::ConfigSanity,
};
use http::{HeaderMap, Method, StatusCode};
use opensovd_cda_lib::config::configfile::{Configuration, ServerTransport};
use sovd_interfaces::apps::sovd2uds::data::network_structure::get::Response as NetworkStructureResponse;
use testcontainers::{
    ContainerAsync, ContainerRequest, GenericImage, ImageExt, TestcontainersError,
    core::{CmdWaitFor, ExecCommand, Mount},
    runners::AsyncRunner,
};
use tokio::sync::{Semaphore, SemaphorePermit};

use crate::util::{
    TestingError,
    config::{
        CDA_CONFIG_FILE, CDA_FLASH_DIR, CDA_HTTP_PORT, CDA_STORAGE_DIR, ECU_SIM_CONTROL_PORT,
        cda_test_config, cda_test_config_can, cda_test_config_mixed, container_config_toml,
        flash_files_host_dir,
    },
    ecusim::{self, EcuSim, Recorder},
    endpoints::APPS_SOVD2UDS_DATA_NETWORKSTRUCTURE,
    http::{auth_header, poll_until, response_to_t, send_cda_request, vehicle_url},
    test_containers::{
        ContainerOwner, ECU_SIM_STARTUP_TIMEOUT, PORT_CONFLICT_ATTEMPTS, PUBLISH_HOST, Service,
        SocketCanEndpoint, cda_container_for, current_test_name, ecu_sim_container_for,
        is_port_conflict, read_only_bind, save_coverage, session_network_prefix,
        socketcand_container_for, start_stopped,
    },
};

const CDA_INTEGRATION_TEST_COVERAGE: &str = "CDA_INTEGRATION_TEST_COVERAGE";
const CDA_INTEGRATION_TEST_USE_CAN: &str = "CDA_INTEGRATION_TEST_USE_CAN";
/// Mixed mode: `DoIP` and CAN run simultaneously. TMCC3000/HOVR4000/JGWT5000
/// are pinned to CAN, FLXC1000 to `DoIP`, the remaining ECUs bind at first
/// detection.
const CDA_INTEGRATION_TEST_USE_MIXED: &str = "CDA_INTEGRATION_TEST_USE_MIXED";

/// Number of environments per [`Transport`] in the pool, see [`pool_size`].
const CDA_TEST_POOL_SIZE: &str = "CDA_TEST_POOL_SIZE";
/// Default of [`CDA_TEST_POOL_SIZE`]. An environment needs roughly 1 GB, most
/// of it for the JVM of ecu-sim; 4 fit a Docker Desktop VM with 8 GB.
const DEFAULT_POOL_SIZE: usize = 4;

/// Grace period for the CDA to exit on `SIGTERM`, so that a coverage
/// instrumented CDA writes its profile.
const CDA_STOP_TIMEOUT_SECS: i32 = 10;

/// Size limit of the tmpfs at [`CDA_STORAGE_DIR`]. The storage holds a few
/// copies of the test MDDs (current, next update, backup, journal), which are
/// well below 1 MB together.
const CDA_STORAGE_SIZE_BYTES: i64 = 64 * 1024 * 1024;

type Container = Arc<ContainerAsync<GenericImage>>;

/// How long [`host_port`] waits for Docker to report a published port.
const HOST_PORT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a failed test waits for the container output still on its way
/// before printing it.
const OUTPUT_CATCH_UP: Duration = Duration::from_secs(1);

/// The removals started by [`TestEnv::discard`].
static DISCARDS: Mutex<Vec<tokio::task::JoinHandle<()>>> = Mutex::new(Vec::new());

/// Numbers the environments of this process.
static NEXT_ENV: AtomicUsize = AtomicUsize::new(1);

/// The runtime all container operations of the environments run on, see the
/// module docs.
pub(crate) static TOKIO_RUNTIME: LazyLock<tokio::runtime::Runtime> =
    LazyLock::new(|| tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime"));

/// The transports the CDA reaches the ECUs over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Transport {
    DoIp,
    /// CAN only, through socketcand.
    Can,
    /// `DoIP` and CAN at the same time.
    Mixed,
}

impl Transport {
    /// The transport selected by the environment: `CDA_INTEGRATION_TEST_USE_MIXED`
    /// or `CDA_INTEGRATION_TEST_USE_CAN`, otherwise `DoIP`.
    pub(crate) fn from_env() -> Self {
        if env_flag(CDA_INTEGRATION_TEST_USE_MIXED) {
            Self::Mixed
        } else if env_flag(CDA_INTEGRATION_TEST_USE_CAN) {
            Self::Can
        } else {
            Self::DoIp
        }
    }

    /// Whether the environment runs socketcand, and the CDA needs the CAN
    /// transport compiled in.
    pub(crate) fn uses_can(self) -> bool {
        self != Self::DoIp
    }

    /// Whether some ECUs are served over `DoIP`: not in pure CAN mode, while
    /// in mixed mode FLXC1000 and FLXCNG1000 are.
    pub(crate) fn uses_doip(self) -> bool {
        self != Self::Can
    }

    fn test_config(self, host: String, cda_port: u16) -> Result<Configuration, TestingError> {
        match self {
            Self::DoIp => cda_test_config(host, cda_port),
            Self::Can => cda_test_config_can(host, cda_port),
            Self::Mixed => cda_test_config_mixed(host, cda_port),
        }
    }
}

/// An isolated test environment, see the module docs. Host ports change when a
/// container is replaced or restarted, so read `config` and `ecu_sim` again.
pub(crate) struct TestEnv {
    /// Where the test reaches the CDA, and the configuration it runs with.
    pub(crate) config: Configuration,
    /// Where the test reaches the control API of ecu-sim.
    pub(crate) ecu_sim: EcuSim,
    spec: EnvSpec,
    default_config: Configuration,
    /// Whether the CDA runs on a read-only root filesystem without a
    /// configuration, see [`TestEnvBuilder::with_read_only_rootfs`].
    read_only_rootfs: bool,
    /// Whether the test changed a part of the environment that the next
    /// lease would otherwise reuse, e.g. stopped ecu-sim. A dirty environment
    /// is discarded instead of going back to the pool.
    dirty: bool,
    containers: Containers,
    /// The header of [`Self::auth_header`], until the CDA is replaced.
    auth: Mutex<Option<HeaderMap>>,
}

/// What container operations need to know about an environment. Cheap to
/// clone into tasks on the shared runtime.
#[derive(Clone)]
struct EnvSpec {
    transport: Transport,
    owner: ContainerOwner,
    /// Name of the network, unique across test processes, which the reaper
    /// removes it by. Also the prefix of the socketcand container name.
    network: String,
}

impl EnvSpec {
    /// Host name of socketcand on the environment's network: its container
    /// name. `testcontainers` 0.28 cannot set network aliases.
    fn socketcand_host(&self) -> String {
        format!("{}-socketcand", self.network)
    }

    /// Names `test_name` as the test using the containers, in their output.
    fn lease_to(&self, test_name: &str) {
        self.owner.set_test_name(test_name);
    }

    /// The configuration file a CDA container of this environment runs with,
    /// for the host-facing `config`, with the storage on the tmpfs at
    /// [`CDA_STORAGE_DIR`].
    fn cda_config_toml(&self, config: &Configuration) -> Result<String, TestingError> {
        let mut config = config.clone();
        CDA_STORAGE_DIR.clone_into(&mut config.runtime_update_config.storage_dir);
        container_config_toml(config, &self.socketcand_host())
    }
}

#[derive(Default)]
struct Containers {
    cda: Option<Container>,
    ecu_sim: Option<Container>,
    socketcand: Option<Container>,
}

impl TestEnv {
    /// A builder for the environment of the calling test; awaiting it leases
    /// the environment. See [`TestEnvBuilder`].
    pub(crate) fn builder() -> TestEnvBuilder {
        TestEnvBuilder::default()
    }

    /// Name of the environment, unique across test processes; also the name of
    /// its network.
    pub(crate) fn name(&self) -> &str {
        &self.spec.network
    }

    /// The configuration the CDA of this environment starts with, host-facing
    /// like [`Self::config`].
    pub(crate) fn default_config(&self) -> &Configuration {
        &self.default_config
    }

    /// Replaces the CDA with a new one running with `config`, which becomes
    /// [`Self::config`], and waits until it is ready. Container-internal
    /// settings (server, gateway, databases, socketcand) are filled in.
    ///
    /// # Errors
    /// Returns [`TestingError::SetupError`] if the new CDA does not become
    /// ready; the environment then has no CDA running. Also if the lease runs
    /// the CDA [without a configuration](TestEnvBuilder::with_read_only_rootfs).
    pub(crate) async fn replace_cda(&mut self, config: &Configuration) -> Result<(), TestingError> {
        if self.read_only_rootfs {
            return Err(TestingError::SetupError(
                "a CDA on a read-only root filesystem runs without a configuration".to_owned(),
            ));
        }
        let toml = self.spec.cda_config_toml(config)?;
        self.start_cda(
            CdaSetup::Configured {
                toml,
                storage: None,
            },
            config.clone(),
        )
        .await
    }

    /// Replaces the CDA like [`Self::replace_cda`], but the new CDA starts
    /// with a copy of the storage of the current one, e.g. to restart a CDA
    /// that applied runtime updates with another configuration.
    ///
    /// # Errors
    /// See [`Self::replace_cda`], or the storage cannot be copied, e.g.
    /// because no CDA is running.
    pub(crate) async fn replace_cda_keeping_storage(
        &mut self,
        config: &Configuration,
    ) -> Result<(), TestingError> {
        if self.read_only_rootfs {
            return Err(TestingError::SetupError(
                "a CDA on a read-only root filesystem runs without a configuration".to_owned(),
            ));
        }
        let cda = self.cda_container()?;
        let storage = tempfile::tempdir().map_err(|e| {
            TestingError::SetupError(format!("Failed to create a directory for the storage: {e}"))
        })?;
        let host_dir = storage.path().to_path_buf();
        on_shared_runtime(async move { copy_storage_out(&cda, &host_dir).await }).await?;
        let toml = self.spec.cda_config_toml(config)?;
        // `storage` is removed when it goes out of scope, after the new CDA
        // was created with its copy.
        self.start_cda(
            CdaSetup::Configured {
                toml,
                storage: Some(storage.path().to_path_buf()),
            },
            config.clone(),
        )
        .await
    }

    /// The content of `path`, relative to the storage directory of the CDA.
    ///
    /// # Errors
    /// Returns [`TestingError::ProcessFailed`] if no CDA is running or the
    /// file cannot be read.
    pub(crate) async fn read_cda_storage_file(&self, path: &str) -> Result<Vec<u8>, TestingError> {
        let cda = self.cda_container()?;
        let path = format!("{CDA_STORAGE_DIR}/{path}");
        on_shared_runtime(async move { exec_stdout(&cda, &["cat", &path]).await }).await
    }

    /// Replaces the CDA with a new one, set up as `setup`. `config` becomes
    /// [`Self::config`], pointed at the new CDA.
    async fn start_cda(
        &mut self,
        setup: CdaSetup,
        config: Configuration,
    ) -> Result<(), TestingError> {
        self.stop_cda().await?;
        let spec = self.spec.clone();
        let (cda, port) = on_shared_runtime(async move { start_cda(&spec, setup).await }).await?;
        self.containers.cda = Some(Arc::new(cda));
        self.config = config;
        self.set_cda_port(port);
        // The healthcheck runs inside the container. Tests reach the CDA
        // through the published host port, which the Docker host may forward
        // only a moment later.
        wait_for_cda_online(&self.config.server).await
    }

    /// Points [`Self::config`] and the default configuration at the CDA on
    /// the host port `port`.
    fn set_cda_port(&mut self, port: u16) {
        self.default_config.server = ServerTransport::Tcp {
            address: self.default_config.server.address().to_owned(),
            port,
            unix_socket: None,
        };
        self.config.server = self.default_config.server.clone();
    }

    /// Starts recording the requests `ecu` receives in ecu-sim, see
    /// [`Recorder`].
    ///
    /// # Errors
    /// Returns an error if ecu-sim cannot be reached.
    pub(crate) async fn record(&self, ecu: &str) -> Result<Recorder, TestingError> {
        Recorder::start(&self.ecu_sim, ecu).await
    }

    /// The `Authorization` header of the default test client for the CDA of
    /// this environment. Authorizes once per CDA start.
    ///
    /// # Errors
    /// Returns an error if the CDA does not authorize the client.
    pub(crate) async fn auth_header(&self) -> Result<HeaderMap, TestingError> {
        if let Some(header) = self
            .auth
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
        {
            return Ok(header);
        }
        let header = auth_header(&self.config, None).await?;
        *self.auth.lock().unwrap_or_else(PoisonError::into_inner) = Some(header.clone());
        Ok(header)
    }

    /// The `Authorization` header of the test client `client_id`, e.g. to act
    /// as another user than [`Self::auth_header`].
    ///
    /// # Errors
    /// Returns an error if the CDA does not authorize the client.
    pub(crate) async fn auth_header_for(&self, client_id: &str) -> Result<HeaderMap, TestingError> {
        auth_header(&self.config, Some(client_id)).await
    }

    /// The URL of `endpoint` below `/vehicle/v15/` of the CDA of this
    /// environment, e.g. `components/flxc1000/data`. Changes whenever the CDA
    /// is replaced, see [`Self::replace_cda`].
    pub(crate) fn vehicle_url(&self, endpoint: &str) -> String {
        vehicle_url(&self.config, endpoint)
    }

    /// Removes the CDA container, on a best effort basis.
    async fn stop_cda(&mut self) -> Result<(), TestingError> {
        *self.auth.get_mut().unwrap_or_else(PoisonError::into_inner) = None;
        if let Some(cda) = self.containers.cda.take() {
            let coverage = coverage_mode();
            on_shared_runtime(async move {
                remove_cda(cda, coverage).await;
                Ok(())
            })
            .await?;
        }
        Ok(())
    }

    /// Stops ecu-sim, keeping its container for [`Self::start_ecu_sim`].
    ///
    /// # Errors
    /// Returns [`TestingError::ProcessFailed`] if it cannot be stopped.
    pub(crate) async fn stop_ecu_sim(&mut self) -> Result<(), TestingError> {
        let sim = self.ecu_sim_container()?;
        self.dirty = true;
        on_shared_runtime(async move {
            sim.stop()
                .await
                .map_err(|e| TestingError::ProcessFailed(format!("Failed to stop ecu-sim: {e}")))
        })
        .await
    }

    /// Starts ecu-sim again and waits until its control API answers, possibly
    /// on another host port, see [`Self::ecu_sim`].
    ///
    /// # Errors
    /// Returns an error if it cannot be started or does not answer in time.
    pub(crate) async fn start_ecu_sim(&mut self) -> Result<(), TestingError> {
        let sim = self.ecu_sim_container()?;
        let owner = self.spec.owner.clone();
        let host = self.ecu_sim.host.clone();
        let port = on_shared_runtime(async move {
            start_stopped(&sim, Service::EcuSim, owner)
                .await
                .map_err(|e| {
                    TestingError::ProcessFailed(format!("Failed to start ecu-sim: {e}"))
                })?;
            let port = host_port(&sim, ECU_SIM_CONTROL_PORT, "ecu-sim").await?;
            let url = format!("http://{host}:{port}");
            wait_for_http(&url, None, ECU_SIM_STARTUP_TIMEOUT).await?;
            Ok(port)
        })
        .await?;
        self.ecu_sim.control_port = port;
        Ok(())
    }

    /// Resets the state of all simulated ECUs, see [`ecusim::reset_sim`].
    ///
    /// # Errors
    /// See [`ecusim::reset_sim`].
    pub(crate) async fn reset(&self) -> Result<(), TestingError> {
        ecusim::reset_sim(&self.ecu_sim).await
    }

    /// Creates an environment with socketcand (CAN and mixed only) and ecu-sim
    /// running, but no CDA yet.
    async fn create(transport: Transport, owner: ContainerOwner) -> Result<Self, TestingError> {
        let number = NEXT_ENV.fetch_add(1, Ordering::Relaxed);
        let spec = EnvSpec {
            transport,
            owner,
            network: format!("{}{number}", session_network_prefix()),
        };
        spec.lease_to(&current_test_name());
        // Fail before starting anything if the configuration the CDA will run
        // with is broken. The host-facing port is assigned after startup.
        let default_config = transport.test_config(bind_address(), 0)?;
        let container_config =
            crate::util::config::container_config(default_config.clone(), &spec.socketcand_host());
        container_config.validate_sanity().map_err(|e| {
            TestingError::SetupError(format!("Configuration sanity check failed: {e:?}"))
        })?;
        spec.cda_config_toml(&default_config)?;

        let task_spec = spec.clone();
        let (containers, sim_host, sim_port) =
            match on_shared_runtime(async move { start_containers(&task_spec).await }).await {
                Ok(started) => started,
                Err(e) => {
                    spec.owner.print_output();
                    return Err(e);
                }
            };

        let mut default_config = default_config;
        default_config.server = ServerTransport::Tcp {
            address: sim_host.clone(),
            port: default_config.server.port(),
            unix_socket: None,
        };
        Ok(Self {
            config: default_config.clone(),
            ecu_sim: EcuSim {
                host: sim_host,
                control_port: sim_port,
            },
            default_config,
            read_only_rootfs: false,
            dirty: false,
            containers,
            spec,
            auth: Mutex::new(None),
        })
    }

    fn cda_container(&self) -> Result<Container, TestingError> {
        self.containers
            .cda
            .clone()
            .ok_or_else(|| TestingError::ProcessFailed("No CDA is running".to_owned()))
    }

    fn ecu_sim_container(&self) -> Result<Container, TestingError> {
        self.containers
            .ecu_sim
            .clone()
            .ok_or_else(|| TestingError::SetupError("ecu-sim container is gone".to_owned()))
    }

    /// Resets the environment for the next lease: no CDA, and the ECU state of
    /// ecu-sim reset. The old CDA goes first, so that it cannot change the ECU
    /// state after the reset (e.g. tester present). Everything else about the
    /// CDA comes from the builder of the next lease; changes to the reused
    /// parts make the environment [dirty](Self::dirty) instead.
    async fn restore(&mut self) -> Result<(), TestingError> {
        self.stop_cda().await?;
        self.config = self.default_config.clone();
        self.reset().await
    }

    /// Prints which containers no longer run, e.g. a crashed CDA, and waits
    /// for the output still on its way, which the failure may be about.
    fn print_container_states(&self) {
        let containers = [
            (Service::Cda, self.containers.cda.clone()),
            (Service::EcuSim, self.containers.ecu_sim.clone()),
            (Service::Socketcand, self.containers.socketcand.clone()),
        ];
        let states = Arc::new(Mutex::new(String::new()));
        let task_states = Arc::clone(&states);
        block_on_shared_runtime(async move {
            for (service, container) in containers {
                let Some(container) = container else {
                    continue;
                };
                let state = match container.exit_code().await {
                    Ok(None) => continue,
                    Ok(Some(code)) => format!("{service} exited with code {code}\n"),
                    Err(e) => format!("Failed to get the state of {service}: {e}\n"),
                };
                task_states
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push_str(&state);
            }
            cda_interfaces::util::tokio_ext::sleep_for(OUTPUT_CATCH_UP).await;
        });
        // On the thread of the test, which libtest captures.
        eprint!("{}", states.lock().unwrap_or_else(PoisonError::into_inner));
    }

    /// Removes the containers and the network in the background, so that the
    /// next test does not wait for it.
    fn discard(mut self) {
        let containers = std::mem::take(&mut self.containers);
        let coverage = coverage_mode();
        let removal = TOKIO_RUNTIME.spawn(remove_containers(containers, coverage));
        // Awaited at exit in coverage mode, see `save_coverage_at_exit`;
        // otherwise the reaper removes what is left.
        let mut discards = DISCARDS.lock().unwrap_or_else(PoisonError::into_inner);
        discards.retain(|removal| !removal.is_finished());
        discards.push(removal);
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        // What a lease has not printed, e.g. why the environment could not
        // be restored.
        self.spec.owner.print_output();
        let containers = std::mem::take(&mut self.containers);
        if containers.cda.is_none()
            && containers.ecu_sim.is_none()
            && containers.socketcand.is_none()
        {
            return;
        }
        let coverage = coverage_mode();
        // Wait, so the environment is gone when the test ends.
        block_on_shared_runtime(async move {
            remove_containers(containers, coverage).await;
        });
    }
}

/// Runs `future` on the shared [`TOKIO_RUNTIME`] and blocks the calling thread
/// until it has finished, or panicked. For cleanup in `Drop`, which cannot
/// await.
fn block_on_shared_runtime<F>(future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    TOKIO_RUNTIME.spawn(async move {
        future.await;
        let _ = done_tx.send(());
    });
    // `recv` also returns when the task panicked.
    let wait = move || {
        let _ = done_rx.recv();
    };
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(wait);
        }
        _ => wait(),
    }
}

/// Up to `size` [`TestEnv`]s of one transport, created on first use.
struct Pool {
    transport: Transport,
    permits: Semaphore,
    idle: Mutex<Vec<TestEnv>>,
}

impl Pool {
    fn new(transport: Transport, size: usize) -> Self {
        Self {
            transport,
            permits: Semaphore::new(size.max(1)),
            idle: Mutex::new(Vec::new()),
        }
    }

    /// Leases a [restored](TestEnv::restore) environment for the calling test,
    /// waiting while all are leased. One that cannot be restored is replaced.
    ///
    /// # Errors
    /// Returns an error if no environment can be created and restored.
    async fn lease(&'static self) -> Result<Lease, TestingError> {
        let test_name = current_test_name();
        let permit = self
            .permits
            .acquire()
            .await
            .map_err(|e| TestingError::SetupError(format!("Environment pool closed: {e}")))?;

        let idle = self
            .idle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop();
        let env = match idle {
            Some(mut env) => {
                // The output since the previous lease ended belongs to no test.
                env.spec.owner.clear_output();
                env.spec.lease_to(&test_name);
                match env.restore().await {
                    Ok(()) => env,
                    Err(e) => {
                        eprintln!(
                            "Replacing test environment {} that cannot be restored: {e}",
                            env.name()
                        );
                        env.discard();
                        self.create(&test_name).await?
                    }
                }
            }
            None => self.create(&test_name).await?,
        };

        Ok(Lease {
            env: Some(env),
            pool: self,
            _permit: permit,
            recorders: Vec::new(),
        })
    }

    async fn create(&self, test_name: &str) -> Result<TestEnv, TestingError> {
        let mut env = TestEnv::create(self.transport, ContainerOwner::new(test_name)).await?;
        env.restore().await?;
        Ok(env)
    }
}

/// Exclusive use of a pooled [`TestEnv`] for one test, from
/// [`TestEnv::builder`]. When the lease is dropped, the environment goes back
/// to its pool, or is discarded if it is dirty or the test panicked.
pub(crate) struct Lease {
    env: Option<TestEnv>,
    pool: &'static Pool,
    /// Released after the environment is back in the pool, or discarded.
    _permit: SemaphorePermit<'static>,
    /// Recorders started by [`TestEnvBuilder::with_recording_for_ecu`], until the
    /// test takes them with [`Lease::recorder`].
    recorders: Vec<Recorder>,
}

impl Lease {
    /// The recorder of `ecu` from [`TestEnvBuilder::with_recording_for_ecu`].
    ///
    /// # Panics
    /// If none was requested for `ecu`, or it was already taken.
    pub(crate) fn recorder(&mut self, ecu: &str) -> Recorder {
        let index = self
            .recorders
            .iter()
            .position(|recorder| recorder.ecu() == ecu)
            .unwrap_or_else(|| panic!("no recording from start of {ecu} requested"));
        self.recorders.swap_remove(index)
    }
}

impl Deref for Lease {
    type Target = TestEnv;

    fn deref(&self) -> &TestEnv {
        self.env
            .as_ref()
            .expect("a lease holds its environment until dropped")
    }
}

impl DerefMut for Lease {
    fn deref_mut(&mut self) -> &mut TestEnv {
        self.env
            .as_mut()
            .expect("a lease holds its environment until dropped")
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        if let Some(env) = self.env.take() {
            if std::thread::panicking() {
                env.print_container_states();
            }
            // On the thread of the test, so libtest shows it if the test fails.
            env.spec.owner.print_output();
            // A panicked test may have left the environment in any state.
            if env.dirty || std::thread::panicking() {
                env.discard();
            } else {
                self.pool
                    .idle
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(env);
            }
        }
    }
}

/// The environment a test starts with. Awaiting it leases one of the
/// transport of [`Transport::from_env`]: ecu-sim reset, then the recordings
/// of [`Self::with_recording_for_ecu`] started, then a new CDA with the
/// default configuration started and its ECUs online.
///
/// ```ignore
/// let env = TestEnv::builder().await?;
/// ```
#[derive(Default)]
#[must_use = "awaiting the builder leases the environment"]
pub(crate) struct TestEnvBuilder {
    /// Communication settings of the CDA, see [`Self::with_cda_communication_settings`].
    communication: Option<CommunicationSettings>,
    /// See [`Self::with_read_only_rootfs`].
    read_only_rootfs: bool,
    record_from_start: Vec<String>,
}

impl TestEnvBuilder {
    /// Starts the CDA with `communication` instead of the default
    /// communication settings. Waits for its ECUs only if they come online on
    /// their own, i.e. with `init_mode = Always` and
    /// `variant_detection = Always`.
    pub(crate) fn with_cda_communication_settings(
        mut self,
        communication: CommunicationSettings,
    ) -> Self {
        self.communication = Some(communication);
        self
    }

    /// Runs the CDA as on a read-only partition, like in a vehicle: on a
    /// read-only root filesystem, which also holds its storage, so that every
    /// write to the storage fails.
    ///
    /// Such a CDA runs **without a configuration**: nothing can be copied onto
    /// a read-only root filesystem, so it starts with its built-in defaults
    /// and only the test databases (`--databases-dir`). It is not set up for
    /// the ECUs of the environment, so they are not waited for, and
    /// [`TestEnv::config`] only tells where to reach it. Configuring it is an
    /// error: awaiting a builder that also has
    /// [`Self::with_cda_communication_settings`] fails, and so does
    /// [`TestEnv::replace_cda`] during the lease.
    pub(crate) fn with_read_only_rootfs(mut self) -> Self {
        self.read_only_rootfs = true;
        self
    }

    /// Records the requests `ecu` receives from before the CDA starts, to
    /// catch its startup traffic. Take the [`Recorder`] with
    /// [`Lease::recorder`].
    pub(crate) fn with_recording_for_ecu(mut self, ecu: &str) -> Self {
        self.record_from_start.push(ecu.to_owned());
        self
    }

    async fn lease(self) -> Result<Lease, TestingError> {
        if self.read_only_rootfs && self.communication.is_some() {
            return Err(TestingError::SetupError(
                "a CDA on a read-only root filesystem runs without a configuration, so it cannot \
                 have communication settings"
                    .to_owned(),
            ));
        }

        // Boxed: the environment makes the futures large.
        let mut lease = Box::pin(pool(Transport::from_env()).lease()).await?;

        for ecu in &self.record_from_start {
            let recorder = lease.record(ecu).await?;
            lease.recorders.push(recorder);
        }

        lease.read_only_rootfs = self.read_only_rootfs;
        if self.read_only_rootfs {
            let config = lease.default_config.clone();
            lease.start_cda(CdaSetup::ReadOnly, config).await?;
            return Ok(lease);
        }

        let communication = self.communication.unwrap_or_default();
        let wait_for_ecus = communication.init_mode == CommunicationInitMode::Always
            && communication.variant_detection == VariantDetectionMode::Always;
        let mut config = lease.default_config.clone();
        config.communication = communication;
        lease.replace_cda(&config).await?;
        if wait_for_ecus {
            wait_for_ecus_online(&lease.config).await?;
        }
        Ok(lease)
    }
}

impl IntoFuture for TestEnvBuilder {
    type Output = Result<Lease, TestingError>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output>>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.lease())
    }
}

/// `Retry-After`, in seconds, of [`on_demand_communication`], distinct from
/// the default so that a `503` tells which configuration the CDA runs with.
pub(crate) const ON_DEMAND_RETRY_AFTER_SECONDS: u64 = 7;

/// Communication settings with `init_mode = OnDemand`, observable as a `503`
/// with [`ON_DEMAND_RETRY_AFTER_SECONDS`] on the first diagnostic request.
pub(crate) fn on_demand_communication() -> CommunicationSettings {
    CommunicationSettings {
        init_mode: CommunicationInitMode::OnDemand,
        variant_detection: VariantDetectionMode::Always,
        post_update_mode: PostUpdateCommunicationMode::Enabled,
        deferred_retry_after_seconds: ON_DEMAND_RETRY_AFTER_SECONDS,
    }
}

/// Whether the environment variable `name` is `true`.
pub(crate) fn env_flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|s| s == "true")
}

/// Whether the CDA image is instrumented for coverage
/// (`CDA_INTEGRATION_TEST_COVERAGE=true`).
pub(crate) fn coverage_mode() -> bool {
    env_flag(CDA_INTEGRATION_TEST_COVERAGE)
}

/// Returns `true`, logging a skip notice, unless the test `runs` with the
/// transport of [`Transport::from_env`], e.g. [`Transport::uses_can`]. Call it
/// from the test itself, for its name.
pub(crate) fn skip_unless(runs: impl FnOnce(Transport) -> bool, reason: &str) -> bool {
    let transport = Transport::from_env();
    if runs(transport) {
        return false;
    }
    eprintln!(
        "skipping {} with {transport:?}: {reason}",
        current_test_name()
    );
    true
}

/// Waits until the CDA reports every ECU `Online`, as connecting and variant
/// detection run asynchronously. CAN gets twice the time: the CDA probes CAN
/// ECUs in turn, and re-probes silent ones only every 5 s.
///
/// # Errors
/// Returns [`TestingError::Timeout`] if an ECU is not online in time, or the
/// error of a failed request.
pub(crate) async fn wait_for_ecus_online(config: &Configuration) -> Result<(), TestingError> {
    const DOIP_TIMEOUT: Duration = Duration::from_secs(30);
    let timeout = if config.can.is_some() {
        DOIP_TIMEOUT.saturating_mul(2)
    } else {
        DOIP_TIMEOUT
    };
    // Every lease waits for this, so a coarse interval adds up.
    poll_until(timeout, Duration::from_millis(250), || async {
        let response = match send_cda_request(
            config,
            APPS_SOVD2UDS_DATA_NETWORKSTRUCTURE,
            StatusCode::OK,
            Method::GET,
            None,
            None,
            None,
        )
        .await
        {
            Ok(response) => response,
            // Right after it reports ready, the CDA may not serve its vehicle
            // routes yet.
            Err(TestingError::UnexpectedResponse { actual, .. }) => {
                return Ok(Err(format!("networkstructure answers {actual}")));
            }
            Err(e) => return Err(e),
        };
        let structure: NetworkStructureResponse = response_to_t(&response)?;
        let offline: Vec<String> = structure
            .data
            .iter()
            .flat_map(|ns| ns.gateways.iter())
            .flat_map(|gw| gw.ecus.iter())
            .filter(|ecu| !matches!(ecu.state.as_str(), "Online" | "Duplicate"))
            .map(|ecu| format!("{}={}", ecu.qualifier, ecu.state))
            .collect();
        Ok(if offline.is_empty() {
            Ok(())
        } else {
            Err(format!("ECUs not online: {}", offline.join(", ")))
        })
    })
    .await
}

/// The address the test harness binds its own servers to, which is also the
/// placeholder server address of the CDA configurations: the containers are
/// reached at the host `testcontainers` reports.
pub(crate) fn bind_address() -> String {
    "0.0.0.0".to_owned()
}

/// Waits until the CDA reports ready on `/health/ready`.
pub(crate) async fn wait_for_cda_online(cfg: &ServerTransport) -> Result<(), TestingError> {
    let url = format!("http://{}:{}/health/ready", cfg.address(), cfg.port());
    wait_for_http(&url, Some(StatusCode::NO_CONTENT), Duration::from_secs(10)).await
}

pub(crate) fn find_available_tcp_port(listen_address: &str) -> Result<u16, TestingError> {
    use std::net::TcpListener;
    let listener = TcpListener::bind(format!("{listen_address}:0"))
        .map_err(|e| TestingError::InvalidNetworkConfig(e.to_string()))?;
    Ok(listener
        .local_addr()
        .map_err(|e| TestingError::InvalidNetworkConfig(e.to_string()))?
        .port())
}

/// The host port Docker published `container_port` of `container` on. It is
/// picked when the container starts, so read it again after every start.
///
/// Docker may report the ports of a container only a moment after it started,
/// so a missing one is read again for [`HOST_PORT_TIMEOUT`].
async fn host_port(
    container: &ContainerAsync<GenericImage>,
    container_port: u16,
    service: &str,
) -> Result<u16, TestingError> {
    poll_until(HOST_PORT_TIMEOUT, Duration::from_millis(100), || async {
        match container.get_host_port_ipv4(container_port).await {
            Ok(port) => Ok(Ok(port)),
            Err(e @ TestcontainersError::PortNotExposed { .. }) => Ok(Err(e.to_string())),
            Err(e) => Err(TestingError::SetupError(format!(
                "Failed to get the {service} host port: {e}"
            ))),
        }
    })
    .await
}

/// Waits until `url` answers, with `status` if given.
async fn wait_for_http(
    url: &str,
    status: Option<StatusCode>,
    timeout: Duration,
) -> Result<(), TestingError> {
    let client = reqwest::Client::new();
    poll_until(timeout, Duration::from_millis(250), || async {
        Ok(match client.get(url).send().await {
            Ok(response) if status.is_none_or(|status| response.status() == status) => Ok(()),
            Ok(response) => Err(format!("{url} answers {}", response.status())),
            Err(e) => Err(format!("{url} does not answer: {e}")),
        })
    })
    .await
}

/// Size of each pool: [`CDA_TEST_POOL_SIZE`], or [`DEFAULT_POOL_SIZE`].
fn pool_size() -> usize {
    std::env::var(CDA_TEST_POOL_SIZE)
        .ok()
        .and_then(|size| size.trim().parse::<usize>().ok())
        .filter(|&size| size > 0)
        .unwrap_or(DEFAULT_POOL_SIZE)
}

fn pool(transport: Transport) -> &'static Pool {
    static DOIP: LazyLock<Pool> = LazyLock::new(|| Pool::new(Transport::DoIp, pool_size()));
    static CAN: LazyLock<Pool> = LazyLock::new(|| Pool::new(Transport::Can, pool_size()));
    static MIXED: LazyLock<Pool> = LazyLock::new(|| Pool::new(Transport::Mixed, pool_size()));
    if coverage_mode() {
        save_coverage_at_exit();
    }
    match transport {
        Transport::DoIp => &DOIP,
        Transport::Can => &CAN,
        Transport::Mixed => &MIXED,
    }
}

/// Runs `future` on the shared [`TOKIO_RUNTIME`], see the module docs.
async fn on_shared_runtime<T, F>(future: F) -> Result<T, TestingError>
where
    T: Send + 'static,
    F: Future<Output = Result<T, TestingError>> + Send + 'static,
{
    TOKIO_RUNTIME
        .spawn(future)
        .await
        .map_err(|e| TestingError::SetupError(format!("Container task failed: {e}")))?
}

/// Starts socketcand if needed and ecu-sim. Returns the containers, the host
/// they are reachable at, and the host port of the ecu-sim control API.
async fn start_containers(spec: &EnvSpec) -> Result<(Containers, String, u16), TestingError> {
    let mut containers = Containers::default();

    let endpoint = if spec.transport.uses_can() {
        let socketcand = start_container(
            || async move {
                Ok(socketcand_container_for(&spec.owner)
                    .await?
                    .with_network(&spec.network)
                    .with_container_name(spec.socketcand_host()))
            },
            |e| {
                TestingError::SetupError(format!(
                    "Failed to start socketcand container: {e}. It creates its vcan0 at start, \
                     which needs the vcan kernel module on the Docker host (`sudo modprobe \
                     vcan`); `Unknown device type` in its output above means it is missing."
                ))
            },
        )
        .await?;
        containers.socketcand = Some(Arc::new(socketcand));
        Some(SocketCanEndpoint::new(spec.socketcand_host()))
    } else {
        None
    };

    let endpoint = endpoint.as_ref();
    let sim = start_container(
        || async move {
            Ok(ecu_sim_container_for(endpoint, &spec.owner)
                .await?
                .with_network(&spec.network))
        },
        |e| ecu_sim_start_error(spec, e),
    )
    .await?;
    let host = PUBLISH_HOST.to_string();
    let port = host_port(&sim, ECU_SIM_CONTROL_PORT, "ecu-sim").await;
    containers.ecu_sim = Some(Arc::new(sim));

    Ok((containers, host, port?))
}

fn ecu_sim_start_error(spec: &EnvSpec, error: &TestcontainersError) -> TestingError {
    TestingError::SetupError(format!(
        "Failed to start ecu-sim container on network {}: {error}. With USE_MULTIPLE_IPS, ecu-sim \
         adds its extra IPs with ipcli.sh, which needs a network prefix of /16 or shorter (see \
         its output above). If Docker assigned a smaller subnet, check the default-address-pools \
         of the Docker daemon.",
        spec.network
    ))
}

/// How a CDA container is set up.
#[derive(Clone)]
enum CdaSetup {
    /// A writable root filesystem, `toml` as the configuration file, and as
    /// the storage at [`CDA_STORAGE_DIR`] an empty tmpfs, or with `storage`
    /// a copy of that host directory on the root filesystem.
    Configured {
        toml: String,
        storage: Option<PathBuf>,
    },
    /// A read-only root filesystem, which also holds the storage, and no
    /// configuration, see [`TestEnvBuilder::with_read_only_rootfs`].
    ReadOnly,
}

/// Copies the storage of the CDA container `cda`, directories included, into
/// the host directory `host_dir`.
async fn copy_storage_out(
    cda: &ContainerAsync<GenericImage>,
    host_dir: &Path,
) -> Result<(), TestingError> {
    let write_error =
        |e: std::io::Error| TestingError::SetupError(format!("Failed to copy the storage: {e}"));

    for dir in storage_entries(cda, "d").await? {
        std::fs::create_dir_all(host_dir.join(dir)).map_err(write_error)?;
    }
    for file in storage_entries(cda, "f").await? {
        let content = exec_stdout(cda, &["cat", &format!("{CDA_STORAGE_DIR}/{file}")]).await?;
        let target = host_dir.join(file);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(write_error)?;
        }
        std::fs::write(target, content).map_err(write_error)?;
    }
    Ok(())
}

/// The paths of the entries of the `find -type` `kind` in the storage of the
/// CDA container `cda`, relative to [`CDA_STORAGE_DIR`].
async fn storage_entries(
    cda: &ContainerAsync<GenericImage>,
    kind: &str,
) -> Result<Vec<String>, TestingError> {
    let output = exec_stdout(
        cda,
        &[
            "find",
            CDA_STORAGE_DIR,
            "-mindepth",
            "1",
            "-type",
            kind,
            "-printf",
            "%P\\n",
        ],
    )
    .await?;
    Ok(String::from_utf8_lossy(&output)
        .lines()
        .map(str::to_owned)
        .collect())
}

/// Runs `cmd` in `container` and returns its standard output.
///
/// # Errors
/// Returns [`TestingError::ProcessFailed`] if it cannot be run or does not
/// exit with 0.
async fn exec_stdout(
    container: &ContainerAsync<GenericImage>,
    cmd: &[&str],
) -> Result<Vec<u8>, TestingError> {
    let error = |e: TestcontainersError| {
        TestingError::ProcessFailed(format!("`{}` failed: {e}", cmd.join(" ")))
    };
    let mut result = container
        .exec(
            ExecCommand::new(cmd.iter().copied())
                .with_cmd_ready_condition(CmdWaitFor::exit_code(0)),
        )
        .await
        .map_err(error)?;
    result.stdout_to_vec().await.map_err(error)
}

/// Starts a CDA container set up as `setup`, with the flash files mounted
/// read-only at [`CDA_FLASH_DIR`]. Returns the container and the host port of
/// its HTTP server.
async fn start_cda(
    spec: &EnvSpec,
    setup: CdaSetup,
) -> Result<(ContainerAsync<GenericImage>, u16), TestingError> {
    let request = || {
        let setup = setup.clone();
        async move {
            let cda = cda_container_for(&spec.owner)
                .await?
                .with_network(&spec.network)
                .with_mount(read_only_bind(
                    flash_files_host_dir()?.to_string_lossy(),
                    CDA_FLASH_DIR,
                ));
            // The configuration needs a writable root filesystem: `with_copy_to`
            // uploads into `/`, which Docker rejects for a read-only one, even when
            // the file would end up in a volume. A read-only CDA runs without one.
            Ok(match setup {
                CdaSetup::Configured { toml, storage } => {
                    let cda = cda
                        .with_copy_to(CDA_CONFIG_FILE, toml.into_bytes())
                        .with_env_var("CDA_CONFIG_FILE", CDA_CONFIG_FILE);
                    match storage {
                        // Not on a tmpfs, which would hide the copy.
                        Some(storage) => cda.with_copy_to(CDA_STORAGE_DIR, storage),
                        None => cda.with_mount(
                            Mount::tmpfs_mount(CDA_STORAGE_DIR)
                                .with_size_bytes(CDA_STORAGE_SIZE_BYTES),
                        ),
                    }
                }
                CdaSetup::ReadOnly => cda.with_readonly_rootfs(true),
            })
        }
    };
    let cda = start_container(request, |e| {
        TestingError::SetupError(format!("Failed to start CDA container: {e}"))
    })
    .await?;
    let port = host_port(&cda, CDA_HTTP_PORT, "CDA").await?;
    Ok((cda, port))
}

/// Starts the container `request` builds. While the host port Docker picked is
/// taken by a host process, see [`is_port_conflict`], it starts a new one.
/// Fails with `start_error` otherwise.
async fn start_container<F, Fut>(
    mut request: F,
    start_error: impl Fn(&TestcontainersError) -> TestingError,
) -> Result<ContainerAsync<GenericImage>, TestingError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<ContainerRequest<GenericImage>, TestingError>>,
{
    let mut started = request().await?.start().await;
    for _ in 1..PORT_CONFLICT_ATTEMPTS {
        match &started {
            Err(e) if is_port_conflict(e) => started = request().await?.start().await,
            _ => break,
        }
    }
    started.map_err(|e| start_error(&e))
}

/// Removes the containers, the CDA first. Removing the last container of an
/// environment also removes its network.
async fn remove_containers(containers: Containers, coverage: bool) {
    let Containers {
        cda,
        ecu_sim,
        socketcand,
    } = containers;
    if let Some(cda) = cda {
        // Separate from the loop below, to copy coverage data.
        remove_cda(cda, coverage).await;
    }
    for container in [ecu_sim, socketcand].into_iter().flatten() {
        remove(container).await;
    }
}

/// Removes a CDA container; with `coverage`, stops it gracefully first and
/// copies its coverage profile out.
async fn remove_cda(cda: Container, coverage: bool) {
    if coverage {
        stop_and_save_coverage(&cda).await;
    }
    remove(cda).await;
}

async fn remove(container: Container) {
    // Only fails while a cancelled operation still holds the container; it
    // is then removed when that one drops it.
    if let Ok(container) = Arc::try_unwrap(container) {
        let id = container.id().to_owned();
        if let Err(e) = container.rm().await {
            eprintln!("Failed to remove container {id}: {e}");
        }
    }
}

/// Stops the coverage instrumented CDA container gracefully, so that it writes
/// its profile, and copies the profile and, once per process, the CDA binary
/// to the coverage directory.
async fn stop_and_save_coverage(cda: &Container) {
    if let Err(e) = cda.stop_with_timeout(Some(CDA_STOP_TIMEOUT_SECS)).await {
        eprintln!(
            "Failed to stop CDA container {} for coverage: {e}",
            cda.id()
        );
    }
    save_coverage(Arc::clone(cda)).await;
}

/// In coverage mode, saves the coverage of the CDAs still running at process
/// exit, like when a CDA is removed during the run: those of the pooled
/// environments, and of the environments still being discarded. The reaper
/// removes the containers afterwards.
fn save_coverage_at_exit() {
    static REGISTERED: Once = Once::new();

    extern "C" fn at_exit() {
        TOKIO_RUNTIME.block_on(async {
            let discards =
                std::mem::take(&mut *DISCARDS.lock().unwrap_or_else(PoisonError::into_inner));
            futures::future::join_all(discards).await;
            let cdas: Vec<Container> = [Transport::DoIp, Transport::Can, Transport::Mixed]
                .into_iter()
                .flat_map(|transport| {
                    let mut idle = pool(transport)
                        .idle
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner);
                    idle.iter_mut()
                        .filter_map(|env| env.containers.cda.take())
                        .collect::<Vec<_>>()
                })
                .collect();
            futures::future::join_all(cdas.iter().map(stop_and_save_coverage)).await;
        });
    }

    REGISTERED.call_once(|| {
        // SAFETY: `at_exit` is a plain `extern "C"` function without arguments,
        // as `atexit` requires.
        unsafe {
            libc::atexit(at_exit);
        }
    });
}

#[cfg(test)]
mod tests {
    //! Tests of the test environments themselves, for what the other tests cannot
    //! notice: that a pooled environment is restored for the next lease, and that
    //! parallel environments are isolated from each other. Every ecu-sim serves
    //! the same ECUs, so a CDA that reached the ECUs of another environment would
    //! pass every other test.

    use std::collections::BTreeSet;

    use http::{Method, StatusCode};
    use opensovd_cda_lib::config::configfile::Configuration;
    use sovd_interfaces::apps::sovd2uds::data::network_structure::get::Response as NetworkStructureResponse;

    use super::{
        Lease, TestEnv, Transport, current_test_name, on_demand_communication, pool_size,
        skip_unless, wait_for_ecus_online,
    };
    use crate::{
        sovd::{COMPONENTS_FLXC1000_DATA, COMPONENTS_TMCC3000_BASE, ECU_FLXC1000},
        util::{
            TestingError, ecusim,
            endpoints::APPS_SOVD2UDS_DATA_NETWORKSTRUCTURE,
            http::{response_to_t, send_authenticated_cda_request, send_cda_request},
        },
    };

    /// What the pool does before it leases an environment again restores it to
    /// its defaults: here after the CDA ran with another configuration.
    #[tokio::test]
    async fn restored_env_runs_with_defaults() -> Result<(), TestingError> {
        let mut env = TestEnv::builder().await?;
        let mut config = env.default_config().clone();
        config.communication = on_demand_communication();
        env.replace_cda(&config).await?;

        // The pool restores, then the builder starts a CDA with the defaults.
        env.restore().await?;
        ecusim::get_ecu_state(&env.ecu_sim, ECU_FLXC1000).await?;
        let default_config = env.default_config().clone();
        env.replace_cda(&default_config).await?;
        wait_for_ecus_online(&env.config).await?;
        send_authenticated_cda_request(
            &env,
            COMPONENTS_FLXC1000_DATA,
            StatusCode::OK,
            Method::GET,
            None,
            None,
        )
        .await?;

        Ok(())
    }

    /// A CDA on a read-only root filesystem runs without a configuration, so
    /// configuring it is an error, before and during the lease.
    #[tokio::test]
    async fn read_only_cda_cannot_be_configured() -> Result<(), TestingError> {
        let configured = TestEnv::builder()
            .with_read_only_rootfs()
            .with_cda_communication_settings(on_demand_communication())
            .await;
        assert!(configured.is_err(), "a read-only CDA was configured");

        let mut env = TestEnv::builder().with_read_only_rootfs().await?;
        let config = env.default_config().clone();
        assert!(
            env.replace_cda(&config).await.is_err(),
            "a read-only CDA was replaced with a configured one"
        );
        Ok(())
    }

    /// Two environments of the pool at once, both online, or `None` (logging a
    /// skip notice) if the pool is too small to hold both.
    async fn lease_two() -> Result<Option<(Lease, Lease)>, TestingError> {
        if pool_size() < 2 {
            eprintln!(
                "skipping {}: needs a pool of 2 or more",
                current_test_name()
            );
            return Ok(None);
        }
        let (first, second) = tokio::join!(TestEnv::builder(), TestEnv::builder());
        Ok(Some((first?, second?)))
    }

    /// The gateways a CDA discovered, and the ECUs behind them.
    async fn discovered_gateways(
        config: &Configuration,
    ) -> Result<(BTreeSet<String>, BTreeSet<String>), TestingError> {
        let response = send_cda_request(
            config,
            APPS_SOVD2UDS_DATA_NETWORKSTRUCTURE,
            StatusCode::OK,
            Method::GET,
            None,
            None,
            None,
        )
        .await?;
        let structure: NetworkStructureResponse = response_to_t(&response)?;
        let gateways = structure.data.iter().flat_map(|data| data.gateways.iter());
        let addresses = gateways
            .clone()
            .map(|gateway| gateway.network_address.clone())
            .collect();
        let ecus = gateways
            .flat_map(|gateway| gateway.ecus.iter().map(|ecu| ecu.qualifier.clone()))
            .collect();
        Ok((addresses, ecus))
    }

    /// Every environment has a network of its own, so the `DoIP` discovery of one
    /// CDA finds only the gateways of its own ecu-sim: the same ECUs as the other
    /// environment, at other addresses.
    #[tokio::test]
    async fn parallel_doip_envs_discover_only_their_own_ecus() -> Result<(), TestingError> {
        if skip_unless(|transport| transport == Transport::DoIp, "needs DoIP only") {
            return Ok(());
        }
        // Both are online once leased.
        let Some((first, second)) = lease_two().await? else {
            return Ok(());
        };

        let (first_gateways, first_ecus) = discovered_gateways(&first.config).await?;
        let (second_gateways, second_ecus) = discovered_gateways(&second.config).await?;
        assert!(!first_ecus.is_empty(), "no ECUs discovered");
        assert_eq!(first_ecus, second_ecus);
        assert!(
            first_gateways.is_disjoint(&second_gateways),
            "both CDAs discovered gateways at the same addresses: {first_gateways:?} and \
             {second_gateways:?}"
        );

        Ok(())
    }

    /// A live read of TMCC3000 through the CDA of `env`. TMCC3000 is served over
    /// CAN in pure-CAN and in mixed mode.
    async fn read_tmcc3000_identification(
        env: &TestEnv,
    ) -> Result<crate::util::http::Response, TestingError> {
        send_authenticated_cda_request(
            env,
            &format!("{COMPONENTS_TMCC3000_BASE}/data/identification"),
            StatusCode::OK,
            Method::GET,
            None,
            None,
        )
        .await
    }

    /// Every CAN environment has a socketcand, and thus a `vcan0`, of its own:
    /// with the ecu-sim of one environment stopped, its CDA gets no answer over
    /// CAN, although the ecu-sim of the other environment serves the same ECU on
    /// the same CAN IDs.
    #[tokio::test]
    async fn parallel_can_envs_have_their_own_bus() -> Result<(), TestingError> {
        if skip_unless(
            Transport::uses_can,
            "needs the CAN transport (pure-CAN or mixed mode)",
        ) {
            return Ok(());
        }
        // Both are online once leased.
        let Some((mut first, second)) = lease_two().await? else {
            return Ok(());
        };
        read_tmcc3000_identification(&first).await?;
        read_tmcc3000_identification(&second).await?;

        first.stop_ecu_sim().await?;
        match read_tmcc3000_identification(&first).await {
            Err(TestingError::UnexpectedResponse { actual, .. }) => {
                eprintln!("{} answers {actual} with its ecu-sim stopped", first.name());
            }
            other => panic!(
                "expected an error status from the CDA of {} with its ecu-sim stopped, got \
                 {other:?}",
                first.name()
            ),
        }
        read_tmcc3000_identification(&second).await?;

        Ok(())
    }
}
