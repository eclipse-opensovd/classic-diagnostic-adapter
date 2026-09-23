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
//! A [`TestEnv`] is a user-defined Docker network of its own with socketcand
//! (CAN and mixed only), ecu-sim and the CDA on it. The network keeps the
//! `DoIP` discovery broadcasts of the CDA and the ECUs of one environment away
//! from all others, so environments can run in parallel.
//!
//! ecu-sim takes a while to start, so tests lease an environment from a pool
//! instead of starting their own with [`TestEnv::start`]; a lease resets the
//! environment to its defaults.
//!
//! # Isolation
//! Every lease gets a new CDA container, started after ecu-sim was reset: the
//! state a CDA builds up (storage, locks, sessions, detected variants) never
//! reaches the next test, whether the previous one passed, failed or
//! panicked. Starting a CDA takes about 1.5 s, see
//! `test_containers::HEALTHCHECK_START_INTERVAL`, a fraction of the ecu-sim
//! start, which is why ecu-sim is pooled and only reset. The CDA keeps its
//! storage (runtime updates) on a tmpfs at [`CDA_STORAGE_DIR`], which goes
//! with the container.
//!
//! # CAN
//! A CAN or mixed environment runs a socketcand container of its own, started
//! and healthy before ecu-sim and the CDA, which both reach it over TCP by its
//! container name. socketcand creates its `vcan0` in the network namespace of
//! its container, so every environment has a CAN bus of its own, and CAN
//! environments are as isolated from each other as `DoIP` ones.
//!
//! # Test-facing API
//! Test suites use [`setup_integration_test`] or
//! [`setup_integration_test_without_cda`], which lease an environment of the
//! transport selected by the environment variables, see
//! [`Transport::from_env`]. The pool bounds the number of live environments.
//! The [`Lease`] dereferences to the [`TestEnv`], whose methods change it:
//! [`TestEnv::restart_cda`], [`TestEnv::restart_cda_with_config`],
//! [`TestEnv::with_temporary_cda`], [`TestEnv::stop_ecu_sim`] and
//! [`TestEnv::start_ecu_sim`]. A test does not have to undo its changes; the
//! next lease restores the environment.
//!
//! # Runtimes
//! Every `#[tokio::test]` has a runtime of its own, and `testcontainers` spawns
//! the log consumers of a container on the runtime that starts it. Pooled
//! environments outlive the test that created them, so all their container
//! operations run on the shared [`TOKIO_RUNTIME`].
//!
//! # Cleanup
//! A dropped environment removes its containers and its network. Pooled ones
//! live in statics, which are never dropped; they are removed at process exit
//! through the session label, see `test_containers::SESSION_LABEL`.

use std::{
    future::Future,
    net::IpAddr,
    ops::{Deref, DerefMut},
    panic::AssertUnwindSafe,
    sync::{
        Arc, LazyLock, Mutex, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use cda_interfaces::config::ConfigSanity;
use futures::FutureExt;
use http::{Method, StatusCode};
use opensovd_cda_lib::config::configfile::{Configuration, ServerConfig};
use sovd_interfaces::apps::sovd2uds::data::network_structure::get::Response as NetworkStructureResponse;
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt, TestcontainersError,
    core::{AccessMode, CmdWaitFor, ExecCommand, IntoContainerPort, Mount},
    runners::AsyncRunner,
};
use tokio::sync::{Semaphore, SemaphorePermit};

use crate::util::{
    TestingError,
    config::{
        CDA_CONFIG_FILE, CDA_FLASH_DIR, CDA_STORAGE_DIR, cda_test_config, cda_test_config_can,
        cda_test_config_mixed, container_config_toml, flash_files_host_dir,
    },
    ecusim::{self, EcuSim},
    http::{response_to_t, send_cda_request},
    test_containers::{
        CDA_HTTP_PORT, CdaVariant, ContainerOwner, ECU_SIM_CONTROL_PORT, ECU_SIM_STARTUP_TIMEOUT,
        SocketcandEndpoint, cda_container_for, current_test_name, ecu_sim_container_for,
        follow_logs_since, save_coverage_with_cli, session_network_prefix,
        socketcand_container_for, unix_time_secs,
    },
};

const CDA_INTEGRATION_TEST_COVERAGE: &str = "CDA_INTEGRATION_TEST_COVERAGE";
const CDA_INTEGRATION_TEST_USE_CAN: &str = "CDA_INTEGRATION_TEST_USE_CAN";
/// Mixed mode: `DoIP` and CAN run simultaneously. TMCC3000/HOVR4000/JGWT5000
/// are pinned to CAN, FLXC1000 to `DoIP`, the remaining ECUs bind at first
/// detection.
const CDA_INTEGRATION_TEST_USE_MIXED: &str = "CDA_INTEGRATION_TEST_USE_MIXED";

/// Number of environments per [`Transport`] in the pool, see [`pool_size`].
pub(crate) const CDA_TEST_POOL_SIZE: &str = "CDA_TEST_POOL_SIZE";
/// Default of [`CDA_TEST_POOL_SIZE`]. An environment needs roughly 1 GB, most
/// of it for the JVM of ecu-sim; 4 fit a Docker Desktop VM with 8 GB.
const DEFAULT_POOL_SIZE: usize = 4;

/// Label holding the name of the environment a container belongs to.
const ENV_LABEL: &str = "org.eclipse.opensovd.cda.test.env";

/// Grace period for the CDA to exit on `SIGTERM`, so that a coverage
/// instrumented CDA writes its profile.
const CDA_STOP_TIMEOUT_SECS: i32 = 10;

/// Size limit of the tmpfs at [`CDA_STORAGE_DIR`]. The storage holds a few
/// copies of the test MDDs (current, next update, backup, journal), which are
/// well below 1 MB together.
const CDA_STORAGE_SIZE_BYTES: i64 = 64 * 1024 * 1024;

type Container = Arc<ContainerAsync<GenericImage>>;

/// Numbers the environments of this process.
static NEXT_ENV: AtomicUsize = AtomicUsize::new(1);

/// The runtime all container operations of the environments run on, see the
/// module docs.
static TOKIO_RUNTIME: LazyLock<tokio::runtime::Runtime> =
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

    /// The CDA image for this transport, instrumented for coverage when
    /// `CDA_INTEGRATION_TEST_COVERAGE` is set.
    pub(crate) fn cda_variant(self) -> CdaVariant {
        CdaVariant {
            can: self.uses_can(),
            coverage: coverage_mode(),
        }
    }

    fn test_config(self, host: String, cda_port: u16) -> Result<Configuration, TestingError> {
        match self {
            Self::DoIp => cda_test_config(host, cda_port),
            Self::Can => cda_test_config_can(host, cda_port),
            Self::Mixed => cda_test_config_mixed(host, cda_port),
        }
    }
}

/// An isolated test environment: socketcand (CAN and mixed only), ecu-sim and
/// the CDA on a network of their own.
///
/// The host ports of the CDA and of the ecu-sim control API are chosen once and
/// stay the same when containers are replaced or restarted, so `config` and
/// `ecu_sim` stay valid.
pub(crate) struct TestEnv {
    /// Where the test reaches the CDA, and the configuration it runs with.
    pub(crate) config: Configuration,
    /// Where the test reaches the control API of ecu-sim.
    pub(crate) ecu_sim: EcuSim,
    spec: EnvSpec,
    default_config: Configuration,
    /// Whether a CDA container runs.
    cda_running: bool,
    ecu_sim_running: bool,
    cda_starts: usize,
    containers: Containers,
}

/// What container operations need to know about an environment. Cheap to
/// clone into tasks on the shared runtime.
#[derive(Clone)]
struct EnvSpec {
    transport: Transport,
    variant: CdaVariant,
    owner: ContainerOwner,
    /// Short name for log prefixes, e.g. `env3`.
    tag: String,
    /// Name of the network, unique across test processes. Also the prefix of
    /// the container names and the value of [`ENV_LABEL`].
    network: String,
    cda_port: u16,
    sim_port: u16,
}

impl EnvSpec {
    /// Host name of socketcand on the environment's network: its container
    /// name. `testcontainers` 0.28 cannot set network aliases.
    fn socketcand_host(&self) -> String {
        format!("{}-socketcand", self.network)
    }

    fn log_name(&self, test_name: &str) -> String {
        format!("{test_name} @{}", self.tag)
    }

    /// The configuration file a CDA container of this environment runs with,
    /// for the host-facing `config`: [`container_config_toml`], with the
    /// storage on the tmpfs at [`CDA_STORAGE_DIR`].
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
    /// Starts an environment of its own for the calling test. It is removed
    /// when dropped.
    ///
    /// Returns once the CDA reports ready.
    ///
    /// # Errors
    /// Returns [`TestingError::SetupError`] if an image cannot be built or a
    /// container does not start.
    pub(crate) async fn start(transport: Transport) -> Result<Self, TestingError> {
        let mut env = Self::create(transport, ContainerOwner::current_test()).await?;
        let config = env.default_config.clone();
        env.restart_cda(&config).await?;
        Ok(env)
    }

    /// Leases an environment from the pool of `transport` for the calling test,
    /// waiting while all of them are leased. See [`Pool::lease`].
    ///
    /// # Errors
    /// See [`Pool::lease`].
    pub(crate) async fn lease(transport: Transport) -> Result<Lease, TestingError> {
        pool(transport).lease().await
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

    /// Replaces the CDA container with one running with `config`, and makes
    /// `config` the [`Self::config`] of this environment. Starts the CDA if it
    /// is not running. Returns once the new CDA reports ready.
    ///
    /// The server, `DoIP` gateway, database and socketcand settings of
    /// `config` are replaced with the container-internal ones; the server
    /// stays reachable at the address and port of [`Self::config`].
    ///
    /// # Errors
    /// Returns [`TestingError::SetupError`] if the new CDA does not become
    /// ready; the environment then has no CDA running.
    pub(crate) async fn restart_cda(&mut self, config: &Configuration) -> Result<(), TestingError> {
        let config_toml = self.spec.cda_config_toml(config)?;
        self.stop_cda().await?;

        let spec = self.spec.clone();
        let generation = self.cda_starts;
        self.cda_starts = self.cda_starts.saturating_add(1);
        let cda = on_shared_runtime(async move { start_cda(&spec, config_toml, generation).await })
            .await?;

        self.containers.cda = Some(Arc::new(cda));
        self.cda_running = true;
        let mut config = config.clone();
        config.server = self.default_config.server.clone();
        self.config = config;
        Ok(())
    }

    /// [`Self::restart_cda`] with the default configuration of this
    /// environment, changed by `configure`.
    ///
    /// # Errors
    /// See [`Self::restart_cda`].
    pub(crate) async fn restart_cda_with_config(
        &mut self,
        configure: impl FnOnce(&mut Configuration),
    ) -> Result<(), TestingError> {
        let mut config = self.default_config.clone();
        configure(&mut config);
        self.restart_cda(&config).await
    }

    /// Runs `body` against a CDA running with `temporary_config`, then
    /// restarts the CDA with the default configuration, also if `body`
    /// panics; the panic is resumed afterwards.
    ///
    /// `pre_start` runs before the CDA is restarted with `temporary_config`,
    /// e.g. to start recording the traffic of ecu-sim. Both get the
    /// environment, whose [`Self::config`] is the temporary configuration
    /// while `body` runs.
    ///
    /// # Panics
    /// If the CDA does not start with `temporary_config`, or cannot be
    /// restored to the default configuration after `body` succeeded.
    pub(crate) async fn with_temporary_cda<Pre, Body>(
        &mut self,
        temporary_config: Configuration,
        pre_start: Pre,
        body: Body,
    ) where
        Pre: AsyncFnOnce(&Self),
        Body: AsyncFnOnce(&Self),
    {
        pre_start(self).await;

        self.restart_cda(&temporary_config)
            .await
            .expect("Failed to start the CDA with the temporary configuration");

        let outcome = AssertUnwindSafe(body(self)).catch_unwind().await;

        let default_config = self.default_config.clone();
        let restored = self.restart_cda(&default_config).await;
        match (outcome, restored) {
            (Ok(()), Ok(())) => {}
            (Ok(()), Err(e)) => panic!("Failed to restore the default CDA: {e}"),
            (Err(panic), restored) => {
                if let Err(e) = restored {
                    // The next lease restores it; the panic of the body is
                    // what the test reports.
                    eprintln!("Failed to restore the default CDA: {e}");
                }
                std::panic::resume_unwind(panic);
            }
        }
    }

    /// Stops and removes the CDA container. Start a new one with
    /// [`Self::restart_cda`].
    ///
    /// # Errors
    /// Never fails today; the container is removed on a best effort basis.
    pub(crate) async fn stop_cda(&mut self) -> Result<(), TestingError> {
        self.cda_running = false;
        if let Some(cda) = self.containers.cda.take() {
            let coverage = self.spec.variant.coverage;
            on_shared_runtime(async move {
                remove_cda(cda, coverage).await;
                Ok(())
            })
            .await?;
        }
        Ok(())
    }

    /// Stops the ecu-sim container, keeping it for [`Self::start_ecu_sim`].
    ///
    /// # Errors
    /// Returns [`TestingError::ProcessFailed`] if the container cannot be
    /// stopped.
    pub(crate) async fn stop_ecu_sim(&mut self) -> Result<(), TestingError> {
        let sim = self.ecu_sim_container()?;
        self.ecu_sim_running = false;
        on_shared_runtime(async move {
            sim.stop()
                .await
                .map_err(|e| TestingError::ProcessFailed(format!("Failed to stop ecu-sim: {e}")))
        })
        .await
    }

    /// Starts the ecu-sim container stopped by [`Self::stop_ecu_sim`] again,
    /// and waits until its control API answers.
    ///
    /// # Errors
    /// Returns [`TestingError::ProcessFailed`] if the container cannot be
    /// started or its control API does not answer in time.
    pub(crate) async fn start_ecu_sim(&mut self) -> Result<(), TestingError> {
        let sim = self.ecu_sim_container()?;
        let owner = self.spec.owner.clone();
        let url = format!("http://{}:{}", self.ecu_sim.host, self.ecu_sim.control_port);
        on_shared_runtime(async move {
            let since = unix_time_secs();
            sim.start().await.map_err(|e| {
                TestingError::ProcessFailed(format!("Failed to start ecu-sim: {e}"))
            })?;
            // The log consumer ended when the container stopped.
            follow_logs_since(sim.id().to_owned(), "ecu-sim", owner, since);
            wait_for_http_ready_with_timeout(url, "ECU sim", None, ECU_SIM_STARTUP_TIMEOUT).await
        })
        .await?;
        self.ecu_sim_running = true;
        Ok(())
    }

    /// Resets the state of all simulated ECUs, see [`ecusim::reset_sim`].
    ///
    /// # Errors
    /// See [`ecusim::reset_sim`].
    pub(crate) async fn reset(&self) -> Result<(), TestingError> {
        ecusim::reset_sim(&self.ecu_sim).await
    }

    /// IP address of ecu-sim on the network of this environment.
    ///
    /// # Errors
    /// Returns [`TestingError::SetupError`] if Docker does not report it.
    pub(crate) async fn ecu_sim_ip(&self) -> Result<IpAddr, TestingError> {
        let sim = self.ecu_sim_container()?;
        on_shared_runtime(async move {
            sim.get_bridge_ip_address()
                .await
                .map_err(|e| TestingError::SetupError(format!("Failed to get ecu-sim IP: {e}")))
        })
        .await
    }

    /// Writes `message` into the output of every running container of this
    /// environment, e.g. to mark where a test starts in the logs.
    ///
    /// # Errors
    /// Returns [`TestingError::ProcessFailed`] if it cannot be written.
    pub(crate) async fn echo_to_logs(&self, message: &str) -> Result<(), TestingError> {
        let mut containers = Vec::new();
        if self.cda_running {
            containers.extend(self.containers.cda.clone());
        }
        if self.ecu_sim_running {
            containers.extend(self.containers.ecu_sim.clone());
        }
        let command = format!("echo '{}' > /proc/1/fd/1", message.replace('\'', ""));
        on_shared_runtime(async move {
            for container in containers {
                container
                    .exec(
                        ExecCommand::new(["sh", "-c", &command])
                            .with_cmd_ready_condition(CmdWaitFor::exit_code(0)),
                    )
                    .await
                    .map_err(|e| {
                        TestingError::ProcessFailed(format!("Failed to write to the logs: {e}"))
                    })?;
            }
            Ok(())
        })
        .await
    }

    /// How many log frames of the containers of this environment have been
    /// printed so far.
    pub(crate) fn log_frames(&self) -> u64 {
        self.spec.owner.log_frames()
    }

    /// Creates an environment with socketcand (CAN and mixed only) and ecu-sim
    /// running, but no CDA yet.
    async fn create(transport: Transport, owner: ContainerOwner) -> Result<Self, TestingError> {
        let number = NEXT_ENV.fetch_add(1, Ordering::Relaxed);
        let spec = EnvSpec {
            transport,
            variant: transport.cda_variant(),
            owner,
            tag: format!("env{number}"),
            network: format!("{}{number}", session_network_prefix()),
            cda_port: find_available_tcp_port(&host())?,
            sim_port: find_available_tcp_port(&host())?,
        };
        spec.owner.set_log_name(spec.log_name(&current_test_name()));

        // Fail before starting anything if the configuration is broken.
        let default_config = transport.test_config(host(), spec.cda_port)?;
        default_config.validate_sanity().map_err(|e| {
            TestingError::SetupError(format!("Configuration sanity check failed: {e:?}"))
        })?;
        spec.cda_config_toml(&default_config)?;

        let task_spec = spec.clone();
        let (containers, sim_host) =
            on_shared_runtime(async move { start_containers(&task_spec).await }).await?;

        let mut default_config = default_config;
        default_config.server.address.clone_from(&sim_host);
        Ok(Self {
            config: default_config.clone(),
            ecu_sim: EcuSim {
                host: sim_host,
                control_port: spec.sim_port,
            },
            default_config,
            cda_running: false,
            ecu_sim_running: true,
            cda_starts: 0,
            containers,
            spec,
        })
    }

    fn ecu_sim_container(&self) -> Result<Container, TestingError> {
        self.containers
            .ecu_sim
            .clone()
            .ok_or_else(|| TestingError::SetupError("ecu-sim container is gone".to_owned()))
    }

    /// Brings a pooled environment to its defaults for the next lease: the
    /// CDA of the previous lease removed, ecu-sim running with the ECU state
    /// reset, and with `start_cda` a new CDA running with the default
    /// configuration, whose ECUs are online.
    ///
    /// The previous CDA is removed first, so that it cannot change the ECU
    /// state after the reset, e.g. with a tester present. The new one starts
    /// after ecu-sim, since a running CDA did not reconnect to a restarted
    /// ecu-sim container within 30 s.
    async fn restore(&mut self, start_cda: bool) -> Result<(), TestingError> {
        self.stop_cda().await?;
        self.config = self.default_config.clone();
        if !self.ecu_sim_running {
            self.start_ecu_sim().await?;
        }
        self.reset().await?;
        if start_cda {
            let config = self.default_config.clone();
            self.restart_cda(&config).await?;
            wait_for_ecus_online(&self.config).await?;
        }
        Ok(())
    }

    /// Removes the containers and the network, like dropping, but without
    /// blocking.
    async fn remove(mut self) {
        let containers = std::mem::take(&mut self.containers);
        let coverage = self.spec.variant.coverage;
        let _ = on_shared_runtime(async move {
            remove_containers(containers, coverage).await;
            Ok(())
        })
        .await;
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        let containers = std::mem::take(&mut self.containers);
        if containers.cda.is_none()
            && containers.ecu_sim.is_none()
            && containers.socketcand.is_none()
        {
            return;
        }
        let coverage = self.spec.variant.coverage;
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        TOKIO_RUNTIME.spawn(async move {
            remove_containers(containers, coverage).await;
            let _ = done_tx.send(());
        });
        // Wait, so the environment is gone when the test ends. `recv` also
        // returns when the task panicked.
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
}

/// A pool of [`TestEnv`]s of one transport.
///
/// Environments are created on first use, at most `size` of them. Each is
/// leased by one test at a time and restored to its defaults, with a new CDA,
/// when leased again.
pub(crate) struct Pool {
    transport: Transport,
    permits: Semaphore,
    idle: Mutex<Vec<TestEnv>>,
}

impl Pool {
    pub(crate) fn new(transport: Transport, size: usize) -> Self {
        Self {
            transport,
            permits: Semaphore::new(size.max(1)),
            idle: Mutex::new(Vec::new()),
        }
    }

    /// Leases an environment for the calling test, exclusively until the
    /// [`Lease`] is dropped. Waits while all environments are leased.
    ///
    /// The environment is restored first: the CDA of the previous lease is
    /// removed, ecu-sim is started again if it was stopped, the state of the
    /// simulated ECUs is reset, and a new CDA is started with the default
    /// configuration. Returns once its ECUs are online. If restoring fails,
    /// the environment is replaced with a new one.
    ///
    /// # Errors
    /// Returns [`TestingError::SetupError`] if no environment can be created,
    /// or another error if the ECUs of a new environment do not come online.
    pub(crate) async fn lease(&'static self) -> Result<Lease, TestingError> {
        // Boxed: the environment makes the future large.
        Box::pin(self.lease_boxed(true)).await
    }

    /// Like [`Self::lease`], but without starting a CDA.
    ///
    /// # Errors
    /// See [`Self::lease`].
    pub(crate) async fn lease_without_cda(&'static self) -> Result<Lease, TestingError> {
        Box::pin(self.lease_boxed(false)).await
    }

    async fn lease_boxed(&'static self, start_cda: bool) -> Result<Lease, TestingError> {
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
                env.spec.owner.set_log_name(env.spec.log_name(&test_name));
                match env.restore(start_cda).await {
                    Ok(()) => env,
                    Err(e) => {
                        eprintln!(
                            "Replacing test environment {} that cannot be restored: {e}",
                            env.name()
                        );
                        Box::pin(env.remove()).await;
                        self.create(&test_name, start_cda).await?
                    }
                }
            }
            None => self.create(&test_name, start_cda).await?,
        };

        Ok(Lease {
            env: Some(env),
            pool: self,
            _permit: permit,
        })
    }

    async fn create(&self, test_name: &str, start_cda: bool) -> Result<TestEnv, TestingError> {
        let mut env = TestEnv::create(self.transport, ContainerOwner::new(test_name)).await?;
        env.restore(start_cda).await?;
        Ok(env)
    }
}

/// Exclusive use of a pooled [`TestEnv`]; returns it to the pool when dropped.
pub(crate) struct Lease {
    env: Option<TestEnv>,
    pool: &'static Pool,
    _permit: SemaphorePermit<'static>,
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
            self.pool
                .idle
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(env);
        }
        // The permit is released after the environment is back in the pool.
    }
}

/// Leases an environment of the transport selected by the environment
/// variables, see [`Transport::from_env`], with the ECU state reset and a new
/// CDA running with the default configuration, whose ECUs are online.
///
/// The lease is exclusive; it returns the environment to the pool when
/// dropped.
///
/// # Errors
/// See [`Pool::lease`].
pub(crate) async fn setup_integration_test() -> Result<Lease, TestingError> {
    TestEnv::lease(Transport::from_env()).await
}

/// Like [`setup_integration_test`], but without a CDA, for tests that need a
/// quiet vehicle network or control exactly when and how the CDA starts,
/// e.g. with [`TestEnv::restart_cda`]. ecu-sim runs, and
/// [`TestEnv::config`] is the default configuration.
///
/// # Errors
/// See [`Pool::lease_without_cda`].
pub(crate) async fn setup_integration_test_without_cda() -> Result<Lease, TestingError> {
    pool(Transport::from_env()).lease_without_cda().await
}

/// Whether the environment variable `name` is `true`.
fn env_flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|s| s == "true")
}

/// Whether the CDA image is instrumented for coverage
/// (`CDA_INTEGRATION_TEST_COVERAGE=true`).
pub(crate) fn coverage_mode() -> bool {
    env_flag(CDA_INTEGRATION_TEST_COVERAGE)
}

/// Whether the tests run over CAN only: [`Transport::from_env`] is
/// [`Transport::Can`] (`CDA_INTEGRATION_TEST_USE_CAN=true`, and not mixed).
pub(crate) fn use_can() -> bool {
    Transport::from_env() == Transport::Can
}

/// Whether the CAN infrastructure (socketcand + sim CAN stack) is needed:
/// true in pure-CAN and in mixed mode.
pub(crate) fn can_infra() -> bool {
    Transport::from_env().uses_can()
}

/// Guard, returning `true` (and logging a skip notice), for tests that cannot
/// run in the pure-CAN suite: either they exercise `DoIP`-only mechanisms
/// (`VAM`, sim restart) or they depend on session/security timing not yet
/// reliable over the CAN transport. Each gated call site documents its
/// specific reason. In MIXED mode these tests DO run: the ECUs they target
/// (FLXC1000/FLXCNG1000) are served over `DoIP` there.
pub(crate) fn skip_for_can(test_name: &str, reason: &str) -> bool {
    if use_can() {
        eprintln!("[can] skipping {test_name}: {reason}");
        return true;
    }
    false
}

/// Guard for tests that need the CAN infrastructure (pure-CAN or mixed
/// mode); mirrors [`skip_for_can`].
pub(crate) fn skip_for_doip(test_name: &str, reason: &str) -> bool {
    if !can_infra() {
        eprintln!("[doip] skipping {test_name}: {reason}");
        return true;
    }
    false
}

/// Poll the networkstructure endpoint until every ECU in every gateway reports
/// `"Online"`, or until the timeout elapses.
///
/// This is needed after `reset_sim` because the `DoIP` reconnection and variant
/// detection run asynchronously: returning immediately after reset would allow
/// tests to start before the ECU is reachable, causing `ecu_state=Offline` at
/// lock creation time and making tester-present tasks skip every tick.
///
/// With CAN (`config.can` set) the budget is longer: nothing announces CAN
/// ECUs, the CDA probes each of them in turn and re-probes the ones that did
/// not answer only every 5 s (`REDISCOVERY_INTERVAL` of `cda-comm-can`).
///
/// # Errors
/// Returns [`TestingError::ProcessFailed`] if an ECU is not online in time, or
/// the error of a failed networkstructure request.
pub(crate) async fn wait_for_ecus_online(config: &Configuration) -> Result<(), TestingError> {
    // Every lease waits for this, so a coarse interval adds up.
    const POLL_INTERVAL: Duration = Duration::from_millis(250);
    const DOIP_TIMEOUT: Duration = Duration::from_secs(30);
    const CAN_TIMEOUT: Duration = DOIP_TIMEOUT.saturating_mul(2);
    let timeout = if config.can.is_some() {
        CAN_TIMEOUT
    } else {
        DOIP_TIMEOUT
    };
    let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
        TestingError::SetupError("timeout duration overflowed Instant".to_owned())
    })?;
    let mut last_offline_ecus: Option<String> = None;

    loop {
        if Instant::now() >= deadline {
            return Err(TestingError::ProcessFailed(format!(
                "ECUs did not reach Online state within {timeout:?}: {}",
                last_offline_ecus.unwrap_or_else(|| "unknown".to_owned())
            )));
        }

        let response = send_cda_request(
            config,
            "apps/sovd2uds/data/networkstructure",
            StatusCode::OK,
            Method::GET,
            None,
            None,
            None,
        )
        .await?;
        let network_structure_response: NetworkStructureResponse = response_to_t(&response)
            .map_err(|e| {
                TestingError::InvalidData(format!("Failed to parse networkstructure response: {e}"))
            })?;

        let offline_ecus: Vec<String> = network_structure_response
            .data
            .iter()
            .flat_map(|ns| ns.gateways.iter())
            .flat_map(|gw| gw.ecus.iter())
            .filter(|ecu| !matches!(ecu.state.as_str(), "Online" | "Duplicate"))
            .map(|ecu| format!("{}={}", ecu.qualifier, ecu.state))
            .collect();

        if offline_ecus.is_empty() {
            return Ok(());
        }

        last_offline_ecus = Some(offline_ecus.join(", "));

        cda_interfaces::util::tokio_ext::sleep_for(POLL_INTERVAL).await;
    }
}

/// The address the test harness binds and reaches the containers at.
pub(crate) fn host() -> String {
    "0.0.0.0".to_owned()
}

pub(crate) async fn wait_for_cda_online(cfg: &ServerConfig) -> Result<(), TestingError> {
    let url = format!("http://{}:{}/health/ready", cfg.address, cfg.port);
    wait_for_http_ready(url, "CDA", Some(http::StatusCode::NO_CONTENT)).await
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

async fn wait_for_http_ready(
    url: String,
    service_name: &str,
    result: Option<http::StatusCode>,
) -> Result<(), TestingError> {
    wait_for_http_ready_with_timeout(url, service_name, result, Duration::from_secs(10)).await
}

pub(crate) async fn wait_for_http_ready_with_timeout(
    url: String,
    service_name: &str,
    result: Option<http::StatusCode>,
    timeout: Duration,
) -> Result<(), TestingError> {
    let client = reqwest::Client::new();
    let start_time = Instant::now();

    while start_time.elapsed() < timeout {
        if let Ok(response) = client.get(&url).send().await {
            if let Some(expected_status) = result {
                if response.status() == expected_status {
                    return Ok(());
                }
            } else {
                return Ok(());
            }
        }
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(250)).await;
    }

    Err(TestingError::ProcessFailed(format!(
        "{service_name} did not become ready within {timeout:?}"
    )))
}

/// Size of each pool: [`CDA_TEST_POOL_SIZE`], or [`DEFAULT_POOL_SIZE`].
pub(crate) fn pool_size() -> usize {
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

/// Starts socketcand if needed and ecu-sim. Returns the containers and the
/// host they are reachable at.
async fn start_containers(spec: &EnvSpec) -> Result<(Containers, String), TestingError> {
    let mut containers = Containers::default();

    let endpoint = if spec.transport.uses_can() {
        let socketcand = socketcand_container_for(&spec.owner)
            .await?
            .with_network(&spec.network)
            .with_container_name(spec.socketcand_host())
            .with_label(ENV_LABEL, &spec.network)
            .start()
            .await
            .map_err(|e| {
                TestingError::SetupError(format!(
                    "Failed to start socketcand container: {e}. It creates its vcan0 at start, \
                     which needs the vcan kernel module on the Docker host (`sudo modprobe \
                     vcan`); `Unknown device type` in its output above means it is missing."
                ))
            })?;
        containers.socketcand = Some(Arc::new(socketcand));
        Some(SocketcandEndpoint::new(spec.socketcand_host()))
    } else {
        None
    };

    let sim = ecu_sim_container_for(endpoint.as_ref(), &spec.owner)
        .await?
        .with_network(&spec.network)
        .with_container_name(format!("{}-ecu-sim", spec.network))
        .with_label(ENV_LABEL, &spec.network)
        .with_mapped_port(spec.sim_port, ECU_SIM_CONTROL_PORT.tcp())
        .start()
        .await
        .map_err(|e| ecu_sim_start_error(spec, &e))?;
    let host = sim
        .get_host()
        .await
        .map_err(|e| TestingError::SetupError(format!("Failed to get the Docker host: {e}")))?
        .to_string();
    containers.ecu_sim = Some(Arc::new(sim));

    Ok((containers, host))
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

/// Starts a CDA container with `config_toml` as its configuration file, the
/// flash files mounted read-only at [`CDA_FLASH_DIR`], and an empty tmpfs as
/// its storage at [`CDA_STORAGE_DIR`].
async fn start_cda(
    spec: &EnvSpec,
    config_toml: String,
    generation: usize,
) -> Result<ContainerAsync<GenericImage>, TestingError> {
    let flash_dir = flash_files_host_dir()?;
    cda_container_for(spec.variant, &spec.owner)
        .await?
        .with_network(&spec.network)
        .with_container_name(format!("{}-cda-{generation}", spec.network))
        .with_label(ENV_LABEL, &spec.network)
        .with_mapped_port(spec.cda_port, CDA_HTTP_PORT.tcp())
        .with_copy_to(CDA_CONFIG_FILE, config_toml.into_bytes())
        .with_env_var("CDA_CONFIG_FILE", CDA_CONFIG_FILE)
        .with_mount(
            Mount::bind_mount(flash_dir.to_string_lossy(), CDA_FLASH_DIR)
                .with_access_mode(AccessMode::ReadOnly),
        )
        .with_mount(Mount::tmpfs_mount(CDA_STORAGE_DIR).with_size_bytes(CDA_STORAGE_SIZE_BYTES))
        .start()
        .await
        .map_err(|e| TestingError::SetupError(format!("Failed to start CDA container: {e}")))
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
        save_coverage(&cda).await;
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
async fn save_coverage(cda: &ContainerAsync<GenericImage>) {
    if let Err(e) = cda.stop_with_timeout(Some(CDA_STOP_TIMEOUT_SECS)).await {
        eprintln!(
            "Failed to stop CDA container {} for coverage: {e}",
            cda.id()
        );
    }
    let id = cda.id().to_owned();
    if let Err(e) = tokio::task::spawn_blocking(move || save_coverage_with_cli(&id)).await {
        eprintln!("Failed to save the coverage of {}: {e}", cda.id());
    }
}
