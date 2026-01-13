/*
 * Copyright (c) 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
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

use std::{
    sync::{Arc, LazyLock},
    time::{Duration, Instant},
};

use cda_core::DiagServiceResponseStruct;
use cda_health::config::HealthConfig;
use cda_interfaces::{
    FunctionalDescriptionConfig,
    datatypes::{ComParams, DatabaseNamingConvention, FlatbBufConfig},
};
use cda_plugin_security::{DefaultSecurityPlugin, DefaultSecurityPluginData};
use cda_tracing::LoggingConfig;
use futures::FutureExt as _;
use opensovd_cda_lib::{
    cda_version,
    config::configfile::{ConfigSanity, Configuration, DatabaseConfig, ServerConfig},
};
use tokio::sync::{Mutex, MutexGuard, OnceCell};
use tracing_subscriber::layer::SubscriberExt;

use crate::util::TestingError;

static TEST_RUNTIME: OnceCell<TestRuntime> = OnceCell::const_new();

static EXCLUSIVE_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

static CDA_SHUTDOWN: LazyLock<Mutex<Option<tokio::sync::broadcast::Sender<()>>>> =
    LazyLock::new(|| Mutex::new(None));

/// Tokio isolates the runtime for each test.
/// As we want to share the webserver over all tests, so we do not have to spin it up every time,
/// a new static runtime is created in which the webserver task is running.
static TOKIO_RUNTIME: LazyLock<tokio::runtime::Runtime> =
    LazyLock::new(|| tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime"));

static ECU_SIM_PROCESS: LazyLock<Mutex<Option<std::process::Child>>> =
    LazyLock::new(|| Mutex::new(None));

const CDA_INTEGRATION_TEST_USE_DOCKER: &str = "CDA_INTEGRATION_TEST_USE_DOCKER";
const CDA_INTEGRATION_TEST_TESTER_ADDRESS: &str = "CDA_INTEGRATION_TEST_TESTER_ADDRESS";

const MAIN_HEALTH_COMPONENT_KEY: &str = "main";

pub(crate) struct TestRuntime {
    pub(crate) config: Configuration,
    pub(crate) ecu_sim: EcuSim,
}

pub(crate) struct EcuSim {
    pub(crate) host: String,
    pub(crate) control_port: u16,
}

pub(crate) async fn setup_integration_test<'a>(
    exclusive: bool,
) -> Result<(&'a TestRuntime, Option<MutexGuard<'a, ()>>), TestingError> {
    let lock_guard = EXCLUSIVE_LOCK.lock().await;

    let runtime = match TEST_RUNTIME
        .get_or_try_init(|| async { initialize_runtime().await })
        .await
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("Failed to initialize test runtime: {e}");
            std::process::exit(1);
        }
    };

    if exclusive {
        // If exclusive access is requested, lock the dedicated mutex
        // and return the guard. The test must hold onto this guard.
        tracing::debug!("forwarding exclusive lock");
        Ok((runtime, Some(lock_guard)))
    } else {
        // For non-exclusive tests, just return the cloned Arc.
        Ok((runtime, None))
    }
}

async fn initialize_runtime() -> Result<TestRuntime, TestingError> {
    let tracing = cda_tracing::new();
    let layers = vec![cda_tracing::new_term_subscriber(
        &cda_tracing::LoggingConfig::default(),
    )];
    cda_tracing::init_tracing(tracing.with(layers)).map_err(|e| {
        TestingError::SetupError(format!("Failed to initialize tracing for tests: {e}"))
    })?;

    // If docker is disabled, we run the sim and cda locally
    // this is useful for debugging tests
    // without having to rebuild the docker containers every time.
    let host = host();
    let (cda_port, gateway_port, sim_control_port) = if use_docker() {
        (
            find_available_tcp_port(&host)?,
            find_available_tcp_port(&host)?,
            find_available_tcp_port(&host)?,
        )
    } else {
        (20002, 13400, 8181) // default ports for local usage
    };

    let config = Configuration {
        server: opensovd_cda_lib::config::configfile::ServerConfig {
            address: host.clone(),
            port: cda_port,
        },
        doip: opensovd_cda_lib::config::configfile::DoipConfig {
            tester_address: host.clone(),
            tester_subnet: "255.255.0.0".to_owned(),
            gateway_port,
            send_timeout_ms: 1000,
        },
        database: DatabaseConfig {
            path: mdd_file_path()?,
            naming_convention: DatabaseNamingConvention::default(),
            exit_no_database_loaded: true,
        },
        logging: LoggingConfig::default(),
        onboard_tester: true,
        flash_files_path: String::default(),
        com_params: ComParams::default(),
        flat_buf: FlatbBufConfig::default(),
        functional_description: FunctionalDescriptionConfig {
            description_database: "functional_groups".to_owned(),
            enabled_functional_groups: None,
            protocol_position: cda_interfaces::datatypes::DiagnosticServiceAffixPosition::Suffix,
            protocol_case_sensitive: false,
        },
        health: HealthConfig::default(),
    };
    config.validate_sanity().map_err(|e| {
        TestingError::SetupError(format!("Configuration sanity check failed: {e:?}"))
    })?;
    let ecu_sim = EcuSim {
        host: host.clone(),
        control_port: sim_control_port,
    };

    register_cleanup();
    if use_docker() {
        start_docker_compose(cda_port, gateway_port, sim_control_port)?;
    } else {
        start_ecu_sim(&ecu_sim).await?;
        start_cda(config.clone());
    }

    wait_for_cda_online(&config.server).await?;

    Ok(TestRuntime { config, ecu_sim })
}

pub(crate) fn host() -> String {
    if use_docker() {
        "0.0.0.0".to_owned()
    } else {
        // Allow overriding the tester address when not using docker.
        // This is useful, as on some systems, using 127.0.0.1 or 0.0.0.0 does not work properly
        // and the CDA will not reach the sim.
        std::env::var(CDA_INTEGRATION_TEST_TESTER_ADDRESS).unwrap_or("0.0.0.0".to_owned())
    }
}

fn start_cda(config: Configuration) {
    // Some unwraps are used here, this is on purpose
    // as we want the tests to fail hard if CDA fails to start.
    TOKIO_RUNTIME.spawn(async move {
        let webserver_config = cda_sovd::WebServerConfig {
            host: config.server.address.clone(),
            port: config.server.port,
        };

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::broadcast::channel(1);
        *CDA_SHUTDOWN.lock().await = Some(shutdown_tx);

        let clonable_shutdown_signal = async move {
            shutdown_rx.recv().await.ok();
        }
        .shared();

        // Launch the webserver with deferred initialization
        let (dynamic_router, webserver_join_handle) =
            match cda_sovd::launch_webserver(webserver_config, clonable_shutdown_signal.clone())
                .await
            {
                Ok((router, jh)) => (router, jh),
                Err(e) => {
                    tracing::error!(error = ?e, "Failed to launch webserver");
                    std::process::exit(1);
                }
            };

        let health = cda_health::add_health_routes(&dynamic_router, cda_version().to_owned()).await;
        let main_health_provider = {
            let provider = Arc::new(cda_health::StatusHealthProvider::new(
                cda_health::Status::Starting,
            ));
            health
                .register_provider(
                    MAIN_HEALTH_COMPONENT_KEY,
                    Arc::clone(&provider) as Arc<dyn cda_health::HealthProvider>,
                )
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "Failed to register main health provider");
                    std::process::exit(1);
                })
                .ok();
            provider
        };
        let health = Some(health);

        let vehicle_data = opensovd_cda_lib::load_vehicle_data::<_, DefaultSecurityPluginData>(
            &config,
            clonable_shutdown_signal.clone(),
            health.as_ref(),
        )
        .await
        .map_err(|e| {
            tracing::error!({error=?e});
            std::process::exit(1);
        })
        .unwrap();

        cda_sovd::add_vehicle_routes::<DiagServiceResponseStruct, _, _, DefaultSecurityPlugin>(
            &dynamic_router,
            vehicle_data.uds_manager,
            config.flash_files_path.clone(),
            vehicle_data.file_managers,
            vehicle_data.locks,
            config.functional_description,
        )
        .await
        .map_err(|e| {
            tracing::error!({error=?e});
            std::process::exit(1);
        })
        .unwrap();

        tracing::info!("CDA fully initialized and ready to serve requests");
        main_health_provider
            .update_status(cda_health::Status::Up)
            .await;

        // Wait for shutdown signal
        clonable_shutdown_signal.await;
        tracing::info!("Shutting down...");
        webserver_join_handle
            .await
            .map_err(|e| {
                tracing::error!({error=?e}, "Webserver task join error");
                std::process::exit(1);
            })
            .ok();
    });
}

async fn stop_cda() -> Result<(), TestingError> {
    if let Some(sender) = CDA_SHUTDOWN.lock().await.as_ref() {
        sender.send(()).ok();
        Ok(())
    } else {
        Err(TestingError::ProcessFailed("CDA not running".to_owned()))
    }
}

fn start_docker_compose(
    cda_port: u16,
    gateway_port: u16,
    sim_control_port: u16,
) -> Result<(), TestingError> {
    let test_container_dir = test_container_dir()?;

    // Write .env file with generated ports
    write_docker_env_file(
        &test_container_dir,
        cda_port,
        gateway_port,
        sim_control_port,
    )?;

    let status = std::process::Command::new("docker")
        .arg("compose")
        .arg("build")
        .current_dir(&test_container_dir)
        .status()
        .map_err(|e| TestingError::ProcessFailed(format!("Failed to build docker compose: {e}")))?;
    check_command_success(status, "docker compose build failed")?;

    docker_compose_up(None)
}

fn docker_compose_up(container: Option<String>) -> Result<(), TestingError> {
    let test_container_dir = test_container_dir()?;
    let mut cmd = std::process::Command::new("docker");
    cmd.arg("compose").arg("up").arg("-d");
    if let Some(container_name) = container {
        cmd.arg(container_name);
    }
    let status = cmd
        .current_dir(&test_container_dir)
        .status()
        .map_err(|e| TestingError::ProcessFailed(format!("Failed to start docker compose: {e}")))?;
    check_command_success(status, "docker compose up failed")
}

fn docker_compose_down(container: Option<String>) -> Result<(), TestingError> {
    let test_container_dir = test_container_dir()?;
    let mut cmd = std::process::Command::new("docker");
    cmd.arg("compose")
        .arg("down")
        .arg("--remove-orphans")
        .current_dir(&test_container_dir);

    if let Some(container_name) = container {
        cmd.arg(container_name);
    }

    let status = cmd
        .status()
        .map_err(|e| TestingError::ProcessFailed(format!("Failed to stop docker compose: {e}")))?;
    check_command_success(status, "docker compose down failed")
}

fn write_docker_env_file(
    test_container_dir: &std::path::Path,
    cda_port: u16,
    gateway_port: u16,
    sim_control_port: u16,
) -> Result<(), TestingError> {
    let env_file_path = test_container_dir.join(".env");
    let env_content = format!(
        "# Auto-generated environment file for integration tests\n# ECU Simulator Control \
         Port\nSIM_CONTROL_PORT={sim_control_port}\n# ECU Simulator Gateway \
         Port\nSIM_GATEWAY_PORT={gateway_port}\n# CDA Service Port\nCDA_PORT={cda_port}\n",
    );

    std::fs::write(&env_file_path, env_content)
        .map_err(|e| TestingError::ProcessFailed(format!("Failed to write .env file: {e}")))?;

    tracing::debug!("Wrote Docker Compose .env file to {:?}", env_file_path);
    Ok(())
}

pub(crate) async fn start_ecu_sim(sim: &EcuSim) -> Result<(), TestingError> {
    if use_docker() {
        docker_compose_up(Some("ecu-sim".to_owned()))?;
    } else {
        let ecu_sim_dir = ecu_sim_dir()?;
        if !ecu_sim_dir.exists() {
            return Err(TestingError::PathNotFound(format!(
                "ecu-sim run script not found at {}",
                ecu_sim_dir.display()
            )));
        }

        let child = std::process::Command::new("bash")
            .current_dir(&ecu_sim_dir)
            .arg("gradlew")
            .arg("run")
            .spawn()
            .map_err(|e| TestingError::ProcessFailed(format!("Failed to start ecu-sim: {e}")))?;

        *ECU_SIM_PROCESS.lock().await = Some(child);
    }
    wait_for_ecu_sim_ready(&sim.host, sim.control_port).await
}

pub(crate) async fn stop_ecu_sim() -> Result<(), TestingError> {
    if use_docker() {
        docker_compose_down(Some("ecu-sim".to_owned()))
    } else {
        if let Some(mut child) = ECU_SIM_PROCESS.lock().await.take() {
            child.kill().map_err(|e| {
                TestingError::ProcessFailed(format!("Failed to kill ecu-sim process: {e}"))
            })?;
            child.wait().ok();
        }
        Ok(())
    }
}

fn stop_ecu_sim_sync() -> Result<(), TestingError> {
    TOKIO_RUNTIME.block_on(async { stop_ecu_sim().await })
}

fn docker_compose_restart(container: Option<String>) -> Result<(), TestingError> {
    let test_container_dir = test_container_dir()?;
    let mut cmd = std::process::Command::new("docker");
    cmd.arg("compose").arg("restart");
    if let Some(container_name) = container {
        cmd.arg(container_name);
    }
    let status = cmd.current_dir(&test_container_dir).status().map_err(|e| {
        TestingError::ProcessFailed(format!("Failed to restart docker compose: {e}"))
    })?;
    check_command_success(status, "docker compose restart failed")
}

pub(crate) async fn restart_cda(config: &Configuration) -> Result<(), TestingError> {
    if use_docker() {
        docker_compose_restart(Some("cda".to_owned()))?;
    } else {
        stop_cda().await?;
        start_cda(config.clone());
    }
    wait_for_cda_online(&config.server).await
}

fn use_docker() -> bool {
    std::env::var(CDA_INTEGRATION_TEST_USE_DOCKER)
        .map(|s| s == "true")
        .unwrap_or(true)
}

async fn wait_for_http_ready(
    url: String,
    service_name: &str,
    result: Option<http::StatusCode>,
) -> Result<(), TestingError> {
    let client = reqwest::Client::new();
    let start_time = Instant::now();
    let timeout = Duration::from_secs(10);

    while start_time.elapsed() < timeout {
        match client.get(&url).send().await {
            Ok(response) => {
                if let Some(expected_status) = result {
                    if response.status() == expected_status {
                        return Ok(());
                    }
                } else {
                    return Ok(());
                }
            }
            _ => tokio::time::sleep(Duration::from_millis(250)).await,
        }
    }

    Err(TestingError::ProcessFailed(format!(
        "{service_name} did not become ready within {timeout:?}"
    )))
}

async fn wait_for_ecu_sim_ready(host: &str, sim_control_port: u16) -> Result<(), TestingError> {
    let url = format!("http://{host}:{sim_control_port}");
    wait_for_http_ready(url, "ECU sim", None).await
}

pub(crate) async fn wait_for_cda_online(cfg: &ServerConfig) -> Result<(), TestingError> {
    let url = format!("http://{}:{}/health/ready", cfg.address, cfg.port);
    wait_for_http_ready(url, "CDA", Some(http::StatusCode::NO_CONTENT)).await
}

fn ecu_sim_dir() -> Result<std::path::PathBuf, TestingError> {
    test_container_dir().map(|mut path| {
        path.push("ecu-sim");
        path
    })
}

fn mdd_file_path() -> Result<String, TestingError> {
    fn mdd_files_exist(path: &std::path::Path) -> bool {
        std::fs::read_dir(path)
            .ok()
            .and_then(|entries| {
                entries.filter_map(Result::ok).find(|entry| {
                    entry.path().extension().and_then(|ext| ext.to_str()) == Some("mdd")
                })
            })
            .is_some()
    }

    let odx_path = test_container_dir()?.join("odx");
    if !odx_path.exists() {
        return Err(TestingError::PathNotFound(format!(
            "odx directory not found at {}",
            odx_path.display()
        )));
    }

    if !mdd_files_exist(&odx_path) {
        return Err(TestingError::PathNotFound(
            "MDD files not found. Please generate MDD files manually using odx-converter. See \
             README for instructions."
                .to_owned(),
        ));
    }

    Ok(odx_path.to_string_lossy().to_string())
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

fn test_container_dir() -> Result<std::path::PathBuf, TestingError> {
    std::env::var("CARGO_MANIFEST_DIR")
        .map(|dir| {
            let mut path = std::path::PathBuf::from(dir);
            path.pop();
            path.push("testcontainer");
            path
        })
        .ok()
        .and_then(|path| if path.exists() { Some(path) } else { None })
        .ok_or_else(|| TestingError::PathNotFound("testcontainer directory not found".to_owned()))
}

fn register_cleanup() {
    extern "C" fn cleanup_handler() {
        let use_docker = std::env::var(CDA_INTEGRATION_TEST_USE_DOCKER)
            .map(|s| s == "true")
            .unwrap_or(true);

        if use_docker {
            if let Err(e) = docker_compose_down(None) {
                eprintln!("Failed to stop docker compose: {e}");
            }
        } else if let Err(e) = stop_ecu_sim_sync() {
            eprintln!("Failed to stop ecu-sim: {e}");
        }
    }
    unsafe {
        libc::atexit(cleanup_handler);
    }
}

fn check_command_success(
    status: std::process::ExitStatus,
    error_msg: &str,
) -> Result<(), TestingError> {
    if status.success() {
        Ok(())
    } else {
        Err(TestingError::ProcessFailed(error_msg.to_owned()))
    }
}
