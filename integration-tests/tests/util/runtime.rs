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

use cda_plugin_security::{DefaultSecurityPlugin, DefaultSecurityPluginData};
use futures::FutureExt as _;
use opensovd_cda_lib::config::configfile::{ConfigSanity, Configuration};
use tokio::sync::{Mutex, MutexGuard, OnceCell, mpsc};
use tracing_subscriber::layer::SubscriberExt;

use crate::util::TestingError;

static TEST_RUNTIME: OnceCell<TestRuntime> = OnceCell::const_new();

static EXCLUSIVE_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// Tokio isolates the runtime for each test.
/// As we want to share the webserver over all tests, so we do not have to spin it up every time,
/// a new static runtime is created in which the webserver task is running.
static TOKIO_RUNTIME: LazyLock<tokio::runtime::Runtime> =
    LazyLock::new(|| tokio::runtime::Runtime::new().unwrap());

static ECU_SIM_PROCESS: LazyLock<Mutex<Option<std::process::Child>>> =
    LazyLock::new(|| Mutex::new(None));

const CDA_INTEGRATION_TEST_USE_DOCKER: &str = "CDA_INTEGRATION_TEST_USE_DOCKER";
const CDA_INTEGRATION_TEST_TESTER_ADDRESS: &str = "CDA_INTEGRATION_TEST_TESTER_ADDRESS";

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
    // If docker is disabled, we run the sim and cda locally
    // this is useful for debugging tests
    // without having to rebuild the docker containers every time.
    let use_docker = std::env::var(CDA_INTEGRATION_TEST_USE_DOCKER)
        .map(|s| s == "true")
        .unwrap_or(true);
    let host = if !use_docker {
        // Allow overriding the tester address when not using docker.
        // This is useful, as on some systems, using 127.0.0.1 or 0.0.0.0 does not work properly
        // and the CDA will not reach the sim.
        std::env::var(CDA_INTEGRATION_TEST_TESTER_ADDRESS).unwrap_or("0.0.0.0".to_owned())
    } else {
        "0.0.0.0".to_owned()
    };

    let (cda_port, gateway_port, sim_control_port) = if use_docker {
        (
            find_available_tcp_port(&host)?,
            find_available_tcp_port(&host)?,
            find_available_tcp_port(&host)?,
        )
    } else {
        (20002, 13400, 8181) // default ports for local usage
    };

    let databases_path = mdd_file_path()?;

    let config = Configuration {
        server: opensovd_cda_lib::config::configfile::ServerConfig {
            address: host.clone(),
            port: cda_port,
        },
        doip: opensovd_cda_lib::config::configfile::DoipConfig {
            tester_address: host.clone(),
            tester_subnet: "255.255.0.0".to_owned(),
            gateway_port,
        },
        logging: Default::default(),
        onboard_tester: true,
        databases_path,
        flash_files_path: "".to_string(),
        com_params: Default::default(),
        database_naming_convention: Default::default(),
        flat_buf: Default::default(),
    };

    register_cleanup();
    if use_docker {
        start_docker_compose(cda_port, gateway_port, sim_control_port)?;
    } else {
        start_ecu_sim().await?;
        // when using docker, docker compose contains the ready contains
        wait_for_ecu_sim_ready(&host, sim_control_port).await?;
        start_cda(config.clone());
    }

    wait_for_cda_online(&config).await?;

    Ok(TestRuntime {
        config,
        ecu_sim: EcuSim {
            host,
            control_port: sim_control_port,
        },
    })
}

fn start_cda(config: Configuration) {
    // Some unwraps are used here, this is on purpose
    // as we want the tests to fail hard if CDA fails to start.
    TOKIO_RUNTIME.spawn(async move {
        config.validate_sanity().unwrap();

        let tracing = cda_tracing::new();
        let mut layers = vec![];
        layers.push(cda_tracing::new_term_subscriber(&config.logging));
        cda_tracing::init_tracing(tracing.with(layers)).unwrap();

        tracing::info!("Starting CDA...");

        let database_path = config.databases_path.clone();
        let flash_files_path = config.flash_files_path.clone();
        let protocol = cda_interfaces::Protocol::DoIpDobt;

        let (databases, file_managers) =
            opensovd_cda_lib::load_databases::<DefaultSecurityPluginData>(
                &database_path,
                protocol,
                config.com_params,
                config.database_naming_convention,
                config.flat_buf,
            )
            .await;

        let webserver_config = cda_sovd::WebServerConfig {
            host: config.server.address.clone(),
            port: config.server.port,
        };

        let clonable_shutdown_signal = opensovd_cda_lib::shutdown_signal().shared();

        let (variant_detection_tx, variant_detection_rx) = mpsc::channel(50);

        let databases = Arc::new(databases);
        let diagnostic_gateway = match opensovd_cda_lib::create_diagnostic_gateway(
            Arc::clone(&databases),
            &config.doip.tester_address,
            &config.doip.tester_subnet,
            config.doip.gateway_port,
            variant_detection_tx,
            clonable_shutdown_signal.clone(),
        )
        .await
        {
            Ok(gateway) => gateway,
            Err(e) => {
                tracing::error!(error = %e, "Failed to create diagnostic gateway");
                std::process::exit(1);
            }
        };

        let uds = opensovd_cda_lib::create_uds_manager(
            diagnostic_gateway,
            databases,
            variant_detection_rx,
        );

        let exit_code = match opensovd_cda_lib::start_webserver::<_, DefaultSecurityPlugin>(
            flash_files_path,
            file_managers,
            webserver_config,
            uds,
            clonable_shutdown_signal,
        )
        .await
        {
            Ok(Ok(())) => {
                tracing::info!("Shutting down...");
                None
            }
            Ok(Err(e)) => {
                tracing::error!(error = ?e, "Failed to start webserver");
                Some(1)
            }
            Err(je) => {
                if je.is_panic() {
                    let reason = je.into_panic();
                    tracing::error!(panic_reason = ?reason, "Webserver thread panicked");
                }
                Some(1)
            }
        };

        if let Some(exit_code) = exit_code {
            std::process::exit(exit_code);
        }
    });
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

    let status = std::process::Command::new("docker")
        .arg("compose")
        .arg("up")
        .arg("-d")
        .current_dir(&test_container_dir)
        .status()
        .map_err(|e| TestingError::ProcessFailed(format!("Failed to start docker compose: {e}")))?;
    check_command_success(status, "docker compose up failed")
}

fn stop_docker_compose() -> Result<(), TestingError> {
    let test_container_dir = test_container_dir()?;
    let status = std::process::Command::new("docker")
        .arg("compose")
        .arg("down")
        .current_dir(&test_container_dir)
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
         Port\nSIM_CONTROL_PORT={}\n# ECU Simulator Gateway Port\nSIM_GATEWAY_PORT={}\n# CDA \
         Service Port\nCDA_PORT={}\n",
        sim_control_port, gateway_port, cda_port
    );

    std::fs::write(&env_file_path, env_content)
        .map_err(|e| TestingError::ProcessFailed(format!("Failed to write .env file: {e}")))?;

    tracing::debug!("Wrote Docker Compose .env file to {:?}", env_file_path);
    Ok(())
}

async fn start_ecu_sim() -> Result<(), TestingError> {
    let ecu_sim_dir = ecu_sim_dir()?;
    if !ecu_sim_dir.exists() {
        return Err(TestingError::PathNotFound(format!(
            "ecu-sim run script not found at {ecu_sim_dir:?}"
        )));
    }

    let child = std::process::Command::new("bash")
        .current_dir(&ecu_sim_dir)
        .arg("gradlew")
        .arg("run")
        .spawn()
        .map_err(|e| TestingError::ProcessFailed(format!("Failed to start ecu-sim: {e}")))?;

    *ECU_SIM_PROCESS.lock().await = Some(child);

    Ok(())
}

fn stop_ecu_sim() -> Result<(), TestingError> {
    TOKIO_RUNTIME.block_on(async {
        if let Some(mut child) = ECU_SIM_PROCESS.lock().await.take() {
            child.kill().map_err(|e| {
                TestingError::ProcessFailed(format!("Failed to kill ecu-sim process: {e}"))
            })?;
            child.wait().ok();
        }
        Ok(())
    })
}

async fn wait_for_http_ready(url: String, service_name: &str) -> Result<(), TestingError> {
    let client = reqwest::Client::new();
    let start_time = Instant::now();
    let timeout = Duration::from_secs(10);

    while start_time.elapsed() < timeout {
        match client.get(&url).send().await {
            Ok(_) => {
                return Ok(());
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
    wait_for_http_ready(url, "ECU sim").await
}

async fn wait_for_cda_online(cfg: &Configuration) -> Result<(), TestingError> {
    let url = format!("http://{}:{}", cfg.server.address, cfg.server.port);
    wait_for_http_ready(url, "CDA").await
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
                    entry
                        .path()
                        .extension()
                        .and_then(|ext| ext.to_str())
                        .map(|ext| ext == "mdd")
                        .unwrap_or(false)
                })
            })
            .is_some()
    }

    let odx_path = test_container_dir()?.join("odx");
    if !odx_path.exists() {
        return Err(TestingError::PathNotFound(format!(
            "odx directory not found at {odx_path:?}"
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

fn find_available_tcp_port(listen_address: &str) -> Result<u16, TestingError> {
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
            if let Err(e) = stop_docker_compose() {
                eprintln!("Failed to stop docker compose: {}", e);
            }
        } else {
            if let Err(e) = stop_ecu_sim() {
                eprintln!("Failed to stop ecu-sim: {}", e);
            }
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
    if !status.success() {
        Err(TestingError::ProcessFailed(error_msg.to_owned()))
    } else {
        Ok(())
    }
}
