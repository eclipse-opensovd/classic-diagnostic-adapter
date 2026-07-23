/*
 * SPDX-FileCopyrightText: 2025 Copyright (c) Contributors to the Eclipse Foundation
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

use cda_config::{
    datatypes::{
        DatabaseNamingConvention, FunctionalDescriptionConfig, HealthConfig, LoggingConfig,
    },
    validate::ConfigSanity,
};
use cda_interfaces::{
    HashMap, HashMapExtensions,
    datatypes::{
        ComParamConfig, ComParamPrecedence, ComParams, ComponentsConfig, DoipComParams,
        FaultConfig, FlatbBufConfig,
    },
};
use cda_plugin_security::{DefaultSecurityPlugin, DefaultSecurityPluginData};
use futures::FutureExt as _;
use http::{Method, StatusCode};
use opensovd_cda_lib::{
    cda_version,
    config::configfile::{
        Configuration, DatabaseConfig, EcuComParams, EcuConfig, RuntimeUpdateConfig, ServerConfig,
        StrictConfig,
    },
};
use sovd_interfaces::apps::sovd2uds::data::network_structure::get::Response as NetworkStructureResponse;
use tokio::sync::{Mutex, MutexGuard, OnceCell};
use tracing_subscriber::layer::SubscriberExt;

use crate::util::{
    TestingError, ecusim,
    http::{response_to_t, send_cda_request},
};

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
const CDA_INTEGRATION_TEST_COVERAGE: &str = "CDA_INTEGRATION_TEST_COVERAGE";

const MAIN_HEALTH_COMPONENT_KEY: &str = "main";

pub(crate) struct TestRuntime {
    pub(crate) config: Configuration,
    pub(crate) ecu_sim: EcuSim,
}

#[derive(Clone)]
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

    // Make sure we have a clean state at the beginning of the test
    ecusim::reset_sim(&runtime.ecu_sim).await?;
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
        &cda_config::datatypes::LoggingConfig::default(),
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

    let config = cda_test_config(host.clone(), cda_port, gateway_port)?;
    config.validate_sanity().map_err(|e| {
        TestingError::SetupError(format!("Configuration sanity check failed: {e:?}"))
    })?;
    let ecu_sim = EcuSim {
        host: host.clone(),
        control_port: sim_control_port,
    };

    register_cleanup();
    register_panic_hook();
    if use_docker() {
        write_config_toml(&test_container_dir()?, config.clone())?;
        start_docker_compose(cda_port, gateway_port, sim_control_port)?;
    } else {
        start_ecu_sim(&ecu_sim).await?;
        start_cda(config.clone());
    }

    if let Err(e) = wait_for_cda_online(&config.server).await {
        dump_docker_logs();
        return Err(e);
    }

    Ok(TestRuntime { config, ecu_sim })
}

fn cda_test_config(
    host: String,
    cda_port: u16,
    gateway_port: u16,
) -> Result<Configuration, TestingError> {
    let config = Configuration {
        server: opensovd_cda_lib::config::configfile::ServerConfig {
            address: host.clone(),
            port: cda_port,
        },
        doip: opensovd_cda_lib::config::configfile::DoipConfig {
            tester_address: host,
            gateway_port,
            ..Default::default()
        },
        database: DatabaseConfig {
            path: mdd_file_path()?,
            naming_convention: DatabaseNamingConvention::default(),
            exit_no_database_loaded: true,
            fallback_to_base_variant: true,
            ignore_protocol: false,
            ignore_invalid_mdd: false,
        },
        logging: LoggingConfig::default(),
        flash_files_path: flash_files_path()?,
        com_params: {
            // logical_functional_address is set globally so that ECUs whose MDD omits
            // this comparam (e.g. TMCC3000) receive it via the global fallback path.
            // ECUs that carry the value in their MDD (FLXC1000, FLXCNG1000, FSNR2000)
            // are unaffected because the DB value takes precedence.
            let mut p = ComParams::default();
            p.doip.logical_functional_address.value = 0xFFFF;
            p
        },
        flat_buf: FlatbBufConfig::default(),
        functional_description: FunctionalDescriptionConfig {
            description_database: "functional_groups".to_owned(),
            enabled_functional_groups: None,
            protocol_position: cda_config::datatypes::DiagnosticServiceAffixPosition::Suffix,
        },
        health: HealthConfig::default(),
        components: ComponentsConfig {
            additional_fields: HashMap::new(),
        },
        faults: FaultConfig {
            user_defined_dtc_clear_service: Some(vec![0x31, 0x01, 0x42, 0x00]),
            user_memory_scope: "Development".to_owned(),
            ..Default::default()
        },
        ecu: {
            let mut map = HashMap::new();
            map.insert(
                "TMCC3000".to_owned(),
                EcuConfig {
                    ignore_protocol: Some(true),
                    com_params: Some(
                        EcuComParams::try_from(ComParams {
                            doip: DoipComParams {
                                logical_gateway_address: ComParamConfig {
                                    name: "logical_gateway_address".to_string(),
                                    value: 0x3000,
                                    precedence: ComParamPrecedence::Config,
                                },
                                ..Default::default()
                            },
                            ..Default::default()
                        })
                        .expect("Failed to create EcuConfig for TMCC3000"),
                    ),
                    ..Default::default()
                },
            );
            map.insert(
                "HOVR4000".to_owned(),
                EcuConfig {
                    com_params: Some(
                        EcuComParams::try_from(ComParams {
                            doip: DoipComParams {
                                logical_gateway_address: ComParamConfig {
                                    name: "logical_gateway_address".to_string(),
                                    value: 0x4000,
                                    precedence: ComParamPrecedence::Config,
                                },
                                ..Default::default()
                            },
                            ..Default::default()
                        })
                        .expect("Failed to create EcuConfig for HOVR4000"),
                    ),
                    protocol: Some("DMC_DoIP".to_owned()),
                    ignore_protocol: Some(false),
                },
            );
            map.insert(
                "JGWT5000".to_owned(),
                EcuConfig {
                    ignore_protocol: Some(true),
                    com_params: Some(
                        EcuComParams::try_from(ComParams {
                            doip: DoipComParams {
                                logical_gateway_address: ComParamConfig {
                                    name: "logical_gateway_address".to_string(),
                                    value: 0x5000,
                                    precedence: ComParamPrecedence::Config,
                                },
                                ..Default::default()
                            },
                            ..Default::default()
                        })
                        .expect("Failed to create EcuConfig for JGWT5000"),
                    ),
                    ..Default::default()
                },
            );
            map
        },
        runtime_update_config: RuntimeUpdateConfig {
            init_storage_from_database_path: true,
            ..RuntimeUpdateConfig::default()
        },
        strict: StrictConfig::default(),
    };
    Ok(config)
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

        // Register version endpoints
        if let serde_json::Value::Object(version_info) = serde_json::json!({
            "id": "version",
            "data": {
                "name": "Eclipse OpenSOVD Classic Diagnostic Adapter",
                "api": {
                    "version": "1.1"
                },
                "implementation": {
                    "version": cda_version(),
                }
            }
        }) {
            cda_sovd::add_static_data_endpoint(
                &dynamic_router,
                version_info.clone(),
                "/vehicle/v15/apps/sovd2uds/data/version",
            )
            .await;
            cda_sovd::add_static_data_endpoint(
                &dynamic_router,
                version_info,
                "/vehicle/v15/data/version",
            )
            .await;
        }

        cda_sovd::add_vehicle_routes::<_, _, DefaultSecurityPlugin>(
            &dynamic_router,
            cda_sovd::VehicleConfig {
                flash_files_path: config.flash_files_path.clone(),
                functional_group_config: config.functional_description,
                components_config: config.components,
            },
            cda_sovd::VehicleResources {
                ecu_uds: vehicle_data.uds_manager,
                file_manager: vehicle_data.file_managers,
                locks: vehicle_data.locks,
                update_in_progress: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            },
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

    let mut cmd = std::process::Command::new("docker");
    cmd.arg("compose");

    if coverage_mode() {
        append_coverage_compose_files(&mut cmd);
    }

    cmd.arg("build")
        // For actual reproducible builds, this should be stamped with something related
        // to the source, but does not matter for the integration tests.
        // If it is not set the build you try to fetch it via git, which is not available either.
        // Same is true to the git sha. Needed to build, but exact content does not matter.
        .arg("--build-arg")
        .arg("SOURCE_DATE_EPOCH=0")
        .arg("--build-arg")
        .arg("SOURCE_GIT_SHA=unknown")
        .env("DOCKER_BUILDKIT", "1")
        .current_dir(&test_container_dir);

    let status = cmd
        .status()
        .map_err(|e| TestingError::ProcessFailed(format!("Failed to build docker compose: {e}")))?;
    check_command_success(status, "docker compose build failed")?;

    docker_compose_up(None)
}

fn docker_compose_up(container: Option<String>) -> Result<(), TestingError> {
    let test_container_dir = test_container_dir()?;
    let mut cmd = std::process::Command::new("docker");
    cmd.arg("compose");

    // Use coverage-enabled compose file when running with coverage instrumentation
    // Note: -f flags are global options and must appear before the subcommand
    if coverage_mode() {
        append_coverage_compose_files(&mut cmd);
    }

    cmd.arg("up").arg("-d").env("DOCKER_BUILDKIT", "1");

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
    cmd.arg("compose");

    // Use coverage-enabled compose file when running with coverage instrumentation
    // Note: -f flags are global options and must appear before the subcommand
    if coverage_mode() {
        append_coverage_compose_files(&mut cmd);
    }

    cmd.arg("down")
        .arg("--remove-orphans")
        .env("DOCKER_BUILDKIT", "1")
        .current_dir(&test_container_dir);

    if let Some(container_name) = container {
        cmd.arg(container_name);
    }

    let status = cmd
        .status()
        .map_err(|e| TestingError::ProcessFailed(format!("Failed to stop docker compose: {e}")))?;
    check_command_success(status, "docker compose down failed")
}

fn dump_docker_logs() {
    if !use_docker() {
        tracing::debug!("Skipping docker logs dump - not using docker");
        return;
    }

    let test_container_dir = match test_container_dir() {
        Ok(dir) => dir,
        Err(e) => {
            tracing::error!("Failed to get test container dir for logs: {e}");
            return;
        }
    };

    tracing::error!("========== Docker Compose Logs ==========");

    let output = std::process::Command::new("docker")
        .arg("compose")
        .arg("logs")
        .arg("--no-color")
        .current_dir(&test_container_dir)
        .output();

    match output {
        Ok(output) => {
            if !output.stdout.is_empty() {
                let log_text = strip_ansi_codes(&String::from_utf8_lossy(&output.stdout));
                tracing::error!("{log_text}");
            }
            if !output.stderr.is_empty() {
                let log_text = strip_ansi_codes(&String::from_utf8_lossy(&output.stderr));
                tracing::error!("{log_text}");
            }
        }
        Err(e) => {
            tracing::error!("Failed to fetch docker compose logs: {e}");
        }
    }

    tracing::error!("========== End Docker Compose Logs ==========");
}

fn append_coverage_compose_files(cmd: &mut std::process::Command) {
    cmd.arg("-f")
        .arg("docker-compose.yml")
        .arg("-f")
        .arg("docker-compose.coverage.yml");
}

/// Strips ANSI escape codes from a string (e.g., color codes like \x1b[0m)
fn strip_ansi_codes(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Skip the escape sequence
            if chars.peek() == Some(&'[') {
                chars.next(); // consume '['
                // Consume until we hit a letter (the terminator)
                while let Some(&next) = chars.peek() {
                    chars.next();
                    if next.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else {
            result.push(c);
        }
    }

    result
}

/// Serializes the test [`Configuration`] to a TOML file in the testcontainer directory.
/// The Docker container mounts this file and loads it via `CDA_CONFIG_FILE`.
///
/// The config is adjusted for the Docker environment: network ports and paths are set to
/// container-internal values (e.g. port 20002, gateway 13400, database `/app/odx`),
/// while non-network settings like `faults` are preserved from the test config.
/// The tester address is overridden by the entrypoint script via CLI args.
fn write_config_toml(
    test_container_dir: &std::path::Path,
    mut config: Configuration,
) -> Result<(), TestingError> {
    // Overwrite some values back to the default, so they match
    // with the docker file.
    // The values in the config are the externally mapped ports and paths.
    config.server.port = 20002;
    config.doip.gateway_port = 13400;
    config.functional_description.description_database = "functional_groups".into();

    "0.0.0.0".clone_into(&mut config.server.address);
    "/app/odx".clone_into(&mut config.database.path);

    let config_path = test_container_dir.join("cda-test-config.toml");
    let toml_content = toml::to_string_pretty(&config).map_err(|e| {
        TestingError::SetupError(format!("Failed to serialize config to TOML: {e}"))
    })?;
    std::fs::write(&config_path, toml_content).map_err(|e| {
        TestingError::ProcessFailed(format!(
            "Failed to write config TOML file '{}': {e}",
            config_path.display()
        ))
    })?;

    // Sync the file itself to ensure content is flushed to disk before Docker
    // mounts the volume. This prevents a race condition where Docker reads a
    // partially written or cached config file.
    let file = std::fs::File::open(&config_path).map_err(|e| {
        TestingError::ProcessFailed(format!(
            "Failed to open config file for sync '{}': {e}",
            config_path.display()
        ))
    })?;
    file.sync_all().map_err(|e| {
        TestingError::ProcessFailed(format!(
            "Failed to fsync config file '{}': {e}",
            config_path.display()
        ))
    })?;

    // Also sync the directory to ensure metadata is flushed.
    let dir = std::fs::File::open(test_container_dir).map_err(|e| {
        TestingError::ProcessFailed(format!(
            "Failed to open config directory '{}': {e}",
            test_container_dir.display()
        ))
    })?;
    dir.sync_all().map_err(|e| {
        TestingError::ProcessFailed(format!(
            "Failed to fsync config directory '{}': {e}",
            test_container_dir.display()
        ))
    })?;

    tracing::debug!("Wrote CDA test config to {:?}", config_path);
    Ok(())
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
    std::env::var(CDA_INTEGRATION_TEST_USE_DOCKER).map_or(true, |s| s == "true")
}

fn coverage_mode() -> bool {
    std::env::var(CDA_INTEGRATION_TEST_COVERAGE).is_ok_and(|s| s == "true")
}

async fn wait_for_http_ready(
    url: String,
    service_name: &str,
    result: Option<http::StatusCode>,
) -> Result<(), TestingError> {
    wait_for_http_ready_with_timeout(url, service_name, result, Duration::from_secs(10)).await
}

async fn wait_for_http_ready_with_timeout(
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

async fn wait_for_ecu_sim_ready(host: &str, sim_control_port: u16) -> Result<(), TestingError> {
    let url = format!("http://{host}:{sim_control_port}");
    // Allow extra time for Gradle to download its distribution on a cold cache.
    let timeout = if use_docker() {
        Duration::from_secs(10)
    } else {
        // use 333 as its not divisible by 60 to prevent
        // nightly clippy from suggesting to use from_mins
        Duration::from_secs(333)
    };
    wait_for_http_ready_with_timeout(url, "ECU sim", None, timeout).await
}

pub(crate) async fn wait_for_cda_online(cfg: &ServerConfig) -> Result<(), TestingError> {
    let url = format!("http://{}:{}/health/ready", cfg.address, cfg.port);
    wait_for_http_ready(url, "CDA", Some(http::StatusCode::NO_CONTENT)).await
}

/// Poll the networkstructure endpoint until every ECU in every gateway reports
/// `"Online"`, or until the timeout elapses.
///
/// This is needed after `reset_sim` because the `DoIP` reconnection and variant
/// detection run asynchronously: returning immediately after reset would allow
/// tests to start before the ECU is reachable, causing `ecu_state=Offline` at
/// lock creation time and making tester-present tasks skip every tick.
pub(crate) async fn wait_for_ecus_online(config: &Configuration) -> Result<(), TestingError> {
    const POLL_INTERVAL: Duration = Duration::from_secs(1);
    const TIMEOUT: Duration = Duration::from_secs(30);
    let deadline = Instant::now().checked_add(TIMEOUT).ok_or_else(|| {
        TestingError::SetupError("timeout duration overflowed Instant".to_owned())
    })?;
    let mut last_offline_ecus: Option<String> = None;

    loop {
        if Instant::now() >= deadline {
            return Err(TestingError::ProcessFailed(format!(
                "ECUs did not reach Online state within 30s after reset: {}",
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

/// Returns the flash files path and ensures a test flash file exists for integration tests.
/// In Docker mode the path points to the container mount (`/app/flash`),
/// otherwise to `testcontainer/flash_files/` on the host.
fn flash_files_path() -> Result<String, TestingError> {
    let flash_dir = test_container_dir()?.join("flash_files");

    let flash_file = flash_dir.join("test_flash.bin");
    if !flash_file.exists() {
        // Create a small test binary file (256 bytes of patterned data)
        let data: Vec<u8> = (0u8..=255).collect();
        std::fs::write(&flash_file, &data).map_err(|e| {
            TestingError::SetupError(format!(
                "Failed to write flash test file '{}': {e}",
                flash_file.display()
            ))
        })?;
    }

    if use_docker() {
        Ok("/app/flash".to_owned())
    } else {
        Ok(flash_dir.to_string_lossy().to_string())
    }
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

pub(crate) fn test_container_dir() -> Result<std::path::PathBuf, TestingError> {
    std::env::var("CARGO_MANIFEST_DIR")
        .map(|dir| {
            let mut path = std::path::PathBuf::from(dir);
            path.pop();
            path.push("testcontainer");
            path
        })
        .ok()
        .filter(|path| path.exists())
        .ok_or_else(|| TestingError::PathNotFound("testcontainer directory not found".to_owned()))
}

fn register_cleanup() {
    extern "C" fn cleanup_handler() {
        let use_docker =
            std::env::var(CDA_INTEGRATION_TEST_USE_DOCKER).map_or(true, |s| s == "true");

        if use_docker {
            // Extract coverage data before shutting down containers
            if coverage_mode()
                && let Err(e) = extract_coverage_from_container()
            {
                eprintln!("Failed to extract coverage data: {e}");
            }

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

/// Extracts .profraw files from the CDA container's coverage volume.
/// The files are copied to the target/coverage directory on the host for merging.
/// Also extracts the instrumented binary so coverage can be properly decoded.
///
/// The CDA container must be gracefully stopped first so that the LLVM coverage
/// runtime writes the .profraw files (they are written on process exit via atexit).
fn extract_coverage_from_container() -> Result<(), TestingError> {
    let test_container_dir = test_container_dir()?;
    let project_dir = test_container_dir.parent().ok_or_else(|| {
        TestingError::PathNotFound("Could not determine project root directory".to_owned())
    })?;
    let coverage_output_dir = project_dir.join("target").join("coverage");

    std::fs::create_dir_all(&coverage_output_dir).map_err(|e| {
        TestingError::ProcessFailed(format!("Failed to create coverage output directory: {e}"))
    })?;

    // Stop the CDA container gracefully so the LLVM coverage runtime writes .profraw files.
    // SIGTERM is sent first (which the CDA binary handles for graceful shutdown), then
    // Docker waits for stop_grace_period before sending SIGKILL.
    let mut cmd = std::process::Command::new("docker");
    cmd.arg("compose");
    append_coverage_compose_files(&mut cmd);
    let stop_status = cmd
        .arg("stop")
        .arg("-t")
        .arg("10")
        .arg("cda")
        .current_dir(&test_container_dir)
        .status()
        .map_err(|e| {
            TestingError::ProcessFailed(format!("Failed to stop CDA container for coverage: {e}"))
        })?;

    if !stop_status.success() {
        return Err(TestingError::ProcessFailed(
            "Failed to stop CDA container for coverage".to_owned(),
        ));
    }

    // Copy coverage data from the (now stopped) container
    let mut cmd = std::process::Command::new("docker");
    cmd.arg("compose");
    append_coverage_compose_files(&mut cmd);
    let status = cmd
        .arg("cp")
        .arg("cda:/app/coverage/.")
        .arg(coverage_output_dir.to_str().unwrap_or_default())
        .current_dir(&test_container_dir)
        .status()
        .map_err(|e| TestingError::ProcessFailed(format!("Failed to copy coverage data: {e}")))?;

    if !status.success() {
        return Err(TestingError::ProcessFailed(
            "Failed to copy coverage data from container".to_owned(),
        ));
    }

    // Also extract the instrumented binary from the container
    // This is needed to decode the coverage data (the binary contains the coverage mapping)
    let binary_output_path = coverage_output_dir.join("opensovd-cda");
    let mut cmd = std::process::Command::new("docker");
    cmd.arg("compose");
    append_coverage_compose_files(&mut cmd);
    let status = cmd
        .arg("cp")
        .arg("cda:/app/opensovd-cda")
        .arg(binary_output_path.to_str().unwrap_or_default())
        .current_dir(&test_container_dir)
        .status()
        .map_err(|e| {
            TestingError::ProcessFailed(format!("Failed to copy instrumented binary: {e}"))
        })?;

    if !status.success() {
        return Err(TestingError::ProcessFailed(
            "Failed to copy instrumented binary from container".to_owned(),
        ));
    }

    Ok(())
}

/// Registers a custom panic hook that dumps docker logs before the default panic handler runs.
/// This ensures container logs are captured on any test failure (assert, unwrap, etc.)
fn register_panic_hook() {
    use std::sync::Once;
    static HOOK_REGISTERED: Once = Once::new();

    HOOK_REGISTERED.call_once(|| {
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |panic_info| {
            // Dump docker logs before the default panic output
            dump_docker_logs();
            // Call the default panic handler to print the panic message and backtrace
            default_hook(panic_info);
        }));
    });
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
