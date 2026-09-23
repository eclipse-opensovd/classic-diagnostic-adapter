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

//! CDA configurations of the integration tests (`test_env`).
//!
//! A test holds the host-facing [`Configuration`]: its server address and port
//! are where the test reaches the CDA. [`container_config`] turns it into the
//! configuration the CDA runs with inside its container.

use cda_health::config::HealthConfig;
use cda_interfaces::{
    FunctionalDescriptionConfig, HashMap, HashMapExtensions,
    communication_control::CommunicationSettings,
    datatypes::{
        ComParamConfig, ComParamPrecedence, ComParams, ComponentsConfig, DatabaseNamingConvention,
        DoipComParams, FaultConfig, FlatbBufConfig,
    },
};
use cda_tracing::LoggingConfig;
use opensovd_cda_lib::config::configfile::{
    CanAddressingMode, CanConfig, CanEcuMapping, Configuration, DatabaseConfig, EcuComParams,
    EcuConfig, RuntimeUpdateConfig, StrictConfig, TransportOverride, TransportType,
};

use crate::util::{
    TestingError,
    test_containers::{CDA_DATABASES_DIR, CDA_HTTP_PORT},
};

/// Port of the socketcand daemon that fronts the shared (v)can bus. CDA and the
/// ecu-sim both connect to it as rawmode clients.
pub(crate) const SOCKETCAND_PORT: u16 = 29536;
/// Name of the CAN bus exposed by socketcand.
pub(crate) const CAN_BUS_NAME: &str = "vcan0";
/// Port the CDA's `DoIP` gateway listens on inside its container.
pub(crate) const DOIP_GATEWAY_PORT: u16 = 13400;
/// Where the CDA container reads its configuration from (`CDA_CONFIG_FILE`).
pub(crate) const CDA_CONFIG_FILE: &str = "/app/cda-test-config.toml";
/// Where the flash files are mounted inside the CDA container, read-only.
pub(crate) const CDA_FLASH_DIR: &str = "/app/flash";
/// Where a `TestEnv` CDA keeps its storage (`runtime_update_config.storage_dir`),
/// e.g. the MDDs of runtime updates: a tmpfs, removed with the container.
pub(crate) const CDA_STORAGE_DIR: &str = "/app/storage";

pub(crate) fn cda_test_config(host: String, cda_port: u16) -> Result<Configuration, TestingError> {
    let mut config = base_test_config(host, cda_port, per_ecu_configs_for_doip())?;
    enable_doip(&mut config);
    Ok(config)
}

/// CAN-only configuration: no `DoIP` transport, so no gateway port either.
pub(crate) fn cda_test_config_can(
    host: String,
    cda_port: u16,
) -> Result<Configuration, TestingError> {
    let mut config = base_test_config(host, cda_port, per_ecu_configs_for_can())?;
    config.can = Some(test_can_config(vec![]));
    Ok(config)
}

/// Mixed `DoIP`+CAN configuration: both transports are live. The three ECUs
/// that already have CAN-style per-ECU configs are pinned to CAN; FLXC1000 is
/// pinned to `DoIP` so the session/security/variant tests (which target it)
/// run deterministically over `DoIP`; the remaining ECUs are left unpinned to
/// exercise sticky first-detection binding.
pub(crate) fn cda_test_config_mixed(
    host: String,
    cda_port: u16,
) -> Result<Configuration, TestingError> {
    let mut ecu = per_ecu_configs_for_doip();
    // Pinned-to-CAN ECUs use the CAN-style protocol handling.
    for (name, cfg) in per_ecu_configs_for_can() {
        ecu.insert(name, cfg);
    }
    let mut config = base_test_config(host, cda_port, ecu)?;
    enable_doip(&mut config);
    let pins = [
        ("TMCC3000", TransportType::Can),
        ("HOVR4000", TransportType::Can),
        ("JGWT5000", TransportType::Can),
        ("FLXC1000", TransportType::DoIP),
    ]
    .into_iter()
    .map(|(ecu_name, transport)| TransportOverride {
        ecu_name: ecu_name.to_owned(),
        transport,
    })
    .collect();
    config.can = Some(test_can_config(pins));
    Ok(config)
}

/// The configuration the CDA runs with inside its container, for the
/// host-facing test `config`.
///
/// Network ports and paths are set to container-internal values (server
/// `0.0.0.0:20002`, gateway port 13400, databases `/app/odx`), and the CAN
/// interface points at socketcand on `socketcand_host`, as the CDA container
/// reaches it. Everything else, e.g. `faults`, is kept. The entrypoint of the
/// CDA image sets the tester address from the container IP.
pub(crate) fn container_config(mut config: Configuration, socketcand_host: &str) -> Configuration {
    config.server.port = CDA_HTTP_PORT;
    config.doip.gateway_port = DOIP_GATEWAY_PORT;
    config.functional_description.description_database = "functional_groups".into();

    "0.0.0.0".clone_into(&mut config.server.address);
    CDA_DATABASES_DIR.clone_into(&mut config.database.dir);

    if let Some(can) = config.can.as_mut() {
        can.interface = format!("socketcand:{socketcand_host}:{SOCKETCAND_PORT}:{CAN_BUS_NAME}");
    }

    config
}

/// [`container_config`] serialized as the TOML file the CDA container reads.
///
/// # Errors
/// Returns [`TestingError::SetupError`] if the configuration cannot be
/// serialized.
pub(crate) fn container_config_toml(
    config: Configuration,
    socketcand_host: &str,
) -> Result<String, TestingError> {
    toml::to_string_pretty(&container_config(config, socketcand_host))
        .map_err(|e| TestingError::SetupError(format!("Failed to serialize config to TOML: {e}")))
}

/// Turns on the `DoIP` transport of a [`base_test_config`].
fn enable_doip(config: &mut Configuration) {
    config.doip.enabled = true;
    config.doip.gateway_port = DOIP_GATEWAY_PORT;
}

fn test_can_config(transport_overrides: Vec<TransportOverride>) -> CanConfig {
    CanConfig {
        interface: format!("socketcand:127.0.0.1:{SOCKETCAND_PORT}:{CAN_BUS_NAME}"),
        ecu_mappings: can_ecu_mappings(),
        transport_overrides,
        response_timeout_ms: 2000,
        probe_timeout_ms: 500,
        // The suites ran with the keep-alive since its introduction; keep
        // it on (the default is off for resident operation).
        keepalive_interval_ms: 2000,
        ..CanConfig::default()
    }
}

/// Transport-less base of every test configuration (server, database,
/// com-params, ...). The `DoIP` section is present but disabled; callers add
/// their transports via [`enable_doip`] and/or by setting `config.can`.
fn base_test_config(
    host: String,
    cda_port: u16,
    ecu: HashMap<String, EcuConfig>,
) -> Result<Configuration, TestingError> {
    Ok(Configuration {
        server: opensovd_cda_lib::config::configfile::ServerConfig {
            address: host.clone(),
            port: cda_port,
        },
        doip: opensovd_cda_lib::config::configfile::DoipConfig {
            tester_address: host,
            enabled: false,
            gateway_port: 0,
            ..Default::default()
        },
        can: None,
        database: DatabaseConfig {
            dir: mdd_file_path()?,
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
            // Faster reconnect ladder against the local simulator: with the
            // production default of 5s, recovering from a simulated gateway
            // restart (several failed reconnect rounds while the entities are
            // down) can take longer than the 30s `wait_for_ecus_online`
            // budget. Precedence Config so the MDD cannot override it.
            p.doip.connection_retry_delay.value = std::time::Duration::from_secs(1);
            p.doip.connection_retry_delay.precedence = ComParamPrecedence::Config;
            p
        },
        flat_buf: FlatbBufConfig::default(),
        functional_description: FunctionalDescriptionConfig {
            description_database: "functional_groups".to_owned(),
            enabled_functional_groups: None,
            protocol_position: cda_interfaces::datatypes::DiagnosticServiceAffixPosition::Suffix,
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
        ecu,
        runtime_update_config: RuntimeUpdateConfig::default(),
        communication: CommunicationSettings::default(),
        strict: StrictConfig::default(),
    })
}

fn per_ecu_configs_for_doip() -> HashMap<String, EcuConfig> {
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
}

fn per_ecu_configs_for_can() -> HashMap<String, EcuConfig> {
    // For CAN we let the MDD's protocol layer win where it exists, and
    // fall back to `ignore_protocol = true` for the protocol-less MDDs
    // (TMCC3000, JGWT5000).
    let mut map = HashMap::new();
    for name in ["TMCC3000", "HOVR4000", "JGWT5000"] {
        map.insert(
            name.to_owned(),
            EcuConfig {
                ignore_protocol: Some(true),
                ..Default::default()
            },
        );
    }
    map
}

fn can_ecu_mappings() -> Vec<CanEcuMapping> {
    // The Kotlin sim assigns each example ECU a distinct (rxId, txId)
    // pair. CDA must mirror the same mapping on its side so that the
    // per-ECU ISO-TP sockets connect to the right arbitration IDs.
    let pairs: &[(&str, u32, u32)] = &[
        ("FLXC1000", 0x700, 0x708),
        ("TMC1001", 0x710, 0x718),
        ("FSNR2000", 0x720, 0x728),
        ("TMCC3000", 0x730, 0x738),
        ("HOVR4000", 0x740, 0x748),
        ("JGWT5000", 0x750, 0x758),
    ];
    pairs
        .iter()
        .map(|(name, req, resp)| CanEcuMapping {
            ecu_name: (*name).to_owned(),
            request_id: *req,
            response_id: *resp,
            addressing_mode: CanAddressingMode::Standard,
        })
        .collect()
}

pub(crate) fn mdd_file_path() -> Result<String, TestingError> {
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

/// Returns the flash files path inside the CDA container, and ensures a test
/// flash file exists in [`flash_files_host_dir`] for integration tests.
///
/// Test environments are created in parallel, and the directory is mounted
/// into every CDA container, so the file is written to a temporary file and
/// renamed into place: a CDA never sees it partially written.
fn flash_files_path() -> Result<String, TestingError> {
    use std::io::Write as _;

    let flash_dir = flash_files_host_dir()?;
    let flash_file = flash_dir.join("test_flash.bin");
    if !flash_file.exists() {
        let write_error = |e: &dyn std::fmt::Display| {
            TestingError::SetupError(format!(
                "Failed to write flash test file '{}': {e}",
                flash_file.display()
            ))
        };
        // A small test binary file (256 bytes of patterned data).
        let data: Vec<u8> = (0u8..=255).collect();
        let mut temp_file =
            tempfile::NamedTempFile::new_in(&flash_dir).map_err(|e| write_error(&e))?;
        temp_file.write_all(&data).map_err(|e| write_error(&e))?;
        temp_file
            .persist(&flash_file)
            .map_err(|e| write_error(&e))?;
    }

    Ok(CDA_FLASH_DIR.to_owned())
}

/// The host directory mounted at [`CDA_FLASH_DIR`] in the CDA container.
pub(crate) fn flash_files_host_dir() -> Result<std::path::PathBuf, TestingError> {
    Ok(test_container_dir()?.join("flash_files"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_config_uses_container_internal_values() {
        let mut config = Configuration::default();
        "localhost".clone_into(&mut config.server.address);
        config.server.port = 45678;
        config.doip.gateway_port = 1;
        "/host/odx".clone_into(&mut config.database.dir);
        config.faults.user_memory_scope = "Development".to_owned();
        config.can = Some(test_can_config(vec![]));

        let config = container_config(config, "env-socketcand");

        assert_eq!(config.server.address, "0.0.0.0");
        assert_eq!(config.server.port, CDA_HTTP_PORT);
        assert_eq!(config.doip.gateway_port, DOIP_GATEWAY_PORT);
        assert_eq!(config.database.dir, CDA_DATABASES_DIR);
        assert_eq!(
            config.can.map(|can| can.interface),
            Some(format!(
                "socketcand:env-socketcand:{SOCKETCAND_PORT}:{CAN_BUS_NAME}"
            ))
        );
        // Everything else is kept.
        assert_eq!(config.faults.user_memory_scope, "Development");
    }
}
