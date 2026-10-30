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

//! ECU list persistence: storing and reusing the vehicle topology.

use std::time::Duration;

use cda_interfaces::communication_control::{CommunicationInitMode, CommunicationSettings};
use http::{Method, StatusCode};
use opensovd_cda_lib::config::configfile::{Configuration, TransportOverride, TransportType};

use crate::{
    sovd::{COMPONENTS_FLXC1000_BASE, COMPONENTS_FSNR2000_BASE, force_variant_detection},
    util::{
        config::CDA_STORAGE_DIR,
        ecusim,
        http::{poll_until, send_authenticated_cda_request},
        locks::{COMPONENTS_FLXC1000_LOCKS, Lock, default_timeout},
        test_env::{Lease, TestEnv, Transport, skip_unless, wait_for_ecus_online},
    },
};

const FLXC1000_APP_VARIANT: &str = "FLXC1000_App_0101";

/// The collection of the persisted topology in the storage of the CDA.
fn topology_dir() -> String {
    format!("{CDA_STORAGE_DIR}/collections/ecu_topology")
}

/// Communication settings with ECU list persistence and `init_mode`.
fn persistence_settings(init_mode: CommunicationInitMode) -> CommunicationSettings {
    let mut settings = CommunicationSettings {
        init_mode,
        ..CommunicationSettings::default()
    };
    settings.ecu_list_persistence.enabled = true;
    settings
}

/// A test environment whose CDA starts with ECU list persistence and
/// `init_mode`, with empty storage, and has its ECUs online.
async fn persistence_env(init_mode: CommunicationInitMode) -> Lease {
    let env = TestEnv::builder()
        .with_cda_communication_settings(persistence_settings(init_mode))
        .await
        .expect("Failed to set up the test environment");
    wait_for_ecus_online(&env.config)
        .await
        .expect("ECUs did not come online");
    env
}

/// All persisted entries, concatenated. Empty if nothing is persisted.
async fn persisted_topology(env: &TestEnv) -> String {
    env.exec_in_cda(&format!("cat {}/* 2>/dev/null || true", topology_dir()))
        .await
        .expect("Failed to read the persisted topology")
}

/// The persisted gateway entry containing the ECU `name`, and that ECU's entry.
async fn persisted_ecu(
    env: &TestEnv,
    name: &str,
) -> Option<(serde_json::Value, serde_json::Value)> {
    let topology = persisted_topology(env).await;
    serde_json::Deserializer::from_str(&topology)
        .into_iter::<serde_json::Value>()
        .map(|entry| entry.expect("Invalid persisted gateway"))
        .find_map(|gateway| {
            let ecu = gateway.get("ecus")?.as_array()?.iter().find(|ecu| {
                ecu.get("name")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|ecu_name| ecu_name.eq_ignore_ascii_case(name))
            })?;
            let ecu = ecu.clone();
            Some((gateway, ecu))
        })
}

async fn persisted_last_seen(env: &TestEnv, name: &str) -> i64 {
    let (_, ecu) = persisted_ecu(env, name)
        .await
        .expect("Persisted ECU missing");
    let last_seen = ecu
        .get("last_seen")
        .and_then(serde_json::Value::as_str)
        .expect("Persisted ECU timestamp missing");
    chrono::DateTime::parse_from_rfc3339(last_seen)
        .expect("Invalid persisted timestamp")
        .timestamp_millis()
}

async fn persisted_state_is(env: &TestEnv, name: &str, state: &str) -> bool {
    persisted_ecu(env, name)
        .await
        .and_then(|(_, ecu)| ecu.get("state")?.as_str().map(|s| s == state))
        .unwrap_or(false)
}

/// Recorded UDS requests without `TesterPresent` (0x3E) keep-alives, which the
/// mixed `DoIP` and CAN setup sends independently of the topology.
fn diagnostic_requests(recorded: &[String]) -> Vec<&String> {
    recorded
        .iter()
        .filter(|frame| !frame.to_lowercase().starts_with("3e"))
        .collect()
}

/// Polls `check` every 500 ms until it holds.
///
/// # Panics
/// If it does not hold within `timeout`.
async fn wait_for<F, Fut>(description: &str, timeout: Duration, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    poll_until(timeout, Duration::from_millis(500), || {
        let done = check();
        async move {
            Ok(if done.await {
                Ok(())
            } else {
                Err(format!("waiting for {description}"))
            })
        }
    })
    .await
    .unwrap_or_else(|e| panic!("Timed out waiting for {description}: {e:?}"));
}

/// Waits until the topology is persisted with the FLXC1000 variant.
async fn wait_for_persisted_topology(env: &TestEnv) {
    wait_for(
        "the persisted topology",
        Duration::from_secs(30),
        || async { persisted_topology(env).await.contains(FLXC1000_APP_VARIANT) },
    )
    .await;
}

/// Whether the SOVD state of the ECU at `endpoint` is `state`.
async fn ecu_state_is(
    env: &TestEnv,
    endpoint: &str,
    state: sovd_interfaces::components::ecu::State,
) -> bool {
    crate::sovd::ecu_status(env, endpoint)
        .await
        .is_ok_and(|ecu| ecu.variant.state == state)
}

async fn ecu_status(
    env: &TestEnv,
    endpoint: &str,
) -> sovd_interfaces::components::ecu::get::Response {
    crate::sovd::ecu_status(env, endpoint)
        .await
        .expect("Failed to read ECU status")
}

/// The address the persisted topology holds for the gateway of the ECU `name`.
async fn persisted_gateway_address(env: &TestEnv, name: &str) -> String {
    persisted_ecu(env, name)
        .await
        .and_then(|(gateway, _)| gateway.get("network_address")?.as_str().map(str::to_owned))
        .expect("The persisted gateway has no network address")
}

/// [[ itest~ecu-list-persistence-disabled, Without ECU list persistence nothing is persisted, itest ]]
#[tokio::test]
async fn persistence_disabled_writes_nothing() {
    if skip_unless(Transport::uses_doip, "DoIP topology only") {
        return;
    }
    let env = TestEnv::builder()
        .await
        .expect("Failed to set up the test environment");
    assert!(!env.config.communication.ecu_list_persistence.enabled);
    wait_for_ecus_online(&env.config)
        .await
        .expect("ECUs did not come online");
    let exists = env
        .exec_in_cda(&format!("[ -e {} ] && echo yes || echo no", topology_dir()))
        .await
        .expect("Failed to check the topology collection");
    assert_eq!(exists.trim(), "no", "no topology may be written by default");
}

/// The topology is persisted, and a restart reuses it: no variant detection,
/// the stored variant and `last_seen` restored. That no VIR discovery
/// runs is covered by a unit test of the discovery plan.
/// [[ itest~ecu-list-persistence-reuse, A restart reuses the persisted topology without redetection, itest ]]
#[tokio::test]
async fn restart_reuses_persisted_topology_without_redetection() {
    if skip_unless(Transport::uses_doip, "DoIP topology only") {
        return;
    }
    // Empty storage: no persisted topology, so a full detection runs.
    let mut env = persistence_env(CommunicationInitMode::WhenNotPersisted).await;
    wait_for_persisted_topology(&env).await;
    let persisted = persisted_topology(&env).await;
    assert!(persisted.contains("\"network_address\""), "{persisted}");
    assert!(persisted.contains("\"state\":\"Online\""), "{persisted}");
    assert!(
        persisted.contains("\"state\":\"Duplicate\""),
        "the fixture must include a resolved duplicate group: {persisted}"
    );

    // The ECU changes its variant while the CDA is down. A reused topology
    // must not notice, since no variant detection runs.
    ecusim::switch_variant(&env.ecu_sim, "FLXC1000", "BOOT")
        .await
        .expect("Failed to switch variant");
    let recorder = env
        .record("flxc1000")
        .await
        .expect("Failed to start recording");
    env.restart_cda().await.expect("Failed to restart CDA");

    // Not contacted yet, so the restored ECU is assumed online: an ECU lock
    // must be granted.
    Lock::acquire(&env, COMPONENTS_FLXC1000_LOCKS, default_timeout())
        .await
        .release(&env)
        .await;
    let ecu = ecu_status(&env, COMPONENTS_FLXC1000_BASE).await;
    assert_eq!(ecu.variant.name, FLXC1000_APP_VARIANT, "restored variant");
    assert_eq!(
        ecu.variant.state,
        sovd_interfaces::components::ecu::State::Online
    );
    assert!(ecu.last_seen.is_some(), "last_seen restored");

    // A read only succeeds over the reconnected gateway, so a detection
    // requested by the reconnect is already queued when it returns.
    send_authenticated_cda_request(
        &env,
        &format!("{COMPONENTS_FLXC1000_BASE}/data/vindataidentifier"),
        StatusCode::OK,
        Method::GET,
        None,
        None,
    )
    .await
    .expect("Failed to read from the restored ECU");
    let recorded = recorder.stop().await.expect("Failed to stop recording");
    // Only the read itself may have been sent, any other request would be a
    // variant detection.
    let requests = diagnostic_requests(&recorded);
    assert_eq!(
        requests.len(),
        1,
        "no variant detection may run for a restored ECU: {requests:?}"
    );

    // An explicit re-detection still finds the real variant.
    force_variant_detection(&env, COMPONENTS_FLXC1000_BASE)
        .await
        .expect("Failed to trigger variant detection");
    let ecu = ecu_status(&env, COMPONENTS_FLXC1000_BASE).await;
    assert_eq!(ecu.variant.name, "FLXC1000_Boot_Variant");
}

/// The `last_seen` of a contacted ECU is written back at a graceful shutdown.
/// [[ itest~ecu-list-persistence-shutdown, `last_seen` is persisted at shutdown, itest ]]
#[tokio::test]
async fn last_seen_is_written_back_at_shutdown() {
    if skip_unless(Transport::uses_doip, "DoIP topology only") {
        return;
    }
    let mut env = persistence_env(CommunicationInitMode::WhenNotPersisted).await;
    wait_for_persisted_topology(&env).await;
    let before = persisted_last_seen(&env, "FLXC1000").await;

    // `last_seen` has second precision.
    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(1)).await;
    send_authenticated_cda_request(
        &env,
        // A real UDS read; the data listing alone does not contact the ECU.
        &format!("{COMPONENTS_FLXC1000_BASE}/data/vindataidentifier"),
        StatusCode::OK,
        Method::GET,
        None,
        None,
    )
    .await
    .expect("Failed to contact the ECU");
    let contact = ecu_status(&env, COMPONENTS_FLXC1000_BASE)
        .await
        .last_seen
        .expect("Contact timestamp missing");
    let contact = chrono::DateTime::parse_from_rfc3339(&contact)
        .expect("Invalid contact timestamp")
        .timestamp_millis();
    assert!(contact > before);

    env.restart_cda().await.expect("Failed to restart CDA");
    let after = persisted_last_seen(&env, "FLXC1000").await;
    assert!(
        after >= contact,
        "shutdown must save the contact made before restart"
    );
}

/// [[ itest~ecu-list-persistence-unreachable, No gateway connected keeps the persisted states, itest ]]
#[tokio::test]
async fn all_gateways_unreachable_keeps_persisted_states() {
    if skip_unless(Transport::uses_doip, "DoIP topology only") {
        return;
    }
    let mut env = persistence_env(CommunicationInitMode::WhenNotPersisted).await;
    wait_for_persisted_topology(&env).await;

    env.stop_ecu_sim()
        .await
        .expect("Failed to stop the ECU sim");
    env.restart_cda().await.expect("Failed to restart CDA");
    wait_for(
        "the ECU to be reported disconnected",
        Duration::from_secs(120),
        || {
            ecu_state_is(
                &env,
                COMPONENTS_FLXC1000_BASE,
                sovd_interfaces::components::ecu::State::Disconnected,
            )
        },
    )
    .await;

    // No gateway is connected, so no write may demote the persisted states.
    let persisted = persisted_topology(&env).await;
    assert!(persisted.contains("\"state\":\"Online\""), "{persisted}");
    assert!(
        !persisted.contains("\"state\":\"Disconnected\""),
        "no gateway is connected, so nothing may be demoted: {persisted}"
    );
    assert!(persisted.contains(FLXC1000_APP_VARIANT), "{persisted}");
}

/// Waits until the topology persisted for `ecu` says `Disconnected`, and checks
/// that the stored address and variant of its gateway are kept.
async fn assert_persisted_disconnected(env: &TestEnv, ecu: &str, variant: &str) {
    wait_for(
        "the unreachable gateway to be persisted",
        Duration::from_secs(180),
        || persisted_state_is(env, ecu, "Disconnected"),
    )
    .await;
    let (gateway, entry) = persisted_ecu(env, ecu)
        .await
        .expect("Persisted ECU missing");
    assert!(
        gateway
            .get("network_address")
            .is_some_and(serde_json::Value::is_string),
        "the stored address must be kept: {gateway}"
    );
    assert!(
        entry.to_string().contains(variant),
        "the stored variant must be kept: {entry}"
    );
}

/// The configuration of `env` with ECU list persistence and
/// `init_mode = WhenNotPersisted`, and, in the mixed `DoIP`+CAN setup,
/// FSNR2000 pinned to `DoIP`, so a restart cannot bring the stopped gateway's
/// ECU Online over CAN.
fn persistence_config_with_fsnr2000_on_doip(env: &TestEnv) -> Configuration {
    let mut config = env.default_config().clone();
    config.communication = persistence_settings(CommunicationInitMode::WhenNotPersisted);
    if let Some(can) = config.can.as_mut() {
        can.transport_overrides.push(TransportOverride {
            ecu_name: "FSNR2000".to_owned(),
            transport: TransportType::DoIP,
        });
    }
    config
}

/// One gateway stopped while another stays up: the failed gateway is persisted
/// as `Disconnected` (address and variant kept) and not restored as `Online`.
/// [[ itest~ecu-list-persistence-unreachable-gateway, A stopped gateway is persisted as Disconnected while another gateway is up, itest ]]
#[tokio::test]
async fn unreachable_gateway_is_persisted_as_disconnected() {
    if skip_unless(Transport::uses_doip, "DoIP topology only") {
        return;
    }
    let mut env = TestEnv::builder()
        .await
        .expect("Failed to set up the test environment");
    let config = persistence_config_with_fsnr2000_on_doip(&env);
    env.replace_cda(&config).await.expect("Failed to start CDA");
    wait_for_ecus_online(&env.config)
        .await
        .expect("ECUs did not come online");
    wait_for(
        "the persisted topology",
        Duration::from_secs(30),
        || async {
            persisted_state_is(&env, "FSNR2000", "Online").await
                && persisted_state_is(&env, "FLXC1000", "Online").await
        },
    )
    .await;

    // The stop closes all `DoIP` connections of the simulator; the other
    // gateways stay reachable and are reconnected by the CDA.
    let address = persisted_gateway_address(&env, "FSNR2000").await;
    ecusim::stop_gateway(&env.ecu_sim, &address)
        .await
        .expect("Failed to stop the gateway");

    env.restart_cda().await.expect("Failed to restart CDA");
    assert_persisted_disconnected(&env, "FSNR2000", "FSNR2000_App").await;
    assert!(
        persisted_state_is(&env, "FLXC1000", "Online").await,
        "the reachable gateway stays Online: {}",
        persisted_topology(&env).await
    );

    let ecu = ecu_status(&env, COMPONENTS_FSNR2000_BASE).await;
    assert_eq!(
        ecu.variant.state,
        sovd_interfaces::components::ecu::State::Disconnected
    );
    assert_eq!(
        ecu_status(&env, COMPONENTS_FLXC1000_BASE)
            .await
            .variant
            .state,
        sovd_interfaces::components::ecu::State::Online
    );

    // The next start must not restore the stopped gateway's ECU as Online.
    let recorder = env
        .record("flxc1000")
        .await
        .expect("Failed to start recording");
    env.restart_cda().await.expect("Failed to restart CDA");
    let ecu = ecu_status(&env, COMPONENTS_FSNR2000_BASE).await;
    assert_eq!(
        ecu.variant.state,
        sovd_interfaces::components::ecu::State::Offline,
        "a gateway persisted as Disconnected is not restored and starts Offline"
    );
    let recorded = recorder.stop().await.expect("Failed to stop recording");
    let requests = diagnostic_requests(&recorded);
    assert!(
        requests.is_empty(),
        "no further detection may run after the restart: {requests:?}"
    );

    ecusim::start_gateway(&env.ecu_sim, &address)
        .await
        .expect("Failed to start the gateway again");
}
