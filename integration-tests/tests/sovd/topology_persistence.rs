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

use cda_interfaces::{
    communication_control::{CommunicationInitMode, CommunicationSettings},
    topology::{PersistedEcu, PersistedEcuState, PersistedGateway},
};
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
    settings.topology.ecu_list_persistence.enabled = true;
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
    env.exec_in_cda_container(&format!("cat {}/* 2>/dev/null || true", topology_dir()))
        .await
        .expect("Failed to read the persisted topology")
}

/// All persisted gateway entries, parsed.
async fn persisted_gateways(env: &TestEnv) -> Vec<PersistedGateway> {
    let topology = persisted_topology(env).await;
    serde_json::Deserializer::from_str(&topology)
        .into_iter::<PersistedGateway>()
        .map(|entry| entry.expect("Invalid persisted gateway"))
        .collect()
}

/// Whether any persisted ECU has the variant `name`.
fn has_variant(gateways: &[PersistedGateway], name: &str) -> bool {
    gateways
        .iter()
        .flat_map(|gateway| &gateway.ecus)
        .any(|ecu| {
            ecu.variant
                .as_ref()
                .is_some_and(|variant| variant.name == name)
        })
}

/// Whether any persisted ECU is in `state`.
fn has_state(gateways: &[PersistedGateway], state: PersistedEcuState) -> bool {
    gateways
        .iter()
        .flat_map(|gateway| &gateway.ecus)
        .any(|ecu| ecu.state == state)
}

/// The persisted gateway entry containing the ECU `name`, and that ECU's entry.
async fn persisted_ecu(env: &TestEnv, name: &str) -> Option<(PersistedGateway, PersistedEcu)> {
    persisted_gateways(env)
        .await
        .into_iter()
        .find_map(|gateway| {
            let ecu = gateway
                .ecus
                .iter()
                .find(|ecu| ecu.name.eq_ignore_ascii_case(name))?
                .clone();
            Some((gateway, ecu))
        })
}

async fn persisted_last_seen(env: &TestEnv, name: &str) -> i64 {
    let (_, ecu) = persisted_ecu(env, name)
        .await
        .expect("Persisted ECU missing");
    let last_seen = ecu.last_seen.expect("Persisted ECU timestamp missing");
    chrono::DateTime::<chrono::Utc>::from(last_seen).timestamp_millis()
}

async fn is_persisted_state(env: &TestEnv, name: &str, state: PersistedEcuState) -> bool {
    persisted_ecu(env, name)
        .await
        .is_some_and(|(_, ecu)| ecu.state == state)
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
        || async { has_variant(&persisted_gateways(env).await, FLXC1000_APP_VARIANT) },
    )
    .await;
}

/// Whether the SOVD state of the ECU at `endpoint` is `state`.
async fn is_ecu_in_state(
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
        .and_then(|(gateway, _)| gateway.network_address)
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
    assert!(
        !env.config
            .communication
            .topology
            .ecu_list_persistence
            .enabled
    );
    wait_for_ecus_online(&env.config)
        .await
        .expect("ECUs did not come online");
    let exists = env
        .exec_in_cda_container(&format!("[ -e {} ] && echo yes || echo no", topology_dir()))
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
    let gateways = persisted_gateways(&env).await;
    assert!(
        gateways.iter().any(|g| g.network_address.is_some()),
        "{gateways:?}"
    );
    assert!(
        has_state(&gateways, PersistedEcuState::Online),
        "{gateways:?}"
    );
    assert!(
        has_state(&gateways, PersistedEcuState::Duplicate),
        "the fixture must include a resolved duplicate group: {gateways:?}"
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
        "the ECU to be reported offline",
        Duration::from_secs(120),
        || {
            is_ecu_in_state(
                &env,
                COMPONENTS_FLXC1000_BASE,
                sovd_interfaces::components::ecu::State::Offline,
            )
        },
    )
    .await;

    // No gateway is connected, so no write may demote the persisted states.
    let gateways = persisted_gateways(&env).await;
    assert!(
        has_state(&gateways, PersistedEcuState::Online),
        "{gateways:?}"
    );
    assert!(
        !has_state(&gateways, PersistedEcuState::Offline)
            && !has_state(&gateways, PersistedEcuState::Disconnected),
        "no gateway is connected, so nothing may be demoted: {gateways:?}"
    );
    assert!(has_variant(&gateways, FLXC1000_APP_VARIANT), "{gateways:?}");
}

/// Waits until the topology persisted for `ecu` says `Offline`, and checks
/// that the stored address and the last known variant of its gateway are kept.
async fn assert_persisted_offline(env: &TestEnv, ecu: &str, variant: &str) {
    wait_for(
        "the unreachable gateway to be persisted",
        Duration::from_secs(180),
        || is_persisted_state(env, ecu, PersistedEcuState::Offline),
    )
    .await;
    let (gateway, entry) = persisted_ecu(env, ecu)
        .await
        .expect("Persisted ECU missing");
    assert!(
        gateway.network_address.is_some(),
        "the stored address must be kept: {gateway:?}"
    );
    assert!(
        entry
            .variant
            .as_ref()
            .is_some_and(|stored| stored.name == variant),
        "the stored variant must be kept: {entry:?}"
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
/// as `Offline` (address and last known variant kept) and not restored as `Online`.
/// [[ itest~ecu-list-persistence-unreachable-gateway, A stopped gateway is persisted as Offline while another gateway is up, itest ]]
#[tokio::test]
async fn unreachable_gateway_is_persisted_as_offline() {
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
            is_persisted_state(&env, "FSNR2000", PersistedEcuState::Online).await
                && is_persisted_state(&env, "FLXC1000", PersistedEcuState::Online).await
        },
    )
    .await;

    // The stop closes all `DoIP` connections of the simulator; the other
    // gateways stay reachable and are reconnected by the CDA.
    let address = persisted_gateway_address(&env, "FSNR2000").await;
    env.stop_gateway(&address)
        .await
        .expect("Failed to stop the gateway");

    env.restart_cda().await.expect("Failed to restart CDA");
    assert_persisted_offline(&env, "FSNR2000", "FSNR2000_App_0101").await;
    assert!(
        is_persisted_state(&env, "FLXC1000", PersistedEcuState::Online).await,
        "the reachable gateway stays Online: {}",
        persisted_topology(&env).await
    );

    let ecu = ecu_status(&env, COMPONENTS_FSNR2000_BASE).await;
    assert_eq!(
        ecu.variant.state,
        sovd_interfaces::components::ecu::State::Offline
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
        "a gateway persisted as Offline is not restored and starts Offline"
    );
    let recorded = recorder.stop().await.expect("Failed to stop recording");
    let requests = diagnostic_requests(&recorded);
    assert!(
        requests.is_empty(),
        "no further detection may run after the restart: {requests:?}"
    );

    env.start_gateway(&address)
        .await
        .expect("Failed to start the gateway again");
}
