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

//! ECU list persistence: storing, reusing and resetting the vehicle topology.

use std::time::{Duration, Instant};

use aide::openapi::{OpenApi, ReferenceOr};
use cda_interfaces::{
    communication_control::{CommunicationInitMode, CommunicationSettings},
    topology::{PersistedEcu, PersistedEcuState, PersistedGateway, logical_address_hex},
};
use http::{Method, StatusCode};
use opensovd_cda_lib::config::configfile::{Configuration, TransportOverride, TransportType};
use sovd_interfaces::{
    Items,
    apps::sovd2uds::operations::networkreset::OperationResponse,
    common::operations::{ExecutionListResponse, OperationCollectionItem},
};

use crate::{
    sovd::{
        COMPONENTS_FLXC1000_BASE, COMPONENTS_FSNR2000_BASE, force_variant_detection, runtimefiles,
    },
    util::{
        TestingError,
        config::CDA_STORAGE_DIR,
        ecusim,
        http::{CdaClient, poll_until, response_to_t, send_authenticated_cda_request},
        locks::{COMPONENTS_FLXC1000_LOCKS, Lock, default_timeout},
        test_env::{Lease, TestEnv, Transport, skip_unless, wait_for_ecus_online},
    },
};

const NETWORK_RESET: &str = "apps/sovd2uds/operations/networkreset/executions";
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

/// Logical address of a gateway that no database knows, see
/// [`plant_stale_gateway`].
const STALE_GATEWAY_ADDRESS: u16 = 0x7FFE;

/// Writes a persisted entry for a gateway that does not exist, like a leftover
/// of an earlier topology. Only a clear or a persist run, which prunes unknown
/// gateways, removes it.
async fn plant_stale_gateway(env: &TestEnv) {
    let entry = serde_json::to_string(&PersistedGateway {
        name: "STALE_GATEWAY".to_owned(),
        logical_address: STALE_GATEWAY_ADDRESS,
        network_address: Some("192.0.2.1".to_owned()),
        doip_protocol_version: None,
        ecus: Vec::new(),
    })
    .expect("Failed to encode the stale gateway");
    let dir = topology_dir();
    env.exec_in_cda_container(&format!(
        "mkdir -p {dir} && printf '%s' '{entry}' > {dir}/{}",
        logical_address_hex(STALE_GATEWAY_ADDRESS)
    ))
    .await
    .expect("Failed to plant the stale gateway");
    assert!(
        has_stale_gateway(env).await,
        "the stale gateway must be persisted"
    );
}

/// Whether the entry written by [`plant_stale_gateway`] is persisted.
async fn has_stale_gateway(env: &TestEnv) -> bool {
    persisted_gateways(env)
        .await
        .iter()
        .any(|gateway| gateway.logical_address == STALE_GATEWAY_ADDRESS)
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
    jiff::Timestamp::try_from(last_seen)
        .expect("Persisted ECU timestamp out of range")
        .as_millisecond()
}

async fn is_persisted_state(env: &TestEnv, name: &str, state: PersistedEcuState) -> bool {
    persisted_ecu(env, name)
        .await
        .is_some_and(|(_, ecu)| ecu.state == state)
}

/// `ReadDataByIdentifier` of DID 0xF100 (`Identification_Read`), the request
/// the variant patterns of the test ECUs match on (see
/// `testcontainer/odx/generate.py`). Only the variant detection sends it.
const VARIANT_DETECTION_REQUEST: &str = "22f100";

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
    let contact = contact
        .parse::<jiff::Timestamp>()
        .expect("Invalid contact timestamp")
        .as_millisecond();
    assert!(contact > before);

    env.restart_cda().await.expect("Failed to restart CDA");
    let after = persisted_last_seen(&env, "FLXC1000").await;
    assert!(
        after >= contact,
        "shutdown must save the contact made before restart"
    );
}

async fn start_reset(cda: &impl CdaClient, body: &str, expected: StatusCode) -> Option<String> {
    let response = send_authenticated_cda_request(
        cda,
        NETWORK_RESET,
        expected,
        Method::POST,
        Some(body),
        None,
    )
    .await
    .expect("networkreset request failed");
    (expected == StatusCode::ACCEPTED).then(|| {
        response_to_t::<sovd_interfaces::common::operations::ExecutionCreatedResponse>(&response)
            .expect("Invalid networkreset response")
            .id
    })
}

async fn wait_reset_completed(cda: &impl CdaClient, id: &str) {
    use sovd_interfaces::apps::sovd2uds::operations::networkreset::{
        ExecutionResponse, ExecutionStatus,
    };
    poll_until(
        Duration::from_secs(60),
        Duration::from_millis(500),
        || async {
            let response = send_authenticated_cda_request(
                cda,
                &format!("{NETWORK_RESET}/{id}?include-schema=true"),
                StatusCode::OK,
                Method::GET,
                None,
                None,
            )
            .await?;
            // Deserializing also checks the capability, which can only be `execute`.
            let execution: ExecutionResponse = response_to_t(&response)?;
            assert!(execution.schema.is_some(), "include-schema must be honored");
            match &execution.status {
                ExecutionStatus::Completed => Ok(Ok(())),
                ExecutionStatus::Running => Ok(Err("networkreset is running".to_owned())),
                status => panic!("networkreset ended with {status:?}: {execution:?}"),
            }
        },
    )
    .await
    .unwrap_or_else(|e| panic!("networkreset did not complete: {e:?}"));
}

/// Deletes the finished `networkreset` execution `id` and verifies the DELETE:
/// the execution is not found anymore and the execution list is empty.
async fn delete_reset(cda: &impl CdaClient, id: &str) {
    send_authenticated_cda_request(
        cda,
        &format!("{NETWORK_RESET}/{id}"),
        StatusCode::NO_CONTENT,
        Method::DELETE,
        None,
        None,
    )
    .await
    .expect("Failed to delete the execution");
    send_authenticated_cda_request(
        cda,
        &format!("{NETWORK_RESET}/{id}"),
        StatusCode::NOT_FOUND,
        Method::GET,
        None,
        None,
    )
    .await
    .expect("A deleted execution must not be found");
    assert!(
        reset_executions(cda).await.items.is_empty(),
        "no execution may be listed after the delete"
    );
}

async fn reset_executions(cda: &impl CdaClient) -> ExecutionListResponse {
    let list =
        send_authenticated_cda_request(cda, NETWORK_RESET, StatusCode::OK, Method::GET, None, None)
            .await
            .expect("Failed to list executions");
    response_to_t(&list).expect("Invalid execution list")
}

/// Without a persistence hook, a rediscovery-only `networkreset` completes and
/// runs a variant detection. Works on both `DoIP` and CAN-only configurations.
/// [[ itest~plugin-vehicle-topology-reset-without-persistence-completes, Networkreset without persistence completes and rediscovers, itest ]]
#[tokio::test]
async fn networkreset_without_persistence_completes() {
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
    let lock_id = runtimefiles::setup_with_lock(&env).await;
    let recorder = env
        .record("flxc1000")
        .await
        .expect("Failed to start recording");
    let id = start_reset(
        &env,
        r#"{"parameters":{"clear_persisted":false}}"#,
        StatusCode::ACCEPTED,
    )
    .await
    .expect("execution id");
    wait_reset_completed(&env, &id).await;
    wait_for(
        "the variant detection of the rediscovery",
        Duration::from_secs(30),
        || async {
            let recorded = recorder.frames().await.expect("Failed to read recording");
            recorded
                .iter()
                .any(|frame| frame.eq_ignore_ascii_case(VARIANT_DETECTION_REQUEST))
        },
    )
    .await;
    recorder.stop().await.expect("Failed to stop recording");
    wait_for_ecus_online(&env.config)
        .await
        .expect("Rediscovered ECUs did not come online");
    delete_reset(&env, &id).await;
    runtimefiles::teardown_lock(&env, &lock_id).await;
}

async fn assert_networkreset_discoverable(cda: &impl CdaClient) {
    let collection = send_authenticated_cda_request(
        cda,
        "apps/sovd2uds/operations",
        StatusCode::OK,
        Method::GET,
        None,
        None,
    )
    .await
    .expect("Operation discovery failed");
    let collection: Items<OperationCollectionItem> =
        response_to_t(&collection).expect("Invalid operations collection");
    let operation = collection
        .items
        .iter()
        .find(|item| item.id == "networkreset")
        .expect("networkreset must be advertised");
    let details = send_authenticated_cda_request(
        cda,
        &format!(
            "apps/sovd2uds/operations/{}?include-schema=true",
            operation.id
        ),
        StatusCode::OK,
        Method::GET,
        None,
        None,
    )
    .await
    .expect("Operation details failed");
    let details: OperationResponse = response_to_t(&details).expect("Invalid operation details");
    assert_eq!(details.item.id, operation.id);
    assert!(details.schema.is_some(), "include-schema must be honored");

    let docs = send_authenticated_cda_request(
        cda,
        &format!("apps/sovd2uds/operations/{}/docs", operation.id),
        StatusCode::OK,
        Method::GET,
        None,
        None,
    )
    .await
    .expect("Operation capability description failed");
    let docs: OpenApi = response_to_t(&docs).expect("Invalid capability description");
    let mut paths = docs
        .paths
        .expect("Capability description has no paths")
        .paths;
    let executions = format!("/apps/sovd2uds/operations/{}/executions", operation.id);
    let execution = paths
        .get(&format!("{executions}/{{execution-id}}"))
        .and_then(ReferenceOr::as_item)
        .expect("Execution path missing");
    assert!(execution.get.is_some());
    assert!(execution.delete.is_some());
    let request_schema = paths
        .swap_remove(&executions)
        .and_then(ReferenceOr::into_item)
        .expect("Executions path missing")
        .post
        .expect("POST capability missing")
        .request_body
        .and_then(ReferenceOr::into_item)
        .expect("Request body missing")
        .content
        .swap_remove(mime::APPLICATION_JSON.as_ref())
        .and_then(|media| media.schema)
        .expect("JSON request schema missing")
        .json_schema;
    for name in ["clear_persisted", "trigger_detection"] {
        let parameter = request_schema
            .pointer(&format!("/properties/parameters/properties/{name}"))
            .expect("Parameter schema missing");
        assert_eq!(
            parameter.get("default"),
            Some(&serde_json::Value::Bool(true))
        );
    }
}

/// `networkreset` clears the persisted topology and rediscovers it.
/// [[ itest~plugin-vehicle-topology-reset-clears-and-rediscovers, networkreset clears and rediscovers the topology, itest ]]
#[tokio::test]
async fn networkreset_clears_and_rediscovers_the_topology() {
    if skip_unless(Transport::uses_doip, "DoIP topology only") {
        return;
    }
    let mut env = persistence_env(CommunicationInitMode::WhenNotPersisted).await;
    wait_for_persisted_topology(&env).await;

    assert_networkreset_discoverable(&env).await;

    // The exclusive vehicle lock is required.
    start_reset(&env, "{}", StatusCode::CONFLICT).await;
    let lock_id = runtimefiles::setup_with_lock(&env).await;

    // Both flags false is no operation.
    start_reset(
        &env,
        r#"{"parameters":{"clear_persisted":false,"trigger_detection":false}}"#,
        StatusCode::BAD_REQUEST,
    )
    .await;

    // Clear only. Only the vehicle lock is required: an ECU lock of the vehicle lock
    // owner does not prevent the reset. `WhenNotPersisted` starts communication on its
    // own, so it comes back right after the clear, as at a startup without a persisted
    // topology, and persists the rediscovered topology again. Any persist run prunes
    // unknown gateways, so the stale gateway being gone verifies the re-persisting,
    // not the clear; the clear itself is verified with `OnDemand` below.
    plant_stale_gateway(&env).await;
    let child = Lock::acquire(&env, COMPONENTS_FLXC1000_LOCKS, default_timeout()).await;
    let id = start_reset(
        &env,
        r#"{"parameters":{"trigger_detection":false}}"#,
        StatusCode::ACCEPTED,
    )
    .await
    .expect("execution id");
    wait_reset_completed(&env, &id).await;
    child.release(&env).await;
    wait_for(
        "the topology persisted again after the clear",
        Duration::from_secs(30),
        || async {
            !has_stale_gateway(&env).await
                && has_variant(&persisted_gateways(&env).await, FLXC1000_APP_VARIANT)
        },
    )
    .await;

    // Clear and detect (default): the topology is rediscovered and persisted
    // again, which drops the stale gateway.
    plant_stale_gateway(&env).await;
    let id = start_reset(&env, "{}", StatusCode::ACCEPTED)
        .await
        .expect("execution id");
    wait_reset_completed(&env, &id).await;
    let gateways = persisted_gateways(&env).await;
    assert!(
        !gateways
            .iter()
            .any(|gateway| gateway.logical_address == STALE_GATEWAY_ADDRESS),
        "the stale gateway must be gone: {gateways:?}"
    );
    assert!(has_variant(&gateways, FLXC1000_APP_VARIANT), "{gateways:?}");

    // Only the latest execution is kept.
    let list = reset_executions(&env).await;
    assert_eq!(list.items.len(), 1, "{:?}", list.items);
    assert_eq!(
        list.items.first().map(|item| item.id.as_str()),
        Some(id.as_str())
    );
    delete_reset(&env, &id).await;
    runtimefiles::teardown_lock(&env, &lock_id).await;

    // `OnDemand` does not start communication after a clear-only reset, so
    // nothing persists the topology again and the clear itself is observed.
    restart_on_demand(&mut env).await;
    let lock_id = runtimefiles::setup_with_lock(&env).await;
    // Otherwise the check for the cleared topology below passes without a clear.
    let topology = persisted_topology(&env).await;
    assert!(
        !topology.trim().is_empty(),
        "the topology must be persisted before the clear"
    );
    let id = start_reset(
        &env,
        r#"{"parameters":{"trigger_detection":false}}"#,
        StatusCode::ACCEPTED,
    )
    .await
    .expect("execution id");
    wait_reset_completed(&env, &id).await;
    let topology = persisted_topology(&env).await;
    assert!(
        topology.trim().is_empty(),
        "a clear-only reset must remove the persisted topology: {topology}"
    );
    delete_reset(&env, &id).await;
    runtimefiles::teardown_lock(&env, &lock_id).await;
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

/// Polls a GET until it answers 200: under `OnDemand` the first requests report
/// pending (503) while communication starts. Any other error fails at once.
async fn get_until_ok(cda: &impl CdaClient, endpoint: &str) {
    poll_until(
        Duration::from_secs(60),
        Duration::from_millis(500),
        || async {
            match send_authenticated_cda_request(
                cda,
                endpoint,
                StatusCode::OK,
                Method::GET,
                None,
                None,
            )
            .await
            {
                Ok(_) => Ok(Ok(())),
                Err(TestingError::UnexpectedResponse {
                    actual: StatusCode::SERVICE_UNAVAILABLE,
                    ..
                }) => Ok(Err(format!("{endpoint} still pending"))),
                Err(error) => panic!("{endpoint} failed: {error}"),
            }
        },
    )
    .await
    .unwrap_or_else(|e| panic!("{endpoint} did not answer 200: {e:?}"));
}

/// A test environment that has persisted the topology with both gateways.
async fn env_with_persisted_gateways() -> Lease {
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
    env
}

/// Restarts the CDA of `env` with `init_mode = OnDemand` and returns the Unix
/// time from which its logs include the restarted CDA.
async fn restart_on_demand(env: &mut Lease) -> i32 {
    let mut on_demand = env.config.clone();
    on_demand.communication = persistence_settings(CommunicationInitMode::OnDemand);
    // Docker timestamps use the container host's clock, not the test host's.
    // Include the current second so even an immediate restart is captured.
    let logs_since = env
        .exec_in_cda_container("date +%s")
        .await
        .expect("Failed to read the container clock")
        .trim()
        .parse::<i32>()
        .expect("Invalid container clock");
    env.restart_cda_with(&on_demand)
        .await
        .expect("Failed to restart CDA");
    logs_since
}

/// Discards any previous run included in the second-resolution log window.
/// `None` while Docker has not delivered the startup line of the restarted
/// CDA yet, so callers poll again.
fn latest_cda_run(logs: &str) -> Option<&str> {
    logs.rsplit_once("Starting CDA - version ")
        .map(|(_, latest)| latest)
}

#[test]
fn latest_cda_run_excludes_previous_run() {
    let logs = "Starting CDA - version old\nBroadcasting VIR\nStarting CDA - version new\nready";
    assert_eq!(latest_cda_run(logs), Some("new\nready"));
    assert_eq!(latest_cda_run("Broadcasting VIR"), None);
}

/// Whether `logs` report the connect of the gateway of the ECU `ecu_name`.
fn logged_ecu_connect(logs: &str, ecu_name: &str) -> bool {
    let name = format!("\"{ecu_name}\"");
    logs.lines()
        .any(|line| line.contains("ECU connected") && line.contains(&name))
}

/// Polls the logs of the latest CDA run since `logs_since` for `window`, checks
/// them with `check` at every poll and returns the latest run's logs of the
/// last poll. Polls until the startup of the latest run is in the logs.
/// An absence assertion needs such an observation window: background work and
/// log delivery can lag behind what is observed.
async fn observe_cda_logs(
    env: &TestEnv,
    logs_since: i32,
    window: Duration,
    check: impl Fn(&str),
) -> String {
    let check = &check;
    let observation = Instant::now();
    poll_until(
        // Well beyond the window, so slow log reads cannot fail the observation.
        window.saturating_add(Duration::from_secs(8)),
        Duration::from_millis(100),
        || async move {
            let logs = env.cda_logs_since(logs_since).await?;
            let Some(latest) = latest_cda_run(&logs) else {
                return Ok(Err("waiting for the CDA startup in the logs".to_owned()));
            };
            check(latest);
            Ok(if observation.elapsed() >= window {
                Ok(latest.to_owned())
            } else {
                Err("observing the logs".to_owned())
            })
        },
    )
    .await
    .expect("Failed to observe logs")
}

/// `OnDemand` with a persisted topology: nothing is connected before the first
/// diagnostic request, which connects all gateways at once at their persisted
/// addresses, without a VIR.
/// [[ itest~deferred-on-demand-all-gateways, The first diagnostic request connects all persisted gateways without a VIR, itest ]]
#[tokio::test]
async fn on_demand_first_request_connects_all_gateways() {
    if skip_unless(Transport::uses_doip, "DoIP topology only") {
        return;
    }
    let mut env = Box::pin(env_with_persisted_gateways()).await;
    let logs_since = restart_on_demand(&mut env).await;

    observe_cda_logs(&env, logs_since, Duration::from_secs(2), |logs| {
        assert!(
            !logs.contains("Connected to gateway"),
            "no gateway may connect before the first request: {logs}"
        );
    })
    .await;

    get_until_ok(
        &env,
        &format!("{COMPONENTS_FLXC1000_BASE}/data/vindataidentifier"),
    )
    .await;

    wait_for(
        "the connects of both gateways",
        Duration::from_secs(30),
        || async {
            let logs = env
                .cda_logs_since(logs_since)
                .await
                .expect("Failed to read logs");
            latest_cda_run(&logs).is_some_and(|logs| {
                logged_ecu_connect(logs, "flxc1000") && logged_ecu_connect(logs, "fsnr2000")
            })
        },
    )
    .await;
    // Logs only grow, so the startup found above is still in them.
    let logs = env
        .cda_logs_since(logs_since)
        .await
        .expect("Failed to read logs");
    assert!(
        latest_cda_run(&logs).is_some_and(|logs| !logs.contains("Broadcasting VIR")),
        "all gateways are reachable at their persisted address: {logs}"
    );
}

/// `OnDemand` with a persisted topology: a gateway that cannot be reached at its
/// persisted address is searched by one VIR at the start, and a later request
/// to its ECU does not send another one.
/// [[ itest~deferred-on-demand-one-vir, The first diagnostic request sends one VIR for unreachable gateways, itest ]]
#[tokio::test]
async fn on_demand_first_request_sends_one_vir() {
    if skip_unless(Transport::uses_doip, "DoIP topology only") {
        return;
    }
    let mut env = Box::pin(env_with_persisted_gateways()).await;

    // The stop closes all `DoIP` connections of the simulator; the other
    // gateways stay reachable.
    let address = persisted_gateway_address(&env, "FSNR2000").await;
    env.stop_gateway(&address)
        .await
        .expect("Failed to stop the gateway");

    let logs_since = restart_on_demand(&mut env).await;
    get_until_ok(
        &env,
        &format!("{COMPONENTS_FLXC1000_BASE}/data/vindataidentifier"),
    )
    .await;
    assert_persisted_offline(&env, "FSNR2000", "FSNR2000_App_0101").await;

    // The stopped gateway's ECU was never detected in this run, so the CDA
    // reports it not ready (503) instead of sending the request.
    send_authenticated_cda_request(
        &env,
        &format!("{COMPONENTS_FSNR2000_BASE}/data/vindataidentifier"),
        StatusCode::SERVICE_UNAVAILABLE,
        Method::GET,
        None,
        None,
    )
    .await
    .expect("The stopped gateway's ECU must not answer");

    let logs = observe_cda_logs(&env, logs_since, Duration::from_secs(2), |logs| {
        let count = logs.matches("Broadcasting VIR").count();
        assert!(count <= 1, "more than one VIR per transport start: {logs}");
    })
    .await;
    assert_eq!(
        logs.matches("Broadcasting VIR").count(),
        1,
        "one VIR per transport start: {logs}"
    );

    env.start_gateway(&address)
        .await
        .expect("Failed to start the gateway again");
}
