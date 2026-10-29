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

use std::{
    panic::AssertUnwindSafe,
    time::{Duration, Instant},
};

use cda_interfaces::communication_control::CommunicationInitMode;
use futures::FutureExt;
use http::{HeaderMap, Method, StatusCode};
use opensovd_cda_lib::config::configfile::Configuration;
use sovd_interfaces::locking::post_put::Response as LockResponse;

use crate::{
    sovd::{ECU_FLXC1000_ENDPOINT, ECU_FSNR2000_ENDPOINT, locks, runtimefiles},
    util::{
        ecusim,
        http::{auth_header, response_to_t, send_cda_request},
        runtime::{
            EcuSim, cda_logs_since, exec_in_cda, restart_cda, restart_cda_keeping_storage,
            setup_integration_test, skip_for_can, start_ecu_sim, stop_ecu_sim,
            wait_for_ecus_online,
        },
    },
};

const TOPOLOGY_DIR: &str = "/app/collections/ecu-topology";
const NETWORK_RESET: &str = "apps/sovd2uds/operations/networkreset/executions";
const FLXC1000_APP_VARIANT: &str = "FLXC1000_App_0101";

fn persistence_config(base: &Configuration, init_mode: CommunicationInitMode) -> Configuration {
    let mut config = base.clone();
    config.communication.init_mode = init_mode;
    config.communication.ecu_list_persistence.enabled = true;
    config
}

/// All persisted entries, concatenated. Empty if nothing is persisted.
fn persisted_topology() -> String {
    exec_in_cda(&format!("cat {TOPOLOGY_DIR}/* 2>/dev/null || true"))
        .expect("Failed to read the persisted topology")
}

fn persisted_last_seen(name: &str) -> i64 {
    serde_json::Deserializer::from_str(&persisted_topology())
        .into_iter::<serde_json::Value>()
        .map(|entry| entry.expect("Invalid persisted gateway"))
        .find_map(|gateway| {
            gateway.get("ecus")?.as_array()?.iter().find_map(|ecu| {
                if !ecu.get("name")?.as_str()?.eq_ignore_ascii_case(name) {
                    return None;
                }
                Some(
                    chrono::DateTime::parse_from_rfc3339(ecu.get("last_seen")?.as_str()?)
                        .expect("Invalid persisted timestamp")
                        .timestamp_millis(),
                )
            })
        })
        .expect("Persisted ECU timestamp missing")
}

/// The persisted gateway entry containing the ECU `name`, and that ECU's entry.
fn persisted_ecu(name: &str) -> Option<(serde_json::Value, serde_json::Value)> {
    serde_json::Deserializer::from_str(&persisted_topology())
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

fn persisted_state_is(name: &str, state: &str) -> bool {
    persisted_ecu(name)
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

async fn wait_for(description: &str, timeout: Duration, mut check: impl FnMut() -> bool) {
    let deadline = Instant::now()
        .checked_add(timeout)
        .expect("Timeout is too large");
    while !check() {
        assert!(
            Instant::now() < deadline,
            "Timed out waiting for {description}"
        );
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(500)).await;
    }
}

async fn ecu_status(
    config: &Configuration,
    headers: &HeaderMap,
) -> sovd_interfaces::components::ecu::get::Response {
    ecu_status_of(config, headers, ECU_FLXC1000_ENDPOINT).await
}

async fn ecu_status_of(
    config: &Configuration,
    headers: &HeaderMap,
    endpoint: &str,
) -> sovd_interfaces::components::ecu::get::Response {
    let response = send_cda_request(
        config,
        endpoint,
        StatusCode::OK,
        Method::GET,
        None,
        Some(headers),
        None,
    )
    .await
    .expect("Failed to read ECU status");
    response_to_t(&response).expect("Invalid ECU status")
}

/// Runs `body` and restores the shared CDA (with a fresh container) afterwards,
/// even if `body` panics.
async fn with_restore<F, Fut>(config: &Configuration, body: F)
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ()>,
{
    let outcome = AssertUnwindSafe(body()).catch_unwind().await;
    restart_cda(config)
        .await
        .expect("Failed to restore normal CDA");
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

/// The address the persisted topology holds for the gateway of the ECU `name`.
fn persisted_gateway_address(name: &str) -> String {
    persisted_ecu(name)
        .and_then(|(gateway, _)| gateway.get("network_address")?.as_str().map(str::to_owned))
        .expect("The persisted gateway has no network address")
}

/// Stops the simulator's `DoIP` gateway `gateway`, found by the address in the
/// persisted topology, runs `body` and starts the gateway again afterwards, even
/// if `body` panics. The stop closes all `DoIP` connections of the simulator; the
/// other gateways stay reachable and are reconnected by the CDA.
async fn with_gateway_stopped<F, Fut>(sim: &EcuSim, gateway: &str, body: F)
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ()>,
{
    let address = persisted_gateway_address(gateway);
    ecusim::stop_gateway(sim, &address)
        .await
        .expect("Failed to stop the gateway");
    let outcome = AssertUnwindSafe(body()).catch_unwind().await;
    ecusim::start_gateway(sim, &address)
        .await
        .expect("Failed to start the gateway again");
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

/// [[ itest~ecu-list-persistence-disabled, Without ECU list persistence nothing is persisted, itest ]]
#[tokio::test]
async fn persistence_disabled_writes_nothing() {
    if skip_for_can("persistence_disabled_writes_nothing", "DoIP topology only") {
        return;
    }
    let (runtime, _guard) = setup_integration_test(true)
        .await
        .expect("Failed to setup runtime");
    assert!(!runtime.config.communication.ecu_list_persistence.enabled);
    restart_cda(&runtime.config)
        .await
        .expect("Failed to start CDA");
    wait_for_ecus_online(&runtime.config)
        .await
        .expect("ECUs did not come online");
    let exists = exec_in_cda(&format!("[ -e {TOPOLOGY_DIR} ] && echo yes || echo no"))
        .expect("Failed to check the topology collection");
    assert_eq!(exists.trim(), "no", "no topology may be written by default");
}

/// The topology is persisted, and a restart reuses it: no broadcast
/// discovery, no variant detection, the stored variant and `last_seen` restored.
/// [[ itest~ecu-list-persistence-reuse, A restart reuses the persisted topology without redetection, itest ]]
#[tokio::test]
async fn restart_reuses_persisted_topology_without_redetection() {
    if skip_for_can(
        "restart_reuses_persisted_topology_without_redetection",
        "DoIP topology only",
    ) {
        return;
    }
    let (runtime, _guard) = setup_integration_test(true)
        .await
        .expect("Failed to setup runtime");
    let config = persistence_config(&runtime.config, CommunicationInitMode::WhenNotPersisted);

    with_restore(&runtime.config, || async {
        // A fresh container: no persisted topology, so a full detection runs.
        restart_cda(&config).await.expect("Failed to start CDA");
        wait_for_ecus_online(&config)
            .await
            .expect("ECUs did not come online");
        wait_for("the persisted topology", Duration::from_secs(30), || {
            persisted_topology().contains(FLXC1000_APP_VARIANT)
        })
        .await;
        let persisted = persisted_topology();
        assert!(persisted.contains("\"network_address\""), "{persisted}");
        assert!(persisted.contains("\"state\":\"Online\""), "{persisted}");
        assert!(
            persisted.contains("\"state\":\"Duplicate\""),
            "the fixture must include a resolved duplicate group: {persisted}"
        );

        // The ECU changes its variant while the CDA is down. A reused topology
        // must not notice, since no variant detection runs.
        ecusim::switch_variant(&runtime.ecu_sim, "FLXC1000", "BOOT")
            .await
            .expect("Failed to switch variant");
        ecusim::start_recording(&runtime.ecu_sim, "flxc1000")
            .await
            .expect("Failed to start recording");
        let restarted_at = chrono::Utc::now().to_rfc3339();
        restart_cda_keeping_storage(&config)
            .await
            .expect("Failed to restart CDA");

        let headers = auth_header(&config, None)
            .await
            .expect("Failed to authenticate");
        // Not contacted yet, so the restored ECU is assumed online: an ECU lock
        // must be granted.
        let lock = locks::create_lock(
            locks::default_timeout(),
            locks::ECU_ENDPOINT,
            StatusCode::CREATED,
            &config,
            &headers,
        )
        .await;
        let lock_id = response_to_t::<LockResponse>(&lock)
            .expect("Invalid lock response")
            .id;
        locks::lock_operation(
            locks::ECU_ENDPOINT,
            Some(&lock_id),
            &config,
            &headers,
            StatusCode::NO_CONTENT,
            Method::DELETE,
        )
        .await;
        let ecu = ecu_status(&config, &headers).await;
        assert_eq!(ecu.variant.name, FLXC1000_APP_VARIANT, "restored variant");
        assert_eq!(
            ecu.variant.state,
            sovd_interfaces::components::ecu::State::Online
        );
        assert!(ecu.last_seen.is_some(), "last_seen restored");

        // The result of the restart is persisted only after its reconnect, the
        // fallback and any detection have settled, so a late detection is recorded
        // before this. Only a write after the new process's reconnect counts: the
        // container log also holds the shutdown write of the old process.
        wait_for(
            "the persisted result of the restart",
            Duration::from_secs(90),
            || {
                cda_logs_since(&restarted_at).is_ok_and(|logs| {
                    logs.split_once("Reconnecting to persisted gateways")
                        .is_some_and(|(_, after)| after.contains("Persisted ECU topology"))
                })
            },
        )
        .await;
        let recorded = ecusim::stop_and_clear_recording(&runtime.ecu_sim, "flxc1000")
            .await
            .expect("Failed to stop recording");
        // Any request would be a variant detection.
        let requests = diagnostic_requests(&recorded);
        assert!(
            requests.is_empty(),
            "no variant detection may run for a restored ECU: {requests:?}"
        );
        let logs = cda_logs_since(&restarted_at).expect("Failed to read logs");
        assert!(
            logs.contains("Reconnecting to persisted gateways"),
            "expected a direct reconnect"
        );
        assert!(
            !logs.contains("Broadcasting VIR"),
            "no broadcast discovery expected after the restart"
        );

        // An explicit re-detection still finds the real variant.
        send_cda_request(
            &config,
            ECU_FLXC1000_ENDPOINT,
            StatusCode::OK,
            Method::PUT,
            None,
            Some(&headers),
            None,
        )
        .await
        .expect("Failed to trigger variant detection");
        let ecu = ecu_status(&config, &headers).await;
        assert_eq!(ecu.variant.name, "FLXC1000_Boot_Variant");

        ecusim::switch_variant(&runtime.ecu_sim, "FLXC1000", "APPLICATION")
            .await
            .expect("Failed to switch variant back");
    })
    .await;
}

/// Polls a GET until it answers 200: under `OnDemand` the first requests report
/// pending (503) while communication starts.
async fn get_until_ok(config: &Configuration, headers: &HeaderMap, endpoint: &str) {
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(60))
        .expect("Timeout is too large");
    while send_cda_request(
        config,
        endpoint,
        StatusCode::OK,
        Method::GET,
        None,
        Some(headers),
        None,
    )
    .await
    .is_err()
    {
        assert!(Instant::now() < deadline, "{endpoint} did not answer 200");
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(500)).await;
    }
}

/// `OnDemand` with a persisted topology: the first diagnostic request connects
/// only the gateway of the requested ECU; other gateways stay unconnected.
/// [[ itest~deferred-on-demand-per-gateway, `OnDemand` connects only the requested ECU's gateway, itest ]]
#[tokio::test]
async fn on_demand_connects_only_the_requested_gateway() {
    if skip_for_can(
        "on_demand_connects_only_the_requested_gateway",
        "DoIP topology only",
    ) {
        return;
    }
    let (runtime, _guard) = setup_integration_test(true)
        .await
        .expect("Failed to setup runtime");
    let persist = persistence_config(&runtime.config, CommunicationInitMode::WhenNotPersisted);
    let on_demand = persistence_config(&runtime.config, CommunicationInitMode::OnDemand);

    with_restore(&runtime.config, || async {
        // Persist a topology with both gateways.
        restart_cda(&persist).await.expect("Failed to start CDA");
        wait_for_ecus_online(&persist)
            .await
            .expect("ECUs did not come online");
        wait_for("the persisted topology", Duration::from_secs(30), || {
            let persisted = persisted_topology();
            persisted.contains(FLXC1000_APP_VARIANT) && persisted.contains("FSNR2000_App")
        })
        .await;

        ecusim::start_recording(&runtime.ecu_sim, "fsnr2000")
            .await
            .expect("Failed to start recording");
        let restarted_at = chrono::Utc::now().to_rfc3339();
        restart_cda_keeping_storage(&on_demand)
            .await
            .expect("Failed to restart CDA");

        let headers = auth_header(&on_demand, None)
            .await
            .expect("Failed to authenticate");
        get_until_ok(
            &on_demand,
            &headers,
            &format!("{ECU_FLXC1000_ENDPOINT}/data/vindataidentifier"),
        )
        .await;

        let logs = cda_logs_since(&restarted_at).expect("Failed to read logs");
        let connects: Vec<&str> = logs
            .lines()
            .filter(|line| line.contains("Connecting persisted gateway on first request"))
            .collect();
        assert!(
            connects.iter().any(|line| line.contains("0x1000")),
            "the requested ECU's gateway must connect: {connects:?}"
        );
        assert!(
            !connects.iter().any(|line| line.contains("0x2000")),
            "another gateway must stay unconnected: {connects:?}"
        );
        assert!(
            !logs.contains("Broadcasting VIR"),
            "no broadcast discovery expected"
        );
        let recorded = ecusim::stop_and_clear_recording(&runtime.ecu_sim, "fsnr2000")
            .await
            .expect("Failed to stop recording");
        assert!(
            diagnostic_requests(&recorded).is_empty(),
            "no request may reach the other gateway's ECU: {recorded:?}"
        );
    })
    .await;
}

/// The `last_seen` of a contacted ECU is written back at a graceful shutdown.
/// [[ itest~ecu-list-persistence-shutdown, `last_seen` is persisted at shutdown, itest ]]
#[tokio::test]
async fn last_seen_is_written_back_at_shutdown() {
    if skip_for_can(
        "last_seen_is_written_back_at_shutdown",
        "DoIP topology only",
    ) {
        return;
    }
    let (runtime, _guard) = setup_integration_test(true)
        .await
        .expect("Failed to setup runtime");
    let config = persistence_config(&runtime.config, CommunicationInitMode::WhenNotPersisted);

    with_restore(&runtime.config, || async {
        restart_cda(&config).await.expect("Failed to start CDA");
        wait_for_ecus_online(&config)
            .await
            .expect("ECUs did not come online");
        wait_for("the persisted topology", Duration::from_secs(30), || {
            persisted_topology().contains(FLXC1000_APP_VARIANT)
        })
        .await;
        let before = persisted_last_seen("FLXC1000");

        let headers = auth_header(&config, None)
            .await
            .expect("Failed to authenticate");
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(1)).await;
        send_cda_request(
            &config,
            // A real UDS read; the data listing alone does not contact the ECU.
            &format!("{ECU_FLXC1000_ENDPOINT}/data/vindataidentifier"),
            StatusCode::OK,
            Method::GET,
            None,
            Some(&headers),
            None,
        )
        .await
        .expect("Failed to contact the ECU");
        let contact = ecu_status(&config, &headers)
            .await
            .last_seen
            .expect("Contact timestamp missing");
        let contact = chrono::DateTime::parse_from_rfc3339(&contact)
            .expect("Invalid contact timestamp")
            .timestamp_millis();
        assert!(contact > before);

        restart_cda_keeping_storage(&config)
            .await
            .expect("Failed to restart CDA");
        let after = persisted_last_seen("FLXC1000");
        assert!(
            after >= contact,
            "shutdown must save the contact made before restart"
        );
    })
    .await;
}

async fn start_reset(
    config: &Configuration,
    headers: &HeaderMap,
    body: &str,
    expected: StatusCode,
) -> Option<String> {
    let response = send_cda_request(
        config,
        NETWORK_RESET,
        expected,
        Method::POST,
        Some(body),
        Some(headers),
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

async fn wait_reset_completed(config: &Configuration, headers: &HeaderMap, id: &str) {
    use sovd_interfaces::apps::sovd2uds::operations::networkreset::{
        ExecutionResponse, ExecutionStatusKind,
    };
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(60))
        .expect("Timeout is too large");
    loop {
        let response = send_cda_request(
            config,
            &format!("{NETWORK_RESET}/{id}?include-schema=true"),
            StatusCode::OK,
            Method::GET,
            None,
            Some(headers),
            None,
        )
        .await
        .expect("Failed to read the execution");
        let execution: ExecutionResponse = response_to_t(&response).expect("Invalid execution");
        assert!(execution.schema.is_some(), "include-schema must be honored");
        let execution_json = serde_json::to_value(&execution).expect("Invalid execution status");
        assert_eq!(
            execution_json.get("capability"),
            Some(&serde_json::json!("execute"))
        );
        match &execution.status {
            ExecutionStatusKind::Completed => return,
            ExecutionStatusKind::Running => {}
            status => panic!("networkreset ended with {status:?}: {execution:?}"),
        }
        assert!(Instant::now() < deadline, "networkreset did not complete");
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(500)).await;
    }
}

/// Works on both `DoIP` and CAN-only configurations, without a persistence hook.
/// [[ itest~plugin-vehicle-topology-reset-networkreset-without-persistence-completes, Networkreset without persistence completes, itest ]]
#[tokio::test]
async fn networkreset_without_persistence_completes() {
    let (runtime, _guard) = setup_integration_test(true)
        .await
        .expect("Failed to setup runtime");
    assert!(!runtime.config.communication.ecu_list_persistence.enabled);
    restart_cda(&runtime.config)
        .await
        .expect("Failed to start CDA");
    wait_for_ecus_online(&runtime.config)
        .await
        .expect("ECUs did not come online");
    let headers = auth_header(&runtime.config, None)
        .await
        .expect("Failed to authenticate");
    let lock_id = runtimefiles::setup_with_lock(&runtime.config, &headers).await;
    let id = start_reset(
        &runtime.config,
        &headers,
        r#"{"parameters":{"clear_persisted":false}}"#,
        StatusCode::ACCEPTED,
    )
    .await
    .expect("execution id");
    wait_reset_completed(&runtime.config, &headers, &id).await;
    wait_for_ecus_online(&runtime.config)
        .await
        .expect("Rediscovered ECUs did not come online");
    runtimefiles::teardown_lock(&runtime.config, &headers, &lock_id).await;
}

async fn assert_networkreset_discoverable(config: &Configuration, headers: &HeaderMap) {
    let collection = send_cda_request(
        config,
        "apps/sovd2uds/operations",
        StatusCode::OK,
        Method::GET,
        None,
        Some(headers),
        None,
    )
    .await
    .expect("Operation discovery failed");
    let collection: serde_json::Value =
        response_to_t(&collection).expect("Invalid operations collection");
    let operation = collection
        .get("items")
        .expect("Operation collection items missing")
        .as_array()
        .expect("Operation collection items must be an array")
        .iter()
        .find(|item| item.get("id").and_then(serde_json::Value::as_str) == Some("networkreset"))
        .expect("networkreset must be advertised");
    let operation_id = operation
        .get("id")
        .and_then(serde_json::Value::as_str)
        .expect("Operation id missing");
    let details = send_cda_request(
        config,
        &format!("apps/sovd2uds/operations/{operation_id}?include-schema=true"),
        StatusCode::OK,
        Method::GET,
        None,
        Some(headers),
        None,
    )
    .await
    .expect("Operation details failed");
    let details: serde_json::Value = response_to_t(&details).expect("Invalid operation details");
    let capabilities = details.get("schema").expect("Capability PathItem missing");
    assert!(capabilities.get("post").is_some());
    assert!(capabilities.get("get").is_some());
    assert!(capabilities.get("delete").is_some());
    assert!(
        capabilities.get("put").is_none(),
        "Reset cannot be adjusted"
    );
    for name in ["clear_persisted", "trigger_detection"] {
        let parameter = capabilities
            .pointer(&format!(
                "/post/requestBody/content/application~1json/schema/properties/parameters/\
                 properties/{name}"
            ))
            .expect("Parameter schema missing");
        assert_eq!(parameter.get("default"), Some(&serde_json::json!(true)));
    }
}

/// `networkreset` clears the persisted topology and rediscovers it.
/// [[ itest~plugin-vehicle-topology-reset, networkreset clears and rediscovers the topology, itest ]]
#[tokio::test]
async fn networkreset_clears_and_rediscovers_the_topology() {
    if skip_for_can(
        "networkreset_clears_and_rediscovers_the_topology",
        "DoIP topology only",
    ) {
        return;
    }
    let (runtime, _guard) = setup_integration_test(true)
        .await
        .expect("Failed to setup runtime");
    let config = persistence_config(&runtime.config, CommunicationInitMode::WhenNotPersisted);

    with_restore(&runtime.config, || async {
        restart_cda(&config).await.expect("Failed to start CDA");
        wait_for_ecus_online(&config)
            .await
            .expect("ECUs did not come online");
        wait_for("the persisted topology", Duration::from_secs(30), || {
            !persisted_topology().is_empty()
        })
        .await;
        let headers = auth_header(&config, None)
            .await
            .expect("Failed to authenticate");

        assert_networkreset_discoverable(&config, &headers).await;

        // A vehicle lock is required.
        start_reset(&config, &headers, "{}", StatusCode::FORBIDDEN).await;
        let lock_id = runtimefiles::setup_with_lock(&config, &headers).await;

        // Both flags false is no operation.
        start_reset(
            &config,
            &headers,
            r#"{"parameters":{"clear_persisted":false,"trigger_detection":false}}"#,
            StatusCode::BAD_REQUEST,
        )
        .await;

        // Clear only: nothing is persisted afterwards.
        let id = start_reset(
            &config,
            &headers,
            r#"{"parameters":{"trigger_detection":false}}"#,
            StatusCode::ACCEPTED,
        )
        .await
        .expect("execution id");
        wait_reset_completed(&config, &headers, &id).await;
        assert!(
            persisted_topology().is_empty(),
            "the topology must be cleared"
        );

        // Clear and detect (default): the topology is rediscovered and persisted.
        let id = start_reset(&config, &headers, "{}", StatusCode::ACCEPTED)
            .await
            .expect("execution id");
        wait_reset_completed(&config, &headers, &id).await;
        assert!(persisted_topology().contains(FLXC1000_APP_VARIANT));

        let list = send_cda_request(
            &config,
            NETWORK_RESET,
            StatusCode::OK,
            Method::GET,
            None,
            Some(&headers),
            None,
        )
        .await
        .expect("Failed to list executions");
        let list: serde_json::Value = response_to_t(&list).expect("Invalid execution list");
        let first_id = list
            .get("items")
            .and_then(|items| items.get(0))
            .and_then(|item| item.get("id"));
        assert_eq!(first_id, Some(&serde_json::json!(id)));
        send_cda_request(
            &config,
            &format!("{NETWORK_RESET}/{id}"),
            StatusCode::NO_CONTENT,
            Method::DELETE,
            None,
            Some(&headers),
            None,
        )
        .await
        .expect("Failed to delete the execution");

        runtimefiles::teardown_lock(&config, &headers, &lock_id).await;
    })
    .await;
}

/// With every gateway stopped (vehicle presumably asleep), the persisted
/// topology is kept: failed gateways are only written while another gateway is
/// connected.
/// [[ itest~ecu-list-persistence-unreachable, No gateway connected keeps the persisted states, itest ]]
#[tokio::test]
async fn all_gateways_unreachable_keeps_persisted_states() {
    if skip_for_can(
        "all_gateways_unreachable_keeps_persisted_states",
        "DoIP topology only",
    ) {
        return;
    }
    let (runtime, _guard) = setup_integration_test(true)
        .await
        .expect("Failed to setup runtime");
    let config = persistence_config(&runtime.config, CommunicationInitMode::WhenNotPersisted);

    with_restore(&runtime.config, || async {
        restart_cda(&config).await.expect("Failed to start CDA");
        wait_for_ecus_online(&config)
            .await
            .expect("ECUs did not come online");
        wait_for("the persisted topology", Duration::from_secs(30), || {
            persisted_topology().contains(FLXC1000_APP_VARIANT)
        })
        .await;

        stop_ecu_sim().await.expect("Failed to stop the ECU sim");
        let restarted_at = chrono::Utc::now().to_rfc3339();
        restart_cda_keeping_storage(&config)
            .await
            .expect("Failed to restart CDA");
        wait_for(
            "the gateways to be reported unreachable",
            Duration::from_secs(120),
            || {
                cda_logs_since(&restarted_at).is_ok_and(|logs| {
                    logs.contains("Gateway not found, marking its ECUs as not reachable")
                })
            },
        )
        .await;
        // Leaves time for a (wrongly) triggered write.
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(5)).await;

        let persisted = persisted_topology();
        assert!(persisted.contains("\"state\":\"Online\""), "{persisted}");
        assert!(
            !persisted.contains("\"state\":\"Disconnected\""),
            "no gateway is connected, so nothing may be demoted: {persisted}"
        );
        assert!(persisted.contains(FLXC1000_APP_VARIANT), "{persisted}");

        start_ecu_sim(&runtime.ecu_sim)
            .await
            .expect("Failed to restart the ECU sim");
    })
    .await;
}

/// Waits until the topology persisted for `ecu` says `Disconnected`, and checks
/// that the stored address and variant of its gateway are kept.
async fn assert_persisted_disconnected(ecu: &str, variant: &str) {
    wait_for(
        "the unreachable gateway to be persisted",
        Duration::from_secs(180),
        || persisted_state_is(ecu, "Disconnected"),
    )
    .await;
    let (gateway, entry) = persisted_ecu(ecu).expect("Persisted ECU missing");
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

/// One gateway stopped while another stays up: the failed gateway is persisted
/// as `Disconnected` (address and variant kept) and not restored as `Online`.
/// [[ itest~ecu-list-persistence-unreachable-gateway, A stopped gateway is persisted as Disconnected while another gateway is up, itest ]]
#[tokio::test]
async fn unreachable_gateway_is_persisted_as_disconnected() {
    if skip_for_can(
        "unreachable_gateway_is_persisted_as_disconnected",
        "DoIP topology only",
    ) {
        return;
    }
    let (runtime, _guard) = setup_integration_test(true)
        .await
        .expect("Failed to setup runtime");
    let config = persistence_config(&runtime.config, CommunicationInitMode::WhenNotPersisted);

    with_restore(&runtime.config, || async {
        restart_cda(&config).await.expect("Failed to start CDA");
        wait_for_ecus_online(&config)
            .await
            .expect("ECUs did not come online");
        wait_for("the persisted topology", Duration::from_secs(30), || {
            persisted_state_is("FSNR2000", "Online") && persisted_state_is("FLXC1000", "Online")
        })
        .await;

        with_gateway_stopped(&runtime.ecu_sim, "FSNR2000", || async {
            let restarted_at = chrono::Utc::now().to_rfc3339();
            restart_cda_keeping_storage(&config)
                .await
                .expect("Failed to restart CDA");
            assert_persisted_disconnected("FSNR2000", "FSNR2000_App").await;
            // The failed direct reconnect falls back to a broadcast, which may
            // still be answered with the stopped gateway's announcement; the TCP
            // connect to its removed address must fail anyway.
            let logs = cda_logs_since(&restarted_at).expect("Failed to read logs");
            assert!(logs.contains("Broadcasting VIR"), "expected the fallback");
            assert!(
                logs.contains("Gateway not found, marking its ECUs as not reachable"),
                "the stopped gateway must be reported unreachable"
            );
            assert!(
                persisted_state_is("FLXC1000", "Online"),
                "the reachable gateway stays Online: {}",
                persisted_topology()
            );

            let headers = auth_header(&config, None)
                .await
                .expect("Failed to authenticate");
            let ecu = ecu_status_of(&config, &headers, ECU_FSNR2000_ENDPOINT).await;
            assert_eq!(
                ecu.variant.state,
                sovd_interfaces::components::ecu::State::Disconnected
            );
            assert_eq!(
                ecu_status(&config, &headers).await.variant.state,
                sovd_interfaces::components::ecu::State::Online
            );

            // The next start must not restore the stopped gateway's ECU as Online.
            ecusim::start_recording(&runtime.ecu_sim, "flxc1000")
                .await
                .expect("Failed to start recording");
            restart_cda_keeping_storage(&config)
                .await
                .expect("Failed to restart CDA");
            let headers = auth_header(&config, None)
                .await
                .expect("Failed to authenticate");
            let ecu = ecu_status_of(&config, &headers, ECU_FSNR2000_ENDPOINT).await;
            assert_ne!(
                ecu.variant.state,
                sovd_interfaces::components::ecu::State::Online,
                "a gateway persisted as Disconnected must not start Online"
            );
            let recorded = ecusim::stop_and_clear_recording(&runtime.ecu_sim, "flxc1000")
                .await
                .expect("Failed to stop recording");
            let requests = diagnostic_requests(&recorded);
            assert!(
                requests.is_empty(),
                "no further detection may run after the restart: {requests:?}"
            );
        })
        .await;
    })
    .await;
}

/// `OnDemand`: a request to an ECU of a stopped gateway fails, and the gateway is
/// persisted as `Disconnected` without any detection run.
/// [[ itest~ecu-list-persistence-unreachable-on-demand, A failed connect on first use is persisted as Disconnected, itest ]]
#[tokio::test]
async fn on_demand_failed_connect_is_persisted_as_disconnected() {
    if skip_for_can(
        "on_demand_failed_connect_is_persisted_as_disconnected",
        "DoIP topology only",
    ) {
        return;
    }
    let (runtime, _guard) = setup_integration_test(true)
        .await
        .expect("Failed to setup runtime");
    let persist = persistence_config(&runtime.config, CommunicationInitMode::WhenNotPersisted);
    let on_demand = persistence_config(&runtime.config, CommunicationInitMode::OnDemand);

    with_restore(&runtime.config, || async {
        restart_cda(&persist).await.expect("Failed to start CDA");
        wait_for_ecus_online(&persist)
            .await
            .expect("ECUs did not come online");
        wait_for("the persisted topology", Duration::from_secs(30), || {
            persisted_state_is("FSNR2000", "Online") && persisted_state_is("FLXC1000", "Online")
        })
        .await;

        with_gateway_stopped(&runtime.ecu_sim, "FSNR2000", || async {
            let restarted_at = chrono::Utc::now().to_rfc3339();
            restart_cda_keeping_storage(&on_demand)
                .await
                .expect("Failed to restart CDA");
            let headers = auth_header(&on_demand, None)
                .await
                .expect("Failed to authenticate");
            // A reachable gateway connects first, so a failed gateway is written.
            get_until_ok(
                &on_demand,
                &headers,
                &format!("{ECU_FLXC1000_ENDPOINT}/data/vindataidentifier"),
            )
            .await;
            assert!(
                persisted_state_is("FSNR2000", "Online"),
                "not attempted yet"
            );

            // The request must fail: the gateway is unreachable.
            let result = send_cda_request(
                &on_demand,
                &format!("{ECU_FSNR2000_ENDPOINT}/data/vindataidentifier"),
                StatusCode::OK,
                Method::GET,
                None,
                Some(&headers),
                None,
            )
            .await;
            assert!(result.is_err(), "the stopped gateway's ECU must not answer");

            assert_persisted_disconnected("FSNR2000", "FSNR2000_App").await;
            assert!(
                persisted_state_is("FLXC1000", "Online"),
                "the reachable gateway stays Online: {}",
                persisted_topology()
            );
            let logs = cda_logs_since(&restarted_at).expect("Failed to read logs");
            assert!(
                logs.contains("Connecting persisted gateway on first request"),
                "the connect on first use must have been attempted"
            );
        })
        .await;
    })
    .await;
}
