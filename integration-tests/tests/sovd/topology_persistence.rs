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

use crate::{
    sovd::{ECU_FLXC1000_ENDPOINT, runtimefiles},
    util::{
        ecusim,
        http::{auth_header, response_to_t, send_cda_request},
        runtime::{
            cda_logs_since, exec_in_cda, restart_cda, restart_cda_keeping_storage,
            setup_integration_test, skip_for_can, wait_for_ecus_online,
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
    let response = send_cda_request(
        config,
        ECU_FLXC1000_ENDPOINT,
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

/// AC1/AC2: the topology is persisted, and a restart reuses it: no broadcast
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
        let ecu = ecu_status(&config, &headers).await;
        assert_eq!(ecu.variant.name, FLXC1000_APP_VARIANT, "restored variant");
        assert_eq!(
            ecu.variant.state,
            sovd_interfaces::components::ecu::State::Online
        );
        assert!(ecu.last_seen.is_some(), "last_seen restored");

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
            StatusCode::CREATED,
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
    let config = persistence_config(&runtime.config, CommunicationInitMode::Always);

    with_restore(&runtime.config, || async {
        restart_cda(&config).await.expect("Failed to start CDA");
        wait_for_ecus_online(&config)
            .await
            .expect("ECUs did not come online");
        wait_for("the persisted topology", Duration::from_secs(30), || {
            persisted_topology().contains(FLXC1000_APP_VARIANT)
        })
        .await;
        let before = persisted_topology();

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

        restart_cda_keeping_storage(&config)
            .await
            .expect("Failed to restart CDA");
        let after = persisted_topology();
        assert_ne!(before, after, "last_seen must be updated at shutdown");
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
        response_to_t::<
            sovd_interfaces::apps::sovd2uds::operations::networkreset::ExecutionCreatedResponse,
        >(&response)
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
            &format!("{NETWORK_RESET}/{id}"),
            StatusCode::OK,
            Method::GET,
            None,
            Some(headers),
            None,
        )
        .await
        .expect("Failed to read the execution");
        let execution: ExecutionResponse = response_to_t(&response).expect("Invalid execution");
        match &execution.status {
            ExecutionStatusKind::Completed => return,
            ExecutionStatusKind::Running => {}
            status => panic!("networkreset ended with {status:?}: {execution:?}"),
        }
        assert!(Instant::now() < deadline, "networkreset did not complete");
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(500)).await;
    }
}

/// AC4: `networkreset` clears the persisted topology and rediscovers it.
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
