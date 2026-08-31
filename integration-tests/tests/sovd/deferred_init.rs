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

use std::{
    panic::AssertUnwindSafe,
    time::{Duration, Instant},
};

use cda_interfaces::communication_control::{
    CommunicationInitMode, CommunicationSettings, PostUpdateCommunicationMode, VariantDetectionMode,
};
use futures::FutureExt;
use http::HeaderMap;
use sovd_interfaces::{
    apps::sovd2uds::operations::runtimefilesupdate::ExecutionMode,
    error::{ApiErrorResponse, ErrorCode},
};

use crate::{
    sovd::{ECU_FLXC1000_ENDPOINT, runtimefiles},
    util::{
        ecusim,
        http::{auth_header, response_to_t, send_cda_request},
        runtime::{
            restart_cda, restart_cda_with_config, setup_integration_test,
            setup_integration_test_without_cda, skip_for_can, use_can, wait_for_ecus_online,
            with_temporary_cda,
        },
    },
};

const ECU_SIM_NAME: &str = "flxc1000";

fn flxc1000_data_path() -> String {
    format!("/vehicle/v15/{ECU_FLXC1000_ENDPOINT}/data")
}

enum CdaMode {
    Deferred(PostUpdateCommunicationMode),
    Disabled,
}

impl CdaMode {
    fn config(
        self,
        runtime: &crate::util::runtime::TestRuntime,
    ) -> opensovd_cda_lib::config::configfile::Configuration {
        let (init_mode, post_update_mode) = match self {
            Self::Deferred(post_update_mode) => (CommunicationInitMode::OnDemand, post_update_mode),
            Self::Disabled => (
                CommunicationInitMode::Disabled,
                PostUpdateCommunicationMode::Enabled,
            ),
        };

        let mut config = runtime.config.clone();
        config.communication = CommunicationSettings {
            init_mode,
            variant_detection: VariantDetectionMode::Always,
            post_update_mode,
            deferred_retry_after_seconds: 1,
        };
        config
    }
}

/// Polls `path` with the given (already-authenticated) headers until it stops
/// returning 503, or the timeout elapses.
async fn wait_until_not_pending(
    base_url: &str,
    path: &str,
    headers: &HeaderMap,
    timeout: Duration,
) -> reqwest::Response {
    let client = reqwest::Client::new();
    let deadline = Instant::now()
        .checked_add(timeout)
        .expect("Timeout is too large");
    loop {
        let response = client
            .get(format!("{base_url}{path}"))
            .headers(headers.clone())
            .send()
            .await
            .unwrap_or_else(|e| panic!("request to {path} failed: {e}"));
        if response.status() != reqwest::StatusCode::SERVICE_UNAVAILABLE {
            return response;
        }
        assert!(
            Instant::now() < deadline,
            "{path} still returned 503 after {timeout:?}"
        );
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(100)).await;
    }
}

/// Polls `path` until the runtime update's `409 Update in progress` protection
/// is lifted, and returns that first unprotected response.
///
/// The protection outlives the execution's `completed` status. The update task
/// publishes the status, then settles the transport, then drops the protection,
/// so the first non-409 response is the one that carries the post-update
/// communication state.
async fn wait_until_update_protection_lifted(
    base_url: &str,
    path: &str,
    headers: &HeaderMap,
    timeout: Duration,
) -> reqwest::Response {
    let client = reqwest::Client::new();
    let deadline = Instant::now()
        .checked_add(timeout)
        .expect("Timeout is too large");
    loop {
        let response = client
            .get(format!("{base_url}{path}"))
            .headers(headers.clone())
            .send()
            .await
            .unwrap_or_else(|e| panic!("request to {path} failed: {e}"));
        if response.status() != reqwest::StatusCode::CONFLICT {
            return response;
        }
        assert!(
            Instant::now() < deadline,
            "{path} still returned 409 (update in progress) after {timeout:?}"
        );
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(100)).await;
    }
}

/// Reads the `Retry-After` header as whole seconds, or `None` when it is absent
/// or not a plain seconds value.
fn retry_after_seconds(response: &reqwest::Response) -> Option<u64> {
    response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
}

fn base_url(runtime: &crate::util::runtime::TestRuntime) -> String {
    format!(
        "http://{}:{}",
        runtime.config.server.address, runtime.config.server.port
    )
}

/// On-demand initialization for an authenticated diagnostic request. The gate
/// returns 503 with `Retry-After` immediately and fires the activation trigger
/// in the background. The endpoint leaves the 503 state once that completes.
#[tokio::test]
async fn on_demand_diagnostic_path_returns_503_then_200() {
    let (runtime, _guard) = setup_integration_test(true)
        .await
        .expect("Failed to setup runtime");
    with_temporary_cda(
        &runtime.config,
        CdaMode::Deferred(PostUpdateCommunicationMode::Enabled).config(runtime),
        || async {},
        || async {
            let client = reqwest::Client::new();
            let base = base_url(runtime);
            let headers = auth_header(&runtime.config, None)
                .await
                .expect("Failed to authenticate");

            // The request must return 503 immediately rather than block through
            // the full activation sequence.
            let response = client
                .get(format!("{base}{}", flxc1000_data_path()))
                .headers(headers.clone())
                .send()
                .await
                .expect("Request failed");

            assert_eq!(
                response.status(),
                reqwest::StatusCode::SERVICE_UNAVAILABLE,
                "Expected 503 before the background activation trigger completes"
            );

            // Retry-After must equal the configured value.
            assert_eq!(
                retry_after_seconds(&response),
                Some(1),
                "Retry-After should be 1 second"
            );

            let body_text = response.text().await.expect("Failed to read response body");
            let body: ApiErrorResponse<String> = serde_json::from_str(&body_text)
                .unwrap_or_else(|e| panic!("failed to parse error body: {e}\nbody: {body_text}"));
            assert_eq!(body.error_code, ErrorCode::VendorSpecific);

            // The gate's own request fired the trigger. Poll until it completes.
            let response = wait_until_not_pending(
                &base,
                &flxc1000_data_path(),
                &headers,
                Duration::from_secs(30),
            )
            .await;
            assert_eq!(
                response.status(),
                reqwest::StatusCode::OK,
                "endpoint must return 200 once the background activation completes"
            );
        },
    )
    .await;
}

/// The CDA stays fully quiet on the vehicle network (no `DoIP` traffic at all)
/// until an authenticated diagnostic request authorizes the first activation.
#[tokio::test]
async fn on_demand_trigger_produces_no_doip_traffic_before_authorized_request() {
    if skip_for_can(
        "on_demand_trigger_produces_no_doip_traffic_before_authorized_request",
        "asserts on recorded DoIP frames",
    ) {
        return;
    }
    // Set up without starting the CDA, so recording can start before it exists.
    let (runtime, _guard) = setup_integration_test_without_cda(true)
        .await
        .expect("Failed to setup runtime");
    with_temporary_cda(
        &runtime.config,
        CdaMode::Deferred(PostUpdateCommunicationMode::Enabled).config(runtime),
        || async {
            // Record from before the CDA starts, to catch startup traffic.
            ecusim::start_recording(&runtime.ecu_sim, ECU_SIM_NAME)
                .await
                .expect("Failed to start recording");
        },
        || async {
            // The CDA is started. Check for traffic before any authenticated
            // request.
            let recorded_frames = ecusim::stop_and_clear_recording(&runtime.ecu_sim, ECU_SIM_NAME)
                .await
                .expect("Failed to stop recording");

            // No diagnostic request yet, so it must be silent on the network.
            assert!(
                recorded_frames.is_empty(),
                "Unexpected DoIP traffic before the authorized trigger: {recorded_frames:?}",
            );

            // Record again across the trigger, so that a recorder which never
            // captures anything cannot satisfy the assertion above.
            ecusim::start_recording(&runtime.ecu_sim, ECU_SIM_NAME)
                .await
                .expect("Failed to restart recording");

            // The first authenticated diagnostic request is the only authorized
            // trigger. It fires the activation in the background, so poll until
            // the guard lifts.
            let base = base_url(runtime);
            let headers = auth_header(&runtime.config, None)
                .await
                .expect("Failed to authenticate");
            let response = wait_until_not_pending(
                &base,
                &flxc1000_data_path(),
                &headers,
                Duration::from_secs(30),
            )
            .await;
            assert_eq!(
                response.status(),
                reqwest::StatusCode::OK,
                "endpoint must return 200 once the background activation completes"
            );

            // The same recorder that saw nothing before must now see traffic.
            let recorded_frames = ecusim::stop_and_clear_recording(&runtime.ecu_sim, ECU_SIM_NAME)
                .await
                .expect("Failed to stop recording");
            assert!(
                !recorded_frames.is_empty(),
                "expected DoIP traffic after the authorized trigger, but the recording was empty"
            );
        },
    )
    .await;
}

/// Verifies that after a runtime update with `PostUpdateCommunicationMode::Deferred`,
/// diagnostic endpoints return 503 again until re-triggered.
///
/// The update takes the transport down through an exclusive disable lease. Under
/// `Deferred` that lease is dropped rather than released, so communication
/// returns to the state it was in before the first trigger.
///
/// The sequence is:
///   a. Start a CDA in deferred mode with `PostUpdateCommunicationMode::Deferred`.
///   b. Trigger initialization (transition away from the 503 state).
///   c. Perform a runtime update (upload an MDD to `runtimefiles-nextupdate`,
///      then run an `Apply` execution and wait for the reload cycle).
///   d. Verify diagnostic endpoints return 503 again after the update.
///   e. Trigger initialization again (exits the 503 state again).
#[tokio::test]
async fn post_update_deferred_mode_returns_503_until_triggered() {
    let (runtime, _guard) = setup_integration_test(true)
        .await
        .expect("Failed to setup runtime");

    // Step a: deferred mode with PostUpdateCommunicationMode::Deferred, and the
    // default plugin, so the first request triggers initialization.
    with_temporary_cda(
        &runtime.config,
        CdaMode::Deferred(PostUpdateCommunicationMode::Deferred).config(runtime),
        || async {},
        || async {
            let base = base_url(runtime);
            let headers = auth_header(&runtime.config, None)
                .await
                .expect("Failed to authenticate");

            // Step b: trigger initialization by sending an authenticated diagnostic
            // request and waiting until the guard exits the 503 state.
            let response = wait_until_not_pending(
                &base,
                &flxc1000_data_path(),
                &headers,
                Duration::from_secs(30),
            )
            .await;
            assert_eq!(
                response.status(),
                reqwest::StatusCode::OK,
                "endpoint must return 200 once the background activation completes"
            );

            // Step c: perform a runtime update. Mutating runtime files needs a
            // vehicle lock.
            let lock_id = runtimefiles::setup_with_lock(&runtime.config, &headers).await;

            // Apply is a snapshot swap. Staging the complete fixture set keeps
            // this update from changing the "vehicle".
            runtimefiles::stage_full_database(&runtime.config, &headers)
                .await
                .expect("Failed to stage the database for the update");

            runtimefiles::execute_mode(&runtime.config, &headers, ExecutionMode::Apply)
                .await
                .expect("Apply execution failed");

            // Step d: the update dropped the disable lease instead of releasing
            // it, so the diagnostic path answers 503 again. A non-deferred
            // post-update mode would have served 200 here.
            let response = wait_until_update_protection_lifted(
                &base,
                &flxc1000_data_path(),
                &headers,
                Duration::from_secs(30),
            )
            .await;
            let status = response.status();
            let retry_after = retry_after_seconds(&response);
            let body = response.text().await.unwrap_or_default();
            assert_eq!(
                status,
                reqwest::StatusCode::SERVICE_UNAVAILABLE,
                "diagnostic endpoint must return 503 again after a Deferred post-update, body: \
                 {body}"
            );
            assert_eq!(retry_after, Some(1), "Retry-After should be 1 second");

            // Step e: that request fired the trigger again. Poll until it
            // completes.
            let response = wait_until_not_pending(
                &base,
                &flxc1000_data_path(),
                &headers,
                Duration::from_secs(30),
            )
            .await;
            assert_eq!(
                response.status(),
                reqwest::StatusCode::OK,
                "endpoint must return 200 once the post-update activation completes"
            );

            // Reset the staging collection so the next test starts from "no
            // pending changes".
            runtimefiles::execute_mode(&runtime.config, &headers, ExecutionMode::Cleanup)
                .await
                .expect("Cleanup execution failed");
            wait_until_update_protection_lifted(
                &base,
                &flxc1000_data_path(),
                &headers,
                Duration::from_secs(30),
            )
            .await;
            // The rest of the shared suite runs against this instance, so the
            // whole vehicle has to survive the update.
            wait_for_ecus_online(&runtime.config)
                .await
                .expect("ECUs did not come back online after the update cycle");
            runtimefiles::teardown_lock(&runtime.config, &headers, &lock_id).await;
        },
    )
    .await;
}

/// In `init_mode = Disabled` an ordinary authenticated diagnostic request
/// must never trigger activation, and the CDA must stay silent on the vehicle
/// network throughout.
#[tokio::test]
async fn disabled_mode_never_activates_or_produces_traffic() {
    if skip_for_can(
        "disabled_mode_never_activates_or_produces_traffic",
        "asserts on recorded DoIP frames",
    ) {
        return;
    }

    let (runtime, _guard) = setup_integration_test_without_cda(true)
        .await
        .expect("Failed to setup runtime");
    with_temporary_cda(
        &runtime.config,
        CdaMode::Disabled.config(runtime),
        || async {
            // Record from before the CDA starts, to catch startup traffic.
            ecusim::start_recording(&runtime.ecu_sim, ECU_SIM_NAME)
                .await
                .expect("Failed to start recording");
        },
        || async {
            // Nothing is authorized to bring the vehicle network up, so the CDA
            // must be as silent at startup as an OnDemand instance.
            let recorded_frames = ecusim::stop_and_clear_recording(&runtime.ecu_sim, ECU_SIM_NAME)
                .await
                .expect("Failed to stop recording");
            assert!(
                recorded_frames.is_empty(),
                "Unexpected DoIP traffic before any request under Disabled: {recorded_frames:?}",
            );

            ecusim::start_recording(&runtime.ecu_sim, ECU_SIM_NAME)
                .await
                .expect("Failed to restart recording");

            let base = base_url(runtime);
            let headers = auth_header(&runtime.config, None)
                .await
                .expect("Failed to authenticate");
            let client = reqwest::Client::new();

            // OnDemand resolves to 200 well inside this window. Disabled must
            // never leave the pending state.
            let deadline = Instant::now()
                .checked_add(Duration::from_secs(3))
                .expect("deadline does not overflow");
            while Instant::now() < deadline {
                let response = client
                    .get(format!("{base}{}", flxc1000_data_path()))
                    .headers(headers.clone())
                    .send()
                    .await
                    .expect("request failed");
                assert_eq!(
                    response.status(),
                    reqwest::StatusCode::SERVICE_UNAVAILABLE,
                    "Disabled must never authorize activation from an ordinary request"
                );
                cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(200)).await;
            }

            // Every rejected request must also have produced zero
            // vehicle-network traffic.
            let recorded_frames = ecusim::stop_and_clear_recording(&runtime.ecu_sim, ECU_SIM_NAME)
                .await
                .expect("Failed to stop recording");
            assert!(
                recorded_frames.is_empty(),
                "Disabled must produce zero vehicle-network traffic, got: {recorded_frames:?}",
            );
        },
    )
    .await;
}

/// Reads the SOVD variant state for `ecu_endpoint` (an authenticated `GET`).
async fn ecu_variant_state(
    config: &opensovd_cda_lib::config::configfile::Configuration,
    headers: &HeaderMap,
    ecu_endpoint: &str,
) -> sovd_interfaces::components::ecu::State {
    let response = send_cda_request(
        config,
        ecu_endpoint,
        http::StatusCode::OK,
        http::Method::GET,
        None,
        Some(headers),
        None,
    )
    .await
    .expect("Failed to get ecu component");
    let ecu: sovd_interfaces::components::ecu::get::Response =
        response_to_t(&response).expect("Failed to parse ecu component response");
    ecu.variant.state
}

/// Polls `ecu_endpoint`'s variant state until it matches `expected`, or
/// panics once `timeout` elapses.
///
/// Not `wait_for_ecus_online`, which waits for `networkstructure` to reach
/// `"Online"` or `"Duplicate"`. That only happens once a variant has been
/// detected, so under `variant_detection = Never` it would hang.
async fn wait_for_ecu_variant_state(
    config: &opensovd_cda_lib::config::configfile::Configuration,
    headers: &HeaderMap,
    ecu_endpoint: &str,
    expected: sovd_interfaces::components::ecu::State,
    timeout: Duration,
) -> sovd_interfaces::components::ecu::State {
    let deadline = Instant::now()
        .checked_add(timeout)
        .expect("deadline does not overflow");
    loop {
        let state = ecu_variant_state(config, headers, ecu_endpoint).await;
        if state == expected {
            return state;
        }
        assert!(
            Instant::now() < deadline,
            "{ecu_endpoint} did not reach {expected:?} within {timeout:?}, last state: {state:?}"
        );
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(200)).await;
    }
}

/// Explicitly triggers per-ECU variant detection for `ecu_endpoint` (an
/// authenticated `PUT`, handled by `UdsVariant::detect_variant`).
///
/// A direct UDS-level probe against one ECU, not
/// `CommunicationPlugin::trigger_detection()`, which has no HTTP-reachable path
/// yet. `variant_detection` does not gate it, because it only controls the
/// automatic whole-vehicle variant detection run as part of an activation.
async fn trigger_variant_detection(
    config: &opensovd_cda_lib::config::configfile::Configuration,
    headers: &HeaderMap,
    ecu_endpoint: &str,
) {
    send_cda_request(
        config,
        ecu_endpoint,
        http::StatusCode::CREATED,
        http::Method::PUT,
        None,
        Some(headers),
        None,
    )
    .await
    .expect("Failed to trigger variant detection");
}

/// `variant_detection = Never` must still bring the transport up under `Always`
/// `init_mode`, but must never settle any ECU's variant via the automatic
/// whole-vehicle variant detection. A manual per-ECU trigger (see
/// [`trigger_variant_detection`]) still works, because it bypasses that path.
#[tokio::test]
async fn variant_detection_never_requires_explicit_trigger() {
    let (runtime, _guard) = setup_integration_test(true)
        .await
        .expect("Failed to setup runtime");

    let outcome = AssertUnwindSafe(async {
        restart_cda_with_config(&runtime.config, |config| {
            config.communication = CommunicationSettings {
                init_mode: CommunicationInitMode::Always,
                variant_detection: VariantDetectionMode::Never,
                post_update_mode: PostUpdateCommunicationMode::Enabled,
                deferred_retry_after_seconds: 1,
            };
        })
        .await
        .expect("Failed to start CDA with variant_detection = Never");

        let headers = auth_header(&runtime.config, None)
            .await
            .expect("Failed to authenticate");

        // `Connectivity` only records that an ECU actually answered:
        // - over `DoIP` the gateway announces its ECUs, so connectivity reaches
        //   Online with the ECU still NotTested.
        // - over CAN nothing announces anything and no exchange happens under
        //   `Never`, so the ECU stays Offline until the manual trigger below.
        //
        // Either way the ECU must never reach Online, which needs a detected
        // variant. A closure rather than a binding, because `State` is neither
        // `Copy` nor `Clone` and both uses below need the value.
        let undetected_state = || {
            if use_can() {
                sovd_interfaces::components::ecu::State::Offline
            } else {
                sovd_interfaces::components::ecu::State::NotTested
            }
        };
        wait_for_ecu_variant_state(
            &runtime.config,
            &headers,
            ECU_FLXC1000_ENDPOINT,
            undetected_state(),
            Duration::from_secs(10),
        )
        .await;

        // Give the absent detector the window it would have had under Always,
        // then confirm the state never moved on its own.
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(2)).await;
        let state = ecu_variant_state(&runtime.config, &headers, ECU_FLXC1000_ENDPOINT).await;
        assert_eq!(
            state,
            undetected_state(),
            "variant_detection = Never must not auto-detect a variant"
        );

        // A manual per-ECU trigger bypasses the gated variant detection and
        // must settle the variant as it would under Always.
        trigger_variant_detection(&runtime.config, &headers, ECU_FLXC1000_ENDPOINT).await;
        let state = ecu_variant_state(&runtime.config, &headers, ECU_FLXC1000_ENDPOINT).await;
        assert_eq!(
            state,
            sovd_interfaces::components::ecu::State::Online,
            "a manual per-ECU trigger must still settle the variant under variant_detection = \
             Never"
        );
    })
    .catch_unwind()
    .await;

    restart_cda(&runtime.config)
        .await
        .expect("Failed to restore normal CDA");
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}
