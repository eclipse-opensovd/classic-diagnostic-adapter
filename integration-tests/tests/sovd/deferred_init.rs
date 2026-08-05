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
    future::Future,
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
        TestingError, ecusim,
        http::{auth_header, response_to_t, send_cda_request},
        runtime::{
            restart_cda, setup_integration_test, setup_integration_test_without_cda, skip_for_can,
            use_can, wait_for_ecus_online,
        },
    },
};

const ECU_SIM_NAME: &str = "flxc1000";

fn flxc1000_data_path() -> String {
    format!("/vehicle/v15/{ECU_FLXC1000_ENDPOINT}/data")
}

/// Runs `body` against a deferred-mode CDA, restoring the normal shared CDA
/// afterward **even if `body` panics**.
///
/// The `pre_start` hook runs AFTER the ECU simulator is ready but BEFORE
/// the deferred CDA is started. This is useful for setting up network
/// traffic recording to verify no premature activity occurs.
///
/// `post_update_mode` only takes effect if `body` actually performs a runtime
/// update; for bodies that do not, any value behaves identically.
///
/// The restore is not optional bookkeeping: the CDA is shared by the whole
/// suite, so an assertion failure that skipped it would leave every later test
/// talking to an on-demand instance and failing with 503. The panic is
/// re-raised after the restore, so the failing test still fails.
async fn with_deferred_cda<F, G, Fut, FutPre>(
    runtime: &crate::util::runtime::TestRuntime,
    post_update_mode: PostUpdateCommunicationMode,
    pre_start: G,
    body: F,
) where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ()>,
    G: FnOnce() -> FutPre,
    FutPre: Future<Output = ()>,
{
    pre_start().await;
    start_deferred(runtime, post_update_mode)
        .await
        .expect("Failed to start deferred CDA");

    let outcome = AssertUnwindSafe(body()).catch_unwind().await;

    restart_cda(&runtime.config)
        .await
        .expect("Failed to restore normal CDA");

    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

/// Stops the normal CDA, then starts a deferred-mode CDA using
/// the supplied `post_update_mode`.
///
/// Prefer [`with_deferred_cda`] over calling this directly: it pairs the start
/// with the restore that subsequent tests depend on.
async fn start_deferred(
    runtime: &crate::util::runtime::TestRuntime,
    post_update_mode: PostUpdateCommunicationMode,
) -> Result<(), TestingError> {
    start_cda(runtime, CommunicationInitMode::OnDemand, post_update_mode).await
}

/// Stops the normal CDA, then starts a `Disabled`-mode CDA.
///
/// `Disabled` is the third `init_mode`, and unlike `OnDemand` above it is a
/// strict authorization boundary rather than a slower on-demand path:
/// ordinary activation (startup, diagnostic requests) is rejected outright,
/// with zero vehicle-network activity, until an explicit
/// `trigger_detection()` call authorizes it (see ADR-006). Prefer
/// [`with_disabled_cda`] over calling this directly: it pairs the start with
/// the restore that subsequent tests depend on.
async fn start_disabled(runtime: &crate::util::runtime::TestRuntime) -> Result<(), TestingError> {
    start_cda(
        runtime,
        CommunicationInitMode::Disabled,
        PostUpdateCommunicationMode::Enabled,
    )
    .await
}

async fn start_cda(
    runtime: &crate::util::runtime::TestRuntime,
    init_mode: CommunicationInitMode,
    post_update_mode: PostUpdateCommunicationMode,
) -> Result<(), TestingError> {
    let mut config = runtime.config.clone();
    config.communication = CommunicationSettings {
        init_mode,
        variant_detection: VariantDetectionMode::Always,
        post_update_mode,
        deferred_retry_after_seconds: 1,
    };

    restart_cda(&config).await
}

/// Runs `body` against a `Disabled`-mode CDA, restoring the normal shared CDA
/// afterward **even if `body` panics**. See [`with_deferred_cda`] for why the
/// restore is not optional bookkeeping.
///
/// The `pre_start` hook runs AFTER the ECU simulator is ready but BEFORE the
/// `Disabled`-mode CDA is started, mirroring [`with_deferred_cda`].
async fn with_disabled_cda<F, G, Fut, FutPre>(
    runtime: &crate::util::runtime::TestRuntime,
    pre_start: G,
    body: F,
) where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ()>,
    G: FnOnce() -> FutPre,
    FutPre: Future<Output = ()>,
{
    pre_start().await;
    start_disabled(runtime)
        .await
        .expect("Failed to start Disabled-mode CDA");

    let outcome = AssertUnwindSafe(body()).catch_unwind().await;

    restart_cda(&runtime.config)
        .await
        .expect("Failed to restore normal CDA");

    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
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
/// The protection outlives the execution's `completed` status by a moment: the
/// update task publishes the status first, then settles the transport, then
/// drops the protection. Sampling the endpoint straight after the execution
/// finishes therefore sees 409, not the post-update communication state. What
/// the *first* non-409 response says is the meaningful observation, since the
/// polling requests are the only diagnostic traffic and so nothing else can
/// have triggered re-activation in the meantime.
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

/// Verifies that on-demand initialization works correctly for an
/// authenticated diagnostic request:
/// - Returns 503 with Retry-After (the gate fires the activation
///   trigger in the background and returns immediately, it does not block
///   the request through the activation sequence)
/// - After the background trigger completes, the endpoint leaves the 503 state
#[tokio::test]
async fn on_demand_diagnostic_path_returns_503_then_200() {
    let (runtime, _guard) = setup_integration_test(true)
        .await
        .expect("Failed to setup runtime");
    with_deferred_cda(
        runtime,
        PostUpdateCommunicationMode::Enabled,
        || async {},
        || async {
            let client = reqwest::Client::new();
            let base = base_url(runtime);
            let headers = auth_header(&runtime.config, None)
                .await
                .expect("Failed to authenticate");

            // Before any trigger, an authenticated diagnostic request must return 503.
            // The gate fires the activation trigger in the background and
            // returns immediately rather than blocking through the full activation
            // sequence (which can take seconds due to variant detection).
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

            // Verify Retry-After header is present and equals the configured value.
            assert_eq!(
                retry_after_seconds(&response),
                Some(1),
                "Retry-After should be 1 second"
            );

            // Verify error body.
            let body_text = response.text().await.expect("Failed to read response body");
            let body: ApiErrorResponse<String> = serde_json::from_str(&body_text)
                .unwrap_or_else(|e| panic!("failed to parse error body: {e}\nbody: {body_text}"));
            assert_eq!(body.error_code, ErrorCode::VendorSpecific);

            // The gate's own request fired the background activation trigger; poll
            // until it completes and the endpoint leaves the 503 state.
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

/// The CDA stays fully quiet on the vehicle
/// network (no `DoIP` traffic at all) until an authenticated diagnostic
/// request authorizes the first activation, and that request's own trigger
/// is what brings communication up, there is no other proactive path.
#[tokio::test]
async fn on_demand_trigger_produces_no_doip_traffic_before_authorized_request() {
    // This asserts on recorded DoIP frames specifically; FLXC1000 is served
    // over CAN in the pure-CAN suite, so there is nothing DoIP to record there.
    if skip_for_can(
        "on_demand_trigger_produces_no_doip_traffic_before_authorized_request",
        "asserts on recorded DoIP frames",
    ) {
        return;
    }
    // Setup WITHOUT starting the CDA - avoid wasteful start/stop cycle and
    // ensure recording can start before the CDA exists.
    let (runtime, _guard) = setup_integration_test_without_cda(true)
        .await
        .expect("Failed to setup runtime");
    with_deferred_cda(
        runtime,
        PostUpdateCommunicationMode::Enabled,
        || async {
            // Start recording BEFORE the CDA starts to capture any startup traffic.
            ecusim::start_recording(&runtime.ecu_sim, ECU_SIM_NAME)
                .await
                .expect("Failed to start recording");
        },
        || async {
            // Now the CDA has been started; check if any traffic occurred before
            // any authenticated request.
            let recorded_frames = ecusim::stop_and_clear_recording(&runtime.ecu_sim, ECU_SIM_NAME)
                .await
                .expect("Failed to stop recording");

            // This deferred instance has not received a diagnostic request yet,
            // so it must be fully silent on the network.
            assert!(
                recorded_frames.is_empty(),
                "Unexpected DoIP traffic before the authorized trigger: {recorded_frames:?}",
            );

            // Record again, this time across the trigger. This is the counterpart of
            // the silence above: without it, a recorder that simply never captured
            // anything would satisfy the assertion just as well.
            ecusim::start_recording(&runtime.ecu_sim, ECU_SIM_NAME)
                .await
                .expect("Failed to restart recording");

            // The first authenticated diagnostic request is the only authorized
            // trigger. It fires the background activation and takes a fast 503 for
            // itself (asserted in `on_demand_diagnostic_path_returns_503_then_200`);
            // initialization then runs asynchronously, so poll until the guard lifts.
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

            // The authorized trigger is what puts the CDA on the wire, so the same
            // recorder that saw nothing before must now have captured traffic.
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
/// The update itself takes the transport down through an exclusive disable
/// lease. Under `Deferred` that lease is dropped rather than released, which
/// leaves communication disabled: the vehicle goes back to exactly the state it
/// was in before the very first trigger, so the next diagnostic request is once
/// again the thing that authorizes bringing it up.
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

    // Step a: start CDA in deferred mode with PostUpdateCommunicationMode::Deferred.
    // Use the default plugin so initialization is triggered by the first request.
    with_deferred_cda(
        runtime,
        PostUpdateCommunicationMode::Deferred,
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

            // Step c: perform a runtime update. Mutating the runtime files needs a
            // vehicle lock.
            let lock_id = runtimefiles::setup_with_lock(&runtime.config, &headers).await;

            // Apply is a *snapshot swap*: whatever is staged in nextupdate becomes the
            // entire active database, and anything missing from it is dropped. Staging
            // the complete fixture set is therefore what keeps this update from
            // changing the "vehicle" - see `stage_full_database` for why the usual
            // "upload one file on top of current" shortcut does not work here.
            runtimefiles::stage_full_database(&runtime.config, &headers)
                .await
                .expect("Failed to stage the database for the update");

            runtimefiles::execute_mode(&runtime.config, &headers, ExecutionMode::Apply)
                .await
                .expect("Apply execution failed");

            // Step d: the update dropped the disable lease instead of releasing it,
            // so communication is deferred again and the diagnostic path is back to
            // answering 503 (with the same Retry-After contract as before the update).
            // The update protection is torn down a moment after the execution reports
            // completion, so the discriminating observation is what the *first*
            // unprotected response says: 503 here, where a non-deferred post-update
            // mode would have served 200.
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

            // Step e: that request fired the background activation trigger again;
            // poll until it completes and the endpoint leaves the 503 state.
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

            // Reset the staging collection so the next test starts from "no pending
            // changes". Cleanup is neither Apply nor Rollback, so it releases its lease
            // normally and leaves communication up.
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
            // The whole vehicle, not just the ECU this test polled, has to survive the
            // update: the rest of the shared suite runs against this instance.
            wait_for_ecus_online(&runtime.config)
                .await
                .expect("ECUs did not come back online after the update cycle");
            runtimefiles::teardown_lock(&runtime.config, &headers, &lock_id).await;
        },
    )
    .await;
}

/// `init_mode = Disabled` is a strict authorization boundary, not merely a
/// slower `OnDemand`: an ordinary authenticated diagnostic request must never
/// trigger activation, and the CDA must stay completely silent on the
/// vehicle network throughout - end to end, against real HTTP and `DoIP`
/// traffic. Previously this mode was exercised only by the communication
/// plugin's own unit tests (see `plugin::default::tests::disabled_mode_*` in
/// `cda-plugin-communication-management`), never against a real transport.
#[tokio::test]
async fn disabled_mode_never_activates_or_produces_traffic() {
    // This asserts on recorded DoIP frames specifically; FLXC1000 is served
    // over CAN in the pure-CAN suite, so there is nothing DoIP to record there.
    if skip_for_can(
        "disabled_mode_never_activates_or_produces_traffic",
        "asserts on recorded DoIP frames",
    ) {
        return;
    }

    let (runtime, _guard) = setup_integration_test_without_cda(true)
        .await
        .expect("Failed to setup runtime");
    with_disabled_cda(
        runtime,
        || async {
            // Start recording BEFORE the CDA starts to capture any startup traffic.
            ecusim::start_recording(&runtime.ecu_sim, ECU_SIM_NAME)
                .await
                .expect("Failed to start recording");
        },
        || async {
            // No activity is authorized to bring the vehicle network up on its
            // own, so the CDA must be exactly as silent at startup as an
            // OnDemand instance is (see
            // `on_demand_trigger_produces_no_doip_traffic_before_authorized_request`).
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

            // Unlike OnDemand (see on_demand_diagnostic_path_returns_503_then_200,
            // which resolves to 200 well inside this same window), an ordinary
            // authenticated diagnostic request must never authorize activation
            // under Disabled: poll for a while and confirm the endpoint never
            // leaves the pending state.
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

            // Every one of those rejected requests must also have produced zero
            // vehicle-network traffic - Disabled authorizes no network activity
            // at all, not merely "eventually".
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
/// Deliberately not `wait_for_ecus_online`: that helper waits for the SOVD
/// `networkstructure` state to reach `"Online"`/`"Duplicate"`, which per the
/// `Connectivity`/`VariantState` mapping in `cda-sovd` only happens once a
/// variant has actually been detected. Under `variant_detection = Never`
/// that never happens automatically, so `wait_for_ecus_online` would hang
/// for its full timeout and then fail - it is not the "did connectivity
/// come up" check this test needs.
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
/// This is a direct UDS-level probe against one ECU, not
/// `CommunicationPlugin::trigger_detection()` - there is no HTTP-reachable
/// path to that whole-vehicle operation yet (see the
/// `networkreset-endpoint` TODO in `cda-plugin-communication-management`).
/// It is ungated by `variant_detection` mode: `Always`/`Never` only control
/// whether the *automatic* whole-vehicle sweep
/// (`CommunicationVariantDetection::detect`, wired to
/// `UdsManager::start_variant_detection`) runs as part of activation, which
/// this manual per-ECU path never goes through.
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

/// `variant_detection = Never` must still bring the transport up under
/// `Always` `init_mode` (and, where the transport announces its ECUs, their
/// connectivity with it), but must never settle any ECU's variant via the
/// automatic whole-vehicle sweep; a manual per-ECU
/// trigger (see [`trigger_variant_detection`]) still works, since it never
/// goes through that gated path. Verified end to end, against real HTTP and
/// `DoIP`/CAN traffic: previously this mode was exercised only by the
/// communication plugin's own unit tests
/// (`variant_detection_never_config_skips_detector_not_hooks` in
/// `cda-plugin-communication-management`), never against a real transport or
/// the `SOVD` surface a consumer actually observes.
#[tokio::test]
async fn variant_detection_never_requires_explicit_trigger() {
    let (runtime, _guard) = setup_integration_test(true)
        .await
        .expect("Failed to setup runtime");

    let mut config = runtime.config.clone();
    config.communication = CommunicationSettings {
        init_mode: CommunicationInitMode::Always,
        variant_detection: VariantDetectionMode::Never,
        post_update_mode: PostUpdateCommunicationMode::Enabled,
        deferred_retry_after_seconds: 1,
    };

    let outcome = AssertUnwindSafe(async {
        restart_cda(&config)
            .await
            .expect("Failed to start CDA with variant_detection = Never");

        let headers = auth_header(&runtime.config, None)
            .await
            .expect("Failed to authenticate");

        // Transport comes up eagerly under Always, but what that settles is
        // transport-specific, because `Connectivity` only ever records that an
        // ECU actually answered:
        // - over `DoIP` the gateway announces its ECUs (`on_gateway_connected`),
        //   so connectivity reaches Online without any variant being detected
        //   and the ECU reports NotTested (connected, undetected).
        // - over CAN nothing announces anything; connectivity is only settled by
        //   a successful exchange, which under `Never` is exactly what does not
        //   happen. The ECU therefore stays Offline (still undetected) until the
        //   manual trigger below.
        //
        // Either way the ECU must never reach Online, which requires a detected
        // variant - see `wait_for_ecu_variant_state`'s doc comment.
        // A closure, not a binding: `State` is neither `Copy` nor `Clone`, and
        // both the wait below and the assertion after it need the value.
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

        // Give the (absent) automatic detector every chance it would have
        // had under Always, then confirm the state never moved off the
        // undetected one on its own.
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(2)).await;
        let state = ecu_variant_state(&runtime.config, &headers, ECU_FLXC1000_ENDPOINT).await;
        assert_eq!(
            state,
            undetected_state(),
            "variant_detection = Never must not auto-detect a variant"
        );

        // A manual per-ECU trigger bypasses the gated automatic sweep
        // entirely (see trigger_variant_detection's doc comment) and must
        // settle the variant here exactly as it would under Always.
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
