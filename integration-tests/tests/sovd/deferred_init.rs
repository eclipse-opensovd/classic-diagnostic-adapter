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

use std::time::{Duration, Instant};

use cda_interfaces::communication_control::{
    CommunicationInitMode, CommunicationSettings, PostUpdateCommunicationMode, VariantDetectionMode,
};
use http::{Method, StatusCode};
use sovd_interfaces::{
    apps::sovd2uds::operations::runtimefilesupdate::ExecutionMode,
    error::{ApiErrorResponse, ErrorCode},
};

use crate::{
    sovd::{
        COMPONENTS_FLXC1000_BASE, COMPONENTS_FLXC1000_DATA, ECU_FLXC1000, ecu_status,
        force_variant_detection, runtimefiles,
    },
    util::{
        endpoints::APPS_SOVD2UDS_DATA_VERSION,
        http::{
            Response, poll_while, response_to_t, send_authenticated_cda_request, send_cda_request,
        },
        test_env::{
            ON_DEMAND_RETRY_AFTER_SECONDS, TestEnv, Transport, on_demand_communication, skip_unless,
        },
    },
};

/// Reads the `Retry-After` header as whole seconds, or `None` when it is absent
/// or not a plain seconds value.
fn retry_after_seconds(response: &Response) -> Option<u64> {
    response
        .header(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
}

/// On-demand initialization for an authenticated diagnostic request. The gate
/// returns 503 with `Retry-After` immediately and fires the activation trigger
/// in the background. The endpoint leaves the 503 state once that completes.
/// [[ itest~deferred-on-demand-pending, On-demand requests report pending before activation completes, itest ]]
#[tokio::test]
async fn on_demand_diagnostic_path_returns_503_then_200() {
    let test_env = TestEnv::builder()
        .with_cda_communication_settings(on_demand_communication())
        .await
        .expect("Failed to set up the test environment");
    send_cda_request(
        &test_env.config,
        APPS_SOVD2UDS_DATA_VERSION,
        StatusCode::OK,
        Method::GET,
        None,
        None,
        None,
    )
    .await
    .expect("non-ECU endpoints must remain available while communication is deferred");

    // The request must return 503 immediately rather than block through
    // the full activation sequence.
    let response = send_authenticated_cda_request(
        &test_env,
        COMPONENTS_FLXC1000_DATA,
        StatusCode::SERVICE_UNAVAILABLE,
        Method::GET,
        None,
        None,
    )
    .await
    .expect("Expected 503 before the background activation trigger completes");

    // Retry-After must equal the configured value.
    assert_eq!(
        retry_after_seconds(&response),
        Some(ON_DEMAND_RETRY_AFTER_SECONDS),
        "Retry-After must equal the configured value"
    );

    let body: ApiErrorResponse<String> =
        response_to_t(&response).expect("failed to parse the error body");
    assert_eq!(body.error_code, ErrorCode::VendorSpecific);
    assert_eq!(body.vendor_code.as_deref(), Some("communication-not-ready"));

    // The gate's own request fired the trigger. Poll until it completes.
    let response = poll_while(
        &test_env,
        COMPONENTS_FLXC1000_DATA,
        StatusCode::SERVICE_UNAVAILABLE,
        Duration::from_secs(30),
    )
    .await
    .expect("endpoint stayed pending");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "endpoint must return 200 once the background activation completes"
    );
}

/// The CDA sends no diagnostic request to the ECU until an authenticated
/// diagnostic request authorizes the first activation.
/// [[ itest~deferred-on-demand-uds-silence, On-demand startup sends no UDS request before an authorized trigger, itest ]]
#[tokio::test]
async fn on_demand_trigger_produces_no_doip_traffic_before_authorized_request() {
    if skip_unless(Transport::uses_doip, "asserts on recorded DoIP frames") {
        return;
    }
    // Record from before the CDA starts, to catch startup traffic.
    let mut test_env = TestEnv::builder()
        .with_cda_communication_settings(on_demand_communication())
        .with_recording_for_ecu(ECU_FLXC1000)
        .await
        .expect("Failed to set up the test environment");

    // The CDA is started. Check for traffic before any authenticated
    // request.
    let recorded_frames = test_env
        .recorder(ECU_FLXC1000)
        .stop()
        .await
        .expect("Failed to stop recording");

    // No diagnostic request yet, so it must be silent on the network.
    assert!(
        recorded_frames.is_empty(),
        "Unexpected DoIP traffic before the authorized trigger: {recorded_frames:?}",
    );

    // Record again across the trigger, so that a recorder which never
    // captures anything cannot satisfy the assertion above.
    let recorder = test_env
        .record(ECU_FLXC1000)
        .await
        .expect("Failed to restart recording");

    // The first authenticated diagnostic request is the only authorized
    // trigger. It fires the activation in the background, so poll until
    // the guard lifts.
    let response = poll_while(
        &test_env,
        COMPONENTS_FLXC1000_DATA,
        StatusCode::SERVICE_UNAVAILABLE,
        Duration::from_secs(30),
    )
    .await
    .expect("endpoint stayed pending");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "endpoint must return 200 once the background activation completes"
    );

    // The same recorder that saw nothing before must now see traffic.
    let recorded_frames = recorder.stop().await.expect("Failed to stop recording");
    assert!(
        !recorded_frames.is_empty(),
        "expected DoIP traffic after the authorized trigger, but the recording was empty"
    );
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
/// [[ itest~deferred-post-update, Deferred post-update mode requires communication reactivation, itest ]]
#[tokio::test]
async fn post_update_deferred_mode_returns_503_until_triggered() {
    // Step a: deferred mode with PostUpdateCommunicationMode::Deferred, and the
    // default plugin, so the first request triggers initialization.
    let test_env = TestEnv::builder()
        .with_cda_communication_settings(CommunicationSettings {
            post_update_mode: PostUpdateCommunicationMode::Deferred,
            ..on_demand_communication()
        })
        .await
        .expect("Failed to set up the test environment");

    // Step b: trigger initialization by sending an authenticated diagnostic
    // request and waiting until the guard exits the 503 state.
    let response = poll_while(
        &test_env,
        COMPONENTS_FLXC1000_DATA,
        StatusCode::SERVICE_UNAVAILABLE,
        Duration::from_secs(30),
    )
    .await
    .expect("endpoint stayed pending");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "endpoint must return 200 once the background activation completes"
    );

    // Step c: perform a runtime update. Mutating runtime files needs a
    // vehicle lock. The update and the lock go with the CDA container when
    // the lease ends.
    runtimefiles::setup_with_lock(&test_env).await;

    // The update starts from the running databases, so re-uploading one of
    // them keeps this update from changing the "vehicle".
    let response = runtimefiles::upload_mdd(&test_env).await;
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "Failed to upload the database for the update"
    );

    runtimefiles::execute_mode(&test_env, ExecutionMode::Apply)
        .await
        .expect("Apply execution failed");

    // Step d: the update dropped the disable lease instead of releasing
    // it, so the diagnostic path answers 503 again. A non-deferred
    // post-update mode would have served 200 here.
    let response = poll_while(
        &test_env,
        COMPONENTS_FLXC1000_DATA,
        StatusCode::CONFLICT,
        Duration::from_secs(30),
    )
    .await
    .expect("update protection was not lifted");
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "diagnostic endpoint must return 503 again after a Deferred post-update: {response:?}"
    );
    assert_eq!(
        retry_after_seconds(&response),
        Some(ON_DEMAND_RETRY_AFTER_SECONDS),
        "Retry-After must equal the configured value"
    );

    // Step e: that request fired the trigger again. Poll until it
    // completes.
    let response = poll_while(
        &test_env,
        COMPONENTS_FLXC1000_DATA,
        StatusCode::SERVICE_UNAVAILABLE,
        Duration::from_secs(30),
    )
    .await
    .expect("endpoint stayed pending");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "endpoint must return 200 once the post-update activation completes"
    );
}

/// In `init_mode = Disabled` an ordinary authenticated diagnostic request
/// must never trigger activation or send a diagnostic request to the ECU.
/// [[ itest~deferred-disabled-uds-silence, Disabled mode rejects request activation and sends no UDS request, itest ]]
#[tokio::test]
async fn disabled_mode_never_activates_or_produces_traffic() {
    if skip_unless(Transport::uses_doip, "asserts on recorded DoIP frames") {
        return;
    }

    // Record from before the CDA starts, to catch startup traffic.
    let mut test_env = TestEnv::builder()
        .with_cda_communication_settings(CommunicationSettings {
            init_mode: CommunicationInitMode::Disabled,
            ..CommunicationSettings::default()
        })
        .with_recording_for_ecu(ECU_FLXC1000)
        .await
        .expect("Failed to set up the test environment");

    // Nothing is authorized to bring the vehicle network up, so the CDA
    // must be as silent at startup as an OnDemand instance.
    let recorded_frames = test_env
        .recorder(ECU_FLXC1000)
        .stop()
        .await
        .expect("Failed to stop recording");
    assert!(
        recorded_frames.is_empty(),
        "Unexpected DoIP traffic before any request under Disabled: {recorded_frames:?}",
    );

    let recorder = test_env
        .record(ECU_FLXC1000)
        .await
        .expect("Failed to restart recording");

    // OnDemand resolves to 200 well inside this window. Disabled must
    // never leave the pending state.
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(3))
        .expect("deadline does not overflow");
    while Instant::now() < deadline {
        send_authenticated_cda_request(
            &test_env,
            COMPONENTS_FLXC1000_DATA,
            StatusCode::SERVICE_UNAVAILABLE,
            Method::GET,
            None,
            None,
        )
        .await
        .expect("Disabled must never authorize activation from an ordinary request");
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(200)).await;
    }

    // Every rejected request must also have produced zero
    // vehicle-network traffic.
    let recorded_frames = recorder.stop().await.expect("Failed to stop recording");
    assert!(
        recorded_frames.is_empty(),
        "Disabled must produce zero vehicle-network traffic, got: {recorded_frames:?}",
    );
}

/// The SOVD variant state of the ECU at `ecu_endpoint`.
async fn ecu_variant_state(
    test_env: &TestEnv,
    ecu_endpoint: &str,
) -> sovd_interfaces::components::ecu::State {
    ecu_status(test_env, ecu_endpoint)
        .await
        .expect("Failed to get ecu component")
        .variant
        .state
}

/// Polls `ecu_endpoint`'s variant state until it matches `expected`, or
/// panics once `timeout` elapses.
///
/// Not `wait_for_ecus_online`, which waits for `networkstructure` to reach
/// `"Online"` or `"Duplicate"`. That only happens once a variant has been
/// detected, so under `variant_detection = Never` it would hang.
async fn wait_for_ecu_variant_state(
    test_env: &TestEnv,
    ecu_endpoint: &str,
    expected: sovd_interfaces::components::ecu::State,
    timeout: Duration,
) -> sovd_interfaces::components::ecu::State {
    let deadline = Instant::now()
        .checked_add(timeout)
        .expect("deadline does not overflow");
    loop {
        let state = ecu_variant_state(test_env, ecu_endpoint).await;
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

/// `variant_detection = Never` must still bring the transport up under `Always`
/// `init_mode`, but must never settle any ECU's variant via the automatic
/// whole-vehicle variant detection. A manual per-ECU trigger (see
/// [`force_variant_detection`]) still works, because it bypasses that path.
/// [[ itest~variant-detection-explicit, Disabled automatic variant detection permits an explicit ECU trigger, itest ]]
#[tokio::test]
async fn variant_detection_never_requires_explicit_trigger() {
    // The only CDA of the test runs with variant_detection = Never from its
    // start.
    let test_env = TestEnv::builder()
        .with_cda_communication_settings(CommunicationSettings {
            variant_detection: VariantDetectionMode::Never,
            ..CommunicationSettings::default()
        })
        .await
        .expect("Failed to start CDA with variant_detection = Never");

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
        if Transport::from_env() == Transport::Can {
            sovd_interfaces::components::ecu::State::Offline
        } else {
            sovd_interfaces::components::ecu::State::NotTested
        }
    };
    wait_for_ecu_variant_state(
        &test_env,
        COMPONENTS_FLXC1000_BASE,
        undetected_state(),
        Duration::from_secs(10),
    )
    .await;

    // Give the absent detector the window it would have had under Always,
    // then confirm the state never moved on its own.
    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(2)).await;
    let state = ecu_variant_state(&test_env, COMPONENTS_FLXC1000_BASE).await;
    assert_eq!(
        state,
        undetected_state(),
        "variant_detection = Never must not auto-detect a variant"
    );

    // A manual per-ECU trigger bypasses the gated variant detection and
    // must settle the variant as it would under Always.
    force_variant_detection(&test_env, COMPONENTS_FLXC1000_BASE)
        .await
        .expect("Failed to trigger variant detection");
    let state = ecu_variant_state(&test_env, COMPONENTS_FLXC1000_BASE).await;
    assert_eq!(
        state,
        sovd_interfaces::components::ecu::State::Online,
        "a manual per-ECU trigger must still settle the variant under variant_detection = Never"
    );
}
