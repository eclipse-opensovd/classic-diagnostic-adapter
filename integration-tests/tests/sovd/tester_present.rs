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

use std::time::Duration;

use http::{Method, StatusCode};

use crate::{
    sovd::{
        self,
        ecu::switch_session,
        locks::{ECU_ENDPOINT as ECU_LOCK_ENDPOINT, create_lock, lock_operation},
    },
    util::{
        TestingError, ecusim,
        http::{auth_header, extract_field_from_json, response_to_json, send_cda_request},
        runtime::{setup_integration_test, wait_for_ecus_online},
    },
};

const ECU_SIM_NAME: &str = "flxc1000";

/// Tester Present frame: SID 0x3E with suppressPositiveResponse bit set (0x80)
const TESTER_PRESENT_FRAME: &str = "3e80";

/// Verifies that Tester Present frames (0x3E 0x80) are sent to the ECU while
/// an ECU lock is held.
///
/// The SOVD specification requires that acquiring a lock on an ECU starts
/// periodic Tester Present messages to keep the diagnostic session alive.
/// This test reproduces a scenario where Tester Present frames were observed
/// to be missing despite an active lock.
#[tokio::test]
async fn tester_present_sent_while_ecu_lock_held() -> Result<(), TestingError> {
    let (runtime, _exclusive) = setup_integration_test(true).await?;
    wait_for_ecus_online(&runtime.config).await?;
    let auth = auth_header(&runtime.config, None).await?;

    // Start recording UDS frames on the ECU simulator before creating the lock
    // so we capture even the very first Tester Present frame.
    ecusim::start_recording(&runtime.ecu_sim, ECU_SIM_NAME)
        .await
        .expect("failed to start ECU sim recording");

    // Create an ECU lock - this should trigger Tester Present to start
    let lock_response = create_lock(
        Duration::from_secs(100),
        ECU_LOCK_ENDPOINT,
        StatusCode::CREATED,
        &runtime.config,
        &auth,
    )
    .await;
    let lock_id = extract_field_from_json::<String>(&response_to_json(&lock_response)?, "id")?;

    // Wait long enough for multiple Tester Present intervals.
    // Default TP interval is 2 seconds; waiting 5 seconds should yield at least 2 frames.
    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(5)).await;

    // Stop recording and collect all UDS frames received by the ECU simulator
    let recorded_frames = ecusim::stop_and_clear_recording(&runtime.ecu_sim, ECU_SIM_NAME)
        .await
        .expect("failed to stop ECU sim recording");

    // Cleanup: delete the lock regardless of the assertion outcome
    let _ = lock_operation(
        ECU_LOCK_ENDPOINT,
        Some(&lock_id),
        &runtime.config,
        &auth,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;

    // Assert that at least one Tester Present frame was received
    let tp_count = recorded_frames
        .iter()
        .filter(|frame| frame.eq_ignore_ascii_case(TESTER_PRESENT_FRAME))
        .count();

    assert!(
        tp_count > 0,
        "Expected at least one Tester Present frame ({TESTER_PRESENT_FRAME}) to be sent while ECU \
         lock is held, but none were found in 5s of recording.\nRecorded frames: \
         {recorded_frames:?}",
    );

    Ok(())
}

/// Verifies that Tester Present frames continue to be sent after switching to
/// a programming session while the ECU lock is held.
///
/// The expectation is that Tester Present continues regardless of session changes
/// as long as the lock is held.
#[tokio::test]
async fn tester_present_sent_after_programming_session_switch() -> Result<(), TestingError> {
    let (runtime, _exclusive) = setup_integration_test(true).await?;
    wait_for_ecus_online(&runtime.config).await?;
    let auth = auth_header(&runtime.config, None).await?;
    let ecu_endpoint = sovd::ECU_FLXC1000_ENDPOINT;

    // Create an ECU lock - this should trigger Tester Present to start
    let lock_response = create_lock(
        Duration::from_secs(100),
        ECU_LOCK_ENDPOINT,
        StatusCode::CREATED,
        &runtime.config,
        &auth,
    )
    .await;
    let lock_id = extract_field_from_json::<String>(&response_to_json(&lock_response)?, "id")?;

    // Switch the ECU sim to BOOT variant (simulates ECU going into bootloader)
    ecusim::switch_variant(&runtime.ecu_sim, "FLXC1000", "BOOT")
        .await
        .expect("failed to switch ECU sim to BOOT variant");

    // Force variant detection so the CDA picks up the boot variant
    send_cda_request(
        &runtime.config,
        ecu_endpoint,
        StatusCode::CREATED,
        Method::PUT,
        None,
        Some(&auth),
        None,
    )
    .await
    .expect("failed to trigger variant detection");

    // Switch to programming session
    switch_session(
        "programming",
        &runtime.config,
        &auth,
        ecu_endpoint,
        StatusCode::OK,
    )
    .await
    .expect("failed to switch to programming session");

    // Now start recording after the session switch to isolate the issue:
    // We want to verify that TP continues to be sent in the new session state.
    ecusim::start_recording(&runtime.ecu_sim, ECU_SIM_NAME)
        .await
        .expect("failed to start ECU sim recording");

    // Wait long enough for multiple Tester Present intervals.
    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(5)).await;

    // Stop recording and collect all UDS frames received by the ECU simulator
    let recorded_frames = ecusim::stop_and_clear_recording(&runtime.ecu_sim, ECU_SIM_NAME)
        .await
        .expect("failed to stop ECU sim recording");

    // Cleanup: switch back to application variant and delete the lock
    ecusim::switch_variant(&runtime.ecu_sim, "FLXC1000", "APPLICATION")
        .await
        .expect("failed to switch ECU sim back to APPLICATION variant");

    // Force variant re-detection
    let _ = send_cda_request(
        &runtime.config,
        ecu_endpoint,
        StatusCode::CREATED,
        Method::PUT,
        None,
        Some(&auth),
        None,
    )
    .await;

    let _ = lock_operation(
        ECU_LOCK_ENDPOINT,
        Some(&lock_id),
        &runtime.config,
        &auth,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;

    // Assert that at least one Tester Present frame was received after session switch
    let tp_count = recorded_frames
        .iter()
        .filter(|frame| frame.eq_ignore_ascii_case(TESTER_PRESENT_FRAME))
        .count();

    assert!(
        tp_count > 0,
        "Expected at least one Tester Present frame ({TESTER_PRESENT_FRAME}) to be sent after \
         switching to programming session while ECU lock is held, but none were found in 5s of \
         recording.\nRecorded frames: {recorded_frames:?}",
    );

    Ok(())
}

/// Verifies that Tester Present frames are sent after the ECU reconnects following
/// a `DoIP` TCP connection drop while the lock is held.
///
/// This reproduces a reconnection scenario where Tester Present could stop:
/// 1. An ECU lock is acquired (starts Tester Present)
/// 2. The `DoIP` TCP connection is forcefully closed (simulates ECU reboot / network glitch)
/// 3. The ECU re-announces itself and the CDA reconnects
/// 4. Tester Present should resume after reconnection
///
/// In this scenario, Tester Present frames may be missing after the
/// connection is re-established, which is the bug this test aims to reproduce.
#[tokio::test]
async fn tester_present_sent_after_doip_reconnection() -> Result<(), TestingError> {
    let (runtime, _exclusive) = setup_integration_test(true).await?;
    wait_for_ecus_online(&runtime.config).await?;
    let auth = auth_header(&runtime.config, None).await?;

    // Create an ECU lock - this should trigger Tester Present to start
    let lock_response = create_lock(
        Duration::from_secs(100),
        ECU_LOCK_ENDPOINT,
        StatusCode::CREATED,
        &runtime.config,
        &auth,
    )
    .await;
    let lock_id = extract_field_from_json::<String>(&response_to_json(&lock_response)?, "id")?;

    // Wait briefly to confirm TP is running before we disconnect
    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(3)).await;

    // Simulate a DoIP TCP connection drop by configuring the ECU sim to perform
    // a hard reset (which closes the TCP connection) for 5 seconds, then triggering
    // the reset via UDS ECU Reset (0x11 0x01) through the CDA's genericservice.
    ecusim::set_hard_reset_duration(&runtime.ecu_sim, "FLXC1000", 5)
        .await
        .expect("failed to set hard reset duration");

    // Send UDS ECU Reset (0x11 0x01) via genericservice - this triggers the ECU sim
    // to close the TCP connection for 5 seconds (simulating a real ECU reboot)
    let _ = send_cda_request(
        &runtime.config,
        &format!("{}/genericservice", sovd::ECU_FLXC1000_ENDPOINT),
        StatusCode::OK,
        Method::PUT,
        Some(&serde_json::json!({"request": "0x11 0x01"}).to_string()),
        Some(&auth),
        None,
    )
    .await;

    // Wait for the ECU to come back online after the hard reset (5s reset + reconnection time)
    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(10)).await;

    // Start recording AFTER reconnection to verify TP resumes
    ecusim::start_recording(&runtime.ecu_sim, ECU_SIM_NAME)
        .await
        .expect("failed to start ECU sim recording");

    // Wait for multiple TP intervals
    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(5)).await;

    // Stop recording and collect all UDS frames received by the ECU simulator
    let recorded_frames = ecusim::stop_and_clear_recording(&runtime.ecu_sim, ECU_SIM_NAME)
        .await
        .expect("failed to stop ECU sim recording");

    // Cleanup: reset hard reset duration to 0 to avoid leaking armed state into subsequent tests,
    // then delete the lock.
    let _ = ecusim::set_hard_reset_duration(&runtime.ecu_sim, "FLXC1000", 0).await;

    let _ = lock_operation(
        ECU_LOCK_ENDPOINT,
        Some(&lock_id),
        &runtime.config,
        &auth,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;

    // Assert that at least one Tester Present frame was received after reconnection
    let tp_count = recorded_frames
        .iter()
        .filter(|frame| frame.eq_ignore_ascii_case(TESTER_PRESENT_FRAME))
        .count();

    assert!(
        tp_count > 0,
        "Expected at least one Tester Present frame ({TESTER_PRESENT_FRAME}) to be sent after \
         DoIP reconnection while ECU lock is held, but none were found in 5s of recording after \
         reconnection.\nRecorded frames: {recorded_frames:?}",
    );

    Ok(())
}

/// Verifies that Tester Present frames resume after a pure network-level `DoIP` TCP disconnect
/// (not triggered by a UDS ECU Reset) while the ECU lock is held.
///
/// Unlike `tester_present_sent_after_doip_reconnection`, which uses the UDS ECU Reset path
/// to trigger a disconnect, this test calls `ecusim::disconnect` directly to simulate a
/// transient network fault (e.g., cable pull, switch reset) where the ECU itself is still
/// running. The ECU re-announces via VAMs immediately and the CDA should re-establish the
/// `DoIP` connection without any lock disruption.
///
/// Two-phase assertion:
/// 1. TP is confirmed running before the disconnect.
/// 2. TP resumes after the reconnect.
#[tokio::test]
async fn tester_present_resumes_after_network_disconnect() -> Result<(), TestingError> {
    let (runtime, _exclusive) = setup_integration_test(true).await?;
    wait_for_ecus_online(&runtime.config).await?;
    let auth = auth_header(&runtime.config, None).await?;

    // Start recording before acquiring the lock to capture the very first TP frame.
    ecusim::start_recording(&runtime.ecu_sim, ECU_SIM_NAME)
        .await
        .expect("failed to start ECU sim recording");

    // Acquire an ECU lock - this should trigger Tester Present to start.
    let lock_response = create_lock(
        Duration::from_secs(100),
        ECU_LOCK_ENDPOINT,
        StatusCode::CREATED,
        &runtime.config,
        &auth,
    )
    .await;
    let lock_id = extract_field_from_json::<String>(&response_to_json(&lock_response)?, "id")?;

    // Wait for multiple TP intervals to confirm TP is running before we disconnect.
    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(3)).await;

    let pre_disconnect_frames = ecusim::stop_and_clear_recording(&runtime.ecu_sim, ECU_SIM_NAME)
        .await
        .expect("failed to stop pre-disconnect recording");

    let pre_tp_count = pre_disconnect_frames
        .iter()
        .filter(|frame| frame.eq_ignore_ascii_case(TESTER_PRESENT_FRAME))
        .count();

    assert!(
        pre_tp_count > 0,
        "Precondition failed: expected Tester Present frames before disconnect but found none in \
         3s of recording.\nRecorded frames: {pre_disconnect_frames:?}"
    );

    // Force-close all active DoIP TCP connections - simulates a transient network fault.
    // The ECU is still running and will re-announce itself via VAMs immediately.
    ecusim::disconnect(&runtime.ecu_sim)
        .await
        .expect("failed to disconnect ECU sim");

    // Wait for the ECU to re-announce via VAM and the CDA to re-establish the DoIP connection.
    wait_for_ecus_online(&runtime.config).await?;

    // Record after reconnection to verify TP resumed.
    ecusim::start_recording(&runtime.ecu_sim, ECU_SIM_NAME)
        .await
        .expect("failed to start post-reconnect recording");

    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(10)).await;

    let post_reconnect_frames = ecusim::stop_and_clear_recording(&runtime.ecu_sim, ECU_SIM_NAME)
        .await
        .expect("failed to stop post-reconnect recording");

    // Cleanup: delete the lock.
    let _ = lock_operation(
        ECU_LOCK_ENDPOINT,
        Some(&lock_id),
        &runtime.config,
        &auth,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;

    let post_tp_count = post_reconnect_frames
        .iter()
        .filter(|frame| frame.eq_ignore_ascii_case(TESTER_PRESENT_FRAME))
        .count();

    assert!(
        post_tp_count > 0,
        "Expected at least one Tester Present frame ({TESTER_PRESENT_FRAME}) to be sent after \
         network-level DoIP disconnect while ECU lock is held, but none were found in 5s of \
         recording after reconnection.\nRecorded frames: {post_reconnect_frames:?}",
    );

    Ok(())
}
