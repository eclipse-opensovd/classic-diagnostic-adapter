/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */
use std::time::Duration;

use http::{Method, StatusCode};
use sovd_interfaces::components::ecu::faults::Fault;

use crate::{
    sovd::{
        self, delete_all_faults, delete_fault,
        ecu::{get_dtc_setting, switch_session},
        get_fault, get_faults, locks, set_dtc_setting,
    },
    util::{
        ecusim::{self, DtcMinimal},
        http::{auth_header, extract_field_from_json, response_to_json, send_cda_request},
        runtime::setup_integration_test,
    },
};

#[tokio::test]
#[allow(clippy::too_many_lines)] // keep test together.
async fn test_dtc_setting() {
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();
    let auth = auth_header(&runtime.config, None).await.unwrap();
    let ecu_endpoint = sovd::ECU_FLXC1000_ENDPOINT;

    // Without lock, the CDA should reject the request
    let dtcs_on = "on";
    set_dtc_setting(
        dtcs_on,
        &runtime.config,
        &auth,
        ecu_endpoint,
        StatusCode::FORBIDDEN,
    )
    .await
    .unwrap();

    // Create and acquire lock
    // Duration::from_mins is only available in rust >= 1.91.0, we want to support 1.88.0
    #[allow(unknown_lints, clippy::duration_suboptimal_units)]
    let expiration_timeout = Duration::from_secs(60);
    let ecu_lock = locks::create_lock(
        expiration_timeout,
        locks::ECU_ENDPOINT,
        StatusCode::CREATED,
        &runtime.config,
        &auth,
    )
    .await;
    let lock_id =
        extract_field_from_json::<String>(&response_to_json(&ecu_lock).unwrap(), "id").unwrap();

    // Test DTC Setting On - without setting session first, this should be not possible
    // as the service has a state precondition for Session == "Extended"
    let _ = set_dtc_setting(
        dtcs_on,
        &runtime.config,
        &auth,
        ecu_endpoint,
        StatusCode::BAD_REQUEST,
    )
    .await;

    switch_session(
        "extended",
        &runtime.config,
        &auth,
        ecu_endpoint,
        StatusCode::OK,
    )
    .await
    .unwrap();

    // Test DTC Setting On, after switching to extended session, should work now.
    // Test remaining services without switching sessions.
    let result = set_dtc_setting(
        dtcs_on,
        &runtime.config,
        &auth,
        ecu_endpoint,
        StatusCode::OK,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(result.value.to_ascii_lowercase(), dtcs_on);

    let current_setting = get_dtc_setting(&runtime.config, &auth, ecu_endpoint)
        .await
        .unwrap();
    assert_eq!(
        current_setting.value.as_ref().map(|s| s.to_lowercase()),
        Some(dtcs_on.to_owned())
    );

    // Validate that ECU sim received and stored the DTC setting
    let ecu_state = ecusim::get_ecu_state(&runtime.ecu_sim, "flxc1000")
        .await
        .expect("Failed to get ECU sim state");
    assert_eq!(
        ecu_state.dtc_setting_type,
        Some(ecusim::DtcSettingType::On),
        "ECU sim did not store the correct DTC setting type"
    );

    // Test DTC Setting Off
    let dtcs_off = "off";
    let result = set_dtc_setting(
        dtcs_off,
        &runtime.config,
        &auth,
        ecu_endpoint,
        StatusCode::OK,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(result.value.to_ascii_lowercase(), dtcs_off);

    let current_setting = get_dtc_setting(&runtime.config, &auth, ecu_endpoint)
        .await
        .unwrap();
    assert_eq!(
        current_setting.value.as_ref().map(|s| s.to_lowercase()),
        Some(dtcs_off.to_owned())
    );

    // Validate that ECU sim received and stored the DTC setting
    let ecu_state = ecusim::get_ecu_state(&runtime.ecu_sim, "flxc1000")
        .await
        .expect("Failed to get ECU sim state");
    assert_eq!(
        ecu_state.dtc_setting_type,
        Some(ecusim::DtcSettingType::Off),
        "ECU sim did not store the correct DTC setting type"
    );

    // Test DTC Setting TimeTravelDTCsOn (custom vendor-specific)
    let dtcs_time_travel = "timetraveldtcson";
    let result = set_dtc_setting(
        dtcs_time_travel,
        &runtime.config,
        &auth,
        ecu_endpoint,
        StatusCode::OK,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(result.value.to_ascii_lowercase(), dtcs_time_travel);

    let current_setting = get_dtc_setting(&runtime.config, &auth, ecu_endpoint)
        .await
        .unwrap();
    assert_eq!(
        current_setting.value.as_ref().map(|s| s.to_lowercase()),
        Some(dtcs_time_travel.to_owned())
    );

    // Validate that ECU sim received and stored the DTC setting
    let ecu_state = ecusim::get_ecu_state(&runtime.ecu_sim, "flxc1000")
        .await
        .expect("Failed to get ECU sim state");
    assert_eq!(
        ecu_state.dtc_setting_type,
        Some(ecusim::DtcSettingType::TimeTravelDtcsOn),
        "ECU sim did not store the correct DTC setting type"
    );

    // Delete the ECU lock
    locks::lock_operation(
        locks::ECU_ENDPOINT,
        Some(&lock_id),
        &runtime.config,
        &auth,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;

    // After deleting lock, we should not be able to set DTC setting
    set_dtc_setting(
        dtcs_on,
        &runtime.config,
        &auth,
        ecu_endpoint,
        StatusCode::FORBIDDEN,
    )
    .await
    .unwrap();
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // its easier to understand the test if its kept together
async fn test_dtc_deletion() {
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();
    let auth = auth_header(&runtime.config, None).await.unwrap();
    let ecu_endpoint = sovd::ECU_FLXC1000_ENDPOINT;
    let ecu_name = "flxc1000";
    let fault_memory = "Standard";

    // Create and acquire lock
    let expiration_timeout = Duration::from_secs(30);
    let ecu_lock = locks::create_lock(
        expiration_timeout,
        locks::ECU_ENDPOINT,
        StatusCode::CREATED,
        &runtime.config,
        &auth,
    )
    .await;
    let lock_id =
        extract_field_from_json::<String>(&response_to_json(&ecu_lock).unwrap(), "id").unwrap();

    // Clear any existing DTCs from the simulator
    ecusim::clear_all_dtcs(&runtime.ecu_sim, ecu_name, fault_memory)
        .await
        .expect("Failed to clear DTCs in simulator");

    // Add test DTCs to the simulator
    // DTC 1: 0x1E240 with status mask 0x29
    // (testFailed=true, confirmedDtc=true, testFailedSinceLastClear=true)
    ecusim::add_dtc(
        &runtime.ecu_sim,
        ecu_name,
        fault_memory,
        &DtcMinimal {
            id: "01E240".into(),
            status_mask: "29".into(),
            emissions_related: false,
        },
    )
    .await
    .expect("Failed to add DTC 0x01E240");

    // DTC 2: 0x39447 with status mask 0x0C (pendingDtc=true, confirmedDtc=true)
    ecusim::add_dtc(
        &runtime.ecu_sim,
        ecu_name,
        fault_memory,
        &DtcMinimal {
            id: "039447".into(),
            status_mask: "0C".into(),
            emissions_related: false,
        },
    )
    .await
    .expect("Failed to add DTC 0x039447");

    // Verify DTCs were added
    let dtcs_in_sim = ecusim::get_dtcs(&runtime.ecu_sim, ecu_name, fault_memory)
        .await
        .expect("Failed to get DTCs from simulator");
    assert_eq!(
        dtcs_in_sim.dtcs.len(),
        2,
        "Expected 2 DTCs in simulator, got {}",
        dtcs_in_sim.dtcs.len()
    );

    // Get DTCs via SOVD API
    // expect 1 failed dtc
    let faults = get_faults(&runtime.config, &auth, ecu_endpoint)
        .await
        .map(filter_failed_faults)
        .expect("Failed to get faults via SOVD");
    assert_eq!(
        faults.len(),
        1,
        "Expected 1 fault via SOVD, got {}",
        faults.len()
    );

    // Test deletion of a single DTC
    delete_fault(
        &runtime.config,
        &auth,
        ecu_endpoint,
        "01E240",
        StatusCode::NO_CONTENT,
    )
    .await
    .expect("Failed to delete fault 0x01E240");

    // Verify the DTC was deleted via ecu simulator
    let dtcs_in_sim_after_delete = ecusim::get_dtcs(&runtime.ecu_sim, ecu_name, fault_memory)
        .await
        .expect("Failed to get DTCs from simulator after deletion");

    assert_eq!(
        dtcs_in_sim_after_delete.dtcs.len(),
        1,
        "Expected 1 fault after deleting one, got {}",
        dtcs_in_sim_after_delete.dtcs.len()
    );

    // Verify the correct DTC was deleted
    let deleted_dtc_still_exists = dtcs_in_sim_after_delete
        .dtcs
        .iter()
        .any(|f| f.id == "1E240");
    assert!(
        !deleted_dtc_still_exists,
        "DTC 0x01E240 should have been deleted"
    );

    // Verify the other DTCs still exist
    let second_dtc_still_exists = dtcs_in_sim_after_delete
        .dtcs
        .iter()
        .any(|f| f.id == "39447");
    assert!(second_dtc_still_exists, "DTC 0x039447 should still exist");

    // Verify that the DTCs are not set to failed in the SOVD API
    let fault_1 = get_fault(&runtime.config, &auth, ecu_endpoint, "01E240")
        .await
        .expect("Failed to get SOVD status for fault 0x01E240");

    let fault_1_failed = fault_1.status.and_then(|status| status.test_failed);
    assert_eq!(
        fault_1_failed,
        Some(false),
        "Expected 0x01E240 to have status test_failed 'false' after deletion, but got \
         {fault_1_failed:?}"
    );

    // Test deletion of all DTCs
    delete_all_faults(&runtime.config, &auth, ecu_endpoint, StatusCode::NO_CONTENT)
        .await
        .expect("Failed to delete all faults");

    // Verify all DTCs were deleted via SOVD API
    let dtcs_after_delete_all = ecusim::get_dtcs(&runtime.ecu_sim, ecu_name, fault_memory)
        .await
        .expect("Failed to get DTCs from simulator after delete all");
    assert_eq!(
        dtcs_after_delete_all.dtcs.len(),
        0,
        "Expected 0 DTCs after deleting all, got {}",
        dtcs_after_delete_all.dtcs.len()
    );

    // Test deletion without lock (should fail)
    locks::lock_operation(
        locks::ECU_ENDPOINT,
        Some(&lock_id),
        &runtime.config,
        &auth,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;

    // Add a DTC for testing deletion without lock
    ecusim::add_dtc(
        &runtime.ecu_sim,
        ecu_name,
        fault_memory,
        &DtcMinimal {
            id: "999999".into(),
            status_mask: "01".into(),
            emissions_related: false,
        },
    )
    .await
    .expect("Failed to add DTC for lock test");

    // Attempt to delete without lock - should fail
    delete_fault(
        &runtime.config,
        &auth,
        ecu_endpoint,
        "999999",
        StatusCode::FORBIDDEN,
    )
    .await
    .expect("Request should be forbidden");

    // Verify the DTC was NOT deleted
    let dtcs_after_forbidden = ecusim::get_dtcs(&runtime.ecu_sim, ecu_name, fault_memory)
        .await
        .expect("Failed to get DTCs from simulator after forbidden deletion");
    assert_eq!(
        dtcs_after_forbidden.dtcs.len(),
        1,
        "Expected 1 fault to remain after forbidden deletion"
    );
}

/// Test GET /faults and GET /faults/{fault-code} with various DTC mask scenarios
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_get_faults_with_different_dtc_masks() {
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();
    let auth = auth_header(&runtime.config, None).await.unwrap();
    let ecu_endpoint = sovd::ECU_FLXC1000_ENDPOINT;
    let ecu_name = "flxc1000";
    let fault_memory = "Standard";

    // Clear any existing DTCs from the simulator
    ecusim::clear_all_dtcs(&runtime.ecu_sim, ecu_name, fault_memory)
        .await
        .expect("Failed to clear DTCs in simulator");

    // Scenario 1: Test with testFailed=true, confirmedDtc=true, testFailedSinceLastClear=true
    // Status mask: 0x29 (binary: 00101001)
    // Bit 0 (testFailed) = 1
    // Bit 3 (confirmedDtc) = 1
    // Bit 5 (testFailedSinceLastClear) = 1
    let dtc1 = DtcMinimal {
        id: "01E240".into(),
        status_mask: "29".into(),
        emissions_related: false,
    };
    ecusim::add_dtc(&runtime.ecu_sim, ecu_name, fault_memory, &dtc1)
        .await
        .expect("Failed to add DTC 0x01E240");

    // Scenario 2: Test with pendingDtc=true, confirmedDtc=true
    // Status mask: 0x0C (binary: 00001100)
    // Bit 2 (pendingDtc) = 1
    // Bit 3 (confirmedDtc) = 1
    let dtc2 = DtcMinimal {
        id: "039447".into(),
        status_mask: "0C".into(),
        emissions_related: false,
    };
    ecusim::add_dtc(&runtime.ecu_sim, ecu_name, fault_memory, &dtc2)
        .await
        .expect("Failed to add DTC 0x039447");

    // Scenario 3: Test with all status flags set
    // Status mask: 0xFF (binary: 11111111)
    let dtc3 = DtcMinimal {
        id: "01E241".into(),
        status_mask: "FF".into(),
        emissions_related: false,
    };
    ecusim::add_dtc(&runtime.ecu_sim, ecu_name, fault_memory, &dtc3)
        .await
        .expect("Failed to add DTC 0x01E241");

    // Scenario 4: Test with no status flags set
    // Status mask: 0x00 (binary: 00000000)
    let dtc4 = DtcMinimal {
        id: "01E242".into(),
        status_mask: "00".into(),
        emissions_related: false,
    };
    ecusim::add_dtc(&runtime.ecu_sim, ecu_name, fault_memory, &dtc4)
        .await
        .expect("Failed to add DTC 01E242");

    // Scenario 5: Test with testFailed=true, testFailedThisOperationCycle=true
    // Status mask: 0x03 (binary: 00000011)
    // Bit 0 (testFailed) = 1
    // Bit 1 (testFailedThisOperationCycle) = 1
    let dtc5 = DtcMinimal {
        id: "01E243".into(),
        status_mask: "03".into(),
        emissions_related: false,
    };
    ecusim::add_dtc(&runtime.ecu_sim, ecu_name, fault_memory, &dtc5)
        .await
        .expect("Failed to add DTC 0x01E243");

    // Scenario 6: Test with warningIndicatorRequested=true
    // Status mask: 0x80 (binary: 10000000)
    // Bit 7 (warningIndicatorRequested) = 1
    let dtc6 = DtcMinimal {
        id: "01E244".into(),
        status_mask: "80".into(),
        emissions_related: false,
    };
    ecusim::add_dtc(&runtime.ecu_sim, ecu_name, fault_memory, &dtc6)
        .await
        .expect("Failed to add DTC 0x01E244");

    // Verify all DTCs were added in the simulator
    let dtcs_in_sim = ecusim::get_dtcs(&runtime.ecu_sim, ecu_name, fault_memory)
        .await
        .expect("Failed to get DTCs from simulator");
    assert_eq!(
        dtcs_in_sim.dtcs.len(),
        6,
        "Expected 6 DTCs in simulator, got {}",
        dtcs_in_sim.dtcs.len()
    );

    // Test GET /faults - should return all 6 faults
    let faults = get_faults(&runtime.config, &auth, ecu_endpoint)
        .await
        .expect("Failed to get faults via SOVD");
    assert_eq!(
        faults.len(),
        6,
        "Expected 6 faults via SOVD, got {}",
        faults.len()
    );

    // Verify DTC1 (0x01E240) - status mask 0x29
    let fault1 = get_fault(&runtime.config, &auth, ecu_endpoint, "01E240")
        .await
        .expect("Failed to get fault 0x01E240");
    assert_eq!(fault1.code, "01E240");
    let status1 = fault1.status.expect("Status should be present for DTC1");
    assert_eq!(
        status1.test_failed,
        Some(true),
        "DTC1: testFailed should be true"
    );
    assert_eq!(
        status1.confirmed_dtc,
        Some(true),
        "DTC1: confirmedDtc should be true"
    );
    assert_eq!(
        status1.test_failed_since_last_clear,
        Some(true),
        "DTC1: testFailedSinceLastClear should be true"
    );
    assert_eq!(
        status1.pending_dtc,
        Some(false),
        "DTC1: pendingDtc should be false"
    );
    assert_eq!(
        status1.mask,
        Some("29".to_string()),
        "DTC1: mask should be 29"
    );

    // Verify DTC2 (0x039447) - status mask 0x0C
    let fault2 = get_fault(&runtime.config, &auth, ecu_endpoint, "039447")
        .await
        .expect("Failed to get fault 0x039447");
    assert_eq!(fault2.code, "039447");
    let status2 = fault2.status.expect("Status should be present for DTC2");
    assert_eq!(
        status2.pending_dtc,
        Some(true),
        "DTC2: pendingDtc should be true"
    );
    assert_eq!(
        status2.confirmed_dtc,
        Some(true),
        "DTC2: confirmedDtc should be true"
    );
    assert_eq!(
        status2.test_failed,
        Some(false),
        "DTC2: testFailed should be false"
    );
    assert_eq!(
        status2.test_failed_since_last_clear,
        Some(false),
        "DTC2: testFailedSinceLastClear should be false"
    );
    assert_eq!(
        status2.mask,
        Some("0C".to_string()),
        "DTC2: mask should be 0C"
    );

    // Verify DTC3 (0x01E241) - status mask 0xFF (all flags set)
    let fault3 = get_fault(&runtime.config, &auth, ecu_endpoint, "01E241")
        .await
        .expect("Failed to get fault 0x01E241");
    assert_eq!(fault3.code, "01E241");
    let status3 = fault3.status.expect("Status should be present for DTC3");
    assert_eq!(
        status3.test_failed,
        Some(true),
        "DTC3: testFailed should be true"
    );
    assert_eq!(
        status3.test_failed_this_operation_cycle,
        Some(true),
        "DTC3: testFailedThisOperationCycle should be true"
    );
    assert_eq!(
        status3.pending_dtc,
        Some(true),
        "DTC3: pendingDtc should be true"
    );
    assert_eq!(
        status3.confirmed_dtc,
        Some(true),
        "DTC3: confirmedDtc should be true"
    );
    assert_eq!(
        status3.test_not_completed_since_last_clear,
        Some(true),
        "DTC3: testNotCompletedSinceLastClear should be true"
    );
    assert_eq!(
        status3.test_failed_since_last_clear,
        Some(true),
        "DTC3: testFailedSinceLastClear should be true"
    );
    assert_eq!(
        status3.test_not_completed_this_operation_cycle,
        Some(true),
        "DTC3: testNotCompletedThisOperationCycle should be true"
    );
    assert_eq!(
        status3.warning_indicator_requested,
        Some(true),
        "DTC3: warningIndicatorRequested should be true"
    );
    assert_eq!(
        status3.mask,
        Some("FF".to_string()),
        "DTC3: mask should be FF"
    );

    // Verify DTC4 (0x01E242) - status mask 0x00 (no flags set)
    let fault4 = get_fault(&runtime.config, &auth, ecu_endpoint, "01E242")
        .await
        .expect("Failed to get fault 0x01E242");
    assert_eq!(fault4.code, "01E242");
    let status4 = fault4.status.expect("Status should be present for DTC4");
    assert_eq!(
        status4.test_failed,
        Some(false),
        "DTC4: testFailed should be false"
    );
    assert_eq!(
        status4.test_failed_this_operation_cycle,
        Some(false),
        "DTC4: testFailedThisOperationCycle should be false"
    );
    assert_eq!(
        status4.pending_dtc,
        Some(false),
        "DTC4: pendingDtc should be false"
    );
    assert_eq!(
        status4.confirmed_dtc,
        Some(false),
        "DTC4: confirmedDtc should be false"
    );
    assert_eq!(
        status4.test_not_completed_since_last_clear,
        Some(false),
        "DTC4: testNotCompletedSinceLastClear should be false"
    );
    assert_eq!(
        status4.test_failed_since_last_clear,
        Some(false),
        "DTC4: testFailedSinceLastClear should be false"
    );
    assert_eq!(
        status4.test_not_completed_this_operation_cycle,
        Some(false),
        "DTC4: testNotCompletedThisOperationCycle should be false"
    );
    assert_eq!(
        status4.warning_indicator_requested,
        Some(false),
        "DTC4: warningIndicatorRequested should be false"
    );
    assert_eq!(
        status4.mask,
        Some("00".to_string()),
        "DTC4: mask should be 00"
    );

    // Verify DTC5 (0x01E243) - status mask 0x03
    let fault5 = get_fault(&runtime.config, &auth, ecu_endpoint, "01E243")
        .await
        .expect("Failed to get fault 0x01E243");
    assert_eq!(fault5.code, "01E243");
    let status5 = fault5.status.expect("Status should be present for DTC5");
    assert_eq!(
        status5.test_failed,
        Some(true),
        "DTC5: testFailed should be true"
    );
    assert_eq!(
        status5.test_failed_this_operation_cycle,
        Some(true),
        "DTC5: testFailedThisOperationCycle should be true"
    );
    assert_eq!(
        status5.pending_dtc,
        Some(false),
        "DTC5: pendingDtc should be false"
    );
    assert_eq!(
        status5.confirmed_dtc,
        Some(false),
        "DTC5: confirmedDtc should be false"
    );
    assert_eq!(
        status5.mask,
        Some("03".to_string()),
        "DTC5: mask should be 03"
    );

    // Verify DTC6 (0x01E244) - status mask 0x80
    let fault6 = get_fault(&runtime.config, &auth, ecu_endpoint, "01E244")
        .await
        .expect("Failed to get fault 0x01E244");
    assert_eq!(fault6.code, "01E244");
    let status6 = fault6.status.expect("Status should be present for DTC6");
    assert_eq!(
        status6.warning_indicator_requested,
        Some(true),
        "DTC6: warningIndicatorRequested should be true"
    );
    assert_eq!(
        status6.test_failed,
        Some(false),
        "DTC6: testFailed should be false"
    );
    assert_eq!(
        status6.confirmed_dtc,
        Some(false),
        "DTC6: confirmedDtc should be false"
    );
    assert_eq!(
        status6.mask,
        Some("80".to_string()),
        "DTC6: mask should be 80"
    );

    // Clean up - clear all DTCs
    ecusim::clear_all_dtcs(&runtime.ecu_sim, ecu_name, fault_memory)
        .await
        .expect("Failed to clear DTCs in simulator");

    // Verify no faults remain
    let failed_faults_after_clear = get_faults(&runtime.config, &auth, ecu_endpoint)
        .await
        .map(filter_failed_faults)
        .expect("Failed to get faults after clear");
    assert_eq!(
        failed_faults_after_clear.len(),
        0,
        "Expected 0 faults after clear, got {}",
        failed_faults_after_clear.len()
    );
}

/// Test GET /faults/{fault-code} with non-existent fault code
#[tokio::test]
async fn test_get_nonexistent_fault() {
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();
    let auth = auth_header(&runtime.config, None).await.unwrap();
    let ecu_endpoint = sovd::ECU_FLXC1000_ENDPOINT;
    let ecu_name = "flxc1000";
    let fault_memory = "Standard";

    // Clear any existing DTCs
    ecusim::clear_all_dtcs(&runtime.ecu_sim, ecu_name, fault_memory)
        .await
        .expect("Failed to clear DTCs in simulator");

    // Try to get a fault that doesn't exist - should return 400
    let path = format!("{ecu_endpoint}/faults/FFFFFF");
    let response = send_cda_request(
        &runtime.config,
        &path,
        StatusCode::BAD_REQUEST,
        Method::GET,
        None,
        Some(&auth),
    )
    .await;

    assert!(
        response.is_ok(),
        "Should return a BAD_REQUEST response for non-existent fault, but got {:?}",
        response.err(),
    );
}

/// Test GET /faults with empty fault memory
#[tokio::test]
async fn test_get_faults_empty() {
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();
    let auth = auth_header(&runtime.config, None).await.unwrap();
    let ecu_endpoint = sovd::ECU_FLXC1000_ENDPOINT;
    let ecu_name = "flxc1000";
    let fault_memory = "Standard";

    // Clear all DTCs
    ecusim::clear_all_dtcs(&runtime.ecu_sim, ecu_name, fault_memory)
        .await
        .expect("Failed to clear DTCs in simulator");

    // Get faults - should return no faults with test_failed==true
    let faults = get_faults(&runtime.config, &auth, ecu_endpoint)
        .await
        .map(filter_failed_faults)
        .expect("Failed to get faults");
    assert_eq!(
        faults.len(),
        0,
        "Expected 0 failed faults when fault memory is empty, got {}",
        faults.len()
    );
}

fn filter_failed_faults(faults: Vec<Fault>) -> Vec<Fault> {
    faults
        .into_iter()
        .filter(|fault| fault.status.as_ref().and_then(|s| s.test_failed) == Some(true))
        .collect::<Vec<_>>()
}
