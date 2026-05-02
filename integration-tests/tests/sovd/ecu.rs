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

use cda_interfaces::HashMap;
use http::{HeaderMap, Method, StatusCode};
use opensovd_cda_lib::config::configfile::Configuration;
use serde::de::DeserializeOwned;
use sovd_interfaces::components::ecu::modes::{self, dtcsetting};

use crate::{
    sovd::{
        self, compute_security_key, get_ecu_component,
        locks::{self, create_lock, lock_operation},
        put_mode,
    },
    util::{
        TestingError,
        ecusim::{self},
        http::{
            QueryParams, auth_header, extract_field_from_json, response_to_json, response_to_t,
            send_cda_request,
        },
        runtime::{TestRuntime, restart_cda, setup_integration_test, start_ecu_sim, stop_ecu_sim},
    },
};

#[allow(clippy::too_many_lines)] // makes sense to keep test together
#[tokio::test]
async fn test_ecu_session_switching() {
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();
    let auth = auth_header(&runtime.config, None).await.unwrap();
    let ecu_endpoint = sovd::ECU_FLXC1000_ENDPOINT;

    // We have no lock yet, thus the CDA should reject the request to send the key.
    send_key(
        "Level_5".to_owned(),
        "0x42".to_owned(),
        &runtime.config,
        &auth,
        ecu_endpoint,
        StatusCode::FORBIDDEN,
    )
    .await
    .unwrap();

    // Duration::from_mins is only available in rust >= 1.91.0, we want to support 1.88.0
    #[cfg_attr(nightly, allow(unknown_lints, clippy::duration_suboptimal_units))]
    let expiration_timeout = Duration::from_secs(60);
    let ecu_lock = create_lock(
        expiration_timeout,
        locks::ECU_ENDPOINT,
        StatusCode::CREATED,
        &runtime.config,
        &auth,
    )
    .await;
    let lock_id =
        extract_field_from_json::<String>(&response_to_json(&ecu_lock).unwrap(), "id").unwrap();

    // Lock the ECU
    lock_operation(
        locks::ECU_ENDPOINT,
        Some(&lock_id),
        &runtime.config,
        &auth,
        StatusCode::OK,
        Method::GET,
    )
    .await;

    force_variant_detection(&runtime.config, &auth, ecu_endpoint)
        .await
        .unwrap();

    let ecu = ecu_status(&runtime.config, &auth, ecu_endpoint)
        .await
        .unwrap();
    assert!(ecu.name.eq_ignore_ascii_case("flxc1000"));
    assert_eq!(ecu.variant.name, "FLXC1000_App_0101".to_string());

    switch_session(
        "this status does not exist",
        &runtime.config,
        &auth,
        ecu_endpoint,
        StatusCode::NOT_FOUND,
    )
    .await
    .unwrap();

    // Get the active diagnostic session using the Configuration GET method.
    let get_config_result = get_configurations(
        &runtime.config,
        &auth,
        ecu_endpoint,
        "activediagnosticsessiondataidentifier",
    )
    .await
    .unwrap();

    assert_eq!(
        get_config_result.id,
        "activediagnosticsessiondataidentifier"
    );
    let session_type = get_config_result
        .data
        .get("EcuSessionType")
        .and_then(|v| v.as_str())
        .expect("Missing or invalid EcuSessionType");
    assert_eq!(session_type, "Default");

    let switch_session_result = switch_session(
        "extended",
        &runtime.config,
        &auth,
        ecu_endpoint,
        StatusCode::OK,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(switch_session_result.value.to_lowercase(), "extended");
    let session_result = session(&runtime.config, &auth, ecu_endpoint).await.unwrap();
    assert_eq!(
        session_result.value.map(|s| s.to_lowercase()),
        Some("extended".to_owned())
    );
    assert_eq!(session_result.name, Some("Diagnostic session".to_owned()));

    // After switching to extended session, fetch again using configuraion GET and verify.
    let get_config_result = get_configurations(
        &runtime.config,
        &auth,
        ecu_endpoint,
        "activediagnosticsessiondataidentifier",
    )
    .await
    .unwrap();

    assert_eq!(
        get_config_result.id,
        "activediagnosticsessiondataidentifier"
    );
    let session_type = get_config_result
        .data
        .get("EcuSessionType")
        .and_then(|v| v.as_str())
        .expect("Missing or invalid EcuSessionType");
    assert_eq!(session_type, "Extended");

    // Reset the ECU using the reset service and verify the session goes back to default
    reset_ecu(
        "hardreset",
        &runtime.config,
        &auth,
        ecu_endpoint,
        StatusCode::NO_CONTENT,
    )
    .await
    .unwrap();

    let session_result_after_reset = session(&runtime.config, &auth, ecu_endpoint).await.unwrap();
    assert_eq!(
        session_result_after_reset.value.map(|s| s.to_lowercase()),
        Some("default".to_owned()),
        "Session should be back to default after hard reset"
    );

    // Switch back to extended session so the remaining test steps work
    let switch_back_result = switch_session(
        "extended",
        &runtime.config,
        &auth,
        ecu_endpoint,
        StatusCode::OK,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(switch_back_result.value.to_lowercase(), "extended");

    // switch ECU sim state to BOOT
    ecusim::switch_variant(&runtime.ecu_sim, "FLXC1000", "BOOT")
        .await
        .unwrap();
    force_variant_detection(&runtime.config, &auth, ecu_endpoint)
        .await
        .unwrap();
    let ecu = ecu_status(&runtime.config, &auth, ecu_endpoint)
        .await
        .unwrap();
    assert_eq!(ecu.variant.name, "FLXC1000_Boot_Variant".to_string());

    let seed_response = request_seed(
        "Level_5_RequestSeed".to_owned(),
        &runtime.config,
        &auth,
        ecu_endpoint,
    )
    .await
    .unwrap()
    .unwrap();

    // Key is too short
    send_key(
        "Level_5".to_owned(),
        "0x42".to_owned(),
        &runtime.config,
        &auth,
        ecu_endpoint,
        StatusCode::BAD_GATEWAY,
    )
    .await
    .unwrap();

    send_key(
        "Level_5".to_owned(),
        seed_response.seed.request_seed.clone(),
        &runtime.config,
        &auth,
        ecu_endpoint,
        StatusCode::BAD_GATEWAY,
    )
    .await
    .unwrap();

    let key = compute_security_key(&seed_response.seed.request_seed);

    send_key(
        "Level_5".to_owned(),
        key,
        &runtime.config,
        &auth,
        ecu_endpoint,
        StatusCode::OK,
    )
    .await
    .unwrap();
    let security_result = security(&runtime.config, &auth, ecu_endpoint)
        .await
        .unwrap();
    assert_eq!(security_result.value, Some("Level_5".to_owned()));
    assert_eq!(security_result.name, Some("Security access".to_owned()));

    // Delete the ECU lock
    lock_operation(
        locks::ECU_ENDPOINT,
        Some(&lock_id),
        &runtime.config,
        &auth,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;
}

#[tokio::test]
async fn test_variant_detection_duplicates() {
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();
    let auth = auth_header(&runtime.config, None).await.unwrap();

    // Switch variant, and check if the NG variant is now online.
    ecusim::switch_variant(&runtime.ecu_sim, "FLXC1000", "APPLICATION")
        .await
        .unwrap();
    let ecu = ecu_status(&runtime.config, &auth, sovd::ECU_FLXC1000_ENDPOINT)
        .await
        .unwrap();
    assert_eq!(
        ecu.variant.state,
        sovd_interfaces::components::ecu::State::Online
    );
    assert_eq!(ecu.variant.logical_address, "0x1000");

    // Switch variant, and check if the NG variant is now online.
    ecusim::switch_variant(&runtime.ecu_sim, "FLXC1000", "APPLICATION2")
        .await
        .unwrap();
    force_variant_detection(&runtime.config, &auth, sovd::ECU_FLXC1000_ENDPOINT)
        .await
        .unwrap();

    validate_ecu_state(
        runtime,
        &auth,
        sovd::ECU_FLXC1000_ENDPOINT,
        sovd_interfaces::components::ecu::State::Duplicate,
    )
    .await;

    validate_ecu_state(
        runtime,
        &auth,
        sovd::ECU_FLXCNG1000_ENDPOINT,
        sovd_interfaces::components::ecu::State::Online,
    )
    .await;

    // No variant associated with APPLICATION3, check if both ECUs are marked as NoVariantDetected
    ecusim::switch_variant(&runtime.ecu_sim, "FLXC1000", "APPLICATION3")
        .await
        .unwrap();
    force_variant_detection(&runtime.config, &auth, sovd::ECU_FLXC1000_ENDPOINT)
        .await
        .unwrap();
    validate_ecu_state(
        runtime,
        &auth,
        sovd::ECU_FLXC1000_ENDPOINT,
        sovd_interfaces::components::ecu::State::NoVariantDetected,
    )
    .await;
    validate_ecu_state(
        runtime,
        &auth,
        sovd::ECU_FLXCNG1000_ENDPOINT,
        sovd_interfaces::components::ecu::State::NoVariantDetected,
    )
    .await;

    // Stop sim and check if ECUs are marked as disconnected after variant detection
    stop_ecu_sim().await.unwrap();
    force_variant_detection(&runtime.config, &auth, sovd::ECU_FLXCNG1000_ENDPOINT)
        .await
        .unwrap();

    validate_ecu_state(
        runtime,
        &auth,
        sovd::ECU_FLXC1000_ENDPOINT,
        sovd_interfaces::components::ecu::State::Disconnected,
    )
    .await;
    validate_ecu_state(
        runtime,
        &auth,
        sovd::ECU_FLXCNG1000_ENDPOINT,
        sovd_interfaces::components::ecu::State::Disconnected,
    )
    .await;

    // restart CDA while sim is offline and check if ECUs are marked as offline
    restart_cda(&runtime.config).await.unwrap();
    validate_ecu_state(
        runtime,
        &auth,
        sovd::ECU_FLXC1000_ENDPOINT,
        sovd_interfaces::components::ecu::State::Offline,
    )
    .await;
    validate_ecu_state(
        runtime,
        &auth,
        sovd::ECU_FLXCNG1000_ENDPOINT,
        sovd_interfaces::components::ecu::State::Offline,
    )
    .await;

    // restart sim and wait for ECUs to come online,
    // status should be detected without manual variant detection
    start_ecu_sim(&runtime.ecu_sim).await.unwrap();

    // wait in loop, to check if the CDA receives the spontaneous VAM when is online
    for attempt in 0..=5 {
        let status = ecu_status(&runtime.config, &auth, sovd::ECU_FLXC1000_ENDPOINT)
            .await
            .expect("failed to get ecu status");

        if status.variant.state == sovd_interfaces::components::ecu::State::Online {
            break;
        }

        assert!(
            attempt < 5,
            "ECU did not come online in time, status {status:?}"
        );
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(1)).await;
    }

    validate_ecu_state(
        runtime,
        &auth,
        sovd::ECU_FLXCNG1000_ENDPOINT,
        sovd_interfaces::components::ecu::State::Duplicate,
    )
    .await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Keep the test together
async fn test_communication_control() {
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();
    let auth = auth_header(&runtime.config, None).await.unwrap();
    let ecu_endpoint = sovd::ECU_FLXC1000_ENDPOINT;

    // Without lock, the CDA should reject the request
    set_comm_control(
        "EnableRxAndEnableTx",
        None,
        &runtime.config,
        &auth,
        ecu_endpoint,
        StatusCode::FORBIDDEN,
    )
    .await
    .unwrap();

    // Create and acquire lock
    // Duration::from_mins is only available in rust >= 1.91.0, we want to support 1.88.0
    #[cfg_attr(nightly, allow(unknown_lints, clippy::duration_suboptimal_units))]
    let expiration_timeout = Duration::from_secs(60);
    let ecu_lock = create_lock(
        expiration_timeout,
        locks::ECU_ENDPOINT,
        StatusCode::CREATED,
        &runtime.config,
        &auth,
    )
    .await;
    let lock_id =
        extract_field_from_json::<String>(&response_to_json(&ecu_lock).unwrap(), "id").unwrap();

    // Sending an invalid value should return BAD_REQUEST with possible values
    sovd::validate_invalid_parameter_error(
        &runtime.config,
        &auth,
        ecu_endpoint,
        "commctrl",
        modes::commctrl::put::Request {
            value: "invalid-value".to_owned(),
            parameters: None,
        },
        &[
            "enablerxandenabletx",
            "enablerxanddisabletx",
            "disablerxandenabletx",
            "disablerxanddisabletx",
            "enablerxanddisabletxwithenhancedaddressinformation",
            "enablerxandtxwithenhancedaddressinformation",
            "temporalsync",
        ],
    )
    .await
    .unwrap();

    let enable_rx_and_enable_tx = "enablerxandenabletx";
    let result = set_comm_control(
        "EnableRxAndEnableTx",
        None,
        &runtime.config,
        &auth,
        ecu_endpoint,
        StatusCode::OK,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(result.value, "EnableRxAndEnableTx");

    let current_state = get_comm_control(&runtime.config, &auth, ecu_endpoint)
        .await
        .unwrap();
    assert_eq!(
        current_state.value.as_ref().map(|s| s.to_lowercase()),
        Some(enable_rx_and_enable_tx.to_owned())
    );

    let enable_rx_and_disable_tx = "enablerxanddisabletx";
    let result = set_comm_control(
        "EnableRxAndDisableTx",
        None,
        &runtime.config,
        &auth,
        ecu_endpoint,
        StatusCode::OK,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(result.value, "EnableRxAndDisableTx");

    let current_state = get_comm_control(&runtime.config, &auth, ecu_endpoint)
        .await
        .unwrap();
    assert_eq!(
        current_state.value.as_ref().map(|s| s.to_lowercase()),
        Some(enable_rx_and_disable_tx.to_owned())
    );

    let disable_rx_and_enable_tx = "disablerxandenabletx";
    let result = set_comm_control(
        "DisableRxAndEnableTx",
        None,
        &runtime.config,
        &auth,
        ecu_endpoint,
        StatusCode::OK,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(result.value, "DisableRxAndEnableTx");

    let current_state = get_comm_control(&runtime.config, &auth, ecu_endpoint)
        .await
        .unwrap();
    assert_eq!(
        current_state.value.as_ref().map(|s| s.to_lowercase()),
        Some(disable_rx_and_enable_tx.to_owned())
    );

    let disable_rx_and_disable_tx = "disablerxanddisabletx";
    let result = set_comm_control(
        "DisableRxAndDisableTx",
        None,
        &runtime.config,
        &auth,
        ecu_endpoint,
        StatusCode::OK,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(result.value, "DisableRxAndDisableTx");

    let current_state = get_comm_control(&runtime.config, &auth, ecu_endpoint)
        .await
        .unwrap();
    assert_eq!(
        current_state.value.as_ref().map(|s| s.to_lowercase()),
        Some(disable_rx_and_disable_tx.to_owned())
    );

    let enable_rx_and_disable_tx_with_enhanced =
        "enablerxanddisabletxwithenhancedaddressinformation";
    let result = set_comm_control(
        "EnableRxAndDisableTxWithEnhancedAddressInformation",
        None,
        &runtime.config,
        &auth,
        ecu_endpoint,
        StatusCode::OK,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        result.value,
        "EnableRxAndDisableTxWithEnhancedAddressInformation"
    );

    let current_state = get_comm_control(&runtime.config, &auth, ecu_endpoint)
        .await
        .unwrap();
    assert_eq!(
        current_state.value.as_ref().map(|s| s.to_lowercase()),
        Some(enable_rx_and_disable_tx_with_enhanced.to_owned())
    );

    let enable_rx_and_tx_with_enhanced = "enablerxandtxwithenhancedaddressinformation";
    let result = set_comm_control(
        "EnableRxAndTxWithEnhancedAddressInformation",
        None,
        &runtime.config,
        &auth,
        ecu_endpoint,
        StatusCode::OK,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(result.value, "EnableRxAndTxWithEnhancedAddressInformation");

    let current_state = get_comm_control(&runtime.config, &auth, ecu_endpoint)
        .await
        .unwrap();
    assert_eq!(
        current_state.value.as_ref().map(|s| s.to_lowercase()),
        Some(enable_rx_and_tx_with_enhanced.to_owned())
    );

    // VendorSpecific (custom TemporalSync 0x88)
    let temporal_era_id: i32 = -1_373_112_000;
    let mut parameters = cda_interfaces::HashMap::default();
    parameters.insert(
        "temporalEraId".to_string(),
        serde_json::json!(temporal_era_id),
    );

    let temporal_sync = "temporalsync";
    let result = set_comm_control(
        "TemporalSync",
        Some(parameters),
        &runtime.config,
        &auth,
        ecu_endpoint,
        StatusCode::OK,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(result.value, "TemporalSync");

    let current_state = get_comm_control(&runtime.config, &auth, ecu_endpoint)
        .await
        .unwrap();
    assert_eq!(
        current_state.value.as_ref().map(|s| s.to_lowercase()),
        Some(temporal_sync.to_owned())
    );

    // Validate that ECU sim received and stored the temporalEraId
    let ecu_state = ecusim::get_ecu_state(&runtime.ecu_sim, "flxc1000")
        .await
        .expect("Failed to get ECU sim state");
    assert_eq!(
        ecu_state.temporal_era_id,
        Some(temporal_era_id),
        "ECU sim did not store the correct temporalEraId, state={ecu_state:#?}",
    );
    assert_eq!(
        ecu_state.communication_control_type,
        Some(ecusim::CommunicationControlType::TemporalSync)
    );

    // Delete the ECU lock
    lock_operation(
        locks::ECU_ENDPOINT,
        Some(&lock_id),
        &runtime.config,
        &auth,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;

    // After deleting lock, we should not be able to set comm control
    set_comm_control(
        "EnableRxAndEnableTx",
        None,
        &runtime.config,
        &auth,
        ecu_endpoint,
        StatusCode::FORBIDDEN,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn test_boot_variant_service_inheritance() {
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();
    let auth = auth_header(&runtime.config, None).await.unwrap();
    let ecu_endpoint = sovd::ECU_FLXC1000_ENDPOINT;

    // Switch ECU sim to BOOT variant
    ecusim::switch_variant(&runtime.ecu_sim, "FLXC1000", "BOOT")
        .await
        .unwrap();
    force_variant_detection(&runtime.config, &auth, ecu_endpoint)
        .await
        .unwrap();

    let ecu = ecu_status(&runtime.config, &auth, ecu_endpoint)
        .await
        .unwrap();
    assert_eq!(ecu.variant.name, "FLXC1000_Boot_Variant".to_string());

    let data_services = get_data_services(&runtime.config, &auth, ecu_endpoint)
        .await
        .unwrap();
    let service_ids: Vec<_> = data_services
        .items
        .iter()
        .map(|item| item.id.to_lowercase())
        .collect();

    // Vindataidentifier is inherited and should be present in boot.
    assert!(
        service_ids.contains(&"vindataidentifier".to_owned()),
        "VIN service should be inherited from base variant, service ids {}",
        service_ids.join(", ")
    );

    // reset ecu-sim variant
    ecusim::switch_variant(&runtime.ecu_sim, "FLXC1000", "APPLICATION")
        .await
        .unwrap();

    // As long as test_ecu_session_switching also works we know that services
    // specific to the boot variant are still looked up correct, otherwise we cannot find
    // RequestSeed and SendKey services, no need to test this again here.
}

#[tokio::test]
async fn test_ecu_session_reset_on_lock_reacquire() {
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();
    let auth = auth_header(&runtime.config, None).await.unwrap();
    let ecu_endpoint = sovd::ECU_FLXC1000_ENDPOINT;

    // Create and acquire lock with 30s timeout
    let lock_expiration_timeout = Duration::from_secs(30);
    let ecu_lock = create_lock(
        lock_expiration_timeout,
        locks::ECU_ENDPOINT,
        StatusCode::CREATED,
        &runtime.config,
        &auth,
    )
    .await;
    let lock_id =
        extract_field_from_json::<String>(&response_to_json(&ecu_lock).unwrap(), "id").unwrap();

    // Set session with 2s expiry
    let session_expiration = 2u64;
    let switch_session_result: modes::security_and_session::put::Response<String> = put_mode(
        &runtime.config,
        &auth,
        ecu_endpoint,
        "session",
        modes::security_and_session::put::Request {
            value: "extended".to_owned(),
            mode_expiration: Some(session_expiration),
            key: None,
        },
        StatusCode::OK,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(switch_session_result.value.to_lowercase(), "extended");

    // Verify ECU sim is in extended session
    let ecu_state = ecusim::get_ecu_state(&runtime.ecu_sim, "flxc1000")
        .await
        .expect("Failed to get ECU sim state");
    assert_eq!(
        ecu_state.session_state,
        Some(ecusim::SessionState::Extended),
        "ECU sim should be in Extended session"
    );

    // Wait for the session to expire
    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(session_expiration + 1)).await;

    // Check if the sim is back to default
    let ecu_state_after_expiry = ecusim::get_ecu_state(&runtime.ecu_sim, "flxc1000")
        .await
        .expect("Failed to get ECU sim state after session expiry");

    assert_eq!(
        ecu_state_after_expiry.session_state,
        Some(ecusim::SessionState::Default),
        "ECU sim should be back to Default session after session expiry"
    );

    // Also verify through CDA API
    let session_result_after = session(&runtime.config, &auth, ecu_endpoint).await.unwrap();
    assert_eq!(
        session_result_after.value.map(|s| s.to_lowercase()),
        Some("default".to_owned())
    );

    // Delete the lock
    lock_operation(
        locks::ECU_ENDPOINT,
        Some(&lock_id),
        &runtime.config,
        &auth,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;
}

#[tokio::test]
async fn test_ecu_sdg_retrieval() {
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();
    let ecu_endpoint = sovd::ECU_FLXC1000_ENDPOINT;

    // Retrieve sdgs and verify contents
    let params = QueryParams(HashMap::from_iter([(
        "x-sovd2uds-includesdgs".to_string(),
        "true".to_string(),
    )]));
    let data = get_ecu_component(&runtime.config, ecu_endpoint, StatusCode::OK, Some(&params))
        .await
        .unwrap();

    let d = data
        .get("data")
        .unwrap()
        .as_str()
        .expect("should contain data");
    assert_eq!(
        d,
        "http://localhost:20002/vehicle/v15/components/flxc1000/data"
    );

    let operations = data
        .get("operations")
        .unwrap()
        .as_str()
        .expect("should contain operations");
    assert_eq!(
        operations,
        "http://localhost:20002/vehicle/v15/components/flxc1000/operations"
    );

    let configurations = data
        .get("configurations")
        .unwrap()
        .as_str()
        .expect("should contain configurations");
    assert_eq!(
        configurations,
        "http://localhost:20002/vehicle/v15/components/flxc1000/configurations"
    );

    let modes = data
        .get("modes")
        .unwrap()
        .as_str()
        .expect("should contain modes");
    assert_eq!(
        modes,
        "http://localhost:20002/vehicle/v15/components/flxc1000/modes"
    );

    let locks = data
        .get("locks")
        .unwrap()
        .as_str()
        .expect("should contain locks");
    assert_eq!(
        locks,
        "http://localhost:20002/vehicle/v15/components/flxc1000/locks"
    );

    let faults = data
        .get("faults")
        .unwrap()
        .as_str()
        .expect("should contain faults");
    assert_eq!(
        faults,
        "http://localhost:20002/vehicle/v15/components/flxc1000/faults"
    );

    let sdgs = data
        .get("sdgs")
        .unwrap()
        .as_array()
        .expect("sdgs should be an array");
    assert_eq!(sdgs.len(), 1);

    let sdg = &sdgs.first().unwrap();
    assert_eq!(sdg.get("caption").unwrap().as_str(), Some("default_sdg"));
    assert_eq!(sdg.get("si").unwrap().as_str(), Some("default"));

    let inner = sdg
        .get("sdgs")
        .unwrap()
        .as_array()
        .expect("nested sdgs should be an array");
    assert_eq!(inner.len(), 1);

    let sd = &inner.first().unwrap();
    assert_eq!(
        sd.get("si").unwrap().as_str(),
        Some("power_requirement_max")
    );
    assert_eq!(sd.get("value").unwrap().as_str(), Some("1.21GW"));
}

#[tokio::test]
async fn test_ecu_sdg_retrieval_alias() {
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();
    let ecu_endpoint = sovd::ECU_FLXC1000_ENDPOINT;

    // Retrieve sdgs and verify contents
    let params = QueryParams(HashMap::from_iter([(
        "x-include-sdgs".to_string(),
        "true".to_string(),
    )]));
    let data = get_ecu_component(&runtime.config, ecu_endpoint, StatusCode::OK, Some(&params))
        .await
        .unwrap();

    let sdgs = data
        .get("sdgs")
        .unwrap()
        .as_array()
        .expect("sdgs should be an array");
    assert_eq!(sdgs.len(), 1);

    let sdg = &sdgs.first().unwrap();
    assert_eq!(sdg.get("caption").unwrap().as_str(), Some("default_sdg"));
    assert_eq!(sdg.get("si").unwrap().as_str(), Some("default"));

    let inner = sdg
        .get("sdgs")
        .unwrap()
        .as_array()
        .expect("nested sdgs should be an array");
    assert_eq!(inner.len(), 1);

    let sd = &inner.first().unwrap();
    assert_eq!(
        sd.get("si").unwrap().as_str(),
        Some("power_requirement_max")
    );
    assert_eq!(sd.get("value").unwrap().as_str(), Some("1.21GW"));
}

async fn validate_ecu_state(
    runtime: &TestRuntime,
    auth: &HeaderMap,
    ecu: &str,
    expected_state: sovd_interfaces::components::ecu::State,
) {
    let ecu_status = ecu_status(&runtime.config, auth, ecu)
        .await
        .expect("failed to get ecu status");
    assert_eq!(
        ecu_status.variant.state, expected_state,
        "ECU {ecu} state does not match {ecu_status:?}"
    );
}

async fn session(
    config: &Configuration,
    headers: &HeaderMap,
    ecu_endpoint: &str,
) -> Result<
    sovd_interfaces::components::ecu::modes::security_and_session::get::Response,
    TestingError,
> {
    get_mode(config, headers, ecu_endpoint, "session").await
}

async fn security(
    config: &Configuration,
    headers: &HeaderMap,
    ecu_endpoint: &str,
) -> Result<
    sovd_interfaces::components::ecu::modes::security_and_session::get::Response,
    TestingError,
> {
    get_mode(config, headers, ecu_endpoint, "security").await
}

pub(crate) async fn switch_session(
    name: &str,
    config: &Configuration,
    headers: &HeaderMap,
    ecu_endpoint: &str,
    expected_status: StatusCode,
) -> Result<
    Option<sovd_interfaces::components::ecu::modes::security_and_session::put::Response<String>>,
    TestingError,
> {
    put_mode(
        config,
        headers,
        ecu_endpoint,
        "session",
        sovd_interfaces::components::ecu::modes::security_and_session::put::Request {
            value: name.to_owned(),
            mode_expiration: None,
            key: None,
        },
        expected_status,
    )
    .await
}

async fn request_seed(
    name: String,
    config: &Configuration,
    headers: &HeaderMap,
    ecu_endpoint: &str,
) -> Result<
    Option<sovd_interfaces::components::ecu::modes::security_and_session::put::RequestSeedResponse>,
    TestingError,
> {
    put_mode(
        config,
        headers,
        ecu_endpoint,
        "security",
        sovd_interfaces::components::ecu::modes::security_and_session::put::Request {
            value: name,
            mode_expiration: None,
            key: None,
        },
        StatusCode::OK,
    )
    .await
}

async fn send_key(
    name: String,
    key: String,
    config: &Configuration,
    headers: &HeaderMap,
    ecu_endpoint: &str,
    excepted_status: StatusCode,
) -> Result<
    Option<sovd_interfaces::components::ecu::modes::security_and_session::put::Response<String>>,
    TestingError,
> {
    put_mode(
        config,
        headers,
        ecu_endpoint,
        "security",
        sovd_interfaces::components::ecu::modes::security_and_session::put::Request {
            value: name,
            mode_expiration: None,
            key: Some(
                sovd_interfaces::components::ecu::modes::security_and_session::put::ModeKey {
                    send_key: key,
                },
            ),
        },
        excepted_status,
    )
    .await
}

async fn get_mode<T: DeserializeOwned>(
    config: &Configuration,
    headers: &HeaderMap,
    ecu_endpoint: &str,
    sub_path: &str,
) -> Result<T, TestingError> {
    let http_response = send_cda_request(
        config,
        &format!("{ecu_endpoint}/modes/{sub_path}"),
        StatusCode::OK,
        Method::GET,
        None,
        Some(headers),
        None,
    )
    .await?;
    response_to_t(&http_response)
}

async fn ecu_status(
    config: &Configuration,
    headers: &HeaderMap,
    ecu_endpoint: &str,
) -> Result<sovd_interfaces::components::ecu::get::Response, TestingError> {
    let http_response = send_cda_request(
        config,
        ecu_endpoint,
        StatusCode::OK,
        Method::GET,
        None,
        Some(headers),
        None,
    )
    .await?;
    response_to_t(&http_response)
}

async fn force_variant_detection(
    config: &Configuration,
    headers: &HeaderMap,
    ecu_endpoint: &str,
) -> Result<(), TestingError> {
    send_cda_request(
        config,
        ecu_endpoint,
        StatusCode::CREATED,
        Method::PUT,
        None,
        Some(headers),
        None,
    )
    .await?;
    Ok(())
}

async fn get_comm_control(
    config: &Configuration,
    headers: &HeaderMap,
    ecu_endpoint: &str,
) -> Result<modes::commctrl::get::Response, TestingError> {
    get_mode(config, headers, ecu_endpoint, "commctrl").await
}

async fn set_comm_control(
    value: &str,
    parameters: Option<cda_interfaces::HashMap<String, serde_json::Value>>,
    config: &Configuration,
    headers: &HeaderMap,
    ecu_endpoint: &str,
    expected_status: StatusCode,
) -> Result<Option<sovd_interfaces::components::ecu::modes::commctrl::put::Response>, TestingError>
{
    put_mode(
        config,
        headers,
        ecu_endpoint,
        "commctrl",
        modes::commctrl::put::Request {
            value: value.to_owned(),
            parameters,
        },
        expected_status,
    )
    .await
}

pub(crate) async fn get_dtc_setting(
    config: &Configuration,
    headers: &HeaderMap,
    ecu_endpoint: &str,
) -> Result<dtcsetting::get::Response, TestingError> {
    get_mode(config, headers, ecu_endpoint, "dtcsetting").await
}

async fn get_configurations(
    config: &Configuration,
    headers: &HeaderMap,
    ecu_endpoint: &str,
    service: &str,
) -> Result<sovd_interfaces::components::ecu::configurations::ServiceResponse, TestingError> {
    let http_response = send_cda_request(
        config,
        &format!("{ecu_endpoint}/configurations/{service}"),
        StatusCode::OK,
        Method::GET,
        None,
        Some(headers),
        None,
    )
    .await?;
    response_to_t(&http_response)
}

async fn reset_ecu(
    value: &str,
    config: &Configuration,
    headers: &HeaderMap,
    ecu_endpoint: &str,
    expected_status: StatusCode,
) -> Result<(), TestingError> {
    let body = serde_json::json!({
        "parameters": {"value": value}
    })
    .to_string();
    send_cda_request(
        config,
        &format!("{ecu_endpoint}/operations/reset/executions"),
        expected_status,
        Method::POST,
        Some(&body),
        Some(headers),
        None,
    )
    .await?;
    Ok(())
}

async fn get_data_services(
    config: &Configuration,
    headers: &HeaderMap,
    ecu_endpoint: &str,
) -> Result<sovd_interfaces::components::ecu::data::get::Response, TestingError> {
    let http_response = send_cda_request(
        config,
        &format!("{ecu_endpoint}/data"),
        StatusCode::OK,
        Method::GET,
        None,
        Some(headers),
        None,
    )
    .await?;
    response_to_t(&http_response)
}
