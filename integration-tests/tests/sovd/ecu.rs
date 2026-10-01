/*
 * SPDX-FileCopyrightText: 2025 Copyright (c) Contributors to the Eclipse Foundation
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
use std::{collections::HashMap, time::Duration};

use http::StatusCode;
use serde_json::json;
use sovd_interfaces::{
    common::modes::{COMM_CONTROL_ID, SECURITY_ID, SESSION_ID},
    components::{
        ComponentQuery,
        ecu::{
            Ecu, SdSdg, ServicesSdgs, State,
            modes::{
                commctrl,
                security_and_session::{
                    self,
                    put::{ModeKey, RequestSeedResponse, SessionRequest},
                },
            },
        },
    },
};

use crate::{
    client::{self, components::Component},
    sovd::{
        self, ECU_FLXC1000, ECU_FSNR2000, ECU_HOVR4000, ECU_JGWT5000, ECU_TMCC3000,
        compute_security_key,
    },
    util::{
        ecusim::{self},
        endpoints::ECU_FLXCNG1000,
        test_env::{TestEnv, skip_for_can, skip_for_doip},
    },
};

/// Reads the Identification DID from the ECU over its transport. Unlike the
/// component listing (served from the loaded MDD even when the ECU is dead),
/// this request only succeeds if the ECU actually answers on the bus, so it
/// proves end-to-end liveness.
async fn assert_ecu_answers_on_bus(test_env: &TestEnv, ecu: &str) {
    let item = test_env
        .client()
        .component(ecu)
        .data("identification")
        .get()
        .await
        .expect("live Identification read over the bus should succeed")
        .expect_status(StatusCode::OK)
        .into_body();
    let data = serde_json::Value::Object(item.data);
    assert!(
        data.to_string().contains("Identification"),
        "data response should contain the Identification parameter: {data}"
    );
}

/// This ECU is missing comm parameters and thus must be configured via the configuration file.
/// The test verifies that the ECU is reachable and reports the correct name and state.
#[tokio::test]
async fn test_tmcc3000_ecu_online() {
    let test_env = TestEnv::builder().await.unwrap();

    let ecu = test_env
        .client()
        .component(ECU_TMCC3000)
        .get()
        .await
        .expect("TMCC3000 component should be reachable via SOVD API")
        .expect_status(StatusCode::OK);
    assert_eq!(
        ecu.name.to_lowercase(),
        ECU_TMCC3000,
        "Component name should be tmcc3000"
    );

    assert_ecu_answers_on_bus(&test_env, ECU_TMCC3000).await;
}

/// HOVR4000 uses a non-default protocol (`DMC_DoIP`) in its MDD. The global
/// protocol is `UDS_Ethernet_DoIP_DOBT`, so without a per-ECU protocol override
/// the CDA would fail to load this ECU.  The test verifies that the per-ECU
/// `protocol` config override works correctly.
#[tokio::test]
async fn test_hovr4000_per_ecu_protocol_override() {
    let test_env = TestEnv::builder().await.unwrap();

    let ecu = test_env
        .client()
        .component(ECU_HOVR4000)
        .get()
        .await
        .expect("HOVR4000 component should be reachable when per-ECU protocol override is set")
        .expect_status(StatusCode::OK);
    assert_eq!(
        ecu.name.to_lowercase(),
        ECU_HOVR4000,
        "Component name should be hovr4000"
    );

    assert_ecu_answers_on_bus(&test_env, ECU_HOVR4000).await;
}

/// JGWT5000 has a non-default protocol (`DMC_DoIP`) in its MDD but no per-ECU
/// protocol override.  With `ignore_protocol` enabled, `into_db_protocol` falls
/// back to the single DB protocol and com-param lookup matches by name alone.
#[tokio::test]
async fn test_jgwt5000_ignore_protocol_with_db_protocol() {
    let test_env = TestEnv::builder().await.unwrap();

    let ecu = test_env
        .client()
        .component(ECU_JGWT5000)
        .get()
        .await
        .expect(
            "JGWT5000 component should be reachable with ignore_protocol and no protocol override",
        )
        .expect_status(StatusCode::OK);
    assert_eq!(
        ecu.name.to_lowercase(),
        ECU_JGWT5000,
        "Component name should be jgwt5000"
    );

    assert_ecu_answers_on_bus(&test_env, ECU_JGWT5000).await;
}

/// A CAN-only ECU must be usable purely from configuration: TMCC3000's MDD
/// carries no `DoIP` addressing and its CAN request/response IDs come
/// exclusively from `[[can.ecu_mappings]]` plus the per-ECU protocol
/// handling in the test config (in mixed mode additionally a transport
/// override pins it to CAN). The test asserts the ECU is actually served
/// over a CAN network address and answers a live read on the bus.
#[tokio::test]
async fn test_can_only_ecu_from_configuration() {
    if skip_for_doip(
        "test_can_only_ecu_from_configuration",
        "needs the CAN transport (pure-CAN or mixed mode)",
    ) {
        return;
    }
    let test_env = TestEnv::builder().await.unwrap();

    // Live read proves the ECU answers on the bus at all.
    assert_ecu_answers_on_bus(&test_env, ECU_TMCC3000).await;

    // The network structure must serve TMCC3000 behind a CAN network address
    // (can:// scheme) carrying the configured request/response CAN IDs.
    let network_structure = test_env
        .anonymous_client()
        .sovd2uds()
        .network_structure()
        .await
        .expect("network structure should be readable")
        .expect_status(StatusCode::OK);
    let gateways: Vec<_> = network_structure
        .data
        .iter()
        .flat_map(|structure| &structure.gateways)
        .collect();
    let tmcc3000_gateway = gateways
        .iter()
        .find(|gateway| {
            gateway
                .ecus
                .iter()
                .any(|ecu| ecu.qualifier.eq_ignore_ascii_case(ECU_TMCC3000))
        })
        .unwrap_or_else(|| {
            let gateways: Vec<_> = gateways
                .iter()
                .map(|gateway| {
                    let ecus: Vec<_> = gateway.ecus.iter().map(|ecu| &ecu.qualifier).collect();
                    format!("{} {ecus:?}", gateway.name)
                })
                .collect();
            panic!("TMCC3000 missing from network structure, gateways: {gateways:?}")
        });
    let network_address = &tmcc3000_gateway.network_address;
    assert!(
        network_address.starts_with("can://"),
        "TMCC3000 should be served over CAN, got network address {network_address}"
    );
    assert!(
        network_address.contains("0x730") && network_address.contains("0x738"),
        "CAN address should carry the configured request/response IDs: {network_address}"
    );
}

#[allow(clippy::too_many_lines, reason = "Makes sense to keep test together")]
#[tokio::test]
async fn test_ecu_session_switching() {
    // TODO(can): SecurityAccess seed/key/lock sequencing is not yet reliable
    // over the CAN transport. Re-enable once the CAN session/security path
    // is hardened, see #444
    if skip_for_can(
        "test_ecu_session_switching",
        "SecurityAccess sequencing not yet supported over CAN",
    ) {
        return;
    }
    let test_env = TestEnv::builder().await.unwrap();
    let component = test_env.client().component(ECU_FLXC1000);

    // We have no lock yet, thus the CDA should reject the request to send the key.
    let error = send_key(&component, "0x42".to_owned())
        .await
        .expect_err("the CDA should reject sending a key without a lock");
    assert_eq!(error.status(), Some(StatusCode::CONFLICT), "{error}");

    let expiration_timeout = Duration::from_secs(60);
    let ecu_lock = component
        .locks()
        .create(expiration_timeout)
        .await
        .expect("Failed to create lock")
        .expect_status(StatusCode::CREATED)
        .into_body();

    // Lock the ECU
    ecu_lock
        .handle()
        .get()
        .await
        .expect("lock operation failed")
        .expect_status(StatusCode::OK);

    component
        .detect_variant()
        .await
        .unwrap()
        .expect_status(StatusCode::CREATED);

    let ecu = component.get().await.unwrap().expect_status(StatusCode::OK);
    assert!(ecu.name.eq_ignore_ascii_case(ECU_FLXC1000));
    assert_eq!(ecu.variant.name, "FLXC1000_App_0101".to_string());

    let error = switch_session(&component, "this status does not exist")
        .await
        .expect_err("the CDA should reject an unknown session");
    assert_eq!(error.status(), Some(StatusCode::NOT_FOUND), "{error}");

    // Get the active diagnostic session using the Configuration GET method.
    let get_config_result = component
        .configuration("activediagnosticsessiondataidentifier")
        .await
        .unwrap()
        .expect_status(StatusCode::OK);

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

    let switch_session_result = switch_session(&component, "extended")
        .await
        .unwrap()
        .expect_status(StatusCode::OK);
    assert_eq!(switch_session_result.value.to_lowercase(), "extended");
    let session_result = component
        .mode(SESSION_ID)
        .get::<security_and_session::get::Response>()
        .await
        .unwrap()
        .expect_status(StatusCode::OK)
        .into_body();
    assert_eq!(
        session_result.value.map(|s| s.to_lowercase()),
        Some("extended".to_owned())
    );
    assert_eq!(session_result.name, Some("Diagnostic session".to_owned()));

    // After switching to extended session, fetch again using configuraion GET and verify.
    let get_config_result = component
        .configuration("activediagnosticsessiondataidentifier")
        .await
        .unwrap()
        .expect_status(StatusCode::OK);

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
    component
        .operation("reset")
        .start(&json!({ "parameters": { "value": "hardreset" } }))
        .await
        .unwrap()
        .expect_status(StatusCode::NO_CONTENT);

    let session_result_after_reset = component
        .mode(SESSION_ID)
        .get::<security_and_session::get::Response>()
        .await
        .unwrap()
        .expect_status(StatusCode::OK)
        .into_body();
    assert_eq!(
        session_result_after_reset.value.map(|s| s.to_lowercase()),
        Some("default".to_owned()),
        "Session should be back to default after hard reset"
    );

    // Switch back to extended session so the remaining test steps work
    let switch_back_result = switch_session(&component, "extended")
        .await
        .unwrap()
        .expect_status(StatusCode::OK);
    assert_eq!(switch_back_result.value.to_lowercase(), "extended");

    // switch ECU sim state to BOOT
    ecusim::switch_variant(&test_env.ecu_sim, "FLXC1000", "BOOT")
        .await
        .unwrap();
    component
        .detect_variant()
        .await
        .unwrap()
        .expect_status(StatusCode::CREATED);
    let ecu = component.get().await.unwrap().expect_status(StatusCode::OK);
    assert_eq!(ecu.variant.name, "FLXC1000_Boot_Variant".to_string());

    let seed_response = request_seed(&component, None)
        .await
        .unwrap()
        .expect_status(StatusCode::OK);

    // Key is too short
    let error = send_key(&component, "0x42".to_owned())
        .await
        .expect_err("the ECU should reject a key that is too short");
    assert_eq!(error.status(), Some(StatusCode::BAD_GATEWAY), "{error}");

    let error = send_key(&component, seed_response.seed.request_seed.clone())
        .await
        .expect_err("the ECU should reject the seed as key");
    assert_eq!(error.status(), Some(StatusCode::BAD_GATEWAY), "{error}");

    let key = compute_security_key(&seed_response.seed.request_seed);

    send_key(&component, key)
        .await
        .unwrap()
        .expect_status(StatusCode::OK);
    let security_result = component
        .mode(SECURITY_ID)
        .get::<security_and_session::get::Response>()
        .await
        .unwrap()
        .expect_status(StatusCode::OK)
        .into_body();
    assert_eq!(security_result.value, Some("Level_5".to_owned()));
    assert_eq!(security_result.name, Some("Security access".to_owned()));

    // Delete the ECU lock
    ecu_lock
        .release()
        .await
        .expect("lock operation failed")
        .expect_status(StatusCode::NO_CONTENT);
}

/// A `RequestSeed` parameter must be encoded into the UDS request; FSNR2000's
/// simulator rejects the seed request unless it receives the configured byte.
#[tokio::test]
async fn request_seed_forwards_parameters_to_fsnr2000() {
    if skip_for_can(
        "request_seed_forwards_parameters_to_fsnr2000",
        "SecurityAccess sequencing not yet supported over CAN",
    ) {
        return;
    }

    let test_env = TestEnv::builder()
        .await
        .expect("test environment should start");
    let component = test_env.client().component(ECU_FSNR2000);

    let ecu_lock = component
        .locks()
        .create(Duration::from_secs(60))
        .await
        .expect("Failed to create lock")
        .expect_status(StatusCode::CREATED)
        .into_body();
    ecu_lock
        .handle()
        .get()
        .await
        .expect("lock operation failed")
        .expect_status(StatusCode::OK);

    ecusim::switch_variant(&test_env.ecu_sim, "FSNR2000", "BOOT")
        .await
        .expect("FSNR2000 should switch to the boot variant");
    component
        .detect_variant()
        .await
        .expect("FSNR2000 boot variant should be detected")
        .expect_status(StatusCode::CREATED);

    assert_request_seed_rejected(&component, None, StatusCode::BAD_REQUEST).await;

    let mut parameters = HashMap::new();
    parameters.insert("Invalid".to_owned(), json!(0x5A));
    assert_request_seed_rejected(&component, Some(parameters), StatusCode::BAD_REQUEST).await;

    let mut parameters = HashMap::new();
    parameters.insert("SeedRequestParameter".to_owned(), json!(0x5B));
    assert_request_seed_rejected(&component, Some(parameters), StatusCode::BAD_GATEWAY).await;

    let recorder = test_env
        .record(ECU_FSNR2000)
        .await
        .expect("FSNR2000 recording should start");

    let mut parameters = HashMap::new();
    parameters.insert("SeedRequestParameter".to_owned(), json!(0x5A));
    request_seed(&component, Some(parameters))
        .await
        .expect("RequestSeed with parameters should return a seed")
        .expect_status(StatusCode::OK);

    let frames = recorder
        .stop()
        .await
        .expect("FSNR2000 recording should stop");
    assert!(
        frames.contains(&"27055A".to_owned()),
        "expected RequestSeed parameter frame 27055A, got: {frames:?}"
    );
}

#[tokio::test]
async fn send_key_rejects_request_seed_parameters() {
    if skip_for_can(
        "send_key_rejects_request_seed_parameters",
        "SecurityAccess sequencing not yet supported over CAN",
    ) {
        return;
    }
    let test_env = TestEnv::builder().await.unwrap();
    let component = test_env.client().component(ECU_FLXC1000);

    let ecu_lock = component
        .locks()
        .create(Duration::from_secs(60))
        .await
        .expect("Failed to create lock")
        .expect_status(StatusCode::CREATED)
        .into_body();
    ecu_lock
        .handle()
        .get()
        .await
        .expect("lock operation failed")
        .expect_status(StatusCode::OK);

    let mut parameters = HashMap::new();
    parameters.insert("Foo".to_owned(), json!(90));
    let error = component
        .mode(SECURITY_ID)
        .put::<security_and_session::put::Response<String>>(&security_and_session::put::Request {
            value: "Level_5".to_owned(),
            mode_expiration: None,
            key: Some(ModeKey {
                send_key: "0x12 0x34".to_owned(),
            }),
            parameters: Some(parameters),
        })
        .await
        .expect_err("SendKey with RequestSeed parameters should be rejected");
    assert_eq!(error.status(), Some(StatusCode::BAD_REQUEST), "{error}");

    ecu_lock
        .release()
        .await
        .expect("lock operation failed")
        .expect_status(StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_variant_detection_duplicates() {
    // DoIP-only: relies on spontaneous VAM announcements and restarts the sim's
    // DoIP entities (which has no CAN-hub equivalent), so it cannot run over the
    // CAN transport.
    if skip_for_can(
        "test_variant_detection_duplicates",
        "depends on DoIP VAM announcements and sim restart",
    ) {
        return;
    }
    let mut test_env = TestEnv::builder().await.unwrap();

    // Switch variant, and check if the NG variant is now online.
    ecusim::switch_variant(&test_env.ecu_sim, "FLXC1000", "APPLICATION")
        .await
        .unwrap();
    let component = test_env.client().component(ECU_FLXC1000);
    component
        .detect_variant()
        .await
        .unwrap()
        .expect_status(StatusCode::CREATED);
    let ecu = component.get().await.unwrap().expect_status(StatusCode::OK);
    assert_eq!(ecu.variant.state, State::Online);
    assert_eq!(ecu.variant.logical_address, "0x1000");

    // Switch variant, and check if the NG variant is now online.
    ecusim::switch_variant(&test_env.ecu_sim, "FLXC1000", "APPLICATION2")
        .await
        .unwrap();
    component
        .detect_variant()
        .await
        .unwrap()
        .expect_status(StatusCode::CREATED);

    validate_ecu_state(&test_env, ECU_FLXC1000, State::Duplicate).await;
    validate_ecu_state(&test_env, ECU_FLXCNG1000, State::Online).await;

    // No variant associated with APPLICATION3, check if both ECUs are marked as NoVariantDetected
    ecusim::switch_variant(&test_env.ecu_sim, "FLXC1000", "APPLICATION3")
        .await
        .unwrap();
    component
        .detect_variant()
        .await
        .unwrap()
        .expect_status(StatusCode::CREATED);
    validate_ecu_state(&test_env, ECU_FLXC1000, State::NoVariantDetected).await;
    validate_ecu_state(&test_env, ECU_FLXCNG1000, State::NoVariantDetected).await;

    // Stop sim and check if ECUs are marked as disconnected after variant detection
    test_env.stop_ecu_sim().await.unwrap();
    test_env
        .client()
        .component(ECU_FLXCNG1000)
        .detect_variant()
        .await
        .unwrap()
        .expect_status(StatusCode::CREATED);

    validate_ecu_state(&test_env, ECU_FLXC1000, State::Disconnected).await;
    validate_ecu_state(&test_env, ECU_FLXCNG1000, State::Disconnected).await;

    // restart CDA while sim is offline and check if ECUs are marked as offline
    test_env.restart_cda_with_config(|_| {}).await.unwrap();
    validate_ecu_state(&test_env, ECU_FLXC1000, State::Offline).await;
    validate_ecu_state(&test_env, ECU_FLXCNG1000, State::Offline).await;

    // restart sim and wait for ECUs to come online,
    // status should be detected without manual variant detection
    test_env.start_ecu_sim().await.unwrap();

    // wait in loop, to check if the CDA receives the spontaneous VAM when is online
    for attempt in 0..=5 {
        let status = test_env
            .client()
            .component(ECU_FLXC1000)
            .get()
            .await
            .expect("failed to get ecu status")
            .expect_status(StatusCode::OK);

        if status.variant.state == State::Online {
            break;
        }

        assert!(
            attempt < 5,
            "ECU did not come online in time, status {status:?}"
        );
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(1)).await;
    }

    validate_ecu_state(&test_env, ECU_FLXCNG1000, State::Duplicate).await;
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "Keep the test together")]
async fn test_communication_control() {
    let test_env = TestEnv::builder().await.unwrap();
    let component = test_env.client().component(ECU_FLXC1000);

    // Without lock, the CDA should reject the request
    let error = set_comm_control(&component, "EnableRxAndEnableTx", None)
        .await
        .expect_err("the CDA should reject comm control without a lock");
    assert_eq!(error.status(), Some(StatusCode::CONFLICT), "{error}");

    // Create and acquire lock
    let expiration_timeout = Duration::from_secs(60);
    let ecu_lock = component
        .locks()
        .create(expiration_timeout)
        .await
        .expect("Failed to create lock")
        .expect_status(StatusCode::CREATED)
        .into_body();

    // Sending an invalid value should return BAD_REQUEST with possible values
    sovd::validate_invalid_parameter_error(
        &component.mode(COMM_CONTROL_ID),
        &commctrl::put::Request {
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
    let result = set_comm_control(&component, "EnableRxAndEnableTx", None)
        .await
        .unwrap()
        .expect_status(StatusCode::OK);
    assert_eq!(result.value, "EnableRxAndEnableTx");

    let current_state = get_comm_control(&component)
        .await
        .unwrap()
        .expect_status(StatusCode::OK);
    assert_eq!(
        current_state.value.as_ref().map(|s| s.to_lowercase()),
        Some(enable_rx_and_enable_tx.to_owned())
    );

    let enable_rx_and_disable_tx = "enablerxanddisabletx";
    let result = set_comm_control(&component, "EnableRxAndDisableTx", None)
        .await
        .unwrap()
        .expect_status(StatusCode::OK);
    assert_eq!(result.value, "EnableRxAndDisableTx");

    let current_state = get_comm_control(&component)
        .await
        .unwrap()
        .expect_status(StatusCode::OK);
    assert_eq!(
        current_state.value.as_ref().map(|s| s.to_lowercase()),
        Some(enable_rx_and_disable_tx.to_owned())
    );

    let disable_rx_and_enable_tx = "disablerxandenabletx";
    let result = set_comm_control(&component, "DisableRxAndEnableTx", None)
        .await
        .unwrap()
        .expect_status(StatusCode::OK);
    assert_eq!(result.value, "DisableRxAndEnableTx");

    let current_state = get_comm_control(&component)
        .await
        .unwrap()
        .expect_status(StatusCode::OK);
    assert_eq!(
        current_state.value.as_ref().map(|s| s.to_lowercase()),
        Some(disable_rx_and_enable_tx.to_owned())
    );

    let disable_rx_and_disable_tx = "disablerxanddisabletx";
    let result = set_comm_control(&component, "DisableRxAndDisableTx", None)
        .await
        .unwrap()
        .expect_status(StatusCode::OK);
    assert_eq!(result.value, "DisableRxAndDisableTx");

    let current_state = get_comm_control(&component)
        .await
        .unwrap()
        .expect_status(StatusCode::OK);
    assert_eq!(
        current_state.value.as_ref().map(|s| s.to_lowercase()),
        Some(disable_rx_and_disable_tx.to_owned())
    );

    let enable_rx_and_disable_tx_with_enhanced =
        "enablerxanddisabletxwithenhancedaddressinformation";
    let result = set_comm_control(
        &component,
        "EnableRxAndDisableTxWithEnhancedAddressInformation",
        None,
    )
    .await
    .unwrap()
    .expect_status(StatusCode::OK);
    assert_eq!(
        result.value,
        "EnableRxAndDisableTxWithEnhancedAddressInformation"
    );

    let current_state = get_comm_control(&component)
        .await
        .unwrap()
        .expect_status(StatusCode::OK);
    assert_eq!(
        current_state.value.as_ref().map(|s| s.to_lowercase()),
        Some(enable_rx_and_disable_tx_with_enhanced.to_owned())
    );

    let enable_rx_and_tx_with_enhanced = "enablerxandtxwithenhancedaddressinformation";
    let result = set_comm_control(
        &component,
        "EnableRxAndTxWithEnhancedAddressInformation",
        None,
    )
    .await
    .unwrap()
    .expect_status(StatusCode::OK);
    assert_eq!(result.value, "EnableRxAndTxWithEnhancedAddressInformation");

    let current_state = get_comm_control(&component)
        .await
        .unwrap()
        .expect_status(StatusCode::OK);
    assert_eq!(
        current_state.value.as_ref().map(|s| s.to_lowercase()),
        Some(enable_rx_and_tx_with_enhanced.to_owned())
    );

    // VendorSpecific (custom TemporalSync 0x88)
    let temporal_era_id: i32 = -1_373_112_000;
    let mut parameters = cda_interfaces::HashMap::default();
    parameters.insert("temporalEraId".to_string(), json!(temporal_era_id));

    let temporal_sync = "temporalsync";
    let result = set_comm_control(&component, "TemporalSync", Some(parameters))
        .await
        .unwrap()
        .expect_status(StatusCode::OK);
    assert_eq!(result.value, "TemporalSync");

    let current_state = get_comm_control(&component)
        .await
        .unwrap()
        .expect_status(StatusCode::OK);
    assert_eq!(
        current_state.value.as_ref().map(|s| s.to_lowercase()),
        Some(temporal_sync.to_owned())
    );

    // Validate that ECU sim received and stored the temporalEraId
    let ecu_state = ecusim::get_ecu_state(&test_env.ecu_sim, ECU_FLXC1000)
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
    ecu_lock
        .release()
        .await
        .expect("lock operation failed")
        .expect_status(StatusCode::NO_CONTENT);

    // After deleting lock, we should not be able to set comm control
    let error = set_comm_control(&component, "EnableRxAndEnableTx", None)
        .await
        .expect_err("the CDA should reject comm control after the lock is deleted");
    assert_eq!(error.status(), Some(StatusCode::CONFLICT), "{error}");
}

#[tokio::test]
async fn test_boot_variant_service_inheritance() {
    let test_env = TestEnv::builder().await.unwrap();
    let component = test_env.client().component(ECU_FLXC1000);

    // Switch ECU sim to BOOT variant
    ecusim::switch_variant(&test_env.ecu_sim, "FLXC1000", "BOOT")
        .await
        .unwrap();
    component
        .detect_variant()
        .await
        .unwrap()
        .expect_status(StatusCode::CREATED);

    let ecu = component.get().await.unwrap().expect_status(StatusCode::OK);
    assert_eq!(ecu.variant.name, "FLXC1000_Boot_Variant".to_string());

    let data_services = component
        .data_list()
        .await
        .unwrap()
        .expect_status(StatusCode::OK);
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
    ecusim::switch_variant(&test_env.ecu_sim, "FLXC1000", "APPLICATION")
        .await
        .unwrap();

    // As long as test_ecu_session_switching also works we know that services
    // specific to the boot variant are still looked up correct, otherwise we cannot find
    // RequestSeed and SendKey services, no need to test this again here.
}

#[tokio::test]
async fn test_ecu_session_reset_on_lock_reacquire() {
    // TODO(can): session expiry depends on TesterPresent keepalive cadence,
    // which is not yet reliable over the CAN transport (per-transaction
    // sockets + busy-poll dispatcher are too slow), see #444
    if skip_for_can(
        "test_ecu_session_reset_on_lock_reacquire",
        "session-expiry keepalive timing not yet reliable over CAN",
    ) {
        return;
    }
    let test_env = TestEnv::builder().await.unwrap();
    let component = test_env.client().component(ECU_FLXC1000);

    // Create and acquire lock with 30s timeout
    let lock_expiration_timeout = Duration::from_secs(30);
    let ecu_lock = component
        .locks()
        .create(lock_expiration_timeout)
        .await
        .expect("Failed to create lock")
        .expect_status(StatusCode::CREATED)
        .into_body();

    // Set session with 2s expiry
    let session_expiration = 2u64;
    let switch_session_result = component
        .mode(SESSION_ID)
        .put::<security_and_session::put::Response<String>>(&SessionRequest {
            value: "extended".to_owned(),
            mode_expiration: Some(session_expiration),
        })
        .await
        .unwrap()
        .expect_status(StatusCode::OK);
    assert_eq!(switch_session_result.value.to_lowercase(), "extended");

    // Verify ECU sim is in extended session
    let ecu_state = ecusim::get_ecu_state(&test_env.ecu_sim, ECU_FLXC1000)
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
    let ecu_state_after_expiry = ecusim::get_ecu_state(&test_env.ecu_sim, ECU_FLXC1000)
        .await
        .expect("Failed to get ECU sim state after session expiry");

    assert_eq!(
        ecu_state_after_expiry.session_state,
        Some(ecusim::SessionState::Default),
        "ECU sim should be back to Default session after session expiry"
    );

    // Also verify through CDA API
    let session_result_after = component
        .mode(SESSION_ID)
        .get::<security_and_session::get::Response>()
        .await
        .unwrap()
        .expect_status(StatusCode::OK)
        .into_body();
    assert_eq!(
        session_result_after.value.map(|s| s.to_lowercase()),
        Some("default".to_owned())
    );

    // Delete the lock
    ecu_lock
        .release()
        .await
        .expect("lock operation failed")
        .expect_status(StatusCode::NO_CONTENT);
}

/// The caption, SI and nested SDGs of `sdg`.
///
/// # Panics
/// If `sdg` is a single SD.
fn expect_sdg(sdg: &SdSdg) -> (Option<&str>, Option<&str>, &[SdSdg]) {
    match sdg {
        SdSdg::Sdg { caption, si, sdgs } => (caption.as_deref(), si.as_deref(), sdgs),
        SdSdg::Sd { .. } => panic!("expected an SDG, got {sdg:?}"),
    }
}

/// The SI and value of `sd`.
///
/// # Panics
/// If `sd` is an SDG.
fn expect_sd(sd: &SdSdg) -> (Option<&str>, Option<&str>) {
    match sd {
        SdSdg::Sd { value, si, ti: _ } => (si.as_deref(), value.as_deref()),
        SdSdg::Sdg { .. } => panic!("expected an SD, got {sd:?}"),
    }
}

/// Checks the SDGs of FLXC1000: one SDG `default_sdg` with the single SD
/// `power_requirement_max`.
fn assert_flxc1000_sdgs(ecu: &Ecu) {
    let sdgs = ecu.sdgs.as_deref().expect("sdgs should be present");
    assert_eq!(sdgs.len(), 1);

    let (caption, si, inner) = expect_sdg(sdgs.first().expect("sdgs should have one element"));
    assert_eq!(caption, Some("default_sdg"));
    assert_eq!(si, Some("default"));
    assert_eq!(inner.len(), 1);

    let (si, value) = expect_sd(inner.first().expect("nested sdgs should have one element"));
    assert_eq!(si, Some("power_requirement_max"));
    assert_eq!(value, Some("1.21GW"));
}

/// [[ itest~sovd-api-component-sdgsd, ECU-level SDG retrieval, itest ]]
#[tokio::test]
async fn test_ecu_sdg_retrieval() {
    let test_env = TestEnv::builder().await.unwrap();

    // Retrieve sdgs and verify contents
    let ecu = test_env
        .client()
        .component(ECU_FLXC1000)
        .get_with(&ComponentQuery {
            include_sdgs: true,
            include_schema: false,
        })
        .await
        .expect("Failed to get the component with SDGs")
        .expect_status(StatusCode::OK);

    assert_eq!(
        ecu.data,
        "http://localhost:20002/vehicle/v15/components/flxc1000/data"
    );
    assert_eq!(
        ecu.operations,
        "http://localhost:20002/vehicle/v15/components/flxc1000/operations"
    );
    assert_eq!(
        ecu.configurations,
        "http://localhost:20002/vehicle/v15/components/flxc1000/configurations"
    );
    assert_eq!(
        ecu.modes,
        "http://localhost:20002/vehicle/v15/components/flxc1000/modes"
    );
    assert_eq!(
        ecu.locks,
        "http://localhost:20002/vehicle/v15/components/flxc1000/locks"
    );
    assert_eq!(
        ecu.faults,
        "http://localhost:20002/vehicle/v15/components/flxc1000/faults"
    );

    assert_flxc1000_sdgs(&ecu);
}

/// [[ itest~sovd-api-component-alias-sdgsd, ECU-level SDG retrieval (alias param), itest ]]
#[tokio::test]
async fn test_ecu_sdg_retrieval_alias() {
    let test_env = TestEnv::builder().await.unwrap();

    // Retrieve sdgs and verify contents. `ComponentQuery` serializes the
    // canonical name only, so the alias goes as JSON.
    let ecu = test_env
        .client()
        .component(ECU_FLXC1000)
        .get_with(&json!({ "x-include-sdgs": true }))
        .await
        .expect("Failed to get the component with SDGs")
        .expect_status(StatusCode::OK);

    assert_flxc1000_sdgs(&ecu);
}

/// Checks that `services_sdgs` has at least one entry, whose first SDG is
/// `caption`/`si` with the single SD `sd_si` = `sd_value`.
fn assert_first_service_sdg(
    services_sdgs: &ServicesSdgs,
    caption: &str,
    si: &str,
    sd_si: &str,
    sd_value: &str,
) {
    assert!(
        !services_sdgs.items.is_empty(),
        "items map should contain at least one entry"
    );

    // Find the entry - key format is "{service_name}_{action:?}" lowercased
    let entry = services_sdgs
        .items
        .values()
        .next()
        .expect("should have at least one service SDG entry");

    assert!(!entry.sdgs.is_empty(), "sdgs array should not be empty");

    let (actual_caption, actual_si, inner) = expect_sdg(
        entry
            .sdgs
            .first()
            .expect("sdgs array should have at least one element"),
    );
    assert_eq!(actual_caption, Some(caption));
    assert_eq!(actual_si, Some(si));
    assert_eq!(inner.len(), 1);

    let (actual_sd_si, actual_sd_value) = expect_sd(
        inner
            .first()
            .expect("inner sdgs should have at least one element"),
    );
    assert_eq!(actual_sd_si, Some(sd_si));
    assert_eq!(actual_sd_value, Some(sd_value));
}

/// [[ itest~sovd-api-component-data-sdgsd, Data-level SDG retrieval, itest ]]
#[tokio::test]
async fn test_data_sdg_retrieval() {
    let test_env = TestEnv::builder().await.unwrap();

    let services_sdgs = test_env
        .client()
        .component(ECU_FLXC1000)
        .data("FluxCapacitorPowerConsumption")
        .sdgs()
        .await
        .expect("Failed to get data SDGs")
        .expect_status(StatusCode::OK);

    assert_first_service_sdg(
        &services_sdgs,
        "flux_capacitor_sdg",
        "sensor_metadata",
        "measurement_unit",
        "gigawatts",
    );
}

/// [[ itest~sovd-api-component-operations-sdgsd, Operation-level SDG retrieval, itest ]]
#[tokio::test]
async fn test_operation_sdg_retrieval() {
    let test_env = TestEnv::builder().await.unwrap();

    let services_sdgs = test_env
        .client()
        .component(ECU_FLXC1000)
        .operation("SelfTest")
        .sdgs()
        .await
        .expect("Failed to get operation SDGs")
        .expect_status(StatusCode::OK);

    assert_first_service_sdg(
        &services_sdgs,
        "self_test_sdg",
        "routine_metadata",
        "expected_duration_ms",
        "5000",
    );
}

/// Polls until the ECU reaches the expected state, then asserts.
///
/// ECU states are updated asynchronously (variant detection tasks probe each
/// ECU on its transport, with per-probe timeouts), so a one-shot check races
/// the startup/detection loop - especially in mixed mode where undetected
/// CAN-mapped ECUs cost a probe timeout each before the loop moves on.
async fn validate_ecu_state(test_env: &TestEnv, ecu: &str, expected_state: State) {
    let component = test_env.client().component(ecu);
    let started = std::time::Instant::now();
    let mut status = component
        .get()
        .await
        .expect("failed to get ecu status")
        .expect_status(StatusCode::OK);
    while status.variant.state != expected_state && started.elapsed() < Duration::from_secs(10) {
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(200)).await;
        status = component
            .get()
            .await
            .expect("failed to get ecu status")
            .expect_status(StatusCode::OK);
    }
    assert_eq!(
        status.variant.state, expected_state,
        "ECU {ecu} state does not match {status:?}"
    );
}

/// Switches the session of `component` to `name`.
///
/// # Errors
/// See [`ModeHandle::put`](crate::client::components::modes::ModeHandle::put).
async fn switch_session(
    component: &Component<'_>,
    name: &str,
) -> client::Result<client::Response<security_and_session::put::Response<String>>> {
    component
        .mode(SESSION_ID)
        .put(&SessionRequest {
            value: name.to_owned(),
            mode_expiration: None,
        })
        .await
}

/// Requests a seed for the security level `Level_5_RequestSeed`, with the
/// `RequestSeed` parameters `parameters`.
async fn request_seed(
    component: &Component<'_>,
    parameters: Option<HashMap<String, serde_json::Value>>,
) -> client::Result<client::Response<RequestSeedResponse>> {
    component
        .mode(SECURITY_ID)
        .put(&security_and_session::put::Request {
            value: "Level_5_RequestSeed".to_owned(),
            mode_expiration: None,
            key: None,
            parameters,
        })
        .await
}

async fn assert_request_seed_rejected(
    component: &Component<'_>,
    parameters: Option<HashMap<String, serde_json::Value>>,
    expected_status: StatusCode,
) {
    let Err(error) = request_seed(component, parameters).await else {
        panic!("RequestSeed should be rejected");
    };
    assert_eq!(error.status(), Some(expected_status), "{error}");
}

/// Sends `key` for the security level `Level_5`.
async fn send_key(
    component: &Component<'_>,
    key: String,
) -> client::Result<client::Response<security_and_session::put::Response<String>>> {
    component
        .mode(SECURITY_ID)
        .put(&security_and_session::put::Request {
            value: "Level_5".to_owned(),
            mode_expiration: None,
            key: Some(ModeKey { send_key: key }),
            parameters: None,
        })
        .await
}

async fn get_comm_control(
    component: &Component<'_>,
) -> client::Result<client::Response<commctrl::get::Response>> {
    component.mode(COMM_CONTROL_ID).get().await
}

async fn set_comm_control(
    component: &Component<'_>,
    value: &str,
    parameters: Option<cda_interfaces::HashMap<String, serde_json::Value>>,
) -> client::Result<client::Response<commctrl::put::Response>> {
    component
        .mode(COMM_CONTROL_ID)
        .put(&commctrl::put::Request {
            value: value.to_owned(),
            parameters,
        })
        .await
}
