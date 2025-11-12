/*
 * Copyright (c) 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
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

use http::{HeaderMap, Method, StatusCode};
use opensovd_cda_lib::config::configfile::Configuration;
use serde::{Serialize, de::DeserializeOwned};

use crate::{
    sovd,
    sovd::{
        locks,
        locks::{create_lock, lock_operation},
    },
    util::{
        TestingError, ecusim,
        http::{
            auth_header, extract_field_from_json, response_to_json, response_to_t, send_cda_request,
        },
        runtime::{TestRuntime, restart_cda, setup_integration_test, start_ecu_sim, stop_ecu_sim},
    },
};

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

    let expiration_timeout = Duration::from_secs(60);
    let ecu_lock = create_lock(
        expiration_timeout,
        &locks::ecu_endpoint(),
        StatusCode::CREATED,
        &runtime.config,
        &auth,
    )
    .await;
    let lock_id =
        extract_field_from_json::<String>(&response_to_json(&ecu_lock).unwrap(), "id").unwrap();

    // Lock the ECU
    lock_operation(
        &locks::ecu_endpoint(),
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

    let switch_session_result = switch_session(
        "extended",
        &&runtime.config,
        &auth,
        ecu_endpoint,
        StatusCode::OK,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(switch_session_result.value, "extended");
    let session_result = session(&runtime.config, &auth, ecu_endpoint).await.unwrap();
    assert_eq!(session_result.value, Some("extended".to_owned()));
    assert_eq!(session_result.name, Some("session".to_owned()));

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

    // The CDA return the RAW response in the seed. this is the _complete_ uds frame
    // including service id and prefix. Which has to be skipped for the key calculation.
    // In the ecu sim it's hard coded that we have to add 13 to each byte of the seed.
    // So we do that here to generate the correct key.
    let key = seed_response
        .seed
        .request_seed
        .split_whitespace()
        // skip 3 because after prefix, sid, there is 1 byte which repeats the requested level
        // this is not part of the seed
        .skip(3)
        .filter_map(|s| u8::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .map(|byte| byte.wrapping_add(13) as i8)
        .map(|byte| format!("0x{:02x}", byte as u8))
        .collect::<Vec<_>>()
        .join(" ");

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
    assert_eq!(security_result.name, Some("security".to_owned()));

    // Delete the ECU lock
    lock_operation(
        &locks::ecu_endpoint(),
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
        &runtime,
        &auth,
        sovd::ECU_FLXC1000_ENDPOINT,
        sovd_interfaces::components::ecu::State::Duplicate,
    )
    .await;

    validate_ecu_state(
        &runtime,
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
        &runtime,
        &auth,
        sovd::ECU_FLXC1000_ENDPOINT,
        sovd_interfaces::components::ecu::State::NoVariantDetected,
    )
    .await;
    validate_ecu_state(
        &runtime,
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
        &runtime,
        &auth,
        sovd::ECU_FLXC1000_ENDPOINT,
        sovd_interfaces::components::ecu::State::Disconnected,
    )
    .await;
    validate_ecu_state(
        &runtime,
        &auth,
        sovd::ECU_FLXCNG1000_ENDPOINT,
        sovd_interfaces::components::ecu::State::Disconnected,
    )
    .await;

    // restart CDA while sim is offline and check if ECUs are marked as offline
    restart_cda(&runtime.config).await.unwrap();
    validate_ecu_state(
        &runtime,
        &auth,
        sovd::ECU_FLXC1000_ENDPOINT,
        sovd_interfaces::components::ecu::State::Offline,
    )
    .await;
    validate_ecu_state(
        &runtime,
        &auth,
        sovd::ECU_FLXCNG1000_ENDPOINT,
        sovd_interfaces::components::ecu::State::Offline,
    )
    .await;

    // restart sim and wait for ECUs to come online,
    // status should be detected without manual variant detection
    start_ecu_sim(&runtime.ecu_sim).await.unwrap();
    // todo: sim needs to run before CDA to work properly
    restart_cda(&runtime.config).await.unwrap();

    validate_ecu_state(
        &runtime,
        &auth,
        sovd::ECU_FLXC1000_ENDPOINT,
        sovd_interfaces::components::ecu::State::Online,
    )
    .await;
    validate_ecu_state(
        &runtime,
        &auth,
        sovd::ECU_FLXCNG1000_ENDPOINT,
        sovd_interfaces::components::ecu::State::Duplicate,
    )
    .await;
}

async fn validate_ecu_state(
    runtime: &TestRuntime,
    auth: &HeaderMap,
    ecu: &str,
    expected_state: sovd_interfaces::components::ecu::State,
) {
    let ecu_status = ecu_status(&runtime.config, &auth, ecu).await.unwrap();
    assert_eq!(
        ecu_status.variant.state, expected_state,
        "ECU {ecu} state does not match {ecu_status:?}"
    );
}

async fn session(
    config: &Configuration,
    headers: &HeaderMap,
    ecu_endpoint: &str,
) -> Result<sovd_interfaces::components::ecu::modes::Mode<String>, TestingError> {
    get_mode(config, headers, ecu_endpoint, "session").await
}

async fn security(
    config: &Configuration,
    headers: &HeaderMap,
    ecu_endpoint: &str,
) -> Result<sovd_interfaces::components::ecu::modes::Mode<String>, TestingError> {
    get_mode(config, headers, ecu_endpoint, "security").await
}

async fn switch_session(
    name: &str,
    config: &Configuration,
    headers: &HeaderMap,
    ecu_endpoint: &str,
    expected_status: StatusCode,
) -> Result<Option<sovd_interfaces::components::ecu::modes::put::Response<String>>, TestingError> {
    put_mode(
        config,
        headers,
        ecu_endpoint,
        "session",
        sovd_interfaces::components::ecu::modes::put::Request {
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
) -> Result<Option<sovd_interfaces::components::ecu::modes::put::RequestSeedResponse>, TestingError>
{
    put_mode(
        config,
        headers,
        ecu_endpoint,
        "security",
        sovd_interfaces::components::ecu::modes::put::Request {
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
) -> Result<Option<sovd_interfaces::components::ecu::modes::put::Response<String>>, TestingError> {
    put_mode(
        config,
        headers,
        ecu_endpoint,
        "security",
        sovd_interfaces::components::ecu::modes::put::Request {
            value: name,
            mode_expiration: None,
            key: Some(sovd_interfaces::components::ecu::modes::put::ModeKey { send_key: key }),
        },
        excepted_status,
    )
    .await
}

async fn put_mode<T: DeserializeOwned, S: Serialize>(
    config: &Configuration,
    headers: &HeaderMap,
    ecu_endpoint: &str,
    sub_path: &str,
    request: S,
    excepted_status: StatusCode,
) -> Result<Option<T>, TestingError> {
    let request_body = serde_json::to_string(&request).map_err(|e| {
        TestingError::InvalidData(format!("Failed to serialize request body: {}", e))
    })?;
    let http_response = send_cda_request(
        config,
        &format!("{ecu_endpoint}/modes/{sub_path}"),
        excepted_status,
        Method::PUT,
        Some(&request_body),
        Some(headers),
    )
    .await?;
    if excepted_status == StatusCode::OK {
        Ok(Some(response_to_t(&http_response)?))
    } else {
        Ok(None)
    }
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
        &config,
        ecu_endpoint,
        StatusCode::OK,
        Method::GET,
        None,
        Some(&headers),
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
        &config,
        ecu_endpoint,
        StatusCode::CREATED,
        Method::PUT,
        None,
        Some(&headers),
    )
    .await?;
    Ok(())
}
