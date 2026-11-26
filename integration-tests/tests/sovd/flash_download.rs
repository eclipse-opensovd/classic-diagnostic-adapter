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
use serde::Deserialize;
use sovd_interfaces::components::ecu::modes::security_and_session::put::RequestSeedResponse;

use crate::{
    sovd::{self, ECU_FLXC1000, compute_security_key, ecu::switch_session, put_mode},
    util::{
        TestingError,
        ecusim::{self, EcuSim},
        endpoints::APPS_SOVD2UDS_BULK_DATA_FLASHFILES,
        http::{
            extract_field_from_json, response_to_json, response_to_t,
            send_authenticated_cda_request,
        },
        locks::{self, Lock, create_lock, lock_operation},
        test_env::TestEnv,
    },
};

/// Integration test for the full flash download sequence:
/// `RequestDownload` (0x34) -> `TransferData` (0x36) -> `TransferExit` (0x37)
///
/// Prerequisites enforced by the ECU simulator:
/// - Variant must be BOOT
/// - Session must be PROGRAMMING
/// - `SecurityAccess` must be at least `LEVEL_05` (test uses `LEVEL_07`)
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "Test scenario is easier to understand kept together"
)]
async fn test_flash_download_transfer_sequence() {
    let test_env = TestEnv::builder().await.unwrap();
    let ecu_endpoint = sovd::COMPONENTS_FLXC1000_BASE;

    // Create and acquire ECU lock
    let expiration_timeout = Duration::from_secs(120);
    let ecu_lock = create_lock(
        expiration_timeout,
        locks::COMPONENTS_FLXC1000_LOCKS,
        StatusCode::CREATED,
        &test_env,
    )
    .await;
    let lock_id =
        extract_field_from_json::<String>(&response_to_json(&ecu_lock).unwrap(), "id").unwrap();

    lock_operation(
        locks::COMPONENTS_FLXC1000_LOCKS,
        Some(&lock_id),
        &test_env,
        StatusCode::OK,
        Method::GET,
    )
    .await;

    // Switch ECU sim to BOOT variant
    ecusim::switch_variant(&test_env.ecu_sim, "FLXC1000", "BOOT")
        .await
        .unwrap();

    // Force variant detection so the CDA picks up the boot variant
    send_authenticated_cda_request(
        &test_env,
        ecu_endpoint,
        StatusCode::OK,
        Method::PUT,
        None,
        None,
    )
    .await
    .unwrap();

    // Switch to programming session
    let session_result = switch_session("programming", &test_env, ecu_endpoint, StatusCode::OK)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        session_result.value.to_lowercase(),
        "programming",
        "Should be in programming session"
    );

    // Start recording to verify the raw UDS frames sent for SecurityAccess Level 7
    let recorder = test_env
        .record(ECU_FLXC1000)
        .await
        .expect("Failed to start ECU sim recording");

    // SecurityAccess Level 7 (request seed + send key)
    let seed_response: RequestSeedResponse = put_mode(
        &test_env,
        ecu_endpoint,
        "security",
        sovd_interfaces::components::ecu::modes::security_and_session::put::Request {
            value: "Level_7_RequestSeed".to_owned(),
            mode_expiration: None,
            key: None,
            parameters: None,
        },
        StatusCode::OK,
    )
    .await
    .unwrap()
    .unwrap();

    // Verify that the seed payload is the deterministic sequence 0x00..0x07
    assert_eq!(
        seed_response.seed.request_seed, "0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07",
        "Expected deterministic seed payload from ECU sim"
    );

    let key = compute_security_key(&seed_response.seed.request_seed);

    let key_result: sovd_interfaces::components::ecu::modes::security_and_session::put::Response<
        String,
    > = put_mode(
        &test_env,
        ecu_endpoint,
        "security",
        sovd_interfaces::components::ecu::modes::security_and_session::put::Request {
            value: "Level_7".to_owned(),
            mode_expiration: None,
            key: Some(
                sovd_interfaces::components::ecu::modes::security_and_session::put::ModeKey {
                    send_key: key,
                },
            ),
            parameters: None,
        },
        StatusCode::OK,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(key_result.value, "Level_7");

    // Verify the ECU sim is in the expected state
    let ecu_state = ecusim::get_ecu_state(&test_env.ecu_sim, ECU_FLXC1000)
        .await
        .expect("Failed to get ECU sim state");
    assert!(
        matches!(
            ecu_state.security_access,
            Some(ecusim::SecurityAccess::Level07)
        ),
        "ECU sim should be at SecurityAccess Level 07, got {:?}",
        ecu_state.security_access
    );

    // Verify the raw UDS frames sent during SecurityAccess Level 7:
    //   RequestSeed: 27 07
    //   SendKey:     27 08 <key> (seed 00..07, key = each byte + 13 = 0d..14)
    let recorded_frames = recorder
        .stop()
        .await
        .expect("Failed to stop ECU sim recording");
    assert!(
        recorded_frames
            .iter()
            .any(|f| f.eq_ignore_ascii_case("2707")),
        "Expected RequestSeed Level_7 frame (2707) in recording, got: {recorded_frames:?}"
    );
    assert!(
        recorded_frames
            .iter()
            .any(|f| f.eq_ignore_ascii_case("27080d0e0f1011121314")),
        "Expected SendKey Level_7 frame (27080d0e0f1011121314) in recording, got: \
         {recorded_frames:?}"
    );

    // List flash files to get the file ID
    let flash_files_response = send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_BULK_DATA_FLASHFILES,
        StatusCode::OK,
        Method::GET,
        None,
        None,
    )
    .await
    .unwrap();
    let flash_files_json = response_to_json(&flash_files_response).unwrap();
    let files = flash_files_json
        .get("items")
        .and_then(|v| v.as_array())
        .expect("Expected 'items' array in flash files response");
    assert!(
        !files.is_empty(),
        "Expected at least one flash file, got none. Response: {flash_files_json:#?}"
    );

    // Find the test_flash.bin file specifically (not .gitkeep or other files)
    // The origin path field is serialized as "x-sovd2uds-OrigPath" in the JSON response
    let flash_file = files
        .iter()
        .find(|f| {
            f.get("x-sovd2uds-OrigPath")
                .and_then(|v| v.as_str())
                .is_some_and(|p| p.contains("test_flash"))
        })
        .expect("Expected to find test_flash.bin in flash files list");
    let file_id = flash_file
        .get("id")
        .and_then(|v| v.as_str())
        .expect("Expected 'id' in flash file")
        .to_owned();
    let file_size = flash_file
        .get("size")
        .and_then(serde_json::Value::as_u64)
        .expect("Expected 'size' in flash file");
    assert!(
        file_size > 0,
        "Flash file size should be > 0, got {file_size}. File: {flash_file:#?}"
    );

    // RequestDownload
    // memory address: 0x00000000, memory size: file_size
    // DataFormatIdentifier: 0x00 (no compression, no encryption)
    // AddressAndLengthFormatIdentifier: 0x44 (4-byte address, 4-byte size)
    let request_download_body = serde_json::json!({
        "requestdownload": {
            "DataFormatIdentifier": 0,
            "AddressAndLengthFormatIdentifier": 0x44,
            "MemoryAddress": "0x00 0x00 0x00 0x00",
            "MemorySize": format!("0x{:02x} 0x{:02x} 0x{:02x} 0x{:02x}",
                (file_size >> 24) & 0xFF,
                (file_size >> 16) & 0xFF,
                (file_size >> 8) & 0xFF,
                file_size & 0xFF
            )
        }
    });
    let request_download_response = send_authenticated_cda_request(
        &test_env,
        &format!("{ecu_endpoint}/x-sovd2uds-download/requestdownload"),
        StatusCode::OK,
        Method::PUT,
        Some(&request_download_body.to_string()),
        None,
    )
    .await
    .unwrap();

    let rd_json = response_to_json(&request_download_response).unwrap();
    let rd_params = rd_json
        .get("requestdownload")
        .expect("Expected 'requestdownload' field in response");
    let max_block_length = rd_params
        .get("MaxNumberOfBlockLength")
        .expect("Expected 'MaxNumberOfBlockLength' in response");
    assert!(
        max_block_length.as_u64().unwrap_or(0) > 0,
        "MaxNumberOfBlockLength should be > 0, got {max_block_length}"
    );

    // Start flash transfer (TransferData)
    let flash_transfer_body = serde_json::json!({
        "blocksequencecounter": 1,
        "blocksize": 128,
        "offset": 0,
        "length": file_size,
        "id": file_id
    });

    let flash_transfer_response = send_authenticated_cda_request(
        &test_env,
        &format!("{ecu_endpoint}/x-sovd2uds-download/flashtransfer"),
        StatusCode::OK,
        Method::POST,
        Some(&flash_transfer_body.to_string()),
        None,
    )
    .await
    .unwrap();

    let transfer_json = response_to_json(&flash_transfer_response).unwrap();
    let transfer_id = transfer_json
        .get("id")
        .and_then(|v| v.as_str())
        .expect("Expected 'id' in flash transfer response")
        .to_owned();

    // Poll transfer status until finished
    let mut transfer_finished = false;
    for attempt in 0..20 {
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(500)).await;

        let status_response = send_authenticated_cda_request(
            &test_env,
            &format!("{ecu_endpoint}/x-sovd2uds-download/flashtransfer/{transfer_id}"),
            StatusCode::OK,
            Method::GET,
            None,
            None,
        )
        .await
        .unwrap();

        let status_json = response_to_json(&status_response).unwrap();
        let status = status_json
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        if status == "finished" {
            transfer_finished = true;
            let acknowledged = status_json
                .get("acknowledgedBytes")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            assert!(
                acknowledged > 0,
                "Expected acknowledgedBytes > 0, got {acknowledged}"
            );
            break;
        }

        assert!(
            status != "aborted",
            "Flash transfer was aborted on attempt {attempt}. Status: {status_json:#?}"
        );
    }
    assert!(
        transfer_finished,
        "Flash transfer did not finish within the timeout"
    );

    // Remove finished flash transfer
    send_authenticated_cda_request(
        &test_env,
        &format!("{ecu_endpoint}/x-sovd2uds-download/flashtransfer/{transfer_id}"),
        StatusCode::NO_CONTENT,
        Method::DELETE,
        None,
        None,
    )
    .await
    .unwrap();

    // TransferExit
    send_authenticated_cda_request(
        &test_env,
        &format!("{ecu_endpoint}/x-sovd2uds-download/transferexit"),
        StatusCode::NO_CONTENT,
        Method::PUT,
        None,
        None,
    )
    .await
    .unwrap();

    // Verify on ECU simulator
    let sim_transfers = get_sim_data_transfers(&test_env.ecu_sim, ECU_FLXC1000)
        .await
        .expect("Failed to get data transfers from ECU sim");
    assert!(
        !sim_transfers.transfers.is_empty(),
        "ECU sim should have at least one data transfer recorded"
    );
    let last_transfer = sim_transfers.transfers.last().unwrap();
    assert!(
        !last_transfer.is_active,
        "Last transfer should be finished (not active)"
    );
    assert!(
        last_transfer.data_transfer_count > 0,
        "Expected at least one data block transferred, got {}",
        last_transfer.data_transfer_count
    );
    assert!(
        last_transfer.checksum.is_some(),
        "Expected a checksum after transfer completion"
    );
    assert_eq!(
        last_transfer.bytes_received, file_size,
        "ECU sim must have received the whole file"
    );
    assert_eq!(
        last_transfer.repeated_blocks, 0,
        "No block should have been sent twice"
    );

    // Cleanup: delete lock
    lock_operation(
        locks::COMPONENTS_FLXC1000_LOCKS,
        Some(&lock_id),
        &test_env,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;
}

/// Verify that attempting a flash transfer with length=0 is rejected with a bad request error.
/// This guards against a zero-length transfer silently staying in "running" status forever.
/// Uses `SecurityAccess` `LEVEL_05` (minimum level accepted by the ECU simulator for flash operations).
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "Test scenario is easier to understand kept together"
)]
async fn test_flash_transfer_zero_length_rejected() {
    let test_env = TestEnv::builder().await.unwrap();
    let ecu_endpoint = sovd::COMPONENTS_FLXC1000_BASE;

    // Create and acquire ECU lock
    let expiration_timeout = Duration::from_secs(120);
    let ecu_lock = create_lock(
        expiration_timeout,
        locks::COMPONENTS_FLXC1000_LOCKS,
        StatusCode::CREATED,
        &test_env,
    )
    .await;
    let lock_id =
        extract_field_from_json::<String>(&response_to_json(&ecu_lock).unwrap(), "id").unwrap();

    lock_operation(
        locks::COMPONENTS_FLXC1000_LOCKS,
        Some(&lock_id),
        &test_env,
        StatusCode::OK,
        Method::GET,
    )
    .await;

    // Switch ECU sim to BOOT variant
    ecusim::switch_variant(&test_env.ecu_sim, "FLXC1000", "BOOT")
        .await
        .unwrap();

    // Force variant detection
    send_authenticated_cda_request(
        &test_env,
        ecu_endpoint,
        StatusCode::OK,
        Method::PUT,
        None,
        None,
    )
    .await
    .unwrap();

    // Switch to programming session
    switch_session("programming", &test_env, ecu_endpoint, StatusCode::OK)
        .await
        .unwrap()
        .unwrap();

    // Start recording to verify the raw UDS frames sent for SecurityAccess Level 5
    let recorder = test_env
        .record(ECU_FLXC1000)
        .await
        .expect("Failed to start ECU sim recording");

    // SecurityAccess Level 5
    let seed_response: RequestSeedResponse = put_mode(
        &test_env,
        ecu_endpoint,
        "security",
        sovd_interfaces::components::ecu::modes::security_and_session::put::Request {
            value: "Level_5_RequestSeed".to_owned(),
            mode_expiration: None,
            key: None,
            parameters: None,
        },
        StatusCode::OK,
    )
    .await
    .unwrap()
    .unwrap();

    // Verify that the seed payload is the deterministic sequence 0x00..0x07
    assert_eq!(
        seed_response.seed.request_seed, "0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07",
        "Expected deterministic seed payload from ECU sim"
    );

    let key = compute_security_key(&seed_response.seed.request_seed);

    let key_result: sovd_interfaces::components::ecu::modes::security_and_session::put::Response<
        String,
    > = put_mode(
        &test_env,
        ecu_endpoint,
        "security",
        sovd_interfaces::components::ecu::modes::security_and_session::put::Request {
            value: "Level_5".to_owned(),
            mode_expiration: None,
            key: Some(
                sovd_interfaces::components::ecu::modes::security_and_session::put::ModeKey {
                    send_key: key,
                },
            ),
            parameters: None,
        },
        StatusCode::OK,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(key_result.value, "Level_5");

    // Verify the ECU sim is in the expected state
    let ecu_state = ecusim::get_ecu_state(&test_env.ecu_sim, ECU_FLXC1000)
        .await
        .expect("Failed to get ECU sim state");
    assert!(
        matches!(
            ecu_state.security_access,
            Some(ecusim::SecurityAccess::Level05)
        ),
        "ECU sim should be at SecurityAccess Level 05, got {:?}",
        ecu_state.security_access
    );

    // Verify the raw UDS frames sent during SecurityAccess Level 5:
    //   `RequestSeed`: 27 05
    //   `SendKey`:     27 06 <key> (seed 00..07, key = each byte + 13 = 0d..14)
    let recorded_frames = recorder
        .stop()
        .await
        .expect("Failed to stop ECU sim recording");
    assert!(
        recorded_frames
            .iter()
            .any(|f| f.eq_ignore_ascii_case("2705")),
        "Expected RequestSeed Level_5 frame (2705) in recording, got: {recorded_frames:?}"
    );
    assert!(
        recorded_frames
            .iter()
            .any(|f| f.eq_ignore_ascii_case("27060d0e0f1011121314")),
        "Expected SendKey Level_5 frame (27060d0e0f1011121314) in recording, got: \
         {recorded_frames:?}"
    );

    // RequestDownload (required before flash transfer)
    let request_download_body = serde_json::json!({
        "requestdownload": {
            "DataFormatIdentifier": 0,
            "AddressAndLengthFormatIdentifier": 0x44,
            "MemoryAddress": "0x00 0x00 0x00 0x00",
            "MemorySize": "0x00 0x00 0x01 0x00"
        }
    });
    send_authenticated_cda_request(
        &test_env,
        &format!("{ecu_endpoint}/x-sovd2uds-download/requestdownload"),
        StatusCode::OK,
        Method::PUT,
        Some(&request_download_body.to_string()),
        None,
    )
    .await
    .unwrap();

    // List flash files to get a valid file ID
    let flash_files_response = send_authenticated_cda_request(
        &test_env,
        APPS_SOVD2UDS_BULK_DATA_FLASHFILES,
        StatusCode::OK,
        Method::GET,
        None,
        None,
    )
    .await
    .unwrap();
    let flash_files_json = response_to_json(&flash_files_response).unwrap();
    let files = flash_files_json
        .get("items")
        .and_then(|v| v.as_array())
        .expect("Expected 'items' array in flash files response");
    let flash_file = files
        .iter()
        .find(|f| {
            f.get("x-sovd2uds-OrigPath")
                .and_then(|v| v.as_str())
                .is_some_and(|p| p.contains("test_flash"))
        })
        .expect("Expected to find test_flash.bin in flash files list");
    let file_id = flash_file
        .get("id")
        .and_then(|v| v.as_str())
        .expect("Expected 'id' in flash file");

    // Attempt flash transfer with length=0 - should be rejected
    let zero_length_body = serde_json::json!({
        "blocksequencecounter": 1,
        "blocksize": 128,
        "offset": 0,
        "length": 0,
        "id": file_id
    });

    send_authenticated_cda_request(
        &test_env,
        &format!("{ecu_endpoint}/x-sovd2uds-download/flashtransfer"),
        StatusCode::BAD_REQUEST,
        Method::POST,
        Some(&zero_length_body.to_string()),
        None,
    )
    .await
    .unwrap();

    // Cleanup
    lock_operation(
        locks::COMPONENTS_FLXC1000_LOCKS,
        Some(&lock_id),
        &test_env,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;
}

/// Integration test for the `Supplier` security access level, which uses (semantic label)
/// naming in the ODX database: `RequestSeed_Supplier` / `SendKey_Supplier`.
///
/// The SOVD seed hint `"Supplier_RequestSeed"` has only two underscore-separated parts,
/// so the lookup relies on the `split_at_last_underscore` two-part path and phase-1
/// service resolution (the level name `"Supplier"` is contained in `RequestSeed_Supplier`).
///
/// UDS bytes verified:
/// - `RequestSeed`: `27 09`
/// - `SendKey`:     `27 0A <key>` (seed 00..07, key = each byte + 13 = 0d..14)
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "Test scenario is easier to understand kept together"
)]
async fn test_security_access_supplier_level() {
    let test_env = TestEnv::builder().await.unwrap();
    let ecu_endpoint = sovd::COMPONENTS_FLXC1000_BASE;

    // Create and acquire ECU lock
    let expiration_timeout = Duration::from_secs(120);
    let ecu_lock = create_lock(
        expiration_timeout,
        locks::COMPONENTS_FLXC1000_LOCKS,
        StatusCode::CREATED,
        &test_env,
    )
    .await;
    let lock_id =
        extract_field_from_json::<String>(&response_to_json(&ecu_lock).unwrap(), "id").unwrap();

    lock_operation(
        locks::COMPONENTS_FLXC1000_LOCKS,
        Some(&lock_id),
        &test_env,
        StatusCode::OK,
        Method::GET,
    )
    .await;

    // Switch ECU sim to BOOT variant (security access services live on the boot variant)
    ecusim::switch_variant(&test_env.ecu_sim, "FLXC1000", "BOOT")
        .await
        .unwrap();

    // Force variant detection
    send_authenticated_cda_request(
        &test_env,
        ecu_endpoint,
        StatusCode::OK,
        Method::PUT,
        None,
        None,
    )
    .await
    .unwrap();

    // Switch to programming session
    switch_session("programming", &test_env, ecu_endpoint, StatusCode::OK)
        .await
        .unwrap()
        .unwrap();

    // Start recording to verify the raw UDS frames sent for SecurityAccess Supplier (Level 9)
    let recorder = test_env
        .record(ECU_FLXC1000)
        .await
        .expect("Failed to start ECU sim recording");

    // SecurityAccess Supplier - RequestSeed via ODX name RequestSeed_Supplier
    // The SOVD value "Supplier_RequestSeed" has exactly two underscore-separated parts;
    // split_at_last_underscore recognises "RequestSeed" as the service suffix and
    // produces level="Supplier", seed_service=Some("RequestSeed").
    let seed_response: RequestSeedResponse = put_mode(
        &test_env,
        ecu_endpoint,
        "security",
        sovd_interfaces::components::ecu::modes::security_and_session::put::Request {
            value: "Supplier_RequestSeed".to_owned(),
            mode_expiration: None,
            key: None,
            parameters: None,
        },
        StatusCode::OK,
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(
        seed_response.seed.request_seed, "0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07",
        "Expected deterministic seed payload from ECU sim"
    );

    let key = compute_security_key(&seed_response.seed.request_seed);

    let key_result: sovd_interfaces::components::ecu::modes::security_and_session::put::Response<
        String,
    > = put_mode(
        &test_env,
        ecu_endpoint,
        "security",
        sovd_interfaces::components::ecu::modes::security_and_session::put::Request {
            value: "Supplier".to_owned(),
            mode_expiration: None,
            key: Some(
                sovd_interfaces::components::ecu::modes::security_and_session::put::ModeKey {
                    send_key: key,
                },
            ),
            parameters: None,
        },
        StatusCode::OK,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(key_result.value, "Supplier");

    // Verify the ECU sim is in the expected state
    let ecu_state = ecusim::get_ecu_state(&test_env.ecu_sim, ECU_FLXC1000)
        .await
        .expect("Failed to get ECU sim state");
    assert!(
        matches!(
            ecu_state.security_access,
            Some(ecusim::SecurityAccess::Level09)
        ),
        "ECU sim should be at SecurityAccess Level 09, got {:?}",
        ecu_state.security_access
    );

    // Verify the raw UDS frames sent during SecurityAccess Supplier:
    //   RequestSeed: 27 09
    //   SendKey:     27 0A <key> (seed 00..07, key = each byte + 13 = 0d..14)
    let recorded_frames = recorder
        .stop()
        .await
        .expect("Failed to stop ECU sim recording");
    assert!(
        recorded_frames
            .iter()
            .any(|f| f.eq_ignore_ascii_case("2709")),
        "Expected RequestSeed Supplier frame (2709) in recording, got: {recorded_frames:?}"
    );
    assert!(
        recorded_frames
            .iter()
            .any(|f| f.eq_ignore_ascii_case("270a0d0e0f1011121314")),
        "Expected SendKey Supplier frame (270a0d0e0f1011121314) in recording, got: \
         {recorded_frames:?}"
    );

    // Cleanup
    lock_operation(
        locks::COMPONENTS_FLXC1000_LOCKS,
        Some(&lock_id),
        &test_env,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;
}

// Helper types and functions for ECU sim data transfer verification

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SimDataTransferDownload {
    address_and_length_identifier: u8,
    memory_address: String,
    #[allow(
        dead_code,
        reason = "Fields deserialized from ECU simulator JSON responses"
    )]
    memory_size: String,
    is_active: bool,
    data_transfer_count: i32,
    checksum: Option<String>,
    bytes_received: u64,
    repeated_blocks: u32,
}

#[derive(Debug, Deserialize)]
struct SimDataTransfers {
    transfers: Vec<SimDataTransferDownload>,
}

async fn get_sim_data_transfers(sim: &EcuSim, ecu: &str) -> Result<SimDataTransfers, TestingError> {
    let url = reqwest::Url::parse(&format!(
        "http://{}:{}/{ecu}/datatransfers/downloads",
        sim.host, sim.control_port
    ))
    .map_err(|e| TestingError::InvalidUrl(e.to_string()))?;

    let response =
        crate::util::http::send_request(StatusCode::OK, Method::GET, None, None, url).await?;
    response_to_t(&response)
}

const FLASH_CLASS_BOOTLOADER: &str = "flash_download_upload_bootloader";

/// Acquires an ECU lock and brings FLXC1000 into the state required for flashing
/// (BOOT variant, programming session, `SecurityAccess` `LEVEL_07`).
/// Returns the lock id.
async fn prepare_flxc1000_for_flashing(test_env: &TestEnv) -> String {
    let ecu_endpoint = sovd::COMPONENTS_FLXC1000_BASE;
    let ecu_lock = create_lock(
        Duration::from_secs(120),
        locks::COMPONENTS_FLXC1000_LOCKS,
        StatusCode::CREATED,
        test_env,
    )
    .await;
    let lock_id = extract_field_from_json::<String>(
        &response_to_json(&ecu_lock).expect("Flash test preparation failed"),
        "id",
    )
    .expect("Flash test preparation failed");

    ecusim::switch_variant(&test_env.ecu_sim, "FLXC1000", "BOOT")
        .await
        .expect("Flash test preparation failed");
    send_authenticated_cda_request(
        test_env,
        ecu_endpoint,
        StatusCode::OK,
        Method::PUT,
        None,
        None,
    )
    .await
    .expect("Flash test preparation failed");

    switch_session("programming", test_env, ecu_endpoint, StatusCode::OK)
        .await
        .expect("Flash test preparation failed")
        .expect("Flash test preparation failed");

    let seed_response: RequestSeedResponse = put_mode(
        test_env,
        ecu_endpoint,
        "security",
        sovd_interfaces::components::ecu::modes::security_and_session::put::Request {
            value: "Level_7_RequestSeed".to_owned(),
            mode_expiration: None,
            key: None,
            parameters: None,
        },
        StatusCode::OK,
    )
    .await
    .expect("Flash test preparation failed")
    .expect("Flash test preparation failed");
    let key = compute_security_key(&seed_response.seed.request_seed);
    let _: sovd_interfaces::components::ecu::modes::security_and_session::put::Response<String> =
        put_mode(
            test_env,
            ecu_endpoint,
            "security",
            sovd_interfaces::components::ecu::modes::security_and_session::put::Request {
                value: "Level_7".to_owned(),
                mode_expiration: None,
                key: Some(
                    sovd_interfaces::components::ecu::modes::security_and_session::put::ModeKey {
                        send_key: key,
                    },
                ),
                parameters: None,
            },
            StatusCode::OK,
        )
        .await
        .expect("Flash test preparation failed")
        .expect("Flash test preparation failed");

    lock_id
}

/// Returns `(id, size)` of `test_flash.bin` from the flash file list.
async fn find_test_flash_file(test_env: &TestEnv) -> (String, u64) {
    let flash_files_response = send_authenticated_cda_request(
        test_env,
        APPS_SOVD2UDS_BULK_DATA_FLASHFILES,
        StatusCode::OK,
        Method::GET,
        None,
        None,
    )
    .await
    .expect("Flash test preparation failed");
    let flash_files_json =
        response_to_json(&flash_files_response).expect("Flash test preparation failed");
    let flash_file = flash_files_json
        .get("items")
        .and_then(|v| v.as_array())
        .and_then(|files| {
            files.iter().find(|f| {
                f.get("x-sovd2uds-OrigPath")
                    .and_then(|v| v.as_str())
                    .is_some_and(|p| p.contains("test_flash"))
            })
        })
        .expect("Expected to find test_flash.bin in flash files list");
    let file_id = flash_file
        .get("id")
        .and_then(|v| v.as_str())
        .expect("Expected 'id' in flash file")
        .to_owned();
    let file_size = flash_file
        .get("size")
        .and_then(serde_json::Value::as_u64)
        .expect("Expected 'size' in flash file");
    (file_id, file_size)
}

/// Verifies that the functional class used to resolve the flash services can be selected
/// per request via `flashClass` (case-insensitive field name and value), and that invalid
/// selections are rejected.
///
/// The test database contains a second set of flash services with the functional class
/// `flash_download_upload_bootloader`, whose `RequestDownload` uses a 2-byte memory address
/// and size (the default one uses 4 bytes). The memory address recorded by the ECU simulator
/// therefore shows which service was used.
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "Test scenario is easier to understand kept together"
)]
async fn test_flash_download_functional_class_selection() {
    let test_env = TestEnv::builder().await.unwrap();
    let ecu_endpoint = sovd::COMPONENTS_FLXC1000_BASE;
    let request_download_url = format!("{ecu_endpoint}/x-sovd2uds-download/requestdownload");
    let flash_transfer_url = format!("{ecu_endpoint}/x-sovd2uds-download/flashtransfer");
    let transfer_exit_url = format!("{ecu_endpoint}/x-sovd2uds-download/transferexit");

    let lock_id = prepare_flxc1000_for_flashing(&test_env).await;
    let (file_id, file_size) = find_test_flash_file(&test_env).await;
    assert!(
        file_size <= 0xFFFF,
        "Test flash file must fit a 2-byte size"
    );

    let request_download_params = serde_json::json!({
        "DataFormatIdentifier": 0,
        "AddressAndLengthFormatIdentifier": 0x22,
        "MemoryAddress": "0x12 0x34",
        "MemorySize": format!("0x{:02x} 0x{:02x}", (file_size >> 8) & 0xFF, file_size & 0xFF),
    });

    // Invalid selections for RequestDownload
    for (body, status) in [
        (
            serde_json::json!({"requestdownload": request_download_params, "flashClass": ""}),
            StatusCode::BAD_REQUEST,
        ),
        (
            serde_json::json!({
                "requestdownload": request_download_params,
                "flashClass": "does_not_exist"
            }),
            StatusCode::NOT_FOUND,
        ),
    ] {
        send_authenticated_cda_request(
            &test_env,
            &request_download_url,
            status,
            Method::PUT,
            Some(&body.to_string()),
            None,
        )
        .await
        .unwrap();
    }
    // Malformed body is reported as bad request
    send_authenticated_cda_request(
        &test_env,
        &request_download_url,
        StatusCode::BAD_REQUEST,
        Method::PUT,
        Some("{\"requestdownload\": "),
        None,
    )
    .await
    .unwrap();

    // RequestDownload via the bootloader functional class, field name and value in other casing
    let request_download_body = serde_json::json!({
        "RequestDownload": request_download_params,
        "FlashClass": FLASH_CLASS_BOOTLOADER.to_uppercase(),
    });
    send_authenticated_cda_request(
        &test_env,
        &request_download_url,
        StatusCode::OK,
        Method::PUT,
        Some(&request_download_body.to_string()),
        None,
    )
    .await
    .unwrap();

    let sim_transfers = get_sim_data_transfers(&test_env.ecu_sim, ECU_FLXC1000)
        .await
        .expect("Failed to get data transfers from ECU sim");
    let last_transfer = sim_transfers
        .transfers
        .last()
        .expect("ECU sim should have recorded the request download");
    assert_eq!(last_transfer.address_and_length_identifier, 0x22);
    assert!(
        last_transfer
            .memory_address
            .replace(' ', "")
            .eq_ignore_ascii_case("1234"),
        "Expected 2-byte memory address of the bootloader service, got {}",
        last_transfer.memory_address
    );

    // TransferData with an unknown functional class must not start a transfer
    send_authenticated_cda_request(
        &test_env,
        &flash_transfer_url,
        StatusCode::NOT_FOUND,
        Method::POST,
        Some(
            &serde_json::json!({
                "blocksequencecounter": 1,
                "blocksize": 128,
                "offset": 0,
                "length": file_size,
                "id": file_id,
                "flashClass": "does_not_exist"
            })
            .to_string(),
        ),
        None,
    )
    .await
    .unwrap();

    let flash_transfer_response = send_authenticated_cda_request(
        &test_env,
        &flash_transfer_url,
        StatusCode::OK,
        Method::POST,
        Some(
            &serde_json::json!({
                "BlockSequenceCounter": 1,
                "BlockSize": 128,
                "Offset": 0,
                "Length": file_size,
                "Id": file_id,
                "FLASHCLASS": FLASH_CLASS_BOOTLOADER
            })
            .to_string(),
        ),
        None,
    )
    .await
    .unwrap();
    let transfer_id = response_to_json(&flash_transfer_response)
        .unwrap()
        .get("id")
        .and_then(|v| v.as_str())
        .expect("Expected 'id' in flash transfer response")
        .to_owned();

    let mut transfer_finished = false;
    for _ in 0..20 {
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(500)).await;
        let status_response = send_authenticated_cda_request(
            &test_env,
            &format!("{flash_transfer_url}/{transfer_id}"),
            StatusCode::OK,
            Method::GET,
            None,
            None,
        )
        .await
        .unwrap();
        let status_json = response_to_json(&status_response).unwrap();
        let status = status_json
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        assert!(
            status != "aborted",
            "Flash transfer was aborted. Status: {status_json:#?}"
        );
        if status == "finished" {
            transfer_finished = true;
            break;
        }
    }
    assert!(
        transfer_finished,
        "Flash transfer did not finish within the timeout"
    );

    send_authenticated_cda_request(
        &test_env,
        &format!("{flash_transfer_url}/{transfer_id}"),
        StatusCode::NO_CONTENT,
        Method::DELETE,
        None,
        None,
    )
    .await
    .unwrap();

    // TransferExit: invalid selections and malformed body are rejected
    for (body, status) in [
        (
            serde_json::json!({"flashClass": "does_not_exist"}).to_string(),
            StatusCode::NOT_FOUND,
        ),
        (
            serde_json::json!({"flashClass": " "}).to_string(),
            StatusCode::BAD_REQUEST,
        ),
        ("{not json".to_owned(), StatusCode::BAD_REQUEST),
    ] {
        send_authenticated_cda_request(
            &test_env,
            &transfer_exit_url,
            status,
            Method::PUT,
            Some(&body),
            None,
        )
        .await
        .unwrap();
    }

    send_authenticated_cda_request(
        &test_env,
        &transfer_exit_url,
        StatusCode::NO_CONTENT,
        Method::PUT,
        Some(&serde_json::json!({"flashclass": FLASH_CLASS_BOOTLOADER}).to_string()),
        None,
    )
    .await
    .unwrap();

    let sim_transfers = get_sim_data_transfers(&test_env.ecu_sim, ECU_FLXC1000)
        .await
        .expect("Failed to get data transfers from ECU sim");
    let last_transfer = sim_transfers.transfers.last().unwrap();
    assert!(!last_transfer.is_active, "Transfer should be finished");
    assert!(last_transfer.data_transfer_count > 0);
    assert!(last_transfer.checksum.is_some());

    lock_operation(
        locks::COMPONENTS_FLXC1000_LOCKS,
        Some(&lock_id),
        &test_env,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;
}

/// A flash transfer belongs to the client that started it. Releasing that client's lock
/// aborts and removes the transfer, so the next lock holder neither inherits it nor is
/// blocked by it.
#[tokio::test]
async fn test_flash_transfer_removed_when_owner_releases_lock() {
    let test_env = TestEnv::builder().await.unwrap();
    let ecu_endpoint = sovd::COMPONENTS_FLXC1000_BASE;
    let flash_transfer_url = format!("{ecu_endpoint}/x-sovd2uds-download/flashtransfer");

    let lock_id = prepare_flxc1000_for_flashing(&test_env).await;
    let (file_id, file_size) = find_test_flash_file(&test_env).await;

    let request_download_body = serde_json::json!({
        "requestdownload": {
            "DataFormatIdentifier": 0,
            "AddressAndLengthFormatIdentifier": 0x44,
            "MemoryAddress": "0x00 0x00 0x00 0x00",
            "MemorySize": format!("0x{:02x} 0x{:02x} 0x{:02x} 0x{:02x}",
                (file_size >> 24) & 0xFF,
                (file_size >> 16) & 0xFF,
                (file_size >> 8) & 0xFF,
                file_size & 0xFF
            )
        }
    });
    send_authenticated_cda_request(
        &test_env,
        &format!("{ecu_endpoint}/x-sovd2uds-download/requestdownload"),
        StatusCode::OK,
        Method::PUT,
        Some(&request_download_body.to_string()),
        None,
    )
    .await
    .unwrap();

    let flash_transfer_response = send_authenticated_cda_request(
        &test_env,
        &flash_transfer_url,
        StatusCode::OK,
        Method::POST,
        Some(
            &serde_json::json!({
                "blocksequencecounter": 1,
                "blocksize": 128,
                "offset": 0,
                "length": file_size,
                "id": file_id
            })
            .to_string(),
        ),
        None,
    )
    .await
    .unwrap();
    let transfer_id = response_to_json(&flash_transfer_response)
        .unwrap()
        .get("id")
        .and_then(|v| v.as_str())
        .expect("Expected 'id' in flash transfer response")
        .to_owned();

    // Release the lock without removing the transfer
    lock_operation(
        locks::COMPONENTS_FLXC1000_LOCKS,
        Some(&lock_id),
        &test_env,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;

    // Another client locks the ECU and finds no transfer of the previous owner
    let auth_other = test_env.auth_header_for("flash-takeover").await.unwrap();
    let other = test_env.with_headers(&auth_other);
    let other_lock = Lock::acquire(
        &other,
        locks::COMPONENTS_FLXC1000_LOCKS,
        Duration::from_secs(120),
    )
    .await;
    for (method, url) in [
        (Method::GET, flash_transfer_url.clone()),
        (
            Method::DELETE,
            format!("{flash_transfer_url}/{transfer_id}"),
        ),
    ] {
        send_authenticated_cda_request(&other, &url, StatusCode::NOT_FOUND, method, None, None)
            .await
            .unwrap();
    }
    other_lock.release(&other).await;
}
/// and a JSON error message.
#[tokio::test]
async fn test_flash_transfer_with_no_body_rejected_with_json_error_message() {
    let test_env = TestEnv::builder().await.unwrap();
    let ecu_endpoint = sovd::COMPONENTS_FLXC1000_BASE;

    // Verify that a flash transfer request with no body is rejected with a JSON HTTP 400 response.
    let flashtransfer_response = send_authenticated_cda_request(
        &test_env,
        &format!("{ecu_endpoint}/x-sovd2uds-download/flashtransfer"),
        StatusCode::BAD_REQUEST,
        Method::POST,
        None,
        None,
    )
    .await
    .unwrap();
    // Validate the response is a JSON object, which is expected for a JSON error message.
    let json_response = response_to_json(&flashtransfer_response).unwrap();
    // Validate the json response string in the body is a JSON object, which is expected for a JSON error message.
    assert!(
        json_response.is_object(),
        "Expected the rejection response to contain a valid JSON object"
    );
    // Verify the contents of the JSON error response.
    let json_response = response_to_json(&flashtransfer_response).unwrap();
    assert!(
        json_response
            .get("message")
            .unwrap()
            .as_str()
            .is_some_and(|message| message.contains("Failed to parse the request body as JSON")),
        "Expected the rejection response to contain message indicating json parsing error for \
         missing request body"
    );
    for (field, expected) in [
        ("error_code", "vendor-specific"),
        ("vendor_code", "bad-request"),
    ] {
        assert_eq!(
            json_response.get(field).and_then(|v| v.as_str()),
            Some(expected),
            "Expected the rejection response to contain {field} as {expected}"
        );
    }
}

/// Verify that attempting a flash transfer with invalid values in the body is rejected with a bad request error
/// and a JSON error message.
#[tokio::test]
async fn test_flash_transfer_with_invalid_body_rejected_with_json_error_message() {
    let test_env = TestEnv::builder().await.unwrap();
    let ecu_endpoint = sovd::COMPONENTS_FLXC1000_BASE;

    // Attempt flash transfer with BlockSize < 0 (negative) - should be rejected with a JSON HTTP 400 response.
    let zero_length_body = serde_json::json!({
        "blocksequencecounter": 1,
        "blocksize": -1,
        "offset": 0,
        "length": 16140,
        "id": "test_id"
    });

    let flashtransfer_response = send_authenticated_cda_request(
        &test_env,
        &format!("{ecu_endpoint}/x-sovd2uds-download/flashtransfer"),
        StatusCode::BAD_REQUEST,
        Method::POST,
        Some(&zero_length_body.to_string()),
        None,
    )
    .await
    .unwrap();
    // Verify the contents of the JSON error response.
    let json_response = response_to_json(&flashtransfer_response).unwrap();
    assert!(
        json_response
            .get("message")
            .unwrap()
            .as_str()
            .is_some_and(|message| message
                .contains("Failed to deserialize the JSON body into the target type")),
        "Expected the rejection response to contain message indicating json parsing error for \
         negative blocksize"
    );
    for (field, expected) in [
        ("error_code", "vendor-specific"),
        ("vendor_code", "bad-request"),
    ] {
        assert_eq!(
            json_response.get(field).and_then(|v| v.as_str()),
            Some(expected),
            "Expected the rejection response to contain {field} as {expected}"
        );
    }
}

/// Verify that attempting a request download with no body is rejected with a bad request error
/// and a JSON error message.
#[tokio::test]
async fn test_request_download_with_no_body_rejected_with_json_error_message() {
    let test_env = TestEnv::builder().await.unwrap();
    let ecu_endpoint = sovd::COMPONENTS_FLXC1000_BASE;

    let request_download_response = send_authenticated_cda_request(
        &test_env,
        &format!("{ecu_endpoint}/x-sovd2uds-download/requestdownload"),
        StatusCode::BAD_REQUEST,
        Method::PUT,
        None,
        None,
    )
    .await
    .unwrap();

    // Verify the contents of the JSON error response.
    let json_response = response_to_json(&request_download_response).unwrap();
    assert!(
        json_response
            .get("message")
            .unwrap()
            .as_str()
            .is_some_and(|message| message.contains("Failed to parse the request body as JSON")),
        "Expected the rejection response to contain message indicating json parsing error for \
         missing request body"
    );
    for (field, expected) in [
        ("error_code", "vendor-specific"),
        ("vendor_code", "bad-request"),
    ] {
        assert_eq!(
            json_response.get(field).and_then(|v| v.as_str()),
            Some(expected),
            "Expected the rejection response to contain {field} as {expected}"
        );
    }
}

const FLASH_TRANSFER_BLOCK_SIZE: u64 = 32;

/// Sends `RequestDownload` for the whole test flash file and starts the flash transfer with
/// [`FLASH_TRANSFER_BLOCK_SIZE`], so that the transfer consists of several blocks.
/// Returns the transfer id.
async fn start_flash_transfer(test_env: &TestEnv, file_id: &str, file_size: u64) -> String {
    let ecu_endpoint = sovd::COMPONENTS_FLXC1000_BASE;
    let request_download_body = serde_json::json!({
        "requestdownload": {
            "DataFormatIdentifier": 0,
            "AddressAndLengthFormatIdentifier": 0x44,
            "MemoryAddress": "0x00 0x00 0x00 0x00",
            "MemorySize": format!("0x{:02x} 0x{:02x} 0x{:02x} 0x{:02x}",
                (file_size >> 24) & 0xFF,
                (file_size >> 16) & 0xFF,
                (file_size >> 8) & 0xFF,
                file_size & 0xFF
            )
        }
    });
    send_authenticated_cda_request(
        test_env,
        &format!("{ecu_endpoint}/x-sovd2uds-download/requestdownload"),
        StatusCode::OK,
        Method::PUT,
        Some(&request_download_body.to_string()),
        None,
    )
    .await
    .expect("RequestDownload failed");

    let flash_transfer_body = serde_json::json!({
        "blocksequencecounter": 1,
        "blocksize": FLASH_TRANSFER_BLOCK_SIZE,
        "offset": 0,
        "length": file_size,
        "id": file_id
    });
    let flash_transfer_response = send_authenticated_cda_request(
        test_env,
        &format!("{ecu_endpoint}/x-sovd2uds-download/flashtransfer"),
        StatusCode::OK,
        Method::POST,
        Some(&flash_transfer_body.to_string()),
        None,
    )
    .await
    .expect("Starting the flash transfer failed");
    response_to_json(&flash_transfer_response)
        .expect("Flash transfer response is not JSON")
        .get("id")
        .and_then(|v| v.as_str())
        .expect("Expected 'id' in flash transfer response")
        .to_owned()
}

/// Polls the flash transfer until it is `finished` or `aborted` and returns its status JSON.
async fn wait_for_flash_transfer_end(test_env: &TestEnv, transfer_id: &str) -> serde_json::Value {
    let url = format!(
        "{}/x-sovd2uds-download/flashtransfer/{transfer_id}",
        sovd::COMPONENTS_FLXC1000_BASE
    );
    for _ in 0..60 {
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(250)).await;
        let status_response =
            send_authenticated_cda_request(test_env, &url, StatusCode::OK, Method::GET, None, None)
                .await
                .expect("Reading the flash transfer status failed");
        let status_json =
            response_to_json(&status_response).expect("Flash transfer status is not JSON");
        if matches!(
            status_json.get("status").and_then(|v| v.as_str()),
            Some("finished" | "aborted")
        ) {
            return status_json;
        }
    }
    panic!("Flash transfer {transfer_id} did not end within the timeout");
}

/// Removes an ended flash transfer from the CDA.
async fn delete_flash_transfer(test_env: &TestEnv, transfer_id: &str) {
    send_authenticated_cda_request(
        test_env,
        &format!(
            "{}/x-sovd2uds-download/flashtransfer/{transfer_id}",
            sovd::COMPONENTS_FLXC1000_BASE
        ),
        StatusCode::NO_CONTENT,
        Method::DELETE,
        None,
        None,
    )
    .await
    .expect("Deleting the flash transfer failed");
}

/// A negative response to `TransferData` must abort the flash transfer: the CDA must neither
/// send further blocks nor report the transfer as finished.
#[tokio::test]
async fn test_flash_transfer_aborted_on_negative_transfer_data_response() {
    const INTERCEPTOR: &str = "transfer_data_suspended";
    let test_env = TestEnv::builder().await.unwrap();

    let lock_id = prepare_flxc1000_for_flashing(&test_env).await;
    let (file_id, file_size) = find_test_flash_file(&test_env).await;
    assert!(
        file_size > 3 * FLASH_TRANSFER_BLOCK_SIZE,
        "Test flash file must have more than 3 blocks"
    );

    // Block 3 is answered with NRC 0x71 (transferDataSuspended)
    ecusim::set_interceptor_config(
        &test_env.ecu_sim,
        ECU_FLXC1000,
        INTERCEPTOR,
        &serde_json::json!({"request": "3603[]", "response": "7F3671"}),
    )
    .await
    .expect("Failed to install interceptor");

    let transfer_id = start_flash_transfer(&test_env, &file_id, file_size).await;
    let status_json = wait_for_flash_transfer_end(&test_env, &transfer_id).await;

    ecusim::clear_interceptor(&test_env.ecu_sim, ECU_FLXC1000, INTERCEPTOR)
        .await
        .expect("Failed to remove interceptor");

    assert_eq!(
        status_json.get("status").and_then(|v| v.as_str()),
        Some("aborted"),
        "Transfer must be aborted on a negative TransferData response: {status_json:#?}"
    );
    assert_eq!(
        status_json
            .get("acknowledgedBytes")
            .and_then(serde_json::Value::as_u64),
        Some(2 * FLASH_TRANSFER_BLOCK_SIZE),
        "Only the blocks before the rejected one count as acknowledged: {status_json:#?}"
    );
    let errors = status_json
        .get("error")
        .and_then(|v| v.as_array())
        .unwrap_or_else(|| panic!("Expected an error array: {status_json:#?}"));
    assert_eq!(errors.len(), 1, "Expected one error: {status_json:#?}");
    let error = errors.first().unwrap();
    assert_eq!(
        error.get("error_code").and_then(|v| v.as_str()),
        Some("error-response")
    );
    assert_eq!(
        error.get("x-errorsource").and_then(|v| v.as_str()),
        Some("ECU")
    );
    assert_eq!(
        error.get("parameters"),
        Some(&serde_json::json!({"BlockSequenceCounter": 3, "NRC": 0x71, "SID": 0x36})),
        "Unexpected error parameters: {status_json:#?}"
    );
    let message = error.get("message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.starts_with("ECU rejected block 0x03 with NRC 0x71"),
        "Message must name the block and the NRC: {status_json:#?}"
    );
    assert_eq!(
        error.get("text").and_then(|v| v.as_str()),
        Some(message),
        "text must repeat the message for older clients"
    );

    let sim_transfers = get_sim_data_transfers(&test_env.ecu_sim, ECU_FLXC1000)
        .await
        .expect("Failed to get data transfers from ECU sim");
    let last_transfer = sim_transfers.transfers.last().unwrap();
    assert_eq!(
        last_transfer.bytes_received,
        2 * FLASH_TRANSFER_BLOCK_SIZE,
        "No block after the rejected one may be sent"
    );

    delete_flash_transfer(&test_env, &transfer_id).await;
    lock_operation(
        locks::COMPONENTS_FLXC1000_LOCKS,
        Some(&lock_id),
        &test_env,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;
}

/// NRC 0x78 (responsePending), 0x21 (busyRepeatRequest) and 0x94 (temporarilyNotAvailable)
/// to `TransferData` must not abort the flash transfer: 0x78 waits for the final response,
/// 0x21 and 0x94 repeat the same block.
#[tokio::test]
async fn test_flash_transfer_continues_on_pending_and_busy_nrcs() {
    const INTERCEPTORS: [&str; 3] = ["td_response_pending", "td_busy_repeat", "td_not_available"];
    let test_env = TestEnv::builder().await.unwrap();

    let lock_id = prepare_flxc1000_for_flashing(&test_env).await;
    let (file_id, file_size) = find_test_flash_file(&test_env).await;
    assert!(
        file_size > 4 * FLASH_TRANSFER_BLOCK_SIZE,
        "Test flash file must have more than 4 blocks"
    );

    // The recorder must be installed before the NRC interceptors: the first interceptor that
    // answers a request ends the chain, so a later recorder would miss the intercepted frames.
    let recorder = test_env
        .record(ECU_FLXC1000)
        .await
        .expect("Failed to start ECU sim recording");
    for (name, config) in INTERCEPTORS.into_iter().zip([
        // block 2: two response pending, then forwarded to the regular handler
        serde_json::json!({
            "request": "3602[]",
            "response": null,
            "pendingResponses": 2,
            "pendingIntervalMs": 100,
            "removeAfterNRequest": 1
        }),
        // block 3: busy repeat request once, the repetition is processed regularly
        serde_json::json!({"request": "3603[]", "response": "7F3621", "removeAfterNRequest": 1}),
        // block 4: temporarily not available once
        serde_json::json!({"request": "3604[]", "response": "7F3694", "removeAfterNRequest": 1}),
    ]) {
        ecusim::set_interceptor_config(&test_env.ecu_sim, ECU_FLXC1000, name, &config)
            .await
            .expect("Failed to install interceptor");
    }

    let transfer_id = start_flash_transfer(&test_env, &file_id, file_size).await;
    let status_json = wait_for_flash_transfer_end(&test_env, &transfer_id).await;
    let recorded_frames = recorder
        .stop()
        .await
        .expect("Failed to stop ECU sim recording");

    for name in INTERCEPTORS {
        // the interceptors remove themselves after the first match, a missing one is fine
        let _ = ecusim::clear_interceptor(&test_env.ecu_sim, ECU_FLXC1000, name).await;
    }

    assert_eq!(
        status_json.get("status").and_then(|v| v.as_str()),
        Some("finished"),
        "Transfer must finish despite NRC 0x78/0x21/0x94: {status_json:#?}"
    );
    assert_eq!(
        status_json
            .get("acknowledgedBytes")
            .and_then(serde_json::Value::as_u64),
        Some(file_size)
    );

    // Blocks answered with 0x21/0x94 are sent again with the same block sequence counter,
    // the block answered with 0x78 is sent only once.
    let count_block = |bsc: &str| {
        recorded_frames
            .iter()
            .filter(|f| f.to_ascii_uppercase().starts_with(&format!("36{bsc}")))
            .count()
    };
    assert_eq!(count_block("02"), 1, "Frames: {recorded_frames:?}");
    assert_eq!(count_block("03"), 2, "Frames: {recorded_frames:?}");
    assert_eq!(count_block("04"), 2, "Frames: {recorded_frames:?}");

    let sim_transfers = get_sim_data_transfers(&test_env.ecu_sim, ECU_FLXC1000)
        .await
        .expect("Failed to get data transfers from ECU sim");
    let last_transfer = sim_transfers.transfers.last().unwrap();
    assert_eq!(last_transfer.bytes_received, file_size);
    assert_eq!(last_transfer.repeated_blocks, 0);

    delete_flash_transfer(&test_env, &transfer_id).await;
    lock_operation(
        locks::COMPONENTS_FLXC1000_LOCKS,
        Some(&lock_id),
        &test_env,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;
}

/// A block the ECU does not answer aborts the flash transfer as `not-responding`. The message
/// keeps the `Failed to read data: ` prefix, which clients use to retry the transfer from the
/// last acknowledged block.
#[tokio::test]
async fn test_flash_transfer_aborted_on_transfer_data_timeout() {
    const INTERCEPTOR: &str = "transfer_data_silent";
    let test_env = TestEnv::builder().await.unwrap();

    let lock_id = prepare_flxc1000_for_flashing(&test_env).await;
    let (file_id, file_size) = find_test_flash_file(&test_env).await;
    assert!(
        file_size > 3 * FLASH_TRANSFER_BLOCK_SIZE,
        "Test flash file must have more than 3 blocks"
    );

    // Block 3 (and every repetition of it) is not answered
    ecusim::set_interceptor_config(
        &test_env.ecu_sim,
        ECU_FLXC1000,
        INTERCEPTOR,
        &serde_json::json!({"request": "3603[]", "response": ""}),
    )
    .await
    .expect("Failed to install interceptor");

    let transfer_id = start_flash_transfer(&test_env, &file_id, file_size).await;
    let status_json = wait_for_flash_transfer_end(&test_env, &transfer_id).await;

    ecusim::clear_interceptor(&test_env.ecu_sim, ECU_FLXC1000, INTERCEPTOR)
        .await
        .expect("Failed to remove interceptor");

    assert_eq!(
        status_json.get("status").and_then(|v| v.as_str()),
        Some("aborted"),
        "Transfer must be aborted when the ECU does not answer: {status_json:#?}"
    );
    assert_eq!(
        status_json
            .get("acknowledgedBytes")
            .and_then(serde_json::Value::as_u64),
        Some(2 * FLASH_TRANSFER_BLOCK_SIZE),
        "Only the blocks before the unanswered one count as acknowledged: {status_json:#?}"
    );
    assert_eq!(
        status_json
            .get("nextBlockSequenceCounter")
            .and_then(serde_json::Value::as_u64),
        Some(3),
        "The unanswered block is the next one: {status_json:#?}"
    );

    let errors = status_json
        .get("error")
        .and_then(|v| v.as_array())
        .unwrap_or_else(|| panic!("Expected an error array: {status_json:#?}"));
    assert_eq!(errors.len(), 1, "Expected one error: {status_json:#?}");
    let error = errors.first().unwrap();
    assert_eq!(
        error.get("error_code").and_then(|v| v.as_str()),
        Some("not-responding"),
        "Unexpected error code: {status_json:#?}"
    );
    assert!(error.get("vendor_code").is_none());
    assert!(error.get("x-errorsource").is_none());
    assert_eq!(
        error.get("parameters"),
        Some(&serde_json::json!({"BlockSequenceCounter": 3})),
        "Unexpected error parameters: {status_json:#?}"
    );
    let message = error.get("message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.starts_with("Failed to read data: block 0x03: "),
        "Message must keep the prefix and name the block: {status_json:#?}"
    );
    assert_eq!(error.get("text").and_then(|v| v.as_str()), Some(message));

    let sim_transfers = get_sim_data_transfers(&test_env.ecu_sim, ECU_FLXC1000)
        .await
        .expect("Failed to get data transfers from ECU sim");
    assert_eq!(
        sim_transfers.transfers.last().unwrap().bytes_received,
        2 * FLASH_TRANSFER_BLOCK_SIZE,
        "No block after the unanswered one may be sent"
    );

    delete_flash_transfer(&test_env, &transfer_id).await;
    lock_operation(
        locks::COMPONENTS_FLXC1000_LOCKS,
        Some(&lock_id),
        &test_env,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;
}
