/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
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
use serde::Deserialize;
use sovd_interfaces::components::ecu::modes::security_and_session::put::RequestSeedResponse;

use crate::{
    sovd::{
        self, compute_security_key,
        ecu::switch_session,
        locks::{self, create_lock, lock_operation},
        put_mode,
    },
    util::{
        TestingError,
        ecusim::{self},
        http::{
            auth_header, extract_field_from_json, response_to_json, response_to_t, send_cda_request,
        },
        runtime::setup_integration_test,
    },
};

/// Integration test for the full flash download sequence:
/// `RequestDownload` (0x34) -> `TransferData` (0x36) -> `TransferExit` (0x37)
///
/// Prerequisites enforced by the ECU simulator:
/// - Variant must be BOOT
/// - Session must be PROGRAMMING
/// - `SecurityAccess` must be `LEVEL_07`
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_flash_download_transfer_sequence() {
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();
    let auth = auth_header(&runtime.config, None).await.unwrap();
    let ecu_endpoint = sovd::ECU_FLXC1000_ENDPOINT;

    // Create and acquire ECU lock
    // Duration::from_mins is only available in rust >= 1.91.0, we want to support 1.88.0
    #[cfg_attr(nightly, allow(unknown_lints, clippy::duration_suboptimal_units))]
    let expiration_timeout = Duration::from_secs(120);
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

    lock_operation(
        locks::ECU_ENDPOINT,
        Some(&lock_id),
        &runtime.config,
        &auth,
        StatusCode::OK,
        Method::GET,
    )
    .await;

    // Switch ECU sim to BOOT variant
    ecusim::switch_variant(&runtime.ecu_sim, "FLXC1000", "BOOT")
        .await
        .unwrap();

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
    .unwrap();

    // Switch to programming session
    let session_result = switch_session(
        "programming",
        &runtime.config,
        &auth,
        ecu_endpoint,
        StatusCode::OK,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        session_result.value.to_lowercase(),
        "programming",
        "Should be in programming session"
    );

    // SecurityAccess Level 7 (request seed + send key)
    let seed_response: RequestSeedResponse = put_mode(
        &runtime.config,
        &auth,
        ecu_endpoint,
        "security",
        sovd_interfaces::components::ecu::modes::security_and_session::put::Request {
            value: "Level_7_RequestSeed".to_owned(),
            mode_expiration: None,
            key: None,
        },
        StatusCode::OK,
    )
    .await
    .unwrap()
    .unwrap();

    let key = compute_security_key(&seed_response.seed.request_seed);

    let key_result: sovd_interfaces::components::ecu::modes::security_and_session::put::Response<
        String,
    > = put_mode(
        &runtime.config,
        &auth,
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
        },
        StatusCode::OK,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(key_result.value, "Level_7");

    // Verify the ECU sim is in the expected state
    let ecu_state = ecusim::get_ecu_state(&runtime.ecu_sim, "flxc1000")
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

    // List flash files to get the file ID
    let flash_files_response = send_cda_request(
        &runtime.config,
        "apps/sovd2uds/bulk-data/flashfiles",
        StatusCode::OK,
        Method::GET,
        None,
        Some(&auth),
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
    let request_download_response = send_cda_request(
        &runtime.config,
        &format!("{ecu_endpoint}/x-sovd2uds-download/requestdownload"),
        StatusCode::OK,
        Method::PUT,
        Some(&request_download_body.to_string()),
        Some(&auth),
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

    let flash_transfer_response = send_cda_request(
        &runtime.config,
        &format!("{ecu_endpoint}/x-sovd2uds-download/flashtransfer"),
        StatusCode::OK,
        Method::POST,
        Some(&flash_transfer_body.to_string()),
        Some(&auth),
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

        let status_response = send_cda_request(
            &runtime.config,
            &format!("{ecu_endpoint}/x-sovd2uds-download/flashtransfer/{transfer_id}"),
            StatusCode::OK,
            Method::GET,
            None,
            Some(&auth),
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
    send_cda_request(
        &runtime.config,
        &format!("{ecu_endpoint}/x-sovd2uds-download/flashtransfer/{transfer_id}"),
        StatusCode::NO_CONTENT,
        Method::DELETE,
        None,
        Some(&auth),
        None,
    )
    .await
    .unwrap();

    // TransferExit
    send_cda_request(
        &runtime.config,
        &format!("{ecu_endpoint}/x-sovd2uds-download/transferexit"),
        StatusCode::NO_CONTENT,
        Method::PUT,
        None,
        Some(&auth),
        None,
    )
    .await
    .unwrap();

    // Verify on ECU simulator
    let sim_transfers = get_sim_data_transfers(&runtime.ecu_sim, "flxc1000")
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

    // Cleanup: delete lock
    lock_operation(
        locks::ECU_ENDPOINT,
        Some(&lock_id),
        &runtime.config,
        &auth,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;

    // Reset ECU sim back to APPLICATION variant for other tests
    ecusim::switch_variant(&runtime.ecu_sim, "FLXC1000", "APPLICATION")
        .await
        .unwrap();
}

/// Verify that attempting a flash transfer with length=0 is rejected with a bad request error.
/// This guards against a zero-length transfer silently staying in "running" status forever.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_flash_transfer_zero_length_rejected() {
    let (runtime, _lock) = setup_integration_test(true).await.unwrap();
    let auth = auth_header(&runtime.config, None).await.unwrap();
    let ecu_endpoint = sovd::ECU_FLXC1000_ENDPOINT;

    // Create and acquire ECU lock
    #[cfg_attr(nightly, allow(unknown_lints, clippy::duration_suboptimal_units))]
    let expiration_timeout = Duration::from_secs(120);
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

    lock_operation(
        locks::ECU_ENDPOINT,
        Some(&lock_id),
        &runtime.config,
        &auth,
        StatusCode::OK,
        Method::GET,
    )
    .await;

    // Switch ECU sim to BOOT variant
    ecusim::switch_variant(&runtime.ecu_sim, "FLXC1000", "BOOT")
        .await
        .unwrap();

    // Force variant detection
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
    .unwrap();

    // Switch to programming session
    switch_session(
        "programming",
        &runtime.config,
        &auth,
        ecu_endpoint,
        StatusCode::OK,
    )
    .await
    .unwrap()
    .unwrap();

    // SecurityAccess Level 7
    let seed_response: RequestSeedResponse = put_mode(
        &runtime.config,
        &auth,
        ecu_endpoint,
        "security",
        sovd_interfaces::components::ecu::modes::security_and_session::put::Request {
            value: "Level_7_RequestSeed".to_owned(),
            mode_expiration: None,
            key: None,
        },
        StatusCode::OK,
    )
    .await
    .unwrap()
    .unwrap();

    let key = compute_security_key(&seed_response.seed.request_seed);

    put_mode::<
        sovd_interfaces::components::ecu::modes::security_and_session::put::Response<String>,
        _,
    >(
        &runtime.config,
        &auth,
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
        },
        StatusCode::OK,
    )
    .await
    .unwrap()
    .unwrap();

    // RequestDownload (required before flash transfer)
    let request_download_body = serde_json::json!({
        "requestdownload": {
            "DataFormatIdentifier": 0,
            "AddressAndLengthFormatIdentifier": 0x44,
            "MemoryAddress": "0x00 0x00 0x00 0x00",
            "MemorySize": "0x00 0x00 0x01 0x00"
        }
    });
    send_cda_request(
        &runtime.config,
        &format!("{ecu_endpoint}/x-sovd2uds-download/requestdownload"),
        StatusCode::OK,
        Method::PUT,
        Some(&request_download_body.to_string()),
        Some(&auth),
        None,
    )
    .await
    .unwrap();

    // List flash files to get a valid file ID
    let flash_files_response = send_cda_request(
        &runtime.config,
        "apps/sovd2uds/bulk-data/flashfiles",
        StatusCode::OK,
        Method::GET,
        None,
        Some(&auth),
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

    send_cda_request(
        &runtime.config,
        &format!("{ecu_endpoint}/x-sovd2uds-download/flashtransfer"),
        StatusCode::BAD_REQUEST,
        Method::POST,
        Some(&zero_length_body.to_string()),
        Some(&auth),
        None,
    )
    .await
    .unwrap();

    // Cleanup
    lock_operation(
        locks::ECU_ENDPOINT,
        Some(&lock_id),
        &runtime.config,
        &auth,
        StatusCode::NO_CONTENT,
        Method::DELETE,
    )
    .await;

    ecusim::switch_variant(&runtime.ecu_sim, "FLXC1000", "APPLICATION")
        .await
        .unwrap();
}

// Helper types and functions for ECU sim data transfer verification

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SimDataTransferDownload {
    #[allow(dead_code)]
    address_and_length_identifier: u8,
    #[allow(dead_code)]
    memory_address: String,
    #[allow(dead_code)]
    memory_size: String,
    is_active: bool,
    data_transfer_count: i32,
    checksum: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SimDataTransfers {
    transfers: Vec<SimDataTransferDownload>,
}

async fn get_sim_data_transfers(
    sim: &crate::util::runtime::EcuSim,
    ecu: &str,
) -> Result<SimDataTransfers, TestingError> {
    let url = reqwest::Url::parse(&format!(
        "http://{}:{}/{ecu}/datatransfers/downloads",
        sim.host, sim.control_port
    ))
    .map_err(|e| TestingError::InvalidUrl(e.to_string()))?;

    let response =
        crate::util::http::send_request(StatusCode::OK, Method::GET, None, None, url).await?;
    response_to_t(&response)
}
