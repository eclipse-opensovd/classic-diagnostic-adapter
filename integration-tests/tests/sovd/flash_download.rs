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
use sovd_interfaces::{
    common::modes::{SECURITY_ID, SESSION_ID},
    components::ecu::{
        modes::security_and_session::put::{
            ModeKey, Request as SecurityRequest, RequestSeedResponse, Response as ModeResponse,
            SessionRequest,
        },
        x::sovd2uds::download::flash_transfer,
    },
};

use crate::{
    client::components::Component,
    sovd::{ECU_FLXC1000, compute_security_key},
    util::{
        TestingError,
        ecusim::{self, EcuSim},
        http::response_to_t,
        test_env::TestEnv,
    },
};

/// Forces the variant detection of `component`, which the CDA answers with
/// `201 Created`.
async fn force_variant_detection(component: &Component<'_>) {
    component
        .detect_variant()
        .await
        .expect("variant detection failed")
        .expect_status(StatusCode::CREATED);
}

/// Switches `component` to the session `name`.
async fn switch_session(component: &Component<'_>, name: &str) -> ModeResponse<String> {
    component
        .mode(SESSION_ID)
        .put::<ModeResponse<String>>(&SessionRequest {
            value: name.to_owned(),
            mode_expiration: None,
        })
        .await
        .expect("session switch failed")
        .expect_status(StatusCode::OK)
        .into_body()
}

/// A security access request for the level `value`, with `key` if given.
fn security_request(value: &str, key: Option<String>) -> SecurityRequest {
    SecurityRequest {
        value: value.to_owned(),
        mode_expiration: None,
        key: key.map(|send_key| ModeKey { send_key }),
        parameters: None,
    }
}

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
    let client = test_env.client();
    let component = client.component(ECU_FLXC1000);
    let download = component.download();

    // Create and acquire ECU lock
    let expiration_timeout = Duration::from_secs(120);
    let ecu_lock = component
        .locks()
        .create(expiration_timeout)
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

    // Switch ECU sim to BOOT variant
    ecusim::switch_variant(&test_env.ecu_sim, "FLXC1000", "BOOT")
        .await
        .unwrap();

    // Force variant detection so the CDA picks up the boot variant
    force_variant_detection(&component).await;

    // Switch to programming session
    let session_result = switch_session(&component, "programming").await;
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
    let security = component.mode(SECURITY_ID);
    let seed_response = security
        .put::<RequestSeedResponse>(&security_request("Level_7_RequestSeed", None))
        .await
        .unwrap()
        .expect_status(StatusCode::OK);

    // Verify that the seed payload is the deterministic sequence 0x00..0x07
    assert_eq!(
        seed_response.seed.request_seed, "0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07",
        "Expected deterministic seed payload from ECU sim"
    );

    let key = compute_security_key(&seed_response.seed.request_seed);

    let key_result = security
        .put::<ModeResponse<String>>(&security_request("Level_7", Some(key)))
        .await
        .unwrap()
        .expect_status(StatusCode::OK);
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
    let files = client
        .sovd2uds()
        .flash_files()
        .await
        .unwrap()
        .expect_status(StatusCode::OK)
        .into_body()
        .files;
    assert!(
        !files.is_empty(),
        "Expected at least one flash file, got none. Response: {files:#?}"
    );

    // Find the test_flash.bin file specifically (not .gitkeep or other files)
    let flash_file = files
        .iter()
        .find(|f| {
            f.origin_path
                .as_deref()
                .is_some_and(|p| p.contains("test_flash"))
        })
        .expect("Expected to find test_flash.bin in flash files list");
    let file_id = flash_file.id.clone();
    let file_size = flash_file.size.expect("Expected 'size' in flash file");
    assert!(
        file_size > 0,
        "Flash file size should be > 0, got {file_size}. File: {flash_file:#?}"
    );

    // RequestDownload
    // memory address: 0x00000000, memory size: file_size
    // DataFormatIdentifier: 0x00 (no compression, no encryption)
    // AddressAndLengthFormatIdentifier: 0x44 (4-byte address, 4-byte size)
    let request_download = download
        .request_download(&serde_json::json!({
            "DataFormatIdentifier": 0,
            "AddressAndLengthFormatIdentifier": 0x44,
            "MemoryAddress": "0x00 0x00 0x00 0x00",
            "MemorySize": format!("0x{:02x} 0x{:02x} 0x{:02x} 0x{:02x}",
                (file_size >> 24) & 0xFF,
                (file_size >> 16) & 0xFF,
                (file_size >> 8) & 0xFF,
                file_size & 0xFF
            )
        }))
        .await
        .unwrap()
        .expect_status(StatusCode::OK)
        .into_body()
        .expect("Expected a body in the RequestDownload response");

    let max_block_length = request_download
        .parameters
        .get("MaxNumberOfBlockLength")
        .expect("Expected 'MaxNumberOfBlockLength' in response");
    assert!(
        max_block_length.as_u64().unwrap_or(0) > 0,
        "MaxNumberOfBlockLength should be > 0, got {max_block_length}"
    );

    // Start flash transfer (TransferData)
    let transfer_id = download
        .start_transfer(&flash_transfer::post::Request {
            block_sequence_counter: 1,
            blocksize: 128,
            offset: 0,
            length: file_size,
            id: file_id,
        })
        .await
        .unwrap()
        .expect_status(StatusCode::OK)
        .into_body()
        .id;

    // Poll transfer status until finished
    let mut transfer_finished = false;
    for attempt in 0..20 {
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(500)).await;

        let transfer = download
            .transfer(&transfer_id)
            .await
            .unwrap()
            .expect_status(StatusCode::OK);

        if transfer.status == flash_transfer::get::DataTransferStatus::Finished {
            transfer_finished = true;
            assert!(
                transfer.acknowledged_bytes > 0,
                "Expected acknowledgedBytes > 0, got {}",
                transfer.acknowledged_bytes
            );
            break;
        }

        assert!(
            transfer.status != flash_transfer::get::DataTransferStatus::Aborted,
            "Flash transfer was aborted on attempt {attempt}. Status: {transfer:#?}"
        );
    }
    assert!(
        transfer_finished,
        "Flash transfer did not finish within the timeout"
    );

    // Remove finished flash transfer
    download
        .delete_transfer(&transfer_id)
        .await
        .unwrap()
        .expect_status(StatusCode::NO_CONTENT);

    // TransferExit
    download
        .transfer_exit()
        .await
        .unwrap()
        .expect_status(StatusCode::NO_CONTENT);

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

    // Cleanup: delete lock
    ecu_lock
        .release()
        .await
        .expect("lock operation failed")
        .expect_status(StatusCode::NO_CONTENT);
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
    let client = test_env.client();
    let component = client.component(ECU_FLXC1000);
    let download = component.download();

    // Create and acquire ECU lock
    let expiration_timeout = Duration::from_secs(120);
    let ecu_lock = component
        .locks()
        .create(expiration_timeout)
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

    // Switch ECU sim to BOOT variant
    ecusim::switch_variant(&test_env.ecu_sim, "FLXC1000", "BOOT")
        .await
        .unwrap();

    // Force variant detection
    force_variant_detection(&component).await;

    // Switch to programming session
    switch_session(&component, "programming").await;

    // Start recording to verify the raw UDS frames sent for SecurityAccess Level 5
    let recorder = test_env
        .record(ECU_FLXC1000)
        .await
        .expect("Failed to start ECU sim recording");

    // SecurityAccess Level 5
    let security = component.mode(SECURITY_ID);
    let seed_response = security
        .put::<RequestSeedResponse>(&security_request("Level_5_RequestSeed", None))
        .await
        .unwrap()
        .expect_status(StatusCode::OK);

    // Verify that the seed payload is the deterministic sequence 0x00..0x07
    assert_eq!(
        seed_response.seed.request_seed, "0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07",
        "Expected deterministic seed payload from ECU sim"
    );

    let key = compute_security_key(&seed_response.seed.request_seed);

    let key_result = security
        .put::<ModeResponse<String>>(&security_request("Level_5", Some(key)))
        .await
        .unwrap()
        .expect_status(StatusCode::OK);
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
    download
        .request_download(&serde_json::json!({
            "DataFormatIdentifier": 0,
            "AddressAndLengthFormatIdentifier": 0x44,
            "MemoryAddress": "0x00 0x00 0x00 0x00",
            "MemorySize": "0x00 0x00 0x01 0x00"
        }))
        .await
        .unwrap()
        .expect_status(StatusCode::OK);

    // List flash files to get a valid file ID
    let files = client
        .sovd2uds()
        .flash_files()
        .await
        .unwrap()
        .expect_status(StatusCode::OK)
        .into_body()
        .files;
    let flash_file = files
        .iter()
        .find(|f| {
            f.origin_path
                .as_deref()
                .is_some_and(|p| p.contains("test_flash"))
        })
        .expect("Expected to find test_flash.bin in flash files list");

    // Attempt flash transfer with length=0 - should be rejected
    let err = download
        .start_transfer(&flash_transfer::post::Request {
            block_sequence_counter: 1,
            blocksize: 128,
            offset: 0,
            length: 0,
            id: flash_file.id.clone(),
        })
        .await
        .expect_err("zero-length flash transfer was accepted");
    assert_eq!(err.status(), Some(StatusCode::BAD_REQUEST), "{err}");

    // Cleanup
    ecu_lock
        .release()
        .await
        .expect("lock operation failed")
        .expect_status(StatusCode::NO_CONTENT);
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
    let component = test_env.client().component(ECU_FLXC1000);

    // Create and acquire ECU lock
    let expiration_timeout = Duration::from_secs(120);
    let ecu_lock = component
        .locks()
        .create(expiration_timeout)
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

    // Switch ECU sim to BOOT variant (security access services live on the boot variant)
    ecusim::switch_variant(&test_env.ecu_sim, "FLXC1000", "BOOT")
        .await
        .unwrap();

    // Force variant detection
    force_variant_detection(&component).await;

    // Switch to programming session
    switch_session(&component, "programming").await;

    // Start recording to verify the raw UDS frames sent for SecurityAccess Supplier (Level 9)
    let recorder = test_env
        .record(ECU_FLXC1000)
        .await
        .expect("Failed to start ECU sim recording");

    // SecurityAccess Supplier - RequestSeed via ODX name RequestSeed_Supplier
    // The SOVD value "Supplier_RequestSeed" has exactly two underscore-separated parts;
    // split_at_last_underscore recognises "RequestSeed" as the service suffix and
    // produces level="Supplier", seed_service=Some("RequestSeed").
    let security = component.mode(SECURITY_ID);
    let seed_response = security
        .put::<RequestSeedResponse>(&security_request("Supplier_RequestSeed", None))
        .await
        .unwrap()
        .expect_status(StatusCode::OK);

    assert_eq!(
        seed_response.seed.request_seed, "0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07",
        "Expected deterministic seed payload from ECU sim"
    );

    let key = compute_security_key(&seed_response.seed.request_seed);

    let key_result = security
        .put::<ModeResponse<String>>(&security_request("Supplier", Some(key)))
        .await
        .unwrap()
        .expect_status(StatusCode::OK);
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
    ecu_lock
        .release()
        .await
        .expect("lock operation failed")
        .expect_status(StatusCode::NO_CONTENT);
}

// Helper types and functions for ECU sim data transfer verification

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SimDataTransferDownload {
    #[allow(
        dead_code,
        reason = "Fields deserialized from ECU simulator JSON responses"
    )]
    address_and_length_identifier: u8,
    #[allow(
        dead_code,
        reason = "Fields deserialized from ECU simulator JSON responses"
    )]
    memory_address: String,
    #[allow(
        dead_code,
        reason = "Fields deserialized from ECU simulator JSON responses"
    )]
    memory_size: String,
    is_active: bool,
    data_transfer_count: i32,
    checksum: Option<String>,
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
