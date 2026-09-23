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
use http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::util::TestingError;

/// Where a test reaches the control API of an ecu-sim.
#[derive(Clone, Debug)]
pub(crate) struct EcuSim {
    pub(crate) host: String,
    pub(crate) control_port: u16,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum Variant {
    Boot,
    Application,
    Application2,
    Application3,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum SessionState {
    Default,
    Programming,
    Extended,
    Safety,
    Custom,
}

#[derive(Debug, Deserialize)]
pub(crate) enum SecurityAccess {
    #[serde(rename = "LOCKED")]
    Locked,
    #[serde(rename = "LEVEL_03")]
    Level03,
    #[serde(rename = "LEVEL_05")]
    Level05,
    #[serde(rename = "LEVEL_07")]
    Level07,
    #[serde(rename = "LEVEL_09")]
    Level09,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum Authentication {
    Unauthenticated,
    AfterMarket,
    AfterSales,
    Development,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum DataBlockType {
    Boot,
    Code,
    Data,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum CommunicationControlType {
    EnableRxAndTx,
    EnableRxAndDisableTx,
    DisableRxAndEnableTx,
    DisableRxAndTx,
    EnableRxAndDisableTxWithEnhancedAddressInformation,
    EnableRxAndTxWithEnhancedAddressInformation,
    TemporalSync,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum DtcSettingType {
    On,
    Off,
    TimeTravelDtcsOn,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(
    dead_code,
    reason = "Struct fields deserialized from ECU simulator JSON. Not all fields consumed by tests"
)]
pub(crate) struct DataBlockDto {
    pub(crate) id: String,
    pub(crate) r#type: DataBlockType,
    pub(crate) software_version: Option<String>,
    pub(crate) part_number: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(
    dead_code,
    reason = "Struct fields deserialized from ECU simulator JSON. Not all fields consumed by tests"
)]
pub(crate) struct EcuState {
    pub(crate) variant: Option<Variant>,
    pub(crate) session_state: Option<SessionState>,
    pub(crate) security_access: Option<SecurityAccess>,
    pub(crate) authentication: Option<Authentication>,
    pub(crate) boot_software_versions: Option<Vec<String>>,
    pub(crate) application_software_versions: Option<Vec<String>>,
    pub(crate) vin: Option<String>,
    pub(crate) hard_reset_for_seconds: Option<i32>,
    pub(crate) max_number_of_block_length: Option<i32>,
    pub(crate) blocks: Option<Vec<DataBlockDto>>,
    pub(crate) communication_control_type: Option<CommunicationControlType>,
    pub(crate) temporal_era_id: Option<i32>,
    pub(crate) dtc_setting_type: Option<DtcSettingType>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(
    dead_code,
    reason = "Struct fields deserialized from ECU simulator JSON. Not all fields consumed by tests"
)]
pub(crate) struct DtcMinimal {
    pub(crate) id: String,
    pub(crate) status_mask: String,
    pub(crate) emissions_related: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(
    dead_code,
    reason = "Struct fields deserialized from ECU simulator JSON. Not all fields consumed by tests"
)]
pub(crate) struct ExtDataRecord {
    pub(crate) record_number: String,
    pub(crate) data: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(
    dead_code,
    reason = "Struct fields deserialized from ECU simulator JSON. Not all fields consumed by tests"
)]
pub(crate) struct SnapshotData {
    pub(crate) did: String,
    pub(crate) data: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(
    dead_code,
    reason = "Struct fields deserialized from ECU simulator JSON. Not all fields consumed by tests"
)]
pub(crate) struct SnapshotRecord {
    pub(crate) record_number: String,
    pub(crate) records: Vec<SnapshotData>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(
    dead_code,
    reason = "Struct fields deserialized from ECU simulator JSON. Not all fields consumed by tests"
)]
pub(crate) struct DtcExtended {
    pub(crate) id: String,
    pub(crate) status_mask: String,
    pub(crate) emissions_related: bool,
    pub(crate) snapshots: Vec<SnapshotRecord>,
    pub(crate) extended_data: Vec<ExtDataRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", transparent)]
#[allow(
    dead_code,
    reason = "Struct fields deserialized from ECU simulator JSON. Not all fields consumed by tests"
)]
pub(crate) struct DtcState {
    pub(crate) dtcs: Vec<DtcMinimal>,
}

pub(crate) async fn switch_variant(
    sim: &EcuSim,
    ecu: &str,
    variant: &str,
) -> Result<(), TestingError> {
    let url = sim_url(sim, &[ecu, "state"])?;

    crate::util::http::send_request(
        StatusCode::OK,
        http::Method::PUT,
        Some(&serde_json::json!({"variant": variant}).to_string()),
        None,
        url,
    )
    .await?;
    Ok(())
}

pub(crate) async fn get_ecu_state(sim: &EcuSim, ecu: &str) -> Result<EcuState, TestingError> {
    let url = sim_url(sim, &[ecu, "state"])?;

    let response =
        crate::util::http::send_request(StatusCode::OK, http::Method::GET, None, None, url).await?;

    crate::util::http::response_to_t(&response)
}

/// The URL of the control API of `sim` at the path `segments`.
fn sim_url(sim: &EcuSim, segments: &[&str]) -> Result<reqwest::Url, TestingError> {
    let mut url = reqwest::Url::parse(&format!("http://{}:{}", sim.host, sim.control_port))?;
    url.path_segments_mut()
        .map_err(|()| TestingError::InvalidUrl("cannot modify URL path".to_owned()))?
        .extend(segments);
    Ok(url)
}

/// Add a DTC to the ECU simulator. Accepts either [`DtcMinimal`] or [`DtcExtended`].
pub(crate) async fn add_dtc<T: serde::Serialize>(
    sim: &EcuSim,
    ecu: &str,
    fault_memory: &str,
    dtc: &T,
) -> Result<(), TestingError> {
    let url = sim_url(sim, &[ecu, "dtc", fault_memory])?;

    let body = serde_json::to_string(dtc)
        .map_err(|_| TestingError::InvalidData("cannot serialize object to JSON".to_owned()))?;

    crate::util::http::send_request(
        StatusCode::CREATED,
        http::Method::PUT,
        Some(&body),
        None,
        url,
    )
    .await?;
    Ok(())
}

/// Get all DTCs from the ECU simulator
pub(crate) async fn get_dtcs(
    sim: &EcuSim,
    ecu: &str,
    fault_memory: &str,
) -> Result<DtcState, TestingError> {
    let url = sim_url(sim, &[ecu, "dtc", fault_memory])?;

    let response =
        crate::util::http::send_request(StatusCode::OK, http::Method::GET, None, None, url).await?;

    crate::util::http::response_to_t(&response)
}

pub(crate) async fn reset_sim(sim: &EcuSim) -> Result<(), TestingError> {
    let url = sim_url(sim, &["reset"])?;

    crate::util::http::send_request(StatusCode::NO_CONTENT, http::Method::POST, None, None, url)
        .await?;
    Ok(())
}

/// Records the UDS requests one ECU of ecu-sim receives, from
/// [`TestEnv::record`](crate::util::test_env::TestEnv::record) or
/// [`Lease::recorder`](crate::util::test_env::Lease::recorder).
///
/// Every request is recorded as a lowercase hex string without separators,
/// e.g. `"31011001"`. [`Self::stop`] returns the requests since the recording
/// started. A recorder dropped without being stopped keeps recording until the
/// next lease resets ecu-sim.
#[must_use = "a recorder returns its frames only through `stop`"]
pub(crate) struct Recorder {
    sim: EcuSim,
    ecu: String,
}

impl Recorder {
    /// Starts recording the requests `ecu` receives, discarding earlier
    /// recordings of it.
    ///
    /// # Errors
    /// Returns an error if ecu-sim cannot be reached or does not know `ecu`.
    pub(crate) async fn start(sim: &EcuSim, ecu: &str) -> Result<Self, TestingError> {
        crate::util::http::send_request(
            StatusCode::NO_CONTENT,
            http::Method::POST,
            None,
            None,
            sim_url(sim, &[ecu, "record"])?,
        )
        .await?;
        Ok(Self {
            sim: sim.clone(),
            ecu: ecu.to_owned(),
        })
    }

    /// The ECU whose requests are recorded.
    pub(crate) fn ecu(&self) -> &str {
        &self.ecu
    }

    /// Stops recording and returns the requests recorded since the start.
    ///
    /// # Errors
    /// Returns an error if ecu-sim cannot be reached, e.g. because it was
    /// restarted since the recording started, which loses the recording.
    pub(crate) async fn stop(self) -> Result<Vec<String>, TestingError> {
        let response = crate::util::http::send_request(
            StatusCode::OK,
            http::Method::DELETE,
            None,
            None,
            sim_url(&self.sim, &[&self.ecu, "record"])?,
        )
        .await?;
        crate::util::http::response_to_t(&response)
    }
}

/// Install a named inbound interceptor on the ECU simulator.
///
/// When installed, any incoming UDS request whose hex representation matches
/// the `request` regex pattern will receive `response` as a raw hex response.
/// If `response` is empty, the ECU will suppress its response (simulating offline).
/// The `[]` sequence in `request` is treated as a wildcard (`.*`).
pub(crate) async fn set_interceptor(
    sim: &EcuSim,
    ecu: &str,
    name: &str,
    request: &str,
    response: &str,
) -> Result<(), TestingError> {
    let url = sim_url(sim, &["interceptor", ecu, "inbound", name])?;

    let body = serde_json::json!({
        "request": request,
        "response": response
    })
    .to_string();

    crate::util::http::send_request(
        StatusCode::ACCEPTED,
        http::Method::PUT,
        Some(&body),
        None,
        url,
    )
    .await?;
    Ok(())
}

/// Remove a previously installed named interceptor from the ECU simulator.
pub(crate) async fn clear_interceptor(
    sim: &EcuSim,
    ecu: &str,
    name: &str,
) -> Result<(), TestingError> {
    let url = sim_url(sim, &["interceptor", ecu, "inbound", name])?;
    crate::util::http::send_request(
        StatusCode::NO_CONTENT,
        http::Method::DELETE,
        None,
        None,
        url,
    )
    .await?;
    Ok(())
}

/// Force-close all active `DoIP` TCP connections for all ECUs.
///
/// This simulates a network disconnect or ECU reboot where the TCP link is lost.
/// After the disconnect, the ECUs will re-announce themselves via VAMs and the CDA
/// should re-establish the connections automatically.
pub(crate) async fn disconnect(sim: &EcuSim) -> Result<(), TestingError> {
    let url = sim_url(sim, &["disconnect"])?;

    crate::util::http::send_request(StatusCode::OK, http::Method::POST, None, None, url).await?;
    Ok(())
}

/// Configure the ECU simulator's hard reset duration.
///
/// When set to a value > 0, subsequent UDS ECU Reset (0x11 0x01) requests will cause
/// the ECU to close its TCP connection for the specified number of seconds, simulating
/// a real ECU reboot with `DoIP` disconnection.
pub(crate) async fn set_hard_reset_duration(
    sim: &EcuSim,
    ecu: &str,
    seconds: i32,
) -> Result<(), TestingError> {
    let url = sim_url(sim, &[ecu, "state"])?;

    let body = serde_json::json!({"hardResetForSeconds": seconds}).to_string();

    crate::util::http::send_request(StatusCode::OK, http::Method::PUT, Some(&body), None, url)
        .await?;
    Ok(())
}
