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
use http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::util::{TestingError, runtime::EcuSim};

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
#[allow(dead_code)]
pub(crate) struct DataBlockDto {
    pub(crate) id: String,
    pub(crate) r#type: DataBlockType,
    pub(crate) software_version: Option<String>,
    pub(crate) part_number: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
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
    pub(crate) running_calibration: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub(crate) struct DtcMinimal {
    pub(crate) id: String,
    pub(crate) status_mask: String,
    pub(crate) emissions_related: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", transparent)]
#[allow(dead_code)]
pub(crate) struct DtcState {
    pub(crate) dtcs: Vec<DtcMinimal>,
}

pub(crate) async fn switch_variant(
    sim: &EcuSim,
    ecu: &str,
    variant: &str,
) -> Result<(), TestingError> {
    let mut url = sim_endpoint(sim)?;
    url.path_segments_mut()
        .map_err(|()| TestingError::InvalidUrl("cannot modify URL path".to_owned()))?
        .push(ecu)
        .push("state");

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
    let mut url = sim_endpoint(sim)?;
    url.path_segments_mut()
        .map_err(|()| TestingError::InvalidUrl("cannot modify URL path".to_owned()))?
        .push(ecu)
        .push("state");

    let response =
        crate::util::http::send_request(StatusCode::OK, http::Method::GET, None, None, url).await?;

    crate::util::http::response_to_t(&response)
}

fn sim_endpoint(sim: &EcuSim) -> Result<reqwest::Url, TestingError> {
    let url = reqwest::Url::parse(&format!("http://{}:{}", sim.host, sim.control_port))?;
    Ok(url)
}

/// Add a DTC to the ECU simulator
pub(crate) async fn add_dtc(
    sim: &EcuSim,
    ecu: &str,
    fault_memory: &str,
    dtc: &DtcMinimal,
) -> Result<(), TestingError> {
    let mut url = sim_endpoint(sim)?;
    url.path_segments_mut()
        .map_err(|()| TestingError::InvalidUrl("cannot modify URL path".to_owned()))?
        .push(ecu)
        .push("dtc")
        .push(fault_memory);

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
    let mut url = sim_endpoint(sim)?;
    url.path_segments_mut()
        .map_err(|()| TestingError::InvalidUrl("cannot modify URL path".to_owned()))?
        .push(ecu)
        .push("dtc")
        .push(fault_memory);

    let response =
        crate::util::http::send_request(StatusCode::OK, http::Method::GET, None, None, url).await?;

    crate::util::http::response_to_t(&response)
}

/// Delete all DTCs from the ECU simulator
pub(crate) async fn clear_all_dtcs(
    sim: &EcuSim,
    ecu: &str,
    fault_memory: &str,
) -> Result<(), TestingError> {
    let mut url = sim_endpoint(sim)?;
    url.path_segments_mut()
        .map_err(|()| TestingError::InvalidUrl("cannot modify URL path".to_owned()))?
        .push(ecu)
        .push("dtc")
        .push(fault_memory);

    crate::util::http::send_request(StatusCode::OK, http::Method::DELETE, None, None, url).await?;
    Ok(())
}

pub(crate) async fn reset_sim(sim: &EcuSim) -> Result<(), TestingError> {
    let mut url = sim_endpoint(sim)?;
    url.path_segments_mut()
        .map_err(|()| TestingError::InvalidUrl("cannot modify URL path".to_owned()))?
        .push("reset");

    crate::util::http::send_request(StatusCode::NO_CONTENT, http::Method::POST, None, None, url)
        .await?;
    Ok(())
}

/// Start recording inbound UDS frames on the ECU simulator.
///
/// Each received frame is appended as a lowercase hex string with no separator
/// (e.g. `"31011001"`). Call [`get_recordings`] or [`stop_and_clear_recording`]
/// to retrieve the accumulated frames.
pub(crate) async fn start_recording(sim: &EcuSim, ecu: &str) -> Result<(), TestingError> {
    let mut url = sim_endpoint(sim)?;
    url.path_segments_mut()
        .map_err(|()| TestingError::InvalidUrl("cannot modify URL path".to_owned()))?
        .push(ecu)
        .push("record");

    crate::util::http::send_request(StatusCode::NO_CONTENT, http::Method::POST, None, None, url)
        .await?;
    Ok(())
}

/// Stop the recorder and return all frames recorded since [`start_recording`].
///
/// The recorder is removed from the ECU simulator after this call; subsequent
/// frames are no longer captured until [`start_recording`] is called again.
pub(crate) async fn stop_and_clear_recording(
    sim: &EcuSim,
    ecu: &str,
) -> Result<Vec<String>, TestingError> {
    let mut url = sim_endpoint(sim)?;
    url.path_segments_mut()
        .map_err(|()| TestingError::InvalidUrl("cannot modify URL path".to_owned()))?
        .push(ecu)
        .push("record");

    let response =
        crate::util::http::send_request(StatusCode::OK, http::Method::DELETE, None, None, url)
            .await?;
    crate::util::http::response_to_t(&response)
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
    let mut url = sim_endpoint(sim)?;
    url.path_segments_mut()
        .map_err(|()| TestingError::InvalidUrl("cannot modify URL path".to_owned()))?
        .push("interceptor")
        .push(ecu)
        .push("inbound")
        .push(name);

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
    let mut url = sim_endpoint(sim)?;
    url.path_segments_mut()
        .map_err(|()| TestingError::InvalidUrl("cannot modify URL path".to_owned()))?
        .push("interceptor")
        .push(ecu)
        .push("inbound")
        .push(name);

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
