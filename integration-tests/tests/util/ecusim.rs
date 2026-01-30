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
use http::StatusCode;
use serde::Deserialize;

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
