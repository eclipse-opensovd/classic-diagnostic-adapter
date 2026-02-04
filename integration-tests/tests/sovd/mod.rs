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
use http::{HeaderMap, Method, StatusCode};
use opensovd_cda_lib::config::configfile::Configuration;
use serde::{Serialize, de::DeserializeOwned};
use sovd_interfaces::components::ecu::modes::dtcsetting;

use crate::util::{
    TestingError,
    http::{response_to_t, send_cda_request},
};

mod custom_routes;
mod ecu;
mod locks;

pub(crate) const ECU_FLXC1000_ENDPOINT: &str = "components/flxc1000";
pub(crate) const ECU_FLXCNG1000_ENDPOINT: &str = "components/flxcng1000";

pub(crate) async fn put_mode<T: DeserializeOwned, S: Serialize>(
    config: &Configuration,
    headers: &HeaderMap,
    ecu_endpoint: &str,
    sub_path: &str,
    request: S,
    excepted_status: StatusCode,
) -> Result<Option<T>, TestingError> {
    let request_body = serde_json::to_string(&request)
        .map_err(|e| TestingError::InvalidData(format!("Failed to serialize request body: {e}")))?;
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

pub(crate) async fn set_dtc_setting(
    value: &str,
    config: &Configuration,
    headers: &HeaderMap,
    ecu_endpoint: &str,
    expected_status: StatusCode,
) -> Result<Option<dtcsetting::put::Response>, TestingError> {
    put_mode(
        config,
        headers,
        ecu_endpoint,
        "dtcsetting",
        dtcsetting::put::Request {
            value: value.to_owned(),
            parameters: None,
        },
        expected_status,
    )
    .await
}
