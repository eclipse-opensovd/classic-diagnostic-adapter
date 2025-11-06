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

use crate::util::{TestingError, runtime::EcuSim};

pub(crate) async fn switch_variant(
    sim: &EcuSim,
    ecu: &str,
    variant: &str,
) -> Result<(), TestingError> {
    let mut url = sim_endpoint(sim)?;
    url.path_segments_mut()
        .map_err(|_| TestingError::InvalidUrl("cannot modify URL path".to_owned()))?
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

fn sim_endpoint(sim: &EcuSim) -> Result<reqwest::Url, TestingError> {
    let url = reqwest::Url::parse(&format!("http://{}:{}", sim.host, sim.control_port))?;
    Ok(url)
}
