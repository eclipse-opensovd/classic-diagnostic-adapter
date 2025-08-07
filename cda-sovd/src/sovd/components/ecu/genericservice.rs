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

use axum::{body::Bytes, extract::State, response::Response};
use cda_interfaces::{
    UdsEcu,
    diagservices::{DiagServiceResponse, UdsPayloadData},
    file_manager::FileManager,
};
use http::{HeaderMap, header};
use sovd_interfaces::components::ecu::data::DataRequestPayload;

use super::*;
use crate::sovd::{WebserverEcuState, get_payload_data};

pub(crate) async fn put<
    R: DiagServiceResponse + Send + Sync,
    T: UdsEcu + Send + Sync + Clone,
    U: FileManager + Send + Sync + Clone,
>(
    headers: HeaderMap,
    State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
    body: Bytes,
) -> Response {
    match headers.get(header::ACCEPT) {
        Some(v) if v == mime::APPLICATION_OCTET_STREAM.essence_str() => (Some(v), false),
        _ => {
            return ErrorWrapper(ApiError::BadRequest(format!(
                "Unsupported Accept, only {} is supported",
                mime::APPLICATION_OCTET_STREAM
            )))
            .into_response();
        }
    };

    let data = match get_payload_data::<DataRequestPayload>(&headers, &body) {
        Ok(value) => value,
        Err(e) => return ErrorWrapper(e).into_response(),
    };
    let uds_raw_payload = match data {
        Some(UdsPayloadData::Raw(raw_data)) => raw_data,
        _ => {
            return ErrorWrapper(ApiError::BadRequest(format!(
                "Unsupported payload, only Content-Type {} containing the raw uds packet is \
                 supported ",
                mime::APPLICATION_OCTET_STREAM
            )))
            .into_response();
        }
    };

    let ecu_response = match uds
        .send_genericservice(&ecu_name, uds_raw_payload, None)
        .await
        .map_err(std::convert::Into::into)
    {
        Err(e) => return ErrorWrapper(e).into_response(),
        Ok(v) => v,
    };
    // Return the raw response
    (StatusCode::OK, Bytes::from_owner(ecu_response)).into_response()
}
