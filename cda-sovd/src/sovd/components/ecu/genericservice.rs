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

use super::*;
use crate::{
    openapi,
    sovd::{WebserverEcuState, get_octet_stream_payload},
};

pub(crate) async fn put<R: DiagServiceResponse, T: UdsEcu + Clone, U: FileManager>(
    headers: HeaderMap,
    State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
    body: Bytes,
) -> Response {
    match headers.get(header::ACCEPT) {
        Some(v) if v == mime::APPLICATION_OCTET_STREAM.essence_str() => (Some(v), false),
        _ => {
            return ErrorWrapper {
                error: ApiError::BadRequest(format!(
                    "Unsupported Accept, only {} is supported",
                    mime::APPLICATION_OCTET_STREAM
                )),
                include_schema: false,
            }
            .into_response();
        }
    };
    match headers.get(header::CONTENT_TYPE) {
        Some(v) if v == mime::APPLICATION_OCTET_STREAM.essence_str() => (),
        _ => {
            return ErrorWrapper {
                error: ApiError::BadRequest(format!(
                    "Unsupported Content-Type, only {} is supported",
                    mime::APPLICATION_OCTET_STREAM
                )),
                include_schema: false,
            }
            .into_response();
        }
    }

    let data = match get_octet_stream_payload(&headers, &body) {
        Ok(value) => value,
        Err(e) => {
            return ErrorWrapper {
                error: e,
                include_schema: false,
            }
            .into_response();
        }
    };
    let Some(UdsPayloadData::Raw(uds_raw_payload)) = data else {
        return ErrorWrapper {
            error: ApiError::InternalServerError(Some("Failure reading payload data.".to_owned())),
            include_schema: false,
        }
        .into_response();
    };

    let ecu_response = match uds
        .send_genericservice(&ecu_name, uds_raw_payload, None)
        .await
        .map_err(std::convert::Into::into)
    {
        Err(e) => {
            return ErrorWrapper {
                error: e,
                include_schema: false,
            }
            .into_response();
        }
        Ok(v) => v,
    };
    // Return the raw response
    (StatusCode::OK, Bytes::from_owner(ecu_response)).into_response()
}

pub(crate) fn docs_put(op: TransformOperation) -> TransformOperation {
    openapi::request_octet(op)
        .description("Send a generic service request to the ECU")
        .response_with::<200, &[u8], _>(|res| res.description("Raw ECU response as bytes"))
        .with(openapi::error_bad_request)
        .with(openapi::error_forbidden)
        .with(openapi::error_internal_server)
        .with(openapi::error_not_found)
        .id("ecu_genericservice_put")
}
