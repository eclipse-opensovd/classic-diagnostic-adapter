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

use std::time::Duration;

use aide::transform::{TransformOperation, TransformParameter};
use axum::{
    Json,
    body::Bytes,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use axum_extra::extract::WithRejection;
use cda_interfaces::{
    DiagServiceError, UdsEcu,
    datatypes::{DTC, semantics},
    diagservices::{DiagServiceResponse, DiagServiceResponseType},
    file_manager::FileManager,
};
use hashbrown::HashMap;
use http::HeaderMap;
use serde::Serialize;
use sovd_interfaces::components::ecu::{
    data::service::get::DiagServiceQuery, faults::get::FaultQuery, modes as sovd_modes,
};

use crate::{
    openapi,
    sovd::{
        WebserverEcuState,
        auth::Claims,
        error::{ApiError, ErrorWrapper, api_error_from_diag_response},
        locks::validate_lock,
    },
};

pub(crate) async fn get<
    R: DiagServiceResponse + Send + Sync,
    T: UdsEcu + Send + Sync + Clone,
    U: FileManager + Send + Sync + Clone,
>(
    State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
    Query(query): Query<FaultQuery>,
) -> Response {
    let dtcs = match uds
        .ecu_dtc_by_mask(&ecu_name, query.status, query.severity, query.scope)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return ApiError::from(e).into_response();
        }
    };
    todo!("2");
}

pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
    openapi::request_octet(op)
        .description(
            "This function retrieves fault entries identified for a specific entity. Results can \
             filtered based on the fault's status, severity, or scope using query parameters.",
        )
        .response_with::<200, &[u8], _>(|res| res.description("Raw ECU response as bytes"))
        .parameter("status", |op: TransformParameter<String>| {
            op.description(
                "Filters the elements based on a status, if the value ia a full match. To allow \
                 multiple values the parameter is repeated. (0..*), they are 'OR' combined.",
            )
        })
        .parameter("severity", |op: TransformParameter<String>| {
            op.description("Filters the elements based on a severity")
        })
        .parameter("scope", |op: TransformParameter<String>| {
            op.description(
                "The scope to retrieve faults for. If not provided, all scopes are considered.",
            )
        })
        .parameter("include-schema", |op: TransformParameter<bool>| {
            op.description(
                "If set to true, the OpenSOVD schema will be included, defaults to false.",
            )
        })
        .with(openapi::error_bad_request)
        .with(openapi::error_forbidden)
        .with(openapi::error_internal_server)
        .with(openapi::error_not_found)
        .id("ecu_faults_get")
}
