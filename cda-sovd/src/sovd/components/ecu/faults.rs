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

use aide::transform::TransformOperation;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use axum_extra::extract::WithRejection;
use cda_interfaces::{
    UdsEcu, datatypes::DtcRecordAndStatus, diagservices::DiagServiceResponse,
    file_manager::FileManager,
};
use serde_qs::axum::QsQuery;
use sovd_interfaces::components::ecu::{
    faults,
    faults::get::{Fault, FaultQuery, FaultStatus},
};

use crate::{
    openapi,
    sovd::{IntoSovd, WebserverEcuState, create_schema, error::ApiError},
};

impl IntoSovd for DtcRecordAndStatus {
    type SovdType = Fault;

    fn into_sovd(self) -> Self::SovdType {
        Fault {
            code: format!("{:X}", self.record.code),
            scope: Some(self.scope),
            display_code: self.record.display_code,
            fault_name: self.record.fault_name,
            severity: Some(self.record.severity),
            status: Some(FaultStatus {
                test_failed: Some(self.status.test_failed),
                test_failed_this_operation_cycle: Some(
                    self.status.test_failed_this_operation_cycle,
                ),
                pending_dtc: Some(self.status.pending_dtc),
                confirmed_dtc: Some(self.status.confirmed_dtc),
                test_not_completed_since_last_clear: Some(
                    self.status.test_not_completed_since_last_clear,
                ),
                test_failed_since_last_clear: Some(self.status.test_failed_since_last_clear),
                test_not_completed_this_operation_cycle: Some(
                    self.status.test_not_completed_this_operation_cycle,
                ),
                warning_indicator_requested: Some(self.status.warning_indicator_requested),
                mask: Some(format!("{:02X}", self.status.mask)),
            }),
        }
    }
}

fn create_faults_schema() -> Result<schemars::Schema, ApiError> {
    let schema = create_schema!(Fault);
    let mut val = schema.to_value();

    crate::sovd::remove_descriptions_recursive(&mut val);
    let val = val
        .as_object_mut()
        .map(std::mem::take)
        .ok_or(ApiError::InternalServerError(Some(
            "Failed to create schema".to_string(),
        )))?;
    Ok(schemars::Schema::from(val))
}

pub(crate) async fn get<
    R: DiagServiceResponse + Send + Sync,
    T: UdsEcu + Send + Sync + Clone,
    U: FileManager + Send + Sync + Clone,
>(
    State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
    WithRejection(QsQuery(query), _): WithRejection<QsQuery<FaultQuery>, ApiError>,
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

    let schema = if query.include_schema {
        match create_faults_schema() {
            Ok(schema) => Some(schema),
            Err(e) => return e.into_response(),
        }
    } else {
        None
    };

    let faults = faults::get::Response {
        items: dtcs.into_iter().map(|dtc| dtc.into_sovd()).collect(),
        schema,
    };

    (StatusCode::OK, Json(faults)).into_response()
}

pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
    openapi::request_octet(op)
        .description(
            "This function retrieves fault entries identified for a specific entity. Results can \
             filtered based on the fault's status, severity, or scope using query parameters.",
        )
        .response_with::<200, Json<Vec<Fault>>, _>(|res| {
            res.description("List with fault entries filtered by the query params")
        })
        .with(openapi::error_bad_request)
        .with(openapi::error_forbidden)
        .with(openapi::error_not_found)
        .id("ecu_faults_get")
}
