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
    faults::{Fault, get::FaultQuery},
};

use crate::{
    openapi,
    sovd::{
        IntoSovd, WebserverEcuState, create_schema, error::ApiError, faults::faults::FaultStatus,
        remove_descriptions_recursive,
    },
};

impl IntoSovd for DtcRecordAndStatus {
    type SovdType = Fault;

    fn into_sovd(self) -> Self::SovdType {
        Self::SovdType {
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
        let mut schema = create_schema!(Fault).to_value();
        remove_descriptions_recursive(&mut schema);
        match crate::sovd::value_to_schema(schema) {
            Ok(s) => Some(s),
            Err(e) => return e.into_response(),
        }
    } else {
        None
    };

    let faults = faults::get::Response {
        items: dtcs.into_values().map(|dtc| dtc.into_sovd()).collect(),
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

pub(crate) mod id {
    use axum::extract::{Path, Query};
    use cda_interfaces::datatypes::{self};
    use sovd_interfaces::{
        components::ecu::faults::id::get::{
            DtcIdQuery, EnvironmentData, ExtendedDataRecords, ExtendedFault, ExtendedSnapshots,
            Snapshot,
        },
        error::DataError,
    };

    use super::*;
    use crate::sovd::{
        IntoSovdWithSchema, components::IdPathParam, error::VendorErrorCode,
        remove_descriptions_recursive,
    };

    impl IntoSovd for datatypes::DtcSnapshot {
        type SovdType = Snapshot;
        fn into_sovd(self) -> Self::SovdType {
            Self::SovdType {
                number_of_identifiers: self.number_of_identifiers,
                record: self.record,
            }
        }
    }

    impl IntoSovd for datatypes::ExtendedDataRecords {
        type SovdType = ExtendedDataRecords<VendorErrorCode>;

        fn into_sovd(self) -> Self::SovdType {
            Self::SovdType {
                data: self.data,
                errors: self
                    .errors
                    .map(|v| v.into_iter().map(|e| e.into_sovd()).collect()),
            }
        }
    }

    impl IntoSovd for datatypes::ExtendedSnapshots {
        type SovdType = ExtendedSnapshots<VendorErrorCode>;

        fn into_sovd(self) -> Self::SovdType {
            Self::SovdType {
                data: self
                    .data
                    .map(|d| d.into_iter().map(|(k, v)| (k, v.into_sovd())).collect()),
                errors: self
                    .errors
                    .map(|v| v.into_iter().map(|e| e.into_sovd()).collect()),
            }
        }
    }

    impl IntoSovdWithSchema for datatypes::DtcExtendedInfo {
        type SovdType = ExtendedFault<VendorErrorCode>;

        fn into_sovd_with_schema(self, include_schema: bool) -> Result<Self::SovdType, ApiError> {
            let t = Self::SovdType {
                // Build the schema manually because the DTC content is dynamic and
                // purely defined by the database.
                // Deriving the types from schemars would not work here.
                item: self.record_and_status.into_sovd(),
                environment_data: if self.snapshots.is_some()
                    || self.extended_data_records.is_some()
                {
                    Some(EnvironmentData {
                        snapshots: self.snapshots.map(|s| s.into_sovd()),
                        extended_data_records: self.extended_data_records.map(|e| e.into_sovd()),
                    })
                } else {
                    None
                },
                schema: if include_schema {
                    let fault_schema = create_schema!(Fault).to_value();

                    let snapshot_schema = self.snapshots_schema.ok_or_else(|| {
                        ApiError::InternalServerError(Some(
                            "Failed to extract snapshot schema".to_string(),
                        ))
                    })?;

                    let extended_schema = self.extended_data_records_schema.ok_or_else(|| {
                        ApiError::InternalServerError(Some(
                            "Failed to extract extended schema".to_string(),
                        ))
                    })?;

                    let schema_entries = [
                        ("item", fault_schema),
                        (
                            "environment_data",
                            serde_json::json!({
                                "snapshots": {
                                    "data": snapshot_schema,
                                    "errors": create_schema!(
                                        Option<Vec<DataError<VendorErrorCode>>>).to_value()
                                },
                                "extended_data_records": {
                                    "data": extended_schema,
                                    "errors": create_schema!(
                                        Option<Vec<DataError<VendorErrorCode>>>).to_value()
                                }
                            }),
                        ),
                    ];

                    let mut schema = serde_json::Value::from(
                        schema_entries
                            .into_iter()
                            .map(|(k, v)| (k.to_owned(), v))
                            .collect::<serde_json::Map<_, _>>(),
                    );
                    remove_descriptions_recursive(&mut schema);
                    match crate::sovd::value_to_schema(schema) {
                        Ok(s) => Some(s),
                        Err(e) => return Err(e),
                    }
                } else {
                    None
                },
            };
            Ok(t)
        }
    }

    pub(crate) async fn get<
        R: DiagServiceResponse + Send + Sync,
        T: UdsEcu + Send + Sync + Clone,
        U: FileManager + Send + Sync + Clone,
    >(
        Path(id): Path<IdPathParam>,
        Query(query): Query<DtcIdQuery>,
        State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
    ) -> Response {
        match uds
            .ecu_dtc_extended(
                &ecu_name,
                &id,
                query.include_extended_data,
                query.include_snapshot_data,
                query.include_schema,
            )
            .await
        {
            Ok(r) => match r.into_sovd_with_schema(query.include_schema) {
                Ok(r) => (StatusCode::OK, Json(r)).into_response(),
                Err(e) => e.into_response(),
            },
            Err(e) => ApiError::from(e).into_response(),
        }
    }

    pub(crate) fn docs_get(op: TransformOperation) -> TransformOperation {
        openapi::request_octet(op)
            .description(
                "Retrieve details about a given DTC. The full schema is only available through \
                 the `includeSchema` query parameter.",
            )
            .response_with::<200, Json<ExtendedFault<VendorErrorCode>>, _>(|res| {
                res.description(
                    "Fault details with optional extended data, snapshot data and schema",
                )
            })
            .with(openapi::error_bad_request)
            .with(openapi::error_forbidden)
            .with(openapi::error_not_found)
            .id("ecu_faults_get")
    }
}
