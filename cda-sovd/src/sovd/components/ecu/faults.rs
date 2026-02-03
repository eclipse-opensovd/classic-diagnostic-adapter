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

use aide::{UseApi, transform::TransformOperation};
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use axum_extra::extract::WithRejection;
use cda_interfaces::{
    DynamicPlugin, UdsEcu,
    datatypes::DtcRecordAndStatus,
    diagservices::{DiagServiceResponse, DiagServiceResponseType},
    file_manager::FileManager,
};
use cda_plugin_security::Secured;
use serde_qs::axum::QsQuery;
use sovd_interfaces::components::ecu::{
    faults,
    faults::{Fault, delete::FaultQuery as DeleteFaultQuery, get::FaultQuery as GetFaultQuery},
};

use crate::{
    openapi,
    sovd::{
        IntoSovd, WebserverEcuState, create_schema,
        error::{ApiError, ErrorWrapper, api_error_from_diag_response},
        faults::faults::FaultStatus,
        locks::validate_lock,
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
    UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
    State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
    WithRejection(QsQuery(query), _): WithRejection<QsQuery<GetFaultQuery>, ApiError>,
) -> Response {
    let dtcs = match uds
        .ecu_dtc_by_mask(
            &ecu_name,
            &(security_plugin as DynamicPlugin),
            query.status,
            query.severity,
            query.scope,
        )
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
        items: dtcs
            .into_values()
            .map(crate::sovd::IntoSovd::into_sovd)
            .collect(),
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

pub(crate) async fn delete<
    R: DiagServiceResponse + Send + Sync,
    T: UdsEcu + Send + Sync + Clone,
    U: FileManager + Send + Sync + Clone,
>(
    UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
    State(WebserverEcuState {
        ecu_name,
        uds,
        locks,
        ..
    }): State<WebserverEcuState<R, T, U>>,
    WithRejection(QsQuery(_query), _): WithRejection<QsQuery<DeleteFaultQuery>, ApiError>,
) -> Response {
    let claims = security_plugin.claims();
    if let Some(validation_failure) = validate_lock(&claims, &ecu_name, &locks, false).await {
        return validation_failure;
    }
    // todo: query.scope to specify which group should be cleared not yet implemented!
    match uds
        .delete_dtcs(&ecu_name, &(security_plugin as DynamicPlugin), None)
        .await
    {
        Ok(res) => match res.response_type() {
            DiagServiceResponseType::Positive => StatusCode::NO_CONTENT.into_response(),
            DiagServiceResponseType::Negative => api_error_from_diag_response(&res, false),
        },
        Err(e) => ErrorWrapper {
            error: e.into(),
            include_schema: false,
        }
        .into_response(),
    }
}

pub(crate) fn docs_delete(op: TransformOperation) -> TransformOperation {
    op.description(
        "This endpoint removes all DTCs for the specified component. If a scope is set via query \
         parameter, only that group of DTCs will be cleared.",
    )
    .response_with::<204, (), _>(|res| {
        res.description("On successfull call a 204 without content will be returned.")
    })
    .with(openapi::error_bad_request)
    .with(openapi::error_forbidden)
    .with(openapi::error_not_found)
    .id("ecu_faults_delete")
}

pub(crate) mod id {
    use aide::UseApi;
    use axum::extract::{Path, Query};
    use cda_interfaces::{
        DynamicPlugin,
        datatypes::{self},
    };
    use cda_plugin_security::Secured;
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
                errors: self.errors.map(|v| {
                    v.into_iter()
                        .map(crate::sovd::IntoSovd::into_sovd)
                        .collect()
                }),
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
                errors: self.errors.map(|v| {
                    v.into_iter()
                        .map(crate::sovd::IntoSovd::into_sovd)
                        .collect()
                }),
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
                        snapshots: self.snapshots.map(crate::sovd::IntoSovd::into_sovd),
                        extended_data_records: self
                            .extended_data_records
                            .map(crate::sovd::IntoSovd::into_sovd),
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
        UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
        Path(id): Path<IdPathParam>,
        Query(query): Query<DtcIdQuery>,
        State(WebserverEcuState { ecu_name, uds, .. }): State<WebserverEcuState<R, T, U>>,
    ) -> Response {
        match uds
            .ecu_dtc_extended(
                &ecu_name,
                &(security_plugin as DynamicPlugin),
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

    pub(crate) async fn delete<
        R: DiagServiceResponse + Send + Sync,
        T: UdsEcu + Send + Sync + Clone,
        U: FileManager + Send + Sync + Clone,
    >(
        UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
        Path(IdPathParam { id }): Path<IdPathParam>,
        State(WebserverEcuState {
            ecu_name,
            uds,
            locks,
            ..
        }): State<WebserverEcuState<R, T, U>>,
    ) -> Response {
        let claims = security_plugin.claims();
        if let Some(validation_failure) = validate_lock(&claims, &ecu_name, &locks, false).await {
            return validation_failure;
        }
        match uds
            .delete_dtcs(&ecu_name, &(security_plugin as DynamicPlugin), Some(id))
            .await
        {
            Ok(res) => match res.response_type() {
                DiagServiceResponseType::Positive => StatusCode::NO_CONTENT.into_response(),
                DiagServiceResponseType::Negative => api_error_from_diag_response(&res, false),
            },
            Err(e) => ErrorWrapper {
                error: e.into(),
                include_schema: false,
            }
            .into_response(),
        }
    }

    pub(crate) fn docs_delete(op: TransformOperation) -> TransformOperation {
        op.description("Clear the given DTC from the specified component.")
            .response_with::<204, (), _>(|res| {
                res.description("Returns 204 without content if DTC could successfully be deleted.")
            })
            .with(openapi::error_bad_request)
            .with(openapi::error_forbidden)
            .with(openapi::error_not_found)
            .id("ecu_faults_delete_by_id")
    }
}

#[cfg(test)]
mod tests {
    use cda_interfaces::{
        HashMap,
        datatypes::{DtcRecord, DtcStatus},
        diagservices::mock::MockDiagServiceResponse,
        file_manager::mock::MockFileManager,
        mock::MockUdsEcu,
    };
    use cda_plugin_security::mock::TestSecurityPlugin;

    use super::*;
    use crate::sovd::tests::create_test_webserver_state;

    #[tokio::test]
    async fn test_get_faults() {
        // Arrange
        let ecu_name = "TestECU".to_string();
        let mut mock_uds = MockUdsEcu::new();
        let mock_file_manager = MockFileManager::new();

        // Create test DTC data
        let test_dtc = DtcRecordAndStatus {
            record: DtcRecord {
                code: 0x42,
                display_code: Some("P1234".to_string()),
                fault_name: "Test Fault".to_string(),
                severity: 2,
            },
            scope: "FaultMem".to_string(),
            status: DtcStatus {
                test_failed: true,
                test_failed_this_operation_cycle: false,
                pending_dtc: false,
                confirmed_dtc: true,
                test_not_completed_since_last_clear: false,
                test_failed_since_last_clear: true,
                test_not_completed_this_operation_cycle: false,
                warning_indicator_requested: false,
                mask: 0x29,
            },
        };

        let expected_dtcs = HashMap::from_iter([(test_dtc.record.code, test_dtc.clone())]);

        // Setup mock expectations
        mock_uds
            .expect_ecu_dtc_by_mask()
            .withf(|name, _, status, severity, scope| {
                name == "TestECU" && status.is_none() && severity.is_none() && scope.is_none()
            })
            .times(1)
            .returning(move |_, _, _, _, _| {
                let dtcs = expected_dtcs.clone();
                Ok(dtcs)
            });

        // Create state using test utility
        let state = create_test_webserver_state::<
            MockDiagServiceResponse,
            MockUdsEcu,
            MockFileManager,
        >(ecu_name, mock_uds, mock_file_manager);

        let query = GetFaultQuery {
            status: None,
            severity: None,
            scope: None,
            include_schema: false,
        };

        // Create security plugin using test utility
        let security_plugin = Box::new(TestSecurityPlugin);
        let response = get::<MockDiagServiceResponse, MockUdsEcu, MockFileManager>(
            UseApi(Secured(security_plugin), std::marker::PhantomData),
            State(state),
            WithRejection(QsQuery(query), std::marker::PhantomData),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("Failed to read response body");

        let response_data: faults::get::Response =
            serde_json::from_slice(&body).expect("Failed to deserialize response");

        // Verify response structure
        assert!(response_data.schema.is_none());
        assert_eq!(response_data.items.len(), 1);

        // Verify fault data using values from test_dtc
        let fault = response_data
            .items
            .first()
            .expect("Fault item should be present");
        assert_eq!(fault.code, format!("{:X}", test_dtc.record.code));
        assert_eq!(fault.display_code, test_dtc.record.display_code);
        assert_eq!(fault.fault_name, test_dtc.record.fault_name);
        assert_eq!(fault.severity, Some(test_dtc.record.severity));
        assert_eq!(fault.scope, Some(test_dtc.scope.clone()));

        // Verify fault status using values from test_dtc
        let status = fault.status.as_ref().expect("Status should be present");
        assert_eq!(status.test_failed, Some(test_dtc.status.test_failed));
        assert_eq!(
            status.test_failed_this_operation_cycle,
            Some(test_dtc.status.test_failed_this_operation_cycle)
        );
        assert_eq!(status.pending_dtc, Some(test_dtc.status.pending_dtc));
        assert_eq!(status.confirmed_dtc, Some(test_dtc.status.confirmed_dtc));
        assert_eq!(
            status.test_not_completed_since_last_clear,
            Some(test_dtc.status.test_not_completed_since_last_clear)
        );
        assert_eq!(
            status.test_failed_since_last_clear,
            Some(test_dtc.status.test_failed_since_last_clear)
        );
        assert_eq!(
            status.test_not_completed_this_operation_cycle,
            Some(test_dtc.status.test_not_completed_this_operation_cycle)
        );
        assert_eq!(
            status.warning_indicator_requested,
            Some(test_dtc.status.warning_indicator_requested)
        );
        assert_eq!(status.mask, Some(format!("{:02X}", test_dtc.status.mask)));
    }
}
