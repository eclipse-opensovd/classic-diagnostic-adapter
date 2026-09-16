/*
 * SPDX-FileCopyrightText: 2025 Copyright (c) Contributors to the Eclipse Foundation
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

pub mod sovd2uds {
    pub mod bulk_data {
        pub use cda_interfaces::runtime_update_api::{
            BulkDataCreated, BulkDataCreatedList, BulkDataDeleted, BulkDataList,
        };

        pub mod flash_files {
            pub mod get {
                pub type Response = crate::sovd2uds::FileList;
            }
        }

        pub mod runtimefiles {
            pub use cda_interfaces::runtime_update_api::RuntimeFilesQuery;
        }
    }

    pub mod operations {
        pub mod runtimefilesupdate {
            use cda_interfaces::runtime_update_api::ExecutionFailureClass;
            pub use cda_interfaces::runtime_update_api::{
                ExecutionFailure, ExecutionMode, ExecutionStatus, UpdateExecution,
            };

            /// The operation-specific parameters for a diagnostic database update execution.
            #[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
            pub struct ExecutionParameters {
                /// The operation to perform on the staged runtime files.
                pub mode: ExecutionMode,
            }

            /// Request body for an execution.
            ///
            /// Follows the standard operations convention of wrapping the
            /// operation-specific inputs in a `parameters` field.
            #[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
            pub struct ExecutionRequest {
                pub parameters: ExecutionParameters,
            }

            /// The discriminant of an execution's status without the inner payload.
            #[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
            #[serde(rename_all = "lowercase")]
            pub enum ExecutionStatusKind {
                Running,
                Completed,
                Failed,
            }

            /// Response body returned by `POST /executions`.
            #[derive(Debug, serde::Serialize, schemars::JsonSchema)]
            pub struct ExecutionCreatedResponse {
                /// Unique execution identifier assigned by the server.
                pub id: String,
            }

            /// Operation-specific values reported for an execution.
            #[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
            pub struct ExecutionResponseParameters {
                /// The operation that was requested.
                pub mode: ExecutionMode,
                /// Human-readable failure description, present only when `status` is `failed`.
                #[serde(default, skip_serializing_if = "Option::is_none")]
                pub reason: Option<String>,
            }

            /// Response body returned by `GET /executions/{id}`.
            #[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
            pub struct ExecutionResponse {
                /// Current lifecycle state of the execution.
                pub status: ExecutionStatusKind,
                /// Operation-specific status details.
                pub parameters: ExecutionResponseParameters,
                #[schemars(skip)]
                #[serde(default, skip_serializing_if = "Option::is_none")]
                pub schema: Option<schemars::Schema>,
            }

            /// Response body returned by `GET /executions`.
            #[derive(serde::Serialize, schemars::JsonSchema)]
            pub struct ExecutionListResponse {
                pub items: Vec<crate::common::operations::OperationIdItem>,
            }

            impl From<UpdateExecution> for ExecutionResponse {
                fn from(exec: UpdateExecution) -> Self {
                    let (status, reason) = match exec.status {
                        ExecutionStatus::Running => (ExecutionStatusKind::Running, None),
                        ExecutionStatus::Completed => (ExecutionStatusKind::Completed, None),
                        ExecutionStatus::Failed(failure) => {
                            let reason = match failure.class() {
                                ExecutionFailureClass::Fatal => format!("fatal: {failure}"),
                                ExecutionFailureClass::Ordinary => failure.to_string(),
                            };
                            (ExecutionStatusKind::Failed, Some(reason))
                        }
                    };
                    Self {
                        status,
                        parameters: ExecutionResponseParameters {
                            mode: exec.mode,
                            reason,
                        },
                        schema: None,
                    }
                }
            }

            #[cfg(test)]
            mod tests {
                use std::sync::Arc;

                use cda_interfaces::runtime_update_api::{
                    RecoveryError, ReloadError, RuntimeUpdateError,
                };

                use super::*;

                #[test]
                fn execution_status_kind_uses_only_standard_sovd_values() {
                    assert_eq!(
                        serde_json::to_value(ExecutionStatusKind::Running).unwrap(),
                        serde_json::json!("running")
                    );
                    assert_eq!(
                        serde_json::to_value(ExecutionStatusKind::Completed).unwrap(),
                        serde_json::json!("completed")
                    );
                    assert_eq!(
                        serde_json::to_value(ExecutionStatusKind::Failed).unwrap(),
                        serde_json::json!("failed")
                    );

                    let schema =
                        serde_json::to_value(schemars::schema_for!(ExecutionStatusKind)).unwrap();
                    assert_eq!(
                        schema.get("enum"),
                        Some(&serde_json::json!(["running", "completed", "failed"]))
                    );
                    for unsupported in [
                        "recovery-failed",
                        "recoveryfailed",
                        "RecoveryFailed",
                        "additional",
                    ] {
                        assert!(
                            serde_json::from_value::<ExecutionStatusKind>(serde_json::json!(
                                unsupported
                            ))
                            .is_err(),
                            "unexpectedly accepted non-SOVD execution status {unsupported}"
                        );
                    }
                }

                fn failed_response(failure: ExecutionFailure) -> serde_json::Value {
                    serde_json::to_value(ExecutionResponse::from(UpdateExecution {
                        id: "execution-id".to_string(),
                        mode: ExecutionMode::Apply,
                        status: ExecutionStatus::Failed(failure),
                    }))
                    .unwrap()
                }

                #[test]
                fn failure_serializes_reason() {
                    assert_eq!(
                        failed_response(ExecutionFailure::RuntimeUnchanged(Arc::new(
                            RuntimeUpdateError::ValidationFailed("verification failed".to_owned())
                        ))),
                        serde_json::json!({
                            "status": "failed",
                            "parameters": {
                                "mode": "apply",
                                "reason": "Validation failed: verification failed"
                            }
                        })
                    );
                }

                #[test]
                fn recovery_failure_serializes_reason() {
                    assert_eq!(
                        failed_response(ExecutionFailure::RecoveryFailed {
                            original: ReloadError::General("candidate rejected".to_owned()),
                            recovery: RecoveryError::PersistentRestore(ReloadError::General(
                                "backup unreadable".to_owned()
                            )),
                        }),
                        serde_json::json!({
                            "status": "failed",
                            "parameters": {
                                "mode": "apply",
                                "reason": "fatal: Runtime update failed and the previous database \
                                    could not be restored: Reload error: candidate rejected; \
                                    Restoring the previous databases failed: Reload error: backup \
                                    unreadable"
                            }
                        })
                    );
                }
            }
        }
    }

    pub mod data {
        pub mod network_structure {
            use serde::{Deserialize, Serialize};

            #[derive(Serialize, Deserialize)]
            #[serde(rename_all = "PascalCase")]
            #[derive(schemars::JsonSchema)]
            pub struct Ecu {
                /// ECU name
                pub qualifier: String,
                /// ECU variant
                pub variant: String,
                /// ECU state \[Online, Offline, `NotTested`]
                #[serde(rename = "EcuState")]
                pub state: String,
                /// ECU logical address
                pub logical_address: String,
                /// ECU link '\<ecu>\_on\_\<protocol>'
                pub logical_link: String,
            }

            #[derive(Serialize, Deserialize)]
            #[serde(rename_all = "PascalCase")]
            #[derive(schemars::JsonSchema)]
            pub struct Gateway {
                /// Gateway ECU name
                pub name: String,
                /// Network (IP) address
                pub network_address: String,
                /// Logical ECU address
                pub logical_address: String,
                /// List of ECUs connected via gateway
                pub ecus: Vec<Ecu>,
            }

            #[derive(Serialize, Deserialize)]
            #[serde(rename_all = "PascalCase")]
            #[derive(schemars::JsonSchema)]
            pub struct FunctionalGroup {
                pub qualifier: String,
                pub ecus: Vec<Ecu>,
            }

            #[derive(Serialize, Deserialize)]
            #[serde(rename_all = "PascalCase")]
            #[derive(schemars::JsonSchema)]
            pub struct NetworkStructure {
                pub functional_groups: Vec<FunctionalGroup>,
                pub gateways: Vec<Gateway>,
            }

            pub mod get {
                use serde::{Deserialize, Serialize};

                #[derive(Serialize, Deserialize, schemars::JsonSchema)]
                #[schemars(rename = "NetworkStructureResponse")]
                pub struct Response {
                    pub id: String,
                    pub data: Vec<crate::apps::sovd2uds::data::network_structure::NetworkStructure>,
                    #[schemars(skip)]
                    #[serde(skip_serializing_if = "Option::is_none")]
                    pub schema: Option<schemars::Schema>,
                }
            }
        }
    }
}
