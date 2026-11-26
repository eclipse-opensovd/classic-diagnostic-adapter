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
    /// Capability document of the `sovd2uds` app, `GET /vehicle/v15/apps/sovd2uds`.
    /// Each link property names a resource of the app.
    pub mod get {
        #[derive(serde::Serialize, schemars::JsonSchema)]
        pub struct Response {
            pub id: String,
            pub name: String,
            #[serde(rename = "bulk-data")]
            pub bulk_data: String,
            pub data: String,
            /// Only present if the app serves at least one operation (Table 53, C1).
            #[serde(skip_serializing_if = "Option::is_none")]
            pub operations: Option<String>,
            #[schemars(skip)]
            #[serde(skip_serializing_if = "Option::is_none")]
            pub schema: Option<schemars::Schema>,
        }

        #[cfg(test)]
        mod tests {
            use super::Response;

            #[test]
            fn capability_document_has_id_name_and_links_without_items() {
                let response = Response {
                    id: "sovd2uds".to_owned(),
                    name: "sovd2uds".to_owned(),
                    bulk_data: "http://host/vehicle/v15/apps/sovd2uds/bulk-data".to_owned(),
                    data: "http://host/vehicle/v15/apps/sovd2uds/data".to_owned(),
                    operations: Some("http://host/vehicle/v15/apps/sovd2uds/operations".to_owned()),
                    schema: None,
                };
                let value = serde_json::to_value(&response).unwrap();
                let object = value.as_object().unwrap();

                assert_eq!(object.get("id").and_then(|v| v.as_str()), Some("sovd2uds"));
                assert_eq!(
                    object.get("name").and_then(|v| v.as_str()),
                    Some("sovd2uds")
                );
                assert_eq!(
                    object.get("bulk-data").and_then(|v| v.as_str()),
                    Some("http://host/vehicle/v15/apps/sovd2uds/bulk-data")
                );
                assert_eq!(
                    object.get("data").and_then(|v| v.as_str()),
                    Some("http://host/vehicle/v15/apps/sovd2uds/data")
                );
                assert_eq!(
                    object.get("operations").and_then(|v| v.as_str()),
                    Some("http://host/vehicle/v15/apps/sovd2uds/operations")
                );
                assert!(!object.contains_key("items"));
                assert!(!object.contains_key("schema"));
            }

            #[test]
            fn operations_link_is_omitted_without_operations() {
                let response = Response {
                    id: "sovd2uds".to_owned(),
                    name: "sovd2uds".to_owned(),
                    bulk_data: String::new(),
                    data: String::new(),
                    operations: None,
                    schema: None,
                };
                let value = serde_json::to_value(&response).unwrap();
                assert!(!value.as_object().unwrap().contains_key("operations"));
            }
        }
    }

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
        /// Operation to connect an ECU's `DoIP` entity directly to an IP address,
        /// instead of waiting for it to be discovered via VIR/VAM.
        ///
        /// Preliminary: this is expected to move into the topology plugin.
        pub mod doip_connect_ecu {
            fn default_protocol_version() -> u8 {
                // ISO 13400-2:2012
                0x02
            }

            /// The operation-specific parameters of an execution.
            #[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
            pub struct ExecutionParameters {
                /// Identifier of the ECU to connect, as used in `/components/{ecu}`.
                pub ecu: String,
                /// IP address of the `DoIP` entity of the ECU.
                pub ip: String,
                /// Raw `DoIP` protocol version byte, defaults to `0x02` (ISO 13400-2:2012).
                #[serde(default = "default_protocol_version")]
                pub protocol_version: u8,
            }

            /// Request body for an execution.
            ///
            /// Follows the standard operations convention of wrapping the
            /// operation-specific inputs in a `parameters` field.
            #[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
            #[schemars(rename = "DoipConnectEcuRequest")]
            pub struct ExecutionRequest {
                pub parameters: ExecutionParameters,
            }

            /// Operation-specific values reported for a finished execution.
            #[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
            pub struct ExecutionResponseParameters {
                /// The ECU that was connected.
                pub ecu: String,
                /// The IP address the ECU was connected to.
                pub ip: String,
            }

            /// Response body of the synchronous execution.
            #[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
            #[schemars(rename = "DoipConnectEcuResponse")]
            pub struct ExecutionResponse {
                pub parameters: ExecutionResponseParameters,
                #[schemars(skip)]
                #[serde(default, skip_serializing_if = "Option::is_none")]
                pub schema: Option<schemars::Schema>,
            }

            /// Operation description (`GET .../operations/doip-connect-ecu`).
            #[derive(serde::Serialize, schemars::JsonSchema)]
            #[schemars(rename = "DoipConnectEcuOperationResponse")]
            pub struct OperationResponse {
                /// The entry of the operation in the operations collection.
                pub item: crate::common::operations::OperationCollectionItem,
                /// JSON schema of the response, only present if requested with
                /// `include-schema=true`.
                #[schemars(skip)]
                #[serde(skip_serializing_if = "Option::is_none")]
                pub schema: Option<schemars::Schema>,
            }

            #[cfg(test)]
            mod tests {
                use super::ExecutionRequest;

                #[test]
                fn protocol_version_defaults_to_iso_13400_2012() {
                    let request: ExecutionRequest = serde_json::from_value(serde_json::json!({
                        "parameters": { "ecu": "my_ecu", "ip": "10.0.0.5" }
                    }))
                    .unwrap();
                    assert_eq!(request.parameters.protocol_version, 0x02);
                }
            }
        }

        /// The `networkreset` operation, which clears the persisted ECU topology and/or runs a new
        /// ECU detection.
        pub mod networkreset {
            pub use cda_interfaces::topology::{
                NetworkResetExecution, NetworkResetFlags, NetworkResetStatus,
            };

            // The status set of ISO 17978-3 Table 185, shared with the other operations.
            pub use crate::components::ecu::operations::ExecutionStatus;

            /// The operation-specific parameters of a `networkreset` execution. Both
            /// flags default to `true`.
            ///
            /// Unknown fields are rejected, so a typo cannot silently select the
            /// destructive defaults.
            #[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
            #[serde(deny_unknown_fields)]
            pub struct ExecutionParameters {
                /// Clear the persisted ECU topology.
                #[serde(default)]
                #[schemars(with = "bool", default = "crate::default_true")]
                pub clear_persisted: Option<bool>,
                /// Run a live detection (VIR/VAM discovery and variant detection).
                #[serde(default)]
                #[schemars(with = "bool", default = "crate::default_true")]
                pub trigger_detection: Option<bool>,
            }

            impl ExecutionParameters {
                /// The flags, with omitted values defaulting to `true`.
                #[must_use]
                pub fn flags(&self) -> NetworkResetFlags {
                    NetworkResetFlags {
                        clear_persisted: self.clear_persisted.unwrap_or(true),
                        trigger_detection: self.trigger_detection.unwrap_or(true),
                    }
                }
            }

            /// Request body for an execution. The body and `parameters` are optional.
            ///
            /// Unknown fields are rejected. The standard SOVD execution field
            /// `proximity_response` is accepted for compatibility but not used.
            #[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
            #[serde(deny_unknown_fields)]
            pub struct ExecutionRequest {
                /// The operation-specific parameters. If omitted, both flags default to `true`.
                #[serde(default)]
                pub parameters: ExecutionParameters,
                /// Seconds after which an execution that is still running is stopped
                /// (status `stopped`). If omitted, the execution has no timeout. At least 1;
                /// `0` is rejected.
                #[serde(default)]
                #[schemars(range(min = 1))]
                pub timeout: Option<u64>,
                /// Accepted for SOVD compatibility, not used.
                #[serde(default)]
                pub proximity_response: Option<String>,
            }

            impl ExecutionRequest {
                /// The requested timeout, `None` if no timeout is requested.
                #[must_use]
                pub fn timeout(&self) -> Option<std::time::Duration> {
                    self.timeout.map(std::time::Duration::from_secs)
                }
            }

            /// Operation-specific values reported for an execution.
            #[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
            pub struct ExecutionResponseParameters {
                /// `true` if the persisted ECU topology is cleared by this execution.
                pub clear_persisted: bool,
                /// `true` if this execution runs a new ECU detection.
                pub trigger_detection: bool,
                /// Failure description, present only when `status` is `failed`.
                #[serde(default, skip_serializing_if = "Option::is_none")]
                pub reason: Option<String>,
            }

            /// Response body returned by `GET /executions/{id}`.
            ///
            /// `T` is the type of the vendor specific error code in `error`.
            #[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
            #[schemars(rename = "NetworkResetExecutionResponse")]
            pub struct ExecutionResponse<T = String> {
                /// Current state of the execution: `running`, `completed`, `failed` (see
                /// `error` and `parameters.reason` for the cause) or `stopped` (stopped
                /// before it finished).
                pub status: ExecutionStatus,
                /// The capability that is active for the execution. Always `execute`.
                pub capability: ExecutionCapability,
                /// The parameters the execution was started with, and its failure reason if it failed.
                pub parameters: ExecutionResponseParameters,
                /// Structured description of the failure. Empty unless `status` is `failed`.
                #[serde(default, skip_serializing_if = "Vec::is_empty")]
                pub error: Vec<crate::error::DataError<T>>,
                /// JSON schema of the response, only present if requested with `include-schema=true`.
                #[schemars(skip)]
                #[serde(default, skip_serializing_if = "Option::is_none")]
                pub schema: Option<schemars::Schema>,
            }

            /// Capability active for network reset executions (ISO 17978-3 Table 189).
            ///
            /// Narrowed from the full capability set
            /// (`components::ecu::operations::executions::Capability`) on purpose: a
            /// network reset only supports `execute`, so the schema advertises only that
            /// value and deserializing a status rejects any other capability.
            #[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
            #[serde(rename_all = "lowercase")]
            pub enum ExecutionCapability {
                /// The operation is executed once and reports its progress through the execution status.
                Execute,
            }

            /// Operation description (`GET .../operations/networkreset`).
            #[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
            pub struct OperationResponse {
                /// The entry of the operation in the operations collection.
                pub item: crate::common::operations::OperationCollectionItem,
                /// JSON schema of the response, only present if requested with
                /// `include-schema=true`.
                #[schemars(skip)]
                #[serde(skip_serializing_if = "Option::is_none")]
                pub schema: Option<schemars::Schema>,
            }

            impl<T> From<NetworkResetExecution> for ExecutionResponse<T> {
                fn from(exec: NetworkResetExecution) -> Self {
                    let (status, reason) = match exec.status {
                        NetworkResetStatus::Running => (ExecutionStatus::Running, None),
                        NetworkResetStatus::Completed => (ExecutionStatus::Completed, None),
                        NetworkResetStatus::Stopped => (ExecutionStatus::Stopped, None),
                        NetworkResetStatus::Failed(reason) => {
                            (ExecutionStatus::Failed, Some(reason.to_string()))
                        }
                    };
                    Self {
                        status,
                        capability: ExecutionCapability::Execute,
                        error: reason
                            .as_ref()
                            .map(|reason| crate::error::DataError {
                                path: "/".to_owned(),
                                error: crate::error::ApiErrorResponse {
                                    message: reason.clone(),
                                    error_code: crate::error::ErrorCode::SovdServerFailure,
                                    vendor_code: None,
                                    parameters: None,
                                    error_source: None,
                                    schema: None,
                                },
                            })
                            .into_iter()
                            .collect(),
                        parameters: ExecutionResponseParameters {
                            clear_persisted: exec.flags.clear_persisted,
                            trigger_detection: exec.flags.trigger_detection,
                            reason,
                        },
                        schema: None,
                    }
                }
            }
        }

        pub mod runtimefilesupdate {
            pub use cda_interfaces::runtime_update_api::{
                ExecutionMode, ExecutionStatus, UpdateExecution,
            };

            // Moved to `common::operations`, re-exported for existing users.
            pub use crate::common::operations::{ExecutionCreatedResponse, ExecutionListResponse};

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

            impl From<UpdateExecution> for ExecutionResponse {
                fn from(exec: UpdateExecution) -> Self {
                    let (status, reason) = match exec.status {
                        ExecutionStatus::Running => (ExecutionStatusKind::Running, None),
                        ExecutionStatus::Completed => (ExecutionStatusKind::Completed, None),
                        ExecutionStatus::Failed(msg) => (ExecutionStatusKind::Failed, Some(msg)),
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
                use super::*;

                #[test]
                fn failed_execution_places_mode_and_reason_in_parameters() {
                    let response = ExecutionResponse::from(UpdateExecution {
                        id: "execution-id".to_string(),
                        mode: ExecutionMode::Apply,
                        status: ExecutionStatus::Failed("verification failed".to_string()),
                    });

                    assert_eq!(
                        serde_json::to_value(response).unwrap(),
                        serde_json::json!({
                            "status": "failed",
                            "parameters": {
                                "mode": "apply",
                                "reason": "verification failed"
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
                /// Time of the last reply of the ECU (RFC 3339, UTC).
                /// Absent if the ECU was never contacted.
                #[serde(skip_serializing_if = "Option::is_none", default)]
                pub last_seen: Option<String>,
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
