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

        pub mod runtimefilesupdate {
            pub use cda_interfaces::runtime_update_api::{
                ExecutionMode, ExecutionStatus, UpdateExecution,
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
