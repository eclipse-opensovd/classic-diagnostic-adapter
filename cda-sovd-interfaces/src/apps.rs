/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

pub mod sovd2uds {
    pub mod bulk_data {
        pub use cda_interfaces::runtime_update_api::{
            BulkDataCreated, BulkDataCreatedList, BulkDataList,
        };

        pub mod flash_files {
            pub mod get {
                pub type Response = crate::sovd2uds::FileList;
            }
        }

        pub mod runtimefiles {
            pub use cda_interfaces::runtime_update_api::{
                ExecutionMode, ExecutionStatus, RuntimeFilesQuery, UpdateExecution,
            };

            /// Request body for an execution.
            #[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
            pub struct ExecutionRequest {
                /// The operation to perform on the staged runtime files.
                pub mode: ExecutionMode,
            }

            /// The discriminant of an execution's status without the inner payload.
            #[derive(Debug, serde::Serialize, schemars::JsonSchema)]
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

            /// Response body returned by `GET /executions/{id}`.
            #[derive(Debug, serde::Serialize, schemars::JsonSchema)]
            pub struct ExecutionResponse {
                /// Unique execution identifier.
                pub id: String,
                /// The operation that was requested.
                pub mode: ExecutionMode,
                /// Current lifecycle state of the execution.
                pub status: ExecutionStatusKind,
                /// Human-readable failure description, present only when `status` is `failed`.
                #[serde(skip_serializing_if = "Option::is_none")]
                pub reason: Option<String>,
            }

            impl From<UpdateExecution> for ExecutionResponse {
                fn from(exec: UpdateExecution) -> Self {
                    let (status, reason) = match exec.status {
                        ExecutionStatus::Running => (ExecutionStatusKind::Running, None),
                        ExecutionStatus::Completed => (ExecutionStatusKind::Completed, None),
                        ExecutionStatus::Failed(msg) => (ExecutionStatusKind::Failed, Some(msg)),
                    };
                    Self {
                        id: exec.id,
                        mode: exec.mode,
                        status,
                        reason,
                    }
                }
            }
        }
    }

    pub mod data {
        pub mod network_structure {
            use serde::Serialize;

            #[derive(Serialize)]
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

            #[derive(Serialize)]
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

            #[derive(Serialize)]
            #[serde(rename_all = "PascalCase")]
            #[derive(schemars::JsonSchema)]
            pub struct FunctionalGroup {
                pub qualifier: String,
                pub ecus: Vec<Ecu>,
            }

            #[derive(Serialize)]
            #[serde(rename_all = "PascalCase")]
            #[derive(schemars::JsonSchema)]
            pub struct NetworkStructure {
                pub functional_groups: Vec<FunctionalGroup>,
                pub gateways: Vec<Gateway>,
            }

            pub mod get {
                use serde::Serialize;

                #[derive(Serialize, schemars::JsonSchema)]
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
