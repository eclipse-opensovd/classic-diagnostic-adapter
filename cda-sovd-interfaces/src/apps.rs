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
        use serde::{Deserialize, Serialize};

        /// Response body for bulk-data list endpoints `BulkDataDescriptor` follows Table 298 shape
        pub type BulkDataList = crate::Items<crate::sovd2uds::BulkDataDescriptor>;

        /// A single item in a bulk-data creation response (Table 303 shape).
        #[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
        pub struct BulkDataCreated {
            /// Bulk-data identifier created by the SOVD server to identify the bulk-data.
            pub id: String,
        }

        /// Response body for bulk-data creation (Table 303 shape).
        pub type BulkDataCreatedList = crate::Items<BulkDataCreated>;

        pub mod flash_files {
            pub mod get {
                pub type Response = crate::sovd2uds::FileList;
            }
        }

        pub mod runtimefiles {
            use serde::Deserialize;

            /// Execution mode for database update operations.
            #[derive(
                Debug, Clone, PartialEq, Eq, serde::Serialize, Deserialize, schemars::JsonSchema,
            )]
            #[serde(rename_all = "lowercase")]
            pub enum ExecutionMode {
                /// Apply staged files as the new current version.
                Apply,
                /// Revert to the backup from the previous apply.
                Rollback,
                /// Remove staged and backup files without applying.
                Cleanup,
            }

            /// Request body for an execution.
            #[derive(Debug, Deserialize, schemars::JsonSchema)]
            pub struct ExecutionRequest {
                /// The operation to perform on the staged runtime files.
                pub mode: ExecutionMode,
            }

            /// Query parameters for runtime file list endpoints.
            #[derive(Debug, Default, Deserialize, schemars::JsonSchema)]
            pub struct RuntimeFilesQuery {
                #[serde(rename = "include-schema", default)]
                pub include_schema: bool,
                #[serde(rename = "x-sovd2uds-include-hash")]
                pub include_hash: Option<crate::sovd2uds::HashAlgorithm>,
                #[serde(rename = "x-sovd2uds-include-file-size", default)]
                pub include_file_size: bool,
                #[serde(rename = "x-sovd2uds-include-revision", default)]
                pub include_revision: bool,
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
