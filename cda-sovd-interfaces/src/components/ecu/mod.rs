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

use hashbrown::HashMap;
use serde::{Deserialize, Serialize};

use crate::Items;

pub mod modes;
pub mod operations;

#[derive(Serialize, schemars::JsonSchema)]
pub struct Ecu {
    pub id: String,
    pub name: String,
    pub variant: String,
    pub locks: String,
    pub operations: String,
    pub data: String,
    pub configurations: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sdgs: Option<Vec<SdSdg>>,
    #[serde(rename = "x-single-ecu-jobs")]
    pub single_ecu_jobs: String,
    pub faults: String,
    #[schemars(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<schemars::Schema>,
}

pub type ComponentData = Items<ComponentDataInfo>;

#[derive(Deserialize, Serialize, Debug, schemars::JsonSchema)]
pub struct ComponentDataInfo {
    pub category: String,
    pub id: String,
    pub name: String,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
#[derive(schemars::JsonSchema)]
pub enum SdSdg {
    /// A single special data group
    Sd {
        #[serde(skip_serializing_if = "Option::is_none")]
        value: Option<String>,
        /// The semantic information (SI) aka the description of the SD
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(default)]
        si: Option<String>,
        /// The text information (TI) of the SD aka the value of the SD
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(default)]
        ti: Option<String>,
    },
    /// A collection of special data groups (SDGs)
    Sdg {
        /// The name of the SDG
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(default)]
        caption: Option<String>,
        /// The semantic information (SI) aka the description of the SD
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(default)]
        si: Option<String>,
        /// The list of SD or SDGs in the SDG
        #[serde(skip_serializing_if = "Vec::is_empty")]
        #[serde(default)]
        #[schemars(with = "Vec<serde_json::Map<String, serde_json::Value>>")]
        sdgs: Vec<SdSdg>,
    },
}

#[derive(Serialize, schemars::JsonSchema)]
pub struct ServicesSdgs {
    pub items: HashMap<String, ServiceSdgs>,
    #[schemars(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<schemars::Schema>,
}
#[derive(Serialize, schemars::JsonSchema)]
pub struct ServiceSdgs {
    pub sdgs: Vec<SdSdg>,
}

pub mod get {
    use super::*;
    pub type Response = Ecu;
}

pub mod configurations {
    use super::*;

    #[derive(Deserialize, Serialize, Debug, schemars::JsonSchema)]
    pub struct Components {
        pub items: Vec<ComponentItem>,
        #[schemars(skip)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub schema: Option<schemars::Schema>,
    }

    #[derive(Deserialize, Serialize, Debug, schemars::JsonSchema)]
    pub struct ComponentItem {
        pub id: String,
        pub name: String,
        pub configurations_type: String,

        #[serde(rename = "x-sovd2uds-ServiceAbstract")]
        pub service_abstract: Vec<String>,
    }

    pub type ConfigurationsQuery = crate::IncludeSchemaQuery;

    pub mod get {
        use super::*;
        pub type Response = Components;
    }
}

pub mod data {
    use hashbrown::HashMap;
    use serde::Deserialize;

    use super::*;
    use crate::Payload;

    #[derive(Deserialize, schemars::JsonSchema)]
    pub struct DataRequestPayload {
        data: HashMap<String, serde_json::Value>,
    }

    impl Payload for DataRequestPayload {
        fn get_data_map(&self) -> HashMap<String, serde_json::Value> {
            self.data.clone()
        }
    }

    pub mod service {
        pub mod put {
            pub type Query = crate::IncludeSchemaQuery;
        }
    }

    pub mod get {
        use super::*;
        pub type Response = ComponentData;
        pub type Query = crate::IncludeSchemaQuery;
    }
}

pub mod x {
    pub mod sovd2uds {
        pub mod bulk_data {
            pub mod embedded_files {
                pub mod get {
                    use crate::{Items, sovd2uds::File};

                    pub type Response = Items<File>;
                    pub type Query = crate::IncludeSchemaQuery;
                }
            }
        }
        pub mod download {
            pub mod flash_transfer {
                pub mod post {
                    use serde::{Deserialize, Serialize};
                    #[derive(Debug, Deserialize, schemars::JsonSchema)]
                    #[schemars(rename = "FlashTransferRequest")]
                    pub struct Request {
                        #[serde(rename = "blocksequencecounter")]
                        pub block_sequence_counter: u8,
                        pub blocksize: usize,
                        pub offset: u64,
                        pub length: u64,
                        pub id: String,
                    }

                    #[derive(Debug, Serialize, schemars::JsonSchema)]
                    #[schemars(rename = "FlashTransferResponse")]
                    pub struct Response {
                        pub id: String,
                        #[schemars(skip)]
                        #[serde(skip_serializing_if = "Option::is_none")]
                        pub schema: Option<schemars::Schema>,
                    }
                }
                pub mod get {
                    use serde::Serialize;

                    use crate::Items;

                    #[derive(Serialize, Clone, schemars::JsonSchema)]
                    #[serde(rename_all = "camelCase")]
                    pub struct DataTransferMetaData {
                        pub acknowledged_bytes: u64,
                        pub blocksize: usize,
                        pub next_block_sequence_counter: u8,
                        pub id: String,
                        pub file_id: String,
                        pub status: DataTransferStatus,
                        #[serde(skip_serializing_if = "Option::is_none")]
                        pub error: Option<Vec<DataTransferError>>,
                        #[schemars(skip)]
                        #[serde(skip_serializing_if = "Option::is_none")]
                        pub schema: Option<schemars::Schema>,
                    }

                    #[derive(Serialize, Clone, schemars::JsonSchema)]
                    pub struct DataTransferError {
                        pub text: String,
                    }

                    #[derive(Serialize, Debug, Clone, PartialEq)]
                    #[serde(rename_all = "lowercase")]
                    #[derive(schemars::JsonSchema)]
                    // allow unused because not all variants are used in the sovd
                    // context yet but are needed to match the CDA internal types
                    // and are useful for an sovd server as well
                    #[allow(dead_code)]
                    pub enum DataTransferStatus {
                        Running,
                        Aborted,
                        Finished,
                        Queued,
                    }

                    pub type Response = Items<DataTransferMetaData>;

                    pub mod id {
                        use super::*;
                        pub type Response = DataTransferMetaData;
                    }
                }
            }

            pub mod request_download {
                pub mod put {
                    use hashbrown::HashMap;
                    use serde::{Deserialize, Serialize};

                    use crate::error::DataError;

                    #[derive(Deserialize, schemars::JsonSchema)]
                    #[schemars(rename = "RequestDownloadRequest")]
                    pub struct Request {
                        #[serde(rename = "requestdownload")]
                        pub parameters: HashMap<String, serde_json::Value>,
                    }
                    #[derive(Serialize, schemars::JsonSchema)]
                    #[schemars(rename = "RequestDownloadResponse")]
                    pub struct Response<T> {
                        #[serde(rename = "requestdownload")]
                        pub parameters: serde_json::Map<String, serde_json::Value>,
                        #[serde(skip_serializing_if = "Vec::is_empty")]
                        pub errors: Vec<DataError<T>>,
                        #[schemars(skip)]
                        #[serde(skip_serializing_if = "Option::is_none")]
                        pub schema: Option<schemars::Schema>,
                    }
                }
            }
        }
    }

    pub mod single_ecu_job {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, schemars::JsonSchema)]
        pub struct LongName {
            #[serde(skip_serializing_if = "Option::is_none")]
            #[serde(default)]
            pub value: Option<String>,

            #[serde(skip_serializing_if = "Option::is_none")]
            #[serde(default)]
            pub ti: Option<String>,
        }

        #[derive(Serialize, Deserialize, schemars::JsonSchema)]
        pub struct Param {
            pub short_name: String,

            #[serde(skip_serializing_if = "Option::is_none")]
            #[serde(default)]
            pub physical_default_value: Option<String>,

            // todo dop is out of for POC
            // pub dop: u32,
            #[serde(skip_serializing_if = "Option::is_none")]
            #[serde(default)]
            pub semantic: Option<String>,

            #[serde(skip_serializing_if = "skip_long_name_if_none_or_empty")]
            #[serde(default)]
            pub long_name: Option<LongName>,
        }

        #[derive(Serialize, Deserialize, schemars::JsonSchema)]
        pub struct ProgCode {
            pub code_file: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            #[serde(default)]
            pub encryption: Option<String>,

            #[serde(skip_serializing_if = "Option::is_none")]
            #[serde(default)]
            pub syntax: Option<String>,

            pub revision: String,

            pub entrypoint: String,
        }

        #[derive(Serialize, Deserialize, schemars::JsonSchema)]
        pub struct Job {
            #[serde(rename = "x-input-params")]
            pub input_params: Vec<Param>,

            #[serde(rename = "x-output-params")]
            pub output_params: Vec<Param>,

            #[serde(rename = "x-neg-output-params")]
            pub neg_output_params: Vec<Param>,

            #[serde(rename = "x-prog-code")]
            pub prog_codes: Vec<ProgCode>,

            #[schemars(skip)]
            #[serde(skip_serializing_if = "Option::is_none")]
            pub schema: Option<schemars::Schema>,
        }

        // Clippy would prefer if we would pass Option<&LongName> instead.
        // But this is not compatible with the Serialization derive from serde.
        #[allow(clippy::ref_option)]
        fn skip_long_name_if_none_or_empty(long_name: &Option<LongName>) -> bool {
            long_name
                .as_ref()
                .and_then(|ln| ln.value.as_ref().or(ln.ti.as_ref()))
                .is_none()
        }
    }
}

pub mod faults {
    use super::*;

    /// Representation of a fault / DTC (Diagnostic Trouble Code)
    /// as described in the OpenSOVD specification.
    /// The following fields are omitted because the CDA does not provide
    /// this information:
    /// * Symptom
    /// * Translation IDs
    ///
    /// This is still compliant with the OpenSOVD specification, as these fields are optional.
    #[derive(Serialize, schemars::JsonSchema)]
    pub struct Fault {
        ///Fault code in the native representation of the entity.
        pub code: String,
        // Defines the scope.
        // The capability description defines which scopes are supported.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub scope: Option<String>,
        /// Display representation of the fault code.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub display_code: Option<String>,
        /// Name / description of the fault code.
        pub fault_name: String,
        /// Severity defines the impact of the fault on the system.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub severity: Option<u32>,
        /// Detailed status information as key value pairs.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub status: Option<FaultStatus>,
    }

    #[derive(Serialize, Debug, schemars::JsonSchema)]
    pub struct FaultStatus {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub test_failed: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub test_failed_this_operation_cycle: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub pending_dtc: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub confirmed_dtc: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub test_not_completed_since_last_clear: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub test_failed_since_last_clear: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub test_not_completed_this_operation_cycle: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub warning_indicator_requested: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub mask: Option<String>,
    }

    pub mod get {
        use super::*;

        #[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
        /// Query parameters for filtering DTC by the given fields.
        #[serde(rename_all = "camelCase")]
        pub struct FaultQuery {
            /// Filters the elements based on a status, if the value ia a full match.
            /// To allow multiple values the parameter is repeated. (0..*), they are 'OR' combined.
            /// Currently supported  (case-insensitive) keys are:
            /// * confirmedDtc
            /// * mask
            /// * pendingDtc
            /// * testFailed
            /// * testFailedSinceLastClear
            /// * testFailedThisOperationCycle
            /// * testNotCompletedSinceLastClear
            /// * testNotCompletedThisOperationCycle
            /// * warningIndicatorRequested
            ///
            /// Additional keys are not read from the database at this time.
            /// The value can be allowed values for these keys are 0|1 or true|false.
            ///
            /// Example:
            ///
            /// `?status[confirmedDtc]=true&status[warningIndicatorRequested]=1`
            pub status: Option<HashMap<String, serde_json::Value>>,
            /// Filters the elements based on their severity
            pub severity: Option<u32>,
            /// The scope to retrieve faults for. If not provided, all scopes are considered.
            pub scope: Option<String>,
            #[serde(rename = "include-schema", default)]
            pub include_schema: bool,
        }

        #[derive(Serialize, schemars::JsonSchema)]
        pub struct Response {
            pub items: Vec<Fault>,
            #[schemars(skip)]
            #[serde(skip_serializing_if = "Option::is_none")]
            pub schema: Option<schemars::Schema>,
        }
    }

    pub mod id {
        use super::*;
        pub mod get {
            use super::*;
            use crate::{default_true, error::DataError};

            #[derive(Serialize, Deserialize, schemars::JsonSchema)]
            #[serde(rename_all = "kebab-case")]
            pub struct DtcIdQuery {
                /// If true, extended dtc data from 0x19 06 is included in the response
                #[serde(default = "default_true")]
                pub include_extended_data: bool,
                /// If true, snapshot data from 0x19 04 is included in the response
                #[serde(default = "default_true")]
                pub include_snapshot_data: bool,
                pub include_schema: bool,
            }

            #[derive(Serialize, schemars::JsonSchema)]
            pub struct Snapshot {
                #[serde(rename = "DTCSnapshotRecordNumberOfIdentifiers")]
                pub number_of_identifiers: u64,
                #[serde(rename = "DTCSnapshotRecord")]
                pub record: Vec<serde_json::Value>,
            }

            #[derive(Serialize, schemars::JsonSchema)]
            pub struct ExtendedSnapshots<T> {
                #[serde(skip_serializing_if = "Option::is_none")]
                pub data: Option<HashMap<String, Snapshot>>,
                #[serde(skip_serializing_if = "Option::is_none")]
                pub errors: Option<Vec<DataError<T>>>,
            }

            #[derive(Serialize, schemars::JsonSchema)]
            pub struct ExtendedDataRecords<T> {
                #[serde(skip_serializing_if = "Option::is_none")]
                pub data: Option<HashMap<String, serde_json::Value>>,
                #[serde(skip_serializing_if = "Option::is_none")]
                pub errors: Option<Vec<DataError<T>>>,
            }

            #[derive(Serialize, schemars::JsonSchema)]
            pub struct EnvironmentData<T> {
                #[serde(skip_serializing_if = "Option::is_none")]
                pub extended_data_records: Option<ExtendedDataRecords<T>>,

                #[serde(skip_serializing_if = "Option::is_none")]
                pub snapshots: Option<ExtendedSnapshots<T>>,
            }

            #[derive(Serialize, schemars::JsonSchema)]
            pub struct ExtendedFault<T> {
                pub item: Fault,
                #[serde(skip_serializing_if = "Option::is_none")]
                pub environment_data: Option<EnvironmentData<T>>,
                #[serde(skip_serializing_if = "Option::is_none")]
                pub schema: Option<schemars::Schema>,
            }
        }
    }
}
