/*
 * SPDX-FileCopyrightText: 2026 Copyright (c) Contributors to the Eclipse Foundation
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

use cda_interfaces::HashMap;
use serde::{Deserialize, Serialize};

use crate::Items;

pub mod modes;
pub mod operations;

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema, PartialEq)]
pub enum State {
    Online,
    Offline,
    NotTested,
    Duplicate,
    Disconnected,
    NoVariantDetected,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Variant {
    pub name: String,
    pub is_base_variant: bool,
    pub state: State,
    pub logical_address: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Ecu {
    pub id: String,
    pub name: String,
    pub variant: Variant,
    pub locks: String,
    pub operations: String,
    pub data: String,
    pub configurations: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sdgs: Option<Vec<SdSdg>>,
    #[serde(rename = "x-single-ecu-jobs")]
    pub single_ecu_jobs: String,
    pub faults: String,
    pub modes: String,
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

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Serialize, Deserialize, schemars::JsonSchema)]
pub struct ServicesSdgs {
    pub items: HashMap<String, ServiceSdgs>,
    #[schemars(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<schemars::Schema>,
}
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
pub struct ServiceSdgs {
    pub sdgs: Vec<SdSdg>,
}

pub mod get {
    use super::Ecu;
    pub type Response = Ecu;
}

pub mod configurations {
    use super::{Deserialize, Serialize};

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

    /// Response returned when querying a service configuration.
    #[derive(Deserialize, Serialize, Debug, schemars::JsonSchema)]
    pub struct ServiceResponse {
        /// Identifier of the service.
        pub id: String,
        /// Configuration data for the service.
        pub data: serde_json::Value,
    }

    pub mod get {
        use super::Components;
        pub type Response = Components;
    }

    /// Module for the `GET /configurations/{service}` endpoint.
    pub mod get_service {
        use super::ServiceResponse;
        /// Response type returned by this endpoint.
        pub type Response = ServiceResponse;
    }
}

pub mod data {
    use cda_interfaces::HashMap;
    use serde::Deserialize;

    use super::ComponentData;
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
        use super::ComponentData;

        pub type Response = ComponentData;

        /// Query parameters for `GET /data`.
        #[derive(serde::Deserialize, schemars::JsonSchema)]
        pub struct Query {
            #[serde(rename = "include-schema", default)]
            pub include_schema: bool,
            /// Optional list of categories. When present, only data resources whose
            /// `category` is one of the given values are returned.
            ///
            /// Per ISO 17978-3 (§6.2.7, §7.9.3) this is an array query parameter serialized
            /// in `OpenAPI` `form` style with `explode=true`, i.e. multiple categories are
            /// passed by repeating the parameter:
            /// `?categories=identData&categories=currentData`.
            ///
            /// Matching is case-insensitive: incoming request URIs (including the query
            /// string) are lowercased by CDA's request normalization middleware before
            /// reaching this handler, so category names must be compared case-insensitively
            /// against the (potentially mixed-case) `category` values produced by
            /// `category_mapping`/`default_category`.
            #[serde(default)]
            pub categories: Option<Vec<String>>,
        }

        #[cfg(test)]
        mod tests {
            use super::Query;

            #[test]
            fn deserializes_single_category() {
                let q: Query = serde_qs::from_str("categories=identData").unwrap();
                assert_eq!(q.categories, Some(vec!["identData".to_owned()]));
            }

            #[test]
            fn deserializes_repeated_categories() {
                let q: Query =
                    serde_qs::from_str("categories=identData&categories=currentData").unwrap();
                assert_eq!(
                    q.categories,
                    Some(vec!["identData".to_owned(), "currentData".to_owned()])
                );
            }

            #[test]
            fn deserializes_without_categories() {
                let q: Query = serde_qs::from_str("include-schema=true").unwrap();
                assert!(q.include_schema);
                assert_eq!(q.categories, None);
            }
        }
    }
}

pub mod data_categories {
    /// A single entry of the `/data-categories` response.
    /// Spec ISO 17978-3 Section 7.9.2.1 (`DataCategoryInformation`).
    #[derive(serde::Deserialize, serde::Serialize, Debug, schemars::JsonSchema)]
    pub struct DataCategoryInformation {
        /// The category name, e.g. `identData`, `currentData`, `storedData`, `sysInfo`, or a
        /// custom `x-<ext>-...` category.
        pub item: String,
        /// Optional identifier for translating the category name. CDA does not currently
        /// support translation, so this is always omitted.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub category_translation_id: Option<String>,
    }

    pub mod get {
        use super::DataCategoryInformation;

        pub type Response = crate::Items<DataCategoryInformation>;
        pub type Query = crate::IncludeSchemaQuery;
    }
}

pub mod x {
    pub mod sovd2uds {
        pub mod bulk_data {
            pub mod embedded_files {
                pub mod get {
                    use crate::{Items, sovd2uds::BulkDataDescriptor};

                    pub type Response = Items<BulkDataDescriptor>;
                    pub type Query = crate::IncludeSchemaQuery;
                }
            }
        }
        pub mod download {
            use serde::{Deserialize, Deserializer};
            use serde_json::{Map, Value};

            /// Reads a JSON object and converts all its top-level keys to lowercase.
            /// Keys that only differ in case are rejected as duplicates.
            pub(crate) fn lowercase_keys<'de, D>(deserializer: D) -> Result<Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                let fields = Map::<String, Value>::deserialize(deserializer)?;
                let mut normalized = Map::with_capacity(fields.len());
                for (key, value) in fields {
                    let lowercase = key.to_ascii_lowercase();
                    if normalized.contains_key(&lowercase) {
                        return Err(serde::de::Error::custom(format!(
                            "Duplicate field `{key}` (fields are matched case-insensitively)"
                        )));
                    }
                    normalized.insert(lowercase, value);
                }
                Ok(Value::Object(normalized))
            }

            /// Implements `Deserialize` for a request type whose top-level field names are
            /// matched case-insensitively.
            ///
            /// The type must derive `Deserialize` with `#[serde(remote = "Self")]` and use
            /// lowercase serde field names. The generated impl lowercases the keys of the
            /// input object and then runs the derived deserializer on it.
            ///
            /// Because serde only sees lowercase keys, the public (documented) field names
            /// are set separately via `#[schemars(rename = "...")]` in camelCase. Both differ
            /// only in casing, so any casing of the documented name is accepted.
            macro_rules! case_insensitive_deserialize {
                ($ty:ty) => {
                    impl<'de> serde::Deserialize<'de> for $ty {
                        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                        where
                            D: serde::Deserializer<'de>,
                        {
                            let value =
                                $crate::components::ecu::x::sovd2uds::download::lowercase_keys(
                                    deserializer,
                                )?;
                            // Track the path so errors name the offending field.
                            let mut track = serde_path_to_error::Track::new();
                            <$ty>::deserialize(serde_path_to_error::Deserializer::new(
                                value, &mut track,
                            ))
                            .map_err(|e| {
                                let path = track.path().to_string();
                                if path == "." {
                                    serde::de::Error::custom(e)
                                } else {
                                    serde::de::Error::custom(format!("Invalid field `{path}`: {e}"))
                                }
                            })
                        }
                    }
                };
            }

            pub mod transfer_exit {
                pub mod put {
                    use serde::Deserialize;

                    /// Optional request body of the `RequestTransferExit` service. Field names
                    /// are matched case-insensitively.
                    #[derive(Debug, Default, Deserialize, schemars::JsonSchema)]
                    #[serde(remote = "Self")]
                    #[schemars(rename = "TransferExitRequest")]
                    pub struct Request {
                        /// Functional class used to resolve the `RequestTransferExit` service.
                        /// Falls back to the configured default when absent.
                        #[serde(rename = "flashclass")]
                        #[schemars(rename = "flashClass")]
                        pub flash_class: Option<String>,
                    }

                    case_insensitive_deserialize!(Request);
                }
            }

            pub mod flash_transfer {
                pub mod post {
                    use serde::{Deserialize, Serialize};

                    /// Request body of the flash transfer. Field names are matched
                    /// case-insensitively.
                    #[derive(Debug, Deserialize, schemars::JsonSchema)]
                    #[serde(remote = "Self")]
                    #[schemars(rename = "FlashTransferRequest")]
                    pub struct Request {
                        #[serde(rename = "blocksequencecounter")]
                        #[schemars(rename = "blockSequenceCounter")]
                        pub block_sequence_counter: u8,
                        #[schemars(rename = "blockSize")]
                        pub blocksize: usize,
                        pub offset: u64,
                        pub length: u64,
                        pub id: String,
                        /// Functional class used to resolve the `TransferData` service.
                        /// Falls back to the configured default when absent.
                        #[serde(rename = "flashclass")]
                        #[schemars(rename = "flashClass")]
                        pub flash_class: Option<String>,
                    }

                    case_insensitive_deserialize!(Request);

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
                    #[allow(
                        dead_code,
                        reason = "Not all variants are used yet. Kept to match CDA internal types \
                                  and future SOVD server use"
                    )]
                    pub enum DataTransferStatus {
                        Running,
                        Aborted,
                        Finished,
                        Queued,
                    }

                    pub type Response = Items<DataTransferMetaData>;

                    pub mod id {
                        use super::DataTransferMetaData;
                        pub type Response = DataTransferMetaData;
                    }
                }
            }

            pub mod request_download {
                pub mod put {
                    use cda_interfaces::HashMap;
                    use serde::{Deserialize, Serialize};

                    use crate::error::DataError;

                    /// Request body of the `RequestDownload` service. Top-level field names are
                    /// matched case-insensitively, the parameter names are passed on unchanged.
                    #[derive(Deserialize, schemars::JsonSchema)]
                    #[serde(remote = "Self")]
                    #[schemars(rename = "RequestDownloadRequest")]
                    pub struct Request {
                        #[serde(rename = "requestdownload")]
                        #[schemars(rename = "requestDownload")]
                        pub parameters: HashMap<String, serde_json::Value>,
                        /// Functional class used to resolve the `RequestDownload` service.
                        /// Falls back to the configured default when absent.
                        #[serde(rename = "flashclass")]
                        #[schemars(rename = "flashClass")]
                        pub flash_class: Option<String>,
                    }

                    case_insensitive_deserialize!(Request);
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

        #[allow(
            clippy::ref_option,
            reason = "Option<&LongName> not compatible with serde Serialize derive"
        )]
        fn skip_long_name_if_none_or_empty(long_name: &Option<LongName>) -> bool {
            long_name
                .as_ref()
                .and_then(|ln| ln.value.as_ref().or(ln.ti.as_ref()))
                .is_none()
        }
    }
}

pub mod faults {
    use super::{Deserialize, HashMap, Serialize};

    /// Representation of a fault / DTC (Diagnostic Trouble Code)
    /// as described in the `OpenSOVD` specification.
    /// The following fields are omitted because the CDA does not provide
    /// this information:
    /// * Symptom
    /// * Translation IDs
    ///
    /// This is still compliant with the `OpenSOVD` specification, as these fields are optional.
    #[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
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

    #[derive(Serialize, Deserialize, Debug, schemars::JsonSchema)]
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
        use super::{Deserialize, Fault, HashMap, Serialize};

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
            /// Value for the memory selection in user defined memory.
            /// Only used for user defined memory, defaults to 0
            #[serde(default)]
            pub memory_selection: Option<u8>,
        }

        #[derive(Serialize, Deserialize, schemars::JsonSchema)]
        pub struct Response {
            pub items: Vec<Fault>,
            #[schemars(skip)]
            #[serde(skip_serializing_if = "Option::is_none")]
            pub schema: Option<schemars::Schema>,
        }
    }

    pub mod delete {
        use serde::{Deserialize, Serialize};

        #[derive(Deserialize, Serialize, schemars::JsonSchema)]
        pub struct FaultQuery {
            /// Defines the scope for which fault entries are deleted
            /// must be a valid scope for the given component
            pub scope: Option<String>,
        }
    }

    pub mod id {
        use super::{Deserialize, Fault, HashMap, Serialize};
        pub mod get {
            use super::{Deserialize, Fault, HashMap, Serialize};
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
                #[serde(default)]
                pub include_schema: bool,
                /// Value for the memory selection in user defined memory.
                /// Only used for user defined memory, defaults to 0
                #[serde(default)]
                pub memory_selection: Option<u8>,
            }

            #[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
            pub struct Snapshot {
                #[serde(rename = "DTCSnapshotRecordNumberOfIdentifiers")]
                pub number_of_identifiers: u64,
                #[serde(rename = "DTCSnapshotRecord")]
                pub record: Vec<serde_json::Value>,
            }

            #[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
            pub struct ExtendedSnapshots {
                #[serde(skip_serializing_if = "Option::is_none")]
                pub data: Option<HashMap<String, Snapshot>>,
            }

            #[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
            pub struct ExtendedDataRecords {
                #[serde(skip_serializing_if = "Option::is_none")]
                pub data: Option<HashMap<String, serde_json::Value>>,
            }

            #[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
            pub struct EnvironmentData {
                #[serde(skip_serializing_if = "Option::is_none")]
                pub extended_data_records: Option<ExtendedDataRecords>,

                #[serde(skip_serializing_if = "Option::is_none")]
                pub snapshots: Option<ExtendedSnapshots>,
            }

            /// Spec Table 65: errors of the whole response are reported in the
            /// top-level `errors` list, each pointing at the failing element via a
            /// JSON pointer (Table 17).
            #[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
            pub struct ExtendedFault<T> {
                pub item: Fault,
                #[serde(skip_serializing_if = "Option::is_none")]
                pub environment_data: Option<EnvironmentData>,
                #[serde(
                    default = "Vec::<DataError<T>>::new",
                    skip_serializing_if = "Vec::is_empty"
                )]
                pub errors: Vec<DataError<T>>,
                #[serde(skip_serializing_if = "Option::is_none")]
                pub schema: Option<schemars::Schema>,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_deserialize_dtc_id_query() {
        let query_str = "include-extended-data=false&include-snapshot-data=true";
        let query: super::faults::id::get::DtcIdQuery = serde_qs::from_str(query_str).unwrap();

        assert!(!query.include_extended_data);
        assert!(query.include_snapshot_data);
        assert!(!query.include_schema);

        let query_str_with_schema =
            "include-extended-data=true&include-snapshot-data=false&include-schema=true";
        let query_with_schema: super::faults::id::get::DtcIdQuery =
            serde_qs::from_str(query_str_with_schema).unwrap();
        assert!(query_with_schema.include_extended_data);
        assert!(!query_with_schema.include_snapshot_data);
        assert!(query_with_schema.include_schema);
    }

    mod flash_requests {
        use crate::components::ecu::x::sovd2uds::download::{
            flash_transfer, request_download, transfer_exit,
        };

        #[test]
        fn flash_transfer_fields_are_case_insensitive() {
            let request: flash_transfer::post::Request = serde_json::from_str(
                r#"{"BlockSequenceCounter":1,"BLOCKSIZE":128,"Offset":0,"length":256,
                    "ID":"file","FLASHCLASS":"flash_download_upload_bootloader"}"#,
            )
            .expect("Request should deserialize");
            assert_eq!(request.block_sequence_counter, 1);
            assert_eq!(request.blocksize, 128);
            assert_eq!(request.length, 256);
            assert_eq!(request.id, "file");
            assert_eq!(
                request.flash_class.as_deref(),
                Some("flash_download_upload_bootloader")
            );
        }

        #[test]
        fn flash_transfer_without_flash_class() {
            let request: flash_transfer::post::Request = serde_json::from_str(
                r#"{"blocksequencecounter":1,"blocksize":128,"offset":0,"length":256,"id":"f"}"#,
            )
            .expect("Request should deserialize");
            assert!(request.flash_class.is_none());
        }

        #[test]
        fn flash_transfer_missing_field_is_rejected() {
            let result: Result<flash_transfer::post::Request, _> =
                serde_json::from_str(r#"{"blocksize":128,"offset":0,"length":256,"id":"f"}"#);
            assert!(result.is_err());
        }

        #[test]
        fn duplicate_fields_differing_in_case_are_rejected() {
            let result: Result<transfer_exit::put::Request, _> =
                serde_json::from_str(r#"{"flashClass":"a","FlashClass":"b"}"#);
            let error = result.expect_err("Duplicate fields should be rejected");
            assert!(
                error.to_string().contains("case-insensitively"),
                "unexpected error: {error}"
            );
        }

        #[test]
        fn invalid_field_type_error_names_the_field() {
            let result: Result<flash_transfer::post::Request, _> = serde_json::from_str(
                r#"{"blocksequencecounter":1,"BlockSize":"x","offset":0,"length":256,"id":"f"}"#,
            );
            let error = result.expect_err("Invalid field type should be rejected");
            assert!(
                error.to_string().contains("Invalid field `blocksize`"),
                "unexpected error: {error}"
            );
        }

        #[test]
        fn missing_field_error_is_not_prefixed() {
            let result: Result<flash_transfer::post::Request, _> =
                serde_json::from_str(r#"{"blocksize":128,"offset":0,"length":256,"id":"f"}"#);
            let error = result.expect_err("Missing field should be rejected");
            let message = error.to_string();
            assert!(
                message.contains("missing field") && !message.contains("Invalid field"),
                "unexpected error: {message}"
            );
        }

        #[test]
        fn request_download_keeps_parameter_names() {
            let request: request_download::put::Request =
                serde_json::from_str(r#"{"RequestDownload":{"MemoryAddress":1},"flashclass":"X"}"#)
                    .expect("Request should deserialize");
            assert!(request.parameters.contains_key("MemoryAddress"));
            assert_eq!(request.flash_class.as_deref(), Some("X"));
        }

        #[test]
        fn transfer_exit_accepts_empty_object() {
            let request: transfer_exit::put::Request =
                serde_json::from_str("{}").expect("Request should deserialize");
            assert!(request.flash_class.is_none());
        }
    }
}
