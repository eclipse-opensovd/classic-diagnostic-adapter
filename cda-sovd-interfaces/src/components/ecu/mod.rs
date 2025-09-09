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

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
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
}

pub type ComponentData = Items<ComponentDataInfo>;

#[derive(Deserialize, Serialize, Debug)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
pub struct ComponentDataInfo {
    pub category: String,
    pub id: String,
    pub name: String,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
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
        #[cfg_attr(
            feature = "openapi",
            schemars(with = "Vec<serde_json::Map<String, serde_json::Value>>")
        )]
        sdgs: Vec<SdSdg>,
    },
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
pub struct ServicesSdgs {
    pub items: HashMap<String, ServiceSdgs>,
}
#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
pub struct ServiceSdgs {
    pub sdgs: Vec<SdSdg>,
}

pub mod get {
    use super::*;
    pub type Response = Ecu;
}

pub mod configurations {
    use super::*;

    #[derive(Deserialize, Serialize, Debug)]
    #[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
    pub struct Components {
        pub items: Vec<ComponentItem>,
    }

    #[derive(Deserialize, Serialize, Debug)]
    #[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
    pub struct ComponentItem {
        pub id: String,
        pub name: String,
        pub configurations_type: String,

        #[serde(rename = "x-sovd2uds-ServiceAbstract")]
        pub service_abstract: Vec<String>,
    }

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

    #[derive(Deserialize)]
    #[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
    pub struct DataRequestPayload {
        data: HashMap<String, serde_json::Value>,
    }

    impl Payload for DataRequestPayload {
        fn get_data_map(&self) -> HashMap<String, serde_json::Value> {
            self.data.clone()
        }
    }

    pub mod service {
        use super::*;
        pub mod get {
            use super::*;
            #[derive(Deserialize)]
            #[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
            pub struct DiagServiceQuery {
                #[serde(rename = "x-include-sdgs")]
                pub include_sdgs: Option<bool>,
                #[serde(rename = "include-schema")]
                pub include_schema: Option<bool>,
            }
        }
    }

    pub mod get {
        use super::*;
        pub type Response = ComponentData;
    }
}

pub mod x {
    pub mod sovd2uds {
        pub mod bulk_data {
            pub mod embedded_files {
                pub mod get {
                    use crate::{Items, sovd2uds::File};

                    pub type Response = Items<File>;
                }
            }
        }
        pub mod download {
            pub mod flash_transfer {
                pub mod post {
                    use serde::{Deserialize, Serialize};
                    #[derive(Debug, Deserialize)]
                    #[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
                    #[cfg_attr(feature = "openapi", schemars(rename = "FlashTransferRequest"))]
                    pub struct Request {
                        #[serde(rename = "blocksequencecounter")]
                        pub block_sequence_counter: u8,
                        pub blocksize: usize,
                        pub offset: u64,
                        pub length: u64,
                        pub id: String,
                    }

                    #[derive(Debug, Serialize)]
                    #[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
                    #[cfg_attr(feature = "openapi", schemars(rename = "FlashTransferResponse"))]
                    pub struct Response {
                        pub id: String,
                    }
                }
                pub mod get {
                    use serde::Serialize;

                    #[derive(Serialize, Clone)]
                    #[serde(rename_all = "PascalCase")]
                    #[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
                    pub struct DataTransferMetaData {
                        pub acknowledged_bytes: u64,
                        pub blocksize: usize,
                        pub next_block_sequence_counter: u8,
                        pub id: String,
                        pub file_id: String,
                        pub status: DataTransferStatus,
                        #[serde(skip_serializing_if = "Option::is_none")]
                        pub error: Option<Vec<DataTransferError>>,
                    }

                    #[derive(Serialize, Clone)]
                    #[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
                    pub struct DataTransferError {
                        pub text: String,
                    }

                    #[derive(Serialize, Debug, Clone, PartialEq)]
                    #[serde(rename_all = "lowercase")]
                    #[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
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

                    pub type Response = Vec<DataTransferMetaData>;

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

                    #[derive(Deserialize)]
                    #[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
                    #[cfg_attr(feature = "openapi", schemars(rename = "RequestDownloadRequest"))]
                    pub struct Request {
                        #[serde(rename = "requestdownload")]
                        pub parameters: HashMap<String, serde_json::Value>,
                    }
                    #[derive(Serialize)]
                    #[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
                    #[cfg_attr(feature = "openapi", schemars(rename = "RequestDownloadResponse"))]
                    pub struct Response<T> {
                        #[serde(rename = "requestdownload")]
                        pub parameters: serde_json::Map<String, serde_json::Value>,
                        #[serde(skip_serializing_if = "Vec::is_empty")]
                        pub errors: Vec<DataError<T>>,
                    }
                }
            }
        }
    }

    pub mod single_ecu_job {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize)]
        #[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
        pub struct LongName {
            #[serde(skip_serializing_if = "Option::is_none")]
            #[serde(default)]
            pub value: Option<String>,

            #[serde(skip_serializing_if = "Option::is_none")]
            #[serde(default)]
            pub ti: Option<String>,
        }

        #[derive(Serialize, Deserialize)]
        #[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
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

        #[derive(Serialize, Deserialize)]
        #[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
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

        #[derive(Serialize, Deserialize)]
        #[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
        pub struct Job {
            #[serde(rename = "x-input-params")]
            pub input_params: Vec<Param>,

            #[serde(rename = "x-output-params")]
            pub output_params: Vec<Param>,

            #[serde(rename = "x-neg-output-params")]
            pub neg_output_params: Vec<Param>,

            #[serde(rename = "x-prog-code")]
            pub prog_codes: Vec<ProgCode>,
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
