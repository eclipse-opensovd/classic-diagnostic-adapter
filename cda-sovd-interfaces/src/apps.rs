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

pub mod sovd2uds {
    pub mod bulk_data {
        pub mod flash_files {
            pub mod get {
                pub type Response = crate::sovd2uds::FileList;
            }
        }
    }

    pub mod data {
        pub mod network_structure {
            use serde::Serialize;

            #[derive(Serialize)]
            #[serde(rename_all = "PascalCase")]
            #[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
            pub struct Ecu {
                pub qualifier: String, // name
                pub variant: String,   // variant
                #[serde(rename = "EcuState")]
                pub state: String, // Online, Offline, NotTested ...
                pub logical_address: String,
                pub logical_link: String, // ${qualifier}_on_${protocol}
            }

            #[derive(Serialize)]
            #[serde(rename_all = "PascalCase")]
            #[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
            pub struct Gateway {
                pub name: String,
                pub network_address: String,
                pub logical_address: String,
                pub ecus: Vec<Ecu>,
            }

            #[derive(Serialize)]
            #[serde(rename_all = "PascalCase")]
            #[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
            pub struct FunctionalGroup {
                pub qualifier: String,
                pub ecus: Vec<Ecu>,
            }

            #[derive(Serialize)]
            #[serde(rename_all = "PascalCase")]
            #[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
            pub struct NetworkStructure {
                pub functional_groups: Vec<FunctionalGroup>,
                pub gateways: Vec<Gateway>,
            }

            pub mod get {
                use serde::Serialize;

                #[derive(Serialize)]
                #[cfg_attr(feature = "openapi", derive(schemars::JsonSchema))]
                #[cfg_attr(feature = "openapi", schemars(rename = "NetworkStructureResponse"))]
                pub struct Response {
                    pub id: String,
                    pub data: Vec<crate::apps::sovd2uds::data::network_structure::NetworkStructure>,
                }
            }
        }
    }
}
