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
#[cfg(feature = "swagger-ui")]
use utoipa::ToSchema;

pub mod comparams {
    use serde::Deserializer;

    use super::*;

    #[derive(Deserialize, Serialize, Clone, Debug)]
    #[cfg_attr(feature = "swagger-ui", derive(ToSchema))]
    pub struct Unit {
        pub factor_to_si_unit: Option<f64>,
        pub offset_to_si_unit: Option<f64>,
    }

    #[derive(Serialize, Clone)]
    #[cfg_attr(feature = "swagger-ui", derive(ToSchema))]
    pub struct ComParamSimpleValue {
        pub value: String,
        pub unit: Option<Unit>,
    }

    /// Custom deserialization for `ComParamSimpleValue` to handle both string and struct formats.
    /// The string format is a simple value, leaving unit None,
    /// while the struct format includes a value and an optional unit.
    /// Mostly necessary to handle incoming data from the webserver, as setting the unit
    /// there is superfluous. Also to retain compatibility with existing clients that
    /// might send just a string value.
    impl<'de> Deserialize<'de> for ComParamSimpleValue {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            #[derive(Deserialize)]
            #[serde(untagged)]
            enum ComParamSimpleValueHelper {
                String(String),
                Struct { value: String, unit: Option<Unit> },
            }

            let helper = ComParamSimpleValueHelper::deserialize(deserializer)?;

            match helper {
                ComParamSimpleValueHelper::String(value) => {
                    Ok(ComParamSimpleValue { value, unit: None })
                }
                ComParamSimpleValueHelper::Struct { value, unit } => {
                    Ok(ComParamSimpleValue { value, unit })
                }
            }
        }
    }

    #[derive(Deserialize, Serialize, Clone)]
    #[serde(untagged)]
    #[cfg_attr(feature = "swagger-ui", derive(ToSchema))]
    pub enum ComParamValue {
        Simple(ComParamSimpleValue),
        // defining the value type as Vec<Object>
        // so the swagger-ui is showing the field as {}
        #[cfg_attr(feature = "swagger-ui", schema(value_type = Vec<Object>, no_recursion))]
        Complex(HashMap<String, ComParamValue>),
    }

    pub type ComplexComParamValue = HashMap<String, ComParamValue>;

    // cannot use type alias because this breaks utoipa generation
    // pub type ComParamMap = HashMap<String, ComParamValue>;

    #[derive(Clone)]
    pub struct Execution {
        pub capability: executions::Capability,
        pub status: executions::Status,
        pub comparam_override: HashMap<String, ComParamValue>,
    }

    pub mod executions {
        use super::*;

        #[derive(Deserialize, Serialize, Clone)]
        #[serde(rename_all = "lowercase")]
        #[cfg_attr(feature = "swagger-ui", derive(ToSchema))]
        pub enum Status {
            Running,
            Completed,
            Failed,
        }

        #[derive(Deserialize, Serialize, Clone)]
        #[serde(rename_all = "lowercase")]
        #[cfg_attr(feature = "swagger-ui", derive(ToSchema))]
        pub enum Capability {
            Execute,
            Stop,
            Freeze,
            Reset,
            Status,
        }

        #[derive(Serialize)]
        #[cfg_attr(feature = "swagger-ui", derive(ToSchema))]
        pub struct Item {
            pub id: String,
        }

        pub mod update {
            use super::*;
            // todo: which ones are optional or not
            #[derive(Deserialize)]
            #[allow(dead_code)]
            #[cfg_attr(feature = "swagger-ui", derive(ToSchema))]
            pub struct Request {
                pub capability: Option<Capability>,
                pub timeout: Option<u32>,
                pub parameters: Option<HashMap<String, ComParamValue>>,
                pub proximity_response: Option<String>,
            }

            #[derive(Serialize)]
            #[cfg_attr(feature = "swagger-ui", derive(ToSchema))]
            pub struct Response {
                pub id: String,
                pub status: Status,
            }
        }

        pub mod get {
            use super::*;
            use crate::Items;

            pub type Response = Items<Item>;
        }

        pub mod id {
            use super::*;
            pub mod get {
                use super::*;
                #[derive(Serialize)]
                #[cfg_attr(feature = "swagger-ui", derive(ToSchema))]
                pub struct Response {
                    pub capability: Capability,
                    // todo: probably out of scope for now:
                    // use trait items here to allow for other execution types than comparam
                    pub parameters: HashMap<String, ComParamValue>,
                    pub status: Status,
                }
            }
        }
    }
}

pub mod service {
    use super::*;
    pub mod executions {
        use super::*;
        use crate::Payload;

        #[derive(Serialize)]
        pub struct Response {
            pub parameters: serde_json::Value,
        }

        #[derive(Deserialize, Serialize, Debug)]
        #[cfg_attr(feature = "swagger-ui", derive(ToSchema))]
        pub struct Request {
            #[serde(skip_serializing_if = "Option::is_none")]
            pub timeout: Option<u32>,
            pub parameters: Option<HashMap<String, serde_json::Value>>,
        }

        impl Payload for Request {
            fn get_data_map(&self) -> HashMap<String, serde_json::Value> {
                self.parameters
                    .as_ref()
                    .map_or(HashMap::new(), std::clone::Clone::clone)
            }
        }
    }
}
