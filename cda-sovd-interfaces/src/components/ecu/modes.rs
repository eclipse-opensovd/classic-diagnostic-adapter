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

pub type Query = crate::IncludeSchemaQuery;

pub mod get {
    pub type Response = crate::common::modes::get::Response;
    pub type ResponseItem = crate::common::modes::get::ModeCollectionItem;
}

/// Module for access to ECUs, encapsulates session and security modes
pub mod security_and_session {
    pub mod get {

        // sovd-interfaces does not define a datatype for security and session, therefore
        // their value is represented as a String
        pub type Response = crate::common::modes::get::Mode<String>;
    }
    pub mod put {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, schemars::JsonSchema)]
        pub struct SovdSeed {
            #[serde(rename = "Request_Seed")]
            pub request_seed: String,
        }

        #[derive(Serialize, Deserialize, schemars::JsonSchema)]
        pub struct RequestSeedResponse {
            pub id: String,
            pub seed: SovdSeed,
            #[serde(skip_serializing_if = "Option::is_none")]
            pub schema: Option<schemars::Schema>,
        }

        #[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
        pub struct ModeKey {
            #[serde(rename = "Send_Key", alias = "Security")]
            pub send_key: String,
        }

        #[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
        #[schemars(rename = "UpdateAccessModesRequest")]
        pub struct Request {
            pub value: String,
            /// Defines after how many seconds the
            /// mode expires and should therefore
            /// be automatically reset to the mode’s
            // default value
            // It's optional although strictly speaking it should be required
            // when following the sovd standard.
            // todo (strict-mode): if strict mode is enabled, this should be required
            pub mode_expiration: Option<u64>,

            #[serde(rename = "Key", alias = "SendKey")]
            pub key: Option<ModeKey>,
        }

        pub type Response<T> = crate::common::modes::put::Response<T>;
    }
}

pub mod commctrl {
    pub mod put {

        pub type Request = crate::common::modes::commctrl::put::Request;
        pub type Response = crate::common::modes::put::Response<String>;
    }
}
