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

        #[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
        pub struct SovdSeed {
            #[serde(rename = "Request_Seed")]
            pub request_seed: String,
        }

        #[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
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
        #[schemars(rename = "UpdateSessionModesRequest")]
        pub struct SessionRequest {
            pub value: String,
            /// Defines after how many seconds the
            /// mode expires and should therefore
            /// be automatically reset to the mode's
            // default value
            // It's optional although strictly speaking it should be required
            // when following the sovd standard.
            // todo (strict-mode): if strict mode is enabled, this should be required
            pub mode_expiration: Option<u64>,
        }

        #[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
        #[schemars(rename = "UpdateSecurityModesRequest")]
        pub struct SecurityRequest {
            pub value: String,
            /// Defines after how many seconds the
            /// mode expires and should therefore
            /// be automatically reset to the mode's
            // default value
            // It's optional although strictly speaking it should be required
            // when following the sovd standard.
            // todo (strict-mode): if strict mode is enabled, this should be required
            pub mode_expiration: Option<u64>,

            #[serde(rename = "Key", alias = "SendKey")]
            pub key: Option<ModeKey>,

            /// Optional parameters forwarded as payload to the `RequestSeed` service.
            pub parameters: Option<std::collections::HashMap<String, serde_json::Value>>,
        }

        pub type Request = SecurityRequest;

        pub type Response<T> = crate::common::modes::put::Response<T>;
    }
}

pub mod commctrl {
    pub mod get {
        pub type Response = crate::common::modes::get::Mode<String>;
    }

    pub mod put {

        pub type Request = crate::common::modes::commctrl::put::Request;
        pub type Response = crate::common::modes::put::Response<String>;
    }
}

pub mod dtcsetting {
    pub mod get {
        pub type Response = crate::common::modes::get::Mode<String>;
    }

    pub mod put {
        pub type Request = crate::common::modes::dtcsetting::put::Request;
        pub type Response = crate::common::modes::put::Response<String>;
    }
}

/// UDS Authentication (SID 0x29), see ADR-007.
pub mod authentication {
    pub mod get {
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
        #[schemars(rename = "AuthenticationModeResponse")]
        pub struct Response {
            /// The mode identifier, always `authentication`
            pub id: String,
            /// The name of the mode
            #[serde(skip_serializing_if = "Option::is_none")]
            pub name: Option<String>,
            /// `authenticated`, `deAuthenticated` or `offline`
            pub value: String,
            /// The last sub-function that resulted in a positive response
            #[serde(
                rename = "x-sovd2uds-last-subfunction",
                skip_serializing_if = "Option::is_none"
            )]
            pub last_subfunction: Option<String>,
            /// ISO 8601 point in time at which the `mode_expiration` elapses
            #[serde(
                rename = "x-sovd2uds-expires-at",
                skip_serializing_if = "Option::is_none"
            )]
            pub expires_at: Option<String>,
            /// JSON schema of the response, only present if `include-schema` was requested
            #[schemars(skip)]
            #[serde(skip_serializing_if = "Option::is_none")]
            pub schema: Option<schemars::Schema>,
        }
    }

    pub mod put {
        use cda_interfaces::HashMap;
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
        #[schemars(rename = "UpdateAuthenticationModesRequest")]
        pub struct Request {
            /// Sub-function name as defined in ISO 14229-1 Table 74,
            /// e.g. `verifyProofOfOwnershipBidirectional` (case-insensitive)
            pub value: String,
            /// Seconds after which `deAuthenticate` is sent, starting with the
            /// request that completes the authentication
            pub mode_expiration: Option<u64>,
            /// Request parameters by their short names in the diagnostic description
            pub parameters: Option<HashMap<String, serde_json::Value>>,
        }

        #[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
        #[schemars(rename = "UpdateAuthenticationModesResponse")]
        pub struct Response {
            /// The mode identifier, always `authentication`
            pub id: String,
            /// The sub-function that was sent, as defined in ISO 14229-1 Table 74
            pub value: String,
            /// Decoded response parameters
            pub parameters: serde_json::Map<String, serde_json::Value>,
            /// JSON schema of the response, only present if `include-schema` was requested
            #[schemars(skip)]
            #[serde(skip_serializing_if = "Option::is_none")]
            pub schema: Option<schemars::Schema>,
        }
    }
}
