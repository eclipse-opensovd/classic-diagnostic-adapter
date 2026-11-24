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

//! JSON form of the `/genericservice` raw UDS passthrough.

pub mod put {
    use serde::{Deserialize, Serialize};

    /// Raw UDS request sent to the ECU.
    #[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
    #[schemars(rename = "GenericServiceRequest")]
    pub struct Request {
        /// UDS request bytes (service id and payload), encoded as selected by
        /// `x-sovd2uds-binary-encoding` (base64 or hex). `request` and `send`
        /// are accepted as aliases.
        #[serde(alias = "request", alias = "send")]
        pub data: String,
    }

    /// Raw UDS response received from the ECU.
    #[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
    #[schemars(rename = "GenericServiceResponse")]
    pub struct Response {
        /// Identifier of the resource, always `genericservice`.
        pub id: String,
        /// UDS response bytes, encoded as selected by
        /// `x-sovd2uds-binary-encoding` (base64 or hex). Hex uses the notation
        /// of a hex coded request.
        pub data: String,
    }
}
