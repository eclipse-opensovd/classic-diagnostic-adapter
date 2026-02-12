/*
 * Copyright (c) 2025-2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
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

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
// allowed, so we can pre-fill this with all sovd error codes
// even though not all are used yet.
#[allow(dead_code)]
#[derive(schemars::JsonSchema, PartialEq, Eq)]
pub enum ErrorCode {
    /// Details are specified in the `vendor_code`
    VendorSpecific,

    /// The Component which handles the request (e.g., an ECU)
    /// has been queried by the SOVD server but did not respond.
    NotResponding,

    /// The Component receiving the request has answered with an
    /// error.
    /// For UDS, the message should include the service identifier
    /// (Key: ‘service’ and Value of type number) and the negative
    /// response code (Key: ‘nrc’ and Value of type number).
    ErrorResponse,

    /// The signature of the data in the payload is invalid.
    InvalidSignature,

    /// The request does not provide all information (e.g., parameter
    /// values for an operation) required to complete the method.
    /// The message should include references to the missing
    /// information.
    IncompleteRequest,

    /// The response provided by the Component contains
    /// information which could not be processed. E.g., the response
    /// of an ECU does not match the conversion information known
    /// to the SOVD server.
    /// The message should include references to the parts of the
    /// invalid response attribute as well as a reason why the
    /// attribute is invalid.
    InvalidResponseContent,

    /// The SOVD server is not configured correctly, e.g., required
    /// configuration files or other data is missing. The message
    /// should include further information about the error. A client
    /// shall assume that this error is fatal and a regular operation of
    /// the SOVD server cannot be expected.
    SovdServerMisconfigured,

    /// The SOVD server is able to answer requests, but an internal
    /// error occurred. The message should include further
    /// information about the error
    SovdServerFailure,

    /// The SOVD client does not have the right to access the
    /// resource.
    InsufficientAccessRights,

    /// The preconditions to execute the method are not fulfilled.
    PreconditionsNotFulfilled,

    /// An update is already in progress and not yet done or aborted.
    UpdateProcessInProgress,

    /// Automatic installation of update is not supported
    UpdateAutomatedNotSupported,

    /// An update is already in preparation and not yet done or aborted.
    UpdatePreparationInProgress,

    /// Another update is currently executed and not yet done or aborted
    UpdateExecutionInProgress,
}

#[derive(Serialize, Deserialize, Debug, schemars::JsonSchema)]
pub struct ApiErrorResponse<T> {
    pub message: String,
    pub error_code: ErrorCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor_code: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<HashMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "x-errorsource")]
    pub error_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<schemars::Schema>,
}

#[derive(Serialize, Deserialize, Debug, schemars::JsonSchema)]
pub struct DataError<T> {
    pub path: String,
    pub error: ApiErrorResponse<T>,
}
