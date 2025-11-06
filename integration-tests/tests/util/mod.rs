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

use ::http::StatusCode;
use thiserror::Error;

pub(crate) mod ecusim;
pub(crate) mod http;
pub(crate) mod runtime;

#[derive(Error, Debug)]
pub enum TestingError {
    #[error("Path not found: {0}")]
    PathNotFound(String),
    #[error("Process failed: {0}")]
    ProcessFailed(String),
    #[error("Invalid JSON: {0}")]
    InvalidData(String),
    #[error(
        "Unexpected response: expected {expected}, got {actual}. Body: {body:?}, Message: \
         {message}, URL: {url}"
    )]
    UnexpectedResponse {
        expected: StatusCode,
        actual: StatusCode,
        body: Option<String>,
        message: String,
        url: String,
    },
    #[error("Invalid network configuration: {0}")]
    InvalidNetworkConfig(String),
    #[error("URL is invalid: {0}")]
    InvalidUrl(String),
    #[error("Timeout: {0}")]
    Timeout(String),
}

impl From<url::ParseError> for TestingError {
    fn from(err: url::ParseError) -> Self {
        TestingError::InvalidUrl(err.to_string())
    }
}
