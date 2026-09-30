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

use http::{HeaderMap, StatusCode};
use serde::de::DeserializeOwned;
use sovd_interfaces::error::ApiErrorResponse;

use crate::util::TestingError;

/// An error of a [`SovdTestClient`](crate::client::SovdTestClient) request.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    /// The CDA answered with a status other than a success.
    #[error("{status} from {url}, body: {body:?}")]
    Api {
        status: StatusCode,
        url: String,
        /// Boxed, so that every `Result` of the client stays small.
        headers: Box<HeaderMap>,
        body: Option<String>,
    },
    /// The request could not be sent, or no response arrived in time.
    #[error("request to {url} failed: {message}")]
    Transport { url: String, message: String },
    /// A response did not have the expected shape.
    #[error("unexpected response from {url}: {message}, body: {body:?}")]
    InvalidResponse {
        url: String,
        message: String,
        body: Option<String>,
    },
    /// Polling did not reach the expected state in time.
    #[error("timeout: {0}")]
    Timeout(String),
}

impl Error {
    /// The status of an [`Error::Api`].
    pub(crate) fn status(&self) -> Option<StatusCode> {
        match self {
            Self::Api { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// The header `name` of an [`Error::Api`] response.
    pub(crate) fn header(&self, name: http::header::HeaderName) -> Option<&http::HeaderValue> {
        match self {
            Self::Api { headers, .. } => headers.get(name),
            _ => None,
        }
    }

    /// The SOVD error body of an [`Error::Api`], with vendor codes of type
    /// `T`, e.g. [`cda_sovd::VendorErrorCode`], or `None` if there is no body
    /// or it is not an SOVD error.
    pub(crate) fn api_error<T: DeserializeOwned>(&self) -> Option<ApiErrorResponse<T>> {
        match self {
            Self::Api {
                body: Some(body), ..
            } => serde_json::from_str(body).ok(),
            _ => None,
        }
    }
}

impl From<Error> for TestingError {
    fn from(error: Error) -> Self {
        match error {
            Error::Api {
                status, url, body, ..
            } => TestingError::UnexpectedResponse {
                expected: StatusCode::OK,
                actual: status,
                body,
                message: "the CDA answered with an error".to_owned(),
                url,
            },
            Error::Timeout(message) => TestingError::Timeout(message),
            other => TestingError::InvalidData(other.to_string()),
        }
    }
}

/// A `Result` of a [`SovdTestClient`](crate::client::SovdTestClient) request.
pub(crate) type Result<T> = std::result::Result<T, Error>;
