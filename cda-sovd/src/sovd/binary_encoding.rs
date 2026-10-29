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

//! Per request selection of the encoding used for binary data in SOVD JSON.

use aide::{OperationInput, generate::GenContext, openapi::Operation};
use axum::extract::FromRequestParts;
use cda_interfaces::BinaryEncoding;
use http::request::Parts;

use crate::sovd::error::ApiError;

/// Name of the query parameter that overrides the configured binary encoding.
pub(crate) const BINARY_ENCODING_QUERY_PARAM: &str = "x-sovd2uds-binary-encoding";

/// Configured default encoding, provided to handlers as request extension.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DefaultBinaryEncoding(pub(crate) BinaryEncoding);

#[derive(serde::Deserialize, schemars::JsonSchema)]
#[allow(dead_code, reason = "Only used to generate the OpenAPI documentation")]
struct BinaryEncodingQueryDoc {
    /// Encoding of binary data (e.g. byte fields) in JSON requests and
    /// responses. Defaults to the configured server setting.
    #[serde(rename = "x-sovd2uds-binary-encoding")]
    binary_encoding: Option<BinaryEncoding>,
}

/// Extracts the binary encoding for the current request: the
/// `x-sovd2uds-binary-encoding` query parameter if given, otherwise the
/// configured default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BinaryEncodingParam(pub(crate) BinaryEncoding);

impl BinaryEncodingParam {
    fn resolve(query: Option<&str>, default: BinaryEncoding) -> Result<Self, ApiError> {
        let requested = query
            .unwrap_or_default()
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .find(|(key, _)| *key == BINARY_ENCODING_QUERY_PARAM)
            .map(|(_, value)| value.parse::<BinaryEncoding>())
            .transpose()
            .map_err(ApiError::BadRequest)?;
        Ok(Self(requested.unwrap_or(default)))
    }
}

impl<S> FromRequestParts<S> for BinaryEncodingParam
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let default = parts
            .extensions
            .get::<DefaultBinaryEncoding>()
            .map_or_else(BinaryEncoding::default, |d| d.0);
        std::future::ready(Self::resolve(parts.uri.query(), default))
    }
}

impl OperationInput for BinaryEncodingParam {
    fn operation_input(ctx: &mut GenContext, operation: &mut Operation) {
        <axum::extract::Query<BinaryEncodingQueryDoc> as OperationInput>::operation_input(
            ctx, operation,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_default() {
        assert_eq!(
            BinaryEncodingParam::resolve(None, BinaryEncoding::Hex).unwrap(),
            BinaryEncodingParam(BinaryEncoding::Hex)
        );
        assert_eq!(
            BinaryEncodingParam::resolve(Some("include-schema=true"), BinaryEncoding::Base64)
                .unwrap(),
            BinaryEncodingParam(BinaryEncoding::Base64)
        );
    }

    #[test]
    fn test_resolve_override() {
        assert_eq!(
            BinaryEncodingParam::resolve(
                Some("include-schema=true&x-sovd2uds-binary-encoding=hex"),
                BinaryEncoding::Base64
            )
            .unwrap(),
            BinaryEncodingParam(BinaryEncoding::Hex)
        );
        assert_eq!(
            BinaryEncodingParam::resolve(
                Some("x-sovd2uds-binary-encoding=base64"),
                BinaryEncoding::Hex
            )
            .unwrap(),
            BinaryEncodingParam(BinaryEncoding::Base64)
        );
    }

    #[test]
    fn test_resolve_invalid() {
        assert!(
            BinaryEncodingParam::resolve(
                Some("x-sovd2uds-binary-encoding=foo"),
                BinaryEncoding::Base64
            )
            .is_err()
        );
    }
}
