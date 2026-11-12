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
use axum::extract::{FromRequestParts, Query};
use cda_interfaces::BinaryEncoding;
use http::request::Parts;

use crate::sovd::error::ApiError;

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

/// Raw query value, parsed via `FromStr` to accept any letter case.
#[derive(serde::Deserialize)]
struct BinaryEncodingQuery {
    #[serde(rename = "x-sovd2uds-binary-encoding")]
    binary_encoding: Option<String>,
}

/// Extracts the binary encoding for the current request: the
/// `x-sovd2uds-binary-encoding` query parameter if given, otherwise the
/// configured default.
///
/// [[ dimpl~sovd-api-binary-encoding-selection, Per request selection of the binary encoding ]]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BinaryEncodingParam(pub(crate) BinaryEncoding);

impl BinaryEncodingParam {
    fn resolve(uri: &http::Uri, default: BinaryEncoding) -> Result<Self, ApiError> {
        // Uses the same (percent decoding) query parser as `Query`; a repeated
        // parameter is rejected as duplicate field.
        let Query(query) = Query::<BinaryEncodingQuery>::try_from_uri(uri)
            .map_err(|e| ApiError::BadRequest(format!("Invalid query: {}", e.body_text())))?;
        let requested = query
            .binary_encoding
            .map(|v| {
                v.parse::<BinaryEncoding>().map_err(|_| {
                    ApiError::BadRequest(format!(
                        "Invalid binary encoding '{v}', expected 'base64' or 'hex'"
                    ))
                })
            })
            .transpose()?;
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
        let default = if let Some(DefaultBinaryEncoding(encoding)) =
            parts.extensions.get::<DefaultBinaryEncoding>()
        {
            *encoding
        } else {
            // Only happens if a router is served without the layer added in
            // `launch_webserver`, i.e. a wiring bug. Warn once instead of per request.
            static WARNED: std::sync::Once = std::sync::Once::new();
            WARNED.call_once(|| {
                tracing::warn!(
                    "No configured binary encoding available (first seen for {}), using {}",
                    parts.uri.path(),
                    BinaryEncoding::default()
                );
            });
            BinaryEncoding::default()
        };
        std::future::ready(Self::resolve(&parts.uri, default))
    }
}

impl OperationInput for BinaryEncodingParam {
    fn operation_input(ctx: &mut GenContext, operation: &mut Operation) {
        <axum::extract::Query<BinaryEncodingQueryDoc> as OperationInput>::operation_input(
            ctx, operation,
        );
    }
}

/// Hex encoding as extracted for a request, for handler tests that expect hex
/// coded binary data.
#[cfg(test)]
pub(crate) fn hex_encoding() -> BinaryEncodingParam {
    BinaryEncodingParam(BinaryEncoding::Hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolve(
        path_and_query: &str,
        default: BinaryEncoding,
    ) -> Result<BinaryEncodingParam, ApiError> {
        BinaryEncodingParam::resolve(&path_and_query.parse().unwrap(), default)
    }

    #[test]
    fn test_resolve_default() {
        assert_eq!(
            resolve("/data", BinaryEncoding::Hex).unwrap(),
            BinaryEncodingParam(BinaryEncoding::Hex)
        );
        assert_eq!(
            resolve("/data?include-schema=true", BinaryEncoding::Base64).unwrap(),
            BinaryEncodingParam(BinaryEncoding::Base64)
        );
    }

    /// [[ test~sovd-api-binary-encoding-selection, Query parameter overrides the configured binary encoding, test ]]
    #[test]
    fn test_resolve_override() {
        assert_eq!(
            resolve(
                "/data?include-schema=true&x-sovd2uds-binary-encoding=hex",
                BinaryEncoding::Base64
            )
            .unwrap(),
            BinaryEncodingParam(BinaryEncoding::Hex)
        );
        assert_eq!(
            resolve(
                "/data?x-sovd2uds-binary-encoding=BASE64",
                BinaryEncoding::Hex
            )
            .unwrap(),
            BinaryEncodingParam(BinaryEncoding::Base64)
        );
        // Percent encoded value
        assert_eq!(
            resolve(
                "/data?x-sovd2uds-binary-encoding=%68ex",
                BinaryEncoding::Base64
            )
            .unwrap(),
            BinaryEncodingParam(BinaryEncoding::Hex)
        );
    }

    #[test]
    fn test_resolve_invalid() {
        assert!(
            resolve(
                "/data?x-sovd2uds-binary-encoding=foo",
                BinaryEncoding::Base64
            )
            .is_err()
        );
        assert!(
            resolve(
                "/data?x-sovd2uds-binary-encoding=hex&x-sovd2uds-binary-encoding=base64",
                BinaryEncoding::Base64
            )
            .is_err()
        );
    }
}
