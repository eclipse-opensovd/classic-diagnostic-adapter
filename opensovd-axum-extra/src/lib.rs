/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

use std::convert::Infallible;

use aide::OperationInput;
use axum::{
    RequestPartsExt,
    extract::{FromRequestParts, OptionalFromRequestParts},
    response::{IntoResponse, Response},
};
#[cfg(feature = "forwarded")]
use http::header::{FORWARDED, HeaderMap};
use http::request::Parts;
#[cfg(feature = "uri-authority")]
use http::uri::Authority;

#[cfg(feature = "x-forwarded-host")]
const X_FORWARDED_HOST_HEADER_KEY: &str = "x-forwarded-host";

/// Extractor that resolves the host of the request.
///
/// Host is resolved through the following, in order:
/// - `Forwarded` header
/// - `X-Forwarded-Host` header
/// - `Host` header
/// - Authority of the request URI
///
/// See <https://www.rfc-editor.org/rfc/rfc9110.html#name-host-and-authority> for the definition of
/// host.
///
/// Note that user agents can set `X-Forwarded-Host` and `Host` headers to arbitrary values so make
/// sure to validate them to avoid security issues.
#[derive(Debug, Clone)]
pub struct ExtractHost(pub String);

impl OperationInput for ExtractHost {}

impl<S> FromRequestParts<S> for ExtractHost
where
    S: Send + Sync,
{
    type Rejection = ExtractHostRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extract::<Option<ExtractHost>>()
            .await
            .ok()
            .flatten()
            .ok_or(ExtractHostRejection::FailedToResolveHost(
                FailedToResolveHost,
            ))
    }
}

impl<S> OptionalFromRequestParts<S> for ExtractHost
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        // suppress unused-parameter warning when all host resolution features are disabled
        #[cfg(not(any(
            feature = "forwarded",
            feature = "x-forwarded-host",
            feature = "host-header",
            feature = "uri-authority"
        )))]
        let _ = parts;

        #[cfg(feature = "forwarded")]
        if let Some(host) = parse_forwarded(&parts.headers) {
            return Ok(Some(ExtractHost(host.to_owned())));
        }

        #[cfg(feature = "x-forwarded-host")]
        if let Some(host) = parts
            .headers
            .get(X_FORWARDED_HOST_HEADER_KEY)
            .and_then(|host| host.to_str().ok())
        {
            return Ok(Some(ExtractHost(host.to_owned())));
        }

        #[cfg(feature = "host-header")]
        if let Some(host) = parts
            .headers
            .get(http::header::HOST)
            .and_then(|host| host.to_str().ok())
        {
            return Ok(Some(ExtractHost(host.to_owned())));
        }

        #[cfg(feature = "uri-authority")]
        if let Some(authority) = parts.uri.authority() {
            return Ok(Some(ExtractHost(parse_authority(authority).to_owned())));
        }

        Ok(None)
    }
}

/// Rejection type used if the `ExtractHost` extractor is unable to resolve a host.
#[derive(Debug, Clone, Copy)]
pub struct FailedToResolveHost;

impl IntoResponse for FailedToResolveHost {
    fn into_response(self) -> Response {
        (http::StatusCode::BAD_REQUEST, "No host found in request").into_response()
    }
}

/// Rejection used for `ExtractHost`.
#[derive(Debug, Clone, Copy)]
pub enum ExtractHostRejection {
    FailedToResolveHost(FailedToResolveHost),
}

impl IntoResponse for ExtractHostRejection {
    fn into_response(self) -> Response {
        match self {
            Self::FailedToResolveHost(rejection) => rejection.into_response(),
        }
    }
}

#[cfg(feature = "forwarded")]
fn parse_forwarded(headers: &HeaderMap) -> Option<&str> {
    // if there are multiple `Forwarded` `HeaderMap::get` will return the first one
    let forwarded_values = headers.get(FORWARDED)?.to_str().ok()?;

    // get the first set of values
    let first_value = forwarded_values.split(',').next()?;

    // find the value of the `host` field
    first_value.split(';').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case("host")
            .then(|| value.trim().trim_matches('"'))
    })
}

#[cfg(feature = "uri-authority")]
fn parse_authority(auth: &Authority) -> &str {
    auth.as_str()
        .rsplit('@')
        .next()
        .expect("split always has at least 1 item")
}

#[cfg(test)]
mod tests {
    use axum::http::Request;
    #[cfg(any(feature = "forwarded", feature = "x-forwarded-host"))]
    use axum::http::header::HeaderName;

    use super::*;

    #[tokio::test]
    #[cfg(feature = "host-header")]
    async fn host_header() {
        let original_host = "some-domain:123";
        let mut parts = Request::new(()).into_parts().0;
        parts
            .headers
            .insert(http::header::HOST, original_host.parse().unwrap());

        let host = parts.extract::<ExtractHost>().await.unwrap();
        assert_eq!(host.0, original_host);
    }

    #[tokio::test]
    #[cfg(feature = "x-forwarded-host")]
    async fn x_forwarded_host_header() {
        let original_host = "some-domain:456";
        let mut parts = Request::new(()).into_parts().0;
        parts.headers.insert(
            HeaderName::from_static("x-forwarded-host"),
            original_host.parse().unwrap(),
        );

        let host = parts.extract::<ExtractHost>().await.unwrap();
        assert_eq!(host.0, original_host);
    }

    #[tokio::test]
    #[cfg(all(feature = "x-forwarded-host", feature = "host-header"))]
    async fn x_forwarded_host_precedence_over_host_header() {
        let x_forwarded_host_header = "some-domain:456";
        let host_header = "some-domain:123";
        let mut parts = Request::new(()).into_parts().0;
        parts.headers.insert(
            HeaderName::from_static("x-forwarded-host"),
            x_forwarded_host_header.parse().unwrap(),
        );
        parts
            .headers
            .insert(http::header::HOST, host_header.parse().unwrap());

        let host = parts.extract::<ExtractHost>().await.unwrap();
        assert_eq!(host.0, x_forwarded_host_header);
    }

    #[tokio::test]
    #[cfg(feature = "uri-authority")]
    async fn ip4_uri_host() {
        let mut parts = Request::new(()).into_parts().0;
        parts.uri = "https://127.0.0.1:1234/image.jpg".parse().unwrap();
        let host = parts.extract::<ExtractHost>().await.unwrap();
        assert_eq!(host.0, "127.0.0.1:1234");
    }

    #[tokio::test]
    #[cfg(feature = "uri-authority")]
    async fn ip6_uri_host() {
        let mut parts = Request::new(()).into_parts().0;
        parts.uri = "http://cool:user@[::1]:456/file.txt".parse().unwrap();
        let host = parts.extract::<ExtractHost>().await.unwrap();
        assert_eq!(host.0, "[::1]:456");
    }

    #[tokio::test]
    async fn missing_host() {
        let mut parts = Request::new(()).into_parts().0;
        let host = parts.extract::<ExtractHost>().await.unwrap_err();
        assert!(matches!(host, ExtractHostRejection::FailedToResolveHost(_)));
    }

    #[tokio::test]
    #[cfg(feature = "uri-authority")]
    async fn optional_extractor() {
        let mut parts = Request::new(()).into_parts().0;
        parts.uri = "https://127.0.0.1:1234/image.jpg".parse().unwrap();
        let host = parts.extract::<Option<ExtractHost>>().await.unwrap();
        assert!(host.is_some());
    }

    #[tokio::test]
    async fn optional_extractor_none() {
        let mut parts = Request::new(()).into_parts().0;
        let host = parts.extract::<Option<ExtractHost>>().await.unwrap();
        assert!(host.is_none());
    }

    #[tokio::test]
    #[cfg(all(feature = "forwarded", feature = "host-header"))]
    async fn prefers_forwarded_host() {
        let mut parts = Request::new(()).into_parts().0;
        parts.headers.insert(
            FORWARDED,
            "host=forwarded.example;proto=https".parse().unwrap(),
        );
        parts
            .headers
            .insert(http::header::HOST, "host.example".parse().unwrap());

        let host = parts.extract::<ExtractHost>().await.unwrap();
        assert_eq!(host.0, "forwarded.example");
    }

    #[test]
    #[cfg(feature = "forwarded")]
    fn forwarded_parsing() {
        // the basic case
        let headers = header_map(&[(FORWARDED, "host=192.0.2.60;proto=http;by=203.0.113.43")]);
        let value = parse_forwarded(&headers).unwrap();
        assert_eq!(value, "192.0.2.60");

        // is case insensitive
        let headers = header_map(&[(FORWARDED, "host=192.0.2.60;proto=http;by=203.0.113.43")]);
        let value = parse_forwarded(&headers).unwrap();
        assert_eq!(value, "192.0.2.60");

        // ipv6
        let headers = header_map(&[(FORWARDED, "host=\"[2001:db8:cafe::17]:4711\"")]);
        let value = parse_forwarded(&headers).unwrap();
        assert_eq!(value, "[2001:db8:cafe::17]:4711");

        // multiple values in one header
        let headers = header_map(&[(FORWARDED, "host=192.0.2.60, host=127.0.0.1")]);
        let value = parse_forwarded(&headers).unwrap();
        assert_eq!(value, "192.0.2.60");

        // multiple header values
        let headers = header_map(&[
            (FORWARDED, "host=192.0.2.60"),
            (FORWARDED, "host=127.0.0.1"),
        ]);
        let value = parse_forwarded(&headers).unwrap();
        assert_eq!(value, "192.0.2.60");
    }

    #[cfg(feature = "forwarded")]
    fn header_map(values: &[(HeaderName, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (key, value) in values {
            headers.append(key, value.parse().unwrap());
        }
        headers
    }
}
