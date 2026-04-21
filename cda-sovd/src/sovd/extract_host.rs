/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

use aide::OperationInput;
use axum::{
    extract::{FromRequestParts, OptionalFromRequestParts},
    response::{IntoResponse, Response},
    RequestPartsExt,
};
use http::{
    header::{HeaderMap, FORWARDED},
    request::Parts,
    uri::Authority,
};
use std::convert::Infallible;

const X_FORWARDED_HOST_HEADER_KEY: &str = "X-Forwarded-Host";

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
pub(crate) struct ExtractHost(pub(crate) String);

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
            .ok_or(ExtractHostRejection::FailedToResolveHost(FailedToResolveHost))
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
        if let Some(host) = parse_forwarded(&parts.headers) {
            return Ok(Some(ExtractHost(host.to_owned())));
        }

        if let Some(host) = parts
            .headers
            .get(X_FORWARDED_HOST_HEADER_KEY)
            .and_then(|host| host.to_str().ok())
        {
            return Ok(Some(ExtractHost(host.to_owned())));
        }

        if let Some(host) = parts
            .headers
            .get(http::header::HOST)
            .and_then(|host| host.to_str().ok())
        {
            return Ok(Some(ExtractHost(host.to_owned())));
        }

        if let Some(authority) = parts.uri.authority() {
            return Ok(Some(ExtractHost(parse_authority(authority).to_owned())));
        }

        Ok(None)
    }
}

/// Rejection type used if the `ExtractHost` extractor is unable to resolve a host.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FailedToResolveHost;

impl IntoResponse for FailedToResolveHost {
    fn into_response(self) -> Response {
        (http::StatusCode::BAD_REQUEST, "No host found in request").into_response()
    }
}

/// Rejection used for `ExtractHost`.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ExtractHostRejection {
    FailedToResolveHost(FailedToResolveHost),
}

impl IntoResponse for ExtractHostRejection {
    fn into_response(self) -> Response {
        match self {
            Self::FailedToResolveHost(rejection) => rejection.into_response(),
        }
    }
}

#[allow(warnings)]
fn parse_forwarded(headers: &HeaderMap) -> Option<&str> {
    // if there are multiple `Forwarded` `HeaderMap::get` will return the first one
    let forwarded_values = headers.get(FORWARDED)?.to_str().ok()?;

    // get the first set of values
    let first_value = forwarded_values.split(',').nth(0)?;

    // find the value of the `host` field
    first_value.split(';').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case("host")
            .then(|| value.trim().trim_matches('"'))
    })
}

fn parse_authority(auth: &Authority) -> &str {
    auth.as_str()
        .rsplit('@')
        .next()
        .expect("split always has at least 1 item")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Request, header::HeaderName};

    #[tokio::test]
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
    async fn ip4_uri_host() {
        let mut parts = Request::new(()).into_parts().0;
        parts.uri = "https://127.0.0.1:1234/image.jpg".parse().unwrap();
        let host = parts.extract::<ExtractHost>().await.unwrap();
        assert_eq!(host.0, "127.0.0.1:1234");
    }

    #[tokio::test]
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

    fn header_map(values: &[(HeaderName, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (key, value) in values {
            headers.append(key, value.parse().unwrap());
        }
        headers
    }
}