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

use aide::UseApi;
use axum::{Json, body::Bytes, extract::State, response::Response};
use cda_interfaces::{
    BinaryEncoding, UdsEcu, diagservices::UdsPayloadData, file_manager::FileManager,
};
use cda_plugin_security::Secured;
use http::{HeaderMap, header};
use sovd_interfaces::components::ecu::genericservice::put as sovd_put;

use super::{ApiError, DynamicPlugin, ErrorWrapper, IntoResponse, StatusCode, TransformOperation};
use crate::{
    openapi,
    sovd::{
        WebserverEcuState, binary_encoding::BinaryEncodingParam,
        components::get_content_type_and_accept, get_octet_stream_payload,
        locks::require_ecu_access,
    },
};

/// Body format of a generic service request or response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyFormat {
    /// JSON object with the UDS bytes in the selected binary encoding (default).
    Json,
    /// Raw UDS bytes, without encoding and decoding overhead.
    OctetStream,
}

impl BodyFormat {
    fn from_mime(mime: &mime::Mime, header: &str) -> Result<Self, ApiError> {
        match (mime.type_(), mime.subtype()) {
            (mime::APPLICATION, mime::JSON) => Ok(BodyFormat::Json),
            (mime::APPLICATION, mime::OCTET_STREAM) => Ok(BodyFormat::OctetStream),
            _ => Err(ApiError::BadRequest(format!(
                "Unsupported {header} '{mime}', expected {} or {}",
                mime::APPLICATION_JSON,
                mime::APPLICATION_OCTET_STREAM
            ))),
        }
    }
}

/// Request and response body format from `Content-Type` and `Accept`.
///
/// Uses the common header handling: a missing `Content-Type` means JSON, a
/// missing `Accept` or `*/*` answers in the format of the request.
fn body_formats(headers: &HeaderMap) -> Result<(BodyFormat, BodyFormat), ApiError> {
    let (content_type, accept) = get_content_type_and_accept(headers)?;
    let request = content_type
        .map(|m| BodyFormat::from_mime(&m, "Content-Type"))
        .transpose()?
        .unwrap_or(BodyFormat::Json);
    Ok((request, BodyFormat::from_mime(&accept, "Accept")?))
}

/// Notation of a hex coded JSON request, mirrored in the JSON response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HexStyle {
    /// One leading `0x` for all bytes, e.g. `0x22F190`.
    PrefixedCompact,
    /// No prefix, e.g. `22F190` or `22 F1 90`.
    Compact,
    /// `0x` before every byte, e.g. `0x22 0xF1 0x90`, the default hex output.
    PerByte,
}

impl HexStyle {
    /// Detects the notation of a hex value. Spaces and commas between the
    /// bytes are not mirrored; mixed notations fall back to [`HexStyle::PerByte`].
    fn detect(value: &str) -> Self {
        let has_prefix = |t: &str| t.starts_with("0x") || t.starts_with("0X");
        let tokens: Vec<&str> = value
            .split(|c: char| c.is_whitespace() || c == ',')
            .filter(|t| !t.is_empty())
            .collect();
        let prefixed = tokens.iter().filter(|t| has_prefix(t)).count();
        match (tokens.first(), prefixed) {
            (_, 0) => HexStyle::Compact,
            (Some(first), 1) if has_prefix(first) => HexStyle::PrefixedCompact,
            _ => HexStyle::PerByte,
        }
    }

    fn encode(self, data: &[u8]) -> String {
        use std::fmt::Write as _;

        let compact = || {
            data.iter().fold(String::new(), |mut out, b| {
                let _ = write!(out, "{b:02X}");
                out
            })
        };
        match self {
            HexStyle::PerByte => BinaryEncoding::Hex.encode(data),
            HexStyle::Compact => compact(),
            HexStyle::PrefixedCompact if data.is_empty() => String::new(),
            HexStyle::PrefixedCompact => format!("0x{}", compact()),
        }
    }
}

/// Encodes the ECU response for a JSON body. Hex follows the notation of the
/// request, if the request was hex coded JSON.
fn encode_response(data: &[u8], encoding: BinaryEncoding, style: Option<HexStyle>) -> String {
    match (encoding, style) {
        (BinaryEncoding::Hex, Some(style)) => style.encode(data),
        _ => encoding.encode(data),
    }
}

/// Extract the raw UDS request bytes from the body in the given format, and
/// the hex notation of a hex coded JSON request.
fn request_payload(
    format: BodyFormat,
    headers: &HeaderMap,
    body: &Bytes,
    encoding: BinaryEncoding,
) -> Result<(Vec<u8>, Option<HexStyle>), ApiError> {
    let (payload, style) = match format {
        BodyFormat::Json => {
            let request: sovd_put::Request = serde_json::from_slice(body)
                .map_err(|e| ApiError::BadRequest(format!("Invalid JSON body: {e}")))?;
            let value = request.request.trim();
            let payload = encoding.decode(value).map_err(|e| {
                ApiError::BadRequest(format!("Invalid {encoding} encoded request: {e}"))
            })?;
            let style = (encoding == BinaryEncoding::Hex).then(|| HexStyle::detect(value));
            (payload, style)
        }
        BodyFormat::OctetStream => match get_octet_stream_payload(headers, body)? {
            Some(UdsPayloadData::Raw(data)) => (data, None),
            _ => (Vec::new(), None),
        },
    };
    if payload.is_empty() {
        return Err(ApiError::BadRequest("Empty UDS request".to_owned()));
    }
    Ok((payload, style))
}

/// [[ dimpl~sovd-api-generic-service, JSON and octet-stream generic service passthrough ]]
pub(crate) async fn put<T: UdsEcu + Clone, U: FileManager>(
    headers: HeaderMap,
    UseApi(Secured(security_plugin), _): UseApi<Secured, ()>,
    BinaryEncodingParam(binary_encoding): BinaryEncodingParam,
    State(WebserverEcuState {
        ecu_name,
        uds,
        locks,
        ..
    }): State<WebserverEcuState<T, U>>,
    body: Bytes,
) -> Response {
    require_ecu_access!(write, security_plugin, &ecu_name, &locks, false);

    let payload = body_formats(&headers).and_then(|(req, resp)| {
        request_payload(req, &headers, &body, binary_encoding).map(|p| (p, resp))
    });
    let ((uds_raw_payload, hex_style), response_format) = match payload {
        Ok(v) => v,
        Err(error) => {
            return ErrorWrapper {
                error,
                include_schema: false,
            }
            .into_response();
        }
    };

    let ecu_response = match uds
        .send_genericservice(
            &ecu_name,
            &(security_plugin as DynamicPlugin),
            uds_raw_payload,
            None,
        )
        .await
    {
        Err(e) => {
            return ErrorWrapper {
                error: e.into(),
                include_schema: false,
            }
            .into_response();
        }
        Ok(v) => v,
    };
    match response_format {
        BodyFormat::Json => (
            StatusCode::OK,
            Json(sovd_put::Response {
                response: encode_response(&ecu_response, binary_encoding, hex_style),
            }),
        )
            .into_response(),
        BodyFormat::OctetStream => (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                mime::APPLICATION_OCTET_STREAM.essence_str(),
            )],
            Bytes::from_owner(ecu_response),
        )
            .into_response(),
    }
}

pub(crate) fn docs_put(op: TransformOperation) -> TransformOperation {
    openapi::request_json_and_octet::<sovd_put::Request>(op)
        .description(
            "Send a raw UDS request to the ECU. By default request and response are JSON objects \
             with the UDS bytes encoded as selected by `x-sovd2uds-binary-encoding`. \
             `application/octet-stream` can be used for the request (`Content-Type`) and the \
             response (`Accept`) to exchange raw bytes instead. A hex coded JSON response uses \
             the notation of the request (`0x22F190`, `22F190` or `0x22 0xF1 0x90`). The request \
             field `send` is accepted as alias of `request`.",
        )
        .response_with::<200, Json<sovd_put::Response>, _>(|res| {
            res.description(
                "Raw ECU response, JSON or raw bytes depending on `Accept`. Negative responses \
                 (`7F <SID> <NRC>`) are returned the same way.",
            )
        })
        .with(openapi::error_bad_request)
        .with(openapi::error_forbidden)
        .with(openapi::error_internal_server)
        .with(openapi::error_not_found)
        .id("ecu_genericservice_put")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn formats(
        content_type: Option<&str>,
        accept: Option<&str>,
    ) -> Result<(BodyFormat, BodyFormat), ApiError> {
        let mut headers = HeaderMap::new();
        if let Some(v) = content_type {
            headers.insert(header::CONTENT_TYPE, v.parse().unwrap());
        }
        if let Some(v) = accept {
            headers.insert(header::ACCEPT, v.parse().unwrap());
        }
        body_formats(&headers)
    }

    /// [[ test~sovd-api-generic-service-format, Content negotiation of the generic service, test ]]
    #[test]
    fn test_body_formats() {
        use BodyFormat::{Json, OctetStream};
        const JSON: &str = "application/json";
        const OCTET: &str = "application/octet-stream";
        assert_eq!(formats(None, None).unwrap(), (Json, Json));
        assert_eq!(
            formats(Some("application/json; charset=utf-8"), None).unwrap(),
            (Json, Json)
        );
        assert_eq!(
            formats(Some(OCTET), None).unwrap(),
            (OctetStream, OctetStream)
        );
        assert_eq!(
            formats(Some(OCTET), Some("*/*")).unwrap(),
            (OctetStream, OctetStream)
        );
        assert_eq!(formats(None, Some(OCTET)).unwrap(), (Json, OctetStream));
        assert_eq!(
            formats(Some(OCTET), Some(JSON)).unwrap(),
            (OctetStream, Json)
        );
        assert!(formats(Some("text/plain"), None).is_err());
        assert!(formats(None, Some("text/plain")).is_err());
    }

    fn json_request(value: &str) -> Result<(Vec<u8>, Option<HexStyle>), ApiError> {
        let body = Bytes::from(serde_json::json!({ "request": value }).to_string());
        request_payload(
            BodyFormat::Json,
            &HeaderMap::new(),
            &body,
            BinaryEncoding::Hex,
        )
    }

    #[test]
    fn test_request_payload_json() {
        let headers = HeaderMap::new();
        assert_eq!(
            json_request(" 22F190 ").unwrap(),
            (vec![0x22, 0xF1, 0x90], Some(HexStyle::Compact))
        );
        let b64 = Bytes::from_static(br#"{"request": "IvGQ"}"#);
        assert_eq!(
            request_payload(BodyFormat::Json, &headers, &b64, BinaryEncoding::Base64).unwrap(),
            (vec![0x22, 0xF1, 0x90], None)
        );
        let alias = Bytes::from_static(br#"{"send": "0x22F190"}"#);
        assert_eq!(
            request_payload(BodyFormat::Json, &headers, &alias, BinaryEncoding::Hex).unwrap(),
            (vec![0x22, 0xF1, 0x90], Some(HexStyle::PrefixedCompact))
        );
        assert!(json_request("").is_err());
        assert!(json_request("zz").is_err());
        let missing = Bytes::from_static(b"{}");
        assert!(
            request_payload(BodyFormat::Json, &headers, &missing, BinaryEncoding::Hex).is_err()
        );
    }

    /// [[ test~sovd-api-generic-service-hex-style, Hex notation of the request is mirrored in the response, test ]]
    #[test]
    fn test_hex_style_detect() {
        for (value, style) in [
            ("0x22F190", HexStyle::PrefixedCompact),
            ("0X22f190", HexStyle::PrefixedCompact),
            ("0x22 F1 90", HexStyle::PrefixedCompact),
            ("0x22", HexStyle::PrefixedCompact),
            ("22F190", HexStyle::Compact),
            ("22 F1 90", HexStyle::Compact),
            ("22,F1,90", HexStyle::Compact),
            ("0x22 0xF1 0x90", HexStyle::PerByte),
            ("0x22,0xF1", HexStyle::PerByte),
            ("22 0xF1", HexStyle::PerByte),
            ("0x22 F1 0x90", HexStyle::PerByte),
        ] {
            assert_eq!(HexStyle::detect(value), style, "{value}");
        }
    }

    #[test]
    fn test_encode_response() {
        let data = [0x62, 0xF1, 0x0A];
        let hex = BinaryEncoding::Hex;
        assert_eq!(
            encode_response(&data, hex, Some(HexStyle::PrefixedCompact)),
            "0x62F10A"
        );
        assert_eq!(
            encode_response(&data, hex, Some(HexStyle::Compact)),
            "62F10A"
        );
        assert_eq!(
            encode_response(&data, hex, Some(HexStyle::PerByte)),
            "0x62 0xF1 0x0A"
        );
        assert_eq!(encode_response(&data, hex, None), "0x62 0xF1 0x0A");
        assert_eq!(
            encode_response(&data, BinaryEncoding::Base64, Some(HexStyle::Compact)),
            "YvEK"
        );
        assert_eq!(
            encode_response(&[], hex, Some(HexStyle::PrefixedCompact)),
            ""
        );
    }
}
