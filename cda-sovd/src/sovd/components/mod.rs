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

use cda_interfaces::diagservices::FieldParseError;
use hashbrown::HashMap;
use sovd_interfaces::error::DataError;

use crate::sovd::error::{ApiError, VendorErrorCode};

pub(crate) mod ecu;

crate::openapi::aide_helper::gen_path_param!(IdPathParam id String);

/// Wrapper Struct around [FieldParseError] to allow implementing
/// [From] for [DataError<VendorErrorCode>]
struct FieldParseErrorWrapper(FieldParseError);
impl From<FieldParseErrorWrapper> for DataError<VendorErrorCode> {
    fn from(value: FieldParseErrorWrapper) -> Self {
        let value: FieldParseError = value.0;
        Self {
            path: value.path,
            error: sovd_interfaces::error::ApiErrorResponse {
                message: "Failed to parse parameter".to_owned(),
                error_code: sovd_interfaces::error::ErrorCode::VendorSpecific,
                vendor_code: Some(VendorErrorCode::ErrorInterpretingMessage),
                parameters: Some(HashMap::from([
                    (
                        "details".to_string(),
                        serde_json::Value::String(value.error.details),
                    ),
                    (
                        "value".to_string(),
                        serde_json::Value::String(value.error.value),
                    ),
                ])),
                error_source: None,
            },
        }
    }
}

fn field_parse_errors_to_json(
    errors: impl IntoIterator<Item = FieldParseError>,
) -> Vec<serde_json::Value> {
    errors
        .into_iter()
        .filter_map(|v| {
            let mut data_error = DataError::from(FieldParseErrorWrapper(v));
            data_error.path = format!("/data{}", data_error.path);
            match serde_json::to_value(data_error) {
                Ok(v) => Some(v),
                Err(e) => {
                    log::warn!(target: "cda-sovd", "Failed to serialize data error: {e:?}");
                    None
                }
            }
        })
        .collect()
}

fn get_content_type_and_accept(
    headers: &http::HeaderMap,
) -> Result<(Option<mime::Mime>, mime::Mime), ApiError> {
    let content_type = headers
        .get(http::header::CONTENT_TYPE)
        .map(parse_mime)
        .transpose()?;
    let accept_header = match headers.get(http::header::ACCEPT) {
        Some(v) => {
            let v = parse_mime(v)?;
            if v == mime::STAR_STAR {
                content_type.clone()
            } else {
                Some(v)
            }
        }
        None => content_type.clone(),
    }
    .unwrap_or(mime::APPLICATION_JSON);
    Ok((content_type, accept_header))
}

fn parse_mime(val: &http::HeaderValue) -> Result<mime::Mime, ApiError> {
    use std::str::FromStr;

    val.to_str()
        .map_err(|e| format!("Invalid header value: {e}"))
        .and_then(|v| {
            v.split(';')
                .next()
                .map(str::trim)
                .ok_or_else(|| format!("invalid or empty accept header {val:?}"))
                .and_then(|s| {
                    mime::Mime::from_str(s)
                        .map_err(|_| format!("Failed to parse mime type {val:?}"))
                })
        })
        .map_err(ApiError::BadRequest)
}
