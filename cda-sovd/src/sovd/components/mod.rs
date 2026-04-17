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

use crate::sovd::error::ApiError;

pub(crate) mod ecu;

crate::openapi::aide_helper::gen_path_param!(IdPathParam id String);

pub(crate) fn get_content_type_and_accept(
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
