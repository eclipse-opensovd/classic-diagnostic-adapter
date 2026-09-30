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
use std::collections::HashSet;

use cda_sovd::VendorErrorCode;
use http::StatusCode;
use serde::{Deserialize, Serialize};
use sovd_interfaces::{
    common::modes::DTC_SETTING_ID,
    components::ecu::modes::dtcsetting,
    error::{ApiErrorResponse, ErrorCode},
};

use crate::{
    client::{
        self,
        components::{Component, modes::ModeHandle},
    },
    util::TestingError,
};

mod custom_routes;
mod data;
mod deferred_init;
mod ecu;
mod faults;
mod flash_download;
mod locks;
mod operations;
mod read_only_partition;
mod runtimefiles;
mod tester_present;
mod version_endpoint;

pub(crate) use crate::util::endpoints::{
    ECU_FLXC1000, ECU_FSNR2000, ECU_HOVR4000, ECU_JGWT5000, ECU_TMCC3000, FUNCTIONAL_GROUP,
};

/// Sets `mode` with `request`, and checks that the CDA rejects it with a
/// `400 Bad Request` with an `invalid-parameter` vendor code, whose
/// `possiblevalues` are exactly `expected_possible_values`.
///
/// # Errors
/// Returns an error if the error body does not have the expected shape.
pub(crate) async fn validate_invalid_parameter_error<S: Serialize>(
    mode: &ModeHandle<'_>,
    request: &S,
    expected_possible_values: &[&str],
) -> Result<(), TestingError> {
    #[derive(Deserialize)]
    struct InvalidParameterDetails {
        details: String,
        possiblevalues: Vec<String>,
    }

    let error = mode
        .put::<serde_json::Value>(request)
        .await
        .expect_err("the CDA accepted an invalid parameter");
    assert_eq!(error.status(), Some(StatusCode::BAD_REQUEST), "{error}");
    let error_response: ApiErrorResponse<VendorErrorCode> = error
        .api_error()
        .ok_or_else(|| TestingError::InvalidData(format!("not an SOVD error: {error}")))?;

    assert_eq!(
        error_response.message, "The parameter value is not valid",
        "Unexpected error message: {}",
        error_response.message
    );
    assert_eq!(
        error_response.error_code,
        ErrorCode::VendorSpecific,
        "Unexpected error_code: {:?}",
        error_response.error_code
    );
    assert_eq!(
        error_response.vendor_code,
        Some(VendorErrorCode::InvalidParameter),
        "Unexpected vendor_code: {:?}",
        error_response.vendor_code
    );

    let params: InvalidParameterDetails = serde_json::from_value(
        serde_json::to_value(
            error_response
                .parameters
                .expect("Expected 'parameters' in error response"),
        )
        .expect("Invalid parameters structure"),
    )
    .expect("Failed to parse InvalidParameterDetails from parameters");

    assert_eq!(params.details, "value", "Unexpected details value");

    let actual_values: HashSet<String> = params
        .possiblevalues
        .iter()
        .map(|s| s.to_lowercase())
        .collect();
    let expected_values: HashSet<String> = expected_possible_values
        .iter()
        .map(|s| s.to_lowercase())
        .collect();
    assert_eq!(
        actual_values, expected_values,
        "Possible values mismatch, Expected: {expected_values:?}, Actual: {actual_values:?}"
    );

    Ok(())
}

/// Sets the DTC setting of `component` to `value`.
///
/// # Errors
/// See [`ModeHandle::put`].
pub(crate) async fn set_dtc_setting(
    component: &Component<'_>,
    value: &str,
) -> client::Result<client::Response<dtcsetting::put::Response>> {
    component
        .mode(DTC_SETTING_ID)
        .put(&dtcsetting::put::Request {
            value: value.to_owned(),
            parameters: None,
        })
        .await
}

/// Computes the security access key from a seed response.
///
/// The CDA returns the raw UDS response in the seed, including service ID and
/// prefix bytes which must be skipped. The ECU simulator expects each seed byte
/// to be incremented by 13 (wrapping), matching its Kotlin implementation.
#[allow(
    clippy::cast_sign_loss,
    reason = "i8 cast to u8 for formatting; wrapping semantics intended"
)]
#[allow(
    clippy::cast_possible_wrap,
    reason = "u8 wrapping_add result cast to i8 for formatting"
)]
pub(crate) fn compute_security_key(seed_response: &str) -> String {
    seed_response
        .split_whitespace()
        .filter_map(|s| u8::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .map(|byte| byte.wrapping_add(13) as i8)
        .map(|byte| format!("0x{:02x}", byte as u8))
        .collect::<Vec<_>>()
        .join(" ")
}
