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
use std::collections::HashSet;

use cda_sovd::VendorErrorCode;
use http::{HeaderMap, Method, StatusCode};
use opensovd_cda_lib::config::configfile::Configuration;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sovd_interfaces::{
    components::ecu::{faults::Fault, modes::dtcsetting},
    error::{ApiErrorResponse, ErrorCode},
};

use crate::util::{
    TestingError,
    http::{
        QueryParams, extract_field_from_json, response_to_json, response_to_t, send_cda_request,
    },
};

mod custom_routes;
mod data;
mod ecu;
mod faults;
mod flash_download;
mod locks;
mod operations;
mod version_endpoint;

pub(crate) const ECU_FLXC1000_ENDPOINT: &str = "components/flxc1000";
pub(crate) const ECU_FLXCNG1000_ENDPOINT: &str = "components/flxcng1000";

pub(crate) async fn put_mode<T: DeserializeOwned, S: Serialize>(
    config: &Configuration,
    headers: &HeaderMap,
    ecu_endpoint: &str,
    sub_path: &str,
    request: S,
    excepted_status: StatusCode,
) -> Result<Option<T>, TestingError> {
    let request_body = serde_json::to_string(&request)
        .map_err(|e| TestingError::InvalidData(format!("Failed to serialize request body: {e}")))?;
    let http_response = send_cda_request(
        config,
        &format!("{ecu_endpoint}/modes/{sub_path}"),
        excepted_status,
        Method::PUT,
        Some(&request_body),
        Some(headers),
        None,
    )
    .await?;
    match response_to_t(&http_response) {
        Ok(v) => Ok(Some(v)),
        Err(_) if excepted_status != StatusCode::OK => Ok(None),
        Err(e) => Err(e),
    }
}

/// Sends a mode PUT request with the given body and validates that the response
/// is a `400 Bad Request` with an `invalid-parameter` vendor code and that
/// the `possiblevalues` field contains exactly the expected values.
pub(crate) async fn validate_invalid_parameter_error<S: Serialize>(
    config: &Configuration,
    headers: &HeaderMap,
    ecu_endpoint: &str,
    sub_path: &str,
    request: S,
    expected_possible_values: &[&str],
) -> Result<(), TestingError> {
    #[derive(Deserialize)]
    struct InvalidParameterDetails {
        details: String,
        possiblevalues: Vec<String>,
    }

    let error_response: ApiErrorResponse<VendorErrorCode> = put_mode(
        config,
        headers,
        ecu_endpoint,
        sub_path,
        request,
        StatusCode::BAD_REQUEST,
    )
    .await?
    .expect("Expected error response body for BAD_REQUEST");

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

pub(crate) async fn set_dtc_setting(
    value: &str,
    config: &Configuration,
    headers: &HeaderMap,
    ecu_endpoint: &str,
    expected_status: StatusCode,
) -> Result<Option<dtcsetting::put::Response>, TestingError> {
    put_mode(
        config,
        headers,
        ecu_endpoint,
        "dtcsetting",
        dtcsetting::put::Request {
            value: value.to_owned(),
            parameters: None,
        },
        expected_status,
    )
    .await
}

pub(crate) async fn get_faults(
    config: &Configuration,
    headers: &HeaderMap,
    ecu_endpoint: &str,
) -> Result<Vec<Fault>, TestingError> {
    let path = format!("{ecu_endpoint}/faults");

    let response = send_cda_request(
        config,
        &path,
        StatusCode::OK,
        Method::GET,
        None,
        Some(headers),
        None,
    )
    .await
    .expect("Failed to get faults");

    let json = response_to_json(&response)?;
    extract_field_from_json::<Vec<Fault>>(&json, "items")
}

pub(crate) async fn get_fault(
    config: &Configuration,
    headers: &HeaderMap,
    ecu_endpoint: &str,
    fault_code: &str,
) -> Result<Fault, TestingError> {
    let path = format!("{ecu_endpoint}/faults/{fault_code}");

    let response = send_cda_request(
        config,
        &path,
        StatusCode::OK,
        Method::GET,
        None,
        Some(headers),
        None,
    )
    .await
    .expect("Failed to get faults");

    let json = response_to_json(&response)?;
    extract_field_from_json::<Fault>(&json, "item")
}

pub(crate) async fn delete_fault(
    config: &Configuration,
    headers: &HeaderMap,
    ecu_endpoint: &str,
    fault_code: &str,
    expected_status: StatusCode,
) -> Result<(), TestingError> {
    let path = format!("{ecu_endpoint}/faults/{fault_code}");
    send_cda_request(
        config,
        &path,
        expected_status,
        Method::DELETE,
        None,
        Some(headers),
        None,
    )
    .await?;
    Ok(())
}

pub(crate) async fn delete_all_faults(
    config: &Configuration,
    headers: &HeaderMap,
    ecu_endpoint: &str,
    expected_status: StatusCode,
) -> Result<(), TestingError> {
    let path = format!("{ecu_endpoint}/faults");
    send_cda_request(
        config,
        &path,
        expected_status,
        Method::DELETE,
        None,
        Some(headers),
        None,
    )
    .await?;
    Ok(())
}

pub(crate) async fn delete_all_faults_with_scope(
    config: &Configuration,
    headers: &HeaderMap,
    ecu_endpoint: &str,
    scope: &str,
    expected_status: StatusCode,
) -> Result<(), TestingError> {
    let path = format!("{ecu_endpoint}/faults?scope={scope}");
    send_cda_request(
        config,
        &path,
        expected_status,
        Method::DELETE,
        None,
        Some(headers),
        None,
    )
    .await?;
    Ok(())
}

pub(crate) async fn delete_fault_with_scope(
    config: &Configuration,
    headers: &HeaderMap,
    ecu_endpoint: &str,
    fault_code: &str,
    scope: &str,
    expected_status: StatusCode,
) -> Result<(), TestingError> {
    let path = format!("{ecu_endpoint}/faults/{fault_code}?scope={scope}");
    send_cda_request(
        config,
        &path,
        expected_status,
        Method::DELETE,
        None,
        Some(headers),
        None,
    )
    .await?;
    Ok(())
}

/// Computes the security access key from a seed response.
///
/// The CDA returns the raw UDS response in the seed, including service ID and
/// prefix bytes which must be skipped. The ECU simulator expects each seed byte
/// to be incremented by 13 (wrapping), matching its Kotlin implementation.
#[allow(clippy::cast_sign_loss)]
#[allow(clippy::cast_possible_wrap)]
pub(crate) fn compute_security_key(seed_response: &str) -> String {
    seed_response
        .split_whitespace()
        .skip(3)
        .filter_map(|s| u8::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .map(|byte| byte.wrapping_add(13) as i8)
        .map(|byte| format!("0x{:02x}", byte as u8))
        .collect::<Vec<_>>()
        .join(" ")
}

pub(crate) async fn get_ecu_component(
    config: &Configuration,
    ecu_endpoint: &str,
    expected_status: StatusCode,
    query_params: Option<&QueryParams>,
) -> Result<serde_json::Value, TestingError> {
    let response = send_cda_request(
        config,
        ecu_endpoint,
        expected_status,
        Method::GET,
        None,
        None,
        query_params,
    )
    .await
    .expect("Failed to get ecu component");

    // Returns the json instead of Ecu, because the deserialization for SdSdg deserializes
    // everything as Sd, we also fail on silent changes in the interface, which is desirable
    response_to_json(&response)
}

pub(crate) fn hook_cleanup<F, Fut>(cleanup_fn: F)
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + 'static,
{
    std::panic::set_hook(Box::new(move |_| {
        // Create a new runtime to drive the future to completion.
        // Don't use Handle::current().block_on() here - it will
        // deadlock if the panic happens on an async worker thread.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build runtime in panic hook");
        rt.block_on(cleanup_fn());
    }));
}
