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
use http::{Method, StatusCode};
use opensovd_cda_lib::config::configfile::Configuration;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sovd_interfaces::{
    components::ecu::{
        faults::{Fault, id::get::ExtendedFault},
        modes::dtcsetting,
    },
    error::{ApiErrorResponse, ErrorCode},
};

use crate::util::{
    TestingError,
    http::{
        CdaClient, QueryParams, extract_field_from_json, response_to_json, response_to_t,
        send_authenticated_cda_request, send_cda_request,
    },
    test_env::TestEnv,
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
    COMPONENTS_FLXC1000_BASE, COMPONENTS_FLXC1000_DATA, COMPONENTS_FLXC1000_DATA_VINDATAIDENTIFIER,
    COMPONENTS_FLXCNG1000_BASE, COMPONENTS_FSNR2000_BASE, COMPONENTS_HOVR4000_BASE,
    COMPONENTS_JGWT5000_BASE, COMPONENTS_TMCC3000_BASE, ECU_FLXC1000, ECU_FSNR2000, ECU_HOVR4000,
    ECU_JGWT5000, ECU_TMCC3000, FUNCTIONS_FUNCTIONALGROUPS_DOIP_BASE,
};

/// Puts `request` to the mode `sub_path` of the ECU at `ecu_endpoint`.
///
/// # Errors
/// Returns an error if the request fails or the status is not
/// `excepted_status`.
pub(crate) async fn put_mode<T: DeserializeOwned, S: Serialize>(
    cda: &impl CdaClient,
    ecu_endpoint: &str,
    sub_path: &str,
    request: S,
    excepted_status: StatusCode,
) -> Result<Option<T>, TestingError> {
    let request_body = serde_json::to_string(&request)
        .map_err(|e| TestingError::InvalidData(format!("Failed to serialize request body: {e}")))?;
    let http_response = send_authenticated_cda_request(
        cda,
        &format!("{ecu_endpoint}/modes/{sub_path}"),
        excepted_status,
        Method::PUT,
        Some(&request_body),
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
    test_env: &TestEnv,
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
        test_env,
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
    cda: &impl CdaClient,
    ecu_endpoint: &str,
    expected_status: StatusCode,
) -> Result<Option<dtcsetting::put::Response>, TestingError> {
    put_mode(
        cda,
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
    test_env: &TestEnv,
    ecu_endpoint: &str,
) -> Result<Vec<Fault>, TestingError> {
    let path = format!("{ecu_endpoint}/faults");

    let response =
        send_authenticated_cda_request(test_env, &path, StatusCode::OK, Method::GET, None, None)
            .await
            .expect("Failed to get faults");

    let json = response_to_json(&response)?;
    extract_field_from_json::<Vec<Fault>>(&json, "items")
}

pub(crate) async fn get_fault(
    test_env: &TestEnv,
    ecu_endpoint: &str,
    fault_code: &str,
) -> Result<Fault, TestingError> {
    let json = do_get_fault(test_env, ecu_endpoint, fault_code).await?;
    extract_field_from_json::<Fault>(&json, "item")
}

pub(crate) async fn get_extended_fault(
    test_env: &TestEnv,
    ecu_endpoint: &str,
    fault_code: &str,
) -> Result<ExtendedFault<VendorErrorCode>, TestingError> {
    let json = do_get_fault(test_env, ecu_endpoint, fault_code).await?;

    serde_json::from_value(json)
        .ok()
        .ok_or_else(|| {
            format!(
                "Failed to deserialize response into: {}",
                std::any::type_name::<ExtendedFault<VendorErrorCode>>()
            )
        })
        .map_err(TestingError::InvalidData)
}

// Executes the GET method to the ECUSim for the specified DTC
async fn do_get_fault(
    test_env: &TestEnv,
    ecu_endpoint: &str,
    fault_code: &str,
) -> Result<serde_json::Value, TestingError> {
    let path = format!("{ecu_endpoint}/faults/{fault_code}");

    let response =
        send_authenticated_cda_request(test_env, &path, StatusCode::OK, Method::GET, None, None)
            .await
            .expect("Failed to get faults");

    response_to_json(&response)
}

/// Deletes the fault `fault_code` of the ECU at `ecu_endpoint`, or all of its
/// faults, optionally limited to `scope`.
///
/// # Errors
/// Returns an error if the request fails or the status is not
/// `expected_status`.
pub(crate) async fn delete_faults(
    test_env: &TestEnv,
    ecu_endpoint: &str,
    fault_code: Option<&str>,
    scope: Option<&str>,
    expected_status: StatusCode,
) -> Result<(), TestingError> {
    let path = match fault_code {
        Some(code) => format!("{ecu_endpoint}/faults/{code}"),
        None => format!("{ecu_endpoint}/faults"),
    };
    let query = scope.map(|scope| {
        QueryParams(
            [("scope".to_owned(), scope.to_owned())]
                .into_iter()
                .collect(),
        )
    });
    send_authenticated_cda_request(
        test_env,
        &path,
        expected_status,
        Method::DELETE,
        None,
        query.as_ref(),
    )
    .await?;
    Ok(())
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

/// Reads the SOVD component of the ECU at `ecu_endpoint`.
///
/// # Errors
/// Returns an error if the request fails or the response cannot be parsed.
pub(crate) async fn ecu_status(
    test_env: &TestEnv,
    ecu_endpoint: &str,
) -> Result<sovd_interfaces::components::ecu::get::Response, TestingError> {
    let http_response = send_authenticated_cda_request(
        test_env,
        ecu_endpoint,
        StatusCode::OK,
        Method::GET,
        None,
        None,
    )
    .await?;
    response_to_t(&http_response)
}

/// Triggers the variant detection of the ECU at `ecu_endpoint` (an
/// authenticated `PUT`, handled by `UdsVariant::detect_variant`).
///
/// A direct UDS-level probe against one ECU, not
/// `CommunicationPlugin::trigger_detection()`, which has no HTTP-reachable path
/// yet. `variant_detection` does not gate it, because it only controls the
/// automatic whole-vehicle variant detection run as part of an activation.
///
/// # Errors
/// Returns an error if the request fails or is not answered with `201`.
pub(crate) async fn force_variant_detection(
    test_env: &TestEnv,
    ecu_endpoint: &str,
) -> Result<(), TestingError> {
    send_authenticated_cda_request(
        test_env,
        ecu_endpoint,
        StatusCode::CREATED,
        Method::PUT,
        None,
        None,
    )
    .await?;
    Ok(())
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
