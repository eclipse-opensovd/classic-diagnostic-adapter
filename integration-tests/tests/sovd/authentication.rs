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

//! Integration tests for `/modes/authentication` (UDS 0x29, ISO 14229-1 clause 10.6).
//!
//! The ECU simulator accepts every certificate. A proof of ownership completes
//! the authentication if it is the ASCII name of one of the simulator's
//! authentication roles (e.g. `DEVELOPMENT`), otherwise it answers with
//! `GeneralReject`.

use std::time::Duration;

use cda_sovd::VendorErrorCode;
use http::StatusCode;
use serde_json::{Value, json};
use sovd_interfaces::components::ecu::modes::authentication;

use crate::{
    client::{self, components::Component, locks::Lock},
    sovd::ECU_FLXC1000,
    util::{
        ecusim::{self, Authentication},
        test_env::TestEnv,
    },
};

const ECU_SIM_NAME: &str = ECU_FLXC1000;
const MODE: &str = "authentication";

const DE_AUTHENTICATED: &str = "deAuthenticated";
const AUTHENTICATED: &str = "authenticated";

// authenticationReturnParameter texts of the test diagnostic description
const RETURN_REQUEST_ACCEPTED: &str = "RequestAccepted";
const RETURN_GENERAL_REJECT: &str = "GeneralReject";
const RETURN_CONFIGURATION_APCE: &str = "AuthenticationConfiguration APCE";
const RETURN_DEAUTHENTICATION_SUCCESSFUL: &str = "DeAuthentication successful";
const RETURN_OWNERSHIP_VERIFICATION_NECESSARY: &str =
    "CertificateVerified, OwnershipVerificationNecessary";
const RETURN_AUTHENTICATION_COMPLETE: &str = "OwnershipVerified, AuthenticationComplete";
const RETURN_CERTIFICATE_VERIFIED: &str = "CertificateVerified";

/// Proof of ownership accepted by the ECU simulator.
const VALID_PROOF_OF_OWNERSHIP: &str = "DEVELOPMENT";

/// Formats bytes as accepted by the CDA for byte field parameters.
fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("0x{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// 16 bytes as sent by the ECU simulator for challenges, keys and proofs:
/// `first`, followed by 0x01 .. 0x0f.
fn sequenced(first: u8) -> Vec<u8> {
    std::iter::once(first).chain(1..16).collect()
}

/// Parses a byte field returned by the CDA.
fn bytes_of(value: &Value) -> Vec<u8> {
    match value {
        Value::Array(items) => items
            .iter()
            .map(|v| {
                v.as_u64()
                    .and_then(|v| u8::try_from(v).ok())
                    .unwrap_or_else(|| panic!("Invalid byte {v} in {value}"))
            })
            .collect(),
        Value::String(s) => s
            .split_whitespace()
            .map(|b| {
                u8::from_str_radix(b.trim_start_matches("0x"), 16)
                    .unwrap_or_else(|_| panic!("Invalid byte '{b}' in {value}"))
            })
            .collect(),
        other => panic!("Unexpected byte field value: {other}"),
    }
}

fn param<'a>(response: &'a authentication::put::Response, name: &str) -> &'a Value {
    response.parameters.get(name).unwrap_or_else(|| {
        panic!(
            "Parameter '{name}' missing in response parameters: {:?}",
            response.parameters
        )
    })
}

fn assert_return_parameter(response: &authentication::put::Response, expected: &str) {
    assert_eq!(
        param(response, "authenticationReturnParameter").as_str(),
        Some(expected),
        "Unexpected authenticationReturnParameter for {}",
        response.value
    );
}

/// Sends `body` to the authentication mode of `component` as it is, so that
/// only the given fields are sent.
async fn put_authentication(
    component: &Component<'_>,
    body: &Value,
) -> client::Result<client::Response<authentication::put::Response>> {
    component.mode(MODE).put(body).await
}

/// Sends a sub-function and expects a positive response.
async fn authenticate(
    component: &Component<'_>,
    value: &str,
    parameters: Option<Value>,
    mode_expiration: Option<u64>,
) -> authentication::put::Response {
    let mut body = serde_json::Map::new();
    body.insert("value".to_owned(), json!(value));
    if let Some(parameters) = parameters {
        body.insert("parameters".to_owned(), parameters);
    }
    if let Some(expiration) = mode_expiration {
        body.insert("mode_expiration".to_owned(), json!(expiration));
    }
    let response = put_authentication(component, &Value::Object(body))
        .await
        .unwrap_or_else(|e| panic!("PUT {value} failed: {e}"))
        .expect_status(StatusCode::OK)
        .into_body();
    assert_eq!(response.id, MODE);
    assert_eq!(response.value, value);
    response
}

async fn get_authentication(component: &Component<'_>) -> authentication::get::Response {
    component
        .mode(MODE)
        .get::<authentication::get::Response>()
        .await
        .expect("GET authentication failed")
        .expect_status(StatusCode::OK)
        .into_body()
}

async fn assert_cda_state(
    component: &Component<'_>,
    status: &str,
    last_subfunction: Option<&str>,
) -> authentication::get::Response {
    let state = get_authentication(component).await;
    assert_eq!(state.id, MODE);
    assert_eq!(state.value, status, "Unexpected CDA authentication state");
    assert_eq!(
        state.last_subfunction.as_deref(),
        last_subfunction,
        "Unexpected last sub-function"
    );
    state
}

/// Checks only the status, not the last sub-function.
async fn assert_cda_status(component: &Component<'_>, status: &str) {
    let state = get_authentication(component).await;
    assert_eq!(state.value, status, "Unexpected CDA authentication state");
}

async fn assert_sim_state(runtime: &TestEnv, expected: &Authentication) {
    let state = ecusim::get_ecu_state(&runtime.ecu_sim, ECU_SIM_NAME)
        .await
        .expect("Failed to get ECU sim state");
    assert_eq!(
        state.authentication.as_ref(),
        Some(expected),
        "Unexpected ECU sim authentication state"
    );
}

/// Acquires the ECU lock.
async fn acquire_lock(component: &Component<'_>) -> Lock {
    component
        .locks()
        .create(Duration::from_secs(60))
        .await
        .expect("Failed to create lock")
        .expect_status(StatusCode::CREATED)
        .into_body()
}

async fn release_lock(lock: Lock) {
    lock.release()
        .await
        .expect("Failed to release lock")
        .expect_status(StatusCode::NO_CONTENT);
}

/// `proofOfOwnership` with the given proof, expecting a positive response.
async fn proof_of_ownership(
    component: &Component<'_>,
    proof: &str,
    mode_expiration: Option<u64>,
) -> authentication::put::Response {
    authenticate(
        component,
        "proofOfOwnership",
        Some(json!({
            "proofOfOwnershipClient": hex(proof.as_bytes()),
            "ephemeralPublicKeyClient": hex(&[0xaa, 0xbb]),
        })),
        mode_expiration,
    )
    .await
}

/// Authentication with PKI certificate exchange, unidirectional
/// (ISO 14229-1 clause 10.6.3): `verifyCertificateUnidirectional`,
/// `proofOfOwnership`, `deAuthenticate`. Also checks the UDS encoding of the
/// leading length parameters on the bus.
///
/// [[ itest~sovd-api-authentication-modes-pki, Authentication with PKI certificate exchange, itest ]]
#[tokio::test]
async fn authentication_with_pki_certificate_exchange() {
    let runtime = TestEnv::builder().await.unwrap();
    let ecu = runtime.client().component(ECU_FLXC1000);
    let lock = acquire_lock(&ecu).await;

    assert_cda_status(&ecu, DE_AUTHENTICATED).await;
    assert_sim_state(&runtime, &Authentication::Unauthenticated).await;

    let recorder = runtime
        .record(ECU_SIM_NAME)
        .await
        .expect("Failed to start recording");

    let verify = authenticate(
        &ecu,
        "verifyCertificateUnidirectional",
        Some(json!({
            "communicationConfiguration": 0,
            "certificateClient": hex(&[0xc0, 0xc1, 0xc2]),
            "challengeClient": hex(&[0xd0, 0xd1]),
        })),
        None,
    )
    .await;
    assert_return_parameter(&verify, RETURN_OWNERSHIP_VERIFICATION_NECESSARY);
    assert_eq!(bytes_of(param(&verify, "challengeServer")), sequenced(0x01));
    assert_eq!(
        bytes_of(param(&verify, "ephemeralPublicKeyServer")),
        sequenced(0x02)
    );
    // The certificate alone does not complete the authentication.
    assert_cda_state(
        &ecu,
        DE_AUTHENTICATED,
        Some("verifyCertificateUnidirectional"),
    )
    .await;

    let proof = proof_of_ownership(&ecu, VALID_PROOF_OF_OWNERSHIP, None).await;
    assert_return_parameter(&proof, RETURN_AUTHENTICATION_COMPLETE);
    assert_eq!(bytes_of(param(&proof, "sessionKeyInfo")), sequenced(0x01));

    let frames = recorder.stop().await.expect("Failed to stop recording");
    // SID, sub-function, communicationConfiguration, then length + value
    // for certificateClient and challengeClient
    let expected_verify = "2901000003c0c1c20002d0d1";
    let expected_proof = format!(
        "2903000b{}0002aabb",
        hex(VALID_PROOF_OF_OWNERSHIP.as_bytes())
            .replace("0x", "")
            .replace(' ', "")
    );
    for expected in [expected_verify, expected_proof.as_str()] {
        assert!(
            frames.iter().any(|f| f.eq_ignore_ascii_case(expected)),
            "Expected request {expected} not found in {frames:?}"
        );
    }

    let state = assert_cda_state(&ecu, AUTHENTICATED, Some("proofOfOwnership")).await;
    assert!(
        state.expires_at.is_none(),
        "No expiration requested, but got {:?}",
        state.expires_at
    );
    assert_sim_state(&runtime, &Authentication::Development).await;

    let deauth = authenticate(&ecu, "deAuthenticate", None, None).await;
    assert_return_parameter(&deauth, RETURN_DEAUTHENTICATION_SUCCESSFUL);
    assert_cda_state(&ecu, DE_AUTHENTICATED, Some("deAuthenticate")).await;
    assert_sim_state(&runtime, &Authentication::Unauthenticated).await;

    release_lock(lock).await;
}

/// Authentication with PKI certificate exchange, bidirectional, and
/// `transmitCertificate`, which completes the authentication on its own
/// in the ECU simulator.
///
/// [[ itest~sovd-api-authentication-modes-pki-bidirectional, Bidirectional certificate exchange and transmitCertificate, itest ]]
#[tokio::test]
async fn authentication_bidirectional_and_transmit_certificate() {
    let runtime = TestEnv::builder().await.unwrap();
    let ecu = runtime.client().component(ECU_FLXC1000);
    let lock = acquire_lock(&ecu).await;

    let verify = authenticate(
        &ecu,
        "verifyCertificateBidirectional",
        Some(json!({
            "communicationConfiguration": 0,
            "certificateClient": hex(&[0xc0, 0xc1, 0xc2]),
            "challengeClient": hex(&[0xd0, 0xd1]),
        })),
        None,
    )
    .await;
    assert_return_parameter(&verify, RETURN_OWNERSHIP_VERIFICATION_NECESSARY);
    for (name, first) in [
        ("challengeServer", 0x01),
        ("certificateServer", 0x02),
        ("ephemeralPublicKeyServer", 0x03),
        ("proofOfOwnershipServer", 0x04),
    ] {
        assert_eq!(bytes_of(param(&verify, name)), sequenced(first), "{name}");
    }
    assert_cda_state(
        &ecu,
        DE_AUTHENTICATED,
        Some("verifyCertificateBidirectional"),
    )
    .await;

    let transmit = authenticate(
        &ecu,
        "transmitCertificate",
        Some(json!({
            "certificateEvaluationId": 0x0102,
            "certificateData": hex(&[0xe0, 0xe1, 0xe2, 0xe3]),
        })),
        None,
    )
    .await;
    assert_return_parameter(&transmit, RETURN_CERTIFICATE_VERIFIED);
    assert_cda_state(&ecu, DE_AUTHENTICATED, Some("transmitCertificate")).await;
    assert_sim_state(&runtime, &Authentication::Unauthenticated).await;

    // Certificate transmission did not authenticate the ECU, so cleanup has
    // no authenticated state to reset.
    release_lock(lock).await;
    assert_cda_state(&ecu, DE_AUTHENTICATED, Some("transmitCertificate")).await;
}

/// Challenge-response authentication (ISO 14229-1 clause 10.6.3):
/// `authenticationConfiguration`, `requestChallengeForAuthentication`,
/// `verifyProofOfOwnershipUnidirectional` and
/// `verifyProofOfOwnershipBidirectional`.
///
/// [[ itest~sovd-api-authentication-modes-challenge-response, Challenge-response authentication, itest ]]
#[tokio::test]
async fn authentication_with_challenge_response() {
    let runtime = TestEnv::builder().await.unwrap();
    let ecu = runtime.client().component(ECU_FLXC1000);
    let lock = acquire_lock(&ecu).await;

    let configuration = authenticate(&ecu, "authenticationConfiguration", None, None).await;
    assert_return_parameter(&configuration, RETURN_CONFIGURATION_APCE);

    let algorithm_indicator = hex(&[0x06; 16]);
    let challenge = authenticate(
        &ecu,
        "requestChallengeForAuthentication",
        Some(json!({
            "communicationConfiguration": 0,
            "algorithmIndicator": algorithm_indicator,
        })),
        None,
    )
    .await;
    assert_return_parameter(&challenge, RETURN_REQUEST_ACCEPTED);
    for (name, first) in [
        ("algorithmIndicator", 0x01),
        ("challengeServer", 0x02),
        ("neededAdditionalParameter", 0x03),
    ] {
        assert_eq!(
            bytes_of(param(&challenge, name)),
            sequenced(first),
            "{name}"
        );
    }
    assert_cda_state(
        &ecu,
        DE_AUTHENTICATED,
        Some("requestChallengeForAuthentication"),
    )
    .await;

    let verify_parameters = |proof: &str| {
        json!({
            "algorithmIndicator": algorithm_indicator,
            "proofOfOwnershipClient": hex(proof.as_bytes()),
            "challengeClient": hex(&[0xd0, 0xd1]),
            "additionalParameter": hex(&[0xa0]),
        })
    };

    let unidirectional = authenticate(
        &ecu,
        "verifyProofOfOwnershipUnidirectional",
        Some(verify_parameters("AFTER_SALES")),
        None,
    )
    .await;
    assert_return_parameter(&unidirectional, RETURN_AUTHENTICATION_COMPLETE);
    assert_eq!(
        bytes_of(param(&unidirectional, "sessionKeyInfo")),
        sequenced(0x02)
    );
    assert_cda_state(
        &ecu,
        AUTHENTICATED,
        Some("verifyProofOfOwnershipUnidirectional"),
    )
    .await;
    assert_sim_state(&runtime, &Authentication::AfterSales).await;

    let bidirectional = authenticate(
        &ecu,
        "verifyProofOfOwnershipBidirectional",
        Some(verify_parameters("AFTER_MARKET")),
        None,
    )
    .await;
    assert_return_parameter(&bidirectional, RETURN_AUTHENTICATION_COMPLETE);
    for (name, first) in [("proofOfOwnershipServer", 0x02), ("sessionKeyInfo", 0x03)] {
        assert_eq!(
            bytes_of(param(&bidirectional, name)),
            sequenced(first),
            "{name}"
        );
    }
    assert_cda_state(
        &ecu,
        AUTHENTICATED,
        Some("verifyProofOfOwnershipBidirectional"),
    )
    .await;
    assert_sim_state(&runtime, &Authentication::AfterMarket).await;

    release_lock(lock).await;
    assert_sim_state(&runtime, &Authentication::Unauthenticated).await;
}

/// A positive response that does not complete the authentication
/// (`GeneralReject`) leaves the ECU deauthenticated.
///
/// [[ itest~sovd-api-authentication-modes-rejected, Rejected proof of ownership, itest ]]
#[tokio::test]
async fn authentication_rejected_proof_of_ownership() {
    let runtime = TestEnv::builder().await.unwrap();
    let ecu = runtime.client().component(ECU_FLXC1000);
    let lock = acquire_lock(&ecu).await;

    let proof = proof_of_ownership(&ecu, "INVALID", None).await;
    assert_return_parameter(&proof, RETURN_GENERAL_REJECT);
    assert_cda_state(&ecu, DE_AUTHENTICATED, Some("proofOfOwnership")).await;
    assert_sim_state(&runtime, &Authentication::Unauthenticated).await;

    release_lock(lock).await;
}

/// `mode_expiration` sends deAuthenticate when it elapses.
///
/// [[ itest~sovd-api-authentication-modes-expiration, Authentication mode expiration, itest ]]
#[tokio::test]
async fn authentication_mode_expiration() {
    let runtime = TestEnv::builder().await.unwrap();
    let ecu = runtime.client().component(ECU_FLXC1000);
    let lock = acquire_lock(&ecu).await;

    let expiration = 2u64;
    proof_of_ownership(&ecu, VALID_PROOF_OF_OWNERSHIP, Some(expiration)).await;
    let state = assert_cda_state(&ecu, AUTHENTICATED, Some("proofOfOwnership")).await;
    assert!(state.expires_at.is_some(), "Expected x-sovd2uds-expires-at");
    assert_sim_state(&runtime, &Authentication::Development).await;

    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(expiration + 2)).await;

    let state = assert_cda_state(&ecu, DE_AUTHENTICATED, Some("deAuthenticate")).await;
    assert!(state.expires_at.is_none());
    assert_sim_state(&runtime, &Authentication::Unauthenticated).await;

    release_lock(lock).await;
}

/// A negative response of the ECU is reported with the NRC and leaves the
/// tracked state unchanged (ISO 14229-1 clause 10.6.4).
///
/// [[ itest~sovd-api-authentication-modes-nrc, Negative response to an authentication request, itest ]]
#[tokio::test]
async fn authentication_negative_response() {
    const INTERCEPTOR: &str = "authentication_nrc";

    let runtime = TestEnv::builder().await.unwrap();
    let ecu = runtime.client().component(ECU_FLXC1000);
    let lock = acquire_lock(&ecu).await;

    proof_of_ownership(&ecu, VALID_PROOF_OF_OWNERSHIP, None).await;
    assert_cda_state(&ecu, AUTHENTICATED, Some("proofOfOwnership")).await;

    // NRC 0x53 certificateVerificationFailed_InvalidSignature
    ecusim::set_interceptor(
        &runtime.ecu_sim,
        "FLXC1000",
        INTERCEPTOR,
        "2901[]",
        "7f2953",
    )
    .await
    .expect("Failed to install interceptor");
    let result = put_authentication(
        &ecu,
        &json!({
            "value": "verifyCertificateUnidirectional",
            "parameters": {
                "communicationConfiguration": 0,
                "certificateClient": hex(&[0xc0]),
                "challengeClient": hex(&[0xd0]),
            },
        }),
    )
    .await;
    ecusim::clear_interceptor(&runtime.ecu_sim, "FLXC1000", INTERCEPTOR)
        .await
        .expect("Failed to remove interceptor");
    let Err(error) = result else {
        panic!("Expected the negative response to be reported as an error");
    };
    assert_eq!(error.status(), Some(StatusCode::BAD_GATEWAY), "{error}");
    let nrc = error
        .api_error::<VendorErrorCode>()
        .and_then(|body| body.parameters)
        .and_then(|parameters| parameters.get("NRC").and_then(Value::as_u64));
    assert_eq!(nrc, Some(0x53), "Expected NRC 0x53 in {error}");

    assert_cda_state(&ecu, AUTHENTICATED, Some("proofOfOwnership")).await;
    assert_sim_state(&runtime, &Authentication::Development).await;

    // Releasing the lock still deauthenticates the ECU.
    release_lock(lock).await;
    assert_sim_state(&runtime, &Authentication::Unauthenticated).await;
}

/// Invalid requests are rejected without communicating with the ECU, and
/// `PUT` requires the ECU lock.
///
/// [[ itest~sovd-api-authentication-modes-invalid, Invalid authentication requests, itest ]]
#[tokio::test]
async fn authentication_invalid_requests() {
    let runtime = TestEnv::builder().await.unwrap();
    let ecu = runtime.client().component(ECU_FLXC1000);

    // Without a lock
    let error = put_authentication(&ecu, &json!({ "value": "authenticationConfiguration" }))
        .await
        .expect_err("Expected rejection without lock");
    assert_eq!(error.status(), Some(StatusCode::CONFLICT), "{error}");

    let lock = acquire_lock(&ecu).await;

    for body in [
        json!({ "value": "unknownSubFunction" }),
        json!({ "value": "deAuthenticate", "mode_expiration": 10 }),
    ] {
        let error = put_authentication(&ecu, &body)
            .await
            .expect_err("Expected the request to be rejected");
        assert_eq!(
            error.status(),
            Some(StatusCode::BAD_REQUEST),
            "Expected BAD_REQUEST for {body}: {error}"
        );
    }
    assert_cda_status(&ecu, DE_AUTHENTICATED).await;

    release_lock(lock).await;
}
