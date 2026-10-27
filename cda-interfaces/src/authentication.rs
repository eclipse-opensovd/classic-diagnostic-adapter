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

//! Types for the UDS service Authentication (SID 0x29, ISO 14229-1 clause 10.6).

use std::{str::FromStr, time::SystemTime};

use strum_macros::IntoStaticStr;

use crate::DiagServiceError;

/// `authenticationReturnParameter` value `OwnershipVerified, AuthenticationComplete`
/// (ISO 14229-1 Table 81).
pub const RETURN_OWNERSHIP_VERIFIED_AUTHENTICATION_COMPLETE: u8 = 0x12;
/// `authenticationReturnParameter` value `CertificateVerified`
/// (ISO 14229-1 Table 81), returned when no proof of ownership is needed.
pub const RETURN_CERTIFICATE_VERIFIED: u8 = 0x13;

/// Sub-functions of the UDS service Authentication (ISO 14229-1 Table 74).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, IntoStaticStr)]
#[strum(serialize_all = "camelCase")]
pub enum AuthenticationSubFunction {
    DeAuthenticate,
    VerifyCertificateUnidirectional,
    VerifyCertificateBidirectional,
    ProofOfOwnership,
    TransmitCertificate,
    RequestChallengeForAuthentication,
    VerifyProofOfOwnershipUnidirectional,
    VerifyProofOfOwnershipBidirectional,
    AuthenticationConfiguration,
}

impl AuthenticationSubFunction {
    /// All sub-functions in ascending order of their sub-function byte.
    pub const ALL: [Self; 9] = [
        Self::DeAuthenticate,
        Self::VerifyCertificateUnidirectional,
        Self::VerifyCertificateBidirectional,
        Self::ProofOfOwnership,
        Self::TransmitCertificate,
        Self::RequestChallengeForAuthentication,
        Self::VerifyProofOfOwnershipUnidirectional,
        Self::VerifyProofOfOwnershipBidirectional,
        Self::AuthenticationConfiguration,
    ];

    /// The sub-function byte as sent on the wire.
    #[must_use]
    pub fn id(self) -> u8 {
        match self {
            Self::DeAuthenticate => 0x00,
            Self::VerifyCertificateUnidirectional => 0x01,
            Self::VerifyCertificateBidirectional => 0x02,
            Self::ProofOfOwnership => 0x03,
            Self::TransmitCertificate => 0x04,
            Self::RequestChallengeForAuthentication => 0x05,
            Self::VerifyProofOfOwnershipUnidirectional => 0x06,
            Self::VerifyProofOfOwnershipBidirectional => 0x07,
            Self::AuthenticationConfiguration => 0x08,
        }
    }

    /// The name used in the SOVD API, as defined by ISO 14229-1.
    #[must_use]
    pub fn name(self) -> &'static str {
        self.into()
    }
}

impl std::fmt::Display for AuthenticationSubFunction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for AuthenticationSubFunction {
    type Err = DiagServiceError;

    /// Parses the sub-function name case-insensitively.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|sf| sf.name().eq_ignore_ascii_case(s))
            .ok_or_else(|| {
                DiagServiceError::InvalidRequest(format!(
                    "Unknown authentication sub-function '{s}', expected one of: {}",
                    Self::ALL.map(Self::name).join(", ")
                ))
            })
    }
}

/// Authentication state of an ECU as confirmed by the ECU.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AuthenticationStatus {
    Authenticated,
    #[default]
    DeAuthenticated,
}

impl AuthenticationStatus {
    /// The value reported by the SOVD API.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Authenticated => "authenticated",
            Self::DeAuthenticated => "deAuthenticated",
        }
    }
}

/// Authentication state tracked per ECU by the CDA. Informational only,
/// the ECU remains the authority.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuthenticationState {
    /// Whether the CDA considers the ECU authenticated.
    pub status: AuthenticationStatus,
    /// The last sub-function that resulted in a positive response.
    pub last_subfunction: Option<AuthenticationSubFunction>,
    /// The point in time at which the requested `mode_expiration` elapses.
    pub expires_at: Option<SystemTime>,
}

impl AuthenticationState {
    /// A deauthenticated state without running expiration.
    /// `last_subfunction` is the last sub-function with a positive response, if any.
    #[must_use]
    pub fn deauthenticated(last_subfunction: Option<AuthenticationSubFunction>) -> Self {
        Self {
            status: AuthenticationStatus::DeAuthenticated,
            last_subfunction,
            expires_at: None,
        }
    }

    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        self.status == AuthenticationStatus::Authenticated
    }
}

/// Returns true if the sub-function and `authenticationReturnParameter` confirm
/// that the ECU authenticated the client.
#[must_use]
pub fn return_value_completes_authentication(
    sub_function: AuthenticationSubFunction,
    value: u64,
) -> bool {
    match sub_function {
        AuthenticationSubFunction::VerifyCertificateUnidirectional
        | AuthenticationSubFunction::VerifyCertificateBidirectional => {
            value == u64::from(RETURN_OWNERSHIP_VERIFIED_AUTHENTICATION_COMPLETE)
                || value == u64::from(RETURN_CERTIFICATE_VERIFIED)
        }
        AuthenticationSubFunction::ProofOfOwnership
        | AuthenticationSubFunction::VerifyProofOfOwnershipUnidirectional
        | AuthenticationSubFunction::VerifyProofOfOwnershipBidirectional => {
            value == u64::from(RETURN_OWNERSHIP_VERIFIED_AUTHENTICATION_COMPLETE)
        }
        AuthenticationSubFunction::DeAuthenticate
        | AuthenticationSubFunction::TransmitCertificate
        | AuthenticationSubFunction::RequestChallengeForAuthentication
        | AuthenticationSubFunction::AuthenticationConfiguration => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_is_case_insensitive() {
        assert_eq!(
            "VERIFYPROOFOFOWNERSHIPBIDIRECTIONAL"
                .parse::<AuthenticationSubFunction>()
                .unwrap(),
            AuthenticationSubFunction::VerifyProofOfOwnershipBidirectional
        );
        assert_eq!(
            "deauthenticate"
                .parse::<AuthenticationSubFunction>()
                .unwrap(),
            AuthenticationSubFunction::DeAuthenticate
        );
    }

    #[test]
    fn parse_unknown_is_bad_request() {
        assert!(matches!(
            "foo".parse::<AuthenticationSubFunction>(),
            Err(DiagServiceError::InvalidRequest(_))
        ));
    }

    #[test]
    fn ids_match_iso_table() {
        for (expected, sf) in (0u8..).zip(AuthenticationSubFunction::ALL) {
            assert_eq!(sf.id(), expected);
            assert_eq!(sf.name().parse::<AuthenticationSubFunction>().unwrap(), sf);
        }
    }

    #[test]
    fn names_match_iso() {
        let names = AuthenticationSubFunction::ALL.map(AuthenticationSubFunction::name);
        assert_eq!(
            names,
            [
                "deAuthenticate",
                "verifyCertificateUnidirectional",
                "verifyCertificateBidirectional",
                "proofOfOwnership",
                "transmitCertificate",
                "requestChallengeForAuthentication",
                "verifyProofOfOwnershipUnidirectional",
                "verifyProofOfOwnershipBidirectional",
                "authenticationConfiguration",
            ]
        );
    }

    #[test]
    fn completion_return_values() {
        let verify = AuthenticationSubFunction::VerifyCertificateBidirectional;
        let proof = AuthenticationSubFunction::ProofOfOwnership;
        assert!(return_value_completes_authentication(verify, 0x12));
        assert!(return_value_completes_authentication(verify, 0x13));
        assert!(return_value_completes_authentication(proof, 0x12));
        assert!(!return_value_completes_authentication(proof, 0x13));
        assert!(!return_value_completes_authentication(verify, 0x11));
        assert!(!return_value_completes_authentication(verify, 0x00));
        assert!(!return_value_completes_authentication(verify, 0x10));
        for value in [0x12, 0x13] {
            assert!(!return_value_completes_authentication(
                AuthenticationSubFunction::TransmitCertificate,
                value
            ));
        }
    }
}
