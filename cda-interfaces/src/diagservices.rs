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

use crate::{
    DataParseError, DiagComm, DiagServiceError, HashMap,
    datatypes::{DtcField, DtcRecord},
    util,
};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DiagServiceResponseType {
    Positive,
    Negative,
}

pub struct MappedNRC {
    pub code: Option<u8>,
    pub description: Option<String>,
    pub sid: Option<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldParseError {
    pub path: String,
    pub error: DataParseError,
}

/// Wrapping struct for mapping a Response to JSON
///
/// The fields contain the mapped response and a list
/// of errors for fields where the data could not be
/// interpreted.
#[derive(Debug, PartialEq, Eq)]
pub struct DiagServiceJsonResponse {
    pub data: serde_json::Value,
    pub errors: Vec<FieldParseError>,
}

pub trait DiagServiceResponse: Sized + Send + Sync + 'static + Clone {
    /// Build a positive, empty response representing a request that the ECU
    /// legitimately did not answer because the `suppressPosRspMsgIndicationBit`
    /// (SPRMIB) was set. Such a response is a success (`response_type` is
    /// `Positive`) with no payload (`is_empty` is `true`), so callers render it
    /// as an empty/no-content result rather than an error.
    ///
    /// The result is intentionally indistinguishable from a normally-decoded
    /// empty positive response (see [`is_empty`](Self::is_empty)): both flow
    /// through the same consumer paths to a `204 No Content`.
    fn empty_positive(service: DiagComm) -> Self;
    /// Returns `true` if the response carries no payload data.
    ///
    /// This is a predicate over *any* response, regardless of how it was
    /// produced: it is `true` both for a response that was decoded from a real
    /// but payload-less positive reply (e.g. a bare `ECUReset` positive ack, or
    /// a service whose response defines no data parameters) and for a response
    /// synthesized via [`empty_positive`](Self::empty_positive) when the ECU
    /// legitimately sent nothing (SPRMIB). These two cases are intentionally
    /// indistinguishable here: consumers (notably the SOVD HTTP layer) use this,
    /// together with [`response_type`](Self::response_type) being `Positive`, to
    /// render a `204 No Content` result in either case.
    fn is_empty(&self) -> bool;
    fn service_name(&self) -> String;
    fn response_type(&self) -> DiagServiceResponseType;
    fn get_raw(&self) -> &[u8];
    /// Convert the response into a JSON representation.
    /// # Errors
    /// Returns `DiagServiceError` if the conversion fails, depending on what went wrong exactly.
    fn into_json(self) -> Result<DiagServiceJsonResponse, DiagServiceError>;
    /// Map the response as a Negative Response Code (NRC).
    /// # Errors
    /// Returns `String` if on failure to map the response as NRC.
    fn as_nrc(&self) -> Result<MappedNRC, DiagServiceError>;

    /// Extract data trouble codes from the response, if any.
    /// # Errors
    /// Returns `DiagServiceError` if unable to extract DTCs, for example if
    /// this is used on a response that is not mapped.
    fn get_dtcs(&self) -> Result<Vec<(DtcField, DtcRecord)>, DiagServiceError>;
}

#[derive(Debug)]
pub enum UdsPayloadData {
    Raw(Vec<u8>),
    ParameterMap(HashMap<String, serde_json::Value>),
}

impl std::fmt::Display for UdsPayloadData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UdsPayloadData::Raw(items) => write!(f, "Raw: {}", util::tracing::print_hex(items, 10)),
            UdsPayloadData::ParameterMap(hash_map) => {
                let dbg = format!("{hash_map:?}");
                write!(f, "ParameterMap: ")?;
                if dbg.len() > 40 {
                    write!(f, "{} ...", dbg.get(..40).unwrap_or(&dbg))
                } else {
                    write!(f, "{dbg}")
                }
            }
        }
    }
}

impl DiagServiceJsonResponse {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_null() && self.errors.is_empty()
    }
}

#[cfg(feature = "test-utils")]
pub mod mock {
    use crate::{DiagServiceError, datatypes, diagservices};

    mockall::mock! {
        pub DiagServiceResponse {}

        impl diagservices::DiagServiceResponse for DiagServiceResponse {
            fn empty_positive(service: crate::DiagComm) -> Self;
            fn is_empty(&self) -> bool;
            fn service_name(&self) -> String;
            fn get_raw(&self) -> &[u8];
            fn into_json(self) -> Result<diagservices::DiagServiceJsonResponse, DiagServiceError>;
            fn as_nrc(&self) -> Result<diagservices::MappedNRC, DiagServiceError>;
            fn get_dtcs(&self) -> Result<
                Vec<(datatypes::DtcField, datatypes::DtcRecord)>,
                DiagServiceError>;
            fn response_type(&self) -> diagservices::DiagServiceResponseType;
        }

        impl Clone for DiagServiceResponse {
            fn clone(&self) -> Self;
        }
    }
}
