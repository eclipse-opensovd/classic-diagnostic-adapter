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

use hashbrown::HashMap;

use crate::{
    DataParseError, DiagServiceError,
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

#[derive(Debug, PartialEq, Eq)]
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

pub trait DiagServiceResponse: Sized + Send + Sync + 'static {
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
                    write!(f, "{} ...", &dbg[..40])
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
