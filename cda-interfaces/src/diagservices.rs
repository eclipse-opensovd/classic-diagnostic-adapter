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

use crate::{DiagServiceError, util};

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

pub trait DiagServiceResponse: Sized + Send + Sync + 'static {
    fn is_empty(&self) -> bool;
    fn service_name(&self) -> String;
    fn response_type(&self) -> DiagServiceResponseType;
    fn get_raw(&self) -> &[u8];
    fn into_json(self) -> Result<serde_json::Value, DiagServiceError>;
    fn as_nrc(&self) -> Result<MappedNRC, String>;
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
