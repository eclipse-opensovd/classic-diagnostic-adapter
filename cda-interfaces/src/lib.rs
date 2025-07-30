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

use std::{
    fmt::{Display, Formatter},
    time::Duration,
};

mod com_param_handling;
pub use com_param_handling::*;
pub mod datatypes;
pub mod diagservices;
mod ecugateway;
pub use ecugateway::*;
mod ecumanager;
pub use ecumanager::*;
mod ecuuds;
pub use ecuuds::*;
pub mod file_manager;

/// # strings module
/// This module contains a type that allows to store unique strings and use references to them
/// instead of cloning the strings themselves in all places.<br>
/// This is to optimize the memory usage of the diagnostic databases, as they contain a lot of
/// strings which are often not unique.<br>
/// The module additionally contains macros to handle string IDs and references in the diagnostic
/// database.
pub(crate) mod strings;
/// Re-export the STRINGS macros to make it available in the crate scope.
pub use strings::*;
pub mod util;

pub type Id = u32;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub enum DiagCommAction {
    Read,
    Write,
    Start,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub struct DiagComm {
    pub name: String,
    pub action: DiagCommAction,
    pub type_: DiagCommType,
    pub lookup_name: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub enum DiagCommType {
    Configurations,
    Data,
    Faults,
    Modes,
    Operations,
}

#[derive(Clone)]
pub enum SecurityAccess {
    RequestSeed(DiagComm),
    SendKey((Id, DiagComm)),
}

#[derive(Clone, Debug)]
pub enum TesterPresentMode {
    Start,
    Stop,
}

#[derive(Clone, Debug)]
pub enum TesterPresentType {
    Functional,
    // Ecu, // todo support tester present for single ecus
}

#[derive(Clone, Debug)]
pub struct TesterPresentControlMessage {
    pub mode: TesterPresentMode,
    pub type_: TesterPresentType,
    pub ecu: String,
    /// If set to `None`, the ECU specific interval will be used.
    pub interval: Option<Duration>,
}

pub mod service_ids {
    pub const SESSION_CONTROL: u8 = 0x10;
    pub const ECU_RESET: u8 = 0x11;
    pub const CLEAR_DIAGNOSTIC_INFORMATION: u8 = 0x14;
    pub const READ_DTC_INFORMATION: u8 = 0x19;
    pub const READ_DATA_BY_IDENTIFIER: u8 = 0x22;
    pub const SECURITY_ACCESS: u8 = 0x27;
    pub const COMMUNICATION_CONTROL: u8 = 0x28;
    pub const AUTHENTICATION: u8 = 0x29;
    pub const WRITE_DATA_BY_IDENTIFIER: u8 = 0x2E;
    pub const INPUT_OUTPUT_CONTROL_BY_IDENTIFIER: u8 = 0x2F;
    pub const ROUTINE_CONTROL: u8 = 0x31;
    pub const REQUEST_DOWNLOAD: u8 = 0x34;
    pub const TRANSFER_DATA: u8 = 0x36;
    pub const REQUEST_TRANSFER_EXIT: u8 = 0x37;
    pub const TESTER_PRESENT: u8 = 0x3E;
    pub const CONTROL_DTC_SETTING: u8 = 0x85;
}

impl DiagCommType {
    #[must_use]
    /// This function returns the service prefix for the given `DiagCommType`
    /// acccording to ASAM_SOVD_BS_V1-0-0
    /// # Service Prefixes Mapping
    ///  - `0x2E` -> `<entity>/configurations`
    ///  - `0x22` -> `<entity>/data`
    ///  - `0x10` -> `<entity>/modes/session`
    ///  - `0x11` -> `<entity>/modes/ecureset`
    ///  - `0x28` -> `<entity>/modes/commctrl`
    ///  - `0x85` -> `<entity>/modes/dtcsetting`
    ///  - `0x27 | 0x29` -> `<entity>/modes/security`
    ///  - `0x14 | 0x19` -> `<entity>/faults`
    ///  - `0x2F | 0x31` -> `<entity>/operations`
    pub fn service_prefix(&self) -> Vec<u8> {
        match self {
            DiagCommType::Configurations => vec![service_ids::WRITE_DATA_BY_IDENTIFIER],
            DiagCommType::Data => vec![service_ids::READ_DATA_BY_IDENTIFIER],
            DiagCommType::Faults => vec![
                service_ids::CLEAR_DIAGNOSTIC_INFORMATION,
                service_ids::READ_DTC_INFORMATION,
            ],
            DiagCommType::Modes => vec![
                service_ids::SESSION_CONTROL,
                service_ids::ECU_RESET,
                service_ids::SECURITY_ACCESS,
                service_ids::COMMUNICATION_CONTROL,
                service_ids::AUTHENTICATION,
                service_ids::CONTROL_DTC_SETTING,
            ],
            DiagCommType::Operations => vec![
                service_ids::INPUT_OUTPUT_CONTROL_BY_IDENTIFIER,
                service_ids::ROUTINE_CONTROL,
                service_ids::REQUEST_DOWNLOAD,
                service_ids::TRANSFER_DATA,
                service_ids::REQUEST_TRANSFER_EXIT,
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "deepsize", derive(DeepSizeOf))]
pub enum DiagServiceError {
    NotFound,
    RequestNotSupported,
    InvalidDatabase(String),
    DatabaseEntryNotFound(String),
    InvalidRequest(String),
    ParameterConversionError(String),
    UnknownOperation,
    UdsLookupError(String),
    BadPayload(String),
    VariantDetectionError(String),
    InvalidSession(String),
    SendFailed(String),
    Nack(u8),
    UnexpectedResponse,
    NoResponse(String),
    ConnectionClosed,
    EcuOffline(String),
    Timeout,
    AccessDenied(String),
}

impl Display for DiagServiceError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            DiagServiceError::NotFound => write!(f, "Not found"),
            DiagServiceError::RequestNotSupported => write!(f, "Request not supported"),
            DiagServiceError::InvalidDatabase(msg) => write!(f, "Invalid database: {msg}"),
            DiagServiceError::DatabaseEntryNotFound(msg) => {
                write!(f, "Database entry not found: {msg}")
            }
            DiagServiceError::InvalidRequest(msg) => write!(f, "Invalid request: {msg}"),
            DiagServiceError::ParameterConversionError(msg) => {
                write!(f, "Parameter conversion error: {msg}")
            }
            DiagServiceError::UnknownOperation => write!(f, "Unknown operation"),
            DiagServiceError::UdsLookupError(msg) => write!(f, "UDS lookup error: {msg}"),
            DiagServiceError::BadPayload(msg) => write!(f, "Bad payload: {msg}"),
            DiagServiceError::VariantDetectionError(msg) => {
                write!(f, "Variant detection error: {msg}")
            }
            DiagServiceError::InvalidSession(msg) => {
                write!(f, "{msg}")
            }
            DiagServiceError::SendFailed(msg) => {
                write!(f, "Sending message failed {msg}")
            }
            DiagServiceError::Nack(code) => write!(f, "Received Nack, code={code:?}"),
            DiagServiceError::UnexpectedResponse => write!(f, "Unexpected response"),
            DiagServiceError::NoResponse(msg) => write!(f, "No response {msg}"),
            DiagServiceError::ConnectionClosed => write!(f, "Connection closed"),
            DiagServiceError::EcuOffline(ecu) => write!(f, "Ecu {ecu} offline"),
            DiagServiceError::Timeout => write!(f, "Timeout"),
            DiagServiceError::AccessDenied(msg) => write!(f, "Access denied: {msg}"),
        }
    }
}

impl std::fmt::Display for DiagComm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DiagService ( name: {}, operation: {:?} )",
            self.name, self.action
        )
    }
}

impl Display for DiagCommAction {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            DiagCommAction::Read => write!(f, "Read"),
            DiagCommAction::Write => write!(f, "Write"),
            DiagCommAction::Start => write!(f, "Start"),
        }
    }
}
