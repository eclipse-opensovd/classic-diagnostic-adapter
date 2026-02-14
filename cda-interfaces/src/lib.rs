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

use std::{
    fmt::{Display, Formatter},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

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
mod schema;
pub use schema::*;

// Deliberately not using new type pattern here, to make sure all crates that take
// std::collection::Hash* still work.
// Together with the foldhash hasher, this is virtually the same as using hashbrown.
pub type Hasher = foldhash::fast::RandomState;
pub type HashMap<K, V> = std::collections::HashMap<K, V, Hasher>;
pub type HashMapEntry<'a, K, V> = std::collections::hash_map::Entry<'a, K, V>;

pub type HashSet<V> = std::collections::HashSet<V, Hasher>;
// Note: hash_set_entry is unstable, hence not defining it.

pub use foldhash::{HashMapExt as HashMapExtensions, HashSetExt as HashSetExtensions};

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

pub type DynamicPlugin = Box<dyn std::any::Any + Send + Sync>;

#[derive(Debug, Clone)]
pub enum DiagCommAction {
    Read,
    Write,
    Start,
}

#[derive(Debug, Clone)]
pub struct DiagComm {
    pub name: String,
    pub type_: DiagCommType,
    pub lookup_name: Option<String>,
}

impl DiagComm {
    #[must_use]
    pub fn new(name: impl Into<String>, type_: DiagCommType) -> Self {
        let name = name.into();
        Self {
            lookup_name: Some(name.clone()),
            name,
            type_,
        }
    }

    #[must_use]
    pub fn action(&self) -> DiagCommAction {
        self.type_.clone().into()
    }
}

impl From<DiagCommType> for DiagCommAction {
    fn from(value: DiagCommType) -> Self {
        match value {
            DiagCommType::Configurations => DiagCommAction::Write,
            DiagCommType::Data => DiagCommAction::Read,
            // Faults is actually Clear or Read, but doesn't matter here
            DiagCommType::Faults | DiagCommType::Modes | DiagCommType::Operations => {
                DiagCommAction::Start
            }
        }
    }
}

#[derive(Debug, Clone)]
/// Enum representing diagnostic communication types according to ASAM SOVD.
///
/// Can be mapped to UDS service prefixes with [`DiagCommType::service_prefixes`]
pub enum DiagCommType {
    /// Service Prefix `0x2E`
    Configurations,
    /// Service Prefix `0x22`
    Data,
    /// Service Prefixes `0x14`, `0x19`
    Faults,
    /// Service Prefixes `0x10`, `0x11`, `0x28`, `0x85`, `0x27`, `0x29`
    Modes,
    /// Service Prefixes `0x2F`, `0x31`, `0x34`, `0x36`, `0x37`
    Operations,
}

impl TryFrom<u8> for DiagCommType {
    type Error = DiagServiceError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            service_ids::WRITE_DATA_BY_IDENTIFIER => Ok(DiagCommType::Configurations),
            service_ids::READ_DATA_BY_IDENTIFIER => Ok(DiagCommType::Data),
            service_ids::CLEAR_DIAGNOSTIC_INFORMATION | service_ids::READ_DTC_INFORMATION => {
                Ok(DiagCommType::Faults)
            }
            service_ids::SESSION_CONTROL
            | service_ids::ECU_RESET
            | service_ids::SECURITY_ACCESS
            | service_ids::COMMUNICATION_CONTROL
            | service_ids::AUTHENTICATION
            | service_ids::CONTROL_DTC_SETTING => Ok(DiagCommType::Modes),
            service_ids::INPUT_OUTPUT_CONTROL_BY_IDENTIFIER
            | service_ids::ROUTINE_CONTROL
            | service_ids::REQUEST_DOWNLOAD
            | service_ids::TRANSFER_DATA
            | service_ids::REQUEST_TRANSFER_EXIT => Ok(DiagCommType::Operations),
            _ => Err(DiagServiceError::InvalidRequest(format!(
                "Invalid DiagCommType value: {value}"
            ))),
        }
    }
}

#[derive(Clone)]
pub enum SecurityAccess {
    RequestSeed(DiagComm),
    SendKey(DiagComm),
}

#[derive(Clone, Debug)]
pub enum TesterPresentMode {
    Start,
    Stop,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TesterPresentType {
    Functional(String),
    Ecu(String),
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
    pub const NEGATIVE_RESPONSE: u8 = 0x7F;
}

pub const UDS_ID_RESPONSE_BITMASK: u8 = 0x40;

const CONFIGURATIONS_PREFIXES: [u8; 1] = [service_ids::WRITE_DATA_BY_IDENTIFIER];

const DATA_PREFIXES: [u8; 1] = [service_ids::READ_DATA_BY_IDENTIFIER];

const FAULTS_PREFIXES: [u8; 2] = [
    service_ids::CLEAR_DIAGNOSTIC_INFORMATION,
    service_ids::READ_DTC_INFORMATION,
];

const MODES_PREFIXES: [u8; 6] = [
    service_ids::SESSION_CONTROL,
    service_ids::ECU_RESET,
    service_ids::SECURITY_ACCESS,
    service_ids::COMMUNICATION_CONTROL,
    service_ids::AUTHENTICATION,
    service_ids::CONTROL_DTC_SETTING,
];

const OPERATIONS_PREFIXES: [u8; 5] = [
    service_ids::INPUT_OUTPUT_CONTROL_BY_IDENTIFIER,
    service_ids::ROUTINE_CONTROL,
    service_ids::REQUEST_DOWNLOAD,
    service_ids::TRANSFER_DATA,
    service_ids::REQUEST_TRANSFER_EXIT,
];

pub const SERVICE_IDS_PARAMETER_META_DATA: [u8; 3] = [
    service_ids::READ_DATA_BY_IDENTIFIER,
    service_ids::WRITE_DATA_BY_IDENTIFIER,
    service_ids::ROUTINE_CONTROL,
];

impl TesterPresentType {
    #[must_use]
    pub fn is_functional(&self) -> bool {
        matches!(self, TesterPresentType::Functional(_))
    }
}

impl DiagCommType {
    #[must_use]
    /// This function returns the service prefix for the given `DiagCommType`
    /// according to ASAM_SOVD_BS_V1-0-0
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
    pub fn service_prefixes(&self) -> &'static [u8] {
        match self {
            DiagCommType::Configurations => &CONFIGURATIONS_PREFIXES,
            DiagCommType::Data => &DATA_PREFIXES,
            DiagCommType::Faults => &FAULTS_PREFIXES,
            DiagCommType::Modes => &MODES_PREFIXES,
            DiagCommType::Operations => &OPERATIONS_PREFIXES,
        }
    }
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct FunctionalDescriptionConfig {
    pub description_database: String,
    pub enabled_functional_groups: Option<HashSet<String>>,
    pub protocol_position: datatypes::DiagnosticServiceAffixPosition,
    pub protocol_case_sensitive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DiagServiceError {
    /// Returned in case a resource can not be found
    #[error("Not found: {0:?}")]
    NotFound(Option<String>),
    #[error("Request not supported: {0}")]
    RequestNotSupported(String),
    #[error("Invalid database: {0}")]
    InvalidDatabase(String),
    #[error("Database entry not found: {0}")]
    DatabaseEntryNotFound(String),
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    #[error("Parameter conversion error: {0}")]
    ParameterConversionError(String),
    #[error("Unknown operation")]
    UnknownOperation,
    #[error("UDS lookup error: {0}")]
    UdsLookupError(String),
    #[error("Bad payload: {0}")]
    BadPayload(String),
    /// Similar to `BadPayload` but indicates that the data received is insufficient to
    /// process the request.
    /// Used to abort reading data gracefully when the data is incomplete or end of pdu is reached.
    #[error("Payload too short, expected at least {expected} bytes, got {actual} bytes")]
    NotEnoughData { expected: usize, actual: usize },
    #[error("Variant detection error: {0}")]
    VariantDetectionError(String),
    #[error("{0}")]
    InvalidState(String),
    #[error("{0}")]
    InvalidAddress(String),
    #[error("Sending message failed {0}")]
    SendFailed(String),
    #[error("Received Nack, code={0:?}")]
    Nack(u8),
    #[error("Unexpected response. {0:?}")]
    UnexpectedResponse(Option<String>),
    #[error("No response {0}")]
    NoResponse(String),
    #[error("Connection closed {0}")]
    ConnectionClosed(String),
    #[error("Ecu {0} offline")]
    EcuOffline(String),
    #[error("Timeout")]
    Timeout,
    #[error("Access denied: {0}")]
    AccessDenied(String),
    /// Returned in case a resource can be found but returns an error
    #[error("Resource error: {0}")]
    ResourceError(String),
    #[error("Data parse error: value='{}', details='{}'", .0.value, .0.details)]
    DataError(DataParseError),
    /// Returned in case the provided value for security plugin cannot be used as `SecurityApi`
    #[error("Invalid security plugin provided")]
    InvalidSecurityPlugin,
    #[error(
        "Unable to find a unique value with the given parameters: name='{name}', \
         candidates='{candidates:?}'"
    )]
    AmbiguousParameters {
        name: String,
        candidates: Vec<String>,
    },
}

#[derive(Error, Debug)]
pub enum DoipGatewaySetupError {
    #[error("Invalid address: `{0}`")]
    InvalidAddress(String),
    #[error("Socket error: `{0}`")]
    SocketCreationFailed(String),
    #[error("Port error: `{0}`")]
    PortBindFailed(String),
    #[error("Configuration error: `{0}`")]
    InvalidConfiguration(String),
    #[error("Resource error: `{0}`")]
    ResourceError(String),
    #[error("Server error: `{0}`")]
    ServerError(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataParseError {
    pub value: String,
    pub details: String,
}

impl std::fmt::Display for DiagComm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DiagService ( name: {}, operation: {:?} )",
            self.name,
            self.action()
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
