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
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;

use crate::{DiagComm, HashMap, diagservices::FieldParseError};

pub type DtcCode = u32;

pub const DTC_CODE_BIT_LEN: u32 = 24;

/// Defined in ISO-14229-1 Table 298
pub const CLEAR_FAULT_MEM_POS_RESPONSE_SID: u8 = 0x54;

/// Provides the supported Types of DTC functions
/// Essentially the byte values
/// are sub functions for service 0x19 (Read DTC information)
#[repr(u8)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, strum_macros::EnumIter, strum_macros::EnumString,
)]
#[strum(ascii_case_insensitive)]
pub enum DtcReadInformationFunction {
    FaultMemoryByStatusMask = 0x02,
    FaultMemorySnapshotRecordByDtcNumber = 0x04,
    FaultMemoryExtDataRecordByDtcNumber = 0x06,
    UserMemoryDtcByStatusMask = 0x17,
    UserMemoryDtcSnapshotRecordByDtcNumber = 0x18,
    UserMemoryDtcExtDataRecordByDtcNumber = 0x19,
}

impl DtcReadInformationFunction {
    /// Describes the default scope for each DTC function.
    /// This will be used if there is no associated functional class in the service definition.
    /// Otherwise, the functional class name will be used instead.
    #[must_use]
    pub fn default_scope(&self) -> &str {
        match self {
            Self::FaultMemoryByStatusMask
            | Self::FaultMemoryExtDataRecordByDtcNumber
            | Self::FaultMemorySnapshotRecordByDtcNumber => "FaultMem",
            Self::UserMemoryDtcByStatusMask
            | Self::UserMemoryDtcExtDataRecordByDtcNumber
            | Self::UserMemoryDtcSnapshotRecordByDtcNumber => "UserMem",
        }
    }

    #[must_use]
    pub fn all() -> Vec<Self> {
        Self::iter().collect()
    }

    /// Parses a DTC read information function from its string representation.
    ///
    /// # Errors
    /// Returns `DiagServiceError::InvalidParameter` if `s` does not match any known
    /// `DtcReadInformationFunction` variant.
    pub fn try_from_str(s: &str) -> Result<Self, crate::DiagServiceError> {
        std::str::FromStr::from_str(s).map_err(|_| crate::DiagServiceError::InvalidParameter {
            possible_values: Self::iter().map(|v| format!("{v:?}")).collect(),
        })
    }
    #[must_use]
    pub fn is_user_scope(&self) -> bool {
        matches!(
            self,
            Self::UserMemoryDtcByStatusMask
                | Self::UserMemoryDtcSnapshotRecordByDtcNumber
                | Self::UserMemoryDtcExtDataRecordByDtcNumber
        )
    }
}

#[repr(u8)]
#[derive(Clone, strum_macros::EnumIter, strum_macros::Display, strum_macros::EnumString)]
pub enum DtcMask {
    TestFailed = 0x01,
    TestFailedThisOperationCycle = 0x02,
    PendingDtc = 0x04,
    ConfirmedDtc = 0x08,
    TestNotCompletedSinceLastClear = 0x10,
    TestFailedSinceLastClear = 0x20,
    TestNotCompletedThisOperationCycle = 0x40,
    WarningIndicatorRequested = 0x80,
}

impl DtcMask {
    #[must_use]
    pub fn all_bits() -> u8 {
        let mut mask = 0u8;
        Self::iter().for_each(|m| mask |= m as u8);
        mask
    }
}

pub struct DtcLookup {
    pub scope: DtcReadInformationFunction,
    pub service: DiagComm,
    pub dtcs: Vec<DtcRecord>,
}

#[derive(Debug, Clone)]
pub struct DtcRecord {
    pub code: DtcCode,
    pub display_code: Option<String>,
    pub fault_name: String,
    pub severity: u32,
}

/// Used to describe the position of a DTC field in the UDS payload.
/// Necessary to parse DTCs from the raw UDS response.
#[derive(Debug, Clone)]
pub struct DtcField {
    pub bit_pos: u32,
    pub bit_len: u32,
    pub byte_pos: u32,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
// The warning is allowed because the bools represent the status bits of a DTC.
#[allow(clippy::struct_excessive_bools)]
pub struct DtcStatus {
    pub test_failed: bool,
    pub test_failed_this_operation_cycle: bool,
    pub pending_dtc: bool,
    pub confirmed_dtc: bool,
    pub test_not_completed_since_last_clear: bool,
    pub test_failed_since_last_clear: bool,
    pub test_not_completed_this_operation_cycle: bool,
    pub warning_indicator_requested: bool,
    pub mask: u8,
}

#[derive(Debug, Clone)]
pub struct DtcRecordAndStatus {
    pub record: DtcRecord,
    pub scope: DtcReadInformationFunction,
    pub status: DtcStatus,
}

#[derive(Debug, Clone)]
pub struct DtcSnapshot {
    pub number_of_identifiers: u64,
    pub record: Vec<serde_json::Value>,
}

pub struct ExtendedSnapshots {
    pub data: Option<HashMap<String, DtcSnapshot>>,
    pub errors: Option<Vec<FieldParseError>>,
}

pub struct ExtendedDataRecords {
    pub data: Option<HashMap<String, serde_json::Value>>,
    pub errors: Option<Vec<FieldParseError>>,
}

pub struct DtcExtendedInfo {
    pub record_and_status: DtcRecordAndStatus,
    pub extended_data_records: Option<ExtendedDataRecords>,
    pub extended_data_records_schema: Option<serde_json::Value>,
    pub snapshots: Option<ExtendedSnapshots>,
    pub snapshots_schema: Option<serde_json::Value>,
}

/// DTC (Diagnostic Trouble Code) fault memory configuration.
#[derive(Deserialize, Serialize, Clone, Debug, schemars::JsonSchema)]
pub struct FaultConfig {
    /// Service definition used to clear all user-defined DTCs.
    /// Specified as a byte array representing the full UDS service identifier.
    ///
    /// Example: `[0x31, 0x01, 0x02, 0x46]`
    /// The first byte is the service ID, followed by any coded constant parameters
    /// (subfunction, routine ID, etc.) as they appear sequentially in the UDS request.
    ///
    /// If not set, clearing user-defined DTCs is not supported.
    pub user_defined_dtc_clear_service: Option<Vec<u8>>,
    /// Name of the scope to pass to the DTC functions to read from the user defined DTC memory.
    /// Matching will be case-insensitive.
    pub user_memory_scope: String,
    /// Default scope name for standard fault memory operations.
    pub default_scope: String,
}

impl Default for FaultConfig {
    fn default() -> Self {
        Self {
            user_defined_dtc_clear_service: None,
            user_memory_scope: "DevelopmentFaultMemory".to_string(),
            default_scope: "FaultMem".to_string(),
        }
    }
}
