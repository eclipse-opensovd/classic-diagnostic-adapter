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

use serde::{Deserialize, Serialize};

use crate::DiagComm;

pub type DtcCode = u32;

/// Provides the supported Types of DTC functions
/// Essentially the byte values
/// are sub functions for service 0x19 (Read DTC information)
#[repr(u8)]
#[derive(Clone, PartialEq, Eq, Hash)]
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
    pub fn default_scope(&self) -> &str {
        match self {
            DtcReadInformationFunction::FaultMemoryByStatusMask
            | DtcReadInformationFunction::FaultMemoryExtDataRecordByDtcNumber
            | DtcReadInformationFunction::FaultMemorySnapshotRecordByDtcNumber => "FaultMem",
            DtcReadInformationFunction::UserMemoryDtcByStatusMask
            | DtcReadInformationFunction::UserMemoryDtcExtDataRecordByDtcNumber
            | DtcReadInformationFunction::UserMemoryDtcSnapshotRecordByDtcNumber => "UserMem",
        }
    }
}

#[repr(u8)]
#[derive(Clone, strum_macros::EnumIter, strum_macros::Display, strum_macros::EnumString)]
#[strum(serialize_all = "camelCase")]
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

pub struct DtcLookup {
    pub scope: String,
    pub service: DiagComm,
    pub dtcs: Vec<DtcRecord>,
}

pub struct DtcRecord {
    pub code: DtcCode,
    pub display_code: Option<String>,
    pub fault_name: String,
    pub severity: u32,
}

/// Used to describe the position of a DTC field in the UDS payload.
/// Necessary to parse DTCs from the raw UDS response.
pub struct DtcField {
    pub bit_pos: u32,
    pub bit_len: u32,
    pub byte_pos: u32,
}

#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
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

pub struct DtcRecordAndStatus {
    pub record: DtcRecord,
    pub scope: String,
    pub status: DtcStatus,
}
