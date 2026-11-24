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

use crate::{DiagServiceError, HashMap};

#[derive(Clone, Debug)]
pub struct Unit {
    pub factor_to_si_unit: Option<f64>,
    pub offset_to_si_unit: Option<f64>,
}

#[derive(Clone)]
pub struct ComParamSimpleValue {
    pub value: String,
    pub unit: Option<Unit>,
}

#[derive(Clone)]
pub enum ComParamValue {
    Simple(ComParamSimpleValue),
    Complex(ComplexComParamValue),
}

pub type ComplexComParamValue = HashMap<String, ComParamValue>;

pub enum ExecutionStatus {
    Running,
    Completed,
    Failed,
}

#[derive(Debug, Clone)]
pub enum Capability {
    Execute,
    Stop,
    Freeze,
    Reset,
    Status,
}

#[derive(Debug, Clone)]
pub enum DataTransferStatus {
    Running,
    Aborted,
    Finished,
    Queued,
}

/// Why a data transfer was aborted.
#[derive(Debug, Clone)]
pub enum DataTransferErrorCause {
    /// The ECU answered a block with a negative response.
    NegativeResponse {
        /// Service identifier echoed in the negative response.
        sid: Option<u8>,
        /// Negative response code.
        nrc: Option<u8>,
        /// Description of the NRC, from the database or ISO 14229-1.
        description: Option<String>,
    },
    /// Sending a block or receiving its response failed, e.g. a timeout.
    Communication(DiagServiceError),
    /// The CDA itself failed, e.g. reading the flash file.
    Internal,
}

#[derive(Debug, Clone)]
pub struct DataTransferError {
    /// Human readable description, including the affected block.
    pub message: String,
    pub cause: DataTransferErrorCause,
    /// Block sequence counter of the block that failed, if a block was involved.
    pub block_sequence_counter: Option<u8>,
}

#[derive(Debug, Clone)]
pub struct DataTransferMetaData {
    pub acknowledged_bytes: u64,
    pub blocksize: usize,
    pub next_block_sequence_counter: u8,
    pub id: String,
    pub file_id: String,
    pub status: DataTransferStatus,
    pub error: Option<Vec<DataTransferError>>,
}
