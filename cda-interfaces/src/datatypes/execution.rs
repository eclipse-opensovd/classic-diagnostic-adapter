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

use crate::HashMap;

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

#[derive(Debug, Clone)]
pub struct DataTransferError {
    pub text: String,
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
