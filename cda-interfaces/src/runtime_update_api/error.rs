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

// SPDX-License-Identifier: Apache-2.0
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

use crate::storage_api::StorageError as CdaStorageError;

#[derive(Debug, thiserror::Error)]
pub enum RuntimeUpdateError {
    #[error("Storage error: {0}")]
    StorageError(CdaStorageError),
    #[error("Invalid MDD file: {0}")]
    InvalidMddFile(String),
    #[error("Invalid config file: {0}")]
    InvalidConfig(String),
    #[error("Invalid file type: {0}")]
    InvalidFileType(String),
    #[error("Validation failed: {0}")]
    ValidationFailed(String),
    #[error("No Lock: {0}")]
    NoLock(String),
    #[error("Lock Conflict: {0}")]
    LockConflict(String),
    #[error("Operations in progress: {0}")]
    OperationsInProgress(String),
    #[error("No pending update available")]
    NoPendingUpdate,
    #[error("No backup available for rollback")]
    NoBackup,
    #[error("Another transaction is already active")]
    TransactionBusy,
    #[error("Reload failed: {0}")]
    ReloadFailed(String),
    #[error("An execution is already in progress")]
    ExecutionConflict,
    #[error("File not found: {0}")]
    FileNotFound(String),
    #[error("Fatal Error: {0}")]
    FatalError(String),
    #[error("Severe Error: {0}")]
    SevereError(String),
}

impl From<CdaStorageError> for RuntimeUpdateError {
    fn from(e: CdaStorageError) -> Self {
        match e {
            CdaStorageError::TransactionBusy => Self::TransactionBusy,
            CdaStorageError::TransactionConflict(msg) => {
                Self::StorageError(CdaStorageError::TransactionConflict(msg))
            }
            other => Self::StorageError(other),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Verification failed: {0}")]
pub struct VerificationError(pub String);

#[derive(Debug, thiserror::Error)]
#[error("Reload error: {0}")]
pub struct ReloadError(pub String);
