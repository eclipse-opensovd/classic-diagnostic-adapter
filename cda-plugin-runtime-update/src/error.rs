// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

use cda_interfaces::storage_api::StorageError as CdaStorageError;

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
    #[error("No vehicle lock held")]
    NoLock,
    #[error("Lock is not owned by the caller")]
    LockNotOwned,
    #[error("Operations in progress, cannot apply now")]
    OperationsInProgress,
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
