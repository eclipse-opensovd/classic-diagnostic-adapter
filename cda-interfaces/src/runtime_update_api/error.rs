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
    ReloadFailed(#[from] ReloadFailure),
    #[error("An execution is already in progress")]
    ExecutionConflict,
    #[error("File not found: {0}")]
    FileNotFound(String),
    #[error("Internal error, the update was not started: {0}")]
    UpdateStartError(String),
    #[error("Fatal Error: {0}")]
    FatalError(String),
    #[error("Severe Error: {0}")]
    SevereError(String),
    #[error("Communication operation failed: {0}")]
    CommunicationFailure(String),
    #[error("Component replacement failed: {0}")]
    ReplacementFailure(String),
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

#[derive(Debug, Clone, thiserror::Error)]
pub enum ReloadError {
    #[error("Reload error: {0}")]
    General(String),
    #[error("Communication operation failed: {0}")]
    CommunicationFailure(String),
    #[error("Component replacement failed: {0}")]
    ReplacementFailure(String),
    #[error(
        "MDD files were provided, yet none of them loaded. On a reload this means a total loss of \
         diagnostic function and grants a rollback: {0}"
    )]
    NoDatabasesLoaded(String),
}

/// Where recovery gave up, and why.
///
/// Names the step at which a runtime update stopped being able to guarantee that
/// the databases on disk and the runtime built from them still agree. Persistent
/// state is the MDD files in storage; live state is what the running process
/// serves from them. Nothing branches on this value: it reaches an operator
/// through the log and through the failure reason of the execution, so that
/// whoever investigates knows which step to look at.
#[derive(Debug, Clone, thiserror::Error)]
pub enum RecoveryError {
    /// The candidate was rejected, and restoring the previous MDD files from the
    /// backup failed as well, so what is on disk matches neither the candidate nor
    /// the previous database. Storage is the first thing to inspect.
    #[error("Restoring the previous databases failed: {0}")]
    PersistentRestore(ReloadError),
    /// The previous files were restored, but building runtime state from them
    /// failed too, so what is live is whatever the rejected candidate left behind.
    /// Both the candidate and the database that worked until now are unusable.
    #[error("The restored databases could not be prepared: {0}")]
    RestoredPreparation(ReloadError),
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ReloadFailure {
    #[error("Requested reload failed but the previous state was restored: {original}")]
    RejectedAndRestored { original: ReloadError },
    #[error("Requested reload failed and coherence could not be restored: {original}; {recovery}")]
    RecoveryFailed {
        original: ReloadError,
        recovery: RecoveryError,
    },
}
