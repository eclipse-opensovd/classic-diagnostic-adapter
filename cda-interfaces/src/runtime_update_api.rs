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

//! Runtime Update Plugin API
//!
//! Provides interfaces for transactional runtime-file snapshots, including security policy,
//! application reload coordination, and error types.
//!
//! The concrete plugin implementation lives in `cda-plugin-runtime-update`.

use std::{str::FromStr, sync::Arc};

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Deserializer, Serialize};
use strum_macros::EnumString;

use crate::{
    communication_control::CommunicationOperationFailure,
    storage_api::{Collection, DirectFileAccess},
};

mod error;
pub use error::{RecoveryError, ReloadError, RuntimeUpdateError, VerificationError};

/// An apply whose fallible work is already done and whose exclusion is already
/// held, so finalizing it cannot fail.
///
/// Where [`ReloadComponent`](crate::ReloadComponent) takes its exclusion when it
/// applies, this took it when it was prepared. That is what a target needs when
/// the party it can race is another writer rather than a reader: a writer cannot
/// be waited out at apply time without invalidating the validation already done.
pub trait PreparedApply: Send {
    /// Publishes the prepared value. Synchronous and infallible: validation
    /// already happened when the reservation was taken.
    fn apply(self: Box<Self>);
}

/// Mutation capability for aligning lockable resources with vehicle database content.
///
/// Kept separate from [`LockStateProvider`] so read-only policy code cannot
/// change which resources may be locked.
#[async_trait]
pub trait VehicleDatabaseLockUpdater: Send + Sync + 'static {
    /// Validates a prospective topology and reserves ECU/group lock admission until it is applied.
    async fn reserve_lock_resources(
        &self,
        ecu_names: Vec<String>,
    ) -> Result<Box<dyn PreparedApply>, ReloadError>;
}

/// A file to be uploaded to the CDA during a runtime update.
#[derive(Debug)]
pub struct UploadFile {
    /// Name of the file including its extension (e.g. `"FLXC1000.mdd"`).
    pub filename: String,
    /// Raw file contents.
    pub data: Bytes,
}

/// Collections passed to [`RuntimeUpdatePolicy::check_execution_allowed`].
///
/// Provides direct access to the staged (`*NextUpdate`) and currently active collections
/// so implementations can inspect file lists, read metadata, or verify file content
/// before permitting an apply operation.
pub struct UpdateCollections<C: Collection + DirectFileAccess> {
    /// Staged MDD collection (`DiagnosticDatabaseNextUpdate`), or `None` if no update is pending.
    pub pending_mdd: Option<Arc<C>>,
    /// Currently active MDD collection (`DiagnosticDatabase`), or `None` if not yet initialized.
    pub current_mdd: Option<Arc<C>>,
    /// Rollback candidate (`DiagnosticDatabaseBackup`), or `None` if nothing has been replaced yet.
    pub backup_mdd: Option<Arc<C>>,
}

impl<C: Collection + DirectFileAccess> Default for UpdateCollections<C> {
    fn default() -> Self {
        Self {
            pending_mdd: None,
            current_mdd: None,
            backup_mdd: None,
        }
    }
}

/// Format-specific operations used by the runtime-update plugin.
///
/// Implementations validate staged and installed files, expose ECU-name and revision metadata,
/// and optionally decompress applied files. Database construction and signature
/// policy remain the application's responsibility. Methods are
/// synchronous because implementations inspect local files directly.
pub trait RuntimeFileInspector: Send + Sync + 'static {
    /// Verifies that `path` holds a well-formed runtime database.
    ///
    /// Called before promotion and before an installed file is constructed into live state.
    ///
    /// # Errors
    /// Returns [`VerificationError`] when the file is malformed or unreadable.
    fn validate(&self, path: &std::path::Path) -> Result<(), VerificationError>;

    /// Applies the application's content-trust policy to `path`, for example a
    /// signature or hash check.
    ///
    /// Called on each staged file before it is accepted. The default delegates
    /// to [`validate`](Self::validate), so an implementor with no signature
    /// policy still gets well-formedness checking; override it only to add more.
    ///
    /// # Errors
    /// Returns [`VerificationError`] to reject the file.
    fn check_integrity(&self, path: &std::path::Path) -> Result<(), VerificationError> {
        self.validate(path)
    }

    /// Returns the short name of the ECU this file describes.
    ///
    /// # Errors
    /// Returns [`RuntimeUpdateError`] when the file cannot be read or carries no name.
    fn ecu_name(&self, path: &std::path::Path) -> Result<String, RuntimeUpdateError>;

    /// Returns the file's revision, or `None` when it carries none or cannot be
    /// read. Surfaced as `x-sovd2uds-revision`, where absent is not an error.
    fn revision(&self, path: &std::path::Path) -> Option<String>;

    /// Rewrites the file uncompressed in place, trading disk for lower runtime
    /// memory. Formats without compression should succeed without doing anything.
    ///
    /// # Errors
    /// Returns [`RuntimeUpdateError`] when rewriting fails.
    fn decompress_in_place(&self, path: &std::path::Path) -> Result<(), RuntimeUpdateError>;
}

/// Provides read-only access to vehicle lock state for security validation.
///
/// Implemented by the SOVD server to expose lock information to plugins
/// without creating a dependency on cda-sovd. OEMs may replace this
/// implementation to integrate custom lock management systems.
#[async_trait]
pub trait LockStateProvider: Send + Sync + 'static {
    /// Returns the opaque identity of the vehicle lock owner, or `None` if no vehicle lock is held.
    async fn vehicle_lock_owner_id(&self) -> Option<String>;

    /// Returns `true` if any ECU or functional-group lock is currently held.
    ///
    /// The vehicle lock is not among them: it lives beside the lock topology,
    /// not in it, and is reported by [`Self::vehicle_lock_owner_id`].
    async fn has_locks(&self) -> bool;
}

/// The database-file transaction one execution runs, and the restore that
/// undoes it.
///
/// Storage only: nothing here loads a database into the running runtime. The
/// staged dispatch that drives this runs the load afterwards, and calls the
/// matching restore when it fails.
#[async_trait]
pub trait RuntimeFileTransaction: Send + Sync + 'static {
    /// Promotes the staged set to current, keeping the displaced set as backup.
    ///
    /// # Errors
    /// Returns [`RuntimeUpdateError`] when the transaction could not be committed.
    async fn apply_files(&self) -> Result<(), RuntimeUpdateError>;

    /// Swaps the backup set back into current, preserving the displaced one as
    /// the new backup. The staged set is left alone, because a rollback is only
    /// committed once the runtime accepted the restored databases: see
    /// [`discard_staged`](Self::discard_staged).
    ///
    /// # Errors
    /// Returns [`RuntimeUpdateError::NoBackup`] when there is nothing to restore.
    async fn rollback_files(&self) -> Result<(), RuntimeUpdateError>;

    /// Discards the staged set, committing a rollback whose restored databases
    /// are now live.
    ///
    /// # Errors
    /// Returns [`RuntimeUpdateError`] when the transaction could not be committed.
    async fn discard_staged(&self) -> Result<(), RuntimeUpdateError>;

    /// Deletes the staged and backup sets. The current set is never touched.
    ///
    /// # Errors
    /// Returns [`RuntimeUpdateError`] when the transaction could not be committed.
    async fn cleanup_files(&self) -> Result<(), RuntimeUpdateError>;

    /// Undoes [`apply_files`](Self::apply_files): the rejected set goes back to
    /// staging for correction and the backup keeps naming the last known good
    /// state.
    ///
    /// # Errors
    /// Returns [`RuntimeUpdateError`] when the previous set could not be restored.
    async fn restore_after_apply(&self) -> Result<(), RuntimeUpdateError>;

    /// Undoes [`rollback_files`](Self::rollback_files). The swap is an
    /// involution, so running it again is what restores the previous state.
    ///
    /// # Errors
    /// Returns [`RuntimeUpdateError`] when the previous set could not be restored.
    async fn restore_after_rollback(&self) -> Result<(), RuntimeUpdateError>;
}

/// Resolves once a dispatched transition is over and its guards are back down.
pub type UpdateCompletion =
    std::pin::Pin<Box<dyn Future<Output = Result<(), ExecutionFailure>> + Send>>;

/// An admitted update dispatch: the guards are up and the runtime is changing.
pub struct AcceptedUpdate {
    /// A client treats a terminal status as permission to resume ordinary
    /// traffic, so the caller publishes one only after this resolves.
    pub completion: UpdateCompletion,
}

/// Runs the runtime transition an execution asks for.
///
/// The plugin owns the files and the policy; which stages a mode visits, which
/// guards it takes and what the transport looks like afterwards belong to the
/// application's lifecycle, so they are reached through this instead.
#[async_trait]
pub trait UpdateDispatcher: Send + Sync + 'static {
    /// Takes the execution guards and starts the transition `mode` asks for.
    ///
    /// Returns as soon as the guards are up, so the caller can answer while the
    /// stages still run.
    ///
    /// # Errors
    /// Returns [`RuntimeUpdateError::ExecutionConflict`] when another dispatch
    /// already holds the guards, and [`RuntimeUpdateError::UpdateStartError`]
    /// when the runtime cannot admit one at all.
    async fn dispatch(&self, mode: ExecutionMode) -> Result<AcceptedUpdate, RuntimeUpdateError>;
}

/// OEM hook for deciding whether an execution may proceed given vehicle and lock state.
///
/// The question it answers is whether swapping the diagnostic databases is safe
/// right now, for example refusing while the vehicle is not parked. Caller
/// authorization is not done here and no caller identity reaches it: the adapter
/// enforces vehicle-lock ownership before an execution is ever started.
#[async_trait]
pub trait RuntimeUpdatePolicy<
    L: LockStateProvider,
    C: Collection + DirectFileAccess + Send + Sync + 'static,
>: Send + Sync + 'static
{
    /// Decides whether an execution may proceed, from lock state and the
    /// `collections` it would act on.
    ///
    /// Consulted before the update guards are acquired: taking them disables
    /// communication and refuses other clients, which a caller this refuses
    /// must not be able to provoke.
    ///
    /// One lock rule is not delegated: a reload replaces the lock topology, so no ECU or
    /// functional-group lock may be held across it. The framework checks that itself,
    /// and a plugin cannot switch it off.
    ///
    /// # Errors
    /// Returns an appropriate [`RuntimeUpdateError`] variant to deny the execution.
    async fn check_execution_allowed(
        &self,
        lock_state_provider: &L,
        collections: &UpdateCollections<C>,
    ) -> Result<(), RuntimeUpdateError>;
}

/// Severity of a runtime update execution failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionFailureClass {
    /// The operation was rejected or the previous state was fully restored.
    Ordinary,
    /// The runtime can no longer be trusted or used and the process must be restarted.
    /// This is an edge case where the update AND the rollback failed.
    /// From here onwards there is no good option left.
    Fatal,
}

/// Why a runtime update execution failed.
///
/// The severity follows from the variant and is read through
/// [`class`](Self::class) rather than chosen by the caller.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ExecutionFailure {
    /// The update was rejected and the previous database could not be brought
    /// back, so neither the candidate nor the previous state can be trusted.
    #[error(
        "Runtime update failed and the previous database could not be restored: {original}; \
         {recovery}"
    )]
    RecoveryFailed {
        /// Why the requested reload was rejected.
        original: ReloadError,
        /// Where restoring the previous state gave up.
        recovery: RecoveryError,
    },
    /// The update failed while the live runtime was left intact, so it can be
    /// retried. Covers a policy rejection, a precondition that was not met, a
    /// storage failure, and a reload that failed and was successfully restored.
    ///
    /// For `Cleanup` the live runtime is what is unchanged; the backup collection
    /// may already be partially deleted.
    #[error("{0}")]
    RuntimeUnchanged(Arc<RuntimeUpdateError>),
    /// The execution task ended without publishing a terminal status, so
    /// whether the update was applied is unknown.
    ///
    /// Deliberately carries no payload: the underlying `JoinError` renders a
    /// panic payload that can come from anywhere in the process, and this text
    /// reaches clients. The panic itself is logged where it is observed.
    #[error("Execution task ended abnormally")]
    AbnormalTermination,
    /// The disable lease held for the execution could not be concluded.
    ///
    /// Releasing it failing leaves the transport down when it should have come
    /// back; finishing it failing leaves pending lifecycle reconfiguration
    /// unfinished, even though staying down was the intended outcome. Either
    /// way communication is left disabled with no one having decided so, which
    /// is why [`Fatal`](ExecutionFailureClass::Fatal) is right for both: both
    /// need an operator.
    #[error(
        "{prefix}Runtime update failed while finalizing communication: the disable lease could \
         not be concluded, so communication stays disabled until an authorized activation: \
         {failure}",
        prefix = preceding.as_ref().map_or_else(String::new, |previous| format!("{previous}; "))
    )]
    CommunicationFinalizationFailed {
        /// The failure the execution already had, if it had one.
        preceding: Option<Box<ExecutionFailure>>,
        /// Why the disable lease could not be concluded.
        failure: CommunicationOperationFailure,
    },
}

impl ExecutionFailure {
    /// Returns the severity this failure implies.
    #[must_use]
    pub fn class(&self) -> ExecutionFailureClass {
        match self {
            Self::RuntimeUnchanged(_) => ExecutionFailureClass::Ordinary,
            Self::RecoveryFailed { .. }
            | Self::AbnormalTermination
            | Self::CommunicationFinalizationFailed { .. } => ExecutionFailureClass::Fatal,
        }
    }
}

/// Status of an in-progress or completed database update execution.
#[derive(Debug, Clone)]
pub enum ExecutionStatus {
    Running,
    Completed,
    Failed(ExecutionFailure),
}

// Bulk-data types used by RuntimeFilesUpdatePlugin

/// Hash algorithm for bulk-data integrity checks (ISO 17978-3).
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    Sha256,
}

/// A single item in a bulk-data creation response (Table 303 shape).
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct BulkDataCreated {
    /// Bulk-data identifier created by the SOVD server to identify the bulk-data.
    pub id: String,
}

/// Response body for deleting all bulk-data in a category (ISO 17978-3 Table 306).
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct BulkDataDeleted {
    pub deleted_ids: Vec<String>,
    // spec requires an errors array to be present, however with transaction semantics
    // this will always be an empty array
    pub errors: Vec<BulkDataDeletionError>,
}

/// A bulk-data item that could not be deleted and its reason.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct BulkDataDeletionError {
    pub id: String,
    pub error: serde_json::Value,
}

/// Generic list wrapper used for bulk-data responses.
#[derive(Deserialize, Serialize, Debug, schemars::JsonSchema)]
pub struct BulkDataItems<T> {
    pub items: Vec<T>,
    #[schemars(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<schemars::Schema>,
}

impl<T> Default for BulkDataItems<T> {
    fn default() -> Self {
        Self {
            items: Vec::new(),
            schema: None,
        }
    }
}

/// A bulk-data descriptor as defined by ISO 17978-3, Table 298.
#[derive(Serialize, Deserialize, Debug, Clone, schemars::JsonSchema)]
pub struct BulkDataDescriptor {
    pub id: String,
    pub mimetype: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_algorithm: Option<HashAlgorithm>,
    #[serde(
        rename = "x-sovd2uds-OrigPath",
        skip_serializing_if = "Option::is_none"
    )]
    pub origin_path: Option<String>,
    #[serde(
        rename = "x-sovd2uds-revision",
        skip_serializing_if = "Option::is_none"
    )]
    pub revision: Option<String>,
}

/// Response body for bulk-data list endpoints (`BulkDataDescriptor` follows Table 298 shape).
pub type BulkDataList = BulkDataItems<BulkDataDescriptor>;

/// Response body for bulk-data creation (Table 303 shape).
pub type BulkDataCreatedList = BulkDataItems<BulkDataCreated>;

/// Execution mode for database update operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, EnumString, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
#[strum(ascii_case_insensitive, serialize_all = "lowercase")]
pub enum ExecutionMode {
    /// Apply staged files as the new current version.
    Apply,
    /// Revert to the backup from the previous apply.
    Rollback,
    /// Remove staged and backup files without applying.
    Cleanup,
}

impl<'de> Deserialize<'de> for ExecutionMode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        ExecutionMode::from_str(&s).map_err(serde::de::Error::custom)
    }
}

/// Query parameters for runtime file list endpoints.
#[derive(Debug, Default, Deserialize, schemars::JsonSchema)]
pub struct RuntimeFilesQuery {
    #[serde(rename = "include-schema", default)]
    pub include_schema: bool,
    #[serde(rename = "x-sovd2uds-include-hash")]
    pub include_hash: Option<HashAlgorithm>,
    #[serde(rename = "x-sovd2uds-include-file-size", default)]
    pub include_file_size: bool,
    #[serde(rename = "x-sovd2uds-include-revision", default)]
    pub include_revision: bool,
    /// Accepted for ISO 17978-3 compatibility but not currently applied.
    #[serde(rename = "created-after")]
    pub created_after: Option<String>,
    /// Accepted for ISO 17978-3 compatibility but not currently applied.
    #[serde(rename = "created-before")]
    pub created_before: Option<String>,
}

/// Stored state for a single database update execution.
#[derive(Debug, Clone)]
pub struct UpdateExecution {
    pub id: String,
    pub mode: ExecutionMode,
    pub status: ExecutionStatus,
}

/// Read-only access to diagnostic runtime file collections.
///
/// Consumers of this capability receive no staging or execution authority.
#[async_trait]
pub trait RuntimeFileCatalog: Send + Sync + 'static {
    /// Lists the currently active diagnostic runtime files.
    ///
    /// Returns files currently loaded and in use by the system.
    async fn list_current(
        &self,
        query: &RuntimeFilesQuery,
    ) -> Result<BulkDataList, RuntimeUpdateError>;

    /// Lists files staged for the next update (pending apply).
    ///
    /// Returns files uploaded via [`RuntimeFileStore::upload`] that have not yet been applied.
    async fn list_nextupdate(
        &self,
        query: &RuntimeFilesQuery,
    ) -> Result<BulkDataList, RuntimeUpdateError>;

    /// Lists backup files from the previous apply operation.
    ///
    /// Returns files that were current before the last apply. Used for rollback.
    async fn list_backup(
        &self,
        query: &RuntimeFilesQuery,
    ) -> Result<BulkDataList, RuntimeUpdateError>;
}

/// Mutating the staging and backup areas.
#[async_trait]
pub trait RuntimeFileStore: Send + Sync + 'static {
    /// Uploads one or more files to the next-update staging area.
    ///
    /// Each file is content-checked through
    /// [`RuntimeFileInspector::check_integrity`] before it is accepted.
    async fn upload(
        &self,
        files: Vec<UploadFile>,
    ) -> Result<BulkDataCreatedList, RuntimeUpdateError>;

    /// Deletes all files from the next-update staging area and returns their identifiers.
    async fn delete_nextupdate(&self) -> Result<Vec<String>, RuntimeUpdateError>;

    /// Deletes a single file by ID from the next-update staging area.
    async fn delete_nextupdate_by_id(&self, file_id: &str) -> Result<(), RuntimeUpdateError>;

    /// Deletes all files from the backup area and returns their identifiers.
    async fn delete_backup(&self) -> Result<Vec<String>, RuntimeUpdateError>;
}

/// Running and observing apply / rollback / cleanup executions asynchronously:
/// [`start_execution`](Self::start_execution) returns a pollable id.
#[async_trait]
pub trait RuntimeUpdateExecutor: Send + Sync + 'static {
    /// Starts an asynchronous execution (Apply, Rollback, or Cleanup).
    ///
    /// Returns an execution ID that can be polled via [`get_execution_status`](Self::get_execution_status).
    async fn start_execution(&self, mode: ExecutionMode) -> Result<String, RuntimeUpdateError>;

    /// Returns all currently tracked executions. Always contains at most one entry;
    /// terminal-state entries are purged when the next execution starts.
    async fn list_executions(&self) -> Vec<UpdateExecution>;

    /// Returns the current status of an execution by its ID, or `None` if not found.
    async fn get_execution_status(&self, execution_id: &str) -> Option<UpdateExecution>;
}

/// The complete plugin surface for managing diagnostic runtime files.
///
/// Provides listing, staging mutation, and apply/rollback/cleanup execution.
/// Security validation for mutating operations is delegated to the associated
/// [`RuntimeUpdatePolicy`]. A blanket implementation composes the three
/// capabilities without granting any one capability additional authority.
pub trait RuntimeFilesUpdatePlugin:
    RuntimeFileCatalog + RuntimeFileStore + RuntimeUpdateExecutor + RuntimeFileTransaction
{
    /// Wraps this plugin in [`ExclusiveRuntimePlugin`], adding read/write mutual exclusion.
    fn with_exclusive_access(self) -> ExclusiveRuntimePlugin<Self>
    where
        Self: Sized,
    {
        ExclusiveRuntimePlugin::new(self)
    }
}

impl<P> RuntimeFilesUpdatePlugin for P where
    P: RuntimeFileCatalog + RuntimeFileStore + RuntimeUpdateExecutor + RuntimeFileTransaction
{
}

/// Wrapper that enforces mutual exclusion on any [`RuntimeFilesUpdatePlugin`].
///
/// Read operations (`list_*`, `get_execution_status`) acquire a shared read lock,
/// write operations (`upload`, `delete_*`, `start_execution`) acquire an exclusive
/// write lock. This prevents concurrent mutations from racing each other while
/// still allowing parallel reads.
///
/// Obtain via [`RuntimeFilesUpdatePlugin::with_exclusive_access`], which is a
/// provided default method on the trait.
pub struct ExclusiveRuntimePlugin<P> {
    inner: P,
    lock: tokio::sync::RwLock<()>,
}

impl<P> ExclusiveRuntimePlugin<P> {
    pub fn new(inner: P) -> Self {
        Self {
            inner,
            lock: tokio::sync::RwLock::new(()),
        }
    }
}

#[async_trait]
impl<P: RuntimeFileCatalog> RuntimeFileCatalog for ExclusiveRuntimePlugin<P> {
    async fn list_current(
        &self,
        query: &RuntimeFilesQuery,
    ) -> Result<BulkDataList, RuntimeUpdateError> {
        let _guard = self.lock.read().await;
        self.inner.list_current(query).await
    }

    async fn list_nextupdate(
        &self,
        query: &RuntimeFilesQuery,
    ) -> Result<BulkDataList, RuntimeUpdateError> {
        let _guard = self.lock.read().await;
        self.inner.list_nextupdate(query).await
    }

    async fn list_backup(
        &self,
        query: &RuntimeFilesQuery,
    ) -> Result<BulkDataList, RuntimeUpdateError> {
        let _guard = self.lock.read().await;
        self.inner.list_backup(query).await
    }
}

#[async_trait]
impl<P: RuntimeFileStore> RuntimeFileStore for ExclusiveRuntimePlugin<P> {
    async fn upload(
        &self,
        files: Vec<UploadFile>,
    ) -> Result<BulkDataCreatedList, RuntimeUpdateError> {
        let _guard = self.lock.write().await;
        self.inner.upload(files).await
    }

    async fn delete_nextupdate(&self) -> Result<Vec<String>, RuntimeUpdateError> {
        let _guard = self.lock.write().await;
        self.inner.delete_nextupdate().await
    }

    async fn delete_nextupdate_by_id(&self, file_id: &str) -> Result<(), RuntimeUpdateError> {
        let _guard = self.lock.write().await;
        self.inner.delete_nextupdate_by_id(file_id).await
    }

    async fn delete_backup(&self) -> Result<Vec<String>, RuntimeUpdateError> {
        let _guard = self.lock.write().await;
        self.inner.delete_backup().await
    }
}

#[async_trait]
impl<P: RuntimeUpdateExecutor> RuntimeUpdateExecutor for ExclusiveRuntimePlugin<P> {
    async fn start_execution(&self, mode: ExecutionMode) -> Result<String, RuntimeUpdateError> {
        let _guard = self.lock.write().await;
        self.inner.start_execution(mode).await
    }

    async fn get_execution_status(&self, execution_id: &str) -> Option<UpdateExecution> {
        let _guard = self.lock.read().await;
        self.inner.get_execution_status(execution_id).await
    }

    async fn list_executions(&self) -> Vec<UpdateExecution> {
        let _guard = self.lock.read().await;
        self.inner.list_executions().await
    }
}

/// Forwarded without the wrapper's lock: the transaction runs inside the staged
/// dispatch that [`RuntimeUpdateExecutor::start_execution`] admitted, and that
/// dispatch already holds the exclusive guards. Taking the write lock here would
/// only queue behind the call that started it.
#[async_trait]
impl<P: RuntimeFileTransaction> RuntimeFileTransaction for ExclusiveRuntimePlugin<P> {
    async fn apply_files(&self) -> Result<(), RuntimeUpdateError> {
        self.inner.apply_files().await
    }

    async fn rollback_files(&self) -> Result<(), RuntimeUpdateError> {
        self.inner.rollback_files().await
    }

    async fn discard_staged(&self) -> Result<(), RuntimeUpdateError> {
        self.inner.discard_staged().await
    }

    async fn cleanup_files(&self) -> Result<(), RuntimeUpdateError> {
        self.inner.cleanup_files().await
    }

    async fn restore_after_apply(&self) -> Result<(), RuntimeUpdateError> {
        self.inner.restore_after_apply().await
    }

    async fn restore_after_rollback(&self) -> Result<(), RuntimeUpdateError> {
        self.inner.restore_after_rollback().await
    }
}
