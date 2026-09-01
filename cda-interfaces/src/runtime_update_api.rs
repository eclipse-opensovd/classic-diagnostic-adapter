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
    storage_api::{Collection, DirectFileAccess},
};

mod error;
pub use error::{ReloadError, ReloadFailure, RuntimeUpdateError, VerificationError};

/// Application capability that prepares one complete runtime update.
///
/// The application owns the concrete data types and delivers each value directly
/// to its typed component owner. Implementations must finish every fallible step,
/// including dependent-resource preparation, before returning success. The
/// returned payload is applied directly to its owner once every participant
/// has succeeded.
#[async_trait]
pub trait ApplicationUpdatePreparation<Config>: Send + Sync + 'static
where
    Config: Send + Sync + 'static,
{
    /// Builds and stages a complete update while communication is disabled.
    ///
    /// # Errors
    /// Returns [`ReloadError`] if any component or dependent resource cannot be prepared.
    ///
    /// Staging happens only once every fallible step has succeeded, so a failed
    /// preparation leaves nothing staged and there is nothing to discard.
    async fn prepare_update(&self, config: &Config) -> Result<(), ReloadError>;
}

/// Opaque validated lock-topology payload that retains update admission until applied.
pub trait ReservedVehicleDatabaseLocks: Send {
    /// Publishes the validated topology. Synchronous and infallible: validation
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
    ) -> Result<Box<dyn ReservedVehicleDatabaseLocks>, ReloadError>;

    /// Validates a prospective lock-resource replacement without applying it.
    ///
    /// # Errors
    /// Returns an error when existing locks prevent updating the resource set.
    async fn validate_lock_resources(&self, ecu_names: &[String]) -> Result<(), ReloadError>;

    /// Validates and stages a replacement in one call for compatibility with
    /// direct owner users. Coordinators requiring an all-owner atomic apply must
    /// use [`Self::validate_lock_resources`] followed by [`Self::stage_lock_resources`].
    ///
    /// # Errors
    /// Returns an error when existing locks prevent updating the resource set.
    async fn update_lock_resources(&self, ecu_names: Vec<String>) -> Result<(), ReloadError>;
}

/// A file to be uploaded to the CDA during a runtime update.
#[derive(Debug)]
pub struct UploadFile {
    /// Name of the file including its extension (e.g. `"FLXC1000.mdd"`).
    pub filename: String,
    /// Raw file contents.
    pub data: Bytes,
}

/// Collections passed to [`RuntimeUpdateSecurityPlugin::check_execution_allowed`].
///
/// Provides direct access to the staged (`*NextUpdate`) and currently active collections
/// so implementations can inspect file lists, read metadata, or verify file content
/// before permitting an apply operation.
pub struct UpdateCollections<C: Collection + DirectFileAccess> {
    /// Staged MDD collection (`DiagnosticDatabaseNextUpdate`), or `None` if no update is pending.
    pub pending_mdd: Option<Arc<C>>,
    /// Currently active MDD collection (`DiagnosticDatabase`), or `None` if not yet initialized.
    pub current_mdd: Option<Arc<C>>,
}

impl<C: Collection + DirectFileAccess> Default for UpdateCollections<C> {
    fn default() -> Self {
        Self {
            pending_mdd: None,
            current_mdd: None,
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

    /// Returns `true` if any non-vehicle resource lock is currently held.
    async fn has_non_vehicle_locks(&self) -> bool;
}

/// Exact phase at which an update stopped being able to prove persistent/live coherence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryPhase {
    /// Preparing the candidate live state failed.
    CandidatePreparation,
    /// Restoring the previous persistent state failed.
    PersistentRestore,
    /// Preparing the restored live state failed.
    RestoredPreparation,
    /// Recommitting the restored persistent state failed.
    Recommit,
    /// Finalizing communication state failed.
    CommunicationFinalization,
}

/// Handler for reloading diagnostic runtime data after file operations (apply/rollback).
///
/// Implementors bridge the runtime-files plugin to the application's live diagnostic state,
/// ensuring that newly applied MDD databases are picked up without a restart.
#[async_trait]
pub trait RuntimeReloaderPlugin: Send + Sync + 'static {
    /// Loads (or re-loads) the MDD databases currently on disk into the running system.
    ///
    /// Called after a successful apply or rollback. The implementor resolves paths
    /// itself on every call, rather than trusting a caller-supplied list that could
    /// disagree with what was just committed. The caller holds a live disable
    /// lease, so no reader can have entered after communication went down.
    async fn reload_databases(&self) -> Result<(), ReloadFailure>;
}

/// Security and file integrity handler for the diagnostic database update process.
///
/// Implementors define the authorization and verification policies that guard
/// execution operations (apply, rollback) and file integrity checks. This is the
/// primary OEM extension point for adding custom lock validation, signature checks,
/// hash verification, version compatibility rules, or any other security requirements.
///
/// Execution ownership is enforced through this trait both before update guards are acquired and
/// again under those guards. HTTP adapters may perform the same check as defense in depth.
#[async_trait]
pub trait RuntimeUpdateSecurityPlugin<
    L: LockStateProvider,
    C: Collection + DirectFileAccess + Send + Sync + 'static,
>: Send + Sync + 'static
{
    /// Applies authoritative lock and content policy before an execution is registered.
    ///
    /// Implementations should verify caller authorization AND check for conflicting
    /// operations (e.g., active ECU or functional-group locks held by other callers).
    ///
    /// # Errors
    /// Returns an appropriate [`RuntimeUpdateError`] variant to deny the execution.
    async fn check_execution_allowed(
        &self,
        lock_state_provider: &L,
        collections: &UpdateCollections<C>,
    ) -> Result<(), RuntimeUpdateError>;

    /// Checks the integrity of all pending files before they are applied.
    ///
    /// Called during the apply operation with all pending MDD files.
    /// Implementations may perform signature verification, hash checks, version
    /// compatibility validation, or any other file-level security checks.
    ///
    /// # Arguments
    /// * `path` - Path to the file to validate
    ///
    /// # Errors
    /// Return [`VerificationError`] to abort the apply operation.
    async fn check_file_integrity(&self, path: &std::path::Path) -> Result<(), VerificationError>;
}

/// Internal classification of a runtime update execution failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionFailureClass {
    /// The operation was rejected or the previous state was fully restored.
    Ordinary,
    /// Recovery is incomplete and operator intervention is required.
    Fatal,
}

/// Safe public failure details for a runtime update execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionFailure {
    pub reason: String,
    pub class: ExecutionFailureClass,
}

impl ExecutionFailure {
    /// Creates an ordinary execution failure with a safe public reason.
    pub fn ordinary(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            class: ExecutionFailureClass::Ordinary,
        }
    }

    /// Creates a fatal execution failure with a safe public reason.
    pub fn fatal(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            class: ExecutionFailureClass::Fatal,
        }
    }
}

/// Status of an in-progress or completed database update execution.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Mutating the staging and backup areas. Every method authorizes through
/// [`RuntimeUpdateSecurityPlugin`] before touching anything.
#[async_trait]
pub trait RuntimeFileStore: Send + Sync + 'static {
    /// Uploads one or more files to the next-update staging area.
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
/// [`RuntimeUpdateSecurityPlugin`]. A blanket implementation composes the three
/// capabilities without granting any one capability additional authority.
pub trait RuntimeFilesUpdatePlugin:
    RuntimeFileCatalog + RuntimeFileStore + RuntimeUpdateExecutor
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
    P: RuntimeFileCatalog + RuntimeFileStore + RuntimeUpdateExecutor
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
