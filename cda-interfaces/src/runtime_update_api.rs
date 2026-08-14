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
//! Provides the interface definitions for runtime MDD database management, including security
//! handler traits, reload handler traits, and error types.
//!
//! The concrete plugin implementation lives in `cda-plugin-runtime-update`.

use std::{path::PathBuf, str::FromStr, sync::Arc};

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Deserializer, Serialize};
use strum_macros::EnumString;

use crate::{
    FunctionalDescriptionConfig, HashMap, Shutdown, UdsQuery,
    file_manager::FileManager,
    storage_api::{Collection, DirectFileAccess},
};

mod error;
pub use error::{ReloadError, RuntimeUpdateError, VerificationError};

/// The result of creating a fresh set of vehicle components inside
/// [`VehicleComponentFactory::create`].
pub struct VehicleComponents<UdsManager, Gateway, File>
where
    UdsManager: UdsQuery + Shutdown,
    Gateway: Shutdown,
    File: FileManager,
{
    pub uds_manager: UdsManager,
    pub file_managers: HashMap<String, File>,
    pub diagnostic_gateway: Gateway,
    pub functional_group_config: FunctionalDescriptionConfig,
}

/// Async factory that recreates vehicle components (UDS manager, diagnostic gateway,
/// file managers) from a configuration snapshot and new MDD paths.
///
///
/// # Type parameters
/// - `C`: opaque application configuration
/// - `Q`: UDS manager type - must implement [`UdsQuery`] + [`Shutdown`]
/// - `G`: diagnostic gateway type - must implement [`Shutdown`]
#[async_trait]
pub trait VehicleComponentFactory<Config, Uds, Gateway>: Send + Sync + 'static
where
    Config: Send + Sync + 'static,
    Uds: UdsQuery + Shutdown,
    Gateway: Shutdown,
{
    /// Concrete file-manager type produced by this factory.
    type FileManager: FileManager;

    /// Creates a fresh set of vehicle components.
    ///
    async fn create(
        &self,
        config: &Config,
        mdd_paths: &[PathBuf],
    ) -> Result<VehicleComponents<Uds, Gateway, Self::FileManager>, ReloadError>;
}

/// A file to be uploaded to the CDA during a runtime update.
#[derive(Debug)]
pub struct UploadFile {
    /// Name of the file including its extension (e.g. `"FLXC1000.mdd"`).
    pub filename: String,
    /// Raw file contents.
    pub data: Bytes,
}

/// Collections passed to [`RuntimeUpdateSecurityPlugin::check_apply_allowed`].
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

/// Provides read-only access to vehicle lock state for security validation.
///
/// Implemented by the SOVD server to expose lock information to plugins
/// without creating a dependency on cda-sovd. OEMs may replace this
/// implementation to integrate custom lock management systems.
#[async_trait]
pub trait LockStateProvider: Send + Sync + 'static {
    /// Returns the `sub` claim of the vehicle lock owner, or `None` if no vehicle lock is held.
    async fn vehicle_lock_owner_sub(&self) -> Option<String>;

    /// Returns `true` if any ECU or functional-group lock is currently held.
    async fn has_non_vehicle_locks(&self) -> bool;
}

/// Handler for reloading diagnostic runtime data after file operations (apply/rollback).
///
/// Implementors bridge the runtime-files plugin to the application's live diagnostic state,
/// ensuring that newly applied MDD databases are picked up without a restart.
#[async_trait]
pub trait RuntimeReloaderPlugin: Send + Sync + 'static {
    /// Loads (or re-loads) the MDD databases at the given paths into the running system.
    ///
    /// Called after a successful apply operation with the paths of all newly active MDD files.
    async fn reload_databases(&self, mdd_paths: Vec<PathBuf>) -> Result<(), ReloadError>;
}

/// Security and file integrity handler for the diagnostic database update process.
///
/// Implementors define the authorization and verification policies that guard
/// execution operations (apply, rollback) and file integrity checks. This is the
/// primary OEM extension point for adding custom lock validation, signature checks,
/// hash verification, version compatibility rules, or any other security requirements.
///
/// Vehicle lock ownership for modifying operations (upload, delete) is enforced at
/// the HTTP handler layer in cda-sovd, not through this trait.
#[async_trait]
pub trait RuntimeUpdateSecurityPlugin<
    L: LockStateProvider,
    C: Collection + DirectFileAccess + Send + Sync + 'static,
>: Send + Sync + 'static
{
    /// Validates that the caller is allowed to start an execution (apply/rollback/cleanup).
    /// Called by the plugin before `start_execution`.
    ///
    /// Implementations should verify caller authorization AND check for conflicting
    /// operations (e.g., active ECU or functional-group locks held by other callers).
    /// `collections` provides handles to the staged and currently active file collections
    /// for version compatibility or signature checks.
    ///
    /// # Errors
    /// Return an appropriate [`RuntimeUpdateError`] variant to deny the execution.
    async fn check_apply_allowed(
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

/// Status of an in-progress or completed database update execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionStatus {
    Running,
    Completed,
    Failed(String),
}

/// Digest algorithm for runtime-file integrity reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
}

/// A digest of a runtime file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHash {
    pub algorithm: HashAlgorithm,
    /// Lower-case hex.
    pub value: String,
}

/// A runtime database file as the update plugin describes it.
///
/// Domain shape, not a wire shape: the ISO 17978-3 bulk-data representation -
/// `mimetype`, the duplicate `name`, the `x-sovd2uds-*` field names, the schema
/// envelope - lives in `cda-sovd-interfaces` and is produced by `cda-sovd` when
/// rendering a response. A plugin reports what it knows and nothing more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeFile {
    /// Identifier, which is also the file name.
    pub id: String,
    /// Byte size, when [`FileListOptions::include_size`] was requested.
    pub size: Option<u64>,
    /// Digest, when [`FileListOptions::include_hash`] was requested.
    pub hash: Option<FileHash>,
    /// Format-reported revision, when [`FileListOptions::include_revision`] was
    /// requested and the file carries one.
    pub revision: Option<String>,
}

/// Which optional metadata a listing should compute.
///
/// Each field costs work - hashing reads the whole file, revision parses it -
/// so they are opt-in per request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FileListOptions {
    pub include_size: bool,
    pub include_hash: Option<HashAlgorithm>,
    pub include_revision: bool,
}

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

/// Stored state for a single database update execution.
#[derive(Debug, Clone)]
pub struct UpdateExecution {
    pub id: String,
    pub mode: ExecutionMode,
    pub status: ExecutionStatus,
}

// RuntimeFilesUpdatePlugin trait + ExclusiveRuntimePlugin wrapper

/// The main plugin trait for managing diagnostic runtime files (MDD databases).
///
/// Provides the full lifecycle for runtime file management: listing, uploading, deleting,
/// and executing apply/rollback/cleanup operations on the diagnostic database.
///
/// Security validation for mutating operations is delegated to the associated
/// [`RuntimeUpdateSecurityPlugin`].
#[async_trait]
pub trait RuntimeFilesUpdatePlugin: Send + Sync + 'static {
    /// Lists the currently active diagnostic runtime files.
    ///
    /// Returns files currently loaded and in use by the system.
    async fn list_current(
        &self,
        options: FileListOptions,
    ) -> Result<Vec<RuntimeFile>, RuntimeUpdateError>;

    /// Lists files staged for the next update (pending apply).
    ///
    /// Returns files uploaded via [`upload`] that have not yet been applied.
    async fn list_nextupdate(
        &self,
        options: FileListOptions,
    ) -> Result<Vec<RuntimeFile>, RuntimeUpdateError>;

    /// Lists backup files from the previous apply operation.
    ///
    /// Returns files that were current before the last apply. Used for rollback.
    async fn list_backup(
        &self,
        options: FileListOptions,
    ) -> Result<Vec<RuntimeFile>, RuntimeUpdateError>;

    /// Uploads one or more files to the next-update staging area.
    /// Returns the identifiers of the created files.
    async fn upload(&self, files: Vec<UploadFile>) -> Result<Vec<String>, RuntimeUpdateError>;

    /// Deletes all files from the next-update staging area and returns their identifiers.
    async fn delete_nextupdate(&self) -> Result<Vec<String>, RuntimeUpdateError>;

    /// Deletes a single file by ID from the next-update staging area.
    async fn delete_nextupdate_by_id(&self, file_id: &str) -> Result<(), RuntimeUpdateError>;

    /// Deletes all files from the backup area and returns their identifiers.
    async fn delete_backup(&self) -> Result<Vec<String>, RuntimeUpdateError>;

    /// Starts an asynchronous execution (Apply, Rollback, or Cleanup).
    ///
    /// Returns an execution ID that can be polled via [`get_execution_status`].
    async fn start_execution(&self, mode: ExecutionMode) -> Result<String, RuntimeUpdateError>;

    /// Returns all currently tracked executions. Always contains at most one entry;
    /// terminal-state entries are purged when the next execution starts.
    async fn list_executions(&self) -> Vec<UpdateExecution>;

    /// Returns the current status of an execution by its ID, or `None` if not found.
    async fn get_execution_status(&self, execution_id: &str) -> Option<UpdateExecution>;

    /// Wraps this plugin in [`ExclusiveRuntimePlugin`], adding read/write mutual exclusion.
    fn with_exclusive_access(self) -> ExclusiveRuntimePlugin<Self>
    where
        Self: Sized,
    {
        ExclusiveRuntimePlugin::new(self)
    }
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
impl<P: RuntimeFilesUpdatePlugin> RuntimeFilesUpdatePlugin for ExclusiveRuntimePlugin<P> {
    async fn list_current(
        &self,
        options: FileListOptions,
    ) -> Result<Vec<RuntimeFile>, RuntimeUpdateError> {
        let _guard = self.lock.read().await;
        self.inner.list_current(options).await
    }

    async fn list_nextupdate(
        &self,
        options: FileListOptions,
    ) -> Result<Vec<RuntimeFile>, RuntimeUpdateError> {
        let _guard = self.lock.read().await;
        self.inner.list_nextupdate(options).await
    }

    async fn list_backup(
        &self,
        options: FileListOptions,
    ) -> Result<Vec<RuntimeFile>, RuntimeUpdateError> {
        let _guard = self.lock.read().await;
        self.inner.list_backup(options).await
    }

    async fn upload(&self, files: Vec<UploadFile>) -> Result<Vec<String>, RuntimeUpdateError> {
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
