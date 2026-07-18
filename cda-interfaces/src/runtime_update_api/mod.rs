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
//! Provides the interface definitions for runtime file management (MDD databases and
//! configuration), including security handler traits, reload handler traits, and error types.
//!
//! The concrete plugin implementation lives in `cda-plugin-runtime-update`.

use std::{
    path::PathBuf,
    str::FromStr,
    sync::{Arc, atomic::AtomicBool},
};

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Deserializer, Serialize};
use strum_macros::EnumString;
use tokio::{sync::Mutex, task::JoinHandle};

use crate::{
    FunctionalDescriptionConfig, HashMap, Shutdown, UdsQuery,
    ecugateway::EcuGatewaySockets,
    file_manager::FileManager,
    storage_api::{Collection, DirectFileAccess},
};

mod error;
pub use error::{ConfigValidationError, ReloadError, RuntimeUpdateError, VerificationError};

/// Guards against activity during a runtime update.
pub trait ActivityGuard: Send + Sync + 'static {
    fn is_active(&self) -> bool;
}

impl ActivityGuard for Vec<Box<dyn ActivityGuard>> {
    fn is_active(&self) -> bool {
        self.iter().any(|g| g.is_active())
    }
}

/// The result of creating a fresh set of vehicle components inside
/// [`VehicleComponentFactory::create`].
pub struct VehicleComponents<UdsManager, EcuSockets, File>
where
    UdsManager: UdsQuery + Shutdown,
    EcuSockets: EcuGatewaySockets + Shutdown,
    File: FileManager,
{
    pub uds_manager: UdsManager,
    pub file_managers: HashMap<String, File>,
    pub diagnostic_gateway: EcuSockets,
    pub variant_detection_handle: JoinHandle<()>,
    pub functional_group_config: FunctionalDescriptionConfig,
}

/// Async factory that recreates vehicle components (UDS manager, `DoIP` gateway,
/// file managers, variant-detection task) from a configuration snapshot and new MDD paths.
///
///
/// # Type parameters
/// - `C`: opaque application configuration
/// - `Q`: UDS manager type - must implement [`UdsQuery`] + [`Shutdown`]
/// - `G`: diagnostic gateway type - must implement [`EcuGatewaySockets`] + [`Shutdown`]
#[async_trait]
pub trait VehicleComponentFactory<Config, Uds, Gateway>: Send + Sync + 'static
where
    Config: Send + Sync + 'static,
    Uds: UdsQuery + Shutdown,
    Gateway: EcuGatewaySockets + Shutdown,
{
    /// Concrete file-manager type produced by this factory.
    type FileManager: FileManager;

    /// Creates a fresh set of vehicle components.
    ///
    /// `existing_udp_socket` is the socket currently owned by the gateway that is being
    /// replaced.  The implementation should reuse it to avoid binding a second socket to
    /// the same port while the old gateway is still running.
    async fn create(
        &self,
        config: &Config,
        mdd_paths: &[PathBuf],
        update_in_progress: Arc<AtomicBool>,
        existing_udp_socket: Arc<Mutex<Gateway::Socket>>,
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
    /// Staged configuration collection (`ConfigurationNextUpdate`), or `None` if not pending.
    pub pending_config: Option<Arc<C>>,
    /// Currently active MDD collection (`DiagnosticDatabase`), or `None` if not yet initialized.
    pub current_mdd: Option<Arc<C>>,
    /// Currently active configuration collection (`Configuration`), or `None` if uninitialised.
    pub current_config: Option<Arc<C>>,
}

impl<C: Collection + DirectFileAccess> Default for UpdateCollections<C> {
    fn default() -> Self {
        Self {
            pending_mdd: None,
            pending_config: None,
            current_mdd: None,
            current_config: None,
        }
    }
}

/// Determines the kind of file being applied in a runtime update.
#[derive(Clone)]
pub enum UpdateFileType<'a> {
    /// A diagnostic database file (`.mdd`).
    Mdd,
    /// A CDA configuration file (`.toml`), with an associated config validator.
    Config(&'a dyn ConfigValidator),
}

impl std::fmt::Debug for UpdateFileType<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mdd => write!(f, "Mdd"),
            Self::Config(_) => write!(f, "Config"),
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
/// ensuring that newly applied MDD databases and configuration are picked up without a restart.
#[async_trait]
pub trait RuntimeReloaderPlugin: Send + Sync + 'static {
    /// Loads (or re-loads) the MDD databases at the given paths into the running system.
    ///
    /// Called after a successful apply operation with the paths of all newly active MDD files.
    async fn reload_databases(&self, mdd_paths: Vec<PathBuf>) -> Result<(), ReloadError>;

    /// Reloads the application configuration from the file at the given path.
    ///
    /// Called when a configuration file is part of the applied update.
    /// The default implementation is a no-op (returns `Ok(())`).
    async fn reload_configuration(&self, config_path: PathBuf) -> Result<(), ReloadError>;
}

/// Validates configuration file content during runtime updates.
///
/// Implementors parse and validate TOML (or other format) configuration files
/// to ensure they are syntactically valid and semantically acceptable before
/// being applied.
pub trait ConfigValidator: Send + Sync + 'static {
    /// Validates configuration file content.
    ///
    /// # Arguments
    /// * `content` - Raw file content as string
    ///
    /// # Returns
    /// * `Ok(())` if configuration is valid
    /// * `Err(ConfigValidationError)` if invalid
    /// # Errors
    /// Returns `ConfigValidationError` on failure during validation.
    fn validate(&self, content: &str) -> Result<(), ConfigValidationError>;
}

/// No-Op configuration validator, which can be used to skip configuration validation.
impl ConfigValidator for () {
    fn validate(&self, _content: &str) -> Result<(), ConfigValidationError> {
        Ok(())
    }
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
    /// Called during the apply operation with all pending MDD and configuration files.
    /// Implementations may perform signature verification, hash checks, version
    /// compatibility validation, or any other file-level security checks.
    ///
    /// The config validator, if needed, is embedded in the [`UpdateFileType::Config`] variant.
    ///
    /// # Arguments
    /// * `type_` - The type of file being validated (MDD or Config)
    /// * `path` - Path to the file to validate
    ///
    /// # Errors
    /// Return [`VerificationError`] to abort the apply operation.
    async fn check_file_integrity(
        &self,
        type_: UpdateFileType<'_>,
        path: &std::path::Path,
    ) -> Result<(), VerificationError>;
}

/// Status of an in-progress or completed database update execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionStatus {
    Running,
    Completed,
    Failed(String),
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
}

/// Stored state for a single database update execution.
#[derive(Debug, Clone)]
pub struct UpdateExecution {
    pub id: String,
    pub mode: ExecutionMode,
    pub status: ExecutionStatus,
}

// RuntimeFilesUpdatePlugin trait + ExclusiveRuntimePlugin wrapper

/// The main plugin trait for managing diagnostic runtime files (MDD databases and configuration).
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
        query: &RuntimeFilesQuery,
    ) -> Result<BulkDataList, RuntimeUpdateError>;

    /// Lists files staged for the next update (pending apply).
    ///
    /// Returns files uploaded via [`upload`] that have not yet been applied.
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

    /// Uploads one or more files to the next-update staging area.
    async fn upload(
        &self,
        files: Vec<UploadFile>,
    ) -> Result<BulkDataCreatedList, RuntimeUpdateError>;

    /// Deletes all files from the next-update staging area.
    async fn delete_nextupdate(&self) -> Result<(), RuntimeUpdateError>;

    /// Deletes a single file by ID from the next-update staging area.
    async fn delete_nextupdate_by_id(&self, file_id: &str) -> Result<(), RuntimeUpdateError>;

    /// Deletes all files from the backup area.
    async fn delete_backup(&self) -> Result<(), RuntimeUpdateError>;

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

/// Blanket implementation so that `Box<dyn RuntimeFilesUpdatePlugin>` (as produced
/// by `DeferredUpdatePluginFn`) can be passed directly to `add_runtime_update_routes`.
#[async_trait]
impl RuntimeFilesUpdatePlugin for Box<dyn RuntimeFilesUpdatePlugin> {
    async fn list_current(
        &self,
        query: &RuntimeFilesQuery,
    ) -> Result<BulkDataList, RuntimeUpdateError> {
        (**self).list_current(query).await
    }

    async fn list_nextupdate(
        &self,
        query: &RuntimeFilesQuery,
    ) -> Result<BulkDataList, RuntimeUpdateError> {
        (**self).list_nextupdate(query).await
    }

    async fn list_backup(
        &self,
        query: &RuntimeFilesQuery,
    ) -> Result<BulkDataList, RuntimeUpdateError> {
        (**self).list_backup(query).await
    }

    async fn upload(
        &self,
        files: Vec<UploadFile>,
    ) -> Result<BulkDataCreatedList, RuntimeUpdateError> {
        (**self).upload(files).await
    }

    async fn delete_nextupdate(&self) -> Result<(), RuntimeUpdateError> {
        (**self).delete_nextupdate().await
    }

    async fn delete_nextupdate_by_id(&self, file_id: &str) -> Result<(), RuntimeUpdateError> {
        (**self).delete_nextupdate_by_id(file_id).await
    }

    async fn delete_backup(&self) -> Result<(), RuntimeUpdateError> {
        (**self).delete_backup().await
    }

    async fn start_execution(&self, mode: ExecutionMode) -> Result<String, RuntimeUpdateError> {
        (**self).start_execution(mode).await
    }

    async fn list_executions(&self) -> Vec<UpdateExecution> {
        (**self).list_executions().await
    }

    async fn get_execution_status(&self, execution_id: &str) -> Option<UpdateExecution> {
        (**self).get_execution_status(execution_id).await
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

    async fn upload(
        &self,
        files: Vec<UploadFile>,
    ) -> Result<BulkDataCreatedList, RuntimeUpdateError> {
        let _guard = self.lock.write().await;
        self.inner.upload(files).await
    }

    async fn delete_nextupdate(&self) -> Result<(), RuntimeUpdateError> {
        let _guard = self.lock.write().await;
        self.inner.delete_nextupdate().await
    }

    async fn delete_nextupdate_by_id(&self, file_id: &str) -> Result<(), RuntimeUpdateError> {
        let _guard = self.lock.write().await;
        self.inner.delete_nextupdate_by_id(file_id).await
    }

    async fn delete_backup(&self) -> Result<(), RuntimeUpdateError> {
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
