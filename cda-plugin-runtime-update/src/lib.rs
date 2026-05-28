// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use bytes::Bytes;
pub use default_runtime_update_plugin::DefaultRuntimeFilesUpdatePlugin;
use sovd_interfaces::{
    apps::sovd2uds::bulk_data::{
        BulkDataCreated, BulkDataCreatedList, BulkDataList,
        runtimefiles::{ExecutionMode, RuntimeFilesQuery},
    },
    sovd2uds::{BulkDataDescriptor, HashAlgorithm},
};

pub mod error;
pub use error::{ReloadError, RuntimeUpdateError, VerificationError};

pub mod config;
pub mod default_runtime_update_plugin;
pub mod operations;
pub mod storage;

/// Guards against running operations during a runtime update.
pub trait ActiveOperationsGuard: Send + Sync + 'static {
    fn has_active_operations(&self) -> bool;
}

macro_rules! impl_active_operations_guard_for_tuple {
    ($($idx:tt $T:ident),+) => {
        impl<$($T: ActiveOperationsGuard),+> ActiveOperationsGuard for ($($T,)+) {
            fn has_active_operations(&self) -> bool {
                $(self.$idx.has_active_operations())||+
            }
        }
    };
}

// Support up to 5 active operations guard. CDA internally currently is using up to two.
// Defining more, so it can be used liberally when it's used as a library.
// The alternative would be to use Vec<dyn ActiveOperationsGuard> instead of the type parameter
impl_active_operations_guard_for_tuple!(0 A, 1 B);
impl_active_operations_guard_for_tuple!(0 A, 1 B, 2 C);
impl_active_operations_guard_for_tuple!(0 A, 1 B, 2 C, 3 D);
impl_active_operations_guard_for_tuple!(0 A, 1 B, 2 C, 3 D, 4 E);

/// A file to be uploaded to the CDA during a runtime update.
#[derive(Debug)]
pub struct UploadFile {
    /// Name of the file including its extension (e.g. `"FLXC1000.mdd"`).
    pub filename: String,
    /// Raw file contents.
    pub data: Bytes,
}

/// Determines the kind of file being applied in a runtime update.
#[derive(Debug, Clone)]
pub enum UpdateFileType {
    /// A diagnostic database file (`.mdd`).
    Mdd,
    /// A CDA configuration file (`.toml`).
    Config,
}

/// Provides read-only access to vehicle lock state for security validation.
///
/// Implemented by the SOVD server to expose lock information to plugins
/// without creating a dependency on cda-sovd. OEMs may replace this
/// implementation to integrate custom lock management systems.
#[async_trait]
pub trait LockStateProvider: Send + Sync + 'static {
    /// Returns the `sub` claim of the vehicle lock owner, or `None` if no vehicle lock is held.
    async fn is_vehicle_lock_owned(&self) -> Option<String>;

    /// Returns `true` if any ECU or functional-group lock is currently held.
    async fn has_non_vehicle_locks(&self) -> bool;
}

/// Handler for reloading diagnostic runtime data after file operations (apply/rollback).
///
/// Implementors bridge the runtime-files plugin to the application's live diagnostic state,
/// ensuring that newly applied MDD databases and configuration are picked up without a restart.
#[async_trait]
pub trait RuntimeFileReloadHandler: Send + Sync + 'static {
    /// Loads (or re-loads) the MDD databases at the given paths into the running system.
    ///
    /// Called after a successful apply operation with the paths of all newly active MDD files.
    async fn reload_databases(&self, mdd_paths: Vec<PathBuf>) -> Result<(), ReloadError>;

    /// Reloads the application configuration from the file at the given path.
    ///
    /// Called when a configuration file is part of the applied update.
    /// The default implementation is a no-op (returns `Ok(())`).
    async fn reload_configuration(&self, _config_path: PathBuf) -> Result<(), ReloadError>;
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
pub trait RuntimeFilesUpdateSecurityHandler<L: LockStateProvider>: Send + Sync + 'static {
    /// Validates that the caller is allowed to start an execution (apply/rollback/cleanup).
    /// Called by the plugin before `start_execution`.
    ///
    /// Implementations should verify caller authorization AND check for conflicting
    /// operations (e.g., active ECU or functional-group locks held by other callers).
    ///
    /// # Errors
    /// Return an appropriate [`RuntimeUpdateError`] variant to deny the execution.
    async fn check_apply_allowed(&self, lock_state_provider: &L) -> Result<(), RuntimeUpdateError>;

    /// Checks the integrity of all pending files before they are applied.
    ///
    /// Called during the apply operation with all pending MDD and configuration files.
    /// Implementations may perform signature verification, hash checks, version
    /// compatibility validation, or any other file-level security checks.
    ///
    /// # Errors
    /// Return [`VerificationError`] to abort the apply operation.
    async fn check_file_integrity(
        &self,
        type_: UpdateFileType,
        path: &Path,
    ) -> Result<(), VerificationError>;
}

/// The main plugin trait for managing diagnostic runtime files (MDD databases and configuration).
///
/// Provides the full lifecycle for runtime file management: listing, uploading, deleting,
/// and executing apply/rollback/cleanup operations on the diagnostic database.
///
/// Security validation for mutating operations is delegated to the associated
/// [`RuntimeFilesUpdateSecurityHandler`].
#[allow(clippy::ptr_arg)]
/// ```
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

    /// Returns the current status of an execution by its ID, or `None` if not found.
    async fn get_execution_status(&self, execution_id: &str) -> Option<UpdateExecution>;
}

/// Status of an in-progress or completed database update execution.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionStatus {
    Running,
    Completed,
    Failed(String),
}

/// Stored state for a single database update execution.
#[derive(Debug, Clone)]
pub struct UpdateExecution {
    pub id: String,
    pub mode: ExecutionMode,
    pub status: ExecutionStatus,
}

/// Shared test utilities for the runtime update plugin tests.
#[cfg(test)]
pub(crate) mod test_utils {
    use std::{
        path::PathBuf,
        sync::{Arc, Mutex},
    };

    use async_trait::async_trait;
    use bytes::Bytes;
    use cda_interfaces::storage_api::{
        Collection as _, CollectionName, ReadableStream, Storage, Transaction,
    };
    use cda_storage::LocalStorage;

    use crate::{
        LockStateProvider, ReloadError, RuntimeFileReloadHandler, RuntimeUpdateError,
        UpdateFileType, UploadFile, VerificationError,
    };

    pub(crate) async fn write_file(
        storage: &impl Storage,
        tx: &mut Transaction,
        collection_name: &CollectionName,
        key: &str,
        data: &mut impl ReadableStream,
    ) -> Result<(), crate::RuntimeUpdateError> {
        let key = key.to_lowercase();
        let collection = storage.get_or_create_collection(collection_name).await?;
        collection.write(tx, &key, data).await?;
        Ok(())
    }

    pub struct MockLockProvider {
        pub owner: Option<String>,
        pub has_conflicts: bool,
    }

    #[async_trait]
    impl LockStateProvider for MockLockProvider {
        async fn is_vehicle_lock_owned(&self) -> Option<String> {
            self.owner.clone()
        }

        async fn has_non_vehicle_locks(&self) -> bool {
            self.has_conflicts
        }
    }

    pub struct MockSecurityHandler;

    impl MockSecurityHandler {
        pub fn new(_lock_provider: Arc<dyn LockStateProvider>) -> Self {
            Self
        }
    }

    #[async_trait]
    impl<L: LockStateProvider> crate::RuntimeFilesUpdateSecurityHandler<L> for MockSecurityHandler {
        async fn check_apply_allowed(
            &self,
            lock_state_provider: &L,
        ) -> Result<(), RuntimeUpdateError> {
            let owner = lock_state_provider.is_vehicle_lock_owned().await;
            match owner {
                None => Err(RuntimeUpdateError::NoLock),
                Some(_) => Ok(()),
            }
        }

        async fn check_file_integrity(
            &self,
            _type: UpdateFileType,
            _path: &std::path::Path,
        ) -> Result<(), VerificationError> {
            Ok(())
        }
    }

    pub fn make_valid_mdd(ecu_name: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"MDD version 0      \0");
        buf.extend_from_slice(&[0x0a, 0x01, 0x31]);
        buf.push(0x1a);
        #[allow(clippy::cast_possible_truncation)]
        buf.push(ecu_name.len() as u8);
        buf.extend_from_slice(ecu_name.as_bytes());
        buf
    }

    pub fn make_valid_config() -> Vec<u8> {
        b"[server]\nport = 8080\n".to_vec()
    }

    pub async fn write_test_file(
        storage: &LocalStorage,
        collection_name: &CollectionName,
        key: &str,
        data: &[u8],
    ) {
        let col = storage
            .get_or_create_collection(collection_name)
            .await
            .unwrap();
        let mut tx = storage.begin_transaction().unwrap();
        let mut cursor: &[u8] = data;
        col.write(&mut tx, key, &mut cursor).await.unwrap();
        tx.commit().await.unwrap();
    }

    pub fn make_upload_files(entries: &[(&str, &[u8])]) -> Vec<UploadFile> {
        entries
            .iter()
            .filter(|(name, _)| !name.is_empty())
            .map(|(name, data)| UploadFile {
                filename: name.to_string(),
                data: Bytes::copy_from_slice(data),
            })
            .collect()
    }

    pub fn make_storage() -> (LocalStorage, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = LocalStorage::new(dir.path()).expect("LocalStorage");
        (storage, dir)
    }

    pub async fn init_collection(
        storage: &LocalStorage,
        name: &CollectionName,
        keys: &[(&str, &[u8])],
    ) {
        storage.get_or_create_collection(name).await.unwrap();
        let mut tx = storage.begin_transaction().unwrap();
        for (key, data) in keys {
            let mut d: &[u8] = data;
            write_file(storage, &mut tx, name, key, &mut d)
                .await
                .unwrap();
        }
        tx.commit().await.unwrap();
    }

    pub struct RecordingReloadHandler {
        pub reload_calls: Arc<Mutex<Vec<Vec<PathBuf>>>>,
        pub config_calls: Arc<Mutex<Vec<PathBuf>>>,
    }

    impl RecordingReloadHandler {
        pub fn new() -> Self {
            Self {
                reload_calls: Arc::new(Mutex::new(Vec::new())),
                config_calls: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    #[async_trait]
    impl RuntimeFileReloadHandler for RecordingReloadHandler {
        async fn reload_databases(&self, paths: Vec<PathBuf>) -> Result<(), ReloadError> {
            self.reload_calls.lock().unwrap().push(paths);
            Ok(())
        }

        async fn reload_configuration(&self, path: PathBuf) -> Result<(), ReloadError> {
            self.config_calls.lock().unwrap().push(path);
            Ok(())
        }
    }

    /// A [`RuntimeFileReloadHandler`] that does nothing, useful as a default in tests.
    pub struct NoopReloadHandler;

    #[async_trait]
    impl RuntimeFileReloadHandler for NoopReloadHandler {
        async fn reload_databases(&self, _mdd_paths: Vec<PathBuf>) -> Result<(), ReloadError> {
            Ok(())
        }

        async fn reload_configuration(&self, _config_path: PathBuf) -> Result<(), ReloadError> {
            Ok(())
        }
    }
}
