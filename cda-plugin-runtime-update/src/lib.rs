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

pub use default_runtime_update_plugin::DefaultRuntimeUpdatePlugin;
pub use security::DefaultUpdateSecurityHandler;

pub mod config;
pub mod default_runtime_reloader_plugin;
pub use default_runtime_reloader_plugin::{ReloadContext, RuntimeReloaderConfig};
pub mod default_runtime_update_plugin;
pub mod operations;
pub mod security;
pub mod storage;

use std::sync::{Arc, atomic::AtomicBool};

use cda_interfaces::runtime_update_api::{
    ConfigValidator, LockStateProvider, RuntimeFilesUpdatePlugin, RuntimeReloaderPlugin,
    RuntimeUpdateError, RuntimeUpdateSecurityPlugin,
};
use cda_storage::{LocalCollection, LocalStorage};

/// Initializes the default runtime-update plugin with a local storage backend.
///
/// This replaces the former `DefaultRuntimeFilesUpdatePluginLoader` factory trait: callers
/// construct the plugin directly via this function. The reload handler is accepted as
/// `Arc<dyn RuntimeReloaderPlugin>`, allowing any implementation to be injected.
///
/// # Type parameters
/// * `T` - security/integrity handler ([`RuntimeUpdateSecurityPlugin`])
/// * `L` - lock-state provider ([`LockStateProvider`])
/// * `V` - config validator ([`ConfigValidator`]; use `()` if no validation is needed)
///
/// # Errors
/// Returns [`RuntimeUpdateError`] if the local storage directory cannot be initialised.
pub fn init_default_runtime_update_plugin<T, L, V>(
    storage_dir: &str,
    reloader_plugin: Arc<dyn RuntimeReloaderPlugin>,
    security_handler: Arc<T>,
    lock_provider: Arc<L>,
    mdd_decompress: bool,
    update_in_progress: Arc<AtomicBool>,
    config_validator: V,
) -> Result<impl RuntimeFilesUpdatePlugin + use<T, L, V>, RuntimeUpdateError>
where
    T: RuntimeUpdateSecurityPlugin<L, LocalCollection>,
    L: LockStateProvider,
    V: ConfigValidator,
{
    let storage = Arc::new(LocalStorage::new(storage_dir)?);
    Ok(DefaultRuntimeUpdatePlugin::new(
        storage,
        reloader_plugin,
        security_handler,
        lock_provider,
        mdd_decompress,
        update_in_progress,
        config_validator,
    ))
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
    use cda_interfaces::{
        runtime_update_api::{
            ConfigValidator, LockStateProvider, ReloadError, RuntimeReloaderPlugin,
            RuntimeUpdateError, UpdateFileType, UploadFile, VerificationError,
        },
        storage_api::{
            Collection, CollectionName, DirectFileAccess, ReadableStream, Storage, Transaction,
        },
    };
    use cda_storage::LocalStorage;

    pub(crate) async fn write_file(
        storage: &impl Storage,
        tx: &mut Transaction,
        collection_name: &CollectionName,
        key: &str,
        data: &mut impl ReadableStream,
    ) -> Result<(), RuntimeUpdateError> {
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
        async fn vehicle_lock_owner_sub(&self) -> Option<String> {
            self.owner.clone()
        }

        async fn has_non_vehicle_locks(&self) -> bool {
            self.has_conflicts
        }
    }

    pub struct MockSecurityHandler;

    impl MockSecurityHandler {
        pub fn new() -> Self {
            Self
        }
    }

    #[async_trait]
    impl<L: LockStateProvider, C: Collection + DirectFileAccess + Send + Sync + 'static>
        cda_interfaces::runtime_update_api::RuntimeUpdateSecurityPlugin<L, C>
        for MockSecurityHandler
    {
        async fn check_apply_allowed(
            &self,
            lock_state_provider: &L,
            _collections: &cda_interfaces::runtime_update_api::UpdateCollections<C>,
        ) -> Result<(), RuntimeUpdateError> {
            let owner = lock_state_provider.vehicle_lock_owner_sub().await;
            match owner {
                None => Err(RuntimeUpdateError::NoLock(
                    "No vehicle lock held".to_string(),
                )),
                Some(_) => Ok(()),
            }
        }

        async fn check_file_integrity<V: ConfigValidator>(
            &self,
            _type: UpdateFileType,
            _path: &std::path::Path,
            _config_validator: &V,
        ) -> Result<(), VerificationError> {
            Ok(())
        }
    }

    pub fn make_valid_mdd(ecu_name: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"MDD version 0      \0");
        buf.extend_from_slice(&[0x0A, 0x01, 0x31]);
        buf.push(0x1A);
        buf.push(u8::try_from(ecu_name.len()).expect("ecu_name must be <= 255 bytes"));
        buf.extend_from_slice(ecu_name.as_bytes());
        buf
    }

    /// Like `make_valid_mdd` but also encodes a `revision` field (proto tag 4).
    pub fn make_valid_mdd_with_revision(ecu_name: &str, revision: &str) -> Vec<u8> {
        let mut buf = make_valid_mdd(ecu_name);
        // Proto field 4, wire type 2 (length-delimited) -> tag byte 0x22
        buf.push(0x22);
        buf.push(u8::try_from(revision.len()).expect("revision must be <= 255 bytes"));
        buf.extend_from_slice(revision.as_bytes());
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
                filename: (*name).to_string(),
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
    impl RuntimeReloaderPlugin for RecordingReloadHandler {
        async fn reload_databases(&self, paths: Vec<PathBuf>) -> Result<(), ReloadError> {
            self.reload_calls.lock().unwrap().push(paths);
            Ok(())
        }

        async fn reload_configuration(&self, path: PathBuf) -> Result<(), ReloadError> {
            self.config_calls.lock().unwrap().push(path);
            Ok(())
        }
    }

    /// A [`RuntimeReloaderPlugin`] that does nothing, useful as a default in tests.
    pub struct NoopReloadHandler;

    #[async_trait]
    impl RuntimeReloaderPlugin for NoopReloadHandler {
        async fn reload_databases(&self, _mdd_paths: Vec<PathBuf>) -> Result<(), ReloadError> {
            Ok(())
        }

        async fn reload_configuration(&self, _config_path: PathBuf) -> Result<(), ReloadError> {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use async_trait::async_trait;
    use cda_interfaces::runtime_update_api::{
        BulkDataCreatedList, BulkDataList, ExclusiveRuntimePlugin, ExecutionMode,
        RuntimeFilesQuery, RuntimeFilesUpdatePlugin, RuntimeUpdateError, UpdateExecution,
        UploadFile,
    };
    use tokio::sync::{Barrier, Notify};

    struct DelayPlugin {
        read_barrier: Arc<Barrier>,
        read_notify: Arc<Notify>,
        write_barrier: Arc<Barrier>,
        write_notify: Arc<Notify>,
        concurrent_reads: Arc<AtomicUsize>,
        concurrent_writes: Arc<AtomicUsize>,
    }

    type PluginHandle = ExclusiveRuntimePlugin<DelayPlugin>;
    type Counter = Arc<AtomicUsize>;
    type Notifier = Arc<Notify>;

    #[async_trait]
    impl RuntimeFilesUpdatePlugin for DelayPlugin {
        async fn list_current(
            &self,
            _query: &RuntimeFilesQuery,
        ) -> Result<BulkDataList, RuntimeUpdateError> {
            self.concurrent_reads.fetch_add(1, Ordering::SeqCst);
            self.read_barrier.wait().await;
            self.read_notify.notified().await;
            self.concurrent_reads.fetch_sub(1, Ordering::SeqCst);
            Ok(BulkDataList {
                items: vec![],
                schema: None,
            })
        }

        async fn list_nextupdate(
            &self,
            _query: &RuntimeFilesQuery,
        ) -> Result<BulkDataList, RuntimeUpdateError> {
            Ok(BulkDataList {
                items: vec![],
                schema: None,
            })
        }

        async fn list_backup(
            &self,
            _query: &RuntimeFilesQuery,
        ) -> Result<BulkDataList, RuntimeUpdateError> {
            Ok(BulkDataList {
                items: vec![],
                schema: None,
            })
        }

        async fn upload(
            &self,
            _files: Vec<UploadFile>,
        ) -> Result<BulkDataCreatedList, RuntimeUpdateError> {
            self.concurrent_writes.fetch_add(1, Ordering::SeqCst);
            self.write_barrier.wait().await;
            self.write_notify.notified().await;
            self.concurrent_writes.fetch_sub(1, Ordering::SeqCst);
            Ok(<_>::default())
        }

        async fn delete_nextupdate(&self) -> Result<(), RuntimeUpdateError> {
            self.concurrent_writes.fetch_add(1, Ordering::SeqCst);
            self.write_barrier.wait().await;
            self.write_notify.notified().await;
            self.concurrent_writes.fetch_sub(1, Ordering::SeqCst);
            Ok(())
        }

        async fn delete_nextupdate_by_id(&self, _file_id: &str) -> Result<(), RuntimeUpdateError> {
            Ok(())
        }

        async fn delete_backup(&self) -> Result<(), RuntimeUpdateError> {
            Ok(())
        }

        async fn start_execution(
            &self,
            _mode: ExecutionMode,
        ) -> Result<String, RuntimeUpdateError> {
            Ok("exec-1".to_owned())
        }

        async fn get_execution_status(&self, _execution_id: &str) -> Option<UpdateExecution> {
            None
        }

        async fn list_executions(&self) -> Vec<UpdateExecution> {
            vec![]
        }
    }

    fn make_plugin(
        read_count: usize,
        write_count: usize,
    ) -> (PluginHandle, Counter, Counter, Notifier, Notifier) {
        let read_notify = Arc::new(Notify::new());
        let write_notify = Arc::new(Notify::new());
        let concurrent_reads = Arc::new(AtomicUsize::new(0));
        let concurrent_writes = Arc::new(AtomicUsize::new(0));
        let plugin = DelayPlugin {
            read_barrier: Arc::new(Barrier::new(read_count)),
            read_notify: Arc::clone(&read_notify),
            write_barrier: Arc::new(Barrier::new(write_count)),
            write_notify: Arc::clone(&write_notify),
            concurrent_reads: Arc::clone(&concurrent_reads),
            concurrent_writes: Arc::clone(&concurrent_writes),
        };
        (
            plugin.with_exclusive_access(),
            concurrent_reads,
            concurrent_writes,
            read_notify,
            write_notify,
        )
    }

    #[tokio::test]
    async fn concurrent_reads_are_parallel() {
        let (plugin, concurrent_reads, _, read_notify, _) = make_plugin(2, 1);
        let plugin = Arc::new(plugin);
        let p1 = Arc::clone(&plugin);
        let t1 =
            tokio::spawn(async move { p1.list_current(&<RuntimeFilesQuery>::default()).await });

        let p2 = Arc::clone(&plugin);
        let t2 =
            tokio::spawn(async move { p2.list_current(&<RuntimeFilesQuery>::default()).await });

        // Both tasks will reach the barrier and wait, proving they run concurrently.
        // Once both hit the barrier they proceed to notified() - at that point
        // concurrent_reads must be 2.
        tokio::task::yield_now().await;
        // Allow a few yields for tasks to reach the barrier
        for _ in 0..10 {
            if concurrent_reads.load(Ordering::SeqCst) == 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(concurrent_reads.load(Ordering::SeqCst), 2);

        read_notify.notify_waiters();
        t1.await.unwrap().unwrap();
        t2.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn write_excludes_other_writes() {
        let (plugin, _, concurrent_writes, _, write_notify) = make_plugin(1, 1);
        let plugin = Arc::new(plugin);

        let p1 = Arc::clone(&plugin);
        let t1 = tokio::spawn(async move { p1.delete_nextupdate().await });

        // Yield until the first write is inside the lock
        for _ in 0..20 {
            if concurrent_writes.load(Ordering::SeqCst) == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(concurrent_writes.load(Ordering::SeqCst), 1);

        // Second write should block on the lock
        let p2 = Arc::clone(&plugin);
        let t2 = tokio::spawn(async move { p2.upload(vec![]).await });

        // Yield and verify second write has NOT entered
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        assert_eq!(concurrent_writes.load(Ordering::SeqCst), 1);

        // Release the first write
        write_notify.notify_waiters();
        t1.await.unwrap().unwrap();

        // Now the second write can proceed - release it too
        write_notify.notify_waiters();
        t2.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn write_excludes_reads() {
        let read_notify = Arc::new(Notify::new());
        let write_notify = Arc::new(Notify::new());
        let concurrent_writes = Arc::new(AtomicUsize::new(0));
        let concurrent_reads = Arc::new(AtomicUsize::new(0));

        let plugin = DelayPlugin {
            read_barrier: Arc::new(Barrier::new(1)),
            read_notify: Arc::clone(&read_notify),
            write_barrier: Arc::new(Barrier::new(1)),
            write_notify: Arc::clone(&write_notify),
            concurrent_reads: Arc::clone(&concurrent_reads),
            concurrent_writes: Arc::clone(&concurrent_writes),
        };
        let plugin = Arc::new(plugin.with_exclusive_access());

        // Start a write that will hold the lock
        let p1 = Arc::clone(&plugin);
        let t1 = tokio::spawn(async move { p1.upload(vec![]).await });

        for _ in 0..20 {
            if concurrent_writes.load(Ordering::SeqCst) == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(concurrent_writes.load(Ordering::SeqCst), 1);

        // Start a read - it should be blocked by the write lock
        let p2 = Arc::clone(&plugin);
        let t2 =
            tokio::spawn(async move { p2.list_current(&<RuntimeFilesQuery>::default()).await });

        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        assert_eq!(concurrent_reads.load(Ordering::SeqCst), 0);

        // Release the write
        write_notify.notify_waiters();
        t1.await.unwrap().unwrap();

        // Release the read (list_current waits on read_notify)
        read_notify.notify_waiters();
        t2.await.unwrap().unwrap();
    }
}
