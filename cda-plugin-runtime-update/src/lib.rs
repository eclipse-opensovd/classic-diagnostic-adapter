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

pub use default_runtime_update_plugin::DefaultRuntimeUpdatePlugin;
pub use security::DefaultUpdatePolicy;

pub mod config;
pub mod default_runtime_reloader_plugin;
pub use default_runtime_reloader_plugin::{
    DefaultReloadContext, DefaultRuntimeReloaderPlugin, RuntimeReloaderConfig,
};
pub mod default_runtime_update_plugin;
pub mod operations;
pub mod security;
pub mod storage;

/// Shared test utilities for the runtime update plugin tests.
#[cfg(test)]
pub(crate) mod test_utils;

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use async_trait::async_trait;
    use cda_interfaces::runtime_update_api::{
        BulkDataCreatedList, BulkDataList, ExclusiveRuntimePlugin, ExecutionMode,
        RuntimeFileCatalog, RuntimeFileStore, RuntimeFilesQuery, RuntimeFilesUpdatePlugin,
        RuntimeUpdateError, RuntimeUpdateExecutor, UpdateExecution, UploadFile,
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
    impl RuntimeFileCatalog for DelayPlugin {
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
    }

    #[async_trait]
    impl RuntimeFileStore for DelayPlugin {
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

        async fn delete_nextupdate(&self) -> Result<Vec<String>, RuntimeUpdateError> {
            self.concurrent_writes.fetch_add(1, Ordering::SeqCst);
            self.write_barrier.wait().await;
            self.write_notify.notified().await;
            self.concurrent_writes.fetch_sub(1, Ordering::SeqCst);
            Ok(vec![])
        }

        async fn delete_nextupdate_by_id(&self, _file_id: &str) -> Result<(), RuntimeUpdateError> {
            Ok(())
        }

        async fn delete_backup(&self) -> Result<Vec<String>, RuntimeUpdateError> {
            Ok(vec![])
        }
    }

    #[async_trait]
    impl RuntimeUpdateExecutor for DelayPlugin {
        async fn start_execution(
            &self,
            _mode: ExecutionMode,
        ) -> Result<String, RuntimeUpdateError> {
            Ok("exec-1".to_owned())
        }

        async fn list_executions(&self) -> Vec<UpdateExecution> {
            vec![]
        }

        async fn get_execution_status(&self, _execution_id: &str) -> Option<UpdateExecution> {
            None
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

    #[tokio::test]
    async fn exclusive_wrapper_forwards_exact_execution_context() {
        let (plugin, _, _, _, _) = make_plugin(1, 1);
        assert_eq!(
            plugin
                .start_execution(ExecutionMode::Cleanup)
                .await
                .unwrap(),
            "exec-1"
        );
    }
}
