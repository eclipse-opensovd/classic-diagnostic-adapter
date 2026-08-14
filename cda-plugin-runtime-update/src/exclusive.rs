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

//! Read/write mutual exclusion over the registered [`RuntimeFilesUpdatePlugin`].
//!
//! # What this serialises, and what it does not
//!
//! Exactly one update plugin is ever registered: `Setup` holds a single builder,
//! and startup mounts one plugin on the runtime-update routes. Two plugins of
//! the same kind are not a state the application can reach, so this wrapper is
//! not about arbitrating between plugins.
//!
//! What it arbitrates is concurrent HTTP requests against that one plugin. The
//! routes are ordinary axum handlers, so an upload, a delete and an apply can be
//! in flight simultaneously; without exclusion they would interleave on the same
//! staging directory - a delete landing between an apply reading the file list
//! and acting on it, for instance. Reads take a shared lock and run in parallel;
//! mutations and executions take the exclusive one.
//!
//! It lives in this crate rather than in `cda-interfaces` because it is a
//! concrete locking policy built on `tokio::sync::RwLock`, not a contract. An
//! implementation that already serialises internally, or that wants different
//! semantics, simply does not wrap itself in it.

use async_trait::async_trait;
use cda_interfaces::runtime_update_api::{
    ExecutionMode, FileListOptions, RuntimeFile, RuntimeFileCatalog, RuntimeFileStore,
    RuntimeFilesUpdatePlugin, RuntimeUpdateError, RuntimeUpdateExecutor, UpdateExecution,
    UploadFile,
};

/// Extension trait adding [`with_exclusive_access`](WithExclusiveAccess::with_exclusive_access).
pub trait WithExclusiveAccess: RuntimeFilesUpdatePlugin + Sized {
    /// Wraps this plugin in [`ExclusiveRuntimePlugin`], adding read/write mutual
    /// exclusion.
    fn with_exclusive_access(self) -> ExclusiveRuntimePlugin<Self> {
        ExclusiveRuntimePlugin::new(self)
    }
}

impl<P: RuntimeFilesUpdatePlugin + Sized> WithExclusiveAccess for P {}

/// Wrapper that enforces mutual exclusion on any [`RuntimeFilesUpdatePlugin`].
///
/// Read operations (`list_*`, `get_execution_status`) acquire a shared read lock,
/// write operations (`upload`, `delete_*`, `start_execution`) acquire an exclusive
/// write lock. This prevents concurrent mutations from racing each other while
/// still allowing parallel reads.
///
/// Obtain it via [`WithExclusiveAccess::with_exclusive_access`], which is
/// blanket-implemented for every [`RuntimeFilesUpdatePlugin`].
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
}

#[async_trait]
impl<P: RuntimeFileStore> RuntimeFileStore for ExclusiveRuntimePlugin<P> {
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
