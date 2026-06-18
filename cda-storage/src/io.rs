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

//! I/O implementations for the local filesystem storage backend.

#[cfg(unix)]
use std::os::unix::fs::FileExt;
#[cfg(windows)]
use std::os::windows::fs::FileExt;
use std::{fs::File, sync::Arc};

use cda_interfaces::storage_api::{RandomAccessData, StorageError};
use tokio::sync::OwnedRwLockReadGuard;

#[cfg(windows)]
fn read_at(file: &File, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
    file.seek_read(buf, offset)
}
#[cfg(unix)]
fn read_at(file: &File, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
    file.read_at(buf, offset)
}

/// File-backed random-access data handle.
///
/// Uses `pread` (via [`FileExt::read_at`]) for positional reads without mutating shared state,
/// making it safe for concurrent access.
///
/// Holds an [`OwnedRwLockReadGuard`] for the duration of its lifetime, ensuring that a commit
/// cannot proceed while this handle is alive.
pub(crate) struct LocalRandomAccessData {
    file: File,
    size: u64,
    /// Holds a read lock on the storage data lock. Ensures commits (which require a write lock)
    /// are blocked while data is being read.
    _read_guard: OwnedRwLockReadGuard<()>,
}

impl LocalRandomAccessData {
    /// Create a new random-access handle for the given file.
    pub(crate) fn new(file: File, size: u64, read_guard: OwnedRwLockReadGuard<()>) -> Self {
        Self {
            file,
            size,
            _read_guard: read_guard,
        }
    }
}

impl RandomAccessData for LocalRandomAccessData {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, StorageError> {
        let bytes_read = read_at(&self.file, buf, offset)?;
        Ok(bytes_read)
    }

    fn data_size(&self) -> Result<u64, StorageError> {
        Ok(self.size)
    }
}

/// Acquire a read lock on the given `RwLock` and return an owned read guard.
pub(crate) async fn acquire_read_lock(
    lock: &Arc<tokio::sync::RwLock<()>>,
) -> OwnedRwLockReadGuard<()> {
    Arc::clone(lock).read_owned().await
}
