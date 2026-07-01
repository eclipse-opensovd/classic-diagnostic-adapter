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

use super::error::StorageError;

/// Random-access read handle for stored data.
///
/// Provides positional reads without cursor state, making it inherently safe for concurrent
/// access. Implementations should not require the caller to manage seek position.
pub trait RandomAccessData: Send + Sync {
    /// Read data starting at the given byte `offset` into `buf`.
    ///
    /// Returns the number of bytes actually read, which may be less than `buf.len()` if the
    /// end of the data is reached.
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`] if the read operation fails.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, StorageError>;

    /// Returns the total size of the data in bytes.
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`] if the size cannot be determined.
    fn data_size(&self) -> Result<u64, StorageError>;
}

/// Marker trait for streaming data sources used in write operations.
///
/// Any type implementing [`tokio::io::AsyncRead`] + [`Send`] + [`Unpin`] automatically
/// satisfies this trait. This avoids buffering large payloads entirely in memory.
pub trait ReadableStream: tokio::io::AsyncRead + Send + Unpin {}

impl<T: tokio::io::AsyncRead + Send + Unpin> ReadableStream for T {}
