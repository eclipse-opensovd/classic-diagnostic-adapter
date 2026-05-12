/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

//! Write-Ahead Log (WAL) persistence for crash-safe transactions.
//!
//! Uses a **one-phase commit with checksums (1PC+C)** strategy: WAL entries are buffered in the
//! OS page cache during the transaction and fsynced once at commit time. Each entry is wrapped
//! in a checksum envelope so that recovery can detect partial/corrupt writes and discard the
//! entire transaction.
//!
//! ## On-disk format
//!
//! The WAL file is a sequence of checksum-enveloped entries:
//!
//! ```text
//! [u32 crc32][u32 payload_len][bincode-encoded Operation] ...
//! ```
//!
//! On recovery, each entry is validated against its CRC32 checksum. The first entry that fails
//! validation (or is truncated) marks the end of the valid journal. Everything up to that
//! point is considered the complete set of recorded operations.

use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
};

use cda_interfaces::storage_api::{Operation, StorageError};

// Each entry is structured as a fixed-size header followed by the variable-size payload.
// Header [4 bytes checksum]
// Header [4 bytes payload_len]
// Data [payload_len bytes payload]
const WAL_HEADER_SIZE: usize = 8;

/// Append a single operation to the WAL file.
///
/// The entry is written to the OS page cache **without** `fsync`. Durability is deferred to
/// [`sync_wal`], which is called once at commit time. This minimizes flash wear and I/O
/// latency during the transaction recording phase.
///
/// # Errors
///
/// Returns a [`StorageError`] if encoding or writing to the WAL file fails.
pub fn append_operation(wal_path: &Path, op: &Operation) -> Result<(), StorageError> {
    let payload =
        rkyv::to_bytes(op).map_err(|e: rkyv::rancor::Error| StorageError::Other(e.to_string()))?;

    let checksum = compute_checksum(&payload);
    let payload_len: u32 = payload
        .len()
        .try_into()
        .map_err(|_| StorageError::Other("WAL entry payload exceeds u32::MAX bytes".to_string()))?;

    let mut file = OpenOptions::new().append(true).open(wal_path)?;
    file.write_all(&checksum.to_le_bytes())?;
    file.write_all(&payload_len.to_le_bytes())?;
    file.write_all(&payload)?;
    // No fsync here. Deferred to commit time.
    Ok(())
}

/// Fsync the WAL file to make all appended entries durable.
///
/// # Errors
///
/// Returns a [`StorageError`] if the fsync fails.
pub fn sync_wal(wal_path: &Path) -> Result<(), StorageError> {
    #[cfg(windows)] // windows needs RW flags to call sync on a file descriptor
    let file = OpenOptions::new().read(true).write(true).open(wal_path)?;
    #[cfg(not(windows))]
    let file = OpenOptions::new().read(true).open(wal_path)?;
    file.sync_all()?;
    Ok(())
}

/// Fsync a batch of staging files to make their contents durable.
///
/// # Errors
///
/// Returns a [`StorageError`] if any fsync fails.
pub fn sync_staging_files(staging_dir: &Path) -> Result<(), StorageError> {
    if !staging_dir.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(staging_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            #[cfg(windows)] // windows needs RW flags to call sync on a file descriptor
            let file = OpenOptions::new().read(true).write(true).open(&path)?;
            #[cfg(not(windows))]
            let file = File::open(&path)?;
            file.sync_all()?;
        }
    }
    Ok(())
}

/// Read all valid entries from the WAL file, stopping at the first corrupt or truncated entry.
///
/// Each entry's checksum is verified. If an entry is truncated or its checksum does not match,
/// that entry and all subsequent data are ignored. The transaction is considered incomplete.
///
/// Returns the list of valid operations.
///
/// # Errors
///
/// Returns a [`StorageError`] if the WAL file cannot be read or a valid entry fails to decode.
pub fn read_wal(wal_path: &Path) -> Result<Vec<Operation>, StorageError> {
    let data = std::fs::read(wal_path)?;
    let mut operations = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        // Need at least 8 bytes for the header.
        let remaining = data.len().saturating_sub(offset);
        if remaining < WAL_HEADER_SIZE {
            // Truncated header -> incomplete entry, stop here.
            tracing::warn!(offset, "WAL truncated: incomplete entry header, discarding");
            break;
        }

        let header = data
            .get(offset..offset.wrapping_add(WAL_HEADER_SIZE))
            .ok_or_else(|| StorageError::Other(format!("WAL offset {offset} out of bounds")))?;

        let checksum_bytes: [u8; 4] = header
            .get(..4)
            .ok_or_else(|| StorageError::Other("WAL header checksum slice".to_string()))?
            .try_into()
            .map_err(|_| StorageError::Other("WAL header checksum conversion".to_string()))?;
        let len_bytes: [u8; 4] = header
            .get(4..8)
            .ok_or_else(|| StorageError::Other("WAL header length slice".to_string()))?
            .try_into()
            .map_err(|_| StorageError::Other("WAL header length conversion".to_string()))?;

        let stored_checksum = u32::from_le_bytes(checksum_bytes);
        let payload_len = u32::from_le_bytes(len_bytes) as usize;

        let payload_start = offset.wrapping_add(WAL_HEADER_SIZE);
        let payload_end = payload_start.wrapping_add(payload_len);

        if payload_end > data.len() {
            // Truncated payload -> incomplete entry, stop here.
            tracing::warn!(
                offset,
                payload_len,
                "WAL truncated: incomplete entry payload, discarding"
            );
            break;
        }

        let payload = data.get(payload_start..payload_end).ok_or_else(|| {
            StorageError::Other(format!("WAL payload at offset {offset} out of bounds"))
        })?;

        // Verify checksum.
        let actual_checksum = compute_checksum(payload);
        if stored_checksum != actual_checksum {
            tracing::warn!(
                offset,
                stored_checksum,
                actual_checksum,
                "WAL checksum mismatch, discarding this and all subsequent entries"
            );
            break;
        }

        // Decode the operation.
        let op: Operation = rkyv::from_bytes(payload).map_err(|e: rkyv::rancor::Error| {
            StorageError::Other(format!(
                "Failed to decode WAL entry at offset {offset}: {e}"
            ))
        })?;

        operations.push(op);
        offset = payload_end;
    }

    Ok(operations)
}

/// Create a new, empty WAL file at the given path.
///
/// # Errors
///
/// Returns a [`StorageError`] if file creation fails.
pub fn create_wal(wal_path: &Path) -> Result<(), StorageError> {
    File::create(wal_path)?;
    Ok(())
}

/// Compute a CRC32 checksum of the given data.
///
/// CRC32 (ISO 3309) is purpose-built for detecting data corruption in storage and
/// transmission, and therefore a good fit for WAL integrity.
fn compute_checksum(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

/// The well-known name of the WAL file inside the journal directory.
pub(crate) const WAL_FILE_NAME: &str = "transaction.wal";

/// The well-known name of the staging subdirectory inside the journal directory.
pub(crate) const STAGING_DIR_NAME: &str = "staging";
