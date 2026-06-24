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

//! Write-Ahead Log (WAL) persistence for crash-safe transactions.
//!
//! Uses a **one-phase commit with checksums (1PC+C)** strategy: WAL entries are buffered in the
//! OS page cache during the transaction and fsynced once at commit time. Each entry is wrapped
//! in a checksum envelope so that recovery can detect partial/corrupt writes and discard the
//! entire transaction.
//!
//! ## On-disk format
//!
//! The WAL file begins with a fixed-length header that records the transaction phase, followed
//! by a sequence of checksum-enveloped operation entries:
//!
//! ```text
//! [u8 magic][u8 status][u16 reserved][u32 header_crc32] [u32 crc32][u32 payload_len][payload] ...
//! |------------- 8-byte header -----------------------| |------- per-entry envelope --------|
//! ```
//!
//! The status byte is initially set to `RECORDING` when the WAL is created. Before the commit
//! fsync, the status is flipped to `COMMITTING` via a single `pwrite`. Both the status change
//! and all appended entries become durable together in one fsync.
//!
//! On recovery:
//! - `RECORDING` status: nothing was applied -- safe to discard WAL and staging.
//! - `COMMITTING` status: commit was in progress -- recovery must read the WAL entries and
//!   undo any partially applied operations.
//!
//! Each operation entry is validated against its CRC32 checksum. The first entry that fails
//! validation (or is truncated) marks the end of the valid journal.

use std::{
    fs::{
        File,
        OpenOptions,
    },
    io::{
        Seek,
        SeekFrom,
        Write,
    },
    path::Path,
};

use cda_interfaces::storage_api::{
    Operation,
    StorageError,
};

/// Magic byte identifying a valid WAL file header.
const WAL_MAGIC: u8 = 0xCA;

/// Status: transaction is still recording operations (not yet committed).
const STATUS_RECORDING: u8 = 0x00;

/// Status: operations have been recorded and the commit phase has started.
const STATUS_COMMITTING: u8 = 0x01;

/// Size of the fixed WAL file header: [u8 magic][u8 status][u8 pad][u8 pad][u32 crc32].
///
/// Padded by 2 bytes after status to a total of 8 bytes to maintain 4-byte alignment
/// as required by rkyv deserialization.
const WAL_FILE_HEADER_SIZE: usize = 8;

// Each operation entry is structured as a fixed-size header followed by the variable-size payload.
// Entry header: [4 bytes checksum][4 bytes payload_len]
// Entry data: [payload_len bytes payload]
const ENTRY_HEADER_SIZE: usize = 8;

/// The status encoded in the WAL file header.
///
/// Returned by [`read_wal_status`] so that callers (recovery, commit path) can decide how to
/// proceed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalStatus {
    /// Transaction was still recording operations. Nothing was applied to collections.
    Recording,
    /// Commit phase started. Operations may have been partially applied.
    Committing,
}

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

/// Flip the WAL header status to [`STATUS_COMMITTING`].
///
/// This writes the new status byte and updated CRC32 at the start of the file without fsync.
/// The caller is expected to call [`sync_wal`] afterwards so that both the status change and
/// all appended entries become durable in a single fsync.
///
/// # Errors
///
/// Returns a [`StorageError`] if the seek or write fails.
pub fn mark_committing(wal_path: &Path) -> Result<(), StorageError> {
    let mut file = OpenOptions::new().read(true).write(true).open(wal_path)?;
    file.seek(SeekFrom::Start(0))?;

    let header = encode_header(STATUS_COMMITTING);
    file.write_all(&header)?;
    // No fsync here. Deferred to the batch fsync in sync_wal.
    Ok(())
}

/// Read the WAL file header and return the transaction status.
///
/// Returns `None` if the file does not exist, is too small to contain a valid header, or the
/// header checksum does not match (corrupt header).
///
/// # Errors
///
/// Returns a [`StorageError`] on I/O failure (other than file-not-found).
pub fn open_wal(wal_path: &Path) -> Result<Option<(WalStatus, Vec<u8>)>, StorageError> {
    if !wal_path.exists() {
        return Ok(None);
    }

    let data = std::fs::read(wal_path)?;

    if data.len() < WAL_FILE_HEADER_SIZE {
        // File too small for a valid header.
        tracing::warn!("WAL file too small for a valid header, treating as absent");
        return Ok(None);
    }

    #[allow(clippy::indexing_slicing)] // header length is checked before, so index access is safe.
    let (magic, status, stored_crc) = {
        let magic = data[0];
        let status = data[1];
        // Bytes [2] and [3] are reserved padding for alignment

        let stored_crc_bytes: [u8; 4] = data
            .get(4..WAL_FILE_HEADER_SIZE)
            .ok_or_else(|| StorageError::Other("WAL header CRC slice out of bounds".to_string()))?
            .try_into()
            .map_err(|_| StorageError::Other("WAL header CRC conversion failed".to_string()))?;
        let stored_crc = u32::from_le_bytes(stored_crc_bytes);
        (magic, status, stored_crc)
    };

    // Verify magic and checksum.
    if magic != WAL_MAGIC {
        tracing::warn!(
            magic,
            "WAL header has invalid magic byte, treating as corrupt"
        );
        return Ok(None);
    }

    let expected_crc = compute_header_checksum(magic, status);
    if stored_crc != expected_crc {
        tracing::warn!(
            stored_crc,
            expected_crc,
            "WAL header checksum mismatch, treating as corrupt"
        );
        return Ok(None);
    }

    match status {
        STATUS_RECORDING => Ok(Some((WalStatus::Recording, data))),
        STATUS_COMMITTING => Ok(Some((WalStatus::Committing, data))),
        _ => {
            tracing::warn!(
                status,
                "WAL header has unknown status byte, treating as corrupt"
            );
            Ok(None)
        }
    }
}

/// Fsync the WAL file to make all appended entries durable.
///
/// # Errors
///
/// Returns a [`StorageError`] if the fsync fails.
pub fn sync_wal(wal_path: &Path) -> Result<(), StorageError> {
    #[cfg(windows)] // Windows needs RW flags to call sync on a file descriptor.
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
            #[cfg(windows)] // Windows needs RW flags to call sync on a file descriptor.
            let file = OpenOptions::new().read(true).write(true).open(&path)?;
            #[cfg(not(windows))]
            let file = File::open(&path)?;
            file.sync_all()?;
        }
    }
    Ok(())
}

/// Result of reading WAL entries.
#[derive(Debug)]
pub struct WalReadResult {
    /// The operations that were successfully parsed from the WAL.
    pub operations: Vec<Operation>,
    /// Whether the WAL was truncated or corrupted (i.e., entries were lost).
    pub truncated: bool,
}

/// Read all valid operation entries from the WAL file, skipping the file header.
///
/// Each entry's checksum is verified. If an entry is truncated or its checksum does not match,
/// that entry and all subsequent data are ignored and `truncated` is set to `true`.
///
/// Returns a [`WalReadResult`] containing the successfully parsed operations and whether
/// truncation was detected.
///
/// # Errors
///
/// Returns a [`StorageError`] if a valid entry fails to decode.
pub fn read_wal(data: &[u8]) -> Result<WalReadResult, StorageError> {
    let mut operations = Vec::new();
    let mut truncated = false;
    // Skip the fixed-length file header and start reading entries from there.
    let mut offset = WAL_FILE_HEADER_SIZE;

    while offset < data.len() {
        // Need at least 8 bytes for the entry header.
        let remaining = data.len().saturating_sub(offset);
        if remaining < ENTRY_HEADER_SIZE {
            // Truncated header -> incomplete entry, stop here.
            tracing::warn!(offset, "WAL truncated: incomplete entry header, discarding");
            truncated = true;
            break;
        }

        let header = data
            .get(offset..offset.saturating_add(ENTRY_HEADER_SIZE))
            .ok_or_else(|| StorageError::Other(format!("WAL offset {offset} out of bounds")))?;

        let checksum_bytes: [u8; 4] = header
            .get(..4)
            .ok_or_else(|| StorageError::Other("WAL entry checksum slice".to_string()))?
            .try_into()
            .map_err(|_| StorageError::Other("WAL entry checksum conversion".to_string()))?;
        let len_bytes: [u8; 4] = header
            .get(4..8)
            .ok_or_else(|| StorageError::Other("WAL entry length slice".to_string()))?
            .try_into()
            .map_err(|_| StorageError::Other("WAL entry length conversion".to_string()))?;

        let stored_checksum = u32::from_le_bytes(checksum_bytes);
        let payload_len = u32::from_le_bytes(len_bytes) as usize;

        let payload_start = offset.saturating_add(ENTRY_HEADER_SIZE);
        let payload_end = payload_start.saturating_add(payload_len);

        if payload_end > data.len() || payload_end <= payload_start {
            // Truncated payload -> incomplete entry, stop here.
            tracing::warn!(
                offset,
                payload_len,
                "WAL truncated: incomplete entry payload, discarding"
            );
            truncated = true;
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
            truncated = true;
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

    Ok(WalReadResult {
        operations,
        truncated,
    })
}

/// Create a new WAL file with an initial `RECORDING` header.
///
/// # Errors
///
/// Returns a [`StorageError`] if file creation or the header write fails.
pub fn create_wal(wal_path: &Path) -> Result<(), StorageError> {
    let mut file = File::create(wal_path)?;
    let header = encode_header(STATUS_RECORDING);
    file.write_all(&header)?;
    Ok(())
}

/// Fsync the journal directory to make WAL file deletion durable.
///
/// On POSIX systems, unlinking a file is not durable until the parent directory is fsynced.
/// On Windows this is a no-op (NTFS journals metadata changes internally).
///
/// # Errors
///
/// Returns a [`StorageError`] if the directory fsync fails.
#[cfg_attr(windows, allow(clippy::unnecessary_wraps, unused_variables))]
pub fn sync_journal_dir(journal_dir: &Path) -> Result<(), StorageError> {
    #[cfg(not(windows))]
    {
        let f = File::open(journal_dir)?;
        f.sync_all()?;
    }
    Ok(())
}

/// Encode the 8-byte WAL file header for the given status byte.
fn encode_header(status: u8) -> [u8; WAL_FILE_HEADER_SIZE] {
    let crc = compute_header_checksum(WAL_MAGIC, status);
    let crc_bytes = crc.to_le_bytes();
    [
        WAL_MAGIC,
        status,
        0x00, // reserved
        0x00, // reserved
        crc_bytes[0],
        crc_bytes[1],
        crc_bytes[2],
        crc_bytes[3],
    ]
}

/// Compute the CRC32 checksum for the WAL file header (over the magic and status bytes).
fn compute_header_checksum(magic: u8, status: u8) -> u32 {
    crc32fast::hash(&[magic, status])
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
