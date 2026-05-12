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

//! Startup recovery for interrupted transactions.
//!
//! When [`LocalStorage`](crate::LocalStorage) is created, it calls [`recover`] to check for
//! leftover WAL, staging, and `.bak` files from a previous run.
//!
//! - **`.bak` files exist:** A commit was partially applied. Restore backups to their original
//!   locations (rollback), then clean up the WAL and staging files.
//! - **WAL exists but no `.bak` files:** The transaction was either still recording or fully
//!   committed (with cleanup interrupted). Discard the WAL and staging files.

use std::path::Path;

use cda_interfaces::storage_api::StorageError;

use crate::wal;

/// File extension used for backup files created during the commit phase.
pub(crate) const BACKUP_EXTENSION: &str = "bak";

/// File extension used for staging (temporary) files created during write operations.
pub(crate) const STAGING_EXTENSION: &str = "tmp";

/// Perform startup recovery on the given journal and collections directories.
///
/// This function is idempotent. Calling it multiple times on a clean state is a no-op.
///
/// # Errors
///
/// Returns a [`StorageError`] if recovery cannot complete (e.g., filesystem is read-only or
/// corrupted beyond repair).
pub(crate) fn recover(journal_dir: &Path, collections_dir: &Path) -> Result<(), StorageError> {
    let wal_path = journal_dir.join(wal::WAL_FILE_NAME);
    let staging_dir = journal_dir.join(wal::STAGING_DIR_NAME);

    // Always check for and restore any orphaned .bak files, regardless of WAL state.
    // .bak files are the ground truth indicator of a partially applied commit.
    if has_backup_files(collections_dir) {
        tracing::info!("Found .bak files. Rolling back partially applied commit");
        rollback_partial_commit(collections_dir)?;
    }

    if wal_path.exists() {
        tracing::info!("Found leftover WAL file. Discarding incomplete transaction");
        std::fs::remove_file(&wal_path)?;
    }

    // Clean up any orphaned staging files.
    cleanup_staging_dir(&staging_dir)?;

    tracing::info!("Recovery complete");
    Ok(())
}

/// Roll back a partially applied commit by restoring `.bak` files.
///
/// This is also called by the commit path in `local_storage.rs` when `apply_operations` fails
/// mid-commit.
///
/// For each `.bak` file found under `collections_dir`:
/// 1. If the corresponding non-`.bak` file exists (i.e., the new file was already renamed into
///    place), remove it.
/// 2. Rename the `.bak` file back to its original name.
pub(crate) fn rollback_partial_commit(collections_dir: &Path) -> Result<(), StorageError> {
    if !collections_dir.exists() {
        return Ok(());
    }

    for collection_entry in std::fs::read_dir(collections_dir)? {
        let collection_entry = collection_entry?;
        let collection_path = collection_entry.path();
        if !collection_path.is_dir() {
            continue;
        }

        // Check for .bak files that are actually directories (collection-level backups from
        // delete_collection).
        let bak_ext = std::ffi::OsStr::new(BACKUP_EXTENSION);
        if collection_path.extension() == Some(bak_ext) {
            let original = collection_path.with_extension("");
            if original.exists() {
                std::fs::remove_dir_all(&original)?;
            }
            std::fs::rename(&collection_path, &original)?;
            tracing::info!(
                path = %original.display(),
                "Restored collection directory from backup"
            );
            continue;
        }

        restore_bak_files_in_dir(&collection_path)?;
    }

    Ok(())
}

/// Check whether any `.bak` files or directories exist under `collections_dir`.
fn has_backup_files(collections_dir: &Path) -> bool {
    if !collections_dir.exists() {
        return false;
    }

    let bak_ext = std::ffi::OsStr::new(BACKUP_EXTENSION);

    let Ok(entries) = std::fs::read_dir(collections_dir) else {
        return false;
    };

    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };
        let path = entry.path();

        // Collection-level .bak directory.
        if path.extension() == Some(bak_ext) {
            return true;
        }

        // Check inside each collection directory for .bak files.
        if path.is_dir() {
            let Ok(inner_entries) = std::fs::read_dir(&path) else {
                continue;
            };
            for inner in inner_entries {
                let Ok(inner) = inner else {
                    continue;
                };
                if inner.path().extension() == Some(bak_ext) {
                    return true;
                }
            }
        }
    }

    false
}

/// Restore all `.bak` files in a single directory to their original names.
fn restore_bak_files_in_dir(dir: &Path) -> Result<(), StorageError> {
    let bak_ext = std::ffi::OsStr::new(BACKUP_EXTENSION);

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.extension() == Some(bak_ext) {
            let original = path.with_extension("");
            // Remove the partially-applied new file if it exists.
            if original.exists() {
                std::fs::remove_file(&original)?;
            }
            std::fs::rename(&path, &original)?;
            tracing::info!(path = %original.display(), "Restored file from backup");
        }

        // Also clean up any orphaned .tmp files (staging files that were renamed into the
        // collection directory during commit but shouldn't be there).
        let tmp_ext = std::ffi::OsStr::new(STAGING_EXTENSION);
        if path.extension() == Some(tmp_ext) {
            std::fs::remove_file(&path)?;
            tracing::warn!(path = %path.display(), "Removed orphaned staging file");
        }
    }

    Ok(())
}

/// Remove all files in the staging directory.
fn cleanup_staging_dir(staging_dir: &Path) -> Result<(), StorageError> {
    if !staging_dir.exists() {
        return Ok(());
    }

    for entry in std::fs::read_dir(staging_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            std::fs::remove_file(&path)?;
        }
    }

    Ok(())
}
