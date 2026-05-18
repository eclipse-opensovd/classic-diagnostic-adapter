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
//! Recovery decisions are driven by the WAL file header status:
//!
//! - **No WAL file (or corrupt/unreadable header):** Either no transaction was in progress, or
//!   a commit completed successfully but cleanup was interrupted. Any orphaned `.bak` files are
//!   deleted and staging is cleaned.
//! - **WAL with `RECORDING` status:** The transaction was still recording operations. Nothing
//!   was applied to collections. Safe to discard the WAL and staging files.
//! - **WAL with `COMMITTING` status:** The commit phase started but did not complete (the WAL
//!   was not yet deleted). Operations may have been partially applied. Recovery reads the WAL
//!   entries, removes newly created artifacts, and restores `.bak` files.

use std::path::Path;

use cda_interfaces::storage_api::{Operation, StorageError};

use crate::wal::{self, WalStatus};

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

    let status = wal::open_wal(&wal_path)?;

    match status {
        Some((WalStatus::Committing, wal_data)) => {
            // Commit was in progress. Operations may have been partially applied.
            tracing::info!("WAL indicates commit was in progress -- rolling back");

            // Read the operations from the WAL so we know what to undo.
            let operations = wal::read_wal(&wal_data)?;

            // Remove newly created artifacts first
            // This must happen before rollback_partial_commit as
            // restoring .bak files could make previously-overwritten files look like new
            // artifacts.
            remove_new_artifacts(collections_dir, &operations)?;

            // restore .bak files (undoes overwrites and deletes).
            rollback_partial_commit(collections_dir)?;
        }
        Some((WalStatus::Recording, _wal_data)) => {
            // Transaction was still recording. Nothing was applied.
            tracing::info!("WAL indicates transaction was still recording -- discarding");
        }
        None => {
            // No valid WAL. Either clean state or commit completed with interrupted cleanup.
            // Delete any orphaned .bak files (leftover from a completed commit whose cleanup
            // was interrupted between WAL deletion and .bak removal).
            if has_backup_files(collections_dir) {
                tracing::info!("No WAL but found orphaned .bak files -- cleaning up");
                delete_all_backup_files(collections_dir)?;
            }
        }
    }

    // Always clean up WAL and staging files.
    if wal_path.exists() {
        std::fs::remove_file(&wal_path)?;
    }
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

/// Remove files and directories that were newly created by a partially applied commit.
///
/// This handles the case where operations created new artifacts (write to new key,
/// `CreateCollection`, `CopyCollection`) that have no `.bak` counterpart and would otherwise
/// remain after `.bak` restoration.
pub(crate) fn remove_new_artifacts(
    collections_dir: &Path,
    operations: &[Operation],
) -> Result<(), StorageError> {
    for op in operations {
        match op {
            Operation::Write {
                collection, key, ..
            } => {
                let target = collections_dir.join(collection.as_str()).join(key);
                let backup = append_bak_extension(&target);
                // If no .bak exists, this was a new file (not an overwrite). Remove it.
                if target.exists() && !backup.exists() {
                    std::fs::remove_file(&target)?;
                    tracing::debug!(path = %target.display(), "Removed newly created file");
                }
            }
            Operation::CreateCollection { name } => {
                let dir = collections_dir.join(name.as_str());
                // Only remove if it is empty (its contents, if any, are handled by other ops).
                if dir.exists() && is_dir_empty(&dir)? {
                    std::fs::remove_dir(&dir)?;
                    tracing::debug!(path = %dir.display(), "Removed newly created collection dir");
                }
            }
            Operation::CopyCollection { dest, .. } => {
                let dest_dir = collections_dir.join(dest.as_str());
                let backup = append_bak_extension(&dest_dir);
                // If a .bak exists, the dest pre-existed and was backed up --
                // rollback_partial_commit will restore it. Only remove if no .bak
                // (dest was newly created by this op).
                if dest_dir.exists() && !backup.exists() {
                    std::fs::remove_dir_all(&dest_dir)?;
                    tracing::debug!(
                        path = %dest_dir.display(),
                        "Removed newly created copy-collection dir"
                    );
                }
            }
            // Delete and DeleteAll only create .bak files -- handled by rollback_partial_commit.
            Operation::Delete { .. }
            | Operation::DeleteAll { .. }
            | Operation::DeleteCollection { .. } => {}
        }
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

/// Delete all `.bak` files and directories under `collections_dir`.
///
/// Used when no WAL is present but orphaned `.bak` files remain from a successfully committed
/// transaction whose post-commit cleanup was interrupted.
fn delete_all_backup_files(collections_dir: &Path) -> Result<(), StorageError> {
    let bak_ext = std::ffi::OsStr::new(BACKUP_EXTENSION);

    for collection_entry in std::fs::read_dir(collections_dir)? {
        let collection_entry = collection_entry?;
        let path = collection_entry.path();

        // Collection-level .bak directory.
        if path.is_dir() && path.extension() == Some(bak_ext) {
            std::fs::remove_dir_all(&path)?;
            tracing::debug!(path = %path.display(), "Removed orphaned .bak directory");
            continue;
        }

        // File-level .bak files inside collection directories.
        if path.is_dir() {
            for entry in std::fs::read_dir(&path)? {
                let entry = entry?;
                let file_path = entry.path();
                if file_path.extension() == Some(bak_ext) {
                    std::fs::remove_file(&file_path)?;
                    tracing::debug!(path = %file_path.display(), "Removed orphaned .bak file");
                }
            }
        }
    }

    Ok(())
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

/// Append `.bak` to a path.
fn append_bak_extension(path: &Path) -> std::path::PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".");
    s.push(BACKUP_EXTENSION);
    std::path::PathBuf::from(s)
}

/// Check if a directory is empty.
fn is_dir_empty(dir: &Path) -> Result<bool, StorageError> {
    let mut entries = std::fs::read_dir(dir)?;
    Ok(entries.next().is_none())
}
