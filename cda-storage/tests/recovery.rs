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

#![cfg(test)] // Workaround to make Clippy in pre-commit hook recognize this file as test code

use std::{io::Write, path::PathBuf};

use cda_interfaces::storage_api::{
    Collection, CollectionName, RandomAccessData, Storage, StorageError,
};
use cda_storage::LocalStorage;

/// Simulates a crash during the recording phase: a WAL file exists with `RECORDING` status and
/// entries, and orphaned staging files are present, but nothing was ever applied to the
/// collections directory. Recovery must discard the WAL and staging files and leave the
/// collection untouched, since the transaction never reached the commit phase.
/// [[ test~storage-atomicity-recovery-discards-recording-phase-crash, Recovery discards an incomplete transaction that crashed while still recording, test ]]
#[tokio::test]
async fn recovery_cleans_up_incomplete_transaction() {
    let fixture = Fixture::new();

    // Create a WAL with RECORDING header and a single write operation.
    cda_storage::wal::create_wal(&fixture.wal_file).unwrap();

    let staged = fixture.staging_dir.join("some_file.tmp");
    std::fs::write(&staged, b"orphaned data").unwrap();
    let staged_str = staged
        .to_str()
        .expect("Failed to convert staging path to string")
        .to_string();

    cda_storage::wal::append_operation(
        &fixture.wal_file,
        &cda_interfaces::storage_api::Operation::Write {
            collection: CollectionName::DiagnosticDatabase,
            key: "test".to_string(),
            staged_path: staged_str,
        },
    )
    .unwrap();

    // Creating a new LocalStorage should trigger recovery.
    let storage = fixture.create_storage();

    // The WAL and staging file should be cleaned up.
    assert!(!fixture.wal_file.exists());
    assert!(!staged.exists());

    // And the collection should not have the key.
    let collection = storage
        .get_or_create_collection(&CollectionName::DiagnosticDatabase)
        .await
        .unwrap();
    let result = collection.read("test").await;
    assert!(matches!(result, Err(StorageError::KeyNotFound(_))));
}

/// Simulates a crash during the commit phase where an existing key was being overwritten: the
/// WAL has `COMMITTING` status and a `.bak` file exists alongside the partially-written new
/// file. Recovery must restore the original data from the `.bak` file, upholding the
/// all-or-nothing guarantee for `Write` operations that overwrite existing keys.
/// [[ test~storage-atomicity-recovery-restores-overwritten-file, Recovery restores the original file from its backup after an interrupted overwrite, test ]]
#[tokio::test]
async fn recovery_rolls_back_partial_commit_with_bak_files() {
    let fixture = Fixture::new();
    let db_dir = &fixture.diagnostic_database_dir;

    // Simulate: original file was backed up, new file was partially written.
    std::fs::write(db_dir.join("mykey.bak"), b"original data").unwrap();
    std::fs::write(db_dir.join("mykey"), b"new data").unwrap();

    // Create a WAL with COMMITTING status.
    cda_storage::wal::create_wal(&fixture.wal_file).unwrap();
    cda_storage::wal::append_operation(
        &fixture.wal_file,
        &cda_interfaces::storage_api::Operation::Write {
            collection: CollectionName::DiagnosticDatabase,
            key: "mykey".to_string(),
            staged_path: "/tmp/does_not_matter.tmp".to_string(),
        },
    )
    .unwrap();
    cda_storage::wal::mark_committing(&fixture.wal_file).unwrap();

    // Recovery should detect COMMITTING + .bak files and restore them.
    let storage = fixture.create_storage();

    let collection = storage
        .get_collection(&CollectionName::DiagnosticDatabase)
        .await
        .unwrap();
    let handle = collection.read("mykey").await.unwrap();
    let mut buf = vec![0u8; 13];
    let n = handle.read_at(0, &mut buf).unwrap();
    assert_eq!(n, 13);
    assert_eq!(&buf, b"original data");
}

/// Whgen a crash happens during commit where only NEW files were  created (no overwrites, so no `.bak` files exist).
/// Recovery must still detect the partial commit via the `COMMITTING` WAL status and remove the newly created files,
/// since a `Write` operation that introduces a brand-new key must be all-or-nothing just like an overwrite.
/// [[ test~storage-atomicity-recovery-removes-new-file, Recovery removes a newly-written file left by an interrupted commit with no backup to restore, test ]]
#[tokio::test]
async fn recovery_rolls_back_new_file_writes_without_bak() {
    let fixture = Fixture::new();
    let db_dir = &fixture.diagnostic_database_dir;

    // Simulate: a new file was written into the collection during a partially applied commit.
    // No .bak file exists because there was nothing to overwrite.
    std::fs::write(db_dir.join("new_key"), b"partially committed data").unwrap();

    // Create a WAL with COMMITTING status containing the write operation.
    cda_storage::wal::create_wal(&fixture.wal_file).unwrap();
    cda_storage::wal::append_operation(
        &fixture.wal_file,
        &cda_interfaces::storage_api::Operation::Write {
            collection: CollectionName::DiagnosticDatabase,
            key: "new_key".to_string(),
            staged_path: "/tmp/does_not_matter.tmp".to_string(),
        },
    )
    .unwrap();
    cda_storage::wal::mark_committing(&fixture.wal_file).unwrap();

    // Recovery should detect COMMITTING, read the WAL, and remove the new file.
    let storage = fixture.create_storage();

    let collection = storage
        .get_collection(&CollectionName::DiagnosticDatabase)
        .await
        .unwrap();
    let result = collection.read("new_key").await;
    assert!(matches!(result, Err(StorageError::KeyNotFound(_))));
}

/// Simulates a crash during commit of a `CreateCollection` operation, where no backup can exist
/// because the collection is entirely new. Recovery must remove the empty collection directory
/// so that a partially-applied `CreateCollection` never leaves a visible trace behind.
/// [[ test~storage-atomicity-recovery-removes-new-collection, Recovery removes an empty collection directory left by an interrupted `CreateCollection` commit, test ]]
#[tokio::test]
async fn recovery_rolls_back_new_collection_without_bak() {
    let fixture = Fixture::new();

    // Simulate: a new empty collection directory was created during partial commit.
    let new_col_dir = fixture.collections_dir.join("brand_new");
    std::fs::create_dir_all(&new_col_dir).unwrap();

    // Create a WAL with COMMITTING status.
    cda_storage::wal::create_wal(&fixture.wal_file).unwrap();
    cda_storage::wal::append_operation(
        &fixture.wal_file,
        &cda_interfaces::storage_api::Operation::CreateCollection {
            name: CollectionName::Custom("brand_new".to_string()),
        },
    )
    .unwrap();
    cda_storage::wal::mark_committing(&fixture.wal_file).unwrap();

    // Recovery should remove the newly created collection directory.
    let _storage = fixture.create_storage();

    assert!(!new_col_dir.exists());
}

/// Simulates a case where a commit succeeded (the WAL was deleted, marking the point of no
/// return) but a subsequent crash interrupted the best-effort `.bak` cleanup step. Recovery must
/// treat the absence of a WAL as "already committed" and simply delete the orphaned backups,
/// keeping the already-committed data intact.
/// [[ test~storage-atomicity-recovery-cleans-orphaned-backups, Recovery cleans up orphaned backup files left after a successful commit, test ]]
#[tokio::test]
async fn recovery_handles_no_wal_with_orphaned_bak_files() {
    let fixture = Fixture::new();
    let db_dir = &fixture.diagnostic_database_dir;

    // The new committed data is in place, but old .bak files remain.
    std::fs::write(db_dir.join("mykey"), b"new committed data").unwrap();
    std::fs::write(db_dir.join("mykey.bak"), b"old data").unwrap();

    // No WAL file exists (it was successfully deleted as point of no return).
    assert!(!fixture.wal_file.exists());

    // Recovery should delete the orphaned .bak and keep the committed data.
    let storage = fixture.create_storage();

    assert!(!db_dir.join("mykey.bak").exists());
    let collection = storage
        .get_collection(&CollectionName::DiagnosticDatabase)
        .await
        .unwrap();
    let handle = collection.read("mykey").await.unwrap();
    let mut buf = vec![0u8; 18];
    let n = handle.read_at(0, &mut buf).unwrap();
    assert_eq!(n, 18);
    assert_eq!(&buf, b"new committed data");
}

/// Creates a WAL with a valid entry followed by corrupted (torn-write) bytes. Recovery must
/// stop reading at the first invalid entry and discard the whole transaction, since a
/// `RECORDING`-status WAL means nothing was ever applied to collections - so a corrupt tail is
/// safe to ignore rather than treated as unrecoverable filesystem corruption.
/// [[ test~storage-atomicity-recovery-discards-corrupt-wal, Recovery discards a WAL with a corrupt checksum during the recording phase, test ]]
#[tokio::test]
async fn recovery_discards_wal_with_corrupt_checksum() {
    let fixture = Fixture::new();

    cda_storage::wal::create_wal(&fixture.wal_file).unwrap();

    // Append a valid entry.
    cda_storage::wal::append_operation(
        &fixture.wal_file,
        &cda_interfaces::storage_api::Operation::CreateCollection {
            name: CollectionName::Custom("valid_collection".to_string()),
        },
    )
    .unwrap();

    // Append garbage bytes to simulate a torn write (corrupt checksum).
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&fixture.wal_file)
        .unwrap();
    file.write_all(&[0xFF; 20]).unwrap();

    // Recovery should succeed, the corrupt entry is simply ignored.
    let _storage = fixture.create_storage();

    // The WAL should be cleaned up.
    assert!(!fixture.wal_file.exists());
}

/// Simulates a crash during commit of a multi-operation transaction where a `CreateCollection`
/// and a `Write` into that same new collection were both partially applied (the directory and
/// its file both exist on disk, with the WAL in `COMMITTING` status). Since the collection did
/// not exist before this transaction, recovery must roll back the *entire* transaction as a
/// unit, removing both the written file and the now-empty collection directory - demonstrating
/// that atomicity applies across all staged operations in an execution, not just individually.
/// [[ test~storage-atomicity-recovery-removes-orphaned-collection-dir, Recovery fully rolls back a multi-operation transaction that created a collection and wrote into it, test ]]
#[tokio::test]
async fn recovery_create_collection_with_write_removes_orphaned_dir() {
    let fixture = Fixture::new();

    // Simulate partial commit state: the collection directory was created AND a file was
    // written into it before the crash.
    let new_col_dir = fixture.collections_dir.join("fresh_collection");
    std::fs::create_dir_all(&new_col_dir).unwrap();
    std::fs::write(new_col_dir.join("data_file"), b"written during commit").unwrap();

    // WAL with COMMITTING status containing both operations in natural order:
    // CreateCollection first, then Write to that collection.
    cda_storage::wal::create_wal(&fixture.wal_file).unwrap();
    cda_storage::wal::append_operation(
        &fixture.wal_file,
        &cda_interfaces::storage_api::Operation::CreateCollection {
            name: CollectionName::Custom("fresh_collection".to_string()),
        },
    )
    .unwrap();
    cda_storage::wal::append_operation(
        &fixture.wal_file,
        &cda_interfaces::storage_api::Operation::Write {
            collection: CollectionName::Custom("fresh_collection".to_string()),
            key: "data_file".to_string(),
            staged_path: "/tmp/irrelevant.tmp".to_string(),
        },
    )
    .unwrap();
    cda_storage::wal::mark_committing(&fixture.wal_file).unwrap();

    // Recovery should fully roll back - the collection did not exist before this transaction.
    let _storage = fixture.create_storage();

    // The collection directory must be completely gone after recovery.
    assert!(
        !new_col_dir.exists(),
        "Orphaned empty collection directory was left behind after recovery"
    );
}

/// A failed collection swap can leave a COMMITTING WAL where a pre-existing destination was
/// never renamed to its backup (for example, when `rename` returns EXDEV). Recovery must retain
/// that untouched current collection rather than treating it as an artifact of the failed copy.
#[tokio::test]
async fn recovery_preserves_untouched_existing_copy_destination() {
    let fixture = Fixture::new();
    let current_dir = &fixture.diagnostic_database_dir;
    std::fs::write(current_dir.join("ecu1.mdd"), b"current data").unwrap();

    cda_storage::wal::create_wal(&fixture.wal_file).unwrap();
    cda_storage::wal::append_operation(
        &fixture.wal_file,
        &cda_interfaces::storage_api::Operation::CopyCollection {
            source: CollectionName::DiagnosticDatabaseNextUpdate,
            dest: CollectionName::DiagnosticDatabase,
            dest_existed: true,
        },
    )
    .unwrap();
    cda_storage::wal::mark_committing(&fixture.wal_file).unwrap();

    let storage = fixture.create_storage();
    let current = storage
        .get_collection(&CollectionName::DiagnosticDatabase)
        .await
        .unwrap();
    let handle = current.read("ecu1.mdd").await.unwrap();
    let mut data = vec![0; "current data".len()];
    handle.read_at(0, &mut data).unwrap();
    assert_eq!(data, b"current data");
}

struct Fixture {
    root_dir: tempfile::TempDir,
    collections_dir: PathBuf,
    staging_dir: PathBuf,
    diagnostic_database_dir: PathBuf,
    wal_file: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root_dir = tempfile::tempdir().unwrap();
        let root = root_dir.path();

        let collections_dir = root.join("collections");
        std::fs::create_dir_all(&collections_dir).unwrap();

        let journal_dir = root.join("journal");

        let staging_dir = journal_dir.join("staging");
        std::fs::create_dir_all(&staging_dir).unwrap();

        let diagnostic_database_dir = collections_dir.join("diagnostic_database");
        std::fs::create_dir_all(&diagnostic_database_dir).unwrap();

        let wal_file = journal_dir.join("transaction.wal");

        Self {
            root_dir,
            collections_dir,
            staging_dir,
            diagnostic_database_dir,
            wal_file,
        }
    }

    fn create_storage(&self) -> LocalStorage {
        LocalStorage::new(self.root_dir.path()).unwrap()
    }
}
