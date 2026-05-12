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

//! Integration tests for the local filesystem storage backend.

use std::io::Write as _;

use cda_interfaces::storage_api::{
    Collection as _, CollectionName, RandomAccessData as _, Storage, StorageError,
};
use cda_storage::LocalStorage;

/// Create a fresh `LocalStorage` in a unique temp directory.
fn create_test_storage() -> (LocalStorage, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage = LocalStorage::new(dir.path()).expect("Failed to create LocalStorage");
    (storage, dir)
}

#[tokio::test]
async fn write_read_roundtrip() {
    let (storage, _dir) = create_test_storage();
    let name = CollectionName::DiagnosticDatabase;
    let collection = storage.get_or_create_collection(&name).await.unwrap();

    let mut tx = storage.begin_transaction().unwrap();
    let mut data: &[u8] = b"hello world";
    collection
        .write(&mut tx, "greeting", &mut data)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let handle = collection.read("greeting").await.unwrap();
    let mut buf = vec![0u8; 11];
    let n = handle.read_at(0, &mut buf).unwrap();
    assert_eq!(n, 11);
    assert_eq!(&buf, b"hello world");
}

#[tokio::test]
async fn read_nonexistent_key_returns_not_found() {
    let (storage, _dir) = create_test_storage();
    let name = CollectionName::DiagnosticDatabase;
    let collection = storage.get_or_create_collection(&name).await.unwrap();

    let result = collection.read("nonexistent").await;
    assert!(matches!(result, Err(StorageError::KeyNotFound(_))));
}

#[tokio::test]
async fn delete_removes_key_after_commit() {
    let (storage, _dir) = create_test_storage();
    let name = CollectionName::DiagnosticDatabase;
    let collection = storage.get_or_create_collection(&name).await.unwrap();

    // Write a key.
    let mut tx = storage.begin_transaction().unwrap();
    let mut data: &[u8] = b"to be deleted";
    collection
        .write(&mut tx, "doomed", &mut data)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    // Delete the key.
    let mut tx = storage.begin_transaction().unwrap();
    collection.delete(&mut tx, "doomed").await.unwrap();
    tx.commit().await.unwrap();

    let result = collection.read("doomed").await;
    assert!(matches!(result, Err(StorageError::KeyNotFound(_))));
}

#[tokio::test]
async fn delete_all_removes_all_keys() {
    let (storage, _dir) = create_test_storage();
    let name = CollectionName::DiagnosticDatabase;
    let collection = storage.get_or_create_collection(&name).await.unwrap();

    // Write multiple keys.
    let mut tx = storage.begin_transaction().unwrap();
    let mut d1: &[u8] = b"one";
    let mut d2: &[u8] = b"two";
    collection.write(&mut tx, "key1", &mut d1).await.unwrap();
    collection.write(&mut tx, "key2", &mut d2).await.unwrap();
    tx.commit().await.unwrap();

    // Delete all.
    let mut tx = storage.begin_transaction().unwrap();
    collection.delete_all(&mut tx).await.unwrap();
    tx.commit().await.unwrap();

    let is_empty = collection.is_empty().await.unwrap();
    assert!(is_empty);
}

// Transaction semantics
#[tokio::test]
async fn rollback_discards_writes() {
    let (storage, _dir) = create_test_storage();
    let name = CollectionName::DiagnosticDatabase;
    let collection = storage.get_or_create_collection(&name).await.unwrap();

    let mut tx = storage.begin_transaction().unwrap();
    let mut data: &[u8] = b"should not persist";
    collection
        .write(&mut tx, "ephemeral", &mut data)
        .await
        .unwrap();
    tx.rollback();

    let result = collection.read("ephemeral").await;
    assert!(matches!(result, Err(StorageError::KeyNotFound(_))));
}

#[tokio::test]
async fn drop_without_commit_is_implicit_rollback() {
    let (storage, _dir) = create_test_storage();
    let name = CollectionName::DiagnosticDatabase;
    let collection = storage.get_or_create_collection(&name).await.unwrap();

    {
        let mut tx = storage.begin_transaction().unwrap();
        let mut data: &[u8] = b"dropped";
        collection.write(&mut tx, "ghost", &mut data).await.unwrap();
        // tx is dropped here without commit.
    }

    let result = collection.read("ghost").await;
    assert!(matches!(result, Err(StorageError::KeyNotFound(_))));
}

#[tokio::test]
async fn no_read_your_writes() {
    let (storage, _dir) = create_test_storage();
    let name = CollectionName::DiagnosticDatabase;
    let collection = storage.get_or_create_collection(&name).await.unwrap();

    let mut tx = storage.begin_transaction().unwrap();
    let mut data: &[u8] = b"uncommitted";
    collection
        .write(&mut tx, "pending", &mut data)
        .await
        .unwrap();

    // Read should not see the uncommitted write.
    let result = collection.read("pending").await;
    assert!(matches!(result, Err(StorageError::KeyNotFound(_))));

    tx.commit().await.unwrap();

    // Now it should be visible.
    let handle = collection.read("pending").await.unwrap();
    assert_eq!(handle.data_size().unwrap(), 11);
}

#[tokio::test]
async fn single_transaction_enforcement() {
    let (storage, _dir) = create_test_storage();

    let _tx = storage.begin_transaction().unwrap();
    let result = storage.begin_transaction();
    assert!(matches!(result, Err(StorageError::TransactionError(_))));
}

#[tokio::test]
async fn can_begin_transaction_after_previous_commits() {
    let (storage, _dir) = create_test_storage();

    let tx = storage.begin_transaction().unwrap();
    tx.commit().await.unwrap();

    // Should be able to begin a new transaction now.
    let tx2 = storage.begin_transaction().unwrap();
    tx2.commit().await.unwrap();
}

#[tokio::test]
async fn can_begin_transaction_after_previous_rollback() {
    let (storage, _dir) = create_test_storage();

    let tx = storage.begin_transaction().unwrap();
    tx.rollback();

    let tx2 = storage.begin_transaction().unwrap();
    tx2.commit().await.unwrap();
}

#[tokio::test]
async fn case_insensitive_keys() {
    let (storage, _dir) = create_test_storage();
    let name = CollectionName::DiagnosticDatabase;
    let collection = storage.get_or_create_collection(&name).await.unwrap();

    let mut tx = storage.begin_transaction().unwrap();
    let mut data: &[u8] = b"case test";
    collection
        .write(&mut tx, "FooBar", &mut data)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    // Reading with different cases should find the same entry.
    let handle = collection.read("foobar").await.unwrap();
    assert_eq!(handle.data_size().unwrap(), 9);

    let handle = collection.read("FOOBAR").await.unwrap();
    assert_eq!(handle.data_size().unwrap(), 9);
}

// Collection management
#[tokio::test]
async fn get_nonexistent_collection_returns_not_found() {
    let (storage, _dir) = create_test_storage();
    let name = CollectionName::Custom("nonexistent".to_string());
    let result = storage.get_collection(&name).await;
    assert!(matches!(result, Err(StorageError::CollectionNotFound(_))));
}

#[tokio::test]
async fn create_and_delete_collection() {
    let (storage, _dir) = create_test_storage();
    let name = CollectionName::Custom("temp_collection".to_string());

    let mut tx = storage.begin_transaction().unwrap();
    let collection = storage.create_collection(&mut tx, &name).await.unwrap();

    // Write data into the new collection (before commit, the dir doesn't exist yet for reads
    // but the write goes to staging).
    let mut data: &[u8] = b"in new collection";
    collection.write(&mut tx, "item", &mut data).await.unwrap();
    tx.commit().await.unwrap();

    // Should be readable now. Drop the handle before the next transaction to avoid deadlock.
    let collection = storage.get_collection(&name).await.unwrap();
    {
        let handle = collection.read("item").await.unwrap();
        assert_eq!(handle.data_size().unwrap(), 17);
    }

    // Delete the collection.
    let mut tx = storage.begin_transaction().unwrap();
    storage.delete_collection(&mut tx, &name).await.unwrap();
    tx.commit().await.unwrap();

    let result = storage.get_collection(&name).await;
    assert!(matches!(result, Err(StorageError::CollectionNotFound(_))));
}

#[tokio::test]
async fn copy_collection() {
    let (storage, _dir) = create_test_storage();
    let source = CollectionName::DiagnosticDatabase;
    let dest = CollectionName::DiagnosticDatabaseBackup;

    // Write some data to source.
    let source_col = storage.get_or_create_collection(&source).await.unwrap();
    let mut tx = storage.begin_transaction().unwrap();
    let mut d1: &[u8] = b"alpha";
    let mut d2: &[u8] = b"beta";
    source_col.write(&mut tx, "a", &mut d1).await.unwrap();
    source_col.write(&mut tx, "b", &mut d2).await.unwrap();
    tx.commit().await.unwrap();

    // Copy source to dest.
    let mut tx = storage.begin_transaction().unwrap();
    storage
        .copy_collection(&mut tx, &source, &dest)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    // Verify dest has the same data.
    let dest_col = storage.get_collection(&dest).await.unwrap();
    let handle_a = dest_col.read("a").await.unwrap();
    let mut buf_a = vec![0u8; 5];
    handle_a.read_at(0, &mut buf_a).unwrap();
    assert_eq!(&buf_a, b"alpha");

    let handle_b = dest_col.read("b").await.unwrap();
    let mut buf_b = vec![0u8; 4];
    handle_b.read_at(0, &mut buf_b).unwrap();
    assert_eq!(&buf_b, b"beta");
}

// Metadata, list, len
#[tokio::test]
async fn metadata_returns_correct_size() {
    let (storage, _dir) = create_test_storage();
    let name = CollectionName::DiagnosticDatabase;
    let collection = storage.get_or_create_collection(&name).await.unwrap();

    let mut tx = storage.begin_transaction().unwrap();
    let mut data: &[u8] = b"twelve chars";
    collection.write(&mut tx, "sized", &mut data).await.unwrap();
    tx.commit().await.unwrap();

    let meta = collection.metadata("sized").await.unwrap();
    assert_eq!(meta.name, "sized");
    assert_eq!(meta.data_size, 12);
}

#[tokio::test]
async fn list_and_len_reflect_committed_state() {
    let (storage, _dir) = create_test_storage();
    let name = CollectionName::DiagnosticDatabase;
    let collection = storage.get_or_create_collection(&name).await.unwrap();

    assert!(collection.is_empty().await.unwrap());
    assert_eq!(collection.len().await.unwrap(), 0);

    let mut tx = storage.begin_transaction().unwrap();
    let mut d1: &[u8] = b"x";
    let mut d2: &[u8] = b"y";
    let mut d3: &[u8] = b"z";
    collection.write(&mut tx, "one", &mut d1).await.unwrap();
    collection.write(&mut tx, "two", &mut d2).await.unwrap();
    collection.write(&mut tx, "three", &mut d3).await.unwrap();
    tx.commit().await.unwrap();

    assert_eq!(collection.len().await.unwrap(), 3);
    assert!(!collection.is_empty().await.unwrap());

    let mut keys = collection.list().await.unwrap();
    keys.sort();
    assert_eq!(keys, vec!["one", "three", "two"]);
}

// Random access data
#[tokio::test]
async fn random_access_read_at_offset() {
    let (storage, _dir) = create_test_storage();
    let name = CollectionName::DiagnosticDatabase;
    let collection = storage.get_or_create_collection(&name).await.unwrap();

    let mut tx = storage.begin_transaction().unwrap();
    let mut data: &[u8] = b"0123456789ABCDEF";
    collection.write(&mut tx, "hex", &mut data).await.unwrap();
    tx.commit().await.unwrap();

    let handle = collection.read("hex").await.unwrap();
    assert_eq!(handle.data_size().unwrap(), 16);

    // Read from offset 10.
    let mut buf = vec![0u8; 6];
    let n = handle.read_at(10, &mut buf).unwrap();
    assert_eq!(n, 6);
    assert_eq!(&buf, b"ABCDEF");

    // Read from offset 14..only 2 bytes remaining.
    let mut buf = vec![0u8; 6];
    let n = handle.read_at(14, &mut buf).unwrap();
    assert_eq!(n, 2);
    assert_eq!(buf.get(..2).unwrap(), b"EF");
}

// Recovery tests
#[tokio::test]
async fn recovery_cleans_up_incomplete_transaction() {
    // Simulate a crash during the recording phase: WAL exists with entries, staging files
    // present, but no .bak files (commit never started applying).
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let collections_dir = root.join("collections");
    let journal_dir = root.join("journal");
    let staging_dir = journal_dir.join("staging");
    std::fs::create_dir_all(&collections_dir).unwrap();
    std::fs::create_dir_all(&staging_dir).unwrap();

    // Create a WAL with a single write operation.
    let wal_path = journal_dir.join("transaction.wal");
    std::fs::File::create(&wal_path).unwrap();

    let staged = staging_dir.join("some_file.tmp");
    std::fs::write(&staged, b"orphaned data").unwrap();
    let staged_str = staged
        .to_str()
        .expect("Failed to convert staging path to string")
        .to_string();

    cda_storage::wal::append_operation(
        &wal_path,
        &cda_interfaces::storage_api::Operation::Write {
            collection: CollectionName::DiagnosticDatabase,
            key: "test".to_string(),
            staged_path: staged_str,
        },
    )
    .unwrap();

    // Creating a new LocalStorage should trigger recovery.
    let storage = LocalStorage::new(root).unwrap();

    // The WAL and staging file should be cleaned up.
    assert!(!wal_path.exists());
    assert!(!staged.exists());

    // And the collection should not have the key.
    let collection = storage
        .get_or_create_collection(&CollectionName::DiagnosticDatabase)
        .await
        .unwrap();
    let result = collection.read("test").await;
    assert!(matches!(result, Err(StorageError::KeyNotFound(_))));
}

#[tokio::test]
async fn recovery_rolls_back_partial_commit() {
    // Simulate a crash during the commit phase: .bak files exist (the commit was partially
    // applied). Recovery should restore the .bak files regardless of WAL state.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let collections_dir = root.join("collections");
    let journal_dir = root.join("journal");
    let staging_dir = journal_dir.join("staging");
    let db_dir = collections_dir.join("diagnostic_database");
    std::fs::create_dir_all(&db_dir).unwrap();
    std::fs::create_dir_all(&staging_dir).unwrap();

    // Simulate: original file was backed up, new file was partially written.
    std::fs::write(db_dir.join("mykey.bak"), b"original data").unwrap();
    std::fs::write(db_dir.join("mykey"), b"new data").unwrap();

    // Create a WAL (its content doesn't matter for rollback. .bak files are the trigger).
    let wal_path = journal_dir.join("transaction.wal");
    std::fs::File::create(&wal_path).unwrap();

    // Recovery should detect .bak files and restore them.
    let storage = LocalStorage::new(root).unwrap();

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

#[tokio::test]
async fn recovery_discards_wal_with_corrupt_checksum() {
    // Create a WAL with valid entries followed by a corrupt entry. Recovery should still work
    // because the WAL reader stops at the first corrupt entry and the incomplete transaction
    // is simply discarded.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let collections_dir = root.join("collections");
    let journal_dir = root.join("journal");
    let staging_dir = journal_dir.join("staging");
    std::fs::create_dir_all(&collections_dir).unwrap();
    std::fs::create_dir_all(&staging_dir).unwrap();

    let wal_path = journal_dir.join("transaction.wal");
    std::fs::File::create(&wal_path).unwrap();

    // Append a valid entry.
    cda_storage::wal::append_operation(
        &wal_path,
        &cda_interfaces::storage_api::Operation::CreateCollection {
            name: CollectionName::Custom("valid_collection".to_string()),
        },
    )
    .unwrap();

    // Append garbage bytes to simulate a torn write (corrupt checksum).
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&wal_path)
        .unwrap();
    file.write_all(&[0xFF; 20]).unwrap();

    // Recovery should succeed, the corrupt entry is simply ignored.
    let _storage = LocalStorage::new(root).unwrap();

    // The WAL should be cleaned up.
    assert!(!wal_path.exists());
}

#[tokio::test]
async fn overwrite_existing_key() {
    let (storage, _dir) = create_test_storage();
    let name = CollectionName::DiagnosticDatabase;
    let collection = storage.get_or_create_collection(&name).await.unwrap();

    // Write initial value.
    let mut tx = storage.begin_transaction().unwrap();
    let mut data: &[u8] = b"version 1";
    collection
        .write(&mut tx, "config", &mut data)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    // Overwrite with new value.
    let mut tx = storage.begin_transaction().unwrap();
    let mut data: &[u8] = b"version 2";
    collection
        .write(&mut tx, "config", &mut data)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let handle = collection.read("config").await.unwrap();
    let mut buf = vec![0u8; 9];
    handle.read_at(0, &mut buf).unwrap();
    assert_eq!(&buf, b"version 2");
}

// WAL checksum round-trip
#[tokio::test]
async fn wal_round_trip_with_checksum_verification() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("test.wal");
    cda_storage::wal::create_wal(&wal_path).unwrap();

    let ops = vec![
        cda_interfaces::storage_api::Operation::CreateCollection {
            name: CollectionName::Custom("col_a".to_string()),
        },
        cda_interfaces::storage_api::Operation::Write {
            collection: CollectionName::DiagnosticDatabase,
            key: "my_key".to_string(),
            staged_path: "/tmp/fake.tmp".to_string(),
        },
        cda_interfaces::storage_api::Operation::Delete {
            collection: CollectionName::DiagnosticDatabase,
            key: "old_key".to_string(),
        },
    ];

    for op in &ops {
        cda_storage::wal::append_operation(&wal_path, op).unwrap();
    }

    let read_ops = cda_storage::wal::read_wal(&wal_path).unwrap();
    assert_eq!(read_ops.len(), 3);

    // Verify the operations match using .get() to satisfy clippy::indexing_slicing.
    let read_op_0 = read_ops.first().expect("Expected 3 operations");
    assert!(matches!(
        read_op_0,
        cda_interfaces::storage_api::Operation::CreateCollection { name }
        if name.as_str() == "col_a"
    ));
    let read_op_1 = read_ops.get(1).expect("Expected 3 operations");
    assert!(matches!(
        read_op_1,
        cda_interfaces::storage_api::Operation::Write { key, .. }
        if key == "my_key"
    ));
    let read_op_2 = read_ops.get(2).expect("Expected 3 operations");
    assert!(matches!(
        read_op_2,
        cda_interfaces::storage_api::Operation::Delete { key, .. }
        if key == "old_key"
    ));
}

#[tokio::test]
async fn wal_stops_at_truncated_entry() {
    let dir = tempfile::tempdir().unwrap();
    let wal_path = dir.path().join("test.wal");
    cda_storage::wal::create_wal(&wal_path).unwrap();

    // Write two valid entries.
    cda_storage::wal::append_operation(
        &wal_path,
        &cda_interfaces::storage_api::Operation::CreateCollection {
            name: CollectionName::Custom("first".to_string()),
        },
    )
    .unwrap();
    cda_storage::wal::append_operation(
        &wal_path,
        &cda_interfaces::storage_api::Operation::CreateCollection {
            name: CollectionName::Custom("second".to_string()),
        },
    )
    .unwrap();

    // Truncate the file to corrupt the second entry (keep first + partial second).
    let data = std::fs::read(&wal_path).unwrap();
    // Write only 80% of the data to truncate the second entry.
    let truncated_len = data.len() * 4 / 5;
    std::fs::write(&wal_path, data.get(..truncated_len).unwrap()).unwrap();

    let read_ops = cda_storage::wal::read_wal(&wal_path).unwrap();
    // Should only have the first valid entry.
    assert_eq!(read_ops.len(), 1);
    let read_op_0 = read_ops.first().expect("Expected 1 operation");
    assert!(matches!(
        read_op_0,
        cda_interfaces::storage_api::Operation::CreateCollection { name }
        if name.as_str() == "first"
    ));
}
