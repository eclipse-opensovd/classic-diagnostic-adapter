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

use std::sync::Arc;

use async_trait::async_trait;
use cda_interfaces::{
    runtime_update_api::{LockStateProvider, RuntimeUpdateError, UploadFile, VerificationError},
    storage_api::{
        Collection, CollectionName, DirectFileAccess, ReadableStream, Storage, Transaction,
    },
};
use cda_storage::LocalStorage;

pub(crate) async fn write_file(
    storage: &impl Storage,
    tx: &mut Transaction,
    collection_name: &CollectionName,
    key: &str,
    data: &mut impl ReadableStream,
) -> Result<(), RuntimeUpdateError> {
    let key = key.to_lowercase();
    let collection = storage.get_or_create_collection(collection_name).await?;
    collection.write(tx, &key, data).await?;
    Ok(())
}

/// Test validator backed by the MDD reader for deterministic format-specific file operations.
pub struct TestMddDatabaseValidator;

impl cda_interfaces::runtime_update_api::DatabaseValidator for TestMddDatabaseValidator {
    fn check_integrity(&self, path: &std::path::Path) -> Result<(), VerificationError> {
        let path_str = path
            .to_str()
            .ok_or_else(|| VerificationError("non-UTF-8 path".to_owned()))?;
        cda_database::mmap_and_decode_mdd(path_str)
            .map_err(|error| VerificationError(format!("{error}")))?;
        Ok(())
    }
}

/// Shared `database_validator` handle for tests.
pub fn test_database_validator() -> Arc<dyn cda_interfaces::runtime_update_api::DatabaseValidator> {
    Arc::new(TestMddDatabaseValidator)
}

/// Validator that accepts everything, for tests about paths other than file content.
pub struct AcceptingDatabaseValidator;

impl cda_interfaces::runtime_update_api::DatabaseValidator for AcceptingDatabaseValidator {
    fn check_integrity(&self, _path: &std::path::Path) -> Result<(), VerificationError> {
        Ok(())
    }
}

pub struct MockLockProvider {
    pub owner: Option<String>,
    pub has_conflicts: bool,
}

#[async_trait]
impl LockStateProvider for MockLockProvider {
    async fn vehicle_lock_owner_id(&self) -> Option<String> {
        self.owner.clone()
    }

    async fn has_locks(&self) -> bool {
        self.has_conflicts
    }
}

pub struct MockUpdatePolicy;

impl MockUpdatePolicy {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl<L: LockStateProvider, C: Collection + DirectFileAccess + Send + Sync + 'static>
    cda_interfaces::runtime_update_api::RuntimeUpdatePolicy<L, C> for MockUpdatePolicy
{
    async fn check_execution_allowed(
        &self,
        lock_state_provider: &L,
        _collections: &cda_interfaces::runtime_update_api::UpdateCollections<C>,
    ) -> Result<(), RuntimeUpdateError> {
        let owner = lock_state_provider.vehicle_lock_owner_id().await;
        match owner {
            None => Err(RuntimeUpdateError::NoLock(
                "No vehicle lock held".to_string(),
            )),
            Some(_) => Ok(()),
        }
    }
}

pub fn make_valid_mdd(ecu_name: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"MDD version 0      \0");
    buf.extend_from_slice(&[0x0A, 0x01, 0x31]);
    buf.push(0x1A);
    buf.push(u8::try_from(ecu_name.len()).expect("ecu_name must be <= 255 bytes"));
    buf.extend_from_slice(ecu_name.as_bytes());
    buf
}

/// Like `make_valid_mdd` but also encodes a `revision` field (proto tag 4).
pub fn make_valid_mdd_with_revision(ecu_name: &str, revision: &str) -> Vec<u8> {
    let mut buf = make_valid_mdd(ecu_name);
    // Proto field 4, wire type 2 (length-delimited) -> tag byte 0x22
    buf.push(0x22);
    buf.push(u8::try_from(revision.len()).expect("revision must be <= 255 bytes"));
    buf.extend_from_slice(revision.as_bytes());
    buf
}

pub fn make_valid_config() -> Vec<u8> {
    b"[server]\nport = 8080\n".to_vec()
}

/// Smallest byte sequence `mmap_and_decode_mdd` accepts, naming `ecu_name`.
///
/// Anything written under a `.mdd` key has to be readable: an execution
/// refuses databases it cannot parse before it moves any state.
#[must_use]
pub fn readable_mdd_bytes(ecu_name: &str) -> Vec<u8> {
    let magic: &[u8] = &[
        0x4D, 0x44, 0x44, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x20, 0x30, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x00,
    ];
    let name_bytes = ecu_name.as_bytes();
    let mut bytes = magic.to_vec();
    bytes.push(0x1A);
    bytes.push(u8::try_from(name_bytes.len()).expect("test ECU name fits in a byte"));
    bytes.extend_from_slice(name_bytes);
    bytes
}

pub async fn write_test_file(
    storage: &LocalStorage,
    collection_name: &CollectionName,
    key: &str,
    data: &[u8],
) {
    let col = storage
        .get_or_create_collection(collection_name)
        .await
        .unwrap();
    let mut tx = storage.begin_transaction().unwrap();
    let mut cursor: &[u8] = data;
    col.write(&mut tx, key, &mut cursor).await.unwrap();
    tx.commit().await.unwrap();
}

pub fn make_upload_files(entries: &[(&str, &[u8])]) -> Vec<UploadFile> {
    entries
        .iter()
        .filter(|(name, _)| !name.is_empty())
        .map(|(name, data)| UploadFile {
            filename: (*name).to_string(),
            data: data.to_vec().into(),
        })
        .collect()
}

pub fn make_storage() -> (LocalStorage, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = LocalStorage::new(dir.path()).expect("LocalStorage");
    (storage, dir)
}

pub async fn init_collection(
    storage: &LocalStorage,
    name: &CollectionName,
    keys: &[(&str, &[u8])],
) {
    storage.get_or_create_collection(name).await.unwrap();
    let mut tx = storage.begin_transaction().unwrap();
    for (key, data) in keys {
        let mut d: &[u8] = data;
        write_file(storage, &mut tx, name, key, &mut d)
            .await
            .unwrap();
    }
    tx.commit().await.unwrap();
}
