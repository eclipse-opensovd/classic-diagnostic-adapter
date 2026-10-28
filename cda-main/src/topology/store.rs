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

//! [`EcuTopologyStore`] on top of the storage API.
//!
//! One entry per gateway in the [`ECU_TOPOLOGY_COLLECTION`] collection, keyed by
//! [`gateway_key`]. Each value is a versioned JSON document, so entries stay
//! readable for diagnosis and can be migrated by bumping [`STORED_VERSION`].

use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use backon::Retryable as _;
use cda_interfaces::{
    HashMap, HashSet,
    storage_api::{
        Collection, CollectionName, RandomAccessData, Storage, StorageError, Transaction,
    },
    topology::{
        ECU_TOPOLOGY_COLLECTION, EcuTopologyStore, PersistedEcu, PersistedEcuState,
        PersistedGateway, PersistedTopology, PersistedVariant, TopologyStoreError, gateway_key,
    },
    util::format_rfc3339_millis,
};
use chrono::DateTime;
use serde::{Deserialize, Serialize};

/// Version of the stored JSON document. Entries with another version are skipped.
pub const STORED_VERSION: u32 = 1;

/// Upper bound for a single entry. Anything larger is not a topology entry.
const MAX_ENTRY_SIZE: u64 = 1024 * 1024;

const TRANSACTION_BUSY_RETRIES: usize = 5;
const TRANSACTION_BUSY_MIN_DELAY: Duration = Duration::from_millis(100);
const TRANSACTION_BUSY_MAX_DELAY: Duration = Duration::from_secs(1);

/// [`EcuTopologyStore`] backed by a [`Storage`] collection.
///
/// Writes (`upsert`, `merge_last_seen`, `prune`, `clear`) are serialized, each for its
/// whole read-modify-write sequence. Every one runs in a task of its own that holds the
/// lock until the commit is done, so a caller that is dropped meanwhile does not release
/// the lock early. A sequence over several calls (e.g. `persist()` load, then upsert)
/// is protected by the persist task lifecycle, not by this lock.
/// [[ dimpl~ecu-topology-store, ECU topology store on the storage API, dimpl ]]
pub struct StorageEcuTopologyStore<S: Storage> {
    inner: Arc<StoreInner<S>>,
}

/// State shared with the tasks that run the writes.
struct StoreInner<S: Storage> {
    storage: Arc<S>,
    write_lock: Arc<tokio::sync::Mutex<()>>,
}

impl<S: Storage + 'static> StorageEcuTopologyStore<S> {
    /// Creates a store on `storage`. The collection is created on the first write.
    #[must_use]
    pub fn new(storage: Arc<S>) -> Self {
        Self {
            inner: Arc::new(StoreInner {
                storage,
                write_lock: Arc::new(tokio::sync::Mutex::new(())),
            }),
        }
    }

    /// Runs `work` in a task of its own, holding the write lock for its whole
    /// duration. The task is not tied to the caller: it completes (and releases
    /// the lock) even if the caller is dropped.
    /// [[ dimpl~ecu-topology-store-serialized, Read-modify-write sequences of the store are serialized and cancel-safe, dimpl ]]
    async fn serialized<T, F, Fut>(&self, work: F) -> Result<T, TopologyStoreError>
    where
        T: Send + 'static,
        F: FnOnce(Arc<StoreInner<S>>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, TopologyStoreError>> + Send + 'static,
    {
        let inner = Arc::clone(&self.inner);
        let task = cda_interfaces::spawn_named!("ecu-topology-store-write", async move {
            let _guard = Arc::clone(&inner.write_lock).lock_owned().await;
            work(inner).await
        });
        task.await.unwrap_or_else(|error| {
            Err(TopologyStoreError::Storage(StorageError::Other(format!(
                "Topology write task failed: {error}"
            ))))
        })
    }
}

impl<S: Storage> StoreInner<S> {
    fn collection_name() -> CollectionName {
        CollectionName::Custom(ECU_TOPOLOGY_COLLECTION.to_owned())
    }

    /// Returns the existing collection, or `None` if it was never created.
    async fn existing_collection(&self) -> Result<Option<Arc<S::CollectionHandle>>, StorageError> {
        match self.storage.get_collection(&Self::collection_name()).await {
            Ok(collection) => Ok(Some(collection)),
            Err(StorageError::CollectionNotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Reads all raw entries. Every read handle is dropped before this returns,
    /// so a following write can replace or delete the files (required on Windows).
    async fn read_entries(&self) -> Result<Vec<(String, StoredGateway)>, StorageError> {
        let Some(collection) = self.existing_collection().await? else {
            return Ok(Vec::new());
        };
        let mut entries = Vec::new();
        for key in collection.list().await? {
            let bytes = match collection.read(&key).await {
                Ok(data) => read_all(data.as_ref()),
                Err(e) => Err(e),
            };
            match bytes.map(|bytes| decode_entry(&key, &bytes)) {
                Ok(Ok(entry)) => entries.push((key, entry)),
                Ok(Err(reason)) => {
                    tracing::warn!(key, reason, "Skipping unreadable persisted topology entry");
                }
                Err(e) => {
                    tracing::warn!(key, error = %e, "Skipping unreadable persisted topology entry");
                }
            }
        }
        Ok(entries)
    }

    /// Applies `op` in its own transaction and commits it. `TransactionBusy` is
    /// retried, since a runtime update may hold the single transaction slot.
    async fn write(&self, op: &WriteOp) -> Result<(), StorageError> {
        // Created outside of the transaction: creating a missing collection runs an
        // implicit transaction of its own, which would be busy otherwise.
        let collection = (async || {
            self.storage
                .get_or_create_collection(&Self::collection_name())
                .await
        })
        .retry(busy_backoff())
        .when(|e| matches!(e, StorageError::TransactionBusy))
        .await?;

        (async || {
            let mut tx = self.storage.begin_transaction()?;
            match apply(collection.as_ref(), &mut tx, op).await {
                Ok(()) => tx.commit().await,
                Err(e) => {
                    tx.rollback();
                    Err(e)
                }
            }
        })
        .retry(busy_backoff())
        .when(|e| matches!(e, StorageError::TransactionBusy))
        .notify(|_, delay: Duration| {
            tracing::debug!(?delay, "Storage transaction busy, retrying topology write");
        })
        .await
    }
}

/// A single topology write, applied in one transaction.
enum WriteOp {
    /// Delete all entries.
    DeleteAll,
    /// Write the encoded entries (replacing existing ones with the same key) and
    /// delete the given keys.
    Update {
        puts: Vec<(String, Vec<u8>)>,
        deletes: Vec<String>,
    },
}

impl WriteOp {
    fn put(puts: Vec<(String, Vec<u8>)>) -> Self {
        Self::Update {
            puts,
            deletes: Vec::new(),
        }
    }
}

async fn apply(
    collection: &impl Collection,
    tx: &mut Transaction,
    op: &WriteOp,
) -> Result<(), StorageError> {
    match op {
        WriteOp::DeleteAll => collection.delete_all(tx).await,
        WriteOp::Update { puts, deletes } => {
            for (key, bytes) in puts {
                collection
                    .write(tx, key, &mut std::io::Cursor::new(bytes.as_slice()))
                    .await?;
            }
            for key in deletes {
                collection.delete(tx, key).await?;
            }
            Ok(())
        }
    }
}

fn to_json<T: Serialize>(value: &T) -> Result<Vec<u8>, TopologyStoreError> {
    serde_json::to_vec(value).map_err(|e| TopologyStoreError::Serialization(e.to_string()))
}

fn busy_backoff() -> backon::ExponentialBuilder {
    backon::ExponentialBuilder::default()
        .with_min_delay(TRANSACTION_BUSY_MIN_DELAY)
        .with_max_delay(TRANSACTION_BUSY_MAX_DELAY)
        .with_max_times(TRANSACTION_BUSY_RETRIES)
}

#[async_trait]
impl<S: Storage + 'static> EcuTopologyStore for StorageEcuTopologyStore<S> {
    fn is_enabled(&self) -> bool {
        true
    }

    async fn load(&self) -> Result<PersistedTopology, TopologyStoreError> {
        let gateways = self
            .inner
            .read_entries()
            .await?
            .into_iter()
            .map(|(_, entry)| entry.into())
            .collect();
        Ok(PersistedTopology { gateways })
    }

    async fn upsert(&self, gateways: &[PersistedGateway]) -> Result<(), TopologyStoreError> {
        if gateways.is_empty() {
            return Ok(());
        }
        let gateways = gateways.to_vec();
        self.serialized(move |inner| async move {
            let encoded = gateways
                .iter()
                .map(|gateway| {
                    to_json(&StoredGateway::from(gateway))
                        .map(|bytes| (gateway_key(gateway.logical_address), bytes))
                })
                .collect::<Result<Vec<_>, _>>()?;

            inner.write(&WriteOp::put(encoded)).await?;
            Ok(())
        })
        .await
    }

    async fn merge_last_seen(
        &self,
        last_seen: &HashMap<String, SystemTime>,
    ) -> Result<usize, TopologyStoreError> {
        if last_seen.is_empty() {
            return Ok(0);
        }
        let last_seen = last_seen.clone();
        self.serialized(move |inner| async move {
            let mut changed = Vec::new();
            for (key, mut entry) in inner.read_entries().await? {
                let mut updated = false;
                for ecu in &mut entry.ecus {
                    if let Some(time) = last_seen.get(&ecu.name.to_lowercase()) {
                        let formatted = Some(format_rfc3339_millis(*time));
                        if ecu.last_seen != formatted {
                            ecu.last_seen = formatted;
                            updated = true;
                        }
                    }
                }
                if updated {
                    let bytes = to_json(&entry)?;
                    changed.push((key, bytes));
                }
            }
            if changed.is_empty() {
                return Ok(0);
            }

            let count = changed.len();
            inner.write(&WriteOp::put(changed)).await?;
            Ok(count)
        })
        .await
    }

    async fn prune(
        &self,
        keep: &HashMap<u16, HashSet<String>>,
    ) -> Result<usize, TopologyStoreError> {
        let keep = keep.clone();
        self.serialized(move |inner| async move {
            let mut puts = Vec::new();
            let mut deletes = Vec::new();
            for (key, mut entry) in inner.read_entries().await? {
                let Some(ecus) = keep.get(&entry.logical_address) else {
                    deletes.push(key);
                    continue;
                };
                let before = entry.ecus.len();
                entry
                    .ecus
                    .retain(|ecu| ecus.contains(&ecu.name.to_lowercase()));
                if entry.ecus.len() != before {
                    let bytes = to_json(&entry)?;
                    puts.push((key, bytes));
                }
            }
            let count = puts.len().saturating_add(deletes.len());
            if count == 0 {
                return Ok(0);
            }
            inner.write(&WriteOp::Update { puts, deletes }).await?;
            Ok(count)
        })
        .await
    }

    async fn clear(&self) -> Result<(), TopologyStoreError> {
        self.serialized(move |inner| async move {
            let Some(collection) = inner.existing_collection().await? else {
                return Ok(());
            };
            if collection.is_empty().await? {
                return Ok(());
            }
            inner.write(&WriteOp::DeleteAll).await?;
            Ok(())
        })
        .await
    }
}

fn read_all(data: &impl RandomAccessData) -> Result<Vec<u8>, StorageError> {
    let size = data.data_size()?;
    if size > MAX_ENTRY_SIZE {
        return Err(StorageError::Other(format!(
            "Entry of {size} bytes exceeds the limit of {MAX_ENTRY_SIZE} bytes"
        )));
    }
    let len = usize::try_from(size).map_err(|e| StorageError::Other(e.to_string()))?;
    let mut buf = vec![0u8; len];
    let mut filled = 0usize;
    while let Some(rest) = buf.get_mut(filled..)
        && !rest.is_empty()
    {
        let offset = u64::try_from(filled).map_err(|e| StorageError::Other(e.to_string()))?;
        let read = data.read_at(offset, rest)?;
        if read == 0 {
            buf.truncate(filled);
            break;
        }
        filled = filled.saturating_add(read);
    }
    Ok(buf)
}

/// Decodes a raw entry. Returns the reason as error for logging.
fn decode_entry(key: &str, bytes: &[u8]) -> Result<StoredGateway, String> {
    let entry: StoredGateway =
        serde_json::from_slice(bytes).map_err(|e| format!("Invalid JSON: {e}"))?;
    if entry.version != STORED_VERSION {
        return Err(format!(
            "Unsupported version {}, expected {STORED_VERSION}",
            entry.version
        ));
    }
    if !key.eq_ignore_ascii_case(&gateway_key(entry.logical_address)) {
        return Err(format!(
            "Key does not match the logical address {:#06x}",
            entry.logical_address
        ));
    }
    // A timestamp that cannot be represented makes the entry unreadable, like invalid
    // JSON, instead of panicking in the conversion or silently dropping it.
    for ecu in &entry.ecus {
        if let Some(value) = &ecu.last_seen
            && parse_time(value).is_none()
        {
            return Err(format!("Invalid last_seen {value:?} of ECU {}", ecu.name));
        }
    }
    Ok(entry)
}

/// Parses an RFC 3339 timestamp. `None` if it is invalid or not representable as
/// [`SystemTime`] on this platform.
fn parse_time(value: &str) -> Option<SystemTime> {
    let time = DateTime::parse_from_rfc3339(value).ok()?;
    let secs = time.timestamp();
    let nanos = time.timestamp_subsec_nanos();
    if secs >= 0 {
        SystemTime::UNIX_EPOCH.checked_add(Duration::new(u64::try_from(secs).ok()?, nanos))
    } else {
        SystemTime::UNIX_EPOCH
            .checked_sub(Duration::from_secs(secs.unsigned_abs()))?
            .checked_add(Duration::from_nanos(nanos.into()))
    }
}

/// On-disk form of a [`PersistedGateway`].
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredGateway {
    version: u32,
    name: String,
    logical_address: u16,
    #[serde(default)]
    network_address: Option<String>,
    #[serde(default)]
    doip_protocol_version: Option<u8>,
    #[serde(default)]
    ecus: Vec<StoredEcu>,
}

/// On-disk form of a [`PersistedEcu`]. `last_seen` is RFC 3339 UTC.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredEcu {
    name: String,
    logical_address: u16,
    #[serde(default)]
    variant: Option<StoredVariant>,
    state: StoredEcuState,
    #[serde(default)]
    last_seen: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredVariant {
    name: String,
    is_base_variant: bool,
    is_fallback: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
enum StoredEcuState {
    Online,
    Offline,
    NotTested,
    NoVariantDetected,
    Duplicate,
    Disconnected,
}

impl From<&PersistedGateway> for StoredGateway {
    fn from(gateway: &PersistedGateway) -> Self {
        Self {
            version: STORED_VERSION,
            name: gateway.name.clone(),
            logical_address: gateway.logical_address,
            network_address: gateway.network_address.clone(),
            doip_protocol_version: gateway.doip_protocol_version,
            ecus: gateway
                .ecus
                .iter()
                .map(|ecu| StoredEcu {
                    name: ecu.name.clone(),
                    logical_address: ecu.logical_address,
                    variant: ecu.variant.as_ref().map(|variant| StoredVariant {
                        name: variant.name.clone(),
                        is_base_variant: variant.is_base_variant,
                        is_fallback: variant.is_fallback,
                    }),
                    state: ecu.state.into(),
                    last_seen: ecu.last_seen.map(format_rfc3339_millis),
                })
                .collect(),
        }
    }
}

impl From<StoredGateway> for PersistedGateway {
    fn from(gateway: StoredGateway) -> Self {
        Self {
            name: gateway.name,
            logical_address: gateway.logical_address,
            network_address: gateway.network_address,
            doip_protocol_version: gateway.doip_protocol_version,
            ecus: gateway
                .ecus
                .into_iter()
                .map(|ecu| PersistedEcu {
                    last_seen: ecu.last_seen.as_deref().and_then(parse_time),
                    name: ecu.name,
                    logical_address: ecu.logical_address,
                    variant: ecu.variant.map(|variant| PersistedVariant {
                        name: variant.name,
                        is_base_variant: variant.is_base_variant,
                        is_fallback: variant.is_fallback,
                    }),
                    state: ecu.state.into(),
                })
                .collect(),
        }
    }
}

impl From<PersistedEcuState> for StoredEcuState {
    fn from(state: PersistedEcuState) -> Self {
        match state {
            PersistedEcuState::Online => Self::Online,
            PersistedEcuState::Offline => Self::Offline,
            PersistedEcuState::NotTested => Self::NotTested,
            PersistedEcuState::NoVariantDetected => Self::NoVariantDetected,
            PersistedEcuState::Duplicate => Self::Duplicate,
            PersistedEcuState::Disconnected => Self::Disconnected,
        }
    }
}

impl From<StoredEcuState> for PersistedEcuState {
    fn from(state: StoredEcuState) -> Self {
        match state {
            StoredEcuState::Online => Self::Online,
            StoredEcuState::Offline => Self::Offline,
            StoredEcuState::NotTested => Self::NotTested,
            StoredEcuState::NoVariantDetected => Self::NoVariantDetected,
            StoredEcuState::Duplicate => Self::Duplicate,
            StoredEcuState::Disconnected => Self::Disconnected,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use cda_interfaces::HashMapExtensions as _;
    use cda_storage::LocalStorage;
    use tempfile::TempDir;

    use super::*;

    struct Fixture {
        storage: Arc<LocalStorage>,
        store: StorageEcuTopologyStore<LocalStorage>,
        _dir: TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("storage dir");
            let storage = Arc::new(LocalStorage::new(dir.path()).expect("storage"));
            Self {
                store: StorageEcuTopologyStore::new(Arc::clone(&storage)),
                storage,
                _dir: dir,
            }
        }

        async fn write_raw(&self, key: &str, bytes: &[u8]) {
            let collection = self
                .storage
                .get_or_create_collection(&StoreInner::<LocalStorage>::collection_name())
                .await
                .unwrap();
            let mut tx = self.storage.begin_transaction().unwrap();
            collection
                .write(&mut tx, key, &mut std::io::Cursor::new(bytes))
                .await
                .unwrap();
            tx.commit().await.unwrap();
        }
    }

    fn time(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_millis(
                secs.saturating_mul(1000).saturating_add(123),
            ))
            .unwrap()
    }

    fn gateway(logical_address: u16, ecu: &str) -> PersistedGateway {
        PersistedGateway {
            name: format!("gw_{logical_address:x}"),
            logical_address,
            network_address: Some("10.2.1.10".to_owned()),
            doip_protocol_version: Some(3),
            ecus: vec![PersistedEcu {
                name: ecu.to_owned(),
                logical_address,
                variant: Some(PersistedVariant {
                    name: format!("{ecu}_App"),
                    is_base_variant: false,
                    is_fallback: false,
                }),
                state: PersistedEcuState::Online,
                last_seen: Some(time(1_700_000_000)),
            }],
        }
    }

    fn sorted(mut topology: PersistedTopology) -> Vec<PersistedGateway> {
        topology.gateways.sort_by_key(|g| g.logical_address);
        topology.gateways
    }

    /// [[ test~ecu-topology-store-upsert-keeps-other-entries, A write upserts its gateways and keeps all other entries, test ]]
    #[tokio::test]
    async fn upsert_keeps_other_entries() {
        let fixture = Fixture::new();
        fixture
            .store
            .upsert(&[gateway(0x1000, "FLXC1000"), gateway(0x2000, "FSNR2000")])
            .await
            .unwrap();

        let mut replaced = gateway(0x1000, "FLXC1000");
        replaced.network_address = Some("10.2.1.99".to_owned());
        fixture.store.upsert(&[replaced.clone()]).await.unwrap();

        assert_eq!(
            sorted(fixture.store.load().await.unwrap()),
            vec![replaced, gateway(0x2000, "FSNR2000")]
        );
    }

    /// [[ test~ecu-topology-store-unreadable-entries-are-skipped, An unreadable entry is skipped, test ]]
    #[tokio::test]
    async fn unreadable_entries_are_skipped() {
        let fixture = Fixture::new();
        fixture
            .store
            .upsert(&[gateway(0x1000, "FLXC1000")])
            .await
            .unwrap();
        fixture.write_raw("0x2000", b"not json").await;
        fixture
            .write_raw(
                "0x3000",
                br#"{"version":99,"name":"gw","logical_address":12288,"ecus":[]}"#,
            )
            .await;
        // Key and logical address disagree.
        fixture
            .write_raw(
                "0x4000",
                br#"{"version":1,"name":"gw","logical_address":4096,"ecus":[]}"#,
            )
            .await;

        assert_eq!(
            fixture.store.load().await.unwrap().gateways,
            vec![gateway(0x1000, "FLXC1000")]
        );
    }

    #[tokio::test]
    async fn busy_transaction_is_retried() {
        let fixture = Fixture::new();
        // Make sure the collection exists, so only the write transaction is contended.
        fixture
            .store
            .upsert(&[gateway(0x1000, "FLXC1000")])
            .await
            .unwrap();

        let tx = fixture.storage.begin_transaction().unwrap();
        let release = async move {
            cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(150)).await;
            tx.rollback();
        };
        let second = [gateway(0x2000, "FSNR2000")];
        let (result, ()) = tokio::join!(fixture.store.upsert(&second), release);
        result.unwrap();
        assert_eq!(fixture.store.load().await.unwrap().gateways.len(), 2);
    }

    /// Storage that holds the next `get_or_create_collection` until released: the
    /// step of a write between its read and its commit.
    struct HoldingStorage {
        inner: LocalStorage,
        hold_next: AtomicBool,
        entered: AtomicBool,
        gate: tokio::sync::watch::Sender<bool>,
    }

    impl HoldingStorage {
        fn new(dir: &TempDir) -> Arc<Self> {
            Arc::new(Self {
                inner: LocalStorage::new(dir.path()).expect("storage"),
                hold_next: AtomicBool::new(false),
                entered: AtomicBool::new(false),
                gate: tokio::sync::watch::Sender::new(true),
            })
        }

        fn hold_next_write(&self) {
            self.entered.store(false, Ordering::SeqCst);
            self.gate.send_replace(false);
            self.hold_next.store(true, Ordering::SeqCst);
        }

        fn release(&self) {
            self.gate.send_replace(true);
        }

        async fn wait_entered(&self) {
            for _ in 0..500 {
                if self.entered.load(Ordering::SeqCst) {
                    return;
                }
                cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(10)).await;
            }
            panic!("the write did not reach the held step");
        }
    }

    impl Storage for HoldingStorage {
        type CollectionHandle = <LocalStorage as Storage>::CollectionHandle;

        fn get_collection(
            &self,
            name: &CollectionName,
        ) -> impl Future<Output = Result<Arc<Self::CollectionHandle>, StorageError>> + Send
        {
            self.inner.get_collection(name)
        }

        async fn get_or_create_collection(
            &self,
            name: &CollectionName,
        ) -> Result<Arc<Self::CollectionHandle>, StorageError> {
            if self.hold_next.swap(false, Ordering::SeqCst) {
                self.entered.store(true, Ordering::SeqCst);
                let _ = self.gate.subscribe().wait_for(|open| *open).await;
            }
            self.inner.get_or_create_collection(name).await
        }

        fn begin_transaction(&self) -> Result<Transaction, StorageError> {
            self.inner.begin_transaction()
        }

        fn create_collection(
            &self,
            tx: &mut Transaction,
            name: &CollectionName,
        ) -> impl Future<Output = Result<Arc<Self::CollectionHandle>, StorageError>> + Send
        {
            self.inner.create_collection(tx, name)
        }

        fn delete_collection(
            &self,
            tx: &mut Transaction,
            name: &CollectionName,
        ) -> impl Future<Output = Result<(), StorageError>> + Send {
            self.inner.delete_collection(tx, name)
        }

        fn copy_collection(
            &self,
            tx: &mut Transaction,
            source: &CollectionName,
            dest: &CollectionName,
        ) -> impl Future<Output = Result<(), StorageError>> + Send {
            self.inner.copy_collection(tx, source, dest)
        }
    }

    /// [[ test~ecu-topology-store-serialized, A clear waits for a merge that is between its read and its commit, test ]]
    #[tokio::test]
    async fn clear_waits_for_merge_last_seen() {
        let dir = tempfile::tempdir().expect("storage dir");
        let storage = HoldingStorage::new(&dir);
        let store = Arc::new(StorageEcuTopologyStore::new(Arc::clone(&storage)));
        store.upsert(&[gateway(0x1000, "FLXC1000")]).await.unwrap();

        storage.hold_next_write();
        let merge = {
            let store = Arc::clone(&store);
            tokio::spawn(async move {
                let mut last_seen = HashMap::new();
                last_seen.insert("flxc1000".to_owned(), time(1_800_000_000));
                store.merge_last_seen(&last_seen).await
            })
        };
        storage.wait_entered().await;
        let clear = {
            let store = Arc::clone(&store);
            tokio::spawn(async move { store.clear().await })
        };
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(100)).await;
        assert!(!clear.is_finished(), "clear must wait for the merge");

        storage.release();
        assert_eq!(merge.await.unwrap().unwrap(), 1);
        clear.await.unwrap().unwrap();
        assert!(store.load().await.unwrap().is_empty(), "clear ran last");
    }

    /// [[ test~ecu-topology-store-cancelled-call-keeps-lock, A write whose caller is dropped keeps the lock until its commit, test ]]
    #[tokio::test]
    async fn dropped_write_keeps_the_lock_until_it_committed() {
        let dir = tempfile::tempdir().expect("storage dir");
        let storage = HoldingStorage::new(&dir);
        let store = Arc::new(StorageEcuTopologyStore::new(Arc::clone(&storage)));
        store.upsert(&[gateway(0x1000, "FLXC1000")]).await.unwrap();

        storage.hold_next_write();
        let first = {
            let store = Arc::clone(&store);
            tokio::spawn(async move { store.upsert(&[gateway(0x2000, "FSNR2000")]).await })
        };
        storage.wait_entered().await;
        first.abort();
        let second = {
            let store = Arc::clone(&store);
            tokio::spawn(async move { store.upsert(&[gateway(0x3000, "FLXC3000")]).await })
        };
        cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(100)).await;
        assert!(
            !second.is_finished(),
            "the dropped caller must not have released the lock"
        );

        storage.release();
        second.await.unwrap().unwrap();
        assert_eq!(sorted(store.load().await.unwrap()).len(), 3);
    }

    /// [[ test~ecu-topology-prune, Entries no longer in the databases are pruned, test ]]
    #[tokio::test]
    async fn prune_removes_what_is_no_longer_in_the_databases() {
        let fixture = Fixture::new();
        let mut two_ecus = gateway(0x1000, "FLXC1000");
        let mut removed_ecu = two_ecus.ecus.first().unwrap().clone();
        removed_ecu.name = "REMOVED".to_owned();
        two_ecus.ecus.push(removed_ecu);
        fixture
            .store
            .upsert(&[
                two_ecus,
                gateway(0x2000, "FSNR2000"),
                gateway(0x7777, "GONE"),
            ])
            .await
            .unwrap();

        let mut keep: HashMap<u16, HashSet<String>> = HashMap::new();
        keep.insert(0x1000, ["flxc1000".to_owned()].into_iter().collect());
        // Still in the databases, but not seen by the last detection run.
        keep.insert(0x2000, ["fsnr2000".to_owned()].into_iter().collect());
        assert_eq!(fixture.store.prune(&keep).await.unwrap(), 2);

        assert_eq!(
            sorted(fixture.store.load().await.unwrap()),
            vec![gateway(0x1000, "FLXC1000"), gateway(0x2000, "FSNR2000")]
        );
        assert_eq!(
            fixture.store.prune(&keep).await.unwrap(),
            0,
            "nothing left to prune"
        );
    }
}
