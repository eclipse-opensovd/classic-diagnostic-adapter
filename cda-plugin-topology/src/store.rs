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
//! One entry per gateway in the [`CollectionName::EcuTopology`] collection, keyed by
//! [`logical_address_hex`]. Each value is the JSON form of a [`PersistedGateway`], so
//! entries stay readable for diagnosis.

use std::{collections::BTreeMap, sync::Arc, time::SystemTime};

use async_trait::async_trait;
use cda_interfaces::{
    HashMap, HashSet,
    storage_api::{Collection, CollectionName, RandomAccessReader, Storage, StorageError},
    topology::{
        EcuTopologyStore, PersistedGateway, PersistedTopology, TopologyStoreError,
        logical_address_hex,
    },
    util::system_time_to_rfc3339,
};

/// [`EcuTopologyStore`] backed by a [`Storage`] collection.
///
/// Writes (`persist_gateways`, `merge_last_seen`, `prune_and_persist_gateways`) are
/// serialized, each for its whole read-modify-write sequence, see
/// [`Self::spawn_locked_write`]. A sequence over several calls (e.g. `persist()` load,
/// then `prune_and_persist_gateways`) is protected by the persist task lifecycle, not
/// by this lock.
/// [[ dimpl~ecu-topology-store, ECU topology store on the storage API, dimpl ]]
pub struct StorageEcuTopologyStore<S: Storage> {
    storage: Arc<S>,
    write_lock: Arc<tokio::sync::Mutex<()>>,
}

/// A single topology write, applied in one transaction: `Some` writes the encoded
/// entry (replacing an existing one with the same key), `None` deletes it.
type WriteOp = BTreeMap<String, Option<Vec<u8>>>;

impl<S: Storage + 'static> StorageEcuTopologyStore<S> {
    /// Creates a store on `storage`. The collection is created on the first write.
    #[must_use]
    pub fn new(storage: Arc<S>) -> Self {
        Self {
            storage,
            write_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// Runs `work` in a task of its own, holding the write lock for its whole
    /// duration. The task is not tied to the caller: it completes (and releases
    /// the lock) even if the caller is dropped. A commit dropped halfway would
    /// leave the storage with an unfinished transaction.
    /// [[ dimpl~ecu-topology-store-spawn-locked-write, Read-modify-write sequences of the store are serialized and cancel-safe, dimpl ]]
    async fn spawn_locked_write<T, F, Fut>(&self, work: F) -> Result<T, TopologyStoreError>
    where
        T: Send + 'static,
        F: FnOnce(Arc<S>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, TopologyStoreError>> + Send + 'static,
    {
        let storage = Arc::clone(&self.storage);
        let write_lock = Arc::clone(&self.write_lock);
        let task = cda_interfaces::spawn_named!("ecu-topology-store-write", async move {
            let _guard = write_lock.lock_owned().await;
            work(storage).await
        });
        task.await.unwrap_or_else(|error| {
            Err(TopologyStoreError::Storage(StorageError::Other(format!(
                "Topology write task failed: {error}"
            ))))
        })
    }
}

/// The entries of the collection: the readable ones and the keys of those that
/// were read but are unusable.
#[derive(Default)]
struct ReadEntries {
    entries: Vec<(String, PersistedGateway)>,
    unreadable: Vec<String>,
}

/// Reads all raw entries. Every read handle is dropped before this returns,
/// so a following write can replace or delete the files (required on Windows).
///
/// An entry that was read but cannot be decoded (or is too large) is
/// returned in `unreadable`, so a prune can remove it. An entry that could
/// not be read at all is only skipped: the failure may be transient.
async fn read_entries<S: Storage>(storage: &S) -> Result<ReadEntries, StorageError> {
    let mut read = ReadEntries::default();
    let collection = match storage.get_collection(&CollectionName::EcuTopology).await {
        Ok(collection) => collection,
        Err(StorageError::CollectionNotFound(_)) => return Ok(read),
        Err(e) => return Err(e),
    };
    for key in collection.list().await? {
        let data = match collection.read(&key).await {
            Ok(data) => data,
            Err(e) => {
                tracing::warn!(key, error = %e, "Skipping unreadable persisted topology entry");
                continue;
            }
        };
        match decode_entry(&key, RandomAccessReader::new(data.as_ref())) {
            Ok(entry) => read.entries.push((key, entry)),
            Err(reason) => {
                tracing::warn!(key, reason, "Skipping unreadable persisted topology entry");
                read.unreadable.push(key);
            }
        }
    }
    Ok(read)
}

/// Applies `op` in its own transaction and commits it. On error the transaction
/// is dropped, which rolls it back.
async fn write<S: Storage>(storage: &S, op: WriteOp) -> Result<(), StorageError> {
    // Created outside the transaction: creating a missing collection runs an
    // implicit transaction of its own.
    let collection = storage
        .get_or_create_collection(&CollectionName::EcuTopology)
        .await?;
    let mut tx = storage.begin_transaction()?;
    for (key, value) in &op {
        match value {
            Some(bytes) => {
                collection
                    .write(&mut tx, key, &mut std::io::Cursor::new(bytes.as_slice()))
                    .await?;
            }
            None => collection.delete(&mut tx, key).await?,
        }
    }
    tx.commit().await
}

fn to_json(gateway: &PersistedGateway) -> Result<Vec<u8>, TopologyStoreError> {
    serde_json::to_vec(gateway).map_err(|e| TopologyStoreError::Serialization(e.to_string()))
}

#[async_trait]
impl<S: Storage + 'static> EcuTopologyStore for StorageEcuTopologyStore<S> {
    async fn load(&self) -> Result<PersistedTopology, TopologyStoreError> {
        let gateways = read_entries(self.storage.as_ref())
            .await?
            .entries
            .into_iter()
            .map(|(_, entry)| entry)
            .collect();
        Ok(PersistedTopology { gateways })
    }

    async fn persist_gateways(
        &self,
        gateways: &[PersistedGateway],
    ) -> Result<(), TopologyStoreError> {
        if gateways.is_empty() {
            return Ok(());
        }
        let op = gateways
            .iter()
            .map(|gateway| {
                Ok((
                    logical_address_hex(gateway.logical_address),
                    Some(to_json(gateway)?),
                ))
            })
            .collect::<Result<WriteOp, TopologyStoreError>>()?;
        self.spawn_locked_write(
            move |storage| async move { Ok(write(storage.as_ref(), op).await?) },
        )
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
        self.spawn_locked_write(move |storage| async move {
            let mut op = WriteOp::new();
            for (key, mut entry) in read_entries(storage.as_ref()).await?.entries {
                let mut updated = false;
                for ecu in &mut entry.ecus {
                    // Compared as stored, with second precision, so a contact within
                    // the same second does not rewrite the entry.
                    if let Some(time) = last_seen.get(&ecu.name.to_lowercase())
                        && ecu.last_seen.map(system_time_to_rfc3339)
                            != Some(system_time_to_rfc3339(*time))
                    {
                        ecu.last_seen = Some(*time);
                        updated = true;
                    }
                }
                if updated {
                    op.insert(key, Some(to_json(&entry)?));
                }
            }
            let count = op.len();
            if count > 0 {
                write(storage.as_ref(), op).await?;
            }
            Ok(count)
        })
        .await
    }

    async fn prune_and_persist_gateways(
        &self,
        keep: &HashMap<u16, HashSet<String>>,
        gateways: &[PersistedGateway],
    ) -> Result<usize, TopologyStoreError> {
        let keep = keep.clone();
        let gateways = gateways.to_vec();
        self.spawn_locked_write(move |storage| async move {
            let mut op = prune_op(storage.as_ref(), &keep).await?;
            let pruned = op.len();
            for gateway in &gateways {
                op.insert(
                    logical_address_hex(gateway.logical_address),
                    Some(to_json(gateway)?),
                );
            }
            if !op.is_empty() {
                write(storage.as_ref(), op).await?;
            }
            Ok(pruned)
        })
        .await
    }
}

/// Builds the write that removes what is not in `keep`: rewrites entries that lose
/// ECUs and deletes entries of gateways that are gone, and unreadable entries,
/// which would otherwise stay in the collection forever.
async fn prune_op<S: Storage>(
    storage: &S,
    keep: &HashMap<u16, HashSet<String>>,
) -> Result<WriteOp, TopologyStoreError> {
    let read = read_entries(storage).await?;
    let mut op: WriteOp = read.unreadable.into_iter().map(|key| (key, None)).collect();
    for (key, mut entry) in read.entries {
        let Some(ecus) = keep.get(&entry.logical_address) else {
            op.insert(key, None);
            continue;
        };
        let before = entry.ecus.len();
        entry
            .ecus
            .retain(|ecu| ecus.contains(&ecu.name.to_lowercase()));
        if entry.ecus.len() != before {
            op.insert(key, Some(to_json(&entry)?));
        }
    }
    Ok(op)
}

/// Decodes a raw entry. Returns the reason as error for logging. A timestamp that
/// cannot be represented makes the entry unreadable, like invalid JSON.
fn decode_entry(key: &str, reader: impl std::io::Read) -> Result<PersistedGateway, String> {
    let entry: PersistedGateway = serde_json::from_reader(std::io::BufReader::new(reader))
        .map_err(|e| format!("Invalid JSON: {e}"))?;
    if !key.eq_ignore_ascii_case(&logical_address_hex(entry.logical_address)) {
        return Err(format!(
            "Key does not match the logical address {:#06x}",
            entry.logical_address
        ));
    }
    Ok(entry)
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicBool, Ordering},
        time::Duration,
    };

    use cda_interfaces::{
        HashMapExtensions as _,
        storage_api::Transaction,
        topology::{PersistedEcu, PersistedEcuState, PersistedVariant},
    };
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
                .get_or_create_collection(&CollectionName::EcuTopology)
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
            .checked_add(Duration::from_secs(secs))
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

    /// [[ test~ecu-topology-store-persist-gateways-keeps-other-entries, A write persists its gateways and keeps all other entries, test ]]
    #[tokio::test]
    async fn persist_gateways_keeps_other_entries() {
        let fixture = Fixture::new();
        fixture
            .store
            .persist_gateways(&[gateway(0x1000, "FLXC1000"), gateway(0x2000, "FSNR2000")])
            .await
            .unwrap();

        let mut replaced = gateway(0x1000, "FLXC1000");
        replaced.network_address = Some("10.2.1.99".to_owned());
        fixture
            .store
            .persist_gateways(&[replaced.clone()])
            .await
            .unwrap();

        assert_eq!(
            sorted(fixture.store.load().await.unwrap()),
            vec![replaced, gateway(0x2000, "FSNR2000")]
        );
    }

    /// The on-disk JSON of an entry stays stable, so persisted topologies remain
    /// readable by later releases.
    #[test]
    fn stored_json_is_stable() {
        let json = r#"{"name":"gw_1000","logical_address":4096,"network_address":"10.2.1.10","doip_protocol_version":3,"ecus":[{"name":"FLXC1000","logical_address":4096,"variant":{"name":"FLXC1000_App","is_base_variant":false,"is_fallback":false},"state":"Online","last_seen":"2023-11-14T22:13:20Z"}]}"#;
        let gateway = gateway(0x1000, "FLXC1000");

        assert_eq!(String::from_utf8(to_json(&gateway).unwrap()).unwrap(), json);
        assert_eq!(decode_entry("0x1000", json.as_bytes()).unwrap(), gateway);
    }

    /// [[ test~ecu-topology-store-unreadable-entries-are-skipped, An unreadable entry is skipped, test ]]
    #[tokio::test]
    async fn unreadable_entries_are_skipped() {
        let fixture = Fixture::new();
        fixture
            .store
            .persist_gateways(&[gateway(0x1000, "FLXC1000")])
            .await
            .unwrap();
        fixture.write_raw("0x2000", b"not json").await;
        fixture
            .write_raw(
                "0x3000",
                // Valid JSON without the required logical address.
                br#"{"name":"gw","ecus":[]}"#,
            )
            .await;
        // Key and logical address disagree.
        fixture
            .write_raw(
                "0x4000",
                br#"{"name":"gw","logical_address":4096,"ecus":[]}"#,
            )
            .await;

        assert_eq!(
            fixture.store.load().await.unwrap().gateways,
            vec![gateway(0x1000, "FLXC1000")]
        );
    }

    /// Pruning also removes the entries that cannot be read.
    #[tokio::test]
    async fn prune_removes_unreadable_entries() {
        let fixture = Fixture::new();
        fixture
            .store
            .persist_gateways(&[gateway(0x1000, "FLXC1000")])
            .await
            .unwrap();
        fixture.write_raw("0x2000", b"not json").await;
        fixture
            .write_raw(
                "0x3000",
                // Valid JSON without the required logical address.
                br#"{"name":"gw","ecus":[]}"#,
            )
            .await;

        let mut keep: HashMap<u16, HashSet<String>> = HashMap::new();
        keep.insert(0x1000, ["flxc1000".to_owned()].into_iter().collect());
        assert_eq!(
            fixture
                .store
                .prune_and_persist_gateways(&keep, &[])
                .await
                .unwrap(),
            2
        );

        let collection = fixture
            .storage
            .get_collection(&CollectionName::EcuTopology)
            .await
            .unwrap();
        assert_eq!(collection.list().await.unwrap(), vec!["0x1000".to_owned()]);
        assert_eq!(
            fixture
                .store
                .prune_and_persist_gateways(&keep, &[])
                .await
                .unwrap(),
            0
        );
    }

    /// Storage that holds the next `get_or_create_collection` until released: the
    /// step of a write between its read and its commit.
    struct HoldingStorage {
        inner: LocalStorage,
        hold_next: AtomicBool,
        entered: tokio::sync::Notify,
        gate: tokio::sync::watch::Sender<bool>,
    }

    impl HoldingStorage {
        fn new(dir: &TempDir) -> Arc<Self> {
            Arc::new(Self {
                inner: LocalStorage::new(dir.path()).expect("storage"),
                hold_next: AtomicBool::new(false),
                entered: tokio::sync::Notify::new(),
                gate: tokio::sync::watch::Sender::new(true),
            })
        }

        fn hold_next_write(&self) {
            self.gate.send_replace(false);
            self.hold_next.store(true, Ordering::SeqCst);
        }

        fn release(&self) {
            self.gate.send_replace(true);
        }

        async fn wait_entered(&self) {
            tokio::time::timeout(Duration::from_secs(5), self.entered.notified())
                .await
                .expect("the write did not reach the held step");
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
                self.entered.notify_one();
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

    /// [[ test~ecu-topology-store-cancelled-call-keeps-lock, A write whose caller is dropped keeps the lock until its commit, test ]]
    #[tokio::test]
    async fn dropped_write_keeps_the_lock_until_it_committed() {
        let dir = tempfile::tempdir().expect("storage dir");
        let storage = HoldingStorage::new(&dir);
        let store = Arc::new(StorageEcuTopologyStore::new(Arc::clone(&storage)));
        store
            .persist_gateways(&[gateway(0x1000, "FLXC1000")])
            .await
            .unwrap();

        storage.hold_next_write();
        let first = {
            let store = Arc::clone(&store);
            tokio::spawn(
                async move { store.persist_gateways(&[gateway(0x2000, "FSNR2000")]).await },
            )
        };
        storage.wait_entered().await;
        first.abort();
        let second = {
            let store = Arc::clone(&store);
            tokio::spawn(
                async move { store.persist_gateways(&[gateway(0x3000, "FLXC3000")]).await },
            )
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
            .persist_gateways(&[
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
        assert_eq!(
            fixture
                .store
                .prune_and_persist_gateways(&keep, &[])
                .await
                .unwrap(),
            2
        );

        assert_eq!(
            sorted(fixture.store.load().await.unwrap()),
            vec![gateway(0x1000, "FLXC1000"), gateway(0x2000, "FSNR2000")]
        );
        assert_eq!(
            fixture
                .store
                .prune_and_persist_gateways(&keep, &[])
                .await
                .unwrap(),
            0,
            "nothing left to prune"
        );
    }

    /// Pruning and persisting in one write: a pruned entry that is persisted
    /// again ends up with the persisted content.
    #[tokio::test]
    async fn prune_and_persist_writes_both() {
        let fixture = Fixture::new();
        let mut two_ecus = gateway(0x1000, "FLXC1000");
        let mut removed_ecu = two_ecus.ecus.first().unwrap().clone();
        removed_ecu.name = "REMOVED".to_owned();
        two_ecus.ecus.push(removed_ecu);
        fixture
            .store
            .persist_gateways(&[two_ecus, gateway(0x7777, "GONE")])
            .await
            .unwrap();

        let mut keep: HashMap<u16, HashSet<String>> = HashMap::new();
        keep.insert(0x1000, ["flxc1000".to_owned()].into_iter().collect());
        keep.insert(0x2000, ["fsnr2000".to_owned()].into_iter().collect());
        let mut moved = gateway(0x1000, "FLXC1000");
        moved.network_address = Some("10.2.1.99".to_owned());
        assert_eq!(
            fixture
                .store
                .prune_and_persist_gateways(&keep, &[moved.clone(), gateway(0x2000, "FSNR2000")])
                .await
                .unwrap(),
            2,
            "the rewritten 0x1000 and the deleted 0x7777"
        );

        assert_eq!(
            sorted(fixture.store.load().await.unwrap()),
            vec![moved, gateway(0x2000, "FSNR2000")]
        );
    }
}
