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
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

/// Version of the stored JSON document. Entries with another version are skipped.
pub const STORED_VERSION: u32 = 1;

/// Upper bound for a single entry. Anything larger is not a topology entry.
const MAX_ENTRY_SIZE: u64 = 1024 * 1024;

const TRANSACTION_BUSY_RETRIES: usize = 5;
const TRANSACTION_BUSY_MIN_DELAY: Duration = Duration::from_millis(100);
const TRANSACTION_BUSY_MAX_DELAY: Duration = Duration::from_secs(1);

/// [`EcuTopologyStore`] backed by a [`Storage`] collection.
/// [[ dimpl~ecu-topology-store, ECU topology store on the storage API, dimpl ]]
pub struct StorageEcuTopologyStore<S: Storage> {
    storage: Arc<S>,
}

impl<S: Storage> StorageEcuTopologyStore<S> {
    /// Creates a store on `storage`. The collection is created on the first write.
    #[must_use]
    pub fn new(storage: Arc<S>) -> Self {
        Self { storage }
    }

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
    /// Write the encoded entries, replacing existing ones with the same key.
    Put(Vec<(String, Vec<u8>)>),
    /// Delete all entries.
    DeleteAll,
    /// Rewrite and delete entries in one transaction.
    Prune {
        puts: Vec<(String, Vec<u8>)>,
        deletes: Vec<String>,
    },
}

async fn apply(
    collection: &impl Collection,
    tx: &mut Transaction,
    op: &WriteOp,
) -> Result<(), StorageError> {
    match op {
        WriteOp::Put(entries) => {
            for (key, bytes) in entries {
                collection
                    .write(tx, key, &mut std::io::Cursor::new(bytes.as_slice()))
                    .await?;
            }
            Ok(())
        }
        WriteOp::DeleteAll => collection.delete_all(tx).await,
        WriteOp::Prune { puts, deletes } => {
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
        let encoded = gateways
            .iter()
            .map(|gateway| {
                serde_json::to_vec(&StoredGateway::from(gateway))
                    .map(|bytes| (gateway_key(gateway.logical_address), bytes))
                    .map_err(|e| TopologyStoreError::Serialization(e.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        self.write(&WriteOp::Put(encoded)).await?;
        Ok(())
    }

    async fn merge_last_seen(
        &self,
        last_seen: &HashMap<String, SystemTime>,
    ) -> Result<usize, TopologyStoreError> {
        if last_seen.is_empty() {
            return Ok(0);
        }
        let mut changed = Vec::new();
        for (key, mut entry) in self.read_entries().await? {
            let mut updated = false;
            for ecu in &mut entry.ecus {
                if let Some(time) = last_seen.get(&ecu.name.to_lowercase()) {
                    let formatted = Some(format_time(*time));
                    if ecu.last_seen != formatted {
                        ecu.last_seen = formatted;
                        updated = true;
                    }
                }
            }
            if updated {
                let bytes = serde_json::to_vec(&entry)
                    .map_err(|e| TopologyStoreError::Serialization(e.to_string()))?;
                changed.push((key, bytes));
            }
        }
        if changed.is_empty() {
            return Ok(0);
        }

        let count = changed.len();
        self.write(&WriteOp::Put(changed)).await?;
        Ok(count)
    }

    async fn prune(
        &self,
        keep: &HashMap<u16, HashSet<String>>,
    ) -> Result<usize, TopologyStoreError> {
        let mut puts = Vec::new();
        let mut deletes = Vec::new();
        for (key, mut entry) in self.read_entries().await? {
            let Some(ecus) = keep.get(&entry.logical_address) else {
                deletes.push(key);
                continue;
            };
            let before = entry.ecus.len();
            entry
                .ecus
                .retain(|ecu| ecus.contains(&ecu.name.to_lowercase()));
            if entry.ecus.len() != before {
                let bytes = serde_json::to_vec(&entry)
                    .map_err(|e| TopologyStoreError::Serialization(e.to_string()))?;
                puts.push((key, bytes));
            }
        }
        let count = puts.len().saturating_add(deletes.len());
        if count == 0 {
            return Ok(0);
        }
        self.write(&WriteOp::Prune { puts, deletes }).await?;
        Ok(count)
    }

    async fn clear(&self) -> Result<(), TopologyStoreError> {
        let Some(collection) = self.existing_collection().await? else {
            return Ok(());
        };
        if collection.is_empty().await? {
            return Ok(());
        }
        self.write(&WriteOp::DeleteAll).await?;
        Ok(())
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
    Ok(entry)
}

fn format_time(time: SystemTime) -> String {
    DateTime::<Utc>::from(time).to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn parse_time(value: &str) -> Option<SystemTime> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|time| SystemTime::from(time.with_timezone(&Utc)))
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
                    last_seen: ecu.last_seen.map(format_time),
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
    use cda_interfaces::{HashMapExtensions as _, topology::DisabledTopologyStore};
    use cda_storage::LocalStorage;
    use tempfile::TempDir;

    use super::*;

    struct Fixture {
        storage: Arc<LocalStorage>,
        store: StorageEcuTopologyStore<LocalStorage>,
        dir: TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("storage dir");
            let storage = Arc::new(LocalStorage::new(dir.path()).expect("storage"));
            Self {
                store: StorageEcuTopologyStore::new(Arc::clone(&storage)),
                storage,
                dir,
            }
        }

        async fn write_raw(&self, key: &str, bytes: &[u8]) {
            let collection = self
                .storage
                .get_or_create_collection(
                    &StorageEcuTopologyStore::<LocalStorage>::collection_name(),
                )
                .await
                .unwrap();
            let mut tx = self.storage.begin_transaction().unwrap();
            collection
                .write(&mut tx, key, &mut std::io::Cursor::new(bytes))
                .await
                .unwrap();
            tx.commit().await.unwrap();
        }

        fn collection_dir_exists(&self) -> bool {
            self.dir
                .path()
                .join("collections")
                .join(ECU_TOPOLOGY_COLLECTION)
                .exists()
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

    /// [[ test~ecu-topology-store-round-trip, Persisted topology is stored and loaded unchanged, test ]]
    #[tokio::test]
    async fn round_trip() {
        let fixture = Fixture::new();
        assert!(fixture.store.load().await.unwrap().is_empty());

        let mut not_found = gateway(0x2000, "FSNR2000");
        not_found.network_address = None;
        not_found.ecus.clear();
        let gateways = vec![gateway(0x1000, "FLXC1000"), not_found];
        fixture.store.upsert(&gateways).await.unwrap();

        assert_eq!(sorted(fixture.store.load().await.unwrap()), gateways);
    }

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

    /// Clearing directly after loading must work on Windows too, where an open
    /// read handle would block the deletion.
    #[tokio::test]
    async fn load_then_clear() {
        let fixture = Fixture::new();
        fixture.store.clear().await.unwrap();
        fixture
            .store
            .upsert(&[gateway(0x1000, "FLXC1000")])
            .await
            .unwrap();
        assert!(!fixture.store.load().await.unwrap().is_empty());

        fixture.store.clear().await.unwrap();
        assert!(fixture.store.load().await.unwrap().is_empty());
    }

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
    async fn merge_last_seen_updates_existing_entries_only() {
        let fixture = Fixture::new();
        fixture
            .store
            .upsert(&[gateway(0x1000, "FLXC1000"), gateway(0x2000, "FSNR2000")])
            .await
            .unwrap();

        let mut last_seen = HashMap::new();
        // Older than the stored value: the newest write wins regardless of order.
        last_seen.insert("flxc1000".to_owned(), time(1_600_000_000));
        last_seen.insert("unknown".to_owned(), time(1_800_000_000));
        assert_eq!(fixture.store.merge_last_seen(&last_seen).await.unwrap(), 1);

        let gateways = sorted(fixture.store.load().await.unwrap());
        assert_eq!(
            gateways
                .first()
                .and_then(|g| g.ecus.first())
                .and_then(|e| e.last_seen),
            Some(time(1_600_000_000))
        );
        assert_eq!(gateways.get(1), Some(&gateway(0x2000, "FSNR2000")));
    }

    #[tokio::test]
    async fn merge_last_seen_never_creates_entries() {
        let fixture = Fixture::new();
        let mut last_seen = HashMap::new();
        last_seen.insert("flxc1000".to_owned(), time(1_700_000_000));
        assert_eq!(fixture.store.merge_last_seen(&last_seen).await.unwrap(), 0);
        assert!(fixture.store.load().await.unwrap().is_empty());
        assert!(!fixture.collection_dir_exists());
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

    #[tokio::test]
    async fn disabled_store_never_touches_storage() {
        let fixture = Fixture::new();
        let store = DisabledTopologyStore;
        store.upsert(&[gateway(0x1000, "FLXC1000")]).await.unwrap();
        store.clear().await.unwrap();
        assert!(store.load().await.unwrap().is_empty());
        assert!(!store.is_enabled());
        assert!(!fixture.collection_dir_exists());
    }

    #[test]
    fn stored_json_is_readable() {
        let json = serde_json::to_value(StoredGateway::from(&gateway(0x1000, "FLXC1000"))).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "version": 1,
                "name": "gw_1000",
                "logical_address": 4096,
                "network_address": "10.2.1.10",
                "doip_protocol_version": 3,
                "ecus": [{
                    "name": "FLXC1000",
                    "logical_address": 4096,
                    "variant": {
                        "name": "FLXC1000_App",
                        "is_base_variant": false,
                        "is_fallback": false
                    },
                    "state": "Online",
                    "last_seen": "2023-11-14T22:13:20.123Z"
                }]
            })
        );
    }
}
