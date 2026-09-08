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

use std::collections::HashSet;

use async_trait::async_trait;
use cda_interfaces::{
    runtime_update_api::{
        LockStateProvider, RuntimeUpdateError, RuntimeUpdatePolicy, UpdateCollections,
    },
    storage_api::{Collection, DirectFileAccess},
};

/// Default [`RuntimeUpdatePolicy`]: a vehicle must be claimed before its
/// databases are swapped.
pub struct DefaultUpdatePolicy<L: LockStateProvider> {
    _lock: std::marker::PhantomData<L>,
}

impl<L: LockStateProvider> DefaultUpdatePolicy<L> {
    /// Creates a policy.
    #[must_use]
    pub fn new() -> Self {
        Self {
            _lock: std::marker::PhantomData,
        }
    }
}

impl<L: LockStateProvider> Default for DefaultUpdatePolicy<L> {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl<L: LockStateProvider, C: Collection + DirectFileAccess + Send + Sync + 'static>
    RuntimeUpdatePolicy<L, C> for DefaultUpdatePolicy<L>
{
    /// Default policy: a vehicle must be claimed before its databases are
    /// swapped, so an unheld vehicle lock refuses the execution. This is not
    /// ownership enforcement - the caller is not visible here. Rejecting held
    /// ECU and functional-group locks is framework-owned and happens in
    /// `validate_execution_preconditions`, not here. Conflicting communication
    /// activity is already excluded by the coordinator's runtime-update block.
    async fn check_execution_allowed(
        &self,
        lock_state_provider: &L,
        collections: &UpdateCollections<C>,
    ) -> Result<(), RuntimeUpdateError> {
        lock_state_provider
            .vehicle_lock_owner_id()
            .await
            .ok_or_else(|| RuntimeUpdateError::NoLock("No vehicle lock owned".to_owned()))?;
        // Example, validate that no ECUs are added or deleted. This only warns:
        // the incoming databases were already checked for readability by the
        // framework, so nothing here gates the execution.
        if let (Some(pending), Some(current)) = (&collections.pending_mdd, &collections.current_mdd)
        {
            let pending_ecus = database_ecu_names(pending.as_ref()).await?;
            let current_ecus = database_ecu_names(current.as_ref()).await?;

            if pending_ecus != current_ecus {
                tracing::warn!(
                    "MDD ECU set mismatch: pending {pending_ecus:?} vs current {current_ecus:?}"
                );
            }
        }
        Ok(())
    }
}

async fn database_ecu_names<C: Collection + DirectFileAccess>(
    col: &C,
) -> Result<HashSet<String>, RuntimeUpdateError> {
    let files = col
        .list()
        .await
        .map_err(|e| RuntimeUpdateError::ValidationFailed(e.to_string()))?;
    files
        .iter()
        .map(|key| {
            let path = col
                .file_path(key)
                .map_err(|e| RuntimeUpdateError::ValidationFailed(e.to_string()))?;
            let path = path.to_str().ok_or_else(|| {
                RuntimeUpdateError::ValidationFailed("MDD path is not valid UTF-8".to_owned())
            })?;
            cda_database::mmap_and_decode_mdd(path)
                .map(|mdd| mdd.ecu_name)
                .map_err(|error| RuntimeUpdateError::ValidationFailed(error.to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use cda_interfaces::{
        runtime_update_api::{RuntimeUpdateError, RuntimeUpdatePolicy, UpdateCollections},
        storage_api::{CollectionName, Storage as _},
    };
    use cda_storage::{LocalCollection, LocalStorage};

    use super::*;

    struct MockLockProvider {
        owner: Option<String>,
        has_ecu_conflicts: bool,
        has_fg_conflicts: bool,
    }

    #[async_trait]
    impl LockStateProvider for MockLockProvider {
        async fn vehicle_lock_owner_id(&self) -> Option<String> {
            self.owner.clone()
        }

        async fn has_locks(&self) -> bool {
            self.has_ecu_conflicts || self.has_fg_conflicts
        }
    }

    fn make_lock_provider(
        owner: Option<&str>,
        has_ecu_conflicts: bool,
        has_fg_conflicts: bool,
    ) -> MockLockProvider {
        MockLockProvider {
            owner: owner.map(ToOwned::to_owned),
            has_ecu_conflicts,
            has_fg_conflicts,
        }
    }

    async fn write_mdd_to_collection(
        storage: &LocalStorage,
        name: &CollectionName,
        key: &str,
        ecu_name: &str,
    ) {
        let col = storage.get_or_create_collection(name).await.unwrap();
        let mut tx = storage.begin_transaction().unwrap();
        let bytes = crate::test_utils::readable_mdd_bytes(ecu_name);
        let mut cursor: &[u8] = &bytes;
        col.write(&mut tx, key, &mut cursor).await.unwrap();
        tx.commit().await.unwrap();
    }

    async fn make_collections(storage: &LocalStorage) -> UpdateCollections<LocalCollection> {
        UpdateCollections {
            pending_mdd: storage
                .get_collection(&CollectionName::DiagnosticDatabaseNextUpdate)
                .await
                .ok(),
            current_mdd: storage
                .get_collection(&CollectionName::DiagnosticDatabase)
                .await
                .ok(),
            backup_mdd: storage
                .get_collection(&CollectionName::DiagnosticDatabaseBackup)
                .await
                .ok(),
        }
    }

    fn make_handler(
        owner: Option<&str>,
        has_ecu_conflicts: bool,
        has_fg_conflicts: bool,
    ) -> (DefaultUpdatePolicy<MockLockProvider>, MockLockProvider) {
        let lock_provider = make_lock_provider(owner, has_ecu_conflicts, has_fg_conflicts);
        let handler = DefaultUpdatePolicy::new();
        (handler, lock_provider)
    }

    #[tokio::test]
    async fn check_execution_allowed_returns_no_lock_when_no_vehicle_lock_held() {
        let (handler, lock_provider) = make_handler(None, false, false);
        let result = handler
            .check_execution_allowed(
                &lock_provider,
                &UpdateCollections::<LocalCollection>::default(),
            )
            .await;
        assert!(matches!(result, Err(RuntimeUpdateError::NoLock(_))));
    }

    #[tokio::test]
    async fn check_execution_allowed_succeeds_when_vehicle_lock_is_held() {
        let (handler, lock_provider) = make_handler(Some("user-b"), false, false);
        let result = handler
            .check_execution_allowed(
                &lock_provider,
                &UpdateCollections::<LocalCollection>::default(),
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn check_execution_allowed_succeeds_when_no_ecu_or_functional_group_locks_are_held() {
        let (handler, lock_provider) = make_handler(Some("user-a"), false, false);
        assert!(
            handler
                .check_execution_allowed(
                    &lock_provider,
                    &UpdateCollections::<LocalCollection>::default()
                )
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn check_execution_allowed_succeeds_when_pending_and_current_mdd_ecu_names_match() {
        let (handler, lock_provider) = make_handler(Some("user"), false, false);
        let dir = tempfile::tempdir().unwrap();
        let storage = LocalStorage::new(dir.path()).unwrap();

        write_mdd_to_collection(
            &storage,
            &CollectionName::DiagnosticDatabaseNextUpdate,
            "ecu.mdd",
            "TestEcu",
        )
        .await;
        write_mdd_to_collection(
            &storage,
            &CollectionName::DiagnosticDatabase,
            "ecu.mdd",
            "TestEcu",
        )
        .await;

        let collections = make_collections(&storage).await;
        let result = handler
            .check_execution_allowed(&lock_provider, &collections)
            .await;
        assert!(result.is_ok());
    }
}
