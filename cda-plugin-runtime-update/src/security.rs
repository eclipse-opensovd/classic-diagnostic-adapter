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

use std::{collections::HashSet, sync::Arc};

use async_trait::async_trait;
use cda_interfaces::{
    DynamicPlugin,
    runtime_update_api::{
        LockStateProvider, RuntimeFileInspector, RuntimeUpdateError, RuntimeUpdateSecurityPlugin,
        UpdateCollections, VerificationError,
    },
    storage_api::{Collection, DirectFileAccess},
};

/// Default implementation of the runtime update security handler.
///
/// Validates vehicle lock ownership, detects lock conflicts, and verifies file
/// integrity through the injected [`RuntimeFileInspector`].
type CallerIdentity = dyn Fn(&DynamicPlugin) -> Option<String> + Send + Sync;

pub struct DefaultUpdateSecurityHandler<L: LockStateProvider> {
    inspector: Arc<dyn RuntimeFileInspector>,
    caller_identity: Arc<CallerIdentity>,
    _lock: std::marker::PhantomData<L>,
}

impl<L: LockStateProvider> DefaultUpdateSecurityHandler<L> {
    /// Creates a security handler with application-owned caller identity interpretation.
    #[must_use]
    pub fn new(
        inspector: Arc<dyn RuntimeFileInspector>,
        caller_identity: Arc<CallerIdentity>,
    ) -> Self {
        Self {
            inspector,
            caller_identity,
            _lock: std::marker::PhantomData,
        }
    }

    async fn check_vehicle_lock_owner(
        &self,
        security: &DynamicPlugin,
        lock_state_provider: &L,
    ) -> Result<(), RuntimeUpdateError> {
        let caller = (self.caller_identity)(security).ok_or_else(|| {
            RuntimeUpdateError::NoLock("Caller cannot be authorized for this operation".to_owned())
        })?;
        let owner = lock_state_provider
            .vehicle_lock_owner_id()
            .await
            .ok_or_else(|| RuntimeUpdateError::NoLock("Vehicle lock is missing".to_owned()))?;
        if owner != caller {
            return Err(RuntimeUpdateError::NoLock(
                "Vehicle lock is owned by another caller".to_owned(),
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl<L: LockStateProvider, C: Collection + DirectFileAccess + Send + Sync + 'static>
    RuntimeUpdateSecurityPlugin<L, C> for DefaultUpdateSecurityHandler<L>
{
    async fn check_execution_admission(
        &self,
        security: &DynamicPlugin,
        lock_state_provider: &L,
    ) -> Result<(), RuntimeUpdateError> {
        self.check_vehicle_lock_owner(security, lock_state_provider)
            .await
    }

    async fn check_execution_allowed(
        &self,
        security: &DynamicPlugin,
        lock_state_provider: &L,
        collections: &UpdateCollections<C>,
    ) -> Result<(), RuntimeUpdateError> {
        self.check_vehicle_lock_owner(security, lock_state_provider)
            .await?;
        if lock_state_provider.has_non_vehicle_locks().await {
            return Err(RuntimeUpdateError::LockConflict(
                "Non-vehicle locks are held, cannot apply update".to_owned(),
            ));
        }
        // Example, validate that no ECUs are added or deleted
        if let (Some(pending), Some(current)) = (&collections.pending_mdd, &collections.current_mdd)
        {
            let pending_ecus = database_ecu_names(pending.as_ref(), &*self.inspector).await?;
            let current_ecus = database_ecu_names(current.as_ref(), &*self.inspector).await?;

            if pending_ecus != current_ecus {
                tracing::warn!(
                    "MDD ECU set mismatch: pending {pending_ecus:?} vs current {current_ecus:?}"
                );
            }
        }
        Ok(())
    }

    async fn check_file_integrity(&self, path: &std::path::Path) -> Result<(), VerificationError> {
        self.inspector.validate(path)
    }
}

async fn database_ecu_names<C: Collection + DirectFileAccess>(
    col: &C,
    inspector: &dyn RuntimeFileInspector,
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
            inspector.ecu_name(&path)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use async_trait::async_trait;
    use cda_interfaces::{
        runtime_update_api::{RuntimeUpdateError, RuntimeUpdateSecurityPlugin, UpdateCollections},
        storage_api::{CollectionName, Storage as _},
    };
    use cda_storage::{LocalCollection, LocalStorage};

    use super::*;

    struct MockLockProvider {
        owner: Option<String>,
        has_ecu_conflicts: bool,
        has_fg_conflicts: bool,
    }

    struct ChangingLockProvider {
        reads: AtomicUsize,
    }

    #[async_trait]
    impl LockStateProvider for ChangingLockProvider {
        async fn vehicle_lock_owner_id(&self) -> Option<String> {
            let read = self.reads.fetch_add(1, Ordering::SeqCst);
            Some(if read == 0 { "caller" } else { "other" }.to_owned())
        }

        async fn has_non_vehicle_locks(&self) -> bool {
            false
        }
    }

    #[async_trait]
    impl LockStateProvider for MockLockProvider {
        async fn vehicle_lock_owner_id(&self) -> Option<String> {
            self.owner.clone()
        }

        async fn has_non_vehicle_locks(&self) -> bool {
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

    async fn check_file_integrity(
        handler: &DefaultUpdateSecurityHandler<MockLockProvider>,
        path: &std::path::Path,
    ) -> Result<(), VerificationError> {
        <DefaultUpdateSecurityHandler<_> as RuntimeUpdateSecurityPlugin<
            MockLockProvider,
            LocalCollection,
        >>::check_file_integrity(handler, path)
        .await
    }

    fn make_mdd_bytes(ecu_name: &str) -> Vec<u8> {
        let magic: &[u8] = &[
            0x4D, 0x44, 0x44, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x20, 0x30, 0x20,
            0x20, 0x20, 0x20, 0x20, 0x20, 0x00,
        ];
        let name_bytes = ecu_name.as_bytes();
        let mut bytes = magic.to_vec();
        bytes.push(0x1A);
        bytes.push(u8::try_from(name_bytes.len()).unwrap());
        bytes.extend_from_slice(name_bytes);
        bytes
    }

    async fn write_mdd_to_collection(
        storage: &LocalStorage,
        name: &CollectionName,
        key: &str,
        ecu_name: &str,
    ) {
        let col = storage.get_or_create_collection(name).await.unwrap();
        let mut tx = storage.begin_transaction().unwrap();
        let bytes = make_mdd_bytes(ecu_name);
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
        }
    }

    fn make_handler(
        owner: Option<&str>,
        has_ecu_conflicts: bool,
        has_fg_conflicts: bool,
    ) -> (
        DefaultUpdateSecurityHandler<MockLockProvider>,
        MockLockProvider,
    ) {
        let lock_provider = make_lock_provider(owner, has_ecu_conflicts, has_fg_conflicts);
        let handler = DefaultUpdateSecurityHandler::new(
            crate::test_utils::test_inspector(),
            Arc::new(|security| security.downcast_ref::<String>().cloned()),
        );
        (handler, lock_provider)
    }

    fn caller(identity: &str) -> DynamicPlugin {
        Box::new(identity.to_owned())
    }

    #[tokio::test]
    async fn check_execution_allowed_returns_no_lock_when_no_vehicle_lock_held() {
        let (handler, lock_provider) = make_handler(None, false, false);
        let result = handler
            .check_execution_allowed(
                &caller("user-a"),
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
                &caller("user-b"),
                &lock_provider,
                &UpdateCollections::<LocalCollection>::default(),
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn check_execution_allowed_returns_lock_conflict_on_ecu_conflicts() {
        let (handler, lock_provider) = make_handler(Some("user-a"), true, false);
        let result = handler
            .check_execution_allowed(
                &caller("user-a"),
                &lock_provider,
                &UpdateCollections::<LocalCollection>::default(),
            )
            .await;
        assert!(matches!(result, Err(RuntimeUpdateError::LockConflict(_))));
    }

    #[tokio::test]
    async fn check_execution_allowed_returns_lock_conflict_on_fg_conflicts() {
        let (handler, lock_provider) = make_handler(Some("user-a"), false, true);
        let result = handler
            .check_execution_allowed(
                &caller("user-a"),
                &lock_provider,
                &UpdateCollections::<LocalCollection>::default(),
            )
            .await;
        assert!(
            matches!(result, Err(RuntimeUpdateError::LockConflict(_))),
            "Expected RuntimeUpdateError::LockConflict, got {result:?}"
        );
    }

    #[tokio::test]
    async fn check_execution_allowed_succeeds_when_owner_matches_and_no_conflicts() {
        let (handler, lock_provider) = make_handler(Some("user-a"), false, false);
        assert!(
            handler
                .check_execution_allowed(
                    &caller("user-a"),
                    &lock_provider,
                    &UpdateCollections::<LocalCollection>::default()
                )
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn execution_admission_rejects_wrong_owner() {
        let (handler, lock_provider) = make_handler(Some("owner"), false, false);
        let result =
            <DefaultUpdateSecurityHandler<_> as RuntimeUpdateSecurityPlugin<
                MockLockProvider,
                LocalCollection,
            >>::check_execution_admission(&handler, &caller("other"), &lock_provider)
            .await;
        assert!(matches!(result, Err(RuntimeUpdateError::NoLock(_))));
    }

    #[tokio::test]
    async fn execution_admission_rejects_foreign_context() {
        let (handler, lock_provider) = make_handler(Some("owner"), false, false);
        let foreign = Box::new(7u8) as DynamicPlugin;
        let result = <DefaultUpdateSecurityHandler<_> as RuntimeUpdateSecurityPlugin<
            MockLockProvider,
            LocalCollection,
        >>::check_execution_admission(&handler, &foreign, &lock_provider)
        .await;
        assert!(matches!(result, Err(RuntimeUpdateError::NoLock(_))));
    }

    #[tokio::test]
    async fn authoritative_check_rejects_vehicle_owner_change() {
        let provider = ChangingLockProvider {
            reads: AtomicUsize::new(0),
        };
        let handler = DefaultUpdateSecurityHandler::<ChangingLockProvider>::new(
            crate::test_utils::test_inspector(),
            Arc::new(|security| security.downcast_ref::<String>().cloned()),
        );
        let security = caller("caller");
        <DefaultUpdateSecurityHandler<_> as RuntimeUpdateSecurityPlugin<
            ChangingLockProvider,
            LocalCollection,
        >>::check_execution_admission(&handler, &security, &provider)
        .await
        .unwrap();
        let result = <DefaultUpdateSecurityHandler<_> as RuntimeUpdateSecurityPlugin<
            ChangingLockProvider,
            LocalCollection,
        >>::check_execution_allowed(
            &handler,
            &security,
            &provider,
            &UpdateCollections::default(),
        )
        .await;
        assert!(matches!(result, Err(RuntimeUpdateError::NoLock(_))));
    }

    #[tokio::test]
    async fn check_file_integrity_mdd_fails_on_nonexistent_file() {
        let (handler, _) = make_handler(Some("user-a"), false, false);
        let path = PathBuf::from("/nonexistent/test.mdd");
        let result = check_file_integrity(&handler, &path).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn check_file_integrity_mdd_fails_on_invalid_data() {
        let (handler, _) = make_handler(Some("user-a"), false, false);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.mdd");
        std::fs::write(&path, b"not a valid mdd file").unwrap();
        let result = check_file_integrity(&handler, &path).await;
        assert!(result.is_err());
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
            .check_execution_allowed(&caller("user"), &lock_provider, &collections)
            .await;
        assert!(result.is_ok());
    }
}
