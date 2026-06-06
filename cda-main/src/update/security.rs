/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

use std::{collections::HashSet, sync::Arc};

use async_trait::async_trait;
use cda_database::mmap_and_decode_mdd;
use cda_interfaces::storage_api::{Collection, DirectFileAccess};
use cda_plugin_runtime_update::{
    ActiveOperationsGuard, LockStateProvider, RuntimeFilesUpdateSecurityHandler,
    RuntimeUpdateError, UpdateCollections, UpdateFileType, VerificationError,
};

pub struct UpdateSecurityHandler<L: LockStateProvider, G: ActiveOperationsGuard> {
    guard: G,
    _lock_provider: std::marker::PhantomData<L>,
}

impl<L: LockStateProvider, G: ActiveOperationsGuard> UpdateSecurityHandler<L, G> {
    pub fn new(_lock_provider: Arc<L>, guard: G) -> Self {
        Self {
            guard,
            _lock_provider: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<
    L: LockStateProvider,
    G: ActiveOperationsGuard,
    C: Collection + DirectFileAccess + Send + Sync + 'static,
> RuntimeFilesUpdateSecurityHandler<L, C> for UpdateSecurityHandler<L, G>
{
    /// Validates that the caller is allowed to start an execution (apply/rollback/cleanup).
    ///
    /// Ensures the caller owns the vehicle lock, no ECU or functional-group locks
    /// are held, and no active operations are in progress.
    async fn check_apply_allowed(
        &self,
        lock_state_provider: &L,
        collections: &UpdateCollections<C>,
    ) -> Result<(), RuntimeUpdateError> {
        lock_state_provider
            .is_vehicle_lock_owned()
            .await
            .ok_or(RuntimeUpdateError::NoLock(
                "No vehicle lock owned".to_owned(),
            ))?;
        if lock_state_provider.has_non_vehicle_locks().await {
            return Err(RuntimeUpdateError::LockConflict(
                "Non-vehicle locks are held, cannot apply update".to_owned(),
            ));
        }
        if self.guard.has_active_operations() {
            return Err(RuntimeUpdateError::OperationsInProgress(
                "Another operation operation is running already (i.e. flash transfer)".to_owned(),
            ));
        }

        // Example, validate that no ECUs are added or deleted
        if let (Some(pending), Some(current)) = (&collections.pending_mdd, &collections.current_mdd)
        {
            let pending_ecus = mdd_ecu_names(pending.as_ref()).await?;
            let current_ecus = mdd_ecu_names(current.as_ref()).await?;

            if pending_ecus != current_ecus {
                tracing::warn!(
                    "MDD ECU set mismatch: pending {pending_ecus:?} vs current {current_ecus:?}"
                );
            }
        }
        Ok(())
    }

    async fn check_file_integrity(
        &self,
        type_: UpdateFileType,
        path: &std::path::Path,
    ) -> Result<(), VerificationError> {
        match type_ {
            UpdateFileType::Mdd => {
                let path_str = path.to_str().ok_or_else(|| {
                    VerificationError(format!("Invalid UTF-8 path: {}", path.display()))
                })?;
                mmap_and_decode_mdd(path_str).map_err(|e| {
                    VerificationError(format!("Failed to parse MDD '{}': {e}", path.display()))
                })?;
            }
            UpdateFileType::Config => {
                let content = std::fs::read_to_string(path).map_err(|e| {
                    VerificationError(format!("Failed to read config '{}': {e}", path.display()))
                })?;
                toml::from_str::<crate::config::configfile::Configuration>(&content).map_err(
                    |e| {
                        VerificationError(format!(
                            "Failed to parse config '{}': {e}",
                            path.display()
                        ))
                    },
                )?;
            }
        }
        Ok(())
    }
}

async fn mdd_ecu_names<C: Collection + DirectFileAccess>(
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
            let path_str = path.to_str().ok_or_else(|| {
                RuntimeUpdateError::ValidationFailed(format!(
                    "MDD path is not valid UTF-8: {}",
                    path.display()
                ))
            })?;
            mmap_and_decode_mdd(path_str)
                .map(|mdd| mdd.ecu_name)
                .map_err(|e| {
                    RuntimeUpdateError::ValidationFailed(format!("Failed to read MDD: {e}"))
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use async_trait::async_trait;
    use cda_interfaces::storage_api::{CollectionName, Storage as _};
    use cda_plugin_runtime_update::{
        RuntimeFilesUpdateSecurityHandler, RuntimeUpdateError, UpdateCollections, UpdateFileType,
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
        async fn is_vehicle_lock_owned(&self) -> Option<String> {
            self.owner.clone()
        }

        async fn has_non_vehicle_locks(&self) -> bool {
            self.has_ecu_conflicts || self.has_fg_conflicts
        }
    }

    struct NoOpGuard;
    impl ActiveOperationsGuard for NoOpGuard {
        fn has_active_operations(&self) -> bool {
            false
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
        handler: &UpdateSecurityHandler<MockLockProvider, NoOpGuard>,
        type_: UpdateFileType,
        path: &std::path::Path,
    ) -> Result<(), VerificationError> {
        <UpdateSecurityHandler<_, _> as RuntimeFilesUpdateSecurityHandler<
            MockLockProvider,
            LocalCollection,
        >>::check_file_integrity(handler, type_, path)
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
            pending_config: storage
                .get_collection(&CollectionName::ConfigurationNextUpdate)
                .await
                .ok(),
            current_mdd: storage
                .get_collection(&CollectionName::DiagnosticDatabase)
                .await
                .ok(),
            current_config: storage
                .get_collection(&CollectionName::Configuration)
                .await
                .ok(),
        }
    }

    fn make_handler(
        owner: Option<&str>,
        has_ecu_conflicts: bool,
        has_fg_conflicts: bool,
    ) -> (
        UpdateSecurityHandler<MockLockProvider, NoOpGuard>,
        MockLockProvider,
    ) {
        let lock_provider = make_lock_provider(owner, has_ecu_conflicts, has_fg_conflicts);
        let handler = UpdateSecurityHandler::new(
            Arc::new(MockLockProvider {
                owner: owner.map(ToOwned::to_owned),
                has_ecu_conflicts,
                has_fg_conflicts,
            }),
            NoOpGuard,
        );
        (handler, lock_provider)
    }

    #[tokio::test]
    async fn check_apply_allowed_returns_no_lock_when_no_vehicle_lock_held() {
        let (handler, lock_provider) = make_handler(None, false, false);
        let result = handler
            .check_apply_allowed(
                &lock_provider,
                &UpdateCollections::<LocalCollection>::default(),
            )
            .await;
        assert!(matches!(result, Err(RuntimeUpdateError::NoLock(_))));
    }

    #[tokio::test]
    async fn check_apply_allowed_succeeds_when_vehicle_lock_is_held() {
        let (handler, lock_provider) = make_handler(Some("user-b"), false, false);
        let result = handler
            .check_apply_allowed(
                &lock_provider,
                &UpdateCollections::<LocalCollection>::default(),
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn check_apply_allowed_returns_lock_conflict_on_ecu_conflicts() {
        let (handler, lock_provider) = make_handler(Some("user-a"), true, false);
        let result = handler
            .check_apply_allowed(
                &lock_provider,
                &UpdateCollections::<LocalCollection>::default(),
            )
            .await;
        assert!(matches!(result, Err(RuntimeUpdateError::LockConflict(_))));
    }

    #[tokio::test]
    async fn check_apply_allowed_returns_lock_conflict_on_fg_conflicts() {
        let (handler, lock_provider) = make_handler(Some("user-a"), false, true);
        let result = handler
            .check_apply_allowed(
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
    async fn check_apply_allowed_succeeds_when_owner_matches_and_no_conflicts() {
        let (handler, lock_provider) = make_handler(Some("user-a"), false, false);
        assert!(
            handler
                .check_apply_allowed(
                    &lock_provider,
                    &UpdateCollections::<LocalCollection>::default()
                )
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn check_file_integrity_config_fails_on_nonexistent_file() {
        let (handler, _) = make_handler(Some("user-a"), false, false);
        let path = PathBuf::from("/nonexistent/config.toml");
        let result = check_file_integrity(&handler, UpdateFileType::Config, &path).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn check_file_integrity_config_fails_on_invalid_toml() {
        let (handler, _) = make_handler(Some("user-a"), false, false);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, "this is not valid toml {{{").unwrap();
        let result = check_file_integrity(&handler, UpdateFileType::Config, &path).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn check_file_integrity_config_succeeds_on_valid_toml() {
        let (handler, _) = make_handler(Some("user-a"), false, false);
        let config = crate::config::configfile::Configuration::default();
        let toml_str = toml::to_string(&config).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("valid.toml");
        std::fs::write(&path, &toml_str).unwrap();
        let result = check_file_integrity(&handler, UpdateFileType::Config, &path).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn check_file_integrity_mdd_fails_on_nonexistent_file() {
        let (handler, _) = make_handler(Some("user-a"), false, false);
        let path = PathBuf::from("/nonexistent/test.mdd");
        let result = check_file_integrity(&handler, UpdateFileType::Mdd, &path).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn check_file_integrity_mdd_fails_on_invalid_data() {
        let (handler, _) = make_handler(Some("user-a"), false, false);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.mdd");
        std::fs::write(&path, b"not a valid mdd file").unwrap();
        let result = check_file_integrity(&handler, UpdateFileType::Mdd, &path).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn check_apply_allowed_succeeds_when_pending_and_current_mdd_ecu_names_match() {
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
            .check_apply_allowed(&lock_provider, &collections)
            .await;
        assert!(result.is_ok());
    }
}
