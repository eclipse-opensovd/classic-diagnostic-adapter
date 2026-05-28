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

use std::sync::Arc;

use async_trait::async_trait;
use cda_database::mmap_and_decode_mdd;
use cda_plugin_runtime_update::{
    ActiveOperationsGuard, LockStateProvider, RuntimeFilesUpdateSecurityHandler,
    RuntimeUpdateError, UpdateFileType, VerificationError,
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
impl<L: LockStateProvider, G: ActiveOperationsGuard> RuntimeFilesUpdateSecurityHandler<L>
    for UpdateSecurityHandler<L, G>
{
    /// Validates that the caller is allowed to start an execution (apply/rollback/cleanup).
    ///
    /// Ensures the caller owns the vehicle lock, no ECU or functional-group locks
    /// are held, and no active operations are in progress.
    async fn check_apply_allowed(&self, lock_state_provider: &L) -> Result<(), RuntimeUpdateError> {
        lock_state_provider
            .is_vehicle_lock_owned()
            .await
            .ok_or(RuntimeUpdateError::NoLock)?;
        if lock_state_provider.has_non_vehicle_locks().await {
            return Err(RuntimeUpdateError::OperationsInProgress);
        }
        if self.guard.has_active_operations() {
            return Err(RuntimeUpdateError::OperationsInProgress);
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use async_trait::async_trait;
    use cda_plugin_runtime_update::{
        RuntimeFilesUpdateSecurityHandler, RuntimeUpdateError, UpdateFileType,
    };

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
        let result = handler.check_apply_allowed(&lock_provider).await;
        assert!(matches!(result, Err(RuntimeUpdateError::NoLock)));
    }

    #[tokio::test]
    async fn check_apply_allowed_succeeds_when_vehicle_lock_is_held() {
        let (handler, lock_provider) = make_handler(Some("user-b"), false, false);
        let result = handler.check_apply_allowed(&lock_provider).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn check_apply_allowed_returns_operations_in_progress_on_ecu_conflicts() {
        let (handler, lock_provider) = make_handler(Some("user-a"), true, false);
        let result = handler.check_apply_allowed(&lock_provider).await;
        assert!(matches!(
            result,
            Err(RuntimeUpdateError::OperationsInProgress)
        ));
    }

    #[tokio::test]
    async fn check_apply_allowed_returns_operations_in_progress_on_fg_conflicts() {
        let (handler, lock_provider) = make_handler(Some("user-a"), false, true);
        let result = handler.check_apply_allowed(&lock_provider).await;
        assert!(matches!(
            result,
            Err(RuntimeUpdateError::OperationsInProgress)
        ));
    }

    #[tokio::test]
    async fn check_apply_allowed_succeeds_when_owner_matches_and_no_conflicts() {
        let (handler, lock_provider) = make_handler(Some("user-a"), false, false);
        assert!(handler.check_apply_allowed(&lock_provider).await.is_ok());
    }

    #[tokio::test]
    async fn check_file_integrity_config_fails_on_nonexistent_file() {
        let (handler, _) = make_handler(Some("user-a"), false, false);
        let path = PathBuf::from("/nonexistent/config.toml");
        let result = handler
            .check_file_integrity(UpdateFileType::Config, &path)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn check_file_integrity_config_fails_on_invalid_toml() {
        let (handler, _) = make_handler(Some("user-a"), false, false);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, "this is not valid toml {{{").unwrap();
        let result = handler
            .check_file_integrity(UpdateFileType::Config, &path)
            .await;
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
        let result = handler
            .check_file_integrity(UpdateFileType::Config, &path)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn check_file_integrity_mdd_fails_on_nonexistent_file() {
        let (handler, _) = make_handler(Some("user-a"), false, false);
        let path = PathBuf::from("/nonexistent/test.mdd");
        let result = handler
            .check_file_integrity(UpdateFileType::Mdd, &path)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn check_file_integrity_mdd_fails_on_invalid_data() {
        let (handler, _) = make_handler(Some("user-a"), false, false);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.mdd");
        std::fs::write(&path, b"not a valid mdd file").unwrap();
        let result = handler
            .check_file_integrity(UpdateFileType::Mdd, &path)
            .await;
        assert!(result.is_err());
    }
}
