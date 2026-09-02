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
    runtime_update_api::{
        ApplicationUpdatePreparation, RecoveryPhase, ReloadError, ReloadFailure,
        RuntimeReloaderPlugin,
    },
    storage_api::Storage,
};
use tokio::sync::RwLock;

/// Application-independent capabilities needed by the default runtime reloader.
pub struct DefaultReloadContext<Config, S>
where
    S: Storage + Send + Sync + 'static,
{
    pub config: Arc<RwLock<Config>>,
    pub storage: Arc<S>,
}

/// Configuration for creating a [`DefaultRuntimeReloaderPlugin`].
pub struct RuntimeReloaderConfig<Config, Preparation, S>
where
    S: Storage + Send + Sync + 'static,
{
    pub infrastructure: DefaultReloadContext<Config, S>,
    pub preparation: Arc<Preparation>,
}

impl<Config, Preparation, S> RuntimeReloaderConfig<Config, Preparation, S>
where
    S: Storage + Send + Sync + 'static,
{
    #[must_use]
    pub fn new(
        infrastructure: DefaultReloadContext<Config, S>,
        preparation: Arc<Preparation>,
    ) -> Self {
        Self {
            infrastructure,
            preparation,
        }
    }
}

/// Delegates construction and typed component delivery to the application.
pub struct DefaultRuntimeReloaderPlugin<Config, Preparation, S>
where
    S: Storage + Send + Sync + 'static,
{
    config: Arc<RwLock<Config>>,
    preparation: Arc<Preparation>,
    storage: Arc<S>,
}

impl<Config, Preparation, S> DefaultRuntimeReloaderPlugin<Config, Preparation, S>
where
    Config: Clone + Send + Sync + 'static,
    Preparation: ApplicationUpdatePreparation<Config>,
    S: Storage + Send + Sync + 'static,
{
    #[must_use]
    pub fn new(config: RuntimeReloaderConfig<Config, Preparation, S>) -> Self {
        Self {
            config: config.infrastructure.config,
            preparation: config.preparation,
            storage: config.infrastructure.storage,
        }
    }

    async fn prepare_once(&self, config: &Config) -> Result<(), ReloadError> {
        self.preparation.prepare_update(config).await
    }
}

#[async_trait]
impl<Config, Preparation, S> RuntimeReloaderPlugin
    for DefaultRuntimeReloaderPlugin<Config, Preparation, S>
where
    Config: Clone + Send + Sync + 'static,
    Preparation: ApplicationUpdatePreparation<Config>,
    S: Storage + Send + Sync + 'static,
{
    async fn reload_databases(&self) -> Result<(), ReloadFailure> {
        let config = self.config.read().await.clone();
        let original = match self.prepare_once(&config).await {
            Ok(()) => return Ok(()),
            Err(error) => error,
        };

        tracing::error!(error = %original, "Runtime preparation failed; restoring persistent backup");
        if let Err(recovery) = crate::operations::rollback::restore_backup(&*self.storage).await {
            return Err(ReloadFailure::RecoveryRequired {
                original,
                recovery: ReloadError::ReplacementFailure(format!(
                    "Recovery failed while restoring backup: {recovery}"
                )),
                phase: RecoveryPhase::PersistentRestore,
            });
        }

        match self.prepare_once(&config).await {
            Ok(()) => Err(ReloadFailure::RejectedAndRestored { original }),
            Err(recovery) => Err(ReloadFailure::RecoveryRequired {
                original,
                recovery,
                phase: RecoveryPhase::RestoredPreparation,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    };

    use cda_interfaces::{
        runtime_update_api::{ApplicationUpdatePreparation, RuntimeUpdateError},
        storage_api::{
            Collection as _, CollectionName, DirectFileAccess as _, RandomAccessData as _,
        },
    };
    use cda_storage::LocalStorage;

    use super::*;

    const A_VALID: &[u8] = b"A-valid";
    const A_INVALID: &[u8] = b"A-invalid";
    const B_VALID: &[u8] = b"B-valid";
    const B_INVALID: &[u8] = b"B-invalid";

    struct BytePreparation {
        fail_a: AtomicBool,
        fail_b: AtomicBool,
        staged: Arc<Mutex<Vec<Vec<u8>>>>,
        storage: Arc<LocalStorage>,
    }

    #[async_trait]
    impl ApplicationUpdatePreparation<()> for BytePreparation {
        async fn prepare_update(&self, _config: &()) -> Result<(), ReloadError> {
            let current = self
                .storage
                .get_collection(&CollectionName::DiagnosticDatabase)
                .await
                .map_err(|error| ReloadError::ReplacementFailure(error.to_string()))?;
            let path = current
                .file_path("ecu.mdd")
                .map_err(|error| ReloadError::ReplacementFailure(error.to_string()))?;
            let bytes = std::fs::read(path).map_err(|error| {
                ReloadError::ReplacementFailure(format!("factory read failed: {error}"))
            })?;
            let fails = if bytes.starts_with(b"A-") {
                self.fail_a.load(Ordering::SeqCst)
            } else {
                self.fail_b.load(Ordering::SeqCst)
            };
            if fails {
                return Err(ReloadError::ReplacementFailure(format!(
                    "factory rejected {}",
                    String::from_utf8_lossy(&bytes)
                )));
            }
            self.staged.lock().unwrap().push(bytes);
            Ok(())
        }
    }

    type StageLog = Arc<Mutex<Vec<Vec<u8>>>>;
    type TestPlugin = DefaultRuntimeReloaderPlugin<(), BytePreparation, LocalStorage>;

    fn plugin(
        storage: Arc<LocalStorage>,
        fail_a: bool,
        fail_b: bool,
    ) -> (TestPlugin, Arc<BytePreparation>, StageLog) {
        let staged = Arc::new(Mutex::new(Vec::new()));
        let preparation = Arc::new(BytePreparation {
            fail_a: AtomicBool::new(fail_a),
            fail_b: AtomicBool::new(fail_b),
            staged: Arc::clone(&staged),
            storage: Arc::clone(&storage),
        });
        let config = RuntimeReloaderConfig::new(
            DefaultReloadContext {
                config: Arc::new(RwLock::new(())),
                storage,
            },
            Arc::clone(&preparation),
        );
        (
            DefaultRuntimeReloaderPlugin::new(config),
            preparation,
            staged,
        )
    }

    async fn seed(storage: &LocalStorage, current: &[u8], backup: &[u8]) {
        crate::test_utils::init_collection(
            storage,
            &CollectionName::DiagnosticDatabase,
            &[("ecu.mdd", current)],
        )
        .await;
        crate::test_utils::init_collection(
            storage,
            &CollectionName::DiagnosticDatabaseBackup,
            &[("ecu.mdd", backup)],
        )
        .await;
    }

    async fn bytes(storage: &LocalStorage, collection: CollectionName) -> Vec<u8> {
        let collection = storage.get_or_create_collection(&collection).await.unwrap();
        let data = collection.read("ecu.mdd").await.unwrap();
        let mut bytes = vec![0; usize::try_from(data.data_size().unwrap()).unwrap()];
        data.read_at(0, &mut bytes).unwrap();
        bytes
    }

    #[tokio::test]
    async fn explicit_rollback_invalid_a_restores_valid_b_and_preserves_a_candidate() {
        let directory = tempfile::tempdir().unwrap();
        let storage = Arc::new(LocalStorage::new(directory.path()).unwrap());
        seed(&storage, B_VALID, A_INVALID).await;
        let (plugin, _, staged) = plugin(Arc::clone(&storage), true, false);

        let result = crate::operations::rollback::execute_rollback(&*storage, &plugin).await;
        assert!(matches!(
            result,
            Err(RuntimeUpdateError::ReloadFailed(
                ReloadFailure::RejectedAndRestored { original }
            )) if original.to_string().contains("A-invalid")
        ));
        assert_eq!(*staged.lock().unwrap(), vec![B_VALID.to_vec()]);
        assert_eq!(
            bytes(&storage, CollectionName::DiagnosticDatabase).await,
            B_VALID
        );
        assert_eq!(
            bytes(&storage, CollectionName::DiagnosticDatabaseBackup).await,
            A_INVALID
        );
    }

    #[tokio::test]
    async fn explicit_rollback_valid_a_preserves_displaced_valid_b_as_backup() {
        let directory = tempfile::tempdir().unwrap();
        let storage = Arc::new(LocalStorage::new(directory.path()).unwrap());
        seed(&storage, B_VALID, A_VALID).await;
        let (plugin, _, staged) = plugin(Arc::clone(&storage), false, false);

        crate::operations::rollback::execute_rollback(&*storage, &plugin)
            .await
            .unwrap();
        assert_eq!(*staged.lock().unwrap(), vec![A_VALID.to_vec()]);
        assert_eq!(
            bytes(&storage, CollectionName::DiagnosticDatabase).await,
            A_VALID
        );
        assert_eq!(
            bytes(&storage, CollectionName::DiagnosticDatabaseBackup).await,
            B_VALID
        );
    }

    #[tokio::test]
    async fn explicit_rollback_reports_a_and_b_failure_and_keeps_b_current() {
        let directory = tempfile::tempdir().unwrap();
        let storage = Arc::new(LocalStorage::new(directory.path()).unwrap());
        seed(&storage, B_INVALID, A_INVALID).await;
        let (plugin, _, staged) = plugin(Arc::clone(&storage), true, true);

        let result = crate::operations::rollback::execute_rollback(&*storage, &plugin).await;
        let Err(RuntimeUpdateError::ReloadFailed(ReloadFailure::RecoveryRequired {
            original,
            recovery,
            ..
        })) = result
        else {
            panic!("both invalid states must require recovery")
        };
        let message = format!("{original}; {recovery}");
        assert!(message.contains("A-invalid"), "{message}");
        assert!(message.contains("B-invalid"), "{message}");
        assert!(staged.lock().unwrap().is_empty());
        assert_eq!(
            bytes(&storage, CollectionName::DiagnosticDatabase).await,
            B_INVALID
        );
        assert_eq!(
            bytes(&storage, CollectionName::DiagnosticDatabaseBackup).await,
            A_INVALID
        );
    }

    #[tokio::test]
    async fn explicit_rollback_retry_is_deterministic_after_b_becomes_usable() {
        let directory = tempfile::tempdir().unwrap();
        let storage = Arc::new(LocalStorage::new(directory.path()).unwrap());
        seed(&storage, B_INVALID, A_INVALID).await;
        let (plugin, preparation, staged) = plugin(Arc::clone(&storage), true, true);

        let _ = crate::operations::rollback::execute_rollback(&*storage, &plugin).await;
        preparation.fail_b.store(false, Ordering::SeqCst);
        let result = crate::operations::rollback::execute_rollback(&*storage, &plugin).await;
        assert!(matches!(
            result,
            Err(RuntimeUpdateError::ReloadFailed(
                ReloadFailure::RejectedAndRestored { original }
            )) if original.to_string().contains("A-invalid")
        ));
        assert_eq!(*staged.lock().unwrap(), vec![B_INVALID.to_vec()]);
        assert_eq!(
            bytes(&storage, CollectionName::DiagnosticDatabase).await,
            B_INVALID
        );
        assert_eq!(
            bytes(&storage, CollectionName::DiagnosticDatabaseBackup).await,
            A_INVALID
        );
    }
}
