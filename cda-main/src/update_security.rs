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

//! Default runtime-update authorization policy.
//!
//! Lives in `cda-main` rather than in `cda-plugin-runtime-update` because it must
//! consult the security plugin, and the update plugin deliberately depends on
//! `cda-interfaces` alone. Policy belongs to the application (or an OEM); the
//! plugin only enforces whatever policy it is handed.

use std::{collections::HashSet, marker::PhantomData, sync::Arc};

use async_trait::async_trait;
use cda_interfaces::{
    DynamicPlugin,
    runtime_update_api::{
        LockStateProvider, RuntimeFileInspector, RuntimeUpdateError, RuntimeUpdateSecurityPlugin,
        UpdateCollections, VerificationError,
    },
    storage_api::{Collection, DirectFileAccess},
};
use cda_plugin_security::SecurityPlugin;

/// Default runtime-update authorization and integrity policy.
///
/// Requires the caller to own the vehicle lock and no other lock to be held, then
/// verifies file integrity through the injected [`RuntimeFileInspector`].
///
/// The caller's identity is obtained from the security plugin instance rather than
/// from a claim read elsewhere, so a replacement security plugin governs who the
/// caller is considered to be.
pub struct DefaultUpdateSecurityHandler<L: LockStateProvider, S: SecurityPlugin> {
    inspector: Arc<dyn RuntimeFileInspector>,
    _lock: PhantomData<L>,
    _security: PhantomData<S>,
}

impl<L: LockStateProvider, S: SecurityPlugin> DefaultUpdateSecurityHandler<L, S> {
    /// Creates a handler that inspects files with `inspector`.
    #[must_use]
    pub fn new(inspector: Arc<dyn RuntimeFileInspector>) -> Self {
        Self {
            inspector,
            _lock: PhantomData,
            _security: PhantomData,
        }
    }

    /// Resolves the caller's identity by asking the security plugin.
    ///
    /// Mirrors `cda_core`'s `check_security_plugin`: downcast the type-erased
    /// handle to the configured plugin, then go through its own accessors. A
    /// handle of the wrong type means the request never passed the security
    /// middleware, so it is refused rather than treated as anonymous.
    fn caller_identity(security: &DynamicPlugin) -> Result<String, RuntimeUpdateError> {
        let plugin = security.downcast_ref::<S>().ok_or_else(|| {
            RuntimeUpdateError::NoLock("No valid security context for this request".to_owned())
        })?;
        Ok(plugin.as_auth_plugin().claims().sub().to_owned())
    }

    /// Shared by mutation and execution: the caller must hold the vehicle lock.
    async fn require_vehicle_lock_owner(
        security: &DynamicPlugin,
        lock_state_provider: &L,
    ) -> Result<(), RuntimeUpdateError> {
        let owner =
            lock_state_provider
                .vehicle_lock_owner_id()
                .await
                .ok_or(RuntimeUpdateError::NoLock(
                    "Vehicle lock is missing".to_owned(),
                ))?;
        if owner != Self::caller_identity(security)? {
            return Err(RuntimeUpdateError::NoLock(
                "Vehicle lock is owned by another user".to_owned(),
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl<
    L: LockStateProvider,
    S: SecurityPlugin,
    C: Collection + DirectFileAccess + Send + Sync + 'static,
> RuntimeUpdateSecurityPlugin<L, C> for DefaultUpdateSecurityHandler<L, S>
{
    async fn check_mutation_allowed(
        &self,
        security: &DynamicPlugin,
        lock_state_provider: &L,
    ) -> Result<(), RuntimeUpdateError> {
        Self::require_vehicle_lock_owner(security, lock_state_provider).await
    }

    /// Ensures the caller owns the vehicle lock and no ECU or functional-group
    /// locks are held. Conflicting communication activity is excluded atomically
    /// by the disable lease before this runs.
    async fn check_apply_allowed(
        &self,
        security: &DynamicPlugin,
        lock_state_provider: &L,
        collections: &UpdateCollections<C>,
    ) -> Result<(), RuntimeUpdateError> {
        Self::require_vehicle_lock_owner(security, lock_state_provider).await?;

        if lock_state_provider.has_non_vehicle_locks().await {
            return Err(RuntimeUpdateError::LockConflict(
                "Non-vehicle locks are held, cannot apply update".to_owned(),
            ));
        }

        // Advisory: an OEM policy would typically reject here rather than warn.
        if let (Some(pending), Some(current)) = (&collections.pending_mdd, &collections.current_mdd)
        {
            let pending_ecus = database_ecu_names(pending.as_ref(), &*self.inspector).await?;
            let current_ecus = database_ecu_names(current.as_ref(), &*self.inspector).await?;
            if pending_ecus != current_ecus {
                tracing::warn!(
                    "Database ECU set mismatch: pending {pending_ecus:?} vs current \
                     {current_ecus:?}"
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
    use cda_plugin_security::{AuthApi, Claims, SecurityApi, SecurityPluginData};

    use super::*;
    use crate::mdd_inspector::MddFileInspector;

    struct MockLockProvider {
        owner: Option<String>,
        has_conflicts: bool,
    }

    #[async_trait]
    impl LockStateProvider for MockLockProvider {
        async fn vehicle_lock_owner_id(&self) -> Option<String> {
            self.owner.clone()
        }

        async fn has_non_vehicle_locks(&self) -> bool {
            self.has_conflicts
        }
    }

    /// Stands in for an OEM security plugin: the identity it reports is the one
    /// authorization must be decided against.
    struct TestSecurityPlugin {
        sub: String,
    }

    impl Claims for TestSecurityPlugin {
        fn sub(&self) -> &str {
            &self.sub
        }
    }

    impl AuthApi for TestSecurityPlugin {
        fn claims(&self) -> Box<&dyn Claims> {
            Box::new(self)
        }
    }

    impl SecurityApi for TestSecurityPlugin {
        fn validate_service(
            &self,
            _service: &cda_database::datatypes::DiagService,
        ) -> Result<(), cda_interfaces::DiagServiceError> {
            Ok(())
        }
    }

    impl cda_plugin_security::SecurityPlugin for TestSecurityPlugin {
        fn as_auth_plugin(&self) -> &dyn AuthApi {
            self
        }

        fn as_security_plugin(&self) -> &dyn SecurityApi {
            self
        }
    }

    type Handler = DefaultUpdateSecurityHandler<MockLockProvider, TestSecurityPlugin>;

    fn handler() -> Handler {
        DefaultUpdateSecurityHandler::new(Arc::new(MddFileInspector))
    }

    fn security_context(sub: &str) -> DynamicPlugin {
        let plugin: SecurityPluginData = Box::new(TestSecurityPlugin {
            sub: sub.to_owned(),
        });
        plugin as DynamicPlugin
    }

    /// Pins the collection type so the trait's `C` parameter is inferable.
    async fn check_mutation(
        security: &DynamicPlugin,
        locks: &MockLockProvider,
    ) -> Result<(), RuntimeUpdateError> {
        RuntimeUpdateSecurityPlugin::<MockLockProvider, cda_storage::LocalCollection>::
            check_mutation_allowed(&handler(), security, locks).await
    }

    fn locks(owner: Option<&str>, has_conflicts: bool) -> MockLockProvider {
        MockLockProvider {
            owner: owner.map(ToOwned::to_owned),
            has_conflicts,
        }
    }

    #[tokio::test]
    async fn mutation_is_refused_without_a_vehicle_lock() {
        let result = check_mutation(&security_context("alice"), &locks(None, false)).await;

        assert!(
            matches!(result, Err(RuntimeUpdateError::NoLock(_))),
            "no vehicle lock must deny the mutation"
        );
    }

    #[tokio::test]
    async fn mutation_is_refused_when_the_lock_belongs_to_someone_else() {
        let result = check_mutation(&security_context("alice"), &locks(Some("bob"), false)).await;

        assert!(
            matches!(result, Err(RuntimeUpdateError::NoLock(_))),
            "a lock held by another identity must deny the mutation"
        );
    }

    #[tokio::test]
    async fn identity_comes_from_the_security_plugin() {
        // The plugin is the authority: the lock owner is compared against whatever
        // identity the plugin reports, not against anything this layer derives.
        let result = check_mutation(&security_context("alice"), &locks(Some("alice"), false)).await;

        assert!(result.is_ok(), "matching the plugin's identity must pass");
    }

    #[tokio::test]
    async fn a_foreign_security_context_is_refused_rather_than_treated_as_anonymous() {
        // A handle that is not the configured plugin type means the request never
        // passed the security middleware.
        let foreign: DynamicPlugin = Box::new(());

        let result = check_mutation(&foreign, &locks(Some("alice"), false)).await;

        assert!(
            result.is_err(),
            "an unrecognized security context must not authorize anything"
        );
    }

    #[tokio::test]
    async fn apply_is_refused_while_other_locks_are_held() {
        let result = RuntimeUpdateSecurityPlugin::<MockLockProvider, cda_storage::LocalCollection>::
            check_apply_allowed(
                &handler(),
                &security_context("alice"),
                &locks(Some("alice"), true),
                &UpdateCollections::default(),
            )
            .await;

        assert!(
            matches!(result, Err(RuntimeUpdateError::LockConflict(_))),
            "ECU or functional-group locks must block an apply"
        );
    }

    #[tokio::test]
    async fn apply_passes_for_the_lock_owner_with_no_conflicts() {
        let result = RuntimeUpdateSecurityPlugin::<MockLockProvider, cda_storage::LocalCollection>::
            check_apply_allowed(
                &handler(),
                &security_context("alice"),
                &locks(Some("alice"), false),
                &UpdateCollections::default(),
            )
            .await;

        assert!(result.is_ok());
    }
}
