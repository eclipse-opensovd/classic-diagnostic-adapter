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

//! The update policy and the vendor database format.
//!
//! Two things worth copying from here:
//!
//! - The policy never compares claims itself to decide who the caller is. It
//!   downcasts the security plugin and asks it, so a different security plugin
//!   changes the answer and any checks that plugin adds still run.
//! - Implementing [`RuntimeFileInspector`] is what lets an integration ship a
//!   database format CDA does not know. The update plugin stages and swaps files
//!   generically; every operation needing to understand their *content* goes
//!   through this trait.

use std::{path::Path, sync::Arc};

use async_trait::async_trait;
use cda_interfaces::{
    DynamicPlugin,
    runtime_update_api::{
        LockStateProvider, RuntimeFileInspector, RuntimeFilesUpdatePlugin, RuntimeUpdateError,
        RuntimeUpdateSecurityPlugin, UpdateCollections, VerificationError,
    },
    storage_api::{Collection, DirectFileAccess},
};
use cda_plugin_security::{DefaultSecurityPluginData, SecurityPlugin};
use cda_storage::LocalStorage;
use opensovd_cda_lib::{AppError, setup::UpdatePluginContext, update::create_update_plugin_with};

/// Update policy that additionally requires a vendor entitlement.
pub struct EntitlementUpdatePolicy;

impl EntitlementUpdatePolicy {
    /// Resolves the caller's identity by asking the security plugin.
    ///
    /// Downcast the type-erased handle to the configured plugin, then go through
    /// its own accessors rather than reading a claim directly. A handle of the
    /// wrong type means the request never passed the security middleware, so it
    /// is refused rather than treated as anonymous.
    fn caller_identity(security: &DynamicPlugin) -> Result<String, RuntimeUpdateError> {
        let plugin = security
            .downcast_ref::<DefaultSecurityPluginData>()
            .ok_or_else(|| {
                RuntimeUpdateError::NoLock("No valid security context for this request".to_owned())
            })?;
        Ok(plugin.as_auth_plugin().claims().sub().to_owned())
    }

    /// The vendor-specific rule that is impossible to express without the plugin.
    ///
    /// A real integration would read a scope, role, or entitlement claim here.
    fn has_flash_entitlement(identity: &str) -> bool {
        !identity.is_empty()
    }
}

#[async_trait]
impl<L, C> RuntimeUpdateSecurityPlugin<L, C> for EntitlementUpdatePolicy
where
    L: LockStateProvider,
    C: Collection + DirectFileAccess + Send + Sync + 'static,
{
    async fn check_mutation_allowed(
        &self,
        security: &DynamicPlugin,
        lock_state_provider: &L,
    ) -> Result<(), RuntimeUpdateError> {
        let caller = Self::caller_identity(security)?;
        let owner = lock_state_provider
            .vehicle_lock_owner_id()
            .await
            .ok_or_else(|| RuntimeUpdateError::NoLock("Vehicle lock is missing".to_owned()))?;
        if owner != caller {
            return Err(RuntimeUpdateError::NoLock(
                "Vehicle lock is owned by another user".to_owned(),
            ));
        }
        Ok(())
    }

    async fn check_apply_allowed(
        &self,
        security: &DynamicPlugin,
        lock_state_provider: &L,
        _collections: &UpdateCollections<C>,
    ) -> Result<(), RuntimeUpdateError> {
        RuntimeUpdateSecurityPlugin::<L, C>::check_mutation_allowed(
            self,
            security,
            lock_state_provider,
        )
        .await?;

        // The check that motivates a custom policy: an entitlement the default
        // handler has no way to know about.
        if !Self::has_flash_entitlement(&Self::caller_identity(security)?) {
            return Err(RuntimeUpdateError::NoLock(
                "Caller lacks the flash entitlement".to_owned(),
            ));
        }

        if lock_state_provider.has_non_vehicle_locks().await {
            return Err(RuntimeUpdateError::LockConflict(
                "Non-vehicle locks are held".to_owned(),
            ));
        }
        Ok(())
    }

    async fn check_file_integrity(&self, path: &Path) -> Result<(), VerificationError> {
        // Where an OEM would verify a signature over the file.
        if path.extension().is_none() {
            return Err(VerificationError("file has no extension".to_owned()));
        }
        Ok(())
    }
}

/// Reads a vendor database format instead of MDD.
pub struct VendorFormatInspector;

impl RuntimeFileInspector for VendorFormatInspector {
    fn validate(&self, path: &Path) -> Result<(), VerificationError> {
        std::fs::metadata(path)
            .map(|_| ())
            .map_err(|error| VerificationError(format!("unreadable: {error}")))
    }

    fn ecu_name(&self, path: &Path) -> Result<String, RuntimeUpdateError> {
        path.file_stem()
            .and_then(|stem| stem.to_str())
            .map(str::to_uppercase)
            .ok_or_else(|| {
                RuntimeUpdateError::ValidationFailed("cannot derive ECU name".to_owned())
            })
    }

    fn revision(&self, _path: &Path) -> Option<String> {
        None
    }

    fn decompress_in_place(&self, _path: &Path) -> Result<(), RuntimeUpdateError> {
        // This format is not compressed, so there is nothing to rewrite.
        Ok(())
    }
}

/// Builds the standard update plugin over the custom policy and format.
///
/// # Errors
/// Returns [`AppError`] when persistent update storage cannot be initialized.
pub async fn build_update_plugin(
    context: UpdatePluginContext,
) -> Result<impl RuntimeFilesUpdatePlugin, AppError> {
    let storage = Arc::new(
        LocalStorage::new(&context.storage_dir)
            .map_err(|error| AppError::InitializationFailed(error.to_string()))?,
    );
    let inspector: Arc<dyn RuntimeFileInspector> = Arc::new(VendorFormatInspector);

    Ok(create_update_plugin_with(
        context,
        storage,
        Arc::new(EntitlementUpdatePolicy),
        inspector,
    ))
}
