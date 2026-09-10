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

use cda_interfaces::{
    HashMap, VariantDetectionSender,
    health::HealthProvider,
    runtime_update_api::{
        PreparedApply, ReloadError, RuntimeFileInspector, VehicleDatabaseLockUpdater,
    },
};
use cda_plugin_security::SecurityPlugin;

use crate::{
    config::configfile::Configuration,
    mdd,
    vehicle::{VehicleDataSource, load_vehicle_databases},
};

/// Loads the diagnostic databases that are currently on disk.
///
/// Startup and reload load them the same way, so a reload cannot produce
/// state that startup would not have produced from the same files.
pub struct VehicleDatabaseLoader<SP>
where
    SP: SecurityPlugin,
{
    variant_detection: VariantDetectionSender,
    file_inspector: Arc<dyn RuntimeFileInspector>,
    _phantom: std::marker::PhantomData<SP>,
}

impl<SP> VehicleDatabaseLoader<SP>
where
    SP: SecurityPlugin,
{
    #[must_use]
    pub fn new(
        variant_detection: VariantDetectionSender,
        file_inspector: Arc<dyn RuntimeFileInspector>,
    ) -> Self {
        Self {
            variant_detection,
            file_inspector,
            _phantom: std::marker::PhantomData,
        }
    }

    /// `health_providers` belongs to whoever asked for the load: the caller that
    /// publishes the database status supplies it, and one that does not passes
    /// `None`.
    #[allow(
        clippy::implicit_hasher,
        reason = "Type alias doesn't allow specifying hasher"
    )]
    pub(crate) async fn create_databases(
        &self,
        config: &Configuration,
        health_providers: Option<&HashMap<String, Arc<dyn HealthProvider>>>,
    ) -> Result<VehicleDataSource<SP>, ReloadError> {
        Ok(load_vehicle_databases::<SP>(
            config,
            health_providers,
            self.variant_detection.clone(),
            &*self.file_inspector,
        )
        .await?)
    }

    /// The revision each database file on disk carries, keyed by the ECU it
    /// describes.
    ///
    /// Read through the injected inspector rather than off the loaded
    /// databases, so an application that supplies its own format reports its
    /// own revisions. A file that names neither is left out; a revision nobody
    /// can read is not an error.
    #[allow(
        clippy::implicit_hasher,
        reason = "Type alias doesn't allow specifying hasher"
    )]
    pub(crate) async fn revisions(&self, config: &Configuration) -> HashMap<String, String> {
        let paths = mdd::resolve_mdd_paths(
            &config.runtime_update_config.storage_dir,
            &config.database.seed_dir,
        )
        .await;

        let mut revisions = HashMap::default();
        for path in paths {
            let (Ok(ecu), Some(revision)) = (
                self.file_inspector.ecu_name(&path),
                self.file_inspector.revision(&path),
            ) else {
                continue;
            };
            revisions.insert(ecu, revision);
        }
        revisions
    }
}

/// Vehicle data built from the databases on disk, not yet live.
///
/// Every step that can fail happened while this was built, against live data
/// that was still untouched, so a failure leaves the runtime as it was and
/// installing what succeeded cannot fail.
pub(crate) struct PreparedVehicleData<SP: SecurityPlugin> {
    /// Normalized SOVD ECU and functional-group membership.
    pub(crate) identities: cda_sovd::SovdIdentities,
    /// `None` when the application is configured without CAN.
    pub(crate) can_topology: Option<crate::vehicle::CanTopologyPayload>,
    /// The UDS view of the vehicle, which owns the loaded databases.
    pub(crate) ecu_data: cda_comm_uds::VehicleEcuData<cda_core::EcuManager<SP>>,
    /// Lock admission for the new topology, reserved so a conflicting lock
    /// aborts the reload while the live data is still intact.
    pub(crate) lock_reservation: Box<dyn PreparedApply>,
    /// What the loaded files report, for whoever publishes the live revisions.
    pub(crate) revisions: HashMap<String, String>,
}

impl<SP: SecurityPlugin> PreparedVehicleData<SP> {
    /// Builds everything a reload needs from the databases that are on disk.
    ///
    /// # Errors
    /// Returns [`ReloadError`] when the databases cannot be loaded, the
    /// configured CAN topology cannot be derived from them, or a held lock
    /// stands in the way of the topology they imply.
    pub(crate) async fn build(
        loader: &VehicleDatabaseLoader<SP>,
        config: &Configuration,
        locks: &dyn VehicleDatabaseLockUpdater,
    ) -> Result<Self, ReloadError> {
        // A reload reports its outcome to the caller that asked for it; the
        // published database status keeps describing the data that is live.
        let databases = loader.create_databases(config, None).await?;

        // `ecu_data` consumes the source, so every other payload is derived
        // from it before that.
        let identities = databases.sovd_registry(config).await;
        let can_topology = databases
            .can_topology(config)
            .await
            .map_err(|error| ReloadError::ReplacementFailure(error.to_string()))?;
        let ecu_data = databases.ecu_data(config);
        let lock_reservation = locks
            .reserve_lock_resources(ecu_data.physical_ecu_names())
            .await?;

        Ok(Self {
            identities,
            can_topology,
            ecu_data,
            lock_reservation,
            revisions: loader.revisions(config).await,
        })
    }
}
