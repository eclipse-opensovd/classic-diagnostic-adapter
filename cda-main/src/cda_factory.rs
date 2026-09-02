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
    HashMap, ReloadComponent, VariantDetectionSender,
    health::HealthProvider,
    runtime_update_api::{ApplicationUpdatePreparation, ReloadError, VehicleDatabaseLockUpdater},
};
use cda_plugin_security::SecurityPlugin;

use crate::{
    config::configfile::Configuration,
    vehicle::{VehicleDatabases, load_vehicle_databases},
};

/// Loads the diagnostic databases that are currently on disk.
///
/// Startup and reload load them the same way, so a reload cannot produce
/// state that startup would not have produced from the same files.
pub struct VehicleDatabaseLoader<SP>
where
    SP: SecurityPlugin,
{
    health_providers: Option<HashMap<String, Arc<dyn HealthProvider>>>,
    variant_detection: VariantDetectionSender,
    _phantom: std::marker::PhantomData<SP>,
}

impl<SP> VehicleDatabaseLoader<SP>
where
    SP: SecurityPlugin,
{
    #[must_use]
    pub fn new(
        health_providers: Option<HashMap<String, Arc<dyn HealthProvider>>>,
        variant_detection: VariantDetectionSender,
    ) -> Self {
        Self {
            health_providers,
            variant_detection,
            _phantom: std::marker::PhantomData,
        }
    }

    pub(crate) async fn create(
        &self,
        config: &Configuration,
    ) -> Result<VehicleDatabases<SP>, ReloadError> {
        Ok(load_vehicle_databases::<SP>(
            config,
            self.health_providers.as_ref(),
            self.variant_detection.clone(),
        )
        .await?)
    }
}

/// The components a database reload replaces, in the order they are applied.
///
/// Held directly rather than behind a registration list: the set is fixed by
/// what the application is built from, and the apply order is a property of
/// this sequence rather than of the order someone happened to register in.
pub struct ReloadTargets<SP: SecurityPlugin> {
    /// Lock resources, reserved before anything is replaced so a conflicting
    /// lock aborts the reload while the live data is still intact.
    pub locks: Arc<dyn VehicleDatabaseLockUpdater>,
    pub uds: Arc<dyn ReloadComponent<cda_comm_uds::VehicleEcuData<cda_core::EcuManager<SP>>>>,
    /// `None` when the application is built or configured without CAN.
    #[cfg(feature = "can")]
    pub can: Option<Arc<dyn ReloadComponent<cda_comm_can::CanTopology>>>,
    pub sovd: Arc<dyn ReloadComponent<cda_sovd::SovdRegistryUpdate>>,
}

/// Rebuilds runtime state from the databases a runtime update just applied.
///
/// The MDD files have already been swapped on disk when this runs; what it
/// prepares is the in-memory state derived from them.
pub struct DatabaseReloadPreparation<SP: SecurityPlugin> {
    database_loader: Arc<VehicleDatabaseLoader<SP>>,
    targets: ReloadTargets<SP>,
}

impl<SP: SecurityPlugin> DatabaseReloadPreparation<SP> {
    #[must_use]
    pub fn new(
        database_loader: Arc<VehicleDatabaseLoader<SP>>,
        targets: ReloadTargets<SP>,
    ) -> Self {
        Self {
            database_loader,
            targets,
        }
    }
}

#[async_trait]
impl<SP> ApplicationUpdatePreparation<Configuration> for DatabaseReloadPreparation<SP>
where
    SP: SecurityPlugin,
{
    async fn prepare_update(&self, config: &Configuration) -> Result<(), ReloadError> {
        let databases = self.database_loader.create(config).await?;

        // Everything that can fail happens first, against live data that is
        // still untouched, so a failure here leaves the runtime as it was.
        let ecu_data = databases.ecu_data(config);
        let lock_reservation = self
            .targets
            .locks
            .reserve_lock_resources(ecu_data.ecu_names())
            .await?;
        let sovd_registry = databases.sovd_registry(config).await;
        #[cfg(feature = "can")]
        let can_topology = match (&self.targets.can, databases.can_topology(config).await?) {
            (Some(owner), Some(topology)) => Some((owner, topology)),
            (None, None) => None,
            _ => {
                return Err(ReloadError::ReplacementFailure(
                    "Prepared CAN topology does not match the configured CAN owner".to_owned(),
                ));
            }
        };

        // Nothing below can fail. It runs under the caller's exclusive disable
        // lease, with the transport down and ordinary HTTP refused, so no
        // reader observes a half-replaced runtime.
        lock_reservation.apply();
        self.targets.uds.apply(ecu_data).await;
        #[cfg(feature = "can")]
        if let Some((owner, topology)) = can_topology {
            owner.apply(topology).await;
        }
        self.targets.sovd.apply(sovd_registry).await;
        Ok(())
    }
}
