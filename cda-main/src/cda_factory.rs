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
use std::{path::PathBuf, sync::Arc};

use async_trait::async_trait;
use cda_comm_can::CanDiagGateway;
use cda_comm_doip::DoipDiagGateway;
use cda_core::EcuManager;
use cda_interfaces::{
    HashMap,
    communication_control::CommunicationAccess,
    health::HealthProvider,
    runtime_update_api::{ReloadError, VehicleComponentFactory, VehicleComponents},
};
use cda_plugin_security::SecurityPlugin;
use cda_transport_router::DiagnosticTransportRouter;

use crate::{config::configfile::Configuration, vehicle::UdsManagerType};

/// Concrete [`VehicleComponentFactory`] that delegates to
/// [`crate::vehicle::create_vehicle_components`].
///
/// Used by [`cda_plugin_runtime_update::default_runtime_reloader_plugin::DefaultRuntimeReloaderPlugin`]
/// and called every time the diagnostic databases are reloaded.
pub struct CdaMainVehicleFactory<SP>
where
    SP: SecurityPlugin,
{
    health_providers: Option<HashMap<String, Arc<dyn HealthProvider>>>,
    communication_access: Arc<dyn CommunicationAccess>,
    _phantom: std::marker::PhantomData<SP>,
}

impl<SP> CdaMainVehicleFactory<SP>
where
    SP: SecurityPlugin,
{
    #[must_use]
    pub fn new(
        health_providers: Option<HashMap<String, Arc<dyn HealthProvider>>>,
        communication_access: Arc<dyn CommunicationAccess>,
    ) -> Self {
        Self {
            health_providers,
            communication_access,
            _phantom: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<SP>
    VehicleComponentFactory<
        Configuration,
        UdsManagerType<SP>,
        DiagnosticTransportRouter<DoipDiagGateway<EcuManager<SP>>, CanDiagGateway>,
    > for CdaMainVehicleFactory<SP>
where
    SP: SecurityPlugin,
{
    type FileManager = cda_database::FileManager;

    async fn create(
        &self,
        config: &Configuration,
        mdd_paths: &[PathBuf],
    ) -> Result<
        VehicleComponents<
            UdsManagerType<SP>,
            DiagnosticTransportRouter<DoipDiagGateway<EcuManager<SP>>, CanDiagGateway>,
            Self::FileManager,
        >,
        ReloadError,
    > {
        let crate_components = crate::vehicle::create_vehicle_components::<SP>(
            config,
            mdd_paths,
            self.health_providers.as_ref(),
            Arc::clone(&self.communication_access),
        )
        .await
        .map_err(|e| {
            ReloadError::ReplacementFailure(format!("Failed to create new vehicle components: {e}"))
        })?;

        Ok(VehicleComponents {
            uds_manager: crate_components.uds_manager,
            diagnostic_gateway: crate_components.diagnostic_gateway,
            file_managers: crate_components.file_managers,
            functional_group_config: config.functional_description.clone(),
        })
    }
}
