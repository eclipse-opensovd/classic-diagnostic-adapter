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
    HashMap, ShutdownSignal,
    health::HealthProvider,
    runtime_update_api::{ReloadError, VehicleComponentFactory, VehicleComponents},
};
use cda_plugin_security::SecurityPlugin;
use cda_transport_orchestrator::DiagnosticTransportRouter;
use tokio::sync::Mutex;

use crate::{UdsManagerType, config::configfile::Configuration};

/// Concrete [`VehicleComponentFactory`] that delegates to
/// [`crate::create_vehicle_components`].
///
/// Used by [`cda_plugin_runtime_update::default_runtime_reloader_plugin::DefaultRuntimeReloaderPlugin`]
/// and called every time the diagnostic databases are reloaded.
pub struct CdaMainVehicleFactory<SP>
where
    SP: SecurityPlugin,
{
    shutdown_signal: ShutdownSignal,
    health_providers: Option<HashMap<String, Arc<dyn HealthProvider>>>,
    _phantom: std::marker::PhantomData<SP>,
}

impl<SP> CdaMainVehicleFactory<SP>
where
    SP: SecurityPlugin,
{
    #[must_use]
    pub fn new(
        shutdown_signal: ShutdownSignal,
        health_providers: Option<HashMap<String, Arc<dyn HealthProvider>>>,
    ) -> Self {
        Self {
            shutdown_signal,
            health_providers,
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
        update_in_progress: Arc<std::sync::atomic::AtomicBool>,
        reusable_transport_resource: Option<Arc<Mutex<cda_comm_doip::socket::DoIPUdpSocket>>>,
    ) -> Result<
        VehicleComponents<
            UdsManagerType<SP>,
            DiagnosticTransportRouter<DoipDiagGateway<EcuManager<SP>>, CanDiagGateway>,
            Self::FileManager,
        >,
        ReloadError,
    > {
        let crate_components = crate::create_vehicle_components::<SP>(
            config,
            mdd_paths,
            self.shutdown_signal.clone(),
            self.health_providers.as_ref(),
            update_in_progress,
            reusable_transport_resource,
        )
        .await
        .map_err(|e| ReloadError(format!("Failed to create vehicle components: {e}")))?;

        Ok(VehicleComponents {
            uds_manager: crate_components.uds_manager,
            diagnostic_gateway: crate_components.diagnostic_gateway,
            file_managers: crate_components.file_managers,
            variant_detection_handle: crate_components.variant_detection_handle,
            functional_group_config: config.functional_description.clone(),
        })
    }
}
