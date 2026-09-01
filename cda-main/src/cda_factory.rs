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
    runtime_update_api::{
        ApplicationUpdatePreparation, ReloadError, ReservedVehicleDatabaseLocks,
        RuntimeFileInspector, VehicleDatabaseLockUpdater,
    },
};
use cda_plugin_security::SecurityPlugin;

use crate::{
    AppError,
    config::configfile::Configuration,
    vehicle::{VehicleModel, create_vehicle_model},
};

fn map_app_error(error: &AppError) -> ReloadError {
    let message = error.to_string();
    match error {
        AppError::NoDatabasesLoaded { .. } => ReloadError::NoDatabasesLoaded(message),
        _ => ReloadError::ReplacementFailure(format!("Failed to create vehicle data: {message}")),
    }
}

#[cfg(feature = "integration-tests")]
fn inject_planned_factory_failure(config: &Configuration) -> Result<(), ReloadError> {
    let plan_path = std::path::Path::new(&config.runtime_update_config.storage_dir)
        .join(".vehicle-factory-failure-plan");
    let Ok(plan) = std::fs::read_to_string(&plan_path) else {
        return Ok(());
    };
    let mut entries = plan.lines();
    let next = entries.next();
    let remaining = entries.collect::<Vec<_>>().join("\n");
    if remaining.is_empty() {
        std::fs::remove_file(&plan_path).map_err(|error| {
            ReloadError::ReplacementFailure(format!(
                "Failed to consume integration-test factory plan: {error}"
            ))
        })?;
    } else {
        std::fs::write(&plan_path, format!("{remaining}\n")).map_err(|error| {
            ReloadError::ReplacementFailure(format!(
                "Failed to consume integration-test factory plan: {error}"
            ))
        })?;
    }
    if next == Some("fail") {
        return Err(ReloadError::ReplacementFailure(
            "Integration-test vehicle factory failure".to_owned(),
        ));
    }
    Ok(())
}

pub struct CdaMainVehicleFactory<SP>
where
    SP: SecurityPlugin,
{
    health_providers: Option<HashMap<String, Arc<dyn HealthProvider>>>,
    variant_detection: VariantDetectionSender,
    file_inspector: Arc<dyn RuntimeFileInspector>,
    _phantom: std::marker::PhantomData<SP>,
}

impl<SP> CdaMainVehicleFactory<SP>
where
    SP: SecurityPlugin,
{
    #[must_use]
    pub fn new(
        health_providers: Option<HashMap<String, Arc<dyn HealthProvider>>>,
        variant_detection: VariantDetectionSender,
        file_inspector: Arc<dyn RuntimeFileInspector>,
    ) -> Self {
        Self {
            health_providers,
            variant_detection,
            file_inspector,
            _phantom: std::marker::PhantomData,
        }
    }

    pub(crate) async fn create(
        &self,
        config: &Configuration,
    ) -> Result<VehicleModel<SP>, ReloadError> {
        let model = create_vehicle_model::<SP>(
            config,
            self.health_providers.as_ref(),
            self.variant_detection.clone(),
            self.file_inspector.as_ref(),
        )
        .await
        .map_err(|error| map_app_error(&error))?;
        #[cfg(feature = "integration-tests")]
        inject_planned_factory_failure(config)?;
        Ok(model)
    }
}

/// Opaque payload whose construction has completed and can be staged infallibly.
#[async_trait]
pub trait ReadyToApply: Send {
    /// Publishes the prepared payload into its component owner, waiting for
    /// in-flight readers of the previous data to finish.
    async fn apply(self: Box<Self>);
}

/// One independently registered owner-specific runtime-update participant.
///
/// Preflight must perform every fallible or asynchronous operation without
/// mutating staged owner state. The returned payload is opaque to the
/// coordinator and stages synchronously only after every participant succeeds.
#[async_trait]
pub trait VehicleUpdateParticipant<SP: SecurityPlugin>: Send + Sync {
    /// Constructs and validates this owner's next payload without applying it.
    async fn preflight(
        &self,
        model: &VehicleModel<SP>,
        config: &Configuration,
    ) -> Result<Box<dyn ReadyToApply>, ReloadError>;
}

struct ComponentPayload<T> {
    owner: Arc<dyn ReloadComponent<T>>,
    data: T,
}

#[async_trait]
impl<T: Send + 'static> ReadyToApply for ComponentPayload<T> {
    async fn apply(self: Box<Self>) {
        self.owner.apply(self.data).await;
    }
}

pub(crate) struct UdsParticipant<SP: SecurityPlugin> {
    pub(crate) owner:
        Arc<dyn ReloadComponent<cda_comm_uds::VehicleEcuData<cda_core::EcuManager<SP>>>>,
}

#[async_trait]
impl<SP: SecurityPlugin> VehicleUpdateParticipant<SP> for UdsParticipant<SP> {
    async fn preflight(
        &self,
        model: &VehicleModel<SP>,
        config: &Configuration,
    ) -> Result<Box<dyn ReadyToApply>, ReloadError> {
        Ok(Box::new(ComponentPayload {
            owner: Arc::clone(&self.owner),
            data: model.ecu_data(config),
        }))
    }
}

pub(crate) struct SovdParticipant {
    pub(crate) owner: Arc<dyn ReloadComponent<cda_sovd::SovdRegistryUpdate>>,
}

#[async_trait]
impl<SP: SecurityPlugin> VehicleUpdateParticipant<SP> for SovdParticipant {
    async fn preflight(
        &self,
        model: &VehicleModel<SP>,
        config: &Configuration,
    ) -> Result<Box<dyn ReadyToApply>, ReloadError> {
        Ok(Box::new(ComponentPayload {
            owner: Arc::clone(&self.owner),
            data: model.sovd_registry(config).await,
        }))
    }
}

struct LockPayload {
    reservation: Box<dyn ReservedVehicleDatabaseLocks>,
}

#[async_trait]
impl ReadyToApply for LockPayload {
    async fn apply(self: Box<Self>) {
        self.reservation.apply();
    }
}

pub(crate) struct LockParticipant {
    pub(crate) owner: Arc<dyn VehicleDatabaseLockUpdater>,
}

#[async_trait]
impl<SP: SecurityPlugin> VehicleUpdateParticipant<SP> for LockParticipant {
    async fn preflight(
        &self,
        model: &VehicleModel<SP>,
        config: &Configuration,
    ) -> Result<Box<dyn ReadyToApply>, ReloadError> {
        let ecu_names = model.ecu_data(config).ecu_names();
        let reservation = self.owner.reserve_lock_resources(ecu_names).await?;
        Ok(Box::new(LockPayload { reservation }))
    }
}

#[cfg(feature = "can")]
pub(crate) struct CanParticipant {
    pub(crate) owner: Option<Arc<dyn ReloadComponent<cda_comm_can::CanTopology>>>,
}

#[cfg(feature = "can")]
#[async_trait]
impl<SP: SecurityPlugin> VehicleUpdateParticipant<SP> for CanParticipant {
    async fn preflight(
        &self,
        model: &VehicleModel<SP>,
        config: &Configuration,
    ) -> Result<Box<dyn ReadyToApply>, ReloadError> {
        match (
            &self.owner,
            model
                .can_topology(config)
                .await
                .map_err(|error| map_app_error(&error))?,
        ) {
            (Some(owner), Some(topology)) => Ok(Box::new(ComponentPayload {
                owner: Arc::clone(owner),
                data: topology,
            })),
            (None, None) => Ok(Box::new(NoopPayload)),
            _ => Err(ReloadError::ReplacementFailure(
                "Prepared CAN topology does not match the configured CAN owner".to_owned(),
            )),
        }
    }
}

#[cfg(feature = "can")]
struct NoopPayload;

#[cfg(feature = "can")]
#[async_trait]
impl ReadyToApply for NoopPayload {
    async fn apply(self: Box<Self>) {}
}

/// Coordinates shared model construction and opaque owner-specific participants.
pub struct CdaVehicleUpdatePreparation<SP: SecurityPlugin> {
    data_factory: Arc<CdaMainVehicleFactory<SP>>,
    participants: Vec<Arc<dyn VehicleUpdateParticipant<SP>>>,
}

impl<SP: SecurityPlugin> CdaVehicleUpdatePreparation<SP> {
    /// Creates an empty coordinator. Owners are registered independently in
    /// their required lifecycle order with [`Self::register_participant`].
    #[must_use]
    pub fn new(data_factory: Arc<CdaMainVehicleFactory<SP>>) -> Self {
        Self {
            data_factory,
            participants: Vec::new(),
        }
    }

    /// Registers one opaque owner-specific participant.
    pub fn register_participant(&mut self, participant: Arc<dyn VehicleUpdateParticipant<SP>>) {
        self.participants.push(participant);
    }
}

#[async_trait]
impl<SP> ApplicationUpdatePreparation<Configuration> for CdaVehicleUpdatePreparation<SP>
where
    SP: SecurityPlugin,
{
    async fn prepare_update(&self, config: &Configuration) -> Result<(), ReloadError> {
        let model = self.data_factory.create(config).await?;
        let mut ready = Vec::with_capacity(self.participants.len());
        for participant in &self.participants {
            ready.push(participant.preflight(&model, config).await?);
        }

        // Every fallible step is done. Applying is infallible and runs under
        // the caller's exclusive disable lease, with the transport down and
        // ordinary HTTP refused, so no reader can observe the sequence.
        for payload in ready {
            payload.apply().await;
        }
        Ok(())
    }
}
