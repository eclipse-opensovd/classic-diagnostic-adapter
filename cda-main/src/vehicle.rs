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

//! Construction of the live vehicle: databases, transports, gateway, UDS manager.
//!
//! The construction surface names concrete transport and manager types, so its
//! signatures reflect the configured transport stack.

use std::{path::PathBuf, sync::Arc, time::Duration};

use cda_comm_can::{CanDiagGateway, config::CanConfig};
use cda_comm_doip::{DoipDiagGateway, config::DoipConfig};
use cda_comm_uds::{UdsManager, state_coordinator::EcuStateCoordinator};
use cda_core::EcuManager;
use cda_database::FileManager;
use cda_interfaces::{
    EcuConnectivityHandler, EcuRuntimeState, FunctionalDescriptionConfig, HashMap,
    HashMapExtensions, TransportType, VariantDetectionReceiver, VariantDetectionSender,
    communication_control::CommunicationAccess, component_slot::ComponentSlot,
    datatypes::FaultConfig, dlt_ctx, health::HealthProvider,
};
use cda_plugin_security::SecurityPlugin;
use cda_sovd::Locks;
use cda_transport_router::DiagnosticTransportRouter;
use tokio::sync::{RwLock, mpsc};

use crate::{
    AppError, DOIP_HEALTH_COMPONENT_KEY,
    config::configfile::Configuration,
    mdd::{self, load_databases, resolve_mdd_paths},
};

pub type DatabaseMap<S> = HashMap<String, RwLock<EcuManager<S>>>;
pub type FileManagerMap = HashMap<String, FileManager>;

pub type UdsManagerType<S> = UdsManager<
    DiagnosticTransportRouter<DoipDiagGateway<EcuManager<S>>, CanDiagGateway>,
    EcuManager<S>,
>;

pub struct VehicleData<S: SecurityPlugin> {
    pub diagnostic_gateway:
        ComponentSlot<DiagnosticTransportRouter<DoipDiagGateway<EcuManager<S>>, CanDiagGateway>>,
    pub locks: Arc<Locks>,
    pub(crate) prepared: PreparedVehicleComponents<S>,
    pub databases: Arc<DatabaseMap<S>>,
    pub health_providers: Option<HashMap<String, Arc<dyn HealthProvider>>>,
}

pub struct VehicleComponents<S: SecurityPlugin> {
    pub uds_manager: UdsManagerType<S>,
    pub diagnostic_gateway:
        DiagnosticTransportRouter<DoipDiagGateway<EcuManager<S>>, CanDiagGateway>,
    pub file_managers: FileManagerMap,
}

pub(crate) struct PreparedVehicleComponents<S: SecurityPlugin> {
    databases: Arc<DatabaseMap<S>>,
    file_managers: FileManagerMap,
    diagnostic_gateway: DiagnosticTransportRouter<DoipDiagGateway<EcuManager<S>>, CanDiagGateway>,
    variant_detection_rx: VariantDetectionReceiver,
    state_coordinator: EcuStateCoordinator,
}

/// The transport sections of the configuration, bundled for
/// [`create_diagnostic_gateway`] so its signature stays within clippy's
/// argument budget as transports are added.
pub struct TransportConfigs<'a> {
    pub doip: &'a DoipConfig,
    /// `None` disables the CAN transport (no `[can]` section).
    pub can: Option<&'a CanConfig>,
}

/// Loads vehicle data including MDD databases and vehicle components.
///
/// # Errors
/// Returns [`AppError`] if MDD path resolution, database loading, or component creation fails.
pub async fn load_vehicle_data<S: SecurityPlugin>(
    config: &Configuration,
    health: Option<&cda_health::HealthState>,
) -> Result<VehicleData<S>, AppError> {
    let mdd_paths: Vec<PathBuf> = {
        let storage_dir = &config.runtime_update_config.storage_dir;
        let paths = resolve_mdd_paths(storage_dir, &config.database.seed_dir).await;
        if paths.is_empty() && config.database.exit_no_database_loaded {
            return Err(AppError::InitializationFailed(
                "No MDD files found".to_string(),
            ));
        }
        paths
    };

    let health_providers = if let Some(health_state) = health {
        let doip = Arc::new(cda_health::StatusHealthProvider::new(
            cda_health::Status::Starting,
        ));
        let database = Arc::new(cda_health::StatusHealthProvider::new(
            cda_health::Status::Starting,
        ));
        health_state
            .register_provider(
                DOIP_HEALTH_COMPONENT_KEY,
                Arc::clone(&doip) as Arc<dyn cda_health::HealthProvider>,
            )
            .await
            .map_err(|e| AppError::InitializationFailed(e.to_string()))?;
        health_state
            .register_provider(
                mdd::DB_HEALTH_COMPONENT_KEY,
                Arc::clone(&database) as Arc<dyn cda_health::HealthProvider>,
            )
            .await
            .map_err(|e| AppError::InitializationFailed(e.to_string()))?;
        let mut providers: HashMap<String, Arc<dyn HealthProvider>> = HashMap::default();
        providers.insert(
            DOIP_HEALTH_COMPONENT_KEY.to_owned(),
            doip as Arc<dyn HealthProvider>,
        );
        providers.insert(
            mdd::DB_HEALTH_COMPONENT_KEY.to_owned(),
            database as Arc<dyn HealthProvider>,
        );
        Some(providers)
    } else {
        None
    };

    let prepared =
        prepare_vehicle_components::<S>(config, &mdd_paths, health_providers.as_ref()).await?;

    // Gateway constructors are passive. The selected plugin is built before
    // consumers receive narrow views over the communication framework.
    let gateway = ComponentSlot::new(prepared.diagnostic_gateway.clone());
    Ok(VehicleData {
        diagnostic_gateway: gateway,
        // Empty on purpose: the real topology arrives via `Locks::update_entries`
        // when vehicle routes are published.
        locks: Arc::new(Locks::new(Vec::new())),
        databases: Arc::clone(&prepared.databases),
        health_providers,
        prepared,
    })
}

#[allow(
    clippy::implicit_hasher,
    reason = "Type alias does not allow specifying hasher. Hasher is set globally"
)]
#[tracing::instrument(skip_all,
    fields(
        database_count = databases.len(),
        dlt_context = dlt_ctx!("MAIN"),
    )
)]
#[allow(
    clippy::too_many_arguments,
    reason = "Combining parameters into a struct is not preferred here, to keep constructor call \
              semantics explicit"
)]
pub fn create_uds_manager<S: SecurityPlugin>(
    gateway: DiagnosticTransportRouter<DoipDiagGateway<EcuManager<S>>, CanDiagGateway>,
    databases: Arc<HashMap<String, RwLock<EcuManager<S>>>>,
    variant_detection_receiver: VariantDetectionReceiver,
    state_coordinator: EcuStateCoordinator,
    functional_description_config: &FunctionalDescriptionConfig,
    fault_config: FaultConfig,
    communication_access: Arc<dyn CommunicationAccess>,
    communication_retry_after: Duration,
) -> UdsManagerType<S> {
    UdsManager::new(
        gateway,
        databases,
        variant_detection_receiver,
        state_coordinator,
        functional_description_config,
        fault_config,
        communication_access,
        communication_retry_after,
    )
}

/// Creates vehicle components (databases, `DoIP` gateway, UDS manager) from configuration.
///
/// # Errors
/// Returns [`AppError`] if database loading or diagnostic gateway creation fails.
#[allow(
    clippy::implicit_hasher,
    reason = "Type alias doesn't allow specifying hasher"
)]
pub async fn create_vehicle_components<S: SecurityPlugin>(
    config: &Configuration,
    mdd_paths: &[PathBuf],
    health_providers: Option<&HashMap<String, Arc<dyn HealthProvider>>>,
    communication_access: Arc<dyn CommunicationAccess>,
) -> Result<VehicleComponents<S>, AppError> {
    let prepared = prepare_vehicle_components(config, mdd_paths, health_providers).await?;
    Ok(finish_vehicle_components(
        prepared,
        config,
        communication_access,
    ))
}

async fn prepare_vehicle_components<S: SecurityPlugin>(
    config: &Configuration,
    mdd_paths: &[PathBuf],
    health_providers: Option<&HashMap<String, Arc<dyn HealthProvider>>>,
) -> Result<PreparedVehicleComponents<S>, AppError> {
    let db_provider: Option<&Arc<dyn HealthProvider>> =
        health_providers.and_then(|h| h.get(mdd::DB_HEALTH_COMPONENT_KEY));
    let doip_provider: Option<&Arc<dyn HealthProvider>> =
        health_providers.and_then(|h| h.get(DOIP_HEALTH_COMPONENT_KEY));

    let (databases, file_managers) = load_databases::<S>(config, mdd_paths, db_provider).await?;

    let (variant_detection_tx, variant_detection_rx) = mpsc::channel(50);
    let variant_detection_tx = VariantDetectionSender::new(variant_detection_tx);
    let variant_detection_rx = VariantDetectionReceiver::new(variant_detection_rx);
    let databases = Arc::new(databases);

    let runtime_states = build_runtime_states(&databases).await;
    let state_coordinator = EcuStateCoordinator::new(runtime_states, variant_detection_tx.clone());
    let connectivity_handler: Arc<dyn EcuConnectivityHandler> = Arc::new(state_coordinator.clone());

    let diagnostic_gateway = create_diagnostic_gateway(
        Arc::clone(&databases),
        TransportConfigs {
            doip: &config.doip,
            can: config.can.as_ref(),
        },
        variant_detection_tx,
        connectivity_handler,
        doip_provider,
    )
    .await?;

    Ok(PreparedVehicleComponents {
        databases,
        file_managers,
        diagnostic_gateway,
        variant_detection_rx,
        state_coordinator,
    })
}

async fn build_runtime_states<S: SecurityPlugin>(
    databases: &DatabaseMap<S>,
) -> HashMap<String, EcuRuntimeState> {
    let mut states = HashMap::new();
    for (ecu_name, ecu_lock) in databases {
        states.insert(ecu_name.clone(), ecu_lock.read().await.runtime_state());
    }
    states
}

// The UDS manager, and the SOVD routes `setup::setup_runtime_routes` builds
// from it, are constructed eagerly regardless of `init_mode`, pointed at a
// gateway that stays network-inert until an authorized
// `activate()`/`trigger_detection()` binds its DoIP socket (see
// `init_doip_gateway`).
pub(crate) fn finish_vehicle_components<S: SecurityPlugin>(
    prepared: PreparedVehicleComponents<S>,
    config: &Configuration,
    communication_access: Arc<dyn CommunicationAccess>,
) -> VehicleComponents<S> {
    let uds_manager = create_uds_manager(
        prepared.diagnostic_gateway.clone(),
        Arc::clone(&prepared.databases),
        prepared.variant_detection_rx,
        prepared.state_coordinator,
        &config.functional_description,
        config.faults.clone(),
        communication_access,
        Duration::from_secs(config.communication.deferred_retry_after_seconds),
    );
    VehicleComponents {
        uds_manager,
        diagnostic_gateway: prepared.diagnostic_gateway,
        file_managers: prepared.file_managers,
    }
}

#[tracing::instrument(
    skip(databases, transports, variant_detection, connectivity_handler, doip_health_provider),
    fields(
        database_count = databases.len(),
        dlt_context = dlt_ctx!("MAIN"),
    )
)]
/// # Errors
/// Returns [`AppError`] if the initialization of any configured transport
/// fails. Transport init failure is always fatal: a CDA that starts without
/// one of its configured transports cannot be told apart from a healthy one,
/// and a supervisor restart is what actually recovers transient causes.
pub async fn create_diagnostic_gateway<S: SecurityPlugin>(
    databases: Arc<DatabaseMap<S>>,
    transports: TransportConfigs<'_>,
    variant_detection: VariantDetectionSender,
    connectivity_handler: Arc<dyn EcuConnectivityHandler>,
    doip_health_provider: Option<&Arc<dyn HealthProvider>>,
) -> Result<DiagnosticTransportRouter<DoipDiagGateway<EcuManager<S>>, CanDiagGateway>, AppError> {
    let TransportConfigs {
        doip: doip_config,
        can: can_config,
    } = transports;
    // Transport owners remain stable while routing bindings are updated in place.
    let transport_overrides: HashMap<String, TransportType> = can_config
        .map(|c| {
            c.transport_overrides
                .iter()
                .map(|o| (o.ecu_name.to_lowercase(), o.transport))
                .collect()
        })
        .unwrap_or_default();

    let mut gateway =
        DiagnosticTransportRouter::<DoipDiagGateway<EcuManager<S>>, CanDiagGateway>::new(
            transport_overrides,
        );

    // Fail clearly when CAN is configured on a build without CAN support.
    // (validate_sanity rejects this too; kept as defense in depth for direct
    // callers of this function.)
    #[cfg(not(feature = "can"))]
    if can_config.is_some() {
        return Err(AppError::ConfigurationError {
            message: "[can] is configured, but this binary was built without CAN support. Rebuild \
                      with `--features can` or remove the [can] section."
                .to_owned(),
            source: None,
        });
    }

    if let Some(doip) = init_doip_gateway(
        &databases,
        doip_config,
        variant_detection.clone(),
        connectivity_handler,
        doip_health_provider,
    )
    .await?
    {
        gateway = gateway.with_doip(doip);
    }

    #[cfg(feature = "can")]
    if let Some(can_cfg) = can_config {
        gateway = gateway.with_can(init_can_gateway(&databases, can_cfg, variant_detection).await?);
    }

    Ok(gateway)
}

/// Constructs the (passive) `DoIP` gateway, reporting the attempt on the health
/// provider. Returns `Ok(None)` when `DoIP` is disabled by config, marking the
/// health provider `Up` immediately so that readiness does not wait forever on
/// an intentionally disabled transport.
///
/// [`DoipDiagGateway::new`] is purely in-memory. Binding the UDP socket,
/// broadcasting VIR and starting listeners all happen lazily in the gateway's
/// own `enable()`, reached only through an authorized `activate()` or
/// `trigger_detection()`. Safe to call at startup in any `init_mode`.
async fn init_doip_gateway<S: SecurityPlugin>(
    databases: &Arc<DatabaseMap<S>>,
    doip_config: &DoipConfig,
    variant_detection: VariantDetectionSender,
    connectivity_handler: Arc<dyn EcuConnectivityHandler>,
    doip_health_provider: Option<&Arc<dyn HealthProvider>>,
) -> Result<Option<DoipDiagGateway<EcuManager<S>>>, AppError> {
    if !doip_config.enabled {
        tracing::info!("DoIP transport disabled by config (doip.enabled = false)");
        if let Some(provider) = doip_health_provider {
            provider.set_status(cda_health::Status::Up).await;
        }
        return Ok(None);
    }

    if let Some(provider) = doip_health_provider {
        provider.set_status(cda_health::Status::Starting).await;
    }
    let result = DoipDiagGateway::new(
        doip_config,
        Arc::clone(databases),
        variant_detection,
        connectivity_handler,
    )
    .await;
    let status = if result.is_ok() {
        cda_health::Status::Up
    } else {
        cda_health::Status::Failed
    };
    if let Some(provider) = doip_health_provider {
        provider.set_status(status).await;
    }
    match result {
        Ok(d) => {
            tracing::info!("DoIP gateway initialized");
            Ok(Some(d))
        }
        // Fatal; main reports the error on exit.
        Err(e) => Err(e.into()),
    }
}

/// Initializes the CAN transport. Like for `DoIP`, an init failure is fatal.
#[cfg(feature = "can")]
async fn init_can_gateway<S: SecurityPlugin>(
    databases: &Arc<DatabaseMap<S>>,
    can_cfg: &CanConfig,
    variant_detection: VariantDetectionSender,
) -> Result<CanDiagGateway, AppError> {
    match CanDiagGateway::new(can_cfg, databases, variant_detection).await {
        Ok(c) => {
            tracing::info!(interface = %can_cfg.interface, "CAN gateway initialized");
            Ok(c)
        }
        // Fatal; main reports the error on exit.
        Err(e) => Err(e.into()),
    }
}
