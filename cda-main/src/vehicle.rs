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
//! Everything here is `pub(crate)` on purpose. These items name concrete
//! transport and manager types (`DoipDiagGateway`, `CanDiagGateway`,
//! `DiagnosticTransportRouter`, `UdsManager`), so any change to the transport
//! stack changes their signatures. An integration that built against them would
//! break on every such refactor - which is exactly what happened before
//! [`crate::extensions`] existed.
//!
//! Integrations reach the same capabilities through the extension context, which
//! is expressed in traits and survives these changes.

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

pub(crate) type DatabaseMap<S> = HashMap<String, RwLock<EcuManager<S>>>;
pub(crate) type FileManagerMap = HashMap<String, FileManager>;

pub(crate) type UdsManagerType<S> = UdsManager<
    DiagnosticTransportRouter<DoipDiagGateway<EcuManager<S>>, CanDiagGateway>,
    EcuManager<S>,
>;

pub(crate) struct VehicleData<S: SecurityPlugin> {
    pub(crate) diagnostic_gateway:
        ComponentSlot<DiagnosticTransportRouter<DoipDiagGateway<EcuManager<S>>, CanDiagGateway>>,
    pub(crate) locks: Arc<Locks>,
    pub(crate) prepared: PreparedVehicleComponents<S>,
    pub(crate) databases: Arc<DatabaseMap<S>>,
    pub(crate) health_providers: Option<HashMap<String, Arc<dyn HealthProvider>>>,
}

pub(crate) struct VehicleComponents<S: SecurityPlugin> {
    pub(crate) uds_manager: UdsManagerType<S>,
    pub(crate) diagnostic_gateway:
        DiagnosticTransportRouter<DoipDiagGateway<EcuManager<S>>, CanDiagGateway>,
    pub(crate) file_managers: FileManagerMap,
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
pub(crate) struct TransportConfigs<'a> {
    pub(crate) doip: &'a DoipConfig,
    /// `None` disables the CAN transport (no `[can]` section).
    pub(crate) can: Option<&'a CanConfig>,
}

/// Loads vehicle data including MDD databases and vehicle components.
///
/// # Errors
/// Returns [`AppError`] if MDD path resolution, database loading, or component creation fails.
pub(crate) async fn load_vehicle_data<S: SecurityPlugin>(
    config: &Configuration,
    health: Option<&cda_health::HealthState>,
) -> Result<VehicleData<S>, AppError> {
    let mdd_paths: Vec<PathBuf> = {
        let storage_dir = &config.runtime_update_config.storage_dir;
        let paths = resolve_mdd_paths(storage_dir, &config.database.path).await;
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

    // Gateway constructors are passive. The selected plugin is built before consumers receive
    // narrow views over the communication framework.
    let gateway = ComponentSlot::new(prepared.diagnostic_gateway.clone());
    Ok(VehicleData {
        diagnostic_gateway: gateway,
        // Empty on purpose: ECU lock entries are created lazily on first use, and
        // the real topology arrives via `Locks::update_entries` when vehicle routes
        // are published. A lock cannot be taken on an unknown ECU regardless, since
        // routes are registered per ECU.
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
pub(crate) fn create_uds_manager<S: SecurityPlugin>(
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
pub(crate) async fn create_vehicle_components<S: SecurityPlugin>(
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

// The UDS manager (and, through it, the SOVD routes built from it in
// `setup::setup_runtime_routes`) is constructed eagerly here regardless of
// `init_mode`, pointed at a gateway that is network-inert until an
// authorized `activate()`/`trigger_detection()` binds its DoIP socket (see
// `init_doip_gateway`). No network activity is possible before authorization (the
// lazy socket above), and no ECU data is served either.
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
pub(crate) async fn create_diagnostic_gateway<S: SecurityPlugin>(
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
    // Build the diagnostic transport router skeleton, then populate the configured
    // transports. ECUs route over CAN or DoIP per `transport_overrides`,
    // defaulting to DoIP-preferred with CAN fallback.
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

/// Constructs the (passive) `DoIP` gateway, reporting the attempt on the
/// health provider. Returns `Ok(None)` when `DoIP` is disabled by config; in
/// that CAN-only operation (`validate_sanity` rejects configs with no
/// transport at all) the health provider is marked `Up` immediately so
/// readiness (/health/ready) does not wait forever on an intentionally
/// disabled transport.
///
/// Does not bind a UDP socket, broadcast VIR, connect to any ECU, or start
/// any listener: [`DoipDiagGateway::new`] is purely in-memory. Those all
/// happen lazily inside the gateway's own `enable()`, reached only through an
/// authorized `CommunicationPlugin::activate()`/`trigger_detection()` (see
/// ADR-006). This function is therefore safe to call unconditionally at
/// startup regardless of `init_mode`.
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
