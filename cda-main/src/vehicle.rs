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

use std::{sync::Arc, time::Duration};

#[cfg(feature = "can")]
use cda_comm_can::CanTopology;
use cda_comm_can::{CanDiagGateway, config::CanConfig};
use cda_comm_doip::{DoipDiagGateway, config::DoipConfig};
use cda_comm_uds::{UdsManager, VehicleEcuData, state_coordinator::EcuStateCoordinator};
use cda_core::EcuManager;
use cda_interfaces::{
    EcuRuntimeState, HashMap, HashMapExtensions, ReloadComponent, Reloadable,
    VariantDetectionReceiver, VariantDetectionSender,
    communication_control::CommunicationAccess,
    dlt_ctx,
    ecu_data::{EcuData, EcuDataView},
    health::HealthProvider,
    runtime_update_api::ReloadError,
};
use cda_plugin_security::SecurityPlugin;
use cda_sovd::SovdRegistryUpdate;
use cda_transport_router::DiagnosticTransportRouter;
use tokio::sync::{RwLock, mpsc};

use crate::{
    AppError, DOIP_HEALTH_COMPONENT_KEY,
    cda_factory::CdaMainVehicleFactory,
    config::configfile::Configuration,
    mdd::{self, load_databases},
};

pub type DatabaseMap<S> = HashMap<String, Arc<RwLock<EcuManager<S>>>>;

pub type UdsManagerType<S> = UdsManager<
    DiagnosticTransportRouter<DoipDiagGateway<EcuManager<S>>, CanDiagGateway>,
    EcuManager<S>,
>;

/// The vehicle's single diagnostic gateway, built once at startup.
pub type VehicleGateway<S> =
    DiagnosticTransportRouter<DoipDiagGateway<EcuManager<S>>, CanDiagGateway>;

pub struct VehicleGatewayParts<S: SecurityPlugin> {
    gateway: VehicleGateway<S>,
    #[cfg(feature = "can")]
    can_reload: Option<Arc<dyn ReloadComponent<CanTopology>>>,
}

pub struct VehicleData<S: SecurityPlugin> {
    pub diagnostic_gateway: Arc<VehicleGateway<S>>,
    pub lock_provider: Arc<cda_sovd::SovdLockStateView>,
    pub(crate) lock_updater:
        Arc<dyn cda_interfaces::runtime_update_api::VehicleDatabaseLockUpdater>,
    pub health_providers: Option<HashMap<String, Arc<dyn HealthProvider>>>,
    /// The process-wide vehicle-data factory used by startup and reload preparation.
    pub vehicle_factory: Arc<CdaMainVehicleFactory<S>>,
    pub(crate) ecu_data: Reloadable<VehicleEcuData<EcuManager<S>>>,
    pub(crate) uds_reload: Arc<dyn ReloadComponent<VehicleEcuData<EcuManager<S>>>>,
    pub(crate) initial_sovd_registry: SovdRegistryUpdate,
    #[cfg(feature = "can")]
    pub(crate) can_reload: Option<Arc<dyn ReloadComponent<CanTopology>>>,
    pub(crate) variant_detection_receiver: VariantDetectionReceiver,
}

/// Database-derived source model shared by independently registered update participants.
///
/// The model contains common immutable source state, not prebuilt owner payloads.
/// Each participant derives and validates only its own payload during preflight.
pub struct VehicleModel<S: SecurityPlugin> {
    databases: Arc<DatabaseMap<S>>,
    state_coordinator: Arc<EcuStateCoordinator>,
}

impl<S: SecurityPlugin> VehicleModel<S> {
    /// Derives the UDS ECU data for this model.
    #[must_use]
    pub fn ecu_data(&self, config: &Configuration) -> VehicleEcuData<EcuManager<S>> {
        EcuData::new(
            Arc::clone(&self.databases),
            &config.functional_description,
            config.faults.clone(),
            Arc::clone(&self.state_coordinator),
        )
    }

    /// Derives and validates the configured CAN topology for this model.
    ///
    /// # Errors
    /// Returns [`AppError`] when configured CAN topology cannot be derived.
    #[cfg(feature = "can")]
    pub async fn can_topology(
        &self,
        config: &Configuration,
    ) -> Result<Option<CanTopology>, AppError> {
        match config.can.as_ref() {
            Some(can) => Ok(Some(
                cda_comm_can::derive_can_topology(can, &self.databases).await?,
            )),
            None => Ok(None),
        }
    }

    /// Per-ECU transport overrides from application configuration.
    ///
    /// Read once: the configuration file is never reloaded, so the router has
    /// nothing to reinstall.
    #[must_use]
    pub fn transport_overrides(
        config: &Configuration,
    ) -> HashMap<String, cda_interfaces::TransportType> {
        let transport_overrides = config
            .can
            .as_ref()
            .map(|can| {
                can.transport_overrides
                    .iter()
                    .map(|entry| (entry.ecu_name.to_lowercase(), entry.transport))
                    .collect()
            })
            .unwrap_or_default();
        transport_overrides
    }

    /// Derives normalized SOVD ECU and functional-group membership.
    pub async fn sovd_registry(&self, config: &Configuration) -> SovdRegistryUpdate {
        build_sovd_registry_update(config, &self.databases).await
    }
}

/// The transport sections of the configuration, bundled for
/// [`create_diagnostic_gateway`] so its signature stays within clippy's
/// argument budget as transports are added.
pub struct TransportConfigs<'a> {
    pub doip: &'a DoipConfig,
    /// `None` disables the CAN transport (no `[can]` section).
    pub can: Option<&'a CanConfig>,
}

/// Registers the vehicle's health providers and returns handles to them.
///
/// Process-lifetime singletons: `HealthState` keeps a registration forever, so
/// this runs once at startup and every later reload reports on the same
/// handles.
///
/// # Errors
/// Returns [`AppError`] if a provider cannot be registered.
pub async fn register_health_providers(
    health: Option<&cda_health::HealthState>,
) -> Result<Option<HashMap<String, Arc<dyn HealthProvider>>>, AppError> {
    let Some(health_state) = health else {
        return Ok(None);
    };

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
    Ok(Some(providers))
}

/// Creates the process's single variant-detection channel.
///
/// Startup keeps the receiver for the lifetime of the `UdsManager`; every
/// gateway built afterwards sends on a clone of the returned sender, so the
/// retained listener cannot go deaf.
#[must_use]
pub fn variant_detection_channel() -> (VariantDetectionSender, VariantDetectionReceiver) {
    let (tx, rx) = mpsc::channel(50);
    (
        VariantDetectionSender::new(tx),
        VariantDetectionReceiver::new(rx),
    )
}

async fn seed_storage_if_configured(config: &Configuration) {
    if config.runtime_update_config.init_storage_from_database_path {
        mdd::seed_storage_from_database_path(
            &config.runtime_update_config.storage_dir,
            &config.database.seed_dir,
        )
        .await;
    }
}

/// Loads the vehicle at startup: creates the process-lifetime singletons, builds
/// the first ECU data through the same factory later reloads use,
/// and builds the one diagnostic gateway over it.
///
/// # Errors
/// Returns [`AppError`] if health registration, database loading, or transport
/// creation fails.
pub async fn load_vehicle_data<S: SecurityPlugin>(
    config: &Configuration,
    health: Option<&cda_health::HealthState>,
) -> Result<VehicleData<S>, AppError> {
    let health_providers = register_health_providers(health).await?;
    let (variant_detection_sender, variant_detection_receiver) = variant_detection_channel();

    seed_storage_if_configured(config).await;

    let vehicle_factory = Arc::new(CdaMainVehicleFactory::<S>::new(
        health_providers.clone(),
        variant_detection_sender.clone(),
    ));

    let reload_data = match vehicle_factory.create(config).await {
        Ok(data) => data,
        // Startup has nothing to roll back to, and refusing to boot would also
        // deny the operator the update endpoint that fixes the broken files.
        // A reload propagates the same error and rolls back instead.
        Err(error @ ReloadError::NoDatabasesLoaded(_)) => {
            tracing::error!(
                %error,
                "Every MDD file failed to load; starting with no ECU database. Push working \
                 files through the runtime-update endpoint to recover."
            );
            assemble_vehicle_model::<S>(
                Arc::new(HashMap::default()),
                variant_detection_sender.clone(),
            )
            .await
        }
        Err(error) => return Err(AppError::InitializationFailed(error.to_string())),
    };
    let initial_sovd_registry = reload_data.sovd_registry(config).await;
    let ecu_data = reload_data.ecu_data(config);
    // Startup only: a reload reports an empty result to its caller instead, so
    // an operator can never lose the running server by pushing an empty set.
    if ecu_data.ecus().is_empty() && config.database.exit_no_database_loaded {
        return Err(AppError::ResourceError(
            "No database loaded, exiting as configured".to_string(),
        ));
    }
    #[cfg(feature = "can")]
    let can_topology = reload_data.can_topology(config).await?;
    let ecu_names = ecu_data.ecu_names();
    let lock_parts = cda_sovd::new_sovd_lock_state(ecu_names);
    let uds_parts = cda_comm_uds::prepare_ecu_data(ecu_data);

    let doip_provider: Option<&Arc<dyn HealthProvider>> = health_providers
        .as_ref()
        .and_then(|h| h.get(DOIP_HEALTH_COMPONENT_KEY));

    // Gateway constructors are passive. Each long-lived owner receives only
    // the reload state it consumes.
    let gateway_parts = create_diagnostic_gateway(
        uds_parts.data.clone(),
        #[cfg(feature = "can")]
        can_topology,
        VehicleModel::<S>::transport_overrides(config),
        TransportConfigs {
            doip: &config.doip,
            can: config.can.as_ref(),
        },
        variant_detection_sender,
        doip_provider,
    )
    .await?;

    Ok(VehicleData {
        diagnostic_gateway: Arc::new(gateway_parts.gateway),
        // Startup topology A is live before any route is mounted.
        lock_provider: lock_parts.lock_state,
        lock_updater: lock_parts.updater,
        health_providers,
        vehicle_factory,
        ecu_data: uds_parts.data,
        uds_reload: uds_parts.reload,
        initial_sovd_registry,
        #[cfg(feature = "can")]
        can_reload: gateway_parts.can_reload,
        variant_detection_receiver,
    })
}

/// Builds installable ECU data from the configured MDD databases
/// currently on disk, wrapped with a fresh state coordinator.
///
/// Shared by startup and by every reload, through
/// [`CdaMainVehicleFactory`](crate::cda_factory::CdaMainVehicleFactory).
///
/// Never constructs a `UdsManager` or a gateway: both are built once at startup
/// and read whatever the last update applied to [`Reloadable`]. Carries no
/// `functional_group_config` because [`cda_sovd`] resolves that list live from
/// [`Configuration`].
///
/// An empty MDD set is allowed: a deployment may legitimately carry no
/// database. MDD files that were all rejected are not, and are reported as
/// [`AppError::NoDatabasesLoaded`] for each caller to act on.
///
/// # Errors
/// Returns [`AppError`] if database loading or CAN topology derivation fails,
/// or [`AppError::NoDatabasesLoaded`] if MDD files resolved but none loaded.
#[allow(
    clippy::implicit_hasher,
    reason = "Type alias doesn't allow specifying hasher"
)]
pub(crate) async fn create_vehicle_model<S: SecurityPlugin>(
    config: &Configuration,
    health_providers: Option<&HashMap<String, Arc<dyn HealthProvider>>>,
    variant_detection: VariantDetectionSender,
) -> Result<VehicleModel<S>, AppError> {
    let mdd_paths = mdd::resolve_configured_mdd_paths(config).await;
    let db_provider: Option<&Arc<dyn HealthProvider>> =
        health_providers.and_then(|h| h.get(mdd::DB_HEALTH_COMPONENT_KEY));
    let databases =
        Arc::new(load_databases::<S>(config, &mdd_paths, db_provider).await?);
    if !mdd_paths.is_empty() && databases.is_empty() {
        return Err(AppError::NoDatabasesLoaded {
            provided: mdd_paths.len(),
        });
    }

    Ok(assemble_vehicle_model::<S>(databases, variant_detection).await)
}

#[allow(
    clippy::implicit_hasher,
    reason = "Type alias doesn't allow specifying hasher"
)]
async fn assemble_vehicle_model<S: SecurityPlugin>(
    databases: Arc<DatabaseMap<S>>,
    variant_detection: VariantDetectionSender,
) -> VehicleModel<S> {
    let runtime_states = build_runtime_states(&databases).await;
    VehicleModel {
        databases,
        state_coordinator: Arc::new(EcuStateCoordinator::new(runtime_states, variant_detection)),
    }
}

async fn build_sovd_registry_update<S: SecurityPlugin>(
    config: &Configuration,
    databases: &DatabaseMap<S>,
) -> SovdRegistryUpdate {
    let description_name = &config.functional_description.description_database;
    let ecus = databases
        .keys()
        .filter(|name| !name.eq_ignore_ascii_case(description_name))
        .map(|name| (name.to_lowercase(), name.clone()))
        .collect();
    let functional_groups = if let Some(database) = databases.get(&description_name.to_lowercase())
    {
        cda_interfaces::ComponentInfos::functional_groups(&*database.read().await)
            .into_iter()
            .filter(|group| {
                config
                    .functional_description
                    .enabled_functional_groups
                    .as_ref()
                    .is_none_or(|enabled| {
                        enabled.iter().any(|name| name.eq_ignore_ascii_case(group))
                    })
            })
            .map(|group| (group.to_lowercase(), group))
            .collect()
    } else {
        HashMap::default()
    };
    SovdRegistryUpdate::new(ecus, functional_groups)
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
    diagnostic_gateway: Arc<VehicleGateway<S>>,
    ecu_data: Reloadable<VehicleEcuData<EcuManager<S>>>,
    variant_detection_receiver: VariantDetectionReceiver,
    config: &Configuration,
    communication_access: Arc<dyn CommunicationAccess>,
) -> UdsManagerType<S> {
    UdsManager::new(
        diagnostic_gateway,
        ecu_data,
        variant_detection_receiver,
        communication_access,
        Duration::from_secs(config.communication.deferred_retry_after_seconds),
    )
}

#[tracing::instrument(
    skip(
        ecu_data,
        can_topology,
        transports,
        variant_detection,
        doip_health_provider
    ),
    fields(dlt_context = dlt_ctx!("MAIN"))
)]
/// Builds the vehicle's one and only diagnostic gateway. Runs at startup only:
/// the transports read `ecu_data` per use, so a reload replaces what they read
/// rather than the gateway itself.
///
/// # Errors
/// Returns [`AppError`] if CAN configuration and topology presence differ, or
/// if the initialization of any configured transport fails. Transport init
/// failure is always fatal: a CDA that starts without one of its configured
/// transports cannot be told apart from a healthy one, and a supervisor
/// restart is what actually recovers transient causes.
pub async fn create_diagnostic_gateway<S: SecurityPlugin>(
    ecu_data: Reloadable<VehicleEcuData<EcuManager<S>>>,
    #[cfg(feature = "can")] can_topology: Option<CanTopology>,
    transport_overrides: HashMap<String, cda_interfaces::TransportType>,
    transports: TransportConfigs<'_>,
    variant_detection: VariantDetectionSender,
    doip_health_provider: Option<&Arc<dyn HealthProvider>>,
) -> Result<VehicleGatewayParts<S>, AppError> {
    let TransportConfigs {
        doip: doip_config,
        can: can_config,
    } = transports;
    #[cfg(feature = "can")]
    let can_transport = match (can_config, can_topology) {
        (Some(config), Some(topology)) => Some((config, topology)),
        (None, None) => None,
        (Some(_), None) => {
            return Err(AppError::InitializationFailed(
                "CAN topology missing while CAN transport is configured".to_owned(),
            ));
        }
        (None, Some(_)) => {
            return Err(AppError::InitializationFailed(
                "CAN topology present while CAN transport is not configured".to_owned(),
            ));
        }
    };
    // The router privately owns its installable bindings so transport instances
    // remain stable across updates.
    let mut gateway =
        DiagnosticTransportRouter::<DoipDiagGateway<EcuManager<S>>, CanDiagGateway>::new(
            transport_overrides,
        );
    #[cfg(feature = "can")]
    let mut can_reload = None;

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
        Arc::new(ecu_data.clone()),
        doip_config,
        variant_detection.clone(),
        doip_health_provider,
    )
    .await?
    {
        gateway = gateway.with_doip(doip);
    }

    #[cfg(feature = "can")]
    if let Some((can_cfg, topology)) = can_transport {
        let parts = init_can_gateway(topology, can_cfg, variant_detection)?;
        gateway = gateway.with_can(parts.gateway);
        can_reload = Some(parts.reload);
    }

    Ok(VehicleGatewayParts {
        gateway,
        #[cfg(feature = "can")]
        can_reload,
    })
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
    ecu_data: Arc<dyn EcuDataView<EcuManager<S>>>,
    doip_config: &DoipConfig,
    variant_detection: VariantDetectionSender,
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
    let result = DoipDiagGateway::new(doip_config, ecu_data, variant_detection).await;
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
///
/// The gateway reads the shared topology per use.
#[cfg(feature = "can")]
fn init_can_gateway(
    can_topology: CanTopology,
    can_cfg: &CanConfig,
    variant_detection: VariantDetectionSender,
) -> Result<cda_comm_can::CanGatewayParts, AppError> {
    match CanDiagGateway::new_managed(can_cfg, can_topology, variant_detection) {
        Ok(c) => {
            tracing::info!(interface = %can_cfg.interface, "CAN gateway initialized");
            Ok(c)
        }
        // Fatal; main reports the error on exit.
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use cda_interfaces::storage_api::{Collection as _, CollectionName, Storage as _};
    use cda_plugin_security::mock::TestSecurityPlugin;
    use cda_storage::LocalStorage;

    use super::*;

    fn config_for(database_dir: &std::path::Path, storage_dir: &std::path::Path) -> Configuration {
        let mut config = crate::config::default_config();
        config.database.seed_dir = database_dir.to_string_lossy().into_owned();
        config.runtime_update_config.storage_dir = storage_dir.to_string_lossy().into_owned();
        config
    }

    async fn create(
        database_dir: &std::path::Path,
        storage_dir: &std::path::Path,
    ) -> Result<VehicleModel<TestSecurityPlugin>, AppError> {
        let config = config_for(database_dir, storage_dir);
        let (sender, _receiver) = variant_detection_channel();
        create_vehicle_model::<TestSecurityPlugin>(&config, None, sender).await
    }

    #[tokio::test]
    async fn disabled_startup_seeding_leaves_storage_absent_and_uses_database_path() {
        let database_dir = tempfile::tempdir().expect("database dir");
        let storage_dir = tempfile::tempdir().expect("storage dir");
        let source = database_dir.path().join("ECU.mdd");
        std::fs::write(&source, b"source").expect("write source");
        let config = config_for(database_dir.path(), storage_dir.path());

        seed_storage_if_configured(&config).await;

        let storage = LocalStorage::new(storage_dir.path()).expect("storage");
        assert!(
            storage
                .get_collection(&CollectionName::DiagnosticDatabase)
                .await
                .is_err()
        );
        assert_eq!(
            mdd::resolve_configured_mdd_paths(&config).await,
            vec![source]
        );
    }

    #[tokio::test]
    async fn enabled_startup_seeding_is_transactional_and_existing_empty_is_authoritative() {
        let database_dir = tempfile::tempdir().expect("database dir");
        let storage_dir = tempfile::tempdir().expect("storage dir");
        std::fs::write(database_dir.path().join("ECU.mdd"), b"source").expect("write source");
        let mut config = config_for(database_dir.path(), storage_dir.path());
        config.runtime_update_config.init_storage_from_database_path = true;

        seed_storage_if_configured(&config).await;
        let storage = LocalStorage::new(storage_dir.path()).expect("storage");
        let collection = storage
            .get_collection(&CollectionName::DiagnosticDatabase)
            .await
            .expect("seeded collection");
        assert_eq!(collection.list().await.expect("list"), vec!["ecu.mdd"]);

        let empty_storage_dir = tempfile::tempdir().expect("empty storage dir");
        config.runtime_update_config.storage_dir =
            empty_storage_dir.path().to_string_lossy().into();
        let empty_storage = LocalStorage::new(empty_storage_dir.path()).expect("empty storage");
        empty_storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .expect("empty authoritative collection");
        seed_storage_if_configured(&config).await;
        seed_storage_if_configured(&config).await;
        let collection = empty_storage
            .get_collection(&CollectionName::DiagnosticDatabase)
            .await
            .expect("existing collection");
        assert!(collection.list().await.expect("list").is_empty());
        assert!(mdd::resolve_configured_mdd_paths(&config).await.is_empty());
    }

    #[tokio::test]
    async fn no_mdd_files_at_all_builds_an_empty_data() {
        let database_dir = tempfile::tempdir().expect("database dir");
        let storage_dir = tempfile::tempdir().expect("storage dir");

        let data = create(database_dir.path(), storage_dir.path())
            .await
            .expect("an empty MDD set is a legitimate state");

        assert!(data.databases.is_empty());
    }

    /// The reload path turns this into a refused update plus a rollback; an
    /// empty ECU set would instead return 404 for every request and report success.
    #[tokio::test]
    async fn provided_mdd_files_that_all_fail_to_load_are_rejected() {
        let database_dir = tempfile::tempdir().expect("database dir");
        let storage_dir = tempfile::tempdir().expect("storage dir");
        std::fs::write(database_dir.path().join("broken.mdd"), b"not an mdd file")
            .expect("write broken MDD");

        let Err(error) = create(database_dir.path(), storage_dir.path()).await else {
            panic!("MDD files were provided but none loaded, this must be an error");
        };

        assert!(
            matches!(error, AppError::NoDatabasesLoaded { provided: 1 }),
            "unexpected error: {error}"
        );
    }

    #[cfg(feature = "can")]
    async fn construct_gateway_for_can_presence(
        can_configured: bool,
        topology_present: bool,
    ) -> Result<VehicleGatewayParts<TestSecurityPlugin>, AppError> {
        let mut config = Configuration::default();
        config.doip.enabled = false;
        config.can = Some(CanConfig {
            ecu_mappings: vec![cda_comm_can::config::CanEcuMapping {
                ecu_name: "FLXC1000".to_owned(),
                request_id: 0x7E0,
                response_id: 0x7E8,
            }],
            ..CanConfig::default()
        });
        let databases = Arc::new(
            load_databases::<TestSecurityPlugin>(
                &config,
                &[std::path::PathBuf::from(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../testcontainer/odx/FLXC1000.mdd"
                ))],
                None,
            )
            .await?,
        );
        let (sender, _receiver) = variant_detection_channel();
        let model = assemble_vehicle_model(databases, sender.clone()).await;
        let topology = model
            .can_topology(&config)
            .await?
            .expect("fixture config includes CAN");
        let uds_parts = cda_comm_uds::prepare_ecu_data(model.ecu_data(&config));

        create_diagnostic_gateway::<TestSecurityPlugin>(
            uds_parts.data,
            topology_present.then_some(topology),
            VehicleModel::<TestSecurityPlugin>::transport_overrides(&config),
            TransportConfigs {
                doip: &config.doip,
                can: can_configured.then_some(config.can.as_ref().expect("CAN config")),
            },
            sender,
            None,
        )
        .await
    }

    #[cfg(feature = "can")]
    #[tokio::test]
    async fn gateway_rejects_can_config_without_topology() {
        let Err(error) = construct_gateway_for_can_presence(true, false).await else {
            panic!("CAN configuration without topology must be rejected");
        };

        assert!(
            error
                .to_string()
                .contains("CAN topology missing while CAN transport is configured"),
            "unexpected error: {error}"
        );
    }

    #[cfg(feature = "can")]
    #[tokio::test]
    async fn gateway_rejects_can_topology_without_config() {
        let Err(error) = construct_gateway_for_can_presence(false, true).await else {
            panic!("CAN topology without configuration must be rejected");
        };

        assert!(
            error
                .to_string()
                .contains("CAN topology present while CAN transport is not configured"),
            "unexpected error: {error}"
        );
    }

    #[cfg(feature = "can")]
    #[tokio::test]
    async fn gateway_without_can_config_or_topology_has_no_can_component() {
        let parts = construct_gateway_for_can_presence(false, false)
            .await
            .expect("matching CAN absence must remain valid");

        assert!(parts.can_reload.is_none());
    }

    #[cfg(feature = "can")]
    #[tokio::test]
    async fn gateway_with_can_config_and_topology_has_can_component() {
        let parts = construct_gateway_for_can_presence(true, true)
            .await
            .expect("matching CAN presence must remain valid");

        assert!(parts.can_reload.is_some());
    }

    #[cfg(feature = "can")]
    #[tokio::test]
    async fn provided_mdd_files_that_all_fail_with_can_report_no_databases() {
        let database_dir = tempfile::tempdir().expect("database dir");
        let storage_dir = tempfile::tempdir().expect("storage dir");
        std::fs::write(database_dir.path().join("broken.mdd"), b"not an mdd file")
            .expect("write broken MDD");
        let mut config = config_for(database_dir.path(), storage_dir.path());
        config.can = Some(CanConfig::default());
        let (sender, _receiver) = variant_detection_channel();

        let Err(error) =
            create_vehicle_model::<TestSecurityPlugin>(&config, None, sender)
                .await
        else {
            panic!("MDD files were provided but none loaded, this must be an error");
        };

        assert!(
            matches!(error, AppError::NoDatabasesLoaded { provided: 1 }),
            "unexpected error: {error}"
        );
    }
}
