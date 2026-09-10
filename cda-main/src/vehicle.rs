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

use cda_comm_can::{CanDiagGateway, config::CanConfig};
use cda_comm_doip::{DoipDiagGateway, config::DoipConfig};
use cda_comm_uds::{UdsManager, VehicleEcuData, state_coordinator::EcuStateCoordinator};
use cda_core::EcuManager;
#[cfg(feature = "can")]
use cda_interfaces::ReloadComponent;
use cda_interfaces::{
    EcuRuntimeState, HashMap, HashMapExtensions, HashSet, Reloadable, VariantDetectionReceiver,
    VariantDetectionSender, communication_control::CommunicationAccess, dlt_ctx, ecu_data::EcuData,
    health::HealthProvider, runtime_update_api::RuntimeFileInspector,
};
use cda_plugin_security::SecurityPlugin;
use cda_sovd::SovdIdentities;
use cda_transport_router::DiagnosticTransportRouter;
use tokio::sync::{RwLock, mpsc};

use crate::{
    AppError,
    config::configfile::Configuration,
    mdd::{self, DatabaseLoadError, load_databases},
};

pub type DatabaseMap<S> = HashMap<String, RwLock<EcuManager<S>>>;

/// The vehicle's single diagnostic gateway, built once at startup.
pub type VehicleGateway<S> =
    DiagnosticTransportRouter<DoipDiagGateway<EcuManager<S>, EcuStateCoordinator>, CanDiagGateway>;

pub type UdsManagerType<S> = UdsManager<VehicleGateway<S>, EcuManager<S>>;

/// The CAN topology a reload replaces, degrading to `()` on a build without
/// CAN support.
#[cfg(feature = "can")]
pub type CanTopologyPayload = cda_comm_can::CanTopology;
/// The CAN topology a reload replaces, degrading to `()` on a build without
/// CAN support.
#[cfg(not(feature = "can"))]
pub type CanTopologyPayload = ();

/// The authority to replace the live CAN topology, `None` when the application
/// is configured without CAN and degrading to `()` on a build without CAN
/// support.
#[cfg(feature = "can")]
pub type CanReloadHandle = Option<Arc<dyn ReloadComponent<CanTopologyPayload>>>;
/// The authority to replace the live CAN topology, `None` when the application
/// is configured without CAN and degrading to `()` on a build without CAN
/// support.
#[cfg(not(feature = "can"))]
pub type CanReloadHandle = ();

/// The database-derived source a reload's participants share.
///
/// Holds common immutable source state, not prebuilt owner payloads: each
/// participant derives and validates only its own payload during preflight.
pub struct VehicleDataSource<S: SecurityPlugin> {
    databases: DatabaseMap<S>,
    state_coordinator: Arc<EcuStateCoordinator>,
}

impl<S: SecurityPlugin> VehicleDataSource<S> {
    /// Derives the UDS ECU data for this source.
    ///
    /// Consumes the source: the databases move into the UDS data, which owns them
    /// until a runtime update replaces it. Derive the other payloads first.
    #[must_use]
    pub fn ecu_data(self, config: &Configuration) -> VehicleEcuData<EcuManager<S>> {
        EcuData::new(
            self.databases,
            &config.functional_description,
            config.faults.clone(),
            self.state_coordinator,
        )
    }

    /// Derives and validates the configured CAN topology for this source.
    ///
    /// Always `None` on a build without CAN, so callers need no feature guard.
    ///
    /// # Errors
    /// Returns [`CanGatewaySetupError`](cda_comm_can::error::CanGatewaySetupError)
    /// when configured CAN topology cannot be derived.
    #[cfg_attr(
        not(feature = "can"),
        allow(
            unused_variables,
            clippy::unused_async,
            reason = "no CAN support: there is no topology to derive from the configuration"
        )
    )]
    pub async fn can_topology(
        &self,
        config: &Configuration,
    ) -> Result<Option<CanTopologyPayload>, AppError> {
        #[cfg(feature = "can")]
        match config.can.as_ref() {
            Some(can) => Ok(Some(
                cda_comm_can::derive_can_topology(can, &self.databases).await?,
            )),
            None => Ok(None),
        }
        #[cfg(not(feature = "can"))]
        Ok(None)
    }

    /// Derives normalized SOVD ECU and functional-group membership.
    pub async fn sovd_registry(&self, config: &Configuration) -> SovdIdentities {
        build_sovd_identities(config, &self.databases).await
    }
}

/// Per-ECU transport overrides from application configuration.
///
/// Read once: the configuration file is never reloaded, so the router has
/// nothing to reinstall. Derived from configuration alone, so it does not
/// belong to any one vehicle model.
#[must_use]
pub fn transport_overrides(
    config: &Configuration,
) -> HashMap<String, cda_interfaces::TransportType> {
    config
        .can
        .as_ref()
        .map(|can| {
            can.transport_overrides
                .iter()
                .map(|entry| (entry.ecu_name.to_lowercase(), entry.transport))
                .collect()
        })
        .unwrap_or_default()
}

/// The transport sections of the configuration, bundled for
/// [`create_diagnostic_gateway`] so its signature stays within clippy's
/// argument budget as transports are added.
pub struct TransportConfigs<'a> {
    pub doip: &'a DoipConfig,
    /// `None` disables the CAN transport (no `[can]` section).
    pub can: Option<&'a CanConfig>,
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

/// Builds installable ECU data from the configured MDD databases
/// currently on disk, wrapped with a fresh state coordinator.
///
/// Shared by startup and by every reload, through
/// [`VehicleDatabaseLoader`](crate::database_reload::VehicleDatabaseLoader).
///
/// Never constructs a `UdsManager` or a gateway: both are built once at startup
/// and read whatever the last update applied to [`Reloadable`]. Carries no
/// `functional_group_config` because [`cda_sovd`] resolves that list live from
/// [`Configuration`].
///
/// An empty MDD set is allowed: a deployment may legitimately carry no
/// database. MDD files that were all rejected are not, and are reported as
/// [`DatabaseLoadError::NoDatabasesLoaded`] for each caller to act on.
///
/// # Errors
/// Returns [`DatabaseLoadError`] if database loading fails, or
/// [`DatabaseLoadError::NoDatabasesLoaded`] if MDD files resolved but none loaded.
#[allow(
    clippy::implicit_hasher,
    reason = "Type alias doesn't allow specifying hasher"
)]
pub(crate) async fn load_vehicle_databases<S: SecurityPlugin>(
    config: &Configuration,
    health_providers: Option<&HashMap<String, Arc<dyn HealthProvider>>>,
    variant_detection: VariantDetectionSender,
    file_inspector: &dyn RuntimeFileInspector,
) -> Result<VehicleDataSource<S>, DatabaseLoadError> {
    let mdd_paths = mdd::resolve_mdd_paths(
        &config.runtime_update_config.storage_dir,
        &config.database.seed_dir,
    )
    .await;
    let db_provider: Option<&Arc<dyn HealthProvider>> =
        health_providers.and_then(|h| h.get(mdd::DB_HEALTH_COMPONENT_KEY));
    let databases = load_databases::<S>(config, &mdd_paths, db_provider, file_inspector).await?;
    if !mdd_paths.is_empty() && databases.is_empty() {
        return Err(DatabaseLoadError::NoDatabasesLoaded {
            provided: mdd_paths.len(),
        });
    }

    Ok(assemble_vehicle_data_source::<S>(databases, variant_detection).await)
}

/// The vehicle every reloadable owner starts on, before any database is loaded.
pub(crate) async fn empty_vehicle_data_source<S: SecurityPlugin>(
    variant_detection: VariantDetectionSender,
) -> VehicleDataSource<S> {
    assemble_vehicle_data_source::<S>(HashMap::default(), variant_detection).await
}

#[allow(
    clippy::implicit_hasher,
    reason = "Type alias doesn't allow specifying hasher"
)]
async fn assemble_vehicle_data_source<S: SecurityPlugin>(
    databases: DatabaseMap<S>,
    variant_detection: VariantDetectionSender,
) -> VehicleDataSource<S> {
    let runtime_states = build_runtime_states(&databases).await;
    VehicleDataSource {
        databases,
        state_coordinator: Arc::new(EcuStateCoordinator::new(runtime_states, variant_detection)),
    }
}

async fn build_sovd_identities<S: SecurityPlugin>(
    config: &Configuration,
    databases: &DatabaseMap<S>,
) -> SovdIdentities {
    let description_name = &config.functional_description.description_database;
    // `databases` is keyed by the lowercased ECU name, which is the only name a
    // SOVD consumer needs; the registry normalizes again on its own.
    let ecus = databases
        .keys()
        .filter(|name| !name.eq_ignore_ascii_case(description_name))
        .cloned()
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
            .map(|group| group.to_lowercase())
            .collect()
    } else {
        HashSet::default()
    };
    SovdIdentities::new(ecus, functional_groups)
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

// The UDS manager, and the SOVD routes the `SovdApi` stage builds
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
/// Returns the gateway and the authority to replace its CAN topology.
///
/// # Errors
/// Returns [`AppError`] if CAN configuration and topology presence differ, or
/// if the initialization of any configured transport fails. Transport init
/// failure is always fatal: a CDA that starts without one of its configured
/// transports cannot be told apart from a healthy one, and a supervisor
/// restart is what actually recovers transient causes.
#[allow(
    clippy::implicit_hasher,
    reason = "Type alias doesn't allow specifying hasher"
)]
#[cfg_attr(
    not(feature = "can"),
    allow(
        unused_variables,
        reason = "no CAN support: the topology degrades to `()` and no transport consumes it"
    )
)]
pub async fn create_diagnostic_gateway<S: SecurityPlugin>(
    ecu_data: Reloadable<VehicleEcuData<EcuManager<S>>>,
    can_topology: Option<CanTopologyPayload>,
    transport_overrides: HashMap<String, cda_interfaces::TransportType>,
    transports: TransportConfigs<'_>,
    variant_detection: VariantDetectionSender,
    doip_health_provider: Option<&Arc<dyn HealthProvider>>,
) -> Result<(VehicleGateway<S>, CanReloadHandle), AppError> {
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
    let mut gateway = DiagnosticTransportRouter::<
        DoipDiagGateway<EcuManager<S>, EcuStateCoordinator>,
        CanDiagGateway,
    >::new(transport_overrides);

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
        ecu_data.clone(),
        doip_config,
        variant_detection.clone(),
        doip_health_provider,
    )
    .await?
    {
        gateway = gateway.with_doip(doip);
    }

    #[cfg(feature = "can")]
    let can_reload = if let Some((can_cfg, topology)) = can_transport {
        let (can_gateway, reload) = init_can_gateway(topology, can_cfg, variant_detection)?;
        gateway = gateway.with_can(can_gateway);
        Some(reload)
    } else {
        None
    };
    #[cfg(not(feature = "can"))]
    #[allow(
        clippy::let_unit_value,
        reason = "no CAN support: the handle is a unit placeholder keeping one return shape"
    )]
    let can_reload = CanReloadHandle::default();

    Ok((gateway, can_reload))
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
    ecu_data: Reloadable<VehicleEcuData<EcuManager<S>>>,
    doip_config: &DoipConfig,
    variant_detection: VariantDetectionSender,
    doip_health_provider: Option<&Arc<dyn HealthProvider>>,
) -> Result<Option<DoipDiagGateway<EcuManager<S>, EcuStateCoordinator>>, AppError> {
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
    can_topology: CanTopologyPayload,
    can_cfg: &CanConfig,
    variant_detection: VariantDetectionSender,
) -> Result<(CanDiagGateway, Arc<dyn ReloadComponent<CanTopologyPayload>>), AppError> {
    match CanDiagGateway::build(can_cfg, can_topology, variant_detection) {
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
    use cda_interfaces::storage_api::{CollectionName, Storage as _};
    use cda_plugin_security::mock::TestSecurityPlugin;
    use cda_storage::LocalStorage;

    use super::*;
    use crate::mdd_inspector::MddFileInspector;

    fn config_for(database_dir: &std::path::Path, storage_dir: &std::path::Path) -> Configuration {
        let mut config = crate::config::default_config();
        config.database.seed_dir = database_dir.to_string_lossy().into_owned();
        config.runtime_update_config.storage_dir = storage_dir.to_string_lossy().into_owned();
        config
    }

    async fn load_test_db(
        database_dir: &std::path::Path,
        storage_dir: &std::path::Path,
    ) -> Result<VehicleDataSource<TestSecurityPlugin>, DatabaseLoadError> {
        let config = config_for(database_dir, storage_dir);
        let (sender, _receiver) = variant_detection_channel();
        load_vehicle_databases::<TestSecurityPlugin>(&config, None, sender, &MddFileInspector).await
    }

    /// An applied empty database set survives a restart: an existing storage
    /// collection is authoritative, so nothing reseeds it from the database dir.
    #[tokio::test]
    async fn existing_empty_storage_is_not_reseeded_from_the_database_dir() {
        let database_dir = tempfile::tempdir().expect("database dir");
        let storage_dir = tempfile::tempdir().expect("storage dir");
        std::fs::write(database_dir.path().join("ECU.mdd"), b"source").expect("write source");
        let storage = LocalStorage::new(storage_dir.path()).expect("storage");
        storage
            .get_or_create_collection(&CollectionName::DiagnosticDatabase)
            .await
            .expect("empty collection");
        drop(storage);

        for _ in 0..2 {
            let resolved = mdd::resolve_mdd_paths(
                &storage_dir.path().to_string_lossy(),
                &database_dir.path().to_string_lossy(),
            )
            .await;
            assert!(
                resolved.is_empty(),
                "an existing collection must stay authoritative: {resolved:?}"
            );
        }
    }

    /// The reload path turns this into a refused update plus a rollback; an
    /// empty ECU set would instead return 404 for every request and report success.
    #[tokio::test]
    async fn provided_mdd_files_that_all_fail_to_load_are_rejected() {
        let database_dir = tempfile::tempdir().expect("database dir");
        let storage_dir = tempfile::tempdir().expect("storage dir");
        std::fs::write(database_dir.path().join("broken.mdd"), b"not an mdd file")
            .expect("write broken MDD");

        let Err(error) = load_test_db(database_dir.path(), storage_dir.path()).await else {
            panic!("MDD files were provided but none loaded, this must be an error");
        };

        assert!(
            matches!(error, DatabaseLoadError::NoDatabasesLoaded { provided: 1 }),
            "unexpected error: {error}"
        );
    }

    #[cfg(feature = "can")]
    async fn construct_gateway_for_can_presence(
        can_configured: bool,
        topology_present: bool,
    ) -> Result<(VehicleGateway<TestSecurityPlugin>, CanReloadHandle), AppError> {
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
        let databases = load_databases::<TestSecurityPlugin>(
            &config,
            &[std::path::PathBuf::from(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../testcontainer/odx/FLXC1000.mdd"
            ))],
            None,
            &MddFileInspector,
        )
        .await?;
        let (sender, _receiver) = variant_detection_channel();
        let model = assemble_vehicle_data_source(databases, sender.clone()).await;
        let topology = model
            .can_topology(&config)
            .await?
            .expect("fixture config includes CAN");
        let (ecu_data, _uds_reload) = cda_comm_uds::prepare_ecu_data(model.ecu_data(&config));

        create_diagnostic_gateway::<TestSecurityPlugin>(
            ecu_data,
            topology_present.then_some(topology),
            transport_overrides(&config),
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
        let (_gateway, can_reload) = construct_gateway_for_can_presence(false, false)
            .await
            .expect("matching CAN absence must remain valid");

        assert!(can_reload.is_none());
    }

    #[cfg(feature = "can")]
    #[tokio::test]
    async fn gateway_with_can_config_and_topology_has_can_component() {
        let (_gateway, can_reload) = construct_gateway_for_can_presence(true, true)
            .await
            .expect("matching CAN presence must remain valid");

        assert!(can_reload.is_some());
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
            load_vehicle_databases::<TestSecurityPlugin>(&config, None, sender, &MddFileInspector)
                .await
        else {
            panic!("MDD files were provided but none loaded, this must be an error");
        };

        assert!(
            matches!(error, DatabaseLoadError::NoDatabasesLoaded { provided: 1 }),
            "unexpected error: {error}"
        );
    }
}
