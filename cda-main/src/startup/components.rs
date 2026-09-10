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

//! The CDA's components, each naming its stage and what it hands over.
//!
//! No component states an order against another one. Its [`CdaStage`] places it
//! against everything outside that stage, and inside a stage nothing is
//! ordered; the graph those stages form lives in `cda-lifecycle`. What a
//! component reads it takes out of the view its stage constructs through, which
//! holds what the stages before it published and nothing else.
//!
//! Work is split between the two halves the same way throughout: `construct`
//! builds the values other components require, and `start` begins whatever this
//! component then does with them. Both run in the same order, so a component
//! whose real work happens on start is still placed by where it is constructed.

use std::{marker::PhantomData, sync::Arc, time::Duration};

use async_trait::async_trait;
use cda_comm_uds::VehicleEcuData;
use cda_core::EcuManager;
use cda_interfaces::{
    ReloadComponent, ShutdownSignal, VariantDetectionReceiver, VariantDetectionSender,
    communication_control::{
        CommunicationAccess, CommunicationInitMode, DisableCommunication, TransportControl,
    },
    health::HealthStatus,
    http_protection::registry::HttpProtectionRegistry,
    lifecycle::{Constructed, ConstructedComponent, LifecycleError, StageResources},
    runtime_update_api::{
        ReloadError, RuntimeFileTransaction, RuntimeFilesUpdatePlugin, VehicleDatabaseLockUpdater,
    },
    util::std_ext,
};
use cda_lifecycle::{
    CdaEvent, CdaLeasePolicy, CdaStage, Component, EcuDataReload, EcuRevisions, HttpProtector,
    LifecycleHandle, LifecycleManager, LifecycleManagerConfig, ReloadExecutionMode,
};
use cda_plugin_communication_management::{
    lifecycle::disable::CommunicationDisableView,
    plugin::{CommunicationPlugin, CommunicationPluginBuilder},
};
use cda_plugin_security::{SecurityPlugin, SecurityPluginLoader};
use cda_sovd::{SovdLockStateView, SovdRegistry, dynamic_router::DynamicRouter};
use cda_storage::LocalStorage;

use crate::{
    AppError,
    config::configfile::Configuration,
    database_reload::{PreparedVehicleData, VehicleDatabaseLoader},
    setup,
    startup::{
        CONSTRUCT, EVENT, START, STOP, WebServer, failed,
        health::Health,
        resources::{
            CanReload, CdaLifecycle, EcuDataCell, FileTransaction, UdsManagerHandle, UpdatePlugin,
            VersionData,
        },
    },
    update::{LifecycleUpdateDispatcher, UpdatePluginBuilder, UpdatePluginResources},
    vehicle::{self, UdsManagerType, VehicleGateway},
};

/// Provides the router every route-mounting component mounts on, and the
/// listener holder the accept loop hands its task to.
///
/// The router half of the webserver. It is early because the components that
/// mount routes require what it provides; the half that accepts is
/// [`AcceptLoop`], which is late for the opposite reason.
pub(crate) struct HttpRouter {
    health: Arc<Health>,
}

/// Publishes the process's own health under `main`.
struct MainHealth {
    health: Arc<Health>,
}

#[async_trait]
impl ConstructedComponent<CdaEvent> for MainHealth {
    fn name(&self) -> &'static str {
        "main"
    }

    fn health(&self) -> Option<Arc<dyn HealthStatus>> {
        self.health.main_status()
    }
}

#[async_trait]
impl Component<CdaEvent> for HttpRouter {
    type Provides = (Arc<DynamicRouter>, Arc<WebServer>);

    fn name(&self) -> &'static str {
        "main"
    }

    fn stage(&self) -> CdaStage {
        CdaStage::Transports
    }

    async fn construct(
        self,
        _resources: &StageResources<'_>,
    ) -> Result<Constructed<Self::Provides, CdaEvent>, LifecycleError> {
        let provides = (Arc::new(DynamicRouter::new()), Arc::new(WebServer::new()));
        Ok(
            Constructed::new(provides).with_component(Arc::new(MainHealth {
                health: self.health,
            })),
        )
    }
}

impl HttpRouter {
    pub(crate) fn new(health: Arc<Health>) -> Self {
        Self { health }
    }
}

/// Starts accepting connections, and stops accepting them first.
///
/// Its stage follows the one that mounts the static routes, so the port opens
/// only once they answer, and because stop is the exact reverse of start it
/// stops before them and before the communication runtime it reads. The SOVD
/// vehicle routes are deliberately later; they mount against an empty vehicle
/// while the server already answers, as they always have.
pub(crate) struct AcceptLoop {
    config: Arc<Configuration>,
}

struct Listener {
    config: Arc<Configuration>,
    router: Arc<DynamicRouter>,
    webserver: Arc<WebServer>,
    shutdown_signal: Arc<ShutdownSignal>,
}

#[async_trait]
impl ConstructedComponent<CdaEvent> for Listener {
    fn name(&self) -> &'static str {
        "http-listener"
    }

    async fn start(&self) -> Result<(), LifecycleError> {
        let webserver_config = cda_sovd::WebServerConfig {
            host: self.config.server.address.clone(),
            port: self.config.server.port,
        };
        let task = cda_sovd::launch_webserver(
            (*self.router).clone(),
            webserver_config,
            self.webserver.serve_until(&self.shutdown_signal),
        )
        .await
        .map_err(|error| failed(self.name(), START, AppError::from(error)))?;
        self.webserver.install(task);
        Ok(())
    }

    async fn stop(&self) -> Result<(), LifecycleError> {
        self.webserver
            .drain()
            .await
            .map_err(|error| failed(self.name(), STOP, error))
    }
}

#[async_trait]
impl Component<CdaEvent> for AcceptLoop {
    type Provides = ();

    fn name(&self) -> &'static str {
        "http-listener"
    }

    fn stage(&self) -> CdaStage {
        CdaStage::Serving
    }

    async fn construct(
        self,
        resources: &StageResources<'_>,
    ) -> Result<Constructed<Self::Provides, CdaEvent>, LifecycleError> {
        let router = resources.get::<DynamicRouter>()?;
        let webserver = resources.get::<WebServer>()?;
        let shutdown_signal = resources.get::<ShutdownSignal>()?;
        // Read and dropped: asking for it is the assertion that the
        // communication runtime is built in an earlier stage, and stop being
        // the reverse of start is what makes the listener stop before it.
        let _access = resources.get::<dyn CommunicationAccess>()?;
        Ok(Constructed::new(()).with_component(Arc::new(Listener {
            config: self.config,
            router,
            webserver,
            shutdown_signal,
        })))
    }
}

impl AcceptLoop {
    pub(crate) fn new(config: Arc<Configuration>) -> Self {
        Self { config }
    }
}

/// Builds the vehicle's one diagnostic gateway. Binds nothing.
///
/// Constructible before any database exists: the transports read the ECU data
/// owner per use, so a load replaces what they read rather than the gateway.
pub(crate) struct Transport<SP: SecurityPlugin> {
    config: Arc<Configuration>,
    variant_detection: VariantDetectionSender,
    health: Arc<Health>,
    _phantom: PhantomData<fn() -> SP>,
}

struct DoipHealth {
    health: Arc<Health>,
}

#[async_trait]
impl ConstructedComponent<CdaEvent> for DoipHealth {
    fn name(&self) -> &'static str {
        crate::DOIP_HEALTH_COMPONENT_KEY
    }

    fn health(&self) -> Option<Arc<dyn HealthStatus>> {
        self.health.doip_status()
    }
}

#[async_trait]
impl<SP: SecurityPlugin> Component<CdaEvent> for Transport<SP> {
    type Provides = (Arc<VehicleGateway<SP>>, Arc<CanReload>);

    fn name(&self) -> &'static str {
        crate::DOIP_HEALTH_COMPONENT_KEY
    }

    fn stage(&self) -> CdaStage {
        CdaStage::Transports
    }

    async fn construct(
        self,
        resources: &StageResources<'_>,
    ) -> Result<Constructed<Self::Provides, CdaEvent>, LifecycleError> {
        let ecu_data = resources.get::<EcuDataCell<SP>>()?;
        let name = self.name();
        let doip_provider = self.health.doip();
        let (gateway, can_owner) = vehicle::create_diagnostic_gateway::<SP>(
            ecu_data.0.clone(),
            startup_topology(&self.config),
            vehicle::transport_overrides(&self.config),
            vehicle::TransportConfigs {
                doip: &self.config.doip,
                can: self.config.can.as_ref(),
            },
            self.variant_detection,
            doip_provider.as_ref(),
        )
        .await
        .map_err(|error| failed(name, CONSTRUCT, error))?;

        let provides = (Arc::new(gateway), Arc::new(CanReload(can_owner)));
        Ok(
            Constructed::new(provides).with_component(Arc::new(DoipHealth {
                health: self.health,
            })),
        )
    }
}

impl<SP: SecurityPlugin> Transport<SP> {
    pub(crate) fn new(
        config: Arc<Configuration>,
        variant_detection: VariantDetectionSender,
        health: Arc<Health>,
    ) -> Self {
        Self {
            config,
            variant_detection,
            health,
            _phantom: PhantomData,
        }
    }
}

/// The topology the CAN gateway is built on, before any database exists.
#[cfg(feature = "can")]
fn startup_topology(config: &Configuration) -> Option<vehicle::CanTopologyPayload> {
    config
        .can
        .as_ref()
        .map(|_| cda_comm_can::CanTopology::empty())
}

#[cfg(not(feature = "can"))]
#[allow(
    clippy::missing_const_for_fn,
    reason = "the CAN-enabled counterpart reads the configuration"
)]
fn startup_topology(_config: &Configuration) -> Option<vehicle::CanTopologyPayload> {
    None
}

/// Builds the communication runtime and the narrow access view over it.
pub(crate) struct Communication<CPB: CommunicationPluginBuilder, SP: SecurityPlugin> {
    config: Arc<Configuration>,
    builder: CPB,
    _phantom: PhantomData<fn() -> SP>,
}

/// Takes the communication runtime down, before anything it talks over.
struct CommunicationRuntime {
    plugin: Arc<dyn CommunicationPlugin>,
}

#[async_trait]
impl ConstructedComponent<CdaEvent> for CommunicationRuntime {
    fn name(&self) -> &'static str {
        "communication-runtime"
    }

    async fn stop(&self) -> Result<(), LifecycleError> {
        cda_interfaces::Shutdown::shutdown(&*self.plugin).await;
        Ok(())
    }
}

#[async_trait]
impl<CPB: CommunicationPluginBuilder + 'static, SP: SecurityPlugin> Component<CdaEvent>
    for Communication<CPB, SP>
{
    type Provides = (
        Arc<dyn CommunicationPlugin>,
        Arc<dyn CommunicationAccess>,
        Arc<dyn DisableCommunication>,
    );

    fn name(&self) -> &'static str {
        "communication-runtime"
    }

    fn stage(&self) -> CdaStage {
        CdaStage::CommunicationRuntime
    }

    async fn construct(
        self,
        resources: &StageResources<'_>,
    ) -> Result<Constructed<Self::Provides, CdaEvent>, LifecycleError> {
        let router = resources.get::<DynamicRouter>()?;
        let protections = resources.get::<HttpProtectionRegistry>()?;
        let gateway = resources.get::<VehicleGateway<SP>>()?;
        let name = self.name();
        let (runtime, access) = setup::build_communication_runtime_and_access(
            &router,
            gateway as Arc<dyn TransportControl>,
            self.builder,
            self.config.communication.init_mode,
            self.config.communication.variant_detection,
            Duration::from_secs(self.config.communication.deferred_retry_after_seconds),
            &protections,
        )
        .await
        .map_err(|error| failed(name, CONSTRUCT, error))?;

        let disable: Arc<dyn DisableCommunication> =
            Arc::new(CommunicationDisableView::new(Arc::clone(&runtime.plugin)));
        let component = Arc::new(CommunicationRuntime {
            plugin: Arc::clone(&runtime.plugin),
        });
        Ok(Constructed::new((runtime.plugin, access, disable)).with_component(component))
    }
}

impl<CPB: CommunicationPluginBuilder, SP: SecurityPlugin> Communication<CPB, SP> {
    pub(crate) fn new(config: Arc<Configuration>, builder: CPB) -> Self {
        Self {
            config,
            builder,
            _phantom: PhantomData,
        }
    }
}

/// Spawns the lifecycle manager that dispatches the runtime's events.
///
/// A component, because the manager needs the exclusive disable lease from the
/// communication runtime and the update plugin needs the manager, and both are
/// then values handed over in stage order instead of a slot each.
pub(crate) struct Lifecycle;

#[async_trait]
impl Component<CdaEvent> for Lifecycle {
    type Provides = (Arc<CdaLifecycle>, Arc<LifecycleHandle<CdaEvent>>);

    fn name(&self) -> &'static str {
        "lifecycle-manager"
    }

    fn stage(&self) -> CdaStage {
        CdaStage::LifecycleManager
    }

    async fn construct(
        self,
        resources: &StageResources<'_>,
    ) -> Result<Constructed<Self::Provides, CdaEvent>, LifecycleError> {
        let protections = resources.get::<HttpProtectionRegistry>()?;
        let communication = resources.get::<dyn DisableCommunication>()?;
        let handle = LifecycleManager::new(LifecycleManagerConfig {
            http_protector: Arc::new((*protections).clone()) as Arc<dyn HttpProtector>,
            communication,
            lease_policy: Arc::new(CdaLeasePolicy),
            // Activation is what decides the transport's final state, so the
            // lease is handed back before that stage rather than after it.
            lease_released_before: Some(CdaStage::Activation),
        })
        .spawn();

        let provides = (Arc::new(CdaLifecycle(handle.downgrade())), Arc::new(handle));
        Ok(Constructed::new(provides))
    }
}

/// Builds the runtime-update plugin, and with it the storage it owns.
///
/// The storage is a [`LocalStorage`] rooted where the configuration says, which
/// is why the plugin is built here and not before the configuration is read.
pub(crate) struct Storage<UPB: UpdatePluginBuilder<LocalStorage>> {
    config: Arc<Configuration>,
    builder: Option<UPB>,
    file_inspector: Arc<dyn cda_interfaces::runtime_update_api::RuntimeFileInspector>,
}

#[async_trait]
impl<UPB: UpdatePluginBuilder<LocalStorage> + 'static> Component<CdaEvent> for Storage<UPB> {
    type Provides = (Arc<UpdatePlugin<UPB::Plugin>>, Arc<FileTransaction>);

    fn name(&self) -> &'static str {
        "storage"
    }

    fn stage(&self) -> CdaStage {
        CdaStage::Storage
    }

    async fn construct(
        self,
        resources: &StageResources<'_>,
    ) -> Result<Constructed<Self::Provides, CdaEvent>, LifecycleError> {
        let lifecycle = resources.get::<CdaLifecycle>()?;
        let lock_provider = resources.get::<SovdLockStateView>()?;
        let name = self.name();
        let plugin = match self.builder {
            // Without a plugin there is nothing to write, so the storage
            // directory is never touched.
            None => None,
            Some(builder) => {
                let storage = LocalStorage::new(&self.config.runtime_update_config.storage_dir)
                    .map_err(|error| {
                        let message = format!("Failed to init storage, error={error:?}");
                        failed(name, CONSTRUCT, AppError::InitializationFailed(message))
                    })?;
                let resources = UpdatePluginResources {
                    storage: Arc::new(storage),
                    update_dispatcher: Arc::new(LifecycleUpdateDispatcher::new(
                        lifecycle.handle(),
                        cda_lifecycle::UpdateHttpProtection {
                            // Which routes stay reachable while an update holds
                            // its protection is a SOVD fact, so it is supplied
                            // here.
                            exempt_routes: cda_sovd::routes_accessible_during_update(),
                            retry_after: Duration::from_secs(
                                self.config.runtime_update_config.retry_after_seconds,
                            ),
                        },
                        self.config.communication.post_update_mode.clone(),
                    )),
                    file_inspector: self.file_inspector,
                    lock_provider,
                };
                let plugin = builder
                    .build(resources)
                    .await
                    .map_err(|error| failed(name, CONSTRUCT, error))?;
                Some(Arc::new(plugin.with_exclusive_access()))
            }
        };

        let transaction = plugin
            .as_ref()
            .map(|plugin| Arc::clone(plugin) as Arc<dyn RuntimeFileTransaction>);
        let provides = (
            Arc::new(UpdatePlugin(plugin)),
            Arc::new(FileTransaction(transaction)),
        );
        Ok(Constructed::new(provides))
    }
}

impl<UPB: UpdatePluginBuilder<LocalStorage>> Storage<UPB> {
    pub(crate) fn new(
        config: Arc<Configuration>,
        builder: Option<UPB>,
        file_inspector: Arc<dyn cda_interfaces::runtime_update_api::RuntimeFileInspector>,
    ) -> Self {
        Self {
            config,
            builder,
            file_inspector,
        }
    }
}

/// Mounts the HTTP that does not depend on ECU data.
pub(crate) struct StaticApi<SL: SecurityPluginLoader, P: RuntimeFilesUpdatePlugin> {
    config: Arc<Configuration>,
    health: Arc<Health>,
    _phantom: PhantomData<fn() -> (SL, P)>,
}

#[async_trait]
impl<SL: SecurityPluginLoader, P: RuntimeFilesUpdatePlugin> Component<CdaEvent>
    for StaticApi<SL, P>
{
    type Provides = ();

    fn name(&self) -> &'static str {
        "static-api"
    }

    fn stage(&self) -> CdaStage {
        CdaStage::StaticApi
    }

    async fn construct(
        self,
        resources: &StageResources<'_>,
    ) -> Result<Constructed<Self::Provides, CdaEvent>, LifecycleError> {
        let router = resources.get::<DynamicRouter>()?;
        let plugin = resources.get::<UpdatePlugin<P>>()?;
        let lock_provider = resources.get::<SovdLockStateView>()?;
        let registry = resources.get::<SovdRegistry>()?;
        let version = resources.get::<VersionData>()?;
        self.health.mount(&router).await;
        crate::register_version_endpoints(&router, version.0.clone()).await;

        if let Some(plugin) = plugin.0.as_ref() {
            crate::update::add_runtime_update_routes::<SL, _>(
                &router,
                Arc::clone(plugin),
                lock_provider,
                self.config.runtime_update_config.upload_body_limit_bytes,
                Duration::from_secs(self.config.runtime_update_config.retry_after_seconds),
            )
            .await;
        }

        cda_sovd::add_openapi_routes(&router, registry.view()).await;
        Ok(Constructed::new(()))
    }
}

impl<SL: SecurityPluginLoader, P: RuntimeFilesUpdatePlugin> StaticApi<SL, P> {
    pub(crate) fn new(config: Arc<Configuration>, health: Arc<Health>) -> Self {
        Self {
            config,
            health,
            _phantom: PhantomData,
        }
    }
}

/// The database-file transaction. Startup applies no files, so it is only a
/// reload or a cleanup that reaches storage here.
pub(crate) struct DatabaseFiles;

struct FileTransactions {
    name: &'static str,
    transaction: Arc<FileTransaction>,
}

impl FileTransactions {
    fn files(&self) -> Result<&Arc<dyn RuntimeFileTransaction>, LifecycleError> {
        self.transaction.0.as_ref().ok_or_else(|| {
            failed(
                self.name,
                EVENT,
                AppError::InitializationFailed(
                    "The application runs without a runtime-update plugin, so no execution can \
                     move files"
                        .to_owned(),
                ),
            )
        })
    }

    fn report(&self, error: &dyn std::fmt::Display) -> LifecycleError {
        failed(self.name, EVENT, AppError::RuntimeError(error.to_string()))
    }
}

#[async_trait]
impl ConstructedComponent<CdaEvent> for FileTransactions {
    fn name(&self) -> &'static str {
        self.name
    }

    async fn on_event(&self, event: &CdaEvent) -> Result<(), LifecycleError> {
        let outcome = match event {
            CdaEvent::ReloadEcuData(reload) => match reload.mode {
                ReloadExecutionMode::Apply => self.files()?.apply_files().await,
                ReloadExecutionMode::Rollback => self.files()?.rollback_files().await,
            },
            CdaEvent::CleanupFiles(_) => self.files()?.cleanup_files().await,
            _ => return Ok(()),
        };
        outcome.map_err(|error| self.report(&error))
    }

    /// A later component failed, so the files go back to what the live
    /// components still hold.
    ///
    /// Nothing is reloaded afterwards: the load happens in `EcuData` and is
    /// committed in `Diagnostics`, so a failure at or before those leaves the
    /// live components on the previous data and restoring the files is what
    /// makes disk and memory agree again.
    async fn revert(&self, event: &CdaEvent) -> Result<(), LifecycleError> {
        let CdaEvent::ReloadEcuData(reload) = event else {
            return Ok(());
        };
        let restored = match reload.mode {
            ReloadExecutionMode::Apply => self.files()?.restore_after_apply().await,
            ReloadExecutionMode::Rollback => self.files()?.restore_after_rollback().await,
        };
        restored.map_err(|error| self.report(&error))
    }
}

#[async_trait]
impl Component<CdaEvent> for DatabaseFiles {
    type Provides = ();

    fn name(&self) -> &'static str {
        "database-files"
    }

    fn stage(&self) -> CdaStage {
        CdaStage::DatabaseFiles
    }

    async fn construct(
        self,
        resources: &StageResources<'_>,
    ) -> Result<Constructed<Self::Provides, CdaEvent>, LifecycleError> {
        let transaction = resources.get::<FileTransaction>()?;
        Ok(
            Constructed::new(()).with_component(Arc::new(FileTransactions {
                name: self.name(),
                transaction,
            })),
        )
    }
}

/// Commits a rollback by discarding the staged set.
///
/// Its stage follows the one that makes a reload live, and deliberately: a
/// rollback is only committed once the runtime has accepted the restored
/// databases. Doing it in the same transaction as the restore would leave a
/// rejected rollback partially applied, because recovering from one swaps
/// current and backup back but cannot bring the staged set back.
pub(crate) struct StagedFiles;

struct DiscardStaged {
    files: FileTransactions,
}

#[async_trait]
impl ConstructedComponent<CdaEvent> for DiscardStaged {
    fn name(&self) -> &'static str {
        "staged-files"
    }

    async fn on_event(&self, event: &CdaEvent) -> Result<(), LifecycleError> {
        let CdaEvent::ReloadEcuData(reload) = event else {
            return Ok(());
        };
        if reload.mode != ReloadExecutionMode::Rollback {
            return Ok(());
        }
        self.files
            .files()?
            .discard_staged()
            .await
            .map_err(|error| self.files.report(&error))
    }
}

#[async_trait]
impl Component<CdaEvent> for StagedFiles {
    type Provides = ();

    fn name(&self) -> &'static str {
        "staged-files"
    }

    fn stage(&self) -> CdaStage {
        CdaStage::StagedFiles
    }

    async fn construct(
        self,
        resources: &StageResources<'_>,
    ) -> Result<Constructed<Self::Provides, CdaEvent>, LifecycleError> {
        let transaction = resources.get::<FileTransaction>()?;
        Ok(Constructed::new(()).with_component(Arc::new(DiscardStaged {
            files: FileTransactions {
                name: self.name(),
                transaction,
            },
        })))
    }
}

/// Builds the UDS manager over the gateway and registers the communication
/// hooks it owns, and is what makes a prepared reload live.
///
/// Its stage follows the one that reads the databases, because what a reload
/// prepares there is committed here.
pub(crate) struct Diagnostics<SP: SecurityPlugin> {
    config: Arc<Configuration>,
    variant_detection_receiver: VariantDetectionReceiver,
    _phantom: PhantomData<fn() -> SP>,
}

/// Makes a prepared reload live, and puts back what it displaced.
struct CommitEcuData<SP: SecurityPlugin> {
    uds_reload: Arc<dyn ReloadComponent<VehicleEcuData<EcuManager<SP>>>>,
    sovd_registry: Arc<SovdRegistry>,
    can_reload: Arc<CanReload>,
}

impl<SP: SecurityPlugin> CommitEcuData<SP> {
    /// Makes the data the load prepared live.
    ///
    /// Nothing here can fail: every fallible step ran while the data was being
    /// built, and this runs under the dispatch's exclusive lease with the
    /// transport down and ordinary HTTP refused, so no reader observes a
    /// half-replaced runtime.
    async fn install(&self, reload: &EcuDataReload) -> Result<(), LifecycleError> {
        let Some(prepared) = reload.prepared.take::<PreparedVehicleData<SP>>() else {
            return Err(failed(
                self.name(),
                EVENT,
                AppError::InitializationFailed(
                    "The load did not park any prepared ECU data on the reload".to_owned(),
                ),
            ));
        };

        prepared.lock_reservation.apply();
        if let Some(displaced) = self.uds_reload.swap(prepared.ecu_data).await {
            reload.outgoing.retain(displaced);
        }
        self.can_reload.install(prepared.can_topology).await;
        self.sovd_registry.apply(prepared.identities).await;
        Ok(())
    }
}

#[async_trait]
impl<SP: SecurityPlugin> ConstructedComponent<CdaEvent> for CommitEcuData<SP> {
    fn name(&self) -> &'static str {
        "diagnostics"
    }

    async fn on_event(&self, event: &CdaEvent) -> Result<(), LifecycleError> {
        let CdaEvent::ReloadEcuData(reload) = event else {
            return Ok(());
        };
        self.install(reload).await
    }

    /// A later component failed, so the ECU data goes back to what it
    /// displaced.
    ///
    /// Only the ECU data can be handed back: the SOVD identities and the CAN
    /// topology are derived from it, and their owners replace rather than swap,
    /// so the next successful reload is what re-derives them.
    async fn revert(&self, event: &CdaEvent) -> Result<(), LifecycleError> {
        let CdaEvent::ReloadEcuData(reload) = event else {
            return Ok(());
        };
        let Some(previous) = reload.outgoing.take::<VehicleEcuData<EcuManager<SP>>>() else {
            return Ok(());
        };
        self.uds_reload.apply(previous).await;
        Ok(())
    }
}

#[async_trait]
impl<SP: SecurityPlugin> Component<CdaEvent> for Diagnostics<SP> {
    type Provides = Arc<UdsManagerHandle<SP>>;

    fn name(&self) -> &'static str {
        "diagnostics"
    }

    fn stage(&self) -> CdaStage {
        CdaStage::Diagnostics
    }

    async fn construct(
        self,
        resources: &StageResources<'_>,
    ) -> Result<Constructed<Self::Provides, CdaEvent>, LifecycleError> {
        let gateway = resources.get::<VehicleGateway<SP>>()?;
        let access = resources.get::<dyn CommunicationAccess>()?;
        let plugin = resources.get::<dyn CommunicationPlugin>()?;
        let ecu_data = resources.get::<EcuDataCell<SP>>()?;
        let uds_reload = resources.get::<dyn ReloadComponent<VehicleEcuData<EcuManager<SP>>>>()?;
        let sovd_registry = resources.get::<SovdRegistry>()?;
        let can_reload = resources.get::<CanReload>()?;
        let name = self.name();
        let uds_manager = vehicle::finish_vehicle_components(
            gateway,
            ecu_data.0.clone(),
            self.variant_detection_receiver,
            &self.config,
            access,
        );
        setup::register_communication_hooks(&plugin, &uds_manager)
            .await
            .map_err(|error| failed(name, CONSTRUCT, error))?;

        let provides = Arc::new(UdsManagerHandle(uds_manager));
        Ok(
            Constructed::new(provides).with_component(Arc::new(CommitEcuData::<SP> {
                uds_reload,
                sovd_registry,
                can_reload,
            })),
        )
    }
}

impl<SP: SecurityPlugin> Diagnostics<SP> {
    pub(crate) fn new(
        config: Arc<Configuration>,
        variant_detection_receiver: VariantDetectionReceiver,
    ) -> Self {
        Self {
            config,
            variant_detection_receiver,
            _phantom: PhantomData,
        }
    }
}

/// Mounts the SOVD component and functional-group routes.
pub(crate) struct SovdApi<SP: SecurityPlugin, SL: SecurityPluginLoader> {
    config: Arc<Configuration>,
    _phantom: PhantomData<fn() -> (SP, SL)>,
}

#[async_trait]
impl<SP: SecurityPlugin, SL: SecurityPluginLoader> Component<CdaEvent> for SovdApi<SP, SL> {
    type Provides = ();

    fn name(&self) -> &'static str {
        "sovd-api"
    }

    fn stage(&self) -> CdaStage {
        CdaStage::VehicleApi
    }

    async fn construct(
        self,
        resources: &StageResources<'_>,
    ) -> Result<Constructed<Self::Provides, CdaEvent>, LifecycleError> {
        let router = resources.get::<DynamicRouter>()?;
        let uds_manager = resources.get::<UdsManagerHandle<SP>>()?;
        let access = resources.get::<dyn CommunicationAccess>()?;
        let lock_provider = resources.get::<SovdLockStateView>()?;
        let registry = resources.get::<SovdRegistry>()?;
        // Routes and OpenAPI share one process-lifetime registry, mounted
        // against whatever the ECU data owner holds. Reloads update
        // component-owned data and never rebuild this index or route tree.
        let _ = cda_sovd::add_vehicle_routes::<UdsManagerType<SP>, SL>(
            &router,
            cda_sovd::VehicleConfig {
                flash_files_path: self.config.flash_files_path.clone(),
                components_config: self.config.components.clone(),
            },
            cda_sovd::VehicleResources {
                ecu_uds: uds_manager.0.clone(),
                lock_provider,
                registry: registry.view(),
                communication_access: access,
            },
        )
        .await
        .map_err(|error| failed(self.name(), CONSTRUCT, AppError::from(error)))?;
        Ok(Constructed::new(()))
    }
}

impl<SP: SecurityPlugin, SL: SecurityPluginLoader> SovdApi<SP, SL> {
    pub(crate) fn new(config: Arc<Configuration>) -> Self {
        Self {
            config,
            _phantom: PhantomData,
        }
    }
}

/// Loads the diagnostic databases into the reloadable ECU data.
///
/// Its stage follows the one that moves the database files, which itself
/// follows the one that opens the port. Both halves matter: what it reads is
/// whatever the file transaction left on disk, and it reads it while `/health`
/// and `/version` already answer rather than behind a closed port, because this
/// is the slowest thing about a start.
pub(crate) struct EcuData<SP: SecurityPlugin> {
    config: Arc<Configuration>,
    loader: Arc<VehicleDatabaseLoader<SP>>,
    variant_detection: VariantDetectionSender,
    lock_updater: Arc<dyn VehicleDatabaseLockUpdater>,
    health: Arc<Health>,
}

/// The owners a database load installs into.
struct EcuDataTargets<SP: SecurityPlugin> {
    uds: Arc<dyn ReloadComponent<VehicleEcuData<EcuManager<SP>>>>,
    sovd: Arc<SovdRegistry>,
    can: Arc<CanReload>,
}

struct LoadEcuData<SP: SecurityPlugin> {
    config: Arc<Configuration>,
    loader: Arc<VehicleDatabaseLoader<SP>>,
    variant_detection: VariantDetectionSender,
    lock_updater: Arc<dyn VehicleDatabaseLockUpdater>,
    health: Arc<Health>,
    revisions: Arc<EcuRevisions>,
    targets: EcuDataTargets<SP>,
}

impl<SP: SecurityPlugin> LoadEcuData<SP> {
    /// Builds the vehicle data a reload asks for, without making any of it live.
    ///
    /// A failure here leaves the live components on the previous data, which is
    /// why the `DatabaseFiles` revert only has to put the files back.
    async fn prepare(&self, reload: &EcuDataReload) -> Result<(), LifecycleError> {
        let prepared =
            PreparedVehicleData::<SP>::build(&self.loader, &self.config, &*self.lock_updater)
                .await
                .map_err(|error| {
                    failed(self.name(), EVENT, AppError::DataError(error.to_string()))
                })?;

        for (ecu, revision) in &prepared.revisions {
            // On the event for whoever reads this reload, and in the shared
            // record for whoever publishes what is live.
            reload.revisions.record(ecu.clone(), revision.clone());
            self.revisions.record(ecu.clone(), revision.clone());
        }
        reload.prepared.retain(prepared);
        Ok(())
    }

    /// Reads the configured databases and installs them into the live owners.
    async fn load(&self) -> Result<(), LifecycleError> {
        let health_providers = self.health.providers();
        let source = match self
            .loader
            .create_databases(&self.config, health_providers.as_ref())
            .await
        {
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
                vehicle::empty_vehicle_data_source::<SP>(self.variant_detection.clone()).await
            }
            Err(error) => {
                return Err(self.refused(AppError::InitializationFailed(error.to_string())));
            }
        };

        let identities = source.sovd_registry(&self.config).await;
        let can_topology = source
            .can_topology(&self.config)
            .await
            .map_err(|error| self.refused(error))?;
        let ecu_data = source.ecu_data(&self.config);
        // Startup only: a reload reports an empty result to its caller instead, so
        // an operator can never lose the running server by pushing an empty set.
        if ecu_data.ecus().is_empty() && self.config.database.exit_no_database_loaded {
            return Err(self.refused(AppError::ResourceError(
                "No database loaded, exiting as configured".to_owned(),
            )));
        }

        for (ecu, revision) in self.loader.revisions(&self.config).await {
            self.revisions.record(ecu, revision);
        }

        let ecu_names = ecu_data.physical_ecu_names();
        self.targets.uds.apply(ecu_data).await;
        self.targets.sovd.apply(identities).await;
        self.targets.can.install(can_topology).await;

        // The lock topology names the ECUs that were just made live, so it is
        // published by whoever knows them rather than handed on to a later
        // component.
        self.lock_updater
            .reserve_lock_resources(ecu_names)
            .await
            .map_err(|error| self.refused(AppError::InitializationFailed(error.to_string())))?
            .apply();
        Ok(())
    }

    /// Only [`load`](Self::load) reports through this, and only from `start`.
    fn refused(&self, error: AppError) -> LifecycleError {
        failed(self.name(), START, error)
    }
}

#[async_trait]
impl<SP: SecurityPlugin> ConstructedComponent<CdaEvent> for LoadEcuData<SP> {
    fn name(&self) -> &'static str {
        crate::mdd::DB_HEALTH_COMPONENT_KEY
    }

    async fn start(&self) -> Result<(), LifecycleError> {
        self.load().await
    }

    async fn on_event(&self, event: &CdaEvent) -> Result<(), LifecycleError> {
        let CdaEvent::ReloadEcuData(reload) = event else {
            return Ok(());
        };
        self.prepare(reload).await
    }

    fn health(&self) -> Option<Arc<dyn HealthStatus>> {
        self.health.database_status()
    }
}

#[async_trait]
impl<SP: SecurityPlugin> Component<CdaEvent> for EcuData<SP> {
    type Provides = ();

    fn name(&self) -> &'static str {
        crate::mdd::DB_HEALTH_COMPONENT_KEY
    }

    fn stage(&self) -> CdaStage {
        CdaStage::EcuData
    }

    async fn construct(
        self,
        resources: &StageResources<'_>,
    ) -> Result<Constructed<Self::Provides, CdaEvent>, LifecycleError> {
        let revisions = resources.get::<EcuRevisions>()?;
        let uds = resources.get::<dyn ReloadComponent<VehicleEcuData<EcuManager<SP>>>>()?;
        let sovd = resources.get::<SovdRegistry>()?;
        let can = resources.get::<CanReload>()?;
        Ok(
            Constructed::new(()).with_component(Arc::new(LoadEcuData::<SP> {
                config: self.config,
                loader: self.loader,
                variant_detection: self.variant_detection,
                lock_updater: self.lock_updater,
                health: self.health,
                revisions,
                targets: EcuDataTargets { uds, sovd, can },
            })),
        )
    }
}

impl<SP: SecurityPlugin> EcuData<SP> {
    pub(crate) fn new(
        config: Arc<Configuration>,
        loader: Arc<VehicleDatabaseLoader<SP>>,
        variant_detection: VariantDetectionSender,
        lock_updater: Arc<dyn VehicleDatabaseLockUpdater>,
        health: Arc<Health>,
    ) -> Self {
        Self {
            config,
            loader,
            variant_detection,
            lock_updater,
            health,
        }
    }
}

/// Republishes the version payload from the revisions the databases report.
///
/// Its stage follows the one that makes a reload live, because `/version` must
/// never name databases the runtime has not accepted.
///
/// The one component that owns static data, so it is the one that answers
/// [`CdaEvent::ReloadStaticData`] with work: its source is the revisions the
/// loaded databases recorded, which it re-reads without touching a database.
/// The routes themselves are never rebuilt, so `/version` keeps answering
/// across a reload and only what it answers with changes.
pub(crate) struct Version;

struct PublishVersion {
    payload: Arc<VersionData>,
    revisions: Arc<EcuRevisions>,
    /// The payload displaced by the reload in flight, so a later stage failing
    /// does not leave `/version` naming databases that are not live.
    previous: std::sync::Mutex<Option<serde_json::Map<String, serde_json::Value>>>,
}

impl PublishVersion {
    fn publish(&self) {
        *std_ext::lock_mutex(&self.previous) = Some(self.payload.0.snapshot());
        self.payload
            .0
            .set(crate::version_payload(&self.revisions.snapshot()));
    }
}

#[async_trait]
impl ConstructedComponent<CdaEvent> for PublishVersion {
    fn name(&self) -> &'static str {
        "version"
    }

    async fn start(&self) -> Result<(), LifecycleError> {
        self.publish();
        Ok(())
    }

    async fn on_event(&self, event: &CdaEvent) -> Result<(), LifecycleError> {
        // A cleanup deletes files without touching a database, so the revisions
        // this republishes from are the ones it is already serving.
        if !matches!(
            event,
            CdaEvent::ReloadEcuData(_) | CdaEvent::ReloadStaticData
        ) {
            return Ok(());
        }
        self.publish();
        Ok(())
    }

    async fn revert(&self, _event: &CdaEvent) -> Result<(), LifecycleError> {
        if let Some(previous) = std_ext::lock_mutex(&self.previous).take() {
            self.payload.0.set(previous);
        }
        Ok(())
    }
}

#[async_trait]
impl Component<CdaEvent> for Version {
    type Provides = ();

    fn name(&self) -> &'static str {
        "version"
    }

    fn stage(&self) -> CdaStage {
        CdaStage::Version
    }

    async fn construct(
        self,
        resources: &StageResources<'_>,
    ) -> Result<Constructed<Self::Provides, CdaEvent>, LifecycleError> {
        let payload = resources.get::<VersionData>()?;
        let revisions = resources.get::<EcuRevisions>()?;
        Ok(
            Constructed::new(()).with_component(Arc::new(PublishVersion {
                payload,
                revisions,
                previous: std::sync::Mutex::new(None),
            })),
        )
    }
}

/// Brings communication up as the configured init mode asks for.
///
/// The last thing a reload does, so its stage follows everything a reload has
/// to have finished: the runtime holds the new data, `/version` names it, and a
/// rolled back staged set is gone.
pub(crate) struct Activation {
    init_mode: CommunicationInitMode,
}

struct ActivateCommunication {
    init_mode: CommunicationInitMode,
    plugin: Arc<dyn CommunicationPlugin>,
}

#[async_trait]
impl ConstructedComponent<CdaEvent> for ActivateCommunication {
    fn name(&self) -> &'static str {
        "activation"
    }

    async fn start(&self) -> Result<(), LifecycleError> {
        setup::activate_communication_per_init_mode(&self.plugin, self.init_mode)
            .await
            .map_err(|error| failed(self.name(), START, error))
    }
}

#[async_trait]
impl Component<CdaEvent> for Activation {
    type Provides = ();

    fn name(&self) -> &'static str {
        "activation"
    }

    fn stage(&self) -> CdaStage {
        CdaStage::Activation
    }

    async fn construct(
        self,
        resources: &StageResources<'_>,
    ) -> Result<Constructed<Self::Provides, CdaEvent>, LifecycleError> {
        let plugin = resources.get::<dyn CommunicationPlugin>()?;
        Ok(
            Constructed::new(()).with_component(Arc::new(ActivateCommunication {
                init_mode: self.init_mode,
                plugin,
            })),
        )
    }
}

impl Activation {
    pub(crate) fn new(init_mode: CommunicationInitMode) -> Self {
        Self { init_mode }
    }
}

/// Reports the instance ready, once everything before it has started.
///
/// Readiness is the last stage in the graph rather than a line after the start
/// call, so nothing has to remember to say it last.
pub(crate) struct Readiness {
    shutdown_signal: Arc<ShutdownSignal>,
}

struct ReportReady {
    health: Arc<Health>,
    #[cfg_attr(
        not(feature = "systemd-notify"),
        allow(dead_code, reason = "only the systemd readiness task consumes it")
    )]
    shutdown_signal: Arc<ShutdownSignal>,
}

#[async_trait]
impl ConstructedComponent<CdaEvent> for ReportReady {
    fn name(&self) -> &'static str {
        "readiness"
    }

    async fn start(&self) -> Result<(), LifecycleError> {
        self.health.mark_up().await;
        #[cfg(feature = "systemd-notify")]
        {
            // The task watches the health state and notifies systemd once it
            // reports ready, so it outlives this call.
            let _sd_notify_task = cda_extra::create_sd_notify_task(
                self.health.state(),
                (*self.shutdown_signal).clone(),
            );
        }
        tracing::info!("CDA fully initialized and ready to serve requests");
        Ok(())
    }
}

#[async_trait]
impl Component<CdaEvent> for Readiness {
    type Provides = ();

    fn name(&self) -> &'static str {
        "readiness"
    }

    fn stage(&self) -> CdaStage {
        CdaStage::Readiness
    }

    async fn construct(
        self,
        resources: &StageResources<'_>,
    ) -> Result<Constructed<Self::Provides, CdaEvent>, LifecycleError> {
        let health = resources.get::<Health>()?;
        Ok(Constructed::new(()).with_component(Arc::new(ReportReady {
            health,
            shutdown_signal: self.shutdown_signal,
        })))
    }
}

impl Readiness {
    pub(crate) fn new(shutdown_signal: Arc<ShutdownSignal>) -> Self {
        Self { shutdown_signal }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use async_trait::async_trait;
    use cda_interfaces::{
        communication_control::{
            CommunicationOperationFailure, CommunicationState, DisableCommunication, DisableError,
            DisableGuard, DisableReason, PostUpdateCommunicationMode,
        },
        config::ConfigSanityError,
        http_protection::registry::HttpProtectionConfig,
        lifecycle::LifecycleComponent,
        util::std_ext,
    };
    use cda_lifecycle::{
        CdaLeasePolicy, HttpProtector, LifecycleManager, LifecycleManagerConfig, LifecycleRuntime,
        UpdateHttpProtection,
    };

    use super::*;

    /// Records the file operations a dispatch asked for, in order.
    #[derive(Default)]
    struct RecordingFiles {
        calls: std::sync::Mutex<Vec<&'static str>>,
    }

    impl RecordingFiles {
        fn calls(&self) -> Vec<&'static str> {
            std_ext::lock_mutex(&self.calls).clone()
        }

        fn record(&self, call: &'static str) {
            std_ext::lock_mutex(&self.calls).push(call);
        }
    }

    #[async_trait]
    impl RuntimeFileTransaction for RecordingFiles {
        async fn apply_files(
            &self,
        ) -> Result<(), cda_interfaces::runtime_update_api::RuntimeUpdateError> {
            self.record("apply");
            Ok(())
        }

        async fn rollback_files(
            &self,
        ) -> Result<(), cda_interfaces::runtime_update_api::RuntimeUpdateError> {
            self.record("rollback");
            Ok(())
        }

        async fn discard_staged(
            &self,
        ) -> Result<(), cda_interfaces::runtime_update_api::RuntimeUpdateError> {
            self.record("discard-staged");
            Ok(())
        }

        async fn cleanup_files(
            &self,
        ) -> Result<(), cda_interfaces::runtime_update_api::RuntimeUpdateError> {
            self.record("cleanup");
            Ok(())
        }

        async fn restore_after_apply(
            &self,
        ) -> Result<(), cda_interfaces::runtime_update_api::RuntimeUpdateError> {
            self.record("restore-after-apply");
            Ok(())
        }

        async fn restore_after_rollback(
            &self,
        ) -> Result<(), cda_interfaces::runtime_update_api::RuntimeUpdateError> {
            self.record("restore-after-rollback");
            Ok(())
        }
    }

    /// Stands in for the component that loads the databases, in the same stage
    /// it belongs to, and refusing when the test asks it to.
    struct EcuDataLoad {
        refuses: bool,
    }

    #[async_trait]
    impl ConstructedComponent<CdaEvent> for EcuDataLoad {
        fn name(&self) -> &'static str {
            "ecu-data-load"
        }

        async fn on_event(&self, event: &CdaEvent) -> Result<(), LifecycleError> {
            let CdaEvent::ReloadEcuData(_) = event else {
                return Ok(());
            };
            if !self.refuses {
                return Ok(());
            }
            Err(failed(
                "ecu-data-load",
                EVENT,
                AppError::DataError("The staged databases do not load".to_owned()),
            ))
        }
    }

    #[async_trait]
    impl Component<CdaEvent> for EcuDataLoad {
        type Provides = ();

        fn name(&self) -> &'static str {
            "ecu-data-load"
        }

        fn stage(&self) -> CdaStage {
            CdaStage::EcuData
        }

        async fn construct(
            self,
            _resources: &StageResources<'_>,
        ) -> Result<Constructed<Self::Provides, CdaEvent>, LifecycleError> {
            let refuses = self.refuses;
            Ok(Constructed::new(()).with_component(Arc::new(EcuDataLoad { refuses })))
        }
    }

    /// Stands in for the component that makes the loaded databases live, in the
    /// same stage it belongs to, and records whether it was ever reached.
    struct CountingCommit {
        commits: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl ConstructedComponent<CdaEvent> for CountingCommit {
        fn name(&self) -> &'static str {
            "counting-commit"
        }

        async fn on_event(&self, event: &CdaEvent) -> Result<(), LifecycleError> {
            if matches!(event, CdaEvent::ReloadEcuData(_)) {
                self.commits.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        }
    }

    #[async_trait]
    impl Component<CdaEvent> for CountingCommit {
        type Provides = ();

        fn name(&self) -> &'static str {
            "counting-commit"
        }

        fn stage(&self) -> CdaStage {
            CdaStage::Diagnostics
        }

        async fn construct(
            self,
            _resources: &StageResources<'_>,
        ) -> Result<Constructed<Self::Provides, CdaEvent>, LifecycleError> {
            let commits = Arc::clone(&self.commits);
            Ok(Constructed::new(()).with_component(Arc::new(CountingCommit { commits })))
        }
    }

    #[derive(Debug)]
    struct FreeLease;

    #[async_trait]
    impl DisableGuard for FreeLease {
        async fn release(
            self: Box<Self>,
        ) -> Result<CommunicationState, CommunicationOperationFailure> {
            Ok(CommunicationState::Enabled)
        }

        async fn finish(self: Box<Self>) -> Result<(), CommunicationOperationFailure> {
            Ok(())
        }
    }

    struct FreeTransport;

    #[async_trait]
    impl DisableCommunication for FreeTransport {
        async fn disable(
            &self,
            _reason: DisableReason,
        ) -> Result<Box<dyn DisableGuard>, DisableError> {
            Ok(Box::new(FreeLease))
        }
    }

    struct NoProtection;

    impl HttpProtector for NoProtection {
        fn protect(
            &self,
            _config: HttpProtectionConfig,
        ) -> Result<Box<dyn Send>, ConfigSanityError> {
            Ok(Box::new(()))
        }
    }

    fn reload(mode: ReloadExecutionMode) -> CdaEvent {
        CdaEvent::ReloadEcuData(EcuDataReload::new(
            mode,
            PostUpdateCommunicationMode::Enabled,
            UpdateHttpProtection::default(),
        ))
    }

    /// Constructs the components a reload runs through, with the load either
    /// succeeding or refusing, and hands back the event participants in the
    /// order the resolver derived.
    async fn file_components(
        files: &Arc<RecordingFiles>,
        load_refuses: bool,
        commits: &Arc<AtomicUsize>,
    ) -> Vec<Arc<dyn LifecycleComponent<CdaEvent>>> {
        let mut runtime = LifecycleRuntime::<CdaEvent>::new();
        runtime.provide(Arc::new(FileTransaction(Some(
            Arc::clone(files) as Arc<dyn RuntimeFileTransaction>
        ))));
        // Registered in an order no phase of the reload runs in, because where
        // a `register` call sits decides nothing: the stages do.
        runtime.register(StagedFiles);
        runtime.register(CountingCommit {
            commits: Arc::clone(commits),
        });
        runtime.register(DatabaseFiles);
        runtime.register(EcuDataLoad {
            refuses: load_refuses,
        });

        runtime
            .resolve()
            .expect("the declarations have an order")
            .construct()
            .await
            .expect("nothing refuses to be built")
            .event_components()
    }

    fn manager(
        components: Vec<Arc<dyn LifecycleComponent<CdaEvent>>>,
    ) -> LifecycleManager<CdaEvent> {
        let mut manager = LifecycleManager::new(LifecycleManagerConfig {
            http_protector: Arc::new(NoProtection) as Arc<dyn HttpProtector>,
            communication: Arc::new(FreeTransport) as Arc<dyn DisableCommunication>,
            lease_policy: Arc::new(CdaLeasePolicy),
            lease_released_before: Some(CdaStage::Activation),
        });
        for component in components {
            manager.register(component);
        }
        manager
    }

    /// Dispatches `event` over the reload components with a load that refuses,
    /// and reports what the file transaction was asked to do and how often the
    /// commit was reached.
    async fn dispatch_with_a_failing_load(
        files: &Arc<RecordingFiles>,
        event: CdaEvent,
    ) -> (Vec<&'static str>, usize) {
        let commits = Arc::new(AtomicUsize::new(0));
        let components = file_components(files, true, &commits).await;

        let accepted = manager(components)
            .spawn()
            .accept(event)
            .await
            .expect("the dispatch is admitted");
        let outcome = accepted.completion.await.expect("completion is reported");
        assert!(outcome.is_err(), "a refused load must fail the dispatch");

        (files.calls(), commits.load(Ordering::SeqCst))
    }

    /// A load that refuses leaves the live components on the previous data,
    /// because the component that commits it never runs. Putting the files back
    /// is then all that is needed for disk and memory to agree again.
    #[tokio::test]
    async fn a_failed_load_restores_the_backup_and_never_commits() {
        let files = Arc::new(RecordingFiles::default());

        let (calls, commits) =
            dispatch_with_a_failing_load(&files, reload(ReloadExecutionMode::Apply)).await;

        assert_eq!(calls, ["apply", "restore-after-apply"]);
        assert_eq!(commits, 0, "the commit must never have been reached");
    }

    /// A rollback is undone by swapping back, and its staged set survives:
    /// only a rollback the runtime accepted discards it.
    #[tokio::test]
    async fn a_failed_load_after_a_rollback_swaps_back_and_keeps_the_staged_set() {
        let files = Arc::new(RecordingFiles::default());

        let (calls, commits) =
            dispatch_with_a_failing_load(&files, reload(ReloadExecutionMode::Rollback)).await;

        assert_eq!(calls, ["rollback", "restore-after-rollback"]);
        assert_eq!(commits, 0);
    }

    /// Committing a rollback happens after the restore, so a load that refuses
    /// cannot have discarded the staged set already.
    #[tokio::test]
    async fn a_completed_rollback_discards_the_staged_set() {
        let files = Arc::new(RecordingFiles::default());
        let commits = Arc::new(AtomicUsize::new(0));
        let components = file_components(&files, false, &commits).await;

        manager(components)
            .spawn()
            .accept(reload(ReloadExecutionMode::Rollback))
            .await
            .expect("the dispatch is admitted")
            .completion
            .await
            .expect("completion is reported")
            .expect("the dispatch succeeds");

        assert_eq!(files.calls(), ["rollback", "discard-staged"]);
    }

    /// The value a reload displaces is parked on the event, so the component
    /// that installed it can put it back when a later component fails.
    #[tokio::test]
    async fn the_displaced_ecu_data_is_retained_for_the_dispatch() {
        let owner = Arc::new(cda_interfaces::ReloadableOwner::new("previous".to_owned()));
        let event = reload(ReloadExecutionMode::Apply);
        let CdaEvent::ReloadEcuData(update) = &event else {
            panic!("a reload event was just built");
        };

        if let Some(displaced) = owner.swap("current".to_owned()).await {
            update.outgoing.retain(displaced);
        }
        assert_eq!(*owner.reader().read().await, "current");

        let restored = update
            .outgoing
            .take::<String>()
            .expect("the displaced value is parked on the event");
        owner.apply(restored).await;
        assert_eq!(*owner.reader().read().await, "previous");
    }
}
