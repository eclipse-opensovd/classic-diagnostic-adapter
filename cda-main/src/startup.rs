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

//! CDA bring-up as a stage-ordered construction.
//!
//! Every step of startup is a [`Component`](cda_interfaces::lifecycle::Component)
//! naming its [`CdaStage`](cda_lifecycle::CdaStage), the types it needs and the
//! types it hands over. The stage graph gives the order of construction, of
//! start and, reversed, of stop; the types deliver the values and order
//! nothing, which is why every step of a chain is a stage of its own. There is
//! no list of steps here to keep in the right order, and no handle is passed
//! out before the component that builds it has run.
//!
//! # What this module still owns
//!
//! The values no component constructs: the parsed configuration, the shutdown
//! signal, the HTTP protection registry, the health providers, and the
//! reloadable owners the vehicle data is installed into. They are seeded into
//! the runtime and count as provided, so a component may require them without
//! anything having to be ordered before it.

pub(crate) mod components;
pub mod health;
pub mod resources;

use std::sync::{Arc, Mutex as StdMutex};

use cda_interfaces::{
    ShutdownSignal,
    http_protection::registry::HttpProtectionRegistry,
    lifecycle::{ErasedComponent, LifecycleError},
    util::std_ext,
};
use cda_lifecycle::{CdaEvent, EcuRevisions, LifecycleHandle};
use cda_plugin_communication_management::plugin::CommunicationPluginBuilder;
use cda_plugin_security::{SecurityPlugin, SecurityPluginLoader};
use cda_storage::LocalStorage;
use tokio::sync::Notify;

use crate::{
    AppError,
    config::configfile::Configuration,
    database_reload::VehicleDatabaseLoader,
    setup::Setup,
    startup::{
        health::Health,
        resources::{EcuDataCell, VersionData},
    },
    update::UpdatePluginBuilder,
    vehicle,
};

/// The webserver task, aborted on drop so a failed startup releases the
/// listener without explicit cleanup on every error path.
pub struct WebServer {
    task: StdMutex<Option<tokio::task::JoinHandle<()>>>,
    /// Ends the serving task on its own, so the accept loop can be taken down
    /// without the process shutdown signal having fired. A start that failed
    /// further up has to stop the listener too, and it has no signal to wait
    /// for.
    drained: Arc<Notify>,
}

impl WebServer {
    fn new() -> Self {
        Self {
            task: StdMutex::new(None),
            drained: Arc::new(Notify::new()),
        }
    }

    /// The signal the serving task drains on: the process shutdown signal, or
    /// this listener being stopped on its own.
    fn serve_until(&self, shutdown_signal: &ShutdownSignal) -> ShutdownSignal {
        let process = shutdown_signal.clone();
        let drained = Arc::clone(&self.drained);
        cda_interfaces::shutdown_signal(async move {
            tokio::select! {
                () = process => {},
                () = drained.notified() => {},
            }
        })
    }

    /// Hands the serving task over for the process lifetime.
    fn install(&self, task: tokio::task::JoinHandle<()>) {
        *std_ext::lock_mutex(&self.task) = Some(task);
    }

    /// Stops accepting and waits for the connections in flight.
    async fn drain(&self) -> Result<(), AppError> {
        // Stores a permit, so a task that has not reached the signal yet still
        // sees it.
        self.drained.notify_one();
        let task = std_ext::lock_mutex(&self.task).take();
        if let Some(task) = task {
            task.await
                .map_err(|e| AppError::RuntimeError(format!("Webserver task join error: {e}")))?;
        }
        Ok(())
    }

    /// Stops serving immediately.
    fn abort(&self) {
        if let Some(task) = std_ext::lock_mutex(&self.task).take() {
            task.abort();
        }
    }
}

impl Drop for WebServer {
    fn drop(&mut self) {
        self.abort();
    }
}

/// Phase label a component names when its construction fails.
const CONSTRUCT: &str = "construct";
/// Phase label a component names when its start fails.
const START: &str = "start";
/// Phase label a component names when its stop fails.
const STOP: &str = "stop";
/// Phase label a component names when it refuses a dispatched event. The
/// manager wraps the result again with the event's own name.
const EVENT: &str = "event";

/// Names the component and phase a failure came from.
fn failed(component: &'static str, phase: &'static str, error: AppError) -> LifecycleError {
    LifecycleError::Component {
        component,
        phase: phase.to_owned(),
        source: Box::new(error),
    }
}

/// The first [`AppError`] in a startup failure's source chain.
fn app_error(error: &LifecycleError) -> Option<&AppError> {
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(error) = current {
        if let Some(app_error) = error.downcast_ref::<AppError>() {
            return Some(app_error);
        }
        current = error.source();
    }
    None
}

/// Registers every component, constructs and starts them in the order their
/// declarations derive, serves until the shutdown signal, and stops them in the
/// exact reverse of the order they started in.
///
/// # Errors
/// Returns [`AppError`] when the declarations have no order, or when a
/// component refuses to be built or to start.
pub(crate) async fn run<SP, SL, UPB, CPB>(
    config: Configuration,
    setup: Setup<SP, SL, UPB, CPB>,
) -> Result<(), AppError>
where
    SP: SecurityPlugin,
    SL: SecurityPluginLoader,
    UPB: UpdatePluginBuilder<LocalStorage> + 'static,
    CPB: CommunicationPluginBuilder + 'static,
{
    let config = Arc::new(config);
    // A subscriber is a process global, so it is a precondition of the runtime
    // rather than a phase of it: no type can carry "logging works" to a
    // component, and everything below has to be observable while it is built.
    // The guards stay bound for the whole of `run`, which is as long as the
    // component that used to hold them lived; dropping them stops the file and
    // OpenTelemetry exporters.
    let _tracing_guards = install_tracing(&config, setup.initialize_tracing)?;
    validate_vendor_overrides()?;

    let shutdown_signal = setup
        .shutdown_signal
        .unwrap_or_else(|| cda_interfaces::shutdown_signal(crate::shutdown_signal()));

    let runtime = register::<SP, SL, UPB, CPB>(
        &config,
        &shutdown_signal,
        setup.components,
        setup.build_update_plugin,
        setup.build_communication_plugin,
        setup.file_inspector,
    )
    .await;

    let constructed = runtime
        .resolve()
        .map_err(|error| AppError::InitializationFailed(error.to_string()))?
        .construct()
        .await
        .map_err(|error| startup_failure(&error))?;

    let health = constructed
        .resources()
        .get::<Health>()
        .ok_or_else(|| AppError::InitializationFailed("Health was not seeded".to_owned()))?;
    // Before anything can be reached: an instance with no providers registered
    // answers `/health/ready` with 204, see `Health`.
    health.register_all(constructed.health_providers()).await?;

    // The manager holds the components an event is dispatched over, in the
    // order the resolver derived. It is spawned during construction, because the
    // update plugin dispatches through it and is built with it.
    let lifecycle = constructed
        .resources()
        .get::<LifecycleHandle<CdaEvent>>()
        .ok_or_else(|| {
            AppError::InitializationFailed("The lifecycle manager was not built".to_owned())
        })?;
    for component in constructed.event_components() {
        lifecycle
            .register(component)
            .await
            .map_err(|error| AppError::InitializationFailed(error.to_string()))?;
    }

    let running = match constructed.start().await {
        Ok(running) => running,
        Err(error) => return started_or_shutdown(&error),
    };

    shutdown_signal.await;
    tracing::info!("Shutting down...");
    running
        .stop()
        .await
        .map_err(|error| AppError::RuntimeError(error.to_string()))
}

/// Installs the process's tracing subscriber and hands back the guards that
/// keep its exporters running.
///
/// `initialize_tracing` is false when the caller installed a subscriber of its
/// own, and there is then nothing to guard.
fn install_tracing(
    config: &Configuration,
    initialize_tracing: bool,
) -> Result<Option<crate::TracingGuards>, AppError> {
    let guards = if initialize_tracing {
        Some(crate::setup_tracing(config).map_err(AppError::from)?)
    } else {
        None
    };
    tracing::info!("Starting CDA - version {}", crate::cda_version());
    Ok(guards)
}

/// Vendor overrides are registered via `linkme` distributed slices, whose final
/// contents are only known after linking; this checks that at most one override
/// is linked in per overridable function before any of them are used. Every
/// crate that defines vendor-overridable functions must be listed there.
fn validate_vendor_overrides() -> Result<(), AppError> {
    cda_core::validate_vendor_overrides().map_err(|errors| {
        AppError::InitializationFailed(format!(
            "Vendor override configuration error(s): {}",
            errors.join("; ")
        ))
    })
}

/// A start that failed because the operator asked for a shutdown is a clean
/// exit, not a failure to report.
fn started_or_shutdown(error: &LifecycleError) -> Result<(), AppError> {
    if matches!(app_error(error), Some(AppError::ShutdownRequested)) {
        tracing::info!("Shutdown requested during database load, exiting cleanly");
        return Ok(());
    }
    Err(startup_failure(error))
}

fn startup_failure(error: &LifecycleError) -> AppError {
    AppError::InitializationFailed(error.to_string())
}

/// Seeds the values no component builds and registers every component.
async fn register<SP, SL, UPB, CPB>(
    config: &Arc<Configuration>,
    shutdown_signal: &ShutdownSignal,
    extra: Vec<Box<dyn ErasedComponent<CdaEvent>>>,
    build_update_plugin: Option<UPB>,
    build_communication_plugin: CPB,
    file_inspector: Arc<dyn cda_interfaces::runtime_update_api::RuntimeFileInspector>,
) -> cda_lifecycle::LifecycleRuntime<CdaEvent>
where
    SP: SecurityPlugin,
    SL: SecurityPluginLoader,
    UPB: UpdatePluginBuilder<LocalStorage> + 'static,
    CPB: CommunicationPluginBuilder + 'static,
{
    let (variant_detection_sender, variant_detection_receiver) =
        vehicle::variant_detection_channel();

    // The empty vehicle every reloadable owner starts on. The load installs the
    // databases into these same owners, so nothing downstream is rebuilt when
    // they arrive.
    let empty = vehicle::empty_vehicle_data_source::<SP>(variant_detection_sender.clone()).await;
    let initial_identities = empty.sovd_registry(config).await;
    let (ecu_data, uds_reload) = cda_comm_uds::prepare_ecu_data(empty.ecu_data(config));
    let (lock_provider, lock_updater) = cda_sovd::new_sovd_lock_state(Vec::new());

    let mut runtime = cda_lifecycle::LifecycleRuntime::<CdaEvent>::new();
    runtime.provide(Arc::clone(config));
    runtime.provide(Arc::new(shutdown_signal.clone()));
    runtime.provide(Arc::new(HttpProtectionRegistry::new()));
    let health = Arc::new(Health::new(config));
    runtime.provide(Arc::clone(&health));
    runtime.provide(Arc::new(EcuDataCell::<SP>(ecu_data)));
    runtime.provide(uds_reload);
    runtime.provide(Arc::new(cda_sovd::SovdRegistry::new(initial_identities)));
    runtime.provide(lock_provider);
    // No database has been read yet, so it starts without revisions.
    runtime.provide(Arc::new(VersionData(cda_sovd::StaticData::new(
        crate::version_payload(&cda_interfaces::HashMap::default()),
    ))));
    runtime.provide(Arc::new(EcuRevisions::default()));

    let loader = Arc::new(VehicleDatabaseLoader::<SP>::new(
        variant_detection_sender.clone(),
        Arc::clone(&file_inspector),
    ));

    for component in extra {
        runtime.register_erased(component);
    }
    runtime.register(components::HttpRouter::new(Arc::clone(&health)));
    runtime.register(components::Transport::<SP>::new(
        Arc::clone(config),
        variant_detection_sender.clone(),
        Arc::clone(&health),
    ));
    runtime.register(components::Communication::<CPB, SP>::new(
        Arc::clone(config),
        build_communication_plugin,
    ));
    runtime.register(components::Lifecycle);
    runtime.register(components::Storage::<UPB>::new(
        Arc::clone(config),
        build_update_plugin,
        file_inspector,
    ));
    runtime.register(components::StaticApi::<SL, UPB::Plugin>::new(
        Arc::clone(config),
        Arc::clone(&health),
    ));
    runtime.register(components::DatabaseFiles);
    runtime.register(components::Diagnostics::<SP>::new(
        Arc::clone(config),
        variant_detection_receiver,
    ));
    runtime.register(components::SovdApi::<SP, SL>::new(Arc::clone(config)));
    runtime.register(components::AcceptLoop::new(Arc::clone(config)));
    runtime.register(components::EcuData::<SP>::new(
        Arc::clone(config),
        loader,
        variant_detection_sender,
        lock_updater,
        Arc::clone(&health),
    ));
    runtime.register(components::StagedFiles);
    runtime.register(components::Version);
    runtime.register(components::Activation::new(config.communication.init_mode));
    runtime.register(components::Readiness::new(Arc::new(
        shutdown_signal.clone(),
    )));

    runtime
}

#[cfg(test)]
mod tests {
    use cda_plugin_communication_management::plugin::default::DefaultCommunicationPluginBuilder;
    use cda_plugin_security::{DefaultSecurityPlugin, DefaultSecurityPluginData};

    use super::*;
    use crate::update::{UpdatePluginFn, create_default_update_plugin, update_plugin_fn};

    /// The order the real component set resolves to, without building anything.
    async fn resolved() -> cda_lifecycle::ResolvedRuntime<CdaEvent> {
        let config = Arc::new(Configuration::default());
        let shutdown = cda_interfaces::shutdown_signal(std::future::pending::<()>());
        let builder: UpdatePluginFn<_> =
            update_plugin_fn(|resources| async { create_default_update_plugin(resources).await });

        register::<
            DefaultSecurityPluginData,
            DefaultSecurityPlugin,
            _,
            DefaultCommunicationPluginBuilder,
        >(
            &config,
            &shutdown,
            Vec::new(),
            Some(builder),
            DefaultCommunicationPluginBuilder,
            Arc::new(crate::mdd_inspector::MddFileInspector),
        )
        .await
        .resolve()
        .expect("the CDA's declarations have an order")
    }

    async fn resolved_order() -> Vec<&'static str> {
        resolved().await.order().names()
    }

    fn position(order: &[&'static str], name: &str) -> usize {
        order
            .iter()
            .position(|entry| *entry == name)
            .unwrap_or_else(|| panic!("{name} is registered: {order:?}"))
    }

    /// The stage graph is the order, so it is what a reader is shown when they
    /// ask why one component ran before another. Only the declared edges are
    /// asserted: `vehicle-api`, `staged-files` and `version` are separated by
    /// nothing, so the resolver shuffles them and pinning one order here would
    /// put back the hidden dependency the shuffle exists to expose.
    #[tokio::test]
    async fn the_stage_graph_is_the_order_the_cda_runs_in() {
        let resolved = resolved().await;
        let stages = resolved.order().stages();

        for [first, second] in [
            ["transports", "communication-runtime"],
            ["communication-runtime", "lifecycle-manager"],
            ["lifecycle-manager", "storage"],
            ["storage", "static-api"],
            ["static-api", "serving"],
            ["serving", "database-files"],
            ["database-files", "ecu-data"],
            ["ecu-data", "diagnostics"],
            ["vehicle-api", "activation"],
            ["staged-files", "activation"],
            ["version", "activation"],
            ["activation", "readiness"],
        ] {
            assert!(
                position(stages, first) < position(stages, second),
                "{first} is declared before {second}: {stages:?}"
            );
        }
        for tied in ["vehicle-api", "staged-files", "version"] {
            assert!(
                position(stages, "diagnostics") < position(stages, tied),
                "{tied} follows diagnostics: {stages:?}"
            );
        }
        assert_eq!(stages.last(), Some(&"readiness"), "{stages:?}");
    }

    /// The whole point of a derived order is that it can be replayed from the
    /// log, which needs the seed both tie-breaks drew from to be in the dump.
    #[tokio::test]
    async fn the_dump_carries_the_seed_the_ties_were_settled_with() {
        let resolved = resolved().await;
        let order = resolved.order();

        let seed = order
            .shuffle_seed()
            .expect("a test build shuffles what nothing separates");
        assert!(order.to_string().contains(&seed.to_string()), "{order}");
    }

    /// Every link of the chain that brings the runtime up is a stage of its
    /// own, because a stage orders nothing inside itself. `main` and `doip`
    /// share the first one: neither reads anything the other publishes, which
    /// is the only reason two components may sit in one stage.
    #[tokio::test]
    async fn each_link_of_the_bring_up_chain_is_a_stage_of_its_own() {
        let order = resolved_order().await;

        for [first, second] in [
            ["main", "communication-runtime"],
            [crate::DOIP_HEALTH_COMPONENT_KEY, "communication-runtime"],
            ["communication-runtime", "lifecycle-manager"],
            ["lifecycle-manager", "storage"],
        ] {
            assert!(
                position(&order, first) < position(&order, second),
                "{first} hands {second} a value, so its stage must come first: {order:?}"
            );
        }
    }

    /// Stop is the exact reverse of start, so the listener stopping before the
    /// communication runtime is the same fact as it starting after it: its
    /// stage follows the one the communication runtime is built in.
    #[tokio::test]
    async fn the_accept_loop_stops_before_the_communication_runtime() {
        let order = resolved_order().await;

        assert!(
            position(&order, "communication-runtime") < position(&order, "http-listener"),
            "{order:?}"
        );
    }

    /// The databases are the slowest part of a start, and they are read while
    /// the API already answers rather than behind a closed port.
    ///
    #[tokio::test]
    async fn the_databases_are_read_after_the_runtime_is_serving() {
        let order = resolved_order().await;

        assert!(
            position(&order, "http-listener") < position(&order, "database"),
            "{order:?}"
        );
        assert!(
            position(&order, "static-api") < position(&order, "http-listener"),
            "{order:?}"
        );
    }

    /// Communication is activated once there is a vehicle to talk to, and the
    /// instance calls itself ready only once that has happened.
    #[tokio::test]
    async fn activation_and_readiness_come_last() {
        let order = resolved_order().await;

        assert!(
            position(&order, "database") < position(&order, "activation"),
            "{order:?}"
        );
        assert_eq!(
            position(&order, "readiness"),
            order.len().saturating_sub(1),
            "{order:?}"
        );
    }

    /// A reload visits its stages in the order the graph sorted them into, so
    /// the chain it runs through has to be a chain of stage edges: the files are
    /// moved, the databases are read from what they left, what was read is made
    /// live, and only once `/version` names it and a rolled back staged set is
    /// gone does the transport come back.
    #[tokio::test]
    async fn a_reload_runs_its_components_in_the_order_the_reload_needs() {
        let order = resolved_order().await;

        for [first, second] in [
            ["database-files", "database"],
            ["database", "diagnostics"],
            ["diagnostics", "version"],
            ["diagnostics", "staged-files"],
            ["version", "activation"],
            ["staged-files", "activation"],
        ] {
            assert!(
                position(&order, first) < position(&order, second),
                "{first} must come before {second}: {order:?}"
            );
        }
    }

    /// An OEM registers a provider that belongs to no component, and it is
    /// reported like any other.
    #[tokio::test]
    async fn a_provider_registered_by_hand_appears_in_the_health_report() {
        let mut config = Configuration::default();
        config.health.enabled = true;
        let health = Health::new(&config);

        health
            .register(
                "oem-subsystem",
                Arc::new(cda_health::StatusHealthProvider::new(
                    cda_health::Status::Starting,
                )) as Arc<dyn cda_interfaces::health::HealthStatus>,
            )
            .await
            .expect("a name nothing else claimed is accepted");

        let state = health.state().expect("health is enabled");
        let reported = state.query_all_providers().await;
        assert_eq!(
            reported.get("oem-subsystem"),
            Some(&cda_health::Status::Starting)
        );
    }

    #[tokio::test]
    async fn drop_aborts_webserver_task() {
        let task = tokio::spawn(std::future::pending::<()>());
        let abort_handle = task.abort_handle();

        let webserver = WebServer::new();
        webserver.install(task);
        drop(webserver);

        // abort() is asynchronous; yield to let the cancellation propagate.
        tokio::task::yield_now().await;
        assert!(abort_handle.is_finished());
    }
}
