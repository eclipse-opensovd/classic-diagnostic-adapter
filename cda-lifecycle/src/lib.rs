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

//! Runtime lifecycle manager.
//!
//! [`LifecycleManager`] is a kameo actor holding the registered
//! [`LifecycleComponent`]s. Dispatch is two phase: [`LifecycleHandle::accept`]
//! takes the event's guards and answers whether the dispatch was admitted, then
//! the components run in a detached task and report through
//! [`Accepted::completion`].
//!
//! # Construct, start, stop
//!
//! Events are one of three phases. [`LifecycleRuntime`] owns the other two: it
//! derives an order from the stage graph, constructs and starts in that order,
//! and stops in its exact reverse. Events dispatch in between, over the
//! components of the stages the event names, in that same derived order.
//!
//! # Reference cycle
//!
//! The manager owns `Arc<dyn LifecycleComponent<E>>`, and a component that
//! dispatches needs a way back to the manager. A strong `ActorRef` in a
//! component would form `ActorRef -> mailbox -> actor state -> component ->
//! ActorRef`, whose strong count never reaches zero, so the actor could never
//! stop. Only [`LifecycleHandle`] holds the strong `ActorRef`, and it is meant
//! for the process owner that spawned the manager. Components get
//! [`WeakLifecycleHandle`] from [`LifecycleHandle::downgrade`], which upgrades
//! per call and fails cleanly once the owner drops the manager.

mod events;
mod guards;
mod resolve;
mod runtime;
mod stages;

use std::sync::Arc;

pub use cda_interfaces::lifecycle::{
    Component, Constructed, ConstructedComponent, DispatchGuards, ErasedComponent, IntoResources,
    LifecycleComponent, LifecycleError, LifecycleEvent, Publisher, Publishers, Resource,
    ResourceError, ResourceId, Resources, Stage, StagePlacement, StageResources, erase,
};
use cda_interfaces::{
    communication_control::DisableCommunication, health::HealthStatus, spawn_named,
};
pub use events::{
    CdaEvent, CdaLeasePolicy, EcuDataReload, EcuRevisions, ParkedValue, ReloadExecutionMode,
    UpdateHttpProtection,
};
use guards::HeldGuards;
pub use guards::{HttpProtector, LeaseOutcome, LeasePolicy};
use kameo::{
    actor::{ActorRef, Spawn, WeakActorRef},
    error::Infallible,
    message::{Context, Message},
};
pub use resolve::{ResolveError, ResolvedComponent, ResolvedOrder};
pub use runtime::{ConstructedRuntime, LifecycleRuntime, ResolvedRuntime, RunningRuntime};
pub use stages::CdaStage;
use tokio::sync::oneshot;

/// The lifecycle manager actor is no longer running.
#[derive(Debug, thiserror::Error)]
#[error("Lifecycle manager is not running")]
pub struct ManagerStopped;

/// An admitted dispatch. The guards are up and the components are running.
#[derive(Debug)]
pub struct Accepted {
    /// Resolves when the components have finished and the guards are down.
    pub completion: oneshot::Receiver<Result<(), LifecycleError>>,
}

/// Everything the manager needs besides its components.
pub struct LifecycleManagerConfig<E: LifecycleEvent> {
    /// Installs the HTTP protection a dispatch declares.
    pub http_protector: Arc<dyn HttpProtector>,
    /// Source of the exclusive communication disable lease.
    pub communication: Arc<dyn DisableCommunication>,
    /// Decides whether a lease is released or dropped when the dispatch ends.
    pub lease_policy: Arc<dyn LeasePolicy<E>>,
    /// The stage the communication lease is handed back before, so that stage
    /// and everything after it run against the transport their target asked for
    /// rather than against a held lease. When a dispatch reaches no component of
    /// that stage, the lease is handed back after the last one instead.
    pub lease_released_before: Option<E::Stage>,
}

/// Dispatches lifecycle events over the registered components.
pub struct LifecycleManager<E: LifecycleEvent> {
    /// In the order they were registered, which is the order
    /// [`LifecycleRuntime`] resolved. An event reaches the ones whose stage it
    /// names.
    components: Vec<Arc<dyn LifecycleComponent<E>>>,
    config: LifecycleManagerConfig<E>,
}

impl<E: LifecycleEvent> LifecycleManager<E> {
    /// Creates a manager with no components registered yet.
    #[must_use]
    pub fn new(config: LifecycleManagerConfig<E>) -> Self {
        Self {
            components: Vec::new(),
            config,
        }
    }

    /// Registers a component before the manager is spawned.
    pub fn register(&mut self, component: Arc<dyn LifecycleComponent<E>>) {
        self.components.push(component);
    }

    /// What the registered components publish under their own
    /// [`LifecycleComponent::name`], in the order the runtime resolved.
    /// Components that publish nothing are left out.
    ///
    /// Read on demand rather than accumulated in [`register`](Self::register):
    /// `components` is already the ordered list, so a second one would only be a
    /// copy to keep in sync.
    #[must_use]
    pub fn health_providers(&self) -> Vec<(&'static str, Arc<dyn HealthStatus>)> {
        self.components
            .iter()
            .filter_map(|component| {
                component
                    .health()
                    .map(|provider| (component.name(), provider))
            })
            .collect()
    }

    /// Spawns the manager and returns the owner's handle.
    #[must_use]
    pub fn spawn(self) -> LifecycleHandle<E> {
        LifecycleHandle {
            actor: Spawn::spawn(self),
        }
    }

    async fn admit(&self, event: E) -> Result<Accepted, LifecycleError> {
        let outcome = self.config.lease_policy.outcome(&event);
        let guards = HeldGuards::acquire(
            &event.guards(),
            outcome,
            &self.config.http_protector,
            &self.config.communication,
        )
        .await?;

        let (sender, completion) = oneshot::channel();
        let components = self.components.clone();
        let lease_released_before = self.config.lease_released_before;
        spawn_named!("lifecycle-dispatch", async move {
            let result = dispatch(&components, &event, guards, lease_released_before).await;
            if sender.send(result).is_err() {
                tracing::debug!("Nobody was waiting for the lifecycle dispatch to complete");
            }
        });

        Ok(Accepted { completion })
    }
}

impl<E: LifecycleEvent> kameo::Actor for LifecycleManager<E> {
    type Args = Self;
    type Error = Infallible;

    async fn on_start(args: Self::Args, _actor_ref: ActorRef<Self>) -> Result<Self, Self::Error> {
        Ok(args)
    }
}

/// Registers one component with a running manager.
struct Register<E: LifecycleEvent>(Arc<dyn LifecycleComponent<E>>);

impl<E: LifecycleEvent> Message<Register<E>> for LifecycleManager<E> {
    type Reply = ();

    async fn handle(&mut self, msg: Register<E>, _ctx: &mut Context<Self, Self::Reply>) {
        self.register(msg.0);
    }
}

/// Asks the manager to admit a dispatch.
struct Accept<E: LifecycleEvent>(E);

impl<E: LifecycleEvent> Message<Accept<E>> for LifecycleManager<E> {
    type Reply = Result<Accepted, LifecycleError>;

    async fn handle(
        &mut self,
        msg: Accept<E>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.admit(msg.0).await
    }
}

/// The owner's handle to a spawned [`LifecycleManager`].
///
/// Holds the strong `ActorRef`. Components must take
/// [`downgrade`](Self::downgrade) instead, see the module documentation.
pub struct LifecycleHandle<E: LifecycleEvent> {
    actor: ActorRef<LifecycleManager<E>>,
}

impl<E: LifecycleEvent> Clone for LifecycleHandle<E> {
    fn clone(&self) -> Self {
        Self {
            actor: self.actor.clone(),
        }
    }
}

impl<E: LifecycleEvent> LifecycleHandle<E> {
    /// A handle that does not keep the manager alive.
    #[must_use]
    pub fn downgrade(&self) -> WeakLifecycleHandle<E> {
        WeakLifecycleHandle {
            actor: self.actor.downgrade(),
        }
    }

    /// Registers a component with the running manager.
    ///
    /// # Errors
    /// Returns [`ManagerStopped`] when the manager is no longer running.
    pub async fn register(
        &self,
        component: Arc<dyn LifecycleComponent<E>>,
    ) -> Result<(), ManagerStopped> {
        register(&self.actor, component).await
    }

    /// Acquires the guards and admits the dispatch, or refuses. Returns before
    /// the components run; `completion` resolves when they finish and the guards
    /// are down.
    ///
    /// # Errors
    /// Returns [`LifecycleError::GuardsUnavailable`] when the declared guards
    /// cannot be taken, which is also how a dispatch that is already in flight
    /// is refused.
    pub async fn accept(&self, event: E) -> Result<Accepted, LifecycleError> {
        accept(&self.actor, event).await
    }
}

/// A [`LifecycleHandle`] that does not keep the manager alive.
pub struct WeakLifecycleHandle<E: LifecycleEvent> {
    actor: WeakActorRef<LifecycleManager<E>>,
}

impl<E: LifecycleEvent> Clone for WeakLifecycleHandle<E> {
    fn clone(&self) -> Self {
        Self {
            actor: self.actor.clone(),
        }
    }
}

impl<E: LifecycleEvent> WeakLifecycleHandle<E> {
    /// Registers a component with the running manager.
    ///
    /// # Errors
    /// Returns [`ManagerStopped`] when the manager is no longer running.
    pub async fn register(
        &self,
        component: Arc<dyn LifecycleComponent<E>>,
    ) -> Result<(), ManagerStopped> {
        let actor = self.actor.upgrade().ok_or(ManagerStopped)?;
        register(&actor, component).await
    }

    /// See [`LifecycleHandle::accept`].
    ///
    /// # Errors
    /// Returns [`LifecycleError::GuardsUnavailable`] when the guards cannot be
    /// taken or the manager is gone.
    pub async fn accept(&self, event: E) -> Result<Accepted, LifecycleError> {
        let actor = self
            .actor
            .upgrade()
            .ok_or_else(|| LifecycleError::GuardsUnavailable(ManagerStopped.to_string()))?;
        accept(&actor, event).await
    }
}

async fn register<E: LifecycleEvent>(
    actor: &ActorRef<LifecycleManager<E>>,
    component: Arc<dyn LifecycleComponent<E>>,
) -> Result<(), ManagerStopped> {
    actor
        .ask(Register(component))
        .await
        .map_err(|_| ManagerStopped)
}

async fn accept<E: LifecycleEvent>(
    actor: &ActorRef<LifecycleManager<E>>,
    event: E,
) -> Result<Accepted, LifecycleError> {
    match actor.ask(Accept(event)).await {
        Ok(accepted) => Ok(accepted),
        Err(kameo::error::SendError::HandlerError(error)) => Err(error),
        Err(_) => Err(LifecycleError::GuardsUnavailable(
            ManagerStopped.to_string(),
        )),
    }
}

/// Runs the components and brings the guards back down afterwards.
async fn dispatch<E: LifecycleEvent>(
    components: &[Arc<dyn LifecycleComponent<E>>],
    event: &E,
    mut guards: HeldGuards,
    lease_released_before: Option<E::Stage>,
) -> Result<(), LifecycleError> {
    let dispatched = run_components(components, event, &mut guards, lease_released_before).await;

    // A failed revert leaves the runtime in an unknown state, so the transport
    // must not be resumed whatever the target asked for.
    let degraded = matches!(dispatched, Err(LifecycleError::RevertFailed { .. }));
    let lease = guards.resolve_lease(degraded).await;

    // The HTTP protection outlives the last component and comes down here.
    drop(guards);

    dispatched.and(lease)
}

/// Hands the event to the components of the stages it names, in the order the
/// runtime derived.
///
/// A component of a visited stage that the event does not concern returns
/// without doing anything and is still recorded as succeeded, which is
/// harmless: reverting a no-op is a no-op.
async fn run_components<E: LifecycleEvent>(
    components: &[Arc<dyn LifecycleComponent<E>>],
    event: &E,
    guards: &mut HeldGuards,
    lease_released_before: Option<E::Stage>,
) -> Result<(), LifecycleError> {
    let mut completed: Vec<&Arc<dyn LifecycleComponent<E>>> = Vec::new();
    let visited = event.stages();

    for component in components
        .iter()
        .filter(|component| visited.contains(&component.stage()))
    {
        // Idempotent, so naming a stage several components share hands the
        // lease back once, before the first of them.
        if lease_released_before.is_some_and(|stage| stage == component.stage()) {
            guards.resolve_lease(false).await?;
        }

        let Err(error) = component.on_event(event).await else {
            completed.push(component);
            continue;
        };

        let failure = LifecycleError::Component {
            component: component.name(),
            phase: event.name().to_owned(),
            source: Box::new(error),
        };
        revert(&completed, event, &failure).await?;
        return Err(failure);
    }

    Ok(())
}

/// Undoes the components that already succeeded, most recent first.
async fn revert<E: LifecycleEvent>(
    completed: &[&Arc<dyn LifecycleComponent<E>>],
    event: &E,
    failure: &LifecycleError,
) -> Result<(), LifecycleError> {
    for component in completed.iter().rev() {
        if let Err(error) = component.revert(event).await {
            tracing::error!(
                %failure,
                component = component.name(),
                "Revert failed, the runtime is degraded and needs a restart"
            );
            return Err(LifecycleError::RevertFailed {
                component: component.name(),
                source: Box::new(error),
            });
        }
    }
    Ok(())
}

/// Manager behavior: dispatch order, revert, guard handling and admission.
#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use async_trait::async_trait;
    use cda_interfaces::{
        communication_control::{
            CommunicationOperationFailure, CommunicationState, DisableCommunication, DisableError,
            DisableGuard, DisableReason,
        },
        config::ConfigSanityError,
        health::{HealthStatus, Status},
        http_protection::registry::{HttpProtectionConfig, HttpProtectionReason, HttpStatusCode},
        lifecycle::{DispatchGuards, LifecycleComponent, LifecycleError, LifecycleEvent, Stage},
        util::{std_ext, tokio_ext},
    };
    use tokio::sync::Notify;

    use crate::{
        HttpProtector, LeaseOutcome, LeasePolicy, LifecycleHandle, LifecycleManager,
        LifecycleManagerConfig,
    };

    /// The reload chain these tests dispatch over, in the order a runtime would
    /// have resolved it. One component per stage, so a test names a point in the
    /// chain by the stage rather than by a position.
    const CHAIN: [&str; 4] = ["files", "databases", "diagnostics", "transport"];

    /// One stage per link of [`CHAIN`].
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TestStage {
        Files,
        Databases,
        Diagnostics,
        Transport,
    }

    const TEST_STAGES: [TestStage; 4] = [
        TestStage::Files,
        TestStage::Databases,
        TestStage::Diagnostics,
        TestStage::Transport,
    ];

    impl Stage for TestStage {
        fn all() -> &'static [Self] {
            &TEST_STAGES
        }

        fn follows(&self) -> &'static [Self] {
            match self {
                TestStage::Files => &[],
                TestStage::Databases => &[TestStage::Files],
                TestStage::Diagnostics => &[TestStage::Databases],
                TestStage::Transport => &[TestStage::Diagnostics],
            }
        }

        fn name(&self) -> &'static str {
            match self {
                TestStage::Files => "files",
                TestStage::Databases => "databases",
                TestStage::Diagnostics => "diagnostics",
                TestStage::Transport => "transport",
            }
        }
    }

    /// The stage a chain component belongs to. Anything outside the chain sits
    /// in the first stage, where a dispatch reaches it along with the rest.
    fn stage_of(name: &str) -> TestStage {
        match name {
            "databases" => TestStage::Databases,
            "diagnostics" => TestStage::Diagnostics,
            "transport" => TestStage::Transport,
            _ => TestStage::Files,
        }
    }

    struct TestEvent {
        guards: DispatchGuards,
        stages: &'static [TestStage],
    }

    const TEST_EVENT_NAME: &str = "test-event";

    impl LifecycleEvent for TestEvent {
        type Stage = TestStage;

        fn name(&self) -> &'static str {
            TEST_EVENT_NAME
        }

        fn stages(&self) -> &'static [Self::Stage] {
            self.stages
        }

        fn guards(&self) -> DispatchGuards {
            self.guards.clone()
        }
    }

    fn protection() -> HttpProtectionConfig {
        HttpProtectionConfig::new(
            HttpProtectionReason::UpdateInProgress,
            HttpStatusCode::CONFLICT,
            "guarded",
        )
    }

    fn guarded_event() -> TestEvent {
        TestEvent {
            guards: DispatchGuards {
                http_protection: Some(protection()),
                communication_lease: true,
            },
            stages: &TEST_STAGES,
        }
    }

    fn unguarded_event() -> TestEvent {
        TestEvent {
            guards: DispatchGuards::default(),
            stages: &TEST_STAGES,
        }
    }

    /// An event that concerns the middle of the chain and nothing else.
    fn narrow_event() -> TestEvent {
        TestEvent {
            guards: DispatchGuards::default(),
            stages: &[TestStage::Databases, TestStage::Diagnostics],
        }
    }

    struct ProtectionToken {
        active: Arc<AtomicUsize>,
    }

    impl Drop for ProtectionToken {
        fn drop(&mut self) {
            self.active.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// Counts the HTTP protections that are currently installed.
    #[derive(Default)]
    struct CountingProtector {
        active: Arc<AtomicUsize>,
    }

    impl CountingProtector {
        fn active(&self) -> usize {
            self.active.load(Ordering::SeqCst)
        }
    }

    impl HttpProtector for CountingProtector {
        fn protect(
            &self,
            _config: HttpProtectionConfig,
        ) -> Result<Box<dyn Send>, ConfigSanityError> {
            self.active.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(ProtectionToken {
                active: Arc::clone(&self.active),
            }))
        }
    }

    #[derive(Debug, Default)]
    struct TransportState {
        leased: bool,
        up: bool,
        log: Vec<&'static str>,
    }

    /// The transport the dispatch takes its exclusive disable lease from.
    #[derive(Default)]
    struct Transport {
        state: Arc<Mutex<TransportState>>,
    }

    impl Transport {
        fn enabled() -> Arc<Self> {
            let transport = Self::default();
            std_ext::lock_mutex(&transport.state).up = true;
            Arc::new(transport)
        }

        fn lease_held(&self) -> bool {
            std_ext::lock_mutex(&self.state).leased
        }

        fn up(&self) -> bool {
            std_ext::lock_mutex(&self.state).up
        }

        fn log(&self) -> Vec<&'static str> {
            std_ext::lock_mutex(&self.state).log.clone()
        }
    }

    #[derive(Debug)]
    struct DisableLease {
        state: Arc<Mutex<TransportState>>,
        displaced_up: bool,
        resolved: bool,
    }

    #[async_trait]
    impl DisableGuard for DisableLease {
        async fn release(
            mut self: Box<Self>,
        ) -> Result<CommunicationState, CommunicationOperationFailure> {
            self.resolved = true;
            let displaced_up = self.displaced_up;
            {
                let mut state = std_ext::lock_mutex(&self.state);
                state.leased = false;
                state.up = displaced_up;
                state.log.push("release");
            }
            Ok(if displaced_up {
                CommunicationState::Enabled
            } else {
                CommunicationState::Disabled
            })
        }

        async fn finish(mut self: Box<Self>) -> Result<(), CommunicationOperationFailure> {
            self.resolved = true;
            let mut state = std_ext::lock_mutex(&self.state);
            state.leased = false;
            state.log.push("finish");
            Ok(())
        }
    }

    impl Drop for DisableLease {
        fn drop(&mut self) {
            if self.resolved {
                return;
            }
            let mut state = std_ext::lock_mutex(&self.state);
            state.leased = false;
            state.log.push("drop");
        }
    }

    #[async_trait]
    impl DisableCommunication for Transport {
        async fn disable(
            &self,
            _reason: DisableReason,
        ) -> Result<Box<dyn DisableGuard>, DisableError> {
            let mut state = std_ext::lock_mutex(&self.state);
            if state.leased {
                return Err(DisableError::InUse);
            }
            state.leased = true;
            let displaced_up = state.up;
            state.up = false;
            state.log.push("disable");
            Ok(Box::new(DisableLease {
                state: Arc::clone(&self.state),
                displaced_up,
                resolved: false,
            }))
        }
    }

    struct FixedOutcome(LeaseOutcome);

    impl LeasePolicy<TestEvent> for FixedOutcome {
        fn outcome(&self, _event: &TestEvent) -> LeaseOutcome {
            self.0
        }
    }

    type Log = Arc<Mutex<Vec<String>>>;

    #[derive(Debug, thiserror::Error)]
    #[error("Component {0} refused the event")]
    struct ComponentFailure(&'static str);

    /// Reports the status it was built with, so a component has something to
    /// publish.
    struct FixedStatus(Status);

    #[async_trait]
    impl HealthStatus for FixedStatus {
        async fn status(&self) -> Status {
            self.0
        }
    }

    /// A component that writes down what it was asked to do.
    struct RecordingComponent {
        name: &'static str,
        stage: TestStage,
        fails: bool,
        revert_fails: bool,
        log: Log,
        gate: Option<Arc<Notify>>,
        probe: Option<Arc<Transport>>,
        health: Option<Arc<dyn HealthStatus>>,
    }

    impl RecordingComponent {
        fn new(name: &'static str, log: &Log) -> Self {
            Self {
                name,
                stage: stage_of(name),
                fails: false,
                revert_fails: false,
                log: Arc::clone(log),
                gate: None,
                probe: None,
                health: None,
            }
        }

        fn failing(mut self) -> Self {
            self.fails = true;
            self
        }

        fn failing_revert(mut self) -> Self {
            self.revert_fails = true;
            self
        }

        fn gated(mut self, gate: &Arc<Notify>) -> Self {
            self.gate = Some(Arc::clone(gate));
            self
        }

        fn probing(mut self, transport: &Arc<Transport>) -> Self {
            self.probe = Some(Arc::clone(transport));
            self
        }

        fn publishing(mut self, status: Status) -> Self {
            self.health = Some(Arc::new(FixedStatus(status)) as Arc<dyn HealthStatus>);
            self
        }

        fn push(&self, entry: String) {
            std_ext::lock_mutex(&self.log).push(entry);
        }

        fn shared(self) -> Arc<dyn LifecycleComponent<TestEvent>> {
            Arc::new(self)
        }
    }

    #[async_trait]
    impl LifecycleComponent<TestEvent> for RecordingComponent {
        fn name(&self) -> &'static str {
            self.name
        }

        fn stage(&self) -> TestStage {
            self.stage
        }

        async fn on_event(&self, _event: &TestEvent) -> Result<(), LifecycleError> {
            if let Some(transport) = &self.probe {
                let held = transport.lease_held();
                self.push(format!("{}:lease={held}", self.name));
            }
            self.push(format!("{}:event", self.name));

            if let Some(gate) = &self.gate {
                gate.notified().await;
            }

            if self.fails {
                return Err(LifecycleError::Component {
                    component: self.name,
                    phase: TEST_EVENT_NAME.to_owned(),
                    source: Box::new(ComponentFailure(self.name)),
                });
            }
            Ok(())
        }

        fn health(&self) -> Option<Arc<dyn HealthStatus>> {
            self.health.clone()
        }

        async fn revert(&self, _event: &TestEvent) -> Result<(), LifecycleError> {
            self.push(format!("{}:revert", self.name));
            if self.revert_fails {
                return Err(LifecycleError::Component {
                    component: self.name,
                    phase: TEST_EVENT_NAME.to_owned(),
                    source: Box::new(ComponentFailure(self.name)),
                });
            }
            Ok(())
        }
    }

    /// A component the event does not concern: it records nothing and succeeds.
    struct Indifferent;

    #[async_trait]
    impl LifecycleComponent<TestEvent> for Indifferent {
        fn name(&self) -> &'static str {
            "indifferent"
        }

        fn stage(&self) -> TestStage {
            TestStage::Files
        }

        async fn on_event(&self, _event: &TestEvent) -> Result<(), LifecycleError> {
            Ok(())
        }
    }

    struct Harness {
        handle: LifecycleHandle<TestEvent>,
        http: Arc<CountingProtector>,
        log: Log,
    }

    fn harness(
        transport: Arc<Transport>,
        outcome: LeaseOutcome,
        lease_released_before: Option<TestStage>,
    ) -> Harness {
        let http = Arc::new(CountingProtector::default());
        let manager = LifecycleManager::new(LifecycleManagerConfig {
            http_protector: Arc::clone(&http) as Arc<dyn HttpProtector>,
            communication: transport as Arc<dyn DisableCommunication>,
            lease_policy: Arc::new(FixedOutcome(outcome)),
            lease_released_before,
        });

        Harness {
            handle: manager.spawn(),
            http,
            log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    impl Harness {
        async fn register(&self, components: Vec<Arc<dyn LifecycleComponent<TestEvent>>>) {
            for component in components {
                self.handle
                    .register(component)
                    .await
                    .expect("manager is running");
            }
        }

        async fn run(&self, event: TestEvent) -> Result<(), LifecycleError> {
            let accepted = self.handle.accept(event).await.expect("dispatch admitted");
            accepted
                .completion
                .await
                .expect("the dispatch task reports completion")
        }

        fn entries(&self) -> Vec<String> {
            std_ext::lock_mutex(&self.log).clone()
        }
    }

    /// The chain, each component probing the transport so a test can see both what
    /// ran and what it saw.
    fn probing_chain(
        harness: &Harness,
        transport: &Arc<Transport>,
    ) -> Vec<Arc<dyn LifecycleComponent<TestEvent>>> {
        CHAIN
            .iter()
            .map(|name| {
                RecordingComponent::new(name, &harness.log)
                    .probing(transport)
                    .shared()
            })
            .collect()
    }

    /// Every component of a visited stage sees the event, in the order the runtime
    /// resolved, and the one it does not concern goes through without recording
    /// anything.
    #[tokio::test]
    async fn every_component_sees_the_event_in_the_resolved_order() {
        let harness = harness(
            Transport::enabled(),
            LeaseOutcome::Release,
            Some(TestStage::Transport),
        );
        harness
            .register(vec![
                RecordingComponent::new("files", &harness.log).shared(),
                Arc::new(Indifferent) as Arc<dyn LifecycleComponent<TestEvent>>,
                RecordingComponent::new("databases", &harness.log).shared(),
                RecordingComponent::new("diagnostics", &harness.log).shared(),
                RecordingComponent::new("transport", &harness.log).shared(),
            ])
            .await;

        harness
            .run(unguarded_event())
            .await
            .expect("dispatch works");

        assert_eq!(
            harness.entries(),
            vec![
                "files:event",
                "databases:event",
                "diagnostics:event",
                "transport:event"
            ]
        );
    }

    /// An event names the stages it visits, and the components of every other
    /// stage are left alone rather than handed an event they would return from.
    #[tokio::test]
    async fn an_event_reaches_only_the_components_of_the_stages_it_names() {
        let harness = harness(
            Transport::enabled(),
            LeaseOutcome::Release,
            Some(TestStage::Transport),
        );
        harness
            .register(
                CHAIN
                    .iter()
                    .map(|name| RecordingComponent::new(name, &harness.log).shared())
                    .collect(),
            )
            .await;

        harness.run(narrow_event()).await.expect("dispatch works");

        assert_eq!(
            harness.entries(),
            vec!["databases:event", "diagnostics:event"]
        );
    }

    #[tokio::test]
    async fn failure_reverts_earlier_components_in_reverse_order() {
        let harness = harness(
            Transport::enabled(),
            LeaseOutcome::Release,
            Some(TestStage::Transport),
        );
        harness
            .register(vec![
                RecordingComponent::new("files", &harness.log).shared(),
                RecordingComponent::new("databases", &harness.log).shared(),
                RecordingComponent::new("diagnostics", &harness.log)
                    .failing()
                    .shared(),
                RecordingComponent::new("transport", &harness.log).shared(),
            ])
            .await;

        let error = harness
            .run(unguarded_event())
            .await
            .expect_err("the third component fails");

        assert_eq!(
            harness.entries(),
            vec![
                "files:event",
                "databases:event",
                "diagnostics:event",
                "databases:revert",
                "files:revert"
            ]
        );
        match error {
            LifecycleError::Component {
                component, phase, ..
            } => {
                assert_eq!(component, "diagnostics");
                assert_eq!(phase, TEST_EVENT_NAME);
            }
            other => panic!("expected a component failure, got {other:?}"),
        }
    }

    /// A component that ignores the event still counts as succeeded, so a later
    /// failure reverts it. Reverting a no-op is a no-op, which is why counting it
    /// costs nothing.
    #[tokio::test]
    async fn a_component_that_ignored_the_event_is_reverted_without_effect() {
        let harness = harness(
            Transport::enabled(),
            LeaseOutcome::Release,
            Some(TestStage::Transport),
        );
        harness
            .register(vec![
                Arc::new(Indifferent) as Arc<dyn LifecycleComponent<TestEvent>>,
                RecordingComponent::new("databases", &harness.log)
                    .failing()
                    .shared(),
            ])
            .await;

        let error = harness
            .run(unguarded_event())
            .await
            .expect_err("the second component fails");

        assert!(matches!(error, LifecycleError::Component { .. }), "{error}");
        assert_eq!(harness.entries(), vec!["databases:event"]);
    }

    #[tokio::test]
    async fn failing_revert_surfaces_as_revert_failed() {
        let harness = harness(
            Transport::enabled(),
            LeaseOutcome::Release,
            Some(TestStage::Transport),
        );
        harness
            .register(vec![
                RecordingComponent::new("files", &harness.log)
                    .failing_revert()
                    .shared(),
                RecordingComponent::new("databases", &harness.log)
                    .failing()
                    .shared(),
            ])
            .await;

        let error = harness
            .run(unguarded_event())
            .await
            .expect_err("the revert fails");

        match error {
            LifecycleError::RevertFailed { component, .. } => assert_eq!(component, "files"),
            other => panic!("expected RevertFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn second_accept_while_a_dispatch_is_in_flight_is_refused() {
        let gate = Arc::new(Notify::new());
        let harness = harness(
            Transport::enabled(),
            LeaseOutcome::Release,
            Some(TestStage::Transport),
        );
        harness
            .register(vec![
                RecordingComponent::new("files", &harness.log)
                    .gated(&gate)
                    .shared(),
            ])
            .await;

        let accepted = harness
            .handle
            .accept(guarded_event())
            .await
            .expect("the first dispatch is admitted");

        let refused = harness
            .handle
            .accept(guarded_event())
            .await
            .expect_err("the second dispatch is refused, not queued");
        assert!(matches!(refused, LifecycleError::LeaseUnavailable(_)));

        gate.notify_waiters();
        accepted
            .completion
            .await
            .expect("completion is reported")
            .expect("the dispatch succeeds");

        // Once the lease is back, a further dispatch is admitted again.
        harness
            .handle
            .accept(guarded_event())
            .await
            .expect("the lease is free again");
    }

    #[tokio::test]
    async fn deferred_target_leaves_the_transport_down() {
        let transport = Transport::enabled();
        let harness = harness(
            Arc::clone(&transport),
            LeaseOutcome::Drop,
            Some(TestStage::Transport),
        );
        harness
            .register(vec![
                RecordingComponent::new("files", &harness.log).shared(),
            ])
            .await;

        harness.run(guarded_event()).await.expect("dispatch works");

        // No "release": the transport is never bounced up on its way to staying down.
        assert_eq!(transport.log(), vec!["disable", "drop"]);
        assert!(!transport.up());
        assert!(!transport.lease_held());
    }

    #[tokio::test]
    async fn enabled_target_restores_the_transport_it_displaced() {
        let transport = Transport::enabled();
        let harness = harness(
            Arc::clone(&transport),
            LeaseOutcome::Release,
            Some(TestStage::Transport),
        );
        harness
            .register(vec![
                RecordingComponent::new("files", &harness.log).shared(),
            ])
            .await;

        harness.run(guarded_event()).await.expect("dispatch works");

        assert_eq!(transport.log(), vec!["disable", "release"]);
        assert!(transport.up());
    }

    #[tokio::test]
    async fn no_component_observes_a_held_communication_lease() {
        // The lease is handed back before the named stage, so that stage and
        // everything after it run against the transport their target asked for.
        // Naming the first stage of the chain means nobody sees the lease at all.
        let transport = Transport::enabled();
        let harness = harness(
            Arc::clone(&transport),
            LeaseOutcome::Release,
            Some(TestStage::Files),
        );
        let components = probing_chain(&harness, &transport);
        harness.register(components).await;

        harness.run(guarded_event()).await.expect("dispatch works");

        let observations: Vec<String> = harness
            .entries()
            .into_iter()
            .filter(|entry| entry.contains(":lease="))
            .collect();
        assert_eq!(observations.len(), CHAIN.len());
        assert!(
            observations.iter().all(|entry| entry.ends_with("=false")),
            "a component saw a held lease: {observations:?}"
        );
        assert!(!transport.lease_held());
    }

    #[tokio::test]
    async fn the_releasing_component_and_everything_after_see_no_lease() {
        let transport = Transport::enabled();
        let harness = harness(
            Arc::clone(&transport),
            LeaseOutcome::Release,
            Some(TestStage::Transport),
        );
        let components = probing_chain(&harness, &transport);
        harness.register(components).await;

        harness.run(guarded_event()).await.expect("dispatch works");

        let observations: Vec<String> = harness
            .entries()
            .into_iter()
            .filter(|entry| entry.contains(":lease="))
            .collect();
        assert_eq!(
            observations,
            vec![
                "files:lease=true",
                "databases:lease=true",
                "diagnostics:lease=true",
                "transport:lease=false",
            ]
        );
    }

    #[tokio::test]
    async fn http_protection_outlives_the_last_component() {
        let gate = Arc::new(Notify::new());
        let transport = Transport::enabled();
        let harness = harness(
            Arc::clone(&transport),
            LeaseOutcome::Release,
            Some(TestStage::Transport),
        );
        harness
            .register(vec![
                RecordingComponent::new("transport", &harness.log)
                    .gated(&gate)
                    .shared(),
            ])
            .await;

        let accepted = harness
            .handle
            .accept(guarded_event())
            .await
            .expect("dispatch admitted");

        // The last component is still running, so the protection is still up.
        while harness.entries().is_empty() {
            tokio_ext::sleep_for(Duration::from_millis(5)).await;
        }
        assert_eq!(harness.http.active(), 1);

        gate.notify_waiters();
        accepted
            .completion
            .await
            .expect("completion is reported")
            .expect("dispatch works");

        // The protection comes down only once the dispatch is finished.
        for _ in 0..100u32 {
            if harness.http.active() == 0 {
                return;
            }
            tokio_ext::sleep_for(Duration::from_millis(10)).await;
        }
        panic!("the HTTP protection was never lifted");
    }

    /// A manager that is never spawned, for the registration-time API.
    fn unspawned_manager() -> LifecycleManager<TestEvent> {
        LifecycleManager::new(LifecycleManagerConfig {
            http_protector: Arc::new(CountingProtector::default()) as Arc<dyn HttpProtector>,
            communication: Transport::enabled() as Arc<dyn DisableCommunication>,
            lease_policy: Arc::new(FixedOutcome(LeaseOutcome::Release)),
            lease_released_before: None,
        })
    }

    #[tokio::test]
    async fn health_providers_are_collected_in_the_resolved_order() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut manager = unspawned_manager();
        // One component publishes nothing: what the others publish is read in the
        // order the runtime resolved, which is the order they were handed over in.
        for component in [
            RecordingComponent::new("files", &log)
                .publishing(Status::Failed)
                .shared(),
            RecordingComponent::new("databases", &log).shared(),
            RecordingComponent::new("diagnostics", &log)
                .publishing(Status::Up)
                .shared(),
            RecordingComponent::new("transport", &log)
                .publishing(Status::Starting)
                .shared(),
        ] {
            manager.register(component);
        }

        let mut collected = Vec::new();
        for (name, provider) in manager.health_providers() {
            collected.push((name, provider.status().await));
        }

        assert_eq!(
            collected,
            vec![
                ("files", Status::Failed),
                ("diagnostics", Status::Up),
                ("transport", Status::Starting),
            ]
        );
    }

    #[test]
    fn health_providers_are_empty_without_publishing_components() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut manager = unspawned_manager();
        manager.register(RecordingComponent::new("files", &log).shared());

        assert!(manager.health_providers().is_empty());
    }
}
