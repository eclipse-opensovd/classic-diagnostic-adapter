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

//! The three phases a component goes through, ordered by the stage graph.
//!
//! Construction runs in stage order, start runs in the same order, and stop
//! runs in the exact reverse of the start that happened. Only the first of
//! those is derived; the other two follow from it, so no order is written down
//! anywhere and none of them can disagree.
//!
//! Events are dispatched between start and stop, by [`LifecycleManager`](
//! crate::LifecycleManager) over the components this module constructed:
//! [`ConstructedRuntime::event_components`] hands them over in the derived
//! order, each carrying the stage it was placed in.
//!
//! Each phase is a separate type, so a runtime that has not been constructed
//! cannot be started and one that has not been started cannot be stopped.

use std::sync::Arc;

use async_trait::async_trait;
use cda_interfaces::{
    health::HealthStatus,
    lifecycle::{
        Component, ConstructedComponent, ErasedComponent, LifecycleComponent, LifecycleError,
        LifecycleEvent, Publishers, Resource, Resources, Stage, StagePlacement, erase,
    },
};

use crate::resolve::{self, Node, ResolveError, ResolvedOrder, StageOrder};

/// Phase label used when a start failure is reported.
const START: &str = "start";
/// Phase label used when a stop failure is reported.
const STOP: &str = "stop";

/// A registered component and where the stage graph put it, which is what
/// decides the values it may read.
struct Placed<E: LifecycleEvent> {
    placement: StagePlacement,
    component: Box<dyn ErasedComponent<E>>,
}

/// A constructed component and the stage it was placed in.
struct Participant<E: LifecycleEvent> {
    /// Carried through because a dispatch reaches the components of the stages
    /// its event names, and releases its guards at a stage boundary.
    stage: E::Stage,
    component: Arc<dyn ConstructedComponent<E>>,
}

/// Lets a constructed component be dispatched by the manager without
/// implementing the event trait twice.
#[async_trait]
impl<E: LifecycleEvent> LifecycleComponent<E> for Participant<E> {
    fn name(&self) -> &'static str {
        self.component.name()
    }

    fn stage(&self) -> E::Stage {
        self.stage
    }

    async fn on_event(&self, event: &E) -> Result<(), LifecycleError> {
        self.component.on_event(event).await
    }

    async fn revert(&self, event: &E) -> Result<(), LifecycleError> {
        self.component.revert(event).await
    }

    fn health(&self) -> Option<Arc<dyn HealthStatus>> {
        self.component.health()
    }
}

/// Components registered but not yet ordered.
pub struct LifecycleRuntime<E: LifecycleEvent> {
    components: Vec<Box<dyn ErasedComponent<E>>>,
    resources: Resources,
}

impl<E: LifecycleEvent> Default for LifecycleRuntime<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E: LifecycleEvent> LifecycleRuntime<E> {
    /// A runtime with nothing registered.
    #[must_use]
    pub fn new() -> Self {
        Self {
            components: Vec::new(),
            resources: Resources::new(),
        }
    }

    /// Publishes a value no component constructs, such as the parsed
    /// configuration the process was started with.
    pub fn provide<T: ?Sized + Resource>(&mut self, value: Arc<T>) {
        self.resources.insert(value);
    }

    /// Registers a component. Registration order does not order anything.
    pub fn register<C: Component<E>>(&mut self, component: C) {
        self.components.push(erase(component));
    }

    /// Everything seeded so far, for a caller that needs one of its own seeds
    /// back while it is still registering.
    #[must_use]
    pub fn resources(&self) -> &Resources {
        &self.resources
    }

    /// Registers a component whose associated types were already erased, for a
    /// caller that collected registrations before it had a runtime to put them
    /// in.
    pub fn register_erased(&mut self, component: Box<dyn ErasedComponent<E>>) {
        self.components.push(component);
    }

    /// Derives the order and logs it.
    ///
    /// # Errors
    /// Returns [`ResolveError`] when the declarations have no order: a stage
    /// outside the graph, a loop between stages, or a type two components
    /// provide. That a component reads only what an earlier stage published is
    /// decided when it is built, by the view it reads through.
    pub fn resolve(self) -> Result<ResolvedRuntime<E>, ResolveError> {
        let mut stages = StageOrder::derive::<E::Stage>()?;
        let nodes: Vec<Node> = self
            .components
            .iter()
            .map(|component| {
                let stage = component.stage();
                Ok(Node {
                    name: component.name(),
                    stage: stages.rank(stage)?,
                    stage_name: stage.name(),
                    provides: component.provides(),
                })
            })
            .collect::<Result<_, ResolveError>>()?;

        let (order, publishers) = resolve::resolve(&nodes, &self.resources.ids(), &mut stages)?;
        tracing::info!("{order}");

        // Reordering here is what makes every later phase a plain iteration.
        let mut registered: Vec<Option<Box<dyn ErasedComponent<E>>>> =
            self.components.into_iter().map(Some).collect();
        let components = order
            .entries()
            .iter()
            .filter_map(|entry| {
                let placement = nodes.get(entry.position())?.placement();
                let component = registered
                    .get_mut(entry.position())
                    .and_then(Option::take)?;
                Some(Placed {
                    placement,
                    component,
                })
            })
            .collect();

        Ok(ResolvedRuntime {
            order,
            components,
            resources: self.resources,
            publishers,
        })
    }
}

/// Components in the derived order, not yet built.
pub struct ResolvedRuntime<E: LifecycleEvent> {
    order: ResolvedOrder,
    components: Vec<Placed<E>>,
    resources: Resources,
    /// Who publishes what, so a component that reads a value it cannot see is
    /// told which stage publishes it.
    publishers: Publishers,
}

impl<E: LifecycleEvent> ResolvedRuntime<E> {
    /// The derived order, for anyone asking why one component ran before
    /// another.
    #[must_use]
    pub fn order(&self) -> &ResolvedOrder {
        &self.order
    }

    /// Builds every component in dependency order, each reading through a view
    /// of what the stages before it published.
    ///
    /// # Errors
    /// Returns the first component's own error, which includes a component that
    /// asks for a value no strictly earlier stage published. Nothing has been
    /// started at this point, so the components already built are dropped
    /// rather than stopped.
    pub async fn construct(self) -> Result<ConstructedRuntime<E>, LifecycleError> {
        let mut resources = self.resources;
        let mut participants = Vec::with_capacity(self.components.len());

        for mut placed in self.components {
            let stage = placed.component.stage();
            let constructed = placed
                .component
                .construct(&mut resources, &self.publishers, placed.placement)
                .await?;
            if let Some(constructed) = constructed {
                participants.push(Participant {
                    stage,
                    component: constructed,
                });
            }
        }

        Ok(ConstructedRuntime {
            order: self.order,
            participants,
            resources,
        })
    }
}

/// Everything built, nothing started.
pub struct ConstructedRuntime<E: LifecycleEvent> {
    order: ResolvedOrder,
    participants: Vec<Participant<E>>,
    resources: Resources,
}

impl<E: LifecycleEvent> ConstructedRuntime<E> {
    /// See [`ResolvedRuntime::order`].
    #[must_use]
    pub fn order(&self) -> &ResolvedOrder {
        &self.order
    }

    /// Everything the components published, for a caller that needs a value the
    /// runtime holds.
    #[must_use]
    pub fn resources(&self) -> &Resources {
        &self.resources
    }

    /// The constructed components as event participants, in the resolved order,
    /// ready to be registered with a [`LifecycleManager`](crate::LifecycleManager).
    #[must_use]
    pub fn event_components(&self) -> Vec<Arc<dyn LifecycleComponent<E>>> {
        event_components(&self.participants)
    }

    /// What the constructed components publish under their own names.
    #[must_use]
    pub fn health_providers(&self) -> Vec<(&'static str, Arc<dyn HealthStatus>)> {
        health_providers(&self.participants)
    }

    /// Starts every component in the resolved order.
    ///
    /// # Errors
    /// Returns the failing component's error. Everything already started is
    /// stopped again first, newest first, so a failed start leaves nothing up.
    pub async fn start(self) -> Result<RunningRuntime<E>, LifecycleError> {
        let mut started: Vec<Arc<dyn ConstructedComponent<E>>> = Vec::new();

        for participant in &self.participants {
            if let Err(error) = participant.component.start().await {
                let failure = failed(participant.component.name(), START, error);
                unwind(&started).await;
                return Err(failure);
            }
            started.push(Arc::clone(&participant.component));
        }

        Ok(RunningRuntime {
            order: self.order,
            participants: self.participants,
            resources: self.resources,
            started,
        })
    }
}

/// Everything started, in the order it was started.
pub struct RunningRuntime<E: LifecycleEvent> {
    order: ResolvedOrder,
    participants: Vec<Participant<E>>,
    resources: Resources,
    /// The start order as it happened, which is what stop reverses. Recorded
    /// rather than recomputed, so the two can never disagree.
    started: Vec<Arc<dyn ConstructedComponent<E>>>,
}

impl<E: LifecycleEvent> RunningRuntime<E> {
    /// See [`ResolvedRuntime::order`].
    #[must_use]
    pub fn order(&self) -> &ResolvedOrder {
        &self.order
    }

    /// See [`ConstructedRuntime::resources`].
    #[must_use]
    pub fn resources(&self) -> &Resources {
        &self.resources
    }

    /// See [`ConstructedRuntime::event_components`].
    #[must_use]
    pub fn event_components(&self) -> Vec<Arc<dyn LifecycleComponent<E>>> {
        event_components(&self.participants)
    }

    /// See [`ConstructedRuntime::health_providers`].
    #[must_use]
    pub fn health_providers(&self) -> Vec<(&'static str, Arc<dyn HealthStatus>)> {
        health_providers(&self.participants)
    }

    /// The names in the order [`start`](ConstructedRuntime::start) ran them.
    #[must_use]
    pub fn start_order(&self) -> Vec<&'static str> {
        self.started
            .iter()
            .map(|component| component.name())
            .collect()
    }

    /// Stops every started component in the exact reverse of the start order.
    ///
    /// # Errors
    /// Returns the first failure. Every component is still asked to stop: one
    /// that refuses must not strand the ones under it.
    pub async fn stop(self) -> Result<(), LifecycleError> {
        let mut first = None;

        for component in self.started.iter().rev() {
            if let Err(error) = component.stop().await {
                let failure = failed(component.name(), STOP, error);
                tracing::error!(%failure, "A component failed to stop");
                first.get_or_insert(failure);
            }
        }

        first.map_or(Ok(()), Err)
    }
}

/// Stops what a failed start already brought up, newest first.
async fn unwind<E: LifecycleEvent>(started: &[Arc<dyn ConstructedComponent<E>>]) {
    for component in started.iter().rev() {
        if let Err(error) = component.stop().await {
            tracing::error!(
                component = component.name(),
                %error,
                "A component failed to stop while unwinding a failed start"
            );
        }
    }
}

fn event_components<E: LifecycleEvent>(
    participants: &[Participant<E>],
) -> Vec<Arc<dyn LifecycleComponent<E>>> {
    participants
        .iter()
        .map(|participant| {
            Arc::new(Participant {
                stage: participant.stage,
                component: Arc::clone(&participant.component),
            }) as Arc<dyn LifecycleComponent<E>>
        })
        .collect()
}

fn health_providers<E: LifecycleEvent>(
    participants: &[Participant<E>],
) -> Vec<(&'static str, Arc<dyn HealthStatus>)> {
    participants
        .iter()
        .filter_map(|participant| {
            participant
                .component
                .health()
                .map(|provider| (participant.component.name(), provider))
        })
        .collect()
}

/// Names the component a phase failure came from.
fn failed(component: &'static str, phase: &str, source: LifecycleError) -> LifecycleError {
    LifecycleError::Component {
        component,
        phase: phase.to_owned(),
        source: Box::new(source),
    }
}

/// Resolver behavior: derived order, the three registration errors, and that
/// stop reverses the start that actually happened.
#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use cda_interfaces::{
        lifecycle::{Constructed, DispatchGuards, ResourceError, Stage, StageResources},
        util::std_ext,
    };

    use super::*;
    use crate::ResolveError;

    struct Signal;

    impl LifecycleEvent for Signal {
        type Stage = TestStage;

        fn name(&self) -> &'static str {
            "signal"
        }

        fn stages(&self) -> &'static [Self::Stage] {
            &TEST_STAGES
        }

        fn guards(&self) -> DispatchGuards {
            DispatchGuards::default()
        }
    }

    /// Build the router, mount what it serves, serve it, then report on what
    /// is being served. Mounting is a stage of its own because the routes read
    /// what the router publishes, and a stage orders nothing inside itself.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TestStage {
        Build,
        Mount,
        Serve,
        Report,
    }

    const TEST_STAGES: [TestStage; 4] = [
        TestStage::Build,
        TestStage::Mount,
        TestStage::Serve,
        TestStage::Report,
    ];

    impl Stage for TestStage {
        fn all() -> &'static [Self] {
            &TEST_STAGES
        }

        fn follows(&self) -> &'static [Self] {
            match self {
                TestStage::Build => &[],
                TestStage::Mount => &[TestStage::Build],
                TestStage::Serve => &[TestStage::Mount],
                TestStage::Report => &[TestStage::Serve],
            }
        }

        fn name(&self) -> &'static str {
            match self {
                TestStage::Build => "build",
                TestStage::Mount => "mount",
                TestStage::Serve => "serve",
                TestStage::Report => "report",
            }
        }
    }

    /// The router the route-mounting components mount on.
    struct MountPoint;

    /// The routes are mounted, so something serving them would answer.
    struct MountedRoutes;

    /// The certificate a secure listener would serve, which nothing here builds.
    struct Certificate;

    /// Which half of the lifecycle a journal entry records.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Phase {
        Construct,
        Start,
        Stop,
    }

    type Journal = Arc<Mutex<Vec<(Phase, &'static str)>>>;

    fn journal() -> Journal {
        Arc::new(Mutex::new(Vec::new()))
    }

    fn record(journal: &Journal, phase: Phase, name: &'static str) {
        std_ext::lock_mutex(journal).push((phase, name));
    }

    fn entries(journal: &Journal) -> Vec<(Phase, &'static str)> {
        std_ext::lock_mutex(journal).clone()
    }

    fn only(journal: &Journal, phase: Phase) -> Vec<&'static str> {
        entries(journal)
            .into_iter()
            .filter_map(|(recorded, name)| (recorded == phase).then_some(name))
            .collect()
    }

    /// Writes down every phase it goes through, under its component's name.
    struct Recorder {
        name: &'static str,
        journal: Journal,
    }

    #[async_trait]
    impl ConstructedComponent<Signal> for Recorder {
        fn name(&self) -> &'static str {
            self.name
        }

        async fn start(&self) -> Result<(), LifecycleError> {
            record(&self.journal, Phase::Start, self.name);
            Ok(())
        }

        async fn stop(&self) -> Result<(), LifecycleError> {
            record(&self.journal, Phase::Stop, self.name);
            Ok(())
        }
    }

    fn recorder(name: &'static str, journal: &Journal) -> Arc<dyn ConstructedComponent<Signal>> {
        Arc::new(Recorder {
            name,
            journal: Arc::clone(journal),
        })
    }

    /// Builds the router. Reads nothing, provides the mount point.
    struct Router {
        journal: Journal,
    }

    #[async_trait]
    impl Component<Signal> for Router {
        type Provides = Arc<MountPoint>;

        fn name(&self) -> &'static str {
            "router"
        }

        fn stage(&self) -> TestStage {
            TestStage::Build
        }

        async fn construct(
            self,
            _resources: &StageResources<'_>,
        ) -> Result<Constructed<Self::Provides, Signal>, LifecycleError> {
            record(&self.journal, Phase::Construct, "router");
            Ok(Constructed::new(Arc::new(MountPoint))
                .with_component(recorder("router", &self.journal)))
        }
    }

    /// Mounts the routes on the router. It reads what the router publishes, so
    /// it is a stage later rather than a value later.
    struct Routes {
        journal: Journal,
    }

    #[async_trait]
    impl Component<Signal> for Routes {
        type Provides = Arc<MountedRoutes>;

        fn name(&self) -> &'static str {
            "routes"
        }

        fn stage(&self) -> TestStage {
            TestStage::Mount
        }

        async fn construct(
            self,
            resources: &StageResources<'_>,
        ) -> Result<Constructed<Self::Provides, Signal>, LifecycleError> {
            let _mount_point = resources.get::<MountPoint>()?;
            record(&self.journal, Phase::Construct, "routes");
            Ok(Constructed::new(Arc::new(MountedRoutes))
                .with_component(recorder("routes", &self.journal)))
        }
    }

    /// Serves the mounted routes, so it comes after both. Provides nothing.
    struct Listener {
        journal: Journal,
    }

    #[async_trait]
    impl Component<Signal> for Listener {
        type Provides = ();

        fn name(&self) -> &'static str {
            "listener"
        }

        fn stage(&self) -> TestStage {
            TestStage::Serve
        }

        async fn construct(
            self,
            resources: &StageResources<'_>,
        ) -> Result<Constructed<Self::Provides, Signal>, LifecycleError> {
            let _mount_point = resources.get::<MountPoint>()?;
            let _routes = resources.get::<MountedRoutes>()?;
            record(&self.journal, Phase::Construct, "listener");
            Ok(Constructed::new(()).with_component(recorder("listener", &self.journal)))
        }
    }

    /// Would serve over TLS, and asks for a certificate nobody builds.
    struct SecureListener;

    #[async_trait]
    impl Component<Signal> for SecureListener {
        type Provides = ();

        fn name(&self) -> &'static str {
            "secure-listener"
        }

        fn stage(&self) -> TestStage {
            TestStage::Serve
        }

        async fn construct(
            self,
            resources: &StageResources<'_>,
        ) -> Result<Constructed<Self::Provides, Signal>, LifecycleError> {
            let _certificate = resources.get::<Certificate>()?;
            Ok(Constructed::new(()))
        }
    }

    /// Reads the mount point from the stage that publishes it, which is the
    /// one stage that cannot deliver it.
    struct SiblingReader;

    #[async_trait]
    impl Component<Signal> for SiblingReader {
        type Provides = ();

        fn name(&self) -> &'static str {
            "sibling-reader"
        }

        fn stage(&self) -> TestStage {
            TestStage::Build
        }

        async fn construct(
            self,
            resources: &StageResources<'_>,
        ) -> Result<Constructed<Self::Provides, Signal>, LifecycleError> {
            let _mount_point = resources.get::<MountPoint>()?;
            Ok(Constructed::new(()))
        }
    }

    /// Builds a second mount point, which leaves no way to say which one a
    /// dependent meant.
    struct DuplicateRouter;

    #[async_trait]
    impl Component<Signal> for DuplicateRouter {
        type Provides = Arc<MountPoint>;

        fn name(&self) -> &'static str {
            "duplicate-router"
        }

        fn stage(&self) -> TestStage {
            TestStage::Build
        }

        async fn construct(
            self,
            _resources: &StageResources<'_>,
        ) -> Result<Constructed<Self::Provides, Signal>, LifecycleError> {
            Ok(Constructed::new(Arc::new(MountPoint)))
        }
    }

    /// Shares the router's stage, which orders nothing inside itself, so the
    /// two are interchangeable.
    struct Metrics;

    #[async_trait]
    impl Component<Signal> for Metrics {
        type Provides = ();

        fn name(&self) -> &'static str {
            "metrics"
        }

        fn stage(&self) -> TestStage {
            TestStage::Build
        }

        async fn construct(
            self,
            _resources: &StageResources<'_>,
        ) -> Result<Constructed<Self::Provides, Signal>, LifecycleError> {
            Ok(Constructed::new(()))
        }
    }

    /// Serves without needing anything, so only its stage places it.
    struct Heartbeat;

    #[async_trait]
    impl Component<Signal> for Heartbeat {
        type Provides = ();

        fn name(&self) -> &'static str {
            "heartbeat"
        }

        fn stage(&self) -> TestStage {
            TestStage::Serve
        }

        async fn construct(
            self,
            _resources: &StageResources<'_>,
        ) -> Result<Constructed<Self::Provides, Signal>, LifecycleError> {
            Ok(Constructed::new(()))
        }
    }

    /// What a report on the running instance is published as.
    struct Summary;

    /// Publishes the summary, in the last stage.
    struct Reporter;

    #[async_trait]
    impl Component<Signal> for Reporter {
        type Provides = Arc<Summary>;

        fn name(&self) -> &'static str {
            "reporter"
        }

        fn stage(&self) -> TestStage {
            TestStage::Report
        }

        async fn construct(
            self,
            _resources: &StageResources<'_>,
        ) -> Result<Constructed<Self::Provides, Signal>, LifecycleError> {
            Ok(Constructed::new(Arc::new(Summary)))
        }
    }

    /// Reads the summary from the first stage, two stages before anything
    /// publishes one.
    struct EarlyReader;

    #[async_trait]
    impl Component<Signal> for EarlyReader {
        type Provides = ();

        fn name(&self) -> &'static str {
            "early-reader"
        }

        fn stage(&self) -> TestStage {
            TestStage::Build
        }

        async fn construct(
            self,
            resources: &StageResources<'_>,
        ) -> Result<Constructed<Self::Provides, Signal>, LifecycleError> {
            let _summary = resources.get::<Summary>()?;
            Ok(Constructed::new(()))
        }
    }

    /// Registers the three cooperating components back to front.
    fn registered_backwards(journal: &Journal) -> LifecycleRuntime<Signal> {
        let mut runtime = LifecycleRuntime::<Signal>::new();
        runtime.register(Listener {
            journal: Arc::clone(journal),
        });
        runtime.register(Routes {
            journal: Arc::clone(journal),
        });
        runtime.register(Router {
            journal: Arc::clone(journal),
        });
        runtime
    }

    /// The stage graph is the coarse order and it is authoritative: the three
    /// that cooperate are placed by it, whatever types they do or do not
    /// exchange.
    #[tokio::test]
    async fn the_stage_graph_is_the_order_that_runs() {
        let mut runtime = LifecycleRuntime::<Signal>::new();
        runtime.register(Reporter);
        runtime.register(Heartbeat);
        runtime.register(Metrics);

        let resolved = runtime.resolve().expect("the declarations have an order");

        assert_eq!(
            resolved.order().stages(),
            ["build", "mount", "serve", "report"]
        );
        assert_eq!(
            resolved.order().names(),
            ["metrics", "heartbeat", "reporter"]
        );
    }

    /// Builds `runtime` and hands back the error the construction refused
    /// with.
    async fn refused(runtime: LifecycleRuntime<Signal>) -> LifecycleError {
        runtime
            .resolve()
            .expect("the declarations have an order")
            .construct()
            .await
            .err()
            .expect("a value nothing visible publishes cannot be read")
    }

    /// A value read before the stage that publishes it has run means the stage
    /// graph and the code disagree, and the message has to name both stages so
    /// whoever reads it knows which of the two to move.
    #[tokio::test]
    async fn reading_a_value_a_later_stage_publishes_refuses_naming_both_stages() {
        let mut runtime = LifecycleRuntime::<Signal>::new();
        runtime.register(EarlyReader);
        runtime.register(Reporter);

        let error = refused(runtime).await;

        let message = error.to_string();
        assert!(
            matches!(
                error,
                LifecycleError::Resource(ResourceError::ProviderNotEarlier { .. })
            ),
            "{message}"
        );
        assert!(message.contains("early-reader"), "{message}");
        assert!(message.contains("reporter"), "{message}");
        assert!(message.contains("build"), "{message}");
        assert!(message.contains("report"), "{message}");
    }

    /// A stage orders nothing inside itself, so a component that reads what
    /// its own stage publishes would receive it in some runs and not in
    /// others. The view it reads through does not hold it at all.
    #[tokio::test]
    async fn reading_a_value_the_same_stage_publishes_refuses_naming_the_rule() {
        let journal = journal();
        let mut runtime = LifecycleRuntime::<Signal>::new();
        runtime.register(SiblingReader);
        runtime.register(Router {
            journal: Arc::clone(&journal),
        });

        let error = refused(runtime).await;

        let message = error.to_string();
        assert!(
            matches!(
                error,
                LifecycleError::Resource(ResourceError::ProviderNotEarlier { .. })
            ),
            "{message}"
        );
        assert!(message.contains("sibling-reader"), "{message}");
        assert!(message.contains("router"), "{message}");
        assert!(message.contains("build"), "{message}");
        assert!(message.contains("strictly earlier stage"), "{message}");
    }

    /// The case the whole scoping exists to allow: what an earlier stage
    /// published is there, and the component that reads it publishes in turn.
    #[tokio::test]
    async fn a_value_an_earlier_stage_published_is_read_by_the_stage_after_it() {
        let journal = journal();

        let constructed = registered_backwards(&journal)
            .resolve()
            .expect("the declarations have an order")
            .construct()
            .await
            .expect("every value read comes from an earlier stage");

        assert!(
            constructed.resources().get::<MountedRoutes>().is_some(),
            "the routes were mounted on what the stage before published"
        );
    }

    #[tokio::test]
    async fn registration_order_does_not_order_construction() {
        let journal = journal();
        let resolved = registered_backwards(&journal)
            .resolve()
            .expect("the declarations have an order");

        resolved
            .construct()
            .await
            .expect("nothing refuses to be built");

        assert_eq!(
            only(&journal, Phase::Construct),
            ["router", "routes", "listener"]
        );
    }

    /// One registration, so a test can apply the same set in several orders.
    type Registration = fn(&mut LifecycleRuntime<Signal>, &Journal);

    const ROUTER: Registration = |runtime, journal| {
        runtime.register(Router {
            journal: Arc::clone(journal),
        });
    };
    const ROUTES: Registration = |runtime, journal| {
        runtime.register(Routes {
            journal: Arc::clone(journal),
        });
    };
    const LISTENER: Registration = |runtime, journal| {
        runtime.register(Listener {
            journal: Arc::clone(journal),
        });
    };
    const METRICS: Registration = |runtime, _| runtime.register(Metrics);

    /// Applies the registrations in the order given.
    fn registered(apply: [Registration; 4], journal: &Journal) -> LifecycleRuntime<Signal> {
        let mut runtime = LifecycleRuntime::<Signal>::new();
        for register in apply {
            register(&mut runtime, journal);
        }
        runtime
    }

    /// Where a `register` call sits is incidental, so it must not reach the derived
    /// order: the declared edges decide, and nothing else does.
    #[test]
    fn every_registration_order_derives_the_same_order() {
        let journal = journal();

        for registration in [
            [ROUTER, ROUTES, LISTENER, METRICS],
            [LISTENER, ROUTES, ROUTER, METRICS],
            [METRICS, LISTENER, ROUTER, ROUTES],
            [ROUTES, METRICS, LISTENER, ROUTER],
            [LISTENER, METRICS, ROUTES, ROUTER],
        ] {
            let order = registered(registration, &journal)
                .resolve()
                .expect("the declarations have an order")
                .order()
                .names();

            let edges: Vec<&&str> = order
                .iter()
                .filter(|name| **name != "metrics")
                .collect::<Vec<_>>();
            assert_eq!(
                edges,
                [&"router", &"routes", &"listener"],
                "{registration:?}"
            );
            assert!(order.contains(&"metrics"), "{registration:?}");
        }
    }

    /// Nothing orders `metrics` against the component it shares a stage with,
    /// so where it lands is not a fact about the declarations and must not
    /// become one.
    #[test]
    fn a_component_no_edge_places_is_not_pinned_to_one_position() {
        let journal = journal();
        let mut seen = std::collections::BTreeSet::new();

        for _ in 0..64u32 {
            let order = registered([ROUTER, ROUTES, LISTENER, METRICS], &journal)
                .resolve()
                .expect("the declarations have an order")
                .order()
                .names();

            seen.insert(
                order
                    .iter()
                    .position(|name| *name == "metrics")
                    .expect("metrics is registered"),
            );
        }

        assert!(seen.len() > 1, "metrics only ever landed at {seen:?}");
    }

    #[tokio::test]
    async fn a_value_nobody_provides_refuses_naming_the_type_and_the_reader() {
        let mut runtime = LifecycleRuntime::<Signal>::new();
        runtime.register(SecureListener);

        let error = refused(runtime).await;

        let message = error.to_string();
        assert!(
            matches!(
                error,
                LifecycleError::Resource(ResourceError::MissingProvider { .. })
            ),
            "{message}"
        );
        assert!(message.contains("Certificate"), "{message}");
        assert!(message.contains("secure-listener"), "{message}");
        assert!(message.contains("serve"), "{message}");
    }

    #[test]
    fn two_providers_of_one_type_are_a_registration_error_naming_both() {
        let journal = journal();
        let mut runtime = LifecycleRuntime::<Signal>::new();
        runtime.register(Router {
            journal: Arc::clone(&journal),
        });
        runtime.register(DuplicateRouter);

        let error = runtime
            .resolve()
            .err()
            .expect("two providers of one type have no order");

        let message = error.to_string();
        assert!(
            matches!(error, ResolveError::DuplicateProvider { .. }),
            "{message}"
        );
        assert!(message.contains("router"), "{message}");
        assert!(message.contains("duplicate-router"), "{message}");
        assert!(message.contains("MountPoint"), "{message}");
    }

    #[tokio::test]
    async fn a_seeded_value_is_read_like_one_an_earlier_stage_published() {
        let mut runtime = LifecycleRuntime::<Signal>::new();
        runtime.provide(Arc::new(Certificate));
        runtime.register(SecureListener);

        runtime
            .resolve()
            .expect("a seeded value counts as provided")
            .construct()
            .await
            .expect("nothing refuses to be built");
    }

    #[tokio::test]
    async fn stop_runs_the_exact_reverse_of_start() {
        let journal = journal();
        let running = registered_backwards(&journal)
            .resolve()
            .expect("the declarations have an order")
            .construct()
            .await
            .expect("nothing refuses to be built")
            .start()
            .await
            .expect("nothing refuses to start");

        let started = running.start_order();
        assert_eq!(started, ["router", "routes", "listener"]);

        running.stop().await.expect("nothing refuses to stop");

        let mut reversed = started;
        reversed.reverse();
        assert_eq!(only(&journal, Phase::Stop), reversed);
    }

    #[tokio::test]
    async fn the_dumped_order_is_the_order_that_ran() {
        let journal = journal();
        let resolved = registered_backwards(&journal)
            .resolve()
            .expect("the declarations have an order");

        let dumped = resolved.order().to_string();
        let names = resolved.order().names();

        let running = resolved
            .construct()
            .await
            .expect("nothing refuses to be built")
            .start()
            .await
            .expect("nothing refuses to start");

        assert_eq!(names, only(&journal, Phase::Construct));
        assert_eq!(names, running.start_order());

        // The dump has to answer "why did the router run before the routes" on its
        // own.
        assert!(dumped.contains("1. [build] router"), "{dumped}");
        assert!(dumped.contains("2. [mount] routes"), "{dumped}");
        assert!(dumped.contains("3. [serve] listener"), "{dumped}");
        assert!(dumped.contains("MountPoint"), "{dumped}");
        assert!(
            dumped.contains("build -> mount -> serve -> report"),
            "{dumped}"
        );
    }
}
