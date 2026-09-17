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

//! Contracts for the runtime lifecycle.
//!
//! # Stages order, types deliver
//!
//! A [`Stage`] graph orders everything. Each stage names the stages it follows,
//! each [`Component`] names the stage it belongs to, and the topological order
//! of that graph is the order of construction, of start and, reversed, of stop.
//! It is coarse and it is written down in one place, so "what runs before what"
//! is read rather than reconstructed.
//!
//! What a component publishes delivers values, and orders nothing. It is built
//! through a [`StageResources`] view that holds exactly what the stages before
//! its own published, so reading a value from the reader's own stage or from a
//! later one is not a declaration to be checked but a lookup that fails, naming
//! both stages. That is what stops the hand written stage graph drifting away
//! from what the code actually reads. [`Resource`] documents the traps that
//! come with keying on types.
//!
//! A dispatched event names the stages it visits, and the components in those
//! stages see it in stage order. One that the event does not concern returns
//! without doing anything.

use std::{
    any::{Any, TypeId, type_name},
    sync::Arc,
};

use async_trait::async_trait;

use crate::{HashMap, health::HealthStatus, http_protection::registry::HttpProtectionConfig};

/// What the manager holds for the duration of a dispatch.
#[derive(Clone, Default)]
pub struct DispatchGuards {
    /// Non-exempt HTTP answers 409 with Retry-After while the dispatch runs.
    /// The exempt matchers are injected: `routes_accessible_during_update()`
    /// lives in `cda-sovd`, which `cda-lifecycle` must not depend on.
    pub http_protection: Option<HttpProtectionConfig>,
    /// Exclusive communication disable lease. Also what serializes dispatches:
    /// a second one fails to acquire it and is refused.
    pub communication_lease: bool,
}

/// One coarse step of the runtime's order.
///
/// The stages and their edges are the authoritative order. They are written by
/// hand, in one place, because the alternative is an order reconstructed from
/// the types fifteen components happen to exchange, which answers a different
/// question.
pub trait Stage: Copy + Eq + Send + Sync + 'static {
    /// Every stage there is, in the order ties between unordered stages are
    /// settled in.
    ///
    /// A stage left out of this is not part of the graph, and a component that
    /// declares it is refused at registration rather than quietly placed.
    fn all() -> &'static [Self];
    /// The stages this one runs after.
    fn follows(&self) -> &'static [Self];
    /// Stable name used in diagnostics and in the resolved-order dump.
    fn name(&self) -> &'static str;
}

/// One dispatchable transition of the runtime.
pub trait LifecycleEvent: Send + Sync + 'static {
    /// The vocabulary of stages the runtime this event is dispatched over is
    /// ordered by.
    type Stage: Stage;

    /// Stable name of the transition, so a subscriber that is told a dispatch
    /// finished can tell which one it was without naming the event type.
    fn name(&self) -> &'static str;
    /// The stages this event visits. Their components see it, in stage order;
    /// everything else is left alone.
    ///
    /// One table, so the order a transition runs in is read in a single place
    /// rather than reassembled from what every component declares.
    fn stages(&self) -> &'static [Self::Stage];
    /// Guards the manager takes before the first component sees the event.
    fn guards(&self) -> DispatchGuards;
}

/// Why a dispatch could not be admitted or could not complete.
#[derive(Debug, thiserror::Error)]
pub enum LifecycleError {
    /// A component rejected the event.
    #[error("Component {component} failed during {phase}: {source}")]
    Component {
        /// Name of the component that failed.
        component: &'static str,
        /// What the component was doing: a lifecycle phase, or the name of the
        /// event it was dispatched.
        phase: String,
        /// The component's own error.
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// A revert failed after a component failed. The runtime is degraded and a
    /// restart is required.
    #[error("Component {component} failed to revert: {source}")]
    RevertFailed {
        /// Name of the component whose revert failed.
        component: &'static str,
        /// The component's own error.
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// The declared guards could not be taken, so the dispatch was refused.
    #[error("Guards could not be acquired: {0}")]
    GuardsUnavailable(String),
    /// The exclusive communication lease could not be taken, which is also how
    /// a dispatch that is already in flight refuses a second one. Structured
    /// rather than a message, because a caller answers differently depending on
    /// which of the three it was.
    #[error("Communication lease unavailable: {0}")]
    LeaseUnavailable(crate::communication_control::DisableError),
    /// The communication lease the dispatch held could not be handed back, so
    /// the transport stays down until an authorized activation.
    #[error("Communication was not restored: {0}")]
    LeaseUnsettled(crate::communication_control::CommunicationOperationFailure),
    /// A component asked for a value it cannot see. Transparent, because the
    /// read already names the component, its stage and the stage it was asking.
    #[error(transparent)]
    Resource(#[from] ResourceError),
}

/// One participant in the dispatched lifecycle.
#[async_trait]
pub trait LifecycleComponent<E: LifecycleEvent>: Send + Sync + 'static {
    /// Stable name used in diagnostics and in [`LifecycleError`].
    fn name(&self) -> &'static str;
    /// The stage this component belongs to. Decides whether an event reaches
    /// it, and lets a dispatch name the point it releases a guard at.
    fn stage(&self) -> E::Stage;
    /// Applies the event to this component.
    ///
    /// # Errors
    /// Returns an error when the component cannot apply the event. The manager
    /// reverts the components that already succeeded and fails the dispatch.
    async fn on_event(&self, event: &E) -> Result<(), LifecycleError>;
    /// Undo this component's part of the event. Called only on components that
    /// already succeeded, in reverse order, when a later one fails. A failure
    /// here is reported as `RevertFailed`, not swallowed.
    ///
    /// # Errors
    /// Returns an error when the component cannot be restored to the state it
    /// held before the event.
    async fn revert(&self, _event: &E) -> Result<(), LifecycleError> {
        Ok(())
    }
    /// Published under `name()`. A component that also sets its status keeps
    /// the `HealthProvider` half itself and publishes the read-only view.
    fn health(&self) -> Option<Arc<dyn HealthStatus>> {
        None
    }
}

/// Identity of a resource: the key that orders, and a name a message can print.
///
/// [`TypeId`] supplies the edges of the dependency graph, and the rendered name
/// travels with it because a `TypeId` on its own cannot be shown to anyone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ResourceId {
    id: TypeId,
    name: &'static str,
}

impl ResourceId {
    /// Identity of `T`.
    #[must_use]
    pub fn of<T: ?Sized + 'static>() -> Self {
        Self {
            id: TypeId::of::<T>(),
            name: type_name::<T>(),
        }
    }

    /// The key this resource is stored and ordered under.
    #[must_use]
    pub fn id(&self) -> TypeId {
        self.id
    }

    /// Rendered type name. Diagnostics only, never an identity.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.name
    }
}

impl std::fmt::Display for ResourceId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.name)
    }
}

/// A value a component provides to the ones that depend on it.
///
/// Blanket implemented, so a provider names the type it hands over instead of
/// implementing anything. The bound exists to state what a shared value has to
/// be, and to give the three traps below one place to be written down.
///
/// # Declare one form of a trait object
///
/// `Arc<dyn Trait>` and `Arc<dyn Trait + Send + Sync>` are different types with
/// different [`TypeId`]s, so a provider of one does not answer a read of the
/// other and the failure reads as "nobody provides it". Give each capability a
/// single type alias and use only that.
///
/// # One provider per type
///
/// Two components providing the same type leaves no way to say which one a
/// dependent meant, so it is a registration error naming both rather than a
/// silent pick.
///
/// # Newtype anything unnamed
///
/// A shared `String` or `Arc<Configuration>` is a de-facto global: every
/// component that wants any string is wired to the one that happens to be
/// registered. Wrap it in a type named after the role it plays.
pub trait Resource: Any + Send + Sync + 'static {}

impl<T: ?Sized + Any + Send + Sync> Resource for T {}

/// One stored resource, with the identity it was stored under.
struct StoredResource {
    id: ResourceId,
    value: Box<dyn Any + Send + Sync>,
}

/// Everything constructed so far, keyed by the type it is published under.
#[derive(Default)]
pub struct Resources {
    values: HashMap<TypeId, StoredResource>,
}

impl Resources {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Stores `value` under `Arc<T>`.
    ///
    /// Replaces whatever was there, which registration has already ruled out:
    /// two providers of one type are refused before anything is constructed.
    pub fn insert<T: ?Sized + Resource>(&mut self, value: Arc<T>) {
        let id = ResourceId::of::<Arc<T>>();
        self.values.insert(
            id.id(),
            StoredResource {
                id,
                value: Box::new(value),
            },
        );
    }

    /// The value stored under `Arc<T>`, or `None` when nothing is.
    #[must_use]
    pub fn get<T: ?Sized + Resource>(&self) -> Option<Arc<T>> {
        self.values
            .get(&TypeId::of::<Arc<T>>())
            .and_then(|stored| stored.value.downcast_ref::<Arc<T>>())
            .map(Arc::clone)
    }

    /// Whether something is stored under `id`.
    #[must_use]
    pub fn contains(&self, id: TypeId) -> bool {
        self.values.contains_key(&id)
    }

    /// Identities of everything stored, so the resolver can count values that
    /// were seeded rather than constructed as provided.
    #[must_use]
    pub fn ids(&self) -> Vec<ResourceId> {
        self.values.values().map(|stored| stored.id).collect()
    }
}

/// A stage, and where it sits in the derived order.
#[derive(Clone, Copy, Debug)]
pub struct StagePlacement {
    /// Stage name, for the message a refused read prints.
    pub stage: &'static str,
    /// Position of that stage in the derived order, which is what decides
    /// whether one stage strictly precedes another.
    pub rank: usize,
}

/// Where a value comes from.
#[derive(Clone, Copy, Debug)]
pub struct Publisher {
    /// The component that publishes it.
    pub component: &'static str,
    /// The stage it is published in, or `None` for a value seeded before any
    /// stage ran, which every stage therefore sees.
    pub stage: Option<StagePlacement>,
}

/// Who publishes what.
///
/// Carried into construction so that a read of a value the reader cannot see
/// is refused with the stage it would have come from, rather than with the
/// absence the reader would otherwise be handed.
#[derive(Default)]
pub struct Publishers {
    by_type: HashMap<TypeId, Publisher>,
}

impl Publishers {
    /// An index with nothing in it.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records who publishes `resource`, handing back whoever claimed it
    /// before, which registration refuses.
    pub fn insert(&mut self, resource: ResourceId, publisher: Publisher) -> Option<Publisher> {
        self.by_type.insert(resource.id(), publisher)
    }

    /// Whoever publishes `resource`.
    #[must_use]
    pub fn get(&self, resource: ResourceId) -> Option<Publisher> {
        self.by_type.get(&resource.id()).copied()
    }
}

/// Why a component could not read a value it asked for.
#[derive(Debug, thiserror::Error)]
pub enum ResourceError {
    /// The value has no provider at all.
    #[error("Nobody provides `{resource}`, required by component {component} in stage {stage}")]
    MissingProvider {
        /// The type that has no provider.
        resource: ResourceId,
        /// The component that asked for it.
        component: &'static str,
        /// The stage it belongs to.
        stage: &'static str,
    },
    /// The value is published by the reader's own stage or by a later one. The
    /// stage graph and what the code reads disagree, and the graph is the thing
    /// to fix.
    #[error(
        "Component {component} in stage {stage} requires `{resource}`, which component {provider} \
         provides in stage {provider_stage}. A required value has to come from a strictly earlier \
         stage: a later stage has not run yet, and the components of one stage run in no order"
    )]
    ProviderNotEarlier {
        /// The component that reads too early.
        component: &'static str,
        /// The stage it belongs to.
        stage: &'static str,
        /// The value it asked for.
        resource: ResourceId,
        /// The component that publishes it.
        provider: &'static str,
        /// The stage that publishes it, which does not precede `stage`.
        provider_stage: &'static str,
    },
    /// An earlier stage published the value and the store does not hold it, so
    /// the two disagree. An internal invariant rather than a mode a caller
    /// handles.
    #[error(
        "No resource of type `{resource}` is available to component {component}, though component \
         {provider} publishes it in an earlier stage"
    )]
    Absent {
        /// The type that is not in the store.
        resource: ResourceId,
        /// The component that asked for it.
        component: &'static str,
        /// The component that was supposed to have published it.
        provider: &'static str,
    },
}

/// What one component may read: the values the stages before its own published.
///
/// A value from the component's own stage or from a later one is not in scope,
/// so "a provider has to be in a strictly earlier stage" is enforced by what a
/// component can reach rather than by a pass over a list it declares and could
/// stop reading.
pub struct StageResources<'a> {
    resources: &'a Resources,
    publishers: &'a Publishers,
    component: &'static str,
    placement: StagePlacement,
}

impl<'a> StageResources<'a> {
    /// The view `component`, placed at `placement`, constructs through.
    #[must_use]
    pub fn new(
        resources: &'a Resources,
        publishers: &'a Publishers,
        component: &'static str,
        placement: StagePlacement,
    ) -> Self {
        Self {
            resources,
            publishers,
            component,
            placement,
        }
    }

    /// The value a strictly earlier stage published under `Arc<T>`.
    ///
    /// # Errors
    /// Returns [`ResourceError::MissingProvider`] when nothing publishes
    /// `Arc<T>`, and [`ResourceError::ProviderNotEarlier`] when the stage that
    /// publishes it is this component's own or a later one.
    // The `Result` is a step towards the rule holding at compile time rather
    // than the end of it: with stages as zero-sized types, a
    // `StrictlyBefore<Later>` relation and a `Provided { type Stage; }`, the
    // bound `T::Stage: StrictlyBefore<S>` would refuse a same-stage or later
    // read before the program runs and this would hand back `&T`. Transitivity
    // has to be generated from the stage list by a `macro_rules!`, because a
    // blanket transitive impl overlaps, and `#[diagnostic::on_unimplemented]`
    // is what keeps the failure readable.
    pub fn get<T: ?Sized + Resource>(&self) -> Result<Arc<T>, ResourceError> {
        let resource = ResourceId::of::<Arc<T>>();
        let Some(publisher) = self.publishers.get(resource) else {
            return Err(ResourceError::MissingProvider {
                resource,
                component: self.component,
                stage: self.placement.stage,
            });
        };

        if let Some(published_in) = publisher.stage
            && published_in.rank >= self.placement.rank
        {
            return Err(ResourceError::ProviderNotEarlier {
                component: self.component,
                stage: self.placement.stage,
                resource,
                provider: publisher.component,
                provider_stage: published_in.stage,
            });
        }

        self.resources.get::<T>().ok_or(ResourceError::Absent {
            resource,
            component: self.component,
            provider: publisher.component,
        })
    }
}

/// What a component hands to the components that depend on it.
pub trait IntoResources: Send + 'static {
    /// The values this component publishes.
    fn type_ids() -> Vec<ResourceId>;

    /// Publishes the values for the components that come after.
    fn insert_into(self, resources: &mut Resources);
}

impl IntoResources for () {
    fn type_ids() -> Vec<ResourceId> {
        Vec::new()
    }

    fn insert_into(self, _resources: &mut Resources) {}
}

impl<T: ?Sized + Resource> IntoResources for Arc<T> {
    fn type_ids() -> Vec<ResourceId> {
        vec![ResourceId::of::<Arc<T>>()]
    }

    fn insert_into(self, resources: &mut Resources) {
        resources.insert(self);
    }
}

// Written out at the two widths components publish at, rather than generated
// over eight of them: a macro over arities nothing uses is a stand-in for
// variadic generics, and a third value to publish is a line to add here.
impl<A: IntoResources, B: IntoResources> IntoResources for (A, B) {
    fn type_ids() -> Vec<ResourceId> {
        let mut ids = A::type_ids();
        ids.extend(B::type_ids());
        ids
    }

    fn insert_into(self, resources: &mut Resources) {
        let (first, second) = self;
        first.insert_into(resources);
        second.insert_into(resources);
    }
}

impl<A: IntoResources, B: IntoResources, C: IntoResources> IntoResources for (A, B, C) {
    fn type_ids() -> Vec<ResourceId> {
        let mut ids = A::type_ids();
        ids.extend(B::type_ids());
        ids.extend(C::type_ids());
        ids
    }

    fn insert_into(self, resources: &mut Resources) {
        let (first, second, third) = self;
        first.insert_into(resources);
        second.insert_into(resources);
        third.insert_into(resources);
    }
}

/// The half of a component that survives construction.
///
/// One object answers the three phases that follow construction: it is started,
/// dispatched events, and stopped. Everything is defaulted, so a component that
/// takes part in only one of them implements only that one.
#[async_trait]
pub trait ConstructedComponent<E: LifecycleEvent>: Send + Sync + 'static {
    /// Stable name used in diagnostics and in [`LifecycleError`].
    fn name(&self) -> &'static str;

    /// Brings this component up, in dependency order.
    ///
    /// # Errors
    /// Returns an error when the component cannot come up. Everything already
    /// started is stopped again, newest first.
    async fn start(&self) -> Result<(), LifecycleError> {
        Ok(())
    }

    /// Takes this component down, in the reverse of the start order.
    ///
    /// # Errors
    /// Returns an error when the component cannot be taken down. The components
    /// below it are still stopped.
    async fn stop(&self) -> Result<(), LifecycleError> {
        Ok(())
    }

    /// Applies an event dispatched between start and stop.
    ///
    /// # Errors
    /// Returns an error when the component cannot apply the event. The manager
    /// reverts the components that already succeeded and fails the dispatch.
    async fn on_event(&self, _event: &E) -> Result<(), LifecycleError> {
        Ok(())
    }

    /// Undoes this component's part of an event, see
    /// [`LifecycleComponent::revert`].
    ///
    /// # Errors
    /// Returns an error when the component cannot be restored to the state it
    /// held before the event.
    async fn revert(&self, _event: &E) -> Result<(), LifecycleError> {
        Ok(())
    }

    /// Published under [`name`](Self::name).
    fn health(&self) -> Option<Arc<dyn HealthStatus>> {
        None
    }
}

/// What a component hands back once it is built.
pub struct Constructed<P, E: LifecycleEvent> {
    /// The values the dependents were waiting for.
    pub provides: P,
    /// The half that is started, dispatched events and stopped. `None` for a
    /// component that only publishes values.
    pub component: Option<Arc<dyn ConstructedComponent<E>>>,
}

impl<P, E: LifecycleEvent> Constructed<P, E> {
    /// A component that publishes `provides` and nothing else.
    #[must_use]
    pub fn new(provides: P) -> Self {
        Self {
            provides,
            component: None,
        }
    }

    /// Attaches the half that takes part in start, events and stop.
    #[must_use]
    pub fn with_component(mut self, component: Arc<dyn ConstructedComponent<E>>) -> Self {
        self.component = Some(component);
        self
    }
}

/// One participant in the dependency-ordered lifecycle.
#[async_trait]
pub trait Component<E: LifecycleEvent>: Send + 'static {
    /// What this component publishes for the components after it.
    type Provides: IntoResources;

    /// Stable name used in diagnostics and in the resolved-order dump.
    fn name(&self) -> &'static str;

    /// The stage this component belongs to, which is what orders it against
    /// every component outside that stage.
    fn stage(&self) -> E::Stage;

    /// Builds from the values the stages before this one published.
    ///
    /// Asynchronous because the values components hand each other are built by
    /// binding sockets, opening storage and reading files, none of which can be
    /// done from a synchronous constructor.
    ///
    /// # Errors
    /// Returns an error when the component cannot be built, and
    /// [`LifecycleError::Resource`] when it reads a value no strictly earlier
    /// stage published.
    async fn construct(
        self,
        resources: &StageResources<'_>,
    ) -> Result<Constructed<Self::Provides, E>, LifecycleError>;
}

/// A [`Component`] with its associated type erased.
///
/// `Component` cannot be a trait object: `Provides` is an associated type and
/// `construct` takes `self` by value. Registration keeps what the component
/// publishes, which is static per component, and moves the value out of the
/// erased holder when construction runs.
#[async_trait]
pub trait ErasedComponent<E: LifecycleEvent>: Send + 'static {
    /// See [`Component::name`].
    fn name(&self) -> &'static str;

    /// See [`Component::stage`].
    fn stage(&self) -> E::Stage;

    /// The values this component publishes.
    fn provides(&self) -> Vec<ResourceId>;

    /// Builds the component from what the stages before `placement` published,
    /// and publishes what it provides into `resources`.
    ///
    /// # Errors
    /// Returns an error when the component refuses to be built, or when it
    /// reads a value no strictly earlier stage published.
    async fn construct(
        &mut self,
        resources: &mut Resources,
        publishers: &Publishers,
        placement: StagePlacement,
    ) -> Result<Option<Arc<dyn ConstructedComponent<E>>>, LifecycleError>;
}

/// Phase label used when a construction failure is reported.
const CONSTRUCT: &str = "construct";

/// Holds a registered [`Component`] until construction moves it out.
struct ErasedHolder<E: LifecycleEvent, C> {
    name: &'static str,
    /// Read off the component while it is still here, because the declarations
    /// outlive the value construction moves out.
    stage: E::Stage,
    component: Option<C>,
    _event: std::marker::PhantomData<fn() -> E>,
}

/// Erases `component` so registrations of different components share one list.
pub fn erase<E, C>(component: C) -> Box<dyn ErasedComponent<E>>
where
    E: LifecycleEvent,
    C: Component<E>,
{
    Box::new(ErasedHolder {
        name: component.name(),
        stage: component.stage(),
        component: Some(component),
        _event: std::marker::PhantomData,
    })
}

#[async_trait]
impl<E, C> ErasedComponent<E> for ErasedHolder<E, C>
where
    E: LifecycleEvent,
    C: Component<E>,
{
    fn name(&self) -> &'static str {
        self.name
    }

    fn stage(&self) -> E::Stage {
        self.stage
    }

    fn provides(&self) -> Vec<ResourceId> {
        C::Provides::type_ids()
    }

    async fn construct(
        &mut self,
        resources: &mut Resources,
        publishers: &Publishers,
        placement: StagePlacement,
    ) -> Result<Option<Arc<dyn ConstructedComponent<E>>>, LifecycleError> {
        let component = self
            .component
            .take()
            .ok_or_else(|| LifecycleError::Component {
                component: self.name,
                phase: CONSTRUCT.to_owned(),
                source: "Component was already constructed".into(),
            })?;

        let constructed = {
            let scoped = StageResources::new(resources, publishers, self.name, placement);
            component.construct(&scoped).await?
        };
        constructed.provides.insert_into(resources);
        Ok(constructed.component)
    }
}

/// What a component may read, which is what the stages before it published.
#[cfg(test)]
mod tests {
    use super::*;

    /// A value one component publishes and others read.
    struct Router;

    /// The store and the index for a `Router` published in `stage`.
    fn published_in(stage: &'static str, rank: usize) -> (Resources, Publishers) {
        let mut resources = Resources::new();
        resources.insert(Arc::new(Router));
        let mut publishers = Publishers::new();
        publishers.insert(
            ResourceId::of::<Arc<Router>>(),
            Publisher {
                component: "router",
                stage: Some(StagePlacement { stage, rank }),
            },
        );
        (resources, publishers)
    }

    fn reader<'a>(
        resources: &'a Resources,
        publishers: &'a Publishers,
        stage: &'static str,
        rank: usize,
    ) -> StageResources<'a> {
        StageResources::new(
            resources,
            publishers,
            "listener",
            StagePlacement { stage, rank },
        )
    }

    #[test]
    fn a_value_an_earlier_stage_published_is_read() {
        let (resources, publishers) = published_in("build", 0);

        let read = reader(&resources, &publishers, "serve", 1).get::<Router>();

        assert!(read.is_ok(), "{:?}", read.err());
    }

    /// A stage orders nothing inside itself, so a value its own stage publishes
    /// would reach the reader on some runs and not others.
    #[test]
    fn a_value_the_same_stage_publishes_is_refused_naming_both_stages() {
        let (resources, publishers) = published_in("build", 1);

        let error = reader(&resources, &publishers, "build", 1)
            .get::<Router>()
            .err()
            .expect("one stage orders nothing inside itself");

        let message = error.to_string();
        assert!(
            matches!(error, ResourceError::ProviderNotEarlier { .. }),
            "{message}"
        );
        assert!(message.contains("listener"), "{message}");
        assert!(message.contains("router"), "{message}");
        assert!(message.contains("build"), "{message}");
        assert!(message.contains("strictly earlier stage"), "{message}");
    }

    #[test]
    fn a_value_a_later_stage_publishes_is_refused_naming_both_stages() {
        let (resources, publishers) = published_in("report", 2);

        let error = reader(&resources, &publishers, "build", 0)
            .get::<Router>()
            .err()
            .expect("a later stage has not run yet");

        let message = error.to_string();
        assert!(
            matches!(error, ResourceError::ProviderNotEarlier { .. }),
            "{message}"
        );
        assert!(message.contains("build"), "{message}");
        assert!(message.contains("report"), "{message}");
        assert!(message.contains("Router"), "{message}");
    }

    /// Seeded before any stage ran, so no stage can be too early for it.
    #[test]
    fn a_seeded_value_is_read_from_the_first_stage() {
        let mut resources = Resources::new();
        resources.insert(Arc::new(Router));
        let mut publishers = Publishers::new();
        publishers.insert(
            ResourceId::of::<Arc<Router>>(),
            Publisher {
                component: "the runtime root",
                stage: None,
            },
        );

        let read = reader(&resources, &publishers, "build", 0).get::<Router>();

        assert!(read.is_ok(), "{:?}", read.err());
    }

    #[test]
    fn a_value_nobody_publishes_is_refused_naming_the_type_and_the_reader() {
        let resources = Resources::new();
        let publishers = Publishers::new();

        let error = reader(&resources, &publishers, "serve", 1)
            .get::<Router>()
            .err()
            .expect("nothing publishes it");

        let message = error.to_string();
        assert!(
            matches!(error, ResourceError::MissingProvider { .. }),
            "{message}"
        );
        assert!(message.contains("Router"), "{message}");
        assert!(message.contains("listener"), "{message}");
        assert!(message.contains("serve"), "{message}");
    }
}
