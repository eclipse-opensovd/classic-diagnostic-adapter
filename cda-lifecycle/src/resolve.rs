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

//! Deriving a construction order from the stage graph.
//!
//! The stage graph is the whole of the order: a component belongs to exactly
//! one stage and runs in its stage's turn, and inside a stage nothing is
//! ordered at all. The types components exchange deliver values and place
//! nothing, which is why a value a component reads has to come from a strictly
//! earlier stage. What can be decided from the declarations alone is reported
//! here, before anything is built; that a component reads only what an earlier
//! stage published is decided by the view it constructs through,
//! [`StageResources`](cda_interfaces::lifecycle::StageResources).

use std::fmt;

use cda_interfaces::{
    HashMap,
    lifecycle::{Publisher, Publishers, ResourceId, Stage, StagePlacement},
};

/// What a value seeded before any component ran is attributed to.
const ROOT: &str = "the runtime root";

/// Why a set of registrations has no construction order.
///
/// Every variant is decided from the declarations alone, so all of them are
/// raised before the first component is built.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// Two providers of one type. Which one a dependent meant is undecidable,
    /// so it is refused rather than picked.
    #[error("Components {first} and {second} both provide `{resource}`")]
    DuplicateProvider {
        /// The type with more than one provider.
        resource: ResourceId,
        /// The component that claimed it first.
        first: &'static str,
        /// The component that claimed it again.
        second: &'static str,
    },
    /// The stage graph closes a loop, so the stages themselves have no order.
    #[error("Stages form a cycle, each following the next: {}", .cycle.join(", "))]
    StageCycle {
        /// The loop, closed by repeating the stage it started at.
        cycle: Vec<&'static str>,
    },
    /// A stage nothing lists in `Stage::all`, so the graph does not contain it.
    #[error("Stage {stage} is not part of the stage graph")]
    UnknownStage {
        /// The stage that is missing from `Stage::all`.
        stage: &'static str,
    },
}

/// The stage graph, topologically sorted.
///
/// Stages that no chain of edges separates are interchangeable, exactly as
/// interchangeable components are, and are settled the same way: shuffled in
/// debug and test builds so that a hidden assumption about their order fails a
/// test run, and picked by name in release. Where a stage sits in
/// [`Stage::all`] therefore decides nothing, any more than where a `register`
/// call sits does; only the declared edges do.
pub(crate) struct StageOrder {
    sorted: Vec<&'static str>,
    /// Rank per stage, keyed by its position in [`Stage::all`].
    ranks: Vec<usize>,
    /// Carried on so the components draw from the same seed the stages did:
    /// one logged seed replays both halves of the order.
    ties: TieBreak,
}

impl StageOrder {
    /// Sorts the stage graph of `S`.
    ///
    /// # Errors
    /// Returns [`ResolveError::StageCycle`] when the declared edges close a
    /// loop, and [`ResolveError::UnknownStage`] when one names a stage that
    /// [`Stage::all`] leaves out.
    pub(crate) fn derive<S: Stage>() -> Result<Self, ResolveError> {
        Self::derive_with::<S>(TieBreak::new())
    }

    fn derive_with<S: Stage>(mut ties: TieBreak) -> Result<Self, ResolveError> {
        let stages = S::all();
        let position = |stage: &S| -> Result<usize, ResolveError> {
            stages
                .iter()
                .position(|candidate| candidate == stage)
                .ok_or(ResolveError::UnknownStage {
                    stage: stage.name(),
                })
        };

        let mut outstanding = vec![0usize; stages.len()];
        let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); stages.len()];
        for (index, stage) in stages.iter().enumerate() {
            for predecessor in stage.follows() {
                let predecessor = position(predecessor)?;
                if let Some(count) = outstanding.get_mut(index) {
                    *count = count.saturating_add(1);
                }
                if let Some(list) = dependents.get_mut(predecessor) {
                    list.push(index);
                }
            }
        }

        let mut sorted = Vec::with_capacity(stages.len());
        let mut ranks = vec![0usize; stages.len()];
        let mut placed = vec![false; stages.len()];
        let mut ready: Vec<usize> = (0..stages.len())
            .filter(|index| outstanding.get(*index) == Some(&0))
            .collect();
        while !ready.is_empty() {
            let index = ready
                .swap_remove(ties.pick(&ready, |index| stages.get(index).map_or("", Stage::name)));
            if let Some(flag) = placed.get_mut(index) {
                *flag = true;
            }
            if let Some(rank) = ranks.get_mut(index) {
                *rank = sorted.len();
            }
            sorted.push(stages.get(index).map_or("", Stage::name));
            for dependent in dependents.get(index).cloned().unwrap_or_default() {
                let Some(count) = outstanding.get_mut(dependent) else {
                    continue;
                };
                *count = count.saturating_sub(1);
                if *count == 0 {
                    ready.push(dependent);
                }
            }
        }

        if sorted.len() != stages.len() {
            return Err(ResolveError::StageCycle {
                cycle: stage_cycle(stages, &placed),
            });
        }

        Ok(Self {
            sorted,
            ranks,
            ties,
        })
    }

    /// Where `stage` sits in the sorted graph.
    ///
    /// # Errors
    /// Returns [`ResolveError::UnknownStage`] when [`Stage::all`] leaves it out.
    pub(crate) fn rank<S: Stage>(&self, stage: S) -> Result<usize, ResolveError> {
        S::all()
            .iter()
            .position(|candidate| *candidate == stage)
            .and_then(|index| self.ranks.get(index).copied())
            .ok_or(ResolveError::UnknownStage {
                stage: stage.name(),
            })
    }

    /// The stage names, in the order they run.
    #[cfg(test)]
    fn names(&self) -> &[&'static str] {
        &self.sorted
    }
}

/// Names one loop out of the stages the sort could not place.
///
/// Every unplaced stage waits on one that was itself never placed, so following
/// any such edge walks into the loop after at most one step per stage.
fn stage_cycle<S: Stage>(stages: &[S], placed: &[bool]) -> Vec<&'static str> {
    let unplaced = |index: usize| placed.get(index).is_some_and(|flag| !flag);
    let Some(start) = (0..stages.len()).find(|index| unplaced(*index)) else {
        return Vec::new();
    };

    let mut path: Vec<usize> = Vec::new();
    let mut visited: HashMap<usize, usize> = HashMap::default();
    let mut current = start;
    loop {
        if let Some(position) = visited.get(&current) {
            let mut cycle: Vec<&'static str> = path
                .get(*position..)
                .unwrap_or_default()
                .iter()
                .filter_map(|index| stages.get(*index).map(Stage::name))
                .collect();
            if let Some(first) = cycle.first().copied() {
                cycle.push(first);
            }
            return cycle;
        }
        visited.insert(current, path.len());
        path.push(current);

        let next = stages.get(current).and_then(|stage| {
            stage.follows().iter().find_map(|predecessor| {
                stages
                    .iter()
                    .position(|candidate| candidate == predecessor)
                    .filter(|index| unplaced(*index))
            })
        });
        let Some(next) = next else {
            return path
                .iter()
                .filter_map(|index| stages.get(*index).map(Stage::name))
                .collect();
        };
        current = next;
    }
}

/// One registration, reduced to what ordering needs.
pub(crate) struct Node {
    /// [`name`](cda_interfaces::lifecycle::Component::name) of the component.
    pub(crate) name: &'static str,
    /// Position of the component's stage in the sorted stage graph.
    pub(crate) stage: usize,
    /// [`name`](Stage::name) of that stage, for the dump and the messages.
    pub(crate) stage_name: &'static str,
    /// The values this component publishes.
    pub(crate) provides: Vec<ResourceId>,
}

impl Node {
    /// Where the component sits, for the view it constructs through.
    pub(crate) fn placement(&self) -> StagePlacement {
        StagePlacement {
            stage: self.stage_name,
            rank: self.stage,
        }
    }
}

/// One component in the derived order.
#[derive(Clone, Debug)]
pub struct ResolvedComponent {
    position: usize,
    name: &'static str,
    stage: &'static str,
    provides: Vec<ResourceId>,
}

impl ResolvedComponent {
    /// Index this component was registered at, so a caller can reorder its own
    /// list to match.
    #[must_use]
    pub fn position(&self) -> usize {
        self.position
    }

    /// [`name`](cda_interfaces::lifecycle::Component::name) of the component.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The stage that placed this component, which is what ordered it against
    /// everything outside that stage.
    #[must_use]
    pub fn stage(&self) -> &'static str {
        self.stage
    }

    /// The values this component publishes.
    #[must_use]
    pub fn provides(&self) -> &[ResourceId] {
        &self.provides
    }
}

/// The order the resolver derived, in construction order.
///
/// Rendered rather than only walked, because with a derived order "why did X
/// run before Y" has to be answerable from a log line rather than by reading
/// the source that no longer states it.
#[derive(Clone, Debug)]
pub struct ResolvedOrder {
    entries: Vec<ResolvedComponent>,
    /// The stage graph, in the order it runs.
    stages: Vec<&'static str>,
    /// Seed the interchangeable stages and components were shuffled with, or
    /// `None` in a build that does not shuffle them.
    shuffle: Option<u64>,
}

impl ResolvedOrder {
    /// The components, in the order they are constructed and started.
    #[must_use]
    pub fn entries(&self) -> &[ResolvedComponent] {
        &self.entries
    }

    /// Seed both tie-breaks drew from, for a caller that wants to replay an
    /// order. `None` in a build that leaves the ties alone.
    #[must_use]
    pub fn shuffle_seed(&self) -> Option<u64> {
        self.shuffle
    }

    /// Just the names, in construction order.
    #[must_use]
    pub fn names(&self) -> Vec<&'static str> {
        self.entries.iter().map(|entry| entry.name).collect()
    }

    /// The stages, in the order they run.
    #[must_use]
    pub fn stages(&self) -> &[&'static str] {
        &self.stages
    }
}

impl fmt::Display for ResolvedOrder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Resolved lifecycle order, {} components in {} stages: {}",
            self.entries.len(),
            self.stages.len(),
            self.stages.join(" -> ")
        )?;
        for (index, entry) in self.entries.iter().enumerate() {
            write!(
                formatter,
                "\n  {}. [{}] {} provides {}",
                index.saturating_add(1),
                entry.stage,
                entry.name,
                render(&entry.provides)
            )?;
        }
        if let Some(seed) = self.shuffle {
            write!(
                formatter,
                "\n  Interchangeable stages and components were shuffled with seed {seed}; set \
                 {SEED_VARIABLE} to it to derive this order again"
            )?;
        }
        Ok(())
    }
}

/// Renders a declared type list for the dump.
fn render(resources: &[ResourceId]) -> String {
    if resources.is_empty() {
        return "nothing".to_owned();
    }
    resources
        .iter()
        .map(|resource| format!("`{resource}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Derives the construction order of `nodes`, given the values in `seeded` and
/// the sorted stage graph in `stages`, and indexes who publishes what so that
/// construction can answer a read with the stage it comes from.
///
/// The stage graph is taken by value rather than by name because the tie-break
/// it was sorted with continues here, so one seed replays both.
///
/// # Errors
/// Returns [`ResolveError::DuplicateProvider`] when two components publish one
/// type.
pub(crate) fn resolve(
    nodes: &[Node],
    seeded: &[ResourceId],
    stages: &mut StageOrder,
) -> Result<(ResolvedOrder, Publishers), ResolveError> {
    let publishers = publishers(nodes, seeded)?;
    let stage_count = stages.sorted.len();
    let order = sort(nodes, stage_count, &mut stages.ties);

    let entries = order
        .into_iter()
        .filter_map(|position| {
            nodes.get(position).map(|node| ResolvedComponent {
                position,
                name: node.name,
                stage: node.stage_name,
                provides: node.provides.clone(),
            })
        })
        .collect();

    Ok((
        ResolvedOrder {
            entries,
            stages: stages.sorted.clone(),
            shuffle: stages.ties.seed(),
        },
        publishers,
    ))
}

/// Indexes who publishes what, refusing a type claimed twice.
///
/// The index outlives registration: it is what a component that asks for a
/// value it cannot see is answered with, so the refusal names the stage that
/// publishes the value instead of only its absence.
fn publishers(nodes: &[Node], seeded: &[ResourceId]) -> Result<Publishers, ResolveError> {
    let mut publishers = Publishers::new();

    for resource in seeded {
        publishers.insert(
            *resource,
            Publisher {
                component: ROOT,
                // Seeded before any stage ran, so every stage sees it.
                stage: None,
            },
        );
    }

    for node in nodes {
        for resource in &node.provides {
            let publisher = Publisher {
                component: node.name,
                stage: Some(node.placement()),
            };
            if let Some(existing) = publishers.insert(*resource, publisher) {
                return Err(ResolveError::DuplicateProvider {
                    resource: *resource,
                    first: existing.component,
                    second: node.name,
                });
            }
        }
    }

    Ok(publishers)
}

/// Orders the components, one stage at a time.
///
/// The stage graph is the whole of it. Every component of a stage runs before
/// every component of the stages that follow it, and inside a stage nothing is
/// ordered: the types components exchange deliver values and place nothing, so
/// the components of one stage are interchangeable and the order between them
/// means nothing. Debug and test builds shuffle them so that a hidden
/// assumption about it fails a test instead of waiting for someone to move a
/// `register` call; release builds pick by name.
///
/// Where a `register` call sits decides nothing.
fn sort(nodes: &[Node], stage_count: usize, ties: &mut TieBreak) -> Vec<usize> {
    let mut order = Vec::with_capacity(nodes.len());
    for stage in 0..stage_count {
        let mut ready: Vec<usize> = nodes
            .iter()
            .enumerate()
            .filter(|(_, node)| node.stage == stage)
            .map(|(index, _)| index)
            .collect();

        while !ready.is_empty() {
            let index = ready.swap_remove(ties.pick(&ready, |index| {
                nodes.get(index).map_or("", |node| node.name)
            }));
            order.push(index);
        }
    }

    order
}

/// Environment variable that replays a shuffle: the seed a run logged, put back
/// in, derives that run's order again.
const SEED_VARIABLE: &str = "CDA_LIFECYCLE_TIE_SEED";

/// Chooses between the stages no edge separates, and between the components of
/// one stage.
#[cfg(not(any(test, debug_assertions)))]
struct TieBreak;

#[cfg(not(any(test, debug_assertions)))]
impl TieBreak {
    fn new() -> Self {
        Self
    }

    /// Nothing was shuffled, so there is no seed to report.
    fn seed(&self) -> Option<u64> {
        None
    }

    /// Picks the first name alphabetically, as a position in `ready`.
    /// Arbitrary, and deliberately not something moving a `register` call or a
    /// line of [`Stage::all`] can change.
    fn pick<N: Fn(usize) -> &'static str>(&mut self, ready: &[usize], name: N) -> usize {
        ready
            .iter()
            .enumerate()
            .min_by_key(|(_, index)| name(**index))
            .map_or(0, |(position, _)| position)
    }
}

/// Shuffles between the stages no edge separates, and between the components of
/// one stage.
///
/// They are interchangeable by definition, so anything that depends on the
/// order between them is a bug, and a fixed order would hide it until the day
/// someone moved a registration or a line of [`Stage::all`]. The seed travels
/// in the resolved-order dump, which is logged, so an order that broke
/// something can be replayed.
#[cfg(any(test, debug_assertions))]
struct TieBreak {
    seed: u64,
    state: u64,
}

#[cfg(any(test, debug_assertions))]
impl TieBreak {
    fn new() -> Self {
        Self::seeded(
            std::env::var(SEED_VARIABLE)
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or_else(|| {
                    std::hash::BuildHasher::hash_one(
                        &std::collections::hash_map::RandomState::new(),
                        SEED_VARIABLE,
                    )
                }),
        )
    }

    fn seeded(seed: u64) -> Self {
        Self { seed, state: seed }
    }

    #[allow(
        clippy::unnecessary_wraps,
        reason = "the release counterpart shuffles nothing and so has no seed to report"
    )]
    fn seed(&self) -> Option<u64> {
        Some(self.seed)
    }

    /// `SplitMix64`, inline because a shuffle nobody has to trust for anything
    /// is not worth a dependency.
    fn draw(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut mixed = self.state;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        mixed ^ (mixed >> 31)
    }

    /// One of the placeable entries, as a position in `ready`.
    fn pick<N: Fn(usize) -> &'static str>(&mut self, ready: &[usize], _name: N) -> usize {
        let Ok(count) = u64::try_from(ready.len()) else {
            return 0;
        };
        // `checked_rem` rather than `%`: an empty `ready` is not reachable here,
        // and this says so without a branch that cannot be exercised.
        usize::try_from(self.draw().checked_rem(count).unwrap_or(0)).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stage graph with a spine and one branch, so a test can pin both the
    /// declared edges and the tie between the stages nothing separates.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TestStage {
        Boot,
        Serve,
        Report,
        Retire,
    }

    const TEST_STAGES: [TestStage; 4] = [
        TestStage::Boot,
        TestStage::Serve,
        TestStage::Report,
        TestStage::Retire,
    ];

    impl Stage for TestStage {
        fn all() -> &'static [Self] {
            &TEST_STAGES
        }

        fn follows(&self) -> &'static [Self] {
            match self {
                TestStage::Boot => &[],
                // Nothing separates these two, so their order is the tie-break.
                TestStage::Serve | TestStage::Report => &[TestStage::Boot],
                TestStage::Retire => &[TestStage::Serve, TestStage::Report],
            }
        }

        fn name(&self) -> &'static str {
            match self {
                TestStage::Boot => "boot",
                TestStage::Serve => "serve",
                TestStage::Report => "report",
                TestStage::Retire => "retire",
            }
        }
    }

    /// Stages that each wait for the other, so the graph has no order.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum LoopedStage {
        Chicken,
        Egg,
    }

    const LOOPED_STAGES: [LoopedStage; 2] = [LoopedStage::Chicken, LoopedStage::Egg];

    impl Stage for LoopedStage {
        fn all() -> &'static [Self] {
            &LOOPED_STAGES
        }

        fn follows(&self) -> &'static [Self] {
            match self {
                LoopedStage::Chicken => &[LoopedStage::Egg],
                LoopedStage::Egg => &[LoopedStage::Chicken],
            }
        }

        fn name(&self) -> &'static str {
            match self {
                LoopedStage::Chicken => "chicken",
                LoopedStage::Egg => "egg",
            }
        }
    }

    /// A stage that follows one nothing lists, which leaves it out of the graph.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum StrandedStage {
        Listed,
        Unlisted,
    }

    const STRANDED_STAGES: [StrandedStage; 1] = [StrandedStage::Listed];

    impl Stage for StrandedStage {
        fn all() -> &'static [Self] {
            &STRANDED_STAGES
        }

        fn follows(&self) -> &'static [Self] {
            match self {
                StrandedStage::Listed => &[StrandedStage::Unlisted],
                StrandedStage::Unlisted => &[],
            }
        }

        fn name(&self) -> &'static str {
            match self {
                StrandedStage::Listed => "listed",
                StrandedStage::Unlisted => "unlisted",
            }
        }
    }

    fn order() -> StageOrder {
        seeded_order(0)
    }

    fn seeded_order(seed: u64) -> StageOrder {
        StageOrder::derive_with::<TestStage>(TieBreak::seeded(seed))
            .expect("the test stage graph has an order")
    }

    fn rank(stage: TestStage) -> usize {
        order().rank(stage).expect("the stage is listed")
    }

    /// A component that publishes nothing, so only the tie-break decides where
    /// it lands inside its stage.
    fn loose(name: &'static str) -> Node {
        in_stage(name, TestStage::Boot, Vec::new())
    }

    fn in_stage(name: &'static str, stage: TestStage, provides: Vec<ResourceId>) -> Node {
        Node {
            name,
            stage: rank(stage),
            stage_name: stage.name(),
            provides,
        }
    }

    fn interchangeable() -> Vec<Node> {
        vec![
            loose("metrics"),
            loose("audit-log"),
            loose("heartbeat"),
            loose("crash-reporter"),
            loose("clock-sync"),
        ]
    }

    fn resolved(nodes: &[Node]) -> Result<ResolvedOrder, ResolveError> {
        resolve(nodes, &[], &mut order()).map(|(order, _)| order)
    }

    fn position(order: &[&'static str], name: &str) -> usize {
        order
            .iter()
            .position(|entry| *entry == name)
            .unwrap_or_else(|| panic!("{name} is in the order: {order:?}"))
    }

    fn ordered(nodes: &[Node], seed: u64) -> Vec<&'static str> {
        sort(nodes, TEST_STAGES.len(), &mut TieBreak::seeded(seed))
            .into_iter()
            .filter_map(|index| nodes.get(index).map(|node| node.name))
            .collect()
    }

    /// The declared edges are the whole of the coarse order: the spine holds,
    /// and the two stages nothing separates land somewhere between its ends.
    #[test]
    fn the_stage_graph_sorts_into_its_declared_edges() {
        let sorted = order();
        let names = sorted.names();

        assert_eq!(names.len(), TEST_STAGES.len(), "{names:?}");
        assert_eq!(names.first(), Some(&"boot"), "{names:?}");
        assert_eq!(names.last(), Some(&"retire"), "{names:?}");
        assert!(
            position(names, "serve") < position(names, "retire"),
            "{names:?}"
        );
        assert!(
            position(names, "report") < position(names, "retire"),
            "{names:?}"
        );
    }

    /// Stages no edge separates are as interchangeable as components no edge
    /// separates, so a fixed order between them would be exactly the hidden
    /// dependency the component shuffle exists to expose.
    #[test]
    fn equal_rank_stages_vary_across_seeds() {
        let first = seeded_order(0).names().to_vec();

        assert!(
            (1u64..16).any(|seed| seeded_order(seed).names() != first),
            "{first:?}"
        );
    }

    /// A stage order is only replayable from the logged seed if putting the
    /// seed back derives it again.
    #[test]
    fn one_seed_derives_one_stage_order() {
        assert_eq!(seeded_order(42).names(), seeded_order(42).names());
    }

    /// The shuffle decides between stages nothing separates and nothing else:
    /// a declared edge survives it.
    #[test]
    fn the_stage_shuffle_never_moves_a_stage_an_edge_places() {
        for seed in 0u64..16 {
            let sorted = seeded_order(seed);
            let names = sorted.names();

            assert!(position(names, "boot") < position(names, "serve"), "{seed}");
            assert!(
                position(names, "boot") < position(names, "report"),
                "{seed}"
            );
            assert!(
                position(names, "serve") < position(names, "retire"),
                "{seed}"
            );
            assert!(
                position(names, "report") < position(names, "retire"),
                "{seed}"
            );
        }
    }

    #[test]
    fn a_stage_graph_that_closes_a_loop_is_refused_naming_the_loop() {
        let error = StageOrder::derive::<LoopedStage>()
            .err()
            .expect("a loop has no order");

        let message = error.to_string();
        assert!(
            matches!(error, ResolveError::StageCycle { .. }),
            "{message}"
        );
        assert!(message.contains("chicken"), "{message}");
        assert!(message.contains("egg"), "{message}");
    }

    #[test]
    fn a_stage_left_out_of_all_is_refused_by_name() {
        let error = StageOrder::derive::<StrandedStage>()
            .err()
            .expect("a stage outside the graph has no rank");

        let message = error.to_string();
        assert!(
            matches!(error, ResolveError::UnknownStage { .. }),
            "{message}"
        );
        assert!(message.contains("unlisted"), "{message}");
    }

    /// Nothing orders the components of one stage, so a shuffle that produced
    /// one order for every seed would be a decoration on a fixed order, which
    /// is the thing it exists to rule out.
    #[test]
    fn the_components_of_one_stage_vary_across_seeds() {
        let nodes = interchangeable();
        let first = ordered(&nodes, 0);

        assert!(
            (1u64..16).any(|seed| ordered(&nodes, seed) != first),
            "{first:?}"
        );
    }

    /// The seed is only worth logging if putting it back derives the same
    /// order.
    #[test]
    fn one_seed_derives_one_order() {
        let nodes = interchangeable();

        assert_eq!(ordered(&nodes, 42), ordered(&nodes, 42));
    }

    /// The shuffle decides between the components of one stage and nothing
    /// else: a component its stage places stays where the stage put it.
    #[test]
    fn the_shuffle_never_moves_a_component_its_stage_places() {
        let nodes = vec![
            loose("metrics"),
            in_stage("router", TestStage::Boot, Vec::new()),
            in_stage("listener", TestStage::Serve, Vec::new()),
        ];

        for seed in 0u64..16 {
            let order = ordered(&nodes, seed);

            assert!(
                position(&order, "router") < position(&order, "listener"),
                "{seed}: {order:?}"
            );
            assert!(
                position(&order, "metrics") < position(&order, "listener"),
                "{seed}: {order:?}"
            );
        }
    }

    /// The stage decides, whatever the shuffle would rather do.
    #[test]
    fn a_later_stage_never_overtakes_an_earlier_one() {
        let nodes = vec![
            in_stage("summary", TestStage::Report, Vec::new()),
            in_stage("boot-log", TestStage::Boot, Vec::new()),
            in_stage("teardown", TestStage::Retire, Vec::new()),
            in_stage("listener", TestStage::Serve, Vec::new()),
        ];

        let names = resolved(&nodes)
            .expect("the declarations have an order")
            .names();

        assert_eq!(names.first(), Some(&"boot-log"), "{names:?}");
        assert_eq!(names.last(), Some(&"teardown"), "{names:?}");
    }

    /// Two components publishing one type leaves no way to say which one a
    /// reader meant, and that is decided from the declarations, so it is
    /// refused before anything is built.
    #[test]
    fn two_providers_of_one_type_are_refused_naming_both() {
        let mount = ResourceId::of::<usize>();
        let nodes = vec![
            in_stage("router", TestStage::Boot, vec![mount]),
            in_stage("second-router", TestStage::Serve, vec![mount]),
        ];

        let error = resolved(&nodes).expect_err("one type has two providers");

        let message = error.to_string();
        assert!(
            matches!(error, ResolveError::DuplicateProvider { .. }),
            "{message}"
        );
        assert!(message.contains("router"), "{message}");
        assert!(message.contains("second-router"), "{message}");
    }

    /// The order is dumped into a log line, and replaying it needs the seed to
    /// be in there with it.
    #[test]
    fn the_dump_carries_the_seed_that_shuffled_it() {
        let order = resolved(&interchangeable()).expect("nothing separates these");

        let seed = order.shuffle_seed().expect("a test build shuffles");
        assert!(order.to_string().contains(&seed.to_string()), "{order}");
        assert!(order.to_string().contains(SEED_VARIABLE), "{order}");
    }

    /// "Why did this run there" is answered by the stage, so the dump has to
    /// carry the graph and the stage every component landed in.
    #[test]
    fn the_dump_names_the_stage_graph_and_every_components_stage() {
        let nodes = vec![in_stage("listener", TestStage::Serve, Vec::new())];

        let resolved = resolved(&nodes).expect("the declarations have an order");
        let dumped = resolved.to_string();

        assert!(dumped.contains(&resolved.stages().join(" -> ")), "{dumped}");
        assert!(dumped.contains("boot -> "), "{dumped}");
        assert!(dumped.contains(" -> retire"), "{dumped}");
        assert!(dumped.contains("[serve] listener"), "{dumped}");
    }
}
