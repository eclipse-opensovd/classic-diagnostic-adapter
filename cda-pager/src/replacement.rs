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

//! Pluggable page-replacement strategies for the userfaultfd pager.
//!
//! # What a policy can observe
//!
//! The pager registers its arenas with userfaultfd in MISSING-only mode, so
//! at the kernel level we only ever learn about *non-resident* pages: the
//! **miss stream**. There is no hit stream: a page that is already resident
//! is read straight from memory, with no kernel event. Only policies that
//! decide from misses and insertions are therefore provided.
//!
//! [`ReplacementPolicy::on_insert`] reports whether a page was
//! demand-faulted or merely speculatively prefetched alongside it. See
//! [`PrefetchFirst`] for a policy that uses this.
//!
//! # Ownership contract
//!
//! [`ReplacementPolicy::take_victims`] *removes* the pages it returns from
//! the policy's own bookkeeping. A policy must never return a page again
//! until a matching [`ReplacementPolicy::on_insert`]. This keeps each
//! policy's notion of residency exact by construction, so the pager needs no
//! stale-entry filtering and no residency back-channel into the policy.
//!
//! This module is deliberately free of `unsafe`, `libc` and `userfaultfd`,
//! so it is unit-testable on any platform without kernel support.

#![allow(
    clippy::cast_possible_truncation,
    reason = "Slot indices are `u32` and bounded by the resident page pool size"
)]
#![allow(
    clippy::arithmetic_side_effects,
    reason = "Page index and counter arithmetic on bounded values in the paging hot path; \
              overflow is impossible by construction (indices are below the region page count)"
)]
#![allow(
    clippy::indexing_slicing,
    reason = "Indices are bounded by the region page count / batch size established when the \
              region is opened, a failed lookup would indicate a broken pager invariant"
)]

use std::collections::{HashMap, VecDeque};

/// Identifies a region (one opened file). Equal to the region's arena base
/// address, mirroring the key used by the pager's region map.
pub type RegionId = usize;

/// A single page of a single region: the unit of replacement.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct PageRef {
    pub region: RegionId,
    pub index: usize,
}

impl PageRef {
    #[must_use]
    pub fn new(region: RegionId, index: usize) -> Self {
        Self { region, index }
    }
}

/// A page-replacement strategy. See the module docs for what a policy can
/// observe and for the ownership contract of [`Self::take_victims`].
pub trait ReplacementPolicy: Send {
    /// Stable identifier of the policy, reported in the pager statistics.
    fn name(&self) -> &'static str;

    /// A miss was observed on `page`, called *before* the corresponding
    /// [`Self::on_insert`].
    fn on_fault(&mut self, page: PageRef);

    /// `page` has become resident. `demand` is true only for the page that
    /// actually faulted, false for pages pulled in by the prefetch batch
    /// around it.
    fn on_insert(&mut self, page: PageRef, demand: bool);

    /// Remove up to `need` pages from the policy's resident set and append
    /// them to `out`. Returning fewer than `need` means "nothing more to
    /// give" and stops the pager's eviction loop.
    ///
    /// Order does not matter: the pager sorts the batch before issuing
    /// `madvise`, so a policy is free to return scattered pages without
    /// having to think about syscall coalescing.
    fn take_victims(&mut self, need: usize, out: &mut Vec<PageRef>);

    /// Every page of `region` is gone (the file handle was dropped). All
    /// state referring to it must be purged.
    fn on_region_closed(&mut self, region: RegionId);
}

/// Selects which [`ReplacementPolicy`] implementation to instantiate.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum EvictionKind {
    /// Evict the longest-resident page. The default.
    #[default]
    Fifo,
    Random,
    PrefetchFirst,
}

impl EvictionKind {
    /// Accepted spellings for the `--pager-eviction` flag.
    pub const CHOICES: &'static str = "fifo|random|prefetch-first";

    /// Parses one of the spellings listed in [`Self::CHOICES`].
    ///
    /// # Errors
    /// Returns an error naming the accepted values if `s` is unknown.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "fifo" => Ok(Self::Fifo),
            "random" | "rand" => Ok(Self::Random),
            "prefetch-first" | "prefetch" => Ok(Self::PrefetchFirst),
            other => Err(format!(
                "unknown eviction policy '{other}', expected one of: {}",
                Self::CHOICES
            )),
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Fifo => "fifo",
            Self::Random => "random",
            Self::PrefetchFirst => "prefetch-first",
        }
    }
}

const RANDOM_SEED: u64 = 42;

/// Instantiates a policy. [`Random`] uses a fixed seed so runs are
/// reproducible.
#[must_use]
pub fn build(kind: EvictionKind) -> Box<dyn ReplacementPolicy> {
    match kind {
        EvictionKind::Fifo => Box::new(Fifo::new()),
        EvictionKind::Random => Box::new(Random::new(RANDOM_SEED)),
        EvictionKind::PrefetchFirst => Box::new(PrefetchFirst::new()),
    }
}

/// Drops every entry belonging to `region`. O(n), but region closes are rare
/// (once per opened file) and this keeps the queues free of stale entries,
/// which is what lets `take_victims` guarantee it only returns resident
/// pages.
fn purge_region(queue: &mut VecDeque<PageRef>, region: RegionId) {
    queue.retain(|page| page.region != region);
}

/// Evicts the page that has been resident longest, regardless of which
/// region it belongs to. The pager's original (and default) behaviour.
pub struct Fifo {
    queue: VecDeque<PageRef>,
}

impl Fifo {
    #[must_use]
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
        }
    }
}

impl Default for Fifo {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplacementPolicy for Fifo {
    fn name(&self) -> &'static str {
        "fifo"
    }

    fn on_fault(&mut self, _page: PageRef) {}

    fn on_insert(&mut self, page: PageRef, _demand: bool) {
        self.queue.push_back(page);
    }

    fn take_victims(&mut self, need: usize, out: &mut Vec<PageRef>) {
        for _ in 0..need {
            match self.queue.pop_front() {
                Some(page) => out.push(page),
                None => break,
            }
        }
    }

    fn on_region_closed(&mut self, region: RegionId) {
        purge_region(&mut self.queue, region);
    }
}

/// Minimal seedable PRNG (`SplitMix64`); good enough for victim selection and
/// avoids pulling in a random number crate.
struct SplitMix64(u64);

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform-enough value in `0..bound`; `bound` must be non-zero.
    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next_u64() % (bound as u64).max(1)).unwrap_or(0)
    }
}

/// Uniformly random victim selection, the standard baseline that any
/// smarter policy has to beat. Seeded for reproducibility.
///
/// Kept O(1) per operation by pairing a dense `Vec` with an index map, so
/// removal is a `swap_remove` rather than a linear scan.
pub struct Random {
    pages: Vec<PageRef>,
    index_of: HashMap<PageRef, usize>,
    rng: SplitMix64,
}

impl Random {
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            pages: Vec::new(),
            index_of: HashMap::new(),
            rng: SplitMix64::new(seed),
        }
    }

    fn remove_at(&mut self, slot: usize) -> PageRef {
        let page = self.pages.swap_remove(slot);
        self.index_of.remove(&page);
        // `swap_remove` moved the former last element into `slot`, unless we
        // removed the last element itself.
        if let Some(moved) = self.pages.get(slot) {
            self.index_of.insert(*moved, slot);
        }
        page
    }
}

impl ReplacementPolicy for Random {
    fn name(&self) -> &'static str {
        "random"
    }

    fn on_fault(&mut self, _page: PageRef) {}

    fn on_insert(&mut self, page: PageRef, _demand: bool) {
        if self.index_of.contains_key(&page) {
            return;
        }
        self.index_of.insert(page, self.pages.len());
        self.pages.push(page);
    }

    fn take_victims(&mut self, need: usize, out: &mut Vec<PageRef>) {
        for _ in 0..need {
            if self.pages.is_empty() {
                break;
            }
            let slot = self.rng.below(self.pages.len());
            let page = self.remove_at(slot);
            out.push(page);
        }
    }

    fn on_region_closed(&mut self, region: RegionId) {
        self.pages.retain(|page| page.region != region);
        self.index_of.clear();
        for (slot, page) in self.pages.iter().enumerate() {
            self.index_of.insert(*page, slot);
        }
    }
}

/// Evicts speculatively prefetched pages before demand-faulted ones, on the
/// theory that a demand fault is proof the page was actually wanted whereas
/// a prefetched neighbour is only a guess.
///
/// Caveat: a prefetched page that turns out to be *heavily* used can never
/// be promoted out of the speculative queue, since resident-page reads are
/// invisible to the pager. It stays a first-choice victim for as long as it
/// is resident.
pub struct PrefetchFirst {
    speculative: VecDeque<PageRef>,
    demand: VecDeque<PageRef>,
}

impl PrefetchFirst {
    #[must_use]
    pub fn new() -> Self {
        Self {
            speculative: VecDeque::new(),
            demand: VecDeque::new(),
        }
    }
}

impl Default for PrefetchFirst {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplacementPolicy for PrefetchFirst {
    fn name(&self) -> &'static str {
        "prefetch-first"
    }

    fn on_fault(&mut self, _page: PageRef) {}

    fn on_insert(&mut self, page: PageRef, demand: bool) {
        if demand {
            self.demand.push_back(page);
        } else {
            self.speculative.push_back(page);
        }
    }

    fn take_victims(&mut self, need: usize, out: &mut Vec<PageRef>) {
        for _ in 0..need {
            let picked = self
                .speculative
                .pop_front()
                .or_else(|| self.demand.pop_front());
            match picked {
                Some(page) => out.push(page),
                None => break,
            }
        }
    }

    fn on_region_closed(&mut self, region: RegionId) {
        purge_region(&mut self.speculative, region);
        purge_region(&mut self.demand, region);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    const R_A: RegionId = 0x1000;
    const R_B: RegionId = 0x2000;

    fn p(region: RegionId, index: usize) -> PageRef {
        PageRef::new(region, index)
    }

    /// Feeds `pages` in as demand faults.
    fn insert_all(policy: &mut dyn ReplacementPolicy, pages: &[PageRef]) {
        for page in pages {
            policy.on_fault(*page);
            policy.on_insert(*page, true);
        }
    }

    fn take(policy: &mut dyn ReplacementPolicy, need: usize) -> Vec<PageRef> {
        let mut out = Vec::new();
        policy.take_victims(need, &mut out);
        out
    }

    #[test]
    fn fifo_evicts_oldest_first() {
        let mut policy = Fifo::new();
        insert_all(&mut policy, &[p(R_A, 0), p(R_A, 1), p(R_A, 2)]);
        assert_eq!(take(&mut policy, 2), vec![p(R_A, 0), p(R_A, 1)]);
        assert_eq!(take(&mut policy, 2), vec![p(R_A, 2)]);
    }

    /// The core ownership contract: a page handed out as a victim must not
    /// be handed out again until it is re-inserted. Violating this would let
    /// the pager decrement its resident count twice and underflow.
    #[test]
    fn victims_are_never_returned_twice() {
        for kind in [
            EvictionKind::Fifo,
            EvictionKind::Random,
            EvictionKind::PrefetchFirst,
        ] {
            let mut policy = build(kind);
            let pages: Vec<PageRef> = (0..8).map(|i| p(R_A, i)).collect();
            insert_all(policy.as_mut(), &pages);

            let mut seen = HashSet::new();
            let mut total = 0;
            for _ in 0..4 {
                for page in take(policy.as_mut(), 5) {
                    assert!(
                        seen.insert(page),
                        "{} returned {page:?} twice",
                        policy.name()
                    );
                    assert!(pages.contains(&page), "{} invented {page:?}", policy.name());
                    total += 1;
                }
            }
            assert_eq!(total, 8, "{} did not drain exactly once", policy.name());
        }
    }

    #[test]
    fn closing_a_region_purges_its_pages() {
        for kind in [
            EvictionKind::Fifo,
            EvictionKind::Random,
            EvictionKind::PrefetchFirst,
        ] {
            let mut policy = build(kind);
            insert_all(
                policy.as_mut(),
                &[p(R_A, 0), p(R_B, 0), p(R_A, 1), p(R_B, 1)],
            );
            policy.on_region_closed(R_A);

            let victims = take(policy.as_mut(), 8);
            assert_eq!(victims.len(), 2, "{} kept stale entries", policy.name());
            assert!(
                victims.iter().all(|page| page.region == R_B),
                "{} returned a page from the closed region: {victims:?}",
                policy.name()
            );
        }
    }

    #[test]
    fn prefetch_first_prefers_speculative_pages() {
        let mut policy = PrefetchFirst::new();
        policy.on_fault(p(R_A, 0));
        policy.on_insert(p(R_A, 0), true);
        policy.on_insert(p(R_A, 1), false);
        policy.on_fault(p(R_A, 4));
        policy.on_insert(p(R_A, 4), true);
        policy.on_insert(p(R_A, 5), false);

        assert_eq!(take(&mut policy, 2), vec![p(R_A, 1), p(R_A, 5)]);
        assert_eq!(take(&mut policy, 2), vec![p(R_A, 0), p(R_A, 4)]);
    }

    #[test]
    fn random_is_reproducible_for_a_given_seed() {
        let run = |seed: u64| {
            let mut policy = Random::new(seed);
            insert_all(&mut policy, &(0..16).map(|i| p(R_A, i)).collect::<Vec<_>>());
            take(&mut policy, 8)
        };
        assert_eq!(run(1234), run(1234));
        assert_ne!(run(1234), run(9876));
    }

    #[test]
    fn eviction_kind_parses_and_round_trips() {
        for kind in [
            EvictionKind::Fifo,
            EvictionKind::Random,
            EvictionKind::PrefetchFirst,
        ] {
            assert_eq!(EvictionKind::parse(kind.as_str()), Ok(kind));
            assert_eq!(build(kind).name(), kind.as_str());
        }
        assert_eq!(EvictionKind::parse("rand"), Ok(EvictionKind::Random));
        assert!(EvictionKind::parse("lru-linked-list").is_err());
        assert!(EvictionKind::parse("arc").is_err());
    }
}
