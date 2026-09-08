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

//! State machine used by the production lock manager.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::SystemTime,
};

use cda_interfaces::lock_priority_api::{LockPrincipal, LockScope};
use serde_json::{Map, Value};

/// Canonical, case-insensitive lock scope key.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ScopeKey {
    /// Whole vehicle.
    Vehicle,
    /// One ECU.
    Ecu(String),
    /// One functional group.
    FunctionalGroup(String),
}

impl From<&LockScope> for ScopeKey {
    fn from(scope: &LockScope) -> Self {
        match scope {
            LockScope::Vehicle => Self::Vehicle,
            LockScope::Ecu { name } => Self::Ecu(normalize_name(name)),
            LockScope::FunctionalGroup { name } => Self::FunctionalGroup(normalize_name(name)),
        }
    }
}

/// Diagnostic entities protected by a lock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LockCoverage {
    /// Every diagnostic entity on the vehicle, including entities added later.
    Vehicle,
    /// One concrete set of ECUs.
    Ecus(BTreeSet<String>),
}

impl Default for LockCoverage {
    fn default() -> Self {
        Self::Ecus(BTreeSet::new())
    }
}

impl LockCoverage {
    /// Creates normalized coverage from ECU names.
    pub(super) fn new(ecu_names: impl IntoIterator<Item = String>) -> Self {
        Self::Ecus(
            ecu_names
                .into_iter()
                .map(|name| normalize_name(&name))
                .collect(),
        )
    }

    /// Creates whole-vehicle coverage.
    pub(super) const fn vehicle() -> Self {
        Self::Vehicle
    }

    /// Reports whether two lock scopes protect at least one common ECU.
    pub(super) fn overlaps(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Vehicle, _) | (_, Self::Vehicle) => true,
            (Self::Ecus(left), Self::Ecus(right)) => left.intersection(right).next().is_some(),
        }
    }

    /// Reports whether this lock covers the named ECU.
    pub(super) fn contains_ecu(&self, ecu_name: &str) -> bool {
        match self {
            Self::Vehicle => true,
            Self::Ecus(ecu_names) => ecu_names.contains(&normalize_name(ecu_name)),
        }
    }

    /// Reports whether this coverage contains all entities in another coverage.
    fn contains(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Vehicle, _) => true,
            (Self::Ecus(_), Self::Vehicle) => false,
            (Self::Ecus(left), Self::Ecus(right)) => right.is_subset(left),
        }
    }

    /// Returns deterministic concrete ECU coverage.
    pub(super) fn covered_ecus(&self) -> Vec<String> {
        match self {
            Self::Vehicle => Vec::new(),
            Self::Ecus(ecu_names) => ecu_names.iter().cloned().collect(),
        }
    }
}

/// Canonical active lock record.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ActiveLock {
    pub(super) id: String,
    pub(super) scope: ScopeKey,
    pub(super) coverage: LockCoverage,
    pub(super) principal: LockPrincipal,
    pub(super) metadata: Map<String, Value>,
    pub(super) exclusive: bool,
    pub(super) expires_at: SystemTime,
    pub(super) parent_vehicle: Option<String>,
}

/// Historical lock record created by preemption.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct DefunctLock {
    pub(super) id: String,
    pub(super) scope: ScopeKey,
    pub(super) coverage: LockCoverage,
    pub(super) principal: LockPrincipal,
    pub(super) metadata: Map<String, Value>,
    pub(super) exclusive: bool,
    pub(super) original_expires_at: SystemTime,
    pub(super) broken_at: SystemTime,
    pub(super) broken_by: String,
    pub(super) replacement_lock_id: String,
    pub(super) replacement_holder: String,
}

/// Outcome of starting active-lock expiration.
pub(super) enum ExpirationStart {
    /// Event referred to a removed lock.
    Stale,
    /// Event arrived before its deadline.
    NotDue(SystemTime),
    /// Lock tree was removed.
    Expired(Vec<ActiveLock>),
}

/// Invalid lock state transition.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub(super) enum StateError {
    #[error("Lock ID already exists: {0}")]
    DuplicateId(String),
    #[error("Lock scope is already active")]
    DuplicateScope,
    #[error("Active lock does not exist: {0}")]
    ActiveLockNotFound(String),
    #[error("Parent vehicle lock does not exist: {0}")]
    ParentNotFound(String),
    #[error("Parent lock is not a vehicle lock: {0}")]
    ParentNotVehicle(String),
    #[error("Replacement conflicts with an active scope")]
    ReplacementScopeConflict,
    #[error("Lock coverage conflicts with active lock: {0}")]
    CoverageConflict(String),
    #[error("State revision overflow")]
    RevisionOverflow,
    #[error("Lock renewal must extend the expiration deadline")]
    RenewalNotExtension,
    #[error("Lock state invariant violated: {0}")]
    Invariant(String),
}

/// Coherent active and defunct lock state.
#[derive(Clone, Debug, Default)]
pub(super) struct LockState {
    revision: u64,
    active_by_id: BTreeMap<String, ActiveLock>,
    active_by_scope: BTreeMap<ScopeKey, String>,
    defunct_by_id: BTreeMap<String, DefunctLock>,
    children_by_vehicle: BTreeMap<String, BTreeSet<String>>,
}

impl LockState {
    /// Current mutation revision.
    pub(super) fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns active records in deterministic ID order.
    pub(super) fn active(&self) -> impl Iterator<Item = &ActiveLock> {
        self.active_by_id.values()
    }

    /// Returns defunct records in deterministic ID order.
    pub(super) fn defunct(&self) -> impl Iterator<Item = &DefunctLock> {
        self.defunct_by_id.values()
    }

    /// Finds an active lock by canonical scope.
    pub(super) fn active_for_scope(&self, scope: &ScopeKey) -> Option<&ActiveLock> {
        self.active_by_scope
            .get(scope)
            .and_then(|id| self.active_by_id.get(id))
    }

    /// Finds an active lock by ID.
    pub(super) fn active_by_id(&self, lock_id: &str) -> Option<&ActiveLock> {
        self.active_by_id.get(lock_id)
    }

    /// Finds a defunct lock by ID.
    pub(super) fn defunct_by_id(&self, lock_id: &str) -> Option<&DefunctLock> {
        self.defunct_by_id.get(lock_id)
    }

    /// Inserts one active lock.
    pub(super) fn insert_active(&mut self, lock: ActiveLock) -> Result<(), StateError> {
        self.transaction(|state| state.insert_active_uncommitted(lock))
    }

    /// Inserts a vehicle lock and adopts existing locks owned by the same principal.
    pub(super) fn insert_vehicle(
        &mut self,
        lock: ActiveLock,
        child_ids: &[String],
    ) -> Result<(), StateError> {
        self.transaction(|state| {
            if lock.scope != ScopeKey::Vehicle || lock.parent_vehicle.is_some() {
                return Err(StateError::Invariant(
                    "Vehicle insertion requires a root vehicle lock".to_owned(),
                ));
            }
            let children: BTreeSet<_> = child_ids.iter().cloned().collect();
            for child_id in &children {
                let child = state
                    .active_by_id
                    .get(child_id)
                    .ok_or_else(|| StateError::ActiveLockNotFound(child_id.clone()))?;
                if child.scope == ScopeKey::Vehicle || child.parent_vehicle.is_some() {
                    return Err(StateError::Invariant(format!(
                        "Invalid vehicle child {child_id}"
                    )));
                }
            }
            let vehicle_id = lock.id.clone();
            state.insert_active_uncommitted(lock)?;
            for child_id in children {
                if let Some(child) = state.active_by_id.get_mut(&child_id) {
                    child.parent_vehicle = Some(vehicle_id.clone());
                }
                state
                    .children_by_vehicle
                    .entry(vehicle_id.clone())
                    .or_default()
                    .insert(child_id);
            }
            Ok(())
        })
    }

    /// Renews an active lock by extending its expiration deadline.
    pub(super) fn renew(
        &mut self,
        lock_id: &str,
        expires_at: SystemTime,
    ) -> Result<(), StateError> {
        self.transaction(|state| {
            let lock = state
                .active_by_id
                .get_mut(lock_id)
                .ok_or_else(|| StateError::ActiveLockNotFound(lock_id.to_owned()))?;
            if lock.expires_at <= SystemTime::now() {
                return Err(StateError::RenewalNotExtension);
            }
            if expires_at <= lock.expires_at {
                return Err(StateError::RenewalNotExtension);
            }
            lock.expires_at = expires_at;
            Ok(())
        })
    }

    /// Removes a lock and vehicle descendants after voluntary deletion.
    pub(super) fn delete(&mut self, lock_id: &str) -> Result<Vec<ActiveLock>, StateError> {
        let mut removed = Vec::new();
        self.transaction(|state| {
            if !state.active_by_id.contains_key(lock_id) {
                return Err(StateError::ActiveLockNotFound(lock_id.to_owned()));
            }
            removed = state.remove_active_tree_uncommitted(lock_id);
            Ok(())
        })?;
        Ok(removed)
    }

    /// Validates an expiration event and atomically removes its complete lock tree.
    pub(super) fn begin_expiration(
        &mut self,
        lock_id: &str,
        now: SystemTime,
    ) -> Result<ExpirationStart, StateError> {
        let Some(lock) = self.active_by_id.get(lock_id) else {
            return Ok(ExpirationStart::Stale);
        };
        if lock.expires_at > now {
            return Ok(ExpirationStart::NotDue(lock.expires_at));
        }
        self.delete(lock_id).map(ExpirationStart::Expired)
    }

    /// Atomically expands and preempts selected lock roots, converts owned roots,
    /// and inserts the replacement lock.
    pub(super) fn commit_replacement(
        &mut self,
        preempted_ids: &[String],
        converted_ids: &[String],
        replacement: ActiveLock,
        broken_by: &str,
        broken_at: SystemTime,
    ) -> Result<Vec<ActiveLock>, StateError> {
        let mut removed = Vec::new();
        self.transaction(|state| {
            let replacement_id = replacement.id.clone();
            let replacement_scope = replacement.scope.clone();
            let replacement_subject = replacement.principal.subject.clone();
            let preempted_roots: BTreeSet<_> = preempted_ids.iter().cloned().collect();
            let converted_roots: BTreeSet<_> = converted_ids.iter().cloned().collect();
            let preempted = state.expand_active_trees(preempted_ids)?;
            let converted = state.expand_active_trees(converted_ids)?;
            if preempted.iter().any(|id| converted.contains(id)) {
                return Err(StateError::Invariant(
                    "Lock selected for preemption and conversion".to_owned(),
                ));
            }
            for id in &converted {
                let lock = state
                    .active_by_id
                    .get(id)
                    .ok_or_else(|| StateError::ActiveLockNotFound(id.clone()))?;
                if lock.principal.subject != replacement_subject {
                    return Err(StateError::Invariant(format!(
                        "Converted lock {id} has a different owner"
                    )));
                }
            }
            if state.id_exists(&replacement.id) {
                return Err(StateError::DuplicateId(replacement.id.clone()));
            }
            if let Some(existing_id) = state.active_by_scope.get(&replacement.scope)
                && !preempted.contains(existing_id)
                && !converted.contains(existing_id)
            {
                return Err(StateError::ReplacementScopeConflict);
            }

            for id in preempted_roots {
                let preempted_tree = state.remove_active_tree_uncommitted(&id);
                for lock in preempted_tree {
                    state.defunct_by_id.insert(
                        lock.id.clone(),
                        DefunctLock {
                            id: lock.id.clone(),
                            scope: lock.scope.clone(),
                            coverage: lock.coverage.clone(),
                            principal: lock.principal.clone(),
                            metadata: lock.metadata.clone(),
                            exclusive: lock.exclusive,
                            original_expires_at: lock.expires_at,
                            broken_at,
                            broken_by: broken_by.to_owned(),
                            replacement_lock_id: replacement.id.clone(),
                            replacement_holder: replacement.principal.subject.clone(),
                        },
                    );
                    removed.push(lock);
                }
            }
            for id in converted_roots {
                removed.extend(state.remove_active_tree_uncommitted(&id));
            }
            state.insert_active_uncommitted(replacement)?;
            if replacement_scope == ScopeKey::Vehicle {
                let children = state
                    .active_by_id
                    .values()
                    .filter(|lock| {
                        lock.id != replacement_id
                            && lock.parent_vehicle.is_none()
                            && lock.principal.subject == replacement_subject
                    })
                    .map(|lock| lock.id.clone())
                    .collect::<Vec<_>>();
                for child_id in children {
                    if let Some(child) = state.active_by_id.get_mut(&child_id) {
                        child.parent_vehicle = Some(replacement_id.clone());
                    }
                    state
                        .children_by_vehicle
                        .entry(replacement_id.clone())
                        .or_default()
                        .insert(child_id);
                }
            }
            Ok(())
        })?;
        Ok(removed)
    }

    /// Removes an acknowledged defunct lock.
    pub(super) fn acknowledge_defunct(&mut self, lock_id: &str) -> Result<bool, StateError> {
        if self.remove_defunct_uncommitted(lock_id) {
            self.increment_revision()?;
            self.validate_invariants()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Removes all defunct locks whose original expiration has elapsed.
    pub(super) fn expire_defunct(&mut self, now: SystemTime) -> Result<Vec<String>, StateError> {
        let expired: Vec<String> = self
            .defunct_by_id
            .iter()
            .filter(|(_, lock)| lock.original_expires_at <= now)
            .map(|(id, _)| id.clone())
            .collect();
        if expired.is_empty() {
            return Ok(expired);
        }
        for id in &expired {
            self.remove_defunct_uncommitted(id);
        }
        self.increment_revision()?;
        self.validate_invariants()?;
        Ok(expired)
    }

    fn remove_defunct_uncommitted(&mut self, lock_id: &str) -> bool {
        let Some((replacement_id, replacement_holder)) =
            self.defunct_by_id.get(lock_id).map(|lock| {
                (
                    lock.replacement_lock_id.clone(),
                    lock.replacement_holder.clone(),
                )
            })
        else {
            return false;
        };
        for lock in self.defunct_by_id.values_mut() {
            if lock.replacement_lock_id == lock_id {
                lock.replacement_lock_id.clone_from(&replacement_id);
                lock.replacement_holder.clone_from(&replacement_holder);
            }
        }
        self.defunct_by_id.remove(lock_id);
        true
    }

    /// Resolves the latest replacement holder, including after its lock was removed.
    pub(super) fn current_holder<'a>(&'a self, defunct: &'a DefunctLock) -> &'a str {
        let mut replacement_id = defunct.replacement_lock_id.as_str();
        let mut replacement_holder = defunct.replacement_holder.as_str();
        let mut visited = BTreeSet::new();
        while visited.insert(replacement_id) {
            if let Some(lock) = self.active_by_id.get(replacement_id) {
                return lock.principal.subject.as_str();
            }
            let Some(replacement) = self.defunct_by_id.get(replacement_id) else {
                return replacement_holder;
            };
            replacement_id = &replacement.replacement_lock_id;
            replacement_holder = &replacement.replacement_holder;
        }
        replacement_holder
    }

    /// Validates all indexes and parent relationships.
    pub(super) fn validate_invariants(&self) -> Result<(), StateError> {
        if self
            .active_by_id
            .keys()
            .any(|id| self.defunct_by_id.contains_key(id))
        {
            return Err(StateError::Invariant(
                "Active and defunct IDs overlap".to_owned(),
            ));
        }
        if self.active_by_scope.len() != self.active_by_id.len() {
            return Err(StateError::Invariant(
                "Active scope and ID indexes differ in size".to_owned(),
            ));
        }
        for (id, lock) in &self.active_by_id {
            if self.active_by_scope.get(&lock.scope) != Some(id) {
                return Err(StateError::Invariant(format!(
                    "Scope index does not reference lock {id}"
                )));
            }
            if let Some(parent_id) = &lock.parent_vehicle {
                let parent = self.active_by_id.get(parent_id).ok_or_else(|| {
                    StateError::Invariant(format!("Missing parent {parent_id} for lock {id}"))
                })?;
                if parent.scope != ScopeKey::Vehicle {
                    return Err(StateError::Invariant(format!(
                        "Parent {parent_id} is not a vehicle lock"
                    )));
                }
                if parent.principal.subject != lock.principal.subject {
                    return Err(StateError::Invariant(format!(
                        "Child lock {id} owner differs from vehicle lock {parent_id}"
                    )));
                }
                if !parent.coverage.contains(&lock.coverage) {
                    return Err(StateError::Invariant(format!(
                        "Child lock {id} coverage is outside vehicle lock {parent_id}"
                    )));
                }
                if !self
                    .children_by_vehicle
                    .get(parent_id)
                    .is_some_and(|children| children.contains(id))
                {
                    return Err(StateError::Invariant(format!(
                        "Parent index does not contain child {id}"
                    )));
                }
            }
        }
        for (parent_id, children) in &self.children_by_vehicle {
            let parent = self.active_by_id.get(parent_id).ok_or_else(|| {
                StateError::Invariant(format!("Child index has missing parent {parent_id}"))
            })?;
            if parent.scope != ScopeKey::Vehicle {
                return Err(StateError::Invariant(format!(
                    "Child index parent {parent_id} is not a vehicle lock"
                )));
            }
            for child_id in children {
                if self
                    .active_by_id
                    .get(child_id)
                    .and_then(|child| child.parent_vehicle.as_ref())
                    != Some(parent_id)
                {
                    return Err(StateError::Invariant(format!(
                        "Child {child_id} does not reference parent {parent_id}"
                    )));
                }
            }
        }
        Ok(())
    }

    fn transaction<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, StateError>,
    ) -> Result<T, StateError> {
        let mut staged = self.clone();
        let output = operation(&mut staged)?;
        staged.increment_revision()?;
        staged.validate_invariants()?;
        *self = staged;
        Ok(output)
    }

    fn insert_active_uncommitted(&mut self, lock: ActiveLock) -> Result<(), StateError> {
        if self.id_exists(&lock.id) {
            return Err(StateError::DuplicateId(lock.id));
        }
        if self.active_by_scope.contains_key(&lock.scope) {
            return Err(StateError::DuplicateScope);
        }
        if let Some(parent_id) = &lock.parent_vehicle {
            let parent = self
                .active_by_id
                .get(parent_id)
                .ok_or_else(|| StateError::ParentNotFound(parent_id.clone()))?;
            if parent.scope != ScopeKey::Vehicle {
                return Err(StateError::ParentNotVehicle(parent_id.clone()));
            }
            if parent.principal.subject != lock.principal.subject {
                return Err(StateError::Invariant(format!(
                    "Child lock {} owner differs from vehicle lock {parent_id}",
                    lock.id
                )));
            }
            if !parent.coverage.contains(&lock.coverage) {
                return Err(StateError::Invariant(format!(
                    "Child lock {} coverage is outside vehicle lock {parent_id}",
                    lock.id
                )));
            }
            self.children_by_vehicle
                .entry(parent_id.clone())
                .or_default()
                .insert(lock.id.clone());
        }
        if let Some(conflicting) = self.active_by_id.values().find(|active| {
            active.coverage.overlaps(&lock.coverage)
                && lock.parent_vehicle.as_ref() != Some(&active.id)
                && active.parent_vehicle.as_ref() != Some(&lock.id)
                && lock.scope != ScopeKey::Vehicle
        }) {
            return Err(StateError::CoverageConflict(conflicting.id.clone()));
        }
        self.active_by_scope
            .insert(lock.scope.clone(), lock.id.clone());
        self.active_by_id.insert(lock.id.clone(), lock);
        Ok(())
    }

    fn remove_active_tree_uncommitted(&mut self, lock_id: &str) -> Vec<ActiveLock> {
        let children = self.children_by_vehicle.remove(lock_id).unwrap_or_default();
        let mut removed: Vec<ActiveLock> = children
            .into_iter()
            .filter_map(|child_id| self.remove_active_uncommitted(&child_id))
            .collect();
        if let Some(lock) = self.remove_active_uncommitted(lock_id) {
            removed.push(lock);
        }
        removed
    }

    fn expand_active_trees(&self, lock_ids: &[String]) -> Result<BTreeSet<String>, StateError> {
        let roots: BTreeSet<_> = lock_ids.iter().cloned().collect();
        let mut expanded = roots.clone();
        for id in roots {
            if !self.active_by_id.contains_key(&id) {
                return Err(StateError::ActiveLockNotFound(id));
            }
            if let Some(children) = self.children_by_vehicle.get(&id) {
                expanded.extend(children.iter().cloned());
            }
        }
        Ok(expanded)
    }

    fn remove_active_uncommitted(&mut self, lock_id: &str) -> Option<ActiveLock> {
        let lock = self.active_by_id.remove(lock_id)?;
        self.active_by_scope.remove(&lock.scope);
        if let Some(parent_id) = &lock.parent_vehicle
            && let Some(children) = self.children_by_vehicle.get_mut(parent_id)
        {
            children.remove(lock_id);
            if children.is_empty() {
                self.children_by_vehicle.remove(parent_id);
            }
        }
        Some(lock)
    }

    fn id_exists(&self, lock_id: &str) -> bool {
        self.active_by_id.contains_key(lock_id) || self.defunct_by_id.contains_key(lock_id)
    }

    fn increment_revision(&mut self) -> Result<(), StateError> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(StateError::RevisionOverflow)?;
        Ok(())
    }
}

fn normalize_name(name: &str) -> String {
    name.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn principal(subject: &str) -> LockPrincipal {
        LockPrincipal {
            subject: subject.to_owned(),
            claims: Map::new(),
        }
    }

    fn active_lock(
        id: &str,
        scope: ScopeKey,
        coverage: &[&str],
        parent_vehicle: Option<&str>,
    ) -> ActiveLock {
        ActiveLock {
            id: id.to_owned(),
            scope,
            coverage: LockCoverage::new(coverage.iter().map(ToString::to_string)),
            principal: principal("owner"),
            metadata: Map::new(),
            exclusive: true,
            expires_at: SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_secs(100))
                .expect("Test expiration should fit"),
            parent_vehicle: parent_vehicle.map(ToOwned::to_owned),
        }
    }

    #[test]
    fn scope_and_coverage_are_case_insensitive() {
        let lower = ScopeKey::from(&LockScope::Ecu {
            name: "engine".to_owned(),
        });
        let upper = ScopeKey::from(&LockScope::Ecu {
            name: "ENGINE".to_owned(),
        });
        assert_eq!(lower, upper);
        assert!(
            LockCoverage::new(["Engine".to_owned()])
                .overlaps(&LockCoverage::new(["ENGINE".to_owned()]))
        );
    }

    #[test]
    fn vehicle_coverage_contains_and_overlaps_any_ecu_set() {
        let vehicle = LockCoverage::vehicle();
        let ecus = LockCoverage::new(["new-ecu".to_owned()]);

        assert!(vehicle.contains(&ecus));
        assert!(vehicle.contains_ecu("new-ecu"));
        assert!(vehicle.overlaps(&ecus));
        assert!(ecus.overlaps(&vehicle));
        assert!(!ecus.contains(&vehicle));
    }

    #[test]
    fn failed_insert_keeps_state_and_revision_unchanged() {
        let mut state = LockState::default();
        state
            .insert_active(active_lock(
                "first",
                ScopeKey::Ecu("engine".to_owned()),
                &["engine"],
                None,
            ))
            .expect("Initial insertion should succeed");
        let before = state.clone();

        let error = state
            .insert_active(active_lock(
                "second",
                ScopeKey::Ecu("engine".to_owned()),
                &["engine"],
                None,
            ))
            .expect_err("Duplicate scope should fail");

        assert_eq!(error, StateError::DuplicateScope);
        assert_eq!(state.revision(), before.revision());
        assert_eq!(
            state.active().collect::<Vec<_>>(),
            before.active().collect::<Vec<_>>()
        );
    }

    #[test]
    fn overlapping_coverage_is_rejected_but_unrelated_coverage_is_allowed() {
        let mut state = LockState::default();
        state
            .insert_active(active_lock(
                "engine",
                ScopeKey::Ecu("engine".to_owned()),
                &["engine"],
                None,
            ))
            .expect("Initial insertion should succeed");
        state
            .insert_active(active_lock(
                "body",
                ScopeKey::FunctionalGroup("body-group".to_owned()),
                &["body"],
                None,
            ))
            .expect("Unrelated coverage should succeed");
        let revision = state.revision();

        let error = state
            .insert_active(active_lock(
                "powertrain",
                ScopeKey::FunctionalGroup("powertrain".to_owned()),
                &["engine", "transmission"],
                None,
            ))
            .expect_err("Overlapping coverage should fail");

        assert_eq!(error, StateError::CoverageConflict("engine".to_owned()));
        assert_eq!(state.revision(), revision);
        assert_eq!(state.active().count(), 2);
    }

    #[test]
    fn renewal_defers_stale_timer_via_not_due() {
        let mut state = LockState::default();
        state
            .insert_active(active_lock(
                "ecu",
                ScopeKey::Ecu("engine".to_owned()),
                &["engine"],
                None,
            ))
            .expect("Insertion should succeed");
        let old_expires_at = SystemTime::now()
            .checked_add(Duration::from_secs(100))
            .expect("Test expiration should fit");
        state
            .active_by_id
            .get_mut("ecu")
            .expect("Inserted lock should exist")
            .expires_at = old_expires_at;
        let expires_at = SystemTime::now()
            .checked_add(Duration::from_secs(200))
            .expect("Test expiration should fit");

        state
            .renew("ecu", expires_at)
            .expect("Renewal should succeed");

        assert!(matches!(
            state
                .begin_expiration("ecu", old_expires_at)
                .expect("Stale timer should be deferred"),
            ExpirationStart::NotDue(returned) if returned == expires_at
        ));
        assert_eq!(state.active().count(), 1);
    }

    #[test]
    fn conversion_consumes_old_expiration_as_stale() {
        let mut state = LockState::default();
        state
            .insert_active(active_lock(
                "ecu",
                ScopeKey::Ecu("engine".to_owned()),
                &["engine"],
                None,
            ))
            .expect("Converted lock insertion should succeed");
        state
            .commit_replacement(
                &[],
                &["ecu".to_owned()],
                active_lock(
                    "group",
                    ScopeKey::FunctionalGroup("powertrain".to_owned()),
                    &["engine"],
                    None,
                ),
                "owner",
                SystemTime::UNIX_EPOCH,
            )
            .expect("Conversion should succeed");

        assert!(matches!(
            state
                .begin_expiration("ecu", SystemTime::UNIX_EPOCH + Duration::from_secs(100))
                .expect("Consumed expiration should be stale"),
            ExpirationStart::Stale
        ));
        assert!(state.active_by_id("group").is_some());
        assert!(state.active_by_id("ecu").is_none());
    }

    #[test]
    fn renewal_rejects_equal_or_shorter_deadline_without_mutation() {
        let mut state = LockState::default();
        state
            .insert_active(active_lock(
                "ecu",
                ScopeKey::Ecu("engine".to_owned()),
                &["engine"],
                None,
            ))
            .expect("Insertion should succeed");
        let before = state.clone();

        for expires_at in [
            SystemTime::UNIX_EPOCH + Duration::from_secs(100),
            SystemTime::UNIX_EPOCH + Duration::from_secs(99),
        ] {
            assert_eq!(
                state.renew("ecu", expires_at),
                Err(StateError::RenewalNotExtension)
            );
            assert_eq!(state.revision(), before.revision());
            assert_eq!(state.active_by_id("ecu"), before.active_by_id("ecu"));
        }
    }

    #[test]
    fn early_expiration_returns_deadline_for_rescheduling() {
        let mut state = LockState::default();
        state
            .insert_active(active_lock(
                "ecu",
                ScopeKey::Ecu("engine".to_owned()),
                &["engine"],
                None,
            ))
            .expect("Insertion should succeed");
        let deadline = SystemTime::UNIX_EPOCH + Duration::from_secs(100);

        assert!(matches!(
            state
                .begin_expiration(
                    "ecu",
                    SystemTime::UNIX_EPOCH + Duration::from_secs(99)
                )
                .expect("Early expiration should be handled"),
            ExpirationStart::NotDue(returned) if returned == deadline
        ));
        assert!(state.active_by_id("ecu").is_some());
    }

    #[test]
    fn vehicle_delete_removes_children_in_one_revision() {
        let mut state = LockState::default();
        state
            .insert_active(active_lock(
                "vehicle",
                ScopeKey::Vehicle,
                &["engine", "body"],
                None,
            ))
            .expect("Vehicle insertion should succeed");
        state
            .insert_active(active_lock(
                "ecu",
                ScopeKey::Ecu("engine".to_owned()),
                &["engine"],
                Some("vehicle"),
            ))
            .expect("Child insertion should succeed");
        let revision = state.revision();

        let removed = state.delete("vehicle").expect("Delete should succeed");

        assert_eq!(removed.len(), 2);
        assert_eq!(state.revision(), revision + 1);
        assert_eq!(state.active().count(), 0);
        state.validate_invariants().expect("State should be valid");
    }

    #[test]
    fn preemption_is_atomic_and_current_holder_is_dynamic() {
        let mut state = LockState::default();
        state
            .insert_active(active_lock(
                "old",
                ScopeKey::Ecu("engine".to_owned()),
                &["engine"],
                None,
            ))
            .expect("Initial insertion should succeed");
        let mut replacement =
            active_lock("new", ScopeKey::Ecu("engine".to_owned()), &["engine"], None);
        replacement.principal = principal("new-owner");

        state
            .commit_replacement(
                &["old".to_owned()],
                &[],
                replacement,
                "priority-app",
                SystemTime::UNIX_EPOCH
                    .checked_add(Duration::from_secs(10))
                    .expect("Test break time should fit"),
            )
            .expect("Preemption should commit");

        let defunct = state.defunct().next().expect("Defunct lock should exist");
        assert_eq!(state.current_holder(defunct), "new-owner");
        state
            .delete("new")
            .expect("Replacement delete should succeed");
        let defunct = state.defunct().next().expect("Defunct lock should remain");
        assert_eq!(state.current_holder(defunct), "new-owner");
    }

    #[test]
    fn invalid_preemption_rolls_back_every_change() {
        let mut state = LockState::default();
        state
            .insert_active(active_lock(
                "old",
                ScopeKey::Ecu("engine".to_owned()),
                &["engine"],
                None,
            ))
            .expect("Initial insertion should succeed");
        let before = state.clone();

        let error = state
            .commit_replacement(
                &["old".to_owned(), "missing".to_owned()],
                &[],
                active_lock("new", ScopeKey::Ecu("engine".to_owned()), &["engine"], None),
                "priority-app",
                SystemTime::UNIX_EPOCH,
            )
            .expect_err("Missing preempted lock should fail");

        assert_eq!(error, StateError::ActiveLockNotFound("missing".to_owned()));
        assert_eq!(state.revision(), before.revision());
        assert_eq!(
            state.active().collect::<Vec<_>>(),
            before.active().collect::<Vec<_>>()
        );
        assert_eq!(state.defunct().count(), 0);
    }

    #[test]
    fn defunct_expiration_never_removes_active_replacement() {
        let mut state = LockState::default();
        state
            .insert_active(active_lock(
                "old",
                ScopeKey::Ecu("engine".to_owned()),
                &["engine"],
                None,
            ))
            .expect("Initial insertion should succeed");
        state
            .commit_replacement(
                &["old".to_owned()],
                &[],
                active_lock("new", ScopeKey::Ecu("engine".to_owned()), &["engine"], None),
                "priority-app",
                SystemTime::UNIX_EPOCH,
            )
            .expect("Preemption should commit");

        let expired = state
            .expire_defunct(
                SystemTime::UNIX_EPOCH
                    .checked_add(Duration::from_secs(100))
                    .expect("Test expiration should fit"),
            )
            .expect("Defunct expiration should succeed");

        assert_eq!(expired, vec!["old"]);
        assert_eq!(
            state
                .active()
                .map(|lock| lock.id.as_str())
                .collect::<Vec<_>>(),
            vec!["new"]
        );
    }

    #[test]
    fn vehicle_preemption_commits_root_and_descendants_once() {
        let mut state = LockState::default();
        state
            .insert_active(active_lock(
                "z-vehicle",
                ScopeKey::Vehicle,
                &["engine", "body"],
                None,
            ))
            .expect("Vehicle insertion should succeed");
        state
            .insert_active(active_lock(
                "a-child",
                ScopeKey::Ecu("engine".to_owned()),
                &["engine"],
                Some("z-vehicle"),
            ))
            .expect("Child insertion should succeed");
        let mut replacement =
            active_lock("replacement", ScopeKey::Vehicle, &["engine", "body"], None);
        replacement.principal = principal("new-owner");

        let removed = state
            .commit_replacement(
                &["z-vehicle".to_owned()],
                &[],
                replacement,
                "new-owner",
                SystemTime::now(),
            )
            .expect("Vehicle root preemption should commit");

        assert_eq!(removed.len(), 2);
        assert_eq!(state.defunct().count(), 2);
        assert_eq!(state.active().count(), 1);
        state
            .validate_invariants()
            .expect("State should remain valid");
    }

    #[test]
    fn defunct_lock_can_be_acknowledged() {
        let mut state = LockState::default();
        state
            .insert_active(active_lock(
                "old",
                ScopeKey::Ecu("engine".to_owned()),
                &["engine"],
                None,
            ))
            .expect("Initial insertion should succeed");
        state
            .commit_replacement(
                &["old".to_owned()],
                &[],
                active_lock("new", ScopeKey::Ecu("engine".to_owned()), &["engine"], None),
                "priority-app",
                SystemTime::UNIX_EPOCH,
            )
            .expect("Preemption should commit");

        assert!(
            state
                .acknowledge_defunct("old")
                .expect("Acknowledgement should succeed")
        );
        assert!(
            !state
                .acknowledge_defunct("old")
                .expect("Repeated acknowledgement should be a no-op")
        );
        assert_eq!(state.defunct().count(), 0);
    }

    #[test]
    fn current_holder_follows_preemption_chain() {
        let mut state = LockState::default();
        state
            .insert_active(active_lock(
                "first",
                ScopeKey::Ecu("engine".to_owned()),
                &["engine"],
                None,
            ))
            .expect("Initial insertion should succeed");
        let mut second = active_lock(
            "second",
            ScopeKey::Ecu("engine".to_owned()),
            &["engine"],
            None,
        );
        second.principal = principal("second-owner");
        state
            .commit_replacement(
                &["first".to_owned()],
                &[],
                second,
                "second-owner",
                SystemTime::UNIX_EPOCH,
            )
            .expect("First preemption should commit");
        let mut third = active_lock(
            "third",
            ScopeKey::Ecu("engine".to_owned()),
            &["engine"],
            None,
        );
        third.principal = principal("third-owner");
        state
            .commit_replacement(
                &["second".to_owned()],
                &[],
                third,
                "third-owner",
                SystemTime::UNIX_EPOCH,
            )
            .expect("Second preemption should commit");

        let first = state
            .defunct()
            .find(|lock| lock.id == "first")
            .expect("First defunct lock should remain");
        assert_eq!(state.current_holder(first), "third-owner");

        state
            .acknowledge_defunct("second")
            .expect("Intermediate acknowledgement should succeed");
        let first = state
            .defunct()
            .find(|lock| lock.id == "first")
            .expect("First defunct lock should remain");
        assert_eq!(state.current_holder(first), "third-owner");
    }
}
