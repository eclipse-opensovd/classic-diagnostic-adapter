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

//! Selection of the lock relevant to a UDS request at the transport boundary.

use std::time::SystemTime;

use cda_interfaces::request_authorization::{RequestLockContext, UdsRequestTarget};

use super::Locks;
use crate::sovd::lock_state::{ActiveLock, LockState, ScopeKey};

/// Selects the most specific effective lock for a request target.
///
/// A physical target prefers its own ECU lock, then a functional-group lock covering the
/// ECU, then the vehicle lock. A functional target prefers the exact functional-group lock,
/// then the vehicle lock. Expired locks and child locks whose vehicle parent is no longer
/// active are ignored.
fn most_specific_lock<'a>(
    state: &'a LockState,
    target: &UdsRequestTarget,
    now: SystemTime,
) -> Option<&'a ActiveLock> {
    let is_effective = |lock: &&ActiveLock| {
        lock.expires_at > now
            && lock.parent_vehicle_lock_id.as_deref().is_none_or(|parent| {
                state
                    .active_by_id(parent)
                    .is_some_and(|parent| parent.expires_at > now)
            })
    };
    let effective = || state.active().filter(is_effective);

    let vehicle = || effective().find(|lock| lock.scope == ScopeKey::Vehicle);
    match target {
        UdsRequestTarget::Ecu { name, .. } => {
            let ecu_key = ScopeKey::Ecu(name.to_ascii_lowercase());
            effective()
                .find(|lock| lock.scope == ecu_key)
                .or_else(|| {
                    effective().find(|lock| {
                        matches!(lock.scope, ScopeKey::FunctionalGroup(_))
                            && lock.coverage.contains_ecu(name)
                    })
                })
                .or_else(vehicle)
        }
        UdsRequestTarget::FunctionalGroup { name, .. } => {
            let group_key = ScopeKey::FunctionalGroup(name.to_ascii_lowercase());
            effective()
                .find(|lock| lock.scope == group_key)
                .or_else(vehicle)
        }
    }
}

impl Locks {
    /// Returns an owned snapshot of the lock relevant to `target`, if any.
    ///
    /// The store guard is released before returning, so callers may invoke vendor code
    /// without holding lock state.
    pub(crate) async fn request_lock_for(
        &self,
        target: &UdsRequestTarget,
    ) -> Option<RequestLockContext> {
        let now = SystemTime::now();
        self.core
            .read_store(|store| {
                most_specific_lock(&store.state, target, now).map(|lock| RequestLockContext {
                    holder: lock.principal.subject.clone(),
                    claims: lock.principal.claims.clone(),
                    metadata: lock.metadata.clone(),
                })
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use cda_interfaces::lock_priority_api::LockPrincipal;
    use serde_json::{Map, Value};

    use super::*;
    use crate::sovd::lock_state::LockCoverage;

    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(seconds))
            .expect("test time should be representable")
    }

    fn lock(
        id: &str,
        scope: ScopeKey,
        coverage: LockCoverage,
        expires_at: u64,
        parent: Option<&str>,
    ) -> ActiveLock {
        ActiveLock {
            id: id.into(),
            scope,
            coverage,
            principal: LockPrincipal {
                subject: "owner".to_owned(),
                claims: Map::new(),
            },
            metadata: Map::from_iter([("use_case".to_owned(), Value::from(id))]),
            exclusive: true,
            expires_at: at(expires_at),
            parent_vehicle_lock_id: parent.map(Into::into),
        }
    }

    fn ecu_lock(id: &str, ecu: &str, expires_at: u64, parent: Option<&str>) -> ActiveLock {
        lock(
            id,
            ScopeKey::Ecu(ecu.to_owned()),
            LockCoverage::new([ecu.to_owned()]),
            expires_at,
            parent,
        )
    }

    fn group_lock(id: &str, group: &str, ecus: &[&str], expires_at: u64) -> ActiveLock {
        lock(
            id,
            ScopeKey::FunctionalGroup(group.to_owned()),
            LockCoverage::new(ecus.iter().map(ToString::to_string)),
            expires_at,
            None,
        )
    }

    fn vehicle_lock(id: &str, expires_at: u64) -> ActiveLock {
        lock(
            id,
            ScopeKey::Vehicle,
            LockCoverage::vehicle(),
            expires_at,
            None,
        )
    }

    fn state(locks: impl IntoIterator<Item = ActiveLock>) -> LockState {
        let mut state = LockState::default();
        for lock in locks {
            state.insert_active(lock).expect("test lock should insert");
        }
        state
    }

    fn physical(name: &str) -> UdsRequestTarget {
        UdsRequestTarget::Ecu {
            name: name.to_owned(),
            additional_fields: Vec::new(),
        }
    }

    fn functional(name: &str) -> UdsRequestTarget {
        UdsRequestTarget::FunctionalGroup {
            name: name.to_owned(),
            ecus: Vec::new(),
        }
    }

    fn selected(state: &LockState, target: &UdsRequestTarget, now: u64) -> Option<String> {
        most_specific_lock(state, target, at(now)).map(|lock| lock.id.to_string())
    }

    #[test]
    fn no_lock_selects_nothing() {
        let state = state([]);
        assert_eq!(selected(&state, &physical("ecu-a"), 10), None);
        assert_eq!(selected(&state, &functional("group"), 10), None);
    }

    #[test]
    fn physical_target_prefers_ecu_then_group_then_vehicle() {
        let all = state([
            vehicle_lock("vehicle", 1000),
            group_lock("group", "group", &["ecu-a"], 1000),
            ecu_lock("ecu", "ecu-a", 1000, None),
        ]);
        assert_eq!(
            selected(&all, &physical("ecu-a"), 10).as_deref(),
            Some("ecu")
        );

        let without_ecu = state([
            vehicle_lock("vehicle", 1000),
            group_lock("group", "group", &["ecu-a"], 1000),
        ]);
        assert_eq!(
            selected(&without_ecu, &physical("ecu-a"), 10).as_deref(),
            Some("group")
        );

        let only_vehicle = state([vehicle_lock("vehicle", 1000)]);
        assert_eq!(
            selected(&only_vehicle, &physical("ecu-a"), 10).as_deref(),
            Some("vehicle")
        );
    }

    #[test]
    fn group_lock_only_applies_to_covered_ecus() {
        let state = state([group_lock("group", "group", &["ecu-a"], 1000)]);
        assert_eq!(selected(&state, &physical("ecu-b"), 10), None);
    }

    #[test]
    fn target_names_are_matched_case_insensitively() {
        let state = state([
            ecu_lock("ecu", "ecu-a", 1000, None),
            group_lock("group", "engine", &["ecu-a"], 1000),
        ]);
        assert_eq!(
            selected(&state, &physical("ECU-A"), 10).as_deref(),
            Some("ecu")
        );
        assert_eq!(
            selected(&state, &functional("Engine"), 10).as_deref(),
            Some("group")
        );
    }

    #[test]
    fn functional_target_prefers_exact_group_then_vehicle() {
        let both = state([
            vehicle_lock("vehicle", 1000),
            group_lock("group", "group", &["ecu-a"], 1000),
            group_lock("other", "other", &["ecu-a"], 1000),
        ]);
        assert_eq!(
            selected(&both, &functional("group"), 10).as_deref(),
            Some("group")
        );
        assert_eq!(
            selected(&both, &functional("unlocked"), 10).as_deref(),
            Some("vehicle")
        );
    }

    #[test]
    fn functional_target_ignores_ecu_locks() {
        let state = state([ecu_lock("ecu", "ecu-a", 1000, None)]);
        assert_eq!(selected(&state, &functional("group"), 10), None);
    }

    #[test]
    fn expired_locks_are_skipped() {
        let state = state([
            ecu_lock("ecu", "ecu-a", 100, None),
            vehicle_lock("vehicle", 1000),
        ]);
        assert_eq!(
            selected(&state, &physical("ecu-a"), 50).as_deref(),
            Some("ecu")
        );
        assert_eq!(
            selected(&state, &physical("ecu-a"), 100).as_deref(),
            Some("vehicle"),
            "a lock expiring exactly now is no longer effective"
        );
    }

    #[test]
    fn child_of_expired_vehicle_lock_is_not_effective() {
        let state = state([
            vehicle_lock("vehicle", 100),
            ecu_lock("child", "ecu-a", 1000, Some("vehicle")),
        ]);
        assert_eq!(
            selected(&state, &physical("ecu-a"), 50).as_deref(),
            Some("child")
        );
        assert_eq!(
            selected(&state, &physical("ecu-a"), 150),
            None,
            "child must not outlive its expired vehicle parent"
        );
    }
}
