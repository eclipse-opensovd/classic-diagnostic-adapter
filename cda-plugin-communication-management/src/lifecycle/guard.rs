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

//! Synchronous RAII communication guard.
//!
//! [`CommunicationGuard`] is an opaque type owned by `cda-interfaces`. This
//! module holds the drop-based release logic it wraps, kept private so that no
//! consumer can construct or inspect a guard directly.

use std::sync::Arc;

use cda_interfaces::communication_control::{CommunicationGuard, PreemptibleCommunicationGuard};

use super::state::{CommunicationStateData, CommunicationStateStore};

/// Opaque identity for one active communication-use guard.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct CommunicationGuardId(pub uuid::Uuid);

/// Marks communication as in use, so it cannot be disabled, for example by a
/// runtime update. Dropping releases the slot synchronously.
pub(crate) struct ActiveGuard {
    id: Option<CommunicationGuardId>,
    state: Arc<CommunicationStateStore>,
}

impl ActiveGuard {
    /// Registers a new guard entry in `data` and returns its sole owner, wrapped
    /// as an opaque [`CommunicationGuard`].
    ///
    /// Takes the caller's live borrow rather than the
    /// [`CommunicationStateStore`], because registration has to happen inside
    /// the same critical section that observed
    /// [`Enabled`](super::state::CommunicationState::Enabled). Locking the store
    /// here would deadlock against the guard the caller already holds.
    pub(crate) fn register(
        data: &mut CommunicationStateData,
        state: Arc<CommunicationStateStore>,
    ) -> CommunicationGuard {
        let id = CommunicationGuardId(uuid::Uuid::new_v4());
        data.active_guards.insert(id);
        CommunicationGuard::new(Self {
            id: Some(id),
            state,
        })
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            let mut state = self.state.lock();
            if state.active_guards.remove(&id) && state.active_guards.is_empty() {
                // Wakes a disable waiting for in-flight requests to finish.
                state.idle.notify_waiters();
            }
        }
    }
}

/// Marks communication as used by preemptible background work, such as tester
/// present. Unlike [`ActiveGuard`] it does not block a disable, which instead
/// stops the holder during deinitialization. Dropping releases the slot
/// synchronously.
pub(crate) struct PreemptibleGuard {
    id: Option<CommunicationGuardId>,
    state: Arc<CommunicationStateStore>,
}

impl PreemptibleGuard {
    /// Registers a new preemptible guard entry in `data`.
    ///
    /// Takes the caller's live borrow for the same reason as
    /// [`ActiveGuard::register`].
    pub(crate) fn register(
        data: &mut CommunicationStateData,
        state: Arc<CommunicationStateStore>,
    ) -> PreemptibleCommunicationGuard {
        let id = CommunicationGuardId(uuid::Uuid::new_v4());
        data.preemptible_guards.insert(id);
        PreemptibleCommunicationGuard::new(Self {
            id: Some(id),
            state,
        })
    }
}

impl Drop for PreemptibleGuard {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            let _removed = self.state.lock().preemptible_guards.remove(&id);
        }
    }
}

#[cfg(test)]
mod tests {
    use cda_interfaces::communication_control::CommunicationState;

    use super::*;

    /// Each `register` adds exactly one entry and each drop releases exactly
    /// that one, so guards neither collide nor release each other's.
    #[test]
    fn guards_are_tracked_independently_and_release_on_drop() {
        let state = Arc::new(CommunicationStateStore::new(
            CommunicationState::Enabled,
            cda_interfaces::communication_control::VariantDetectionMode::Always,
        ));
        let guards = || state.lock().active_guards.len();

        let guard1 = ActiveGuard::register(&mut state.lock(), Arc::clone(&state));
        assert_eq!(guards(), 1);
        let guard2 = ActiveGuard::register(&mut state.lock(), Arc::clone(&state));
        assert_eq!(guards(), 2, "a second guard must claim its own entry");

        drop(guard1);
        assert_eq!(guards(), 1, "a guard must not release another's entry");
        drop(guard2);
        assert_eq!(guards(), 0);
    }

    /// Preemptible guards are tracked separately and never count as request
    /// guards.
    #[test]
    fn preemptible_guards_are_tracked_separately() {
        let state = Arc::new(CommunicationStateStore::new(
            CommunicationState::Enabled,
            cda_interfaces::communication_control::VariantDetectionMode::Always,
        ));
        let guard = PreemptibleGuard::register(&mut state.lock(), Arc::clone(&state));
        assert_eq!(state.lock().preemptible_guards.len(), 1);
        assert!(state.lock().active_guards.is_empty());
        assert!(!state.lock().blocks_disable());
        drop(guard);
        assert!(state.lock().preemptible_guards.is_empty());
    }
}
