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
//! [`CommunicationGuard`]
//! is an opaque type owned by `cda-interfaces`; this module holds the
//! concrete drop-based release logic it wraps for this plugin's guards, kept
//! private so no consumer can construct or inspect one directly.

use std::sync::Arc;

use cda_interfaces::communication_control::CommunicationGuard;

use super::state::{CommunicationStateData, CommunicationStateStore};

/// Opaque identity for one active communication-use guard.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct CommunicationGuardId(pub uuid::Uuid);

/// Marks the communication as used, so it cannot be disabled, i.e. by an runtime update.
///
/// Dropping releases the slot synchronously. Wrapped in an opaque
/// [`CommunicationGuard`] before it is handed to a caller, so nothing outside
/// this crate can construct or inspect the id/state pair directly.
pub(crate) struct ActiveGuard {
    id: Option<CommunicationGuardId>,
    state: Arc<CommunicationStateStore>,
}

impl ActiveGuard {
    /// Registers a new guard entry in `data` and returns its sole owner,
    /// wrapped as an opaque [`CommunicationGuard`].
    ///
    /// Creating the id, registering it, and releasing it in [`Drop`] all live
    /// in this type, so an entry can never exist without a guard to release it
    /// (which would refuse every future `disable()` forever) and a guard can
    /// never exist without an entry.
    ///
    /// Takes the caller's live borrow rather than the [`CommunicationStateStore`]
    /// because the registration has to happen inside the same critical section
    /// that observed [`Enabled`](super::state::CommunicationState::Enabled).
    /// Locking the store here instead would deadlock against the guard the
    /// caller already holds, and registering after releasing that guard would
    /// let a `disable()` claim `Enabled -> Disabling` in between and take the
    /// transport down underneath a guard about to exist.
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
            let _removed = self.state.lock().active_guards.remove(&id);
        }
    }
}

#[cfg(test)]
mod tests {
    use cda_interfaces::communication_control::CommunicationState;

    use super::*;

    /// Each `register` adds exactly one entry and each drop releases exactly
    /// that one, so guards neither collide nor release each other's.
    ///
    /// There is deliberately no case here for "a guard over an unregistered
    /// id" or "an entry with no guard": [`ActiveGuard::register`] owns both
    /// halves, so neither is constructible.
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
}
