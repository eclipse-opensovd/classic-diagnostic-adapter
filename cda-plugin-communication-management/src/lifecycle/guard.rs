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

use std::sync::Arc;

use super::state::CommunicationStateStore;

/// Opaque identity for one active communication-use guard.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct CommunicationGuardId(pub uuid::Uuid);

/// Marks the communication as used, so it cannot be disabled, i.e. by an runtime update
///
/// Dropping the guard synchronously releases the slot.
#[must_use = "The guard must be held for the complete diagnostic-activity lifetime. Communication \
              is marked as 'free' once the last guard is dropped"]
#[derive(Debug)]
pub struct CommunicationGuard {
    id: Option<CommunicationGuardId>,
    state: Arc<CommunicationStateStore>,
}

impl CommunicationGuard {
    pub(crate) fn new(id: CommunicationGuardId, state: Arc<CommunicationStateStore>) -> Self {
        Self {
            id: Some(id),
            state,
        }
    }
}

impl Drop for CommunicationGuard {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            let _removed = self.state.lock().active_guards.remove(&id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::state::CommunicationState;

    #[test]
    fn guard_releases_on_drop() {
        let state = Arc::new(CommunicationStateStore::new(CommunicationState::Enabled));
        let id = CommunicationGuardId(uuid::Uuid::new_v4());
        state.lock().active_guards.insert(id);

        let guards = || state.lock().active_guards.len();

        assert_eq!(guards(), 1);
        {
            let _guard = CommunicationGuard::new(id, Arc::clone(&state));
            assert_eq!(guards(), 1);
        }
        assert_eq!(guards(), 0);
    }

    #[test]
    fn multiple_guards_tracked_independently() {
        let state = Arc::new(CommunicationStateStore::new(CommunicationState::Enabled));
        let id1 = CommunicationGuardId(uuid::Uuid::new_v4());
        let id2 = CommunicationGuardId(uuid::Uuid::new_v4());

        state.lock().active_guards.insert(id1);
        state.lock().active_guards.insert(id2);

        {
            let _guard1 = CommunicationGuard::new(id1, Arc::clone(&state));
            let _guard2 = CommunicationGuard::new(id2, Arc::clone(&state));
            assert_eq!(state.lock().active_guards.len(), 2);
        }
        assert_eq!(state.lock().active_guards.len(), 0);
    }
}
