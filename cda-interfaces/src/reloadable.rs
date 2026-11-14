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

//! Vehicle data that a runtime update replaces, and the capability to replace it.

use std::sync::Arc;

use tokio::sync::{RwLock, RwLockReadGuard};

/// Read access to one component's vehicle data.
///
/// A runtime update waits for outstanding guards rather than replacing the
/// data underneath them. The lock is uncontended outside an update.
pub struct Reloadable<T> {
    data: Arc<RwLock<T>>,
}

impl<T> Reloadable<T> {
    /// Borrows the current vehicle data for the caller's operation.
    ///
    /// Hold the guard at least for the lookup. Two styles are allowed:
    ///
    /// - Hold it for the whole operation (e.g. the UDS layer's ECU data). The
    ///   data cannot change underneath, and [`ReloadComponent::apply`] returns
    ///   only once the operation is done.
    /// - A component that must not block a reload on I/O (e.g. the CAN
    ///   transport, whose probes wait out timeouts) may copy owned handles out
    ///   under the guard **for one operation**, drop it, and then do the I/O.
    ///   Such handles must never be stored beyond that operation, and state
    ///   derived from them must be re-validated against the current data.
    ///   The price is that `apply` returning no longer means the previous
    ///   value is fully dropped: an operation in flight finishes on its copy.
    pub async fn read(&self) -> RwLockReadGuard<'_, T> {
        self.data.read().await
    }
}

impl<T> Clone for Reloadable<T> {
    fn clone(&self) -> Self {
        Self {
            data: Arc::clone(&self.data),
        }
    }
}

/// Sole authority to replace one [`Reloadable`]'s data.
///
/// Handed to update wiring; runtime handles get only a [`Reloadable`], so they
/// can read the data but never replace it.
pub struct ReloadableOwner<T> {
    data: Arc<RwLock<T>>,
}

impl<T> ReloadableOwner<T> {
    /// Creates the owner, with `value` as the starting data.
    #[must_use]
    pub fn new(value: T) -> Self {
        Self {
            data: Arc::new(RwLock::new(value)),
        }
    }

    /// Returns read-only access for the runtime handles.
    #[must_use]
    pub fn reader(&self) -> Reloadable<T> {
        Reloadable {
            data: Arc::clone(&self.data),
        }
    }
}

/// A component whose vehicle data a runtime update can replace.
///
/// Replacing is infallible: every fallible step ran during preflight. It is
/// asynchronous because it waits for in-flight readers.
#[async_trait::async_trait]
pub trait ReloadComponent<T>: Send + Sync + 'static {
    /// Replaces this component's data with `data`.
    ///
    /// The normal update flow calls this under the exclusive communication
    /// disable lease, with the transport down, but a component must not rely
    /// on that for correctness: `apply` may run while it is enabled. State
    /// derived from the previous data must not survive as if it still
    /// applied.
    async fn apply(&self, data: T);
}

/// Replaces the data, waiting for outstanding read guards to be dropped first.
///
/// When this returns, no guard on the previous value is held and the value
/// has been dropped. Only owned handles a reader copied out of it for an
/// operation still in flight can keep parts of it alive; see
/// [`Reloadable::read`].
#[async_trait::async_trait]
impl<T: Send + Sync + 'static> ReloadComponent<T> for ReloadableOwner<T> {
    async fn apply(&self, data: T) {
        *self.data.write().await = data;
    }
}

#[cfg(test)]
mod tests {
    use super::{ReloadComponent, ReloadableOwner};

    /// The property every reload path on top of this relies on: `apply` does not
    /// return while a reader still holds a guard, so no caller can observe a
    /// value that was replaced mid-operation.
    #[tokio::test]
    async fn apply_waits_for_an_outstanding_read_guard() {
        let owner = std::sync::Arc::new(ReloadableOwner::new(1u32));
        let reader = owner.reader();

        let guard = reader.read().await;
        let applying = {
            let owner = std::sync::Arc::clone(&owner);
            tokio::spawn(async move { owner.apply(2).await })
        };

        tokio::task::yield_now().await;
        assert!(
            !applying.is_finished(),
            "apply must not replace the value while a read guard is held"
        );
        assert_eq!(*guard, 1, "the held guard must still see the old value");

        drop(guard);
        applying.await.expect("apply task");
        assert_eq!(*reader.read().await, 2);
    }

    /// A reader outlives the owner: both hold the same `Arc`, so dropping the
    /// authority to replace does not take the data with it.
    #[tokio::test]
    async fn reader_keeps_working_after_the_owner_is_dropped() {
        let owner = ReloadableOwner::new(7u32);
        let reader = owner.reader();
        drop(owner);
        assert_eq!(*reader.read().await, 7);
    }
}
