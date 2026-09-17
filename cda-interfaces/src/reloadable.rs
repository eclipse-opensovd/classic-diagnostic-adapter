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
/// Readers hold a guard for the whole operation, so a runtime update waits for
/// them rather than replacing the data underneath. The lock is uncontended
/// outside an update.
pub struct Reloadable<T> {
    data: Arc<RwLock<T>>,
}

impl<T> Reloadable<T> {
    /// Borrows the current vehicle data for the caller's operation.
    ///
    /// Hold the guard for as long as the data is used: that is what makes
    /// [`ReloadComponent::apply`] deterministic. Extracting owned handles from
    /// under it and dropping the guard early defeats that: the extracted value
    /// keeps the replaced data alive.
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
/// Replacing is infallible: every fallible step ran during preflight, and the
/// update holds the exclusive disable lease. It is asynchronous because it
/// waits for in-flight readers.
#[async_trait::async_trait]
pub trait ReloadComponent<T: Send + 'static>: Send + Sync + 'static {
    /// Replaces this component's data with `data`.
    async fn apply(&self, data: T);

    /// Replaces this component's data with `data` and hands back what it
    /// displaced, so a dispatch that fails after this can put the previous
    /// value back.
    ///
    /// The default hands nothing back: only a target that owns the value itself
    /// can, and one that forwards or derives has nothing to return.
    async fn swap(&self, data: T) -> Option<T> {
        self.apply(data).await;
        None
    }
}

/// Replaces the data, waiting for in-flight readers to finish first.
///
/// When this returns, nothing is reading the previous value: it has been
/// dropped, along with everything it owned.
#[async_trait::async_trait]
impl<T: Send + Sync + 'static> ReloadComponent<T> for ReloadableOwner<T> {
    async fn apply(&self, data: T) {
        *self.data.write().await = data;
    }

    async fn swap(&self, data: T) -> Option<T> {
        Some(std::mem::replace(&mut *self.data.write().await, data))
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
