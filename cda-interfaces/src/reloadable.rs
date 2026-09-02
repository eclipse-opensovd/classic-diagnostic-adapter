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
pub struct Reloadable<T>(Arc<RwLock<T>>);

impl<T> Reloadable<T> {
    /// Borrows the current vehicle data for the caller's operation.
    ///
    /// Hold the guard for as long as the data is used: that is what makes
    /// [`ReloadableOwner::apply`] deterministic. Extracting owned handles from
    /// under it and dropping the guard early defeats that: the extracted value
    /// keeps the replaced data alive.
    pub async fn read(&self) -> RwLockReadGuard<'_, T> {
        self.0.read().await
    }
}

impl<T> Clone for Reloadable<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

/// Sole authority to replace one [`Reloadable`]'s data.
///
/// Handed to update wiring; runtime handles get only a [`Reloadable`], so they
/// can read the data but never replace it.
pub struct ReloadableOwner<T>(Reloadable<T>);

impl<T> ReloadableOwner<T> {
    /// Creates the owner, with `value` as the starting data.
    #[must_use]
    pub fn new(value: T) -> Self {
        Self(Reloadable(Arc::new(RwLock::new(value))))
    }

    /// Returns read-only access for the runtime handles.
    #[must_use]
    pub fn reader(&self) -> Reloadable<T> {
        self.0.clone()
    }

    /// Replaces the data, waiting for in-flight readers to finish first.
    ///
    /// When this returns, nothing is reading the previous value: it has been
    /// dropped, along with everything it owned.
    pub async fn apply(&self, value: T) {
        *self.0.0.write().await = value;
    }
}

/// A component whose vehicle data a runtime update can replace.
///
/// Replacing is infallible: every fallible step ran during preflight, and the
/// update holds the exclusive disable lease. It is asynchronous because it
/// waits for in-flight readers.
#[async_trait::async_trait]
pub trait ReloadComponent<T>: Send + Sync + 'static {
    /// Replaces this component's data with `data`.
    async fn apply(&self, data: T);
}

#[async_trait::async_trait]
impl<T: Send + Sync + 'static> ReloadComponent<T> for ReloadableOwner<T> {
    async fn apply(&self, data: T) {
        Self::apply(self, data).await;
    }
}
