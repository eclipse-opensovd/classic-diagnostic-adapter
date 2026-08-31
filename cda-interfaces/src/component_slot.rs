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

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{RwLock, RwLockReadGuard};

use crate::Shutdown;

/// Replace-only capability over a [`ComponentSlot`]: implementors atomically
/// install a replacement component and shut down the instance it displaced,
/// without granting any read access to it.
#[async_trait]
pub trait ReplaceComponent<T: Shutdown>: Send + Sync + 'static {
    /// Atomically installs `replacement` into the slot, then shuts down the
    /// component it displaced.
    ///
    /// The write guard is held only for the swap itself. `shutdown()` runs
    /// after the guard is released, so it never blocks concurrent readers.
    async fn replace(&self, replacement: T);
}

/// Owns a hot-swappable component and grants two disjoint views over it:
///
/// - **Read access** (via [`ComponentSlot::read`]), for consumers that operate
///   the live component.
/// - **Replace-only access** (via [`ComponentSlot::replacer`]), for consumers
///   that only install a freshly constructed replacement, such as a
///   runtime-update plugin performing a hot reload.
///
/// The two views are disjoint at the type level, and only the slot's owner can
/// mint either.
///
/// # Locking
///
/// The slot is guarded by a [`tokio::sync::RwLock`]. Read views (including
/// derived ones, see `communication_control::SwappableGateway`) take a read
/// guard per call. `replace()` takes the write guard only for the `mem::replace`
/// itself, so a pending replacement cannot stall reads for longer than the
/// swap.
pub struct ComponentSlot<T: Shutdown> {
    component: Arc<RwLock<T>>,
}

impl<T: Shutdown> ComponentSlot<T> {
    /// Creates a new slot owning `component`.
    #[must_use]
    pub fn new(component: T) -> Self {
        Self {
            component: Arc::new(RwLock::new(component)),
        }
    }

    /// Acquires shared read access to the current component.
    pub async fn read(&self) -> RwLockReadGuard<'_, T> {
        self.component.read().await
    }
}

impl<T: Shutdown> Clone for ComponentSlot<T> {
    fn clone(&self) -> Self {
        Self {
            component: Arc::clone(&self.component),
        }
    }
}

impl<T: Shutdown> ComponentSlot<T> {
    /// Mints a replace-only capability over this slot. See
    /// [`ReplaceComponent`].
    #[must_use]
    pub fn replacer(&self) -> Arc<dyn ReplaceComponent<T>> {
        Arc::new(ComponentReplacer {
            component: Arc::clone(&self.component),
        })
    }
}

/// Private replace-only view over a [`ComponentSlot`]'s inner component,
/// constructed only by [`ComponentSlot::replacer`]. It has no accessor for
/// `component` beyond [`ReplaceComponent::replace`], which is what enforces the
/// capability boundary.
struct ComponentReplacer<T> {
    component: Arc<RwLock<T>>,
}

#[async_trait]
impl<T: Shutdown> ReplaceComponent<T> for ComponentReplacer<T> {
    async fn replace(&self, replacement: T) {
        let displaced = {
            let mut guard = self.component.write().await;
            std::mem::replace(&mut *guard, replacement)
        };
        displaced.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use async_trait::async_trait;

    use super::ComponentSlot;
    use crate::Shutdown;

    struct CountingComponent {
        id: usize,
        shutdown_calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Shutdown for CountingComponent {
        async fn shutdown(&self) {
            self.shutdown_calls.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn read_observes_replacement() {
        let shutdown_calls = Arc::new(AtomicUsize::new(0));
        let slot = ComponentSlot::new(CountingComponent {
            id: 1,
            shutdown_calls: Arc::clone(&shutdown_calls),
        });

        assert_eq!(slot.read().await.id, 1);

        let replacer = slot.replacer();
        replacer
            .replace(CountingComponent {
                id: 2,
                shutdown_calls: Arc::clone(&shutdown_calls),
            })
            .await;

        assert_eq!(slot.read().await.id, 2);
    }

    #[tokio::test]
    async fn replace_shuts_down_displaced_component_exactly_once() {
        let shutdown_calls = Arc::new(AtomicUsize::new(0));
        let slot = ComponentSlot::new(CountingComponent {
            id: 1,
            shutdown_calls: Arc::clone(&shutdown_calls),
        });
        let replacer = slot.replacer();

        replacer
            .replace(CountingComponent {
                id: 2,
                shutdown_calls: Arc::clone(&shutdown_calls),
            })
            .await;
        assert_eq!(shutdown_calls.load(Ordering::SeqCst), 1);

        replacer
            .replace(CountingComponent {
                id: 3,
                shutdown_calls: Arc::clone(&shutdown_calls),
            })
            .await;
        assert_eq!(shutdown_calls.load(Ordering::SeqCst), 2);
    }

    /// A component whose `shutdown()` re-enters the slot via `read()`, which
    /// only succeeds if `replace()` released the write guard before awaiting
    /// `shutdown()`.
    struct ReentrantComponent {
        slot: ComponentSlot<ReadableComponent>,
        reentry_observed_value: Arc<AtomicUsize>,
    }

    struct ReadableComponent(u32);

    #[async_trait]
    impl Shutdown for ReadableComponent {
        async fn shutdown(&self) {}
    }

    #[async_trait]
    impl Shutdown for ReentrantComponent {
        async fn shutdown(&self) {
            let value = self.slot.read().await.0;
            self.reentry_observed_value
                .store(value as usize, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn shutdown_runs_after_write_guard_is_released() {
        let inner_slot = ComponentSlot::new(ReadableComponent(42));
        let reentry_observed_value = Arc::new(AtomicUsize::new(0));
        let outer_slot = ComponentSlot::new(ReentrantComponent {
            slot: inner_slot.clone(),
            reentry_observed_value: Arc::clone(&reentry_observed_value),
        });

        let replacer = outer_slot.replacer();
        replacer
            .replace(ReentrantComponent {
                slot: inner_slot.clone(),
                reentry_observed_value: Arc::clone(&reentry_observed_value),
            })
            .await;

        // This read deadlocks if shutdown() ran under the write guard.
        assert_eq!(reentry_observed_value.load(Ordering::SeqCst), 42);
    }
}
