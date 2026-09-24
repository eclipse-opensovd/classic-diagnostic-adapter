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

use std::{pin::Pin, sync::Arc, time::SystemTime};

use cda_interfaces::{DynamicPlugin, UdsEcu, lock_priority_api::LockLifecycleEvent};
use futures::FutureExt;
use tokio::{
    sync::OwnedMutexGuard,
    time::{Instant, sleep_until},
};

use super::{ActiveLock, ApiError, Locks, active_snapshot, enqueue_lock_event};
use crate::sovd::lock_state::ExpirationStart;

/// Type alias for the async cleanup closure called when dropping a lock
type LockCleanupFn = dyn FnOnce() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync;

/// Wrapper struct to hold an async closure
///
/// This is needed because `AsyncFnOnce` cannot be used directly as a trait object
/// And the returned Future needs to be pinned. To reduce the complexity at caller site,
/// the `new` function of this helper struct takes care of that
pub(super) struct LockCleanupFnHelper {
    func: Box<LockCleanupFn>,
}

impl LockCleanupFnHelper {
    pub(super) fn new<F, Out>(f: F) -> Self
    where
        F: FnOnce() -> Out + Send + Sync + 'static,
        Out: Future<Output = ()> + Send + 'static,
    {
        Self {
            func: Box::new(move || Box::pin(f())),
        }
    }

    async fn call(self) {
        (self.func)().await;
    }
}
impl Locks {
    pub(super) fn expiration_target(lock: &ActiveLock) -> Result<Instant, ApiError> {
        Self::expiration_target_at(lock.expires_at, SystemTime::now())
    }

    pub(super) fn expiration_target_at(
        expires_at: SystemTime,
        now: SystemTime,
    ) -> Result<Instant, ApiError> {
        let duration = expires_at
            .duration_since(now)
            .map_err(|_| ApiError::BadRequest("Expiration date is in the past".to_owned()))?;
        Instant::now()
            .checked_add(duration)
            .ok_or_else(|| ApiError::BadRequest("Lock expiration is too large".to_owned()))
    }

    pub(super) async fn schedule_expiration(&self, lock: &ActiveLock, target: Instant) {
        self.ensure_lifecycle_worker().await;
        let store = Arc::clone(&self.store);
        let transition_gate = Arc::clone(&self.transition_gate);
        let policy = Arc::clone(&self.priority_policy);
        let lifecycle_sender = self.lifecycle_sender.clone();
        let lock_id = lock.id.clone();
        cda_interfaces::spawn_named!(&format!("lock-expiration-{lock_id}"), async move {
            let mut target = target;
            let (removed, pending_cleanups, transition_id, transition_guard) = loop {
                sleep_until(target).await;
                let (transition_id, transition_guard) =
                    reserve_transition(&store, &transition_gate).await;
                let outcome = {
                    let mut store = store.lock().await;
                    match store.state.begin_expiration(&lock_id, SystemTime::now()) {
                        Ok(ExpirationStart::Expired(removed)) => {
                            let cleanups = take_cleanups(&mut store.cleanups, &removed);
                            Ok(Some((removed, cleanups)))
                        }
                        Ok(ExpirationStart::Stale) => Ok(None),
                        Ok(ExpirationStart::NotDue(expires_at)) => {
                            let duration = expires_at
                                .duration_since(SystemTime::now())
                                .unwrap_or_default();
                            target = Instant::now()
                                .checked_add(duration)
                                .unwrap_or_else(Instant::now);
                            Err(())
                        }
                        Err(error) => {
                            tracing::error!(%error, %lock_id, "Failed to expire lock");
                            Ok(None)
                        }
                    }
                };
                match outcome {
                    Ok(Some((removed, cleanups))) => {
                        break (removed, cleanups, transition_id, transition_guard);
                    }
                    Ok(None) => {
                        finish_transition(&store, transition_id, transition_guard).await;
                        return;
                    }
                    Err(()) => {
                        finish_transition(&store, transition_id, transition_guard).await;
                    }
                }
            };
            let events: Vec<_> = removed
                .iter()
                .map(|lock| LockLifecycleEvent::Expired {
                    lock: active_snapshot(lock),
                })
                .collect();
            run_cleanups(pending_cleanups).await;
            finish_transition(&store, transition_id, transition_guard).await;
            for event in events {
                enqueue_lock_event(&lifecycle_sender, Arc::clone(&policy), event);
            }
        });
    }

    pub(super) fn schedule_defunct_expiration(
        &self,
        expires_at: SystemTime,
    ) -> Result<(), ApiError> {
        let duration = expires_at
            .duration_since(SystemTime::now())
            .unwrap_or_default();
        let target = Instant::now()
            .checked_add(duration)
            .ok_or_else(|| ApiError::BadRequest("Lock expiration is too large".to_owned()))?;
        let store = Arc::clone(&self.store);
        let transition_gate = Arc::clone(&self.transition_gate);
        cda_interfaces::spawn_named!("defunct-lock-expiration", async move {
            sleep_until(target).await;
            let mut store = lock_idle(&store, &transition_gate).await;
            if let Err(error) = store.state.expire_defunct(SystemTime::now()) {
                tracing::error!(%error, "Failed to expire defunct locks");
            }
        });
        Ok(())
    }
}

pub(super) async fn run_cleanups(pending: Vec<LockCleanupFnHelper>) {
    for cleanup in pending {
        if let Err(panic) = std::panic::AssertUnwindSafe(cleanup.call())
            .catch_unwind()
            .await
        {
            let message = panic
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| panic.downcast_ref::<String>().map(String::as_str))
                .unwrap_or("Unknown panic payload");
            tracing::error!(%message, "Lock cleanup panicked");
        }
    }
}

pub(super) fn take_cleanups(
    cleanups: &mut cda_interfaces::HashMap<String, LockCleanupFnHelper>,
    removed: &[ActiveLock],
) -> Vec<LockCleanupFnHelper> {
    removed
        .iter()
        .filter_map(|lock| cleanups.remove(&lock.id))
        .collect()
}

async fn reserve_transition(
    store: &Arc<tokio::sync::Mutex<super::LockStore>>,
    transition_gate: &Arc<tokio::sync::Mutex<()>>,
) -> (super::TransitionId, OwnedMutexGuard<()>) {
    let transition_guard = Arc::clone(transition_gate).lock_owned().await;
    let mut store = store.lock().await;
    store.next_transition_id = store.next_transition_id.saturating_add(1);
    let id = store.next_transition_id;
    store.transition = Some(id);
    (id, transition_guard)
}

async fn finish_transition(
    store: &Arc<tokio::sync::Mutex<super::LockStore>>,
    transition_id: super::TransitionId,
    _transition_guard: OwnedMutexGuard<()>,
) {
    let mut store = store.lock().await;
    if store.transition == Some(transition_id) {
        store.transition = None;
    }
}

async fn lock_idle<'a>(
    store: &'a Arc<tokio::sync::Mutex<super::LockStore>>,
    transition_gate: &Arc<tokio::sync::Mutex<()>>,
) -> tokio::sync::MutexGuard<'a, super::LockStore> {
    let transition_guard = transition_gate.lock().await;
    let store = store.lock().await;
    drop(transition_guard);
    store
}

pub(super) async fn reset_ecu_session_and_security<T: UdsEcu>(
    uds: &T,
    ecu_name: &str,
    context: &str,
    security_plugin: &DynamicPlugin,
) {
    if let Err(e) = uds.reset_ecu_session(ecu_name, security_plugin).await {
        tracing::error!("Failed to reset ECU session for ECU {ecu_name} during {context}: {e}");
    } else {
        tracing::info!("ECU session reset for ECU {ecu_name} during {context}");
    }

    if let Err(e) = uds
        .reset_ecu_security_access(ecu_name, security_plugin)
        .await
    {
        tracing::error!(
            "Failed to reset ECU security access for ECU {ecu_name} during {context}: {e}"
        );
    } else {
        tracing::info!("ECU security access reset for ECU {ecu_name} during {context}");
    }
}
