/*
 * SPDX-FileCopyrightText: 2025 Copyright (c) Contributors to the Eclipse Foundation
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

use std::{future::Future, pin::Pin, sync::Arc, time::SystemTime};

use cda_interfaces::{DynamicPlugin, UdsEcu, lock_priority_api::LockLifecycleEvent};
use futures::FutureExt;
use tokio::{
    task,
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
        Self::expiration_target_at(lock.expires_at)
    }

    pub(super) fn expiration_target_at(expires_at: SystemTime) -> Result<Instant, ApiError> {
        let duration = expires_at
            .duration_since(SystemTime::now())
            .map_err(|_| ApiError::BadRequest("Expiration date is in the past".to_owned()))?;
        Instant::now()
            .checked_add(duration)
            .ok_or_else(|| ApiError::InternalServerError(Some("Timeout is too large".to_owned())))
    }

    pub(super) async fn schedule_expiration(&self, lock: &ActiveLock, target: Instant) {
        self.ensure_lifecycle_worker().await;
        let store = Arc::clone(&self.store);
        let transition_changed = Arc::clone(&self.transition_changed);
        let policy = Arc::clone(&self.priority_policy);
        let lifecycle_sender = self.lifecycle_sender.clone();
        let lock_id = lock.id.clone();
        task::spawn(async move {
            let mut target = target;
            let (removed, pending_cleanups, transition_id) = loop {
                sleep_until(target).await;
                let transition_id = reserve_transition(&store, &transition_changed).await;
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
                    Ok(Some((removed, cleanups))) => break (removed, cleanups, transition_id),
                    Ok(None) => {
                        finish_transition(&store, &transition_changed, transition_id).await;
                        return;
                    }
                    Err(()) => {
                        finish_transition(&store, &transition_changed, transition_id).await;
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
            finish_transition(&store, &transition_changed, transition_id).await;
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
        let target = Instant::now().checked_add(duration).ok_or_else(|| {
            ApiError::InternalServerError(Some("Timeout is too large".to_owned()))
        })?;
        let store = Arc::clone(&self.store);
        let transition_changed = Arc::clone(&self.transition_changed);
        task::spawn(async move {
            sleep_until(target).await;
            let mut store = lock_idle(&store, &transition_changed).await;
            if let Err(error) = store.state.expire_defunct(SystemTime::now()) {
                tracing::error!(%error, "Failed to expire defunct locks");
            }
        });
        Ok(())
    }
}

pub(super) async fn run_cleanups(pending: Vec<LockCleanupFnHelper>) {
    for cleanup in pending {
        if std::panic::AssertUnwindSafe(cleanup.call())
            .catch_unwind()
            .await
            .is_err()
        {
            tracing::error!("Lock cleanup panicked");
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
    changed: &Arc<tokio::sync::Notify>,
) -> super::TransitionId {
    loop {
        let notified = changed.notified();
        let mut store = store.lock().await;
        if store.transition.is_none() {
            store.next_transition_id = store.next_transition_id.saturating_add(1);
            let id = store.next_transition_id;
            store.transition = Some(id);
            return id;
        }
        drop(store);
        notified.await;
    }
}

async fn finish_transition(
    store: &Arc<tokio::sync::Mutex<super::LockStore>>,
    changed: &Arc<tokio::sync::Notify>,
    transition_id: super::TransitionId,
) {
    let mut store = store.lock().await;
    if store.transition == Some(transition_id) {
        store.transition = None;
        drop(store);
        changed.notify_waiters();
    }
}

async fn lock_idle<'a>(
    store: &'a Arc<tokio::sync::Mutex<super::LockStore>>,
    changed: &Arc<tokio::sync::Notify>,
) -> tokio::sync::MutexGuard<'a, super::LockStore> {
    loop {
        let notified = changed.notified();
        let guard = store.lock().await;
        if guard.transition.is_none() {
            return guard;
        }
        drop(guard);
        notified.await;
    }
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
