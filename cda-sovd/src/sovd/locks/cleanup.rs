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

use cda_interfaces::{
    DynamicPlugin, HashMap, ResetOutcome, UdsEcu,
    lock_priority_api::{LockId, LockLifecycleEvent},
};
use futures::FutureExt;
use tokio::time::{Instant, sleep_until};

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
        let core = self.core.clone();
        let policy = Arc::clone(&self.priority_policy);
        let lifecycle_sender = self.lifecycle_sender.clone();
        let lock_id = lock.id.clone();
        cda_interfaces::spawn_named!(&format!("lock-expiration-{lock_id}"), async move {
            let mut target = target;
            let (removed, pending_cleanups, reservation) = loop {
                sleep_until(target).await;
                let reservation = core.reserve_transition().await;
                let outcome = {
                    let mut store = reservation.write_store().await;
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
                        break (removed, cleanups, reservation);
                    }
                    Ok(None) => {
                        reservation.finish();
                        return;
                    }
                    Err(()) => reservation.finish(),
                }
            };
            let events: Vec<_> = removed
                .iter()
                .map(|lock| LockLifecycleEvent::Expired {
                    lock: active_snapshot(lock),
                })
                .collect();
            run_cleanups(pending_cleanups).await;
            reservation.finish();
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
        let core = self.core.clone();
        cda_interfaces::spawn_named!("defunct-lock-expiration", async move {
            sleep_until(target).await;
            let reservation = core.reserve_transition().await;
            let mut store = reservation.write_store().await;
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
    cleanups: &mut HashMap<LockId, LockCleanupFnHelper>,
    removed: &[ActiveLock],
) -> Vec<LockCleanupFnHelper> {
    removed
        .iter()
        .filter_map(|lock| cleanups.remove(&lock.id))
        .collect()
}

pub(super) async fn reset_ecu_session_and_security<T: UdsEcu>(
    uds: &T,
    ecu_name: &str,
    context: &str,
    security_plugin: &DynamicPlugin,
) {
    match uds.reset_ecu_session(ecu_name, security_plugin).await {
        Ok(ResetOutcome::Completed) => {
            tracing::info!("ECU session reset for ECU {ecu_name} during {context}");
        }
        Ok(ResetOutcome::Deferred) => tracing::info!(
            "ECU session reset for ECU {ecu_name} during {context} deferred until communication \
             is enabled"
        ),
        Err(e) => {
            tracing::error!("Failed to reset ECU session for ECU {ecu_name} during {context}: {e}");
        }
    }

    match uds
        .reset_ecu_security_access(ecu_name, security_plugin)
        .await
    {
        Ok(ResetOutcome::Completed) => {
            tracing::info!("ECU security access reset for ECU {ecu_name} during {context}");
        }
        Ok(ResetOutcome::Deferred) => tracing::info!(
            "ECU security access reset for ECU {ecu_name} during {context} deferred until \
             communication is enabled"
        ),
        Err(e) => tracing::error!(
            "Failed to reset ECU security access for ECU {ecu_name} during {context}: {e}"
        ),
    }
}
