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

use std::sync::Arc;

use cda_interfaces::lock_priority_api::{LockLifecycleEvent, LockPriorityPolicy};
use futures::FutureExt;
use tokio::{sync::mpsc, task};

use super::Locks;

pub(super) struct LifecycleDelivery {
    policy: Arc<dyn LockPriorityPolicy>,
    event: LockLifecycleEvent,
}
impl Locks {
    pub(super) async fn ensure_lifecycle_worker(&self) {
        if let Some(receiver) = self.lifecycle_receiver.lock().await.take() {
            spawn_lifecycle_worker(
                receiver,
                std::time::Duration::from_millis(self.config.priority_lifecycle_timeout_ms),
            );
        }
    }

    /// Queues a committed lifecycle event without blocking lock processing.
    pub(super) fn notify_lock_event(
        &self,
        policy: Arc<dyn LockPriorityPolicy>,
        event: LockLifecycleEvent,
    ) {
        if let Err(error) = self
            .lifecycle_sender
            .try_send(LifecycleDelivery { policy, event })
        {
            tracing::warn!(%error, "Dropping lock lifecycle event because delivery queue is full or closed");
        }
    }
}
pub(super) fn spawn_lifecycle_worker(
    mut receiver: mpsc::Receiver<LifecycleDelivery>,
    timeout: std::time::Duration,
) {
    task::spawn(async move {
        while let Some(delivery) = receiver.recv().await {
            deliver_lock_event(&delivery.policy, delivery.event, timeout).await;
        }
    });
}

pub(super) fn enqueue_lock_event(
    sender: &mpsc::Sender<LifecycleDelivery>,
    policy: Arc<dyn LockPriorityPolicy>,
    event: LockLifecycleEvent,
) {
    if let Err(error) = sender.try_send(LifecycleDelivery { policy, event }) {
        tracing::warn!(%error, "Dropping lock lifecycle event because delivery queue is full or closed");
    }
}

/// Best-effort bounded delivery of a committed lock lifecycle event.
async fn deliver_lock_event(
    policy: &Arc<dyn LockPriorityPolicy>,
    event: LockLifecycleEvent,
    timeout: std::time::Duration,
) {
    match tokio::time::timeout(
        timeout,
        std::panic::AssertUnwindSafe(policy.on_lock_event(&event)).catch_unwind(),
    )
    .await
    {
        Err(_) => tracing::warn!(?event, "Lock priority policy on_lock_event timed out"),
        Ok(Err(_)) => tracing::error!(?event, "Lock priority policy on_lock_event panicked"),
        Ok(Ok(())) => {}
    }
}
