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

//! Handle for the gateway's cancellable background tasks (keep-alive
//! broadcast, rediscovery).

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// A running background task of the gateway.
///
/// Call [`Self::shutdown`] to stop the task and wait for its termination.
/// Dropping the handle without a shutdown aborts the task as a last resort,
/// without waiting for it to finish.
pub(crate) struct BackgroundTask {
    cancel: CancellationToken,
    task: std::sync::Mutex<Option<JoinHandle<()>>>,
}

impl BackgroundTask {
    /// Wraps a spawned task with the token that cancels it.
    pub(crate) fn new(cancel: CancellationToken, task: JoinHandle<()>) -> Self {
        Self {
            cancel,
            task: std::sync::Mutex::new(Some(task)),
        }
    }

    /// Stops the task and waits until it has terminated. Idempotent.
    pub(crate) async fn shutdown(&self) {
        self.cancel.cancel();
        let task = self.task.lock().map_or(None, |mut guard| guard.take());
        if let Some(task) = task {
            let _ = task.await;
        }
    }
}

impl Drop for BackgroundTask {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Ok(mut guard) = self.task.lock()
            && let Some(task) = guard.take()
        {
            task.abort();
        }
    }
}
