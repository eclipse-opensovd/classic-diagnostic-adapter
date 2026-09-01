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

//! Admission for whole-vehicle variant detection.
//!
//! Detection runs are admitted while the manager is live and refused once it is
//! shutting down. A run holds a guard for its lifetime, so shutdown can cancel
//! the in-flight runs and then wait for them to finish before tearing down the
//! task maps they touch.

use std::sync::{Arc, Mutex as StdMutex};

use cda_interfaces::util::std_ext;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

pub(crate) struct DetectionAdmissionState {
    open: bool,
    admitted: usize,
    cancel: CancellationToken,
}

/// Manager-wide admission gate and quiescence counter for every variant-detection path.
pub(crate) struct DetectionAdmission {
    state: StdMutex<DetectionAdmissionState>,
    quiescent: Notify,
}

impl DetectionAdmission {
    pub(crate) fn new() -> Self {
        Self {
            state: StdMutex::new(DetectionAdmissionState {
                open: false,
                admitted: 0,
                cancel: CancellationToken::new(),
            }),
            quiescent: Notify::new(),
        }
    }

    pub(crate) fn admit(self: &Arc<Self>) -> Option<DetectionAdmissionGuard> {
        let mut state = std_ext::lock_mutex(&self.state);
        if !state.open || state.cancel.is_cancelled() {
            return None;
        }
        state.admitted = state.admitted.saturating_add(1);
        Some(DetectionAdmissionGuard {
            admission: Arc::clone(self),
            cancel: state.cancel.clone(),
        })
    }

    pub(crate) fn open(&self) {
        let mut state = std_ext::lock_mutex(&self.state);
        debug_assert_eq!(state.admitted, 0, "detection reopened before quiescence");
        state.cancel = CancellationToken::new();
        state.open = true;
    }

    pub(crate) fn close_and_cancel(&self) {
        let mut state = std_ext::lock_mutex(&self.state);
        state.open = false;
        state.cancel.cancel();
    }

    pub(crate) async fn wait_for_quiescence(&self) {
        loop {
            let notified = self.quiescent.notified();
            if std_ext::lock_mutex(&self.state).admitted == 0 {
                return;
            }
            notified.await;
        }
    }
}

/// Owns one admitted variant-detection operation and its associated cancellation token.
///
/// Dropping the guard releases that operation and signals quiescence once no admitted
/// detection operations remain.
pub(crate) struct DetectionAdmissionGuard {
    admission: Arc<DetectionAdmission>,
    cancel: CancellationToken,
}

impl DetectionAdmissionGuard {
    pub(crate) fn cancellation_token(&self) -> &CancellationToken {
        &self.cancel
    }
}

impl Drop for DetectionAdmissionGuard {
    fn drop(&mut self) {
        let mut state = std_ext::lock_mutex(&self.admission.state);
        debug_assert!(
            state.admitted > 0,
            "dropping an untracked detection admission"
        );
        state.admitted = state.admitted.saturating_sub(1);
        if state.admitted == 0 {
            self.admission.quiescent.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use tokio::sync::Notify;

    use super::DetectionAdmission;

    #[tokio::test]
    async fn close_cancels_and_waits_for_every_admitted_detection() {
        let admission = Arc::new(DetectionAdmission::new());
        admission.open();
        let first = admission.admit().expect("first admission");
        let second = admission.admit().expect("second admission");
        let cancel = first.cancellation_token().clone();

        admission.close_and_cancel();
        assert!(cancel.is_cancelled());
        assert!(
            admission.admit().is_none(),
            "closed gate must reject entrants"
        );

        let waiting = {
            let admission = Arc::clone(&admission);
            tokio::spawn(async move { admission.wait_for_quiescence().await })
        };
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        drop(first);
        tokio::task::yield_now().await;
        assert!(
            !waiting.is_finished(),
            "quiescence must wait for every admitted detection"
        );
        drop(second);
        waiting.await.expect("quiescence waiter");
    }

    #[tokio::test]
    async fn unwind_releases_detection_admission() {
        let admission = Arc::new(DetectionAdmission::new());
        admission.open();
        let task_admission = Arc::clone(&admission);
        let task = tokio::spawn(async move {
            let _guard = task_admission.admit().expect("task admission");
            panic!("exercise admission guard unwind");
        });
        assert!(task.await.expect_err("task must panic").is_panic());

        admission.close_and_cancel();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            admission.wait_for_quiescence(),
        )
        .await
        .expect("unwind must not leak admission ownership");
    }

    #[tokio::test]
    async fn deinitialization_quiescence_waits_for_admitted_mutation() {
        let admission = Arc::new(DetectionAdmission::new());
        admission.open();
        let guard = admission.admit().expect("mutation admission");
        let mutation_entered = Arc::new(Notify::new());
        let release_mutation = Arc::new(Notify::new());
        let mutations = Arc::new(AtomicUsize::new(0));
        let mutation = tokio::spawn({
            let mutation_entered = Arc::clone(&mutation_entered);
            let release_mutation = Arc::clone(&release_mutation);
            let mutations = Arc::clone(&mutations);
            async move {
                mutation_entered.notify_one();
                release_mutation.notified().await;
                mutations.fetch_add(1, Ordering::SeqCst);
                drop(guard);
            }
        });
        mutation_entered.notified().await;
        admission.close_and_cancel();
        let deinitialize = tokio::spawn({
            let admission = Arc::clone(&admission);
            async move { admission.wait_for_quiescence().await }
        });
        tokio::task::yield_now().await;
        assert!(!deinitialize.is_finished());

        release_mutation.notify_one();
        mutation.await.expect("mutation task");
        deinitialize.await.expect("deinitialization waiter");
        assert_eq!(mutations.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn no_send_or_mutation_can_start_after_deinitialization_quiesces() {
        let admission = Arc::new(DetectionAdmission::new());
        admission.open();
        let effects = Arc::new(AtomicUsize::new(0));

        admission.close_and_cancel();
        admission.wait_for_quiescence().await;
        for _ in 0..2 {
            if let Some(_guard) = admission.admit() {
                effects.fetch_add(1, Ordering::SeqCst);
            }
        }

        assert_eq!(effects.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn new_epoch_cannot_overlap_old_epoch() {
        let admission = Arc::new(DetectionAdmission::new());
        admission.open();
        let old = admission.admit().expect("old admission");
        let old_cancel = old.cancellation_token().clone();
        admission.close_and_cancel();
        assert!(old_cancel.is_cancelled());

        let waiting = {
            let admission = Arc::clone(&admission);
            tokio::spawn(async move { admission.wait_for_quiescence().await })
        };
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        drop(old);
        waiting.await.expect("old epoch quiescence");

        admission.open();
        let new = admission.admit().expect("new admission");
        assert!(!new.cancellation_token().is_cancelled());
    }
}
