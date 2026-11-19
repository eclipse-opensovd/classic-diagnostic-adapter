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

//! Tests for a disable waiting for in-flight requests, and for preemptible
//! guards that never block it.

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use cda_interfaces::communication_control::{
    CommunicationError, CommunicationLifecycle, CommunicationState, CommunicationVariantDetection,
    DetectionPhase, PreemptibleCommunicationGuard, TransportControl, TransportState,
    error::CommControlError,
};
use tokio::sync::Notify;

use super::{CommunicationHandle, test_utils::communication_handle_new};
use crate::lifecycle::disable::{DisableError, DisableLease, DisableReason};

const DRAIN_TIMEOUT: Duration = Duration::from_millis(5000);

#[derive(Default)]
struct CountingControl {
    disable_count: AtomicUsize,
}

#[async_trait]
impl TransportControl for CountingControl {
    async fn enable(&self) -> Result<(), CommControlError> {
        Ok(())
    }
    async fn disable(&self) -> Result<(), CommControlError> {
        self.disable_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    async fn state(&self) -> TransportState {
        TransportState::Disabled
    }
}

/// An enabled handle that waits `DRAIN_TIMEOUT` for in-flight requests.
async fn enabled_handle() -> (CommunicationHandle, Arc<CountingControl>) {
    let control = Arc::new(CountingControl::default());
    let handle = communication_handle_new(Arc::clone(&control) as Arc<dyn TransportControl>);
    handle.set_disable_drain_timeout(DRAIN_TIMEOUT);
    assert_eq!(handle.enable().await, Ok(CommunicationState::Enabled));
    (handle, control)
}

fn spawn_disable(
    handle: &CommunicationHandle,
) -> tokio::task::JoinHandle<Result<DisableLease, DisableError>> {
    let handle = handle.clone();
    tokio::spawn(async move { handle.disable(DisableReason::RuntimeUpdate).await })
}

/// Yields until the disable has claimed the state and is waiting.
async fn wait_until_disabling(handle: &CommunicationHandle) {
    for _ in 0..1000 {
        if handle.state() == CommunicationState::Disabling {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("disable never started waiting, state {:?}", handle.state());
}

/// Lifecycle hook that drops the preemptible guard it is given when
/// deinitialized, the way `suspend_tester_present` aborts the tester present
/// loop.
#[derive(Default)]
struct PreemptingHook {
    guard: Mutex<Option<PreemptibleCommunicationGuard>>,
    deinitialized: AtomicUsize,
}

#[async_trait]
impl CommunicationLifecycle for PreemptingHook {
    fn name(&self) -> &'static str {
        "preempting-hook"
    }
    async fn initialize(&self) -> Result<(), CommControlError> {
        Ok(())
    }
    async fn on_enabled(&self) {}
    async fn deinitialize(&self) {
        self.deinitialized.fetch_add(1, Ordering::Relaxed);
        drop(self.guard.lock().expect("hook mutex poisoned").take());
    }
}

struct BlockingDetector {
    entered: Notify,
    proceed: Notify,
}

#[async_trait]
impl CommunicationVariantDetection for BlockingDetector {
    fn name(&self) -> &'static str {
        "blocking-detector"
    }
    async fn detect(&self, _phase: DetectionPhase) -> Result<(), CommControlError> {
        self.entered.notify_one();
        self.proceed.notified().await;
        Ok(())
    }
}

/// A short request in flight makes the disable wait, not fail.
///
/// [[ test~communication-disable-drain-success, Disable waits for a short request, test ]]
#[tokio::test(start_paused = true)]
async fn disable_waits_for_a_short_request_and_succeeds() {
    let (handle, control) = enabled_handle().await;
    let guard = handle.acquire().expect("enabled admits requests");

    let disable = spawn_disable(&handle);
    wait_until_disabling(&handle).await;
    assert_eq!(control.disable_count.load(Ordering::Relaxed), 0);

    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(100)).await;
    drop(guard);

    let lease = disable
        .await
        .expect("disable task")
        .expect("disable succeeds once the request finished");
    assert_eq!(handle.state(), CommunicationState::DisabledExclusive);
    assert_eq!(control.disable_count.load(Ordering::Relaxed), 1);
    assert_eq!(lease.release().await, Ok(CommunicationState::Enabled));
}

/// A request outliving the wait refuses the disable with details, and leaves
/// communication enabled and usable.
///
/// [[ test~communication-disable-drain-timeout, Disable wait timeout restores Enabled, test ]]
#[tokio::test(start_paused = true)]
async fn disable_times_out_and_restores_enabled() {
    let (handle, control) = enabled_handle().await;
    let guard = handle.acquire().expect("enabled admits requests");
    let started = tokio::time::Instant::now();

    let result = handle.disable(DisableReason::RuntimeUpdate).await;

    let Err(DisableError::InUse(in_use)) = result else {
        panic!("expected InUse, got {result:?}");
    };
    assert_eq!(in_use.requests_in_flight, 1);
    assert!(!in_use.detection_in_flight);
    assert!(in_use.waited >= DRAIN_TIMEOUT);
    assert!(started.elapsed() >= DRAIN_TIMEOUT);
    assert!(
        in_use.to_string().contains("1 request(s) in flight"),
        "message: {in_use}"
    );
    assert_eq!(handle.state(), CommunicationState::Enabled);
    assert_eq!(control.disable_count.load(Ordering::Relaxed), 0);
    assert!(handle.acquire().is_ok(), "requests are admitted again");
    drop(guard);
}

/// While the disable waits, new requests are refused, but preemptible work is
/// still admitted.
///
/// [[ test~communication-disable-drain-admission, Guard admission while a disable waits, test ]]
#[tokio::test(start_paused = true)]
async fn waiting_disable_refuses_requests_but_admits_preemptible_work() {
    let (handle, _control) = enabled_handle().await;
    let guard = handle.acquire().expect("enabled admits requests");

    let disable = spawn_disable(&handle);
    wait_until_disabling(&handle).await;

    assert!(matches!(
        handle.acquire(),
        Err(CommunicationError::Disabling)
    ));
    let preemptible = handle
        .acquire_preemptible()
        .expect("preemptible work keeps running while the disable waits");
    drop(preemptible);

    drop(guard);
    drop(
        disable
            .await
            .expect("disable task")
            .expect("disable succeeds"),
    );
}

/// A detection finishing within the wait lets the disable proceed. One that
/// does not is reported.
///
/// [[ test~communication-disable-drain-detection, Disable waits for variant detection, test ]]
#[tokio::test(start_paused = true)]
async fn disable_waits_for_detection() {
    let (handle, _control) = enabled_handle().await;
    let detector = Arc::new(BlockingDetector {
        entered: Notify::new(),
        proceed: Notify::new(),
    });
    handle
        .register_variant_detection(Arc::clone(&detector) as Arc<dyn CommunicationVariantDetection>)
        .await
        .expect("registration");

    // Not finishing in time.
    let sweep = tokio::spawn({
        let handle = handle.clone();
        async move { handle.redetect().await }
    });
    detector.entered.notified().await;
    let result = handle.disable(DisableReason::RuntimeUpdate).await;
    let Err(DisableError::InUse(in_use)) = result else {
        panic!("expected InUse, got {result:?}");
    };
    assert!(in_use.detection_in_flight);
    assert!(in_use.to_string().contains("variant detection running"));
    assert_eq!(handle.state(), CommunicationState::Enabled);
    detector.proceed.notify_one();
    assert_eq!(
        sweep.await.expect("sweep task"),
        Ok(CommunicationState::Enabled)
    );

    // Finishing in time.
    let sweep = tokio::spawn({
        let handle = handle.clone();
        async move { handle.redetect().await }
    });
    detector.entered.notified().await;
    let disable = spawn_disable(&handle);
    wait_until_disabling(&handle).await;
    detector.proceed.notify_one();
    assert_eq!(
        sweep.await.expect("sweep task"),
        Ok(CommunicationState::Enabled)
    );
    let lease = disable
        .await
        .expect("disable task")
        .expect("disable succeeds");
    assert_eq!(handle.state(), CommunicationState::DisabledExclusive);
    // Dropped rather than released: a resume would re-enter the blocking
    // detector with nobody left to unblock it.
    drop(lease);
}

/// Abandoning the `disable()` call must not leave communication stuck in
/// `Disabling`.
///
/// [[ test~communication-disable-drain-abandoned, Abandoned disable does not leave the state stuck, test ]]
#[tokio::test(start_paused = true)]
async fn abandoned_disable_never_leaves_the_state_stuck() {
    let (handle, _control) = enabled_handle().await;
    let guard = handle.acquire().expect("enabled admits requests");

    let disable = spawn_disable(&handle);
    wait_until_disabling(&handle).await;
    disable.abort();
    let _ = disable.await;

    // The detached disable task still times out and rolls back.
    cda_interfaces::util::tokio_ext::sleep_for(DRAIN_TIMEOUT + Duration::from_millis(1)).await;
    assert_eq!(handle.state(), CommunicationState::Enabled);
    drop(guard);
}

/// Shutdown during the wait ends it with `ShuttingDown`.
///
/// [[ test~communication-disable-drain-shutdown, Shutdown ends a waiting disable, test ]]
#[tokio::test(start_paused = true)]
async fn shutdown_ends_a_waiting_disable() {
    let (handle, _control) = enabled_handle().await;
    let guard = handle.acquire().expect("enabled admits requests");

    let disable = spawn_disable(&handle);
    wait_until_disabling(&handle).await;
    handle.shutdown().await;

    let result = disable.await.expect("disable task");
    assert!(
        matches!(
            result,
            Err(DisableError::Failed(
                cda_interfaces::communication_control::CommunicationOperationFailure::ShuttingDown { .. }
            ))
        ),
        "got {result:?}"
    );
    assert_ne!(handle.state(), CommunicationState::Disabling);
    drop(guard);
}

/// A zero timeout keeps refusing immediately while a request is in flight.
///
/// [[ test~communication-disable-drain-zero-timeout, Zero drain timeout refuses immediately, test ]]
#[tokio::test(start_paused = true)]
async fn zero_timeout_refuses_immediately() {
    let (handle, _control) = enabled_handle().await;
    handle.set_disable_drain_timeout(Duration::ZERO);
    let guard = handle.acquire().expect("enabled admits requests");
    let started = tokio::time::Instant::now();

    assert!(matches!(
        handle.disable(DisableReason::RuntimeUpdate).await,
        Err(DisableError::InUse(_))
    ));
    assert_eq!(started.elapsed(), Duration::ZERO);
    assert_eq!(handle.state(), CommunicationState::Enabled);
    drop(guard);
}

/// A preemptible guard neither blocks the disable (even with a zero timeout)
/// nor a detection. Deinitialization releases it, and once the disable
/// proceeds, no new one is admitted.
///
/// [[ test~communication-preemptible-guard-never-blocks, Preemptible guard never blocks disable or detection, test ]]
#[tokio::test(start_paused = true)]
async fn preemptible_guard_never_blocks_and_is_released_by_deinitialize() {
    let (handle, control) = enabled_handle().await;
    handle.set_disable_drain_timeout(Duration::ZERO);
    let hook = Arc::new(PreemptingHook::default());
    handle
        .register_lifecycle_hook(Arc::clone(&hook) as Arc<dyn CommunicationLifecycle>)
        .await
        .expect("registration");
    // Hooks registered after enable are only initialized on the next enable,
    // but they are deinitialized on every disable.
    *hook.guard.lock().expect("hook mutex") = Some(
        handle
            .acquire_preemptible()
            .expect("enabled admits preemptible work"),
    );

    assert_eq!(
        handle.redetect().await,
        Ok(CommunicationState::Enabled),
        "a preemptible guard must not refuse a detection"
    );

    let lease = handle
        .disable(DisableReason::RuntimeUpdate)
        .await
        .expect("a preemptible guard must not block the disable");
    assert_eq!(hook.deinitialized.load(Ordering::Relaxed), 1);
    assert!(hook.guard.lock().expect("hook mutex").is_none());
    assert_eq!(control.disable_count.load(Ordering::Relaxed), 1);
    assert!(matches!(
        handle.acquire_preemptible(),
        Err(CommunicationError::DisabledExclusive)
    ));

    assert_eq!(lease.release().await, Ok(CommunicationState::Enabled));
    assert!(
        handle.acquire_preemptible().is_ok(),
        "preemptible work is admitted again after the lease is released"
    );
}
