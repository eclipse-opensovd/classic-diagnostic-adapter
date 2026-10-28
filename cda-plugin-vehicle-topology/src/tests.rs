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

use std::sync::{
    Mutex as StdMutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use cda_interfaces::{
    communication_control::{
        CommunicationOperationFailure, CommunicationState,
        disable::DisableGuard,
        quiesce::{QuiesceCommunication, QuiesceGuard},
    },
    topology::{TopologyClearError, TopologyStoreError},
};

use super::*;

#[derive(Debug, Default)]
struct Calls {
    log: StdMutex<Vec<&'static str>>,
}

impl Calls {
    fn push(&self, call: &'static str) {
        self.log.lock().unwrap().push(call);
    }

    fn get(&self) -> Vec<&'static str> {
        self.log.lock().unwrap().clone()
    }
}

struct FakeBackend {
    calls: Arc<Calls>,
    /// Released by the test to let the rediscovery settle.
    settle: Arc<tokio::sync::Notify>,
    panic_on_clear: bool,
    /// When set, clearing blocks until the test notifies it. Clearing is not
    /// cancellable, so this models a step that must finish after a DELETE.
    hold_clear: Option<Arc<tokio::sync::Notify>>,
    /// When set, the rediscovery settles, but persisting its result failed.
    persist_failure: Arc<std::sync::Mutex<Option<String>>>,
    /// The settle budget the backend applies, like the persistence does.
    settle_budget: Duration,
    /// When set, clearing fails.
    fail_clear: Arc<AtomicBool>,
}

#[async_trait]
impl TopologyResetBackend for FakeBackend {
    async fn clear_persisted(&self) -> Result<(), TopologyClearError> {
        self.calls.push("clear");
        assert!(!self.panic_on_clear, "clear_persisted failed hard");
        if let Some(hold) = &self.hold_clear {
            hold.notified().await;
        }
        if self.fail_clear.load(Ordering::Relaxed) {
            return Err(TopologyStoreError::Serialization("disk full".to_owned()).into());
        }
        Ok(())
    }

    async fn prepare_rediscovery(&self) -> u64 {
        self.calls.push("prepare");
        7
    }

    async fn wait_rediscovered(&self, marker: u64) -> RediscoveryWait {
        assert_eq!(marker, 7);
        if tokio::time::timeout(self.settle_budget, self.settle.notified())
            .await
            .is_err()
        {
            return RediscoveryWait::TimedOut;
        }
        match self.persist_failure.lock().unwrap().clone() {
            Some(error) => RediscoveryWait::PersistFailed(error),
            None => RediscoveryWait::Settled,
        }
    }
}

struct FakeRediscovery {
    calls: Arc<Calls>,
    /// When set, the rediscovery blocks until the test notifies it.
    hold: Option<Arc<tokio::sync::Notify>>,
    /// When set, the rediscovery fails with this error.
    fail_with: Option<String>,
}

#[async_trait]
impl TopologyRediscovery for FakeRediscovery {
    async fn rediscover(&self) -> Result<(), String> {
        self.calls.push("rediscover");
        if let Some(hold) = &self.hold {
            hold.notified().await;
        }
        self.fail_with.clone().map_or(Ok(()), Err)
    }
}

#[derive(Debug)]
struct FakeGuard(Arc<Calls>);

#[async_trait]
impl DisableGuard for FakeGuard {
    async fn release(self: Box<Self>) -> Result<CommunicationState, CommunicationOperationFailure> {
        self.0.push("release");
        Ok(CommunicationState::Enabled)
    }

    async fn finish(self: Box<Self>) -> Result<(), CommunicationOperationFailure> {
        self.0.push("finish");
        Ok(())
    }
}

struct FakeDisable {
    calls: Arc<Calls>,
    in_use: AtomicBool,
}

#[async_trait]
impl DisableCommunication for FakeDisable {
    async fn disable(&self, _reason: DisableReason) -> Result<Box<dyn DisableGuard>, DisableError> {
        if self.in_use.load(Ordering::Relaxed) {
            return Err(DisableError::InUse);
        }
        self.calls.push("disable");
        Ok(Box::new(FakeGuard(Arc::clone(&self.calls))))
    }
}

#[derive(Debug)]
struct FakeQuiesceGuard(Arc<Calls>);

impl QuiesceGuard for FakeQuiesceGuard {}

impl Drop for FakeQuiesceGuard {
    fn drop(&mut self) {
        self.0.push("unquiesce");
    }
}

struct FakeQuiesce {
    calls: Arc<Calls>,
    in_use: bool,
}

#[async_trait]
impl QuiesceCommunication for FakeQuiesce {
    async fn quiesce(&self, _reason: DisableReason) -> Result<Box<dyn QuiesceGuard>, DisableError> {
        if self.in_use {
            return Err(DisableError::InUse);
        }
        self.calls.push("quiesce");
        Ok(Box::new(FakeQuiesceGuard(Arc::clone(&self.calls))))
    }
}

struct FakeLocks(AtomicUsize);

#[async_trait]
impl LockStateProvider for FakeLocks {
    async fn vehicle_lock_owner_sub(&self) -> Option<String> {
        Some("tester".to_owned())
    }

    async fn has_non_vehicle_locks(&self) -> bool {
        self.0.load(Ordering::Relaxed) > 0
    }
}

struct Fixture {
    plugin: DefaultVehicleTopologyPlugin,
    calls: Arc<Calls>,
    settle: Arc<tokio::sync::Notify>,
    protections: HttpProtectionRegistry,
    /// Releases a held rediscovery.
    hold: Arc<tokio::sync::Notify>,
    /// Makes persisting the rediscovered topology fail with this error.
    persist_failure: Arc<std::sync::Mutex<Option<String>>>,
    /// Makes clearing fail.
    fail_clear: Arc<AtomicBool>,
}

fn fixture(in_use: bool, component_locks: usize) -> Fixture {
    fixture_with(in_use, component_locks, false)
}

/// Holds the (not cancellable) clearing step.
fn held_fixture() -> Fixture {
    build_fixture(false, 0, false, Hold::Clear, None)
}

/// Holds the rediscovery, which DELETE and the deadline interrupt.
fn hanging_fixture() -> Fixture {
    build_fixture(false, 0, false, Hold::Rediscovery, None)
}

#[derive(Clone, Copy, PartialEq)]
enum Hold {
    Nothing,
    Clear,
    Rediscovery,
}

fn fixture_with(in_use: bool, component_locks: usize, panic_on_clear: bool) -> Fixture {
    build_fixture(in_use, component_locks, panic_on_clear, Hold::Nothing, None)
}

fn build_fixture(
    in_use: bool,
    component_locks: usize,
    panic_on_clear: bool,
    hold_at: Hold,
    fail_with: Option<String>,
) -> Fixture {
    let calls = Arc::new(Calls::default());
    let settle = Arc::new(tokio::sync::Notify::new());
    let protections = HttpProtectionRegistry::new();
    let hold = Arc::new(tokio::sync::Notify::new());
    let persist_failure = Arc::new(std::sync::Mutex::new(None));
    let fail_clear = Arc::new(AtomicBool::new(false));
    let plugin = DefaultVehicleTopologyPlugin::new(VehicleTopologyDeps {
        backend: Arc::new(FakeBackend {
            calls: Arc::clone(&calls),
            settle: Arc::clone(&settle),
            panic_on_clear,
            hold_clear: (hold_at == Hold::Clear).then(|| Arc::clone(&hold)),
            persist_failure: Arc::clone(&persist_failure),
            settle_budget: Duration::from_secs(30),
            fail_clear: Arc::clone(&fail_clear),
        }),
        rediscovery: Arc::new(FakeRediscovery {
            calls: Arc::clone(&calls),
            hold: (hold_at == Hold::Rediscovery).then(|| Arc::clone(&hold)),
            fail_with,
        }),
        communication_disable: Arc::new(FakeDisable {
            calls: Arc::clone(&calls),
            in_use: AtomicBool::new(in_use),
        }),
        communication_quiesce: Arc::new(FakeQuiesce {
            calls: Arc::clone(&calls),
            in_use,
        }),
        locks: Arc::new(FakeLocks(AtomicUsize::new(component_locks))),
        http_protections: protections.clone(),
        rediscovery_timeout: Duration::from_secs(5),
    });
    Fixture {
        plugin,
        calls,
        settle,
        protections,
        hold,
        persist_failure,
        fail_clear,
    }
}

fn flags(clear_persisted: bool, trigger_detection: bool) -> NetworkResetFlags {
    NetworkResetFlags {
        clear_persisted,
        trigger_detection,
    }
}

async fn wait_finished(plugin: &DefaultVehicleTopologyPlugin, id: &str) -> NetworkResetStatus {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let status = plugin.get_reset(id).await.unwrap().status;
            if status != NetworkResetStatus::Running {
                return status;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("execution did not finish")
}

fn network_structure_blocked(protections: &HttpProtectionRegistry) -> bool {
    use cda_interfaces::http_protection::registry::HttpRestrictionGuard as _;
    protections
        .evaluate(NETWORK_STRUCTURE_ROUTE, &HttpMethod::GET)
        .is_err()
}

/// [[ test~plugin-vehicle-topology-reset-clear-and-detect-runs-one-rediscovery-and-blocks-network-structure, A detection run finishes the lease without resuming and brings communication up once, test ]]
#[tokio::test]
async fn clear_and_detect_runs_one_rediscovery_and_blocks_network_structure() {
    let fixture = fixture(false, 0);
    let id = fixture.plugin.start_reset(flags(true, true)).await.unwrap();
    assert!(network_structure_blocked(&fixture.protections));
    let running = fixture.plugin.get_reset(&id).await.unwrap();
    assert_eq!(running.status, NetworkResetStatus::Running);
    assert_eq!(fixture.plugin.list_resets().await.len(), 1);
    assert!(matches!(
        fixture.plugin.start_reset(flags(true, true)).await,
        Err(NetworkResetError::ExecutionConflict)
    ));

    tokio::time::timeout(Duration::from_secs(5), async {
        while !fixture.calls.get().contains(&"rediscover") {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    fixture.settle.notify_one();
    assert_eq!(
        wait_finished(&fixture.plugin, &id).await,
        NetworkResetStatus::Completed
    );
    // The lease is finished, not released: only the rediscovery brings
    // communication back up.
    assert_eq!(
        fixture.calls.get(),
        vec!["disable", "clear", "prepare", "finish", "rediscover"]
    );
    assert!(!network_structure_blocked(&fixture.protections));
    assert_eq!(fixture.plugin.list_resets().await.len(), 1);
}

/// [[ test~plugin-vehicle-topology-reset-failed-persisting-of-the-rediscovered-topology-is-reported, A failed write of the rediscovered topology fails the execution, test ]]
#[tokio::test]
async fn failed_persisting_of_the_rediscovered_topology_is_reported() {
    let fixture = fixture(false, 0);
    *fixture.persist_failure.lock().unwrap() = Some("disk full".to_owned());
    let id = fixture
        .plugin
        .start_reset(flags(false, true))
        .await
        .unwrap();
    wait_for_call(&fixture.calls, "rediscover").await;
    fixture.settle.notify_one();
    assert_eq!(
        wait_finished(&fixture.plugin, &id).await,
        NetworkResetStatus::Failed(
            "Persisting the rediscovered topology failed: disk full".to_owned()
        )
    );
}

/// [[ test~plugin-vehicle-topology-reset-failed-clear-gives-the-lease-back, A failed clear gives the communication lease back and fails the execution, test ]]
#[tokio::test]
async fn failed_clear_gives_the_lease_back() {
    for (trigger_detection, expected) in [
        (true, vec!["disable", "clear", "release"]),
        (false, vec!["quiesce", "clear", "unquiesce"]),
    ] {
        let fixture = fixture(false, 0);
        fixture.fail_clear.store(true, Ordering::Relaxed);
        let id = fixture
            .plugin
            .start_reset(flags(true, trigger_detection))
            .await
            .unwrap();
        assert!(
            matches!(
                wait_finished(&fixture.plugin, &id).await,
                NetworkResetStatus::Failed(_)
            ),
            "trigger_detection={trigger_detection}"
        );
        assert_eq!(
            fixture.calls.get(),
            expected,
            "trigger_detection={trigger_detection}"
        );
    }
}

/// [[ test~plugin-vehicle-topology-reset-diagnostics-in-progress-reject-the-reset, Diagnostic operations using communication reject the reset, test ]]
#[tokio::test]
async fn diagnostics_in_progress_reject_the_reset() {
    let fixture = fixture(true, 0);
    assert!(matches!(
        fixture.plugin.start_reset(flags(true, true)).await,
        Err(NetworkResetError::OperationsInProgress(_))
    ));
    assert!(!network_structure_blocked(&fixture.protections));

    let fixture = self::fixture(false, 1);
    assert!(matches!(
        fixture.plugin.start_reset(flags(true, false)).await,
        Err(NetworkResetError::OperationsInProgress(_))
    ));
}

async fn wait_for_call(calls: &Calls, call: &'static str) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !calls.get().contains(&call) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("step was not reached");
}

/// [[ test~plugin-vehicle-topology-reset-single-execution, networkreset keeps one execution until the task finished, test ]]
#[tokio::test]
async fn second_delete_waits_for_the_running_task() {
    let fixture = held_fixture();
    let id = fixture.plugin.start_reset(flags(true, true)).await.unwrap();
    wait_for_call(&fixture.calls, "clear").await;

    let mut deletes = Box::pin(async {
        tokio::join!(
            fixture.plugin.delete_reset(&id),
            fixture.plugin.delete_reset(&id)
        )
    });
    // Neither delete returns while the task is held.
    assert!(
        tokio::time::timeout(Duration::from_millis(200), &mut deletes)
            .await
            .is_err()
    );
    assert_eq!(fixture.plugin.list_resets().await.len(), 1);
    assert!(network_structure_blocked(&fixture.protections));

    fixture.hold.notify_one();
    let both = tokio::time::timeout(Duration::from_secs(5), deletes)
        .await
        .expect("deletes did not finish");
    assert_eq!(both, (true, true));
    assert!(fixture.plugin.list_resets().await.is_empty());
    assert!(!network_structure_blocked(&fixture.protections));
    // The next execution clears (and so holds) as well.
    fixture.hold.notify_one();
    let id = fixture
        .plugin
        .start_reset(flags(true, false))
        .await
        .unwrap();
    assert_eq!(
        wait_finished(&fixture.plugin, &id).await,
        NetworkResetStatus::Completed
    );
}

/// [[ test~plugin-vehicle-topology-reset-dropped-delete-still-removes-the-execution, The execution is removed by its own task also when the DELETE is dropped, test ]]
#[tokio::test]
async fn dropped_delete_still_removes_the_execution() {
    let fixture = held_fixture();
    let id = fixture.plugin.start_reset(flags(true, true)).await.unwrap();
    wait_for_call(&fixture.calls, "clear").await;

    {
        let mut delete = Box::pin(fixture.plugin.delete_reset(&id));
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut delete)
                .await
                .is_err()
        );
    }
    assert!(matches!(
        fixture.plugin.start_reset(flags(true, false)).await,
        Err(NetworkResetError::ExecutionConflict)
    ));
    assert_eq!(fixture.plugin.list_resets().await.len(), 1);

    fixture.hold.notify_one();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !fixture.plugin.list_resets().await.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("execution was not removed");
    assert!(!network_structure_blocked(&fixture.protections));
}

/// [[ test~plugin-vehicle-topology-reset-panicking-reset-reports-failed, A panic inside the execution is reported as a failed execution, test ]]
#[tokio::test]
async fn panicking_reset_reports_failed() {
    let fixture = fixture_with(false, 0, true);
    let id = fixture
        .plugin
        .start_reset(flags(true, false))
        .await
        .unwrap();
    assert_eq!(
        wait_finished(&fixture.plugin, &id).await,
        NetworkResetStatus::Failed("internal error".to_owned())
    );
    assert!(!network_structure_blocked(&fixture.protections));
    assert_eq!(fixture.calls.get(), vec!["quiesce", "clear", "unquiesce"]);
    let next = self::fixture(false, 0);
    assert!(next.plugin.start_reset(flags(true, false)).await.is_ok());
    // Same plugin: a finished execution may be replaced.
    assert!(fixture.plugin.start_reset(flags(true, false)).await.is_ok());
}

/// [[ test~plugin-vehicle-topology-reset-deadline, networkreset bounds and cancels the rediscovery and reports a failed bring-up, test ]]
#[tokio::test(start_paused = true)]
async fn hanging_rediscover_fails_after_deadline() {
    let fixture = hanging_fixture();
    let id = fixture.plugin.start_reset(flags(true, true)).await.unwrap();
    wait_for_call(&fixture.calls, "rediscover").await;
    assert_eq!(
        fixture.plugin.get_reset(&id).await.unwrap().status,
        NetworkResetStatus::Running
    );
    tokio::time::advance(Duration::from_secs(6)).await;
    assert_eq!(
        wait_finished(&fixture.plugin, &id).await,
        NetworkResetStatus::Failed("Rediscovery did not complete within 5s".to_owned())
    );
    assert!(!network_structure_blocked(&fixture.protections));
}

/// [[ test~plugin-vehicle-topology-reset-delete-interrupts-hanging-rediscover, A DELETE interrupts a hanging rediscovery, test ]]
#[tokio::test(start_paused = true)]
async fn delete_interrupts_hanging_rediscover() {
    let fixture = hanging_fixture();
    let id = fixture.plugin.start_reset(flags(true, true)).await.unwrap();
    wait_for_call(&fixture.calls, "rediscover").await;
    assert!(fixture.plugin.delete_reset(&id).await);
    assert!(fixture.plugin.list_resets().await.is_empty());
    assert!(!network_structure_blocked(&fixture.protections));
    assert!(!fixture.calls.get().contains(&"release"));
}

/// [[ test~plugin-vehicle-topology-reset-failed-rediscover-reports-disabled-communication, A failed rediscovery after the lease was finished reports that communication stays disabled, test ]]
#[tokio::test]
async fn failed_rediscover_reports_disabled_communication() {
    let fixture = build_fixture(
        false,
        0,
        false,
        Hold::Nothing,
        Some("transport down".to_owned()),
    );
    let id = fixture.plugin.start_reset(flags(true, true)).await.unwrap();
    let NetworkResetStatus::Failed(message) = wait_finished(&fixture.plugin, &id).await else {
        panic!("expected a failed execution");
    };
    assert!(
        message.contains("Communication stays disabled"),
        "{message}"
    );
    assert!(message.contains("transport down"), "{message}");
}

/// [[ test~plugin-vehicle-topology-reset-delete-during-clear, A DELETE during the clear gives communication back once the clear finished, test ]]
#[tokio::test]
async fn delete_during_the_clear_gives_communication_back() {
    let fixture = held_fixture();
    let id = fixture.plugin.start_reset(flags(true, true)).await.unwrap();
    wait_for_call(&fixture.calls, "clear").await;
    let delete = fixture.plugin.delete_reset(&id);
    tokio::pin!(delete);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut delete)
            .await
            .is_err()
    );
    fixture.hold.notify_one();
    assert!(delete.await);

    assert_eq!(
        fixture.calls.get(),
        vec!["disable", "clear", "prepare", "release"]
    );
    assert!(!network_structure_blocked(&fixture.protections));
}

/// [[ test~plugin-vehicle-topology-reset-deadline-before-finish, An expired bring-up deadline releases the lease and fails the reset, test ]]
#[tokio::test(start_paused = true)]
async fn expired_deadline_before_finish_releases_the_lease() {
    let mut fixture = fixture(false, 0);
    Arc::get_mut(&mut fixture.plugin.deps)
        .expect("the plugin owns its deps")
        .rediscovery_timeout = Duration::ZERO;
    let id = fixture
        .plugin
        .start_reset(flags(false, true))
        .await
        .unwrap();

    assert_eq!(
        wait_finished(&fixture.plugin, &id).await,
        NetworkResetStatus::Failed("Rediscovery did not complete within 0ns".to_owned())
    );
    assert_eq!(fixture.calls.get(), vec!["disable", "prepare", "release"]);
}

/// [[ test~plugin-vehicle-topology-reset-verdict-from-persistence, The settling is bounded by the persistence verdict and not by the bring-up budget, test ]]
#[tokio::test(start_paused = true)]
async fn slow_settling_inside_the_persistence_budget_completes() {
    let fixture = hanging_fixture();
    let id = fixture
        .plugin
        .start_reset(flags(false, true))
        .await
        .unwrap();
    wait_for_call(&fixture.calls, "rediscover").await;
    // Most of the bring-up budget (5s) is used up.
    tokio::time::advance(Duration::from_secs(4)).await;
    fixture.hold.notify_one();
    // Settling takes longer than the bring-up budget, inside the settle budget (30s).
    tokio::time::advance(Duration::from_secs(10)).await;
    fixture.settle.notify_one();

    assert_eq!(
        wait_finished(&fixture.plugin, &id).await,
        NetworkResetStatus::Completed
    );
}

/// [[ test~plugin-vehicle-topology-reset-persist-timeout, A rediscovery the persistence reports as timed out fails the reset, test ]]
#[tokio::test(start_paused = true)]
async fn persistence_timeout_fails_the_reset() {
    let fixture = fixture(false, 0);
    let id = fixture
        .plugin
        .start_reset(flags(false, true))
        .await
        .unwrap();
    wait_for_call(&fixture.calls, "rediscover").await;
    // Nobody settles: the backend's budget ends the wait.
    tokio::time::advance(Duration::from_secs(31)).await;

    assert_eq!(
        wait_finished(&fixture.plugin, &id).await,
        NetworkResetStatus::Failed("Rediscovery did not settle in time".to_owned())
    );
}
