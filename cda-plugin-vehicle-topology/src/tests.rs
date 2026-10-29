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
    atomic::{AtomicBool, Ordering},
};

use cda_interfaces::{
    communication_control::{
        CommunicationOperation, CommunicationOperationFailure, CommunicationState,
        disable::DisableGuard,
    },
    topology::{RediscoveryTicket, TopologyClearError, TopologyStoreError},
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

struct FakeNetworkReset {
    calls: Arc<Calls>,
    /// Released by the test to let the rediscovery settle.
    settle: Arc<tokio::sync::Notify>,
    panic_on_clear: bool,
    /// When set, clearing blocks until the test notifies it. Clearing is not
    /// cancellable, so this models a step that must finish after a DELETE.
    hold_clear: Option<Arc<tokio::sync::Notify>>,
    /// When set, the rediscovery settles, but persisting its result failed.
    persist_failure: Arc<std::sync::Mutex<Option<String>>>,
    /// The settle budget the network reset applies, like the persistence does.
    settle_budget: Duration,
    /// When set, clearing fails.
    fail_clear: Arc<AtomicBool>,
}

#[async_trait]
impl NetworkReset for FakeNetworkReset {
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

    async fn prepare_rediscovery(&self) -> RediscoveryTicket {
        self.calls.push("prepare");
        let settle = Arc::clone(&self.settle);
        let persist_failure = Arc::clone(&self.persist_failure);
        RediscoveryTicket::new(self.settle_budget, async move {
            settle.notified().await;
            match persist_failure.lock().unwrap().clone() {
                Some(error) => RediscoveryWait::PersistFailed(error),
                None => RediscoveryWait::Settled,
            }
        })
    }
}

#[derive(Debug)]
struct FakeGuard {
    calls: Arc<Calls>,
    /// When set, the hand-over to the rediscovery blocks until the test notifies it.
    hold_rediscovery: Option<Arc<tokio::sync::Notify>>,
    /// When set, the hand-over to the rediscovery and finishing the lease fail
    /// with this error.
    fail_rediscovery: Option<CommunicationOperationFailure>,
}

#[async_trait]
impl DisableGuard for FakeGuard {
    async fn release(self: Box<Self>) -> Result<CommunicationState, CommunicationOperationFailure> {
        self.calls.push("release");
        Ok(CommunicationState::Enabled)
    }

    async fn finish(self: Box<Self>) -> Result<(), CommunicationOperationFailure> {
        self.calls.push("finish");
        self.fail_rediscovery.clone().map_or(Ok(()), Err)
    }

    async fn release_with_detection(
        self: Box<Self>,
    ) -> Result<CommunicationState, CommunicationOperationFailure> {
        self.calls.push("rediscover");
        if let Some(hold) = &self.hold_rediscovery {
            hold.notified().await;
        }
        self.fail_rediscovery
            .clone()
            .map_or(Ok(CommunicationState::Enabled), Err)
    }
}

struct FakeDisable {
    calls: Arc<Calls>,
    in_use: AtomicBool,
    hold_rediscovery: Option<Arc<tokio::sync::Notify>>,
    fail_rediscovery: Option<CommunicationOperationFailure>,
    /// When set, granting the lease blocks until the test notifies it.
    hold_disable: Option<Arc<tokio::sync::Notify>>,
}

#[async_trait]
impl DisableCommunication for FakeDisable {
    async fn disable(&self, _reason: DisableReason) -> Result<Box<dyn DisableGuard>, DisableError> {
        if self.in_use.load(Ordering::Relaxed) {
            return Err(DisableError::InUse);
        }
        if let Some(hold) = &self.hold_disable {
            hold.notified().await;
        }
        self.calls.push("disable");
        Ok(Box::new(FakeGuard {
            calls: Arc::clone(&self.calls),
            hold_rediscovery: self.hold_rediscovery.clone(),
            fail_rediscovery: self.fail_rediscovery.clone(),
        }))
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

fn fixture(in_use: bool) -> Fixture {
    fixture_with(in_use, false)
}

/// Holds the (not cancellable) clearing step.
fn held_fixture() -> Fixture {
    build_fixture(false, false, Hold::Clear, None)
}

/// Holds the rediscovery, which DELETE and the deadline interrupt.
fn hanging_fixture() -> Fixture {
    build_fixture(false, false, Hold::Rediscovery, None)
}

#[derive(Clone, Copy, PartialEq)]
enum Hold {
    Nothing,
    Disable,
    Clear,
    Rediscovery,
}

fn fixture_with(in_use: bool, panic_on_clear: bool) -> Fixture {
    build_fixture(in_use, panic_on_clear, Hold::Nothing, None)
}

fn build_fixture(
    in_use: bool,
    panic_on_clear: bool,
    hold_at: Hold,
    fail_with: Option<CommunicationOperationFailure>,
) -> Fixture {
    let calls = Arc::new(Calls::default());
    let settle = Arc::new(tokio::sync::Notify::new());
    let protections = HttpProtectionRegistry::new();
    let hold = Arc::new(tokio::sync::Notify::new());
    let persist_failure = Arc::new(std::sync::Mutex::new(None));
    let fail_clear = Arc::new(AtomicBool::new(false));
    let plugin = DefaultVehicleTopologyPlugin::new(VehicleTopologyDeps {
        network_reset: Arc::new(FakeNetworkReset {
            calls: Arc::clone(&calls),
            settle: Arc::clone(&settle),
            panic_on_clear,
            hold_clear: (hold_at == Hold::Clear).then(|| Arc::clone(&hold)),
            persist_failure: Arc::clone(&persist_failure),
            settle_budget: Duration::from_secs(30),
            fail_clear: Arc::clone(&fail_clear),
        }),
        communication_disable: Arc::new(FakeDisable {
            calls: Arc::clone(&calls),
            in_use: AtomicBool::new(in_use),
            hold_rediscovery: (hold_at == Hold::Rediscovery).then(|| Arc::clone(&hold)),
            fail_rediscovery: fail_with,
            hold_disable: (hold_at == Hold::Disable).then(|| Arc::clone(&hold)),
        }),
        clear_resumes_transport: false,
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

#[tokio::test]
async fn builders_forward_dependencies_and_propagate_errors() {
    let fixture = fixture(false);
    let deps = Arc::try_unwrap(fixture.plugin.deps).unwrap_or_else(|_| panic!("unique deps"));
    let plugin = DefaultVehicleTopologyPluginBuilder
        .build(deps)
        .await
        .expect("default construction is infallible");
    assert_eq!(plugin.deps.rediscovery_timeout, Duration::from_secs(5));

    let deps = Arc::try_unwrap(plugin.deps).unwrap_or_else(|_| panic!("unique deps"));
    let builder = vehicle_topology_plugin_fn(|deps: VehicleTopologyDeps| async move {
        assert_eq!(deps.rediscovery_timeout, Duration::from_secs(5));
        Ok::<_, std::convert::Infallible>(DefaultVehicleTopologyPlugin::new(deps))
    });
    let plugin = builder.build(deps).await.expect("custom builder succeeds");

    let deps = Arc::try_unwrap(plugin.deps).unwrap_or_else(|_| panic!("unique deps"));
    let builder = vehicle_topology_plugin_fn(|_deps| async {
        Err::<DefaultVehicleTopologyPlugin, _>("construction failed")
    });
    let Err(error) = builder.build(deps).await else {
        panic!("custom builder failure must propagate");
    };
    assert_eq!(error, "construction failed");
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

/// [[ test~plugin-vehicle-topology-reset-invalid-timeout, An unrepresentable timeout is rejected before admission, test ]]
#[tokio::test]
async fn unrepresentable_timeout_is_rejected_before_admission() {
    let fixture = fixture(false);
    for trigger_detection in [false, true] {
        let result = fixture
            .plugin
            .start_reset(flags(true, trigger_detection), Some(Duration::MAX))
            .await;
        assert!(matches!(result, Err(NetworkResetError::InvalidRequest(_))));
        assert!(fixture.plugin.list_resets().await.is_empty());
        assert!(fixture.calls.get().is_empty());
        assert!(!network_structure_blocked(&fixture.protections));
    }
}

#[tokio::test]
async fn zero_timeout_is_rejected_before_admission() {
    let fixture = fixture(false);
    let result = fixture
        .plugin
        .start_reset(flags(true, true), Some(Duration::ZERO))
        .await;
    assert!(
        matches!(&result, Err(NetworkResetError::InvalidRequest(message)) if message.starts_with("Timeout")),
        "{result:?}"
    );
    assert!(fixture.plugin.list_resets().await.is_empty());
    assert!(fixture.calls.get().is_empty());
    assert!(!network_structure_blocked(&fixture.protections));
}

/// A start whose request is dropped while the lease is still being acquired
/// still records and runs the execution once the lease is granted, so the lease
/// is neither leaked nor silently dropped.
#[tokio::test]
async fn dropped_start_while_the_lease_is_acquired_keeps_the_execution() {
    let fixture = build_fixture(false, false, Hold::Disable, None);
    let mut start = Box::pin(fixture.plugin.start_reset(flags(true, false), None));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut start)
            .await
            .is_err()
    );
    drop(start);
    assert!(fixture.plugin.list_resets().await.is_empty());
    fixture.hold.notify_one();

    let id = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(execution) = fixture.plugin.list_resets().await.into_iter().next() {
                return execution.id;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the execution was not recorded");
    assert_eq!(
        wait_finished(&fixture.plugin, &id).await,
        NetworkResetStatus::Completed
    );
    assert_eq!(fixture.calls.get(), vec!["disable", "clear", "finish"]);
    assert!(!network_structure_blocked(&fixture.protections));
}

/// A second start while the first still waits for its lease is a conflict.
#[tokio::test]
async fn start_while_another_waits_for_the_lease_conflicts() {
    let fixture = build_fixture(false, false, Hold::Disable, None);
    let mut first = Box::pin(fixture.plugin.start_reset(flags(true, false), None));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut first)
            .await
            .is_err()
    );
    assert!(matches!(
        fixture.plugin.start_reset(flags(true, false), None).await,
        Err(NetworkResetError::ExecutionConflict)
    ));
    fixture.hold.notify_one();
    let id = tokio::time::timeout(Duration::from_secs(5), first)
        .await
        .expect("first start did not finish")
        .unwrap();
    assert_eq!(
        wait_finished(&fixture.plugin, &id).await,
        NetworkResetStatus::Completed
    );
    assert_eq!(fixture.calls.get(), vec!["disable", "clear", "finish"]);
}

/// A new start after a finished execution replaces it.
#[tokio::test]
async fn start_after_a_finished_execution_replaces_it() {
    let fixture = fixture(false);
    let first = fixture
        .plugin
        .start_reset(flags(true, false), None)
        .await
        .unwrap();
    assert_eq!(
        wait_finished(&fixture.plugin, &first).await,
        NetworkResetStatus::Completed
    );
    let second = fixture
        .plugin
        .start_reset(flags(true, false), None)
        .await
        .unwrap();
    assert_ne!(first, second);
    assert!(fixture.plugin.get_reset(&first).await.is_none());
    let executions = fixture.plugin.list_resets().await;
    assert_eq!(executions.len(), 1);
    assert_eq!(
        executions.first().map(|e| e.id.as_str()),
        Some(second.as_str())
    );
    assert_eq!(
        wait_finished(&fixture.plugin, &second).await,
        NetworkResetStatus::Completed
    );
}

/// [[ test~plugin-vehicle-topology-reset-clear-and-detect-runs-one-rediscovery-and-blocks-network-structure, A detection run hands the lease over to one bring-up with detection, test ]]
#[tokio::test]
async fn clear_and_detect_runs_one_rediscovery_and_blocks_network_structure() {
    let fixture = fixture(false);
    let id = fixture
        .plugin
        .start_reset(flags(true, true), None)
        .await
        .unwrap();
    assert!(network_structure_blocked(&fixture.protections));
    let running = fixture.plugin.get_reset(&id).await.unwrap();
    assert_eq!(running.status, NetworkResetStatus::Running);
    assert_eq!(fixture.plugin.list_resets().await.len(), 1);
    assert!(matches!(
        fixture.plugin.start_reset(flags(true, true), None).await,
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
    // The lease is handed over to the rediscovery, neither released nor
    // finished: only the rediscovery brings communication back up.
    assert_eq!(
        fixture.calls.get(),
        vec!["disable", "clear", "prepare", "rediscover"]
    );
    assert!(!network_structure_blocked(&fixture.protections));
    assert_eq!(fixture.plugin.list_resets().await.len(), 1);
}

/// [[ test~plugin-vehicle-topology-reset-failed-persisting-of-the-rediscovered-topology-is-reported, A failed write of the rediscovered topology fails the execution, test ]]
#[tokio::test]
async fn failed_persisting_of_the_rediscovered_topology_is_reported() {
    let fixture = fixture(false);
    *fixture.persist_failure.lock().unwrap() = Some("disk full".to_owned());
    let id = fixture
        .plugin
        .start_reset(flags(false, true), None)
        .await
        .unwrap();
    wait_for_call(&fixture.calls, "rediscover").await;
    fixture.settle.notify_one();
    assert_eq!(
        wait_finished(&fixture.plugin, &id).await,
        NetworkResetStatus::Failed(NetworkResetFailure::Persist("disk full".to_owned()))
    );
}

/// [[ test~plugin-vehicle-topology-reset-failed-clear-gives-the-lease-back, A failed clear gives the communication lease back and fails the execution, test ]]
#[tokio::test]
async fn failed_clear_gives_the_lease_back() {
    for (trigger_detection, expected) in [
        (true, vec!["disable", "clear", "release"]),
        (false, vec!["disable", "clear", "release"]),
    ] {
        let fixture = fixture(false);
        fixture.fail_clear.store(true, Ordering::Relaxed);
        let id = fixture
            .plugin
            .start_reset(flags(true, trigger_detection), None)
            .await
            .unwrap();
        let NetworkResetStatus::Failed(reason) = wait_finished(&fixture.plugin, &id).await else {
            panic!("trigger_detection={trigger_detection}: expected a failed execution");
        };
        assert!(
            matches!(reason, NetworkResetFailure::Clear(_)),
            "trigger_detection={trigger_detection}: {reason:?}"
        );
        assert_eq!(
            reason.to_string(),
            "Clearing the persisted topology failed: Topology serialization failed: disk full"
        );
        assert_eq!(
            fixture.calls.get(),
            expected,
            "trigger_detection={trigger_detection}"
        );
    }
}

/// [[ test~plugin-vehicle-topology-reset-clear-only-follows-init-mode, A clear-only execution takes communication down and gives it back only under an `init_mode` that starts it on its own, test ]]
#[tokio::test]
async fn clear_only_follows_init_mode() {
    for (clear_resumes_transport, ending) in [(false, "finish"), (true, "release")] {
        let mut fixture = fixture(false);
        Arc::get_mut(&mut fixture.plugin.deps)
            .expect("the plugin owns its deps")
            .clear_resumes_transport = clear_resumes_transport;
        let id = fixture
            .plugin
            .start_reset(flags(true, false), None)
            .await
            .unwrap();
        assert_eq!(
            wait_finished(&fixture.plugin, &id).await,
            NetworkResetStatus::Completed
        );
        // No rediscovery: the clear causes no vehicle communication.
        assert_eq!(fixture.calls.get(), vec!["disable", "clear", ending]);
        assert!(!network_structure_blocked(&fixture.protections));
    }
}

/// [[ test~plugin-vehicle-topology-reset-diagnostics-in-progress-reject-the-reset, Diagnostic operations using communication reject the reset, test ]]
#[tokio::test]
async fn diagnostics_in_progress_reject_the_reset() {
    for trigger_detection in [false, true] {
        let fixture = fixture(true);
        assert!(matches!(
            fixture
                .plugin
                .start_reset(flags(true, trigger_detection), None)
                .await,
            Err(NetworkResetError::OperationsInProgress(_))
        ));
        assert!(!network_structure_blocked(&fixture.protections));
        assert!(fixture.calls.get().is_empty());
    }
}

async fn wait_unblocked(protections: &HttpProtectionRegistry) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while network_structure_blocked(protections) {
            // A timer, not a yield: under paused time the clock only advances
            // while the runtime is idle, so a yield loop could hang the test.
            cda_interfaces::util::tokio_ext::sleep_for(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("protection was not released");
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
    let id = fixture
        .plugin
        .start_reset(flags(true, true), None)
        .await
        .unwrap();
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
        .start_reset(flags(true, false), None)
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
    let id = fixture
        .plugin
        .start_reset(flags(true, true), None)
        .await
        .unwrap();
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
        fixture.plugin.start_reset(flags(true, false), None).await,
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
    let fixture = fixture_with(false, true);
    let id = fixture
        .plugin
        .start_reset(flags(true, false), None)
        .await
        .unwrap();
    assert_eq!(
        wait_finished(&fixture.plugin, &id).await,
        NetworkResetStatus::Failed(NetworkResetFailure::Internal)
    );
    assert!(!network_structure_blocked(&fixture.protections));
    // The lease is dropped with the panicked task, which defers its release.
    assert_eq!(fixture.calls.get(), vec!["disable", "clear"]);
    let next = self::fixture(false);
    assert!(
        next.plugin
            .start_reset(flags(true, false), None)
            .await
            .is_ok()
    );
    // Same plugin: a finished execution may be replaced.
    assert!(
        fixture
            .plugin
            .start_reset(flags(true, false), None)
            .await
            .is_ok()
    );
}

/// [[ test~plugin-vehicle-topology-reset-deadline, networkreset bounds and cancels the rediscovery and reports a failed bring-up, test ]]
#[tokio::test(start_paused = true)]
async fn hanging_rediscover_fails_after_deadline() {
    let fixture = hanging_fixture();
    let id = fixture
        .plugin
        .start_reset(flags(true, true), None)
        .await
        .unwrap();
    wait_for_call(&fixture.calls, "rediscover").await;
    assert_eq!(
        fixture.plugin.get_reset(&id).await.unwrap().status,
        NetworkResetStatus::Running
    );
    tokio::time::advance(Duration::from_secs(6)).await;
    assert_eq!(
        wait_finished(&fixture.plugin, &id).await,
        NetworkResetStatus::Failed(NetworkResetFailure::DeadlineElapsed(Duration::from_secs(5)))
    );
    // The rediscovery still runs and holds the protection until it has settled.
    assert!(network_structure_blocked(&fixture.protections));
    fixture.hold.notify_one();
    fixture.settle.notify_one();
    wait_unblocked(&fixture.protections).await;
}

/// [[ test~plugin-vehicle-topology-reset-delete-interrupts-hanging-rediscover, A DELETE interrupts a hanging rediscovery, test ]]
#[tokio::test(start_paused = true)]
async fn delete_interrupts_hanging_rediscover() {
    let fixture = hanging_fixture();
    let id = fixture
        .plugin
        .start_reset(flags(true, true), None)
        .await
        .unwrap();
    wait_for_call(&fixture.calls, "rediscover").await;
    assert!(fixture.plugin.delete_reset(&id).await);
    assert!(fixture.plugin.list_resets().await.is_empty());
    assert!(!fixture.calls.get().contains(&"release"));
}

/// The protection outlives a deleted execution until the rediscovery it started
/// has finished and settled, so the network structure is never read half updated.
#[tokio::test]
async fn protection_outlives_a_deleted_execution_until_the_rediscovery_settled() {
    let fixture = hanging_fixture();
    let id = fixture
        .plugin
        .start_reset(flags(true, true), None)
        .await
        .unwrap();
    wait_for_call(&fixture.calls, "rediscover").await;
    assert!(fixture.plugin.delete_reset(&id).await);
    assert!(fixture.plugin.list_resets().await.is_empty());
    assert!(network_structure_blocked(&fixture.protections));

    // The rediscovery returns, but has not settled yet.
    fixture.hold.notify_one();
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert!(network_structure_blocked(&fixture.protections));

    fixture.settle.notify_one();
    wait_unblocked(&fixture.protections).await;
}

/// [[ test~plugin-vehicle-topology-reset-timeout-stops-the-execution, An execution still running when its timeout elapses is stopped and kept, test ]]
#[tokio::test(start_paused = true)]
async fn timeout_stops_a_running_execution_and_keeps_it() {
    let fixture = hanging_fixture();
    let id = fixture
        .plugin
        .start_reset(flags(true, true), Some(Duration::from_secs(2)))
        .await
        .unwrap();
    wait_for_call(&fixture.calls, "rediscover").await;
    // Below the bring-up deadline (5s), so only the timeout ends the execution.
    tokio::time::advance(Duration::from_secs(2)).await;

    assert_eq!(
        wait_finished(&fixture.plugin, &id).await,
        NetworkResetStatus::Stopped
    );
    assert_eq!(fixture.plugin.list_resets().await.len(), 1);
    // The hanging rediscovery keeps the protection.
    assert!(network_structure_blocked(&fixture.protections));
    // A stopped execution does not block the next one.
    assert!(
        fixture
            .plugin
            .start_reset(flags(true, false), None)
            .await
            .is_ok()
    );
}

/// An execution that finishes before its timeout keeps its own result.
#[tokio::test(start_paused = true)]
async fn execution_finishing_before_its_timeout_completes() {
    let fixture = fixture(false);
    let id = fixture
        .plugin
        .start_reset(flags(true, false), Some(Duration::from_secs(2)))
        .await
        .unwrap();

    assert_eq!(
        wait_finished(&fixture.plugin, &id).await,
        NetworkResetStatus::Completed
    );
}

/// [[ test~plugin-vehicle-topology-reset-failed-rediscover-reports-disabled-communication, A failed rediscovery reports that communication may not be fully available, test ]]
#[tokio::test]
async fn failed_rediscover_reports_unavailable_communication() {
    let failure = CommunicationOperationFailure::TransportFailure {
        operation: CommunicationOperation::EnableAndDetect,
        error: "transport down".to_owned(),
    };
    let fixture = build_fixture(false, false, Hold::Nothing, Some(failure.clone()));
    let id = fixture
        .plugin
        .start_reset(flags(true, true), None)
        .await
        .unwrap();
    let NetworkResetStatus::Failed(reason) = wait_finished(&fixture.plugin, &id).await else {
        panic!("expected a failed execution");
    };
    assert_eq!(reason, NetworkResetFailure::Rediscovery(failure));
    let message = reason.to_string();
    assert!(
        message.contains("Communication may not be fully available"),
        "{message}"
    );
    assert!(message.contains("transport down"), "{message}");
}

/// A communication plugin that refuses the hand-over is a policy decision, so the
/// failure carries no hint to retry.
/// [[ test~plugin-vehicle-topology-reset-refused-rediscovery-reports-the-refusal, A rediscovery refused by the communication plugin is reported without a retry hint, test ]]
#[tokio::test]
async fn refused_rediscovery_reports_the_refusal() {
    let failure = CommunicationOperationFailure::PermissionFailure {
        operation: CommunicationOperation::EnableAndDetect,
    };
    let fixture = build_fixture(false, false, Hold::Nothing, Some(failure.clone()));
    let id = fixture
        .plugin
        .start_reset(flags(true, true), None)
        .await
        .unwrap();
    let NetworkResetStatus::Failed(reason) = wait_finished(&fixture.plugin, &id).await else {
        panic!("expected a failed execution");
    };
    assert_eq!(reason, NetworkResetFailure::RediscoveryRefused(failure));
    assert!(
        !reason.to_string().contains("trigger_detection=true"),
        "{reason}"
    );
}

/// A clear-only execution whose lease cannot be ended reports that failure.
/// [[ test~plugin-vehicle-topology-reset-clear-only-end-lease-failure, A clear-only execution reports a failure to end its lease, test ]]
#[tokio::test]
async fn clear_only_reports_a_failure_to_end_the_lease() {
    let failure = CommunicationOperationFailure::TransportFailure {
        operation: CommunicationOperation::FinishDisableLease,
        error: "worker gone".to_owned(),
    };
    let fixture = build_fixture(false, false, Hold::Nothing, Some(failure.clone()));
    let id = fixture
        .plugin
        .start_reset(flags(true, false), None)
        .await
        .unwrap();
    assert_eq!(
        wait_finished(&fixture.plugin, &id).await,
        NetworkResetStatus::Failed(NetworkResetFailure::EndLease(failure))
    );
    assert_eq!(fixture.calls.get(), vec!["disable", "clear", "finish"]);
}

/// [[ test~plugin-vehicle-topology-reset-delete-during-clear, A DELETE during the clear gives communication back once the clear finished, test ]]
#[tokio::test]
async fn delete_during_the_clear_gives_communication_back() {
    let fixture = held_fixture();
    let id = fixture
        .plugin
        .start_reset(flags(true, true), None)
        .await
        .unwrap();
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

    // Nothing was prepared, so the ECU states and the discovery strategy are
    // untouched when communication returns.
    assert_eq!(fixture.calls.get(), vec!["disable", "clear", "release"]);
    assert!(!network_structure_blocked(&fixture.protections));
}

/// A DELETE during the clear of a clear-only execution: the clear has
/// happened, so communication ends as after a completed clear. The DELETE
/// removes the execution; the stopped status is covered by the timeout test.
#[tokio::test]
async fn clear_only_delete_during_the_clear_finishes_the_lease() {
    let fixture = held_fixture();
    let id = fixture
        .plugin
        .start_reset(flags(true, false), None)
        .await
        .unwrap();
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
    assert!(fixture.plugin.list_resets().await.is_empty());
    assert_eq!(fixture.calls.get(), vec!["disable", "clear", "finish"]);
}

/// A clear-only execution whose timeout elapses during the clear is stopped and
/// kept, like any other execution that times out.
#[tokio::test(start_paused = true)]
async fn clear_only_timing_out_during_the_clear_is_stopped_and_kept() {
    let fixture = held_fixture();
    let id = fixture
        .plugin
        .start_reset(flags(true, false), Some(Duration::from_secs(2)))
        .await
        .unwrap();
    wait_for_call(&fixture.calls, "clear").await;
    tokio::time::advance(Duration::from_secs(3)).await;
    fixture.hold.notify_one();
    assert_eq!(
        wait_finished(&fixture.plugin, &id).await,
        NetworkResetStatus::Stopped
    );
    assert_eq!(fixture.plugin.list_resets().await.len(), 1);
    assert_eq!(fixture.calls.get(), vec!["disable", "clear", "finish"]);
    assert!(!network_structure_blocked(&fixture.protections));
}

/// A rediscovery that never returns gives up the network structure protection
/// after a multiple of the rediscovery timeout.
#[tokio::test(start_paused = true)]
async fn wedged_rediscovery_gives_up_the_protection() {
    let fixture = hanging_fixture();
    let id = fixture
        .plugin
        .start_reset(flags(false, true), None)
        .await
        .unwrap();
    wait_for_call(&fixture.calls, "rediscover").await;
    tokio::time::advance(Duration::from_secs(6)).await;
    assert!(matches!(
        wait_finished(&fixture.plugin, &id).await,
        NetworkResetStatus::Failed(_)
    ));
    assert!(network_structure_blocked(&fixture.protections));
    // The bound is four times the rediscovery timeout (5s), counted from the
    // start of the rediscovery.
    tokio::time::advance(Duration::from_secs(15)).await;
    wait_unblocked(&fixture.protections).await;
}

/// [[ test~plugin-vehicle-topology-reset-verdict-from-persistence, The settling is bounded by the persistence verdict and not by the bring-up budget, test ]]
#[tokio::test(start_paused = true)]
async fn slow_settling_inside_the_persistence_budget_completes() {
    let fixture = hanging_fixture();
    let id = fixture
        .plugin
        .start_reset(flags(false, true), None)
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
    let fixture = fixture(false);
    let id = fixture
        .plugin
        .start_reset(flags(false, true), None)
        .await
        .unwrap();
    wait_for_call(&fixture.calls, "rediscover").await;
    // Nobody settles: the network reset's budget ends the wait.
    tokio::time::advance(Duration::from_secs(31)).await;

    assert_eq!(
        wait_finished(&fixture.plugin, &id).await,
        NetworkResetStatus::Failed(NetworkResetFailure::SettleTimedOut)
    );
}
