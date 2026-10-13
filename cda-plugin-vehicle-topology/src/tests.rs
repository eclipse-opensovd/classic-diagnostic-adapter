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
        CommunicationOperationFailure, CommunicationState, disable::DisableGuard,
    },
    topology::TopologyStoreError,
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
}

#[async_trait]
impl TopologyResetBackend for FakeBackend {
    async fn clear_persisted(&self) -> Result<(), TopologyStoreError> {
        self.calls.push("clear");
        Ok(())
    }

    async fn prepare_rediscovery(&self) -> u64 {
        self.calls.push("prepare");
        7
    }

    async fn wait_rediscovered(&self, marker: u64, timeout: Duration) -> bool {
        assert_eq!(marker, 7);
        tokio::time::timeout(timeout, self.settle.notified())
            .await
            .is_ok()
    }
}

struct FakeRediscovery(Arc<Calls>);

#[async_trait]
impl TopologyRediscovery for FakeRediscovery {
    async fn rediscover(&self) -> Result<(), String> {
        self.0.push("rediscover");
        Ok(())
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
}

fn fixture(in_use: bool, component_locks: usize) -> Fixture {
    let calls = Arc::new(Calls::default());
    let settle = Arc::new(tokio::sync::Notify::new());
    let protections = HttpProtectionRegistry::new();
    let plugin = DefaultVehicleTopologyPlugin::new(VehicleTopologyDeps {
        backend: Arc::new(FakeBackend {
            calls: Arc::clone(&calls),
            settle: Arc::clone(&settle),
        }),
        rediscovery: Arc::new(FakeRediscovery(Arc::clone(&calls))),
        communication_disable: Arc::new(FakeDisable {
            calls: Arc::clone(&calls),
            in_use: AtomicBool::new(in_use),
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

/// [[ test~plugin-vehicle-topology-reset-flags, networkreset handles every flag combination, test ]]
#[tokio::test]
async fn both_flags_false_is_rejected() {
    let fixture = fixture(false, 0);
    assert!(matches!(
        fixture.plugin.start_reset(flags(false, false)).await,
        Err(NetworkResetError::InvalidRequest(_))
    ));
    assert!(fixture.calls.get().is_empty());
    assert!(fixture.plugin.list_resets().await.is_empty());
}

#[tokio::test]
async fn clear_only_never_touches_communication() {
    let fixture = fixture(false, 0);
    let id = fixture
        .plugin
        .start_reset(flags(true, false))
        .await
        .unwrap();
    assert_eq!(
        wait_finished(&fixture.plugin, &id).await,
        NetworkResetStatus::Completed
    );
    assert_eq!(fixture.calls.get(), vec!["clear"]);
}

#[tokio::test]
async fn clear_and_detect_runs_one_rediscovery_and_blocks_network_structure() {
    let fixture = fixture(false, 0);
    let id = fixture.plugin.start_reset(flags(true, true)).await.unwrap();
    assert!(network_structure_blocked(&fixture.protections));
    assert!(fixture.plugin.is_running().await);
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

#[tokio::test]
async fn detect_only_does_not_clear() {
    let fixture = fixture(false, 0);
    let id = fixture
        .plugin
        .start_reset(flags(false, true))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !fixture.calls.get().contains(&"rediscover") {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    fixture.settle.notify_one();
    wait_finished(&fixture.plugin, &id).await;
    assert!(!fixture.calls.get().contains(&"clear"));
}

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

#[tokio::test]
async fn delete_stops_and_removes_a_running_execution() {
    let fixture = fixture(false, 0);
    let id = fixture.plugin.start_reset(flags(true, true)).await.unwrap();
    assert!(!fixture.plugin.delete_reset("unknown").await);
    assert!(fixture.plugin.delete_reset(&id).await);
    assert!(fixture.plugin.list_resets().await.is_empty());
    assert!(!network_structure_blocked(&fixture.protections));
    // A new execution can start right away.
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
