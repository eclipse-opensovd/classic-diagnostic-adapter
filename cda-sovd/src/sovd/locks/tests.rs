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

use std::{
    sync::{
        Mutex as StdMutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime},
};

use axum::{http::StatusCode, response::IntoResponse};
use cda_interfaces::{
    TesterPresentType,
    lock_priority_api::{
        LockLifecycleEvent, LockPrincipal, LockPriorityDecision, LockPriorityError,
        LockPriorityEvaluation, LockPriorityOperation, LockPriorityPolicy, LockRequest,
        LockSnapshot,
    },
    mock::MockUdsEcu,
};
use cda_plugin_security::{
    AuthApi,
    mock::{ConfigurableTestClaims as TestClaims, TestSecurityPlugin},
};
use mockall::predicate::*;
use tokio::{sync::Notify, task};

use super::{
    cleanup::{run_cleanups, take_cleanups},
    handlers::common::{run_acquisition_transaction, sovd_lock_response, validated_expiration},
    policy::sort_lock_snapshots,
    validation::validate_active_locks,
    *,
};
use crate::test_utils::axum_response_into;

mod cleanup;
mod handlers;
mod lifecycle;
mod policy;
mod transactions;
mod validation;

const POLL_INTERVAL: Duration = Duration::from_millis(10);
const WAIT_TIMEOUT: Duration = Duration::from_secs(10);

async fn wait_until<F, Fut>(description: &str, mut condition: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let poll = async {
        while !condition().await {
            cda_interfaces::util::tokio_ext::sleep_for(POLL_INTERVAL).await;
        }
    };
    assert!(
        tokio::time::timeout(WAIT_TIMEOUT, poll).await.is_ok(),
        "Timed out waiting until {description}"
    );
}

async fn await_events(policy: &EventRecordingPolicy, count: usize) {
    wait_until("lock lifecycle events are delivered", || async {
        policy.events.lock().expect("Event mutex poisoned").len() >= count
    })
    .await;
}

async fn commit_pending_preemption(
    locks: &Locks,
    acquisition: AcquisitionGuard,
    mut pending: PendingPreemption,
    replacement: ActiveLock,
) -> Vec<ActiveLock> {
    let removed = locks
        .store
        .lock()
        .await
        .state
        .commit_replacement(
            &pending.root_lock_ids,
            replacement,
            &pending.broken_by,
            pending.broken_at,
        )
        .expect("Preemption commit should succeed");
    pending.disarm();
    acquisition.finish().await;
    let cleanups = {
        let mut store = locks.store.lock().await;
        take_cleanups(&mut store.cleanups, &removed)
    };
    run_cleanups(cleanups).await;
    removed
}

impl Locks {
    async fn active_snapshots(&self) -> Vec<LockSnapshot> {
        let mut snapshots = self
            .store
            .lock()
            .await
            .state
            .active()
            .map(active_snapshot)
            .collect::<Vec<_>>();
        sort_lock_snapshots(&mut snapshots);
        snapshots
    }

    async fn test_insert_active(&self, lock: ActiveLock) {
        self.store
            .lock()
            .await
            .state
            .insert_active(lock)
            .expect("Test lock insertion should succeed");
    }

    async fn test_insert_cleanup(&self, lock_id: String, cleanup: LockCleanupFnHelper) {
        self.store.lock().await.cleanups.insert(lock_id, cleanup);
    }

    async fn test_has_active(&self, lock_id: &str) -> bool {
        self.store
            .lock()
            .await
            .state
            .active_by_id(lock_id)
            .is_some()
    }

    async fn test_reservation(&self) -> AcquisitionGuard {
        let transition_id = self.reserve_transition().await;
        AcquisitionGuard {
            reservation: transition_id,
            evaluation_id: None,
            policy: Arc::clone(&self.priority_policy),
        }
    }
}

fn locks_with_policy<P: LockPriorityPolicy>(policy: Arc<P>) -> Locks {
    Locks::new_with_policy(policy)
}

struct TestPolicy {
    decision: Option<LockPriorityDecision>,
    evaluations: StdMutex<Vec<LockPriorityEvaluation>>,
}

#[async_trait::async_trait]
impl LockPriorityPolicy for TestPolicy {
    async fn evaluate(
        &self,
        evaluation: &LockPriorityEvaluation,
    ) -> Result<LockPriorityDecision, LockPriorityError> {
        self.evaluations
            .lock()
            .expect("policy evaluation mutex poisoned")
            .push(evaluation.clone());
        match &self.decision {
            Some(decision) => Ok(decision.clone()),
            None => std::future::pending().await,
        }
    }
}

#[derive(Default)]
struct EventRecordingPolicy {
    events: StdMutex<Vec<LockLifecycleEvent>>,
}

#[derive(Default)]
struct AbandonmentRecordingPolicy {
    events: StdMutex<Vec<LockLifecycleEvent>>,
}

#[async_trait::async_trait]
impl LockPriorityPolicy for EventRecordingPolicy {
    async fn evaluate(
        &self,
        _evaluation: &LockPriorityEvaluation,
    ) -> Result<LockPriorityDecision, LockPriorityError> {
        Ok(LockPriorityDecision::Allow)
    }

    async fn on_lock_event(&self, event: &LockLifecycleEvent) {
        self.events
            .lock()
            .expect("event mutex poisoned")
            .push(event.clone());
    }
}

#[async_trait::async_trait]
impl LockPriorityPolicy for AbandonmentRecordingPolicy {
    async fn evaluate(
        &self,
        _evaluation: &LockPriorityEvaluation,
    ) -> Result<LockPriorityDecision, LockPriorityError> {
        Ok(LockPriorityDecision::Preempt {
            lock_ids: vec!["existing-lock".to_owned()],
            broken_by: "priority-policy".to_owned(),
        })
    }

    async fn on_lock_event(&self, event: &LockLifecycleEvent) {
        self.events
            .lock()
            .expect("event mutex poisoned")
            .push(event.clone());
    }
}

struct PanickingPolicy;

#[async_trait::async_trait]
impl LockPriorityPolicy for PanickingPolicy {
    async fn evaluate(
        &self,
        _evaluation: &LockPriorityEvaluation,
    ) -> Result<LockPriorityDecision, LockPriorityError> {
        panic!("Policy panic for test");
    }
}

struct BlockingPolicy {
    evaluations: AtomicUsize,
    requests: StdMutex<Vec<LockPriorityEvaluation>>,
    started: Notify,
    release: Notify,
}

struct MetadataVerificationPolicy {
    result: Result<(), LockPriorityError>,
    requests: StdMutex<Vec<LockRequest>>,
}

struct BlockingMetadataPolicy;

#[async_trait::async_trait]
impl LockPriorityPolicy for BlockingMetadataPolicy {
    async fn verify_metadata(&self, _request: &LockRequest) -> Result<(), LockPriorityError> {
        std::future::pending().await
    }

    async fn evaluate(
        &self,
        _evaluation: &LockPriorityEvaluation,
    ) -> Result<LockPriorityDecision, LockPriorityError> {
        Ok(LockPriorityDecision::Allow)
    }
}

struct PanickingMetadataPolicy;

#[async_trait::async_trait]
impl LockPriorityPolicy for PanickingMetadataPolicy {
    async fn verify_metadata(&self, _request: &LockRequest) -> Result<(), LockPriorityError> {
        panic!("Metadata verification panic for test");
    }

    async fn evaluate(
        &self,
        _evaluation: &LockPriorityEvaluation,
    ) -> Result<LockPriorityDecision, LockPriorityError> {
        Ok(LockPriorityDecision::Allow)
    }
}

#[async_trait::async_trait]
impl LockPriorityPolicy for MetadataVerificationPolicy {
    async fn verify_metadata(&self, request: &LockRequest) -> Result<(), LockPriorityError> {
        self.requests
            .lock()
            .expect("Metadata verification mutex poisoned")
            .push(request.clone());
        self.result.clone()
    }

    async fn evaluate(
        &self,
        _evaluation: &LockPriorityEvaluation,
    ) -> Result<LockPriorityDecision, LockPriorityError> {
        Ok(LockPriorityDecision::Allow)
    }
}

#[async_trait::async_trait]
impl LockPriorityPolicy for BlockingPolicy {
    async fn evaluate(
        &self,
        evaluation: &LockPriorityEvaluation,
    ) -> Result<LockPriorityDecision, LockPriorityError> {
        self.evaluations.fetch_add(1, Ordering::SeqCst);
        self.requests
            .lock()
            .expect("Policy evaluation mutex poisoned")
            .push(evaluation.clone());
        self.started.notify_one();
        self.release.notified().await;
        Ok(LockPriorityDecision::Allow)
    }
}

pub(crate) async fn insert_test_fg_lock(locks: &Locks, functional_group_name: &str) {
    let lock = ActiveLock {
        id: "test-fg-lock-id".to_owned(),
        scope: ScopeKey::FunctionalGroup(functional_group_name.to_ascii_lowercase()),
        coverage: LockCoverage::new(["test-ecu".to_owned()]),
        principal: LockPrincipal {
            subject: "test_user".to_owned(),
            claims: serde_json::Map::new(),
        },
        metadata: serde_json::Map::new(),
        exclusive: true,
        expires_at: SystemTime::now()
            .checked_add(Duration::from_secs(3600))
            .expect("test expiration should be representable"),
        parent_vehicle_lock_id: None,
    };
    locks.test_insert_active(lock).await;
}

pub(crate) async fn insert_test_ecu_lock(locks: &Locks, ecu_name: &str) {
    let lock = ActiveLock {
        id: "test-lock-id".to_owned(),
        scope: ScopeKey::Ecu(ecu_name.to_ascii_lowercase()),
        coverage: LockCoverage::new([ecu_name.to_owned()]),
        principal: LockPrincipal {
            subject: "test_user".to_owned(),
            claims: serde_json::Map::new(),
        },
        metadata: serde_json::Map::new(),
        exclusive: true,
        expires_at: SystemTime::now()
            .checked_add(Duration::from_secs(3600))
            .expect("test expiration should be representable"),
        parent_vehicle_lock_id: None,
    };
    locks.test_insert_active(lock).await;
}

async fn insert_policy_test_lock(locks: &Locks, cleanup_count: Arc<AtomicUsize>) -> String {
    let id = "existing-lock".to_owned();
    let lock = ActiveLock {
        id: id.clone(),
        scope: ScopeKey::Vehicle,
        coverage: LockCoverage::vehicle(),
        principal: LockPrincipal {
            subject: "existing-client".to_owned(),
            claims: serde_json::Map::new(),
        },
        metadata: serde_json::Map::new(),
        exclusive: true,
        expires_at: SystemTime::now()
            .checked_add(Duration::from_secs(300))
            .expect("test expiration should be representable"),
        parent_vehicle_lock_id: None,
    };
    locks.test_insert_active(lock).await;
    locks
        .test_insert_cleanup(
            id.clone(),
            LockCleanupFnHelper::new(move || async move {
                cleanup_count.fetch_add(1, Ordering::SeqCst);
            }),
        )
        .await;
    id
}

fn test_lock(id: &str) -> TestLockBuilder {
    TestLockBuilder {
        lock: ActiveLock {
            id: id.to_owned(),
            scope: ScopeKey::Ecu("ecu-a".to_owned()),
            coverage: LockCoverage::new(["ecu-a".to_owned()]),
            principal: LockPrincipal {
                subject: "test_user".to_owned(),
                claims: serde_json::Map::new(),
            },
            metadata: serde_json::Map::new(),
            exclusive: true,
            expires_at: SystemTime::now()
                .checked_add(Duration::from_secs(300))
                .expect("test expiration should be representable"),
            parent_vehicle_lock_id: None,
        },
    }
}

struct TestLockBuilder {
    lock: ActiveLock,
}

impl TestLockBuilder {
    fn owner(mut self, subject: &str) -> Self {
        self.lock.principal.subject = subject.to_owned();
        self
    }

    fn exclusive(mut self, exclusive: bool) -> Self {
        self.lock.exclusive = exclusive;
        self
    }

    fn vehicle(mut self) -> Self {
        self.lock.scope = ScopeKey::Vehicle;
        self.lock.coverage = LockCoverage::vehicle();
        self
    }

    fn ecu(mut self, name: &str) -> Self {
        self.lock.scope = ScopeKey::Ecu(name.to_owned());
        self.lock.coverage = LockCoverage::new([name.to_owned()]);
        self
    }

    fn functional_group(mut self, name: &str, coverage: impl IntoIterator<Item = String>) -> Self {
        self.lock.scope = ScopeKey::FunctionalGroup(name.to_owned());
        self.lock.coverage = LockCoverage::new(coverage);
        self
    }

    fn expires_at(mut self, expires_at: SystemTime) -> Self {
        self.lock.expires_at = expires_at;
        self
    }

    fn parent(mut self, lock_id: &str) -> Self {
        self.lock.parent_vehicle_lock_id = Some(lock_id.to_owned());
        self
    }

    fn build(self) -> ActiveLock {
        self.lock
    }
}

fn preemption_request() -> sovd_interfaces::locking::Request {
    sovd_interfaces::locking::Request {
        lock_expiration: 60,
        break_lock: true,
        x_sovd2uds_isexclusive: None,
        metadata: serde_json::Map::new(),
    }
}
