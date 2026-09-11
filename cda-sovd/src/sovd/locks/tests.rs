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

use std::{
    sync::{
        Mutex as StdMutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime},
};

use axum::{http::StatusCode, response::IntoResponse};
use cda_interfaces::{
    TesterPresentType,
    lock_priority_api::{
        LockLifecycleEvent, LockPrincipal, LockPriorityDecision, LockPriorityError,
        LockPriorityEvaluation, LockPriorityOperation, LockPriorityPolicy, LockSnapshot,
    },
    mock::MockUdsEcu,
};
use cda_plugin_security::{AuthApi, Claims, mock::TestSecurityPlugin};
use mockall::predicate::*;
use tokio::{sync::Notify, task};

use super::{
    cleanup::{run_cleanups, take_cleanups},
    handlers::common::{run_acquisition_transaction, sovd_lock_response},
    policy::scope_sort_key,
    validation::{validate_active_locks, validate_defunct_fg_lock},
    *,
};
use crate::test_utils::axum_response_into;

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
        snapshots.sort_by(|left, right| {
            scope_sort_key(&left.scope)
                .cmp(&scope_sort_key(&right.scope))
                .then_with(|| left.id.cmp(&right.id))
        });
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

    async fn test_has_cleanup(&self, lock_id: &str) -> bool {
        self.store.lock().await.cleanups.contains_key(lock_id)
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

struct TestClaims {
    subject: String,
    attributes: serde_json::Map<String, serde_json::Value>,
}

impl Claims for TestClaims {
    fn sub(&self) -> &str {
        &self.subject
    }

    fn attributes(&self) -> serde_json::Map<String, serde_json::Value> {
        self.attributes.clone()
    }
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
    decision: Option<LockPriorityDecision>,
    events: StdMutex<Vec<LockLifecycleEvent>>,
}

#[async_trait::async_trait]
impl LockPriorityPolicy for EventRecordingPolicy {
    async fn evaluate(
        &self,
        _evaluation: &LockPriorityEvaluation,
    ) -> Result<LockPriorityDecision, LockPriorityError> {
        Ok(self.decision.clone().unwrap_or(LockPriorityDecision::Allow))
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
    started: Notify,
    release: Notify,
}

#[async_trait::async_trait]
impl LockPriorityPolicy for BlockingPolicy {
    async fn evaluate(
        &self,
        _evaluation: &LockPriorityEvaluation,
    ) -> Result<LockPriorityDecision, LockPriorityError> {
        self.evaluations.fetch_add(1, Ordering::SeqCst);
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
        parent_vehicle: None,
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
        parent_vehicle: None,
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
        parent_vehicle: None,
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

fn active_test_lock(subject: &str, exclusive: bool) -> ActiveLock {
    ActiveLock {
        id: "access-lock".to_owned(),
        scope: ScopeKey::Ecu("ecu-a".to_owned()),
        coverage: LockCoverage::new(["ecu-a".to_owned()]),
        principal: LockPrincipal {
            subject: subject.to_owned(),
            claims: serde_json::Map::new(),
        },
        metadata: serde_json::Map::new(),
        exclusive,
        expires_at: SystemTime::now()
            .checked_add(Duration::from_secs(300))
            .expect("test expiration should be representable"),
        parent_vehicle: None,
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

mod cleanup;
mod handlers;
mod lifecycle;
mod policy;
mod transactions;
mod validation;
