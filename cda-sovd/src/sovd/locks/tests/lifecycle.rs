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

use super::*;

#[test]
fn locks_can_be_constructed_without_tokio_runtime() {
    drop(Locks::new());
}

#[tokio::test]
async fn expiration_holds_mutation_guard_until_cleanup_finishes() {
    let policy = Arc::new(EventRecordingPolicy::default());
    let locks = Arc::new(Locks::new_with_policy(Arc::<EventRecordingPolicy>::clone(
        &policy,
    )));
    let cleanup_started = Arc::new(Notify::new());
    let release_cleanup = Arc::new(Notify::new());
    let lock = ActiveLock {
        id: "expiring-lock".to_owned(),
        scope: ScopeKey::Vehicle,
        coverage: LockCoverage::vehicle(),
        principal: LockPrincipal {
            subject: "owner".to_owned(),
            claims: serde_json::Map::new(),
        },
        metadata: serde_json::Map::new(),
        exclusive: true,
        expires_at: SystemTime::now() + Duration::from_millis(20),
        parent_vehicle: None,
    };
    locks.test_insert_active(lock.clone()).await;
    let child = ActiveLock {
        id: "expiring-child".to_owned(),
        scope: ScopeKey::Ecu("ecu-a".to_owned()),
        coverage: LockCoverage::vehicle(),
        principal: lock.principal.clone(),
        metadata: serde_json::Map::new(),
        exclusive: true,
        expires_at: lock.expires_at + Duration::from_secs(30),
        parent_vehicle: Some(lock.id.clone()),
    };
    locks.test_insert_active(child.clone()).await;
    let cleanup_started_task = Arc::clone(&cleanup_started);
    let release_cleanup_task = Arc::clone(&release_cleanup);
    locks
        .test_insert_cleanup(
            lock.id.clone(),
            LockCleanupFnHelper::new(move || async move {
                cleanup_started_task.notify_one();
                release_cleanup_task.notified().await;
            }),
        )
        .await;
    let expiration_target =
        Locks::expiration_target(&lock).expect("Test expiration target should be representable");
    locks.schedule_expiration(&lock, expiration_target).await;

    tokio::time::timeout(Duration::from_secs(1), cleanup_started.notified())
        .await
        .expect("Expiration cleanup should start");
    assert!(!locks.test_has_active(&lock.id).await);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), locks.lock_idle())
            .await
            .is_err(),
        "Mutation guard must remain held during expiration cleanup"
    );
    assert!(
        policy
            .events
            .lock()
            .expect("Event mutex poisoned")
            .is_empty()
    );

    release_cleanup.notify_one();
    let released_guard = tokio::time::timeout(Duration::from_secs(1), locks.lock_idle())
        .await
        .expect("Mutation guard should be released after cleanup");
    drop(released_guard);
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if policy
                .events
                .lock()
                .expect("Event mutex poisoned")
                .iter()
                .len()
                == 2
            {
                break;
            }
            task::yield_now().await;
        }
    })
    .await
    .expect("Expired event should be delivered after cleanup");
    let events = policy.events.lock().expect("Event mutex poisoned");
    assert!(matches!(
        events.as_slice(),
        [
            LockLifecycleEvent::Expired { lock: child_lock },
            LockLifecycleEvent::Expired { lock: root_lock }
        ] if child_lock.id == child.id
            && matches!(child_lock.scope, LockScope::Ecu { .. })
            && root_lock.id == lock.id
            && root_lock.scope == LockScope::Vehicle
    ));
}

#[tokio::test]
async fn expiration_releases_transition_after_cleanup_panic() {
    let locks = Arc::new(Locks::new());
    let lock = ActiveLock {
        id: "panicking-cleanup".to_owned(),
        scope: ScopeKey::Vehicle,
        coverage: LockCoverage::new(["ecu-a".to_owned()]),
        principal: LockPrincipal {
            subject: "owner".to_owned(),
            claims: serde_json::Map::new(),
        },
        metadata: serde_json::Map::new(),
        exclusive: true,
        expires_at: SystemTime::now() + Duration::from_millis(20),
        parent_vehicle: None,
    };
    locks.test_insert_active(lock.clone()).await;
    locks
        .test_insert_cleanup(
            lock.id.clone(),
            LockCleanupFnHelper::new(|| async { panic!("Test cleanup panic") }),
        )
        .await;
    let expiration_target =
        Locks::expiration_target(&lock).expect("Test expiration target should be representable");
    locks.schedule_expiration(&lock, expiration_target).await;

    tokio::time::timeout(Duration::from_secs(1), async {
        while locks.test_has_active(&lock.id).await {
            task::yield_now().await;
        }
    })
    .await
    .expect("Lock should expire despite cleanup panic");
    let guard = tokio::time::timeout(Duration::from_secs(1), locks.lock_idle())
        .await
        .expect("Cleanup panic must not retain transition reservation");
    drop(guard);
}
