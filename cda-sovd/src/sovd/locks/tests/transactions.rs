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

async fn install_counted_cleanup(locks: &Locks, lock_id: &str) -> Arc<AtomicUsize> {
    let cleanup_count = Arc::new(AtomicUsize::new(0));
    let cleanup_count_clone = Arc::clone(&cleanup_count);
    locks.store.lock().await.cleanups.insert(
        lock_id.to_owned(),
        LockCleanupFnHelper::new(move || async move {
            cleanup_count_clone.fetch_add(1, Ordering::SeqCst);
        }),
    );
    cleanup_count
}

fn ecu_replacement(id: &str, subject: &str) -> ActiveLock {
    let mut replacement = active_test_lock(subject, true);
    replacement.id = id.to_owned();
    replacement.scope = ScopeKey::Ecu("ecu-a".to_owned());
    replacement.coverage = LockCoverage::new(["ecu-a".to_owned()]);
    replacement
}

#[tokio::test]
async fn conversion_commits_without_running_old_cleanup() {
    let locks = Arc::new(Locks::new());
    insert_test_ecu_lock(&locks, "ecu-a").await;
    let cleanup_count = install_counted_cleanup(&locks, "test-lock-id").await;
    let acquisition = locks.test_reservation().await;
    let replacement = ActiveLock {
        id: "replacement".to_owned(),
        scope: ScopeKey::FunctionalGroup("group".to_owned()),
        coverage: LockCoverage::new(["ecu-a".to_owned()]),
        principal: LockPrincipal {
            subject: "test_user".to_owned(),
            claims: serde_json::Map::new(),
        },
        metadata: serde_json::Map::new(),
        exclusive: true,
        expires_at: SystemTime::now() + Duration::from_secs(300),
        parent_vehicle: None,
    };
    let target = Locks::expiration_target(&replacement).expect("Expiration should be valid");
    let mut uds = MockUdsEcu::default();
    uds.expect_stop_tester_present()
        .with(eq(TesterPresentType::Ecu("ecu-a".to_owned())))
        .times(1)
        .returning(|_| Ok(()));
    let result = run_acquisition_transaction(
        uds,
        Arc::clone(&locks),
        acquisition,
        None,
        vec!["test-lock-id".to_owned()],
        replacement,
        LockCleanupFnHelper::new(|| async {}),
        None,
        target,
    )
    .await;

    assert_eq!(result.expect("Conversion should succeed"), "replacement");
    assert!(
        locks
            .store
            .lock()
            .await
            .state
            .active_by_id("replacement")
            .is_some()
    );
    assert!(
        locks
            .store
            .lock()
            .await
            .state
            .active_by_id("test-lock-id")
            .is_none()
    );
    assert_eq!(cleanup_count.load(Ordering::SeqCst), 0);
    assert!(!locks.test_has_cleanup("test-lock-id").await);
}

#[tokio::test]
async fn tester_present_starts_before_conversion_and_old_cleanup_is_discarded() {
    let locks = Arc::new(Locks::new());
    insert_test_ecu_lock(&locks, "ecu-a").await;
    let tester_present_started = Arc::new(AtomicBool::new(false));
    let cleanup_count = install_counted_cleanup(&locks, "test-lock-id").await;
    let acquisition = locks.test_reservation().await;
    let mut replacement = active_test_lock("test_user", true);
    replacement.id = "replacement-with-tp".to_owned();
    replacement.scope = ScopeKey::FunctionalGroup("group".to_owned());
    replacement.coverage = LockCoverage::new(["ecu-a".to_owned()]);
    let target = Locks::expiration_target(&replacement).expect("Expiration should be valid");
    let start_locks = Arc::clone(&locks);
    let started = Arc::clone(&tester_present_started);
    let mut uds = MockUdsEcu::default();
    uds.expect_check_tester_present_active()
        .times(1)
        .returning(|_| false);
    uds.expect_start_tester_present()
        .times(1)
        .returning(move |_| {
            assert!(
                start_locks
                    .store
                    .try_lock()
                    .expect("State should not be write-locked during start")
                    .state
                    .active_by_id("test-lock-id")
                    .is_some()
            );
            assert!(
                start_locks
                    .store
                    .try_lock()
                    .expect("State should not be write-locked during start")
                    .state
                    .active_by_id("replacement-with-tp")
                    .is_none()
            );
            started.store(true, Ordering::SeqCst);
            Ok(())
        });
    uds.expect_stop_tester_present()
        .with(eq(TesterPresentType::Ecu("ecu-a".to_owned())))
        .times(1)
        .returning(|_| Ok(()));

    let result = run_acquisition_transaction(
        uds,
        Arc::clone(&locks),
        acquisition,
        None,
        vec!["test-lock-id".to_owned()],
        replacement,
        LockCleanupFnHelper::new(|| async {}),
        Some(TesterPresentType::Functional("group".to_owned())),
        target,
    )
    .await;

    assert_eq!(
        result.expect("Acquisition should succeed"),
        "replacement-with-tp"
    );
    assert!(tester_present_started.load(Ordering::SeqCst));
    assert_eq!(cleanup_count.load(Ordering::SeqCst), 0);
    assert!(!locks.test_has_cleanup("test-lock-id").await);
}

#[tokio::test]
async fn failed_acquisition_stops_only_new_tester_present_and_preserves_old_lock() {
    let locks = Arc::new(Locks::new());
    insert_test_ecu_lock(&locks, "ecu-a").await;
    let acquisition = locks.test_reservation().await;
    let replacement = ecu_replacement("conflicting-replacement", "other-user");
    let target = Locks::expiration_target(&replacement).expect("Expiration should be valid");
    let mut uds = MockUdsEcu::default();
    uds.expect_check_tester_present_active()
        .times(1)
        .returning(|_| false);
    uds.expect_start_tester_present()
        .times(1)
        .returning(|_| Ok(()));
    uds.expect_stop_tester_present()
        .with(eq(TesterPresentType::Ecu("ecu-a".to_owned())))
        .times(1)
        .returning(|_| Ok(()));

    let result = run_acquisition_transaction(
        uds,
        Arc::clone(&locks),
        acquisition,
        None,
        Vec::new(),
        replacement,
        LockCleanupFnHelper::new(|| async {}),
        Some(TesterPresentType::Ecu("ecu-a".to_owned())),
        target,
    )
    .await;

    assert!(result.is_err());
    let store = locks.store.lock().await;
    let state = &store.state;
    assert!(state.active_by_id("test-lock-id").is_some());
    assert!(state.active_by_id("conflicting-replacement").is_none());
}

#[tokio::test]
async fn pre_existing_exact_tester_present_is_not_started_or_stopped_on_failure() {
    let locks = Arc::new(Locks::new());
    insert_test_ecu_lock(&locks, "ecu-a").await;
    let acquisition = locks.test_reservation().await;
    let replacement = ecu_replacement("conflicting-replacement", "other-user");
    let target = Locks::expiration_target(&replacement).expect("Expiration should be valid");
    let mut uds = MockUdsEcu::default();
    uds.expect_check_tester_present_active()
        .with(eq(TesterPresentType::Ecu("ecu-a".to_owned())))
        .times(1)
        .returning(|_| true);
    uds.expect_start_tester_present().times(0);
    uds.expect_stop_tester_present().times(0);

    let result = run_acquisition_transaction(
        uds,
        Arc::clone(&locks),
        acquisition,
        None,
        Vec::new(),
        replacement,
        LockCleanupFnHelper::new(|| async {}),
        Some(TesterPresentType::Ecu("ecu-a".to_owned())),
        target,
    )
    .await;

    assert!(result.is_err());
    assert!(
        locks
            .store
            .lock()
            .await
            .state
            .active_by_id("test-lock-id")
            .is_some()
    );
}

#[tokio::test]
async fn tester_present_start_failure_preserves_existing_state_without_stop() {
    let locks = Arc::new(Locks::new());
    insert_test_ecu_lock(&locks, "ecu-a").await;
    let acquisition = locks.test_reservation().await;
    let replacement = ecu_replacement("failed-start", "test_user");
    let target = Locks::expiration_target(&replacement).expect("Expiration should be valid");
    let mut uds = MockUdsEcu::default();
    uds.expect_check_tester_present_active()
        .times(1)
        .returning(|_| false);
    uds.expect_start_tester_present().times(1).returning(|_| {
        Err(cda_interfaces::DiagServiceError::ResourceError(
            "Start failed".to_owned(),
        ))
    });
    uds.expect_stop_tester_present().times(0);

    let result = run_acquisition_transaction(
        uds,
        Arc::clone(&locks),
        acquisition,
        None,
        vec!["test-lock-id".to_owned()],
        replacement,
        LockCleanupFnHelper::new(|| async {}),
        Some(TesterPresentType::Ecu("ecu-a".to_owned())),
        target,
    )
    .await;

    assert!(result.is_err());
    let store = locks.store.lock().await;
    let state = &store.state;
    assert!(state.active_by_id("test-lock-id").is_some());
    assert!(state.active_by_id("failed-start").is_none());
}
