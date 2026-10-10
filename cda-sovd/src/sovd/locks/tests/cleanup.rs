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

use cda_interfaces::ResetOutcome;

use super::*;
use crate::sovd::locks::acquisition::stop_tester_present_unless_needed;

/// A lock's cleanup runs after its lock was removed. When an active lock
/// still needs the same tester present (after a preemption on the same scope,
/// the new lock), the cleanup hands it over instead of stopping it.
#[tokio::test]
async fn cleanup_hands_over_tester_present_an_active_lock_still_needs() {
    let locks = Locks::new();
    insert_test_ecu_lock(&locks, "ecu-a").await;
    let mut uds = MockUdsEcu::default();
    uds.expect_stop_tester_present().times(0);

    stop_tester_present_unless_needed(&uds, &locks, TesterPresentType::Ecu("ecu-a".to_owned()))
        .await;
}

/// Without an active lock that needs the type, the cleanup stops it.
#[tokio::test]
async fn cleanup_stops_tester_present_no_active_lock_needs() {
    let locks = Locks::new();
    insert_test_ecu_lock(&locks, "ecu-b").await;
    let tp_type = TesterPresentType::Ecu("ecu-a".to_owned());
    let mut uds = MockUdsEcu::default();
    uds.expect_stop_tester_present()
        .with(eq(tp_type.clone()))
        .times(1)
        .returning(|_| Ok(()));

    stop_tester_present_unless_needed(&uds, &locks, tp_type).await;
}

#[tokio::test]
async fn test_ecu_lock_cleanup_calls_reset() {
    let (mock_uds, ecu_name, locks, session_resets, security_resets) = setup_ecu_lock_test();
    let lock_id = create_ecu_lock(&mock_uds, &locks, &ecu_name, Duration::from_secs(60)).await;

    let delete_response = delete_handler(
        &locks,
        LockScope::Ecu {
            name: ecu_name.clone(),
        },
        &lock_id,
        &TestSecurityPlugin.claims(),
        false,
    )
    .await;

    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);
    assert_eq!(session_resets.load(Ordering::SeqCst), 1);
    assert_eq!(security_resets.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_ecu_lock_cleanup_timeout_cleans() {
    let (mock_uds, ecu_name, locks, _, _) = setup_ecu_lock_test();
    create_ecu_lock(&mock_uds, &locks, &ecu_name, Duration::from_secs(1)).await;

    assert!(locks.has_non_vehicle_locks().await);
    wait_until("ECU lock expires", || async {
        !locks.has_non_vehicle_locks().await
    })
    .await;
}

#[tokio::test]
async fn test_functional_group_lock_cleanup_calls_reset_for_all_ecus() {
    let (mock_uds, fg_name, locks) = setup_functional_group_lock_test();
    let lock_id =
        create_functional_group_lock(&mock_uds, &locks, &fg_name, Duration::from_secs(1)).await;

    let delete_response = delete_handler(
        &locks,
        LockScope::FunctionalGroup {
            name: fg_name.clone(),
        },
        &lock_id,
        &TestSecurityPlugin.claims(),
        false,
    )
    .await;

    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_functional_group_lock_cleanup_timeout_cleans() {
    let (mock_uds, fg_name, locks) = setup_functional_group_lock_test();
    create_functional_group_lock(&mock_uds, &locks, &fg_name, Duration::from_secs(1)).await;

    assert!(locks.has_non_vehicle_locks().await);
    wait_until("functional group lock expires", || async {
        !locks.has_non_vehicle_locks().await
    })
    .await;
}

#[tokio::test]
async fn test_vehicle_lock_cleanup_calls_reset_for_all_ecus() {
    let (mock_uds, locks) = setup_vehicle_lock_test();
    let lock_id = create_vehicle_lock(&mock_uds, &locks, Duration::from_secs(60)).await;

    let delete_response = delete_handler(
        &locks,
        LockScope::Vehicle,
        &lock_id,
        &TestSecurityPlugin.claims(),
        false,
    )
    .await;

    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_vehicle_lock_cleanup_timeout_cleans() {
    let (mock_uds, locks) = setup_vehicle_lock_test();
    create_vehicle_lock(&mock_uds, &locks, Duration::from_secs(1)).await;

    assert!(locks.vehicle_lock_owner_sub().await.is_some());
    wait_until("vehicle lock expires", || async {
        locks.vehicle_lock_owner_sub().await.is_none()
    })
    .await;
}

fn expect_ecu_lock_cleanup_multiple(uds_ecu: &mut MockUdsEcu, ecus: &Vec<String>) {
    // Expect reset methods to be called for each ECU during cleanup
    for ecu in ecus {
        uds_ecu
            .expect_reset_ecu_session()
            .with(eq(ecu.clone()), always())
            .times(1)
            .returning(|_, _| Ok(ResetOutcome::Completed));

        uds_ecu
            .expect_reset_ecu_security_access()
            .with(eq(ecu.clone()), always())
            .times(1)
            .returning(|_, _| Ok(ResetOutcome::Completed));
    }
}

pub(super) fn setup_ecu_lock_test() -> (
    MockUdsEcu,
    String,
    Arc<Locks>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
) {
    let mut mock_uds = MockUdsEcu::default();
    let session_resets = Arc::new(AtomicUsize::new(0));
    let security_resets = Arc::new(AtomicUsize::new(0));
    let session_resets_for_clone = Arc::clone(&session_resets);
    let security_resets_for_clone = Arc::clone(&security_resets);
    let ecu_name = "test_ecu".to_string();
    let tp_type = TesterPresentType::Ecu(ecu_name.clone());
    let ecu_name_clone = ecu_name.clone();
    mock_uds.expect_clone().times(1).returning(move || {
        let mut transaction = MockUdsEcu::default();
        transaction
            .expect_check_tester_present_active()
            .with(eq(tp_type.clone()))
            .times(1)
            .returning(|_| false);
        transaction
            .expect_start_tester_present()
            .with(eq(tp_type.clone()))
            .times(1)
            .returning(|_| Ok(()));
        let cleanup_tp_type = tp_type.clone();
        let cleanup_ecu_name = ecu_name_clone.clone();
        let session_resets = Arc::clone(&session_resets_for_clone);
        let security_resets = Arc::clone(&security_resets_for_clone);
        transaction.expect_clone().times(1).returning(move || {
            let mut cleanup = MockUdsEcu::default();
            let session_resets = Arc::clone(&session_resets);
            let security_resets = Arc::clone(&security_resets);
            cleanup
                .expect_stop_tester_present()
                .with(eq(cleanup_tp_type.clone()))
                .times(1)
                .returning(|_| Ok(()));
            cleanup
                .expect_reset_ecu_session()
                .with(eq(cleanup_ecu_name.clone()), always())
                .times(1)
                .returning(move |_, _| {
                    session_resets.fetch_add(1, Ordering::SeqCst);
                    Ok(ResetOutcome::Completed)
                });
            cleanup
                .expect_reset_ecu_security_access()
                .with(eq(cleanup_ecu_name.clone()), always())
                .times(1)
                .returning(move |_, _| {
                    security_resets.fetch_add(1, Ordering::SeqCst);
                    Ok(ResetOutcome::Completed)
                });
            cleanup
        });
        transaction
    });

    let locks = Arc::new(Locks::new());
    (mock_uds, ecu_name, locks, session_resets, security_resets)
}

pub(super) async fn create_ecu_lock(
    mock_uds: &MockUdsEcu,
    locks: &Arc<Locks>,
    ecu_name: &str,
    expiration: Duration,
) -> String {
    let expiration = sovd_interfaces::locking::Request {
        lock_expiration: expiration.as_secs(),
        break_lock: false,
        x_sovd2uds_isexclusive: None,
        metadata: serde_json::Map::new(),
    };
    let claims = TestSecurityPlugin.claims();
    let (acquisition, pending, request) = locks
        .evaluate_acquisition(
            LockScope::Ecu {
                name: ecu_name.to_owned(),
            },
            LockCoverage::new([ecu_name.to_owned()]),
            &expiration,
            &claims,
        )
        .await
        .expect("Lock request should resolve");

    let security_plugin = Box::new(TestSecurityPlugin);
    let response = post_handler(
        mock_uds,
        LockContext {
            all_locks: locks,
            acquisition,
            pending,
            coverage: LockCoverage::new([ecu_name.to_owned()]),
        },
        request,
        "/vehicle/v15/components/test_ecu/locks",
        false,
        security_plugin,
    )
    .await;

    assert_eq!(response.status(), StatusCode::CREATED);
    let lock_response: sovd_interfaces::locking::post_put::Response = axum_response_into(response)
        .await
        .expect("failed to extract response");
    lock_response.id
}

fn setup_functional_group_lock_test() -> (MockUdsEcu, String, Arc<Locks>) {
    let mut mock_uds = MockUdsEcu::default();
    let fg_name = "test_fg".to_string();
    let tp_type = TesterPresentType::Functional(fg_name.clone());
    mock_uds.expect_clone().times(1).returning(move || {
        let mut transaction = MockUdsEcu::default();
        transaction
            .expect_check_tester_present_active()
            .with(eq(tp_type.clone()))
            .times(1)
            .returning(|_| false);
        transaction
            .expect_start_tester_present()
            .with(eq(tp_type.clone()))
            .times(1)
            .returning(|_| Ok(()));
        // Acquiring the functional-group lock replaces the physical tester
        // present of the ECUs it covers; this runs once the commit succeeds.
        for ecu in ["ecu1", "ecu2"] {
            transaction
                .expect_stop_tester_present()
                .with(eq(TesterPresentType::Ecu(ecu.to_owned())))
                .times(1)
                .returning(|_| Ok(()));
        }
        let cleanup_tp_type = tp_type.clone();
        transaction.expect_clone().times(1).returning(move || {
            let mut cleanup = MockUdsEcu::default();
            cleanup
                .expect_stop_tester_present()
                .with(eq(cleanup_tp_type.clone()))
                .times(1)
                .returning(|_| Ok(()));
            let cleanup_ecus = vec!["ecu1".to_owned(), "ecu2".to_owned()];
            expect_ecu_lock_cleanup_multiple(&mut cleanup, &cleanup_ecus);
            cleanup
        });
        transaction
    });

    let locks = Arc::new(Locks::new());
    (mock_uds, fg_name, locks)
}

async fn create_functional_group_lock(
    mock_uds: &MockUdsEcu,
    locks: &Arc<Locks>,
    fg_name: &str,
    expiration: Duration,
) -> String {
    let expiration = sovd_interfaces::locking::Request {
        lock_expiration: expiration.as_secs(),
        break_lock: false,
        x_sovd2uds_isexclusive: None,
        metadata: serde_json::Map::new(),
    };
    let claims = TestSecurityPlugin.claims();
    let (acquisition, _, request) = locks
        .evaluate_acquisition(
            LockScope::FunctionalGroup {
                name: fg_name.to_owned(),
            },
            LockCoverage::new(["ecu1".to_owned(), "ecu2".to_owned()]),
            &expiration,
            &claims,
        )
        .await
        .expect("Lock request should resolve");

    let security_plugin = Box::new(TestSecurityPlugin);
    let response = post_handler(
        mock_uds,
        LockContext {
            all_locks: locks,
            acquisition,
            pending: None,
            coverage: LockCoverage::new(["ecu1".to_owned(), "ecu2".to_owned()]),
        },
        request,
        "/vehicle/v15/functions/functionalgroups/test_fg/locks",
        false,
        security_plugin,
    )
    .await;

    assert_eq!(response.status(), StatusCode::CREATED);
    let lock_response: sovd_interfaces::locking::post_put::Response = axum_response_into(response)
        .await
        .expect("failed to extract response");
    lock_response.id
}

fn setup_vehicle_lock_test() -> (MockUdsEcu, Arc<Locks>) {
    setup_vehicle_lock_test_with_policy(Arc::new(cda_plugin_lock_priority::NoPreemptionPolicy))
}

pub(super) fn setup_vehicle_lock_test_with_policy(
    policy: Arc<dyn LockPriorityPolicy>,
) -> (MockUdsEcu, Arc<Locks>) {
    let mut mock_uds = MockUdsEcu::default();
    mock_uds.expect_clone().times(1).returning(|| {
        let mut transaction = MockUdsEcu::default();
        transaction
            .expect_clone()
            .times(1)
            .returning(expect_vehicle_lock_cleanup);
        transaction
    });

    let locks = Arc::new(Locks::new_with_policy(policy));
    (mock_uds, locks)
}

async fn create_vehicle_lock(
    mock_uds: &MockUdsEcu,
    locks: &Arc<Locks>,
    expiration: Duration,
) -> String {
    let expiration = sovd_interfaces::locking::Request {
        lock_expiration: expiration.as_secs(),
        break_lock: false,
        x_sovd2uds_isexclusive: None,
        metadata: serde_json::Map::new(),
    };
    let claims = TestSecurityPlugin.claims();
    let (acquisition, pending, request) = locks
        .evaluate_acquisition(
            LockScope::Vehicle,
            LockCoverage::vehicle(),
            &expiration,
            &claims,
        )
        .await
        .expect("Lock request should resolve");

    let security_plugin = Box::new(TestSecurityPlugin);
    let response = post_handler(
        mock_uds,
        LockContext {
            all_locks: locks,
            acquisition,
            pending,
            coverage: LockCoverage::vehicle(),
        },
        request,
        "/vehicle/v15/locks",
        false,
        security_plugin,
    )
    .await;

    assert_eq!(response.status(), StatusCode::CREATED);
    let lock_response: sovd_interfaces::locking::post_put::Response = axum_response_into(response)
        .await
        .expect("failed to extract response");
    lock_response.id
}

#[tokio::test]
async fn creation_and_deletion_notify_registered_policy() {
    let policy = Arc::new(EventRecordingPolicy::default());
    let (mock_uds, locks) =
        setup_vehicle_lock_test_with_policy(Arc::<EventRecordingPolicy>::clone(&policy));

    let lock_id = create_vehicle_lock(&mock_uds, &locks, Duration::from_secs(60)).await;
    await_events(&policy, 1).await;
    {
        let events = policy.events.lock().expect("event mutex poisoned");
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events.first(),
            Some(LockLifecycleEvent::Created { .. })
        ));
    }
    let child = ActiveLock {
        id: "released-child".into(),
        scope: ScopeKey::Ecu("child".to_owned()),
        coverage: LockCoverage::default(),
        principal: LockPrincipal {
            subject: TestSecurityPlugin.claims().sub().to_owned(),
            claims: serde_json::Map::new(),
        },
        metadata: serde_json::Map::new(),
        exclusive: true,
        expires_at: SystemTime::now() + Duration::from_secs(60),
        parent_vehicle_lock_id: Some(lock_id.clone().into()),
    };
    locks
        .test_mutate_store(|store| {
            store
                .state
                .insert_active(child.clone())
                .expect("Vehicle child insertion should succeed");
        })
        .await;

    let delete_response = delete_handler(
        &locks,
        LockScope::Vehicle,
        &lock_id,
        &TestSecurityPlugin.claims(),
        false,
    )
    .await;
    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);

    await_events(&policy, 3).await;
    let events = policy.events.lock().expect("event mutex poisoned");
    assert_eq!(events.len(), 3);
    assert!(matches!(
        events.get(1),
        Some(LockLifecycleEvent::Released { lock })
            if lock.id == child.id && matches!(lock.scope, LockScope::Ecu { .. })
    ));
    assert!(matches!(
        events.get(2),
        Some(LockLifecycleEvent::Released { lock })
            if lock.id.as_str() == lock_id && lock.scope == LockScope::Vehicle
    ));
}

fn expect_vehicle_lock_cleanup() -> MockUdsEcu {
    let mut cloned = MockUdsEcu::default();

    let ecus = vec!["ecu1".to_owned(), "ecu2".to_owned()];
    let ecu_clone = ecus.clone();

    // Expect to get all ECUs during cleanup
    cloned
        .expect_get_ecus()
        .times(1)
        .returning(move || ecu_clone.clone());

    expect_ecu_lock_cleanup_multiple(&mut cloned, &ecus);

    cloned
}

/// Inserts an active lock together with a cleanup that only counts
/// invocations, bypassing `create_lock`/`MockUdsEcu` entirely. This isolates
/// lock-state removal and cleanup-skip behavior from tester-present and
/// session/security wiring, which is covered separately in `transactions.rs`.
async fn insert_lock_with_counted_cleanup(locks: &Locks, lock: ActiveLock) -> Arc<AtomicUsize> {
    let count = Arc::new(AtomicUsize::new(0));
    let count_for_closure = Arc::clone(&count);
    let lock_id = lock.id.clone();
    locks.test_insert_active(lock).await;
    locks
        .test_insert_cleanup(
            lock_id,
            LockCleanupFnHelper::new(move || async move {
                count_for_closure.fetch_add(1, Ordering::SeqCst);
            }),
        )
        .await;
    count
}

#[tokio::test]
async fn ecu_lock_release_under_functional_lock_skips_cleanup() {
    let locks = Arc::new(Locks::new());
    let ecu_lock = test_lock("ecu-lock")
        .owner("test_user")
        .ecu("ecu-a")
        .build();
    let ecu_cleanup_count = insert_lock_with_counted_cleanup(&locks, ecu_lock).await;
    let fg_lock = test_lock("fg-lock")
        .owner("test_user")
        .functional_group("group", ["ecu-a".to_owned()])
        .build();
    insert_lock_with_counted_cleanup(&locks, fg_lock).await;

    let delete_response = delete_handler(
        &locks,
        LockScope::Ecu {
            name: "ecu-a".to_owned(),
        },
        "ecu-lock",
        &TestSecurityPlugin.claims(),
        false,
    )
    .await;

    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);
    assert!(!locks.test_has_active("ecu-lock").await);
    assert!(locks.test_has_active("fg-lock").await);
    assert_eq!(
        ecu_cleanup_count.load(Ordering::SeqCst),
        0,
        "cleanup must be skipped while the functional-group lock still covers this ECU"
    );
}

#[tokio::test]
async fn ecu_lock_release_after_functional_lock_gone_runs_cleanup() {
    let locks = Arc::new(Locks::new());
    let ecu_lock = test_lock("ecu-lock")
        .owner("test_user")
        .ecu("ecu-a")
        .build();
    let ecu_cleanup_count = insert_lock_with_counted_cleanup(&locks, ecu_lock).await;
    let fg_lock = test_lock("fg-lock")
        .owner("test_user")
        .functional_group("group", ["ecu-a".to_owned()])
        .build();
    insert_lock_with_counted_cleanup(&locks, fg_lock).await;

    // The functional-group lock is gone before the ECU lock is released on
    // its own.
    let fg_delete_response = delete_handler(
        &locks,
        LockScope::FunctionalGroup {
            name: "group".to_owned(),
        },
        "fg-lock",
        &TestSecurityPlugin.claims(),
        false,
    )
    .await;
    assert_eq!(fg_delete_response.status(), StatusCode::NO_CONTENT);
    assert!(
        !locks.test_has_active("ecu-lock").await,
        "the functional-group lock release must also release the covered ECU lock"
    );
    assert_eq!(
        ecu_cleanup_count.load(Ordering::SeqCst),
        1,
        "the covered ECU lock's cleanup runs too: it has no surviving functional-group lock once \
         the functional-group lock that covered it is gone"
    );

    // Re-insert an ECU lock to exercise an independent release once no
    // functional-group lock covers it.
    let ecu_lock_again = test_lock("ecu-lock-2")
        .owner("test_user")
        .ecu("ecu-a")
        .build();
    let ecu_cleanup_count_again = insert_lock_with_counted_cleanup(&locks, ecu_lock_again).await;

    let delete_response = delete_handler(
        &locks,
        LockScope::Ecu {
            name: "ecu-a".to_owned(),
        },
        "ecu-lock-2",
        &TestSecurityPlugin.claims(),
        false,
    )
    .await;

    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        ecu_cleanup_count_again.load(Ordering::SeqCst),
        1,
        "cleanup must run once no functional-group lock covers the ECU"
    );
}

#[tokio::test]
async fn functional_release_removes_covered_ecu_lock_and_runs_both_cleanups() {
    let locks = Arc::new(Locks::new());
    let ecu_lock = test_lock("ecu-lock")
        .owner("test_user")
        .ecu("ecu-a")
        .build();
    let ecu_cleanup_count = insert_lock_with_counted_cleanup(&locks, ecu_lock).await;
    let fg_lock = test_lock("fg-lock")
        .owner("test_user")
        .functional_group("group", ["ecu-a".to_owned()])
        .build();
    let fg_cleanup_count = insert_lock_with_counted_cleanup(&locks, fg_lock).await;

    let delete_response = delete_handler(
        &locks,
        LockScope::FunctionalGroup {
            name: "group".to_owned(),
        },
        "fg-lock",
        &TestSecurityPlugin.claims(),
        false,
    )
    .await;

    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);
    assert!(!locks.test_has_active("fg-lock").await);
    assert!(!locks.test_has_active("ecu-lock").await);
    assert_eq!(ecu_cleanup_count.load(Ordering::SeqCst), 1);
    assert_eq!(fg_cleanup_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn functional_release_keeps_uncovered_and_foreign_ecu_locks() {
    let locks = Arc::new(Locks::new());
    let fg_lock = test_lock("fg-lock")
        .owner("test_user")
        .functional_group("group", ["ecu-a".to_owned()])
        .build();
    insert_lock_with_counted_cleanup(&locks, fg_lock).await;
    let uncovered_lock = test_lock("uncovered-lock")
        .owner("test_user")
        .ecu("ecu-b")
        .build();
    let uncovered_cleanup_count = insert_lock_with_counted_cleanup(&locks, uncovered_lock).await;
    let foreign_lock = test_lock("foreign-lock")
        .owner("other_user")
        .ecu("ecu-c")
        .build();
    let foreign_cleanup_count = insert_lock_with_counted_cleanup(&locks, foreign_lock).await;

    let delete_response = delete_handler(
        &locks,
        LockScope::FunctionalGroup {
            name: "group".to_owned(),
        },
        "fg-lock",
        &TestSecurityPlugin.claims(),
        false,
    )
    .await;

    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);
    assert!(locks.test_has_active("uncovered-lock").await);
    assert!(locks.test_has_active("foreign-lock").await);
    assert_eq!(uncovered_cleanup_count.load(Ordering::SeqCst), 0);
    assert_eq!(foreign_cleanup_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn ecu_lock_expiry_under_functional_lock_skips_cleanup() {
    let locks = Arc::new(Locks::new());
    let ecu_lock = test_lock("ecu-lock")
        .owner("test_user")
        .ecu("ecu-a")
        .expires_at(
            SystemTime::now()
                .checked_add(Duration::from_millis(50))
                .expect("test expiration should be representable"),
        )
        .build();
    let ecu_cleanup_count = insert_lock_with_counted_cleanup(&locks, ecu_lock.clone()).await;
    let fg_lock = test_lock("fg-lock")
        .owner("test_user")
        .functional_group("group", ["ecu-a".to_owned()])
        .build();
    insert_lock_with_counted_cleanup(&locks, fg_lock).await;

    let target = Locks::expiration_target(&ecu_lock).expect("Expiration should be valid");
    locks.schedule_expiration(&ecu_lock, target).await;

    wait_until("ECU lock expires", || async {
        !locks.test_has_active("ecu-lock").await
    })
    .await;

    assert!(locks.test_has_active("fg-lock").await);
    assert_eq!(
        ecu_cleanup_count.load(Ordering::SeqCst),
        0,
        "cleanup must be skipped on expiry while the functional-group lock still covers this ECU"
    );
}
