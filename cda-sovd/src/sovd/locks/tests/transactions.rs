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

use super::*;

fn ecu_replacement(id: &str, subject: &str) -> ActiveLock {
    test_lock(id).owner(subject).ecu("ecu-a").build()
}

/// Acquiring a functional-group lock replaces the physical tester present of
/// the ECUs it covers: after the commit succeeds, the ECU-scoped tester
/// present of each covered ECU is stopped.
#[tokio::test]
async fn functional_acquire_stops_covered_ecu_tester_present_after_commit() {
    let locks = Arc::new(Locks::new());
    let acquisition = locks.test_reservation().await;
    let new_lock = test_lock("fg-lock")
        .owner("test_user")
        .functional_group("group", ["ecu-a".to_owned(), "ecu-b".to_owned()])
        .build();
    let tester_present = TesterPresentType::Functional("group".to_owned());
    let target = Locks::expiration_target(&new_lock).expect("Expiration should be valid");
    let mut uds = MockUdsEcu::default();
    uds.expect_check_tester_present_active()
        .with(eq(tester_present.clone()))
        .times(1)
        .returning(|_| false);
    uds.expect_start_tester_present()
        .with(eq(tester_present.clone()))
        .times(1)
        .returning(|_| Ok(()));
    uds.expect_stop_tester_present()
        .with(eq(TesterPresentType::Ecu("ecu-a".to_owned())))
        .times(1)
        .returning(|_| Ok(()));
    uds.expect_stop_tester_present()
        .with(eq(TesterPresentType::Ecu("ecu-b".to_owned())))
        .times(1)
        .returning(|_| Ok(()));

    let result = run_acquisition_transaction(
        uds,
        Arc::clone(&locks),
        acquisition,
        None,
        new_lock,
        LockCleanupFnHelper::new(|| async {}),
        Some(tester_present),
        target,
    )
    .await;

    assert!(result.is_ok());
    assert!(locks.test_has_active("fg-lock").await);
}

/// When the commit itself fails, the ECU tester-present replacement must not
/// run: existing ECU tester present stays untouched so a rejected
/// acquisition cannot disturb another client's running tester present.
#[tokio::test]
async fn functional_acquire_failed_commit_does_not_stop_ecu_tester_present() {
    let locks = Arc::new(Locks::new());
    insert_test_ecu_lock(&locks, "ecu-a").await;
    let acquisition = locks.test_reservation().await;
    let replacement = test_lock("conflicting-replacement")
        .owner("other-user")
        .functional_group("group", ["ecu-a".to_owned(), "ecu-b".to_owned()])
        .build();
    let tester_present = TesterPresentType::Functional("group".to_owned());
    let target = Locks::expiration_target(&replacement).expect("Expiration should be valid");
    let mut uds = MockUdsEcu::default();
    uds.expect_check_tester_present_active()
        .with(eq(tester_present.clone()))
        .times(1)
        .returning(|_| false);
    uds.expect_start_tester_present()
        .with(eq(tester_present.clone()))
        .times(1)
        .returning(|_| Ok(()));
    // The commit fails (coverage conflict with the pre-existing "ecu-a"
    // lock owned by a different client), so only the tester present this
    // acquisition itself started is rolled back. `stop_tester_present` for
    // "ecu-a"/"ecu-b" must never be called: no expectation is configured for
    // it, so an unexpected call panics this test.
    uds.expect_stop_tester_present()
        .with(eq(tester_present.clone()))
        .times(1)
        .returning(|_| Ok(()));

    let result = run_acquisition_transaction(
        uds,
        Arc::clone(&locks),
        acquisition,
        None,
        replacement,
        LockCleanupFnHelper::new(|| async {}),
        Some(tester_present),
        target,
    )
    .await;

    assert!(result.is_err());
    assert!(!locks.test_has_active("conflicting-replacement").await);
}

/// An ECU lock acquired while the same client already holds a
/// functional-group lock covering that ECU must start no physical tester
/// present: the functional-group lock already sends functional tester
/// present to it.
#[tokio::test]
async fn ecu_lock_under_owned_functional_lock_starts_no_tp() {
    let locks = Arc::new(Locks::new());
    let fg_lock = test_lock("fg-lock")
        .owner("test_user")
        .functional_group("group", ["ecu-a".to_owned()])
        .build();
    locks.test_insert_active(fg_lock).await;

    let mut uds = MockUdsEcu::default();
    uds.expect_clone().returning(MockUdsEcu::default);

    let request = LockRequest {
        scope: LockScope::Ecu {
            name: "ecu-a".to_owned(),
        },
        principal: LockPrincipal {
            subject: "test_user".to_owned(),
            claims: serde_json::Map::new(),
        },
        expires_at: SystemTime::now()
            .checked_add(Duration::from_secs(60))
            .expect("test expiration should be representable"),
        break_lock: false,
        exclusive: true,
        metadata: serde_json::Map::new(),
    };

    let (_, _, tester_present) = create_lock(
        &uds,
        request,
        &locks,
        LockCoverage::new(["ecu-a".to_owned()]),
        Box::new(TestSecurityPlugin),
    )
    .await
    .expect("Lock creation should succeed");

    assert_eq!(
        tester_present, None,
        "an ECU lock adopted under an owned functional-group lock must not start its own physical \
         tester present"
    );
}

/// An ECU lock acquired without any covering functional-group lock starts
/// its own physical tester present as usual.
#[tokio::test]
async fn ecu_lock_without_covering_functional_lock_starts_tp() {
    let locks = Arc::new(Locks::new());

    let mut uds = MockUdsEcu::default();
    uds.expect_clone().returning(MockUdsEcu::default);

    let request = LockRequest {
        scope: LockScope::Ecu {
            name: "ecu-a".to_owned(),
        },
        principal: LockPrincipal {
            subject: "test_user".to_owned(),
            claims: serde_json::Map::new(),
        },
        expires_at: SystemTime::now()
            .checked_add(Duration::from_secs(60))
            .expect("test expiration should be representable"),
        break_lock: false,
        exclusive: true,
        metadata: serde_json::Map::new(),
    };

    let (_, _, tester_present) = create_lock(
        &uds,
        request,
        &locks,
        LockCoverage::new(["ecu-a".to_owned()]),
        Box::new(TestSecurityPlugin),
    )
    .await
    .expect("Lock creation should succeed");

    assert_eq!(
        tester_present,
        Some(TesterPresentType::Ecu("ecu-a".to_owned()))
    );
}

#[tokio::test]
async fn failed_acquisition_stops_only_new_tester_present_and_preserves_old_lock() {
    let locks = Arc::new(Locks::new());
    insert_test_ecu_lock(&locks, "ecu-a").await;
    let acquisition = locks.test_reservation().await;
    let replacement = test_lock("conflicting-replacement")
        .owner("other-user")
        .functional_group("group", ["ecu-a".to_owned()])
        .build();
    let tester_present = TesterPresentType::Functional("group".to_owned());
    let target = Locks::expiration_target(&replacement).expect("Expiration should be valid");
    let mut uds = MockUdsEcu::default();
    uds.expect_check_tester_present_active()
        .with(eq(tester_present.clone()))
        .times(1)
        .returning(|_| false);
    uds.expect_start_tester_present()
        .with(eq(tester_present.clone()))
        .times(1)
        .returning(|_| Ok(()));
    uds.expect_stop_tester_present()
        .with(eq(tester_present.clone()))
        .times(1)
        .returning(|_| Ok(()));

    let result = run_acquisition_transaction(
        uds,
        Arc::clone(&locks),
        acquisition,
        None,
        replacement,
        LockCleanupFnHelper::new(|| async {}),
        Some(tester_present),
        target,
    )
    .await;

    assert!(result.is_err());
    locks
        .core
        .read_store(|store| {
            assert!(store.state.active_by_id("test-lock-id").is_some());
            assert!(
                store
                    .state
                    .active_by_id("conflicting-replacement")
                    .is_none()
            );
        })
        .await;
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
        replacement,
        LockCleanupFnHelper::new(|| async {}),
        Some(TesterPresentType::Ecu("ecu-a".to_owned())),
        target,
    )
    .await;

    assert!(result.is_err());
    assert!(
        locks
            .core
            .read_store(|store| store.state.active_by_id("test-lock-id").is_some())
            .await
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
        replacement,
        LockCleanupFnHelper::new(|| async {}),
        Some(TesterPresentType::Ecu("ecu-a".to_owned())),
        target,
    )
    .await;

    assert!(result.is_err());
    locks
        .core
        .read_store(|store| {
            assert!(store.state.active_by_id("test-lock-id").is_some());
            assert!(store.state.active_by_id("failed-start").is_none());
        })
        .await;
}

#[tokio::test]
async fn functional_group_lock_waits_for_communication_to_settle() {
    let locks = Arc::new(Locks::new());
    let acquisition = locks.test_reservation().await;
    let replacement = test_lock("still-enabling")
        .owner("test_user")
        .functional_group("group", ["ecu-a".to_owned()])
        .build();
    let tester_present = TesterPresentType::Functional("group".to_owned());
    let target = Locks::expiration_target(&replacement).expect("Expiration should be valid");
    let mut uds = MockUdsEcu::default();
    uds.expect_check_tester_present_active()
        .times(1)
        .returning(|_| false);
    uds.expect_start_tester_present().times(1).returning(|_| {
        Err(cda_interfaces::DiagServiceError::CommunicationNotReady {
            message: "Communication is still enabling".to_owned(),
            retry_after: std::time::Duration::from_secs(3),
        })
    });
    uds.expect_stop_tester_present().times(0);

    let result = run_acquisition_transaction(
        uds,
        Arc::clone(&locks),
        acquisition,
        None,
        replacement,
        LockCleanupFnHelper::new(|| async {}),
        Some(tester_present),
        target,
    )
    .await;

    assert!(matches!(
        result,
        Err(ApiError::ServiceUnavailable {
            retry_after: Some(retry_after),
            ..
        }) if retry_after == std::time::Duration::from_secs(3)
    ));
    locks
        .core
        .read_store(|store| assert!(store.state.active_by_id("still-enabling").is_none()))
        .await;
}
