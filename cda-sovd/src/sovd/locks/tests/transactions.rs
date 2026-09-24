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
