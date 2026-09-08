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

#[tokio::test]
async fn child_lock_created_under_owned_vehicle_has_parent() {
    let (mock_uds, ecu_name, locks) = setup_ecu_lock_test();
    let vehicle = ActiveLock {
        id: "vehicle".to_owned(),
        scope: ScopeKey::Vehicle,
        coverage: LockCoverage::vehicle(),
        principal: LockPrincipal {
            subject: "test_user".to_owned(),
            claims: serde_json::Map::new(),
        },
        metadata: serde_json::Map::new(),
        exclusive: true,
        expires_at: SystemTime::now() + Duration::from_secs(300),
        parent_vehicle: None,
    };
    locks.test_insert_active(vehicle).await;

    let lock_id = create_ecu_lock(&mock_uds, &locks, &ecu_name, Duration::from_secs(60)).await;

    assert_eq!(
        locks
            .store
            .lock()
            .await
            .state
            .active_by_id(&lock_id)
            .and_then(|lock| lock.parent_vehicle.as_deref()),
        Some("vehicle")
    );
}
#[tokio::test]
async fn test_ecu_lock_cleanup_calls_reset() {
    let (mock_uds, ecu_name, locks) = setup_ecu_lock_test();
    #[allow(
        unknown_lints,
        clippy::duration_suboptimal_units,
        reason = "Literal duration for test clarity. Lint not available in all toolchains"
    )]
    let lock_id = create_ecu_lock(&mock_uds, &locks, &ecu_name, Duration::from_secs(60)).await;

    let delete_response = delete_handler(
        &locks,
        LockTarget::Ecu,
        LockScope::Ecu {
            name: ecu_name.clone(),
        },
        &lock_id,
        &TestSecurityPlugin.claims(),
        Some(&ecu_name),
        false,
    )
    .await;

    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_ecu_lock_cleanup_timeout_cleans() {
    let (mock_uds, ecu_name, locks) = setup_ecu_lock_test();
    create_ecu_lock(&mock_uds, &locks, &ecu_name, Duration::from_secs(1)).await;

    assert!(locks.has_non_vehicle_locks().await);
    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(2)).await;
    assert!(!locks.has_non_vehicle_locks().await);
}

#[tokio::test]
async fn test_functional_group_lock_cleanup_calls_reset_for_all_ecus() {
    let (mock_uds, fg_name, locks) = setup_functional_group_lock_test();
    let lock_id =
        create_functional_group_lock(&mock_uds, &locks, &fg_name, Duration::from_secs(1)).await;

    let delete_response = delete_handler(
        &locks,
        LockTarget::FunctionalGroup,
        LockScope::FunctionalGroup {
            name: fg_name.clone(),
        },
        &lock_id,
        &TestSecurityPlugin.claims(),
        Some(&fg_name),
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
    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(2)).await;
    assert!(!locks.has_non_vehicle_locks().await);
}

#[tokio::test]
async fn test_vehicle_lock_cleanup_calls_reset_for_all_ecus() {
    let (mock_uds, locks) = setup_vehicle_lock_test();
    #[allow(
        unknown_lints,
        clippy::duration_suboptimal_units,
        reason = "Literal duration for test clarity. Lint not available in all toolchains"
    )]
    let lock_id = create_vehicle_lock(&mock_uds, &locks, Duration::from_secs(60)).await;

    let delete_response = delete_handler(
        &locks,
        LockTarget::Vehicle,
        LockScope::Vehicle,
        &lock_id,
        &TestSecurityPlugin.claims(),
        None,
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
    cda_interfaces::util::tokio_ext::sleep_for(Duration::from_secs(2)).await;
    assert!(locks.vehicle_lock_owner_sub().await.is_none());
}

pub fn init_locks() -> Arc<Locks> {
    Arc::new(Locks::new())
}

fn expect_ecu_lock_cleanup_multiple(uds_ecu: &mut MockUdsEcu, ecus: &Vec<String>) {
    // Expect reset methods to be called for each ECU during cleanup
    for ecu in ecus {
        uds_ecu
            .expect_reset_ecu_session()
            .with(eq(ecu.clone()), always())
            .times(1)
            .returning(|_, _| Ok(()));

        uds_ecu
            .expect_reset_ecu_security_access()
            .with(eq(ecu.clone()), always())
            .times(1)
            .returning(|_, _| Ok(()));
    }
}

fn setup_ecu_lock_test() -> (MockUdsEcu, String, Arc<Locks>) {
    let mut mock_uds = MockUdsEcu::default();
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
        transaction.expect_clone().times(1).returning(move || {
            let mut cleanup = MockUdsEcu::default();
            cleanup
                .expect_stop_tester_present()
                .with(eq(cleanup_tp_type.clone()))
                .times(1)
                .returning(|_| Ok(()));
            cleanup
                .expect_reset_ecu_session()
                .with(eq(cleanup_ecu_name.clone()), always())
                .times(1)
                .returning(|_, _| Ok(()));
            cleanup
                .expect_reset_ecu_security_access()
                .with(eq(cleanup_ecu_name.clone()), always())
                .times(1)
                .returning(|_, _| Ok(()));
            cleanup
        });
        transaction
    });

    let locks = init_locks();
    (mock_uds, ecu_name, locks)
}

async fn create_ecu_lock(
    mock_uds: &MockUdsEcu,
    locks: &Arc<Locks>,
    ecu_name: &String,
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
                name: ecu_name.clone(),
            },
            LockCoverage::new([ecu_name.clone()]),
            &expiration,
            &claims,
        )
        .await
        .expect("Lock request should resolve");

    let security_plugin = Box::new(TestSecurityPlugin);
    let response = post_handler(
        mock_uds,
        LockContext {
            lock: LockTarget::Ecu,
            all_locks: locks,
            acquisition,
            pending,
            converted_lock_ids: Vec::new(),
            coverage: LockCoverage::new([ecu_name.clone()]),
        },
        Some(ecu_name),
        request,
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

    let locks = init_locks();
    (mock_uds, fg_name, locks)
}

async fn create_functional_group_lock(
    mock_uds: &MockUdsEcu,
    locks: &Arc<Locks>,
    fg_name: &String,
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
                name: fg_name.clone(),
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
            lock: LockTarget::FunctionalGroup,
            all_locks: locks,
            acquisition,
            pending: None,
            converted_lock_ids: Vec::new(),
            coverage: LockCoverage::new(["ecu1".to_owned(), "ecu2".to_owned()]),
        },
        Some(fg_name),
        request,
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

fn setup_vehicle_lock_test_with_policy(
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
            LockCoverage::default(),
            &expiration,
            &claims,
        )
        .await
        .expect("Lock request should resolve");

    let security_plugin = Box::new(TestSecurityPlugin);
    let response = post_handler(
        mock_uds,
        LockContext {
            lock: LockTarget::Vehicle,
            all_locks: locks,
            acquisition,
            pending,
            converted_lock_ids: Vec::new(),
            coverage: LockCoverage::vehicle(),
        },
        None,
        request,
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

    #[allow(
        unknown_lints,
        clippy::duration_suboptimal_units,
        reason = "Literal duration for test clarity. Lint not available in all toolchains"
    )]
    let lock_id = create_vehicle_lock(&mock_uds, &locks, Duration::from_secs(60)).await;
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if !policy
                .events
                .lock()
                .expect("event mutex poisoned")
                .is_empty()
            {
                break;
            }
            task::yield_now().await;
        }
    })
    .await
    .expect("Created event should be delivered");
    {
        let events = policy.events.lock().expect("event mutex poisoned");
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events.first(),
            Some(LockLifecycleEvent::Created { .. })
        ));
    }
    let child = ActiveLock {
        id: "released-child".to_owned(),
        scope: ScopeKey::Ecu("child".to_owned()),
        coverage: LockCoverage::default(),
        principal: LockPrincipal {
            subject: TestSecurityPlugin.claims().sub().to_owned(),
            claims: serde_json::Map::new(),
        },
        metadata: serde_json::Map::new(),
        exclusive: true,
        expires_at: SystemTime::now() + Duration::from_secs(60),
        parent_vehicle: Some(lock_id.clone()),
    };
    locks
        .store
        .lock()
        .await
        .state
        .insert_active(child.clone())
        .expect("Vehicle child insertion should succeed");

    let delete_response = delete_handler(
        &locks,
        LockTarget::Vehicle,
        LockScope::Vehicle,
        &lock_id,
        &TestSecurityPlugin.claims(),
        None,
        false,
    )
    .await;
    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if policy.events.lock().expect("event mutex poisoned").len() >= 3 {
                break;
            }
            task::yield_now().await;
        }
    })
    .await
    .expect("Released event should be delivered");
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
            if lock.id == lock_id && lock.scope == LockScope::Vehicle
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
