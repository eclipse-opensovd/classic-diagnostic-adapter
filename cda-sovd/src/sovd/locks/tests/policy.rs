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
async fn priority_policy_receives_claims_metadata_and_active_locks() {
    let cleanup_count = Arc::new(AtomicUsize::new(0));
    let policy = Arc::new(TestPolicy {
        decision: Some(LockPriorityDecision::Preempt {
            lock_ids: vec!["existing-lock".to_owned()],
            broken_by: "priority-app".to_owned(),
        }),
        evaluations: StdMutex::new(Vec::new()),
    });
    let locks = locks_with_policy(Arc::<TestPolicy>::clone(&policy));
    insert_policy_test_lock(&locks, cleanup_count).await;
    let mut attributes = serde_json::Map::new();
    attributes.insert("application".to_owned(), serde_json::json!("cda"));
    let claims = TestClaims {
        subject: "priority-client".to_owned(),
        attributes,
    };
    let mut metadata = serde_json::Map::new();
    metadata.insert("x-vendor-use-case".to_owned(), serde_json::json!("flash"));
    let request = sovd_interfaces::locking::Request {
        lock_expiration: 60,
        break_lock: true,
        x_sovd2uds_isexclusive: Some(false),
        metadata,
    };

    let (acquisition, pending, _) = locks
        .evaluate_acquisition(
            LockScope::Vehicle,
            LockCoverage::default(),
            &request,
            &claims,
        )
        .await
        .expect("policy evaluation must succeed");
    let pending = pending.expect("preemption must be staged");

    {
        let evaluations = policy.evaluations.lock().expect("policy mutex poisoned");
        assert_eq!(evaluations.len(), 1);
        let evaluation = evaluations.first().expect("one evaluation was recorded");
        let policy_request = &evaluation.request;
        assert_eq!(policy_request.principal.subject, "priority-client");
        assert!(!policy_request.exclusive);
        assert_eq!(
            policy_request.principal.claims.get("application"),
            Some(&serde_json::json!("cda"))
        );
        assert_eq!(
            policy_request.metadata.get("x-vendor-use-case"),
            Some(&serde_json::json!("flash"))
        );
        assert_eq!(evaluation.active_locks.len(), 1);
    }
    pending.rollback();
    acquisition.finish().await;
    assert!(locks.vehicle_lock_owner_sub().await.is_some());
}

#[tokio::test]
async fn ecu_and_fg_scope_acquisition_never_invokes_priority_policy() {
    // req~sovd-api-lock-priority: the priority mechanism is applicable to
    // vehicle locks only; ECU and functional-group acquisitions must never
    // invoke the plugin, even when one is registered.
    let policy = Arc::new(TestPolicy {
        decision: Some(LockPriorityDecision::Allow),
        evaluations: StdMutex::new(Vec::new()),
    });
    let locks = locks_with_policy(Arc::<TestPolicy>::clone(&policy));
    let claims = TestClaims {
        subject: "priority-client".to_owned(),
        attributes: serde_json::Map::new(),
    };

    let (ecu_acquisition, pending, _) = locks
        .evaluate_acquisition(
            LockScope::Ecu {
                name: "ecu-a".to_owned(),
            },
            LockCoverage::new(["ecu-a".to_owned()]),
            &preemption_request(),
            &claims,
        )
        .await
        .expect("ECU-scope acquisition must succeed without invoking the policy");
    assert!(pending.is_none());
    ecu_acquisition.finish().await;

    let (acquisition, pending, _) = locks
        .evaluate_acquisition(
            LockScope::FunctionalGroup {
                name: "fg-a".to_owned(),
            },
            LockCoverage::new(["ecu-a".to_owned()]),
            &preemption_request(),
            &claims,
        )
        .await
        .expect("Functional-group-scope acquisition must succeed without invoking the policy");
    assert!(pending.is_none());
    acquisition.finish().await;

    let evaluations = policy
        .evaluations
        .lock()
        .expect("policy evaluation mutex poisoned");
    assert!(
        evaluations.is_empty(),
        "policy must never be evaluated for ECU or functional-group scope"
    );
}

#[tokio::test]
async fn uncontended_vehicle_acquisition_never_invokes_priority_policy() {
    let policy = Arc::new(TestPolicy {
        decision: Some(LockPriorityDecision::Deny {
            reason: "Must not be evaluated".to_owned(),
            parameters: serde_json::Map::new(),
        }),
        evaluations: StdMutex::new(Vec::new()),
    });
    let locks = locks_with_policy(Arc::<TestPolicy>::clone(&policy));

    let result = locks
        .evaluate_acquisition(
            LockScope::Vehicle,
            LockCoverage::default(),
            &preemption_request(),
            &TestClaims {
                subject: "priority-client".to_owned(),
                attributes: serde_json::Map::new(),
            },
        )
        .await;

    assert!(result.is_ok());
    assert!(
        policy
            .evaluations
            .lock()
            .expect("Policy mutex poisoned")
            .is_empty()
    );
}

#[tokio::test]
async fn default_policy_preserves_normal_lock_conflict() {
    let locks = Arc::new(Locks::new());
    insert_policy_test_lock(&locks, Arc::new(AtomicUsize::new(0))).await;
    let claims = TestClaims {
        subject: "other-client".to_owned(),
        attributes: serde_json::Map::new(),
    };

    let (acquisition, pending, request) = locks
        .evaluate_acquisition(
            LockScope::Vehicle,
            LockCoverage::default(),
            &preemption_request(),
            &claims,
        )
        .await
        .expect("No-preemption policy evaluation should succeed");
    let response = post_handler(
        &MockUdsEcu::default(),
        LockContext {
            lock: LockTarget::Vehicle,
            all_locks: &locks,
            acquisition,
            pending,
            converted_lock_ids: Vec::new(),
            coverage: LockCoverage::default(),
        },
        None,
        request,
        false,
        Box::new(TestSecurityPlugin),
    )
    .await;

    assert_eq!(response.status(), StatusCode::LOCKED);
}

#[tokio::test]
async fn vehicle_policy_receives_all_open_locks_as_candidates() {
    // The lock priority mechanism is applicable to vehicle locks only
    // (req~sovd-api-lock-priority); a vehicle-scope acquisition offers every
    // Open active lock as a preemption candidate, regardless of coverage.
    let policy = Arc::new(TestPolicy {
        decision: Some(LockPriorityDecision::Allow),
        evaluations: StdMutex::new(Vec::new()),
    });
    let locks = locks_with_policy(Arc::<TestPolicy>::clone(&policy));
    insert_test_ecu_lock(&locks, "ecu-a").await;
    let unrelated = ActiveLock {
        id: "unrelated-lock".to_owned(),
        scope: ScopeKey::Ecu("ecu-b".to_owned()),
        coverage: LockCoverage::new(["ecu-b".to_owned()]),
        principal: LockPrincipal {
            subject: "other-client".to_owned(),
            claims: serde_json::Map::new(),
        },
        metadata: serde_json::Map::new(),
        exclusive: true,
        expires_at: SystemTime::now()
            .checked_add(Duration::from_secs(300))
            .expect("test expiration should be representable"),
        parent_vehicle: None,
    };
    locks.test_insert_active(unrelated).await;
    let request = sovd_interfaces::locking::Request {
        lock_expiration: 60,
        break_lock: false,
        x_sovd2uds_isexclusive: None,
        metadata: serde_json::Map::new(),
    };

    let (acquisition, pending, _) = locks
        .evaluate_acquisition(
            LockScope::Vehicle,
            LockCoverage::new(["ecu-a".to_owned(), "ecu-b".to_owned()]),
            &request,
            &TestClaims {
                subject: "priority-client".to_owned(),
                attributes: serde_json::Map::new(),
            },
        )
        .await
        .expect("policy evaluation must succeed");

    assert!(pending.is_none());
    acquisition.finish().await;
    let evaluations = policy
        .evaluations
        .lock()
        .expect("policy evaluation mutex poisoned");
    let evaluation = evaluations.first().expect("one evaluation expected");
    assert_eq!(evaluation.operation, LockPriorityOperation::Acquire);
    assert_eq!(evaluation.revision, 2);
    assert_eq!(evaluation.active_locks.len(), 2);
    let mut candidates = evaluation.preemption_candidates.clone();
    candidates.sort();
    assert_eq!(candidates, ["test-lock-id", "unrelated-lock"]);
}

#[tokio::test]
async fn same_owner_post_renew_never_invokes_priority_policy() {
    let policy = Arc::new(TestPolicy {
        decision: Some(LockPriorityDecision::Allow),
        evaluations: StdMutex::new(Vec::new()),
    });
    let locks = locks_with_policy(Arc::<TestPolicy>::clone(&policy));
    let expires_at = SystemTime::now()
        .checked_add(Duration::from_secs(300))
        .expect("Test expiration should be representable");
    let principal = LockPrincipal {
        subject: "priority-client".to_owned(),
        claims: serde_json::Map::new(),
    };
    let vehicle = ActiveLock {
        id: "vehicle-lock".to_owned(),
        scope: ScopeKey::Vehicle,
        coverage: LockCoverage::vehicle(),
        principal: principal.clone(),
        metadata: serde_json::Map::new(),
        exclusive: true,
        expires_at,
        parent_vehicle: None,
    };
    let child = ActiveLock {
        id: "child-lock".to_owned(),
        scope: ScopeKey::Ecu("ecu-a".to_owned()),
        coverage: LockCoverage::new(["ecu-a".to_owned()]),
        principal,
        metadata: serde_json::Map::new(),
        exclusive: true,
        expires_at,
        parent_vehicle: Some("vehicle-lock".to_owned()),
    };
    {
        let mut store = locks.store.lock().await;
        let state = &mut store.state;
        state.insert_active(vehicle).unwrap();
        state.insert_active(child).unwrap();
    }

    let (acquisition, pending, _request) = locks
        .evaluate_acquisition(
            LockScope::Vehicle,
            LockCoverage::new(["ECU-B".to_owned(), "ecu-a".to_owned()]),
            &preemption_request(),
            &TestClaims {
                subject: "priority-client".to_owned(),
                attributes: serde_json::Map::new(),
            },
        )
        .await
        .expect("Policy evaluation should succeed");

    assert!(pending.is_none());
    acquisition.finish().await;
    let evaluations = policy.evaluations.lock().expect("Policy mutex poisoned");
    assert!(evaluations.is_empty());
}

#[tokio::test]
async fn policy_denial_maps_cda_vendor_code_to_top_level() {
    let locks = Locks::new_with_policy(Arc::new(TestPolicy {
        decision: Some(LockPriorityDecision::Deny {
            reason: "Denied by CDA".to_owned(),
            parameters: serde_json::Map::new(),
        }),
        evaluations: StdMutex::new(Vec::new()),
    }));
    insert_policy_test_lock(&locks, Arc::new(AtomicUsize::new(0))).await;

    let result = locks
        .evaluate_acquisition(
            LockScope::Vehicle,
            LockCoverage::default(),
            &preemption_request(),
            &TestClaims {
                subject: "priority-client".to_owned(),
                attributes: serde_json::Map::new(),
            },
        )
        .await;
    let Err(error) = result else {
        panic!("Policy should deny acquisition");
    };
    let response = error.into_response();
    assert_eq!(response.status(), StatusCode::LOCKED);
    let body: sovd_interfaces::error::ApiErrorResponse<crate::sovd::error::VendorErrorCode> =
        axum_response_into(response)
            .await
            .expect("Error should decode");
    assert_eq!(
        body.vendor_code,
        Some(crate::sovd::error::VendorErrorCode::LockPriorityDenied)
    );
    assert!(
        body.parameters
            .is_some_and(|parameters| parameters.is_empty())
    );
}

#[tokio::test]
async fn revisioned_policy_timeout_is_service_unavailable() {
    let config = LockConfig {
        priority_policy_timeout_ms: 1,
        ..LockConfig::default()
    };
    let locks = Locks::new_with_config_and_policy(
        config,
        Arc::new(TestPolicy {
            decision: None,
            evaluations: StdMutex::new(Vec::new()),
        }),
    );
    insert_policy_test_lock(&locks, Arc::new(AtomicUsize::new(0))).await;
    let request = sovd_interfaces::locking::Request {
        lock_expiration: 60,
        break_lock: false,
        x_sovd2uds_isexclusive: None,
        metadata: serde_json::Map::new(),
    };

    let result = locks
        .evaluate_acquisition(
            LockScope::Vehicle,
            LockCoverage::default(),
            &request,
            &TestClaims {
                subject: "priority-client".to_owned(),
                attributes: serde_json::Map::new(),
            },
        )
        .await;

    assert!(matches!(result, Err(ApiError::ServiceUnavailable { .. })));
}

#[tokio::test]
async fn stale_policy_decision_is_reevaluated_with_fresh_state() {
    let policy = Arc::new(BlockingPolicy {
        evaluations: AtomicUsize::new(0),
        started: Notify::new(),
        release: Notify::new(),
    });
    let locks = Arc::new(locks_with_policy(Arc::<BlockingPolicy>::clone(&policy)));
    insert_test_ecu_lock(&locks, "ecu-a").await;
    let task_locks = Arc::clone(&locks);
    let evaluation = task::spawn(async move {
        task_locks
            .evaluate_acquisition(
                LockScope::Vehicle,
                LockCoverage::new(["ecu-a".to_owned()]),
                &preemption_request(),
                &TestClaims {
                    subject: "priority-client".to_owned(),
                    attributes: serde_json::Map::new(),
                },
            )
            .await
    });

    policy.started.notified().await;
    {
        let mut store = locks.store.lock().await;
        let state = &mut store.state;
        state
            .delete("test-lock-id")
            .expect("Concurrent deletion should succeed");
        state
            .insert_active(active_test_lock("other-client", true))
            .expect("Concurrent insertion should succeed");
    }
    policy.release.notify_one();

    policy.started.notified().await;
    policy.release.notify_one();

    let result = evaluation
        .await
        .expect("Policy evaluation task should finish");
    assert!(result.is_ok());
    assert_eq!(policy.evaluations.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn revisioned_policy_panic_is_internal_error_and_preserves_state() {
    let locks = Locks::new_with_policy(Arc::new(PanickingPolicy));
    insert_test_ecu_lock(&locks, "ecu-a").await;
    let revision = locks.store.lock().await.state.revision();

    let result = locks
        .evaluate_acquisition(
            LockScope::Vehicle,
            LockCoverage::new(["ecu-a".to_owned()]),
            &preemption_request(),
            &TestClaims {
                subject: "priority-client".to_owned(),
                attributes: serde_json::Map::new(),
            },
        )
        .await;

    let Err(error) = result else {
        panic!("Policy panic should fail evaluation");
    };
    assert_eq!(
        error.into_response().status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    let store = locks.store.lock().await;
    let state = &store.state;
    assert_eq!(state.revision(), revision);
    assert!(state.active_by_id("test-lock-id").is_some());
}

#[tokio::test]
async fn runtime_update_guard_reads_canonical_active_state() {
    let locks = Locks::new();
    insert_test_ecu_lock(&locks, "old-ecu").await;

    assert!(matches!(
        locks.prepare_runtime_update().await,
        Err(LockUpdateError::EcuLocksHeld)
    ));
    assert_eq!(locks.active_snapshots().await.len(), 1);
}

#[tokio::test]
async fn preemption_requires_break_lock() {
    let locks = Locks::new_with_policy(Arc::new(TestPolicy {
        decision: Some(LockPriorityDecision::Preempt {
            lock_ids: vec!["existing-lock".to_owned()],
            broken_by: "priority-app".to_owned(),
        }),
        evaluations: StdMutex::new(Vec::new()),
    }));
    insert_policy_test_lock(&locks, Arc::new(AtomicUsize::new(0))).await;
    let request = sovd_interfaces::locking::Request {
        lock_expiration: 60,
        break_lock: false,
        x_sovd2uds_isexclusive: None,
        metadata: serde_json::Map::new(),
    };

    let result = locks
        .evaluate_acquisition(
            LockScope::Vehicle,
            LockCoverage::default(),
            &request,
            &TestClaims {
                subject: "priority-client".to_owned(),
                attributes: serde_json::Map::new(),
            },
        )
        .await;

    assert!(matches!(result, Err(ApiError::Locked(_))));
    assert!(locks.vehicle_lock_owner_sub().await.is_some());
}

#[tokio::test]
async fn committed_preemption_cleans_once_and_creates_defunct_lock() {
    let cleanup_count = Arc::new(AtomicUsize::new(0));
    let locks = Locks::new_with_policy(Arc::new(TestPolicy {
        decision: Some(LockPriorityDecision::Preempt {
            lock_ids: vec!["existing-lock".to_owned()],
            broken_by: "priority-app".to_owned(),
        }),
        evaluations: StdMutex::new(Vec::new()),
    }));
    let lock_id = insert_policy_test_lock(&locks, Arc::clone(&cleanup_count)).await;
    let request = sovd_interfaces::locking::Request {
        lock_expiration: 60,
        break_lock: true,
        x_sovd2uds_isexclusive: None,
        metadata: serde_json::Map::new(),
    };

    let (acquisition, pending, _) = locks
        .evaluate_acquisition(
            LockScope::Vehicle,
            LockCoverage::default(),
            &request,
            &TestClaims {
                subject: "priority-client".to_owned(),
                attributes: serde_json::Map::new(),
            },
        )
        .await
        .expect("policy evaluation must succeed");
    let pending = pending.expect("preemption must be staged");
    let replacement = ActiveLock {
        id: "replacement".to_owned(),
        scope: ScopeKey::Vehicle,
        coverage: LockCoverage::vehicle(),
        principal: LockPrincipal {
            subject: "priority-client".to_owned(),
            claims: serde_json::Map::new(),
        },
        metadata: serde_json::Map::new(),
        exclusive: true,
        expires_at: SystemTime::now() + Duration::from_secs(300),
        parent_vehicle: None,
    };
    let removed = locks
        .store
        .lock()
        .await
        .state
        .commit_replacement(
            &pending.root_lock_ids,
            &[],
            replacement,
            &pending.broken_by,
            pending.broken_at,
        )
        .unwrap();
    acquisition.finish().await;
    let cleanups = {
        let mut store = locks.store.lock().await;
        take_cleanups(&mut store.cleanups, &removed)
    };
    run_cleanups(cleanups).await;

    assert_eq!(cleanup_count.load(Ordering::SeqCst), 1);
    assert_eq!(
        locks.vehicle_lock_owner_sub().await.as_deref(),
        Some("priority-client")
    );
    assert!(
        locks
            .defunct_by_id(&lock_id, &LockScope::Vehicle)
            .await
            .is_some()
    );
}

#[tokio::test]
async fn vehicle_preemption_advertises_and_selects_only_root() {
    let policy = Arc::new(TestPolicy {
        decision: Some(LockPriorityDecision::Preempt {
            lock_ids: vec!["vehicle-lock".to_owned()],
            broken_by: "priority-app".to_owned(),
        }),
        evaluations: StdMutex::new(Vec::new()),
    });
    let locks = locks_with_policy(Arc::<TestPolicy>::clone(&policy));
    let expires_at = SystemTime::now()
        .checked_add(Duration::from_secs(300))
        .expect("Test expiration should be representable");
    let principal = LockPrincipal {
        subject: "existing-client".to_owned(),
        claims: serde_json::Map::new(),
    };
    let vehicle = ActiveLock {
        id: "vehicle-lock".to_owned(),
        scope: ScopeKey::Vehicle,
        coverage: LockCoverage::vehicle(),
        principal: principal.clone(),
        metadata: serde_json::Map::new(),
        exclusive: true,
        expires_at,
        parent_vehicle: None,
    };
    let child = ActiveLock {
        id: "child-lock".to_owned(),
        scope: ScopeKey::Ecu("ecu-a".to_owned()),
        coverage: LockCoverage::vehicle(),
        principal,
        metadata: serde_json::Map::new(),
        exclusive: true,
        expires_at,
        parent_vehicle: Some("vehicle-lock".to_owned()),
    };
    {
        let mut store = locks.store.lock().await;
        let state = &mut store.state;
        state.insert_active(vehicle).unwrap();
        state.insert_active(child).unwrap();
    }
    let request = sovd_interfaces::locking::Request {
        lock_expiration: 60,
        break_lock: true,
        x_sovd2uds_isexclusive: None,
        metadata: serde_json::Map::new(),
    };

    let (acquisition, pending, _) = locks
        .evaluate_acquisition(
            LockScope::Vehicle,
            LockCoverage::new(["ecu-a".to_owned()]),
            &request,
            &TestClaims {
                subject: "priority-client".to_owned(),
                attributes: serde_json::Map::new(),
            },
        )
        .await
        .expect("Preemption staging must succeed for root selection");
    let pending = pending.expect("Preemption must be staged");
    assert_eq!(pending.root_lock_ids, ["vehicle-lock"]);
    assert_eq!(
        policy
            .evaluations
            .lock()
            .expect("Policy mutex poisoned")
            .first()
            .expect("Evaluation expected")
            .preemption_candidates,
        ["vehicle-lock"]
    );
    let replacement = ActiveLock {
        id: "replacement".to_owned(),
        scope: ScopeKey::Vehicle,
        coverage: LockCoverage::new(["ecu-a".to_owned()]),
        principal: LockPrincipal {
            subject: "priority-client".to_owned(),
            claims: serde_json::Map::new(),
        },
        metadata: serde_json::Map::new(),
        exclusive: true,
        expires_at: SystemTime::now() + Duration::from_secs(300),
        parent_vehicle: None,
    };
    locks
        .store
        .lock()
        .await
        .state
        .commit_replacement(
            &pending.root_lock_ids,
            &[],
            replacement,
            &pending.broken_by,
            pending.broken_at,
        )
        .expect("Replacement commit must succeed after canonicalization");
    acquisition.finish().await;

    let store = locks.store.lock().await;
    let state = &store.state;
    assert!(state.active_by_id("replacement").is_some());
    assert!(state.active_by_id("vehicle-lock").is_none());
    assert!(state.active_by_id("child-lock").is_none());
    assert!(state.defunct_by_id("vehicle-lock").is_some());
    assert!(state.defunct_by_id("child-lock").is_some());
}
