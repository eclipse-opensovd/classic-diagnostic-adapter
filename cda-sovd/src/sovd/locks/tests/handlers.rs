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

#[test]
fn oversized_lock_expiration_is_rejected_as_bad_request() {
    let request = sovd_interfaces::locking::Request {
        lock_expiration: 9_223_372_036_854_776,
        break_lock: false,
        x_sovd2uds_isexclusive: None,
        metadata: serde_json::Map::new(),
    };

    assert!(matches!(
        validated_expiration(&request),
        Err(ApiError::BadRequest(_))
    ));
}

#[tokio::test]
async fn child_lock_created_under_owned_vehicle_has_parent() {
    let (mock_uds, ecu_name, locks, _, _) = super::cleanup::setup_ecu_lock_test();
    let vehicle = test_lock("vehicle").owner("test_user").vehicle().build();
    locks.test_insert_active(vehicle).await;

    let lock_id =
        super::cleanup::create_ecu_lock(&mock_uds, &locks, &ecu_name, Duration::from_secs(60))
            .await;

    let parent = locks
        .core
        .read_store(|store| {
            store
                .state
                .active_by_id(&lock_id)
                .and_then(|lock| lock.parent_vehicle_lock_id.clone())
        })
        .await;
    assert_eq!(parent.as_deref(), Some("vehicle"));
    let response = delete_handler(
        &locks,
        LockScope::Ecu { name: ecu_name },
        &lock_id,
        &TestSecurityPlugin.claims(),
        false,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn post_handler_commits_policy_preemption_end_to_end() {
    let policy = Arc::new(TestPolicy {
        decision: Some(LockPriorityDecision::Preempt {
            lock_ids: vec!["existing-lock".to_owned()],
            broken_by: "priority-app".to_owned(),
        }),
        evaluations: StdMutex::new(Vec::new()),
    });
    let (uds, locks) =
        super::cleanup::setup_vehicle_lock_test_with_policy(Arc::<TestPolicy>::clone(&policy));
    let cleanup_count = Arc::new(AtomicUsize::new(0));
    insert_policy_test_lock(&locks, Arc::clone(&cleanup_count)).await;
    let claims = TestClaims {
        subject: "priority-client".to_owned(),
        attributes: serde_json::Map::new(),
    };
    let (acquisition, pending, request) = locks
        .evaluate_acquisition(
            LockScope::Vehicle,
            LockCoverage::vehicle(),
            &preemption_request(),
            &claims,
        )
        .await
        .expect("Policy preemption should be staged");

    let response = post_handler(
        &uds,
        LockContext {
            all_locks: &locks,
            acquisition,
            pending,
            coverage: LockCoverage::vehicle(),
        },
        request,
        "/vehicle/v15/locks",
        false,
        Box::new(TestSecurityPlugin),
    )
    .await;

    assert_eq!(response.status(), StatusCode::CREATED);
    let location = response
        .headers()
        .get(axum::http::header::LOCATION)
        .expect("Created lock response should include Location")
        .to_str()
        .expect("Location should be a valid header value")
        .to_owned();
    let response: sovd_interfaces::locking::post_put::Response = axum_response_into(response)
        .await
        .expect("Created lock response should decode");
    assert_eq!(location, format!("/vehicle/v15/locks/{}", response.id));
    assert!(response.x_sovd2uds_isexclusive);
    assert_eq!(cleanup_count.load(Ordering::SeqCst), 1);
    locks
        .core
        .read_store(|store| {
            assert!(store.state.active_by_id(&response.id).is_some());
            assert!(store.state.defunct_by_id("existing-lock").is_some());
        })
        .await;
}

#[tokio::test]
async fn same_owner_post_renewal_returns_ok_without_location() {
    let locks = Arc::new(Locks::new());
    let original_expiration = SystemTime::now()
        .checked_add(Duration::from_secs(300))
        .expect("Test expiration should be representable");
    locks
        .test_insert_active(
            test_lock("existing-lock")
                .expires_at(original_expiration)
                .build(),
        )
        .await;
    let claims = TestSecurityPlugin.claims();
    let request = sovd_interfaces::locking::Request {
        lock_expiration: 600,
        break_lock: false,
        x_sovd2uds_isexclusive: None,
        metadata: serde_json::Map::new(),
    };
    let (acquisition, pending, request) = locks
        .evaluate_acquisition(
            LockScope::Ecu {
                name: "ecu-a".to_owned(),
            },
            LockCoverage::new(["ecu-a".to_owned()]),
            &request,
            &claims,
        )
        .await
        .expect("Same-owner renewal should be accepted");
    let expected_expiration = request.expires_at;

    let response = post_handler(
        &MockUdsEcu::default(),
        LockContext {
            all_locks: &locks,
            acquisition,
            pending,
            coverage: LockCoverage::new(["ecu-a".to_owned()]),
        },
        request,
        "/vehicle/v15/components/ecu-a/locks",
        false,
        Box::new(TestSecurityPlugin),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get(axum::http::header::LOCATION)
            .is_none()
    );
    let response: sovd_interfaces::locking::post_put::Response = axum_response_into(response)
        .await
        .expect("Renewed lock response should decode");
    assert_eq!(response.id, "existing-lock");
    let expiration = locks
        .core
        .read_store(|store| {
            store
                .state
                .active_by_id("existing-lock")
                .map(|lock| lock.expires_at)
        })
        .await;
    assert_eq!(expiration, Some(expected_expiration));
}

#[tokio::test]
async fn defunct_lock_remains_visible_and_reports_lock_broken() {
    let locks = Locks::new_with_policy(Arc::new(TestPolicy {
        decision: Some(LockPriorityDecision::Preempt {
            lock_ids: vec!["existing-lock".to_owned()],
            broken_by: "priority-app".to_owned(),
        }),
        evaluations: StdMutex::new(Vec::new()),
    }));
    let lock_id = insert_policy_test_lock(&locks, Arc::new(AtomicUsize::new(0))).await;
    let request = sovd_interfaces::locking::Request {
        lock_expiration: 60,
        break_lock: true,
        x_sovd2uds_isexclusive: None,
        metadata: serde_json::Map::new(),
    };
    let claims = TestClaims {
        subject: "priority-client".to_owned(),
        attributes: serde_json::Map::new(),
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
    let replacement = test_lock("replacement")
        .owner("priority-client")
        .vehicle()
        .build();
    commit_pending_preemption(acquisition, pending, replacement).await;

    let response = get_handler(
        &locks,
        LockScope::Vehicle,
        &TestClaims {
            subject: "existing-client".to_owned(),
            attributes: serde_json::Map::new(),
        },
        false,
    )
    .await;
    let response: sovd_interfaces::locking::get::Response = axum_response_into(response)
        .await
        .expect("failed to extract lock list");
    let defunct = response.items.first().expect("defunct lock must be listed");
    assert_eq!(defunct.id, lock_id);
    assert_eq!(
        defunct.x_sovd2uds_broken_by.as_deref(),
        Some("priority-app")
    );
    assert_eq!(
        defunct.x_sovd2uds_current_holder.as_deref(),
        Some("priority-client")
    );

    let response = validate_ecu_write(
        &TestClaims {
            subject: "existing-client".to_owned(),
            attributes: serde_json::Map::new(),
        },
        "some-ecu",
        &locks,
        false,
    )
    .await
    .expect_err("vehicle preemption must block ECU communication")
    .into_response();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let error: sovd_interfaces::error::ApiErrorResponse<crate::sovd::error::VendorErrorCode> =
        axum_response_into(response)
            .await
            .expect("failed to extract broken-lock error");
    assert_eq!(
        error.error_code,
        sovd_interfaces::error::ErrorCode::LockBroken
    );
    let parameters = error.parameters.expect("broken-lock parameters must exist");
    assert_eq!(
        parameters.get("broken_by"),
        Some(&serde_json::json!("priority-app"))
    );
}

#[tokio::test]
async fn defunct_put_validates_owner_before_reporting_broken_lock() {
    let locks = Locks::new();
    let preempted = test_lock("preempted").owner("old-owner").build();
    locks.test_insert_active(preempted).await;
    let replacement = test_lock("replacement").owner("new-owner").build();
    locks
        .test_mutate_store(|store| {
            store
                .state
                .commit_replacement(
                    &["preempted".to_owned()],
                    replacement,
                    "priority-app",
                    SystemTime::now(),
                )
                .unwrap();
        })
        .await;

    let response = put_handler(
        LockUpdateContext {
            all_locks: &locks,
            scope: LockScope::Ecu {
                name: "ecu-a".to_owned(),
            },
        },
        "preempted",
        &TestClaims {
            subject: "unrelated-client".to_owned(),
            attributes: serde_json::Map::new(),
        },
        sovd_interfaces::locking::UpdateRequest {
            lock_expiration: 600,
        },
        false,
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let error: sovd_interfaces::error::ApiErrorResponse<crate::sovd::error::VendorErrorCode> =
        axum_response_into(response)
            .await
            .expect("Forbidden response should decode");
    assert_eq!(
        error.error_code,
        sovd_interfaces::error::ErrorCode::InsufficientAccessRights
    );
    assert!(error.parameters.is_none());
}

#[tokio::test]
async fn put_preserves_lock_identity_metadata_and_exclusivity() {
    let locks = Locks::new();
    let mut active = test_lock("renewed").owner("owner").exclusive(false).build();
    active
        .principal
        .claims
        .insert("role".to_owned(), serde_json::json!("diagnostic"));
    active
        .metadata
        .insert("vendor".to_owned(), serde_json::json!({"priority": 3}));
    let original = active.clone();
    locks.test_insert_active(active).await;

    let response = put_handler(
        LockUpdateContext {
            all_locks: &locks,
            scope: LockScope::Ecu {
                name: "ecu-a".to_owned(),
            },
        },
        "renewed",
        &TestClaims {
            subject: "owner".to_owned(),
            attributes: serde_json::Map::new(),
        },
        sovd_interfaces::locking::UpdateRequest {
            lock_expiration: 600,
        },
        false,
    )
    .await;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let renewed = locks
        .core
        .read_store(|store| store.state.active_by_id("renewed").cloned())
        .await
        .expect("Lock should remain active");
    assert_eq!(renewed.principal, original.principal);
    assert_eq!(renewed.metadata, original.metadata);
    assert_eq!(renewed.exclusive, original.exclusive);
    assert!(renewed.expires_at > original.expires_at);
}

#[tokio::test]
async fn get_handlers_hide_expired_defunct_records() {
    let locks = Locks::new();
    let preempted = test_lock("expired-preempted")
        .owner("old-owner")
        .expires_at(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
        .build();
    locks.test_insert_active(preempted).await;
    let replacement = test_lock("replacement")
        .owner("new-owner")
        .expires_at(SystemTime::now() + Duration::from_secs(300))
        .build();
    locks
        .test_mutate_store(|store| {
            store
                .state
                .commit_replacement(
                    &["expired-preempted".to_owned()],
                    replacement,
                    "priority-app",
                    SystemTime::UNIX_EPOCH,
                )
                .unwrap();
        })
        .await;

    let list = get_handler(
        &locks,
        LockScope::Ecu {
            name: "ecu-a".to_owned(),
        },
        &TestClaims {
            subject: "old-owner".to_owned(),
            attributes: serde_json::Map::new(),
        },
        false,
    )
    .await;
    let list: sovd_interfaces::locking::get::Response = axum_response_into(list)
        .await
        .expect("Lock list should decode");
    assert_eq!(list.items.len(), 1);
    assert_eq!(
        list.items.first().map(|lock| lock.id.as_str()),
        Some("replacement")
    );

    let expired_id = "expired-preempted".to_owned();
    let response = get_id_handler(
        &locks,
        LockScope::Ecu {
            name: "ecu-a".to_owned(),
        },
        &expired_id,
        &TestClaims {
            subject: "old-owner".to_owned(),
            attributes: serde_json::Map::new(),
        },
        false,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn lock_get_responses_include_schema_when_requested() {
    let locks = Locks::new();
    insert_test_ecu_lock(&locks, "ecu-a").await;
    let claims = TestClaims {
        subject: "test_user".to_owned(),
        attributes: serde_json::Map::new(),
    };

    let list = get_handler(
        &locks,
        LockScope::Ecu {
            name: "ecu-a".to_owned(),
        },
        &claims,
        true,
    )
    .await;
    let list: sovd_interfaces::locking::get::Response = axum_response_into(list)
        .await
        .expect("Lock list should decode");
    assert!(list.schema.is_some());

    let details = get_id_handler(
        &locks,
        LockScope::Ecu {
            name: "ecu-a".to_owned(),
        },
        &"test-lock-id".to_owned(),
        &claims,
        true,
    )
    .await;
    let details: sovd_interfaces::locking::id::get::Response = axum_response_into(details)
        .await
        .expect("Lock details should decode");
    assert!(details.schema.is_some());
}

#[tokio::test]
async fn lock_errors_include_schema_when_requested() {
    let locks = Locks::new();
    let response = get_id_handler(
        &locks,
        LockScope::Ecu {
            name: "ecu-a".to_owned(),
        },
        &"missing".to_owned(),
        &TestClaims {
            subject: "test_user".to_owned(),
            attributes: serde_json::Map::new(),
        },
        true,
    )
    .await;
    let error: sovd_interfaces::error::ApiErrorResponse<crate::sovd::error::VendorErrorCode> =
        axum_response_into(response)
            .await
            .expect("Lock error should decode");
    assert!(error.schema.is_some());
}

#[tokio::test]
async fn lock_details_report_ownership_relative_to_requesting_client() {
    let locks = Locks::new();
    locks
        .test_insert_active(test_lock("active").owner("original-owner").build())
        .await;

    for (subject, expected_owned) in [("original-owner", true), ("other-client", false)] {
        let response = get_id_handler(
            &locks,
            LockScope::Ecu {
                name: "ecu-a".to_owned(),
            },
            &"active".to_owned(),
            &TestClaims {
                subject: subject.to_owned(),
                attributes: serde_json::Map::new(),
            },
            false,
        )
        .await;
        let details: sovd_interfaces::locking::id::get::Response = axum_response_into(response)
            .await
            .expect("Active lock details should decode");
        assert_eq!(details.owned, expected_owned);
    }
}

#[tokio::test]
async fn defunct_lock_details_remain_owned_by_original_client() {
    let locks = Locks::new();
    locks
        .test_insert_active(test_lock("preempted").owner("original-owner").build())
        .await;
    locks
        .test_mutate_store(|store| {
            store
                .state
                .commit_replacement(
                    &["preempted".to_owned()],
                    test_lock("replacement").owner("replacement-owner").build(),
                    "priority-app",
                    SystemTime::now(),
                )
                .expect("Replacement should be committed");
        })
        .await;

    for (subject, expected_owned) in [("original-owner", true), ("replacement-owner", false)] {
        let response = get_id_handler(
            &locks,
            LockScope::Ecu {
                name: "ecu-a".to_owned(),
            },
            &"preempted".to_owned(),
            &TestClaims {
                subject: subject.to_owned(),
                attributes: serde_json::Map::new(),
            },
            false,
        )
        .await;
        let details: sovd_interfaces::locking::id::get::Response = axum_response_into(response)
            .await
            .expect("Defunct lock details should decode");
        assert_eq!(details.owned, expected_owned);
    }
}

#[test]
fn lock_create_response_includes_exclusivity_and_requested_schema() {
    let response = sovd_lock_response("lock-id", false, true);
    assert!(!response.x_sovd2uds_isexclusive);
    assert!(response.schema.is_some());
    assert!(sovd_lock_response("lock-id", true, false).schema.is_none());
}
