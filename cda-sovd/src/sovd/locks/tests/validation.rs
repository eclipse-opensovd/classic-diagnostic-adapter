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
fn vehicle_acquisition_rejects_foreign_child_as_locked() {
    let active = [active_test_lock("other-client", true)];

    assert!(matches!(
        validate_vehicle_children(&active, &[], "requesting-client"),
        Err(ApiError::Locked(_))
    ));
}

#[test]
fn communication_access_matches_lock_matrix() {
    struct Case {
        name: &'static str,
        locks: Vec<ActiveLock>,
        write: bool,
        expected: Option<StatusCode>,
    }

    let cases = [
        Case {
            name: "unlocked read",
            locks: vec![],
            write: false,
            expected: None,
        },
        Case {
            name: "unlocked write",
            locks: vec![],
            write: true,
            expected: Some(StatusCode::CONFLICT),
        },
        Case {
            name: "owned non-exclusive write",
            locks: vec![active_test_lock("caller", false)],
            write: true,
            expected: None,
        },
        Case {
            name: "foreign non-exclusive read",
            locks: vec![active_test_lock("other", false)],
            write: false,
            expected: None,
        },
        Case {
            name: "foreign non-exclusive write",
            locks: vec![active_test_lock("other", false)],
            write: true,
            expected: Some(StatusCode::LOCKED),
        },
        Case {
            name: "owned exclusive read",
            locks: vec![active_test_lock("caller", true)],
            write: false,
            expected: None,
        },
        Case {
            name: "foreign exclusive read",
            locks: vec![active_test_lock("other", true)],
            write: false,
            expected: Some(StatusCode::LOCKED),
        },
        Case {
            name: "foreign exclusive write",
            locks: vec![active_test_lock("other", true)],
            write: true,
            expected: Some(StatusCode::LOCKED),
        },
    ];

    for case in cases {
        let result = validate_active_locks("caller", case.locks.iter(), case.write);
        let status = result.err().map(|error| error.into_response().status());
        assert_eq!(status, case.expected, "{}", case.name);
    }
}

#[test]
fn ineffective_preemption_selections_are_locked() {
    let candidates = vec!["candidate".to_owned()];
    let cases = [
        (false, vec!["candidate".to_owned()]),
        (true, Vec::new()),
        (true, vec!["candidate".to_owned(), "candidate".to_owned()]),
        (true, vec!["not-a-candidate".to_owned()]),
    ];

    for (break_lock, lock_ids) in cases {
        assert!(matches!(
            Locks::validate_preemption_selection(break_lock, &lock_ids, &candidates),
            Err(ApiError::Locked(_))
        ));
    }
}

#[tokio::test]
async fn elapsed_locks_do_not_authorize_or_block_communication() {
    let owner = TestClaims {
        subject: "owner".to_owned(),
        attributes: serde_json::Map::new(),
    };
    let other = TestClaims {
        subject: "other".to_owned(),
        attributes: serde_json::Map::new(),
    };
    let locks = Locks::new();
    let mut expired = active_test_lock("owner", true);
    expired.expires_at = SystemTime::now() - Duration::from_secs(1);
    locks.test_insert_active(expired).await;

    assert_eq!(
        validate_ecu_write(&owner, "ecu-a", &locks, false)
            .await
            .expect_err("Elapsed lock must not authorize writes")
            .into_response()
            .status(),
        StatusCode::CONFLICT
    );
    assert!(
        validate_ecu_read(&other, "ecu-a", &locks, false)
            .await
            .is_ok()
    );

    let locks = Locks::new();
    let vehicle = ActiveLock {
        id: "expired-vehicle".to_owned(),
        scope: ScopeKey::Vehicle,
        coverage: LockCoverage::vehicle(),
        principal: LockPrincipal {
            subject: "owner".to_owned(),
            claims: serde_json::Map::new(),
        },
        metadata: serde_json::Map::new(),
        exclusive: true,
        expires_at: SystemTime::now() - Duration::from_secs(1),
        parent_vehicle: None,
    };
    locks.test_insert_active(vehicle).await;
    let mut child = active_test_lock("owner", true);
    child.id = "future-child".to_owned();
    child.parent_vehicle = Some("expired-vehicle".to_owned());
    locks.test_insert_active(child).await;

    assert_eq!(
        validate_ecu_write(&owner, "ecu-a", &locks, false)
            .await
            .expect_err("Child of elapsed vehicle must not authorize writes")
            .into_response()
            .status(),
        StatusCode::CONFLICT
    );
    assert!(
        validate_ecu_read(&other, "ecu-a", &locks, false)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn ecu_access_includes_functional_group_coverage() {
    let locks = Locks::new();
    let mut lock = active_test_lock("other", true);
    lock.scope = ScopeKey::FunctionalGroup("group-a".to_owned());
    locks.test_insert_active(lock).await;
    let claims = TestClaims {
        subject: "caller".to_owned(),
        attributes: serde_json::Map::new(),
    };

    let response = validate_ecu_read(&claims, "ecu-a", &locks, false)
        .await
        .expect_err("Foreign exclusive functional-group lock must block ECU reads");

    assert_eq!(response.into_response().status(), StatusCode::LOCKED);
}

#[tokio::test]
async fn functional_group_access_includes_ecu_coverage() {
    let locks = Locks::new();
    locks
        .store
        .lock()
        .await
        .state
        .insert_active(active_test_lock("other", true))
        .unwrap();
    let mut uds = MockUdsEcu::new();
    uds.expect_ecus_for_functional_group()
        .times(2)
        .with(eq("group-a"), eq(false))
        .returning(|_, _| vec!["ecu-a".to_owned()]);
    let claims = TestClaims {
        subject: "caller".to_owned(),
        attributes: serde_json::Map::new(),
    };

    let response = validate_fg_read(&claims, "group-a", &uds, &locks, false)
        .await
        .expect_err("Foreign exclusive ECU lock must block functional-group reads");

    assert_eq!(response.into_response().status(), StatusCode::LOCKED);
}

#[tokio::test]
async fn fg_validation_rejects_defunct_overlapping_ecu_coverage() {
    let locks = Locks::new();
    insert_test_ecu_lock(&locks, "ecu-a").await;
    let mut replacement = active_test_lock("other-client", true);
    replacement.id = "replacement".to_owned();
    locks
        .store
        .lock()
        .await
        .state
        .commit_replacement(
            &["test-lock-id".to_owned()],
            &[],
            replacement,
            "priority-app",
            SystemTime::now(),
        )
        .expect("Preemption should succeed");
    let mut uds = MockUdsEcu::new();
    uds.expect_ecus_for_functional_group()
        .with(eq("group-a"), eq(false))
        .return_once(|_, _| vec!["ecu-a".to_owned()]);

    let result = validate_defunct_fg_lock(
        &TestClaims {
            subject: "test_user".to_owned(),
            attributes: serde_json::Map::new(),
        },
        "group-a",
        &uds,
        &locks,
        false,
    )
    .await;

    assert!(result.is_err());
}
