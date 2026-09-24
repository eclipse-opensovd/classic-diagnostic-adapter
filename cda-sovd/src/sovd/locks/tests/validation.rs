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

use cda_interfaces::UdsEcu;

use super::*;
use crate::sovd::locks::validation::validate_defunct_fg_lock_in_state;

async fn validate_defunct_fg_lock<T: UdsEcu>(
    claims: &impl Claims,
    functional_group_name: &str,
    uds: &T,
    locks: &Locks,
    include_schema: bool,
) -> Result<(), ErrorWrapper> {
    let target_coverage = LockCoverage::new(
        uds.ecus_for_functional_group(functional_group_name, false)
            .await,
    );
    let target_scope = ScopeKey::FunctionalGroup(functional_group_name.to_ascii_lowercase());
    let mut store = locks.lock_idle().await;
    validate_defunct_fg_lock_in_state(
        claims,
        &target_scope,
        &target_coverage,
        &mut store.state,
        include_schema,
    )
}

#[test]
fn vehicle_acquisition_rejects_foreign_child_as_locked() {
    let active = [test_lock("access-lock").owner("other-client").build()];

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
            locks: vec![
                test_lock("access-lock")
                    .owner("caller")
                    .exclusive(false)
                    .build(),
            ],
            write: true,
            expected: None,
        },
        Case {
            name: "foreign non-exclusive read",
            locks: vec![
                test_lock("access-lock")
                    .owner("other")
                    .exclusive(false)
                    .build(),
            ],
            write: false,
            expected: None,
        },
        Case {
            name: "foreign non-exclusive write",
            locks: vec![
                test_lock("access-lock")
                    .owner("other")
                    .exclusive(false)
                    .build(),
            ],
            write: true,
            expected: Some(StatusCode::LOCKED),
        },
        Case {
            name: "owned exclusive read",
            locks: vec![test_lock("access-lock").owner("caller").build()],
            write: false,
            expected: None,
        },
        Case {
            name: "foreign exclusive read",
            locks: vec![test_lock("access-lock").owner("other").build()],
            write: false,
            expected: Some(StatusCode::LOCKED),
        },
        Case {
            name: "foreign exclusive write",
            locks: vec![test_lock("access-lock").owner("other").build()],
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
    struct Case {
        name: &'static str,
        break_lock: bool,
        lock_ids: Vec<String>,
    }

    let candidates = vec!["candidate".to_owned()];
    let cases = [
        Case {
            name: "breaking not requested",
            break_lock: false,
            lock_ids: vec!["candidate".to_owned()],
        },
        Case {
            name: "empty selection",
            break_lock: true,
            lock_ids: Vec::new(),
        },
        Case {
            name: "duplicate selection",
            break_lock: true,
            lock_ids: vec!["candidate".to_owned(), "candidate".to_owned()],
        },
        Case {
            name: "unknown candidate",
            break_lock: true,
            lock_ids: vec!["not-a-candidate".to_owned()],
        },
    ];

    for case in cases {
        assert!(
            matches!(
                Locks::validate_preemption_selection(case.break_lock, &case.lock_ids, &candidates),
                Err(ApiError::Locked(_))
            ),
            "{}",
            case.name
        );
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
    let expired = test_lock("access-lock")
        .owner("owner")
        .expires_at(SystemTime::now() - Duration::from_secs(1))
        .build();
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
        parent_vehicle_lock_id: None,
    };
    locks.test_insert_active(vehicle).await;
    let child = test_lock("future-child")
        .owner("owner")
        .parent("expired-vehicle")
        .build();
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
    let lock = test_lock("access-lock")
        .owner("other")
        .functional_group("group-a", ["ecu-a".to_owned()])
        .build();
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
        .insert_active(test_lock("access-lock").owner("other").build())
        .unwrap();
    let mut uds = MockUdsEcu::new();
    uds.expect_ecus_for_functional_group()
        .times(1)
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
    let replacement = test_lock("replacement").owner("other-client").build();
    locks
        .store
        .lock()
        .await
        .state
        .commit_replacement(
            &["test-lock-id".to_owned()],
            replacement,
            "priority-app",
            SystemTime::now(),
        )
        .expect("Preemption should succeed");
    let mut uds = MockUdsEcu::new();
    uds.expect_ecus_for_functional_group()
        .with(eq("group-a"), eq(false))
        .return_once(|_, _| vec!["ecu-a".to_owned()]);

    let error = validate_defunct_fg_lock(
        &TestClaims {
            subject: "test_user".to_owned(),
            attributes: serde_json::Map::new(),
        },
        "group-a",
        &uds,
        &locks,
        false,
    )
    .await
    .expect_err("Defunct overlapping lock should reject access");

    assert_eq!(error.into_response().status(), StatusCode::CONFLICT);
}
