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
    locks
        .core
        .read_store(|store| {
            validate_defunct_fg_lock_in_state(
                claims,
                &target_scope,
                &target_coverage,
                &store.state,
                include_schema,
            )
        })
        .await
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
fn ineffective_preemption_selections_are_priority_denied() {
    struct Case {
        name: &'static str,
        break_lock: bool,
        lock_ids: Vec<LockId>,
    }

    let candidates = vec![LockId::from("candidate")];
    let cases = [
        Case {
            name: "breaking not requested",
            break_lock: false,
            lock_ids: vec!["candidate".into()],
        },
        Case {
            name: "empty selection",
            break_lock: true,
            lock_ids: Vec::new(),
        },
        Case {
            name: "duplicate selection",
            break_lock: true,
            lock_ids: vec!["candidate".into(), "candidate".into()],
        },
        Case {
            name: "unknown candidate",
            break_lock: true,
            lock_ids: vec!["not-a-candidate".into()],
        },
    ];

    for case in cases {
        assert!(
            matches!(
                Locks::validate_preemption_selection(case.break_lock, &case.lock_ids, &candidates),
                Err(ApiError::LockPriorityDenied { .. })
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
        id: "expired-vehicle".into(),
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

/// [[ test~plugin-vehicle-topology-reset-exclusive-lock-state, Only an unexpired exclusive vehicle lock is accepted, test ]]
#[tokio::test]
async fn vehicle_write_requires_the_callers_vehicle_lock() {
    use crate::sovd::locks::VehicleLockRequirement::{Any, Exclusive};

    struct Case {
        name: &'static str,
        locks: Vec<ActiveLock>,
        any: Option<(StatusCode, String)>,
        exclusive: Option<(StatusCode, String)>,
    }

    let caller = TestClaims {
        subject: "caller".to_owned(),
        attributes: serde_json::Map::new(),
    };
    let elapsed = SystemTime::now()
        .checked_sub(Duration::from_secs(1))
        .expect("now is after the epoch");
    let outcome = |result: Result<(), ErrorWrapper>| {
        result.err().map(|error| {
            let message = match &error.error {
                ApiError::LockRequired(message)
                | ApiError::Locked(message)
                | ApiError::LockBroken { message, .. } => message.clone(),
                other => panic!("Unexpected error {other:?}"),
            };
            (error.into_response().status(), message)
        })
    };
    let conflict = |message: &str| Some((StatusCode::CONFLICT, message.to_owned()));

    let cases = [
        Case {
            name: "no vehicle lock",
            locks: vec![],
            any: conflict("Vehicle lock required"),
            exclusive: conflict("Exclusive vehicle lock required"),
        },
        Case {
            name: "an ECU lock is not a vehicle lock",
            locks: vec![test_lock("ecu-lock").owner("caller").build()],
            any: conflict("Vehicle lock required"),
            exclusive: conflict("Exclusive vehicle lock required"),
        },
        Case {
            name: "own exclusive vehicle lock",
            locks: vec![test_lock("vehicle-lock").owner("caller").vehicle().build()],
            any: None,
            exclusive: None,
        },
        Case {
            name: "own non-exclusive vehicle lock",
            locks: vec![
                test_lock("vehicle-lock")
                    .owner("caller")
                    .vehicle()
                    .exclusive(false)
                    .build(),
            ],
            any: None,
            exclusive: conflict("Exclusive vehicle lock required"),
        },
        Case {
            name: "foreign vehicle lock",
            locks: vec![test_lock("vehicle-lock").owner("other").vehicle().build()],
            any: Some((
                StatusCode::LOCKED,
                "Vehicle lock is held by another client".to_owned(),
            )),
            exclusive: Some((
                StatusCode::LOCKED,
                "Vehicle lock is held by another client".to_owned(),
            )),
        },
        Case {
            name: "elapsed own vehicle lock",
            locks: vec![
                test_lock("vehicle-lock")
                    .owner("caller")
                    .vehicle()
                    .expires_at(elapsed)
                    .build(),
            ],
            any: conflict("Vehicle lock expired"),
            exclusive: conflict("Vehicle lock expired"),
        },
        Case {
            name: "elapsed foreign vehicle lock",
            locks: vec![
                test_lock("vehicle-lock")
                    .owner("other")
                    .vehicle()
                    .expires_at(elapsed)
                    .build(),
            ],
            any: conflict("Vehicle lock required"),
            exclusive: conflict("Exclusive vehicle lock required"),
        },
    ];

    for case in cases {
        let locks = Locks::new();
        for lock in case.locks {
            locks.test_insert_active(lock).await;
        }
        assert_eq!(
            outcome(validate_vehicle_write(&caller, &locks, false, Any).await),
            case.any,
            "{} (any)",
            case.name
        );
        assert_eq!(
            outcome(validate_vehicle_write(&caller, &locks, false, Exclusive).await),
            case.exclusive,
            "{} (exclusive)",
            case.name
        );
    }

    // A preempted own vehicle lock reports that it was broken.
    let locks = Locks::new();
    insert_test_vehicle_lock(&locks, "caller").await;
    break_test_vehicle_lock(&locks, "other").await;
    for requirement in [Any, Exclusive] {
        assert_eq!(
            outcome(validate_vehicle_write(&caller, &locks, false, requirement).await),
            conflict("Client lock was broken"),
            "broken vehicle lock ({requirement:?})"
        );
    }
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
        .test_mutate_store(|store| {
            store
                .state
                .insert_active(test_lock("access-lock").owner("other").build())
                .unwrap();
        })
        .await;
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
        .test_mutate_store(|store| {
            store
                .state
                .commit_replacement(
                    &["test-lock-id".into()],
                    replacement,
                    "priority-app",
                    SystemTime::now(),
                )
                .expect("Preemption should succeed");
        })
        .await;
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

#[tokio::test]
async fn defunct_lock_rejects_reads_with_conflict_for_nonexclusive_replacement() {
    let locks = Locks::new();
    locks
        .test_insert_active(test_lock("preempted").owner("original-owner").build())
        .await;
    locks
        .test_mutate_store(|store| {
            store
                .state
                .commit_replacement(
                    &["preempted".into()],
                    test_lock("replacement")
                        .owner("replacement-owner")
                        .exclusive(false)
                        .build(),
                    "priority-client",
                    SystemTime::now(),
                )
                .expect("Replacement should be committed");
        })
        .await;

    let response = validate_ecu_read(
        &TestClaims {
            subject: "original-owner".to_owned(),
            attributes: serde_json::Map::new(),
        },
        "ecu-a",
        &locks,
        false,
    )
    .await
    .expect_err("Defunct lock must reject read access")
    .into_response();

    assert_eq!(response.status(), StatusCode::CONFLICT);
    let error: sovd_interfaces::error::ApiErrorResponse<crate::sovd::error::VendorErrorCode> =
        crate::test_utils::axum_response_into(response)
            .await
            .expect("Broken-lock response should decode");
    assert_eq!(
        error.error_code,
        sovd_interfaces::error::ErrorCode::LockBroken
    );
}

/// [[ test~sovd-api-lock-acquisition-policy-validation, Acquisition policy requires an active vehicle lock of any owner, test ]]
#[tokio::test]
async fn acquisition_policy_controls_child_locks_without_vehicle_lock() {
    let requester = TestClaims {
        subject: "requester".to_owned(),
        attributes: serde_json::Map::new(),
    };

    let unrestricted = Locks::new();
    assert!(
        validate_vehicle_owner(&unrestricted, &requester)
            .await
            .is_ok()
    );

    let required = Locks::new_with_config(cda_interfaces::lock_config::LockConfig {
        lock_acquisition_policy:
            cda_interfaces::lock_config::LockAcquisitionPolicy::VehicleLockRequired,
        ..cda_interfaces::lock_config::LockConfig::default()
    });
    assert!(matches!(
        validate_vehicle_owner(&required, &requester).await,
        Err(ApiError::Conflict(_))
    ));

    // Any client's vehicle lock satisfies the precondition; a foreign one still blocks
    // through vehicle-lock blocking.
    required
        .test_insert_active(test_lock("vehicle").owner("requester").vehicle().build())
        .await;
    assert!(validate_vehicle_owner(&required, &requester).await.is_ok());
    let other = TestClaims {
        subject: "other".to_owned(),
        attributes: serde_json::Map::new(),
    };
    assert!(matches!(
        validate_vehicle_owner(&required, &other).await,
        Err(ApiError::Conflict(_))
    ));

    // An expired own vehicle lock not removed yet no longer satisfies the precondition,
    // and an expired foreign one still blocks until it is removed.
    let expired = std::time::SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(1))
        .expect("now is after the epoch");
    required
        .test_mutate_store(|store| {
            store.state.delete("vehicle").expect("lock exists");
        })
        .await;
    required
        .test_insert_active(
            test_lock("vehicle")
                .owner("requester")
                .vehicle()
                .expires_at(expired)
                .build(),
        )
        .await;
    for claims in [&requester, &other] {
        assert!(matches!(
            validate_vehicle_owner(&required, claims).await,
            Err(ApiError::Conflict(_))
        ));
    }
}

/// Without the `VehicleLockRequired` policy an expired own vehicle lock that is not
/// removed yet does not block child locks of its owner, while an expired foreign one
/// still blocks until it is removed.
#[tokio::test]
async fn expired_own_vehicle_lock_does_not_block_without_required_policy() {
    let requester = TestClaims {
        subject: "requester".to_owned(),
        attributes: serde_json::Map::new(),
    };
    let other = TestClaims {
        subject: "other".to_owned(),
        attributes: serde_json::Map::new(),
    };
    let expired = SystemTime::now()
        .checked_sub(Duration::from_secs(1))
        .expect("now is after the epoch");
    let locks = Locks::new();
    locks
        .test_insert_active(
            test_lock("vehicle")
                .owner("requester")
                .vehicle()
                .expires_at(expired)
                .build(),
        )
        .await;

    assert!(validate_vehicle_owner(&locks, &requester).await.is_ok());
    assert!(matches!(
        validate_vehicle_owner(&locks, &other).await,
        Err(ApiError::Conflict(_))
    ));
}
