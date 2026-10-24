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

//! Snapshot handed to the security plugin by the request lock provider.

use std::{sync::Arc, time::Duration};

use cda_interfaces::request_authorization::{
    RequestLockContext, RequestLockProvider, UdsRequestTarget,
};
use serde_json::{Map, Value, json};

use super::*;
use crate::sovd::SovdLockStateProvider;

fn target(ecu: &str) -> UdsRequestTarget {
    UdsRequestTarget::Ecu {
        name: ecu.to_owned(),
        additional_fields: Vec::new(),
    }
}

fn map(entries: &[(&str, Value)]) -> Map<String, Value> {
    entries
        .iter()
        .map(|(key, value)| ((*key).to_owned(), value.clone()))
        .collect()
}

fn ecu_lock(ecu: &str, expires_in: Duration, past: bool) -> ActiveLock {
    let now = SystemTime::now();
    ActiveLock {
        id: format!("{ecu}-lock").into(),
        scope: ScopeKey::Ecu(ecu.to_owned()),
        coverage: LockCoverage::new([ecu.to_owned()]),
        principal: LockPrincipal {
            subject: "holder-sub".to_owned(),
            claims: map(&[("scope", json!("Development_ENHANCED"))]),
        },
        metadata: map(&[("use_case", json!("sw_update"))]),
        exclusive: true,
        expires_at: if past {
            now.checked_sub(expires_in)
        } else {
            now.checked_add(expires_in)
        }
        .expect("test time should be representable"),
        parent_vehicle_lock_id: None,
    }
}

#[tokio::test]
async fn snapshot_carries_holder_claims_and_metadata() {
    let locks = Locks::new();
    locks
        .test_insert_active(ecu_lock("ecu-a", Duration::from_secs(300), false))
        .await;

    let snapshot = locks.request_lock_for(&target("ECU-A")).await;

    assert_eq!(
        snapshot,
        Some(RequestLockContext {
            holder: "holder-sub".to_owned(),
            claims: map(&[("scope", json!("Development_ENHANCED"))]),
            metadata: map(&[("use_case", json!("sw_update"))]),
        })
    );
}

#[tokio::test]
async fn no_snapshot_without_an_effective_lock() {
    let locks = Locks::new();
    assert_eq!(locks.request_lock_for(&target("ecu-a")).await, None);

    locks
        .test_insert_active(ecu_lock("ecu-a", Duration::from_secs(300), true))
        .await;
    assert_eq!(
        locks.request_lock_for(&target("ecu-a")).await,
        None,
        "an expired lock must not be reported"
    );
    assert_eq!(locks.request_lock_for(&target("ecu-b")).await, None);
}

#[tokio::test]
async fn snapshot_is_independent_of_later_lock_changes() {
    let locks = Locks::new();
    locks
        .test_insert_active(ecu_lock("ecu-a", Duration::from_secs(300), false))
        .await;

    let snapshot = locks.request_lock_for(&target("ecu-a")).await;
    locks
        .test_mutate_store(|store| {
            store.state.delete("ecu-a-lock").expect("lock exists");
        })
        .await;

    assert!(snapshot.is_some(), "an owned snapshot outlives the lock");
    assert_eq!(locks.request_lock_for(&target("ecu-a")).await, None);
}

#[tokio::test]
async fn provider_reads_the_current_locks_through_the_trait() {
    let locks = Arc::new(Locks::new());
    locks
        .test_insert_active(ecu_lock("ecu-a", Duration::from_secs(300), false))
        .await;
    let provider = SovdLockStateProvider::new(locks);

    let snapshot = provider.current_lock(&target("ecu-a")).await;

    assert_eq!(
        snapshot.map(|lock| lock.holder),
        Some("holder-sub".to_owned())
    );
}
