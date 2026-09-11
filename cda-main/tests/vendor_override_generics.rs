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

//! Cross-crate test for the `vendor_overridable` / `vendor_override` generics
//! support: registers a vendor override for `cda_core::lookup_request_seed_service`
//! from this crate (a different crate than the one defining the overridable
//! function), verifying that:
//! - the generated hook and dispatcher are reachable from another crate
//!   (exercising the `#[deny(unreachable_pub)]` + `pub use` re-export contract)
//! - the override is dispatched when the runtime concrete type matches
//! - the dispatcher falls back to the default implementation when the
//!   runtime concrete type does not match the type declared by the override
//!
//! WARNING: `vendor_override` registrations are process-global for the whole
//! test binary. Every test in this file uses`EcuManager<TestSecurityPlugin>`
//! will hit the override below instead of the default implementation.
//! Because each file under `tests/` is compiled into its own binary, this only
//! affects tests in this file.
//! Do not add tests here that rely on the default `lookup_request_seed_service`
//! behavior with `TestSecurityPlugin`.

use std::path::PathBuf;

use cda_core::EcuManager;
use cda_interfaces::DiagServiceError;
use cda_plugin_security::{DefaultSecurityPluginData, mock::TestSecurityPlugin};
use opensovd_cda_lib::{config::configfile::Configuration, mdd::load_databases};

/// Vendor override for `cda_core::lookup_request_seed_service`, registered only
/// for `EcuManager<TestSecurityPlugin>`.
#[override_macros::vendor_override(cda_core::lookup_request_seed_service, erase(ecu_mgr))]
fn lookup_request_seed_vendor_override(
    ecu_mgr: &EcuManager<TestSecurityPlugin>,
    level: &str,
) -> Result<cda_interfaces::SecurityAccess, DiagServiceError> {
    let _ = (ecu_mgr, level);
    Err(DiagServiceError::InvalidRequest(
        "vendor override called".to_owned(),
    ))
}

fn test_mdd_path() -> PathBuf {
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../testcontainer/odx/FLXC1000.mdd"
    ))
}

fn is_vendor_override_marker(
    result: &Result<cda_interfaces::SecurityAccess, DiagServiceError>,
) -> bool {
    matches!(result, Err(DiagServiceError::InvalidRequest(msg)) if msg == "vendor override called")
}

/// `SecurityAccess` does not implement `Debug`, so build a short description
/// of the result for assertion failure messages instead of using `{:?}`.
fn describe_result(result: &Result<cda_interfaces::SecurityAccess, DiagServiceError>) -> String {
    match result {
        Ok(cda_interfaces::SecurityAccess::RequestSeed(_)) => "Ok(RequestSeed(..))".to_owned(),
        Ok(cda_interfaces::SecurityAccess::SendKey(_)) => "Ok(SendKey(..))".to_owned(),
        Err(err) => format!("Err({err})"),
    }
}

#[tokio::test]
async fn vendor_override_is_dispatched_for_matching_concrete_type() {
    let config = Configuration::default();
    let mdd_paths = vec![test_mdd_path()];
    let (databases, _file_managers) =
        load_databases::<TestSecurityPlugin>(&config, &mdd_paths, None)
            .await
            .expect("failed to load test ECU database");
    let (_, ecu_lock) = databases.iter().next().expect("no ECU was loaded");
    let ecu_manager = ecu_lock.read().await;

    let result = cda_core::lookup_request_seed_service(&ecu_manager, "level_01");

    assert!(
        is_vendor_override_marker(&result),
        "expected vendor override to be dispatched, got: {}",
        describe_result(&result)
    );
}

#[tokio::test]
async fn dispatcher_falls_back_when_concrete_type_does_not_match() {
    let config = Configuration::default();
    let mdd_paths = vec![test_mdd_path()];
    let (databases, _file_managers) =
        load_databases::<DefaultSecurityPluginData>(&config, &mdd_paths, None)
            .await
            .expect("failed to load test ECU database");
    let (_, ecu_lock) = databases.iter().next().expect("no ECU was loaded");
    let ecu_manager = ecu_lock.read().await;

    let result = cda_core::lookup_request_seed_service(&ecu_manager, "level_01");

    // The override above is registered for `EcuManager<TestSecurityPlugin>`, but this
    // ECU manager is `EcuManager<DefaultSecurityPluginData>`. The downcast in the
    // generated shim fails, so the dispatcher must fall back to the default
    // implementation instead of returning the vendor override's marker error.
    assert!(
        !is_vendor_override_marker(&result),
        "expected fallback to the default implementation, but the vendor override marker was \
         returned: {}",
        describe_result(&result)
    );
}
