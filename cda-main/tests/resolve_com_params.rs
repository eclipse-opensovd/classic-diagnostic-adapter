/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2025 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

//! Integration tests for the `resolve_com_params` behaviour.
//!
//! `resolve_com_params` is a private function; the `#[cfg(test)]` unit tests
//! inside `cda-main/src/lib.rs` cover its return-value contracts directly.
//! The two tests below provide complementary coverage that unit tests cannot:
//!
//! * `serde_skip_fields_are_dropped_by_figment_without_restoration` — proves
//!   the underlying figment bug (fields become `None` without the restore step)
//!   using the real figment API, anchoring the necessity of the fix in a
//!   falsifiable assertion.
//!
//! * `figment_extraction_fails_on_incompatible_type_in_ecu_table` — confirms
//!   that the `Err` branch inside `resolve_com_params` is reachable by
//!   demonstrating that figment extraction genuinely fails on the same
//!   incompatible-type input used in the unit test, without depending on
//!   private implementation access.

use cda_interfaces::datatypes::ComParams;
use figment::{
    Figment,
    providers::{Format, Serialized, Toml},
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a `ComParams` with both runtime-only fields set to their canonical
/// sentinel values (matching the unit-test helper in `lib.rs`).
fn global_with_runtime_fields() -> ComParams {
    let mut global = ComParams::default();
    global.doip.protocol_name_uds = Some("UDS_Ethernet_DoIP".to_owned());
    global.doip.protocol_name_uds_dobt = Some("UDS_Ethernet_DoIP_DOBT".to_owned());
    global
}

// ---------------------------------------------------------------------------
// Proves the bug: figment drops #[serde(skip)] fields
// ---------------------------------------------------------------------------

/// Demonstrates that figment **drops** `#[serde(skip)]` fields during its
/// internal serde round-trip, establishing why `resolve_com_params` must
/// explicitly restore them after extraction.
#[test]
fn serde_skip_fields_are_dropped_by_figment_without_restoration() {
    let global = global_with_runtime_fields();
    let ecu_toml = r"
[doip.logical_gateway_address]
default = 1234
";
    let merged: ComParams = Figment::from(Serialized::defaults(&global))
        .merge(Toml::string(ecu_toml))
        .extract()
        .expect("figment merge should succeed for well-formed TOML");

    // Without the restoration step the fields are None — the bug that the fix addresses.
    assert!(
        merged.doip.protocol_name_uds.is_none(),
        "figment drops #[serde(skip)] fields; validates the bug exists without the restore step"
    );
    assert!(
        merged.doip.protocol_name_uds_dobt.is_none(),
        "figment drops #[serde(skip)] fields; validates the bug exists without the restore step"
    );
}

// ---------------------------------------------------------------------------
// Confirms the Err branch in resolve_com_params is reachable
// ---------------------------------------------------------------------------

/// Validates that the figment extraction error path is reachable: when the
/// per-ECU TOML contains a scalar where a struct is expected, `extract` fails.
/// This anchors the `Err(e) => { ...; return None }` branch in
/// `resolve_com_params` to a real, reproducible input without requiring
/// access to the private function itself.
#[test]
fn figment_extraction_fails_on_incompatible_type_in_ecu_table() {
    let global = ComParams::default();

    // A plain scalar where figment expects the ComParamConfig struct.
    let bad_toml = r"
[doip]
logical_gateway_address = 9999
";
    let result = Figment::from(Serialized::defaults(&global))
        .merge(Toml::string(bad_toml))
        .extract::<ComParams>();

    assert!(
        result.is_err(),
        "figment extraction must fail when the TOML contains an incompatible type; confirms the \
         resolve_com_params Err branch is reachable"
    );
}
