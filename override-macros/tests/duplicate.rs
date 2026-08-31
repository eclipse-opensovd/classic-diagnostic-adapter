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

//! Registering two overrides for the same non-generic overridable function is
//! a misconfiguration; `validate_vendor_overrides()` must report it. This
//! lives in its own test binary because `linkme` registration is
//! process-global.

override_macros::declare_vendor_override_registry!();

pub mod overridable {
    #[override_macros::vendor_overridable(name = double)]
    fn double_fallback(value: u32) -> u32 {
        value.saturating_mul(2)
    }
}

#[override_macros::vendor_override(crate::overridable::double)]
fn double_vendor_a(value: u32) -> u32 {
    value.saturating_mul(2).saturating_add(1000)
}

#[override_macros::vendor_override(crate::overridable::double)]
fn double_vendor_b(value: u32) -> u32 {
    value.saturating_mul(2).saturating_add(2000)
}

#[test]
fn validation_reports_duplicate_override() {
    let result = validate_vendor_overrides();
    let errors = result.expect_err("expected duplicate override registration to be reported");
    assert_eq!(errors.len(), 1);
    let message = errors.first().expect("checked len() == 1 above");
    assert!(message.contains("double"));
    assert!(message.contains('2'));
}
