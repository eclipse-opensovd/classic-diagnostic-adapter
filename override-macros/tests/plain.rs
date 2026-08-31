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

//! Tests for the non-generic `vendor_overridable` / `vendor_override` path:
//! the hook stores plain `fn` pointers returning the result directly (no
//! `Option`), and the dispatcher supports at most one registered override.

override_macros::declare_vendor_override_registry!();

pub mod overridable {
    /// Doubles the given value.
    #[override_macros::vendor_overridable(name = double)]
    fn double_fallback(value: u32) -> u32 {
        value.saturating_mul(2)
    }

    /// Triples the given value.
    #[override_macros::vendor_overridable(name = triple)]
    fn triple_fallback(value: u32) -> u32 {
        value.saturating_mul(3)
    }

    /// Concatenates the prefix with the value.
    #[override_macros::vendor_overridable(name = describe)]
    fn describe_fallback(prefix: &str, value: u32) -> String {
        format!("{prefix}: {value}")
    }
}

#[override_macros::vendor_override(crate::overridable::double)]
fn double_vendor(value: u32) -> u32 {
    value.saturating_mul(2).saturating_add(1000)
}

#[override_macros::vendor_override(crate::overridable::describe)]
fn describe_vendor(prefix: &str, value: u32) -> String {
    format!("vendor {prefix}: {value}")
}

#[test]
fn override_replaces_fallback() {
    assert_eq!(overridable::double(4), 1008);
}

#[test]
fn fallback_is_used_without_registered_override() {
    assert_eq!(overridable::triple(4), 12);
}

#[test]
fn override_with_reference_parameters_replaces_fallback() {
    assert_eq!(overridable::describe("count", 7), "vendor count: 7");
}

#[test]
fn all_overridables_have_at_most_one_registered_override() {
    assert_eq!(validate_vendor_overrides(), Ok(()));
}
