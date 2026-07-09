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

pub trait SomeTrait: 'static {}

override_macros::declare_vendor_override_registry!();

pub struct PluginA;
impl SomeTrait for PluginA {}

pub struct PluginB;
impl SomeTrait for PluginB {}

pub struct Manager<S: SomeTrait> {
    pub counter: u32,
    pub plugin: S,
}

pub mod overridable {
    use super::{Manager, SomeTrait};

    #[override_macros::vendor_overridable(name = compute)]
    fn compute_fallback<S: SomeTrait>(mgr: &Manager<S>, base: u32) -> u32 {
        let _ = mgr;
        base
    }

    #[override_macros::vendor_overridable(name = bump)]
    fn bump_fallback<S: SomeTrait>(mgr: &mut Manager<S>, amount: u32) -> u32 {
        mgr.counter = mgr.counter.saturating_add(amount);
        mgr.counter
    }
}

#[override_macros::vendor_override(crate::overridable::compute, erase(mgr))]
fn compute_vendor(mgr: &Manager<PluginA>, base: u32) -> u32 {
    mgr.counter.saturating_add(base).saturating_add(1000)
}

#[override_macros::vendor_override(crate::overridable::bump, erase(mgr))]
fn bump_vendor(mgr: &mut Manager<PluginA>, amount: u32) -> u32 {
    mgr.counter = mgr.counter.saturating_add(amount.saturating_mul(2));
    mgr.counter
}

#[test]
fn override_is_used_for_matching_concrete_type() {
    let mgr = Manager {
        counter: 5,
        plugin: PluginA,
    };
    assert_eq!(overridable::compute(&mgr, 3), 5 + 3 + 1000);
}

#[test]
fn fallback_is_used_when_downcast_fails() {
    let mgr = Manager {
        counter: 5,
        plugin: PluginB,
    };
    // The registered override expects a different concrete type
    // (Manager<PluginA>); the downcast fails, dispatcher falls back to the
    // default implementation.
    assert_eq!(overridable::compute(&mgr, 3), 3);
}

#[test]
fn all_overridables_have_at_most_one_registered_override() {
    assert_eq!(validate_vendor_overrides(), Ok(()));
}

#[test]
fn mut_override_is_used_for_matching_concrete_type() {
    let mut mgr = Manager {
        counter: 10,
        plugin: PluginA,
    };
    assert_eq!(overridable::bump(&mut mgr, 4), 18);
    assert_eq!(mgr.counter, 18);
}

#[test]
fn mut_fallback_is_used_when_downcast_fails() {
    let mut mgr = Manager {
        counter: 10,
        plugin: PluginB,
    };
    assert_eq!(overridable::bump(&mut mgr, 4), 14);
    assert_eq!(mgr.counter, 14);
}
